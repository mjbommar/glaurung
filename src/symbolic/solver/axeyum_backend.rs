//! Pure-Rust, in-process SMT backends via the `axeyum` solver.
//!
//! Two implementations of [`Solver`], both backed by axeyum (a pure-Rust
//! QF_BV solver with DRAT-checked unsat proofs -- no libz3, no C, no
//! subprocess):
//!
//! - [`AxeyumSolver`] (P2, native): translates glaurung's [`Expr`] IR
//!   directly into `axeyum-ir` terms and solves with
//!   `IncrementalBvSolver`, returning the model straight out of
//!   `CheckResult::Sat`. This is the real backend.
//! - `AxeyumTextSolver` (P1, `solver-axeyum-text` text bridge): renders the query to SMT-LIB2
//!   via [`super::pipe::build_script`] and calls axeyum's `solve_smtlib`.
//!   Kept as a cross-check / reference and a zero-translation fallback.
//!
//! See `docs/architecture/solver/interface-mapping.md` (live contract; record in `docs/history/axeyum-integration-2026-07/`).

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use axeyum_ir::{IrError, Sort, SymbolId, TermArena, TermId, Value, WideUint};
use axeyum_solver::{
    export_qf_bv_unsat_proof_within, AigConstructionStats, CheckResult, IncrementalBvSolver,
    IncrementalBvStats, IncrementalCnfStats, IncrementalLoweringStats, IncrementalModelLiftStats,
    IncrementalSolver as AxeyumIncrementalSolver, ReplayCheckedSatCachePolicy,
    ReplayCheckedSatCacheStats, SolverConfig, UnknownKind, UnsatProof, UnsatProofOutcome,
};
#[cfg(feature = "solver-axeyum-text")]
use axeyum_solver::{solve_smtlib, solve_smtlib_get_value};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::ir::types::{BinOp, CmpOp, UnOp};
use crate::symbolic::expr::{Expr, ExprId, ExprPool};
use crate::symbolic::solver::{
    check_timeout, pipe, solver_work_budgets, Assert, AxeyumExecutionClass, IncrementalSolver,
    Model, SolveResult, SolveUnknownReason, Solver, SolverWorkBudgets, WarmAssertionPrefix,
    WarmDeltaContext,
};

mod config;
mod profile;
mod snapshot;
mod translate;
mod warm_paths;
mod warm_stats;

use config::{
    config, replay_sat_cache_policy, select_warm_timeout_continuation, warm_reuse_limits,
    warm_reuse_policy, warm_timeout_continue_enabled, WarmReusePolicy,
};
pub(crate) use config::{
    direct_delta_enabled, last_direct_delta_synced, reset_direct_delta_sync,
    warm_owner_transfer_enabled, warm_serial_sibling_reuse_enabled,
    warm_timeout_cold_retry_enabled,
};
use profile::{finish_warm_profile, start_warm_profile, AxeyumCheckProfile};
pub use profile::{ProfiledSolveResult, WarmAxeyumCheckProfile};
pub use snapshot::{SnapshotIncrementalAxeyumSolver, SnapshotReuseStats};
use translate::{translate_path, translate_query};
pub(crate) use warm_paths::{
    check_warm_thread_local, close_fair_warm_path, close_warm_path,
    share_serial_warm_owner_with_children, warm_reuse_enabled,
};
use warm_paths::{
    AutoLineageAdmission, DirectDeltaLineageAxeyumSolver, LineageIncrementalAxeyumSolver,
    SerialWarmOwnerLeases,
};
// `check_fair_warm_thread_local` has exactly one caller, and it sits behind this
// same gate in `super::solve`; re-exporting it unconditionally would be an
// unused import in every build that is not the fair-shadow one.
#[cfg(all(feature = "solver-z3", feature = "solver-axeyum"))]
pub(crate) use warm_paths::check_fair_warm_thread_local;
pub use warm_stats::{
    adaptive_lineage_reuse_stats, auto_lineage_reuse_stats, replay_sat_cache_stats,
    serial_sibling_reuse_stats, warm_path_reuse_stats, warm_reuse_stats,
    warm_timeout_cold_retry_stats, warm_timeout_continuation_stats, AdaptiveLineageReuseStats,
    AutoLineageReuseStats, ReplaySatCacheProcessStats, SerialSiblingReuseStats, WarmPathReuseStats,
    WarmTimeoutColdRetryStats, WarmTimeoutContinuationStats,
};
use warm_stats::{record_replay_sat_cache_delta, subtract_replay_sat_cache_gauges};

// Re-exports whose only consumer is this module's own `#[cfg(test)]` block. In a
// shipped `lib` build each of these would be an unused import, so they are gated
// to match.
#[cfg(test)]
use config::{
    config_with_work_budgets, parse_direct_delta, parse_replay_sat_cache_policy, parse_warm_limit,
    parse_warm_owner_transfer, parse_warm_reuse_policy, parse_warm_serial_sibling_reuse,
    parse_warm_timeout_cold_retry, parse_warm_timeout_continue,
};
#[cfg(test)]
use profile::{
    aig_construction, cnf_gate_mix, lowering_work, model_lift_work, replay_sat_cache_profile,
};
#[cfg(test)]
use warm_paths::{
    adaptive_live_path_limit, check_warm_thread_local_selected, try_reserve_path_counter,
    DirectDeltaStats, SerialLeaseRelease,
};

const PROFILE_DIR_ENV: &str = "GLAURUNG_AXEYUM_PROFILE_DIR";
const CNF_SNAPSHOT_DIR_ENV: &str = "GLAURUNG_AXEYUM_CNF_SNAPSHOT_DIR";
pub(crate) const WARM_REUSE_ENV: &str = "GLAURUNG_AXEYUM_WARM_REUSE";
pub(crate) const WARM_OWNER_TRANSFER_ENV: &str = "GLAURUNG_AXEYUM_WARM_OWNER_TRANSFER";
pub(crate) const WARM_SERIAL_SIBLING_REUSE_ENV: &str = "GLAURUNG_AXEYUM_WARM_SERIAL_SIBLING_REUSE";
pub(crate) const DIRECT_DELTA_ENV: &str = "GLAURUNG_AXEYUM_DIRECT_DELTA";
pub(crate) const WARM_TIMEOUT_COLD_RETRY_ENV: &str = "GLAURUNG_AXEYUM_WARM_TIMEOUT_COLD_RETRY";
pub(crate) const WARM_TIMEOUT_CONTINUE_ENV: &str = "GLAURUNG_AXEYUM_WARM_TIMEOUT_CONTINUE";
const INTERNAL_AND_FLATTENING_ENV: &str = "GLAURUNG_AXEYUM_INTERNAL_AND_FLATTENING";
pub(crate) const REPLAY_SAT_CACHE_ENV: &str = "GLAURUNG_AXEYUM_REPLAY_SAT_CACHE";
const WARM_MAX_LIVE_PATHS_ENV: &str = "GLAURUNG_AXEYUM_WARM_MAX_LIVE_PATHS";
const WARM_MAX_ASSERTIONS_PER_PATH_ENV: &str = "GLAURUNG_AXEYUM_WARM_MAX_ASSERTIONS_PER_PATH";
const DEFAULT_WARM_MAX_LIVE_PATHS: u64 = 9;
const DEFAULT_WARM_MAX_ASSERTIONS_PER_PATH: u64 = 512;
const DEFAULT_REPLAY_SAT_CACHE_ENTRIES: usize = 64;
const DEFAULT_REPLAY_SAT_CACHE_MODEL_VALUES: usize = 4_096;
const DEFAULT_REPLAY_SAT_CACHE_MODEL_BITS: usize = 262_144;

static PROFILE_DIR: OnceLock<Option<PathBuf>> = OnceLock::new();
static CNF_SNAPSHOT_DIR: OnceLock<Option<PathBuf>> = OnceLock::new();
static PROFILE_WRITE_LOCK: Mutex<()> = Mutex::new(());
static PROFILE_SEQUENCE: AtomicU64 = AtomicU64::new(0);
static CNF_SNAPSHOT_SEQUENCE: AtomicU64 = AtomicU64::new(0);
static WARM_CHECKS: AtomicU64 = AtomicU64::new(0);
static WARM_EXACT_REUSES: AtomicU64 = AtomicU64::new(0);
static WARM_PREFIX_REUSES: AtomicU64 = AtomicU64::new(0);
static WARM_ASSERTIONS_ADDED: AtomicU64 = AtomicU64::new(0);
static WARM_ASSERTIONS_POPPED: AtomicU64 = AtomicU64::new(0);
static WARM_RESETS: AtomicU64 = AtomicU64::new(0);
static WARM_PATHS_CREATED: AtomicU64 = AtomicU64::new(0);
static WARM_PATHS_CLOSED: AtomicU64 = AtomicU64::new(0);
static WARM_PATHS_LIVE: AtomicU64 = AtomicU64::new(0);
static WARM_PATHS_PEAK_LIVE: AtomicU64 = AtomicU64::new(0);
static WARM_PATH_LIMIT_FALLBACKS: AtomicU64 = AtomicU64::new(0);
static WARM_ASSERTION_LIMIT_FALLBACKS: AtomicU64 = AtomicU64::new(0);
static WARM_TIMEOUT_COLD_RETRIES: AtomicU64 = AtomicU64::new(0);
static WARM_TIMEOUT_COLD_RECOVERIES: AtomicU64 = AtomicU64::new(0);
static WARM_TIMEOUT_COLD_UNKNOWNS: AtomicU64 = AtomicU64::new(0);
static WARM_TIMEOUT_COLD_ERRORS: AtomicU64 = AtomicU64::new(0);
static WARM_TIMEOUT_CONTINUATIONS: AtomicU64 = AtomicU64::new(0);
static WARM_TIMEOUT_CONTINUATION_RECOVERIES: AtomicU64 = AtomicU64::new(0);
static WARM_TIMEOUT_CONTINUATION_UNKNOWNS: AtomicU64 = AtomicU64::new(0);
static WARM_TIMEOUT_CONTINUATION_ERRORS: AtomicU64 = AtomicU64::new(0);
static WARM_AUTO_PROBES: AtomicU64 = AtomicU64::new(0);
static WARM_AUTO_ACTIVATIONS: AtomicU64 = AtomicU64::new(0);
static WARM_ADAPTIVE_PRESSURE_EVENTS: AtomicU64 = AtomicU64::new(0);
static WARM_ADAPTIVE_EXPANSIONS: AtomicU64 = AtomicU64::new(0);
static WARM_SERIAL_SHARE_EVENTS: AtomicU64 = AtomicU64::new(0);
static WARM_SERIAL_TRACKED_OWNERS: AtomicU64 = AtomicU64::new(0);
static WARM_SERIAL_REFERENCES: AtomicU64 = AtomicU64::new(0);
static WARM_SERIAL_PEAK_REFERENCES: AtomicU64 = AtomicU64::new(0);
static WARM_REUSE_LIMITS: OnceLock<WarmReuseLimits> = OnceLock::new();
static REPLAY_SAT_CACHE_POLICY: OnceLock<Option<ReplayCheckedSatCachePolicy>> = OnceLock::new();
static REPLAY_SAT_CACHE_HITS: AtomicU64 = AtomicU64::new(0);
static REPLAY_SAT_CACHE_MISSES: AtomicU64 = AtomicU64::new(0);
static REPLAY_SAT_CACHE_INSERTIONS: AtomicU64 = AtomicU64::new(0);
static REPLAY_SAT_CACHE_EVICTIONS: AtomicU64 = AtomicU64::new(0);
static REPLAY_SAT_CACHE_REPLAY_FAILURES: AtomicU64 = AtomicU64::new(0);
static REPLAY_SAT_CACHE_DECLINED_UNSAT: AtomicU64 = AtomicU64::new(0);
static REPLAY_SAT_CACHE_DECLINED_UNKNOWN: AtomicU64 = AtomicU64::new(0);
static REPLAY_SAT_CACHE_DECLINED_OVERSIZED_MODELS: AtomicU64 = AtomicU64::new(0);
static REPLAY_SAT_CACHE_DECLINED_NON_SCALAR_MODELS: AtomicU64 = AtomicU64::new(0);
static REPLAY_SAT_CACHE_ENTRIES: AtomicU64 = AtomicU64::new(0);
static REPLAY_SAT_CACHE_MODEL_VALUES: AtomicU64 = AtomicU64::new(0);
static REPLAY_SAT_CACHE_MODEL_BITS: AtomicU64 = AtomicU64::new(0);

const ADAPTIVE_INITIAL_LIVE_PATHS: u64 = 2;
const ADAPTIVE_PRESSURE_THRESHOLD: u64 = 128;

thread_local! {
    /// One retained snapshot adapter per explorer thread. Glaurung currently
    /// submits complete assertion snapshots rather than explicit path scopes;
    /// the adapter reconstructs the common prefix and maps it to Axeyum scopes.
    static WARM_SOLVER: RefCell<SnapshotIncrementalAxeyumSolver> =
        RefCell::new(SnapshotIncrementalAxeyumSolver::new());
    /// Retained mutable solver state keyed by explorer-owned path identity.
    /// Each worker owns its map; no solver is shared across paths or threads.
    static LINEAGE_SOLVERS: RefCell<LineageIncrementalAxeyumSolver> =
        RefCell::new(LineageIncrementalAxeyumSolver::default());
    /// Opt-in sessions driven by explicit explorer prefix deltas. Separate from
    /// the accepted snapshot lineage map so the control remains exact.
    static DIRECT_DELTA_SOLVERS: RefCell<DirectDeltaLineageAxeyumSolver> =
        RefCell::new(DirectDeltaLineageAxeyumSolver::default());
    /// Whether the immediately preceding Axeyum check synchronized its direct
    /// persistent session. Explorer retain markers advance only on `true`.
    static LAST_DIRECT_DELTA_SYNCED: Cell<bool> = const { Cell::new(false) };
    /// Path IDs observed once by GQ9's opt-in auto policy. This set is the
    /// constant-size-per-path admission probe; it retains no arena or solver.
    static AUTO_LINEAGE_ADMISSION: RefCell<AutoLineageAdmission> =
        RefCell::new(AutoLineageAdmission::default());
    /// Logical references held by the active DFS state and its queued sibling
    /// continuations. One thread executes them serially; this is lifecycle
    /// bookkeeping, not concurrent solver access.
    static SERIAL_WARM_OWNER_LEASES: RefCell<SerialWarmOwnerLeases> =
        RefCell::new(SerialWarmOwnerLeases::default());
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WarmReuseLimits {
    max_live_paths: u64,
    max_assertions_per_path: u64,
}

// ---------------------------------------------------------------------------
// P2: native term-translation backend
// ---------------------------------------------------------------------------

/// The native, in-process axeyum backend: `Expr` -> `axeyum-ir` -> solve.
#[derive(Debug, Default, Clone, Copy)]
pub struct AxeyumSolver;

struct WarmProfileContext {
    profile: WarmAxeyumCheckProfile,
    total_started: Instant,
    solver_before: IncrementalBvStats,
    replay_sat_cache_before: ReplayCheckedSatCacheStats,
}

struct TranslatedQuery {
    assertions: Vec<TermId>,
    sym_map: Vec<(u32, SymbolId)>,
    exprs: usize,
}

impl AxeyumSolver {
    pub fn new() -> Self {
        Self
    }

    /// Run the unchanged raw one-shot policy with explicit client attribution.
    ///
    /// This is diagnostic and opt-in. Ordinary [`Solver::check`] does not
    /// render/hash the query or enable Axeyum's phase clocks.
    pub fn check_profiled(&self, pool: &ExprPool, asserts: &[Assert]) -> ProfiledSolveResult {
        let (script, _) = pipe::build_script(pool, asserts);
        let query_hash = format!("sha256:{}", hex::encode(Sha256::digest(script.as_bytes())));
        let total_started = Instant::now();
        let arena_started = Instant::now();
        let mut arena = TermArena::new();
        let arena_create_nanos = nanos(arena_started.elapsed());
        let assertion_count = count(asserts.len());

        let translation_started = Instant::now();
        let translated = translate_query(pool, asserts, &mut arena);
        let translation_nanos = nanos(translation_started.elapsed());
        let mut profile = AxeyumCheckProfile {
            schema: "glaurung-axeyum-native-profile-v1",
            process_id: std::process::id(),
            sequence: None,
            query_hash,
            word_policy: "raw",
            timeout_ms: u64::try_from(check_timeout().as_millis()).unwrap_or(u64::MAX),
            outcome: "error",
            complete: false,
            assertion_count,
            translated_exprs: 0,
            arena_terms: count(arena.len()),
            symbols: 0,
            model_values: 0,
            root_encodings: 0,
            checks: 0,
            aig_nodes: 0,
            cnf_variables: 0,
            cnf_clauses: 0,
            arena_create_nanos,
            translation_nanos,
            solver_create_nanos: 0,
            word_rewrite_nanos: 0,
            bit_blast_nanos: 0,
            cnf_encode_nanos: 0,
            solve_nanos: 0,
            model_lift_nanos: 0,
            replay_nanos: 0,
            model_extract_nanos: 0,
            total_nanos: 0,
        };
        let translated = match translated {
            Ok(translated) => translated,
            Err(err) => {
                profile.arena_terms = count(arena.len());
                profile.total_nanos = nanos(total_started.elapsed());
                return ProfiledSolveResult {
                    result: SolveResult::Error(format!("axeyum translate: {err}")),
                    profile,
                };
            }
        };
        profile.translated_exprs = count(translated.exprs);
        profile.arena_terms = count(arena.len());
        profile.symbols = count(translated.sym_map.len());

        let solver_started = Instant::now();
        let mut solver = IncrementalBvSolver::with_config_and_profiling(config());
        profile.solver_create_nanos = nanos(solver_started.elapsed());
        for &term in &translated.assertions {
            if let Err(err) = solver.assert(&arena, term) {
                apply_solver_stats(&mut profile, solver.stats());
                profile.total_nanos = nanos(total_started.elapsed());
                return ProfiledSolveResult {
                    result: SolveResult::Error(format!("axeyum assert: {err}")),
                    profile,
                };
            }
        }
        let checked = solver.check(&arena);
        apply_solver_stats(&mut profile, solver.stats());

        let model_started = Instant::now();
        let result = map_check_result(checked, &translated.sym_map);
        profile.model_extract_nanos = nanos(model_started.elapsed());
        if let SolveResult::Sat(model) = &result {
            profile.model_values = count(model.values.len());
        }
        profile.outcome = result_name(&result);
        profile.complete = !matches!(&result, SolveResult::Error(_));
        profile.total_nanos = nanos(total_started.elapsed());
        ProfiledSolveResult { result, profile }
    }
}

impl Solver for AxeyumSolver {
    fn check(&mut self, pool: &ExprPool, asserts: &[Assert]) -> SolveResult {
        if let Some(output_dir) = profile_output_dir() {
            let profiled = self.check_profiled(pool, asserts);
            if let Err(error) = write_profile_record(output_dir, &profiled.profile) {
                return SolveResult::Error(error);
            }
            return profiled.result;
        }

        let mut arena = TermArena::new();
        let translated = match translate_query(pool, asserts, &mut arena) {
            Ok(translated) => translated,
            Err(err) => return SolveResult::Error(format!("axeyum translate: {err}")),
        };

        let mut solver = IncrementalBvSolver::with_config(config());
        for t in &translated.assertions {
            // Raw `assert` (no preprocessing) is fastest for this ONE-SHOT
            // trait: axeyum's word-level preprocessing (`assert_configured`,
            // added 2026-07-13) pays a per-query canonicalization cost that
            // only amortizes across REUSED checks on the warm path. Measured:
            // in one-shot mode `assert_configured` is ~1.3-2x SLOWER than
            // `assert` on real drivers (no reuse to amortize). It becomes the
            // right call once the incremental (warm) Solver trait lands (P5).
            if let Err(err) = solver.assert(&arena, *t) {
                return SolveResult::Error(format!("axeyum assert: {err}"));
            }
        }
        map_check_result(solver.check(&arena), &translated.sym_map)
    }
}

/// A direct-delta Axeyum session for Glaurung's first-class incremental trait.
///
/// Each [`IncrementalSolver::assert`] translates only that assertion's
/// expression DAG. The Axeyum arena, AIG, CNF, SAT state, learned clauses, and
/// original-term replay metadata remain live across checks. Per-scope symbol
/// maps are retained alongside the solver frames so popped and temporary terms
/// cannot leak values into a later client model.
#[derive(Debug)]
pub struct IncrementalAxeyumSolver {
    arena: TermArena,
    solver: IncrementalBvSolver,
    symbol_frames: Vec<Vec<(u32, SymbolId)>>,
}

impl Default for IncrementalAxeyumSolver {
    fn default() -> Self {
        Self::new()
    }
}

impl IncrementalAxeyumSolver {
    /// Create an empty raw-policy retained session.
    pub fn new() -> Self {
        Self::with_cache_policy(None, false)
    }

    fn new_path_owned(profiling: bool) -> Self {
        Self::with_cache_policy(replay_sat_cache_policy(), profiling)
    }

    fn with_cache_policy(policy: Option<ReplayCheckedSatCachePolicy>, profiling: bool) -> Self {
        let solver_config = config().with_preprocess(false);
        let mut solver = if profiling {
            IncrementalBvSolver::with_config_and_profiling(solver_config)
        } else {
            IncrementalBvSolver::with_config(solver_config)
        };
        if let Some(policy) = policy {
            solver
                .enable_replay_checked_sat_cache(policy)
                .expect("Glaurung replay-SAT-cache bounds are nonzero constants");
        }
        Self {
            arena: TermArena::new(),
            solver,
            symbol_frames: vec![Vec::new()],
        }
    }

    fn replay_sat_cache_stats(&self) -> ReplayCheckedSatCacheStats {
        self.solver.replay_checked_sat_cache_stats()
    }

    fn solver_stats(&self) -> IncrementalBvStats {
        self.solver.stats()
    }

    fn profiled_last_cnf_snapshot(&self) -> Result<Option<RetainedCnfSnapshot>, String> {
        self.solver
            .profiled_last_cnf_snapshot()
            .map(|snapshot| {
                snapshot.map(|formula| RetainedCnfSnapshot {
                    variable_count: count(formula.variable_count()),
                    clause_count: count(formula.clauses().len()),
                    dimacs: formula.to_dimacs(),
                })
            })
            .map_err(|error| format!("axeyum retained CNF snapshot: {error}"))
    }

    fn arena_len(&self) -> usize {
        self.arena.len()
    }

    fn active_symbol_map(&self) -> Vec<(u32, SymbolId)> {
        self.symbol_frames.iter().flatten().copied().collect()
    }

    fn translate(
        &mut self,
        pool: &ExprPool,
        assertions: &[Assert],
    ) -> Result<TranslatedQuery, IrError> {
        translate_query(pool, assertions, &mut self.arena)
    }

    fn assert_measured(
        &mut self,
        pool: &ExprPool,
        assertion: Assert,
        profiling: bool,
    ) -> Result<DirectTranslationMetrics, String> {
        let started = profiling.then(Instant::now);
        let translated = self
            .translate(pool, std::slice::from_ref(&assertion))
            .map_err(|error| format!("axeyum translate: {error}"))?;
        let metrics = DirectTranslationMetrics {
            nanos: started.map_or(0, |started| nanos(started.elapsed())),
            roots: 1,
            exprs: count(translated.exprs),
            symbols: count(translated.sym_map.len()),
        };
        let term = translated.assertions[0];
        AxeyumIncrementalSolver::assert(&mut self.solver, &self.arena, term)
            .map_err(|error| format!("axeyum assert: {error}"))?;
        self.symbol_frames
            .last_mut()
            .expect("base symbol frame is invariant")
            .extend(translated.sym_map);
        Ok(metrics)
    }

    fn check_measured(&mut self, profiling: bool) -> (SolveResult, u64) {
        let symbols = self.active_symbol_map();
        let checked = AxeyumIncrementalSolver::check(&mut self.solver, &self.arena);
        let started = profiling.then(Instant::now);
        let result = map_check_result(checked, &symbols);
        (
            result,
            started.map_or(0, |started| nanos(started.elapsed())),
        )
    }

    fn check_assuming_measured(
        &mut self,
        pool: &ExprPool,
        assumptions: &[Assert],
        profiling: bool,
        continue_on_unknown: bool,
    ) -> (SolveResult, DirectTranslationMetrics, u64) {
        let translation_started = profiling.then(Instant::now);
        let translated = match self.translate(pool, assumptions) {
            Ok(translated) => translated,
            Err(error) => {
                return (
                    SolveResult::Error(format!("axeyum translate: {error}")),
                    DirectTranslationMetrics::default(),
                    0,
                );
            }
        };
        let translation = DirectTranslationMetrics {
            nanos: translation_started.map_or(0, |started| nanos(started.elapsed())),
            roots: count(assumptions.len()),
            exprs: count(translated.exprs),
            symbols: count(translated.sym_map.len()),
        };
        let mut symbols = self.active_symbol_map();
        symbols.extend(translated.sym_map);
        let checked = AxeyumIncrementalSolver::check_assuming(
            &mut self.solver,
            &self.arena,
            &translated.assertions,
        );
        let model_started = profiling.then(Instant::now);
        let mut result = map_check_result(checked, &symbols);
        let mut model_extract_nanos = model_started.map_or(0, |started| nanos(started.elapsed()));
        if continue_on_unknown
            && matches!(
                result,
                SolveResult::Unknown(SolveUnknownReason::WallTimeout)
            )
        {
            WARM_TIMEOUT_CONTINUATIONS.fetch_add(1, Ordering::Relaxed);
            let checked = AxeyumIncrementalSolver::check_assuming(
                &mut self.solver,
                &self.arena,
                &translated.assertions,
            );
            let model_started = profiling.then(Instant::now);
            let continuation = map_check_result(checked, &symbols);
            model_extract_nanos = model_extract_nanos
                .saturating_add(model_started.map_or(0, |started| nanos(started.elapsed())));
            result = select_warm_timeout_continuation(result, continuation);
        }
        (result, translation, model_extract_nanos)
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct DirectTranslationMetrics {
    nanos: u64,
    roots: u64,
    exprs: u64,
    symbols: u64,
}

impl DirectTranslationMetrics {
    fn add(&mut self, other: Self) {
        self.nanos = self.nanos.saturating_add(other.nanos);
        self.roots = self.roots.saturating_add(other.roots);
        self.exprs = self.exprs.saturating_add(other.exprs);
        self.symbols = self.symbols.saturating_add(other.symbols);
    }
}

impl IncrementalSolver for IncrementalAxeyumSolver {
    fn assert(&mut self, pool: &ExprPool, assertion: Assert) -> Result<(), String> {
        self.assert_measured(pool, assertion, false).map(|_| ())
    }

    fn push(&mut self) -> Result<(), String> {
        AxeyumIncrementalSolver::push(&mut self.solver)
            .map_err(|error| format!("axeyum push: {error}"))?;
        self.symbol_frames.push(Vec::new());
        Ok(())
    }

    fn pop(&mut self) -> bool {
        if !AxeyumIncrementalSolver::pop(&mut self.solver) {
            return false;
        }
        let popped = self.symbol_frames.pop();
        debug_assert!(popped.is_some());
        true
    }

    fn scope_depth(&self) -> usize {
        AxeyumIncrementalSolver::scope_depth(&self.solver)
    }

    fn check(&mut self) -> SolveResult {
        self.check_measured(false).0
    }

    fn check_assuming(&mut self, pool: &ExprPool, assumptions: &[Assert]) -> SolveResult {
        self.check_assuming_measured(pool, assumptions, false, false)
            .0
    }
}

#[derive(Debug, Clone, Copy)]
struct WarmProfileEntry {
    mode: &'static str,
    persistent_assertions: usize,
    temporary_assumptions: usize,
    persistent_translated: usize,
    temporary_translated: usize,
}

#[derive(Debug, Clone, Copy)]
struct DirectCheckInput<'a> {
    complete_asserts: &'a [Assert],
    persistent: &'a [Assert],
    persistent_prefix: &'a WarmAssertionPrefix,
    retain_assertions: usize,
    temporary: &'a [Assert],
}

struct RetainedCnfSnapshot {
    variable_count: u64,
    clause_count: u64,
    dimacs: String,
}

#[derive(Serialize)]
struct RetainedCnfSnapshotMetadata<'a> {
    schema: &'static str,
    process_id: u32,
    sequence: u64,
    query_hash: &'a str,
    path_id: u64,
    outcome: &'a str,
    variable_count: u64,
    clause_count: u64,
    dimacs_sha256: String,
    learned_clauses_included: bool,
    active_assumptions_materialized_as_units: bool,
}

fn map_check_result(
    checked: Result<CheckResult, axeyum_solver::SolverError>,
    sym_map: &[(u32, SymbolId)],
) -> SolveResult {
    match checked {
        Ok(CheckResult::Sat(model)) => {
            let mut values = BTreeMap::new();
            for &(glaurung_id, axeyum_id) in sym_map {
                if let Some(Value::Bv { value, .. }) = model.get(axeyum_id) {
                    values.insert(glaurung_id, value);
                }
                // WideBv (>128-bit) does not fit glaurung's u128 slot; skipped
                // (it does not occur for <=128-bit symbols).
            }
            SolveResult::Sat(Model { values })
        }
        Ok(CheckResult::Unsat) => SolveResult::Unsat,
        Ok(CheckResult::Unknown(reason)) => SolveResult::Unknown(match reason.kind {
            UnknownKind::ResourceLimit
            | UnknownKind::NodeBudget
            | UnknownKind::MemoryLimit
            | UnknownKind::EncodingBudget => SolveUnknownReason::ResourceLimit,
            UnknownKind::Timeout => SolveUnknownReason::WallTimeout,
            _ => SolveUnknownReason::Other,
        }),
        Err(err) => SolveResult::Error(format!("axeyum check: {err}")),
    }
}

fn apply_solver_stats(profile: &mut AxeyumCheckProfile, stats: IncrementalBvStats) {
    profile.word_rewrite_nanos = nanos(stats.word_rewrite);
    profile.bit_blast_nanos = nanos(stats.bit_blast);
    profile.cnf_encode_nanos = nanos(stats.cnf_encode);
    profile.solve_nanos = nanos(stats.solve);
    profile.model_lift_nanos = nanos(stats.model_lift);
    profile.replay_nanos = nanos(stats.replay);
    profile.root_encodings = stats.root_encodings;
    profile.checks = stats.checks;
    profile.aig_nodes = stats.aig_nodes;
    profile.cnf_variables = stats.cnf_variables;
    profile.cnf_clauses = stats.cnf_clauses;
}

fn profile_output_dir() -> Option<&'static Path> {
    PROFILE_DIR
        .get_or_init(|| std::env::var_os(PROFILE_DIR_ENV).map(PathBuf::from))
        .as_deref()
}

fn cnf_snapshot_output_dir() -> Option<&'static Path> {
    CNF_SNAPSHOT_DIR
        .get_or_init(|| std::env::var_os(CNF_SNAPSHOT_DIR_ENV).map(PathBuf::from))
        .as_deref()
}

fn diagnostics_enabled() -> bool {
    profile_output_dir().is_some() || cnf_snapshot_output_dir().is_some()
}

fn write_retained_cnf_snapshot(
    output_dir: &Path,
    query_hash: &str,
    path_id: u64,
    outcome: &str,
    snapshot: &RetainedCnfSnapshot,
) -> Result<(), String> {
    std::fs::create_dir_all(output_dir).map_err(|error| {
        format!(
            "create {CNF_SNAPSHOT_DIR_ENV} directory {}: {error}",
            output_dir.display()
        )
    })?;
    let sequence = CNF_SNAPSHOT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let process_id = std::process::id();
    let hash = query_hash.strip_prefix("sha256:").unwrap_or(query_hash);
    let stem = format!("retained-{outcome}-{process_id}-{sequence:06}-{hash}");
    let cnf_path = output_dir.join(format!("{stem}.cnf"));
    let metadata_path = output_dir.join(format!("{stem}.json"));
    std::fs::write(&cnf_path, snapshot.dimacs.as_bytes())
        .map_err(|error| format!("write retained CNF {}: {error}", cnf_path.display()))?;
    let metadata = RetainedCnfSnapshotMetadata {
        schema: "glaurung-axeyum-retained-cnf-snapshot-v1",
        process_id,
        sequence,
        query_hash,
        path_id,
        outcome,
        variable_count: snapshot.variable_count,
        clause_count: snapshot.clause_count,
        dimacs_sha256: hex::encode(Sha256::digest(snapshot.dimacs.as_bytes())),
        learned_clauses_included: false,
        active_assumptions_materialized_as_units: true,
    };
    let encoded = serde_json::to_vec_pretty(&metadata)
        .map_err(|error| format!("serialize retained CNF metadata: {error}"))?;
    std::fs::write(&metadata_path, encoded).map_err(|error| {
        format!(
            "write retained CNF metadata {}: {error}",
            metadata_path.display()
        )
    })
}

fn write_profile_record<T: Serialize>(output_dir: &Path, profile: &T) -> Result<(), String> {
    std::fs::create_dir_all(output_dir).map_err(|error| {
        format!(
            "create {PROFILE_DIR_ENV} directory {}: {error}",
            output_dir.display()
        )
    })?;
    let _guard = PROFILE_WRITE_LOCK
        .lock()
        .map_err(|_| "axeyum profile writer lock poisoned".to_string())?;
    let path = output_dir.join(format!("axeyum-profile-{}.jsonl", std::process::id()));
    let mut output = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|error| format!("open axeyum profile {}: {error}", path.display()))?;
    let mut record = serde_json::to_value(profile)
        .map_err(|error| format!("serialize axeyum profile: {error}"))?;
    let Some(record) = record.as_object_mut() else {
        return Err("serialize axeyum profile: record is not an object".to_string());
    };
    record.insert(
        "sequence".to_string(),
        serde_json::Value::from(PROFILE_SEQUENCE.fetch_add(1, Ordering::Relaxed)),
    );
    serde_json::to_writer(&mut output, &record)
        .map_err(|error| format!("serialize axeyum profile: {error}"))?;
    writeln!(output).map_err(|error| format!("write axeyum profile {}: {error}", path.display()))
}

fn result_name(result: &SolveResult) -> &'static str {
    match result {
        SolveResult::Sat(_) => "sat",
        SolveResult::Unsat => "unsat",
        SolveResult::Unknown(_) => "unknown",
        SolveResult::NoSolver => "no-solver",
        SolveResult::Error(_) => "error",
    }
}

fn nanos(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

fn count(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

/// A source-recheckable certificate attached to an infeasible Glaurung path.
#[derive(Debug)]
pub struct InfeasiblePathCertificate {
    proof: UnsatProof,
}

impl InfeasiblePathCertificate {
    /// Standard DIMACS text consumed by the DRAT certificate.
    #[must_use]
    pub fn dimacs(&self) -> &str {
        &self.proof.dimacs
    }

    /// Standard textual DRAT refutation.
    #[must_use]
    pub fn drat(&self) -> &str {
        &self.proof.drat
    }

    /// Optional textual LRAT elaboration of the same refutation.
    #[must_use]
    pub fn lrat(&self) -> Option<&str> {
        self.proof.lrat.as_deref()
    }

    /// Re-translate `asserts`, require byte-identical deterministic CNF, and
    /// independently recheck the attached DRAT/LRAT certificate.
    ///
    /// This is stronger than checking the stored bytes alone: a proof exported
    /// for one path cannot be rebound to a weakened or different Glaurung path.
    pub fn recheck_for_path(&self, pool: &ExprPool, asserts: &[Assert]) -> Result<bool, String> {
        let (arena, assert_terms) = translate_path(pool, asserts)
            .map_err(|error| format!("translate path for certificate recheck: {error}"))?;
        self.proof
            .recheck_for_bool_terms(&arena, &assert_terms)
            .map_err(|error| format!("recheck infeasible-path certificate: {error}"))
    }
}

/// Proof-carrying feasibility verdict for one exact Glaurung path conjunction.
#[derive(Debug)]
pub enum InfeasiblePathVerdict {
    /// The path is unsatisfiable and owns a source-bound checked certificate.
    Infeasible(InfeasiblePathCertificate),
    /// The path is satisfiable, so no infeasibility certificate exists.
    Feasible,
    /// The proof core exhausted its budget without deciding.
    Inconclusive,
    /// Translation, export, or source-bound recheck failed.
    Error(String),
}

impl AxeyumSolver {
    /// Decide one exact path conjunction and attach a source-bound DRAT-checked
    /// certificate only when it is infeasible.
    ///
    /// This stays off the generic [`Solver`] trait (ADR-006), so ordinary
    /// exploration and backends without proof production are unaffected.
    /// The DRAT certifies the CNF layer; term-to-AIG-to-CNF remains the explicit
    /// trusted reduction described by Axeyum's proof contract.
    pub fn prove_infeasible_path(
        &self,
        pool: &ExprPool,
        asserts: &[Assert],
    ) -> InfeasiblePathVerdict {
        self.prove_infeasible_path_before(pool, asserts, Some(Instant::now() + check_timeout()))
    }

    fn prove_infeasible_path_before(
        &self,
        pool: &ExprPool,
        asserts: &[Assert],
        deadline: Option<Instant>,
    ) -> InfeasiblePathVerdict {
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return InfeasiblePathVerdict::Inconclusive;
        }
        let (arena, assert_terms) = match translate_path(pool, asserts) {
            Ok(translated) => translated,
            Err(error) => return InfeasiblePathVerdict::Error(format!("translate: {error}")),
        };
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return InfeasiblePathVerdict::Inconclusive;
        }
        match export_qf_bv_unsat_proof_within(&arena, &assert_terms, deadline) {
            Ok(UnsatProofOutcome::Proved(proof)) => {
                match proof.recheck_for_bool_terms(&arena, &assert_terms) {
                    Ok(true) => {
                        InfeasiblePathVerdict::Infeasible(InfeasiblePathCertificate { proof })
                    }
                    Ok(false) => InfeasiblePathVerdict::Error(
                        "proof did not rebind to the translated Glaurung path".to_string(),
                    ),
                    Err(error) => InfeasiblePathVerdict::Error(format!(
                        "source-bound proof recheck failed: {error}"
                    )),
                }
            }
            Ok(UnsatProofOutcome::Satisfiable) => InfeasiblePathVerdict::Feasible,
            Ok(UnsatProofOutcome::Inconclusive) => InfeasiblePathVerdict::Inconclusive,
            Err(error) => InfeasiblePathVerdict::Error(error.to_string()),
        }
    }
}

// ---------------------------------------------------------------------------
// P1: SMT-LIB2 text-bridge backend (reference / fallback)
// ---------------------------------------------------------------------------

/// The in-process SMT-LIB2 text-bridge backend (P1).
#[cfg(feature = "solver-axeyum-text")]
#[derive(Debug, Default, Clone, Copy)]
pub struct AxeyumTextSolver;

#[cfg(feature = "solver-axeyum-text")]
impl AxeyumTextSolver {
    pub fn new() -> Self {
        Self
    }
}

#[cfg(feature = "solver-axeyum-text")]
impl Solver for AxeyumTextSolver {
    fn check(&mut self, pool: &ExprPool, asserts: &[Assert]) -> SolveResult {
        let (script, names) = pipe::build_script(pool, asserts);
        let cfg = config();
        match solve_smtlib(&script, &cfg) {
            Ok(outcome) => match outcome.result {
                CheckResult::Sat(_) => SolveResult::Sat(extract_model(&script, &names, &cfg)),
                CheckResult::Unsat => SolveResult::Unsat,
                CheckResult::Unknown(reason) => SolveResult::Unknown(match reason.kind {
                    UnknownKind::ResourceLimit
                    | UnknownKind::NodeBudget
                    | UnknownKind::MemoryLimit
                    | UnknownKind::EncodingBudget => SolveUnknownReason::ResourceLimit,
                    UnknownKind::Timeout => SolveUnknownReason::WallTimeout,
                    _ => SolveUnknownReason::Other,
                }),
            },
            Err(e) => SolveResult::Error(e.to_string()),
        }
    }
}

/// Recover the assignment via `get-value` (a second solve on a Sat -- a text
/// bridge inefficiency; the native backend avoids it).
#[cfg(feature = "solver-axeyum-text")]
fn extract_model(script: &str, names: &[(u32, String)], cfg: &SolverConfig) -> Model {
    let mut values = BTreeMap::new();
    if names.is_empty() {
        return Model { values };
    }
    if let Ok(Some(vals)) = solve_smtlib_get_value(script, cfg) {
        for ((id, _name), v) in names.iter().zip(vals.iter()) {
            if let Value::Bv { value, .. } = v {
                values.insert(*id, *value);
            }
        }
    }
    Model { values }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::types::Width;

    #[test]
    fn config_forwards_the_axeyum_progress_check_budget() {
        let config = config_with_work_budgets(SolverWorkBudgets {
            axeyum_progress_checks: Some(17),
            ..SolverWorkBudgets::default()
        });

        assert_eq!(config.resource_limit, Some(17));
    }

    // ---- helpers ----------------------------------------------------------

    /// Solve `asserts` with the native backend.
    pub(super) fn solve_native(pool: &ExprPool, asserts: &[Assert]) -> SolveResult {
        AxeyumSolver::new().check(pool, asserts)
    }

    pub(super) fn c(p: &mut ExprPool, value: u128, w: Width) -> ExprId {
        p.intern(Expr::Const { value, width: w })
    }
    pub(super) fn bin(p: &mut ExprPool, op: BinOp, a: ExprId, b: ExprId, w: Width) -> ExprId {
        p.intern(Expr::Bin { op, a, b, width: w })
    }
    pub(super) fn cmp(p: &mut ExprPool, op: CmpOp, a: ExprId, b: ExprId, w: Width) -> ExprId {
        p.intern(Expr::Cmp { op, a, b, width: w })
    }

    pub(super) fn direct_input<'a>(
        complete_asserts: &'a [Assert],
        persistent: &'a [Assert],
        persistent_prefix: &'a WarmAssertionPrefix,
        retain_assertions: usize,
        temporary: &'a [Assert],
    ) -> DirectCheckInput<'a> {
        DirectCheckInput {
            complete_asserts,
            persistent,
            persistent_prefix,
            retain_assertions,
            temporary,
        }
    }

    /// Assert `pred` (a BV1) is true; expect Sat if the predicate genuinely
    /// holds, Unsat if it does not. Takes `&ExprPool` so callers can build
    /// `pred` with `&mut p` first, then check.
    pub(super) fn expect_pred(p: &ExprPool, pred: ExprId, want_true: bool) {
        match solve_native(p, &[(pred, true)]) {
            SolveResult::Sat(_) if want_true => {}
            SolveResult::Unsat if !want_true => {}
            other => panic!("pred want_true={want_true}, got {other:?}"),
        }
    }

    // ---- leaf / sat-with-model -------------------------------------------

    #[test]
    fn native_add_eq_model() {
        // x + 1 == 0x100 (32-bit) => x = 0xff
        let mut p = ExprPool::new();
        let x = p.fresh_symbol(Width::W32);
        let one = c(&mut p, 1, Width::W32);
        let sum = bin(&mut p, BinOp::Add, x, one, Width::W32);
        let k = c(&mut p, 0x100, Width::W32);
        let eq = cmp(&mut p, CmpOp::Eq, sum, k, Width::W32);
        match solve_native(&p, &[(eq, true)]) {
            SolveResult::Sat(m) => assert_eq!(m.values.get(&0).copied(), Some(0xff)),
            other => panic!("expected sat x=0xff, got {other:?}"),
        }
    }

    #[test]
    fn native_wide_assertion_uses_truthiness() {
        let mut pool = ExprPool::new();
        let wide = pool.fresh_symbol(Width::W64);
        let zero = c(&mut pool, 0, Width::W64);
        let is_zero = cmp(&mut pool, CmpOp::Eq, wide, zero, Width::W64);

        assert!(matches!(
            solve_native(&pool, &[(wide, true), (is_zero, true)]),
            SolveResult::Unsat
        ));
        assert!(matches!(
            solve_native(&pool, &[(wide, false), (is_zero, true)]),
            SolveResult::Sat(_)
        ));

        #[cfg(feature = "solver-z3")]
        {
            use crate::symbolic::solver::z3_backend::Z3Solver;

            assert_eq!(
                Z3Solver::new().check(&pool, &[(wide, true), (is_zero, true)]),
                SolveResult::Unsat
            );
            assert!(matches!(
                Z3Solver::new().check(&pool, &[(wide, false), (is_zero, true)]),
                SolveResult::Sat(_)
            ));
        }
    }

    #[test]
    #[cfg(feature = "solver-axeyum-text")]
    fn text_bridge_accepts_shared_let_script() {
        let mut pool = ExprPool::new();
        let x = pool.fresh_symbol(Width::W64);
        let one = c(&mut pool, 1, Width::W64);
        let mut shared = bin(&mut pool, BinOp::Add, x, one, Width::W64);
        for _ in 0..24 {
            shared = bin(&mut pool, BinOp::Xor, shared, shared, Width::W64);
        }

        assert_eq!(
            AxeyumTextSolver::new().check(&pool, &[(shared, true)]),
            SolveResult::Unsat
        );
    }

    #[test]
    fn profiled_native_check_is_capture_keyed_and_phase_complete() {
        use sha2::{Digest, Sha256};

        let mut p = ExprPool::new();
        let x = p.fresh_symbol(Width::W32);
        let one = c(&mut p, 1, Width::W32);
        let sum = bin(&mut p, BinOp::Add, x, one, Width::W32);
        let k = c(&mut p, 0x100, Width::W32);
        let eq = cmp(&mut p, CmpOp::Eq, sum, k, Width::W32);
        let asserts = [(eq, true)];

        let (script, _) = pipe::build_script(&p, &asserts);
        let expected_hash = format!("sha256:{:x}", Sha256::digest(script.as_bytes()));
        let profiled = AxeyumSolver::new().check_profiled(&p, &asserts);

        assert!(
            matches!(&profiled.result, SolveResult::Sat(model) if model.values.get(&0) == Some(&0xff))
        );
        assert_eq!(profiled.profile.schema, "glaurung-axeyum-native-profile-v1");
        assert_eq!(profiled.profile.process_id, std::process::id());
        assert_eq!(profiled.profile.sequence, None);
        assert_eq!(profiled.profile.query_hash, expected_hash);
        assert_eq!(profiled.profile.word_policy, "raw");
        assert_eq!(profiled.profile.timeout_ms, 250);
        assert_eq!(profiled.profile.outcome, "sat");
        assert_eq!(profiled.profile.assertion_count, 1);
        assert!(profiled.profile.translated_exprs > 0);
        assert!(profiled.profile.arena_terms >= profiled.profile.translated_exprs);
        assert_eq!(profiled.profile.symbols, 1);
        assert_eq!(profiled.profile.root_encodings, 1);
        assert_eq!(profiled.profile.checks, 1);
        assert!(profiled.profile.aig_nodes > 0);
        assert!(profiled.profile.cnf_variables > 0);
        assert!(profiled.profile.cnf_clauses > 0);
        assert_eq!(profiled.profile.model_values, 1);
        assert!(profiled.profile.attributed_nanos() <= profiled.profile.total_nanos);
        assert_eq!(
            profiled.profile.unattributed_nanos(),
            profiled
                .profile
                .total_nanos
                .saturating_sub(profiled.profile.attributed_nanos())
        );
        assert!(serde_json::to_value(&profiled.profile).is_ok());
    }

    #[test]
    fn snapshot_incremental_reuses_exact_and_prefix_then_switches_sibling() {
        for preprocess in [false, true] {
            let mut root = ExprPool::new();
            let x = root.fresh_symbol(Width::W32);
            let six = c(&mut root, 6, Width::W32);
            let below_six = cmp(&mut root, CmpOp::Ult, x, six, Width::W32);

            // Cloning at the fork deliberately gives both siblings the same
            // numeric ExprIds for different new nodes. Warm reuse must compare
            // translated structure, never raw ExprId identity across pools.
            let mut left = root.clone();
            let five = c(&mut left, 5, Width::W32);
            let x_is_five = cmp(&mut left, CmpOp::Eq, x, five, Width::W32);
            let mut right = root.clone();
            let seven = c(&mut right, 7, Width::W32);
            let x_is_seven = cmp(&mut right, CmpOp::Eq, x, seven, Width::W32);
            assert_eq!(five, seven);
            assert_eq!(x_is_five, x_is_seven);

            let mut solver = SnapshotIncrementalAxeyumSolver::with_preprocessing(preprocess);
            let left_snapshot = [(below_six, true), (x_is_five, true)];
            match solver.check_snapshot(&left, &left_snapshot) {
                SolveResult::Sat(model) => {
                    assert_eq!(model.values.get(&0).copied(), Some(5));
                }
                other => panic!("expected left sibling sat, got {other:?}"),
            }
            assert!(matches!(
                solver.check_snapshot(&left, &left_snapshot),
                SolveResult::Sat(_)
            ));

            let right_snapshot = [(below_six, true), (x_is_seven, true)];
            assert!(matches!(
                solver.check_snapshot(&right, &right_snapshot),
                SolveResult::Unsat
            ));

            assert_eq!(
                solver.stats(),
                SnapshotReuseStats {
                    checks: 3,
                    exact_snapshot_reuses: 1,
                    prefix_assertions_reused: 3,
                    assertions_added: 3,
                    assertions_popped: 1,
                    resets_after_error: 0,
                }
            );
        }
    }

    #[test]
    fn snapshot_incremental_handles_empty_and_shrinking_snapshots() {
        let mut pool = ExprPool::new();
        let x = pool.fresh_symbol(Width::W8);
        let one = c(&mut pool, 1, Width::W8);
        let x_is_one = cmp(&mut pool, CmpOp::Eq, x, one, Width::W8);
        let mut solver = SnapshotIncrementalAxeyumSolver::new();

        assert!(matches!(
            solver.check_snapshot(&pool, &[(x_is_one, true)]),
            SolveResult::Sat(_)
        ));
        assert!(matches!(
            solver.check_snapshot(&pool, &[]),
            SolveResult::Sat(_)
        ));
        assert!(matches!(
            solver.check_snapshot(&pool, &[]),
            SolveResult::Sat(_)
        ));
        assert_eq!(solver.stats().assertions_popped, 1);
        assert_eq!(solver.stats().exact_snapshot_reuses, 1);
    }

    #[test]
    fn direct_incremental_trait_handles_scopes_and_ephemeral_assumptions() {
        let mut root = ExprPool::new();
        let x = root.fresh_symbol(Width::W32);
        let six = c(&mut root, 6, Width::W32);
        let below_six = cmp(&mut root, CmpOp::Ult, x, six, Width::W32);

        let mut left = root.clone();
        let five = c(&mut left, 5, Width::W32);
        let x_is_five = cmp(&mut left, CmpOp::Eq, x, five, Width::W32);
        let mut right = root.clone();
        let seven = c(&mut right, 7, Width::W32);
        let x_is_seven = cmp(&mut right, CmpOp::Eq, x, seven, Width::W32);

        let mut concrete = IncrementalAxeyumSolver::new();
        let solver: &mut dyn IncrementalSolver = &mut concrete;
        solver.assert(&root, (below_six, true)).unwrap();
        assert!(matches!(solver.check(), SolveResult::Sat(_)));

        solver.push().unwrap();
        solver.assert(&left, (x_is_five, true)).unwrap();
        match solver.check() {
            SolveResult::Sat(model) => assert_eq!(model.values.get(&0), Some(&5)),
            other => panic!("expected direct-delta left SAT, got {other:?}"),
        }
        assert_eq!(solver.scope_depth(), 1);
        assert!(solver.pop());
        assert_eq!(solver.scope_depth(), 0);
        assert!(!solver.pop());

        assert_eq!(
            solver.check_assuming(&right, &[(x_is_seven, true)]),
            SolveResult::Unsat
        );
        assert!(
            matches!(solver.check(), SolveResult::Sat(_)),
            "the contradictory one-shot assumption must not persist"
        );
    }

    #[test]
    fn warm_resource_limits_fail_closed_and_reserve_atomically() {
        assert_eq!(parse_warm_limit(None, 9), 9);
        assert_eq!(parse_warm_limit(Some("17".to_owned()), 9), 17);
        assert_eq!(parse_warm_limit(Some("invalid".to_owned()), 9), 0);

        let live = AtomicU64::new(0);
        let peak = AtomicU64::new(0);
        assert!(try_reserve_path_counter(&live, &peak, 1));
        assert!(!try_reserve_path_counter(&live, &peak, 1));
        assert_eq!(live.load(Ordering::Relaxed), 1);
        assert_eq!(peak.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn adaptive_lineage_expands_only_after_sustained_pressure() {
        assert_eq!(adaptive_live_path_limit(9, 0), 2);
        assert_eq!(adaptive_live_path_limit(9, 127), 2);
        assert_eq!(adaptive_live_path_limit(9, 128), 9);
        assert_eq!(adaptive_live_path_limit(1, 0), 1);
        assert_eq!(adaptive_live_path_limit(0, 128), 0);
    }

    #[test]
    fn adaptive_is_default_with_explicit_one_shot_override() {
        assert_eq!(parse_warm_reuse_policy(None), WarmReusePolicy::Adaptive);
        assert_eq!(
            parse_warm_reuse_policy(Some("adaptive")),
            WarmReusePolicy::Adaptive
        );
        for value in ["off", "false", "0"] {
            assert_eq!(parse_warm_reuse_policy(Some(value)), WarmReusePolicy::Off);
        }
        assert_eq!(
            parse_warm_reuse_policy(Some("lineage")),
            WarmReusePolicy::Lineage
        );
        assert_eq!(parse_warm_reuse_policy(Some("auto")), WarmReusePolicy::Auto);
        assert_eq!(
            parse_warm_reuse_policy(Some("snapshot")),
            WarmReusePolicy::Snapshot
        );
    }

    #[test]
    fn direct_delta_is_strictly_opt_in() {
        for value in [None, Some("off"), Some("false"), Some("0"), Some("invalid")] {
            assert!(!parse_direct_delta(value));
        }
        for value in [Some("on"), Some("true"), Some("TRUE"), Some("1")] {
            assert!(parse_direct_delta(value));
        }
    }

    #[test]
    fn warm_timeout_cold_retry_is_strictly_opt_in() {
        for value in [None, Some("off"), Some("false"), Some("0"), Some("invalid")] {
            assert!(!parse_warm_timeout_cold_retry(value));
        }
        for value in [Some("on"), Some("true"), Some("TRUE"), Some("1")] {
            assert!(parse_warm_timeout_cold_retry(value));
        }
    }

    #[test]
    fn warm_timeout_continue_is_default_on_with_fail_closed_override() {
        assert!(parse_warm_timeout_continue(None));
        for value in [Some("off"), Some("false"), Some("0"), Some("invalid")] {
            assert!(!parse_warm_timeout_continue(value));
        }
        for value in [Some("on"), Some("true"), Some("TRUE"), Some("1")] {
            assert!(parse_warm_timeout_continue(value));
        }
    }

    #[test]
    fn warm_owner_transfer_is_default_on_with_fail_closed_override() {
        assert!(parse_warm_owner_transfer(None));
        assert!(!parse_warm_owner_transfer(Some("off")));
        assert!(!parse_warm_owner_transfer(Some("false")));
        assert!(!parse_warm_owner_transfer(Some("0")));
        assert!(!parse_warm_owner_transfer(Some("unexpected")));
        assert!(parse_warm_owner_transfer(Some("1")));
        assert!(parse_warm_owner_transfer(Some("on")));
        assert!(parse_warm_owner_transfer(Some("TRUE")));
    }

    #[test]
    fn serial_sibling_reuse_is_default_on_and_fail_closed() {
        assert!(parse_warm_serial_sibling_reuse(None));
        for value in ["off", "false", "0", "unexpected"] {
            assert!(!parse_warm_serial_sibling_reuse(Some(value)));
        }
        for value in ["on", "true", "1", "TRUE"] {
            assert!(parse_warm_serial_sibling_reuse(Some(value)));
        }
    }

    #[test]
    fn replay_sat_cache_is_bounded_default_on_with_explicit_off() {
        let expected = Some(ReplayCheckedSatCachePolicy::new(
            DEFAULT_REPLAY_SAT_CACHE_ENTRIES,
            DEFAULT_REPLAY_SAT_CACHE_MODEL_VALUES,
            DEFAULT_REPLAY_SAT_CACHE_MODEL_BITS,
        ));
        assert_eq!(parse_replay_sat_cache_policy(None), expected);
        for value in ["off", "false", "0", "invalid"] {
            assert_eq!(parse_replay_sat_cache_policy(Some(value)), None);
        }
        for value in ["on", "true", "1"] {
            assert_eq!(parse_replay_sat_cache_policy(Some(value)), expected);
        }
    }

    #[test]
    fn warm_profile_exports_complete_cnf_gate_mix() {
        let mut stats = IncrementalCnfStats::default();
        stats.and_nodes_synced = 3;
        stats.and_tree_half_definitions = 2;
        stats.root_clauses = 1;

        let mix = cnf_gate_mix(stats);

        assert_eq!(mix.len(), 42);
        assert_eq!(mix["and_nodes_synced"], 3);
        assert_eq!(mix["and_tree_half_definitions"], 2);
        assert_eq!(mix["root_clauses"], 1);
        assert_eq!(mix["internal_positive_and_opportunities"], 0);
        assert_eq!(mix["internal_positive_and_immediate_clauses_avoided"], 0);
        assert_eq!(mix["tautological_root_clauses"], 0);
    }

    #[test]
    fn retained_cnf_snapshot_writer_binds_dimacs_and_metadata() {
        let output = tempfile::tempdir().unwrap();
        let snapshot = RetainedCnfSnapshot {
            variable_count: 1,
            clause_count: 2,
            dimacs: "p cnf 1 2\n1 0\n-1 0\n".to_string(),
        };
        write_retained_cnf_snapshot(
            output.path(),
            &format!("sha256:{}", "a".repeat(64)),
            17,
            "unsat",
            &snapshot,
        )
        .unwrap();

        let mut paths = std::fs::read_dir(output.path())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect::<Vec<_>>();
        paths.sort();
        assert_eq!(paths.len(), 2);
        let cnf = paths
            .iter()
            .find(|path| path.extension().is_some_and(|extension| extension == "cnf"))
            .unwrap();
        let metadata = paths
            .iter()
            .find(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "json")
            })
            .unwrap();
        assert_eq!(std::fs::read_to_string(cnf).unwrap(), snapshot.dimacs);
        let metadata: serde_json::Value =
            serde_json::from_slice(&std::fs::read(metadata).unwrap()).unwrap();
        assert_eq!(metadata["path_id"], 17);
        assert_eq!(metadata["variable_count"], 1);
        assert_eq!(metadata["clause_count"], 2);
        assert_eq!(metadata["learned_clauses_included"], false);
        assert_eq!(metadata["active_assumptions_materialized_as_units"], true);
        assert_eq!(
            metadata["dimacs_sha256"],
            hex::encode(Sha256::digest(snapshot.dimacs.as_bytes()))
        );
    }

    #[test]
    fn warm_profile_exports_complete_aig_and_lowering_work() {
        let aig = aig_construction(AigConstructionStats {
            and_requests: 5,
            and_trivial_simplifications: 1,
            and_absorption_simplifications: 1,
            and_structural_hash_hits: 1,
            and_nodes_created: 2,
        });
        assert_eq!(aig.len(), 5);
        assert_eq!(aig["and_requests"], 5);
        assert_eq!(aig["and_nodes_created"], 2);

        let work = lowering_work(IncrementalLoweringStats {
            lower_calls: 1,
            term_memo_lookups: 9,
            term_memo_hits: 2,
            terms_lowered: 4,
            operand_vectors_copied: 6,
            operand_bits_copied: 64,
            root_bits_copied: 1,
            term_bit_bindings_written: 33,
            memoized_terms: 4,
            term_bit_bindings: 33,
            symbol_bit_inputs: 8,
        });
        assert_eq!(work.len(), 11);
        assert_eq!(work["operand_bits_copied"], 64);
        assert_eq!(work["term_bit_bindings"], 33);
    }

    #[test]
    fn warm_profile_exports_complete_model_lift_work() {
        let mut stats = IncrementalModelLiftStats::default();
        stats.aig_recompute = Duration::from_nanos(11);
        stats.assignment_reconstruct = Duration::from_nanos(13);
        stats.model_completion = Duration::from_nanos(17);
        stats.aig_nodes_recomputed = 19;
        stats.symbol_bit_inputs_scanned = 23;
        stats.assignment_symbols_produced = 2;
        stats.arena_symbols_scanned = 3;
        stats.completed_model_values = 2;
        let work = model_lift_work(stats);

        assert_eq!(work.len(), 8);
        assert_eq!(work["aig_recompute_nanos"], 11);
        assert_eq!(work["assignment_reconstruct_nanos"], 13);
        assert_eq!(work["model_completion_nanos"], 17);
        assert_eq!(work["aig_nodes_recomputed"], 19);
        assert_eq!(work["symbol_bit_inputs_scanned"], 23);
        assert_eq!(work["assignment_symbols_produced"], 2);
        assert_eq!(work["arena_symbols_scanned"], 3);
        assert_eq!(work["completed_model_values"], 2);
    }

    #[test]
    fn warm_profile_exports_exact_replay_sat_cache_delta() {
        let policy = Some(ReplayCheckedSatCachePolicy::new(64, 4_096, 262_144));
        let mut before = ReplayCheckedSatCacheStats::default();
        before.misses = 4;
        before.insertions = 3;
        before.entries = 3;
        before.model_values = 12;
        before.model_bits = 96;
        let mut after = before;
        after.hits = 1;

        let cache = replay_sat_cache_profile(policy, before, after);

        assert_eq!(cache.len(), 16);
        assert_eq!(cache["enabled"], 1);
        assert_eq!(cache["max_entries"], 64);
        assert_eq!(cache["max_model_values"], 4_096);
        assert_eq!(cache["max_model_bits"], 262_144);
        assert_eq!(cache["hits"], 1);
        assert_eq!(cache["misses"], 0);
        assert_eq!(cache["insertions"], 0);
        assert_eq!(cache["entries"], 3);
        assert_eq!(cache["model_values"], 12);
        assert_eq!(cache["model_bits"], 96);
    }

    #[test]
    fn profile_writer_uses_process_isolated_jsonl() {
        let mut p = ExprPool::new();
        let x = p.fresh_symbol(Width::W8);
        let seven = c(&mut p, 7, Width::W8);
        let eq = cmp(&mut p, CmpOp::Eq, x, seven, Width::W8);
        let profiled = AxeyumSolver::new().check_profiled(&p, &[(eq, true)]);
        let output = tempfile::tempdir().unwrap();

        write_profile_record(output.path(), &profiled.profile).unwrap();
        write_profile_record(
            output.path(),
            &serde_json::json!({
                "schema": "glaurung-axeyum-warm-profile-v1",
                "process_id": std::process::id(),
                "sequence": null,
            }),
        )
        .unwrap();
        let path = output
            .path()
            .join(format!("axeyum-profile-{}.jsonl", std::process::id()));
        let contents = std::fs::read_to_string(path).unwrap();
        let records = contents.lines().collect::<Vec<_>>();

        assert_eq!(records.len(), 2);
        let record: serde_json::Value = serde_json::from_str(records[0]).unwrap();
        assert_eq!(record["query_hash"], profiled.profile.query_hash);
        assert_eq!(record["word_policy"], "raw");
        assert_eq!(record["outcome"], "sat");
        assert_eq!(record["complete"], true);
        assert_eq!(record["process_id"], std::process::id());
        assert!(record["sequence"].as_u64().is_some());
        let warm: serde_json::Value = serde_json::from_str(records[1]).unwrap();
        assert_eq!(warm["schema"], "glaurung-axeyum-warm-profile-v1");
        assert!(warm["sequence"].as_u64().unwrap() > record["sequence"].as_u64().unwrap());
    }

    #[test]
    fn native_detects_unsat() {
        let mut p = ExprPool::new();
        let x = p.fresh_symbol(Width::W32);
        let one = c(&mut p, 1, Width::W32);
        let sum = bin(&mut p, BinOp::Add, x, one, Width::W32);
        let k = c(&mut p, 0x100, Width::W32);
        let eq = cmp(&mut p, CmpOp::Eq, sum, k, Width::W32);
        let zero = c(&mut p, 0, Width::W32);
        let xz = cmp(&mut p, CmpOp::Eq, x, zero, Width::W32);
        assert!(matches!(
            solve_native(&p, &[(eq, true), (xz, true)]),
            SolveResult::Unsat
        ));
    }

    // ---- per-operator known-answer (the tricky ones) ---------------------

    #[test]
    fn native_arith_and_bitwise_constants() {
        let mut p = ExprPool::new();
        let w = Width::W8;
        let a = c(&mut p, 0x0A, w);
        let b = c(&mut p, 0x05, w);
        let sum = bin(&mut p, BinOp::Add, a, b, w);
        let k = c(&mut p, 0x0F, w);
        let pred1 = cmp(&mut p, CmpOp::Eq, sum, k, w);
        expect_pred(&p, pred1, true); // 0x0A + 0x05 == 0x0F

        let f = c(&mut p, 0x0F, w);
        let n = c(&mut p, 0x09, w);
        let and = bin(&mut p, BinOp::And, f, n, w);
        let pred2 = cmp(&mut p, CmpOp::Eq, and, n, w);
        expect_pred(&p, pred2, true); // 0x0F & 0x09 == 0x09
    }

    /// `BinOp::LogicalAnd` / `LogicalOr` are source-level short-circuit
    /// operators, not bitvector ALU ops. They reach a solver backend through
    /// `native_trace::parse_bin_op` (which accepts `"logical_and"` /
    /// `"logical_or"`) when `ordered_replay` imports a native assertion pack,
    /// and nothing between the pool and the backend desugars them.
    ///
    /// This pins the lowering against the SMT-LIB text bridge in
    /// `ExprPool::render_smtlib`, which is the definition `ordered_replay`
    /// enforces: it re-renders every imported pack through the text bridge and
    /// rejects the pack unless the rendering hashes to the recorded constraint.
    /// The concrete pairs are chosen so a naive `bvand` / `bvor` lowering --
    /// the obvious wrong answer -- gives a different verdict on every row.
    #[test]
    fn native_source_logical_ops_match_the_text_bridge_truthiness() {
        let w = Width::W32;
        // (lhs, rhs, expected `&&`, expected `||`, wrong `bvand`, wrong `bvor`)
        let table: &[(u128, u128, u128, u128, u128, u128)] = &[
            (1, 2, 1, 1, 0, 3),
            (0, 5, 0, 1, 0, 5),
            (0, 0, 0, 0, 0, 0),
            (6, 6, 1, 1, 6, 6),
            (0xFFFF_FFFF, 1, 1, 1, 1, 0xFFFF_FFFF),
        ];

        for &(lhs, rhs, want_and, want_or, bitwise_and, bitwise_or) in table {
            for (op, want, bitwise) in [
                (BinOp::LogicalAnd, want_and, bitwise_and),
                (BinOp::LogicalOr, want_or, bitwise_or),
            ] {
                let mut p = ExprPool::new();
                let a = c(&mut p, lhs, w);
                let b = c(&mut p, rhs, w);
                let node = bin(&mut p, op, a, b, w);

                let k = c(&mut p, want, w);
                let holds = cmp(&mut p, CmpOp::Eq, node, k, w);
                expect_pred(&p, holds, true);

                // The discriminator: where the truthiness result differs from
                // the bitwise one, the backend must NOT answer bitwise.
                if bitwise != want {
                    let wrong = c(&mut p, bitwise, w);
                    let bitwise_holds = cmp(&mut p, CmpOp::Eq, node, wrong, w);
                    expect_pred(&p, bitwise_holds, false);
                }
            }
        }

        // The native lowering and the text bridge must denote the same term.
        // If either side is edited alone, this literal fails.
        let mut p = ExprPool::new();
        let a = c(&mut p, 1, w);
        let b = c(&mut p, 2, w);
        let conjunction = bin(&mut p, BinOp::LogicalAnd, a, b, w);
        assert_eq!(
            p.render_smtlib(conjunction),
            concat!(
                "(ite (and (distinct (_ bv1 32) (_ bv0 32)) ",
                "(distinct (_ bv2 32) (_ bv0 32))) (_ bv1 32) (_ bv0 32))"
            ),
        );
    }

    /// The native lowering of every shift and division must denote what
    /// `crate::exec::Concrete` computes.
    ///
    /// Shares the case table with
    /// `crate::symbolic::expr::smt_concrete_agreement`, which runs the same
    /// differential against the SMT-LIB text bridge and against z3: shift
    /// distances below, at and above the operand width, at widths including one
    /// that is not a power of two, plus division by zero. Bare
    /// `bv_shl`/`bv_udiv` fail dozens of these rows.
    #[test]
    fn native_shifts_and_division_agree_with_the_concrete_domain() {
        use crate::exec::domain::Domain;
        use crate::exec::Concrete;
        use crate::symbolic::expr::smt_concrete_agreement::cases;

        let all = cases();
        assert!(all.len() > 100, "the shared case table went missing");
        for (op, a, b, width) in all {
            let expected = Concrete.binop(op, &a, &b, width);
            let mut p = ExprPool::new();
            let left = c(&mut p, a, width);
            let right = c(&mut p, b, width);
            let node = bin(&mut p, op, left, right, width);
            let want = c(&mut p, expected, width);
            let holds = cmp(&mut p, CmpOp::Eq, node, want, width);
            // `expect_pred(.., false)` demands unsat: the lowered term cannot
            // be anything but the concrete answer.
            let differs = cmp(&mut p, CmpOp::Ne, node, want, width);
            expect_pred(&p, holds, true);
            expect_pred(&p, differs, false);
        }
    }

    /// Both operands must survive the lowering. A backend that dropped one --
    /// or replaced the pair with a single truthiness test -- would still pass
    /// the constant table above on some rows, but cannot satisfy this.
    #[test]
    fn native_source_logical_and_constrains_both_operands() {
        let w = Width::W32;
        let mut p = ExprPool::new();
        let x = p.fresh_symbol(w);
        let y = p.fresh_symbol(w);
        let conjunction = bin(&mut p, BinOp::LogicalAnd, x, y, w);
        let zero = c(&mut p, 0, w);
        let x_is_zero = cmp(&mut p, CmpOp::Eq, x, zero, w);

        // `x && y` true is satisfiable on its own ...
        match solve_native(&p, &[(conjunction, true)]) {
            SolveResult::Sat(model) => {
                for symbol in [0_u32, 1] {
                    assert_ne!(
                        model.values.get(&symbol).copied().unwrap_or(0),
                        0,
                        "`x && y` held with symbol {symbol} equal to zero",
                    );
                }
            }
            other => panic!("`x && y` should be satisfiable, got {other:?}"),
        }

        // ... but not together with `x == 0`.
        assert!(
            matches!(
                solve_native(&p, &[(conjunction, true), (x_is_zero, true)]),
                SolveResult::Unsat
            ),
            "`x && y` must be false whenever x is zero",
        );
    }

    /// Truncation can turn a non-zero operand into zero, so the `!= 0` test
    /// has to run on the operand AFTER it is coerced to the node width -- the
    /// order `ExprPool::render_smtlib` uses. A backend that tested truthiness
    /// before coercing would answer `1` here instead of `0`.
    #[test]
    fn native_source_logical_and_tests_truthiness_after_width_coercion() {
        let mut p = ExprPool::new();
        // 0x100 is non-zero at 32 bits but truncates to zero at 8.
        let wide = c(&mut p, 0x100, Width::W32);
        let one = c(&mut p, 1, Width::W8);
        let node = bin(&mut p, BinOp::LogicalAnd, wide, one, Width::W8);
        let zero = c(&mut p, 0, Width::W8);
        let is_zero = cmp(&mut p, CmpOp::Eq, node, zero, Width::W8);
        expect_pred(&p, is_zero, true);
    }

    #[test]
    fn native_udiv() {
        // 0xFF / 0x10 == 0x0F (unsigned)
        let mut p = ExprPool::new();
        let w = Width::W8;
        let a = c(&mut p, 0xFF, w);
        let b = c(&mut p, 0x10, w);
        let d = bin(&mut p, BinOp::Div, a, b, w);
        let k = c(&mut p, 0x0F, w);
        let pred = cmp(&mut p, CmpOp::Eq, d, k, w);
        expect_pred(&p, pred, true);
    }

    #[test]
    fn native_logical_vs_arith_shift() {
        // 0x80 >>logical 1 == 0x40 ; 0x80 >>arith 1 == 0xC0 (sign fill)
        let mut p = ExprPool::new();
        let w = Width::W8;
        let v = c(&mut p, 0x80, w);
        let one = c(&mut p, 1, w);
        let lsh = bin(&mut p, BinOp::Shr, v, one, w);
        let k40 = c(&mut p, 0x40, w);
        let pred_l = cmp(&mut p, CmpOp::Eq, lsh, k40, w);
        expect_pred(&p, pred_l, true);
        let ash = bin(&mut p, BinOp::Sar, v, one, w);
        let kc0 = c(&mut p, 0xC0, w);
        let pred_a = cmp(&mut p, CmpOp::Eq, ash, kc0, w);
        expect_pred(&p, pred_a, true);
    }

    #[test]
    fn native_signed_vs_unsigned_compare() {
        // 0xFF (=-1 signed, =255 unsigned) vs 0x01:
        //   0xFF <s 0x01  is TRUE  (-1 < 1)
        //   0xFF <u 0x01  is FALSE (255 < 1 is false)
        let mut p = ExprPool::new();
        let w = Width::W8;
        let ff = c(&mut p, 0xFF, w);
        let one = c(&mut p, 0x01, w);
        let slt = cmp(&mut p, CmpOp::Slt, ff, one, w);
        expect_pred(&p, slt, true);
        let ult = cmp(&mut p, CmpOp::Ult, ff, one, w);
        expect_pred(&p, ult, false);
    }

    #[test]
    fn native_concat_and_extract_order() {
        // concat(0xAB@8, 0xCD@8) == 0xABCD@16  (hi first)
        let mut p = ExprPool::new();
        let hi = c(&mut p, 0xAB, Width::W8);
        let lo = c(&mut p, 0xCD, Width::W8);
        let cat = p.intern(Expr::Concat {
            hi,
            lo,
            hi_w: Width::W8,
            lo_w: Width::W8,
        });
        let k = c(&mut p, 0xABCD, Width::W16);
        let pred_cat = cmp(&mut p, CmpOp::Eq, cat, k, Width::W16);
        expect_pred(&p, pred_cat, true);

        // extract the top byte of 0xABCD == 0xAB. glaurung's `hi` is
        // EXCLUSIVE, so bits [15:8] are hi=16, lo=8 (width = hi - lo = 8).
        let word = c(&mut p, 0xABCD, Width::W16);
        let ex = p.intern(Expr::Extract {
            a: word,
            hi: 16,
            lo: 8,
        });
        let kab = c(&mut p, 0xAB, Width::W8);
        let pred_ex = cmp(&mut p, CmpOp::Eq, ex, kab, Width::W8);
        expect_pred(&p, pred_ex, true);
    }

    #[test]
    fn native_concat_coerces_to_declared_operand_widths() {
        let mut p = ExprPool::new();
        let hi = c(&mut p, 0x12, Width(56));
        let lo = c(&mut p, 1, Width::W1);
        let cat = p.intern(Expr::Concat {
            hi,
            lo,
            hi_w: Width(56),
            lo_w: Width::W8,
        });
        let expected = c(&mut p, 0x1201, Width::W64);
        let pred = cmp(&mut p, CmpOp::Eq, cat, expected, Width::W64);
        expect_pred(&p, pred, true);
    }

    #[test]
    fn native_zext_vs_sext() {
        // 0xFF@8 zext->16 == 0x00FF ; sext->16 == 0xFFFF
        let mut p = ExprPool::new();
        let v = c(&mut p, 0xFF, Width::W8);
        let z = p.intern(Expr::ZExt {
            a: v,
            from: Width::W8,
            to: Width::W16,
        });
        let kzz = c(&mut p, 0x00FF, Width::W16);
        let pred_z = cmp(&mut p, CmpOp::Eq, z, kzz, Width::W16);
        expect_pred(&p, pred_z, true);
        let s = p.intern(Expr::SExt {
            a: v,
            from: Width::W8,
            to: Width::W16,
        });
        let kss = c(&mut p, 0xFFFF, Width::W16);
        let pred_s = cmp(&mut p, CmpOp::Eq, s, kss, Width::W16);
        expect_pred(&p, pred_s, true);
    }

    #[test]
    fn native_extension_coerces_to_declared_source_width() {
        let mut p = ExprPool::new();
        let wide = c(&mut p, 0x1_0000_0001, Width::W64);
        let z = p.intern(Expr::ZExt {
            a: wide,
            from: Width::W32,
            to: Width::W64,
        });
        let low = c(&mut p, 1, Width::W64);
        let pred = cmp(&mut p, CmpOp::Eq, z, low, Width::W64);
        expect_pred(&p, pred, true);
    }

    #[test]
    fn native_ite() {
        // ite(1==1, 0xAA, 0xBB) == 0xAA
        let mut p = ExprPool::new();
        let w = Width::W8;
        let one = c(&mut p, 1, w);
        let cond = cmp(&mut p, CmpOp::Eq, one, one, w); // BV1 = 1
        let t = c(&mut p, 0xAA, w);
        let e = c(&mut p, 0xBB, w);
        let ite = p.intern(Expr::Ite {
            c: cond,
            t,
            e,
            width: w,
        });
        let kaa = c(&mut p, 0xAA, w);
        let pred = cmp(&mut p, CmpOp::Eq, ite, kaa, w);
        expect_pred(&p, pred, true);
    }

    #[test]
    fn native_non_power_of_two_width() {
        // 12-bit: 0xFFF + 1 wraps to 0 => sat
        let mut p = ExprPool::new();
        let w = Width(12);
        let x = p.fresh_symbol(w);
        let all = c(&mut p, 0xFFF, w);
        let is_max = cmp(&mut p, CmpOp::Eq, x, all, w);
        let one = c(&mut p, 1, w);
        let inc = bin(&mut p, BinOp::Add, x, one, w);
        let zero = c(&mut p, 0, w);
        let wraps = cmp(&mut p, CmpOp::Eq, inc, zero, w);
        // x == 0xFFF AND x+1 == 0 should be sat (wrap at 12 bits)
        match solve_native(&p, &[(is_max, true), (wraps, true)]) {
            SolveResult::Sat(m) => assert_eq!(m.values.get(&0).copied(), Some(0xFFF)),
            other => panic!("expected sat x=0xFFF at 12-bit, got {other:?}"),
        }
    }

    // ---- proof-carrying unsat (G3) ---------------------------------------

    #[test]
    fn prove_infeasible_path_attaches_source_bound_drat() {
        // x == 5 AND x == 6 is one infeasible Glaurung path. The verdict must
        // retain the certificate, and the certificate must bind to this exact
        // source path rather than merely recheck its own CNF bytes.
        let mut p = ExprPool::new();
        let w = Width::W32;
        let x = p.fresh_symbol(w);
        let five = c(&mut p, 5, w);
        let six = c(&mut p, 6, w);
        let e5 = cmp(&mut p, CmpOp::Eq, x, five, w);
        let e6 = cmp(&mut p, CmpOp::Eq, x, six, w);
        let path = [(e5, true), (e6, true)];
        match AxeyumSolver::new().prove_infeasible_path(&p, &path) {
            InfeasiblePathVerdict::Infeasible(certificate) => {
                assert!(!certificate.drat().is_empty());
                assert_eq!(certificate.recheck_for_path(&p, &path), Ok(true));
                assert_eq!(
                    certificate.recheck_for_path(&p, &[(e5, true)]),
                    Ok(false),
                    "the proof must not rebind to a weakened satisfiable path"
                );
            }
            other => panic!("expected an attached infeasible-path certificate, got {other:?}"),
        }
    }

    #[test]
    fn prove_infeasible_path_reports_feasible_without_certificate() {
        // x == 5 is feasible; no infeasibility certificate may be attached.
        let mut p = ExprPool::new();
        let w = Width::W32;
        let x = p.fresh_symbol(w);
        let five = c(&mut p, 5, w);
        let e5 = cmp(&mut p, CmpOp::Eq, x, five, w);
        assert!(matches!(
            AxeyumSolver::new().prove_infeasible_path(&p, &[(e5, true)]),
            InfeasiblePathVerdict::Feasible
        ));
    }

    #[test]
    fn prove_infeasible_path_keeps_expired_search_inconclusive() {
        let mut p = ExprPool::new();
        let x = p.fresh_symbol(Width::W32);
        let five = c(&mut p, 5, Width::W32);
        let equals_five = cmp(&mut p, CmpOp::Eq, x, five, Width::W32);
        match AxeyumSolver::new().prove_infeasible_path_before(
            &p,
            &[(equals_five, true)],
            Some(Instant::now() - Duration::from_secs(1)),
        ) {
            InfeasiblePathVerdict::Inconclusive => {}
            other => panic!("expired proof search should be inconclusive, got {other:?}"),
        }
    }

    #[test]
    fn prove_infeasible_path_keeps_translation_failure_as_error() {
        let mut p = ExprPool::new();
        let invalid = p.intern(Expr::Const {
            value: 0,
            width: Width(0),
        });
        assert!(matches!(
            AxeyumSolver::new().prove_infeasible_path(&p, &[(invalid, true)]),
            InfeasiblePathVerdict::Error(_)
        ));
    }

    // ---- incremental push/pop PoC (P5 direction) -------------------------

    #[test]
    fn incremental_push_pop_reuses_base() {
        // Demonstrates axeyum's warm incremental API driving glaurung's fork
        // shape: assert a base path condition once, then push/check/pop each
        // branch. This is the mechanism a future incremental Solver trait
        // (P5) would use to avoid re-blasting the base every solve.
        use axeyum_ir::{Sort, TermArena};
        use axeyum_solver::{CheckResult, IncrementalBvSolver, SolverConfig};

        let mut arena = TermArena::new();
        // base: x <u 100  (BitVec 32)
        let xid = arena.declare("x", Sort::BitVec(32)).unwrap();
        let x = arena.var(xid);
        let hundred = arena.bv_const(32, 100).unwrap();
        let base = arena.bv_ult(x, hundred).unwrap(); // Bool
        let mut s = IncrementalBvSolver::with_config(SolverConfig::new());
        s.assert(&arena, base).unwrap();

        // fork A: x == 50 -> sat under base
        let fifty = arena.bv_const(32, 50).unwrap();
        let eq50 = arena.eq(x, fifty).unwrap();
        s.push().unwrap();
        s.assert(&arena, eq50).unwrap();
        assert!(matches!(s.check(&arena).unwrap(), CheckResult::Sat(_)));
        s.pop();

        // fork B: x == 200 -> unsat under base (200 >= 100)
        let two_hundred = arena.bv_const(32, 200).unwrap();
        let eq200 = arena.eq(x, two_hundred).unwrap();
        s.push().unwrap();
        s.assert(&arena, eq200).unwrap();
        assert!(matches!(s.check(&arena).unwrap(), CheckResult::Unsat));
        s.pop();

        // base alone is still sat after both forks popped
        assert!(matches!(s.check(&arena).unwrap(), CheckResult::Sat(_)));
    }

    // ---- text bridge still works -----------------------------------------

    #[test]
    #[cfg(feature = "solver-axeyum-text")]
    fn text_bridge_solves_add_eq() {
        let mut p = ExprPool::new();
        let x = p.fresh_symbol(Width::W32);
        let one = c(&mut p, 1, Width::W32);
        let sum = bin(&mut p, BinOp::Add, x, one, Width::W32);
        let k = c(&mut p, 0x100, Width::W32);
        let eq = cmp(&mut p, CmpOp::Eq, sum, k, Width::W32);
        match AxeyumTextSolver::new().check(&p, &[(eq, true)]) {
            SolveResult::Sat(m) => assert_eq!(m.values.get(&0).copied(), Some(0xff)),
            other => panic!("expected sat x=0xff, got {other:?}"),
        }
    }

    #[test]
    #[cfg(feature = "solver-axeyum-text")]
    fn text_bridge_wide_assertion_uses_truthiness() {
        let mut pool = ExprPool::new();
        let wide = pool.fresh_symbol(Width::W64);
        let zero = c(&mut pool, 0, Width::W64);
        let is_zero = cmp(&mut pool, CmpOp::Eq, wide, zero, Width::W64);

        assert!(matches!(
            AxeyumTextSolver::new().check(&pool, &[(wide, true), (is_zero, true)]),
            SolveResult::Unsat
        ));
        assert!(matches!(
            AxeyumTextSolver::new().check(&pool, &[(wide, false), (is_zero, true)]),
            SolveResult::Sat(_)
        ));
    }
}
