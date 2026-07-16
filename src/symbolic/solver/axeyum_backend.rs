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
//! - [`AxeyumTextSolver`] (P1, text bridge): renders the query to SMT-LIB2
//!   via [`super::pipe::build_script`] and calls axeyum's `solve_smtlib`.
//!   Kept as a cross-check / reference and a zero-translation fallback.
//!
//! See `docs/axeyum-integration/` (esp. `02-interface-mapping.md`).

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use axeyum_ir::{IrError, Sort, SymbolId, TermArena, TermId, Value, WideUint};
use axeyum_solver::{
    export_qf_bv_unsat_proof, solve_smtlib, solve_smtlib_get_value, AigConstructionStats,
    CheckResult, IncrementalBvSolver, IncrementalBvStats, IncrementalCnfStats,
    IncrementalLoweringStats, IncrementalModelLiftStats,
    IncrementalSolver as AxeyumIncrementalSolver, ReplayCheckedSatCachePolicy,
    ReplayCheckedSatCacheStats, SolverConfig, UnsatProofOutcome,
};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::ir::types::{BinOp, CmpOp, UnOp};
use crate::symbolic::expr::{Expr, ExprId, ExprPool};
use crate::symbolic::solver::{
    pipe, Assert, IncrementalSolver, Model, SolveResult, Solver, WarmDeltaContext,
};

/// Per-solve timeout, matching the z3 backend's 250 ms budget so coverage
/// and metering behave the same regardless of which backend is compiled in.
const SOLVE_TIMEOUT: Duration = Duration::from_millis(250);
const PROFILE_DIR_ENV: &str = "GLAURUNG_AXEYUM_PROFILE_DIR";
pub(crate) const WARM_REUSE_ENV: &str = "GLAURUNG_AXEYUM_WARM_REUSE";
pub(crate) const WARM_OWNER_TRANSFER_ENV: &str = "GLAURUNG_AXEYUM_WARM_OWNER_TRANSFER";
pub(crate) const WARM_SERIAL_SIBLING_REUSE_ENV: &str = "GLAURUNG_AXEYUM_WARM_SERIAL_SIBLING_REUSE";
pub(crate) const DIRECT_DELTA_ENV: &str = "GLAURUNG_AXEYUM_DIRECT_DELTA";
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
static PROFILE_WRITE_LOCK: Mutex<()> = Mutex::new(());
static PROFILE_SEQUENCE: AtomicU64 = AtomicU64::new(0);
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
enum WarmReusePolicy {
    Off,
    Snapshot,
    Lineage,
    Auto,
    Adaptive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WarmReuseLimits {
    max_live_paths: u64,
    max_assertions_per_path: u64,
}

fn warm_reuse_limits() -> WarmReuseLimits {
    *WARM_REUSE_LIMITS.get_or_init(|| WarmReuseLimits {
        max_live_paths: parse_warm_limit(
            std::env::var(WARM_MAX_LIVE_PATHS_ENV).ok(),
            DEFAULT_WARM_MAX_LIVE_PATHS,
        ),
        max_assertions_per_path: parse_warm_limit(
            std::env::var(WARM_MAX_ASSERTIONS_PER_PATH_ENV).ok(),
            DEFAULT_WARM_MAX_ASSERTIONS_PER_PATH,
        ),
    })
}

fn parse_warm_limit(value: Option<String>, default: u64) -> u64 {
    match value {
        None => default,
        Some(value) => value.parse().unwrap_or(0),
    }
}

fn warm_reuse_policy() -> WarmReusePolicy {
    let value = std::env::var(WARM_REUSE_ENV).ok();
    parse_warm_reuse_policy(value.as_deref())
}

fn parse_warm_reuse_policy(value: Option<&str>) -> WarmReusePolicy {
    match value {
        None => WarmReusePolicy::Adaptive,
        Some(value) if value.eq_ignore_ascii_case("off") => WarmReusePolicy::Off,
        Some(value) if value.eq_ignore_ascii_case("false") => WarmReusePolicy::Off,
        Some("0") => WarmReusePolicy::Off,
        Some(value) if value.eq_ignore_ascii_case("auto") => WarmReusePolicy::Auto,
        Some(value) if value.eq_ignore_ascii_case("adaptive") => WarmReusePolicy::Adaptive,
        Some(value) if value.eq_ignore_ascii_case("lineage") => WarmReusePolicy::Lineage,
        Some(_) => WarmReusePolicy::Snapshot,
    }
}

pub(crate) fn direct_delta_enabled() -> bool {
    parse_direct_delta(std::env::var(DIRECT_DELTA_ENV).ok().as_deref())
}

fn parse_direct_delta(value: Option<&str>) -> bool {
    matches!(value, Some("1"))
        || value.is_some_and(|value| {
            value.eq_ignore_ascii_case("true") || value.eq_ignore_ascii_case("on")
        })
}

pub(crate) fn last_direct_delta_synced() -> bool {
    LAST_DIRECT_DELTA_SYNCED.with(Cell::get)
}

pub(crate) fn reset_direct_delta_sync() {
    LAST_DIRECT_DELTA_SYNCED.with(|synced| synced.set(false));
}

pub(crate) fn warm_owner_transfer_enabled() -> bool {
    parse_warm_owner_transfer(std::env::var(WARM_OWNER_TRANSFER_ENV).ok().as_deref())
}

fn parse_warm_owner_transfer(value: Option<&str>) -> bool {
    match value {
        None => true,
        Some(value) if value.eq_ignore_ascii_case("off") => false,
        Some(value) if value.eq_ignore_ascii_case("false") => false,
        Some("0") => false,
        Some(value) if value.eq_ignore_ascii_case("on") => true,
        Some(value) if value.eq_ignore_ascii_case("true") => true,
        Some("1") => true,
        Some(_) => false,
    }
}

pub(crate) fn warm_serial_sibling_reuse_enabled() -> bool {
    warm_reuse_policy() == WarmReusePolicy::Adaptive
        && parse_warm_serial_sibling_reuse(
            std::env::var(WARM_SERIAL_SIBLING_REUSE_ENV).ok().as_deref(),
        )
}

fn parse_warm_serial_sibling_reuse(value: Option<&str>) -> bool {
    match value {
        None => true,
        Some(value) if value.eq_ignore_ascii_case("off") => false,
        Some(value) if value.eq_ignore_ascii_case("false") => false,
        Some("0") => false,
        Some(value) if value.eq_ignore_ascii_case("on") => true,
        Some(value) if value.eq_ignore_ascii_case("true") => true,
        Some("1") => true,
        Some(_) => false,
    }
}

fn replay_sat_cache_policy() -> Option<ReplayCheckedSatCachePolicy> {
    *REPLAY_SAT_CACHE_POLICY.get_or_init(|| {
        parse_replay_sat_cache_policy(std::env::var(REPLAY_SAT_CACHE_ENV).ok().as_deref())
    })
}

fn parse_replay_sat_cache_policy(value: Option<&str>) -> Option<ReplayCheckedSatCachePolicy> {
    let enabled = match value {
        None => true,
        Some(value) if value.eq_ignore_ascii_case("off") => false,
        Some(value) if value.eq_ignore_ascii_case("false") => false,
        Some("0") => false,
        Some(value) if value.eq_ignore_ascii_case("on") => true,
        Some(value) if value.eq_ignore_ascii_case("true") => true,
        Some("1") => true,
        Some(_) => false,
    };
    enabled.then(|| {
        ReplayCheckedSatCachePolicy::new(
            DEFAULT_REPLAY_SAT_CACHE_ENTRIES,
            DEFAULT_REPLAY_SAT_CACHE_MODEL_VALUES,
            DEFAULT_REPLAY_SAT_CACHE_MODEL_BITS,
        )
    })
}

fn config() -> SolverConfig {
    let internal_and_flattening = std::env::var(INTERNAL_AND_FLATTENING_ENV)
        .is_ok_and(|value| matches!(value.as_str(), "1" | "true" | "on"));
    SolverConfig::new()
        .with_timeout(SOLVE_TIMEOUT)
        .with_incremental_positive_and_flattening(internal_and_flattening)
}

// ---------------------------------------------------------------------------
// P2: native term-translation backend
// ---------------------------------------------------------------------------

/// The native, in-process axeyum backend: `Expr` -> `axeyum-ir` -> solve.
#[derive(Debug, Default, Clone, Copy)]
pub struct AxeyumSolver;

/// Query-hash-keyed attribution for one diagnostic native Axeyum check.
///
/// All durations are integer nanoseconds so JSON artifacts preserve exact
/// values without relying on a platform-specific `Duration` representation.
/// The query hash is computed from the same SMT-LIB bytes as the corpus-capture
/// hook, but rendering/hashing happens before `total_nanos` starts so the
/// diagnostic key does not masquerade as solver work.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AxeyumCheckProfile {
    /// Versioned JSON record schema.
    pub schema: &'static str,
    /// Operating-system process that produced the record.
    pub process_id: u32,
    /// Monotone process-local output order, assigned by the JSONL writer.
    pub sequence: Option<u64>,
    /// SHA-256 of the exact SMT-LIB bytes used by the capture hook.
    pub query_hash: String,
    /// Word-level assertion policy used by this check.
    pub word_policy: &'static str,
    /// Configured per-solve timeout in milliseconds.
    pub timeout_ms: u64,
    /// Stable result class: `sat`, `unsat`, `unknown`, or `error`.
    pub outcome: &'static str,
    /// Whether translation and solving completed without an operational error.
    pub complete: bool,
    /// Number of Glaurung assertions in the query.
    pub assertion_count: u64,
    /// Number of distinct Glaurung expressions translated through the memo.
    pub translated_exprs: u64,
    /// Number of interned Axeyum terms after translation.
    pub arena_terms: u64,
    /// Number of translated Glaurung symbols.
    pub symbols: u64,
    /// Number of values exposed in the client model.
    pub model_values: u64,
    /// Number of assertion roots added to the retained CNF.
    pub root_encodings: u64,
    /// Number of incremental solver checks attempted.
    pub checks: u64,
    /// Retained AIG node count at the end of the check.
    pub aig_nodes: u64,
    /// Retained CNF variable count at the end of the check.
    pub cnf_variables: u64,
    /// Retained CNF clause count at the end of the check.
    pub cnf_clauses: u64,
    /// Nanoseconds spent constructing the Axeyum arena.
    pub arena_create_nanos: u64,
    /// Nanoseconds spent translating Glaurung expressions and assertions.
    pub translation_nanos: u64,
    /// Nanoseconds spent constructing the incremental solver.
    pub solver_create_nanos: u64,
    /// Nanoseconds spent in configured word-level rewriting.
    pub word_rewrite_nanos: u64,
    /// Nanoseconds spent lowering terms into the retained AIG.
    pub bit_blast_nanos: u64,
    /// Nanoseconds spent extending the retained CNF.
    pub cnf_encode_nanos: u64,
    /// Nanoseconds spent in the SAT adapter.
    pub solve_nanos: u64,
    /// Nanoseconds spent reconstructing the Axeyum model.
    pub model_lift_nanos: u64,
    /// Nanoseconds spent replaying SAT candidates against original terms.
    pub replay_nanos: u64,
    /// Nanoseconds spent converting the Axeyum model into Glaurung's model.
    pub model_extract_nanos: u64,
    /// Total native-adapter nanoseconds, excluding query rendering and output.
    pub total_nanos: u64,
}

/// Exact-query attribution for one opt-in retained warm check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WarmAxeyumCheckProfile {
    /// Versioned JSON record schema.
    pub schema: &'static str,
    /// Operating-system process that produced the record.
    pub process_id: u32,
    /// Monotone process-local order across cold and warm profile records.
    pub sequence: Option<u64>,
    /// SHA-256 of the exact SMT-LIB bytes used by the capture hook.
    pub query_hash: String,
    /// Explicit explorer path owner, absent for consecutive-snapshot mode.
    pub path_id: Option<u64>,
    /// Whether this check lazily created its retained path session.
    pub path_created: bool,
    /// Stable result class: `sat`, `unsat`, `unknown`, or `error`.
    pub outcome: &'static str,
    /// Whether translation and solving completed without an operational error.
    pub complete: bool,
    /// Number of Glaurung assertions in the complete snapshot.
    pub assertion_count: u64,
    /// Number of assertion roots retained as the common prefix.
    pub common_prefix_assertions: u64,
    /// Number of newly asserted roots.
    pub assertions_added: u64,
    /// Number of divergent roots popped before this check.
    pub assertions_popped: u64,
    /// Number of distinct Glaurung expressions translated through the memo.
    pub translated_exprs: u64,
    /// Current retained Axeyum arena term count.
    pub arena_terms: u64,
    /// Number of translated Glaurung symbols.
    pub symbols: u64,
    /// Number of values exposed in the client model.
    pub model_values: u64,
    /// Time spent lazily constructing a new retained path session.
    pub session_create_nanos: u64,
    /// Time spent translating the complete client snapshot into the arena.
    pub translation_nanos: u64,
    /// Time spent in configured word-level rewriting for newly added roots.
    pub word_rewrite_nanos: u64,
    /// Time spent lowering newly required terms into the retained AIG.
    pub bit_blast_nanos: u64,
    /// Time spent extending CNF and asserting new roots.
    pub cnf_encode_nanos: u64,
    /// Time spent inside the retained SAT adapter.
    pub solve_nanos: u64,
    /// Time spent reconstructing the Axeyum model.
    pub model_lift_nanos: u64,
    /// Time spent replaying the candidate against original assertions.
    pub replay_nanos: u64,
    /// Time spent converting the Axeyum model into Glaurung's model.
    pub model_extract_nanos: u64,
    /// Total warm-adapter time, excluding query rendering, hashing, and output.
    pub total_nanos: u64,
    /// Adapter time not covered by the named non-overlapping phases.
    pub unattributed_nanos: u64,
    /// Newly encoded retained roots in this check.
    pub root_encodings: u64,
    /// Newly retained AIG nodes in this check.
    pub aig_nodes_added: u64,
    /// Newly retained CNF variables in this check.
    pub cnf_variables_added: u64,
    /// Newly retained CNF clauses in this check.
    pub cnf_clauses_added: u64,
    /// Current retained AIG nodes after this check.
    pub aig_nodes: u64,
    /// Current retained CNF variables after this check.
    pub cnf_variables: u64,
    /// Current retained CNF clauses after this check.
    pub cnf_clauses: u64,
    /// Per-check incremental CNF gate/root-family deltas.
    pub cnf_gate_mix: BTreeMap<&'static str, u64>,
    /// Per-check primitive AIG construction classification.
    pub aig_construction: BTreeMap<&'static str, u64>,
    /// Per-check term-memo, literal-copy, and lift-map work.
    pub lowering_work: BTreeMap<&'static str, u64>,
    /// Per-check model-lift subphase durations and operation counts.
    pub model_lift_work: BTreeMap<&'static str, u64>,
    /// Per-check replay-cache traffic plus current per-path gauges.
    pub replay_sat_cache: BTreeMap<&'static str, u64>,
}

struct WarmProfileContext {
    profile: WarmAxeyumCheckProfile,
    total_started: Instant,
    solver_before: IncrementalBvStats,
    replay_sat_cache_before: ReplayCheckedSatCacheStats,
}

impl AxeyumCheckProfile {
    /// Sum of non-overlapping attributed phase durations.
    pub fn attributed_nanos(&self) -> u64 {
        self.arena_create_nanos
            .saturating_add(self.translation_nanos)
            .saturating_add(self.solver_create_nanos)
            .saturating_add(self.word_rewrite_nanos)
            .saturating_add(self.bit_blast_nanos)
            .saturating_add(self.cnf_encode_nanos)
            .saturating_add(self.solve_nanos)
            .saturating_add(self.model_lift_nanos)
            .saturating_add(self.replay_nanos)
            .saturating_add(self.model_extract_nanos)
    }

    /// Time inside the native adapter not covered by a named phase.
    pub fn unattributed_nanos(&self) -> u64 {
        self.total_nanos.saturating_sub(self.attributed_nanos())
    }
}

/// Result plus diagnostic attribution from [`AxeyumSolver::check_profiled`].
#[derive(Debug)]
pub struct ProfiledSolveResult {
    /// Normal Glaurung solve result.
    pub result: SolveResult,
    /// Diagnostic attribution for the same solve.
    pub profile: AxeyumCheckProfile,
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
            timeout_ms: u64::try_from(SOLVE_TIMEOUT.as_millis()).unwrap_or(u64::MAX),
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
        Self::with_cache_policy(None)
    }

    fn new_path_owned() -> Self {
        Self::with_cache_policy(replay_sat_cache_policy())
    }

    fn with_cache_policy(policy: Option<ReplayCheckedSatCachePolicy>) -> Self {
        let mut solver = IncrementalBvSolver::with_config(config().with_preprocess(false));
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
}

impl IncrementalSolver for IncrementalAxeyumSolver {
    fn assert(&mut self, pool: &ExprPool, assertion: Assert) -> Result<(), String> {
        let translated = self
            .translate(pool, std::slice::from_ref(&assertion))
            .map_err(|error| format!("axeyum translate: {error}"))?;
        let term = translated.assertions[0];
        AxeyumIncrementalSolver::assert(&mut self.solver, &self.arena, term)
            .map_err(|error| format!("axeyum assert: {error}"))?;
        self.symbol_frames
            .last_mut()
            .expect("base symbol frame is invariant")
            .extend(translated.sym_map);
        Ok(())
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
        let symbols = self.active_symbol_map();
        map_check_result(
            AxeyumIncrementalSolver::check(&mut self.solver, &self.arena),
            &symbols,
        )
    }

    fn check_assuming(&mut self, pool: &ExprPool, assumptions: &[Assert]) -> SolveResult {
        let translated = match self.translate(pool, assumptions) {
            Ok(translated) => translated,
            Err(error) => return SolveResult::Error(format!("axeyum translate: {error}")),
        };
        let mut symbols = self.active_symbol_map();
        symbols.extend(translated.sym_map);
        map_check_result(
            AxeyumIncrementalSolver::check_assuming(
                &mut self.solver,
                &self.arena,
                &translated.assertions,
            ),
            &symbols,
        )
    }
}

/// Cumulative behavior of [`SnapshotIncrementalAxeyumSolver`].
///
/// Counts describe assertion roots, not expression-DAG nodes. They make the
/// first Glaurung warm integration measurable before the explorer grows an
/// explicit lineage/scope API.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SnapshotReuseStats {
    /// Complete snapshots checked.
    pub checks: u64,
    /// Checks whose complete assertion vector matched the preceding snapshot.
    pub exact_snapshot_reuses: u64,
    /// Assertion roots retained across snapshot transitions.
    pub prefix_assertions_reused: u64,
    /// New assertion roots encoded after the common prefix.
    pub assertions_added: u64,
    /// Divergent assertion scopes deactivated after the common prefix.
    pub assertions_popped: u64,
    /// Sessions discarded after a push/assert/check operational error.
    pub resets_after_error: u64,
}

/// Adapts Glaurung's complete assertion snapshots to Axeyum's warm scopes.
///
/// The retained [`TermArena`] structurally interns translated terms, so common
/// roots receive the same [`TermId`] even when Glaurung cloned an [`ExprPool`]
/// and sibling pools reused numeric [`ExprId`] values for different nodes. The
/// longest common structural prefix stays active; divergent suffix scopes are
/// popped and only the new suffix is asserted. Every SAT result still follows
/// Axeyum's original-term model replay before it reaches this adapter.
#[derive(Debug)]
pub struct SnapshotIncrementalAxeyumSolver {
    arena: TermArena,
    solver: IncrementalBvSolver,
    active: Vec<TermId>,
    has_snapshot: bool,
    preprocess: bool,
    profiling: bool,
    replay_sat_cache_policy: Option<ReplayCheckedSatCachePolicy>,
    stats: SnapshotReuseStats,
}

impl Default for SnapshotIncrementalAxeyumSolver {
    fn default() -> Self {
        Self::new()
    }
}

impl SnapshotIncrementalAxeyumSolver {
    /// Creates an empty raw-policy snapshot adapter.
    pub fn new() -> Self {
        Self::with_preprocessing(false)
    }

    /// Creates an empty adapter and optionally canonicalizes each newly added
    /// assertion. Existing prefix assertions are never reprocessed.
    pub fn with_preprocessing(preprocess: bool) -> Self {
        Self::with_preprocessing_and_profiling(preprocess, profile_output_dir().is_some())
    }

    fn with_preprocessing_and_profiling(preprocess: bool, profiling: bool) -> Self {
        Self::with_policy(preprocess, profiling, None)
    }

    fn new_path_owned() -> Self {
        Self::with_policy(
            false,
            profile_output_dir().is_some(),
            replay_sat_cache_policy(),
        )
    }

    #[cfg(test)]
    fn with_cache_for_test(policy: ReplayCheckedSatCachePolicy) -> Self {
        Self::with_policy(false, false, Some(policy))
    }

    fn with_policy(
        preprocess: bool,
        profiling: bool,
        replay_sat_cache_policy: Option<ReplayCheckedSatCachePolicy>,
    ) -> Self {
        let solver_config = config().with_preprocess(preprocess);
        let mut solver = if profiling {
            IncrementalBvSolver::with_config_and_profiling(solver_config)
        } else {
            IncrementalBvSolver::with_config(solver_config)
        };
        if let Some(policy) = replay_sat_cache_policy {
            solver
                .enable_replay_checked_sat_cache(policy)
                .expect("Glaurung replay-SAT-cache bounds are nonzero constants");
        }
        Self {
            arena: TermArena::new(),
            solver,
            active: Vec::new(),
            has_snapshot: false,
            preprocess,
            profiling,
            replay_sat_cache_policy,
            stats: SnapshotReuseStats::default(),
        }
    }

    /// Returns cumulative snapshot-reuse counters.
    pub fn stats(&self) -> SnapshotReuseStats {
        self.stats
    }

    fn replay_sat_cache_stats(&self) -> ReplayCheckedSatCacheStats {
        self.solver.replay_checked_sat_cache_stats()
    }

    fn reset_session(&mut self) {
        self.arena = TermArena::new();
        let solver_config = config().with_preprocess(self.preprocess);
        self.solver = if self.profiling {
            IncrementalBvSolver::with_config_and_profiling(solver_config)
        } else {
            IncrementalBvSolver::with_config(solver_config)
        };
        if let Some(policy) = self.replay_sat_cache_policy {
            self.solver
                .enable_replay_checked_sat_cache(policy)
                .expect("Glaurung replay-SAT-cache bounds are nonzero constants");
        }
        self.active.clear();
        self.has_snapshot = false;
        self.stats.resets_after_error = self.stats.resets_after_error.saturating_add(1);
    }

    /// Checks one complete Glaurung assertion snapshot using retained Axeyum
    /// translation, AIG, CNF, and SAT state.
    pub fn check_snapshot(&mut self, pool: &ExprPool, asserts: &[Assert]) -> SolveResult {
        self.check_snapshot_for_path(pool, asserts, None, false, 0)
    }

    fn check_snapshot_for_path(
        &mut self,
        pool: &ExprPool,
        asserts: &[Assert],
        path_id: Option<u64>,
        path_created: bool,
        session_create_nanos: u64,
    ) -> SolveResult {
        let mut profile =
            self.start_profile(pool, asserts, path_id, path_created, session_create_nanos);
        let translation_started = profile.as_ref().map(|_| Instant::now());
        let translated = match translate_query(pool, asserts, &mut self.arena) {
            Ok(translated) => translated,
            Err(err) => {
                if let (Some(profile), Some(started)) = (&mut profile, translation_started) {
                    profile.profile.translation_nanos = nanos(started.elapsed());
                }
                let solver_after = self.solver.stats();
                return self.finish_profile(
                    profile,
                    solver_after,
                    SolveResult::Error(format!("axeyum translate: {err}")),
                );
            }
        };
        if let (Some(profile), Some(started)) = (&mut profile, translation_started) {
            profile.profile.translation_nanos = nanos(started.elapsed());
            profile.profile.translated_exprs = count(translated.exprs);
            profile.profile.symbols = count(translated.sym_map.len());
        }
        let common = self
            .active
            .iter()
            .zip(&translated.assertions)
            .take_while(|(active, next)| active == next)
            .count();
        if let Some(profile) = &mut profile {
            profile.profile.common_prefix_assertions = count(common);
        }

        self.stats.checks = self.stats.checks.saturating_add(1);
        self.stats.prefix_assertions_reused = self
            .stats
            .prefix_assertions_reused
            .saturating_add(count(common));
        if self.has_snapshot && common == self.active.len() && common == translated.assertions.len()
        {
            self.stats.exact_snapshot_reuses = self.stats.exact_snapshot_reuses.saturating_add(1);
        }

        let pop_count = self.active.len().saturating_sub(common);
        if let Some(profile) = &mut profile {
            profile.profile.assertions_popped = count(pop_count);
            profile.profile.assertions_added = count(translated.assertions.len() - common);
        }
        for _ in 0..pop_count {
            if !self.solver.pop() {
                let solver_after = self.solver.stats();
                self.reset_session();
                return self.finish_profile(
                    profile,
                    solver_after,
                    SolveResult::Error(
                        "axeyum warm snapshot scope underflow; session reset".to_string(),
                    ),
                );
            }
        }
        self.active.truncate(common);
        self.stats.assertions_popped = self
            .stats
            .assertions_popped
            .saturating_add(count(pop_count));

        for &term in &translated.assertions[common..] {
            if let Err(err) = self.solver.push() {
                let solver_after = self.solver.stats();
                self.reset_session();
                return self.finish_profile(
                    profile,
                    solver_after,
                    SolveResult::Error(format!("axeyum warm push: {err}")),
                );
            }
            if let Err(err) = self.solver.assert_configured(&mut self.arena, term) {
                let solver_after = self.solver.stats();
                self.reset_session();
                return self.finish_profile(
                    profile,
                    solver_after,
                    SolveResult::Error(format!("axeyum warm assert: {err}")),
                );
            }
            self.active.push(term);
            self.stats.assertions_added = self.stats.assertions_added.saturating_add(1);
        }
        self.has_snapshot = true;

        let checked = self.solver.check(&self.arena);
        let solver_after = self.solver.stats();
        if checked.is_err() {
            self.reset_session();
        }
        let model_started = profile.as_ref().map(|_| Instant::now());
        let result = map_check_result(checked, &translated.sym_map);
        if let (Some(profile), Some(started)) = (&mut profile, model_started) {
            profile.profile.model_extract_nanos = nanos(started.elapsed());
            if let SolveResult::Sat(model) = &result {
                profile.profile.model_values = count(model.values.len());
            }
        }
        self.finish_profile(profile, solver_after, result)
    }

    fn start_profile(
        &self,
        pool: &ExprPool,
        asserts: &[Assert],
        path_id: Option<u64>,
        path_created: bool,
        session_create_nanos: u64,
    ) -> Option<WarmProfileContext> {
        if !self.profiling {
            return None;
        }
        let (script, _) = pipe::build_script(pool, asserts);
        let query_hash = format!("sha256:{}", hex::encode(Sha256::digest(script.as_bytes())));
        Some(WarmProfileContext {
            profile: WarmAxeyumCheckProfile {
                schema: "glaurung-axeyum-warm-profile-v6",
                process_id: std::process::id(),
                sequence: None,
                query_hash,
                path_id,
                path_created,
                outcome: "error",
                complete: false,
                assertion_count: count(asserts.len()),
                common_prefix_assertions: 0,
                assertions_added: 0,
                assertions_popped: 0,
                translated_exprs: 0,
                arena_terms: 0,
                symbols: 0,
                model_values: 0,
                session_create_nanos,
                translation_nanos: 0,
                word_rewrite_nanos: 0,
                bit_blast_nanos: 0,
                cnf_encode_nanos: 0,
                solve_nanos: 0,
                model_lift_nanos: 0,
                replay_nanos: 0,
                model_extract_nanos: 0,
                total_nanos: 0,
                unattributed_nanos: 0,
                root_encodings: 0,
                aig_nodes_added: 0,
                cnf_variables_added: 0,
                cnf_clauses_added: 0,
                aig_nodes: 0,
                cnf_variables: 0,
                cnf_clauses: 0,
                cnf_gate_mix: BTreeMap::new(),
                aig_construction: BTreeMap::new(),
                lowering_work: BTreeMap::new(),
                model_lift_work: BTreeMap::new(),
                replay_sat_cache: BTreeMap::new(),
            },
            total_started: Instant::now(),
            solver_before: self.solver.stats(),
            replay_sat_cache_before: self.solver.replay_checked_sat_cache_stats(),
        })
    }

    fn finish_profile(
        &self,
        context: Option<WarmProfileContext>,
        solver_after: IncrementalBvStats,
        result: SolveResult,
    ) -> SolveResult {
        let Some(mut context) = context else {
            return result;
        };
        let delta = solver_after.delta_since(context.solver_before);
        context.profile.word_rewrite_nanos = nanos(delta.word_rewrite);
        context.profile.bit_blast_nanos = nanos(delta.bit_blast);
        context.profile.cnf_encode_nanos = nanos(delta.cnf_encode);
        context.profile.solve_nanos = nanos(delta.solve);
        context.profile.model_lift_nanos = nanos(delta.model_lift);
        context.profile.replay_nanos = nanos(delta.replay);
        context.profile.root_encodings = delta.root_encodings;
        context.profile.aig_nodes_added = delta.aig_nodes;
        context.profile.cnf_variables_added = delta.cnf_variables;
        context.profile.cnf_clauses_added = delta.cnf_clauses;
        context.profile.aig_nodes = solver_after.aig_nodes;
        context.profile.cnf_variables = solver_after.cnf_variables;
        context.profile.cnf_clauses = solver_after.cnf_clauses;
        context.profile.cnf_gate_mix = cnf_gate_mix(delta.cnf_gate_mix);
        context.profile.aig_construction = aig_construction(delta.aig_construction);
        context.profile.lowering_work = lowering_work(delta.lowering_work);
        context.profile.model_lift_work = model_lift_work(delta.model_lift_work);
        context.profile.replay_sat_cache = replay_sat_cache_profile(
            self.replay_sat_cache_policy,
            context.replay_sat_cache_before,
            self.solver.replay_checked_sat_cache_stats(),
        );
        context.profile.arena_terms = count(self.arena.len());
        context.profile.outcome = result_name(&result);
        context.profile.complete = !matches!(&result, SolveResult::Error(_));
        context.profile.total_nanos = nanos(context.total_started.elapsed())
            .saturating_add(context.profile.session_create_nanos);
        let attributed = context
            .profile
            .session_create_nanos
            .saturating_add(context.profile.translation_nanos)
            .saturating_add(context.profile.word_rewrite_nanos)
            .saturating_add(context.profile.bit_blast_nanos)
            .saturating_add(context.profile.cnf_encode_nanos)
            .saturating_add(context.profile.solve_nanos)
            .saturating_add(context.profile.model_lift_nanos)
            .saturating_add(context.profile.replay_nanos)
            .saturating_add(context.profile.model_extract_nanos);
        context.profile.unattributed_nanos = context.profile.total_nanos.saturating_sub(attributed);
        let Some(output_dir) = profile_output_dir() else {
            return result;
        };
        if let Err(error) = write_profile_record(output_dir, &context.profile) {
            return SolveResult::Error(error);
        }
        result
    }
}

fn cnf_gate_mix(stats: IncrementalCnfStats) -> BTreeMap<&'static str, u64> {
    BTreeMap::from([
        ("and_nodes_synced", stats.and_nodes_synced),
        ("up_half_definitions", stats.up_half_definitions),
        ("down_half_definitions", stats.down_half_definitions),
        ("xor_half_definitions", stats.xor_half_definitions),
        ("not_ite_half_definitions", stats.not_ite_half_definitions),
        ("not_and_half_definitions", stats.not_and_half_definitions),
        ("and_tree_half_definitions", stats.and_tree_half_definitions),
        (
            "binary_and_half_definitions",
            stats.binary_and_half_definitions,
        ),
        (
            "internal_positive_and_opportunities",
            stats.internal_positive_and_opportunities,
        ),
        (
            "internal_positive_and_opportunity_nodes",
            stats.internal_positive_and_opportunity_nodes,
        ),
        (
            "internal_positive_and_flattened",
            stats.internal_positive_and_flattened,
        ),
        (
            "internal_positive_and_immediate_clauses_avoided",
            stats.internal_positive_and_immediate_clauses_avoided,
        ),
        ("constant_clauses", stats.constant_clauses),
        ("definition_clauses", stats.definition_clauses),
        ("root_clauses", stats.root_clauses),
        ("direct_positive_and_roots", stats.direct_positive_and_roots),
        ("direct_positive_and_nodes", stats.direct_positive_and_nodes),
        (
            "direct_positive_and_leaves",
            stats.direct_positive_and_leaves,
        ),
        ("direct_xor_leaves", stats.direct_xor_leaves),
        ("direct_not_ite_leaves", stats.direct_not_ite_leaves),
        ("direct_negative_and_roots", stats.direct_negative_and_roots),
        ("fused_positive_and_roots", stats.fused_positive_and_roots),
        ("fused_positive_and_nodes", stats.fused_positive_and_nodes),
        ("fused_xor_leaves", stats.fused_xor_leaves),
        ("root_assertions", stats.root_assertions),
        ("guarded_root_assertions", stats.guarded_root_assertions),
        (
            "repeated_same_context_roots",
            stats.repeated_same_context_roots,
        ),
        (
            "deduplicated_root_assertions",
            stats.deduplicated_root_assertions,
        ),
        (
            "reused_cross_context_roots",
            stats.reused_cross_context_roots,
        ),
        ("guarded_root_clauses", stats.guarded_root_clauses),
        ("root_clause_attempts", stats.root_clause_attempts),
        ("unit_payload_root_clauses", stats.unit_payload_root_clauses),
        (
            "binary_payload_root_clauses",
            stats.binary_payload_root_clauses,
        ),
        ("wide_payload_root_clauses", stats.wide_payload_root_clauses),
        (
            "duplicate_definition_clauses",
            stats.duplicate_definition_clauses,
        ),
        ("duplicate_root_clauses", stats.duplicate_root_clauses),
        (
            "duplicate_prior_root_clauses",
            stats.duplicate_prior_root_clauses,
        ),
        (
            "root_clauses_duplicate_non_root",
            stats.root_clauses_duplicate_non_root,
        ),
        (
            "tautological_definition_clauses",
            stats.tautological_definition_clauses,
        ),
        ("tautological_root_clauses", stats.tautological_root_clauses),
        (
            "fresh_negative_root_definitions",
            stats.fresh_negative_root_definitions,
        ),
        (
            "reused_negative_root_definitions",
            stats.reused_negative_root_definitions,
        ),
    ])
}

fn aig_construction(stats: AigConstructionStats) -> BTreeMap<&'static str, u64> {
    BTreeMap::from([
        ("and_requests", stats.and_requests),
        (
            "and_trivial_simplifications",
            stats.and_trivial_simplifications,
        ),
        (
            "and_absorption_simplifications",
            stats.and_absorption_simplifications,
        ),
        ("and_structural_hash_hits", stats.and_structural_hash_hits),
        ("and_nodes_created", stats.and_nodes_created),
    ])
}

fn lowering_work(stats: IncrementalLoweringStats) -> BTreeMap<&'static str, u64> {
    BTreeMap::from([
        ("lower_calls", stats.lower_calls),
        ("term_memo_lookups", stats.term_memo_lookups),
        ("term_memo_hits", stats.term_memo_hits),
        ("terms_lowered", stats.terms_lowered),
        ("operand_vectors_copied", stats.operand_vectors_copied),
        ("operand_bits_copied", stats.operand_bits_copied),
        ("root_bits_copied", stats.root_bits_copied),
        ("term_bit_bindings_written", stats.term_bit_bindings_written),
        ("memoized_terms", stats.memoized_terms),
        ("term_bit_bindings", stats.term_bit_bindings),
        ("symbol_bit_inputs", stats.symbol_bit_inputs),
    ])
}

fn model_lift_work(stats: IncrementalModelLiftStats) -> BTreeMap<&'static str, u64> {
    BTreeMap::from([
        ("aig_recompute_nanos", nanos(stats.aig_recompute)),
        (
            "assignment_reconstruct_nanos",
            nanos(stats.assignment_reconstruct),
        ),
        ("model_completion_nanos", nanos(stats.model_completion)),
        ("aig_nodes_recomputed", stats.aig_nodes_recomputed),
        ("symbol_bit_inputs_scanned", stats.symbol_bit_inputs_scanned),
        (
            "assignment_symbols_produced",
            stats.assignment_symbols_produced,
        ),
        ("arena_symbols_scanned", stats.arena_symbols_scanned),
        ("completed_model_values", stats.completed_model_values),
    ])
}

fn replay_sat_cache_profile(
    policy: Option<ReplayCheckedSatCachePolicy>,
    before: ReplayCheckedSatCacheStats,
    after: ReplayCheckedSatCacheStats,
) -> BTreeMap<&'static str, u64> {
    BTreeMap::from([
        ("enabled", u64::from(policy.is_some())),
        (
            "max_entries",
            policy.map_or(0, |policy| count(policy.max_entries)),
        ),
        (
            "max_model_values",
            policy.map_or(0, |policy| count(policy.max_model_values)),
        ),
        (
            "max_model_bits",
            policy.map_or(0, |policy| count(policy.max_model_bits)),
        ),
        ("hits", after.hits.saturating_sub(before.hits)),
        ("misses", after.misses.saturating_sub(before.misses)),
        (
            "insertions",
            after.insertions.saturating_sub(before.insertions),
        ),
        (
            "evictions",
            after.evictions.saturating_sub(before.evictions),
        ),
        (
            "replay_failures",
            after.replay_failures.saturating_sub(before.replay_failures),
        ),
        (
            "declined_unsat",
            after.declined_unsat.saturating_sub(before.declined_unsat),
        ),
        (
            "declined_unknown",
            after
                .declined_unknown
                .saturating_sub(before.declined_unknown),
        ),
        (
            "declined_oversized_models",
            after
                .declined_oversized_models
                .saturating_sub(before.declined_oversized_models),
        ),
        (
            "declined_non_scalar_models",
            after
                .declined_non_scalar_models
                .saturating_sub(before.declined_non_scalar_models),
        ),
        ("entries", after.entries),
        ("model_values", after.model_values),
        ("model_bits", after.model_bits),
    ])
}

/// One independently mutable retained solver per explorer-owned path.
///
/// A path's first check materializes its complete assertion snapshot. Later
/// checks on that same path reuse its prefix and add only the delta. Siblings
/// never share an [`IncrementalBvSolver`]; their common prefix is replayed into
/// separate sessions, preserving push/pop ownership and learned-state isolation.
#[derive(Debug, Default)]
struct LineageIncrementalAxeyumSolver {
    paths: BTreeMap<u64, SnapshotIncrementalAxeyumSolver>,
}

/// Exact work counters for the direct-delta P5 session adapter.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct DirectDeltaStats {
    checks: u64,
    full_materializations: u64,
    exact_reuses: u64,
    prefix_assertions_reused: u64,
    persistent_assertions_translated: u64,
    temporary_assumptions_translated: u64,
    assertions_added: u64,
    assertions_popped: u64,
    resets_after_error: u64,
}

#[derive(Debug)]
struct DirectDeltaPath {
    solver: IncrementalAxeyumSolver,
    active_assertions: usize,
}

/// Path-owned retained sessions driven by explicit absolute-prefix deltas.
///
/// A missing path always materializes the complete persistent snapshot. An
/// existing path may retain only a prefix no deeper than both its current
/// session and the caller's persistent vector. Any invalid transition fails
/// closed and drops the entire session; a later call must materialize again.
#[derive(Debug, Default)]
struct DirectDeltaLineageAxeyumSolver {
    paths: BTreeMap<u64, DirectDeltaPath>,
    stats: DirectDeltaStats,
}

impl DirectDeltaLineageAxeyumSolver {
    fn has_path(&self, path_id: u64) -> bool {
        self.paths.contains_key(&path_id)
    }

    fn check_path(
        &mut self,
        path_id: u64,
        pool: &ExprPool,
        persistent: &[Assert],
        retain_assertions: usize,
        temporary: &[Assert],
    ) -> (SolveResult, bool, Option<ReplayCheckedSatCacheStats>) {
        self.stats.checks = self.stats.checks.saturating_add(1);
        let created = !self.paths.contains_key(&path_id);
        if created {
            self.stats.full_materializations = self.stats.full_materializations.saturating_add(1);
            self.paths.insert(
                path_id,
                DirectDeltaPath {
                    solver: IncrementalAxeyumSolver::new_path_owned(),
                    active_assertions: 0,
                },
            );
        }

        let exact_reuse = !created
            && self.paths.get(&path_id).is_some_and(|path| {
                retain_assertions == path.active_assertions
                    && retain_assertions == persistent.len()
                    && temporary.is_empty()
            });

        let result = self.transition_and_check(
            path_id,
            pool,
            persistent,
            if created { 0 } else { retain_assertions },
            temporary,
        );
        let synced = !matches!(result, SolveResult::Error(_));
        if synced && !created {
            self.stats.prefix_assertions_reused = self
                .stats
                .prefix_assertions_reused
                .saturating_add(count(retain_assertions));
            if exact_reuse {
                self.stats.exact_reuses = self.stats.exact_reuses.saturating_add(1);
            }
        } else if !synced {
            let removed_cache = self.close_path(path_id);
            self.stats.resets_after_error = self.stats.resets_after_error.saturating_add(1);
            return (result, false, removed_cache);
        }
        (result, true, None)
    }

    fn transition_and_check(
        &mut self,
        path_id: u64,
        pool: &ExprPool,
        persistent: &[Assert],
        retain_assertions: usize,
        temporary: &[Assert],
    ) -> SolveResult {
        let path = self
            .paths
            .get_mut(&path_id)
            .expect("direct path was materialized before transition");
        if retain_assertions > path.active_assertions || retain_assertions > persistent.len() {
            return SolveResult::Error(format!(
                "axeyum direct-delta prefix {retain_assertions} exceeds active {} or persistent {}",
                path.active_assertions,
                persistent.len()
            ));
        }

        let pop_count = path.active_assertions - retain_assertions;
        for _ in 0..pop_count {
            if !path.solver.pop() {
                return SolveResult::Error(
                    "axeyum direct-delta scope underflow; session reset".to_string(),
                );
            }
            path.active_assertions -= 1;
            self.stats.assertions_popped = self.stats.assertions_popped.saturating_add(1);
        }
        debug_assert_eq!(path.active_assertions, retain_assertions);

        let suffix = &persistent[retain_assertions..];
        for &assertion in suffix {
            if let Err(error) = path.solver.push() {
                return SolveResult::Error(error);
            }
            if let Err(error) = path.solver.assert(pool, assertion) {
                return SolveResult::Error(error);
            }
            path.active_assertions += 1;
            self.stats.persistent_assertions_translated = self
                .stats
                .persistent_assertions_translated
                .saturating_add(1);
            self.stats.assertions_added = self.stats.assertions_added.saturating_add(1);
        }
        self.stats.temporary_assumptions_translated = self
            .stats
            .temporary_assumptions_translated
            .saturating_add(count(temporary.len()));

        if temporary.is_empty() {
            path.solver.check()
        } else {
            path.solver.check_assuming(pool, temporary)
        }
    }

    #[cfg(test)]
    fn stats(&self) -> DirectDeltaStats {
        self.stats
    }

    fn snapshot_stats(&self) -> SnapshotReuseStats {
        SnapshotReuseStats {
            checks: self.stats.checks,
            exact_snapshot_reuses: self.stats.exact_reuses,
            prefix_assertions_reused: self.stats.prefix_assertions_reused,
            assertions_added: self.stats.assertions_added,
            assertions_popped: self.stats.assertions_popped,
            resets_after_error: self.stats.resets_after_error,
        }
    }

    fn replay_sat_cache_stats(&self, path_id: u64) -> ReplayCheckedSatCacheStats {
        self.paths
            .get(&path_id)
            .map_or_else(ReplayCheckedSatCacheStats::default, |path| {
                path.solver.replay_sat_cache_stats()
            })
    }

    fn close_path(&mut self, path_id: u64) -> Option<ReplayCheckedSatCacheStats> {
        self.paths
            .remove(&path_id)
            .map(|path| path.solver.replay_sat_cache_stats())
    }
}

/// Minimal GQ9 admission state: retain only IDs until a path proves reuse.
#[derive(Debug, Default)]
struct AutoLineageAdmission {
    seen_once: BTreeSet<u64>,
}

impl AutoLineageAdmission {
    /// Returns true from the second observation onward.
    fn observe(&mut self, path_id: u64) -> bool {
        !self.seen_once.insert(path_id)
    }

    fn remove(&mut self, path_id: u64) -> bool {
        self.seen_once.remove(&path_id)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SerialLeaseRelease {
    Untracked,
    Retained,
    Final,
}

/// Reference counts for one serial DFS owner's active and queued states.
#[derive(Debug, Default)]
struct SerialWarmOwnerLeases {
    references: BTreeMap<u64, u64>,
}

impl SerialWarmOwnerLeases {
    fn share_with_children(&mut self, path_id: u64, children: u64) -> (bool, u64) {
        let newly_tracked = !self.references.contains_key(&path_id);
        let references = self.references.entry(path_id).or_insert(1);
        *references = references.saturating_add(children);
        (newly_tracked, *references)
    }

    fn release(&mut self, path_id: u64) -> SerialLeaseRelease {
        let Some(references) = self.references.get_mut(&path_id) else {
            return SerialLeaseRelease::Untracked;
        };
        *references = references.saturating_sub(1);
        if *references == 0 {
            self.references.remove(&path_id);
            SerialLeaseRelease::Final
        } else {
            SerialLeaseRelease::Retained
        }
    }
}

pub(crate) fn share_serial_warm_owner_with_children(path_id: u64, children: u64) {
    debug_assert!(children > 0);
    let (newly_tracked, references) = SERIAL_WARM_OWNER_LEASES
        .with(|leases| leases.borrow_mut().share_with_children(path_id, children));
    WARM_SERIAL_SHARE_EVENTS.fetch_add(1, Ordering::Relaxed);
    let added = if newly_tracked {
        WARM_SERIAL_TRACKED_OWNERS.fetch_add(1, Ordering::Relaxed);
        children.saturating_add(1)
    } else {
        children
    };
    let current = WARM_SERIAL_REFERENCES
        .fetch_add(added, Ordering::Relaxed)
        .saturating_add(added);
    debug_assert!(current >= references);
    WARM_SERIAL_PEAK_REFERENCES.fetch_max(current, Ordering::Relaxed);
}

fn release_serial_warm_owner(path_id: u64) -> bool {
    match SERIAL_WARM_OWNER_LEASES.with(|leases| leases.borrow_mut().release(path_id)) {
        SerialLeaseRelease::Untracked => true,
        SerialLeaseRelease::Retained => {
            WARM_SERIAL_REFERENCES.fetch_sub(1, Ordering::Relaxed);
            false
        }
        SerialLeaseRelease::Final => {
            WARM_SERIAL_REFERENCES.fetch_sub(1, Ordering::Relaxed);
            WARM_SERIAL_TRACKED_OWNERS.fetch_sub(1, Ordering::Relaxed);
            true
        }
    }
}

impl LineageIncrementalAxeyumSolver {
    fn has_path(&self, path_id: u64) -> bool {
        self.paths.contains_key(&path_id)
    }

    fn check_path(
        &mut self,
        path_id: u64,
        pool: &ExprPool,
        asserts: &[Assert],
    ) -> (
        SolveResult,
        SnapshotReuseStats,
        SnapshotReuseStats,
        ReplayCheckedSatCacheStats,
        ReplayCheckedSatCacheStats,
        bool,
    ) {
        let created = !self.paths.contains_key(&path_id);
        let create_started = (created && profile_output_dir().is_some()).then(Instant::now);
        let solver = self
            .paths
            .entry(path_id)
            .or_insert_with(SnapshotIncrementalAxeyumSolver::new_path_owned);
        let session_create_nanos = create_started.map_or(0, |started| nanos(started.elapsed()));
        let before = solver.stats();
        let cache_before = solver.replay_sat_cache_stats();
        let result = solver.check_snapshot_for_path(
            pool,
            asserts,
            Some(path_id),
            created,
            session_create_nanos,
        );
        (
            result,
            before,
            solver.stats(),
            cache_before,
            solver.replay_sat_cache_stats(),
            created,
        )
    }

    fn close_path(&mut self, path_id: u64) -> Option<ReplayCheckedSatCacheStats> {
        self.paths
            .remove(&path_id)
            .map(|solver| solver.replay_sat_cache_stats())
    }
}

/// Whether a retained snapshot-to-incremental policy is selected.
pub(crate) fn warm_reuse_enabled() -> bool {
    warm_reuse_policy() != WarmReusePolicy::Off
}

/// Checks through the selected retained worker-local adapter.
pub(crate) fn check_warm_thread_local(
    pool: &ExprPool,
    asserts: &[Assert],
    path_id: Option<u64>,
    delta: Option<WarmDeltaContext>,
) -> SolveResult {
    check_warm_thread_local_selected(
        pool,
        asserts,
        path_id,
        delta,
        warm_reuse_policy(),
        direct_delta_enabled(),
    )
}

fn check_warm_thread_local_selected(
    pool: &ExprPool,
    asserts: &[Assert],
    path_id: Option<u64>,
    delta: Option<WarmDeltaContext>,
    policy: WarmReusePolicy,
    direct_delta_requested: bool,
) -> SolveResult {
    LAST_DIRECT_DELTA_SYNCED.with(|synced| synced.set(false));
    let (result, before, after) = match policy {
        WarmReusePolicy::Off => return AxeyumSolver::new().check(pool, asserts),
        WarmReusePolicy::Snapshot => WARM_SOLVER.with(|solver| {
            let mut solver = solver.borrow_mut();
            let before = solver.stats();
            let result = solver.check_snapshot(pool, asserts);
            (result, before, solver.stats())
        }),
        policy @ (WarmReusePolicy::Lineage | WarmReusePolicy::Auto | WarmReusePolicy::Adaptive) => {
            let Some(path_id) = path_id else {
                return AxeyumSolver::new().check(pool, asserts);
            };
            let direct = direct_delta_requested && delta.is_some();
            if direct {
                let delta = delta.expect("direct mode requires an explicit delta");
                if delta.retain_assertions > delta.persistent_assertions
                    || delta.persistent_assertions > asserts.len()
                {
                    let (before, after, closed_cache) = DIRECT_DELTA_SOLVERS.with(|lineage| {
                        let mut lineage = lineage.borrow_mut();
                        let before = lineage.snapshot_stats();
                        lineage.stats.checks = lineage.stats.checks.saturating_add(1);
                        let closed_cache = lineage.close_path(path_id);
                        if closed_cache.is_some() {
                            lineage.stats.resets_after_error =
                                lineage.stats.resets_after_error.saturating_add(1);
                        }
                        (before, lineage.snapshot_stats(), closed_cache)
                    });
                    if let Some(cache) = closed_cache {
                        subtract_replay_sat_cache_gauges(cache);
                        WARM_PATHS_CLOSED.fetch_add(1, Ordering::Relaxed);
                        WARM_PATHS_LIVE.fetch_sub(1, Ordering::Relaxed);
                    }
                    record_warm_delta(before, after);
                    return SolveResult::Error(format!(
                        "invalid axeyum direct delta: retain {}, persistent {}, total {}",
                        delta.retain_assertions,
                        delta.persistent_assertions,
                        asserts.len()
                    ));
                }
            }
            let limits = warm_reuse_limits();
            if count(asserts.len()) > limits.max_assertions_per_path {
                // A serial sibling continuation may still need this owner's
                // retained prefix. The oversized active state falls back
                // one-shot, then releases its lease only at real termination.
                if !warm_serial_sibling_reuse_enabled() {
                    close_warm_path(path_id);
                }
                WARM_ASSERTION_LIMIT_FALLBACKS.fetch_add(1, Ordering::Relaxed);
                return AxeyumSolver::new().check(pool, asserts);
            }
            let exists = if direct {
                DIRECT_DELTA_SOLVERS.with(|lineage| lineage.borrow().has_path(path_id))
            } else {
                LINEAGE_SOLVERS.with(|lineage| lineage.borrow().has_path(path_id))
            };
            if policy == WarmReusePolicy::Auto && !exists {
                let repeated = AUTO_LINEAGE_ADMISSION
                    .with(|admission| admission.borrow_mut().observe(path_id));
                if !repeated {
                    WARM_AUTO_PROBES.fetch_add(1, Ordering::Relaxed);
                    return AxeyumSolver::new().check(pool, asserts);
                }
            }
            let reserved = if exists {
                false
            } else {
                let pressure = WARM_ADAPTIVE_PRESSURE_EVENTS.load(Ordering::Relaxed);
                let initial_limit = if policy == WarmReusePolicy::Adaptive {
                    adaptive_live_path_limit(limits.max_live_paths, pressure)
                } else {
                    limits.max_live_paths
                };
                if try_reserve_warm_path(initial_limit) {
                    true
                } else if policy == WarmReusePolicy::Adaptive
                    && initial_limit < limits.max_live_paths
                {
                    let pressure = WARM_ADAPTIVE_PRESSURE_EVENTS
                        .fetch_add(1, Ordering::Relaxed)
                        .saturating_add(1);
                    if pressure == ADAPTIVE_PRESSURE_THRESHOLD {
                        WARM_ADAPTIVE_EXPANSIONS.fetch_add(1, Ordering::Relaxed);
                    }
                    if pressure >= ADAPTIVE_PRESSURE_THRESHOLD
                        && try_reserve_warm_path(limits.max_live_paths)
                    {
                        true
                    } else {
                        WARM_PATH_LIMIT_FALLBACKS.fetch_add(1, Ordering::Relaxed);
                        return AxeyumSolver::new().check(pool, asserts);
                    }
                } else {
                    WARM_PATH_LIMIT_FALLBACKS.fetch_add(1, Ordering::Relaxed);
                    return AxeyumSolver::new().check(pool, asserts);
                }
            };
            if direct {
                let delta = delta.expect("direct mode requires an explicit delta");
                let persistent = &asserts[..delta.persistent_assertions];
                let temporary = &asserts[delta.persistent_assertions..];
                let (
                    result,
                    before,
                    after,
                    cache_before,
                    cache_after,
                    removed_cache,
                    created,
                    synced,
                ) = DIRECT_DELTA_SOLVERS.with(|lineage| {
                    let mut lineage = lineage.borrow_mut();
                    let created = !lineage.has_path(path_id);
                    let before = lineage.snapshot_stats();
                    let cache_before = lineage.replay_sat_cache_stats(path_id);
                    let (result, synced, removed_cache) = lineage.check_path(
                        path_id,
                        pool,
                        persistent,
                        delta.retain_assertions,
                        temporary,
                    );
                    (
                        result,
                        before,
                        lineage.snapshot_stats(),
                        cache_before,
                        removed_cache.unwrap_or_else(|| lineage.replay_sat_cache_stats(path_id)),
                        removed_cache,
                        created,
                        synced,
                    )
                });
                record_replay_sat_cache_delta(cache_before, cache_after);
                if let Some(cache) = removed_cache {
                    subtract_replay_sat_cache_gauges(cache);
                }
                debug_assert_eq!(created, reserved);
                LAST_DIRECT_DELTA_SYNCED.with(|state| state.set(synced));
                if created {
                    WARM_PATHS_CREATED.fetch_add(1, Ordering::Relaxed);
                    if policy == WarmReusePolicy::Auto {
                        AUTO_LINEAGE_ADMISSION.with(|admission| {
                            admission.borrow_mut().remove(path_id);
                        });
                        WARM_AUTO_ACTIVATIONS.fetch_add(1, Ordering::Relaxed);
                    }
                }
                if !synced {
                    WARM_PATHS_CLOSED.fetch_add(1, Ordering::Relaxed);
                    WARM_PATHS_LIVE.fetch_sub(1, Ordering::Relaxed);
                }
                (result, before, after)
            } else {
                let (result, before, after, cache_before, cache_after, created) = LINEAGE_SOLVERS
                    .with(|lineage| {
                        let mut lineage = lineage.borrow_mut();
                        lineage.check_path(path_id, pool, asserts)
                    });
                record_replay_sat_cache_delta(cache_before, cache_after);
                debug_assert_eq!(created, reserved);
                if created {
                    WARM_PATHS_CREATED.fetch_add(1, Ordering::Relaxed);
                    if policy == WarmReusePolicy::Auto {
                        AUTO_LINEAGE_ADMISSION.with(|admission| {
                            admission.borrow_mut().remove(path_id);
                        });
                        WARM_AUTO_ACTIVATIONS.fetch_add(1, Ordering::Relaxed);
                    }
                }
                (result, before, after)
            }
        }
    };
    record_warm_delta(before, after);
    result
}

fn adaptive_live_path_limit(configured: u64, pressure_events: u64) -> u64 {
    if pressure_events >= ADAPTIVE_PRESSURE_THRESHOLD {
        configured
    } else {
        configured.min(ADAPTIVE_INITIAL_LIVE_PATHS)
    }
}

fn try_reserve_warm_path(limit: u64) -> bool {
    try_reserve_path_counter(&WARM_PATHS_LIVE, &WARM_PATHS_PEAK_LIVE, limit)
}

fn try_reserve_path_counter(
    live_counter: &AtomicU64,
    peak_counter: &AtomicU64,
    limit: u64,
) -> bool {
    let mut live = live_counter.load(Ordering::Relaxed);
    loop {
        if live >= limit {
            return false;
        }
        match live_counter.compare_exchange_weak(
            live,
            live + 1,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => {
                peak_counter.fetch_max(live + 1, Ordering::Relaxed);
                return true;
            }
            Err(observed) => live = observed,
        }
    }
}

fn record_warm_delta(before: SnapshotReuseStats, after: SnapshotReuseStats) {
    WARM_CHECKS.fetch_add(
        after.checks.saturating_sub(before.checks),
        Ordering::Relaxed,
    );
    WARM_EXACT_REUSES.fetch_add(
        after
            .exact_snapshot_reuses
            .saturating_sub(before.exact_snapshot_reuses),
        Ordering::Relaxed,
    );
    WARM_PREFIX_REUSES.fetch_add(
        after
            .prefix_assertions_reused
            .saturating_sub(before.prefix_assertions_reused),
        Ordering::Relaxed,
    );
    WARM_ASSERTIONS_ADDED.fetch_add(
        after
            .assertions_added
            .saturating_sub(before.assertions_added),
        Ordering::Relaxed,
    );
    WARM_ASSERTIONS_POPPED.fetch_add(
        after
            .assertions_popped
            .saturating_sub(before.assertions_popped),
        Ordering::Relaxed,
    );
    WARM_RESETS.fetch_add(
        after
            .resets_after_error
            .saturating_sub(before.resets_after_error),
        Ordering::Relaxed,
    );
}

/// Release retained mutable state when an explorer path becomes terminal.
pub(crate) fn close_warm_path(path_id: u64) {
    if !matches!(
        warm_reuse_policy(),
        WarmReusePolicy::Lineage | WarmReusePolicy::Auto | WarmReusePolicy::Adaptive
    ) {
        return;
    }
    if !release_serial_warm_owner(path_id) {
        return;
    }
    AUTO_LINEAGE_ADMISSION.with(|admission| {
        admission.borrow_mut().remove(path_id);
    });
    close_retained_lineage_paths(path_id);
}

fn close_retained_lineage_paths(path_id: u64) {
    let snapshot_cache = LINEAGE_SOLVERS.with(|lineage| lineage.borrow_mut().close_path(path_id));
    let direct_cache =
        DIRECT_DELTA_SOLVERS.with(|lineage| lineage.borrow_mut().close_path(path_id));
    for cache in [snapshot_cache, direct_cache].into_iter().flatten() {
        subtract_replay_sat_cache_gauges(cache);
        WARM_PATHS_CLOSED.fetch_add(1, Ordering::Relaxed);
        WARM_PATHS_LIVE.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Process-wide explorer-path ownership counters for lineage warm reuse.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WarmPathReuseStats {
    /// Configured process-wide retained-session ceiling.
    pub max_live_paths: u64,
    /// Configured maximum assertion roots in one retained snapshot.
    pub max_assertions_per_path: u64,
    /// Path-owned solver sessions created lazily on first check.
    pub paths_created: u64,
    /// Path-owned solver sessions released at terminal path events.
    pub paths_closed: u64,
    /// Sessions currently retained across all explorer workers.
    pub live_paths: u64,
    /// Maximum simultaneously retained sessions observed in this process.
    pub peak_live_paths: u64,
    /// Checks sent one-shot because the process-wide live-path cap was full.
    pub path_limit_fallbacks: u64,
    /// Checks sent one-shot because their assertion snapshot exceeded the cap.
    pub assertion_limit_fallbacks: u64,
}

/// Process-wide GQ9 detected-reuse admission counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AutoLineageReuseStats {
    /// First observations solved one-shot without retaining a solver.
    pub probes: u64,
    /// Repeated paths promoted to bounded lineage sessions.
    pub activations: u64,
}

/// Process-wide counters for the bounded pressure-adaptive lineage policy.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AdaptiveLineageReuseStats {
    /// Failed reservations observed while the initial cap was active.
    pub pressure_events: u64,
    /// One-way expansions from the initial cap to the configured hard cap.
    pub expansions: u64,
    /// Initial live-session cap used before sustained pressure is observed.
    pub initial_live_paths: u64,
    /// Pressure-event count that triggers the one-way expansion.
    pub pressure_threshold: u64,
}

/// Process-wide lifecycle counters for the opt-in serial sibling lease.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SerialSiblingReuseStats {
    /// Forks that created queued sibling references to one logical owner.
    pub share_events: u64,
    /// Owners with at least one active or queued reference.
    pub tracked_owners: u64,
    /// Active plus queued references across tracked owners.
    pub references: u64,
    /// Maximum tracked references observed at once.
    pub peak_references: u64,
}

/// Returns process-wide lineage ownership counters.
pub fn warm_path_reuse_stats() -> WarmPathReuseStats {
    let limits = warm_reuse_limits();
    WarmPathReuseStats {
        max_live_paths: limits.max_live_paths,
        max_assertions_per_path: limits.max_assertions_per_path,
        paths_created: WARM_PATHS_CREATED.load(Ordering::Relaxed),
        paths_closed: WARM_PATHS_CLOSED.load(Ordering::Relaxed),
        live_paths: WARM_PATHS_LIVE.load(Ordering::Relaxed),
        peak_live_paths: WARM_PATHS_PEAK_LIVE.load(Ordering::Relaxed),
        path_limit_fallbacks: WARM_PATH_LIMIT_FALLBACKS.load(Ordering::Relaxed),
        assertion_limit_fallbacks: WARM_ASSERTION_LIMIT_FALLBACKS.load(Ordering::Relaxed),
    }
}

/// Returns process-wide detected-reuse admission counters.
pub fn auto_lineage_reuse_stats() -> AutoLineageReuseStats {
    AutoLineageReuseStats {
        probes: WARM_AUTO_PROBES.load(Ordering::Relaxed),
        activations: WARM_AUTO_ACTIVATIONS.load(Ordering::Relaxed),
    }
}

/// Returns process-wide pressure-adaptive admission counters.
pub fn adaptive_lineage_reuse_stats() -> AdaptiveLineageReuseStats {
    AdaptiveLineageReuseStats {
        pressure_events: WARM_ADAPTIVE_PRESSURE_EVENTS.load(Ordering::Relaxed),
        expansions: WARM_ADAPTIVE_EXPANSIONS.load(Ordering::Relaxed),
        initial_live_paths: ADAPTIVE_INITIAL_LIVE_PATHS,
        pressure_threshold: ADAPTIVE_PRESSURE_THRESHOLD,
    }
}

/// Returns lifecycle counters for the opt-in serial sibling lease.
pub fn serial_sibling_reuse_stats() -> SerialSiblingReuseStats {
    SerialSiblingReuseStats {
        share_events: WARM_SERIAL_SHARE_EVENTS.load(Ordering::Relaxed),
        tracked_owners: WARM_SERIAL_TRACKED_OWNERS.load(Ordering::Relaxed),
        references: WARM_SERIAL_REFERENCES.load(Ordering::Relaxed),
        peak_references: WARM_SERIAL_PEAK_REFERENCES.load(Ordering::Relaxed),
    }
}

/// Process-wide aggregate of warm snapshot reuse across explorer
/// threads. A fresh process starts all counters at zero.
pub fn warm_reuse_stats() -> SnapshotReuseStats {
    SnapshotReuseStats {
        checks: WARM_CHECKS.load(Ordering::Relaxed),
        exact_snapshot_reuses: WARM_EXACT_REUSES.load(Ordering::Relaxed),
        prefix_assertions_reused: WARM_PREFIX_REUSES.load(Ordering::Relaxed),
        assertions_added: WARM_ASSERTIONS_ADDED.load(Ordering::Relaxed),
        assertions_popped: WARM_ASSERTIONS_POPPED.load(Ordering::Relaxed),
        resets_after_error: WARM_RESETS.load(Ordering::Relaxed),
    }
}

/// Process-wide aggregate of the bounded path-owned replay-checked SAT cache.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReplaySatCacheProcessStats {
    /// Whether newly created path-owned warm solvers enable the cache.
    pub enabled: bool,
    /// Maximum exact SAT entries retained by each live path solver.
    pub max_entries_per_path: u64,
    /// Maximum scalar model values retained by each live path solver.
    pub max_model_values_per_path: u64,
    /// Maximum Bool/BV model payload bits retained by each live path solver.
    pub max_model_bits_per_path: u64,
    /// Aggregate traffic and current gauges across live path solvers.
    pub cache: ReplayCheckedSatCacheStats,
}

/// Returns cache traffic accumulated across all retained path-owned solvers.
pub fn replay_sat_cache_stats() -> ReplaySatCacheProcessStats {
    let policy = replay_sat_cache_policy();
    let mut cache = ReplayCheckedSatCacheStats::default();
    cache.hits = REPLAY_SAT_CACHE_HITS.load(Ordering::Relaxed);
    cache.misses = REPLAY_SAT_CACHE_MISSES.load(Ordering::Relaxed);
    cache.insertions = REPLAY_SAT_CACHE_INSERTIONS.load(Ordering::Relaxed);
    cache.evictions = REPLAY_SAT_CACHE_EVICTIONS.load(Ordering::Relaxed);
    cache.replay_failures = REPLAY_SAT_CACHE_REPLAY_FAILURES.load(Ordering::Relaxed);
    cache.declined_unsat = REPLAY_SAT_CACHE_DECLINED_UNSAT.load(Ordering::Relaxed);
    cache.declined_unknown = REPLAY_SAT_CACHE_DECLINED_UNKNOWN.load(Ordering::Relaxed);
    cache.declined_oversized_models =
        REPLAY_SAT_CACHE_DECLINED_OVERSIZED_MODELS.load(Ordering::Relaxed);
    cache.declined_non_scalar_models =
        REPLAY_SAT_CACHE_DECLINED_NON_SCALAR_MODELS.load(Ordering::Relaxed);
    cache.entries = REPLAY_SAT_CACHE_ENTRIES.load(Ordering::Relaxed);
    cache.model_values = REPLAY_SAT_CACHE_MODEL_VALUES.load(Ordering::Relaxed);
    cache.model_bits = REPLAY_SAT_CACHE_MODEL_BITS.load(Ordering::Relaxed);
    ReplaySatCacheProcessStats {
        enabled: policy.is_some(),
        max_entries_per_path: policy.map_or(0, |policy| count(policy.max_entries)),
        max_model_values_per_path: policy.map_or(0, |policy| count(policy.max_model_values)),
        max_model_bits_per_path: policy.map_or(0, |policy| count(policy.max_model_bits)),
        cache,
    }
}

fn record_replay_sat_cache_delta(
    before: ReplayCheckedSatCacheStats,
    after: ReplayCheckedSatCacheStats,
) {
    let monotone = [
        (&REPLAY_SAT_CACHE_HITS, before.hits, after.hits),
        (&REPLAY_SAT_CACHE_MISSES, before.misses, after.misses),
        (
            &REPLAY_SAT_CACHE_INSERTIONS,
            before.insertions,
            after.insertions,
        ),
        (
            &REPLAY_SAT_CACHE_EVICTIONS,
            before.evictions,
            after.evictions,
        ),
        (
            &REPLAY_SAT_CACHE_REPLAY_FAILURES,
            before.replay_failures,
            after.replay_failures,
        ),
        (
            &REPLAY_SAT_CACHE_DECLINED_UNSAT,
            before.declined_unsat,
            after.declined_unsat,
        ),
        (
            &REPLAY_SAT_CACHE_DECLINED_UNKNOWN,
            before.declined_unknown,
            after.declined_unknown,
        ),
        (
            &REPLAY_SAT_CACHE_DECLINED_OVERSIZED_MODELS,
            before.declined_oversized_models,
            after.declined_oversized_models,
        ),
        (
            &REPLAY_SAT_CACHE_DECLINED_NON_SCALAR_MODELS,
            before.declined_non_scalar_models,
            after.declined_non_scalar_models,
        ),
    ];
    for (counter, before, after) in monotone {
        counter.fetch_add(after.saturating_sub(before), Ordering::Relaxed);
    }
    update_replay_sat_cache_gauge(&REPLAY_SAT_CACHE_ENTRIES, before.entries, after.entries);
    update_replay_sat_cache_gauge(
        &REPLAY_SAT_CACHE_MODEL_VALUES,
        before.model_values,
        after.model_values,
    );
    update_replay_sat_cache_gauge(
        &REPLAY_SAT_CACHE_MODEL_BITS,
        before.model_bits,
        after.model_bits,
    );
}

fn update_replay_sat_cache_gauge(counter: &AtomicU64, before: u64, after: u64) {
    if after >= before {
        counter.fetch_add(after - before, Ordering::Relaxed);
    } else {
        counter.fetch_sub(before - after, Ordering::Relaxed);
    }
}

fn subtract_replay_sat_cache_gauges(stats: ReplayCheckedSatCacheStats) {
    REPLAY_SAT_CACHE_ENTRIES.fetch_sub(stats.entries, Ordering::Relaxed);
    REPLAY_SAT_CACHE_MODEL_VALUES.fetch_sub(stats.model_values, Ordering::Relaxed);
    REPLAY_SAT_CACHE_MODEL_BITS.fetch_sub(stats.model_bits, Ordering::Relaxed);
}

fn translate_query(
    pool: &ExprPool,
    asserts: &[Assert],
    arena: &mut TermArena,
) -> Result<TranslatedQuery, IrError> {
    let mut translator = Translator {
        pool,
        arena,
        memo: HashMap::new(),
        sym_map: Vec::new(),
    };
    let mut assertions = Vec::with_capacity(asserts.len());
    for &(expr, expected) in asserts {
        assertions.push(translator.translate_assert(expr, expected)?);
    }
    Ok(TranslatedQuery {
        assertions,
        exprs: translator.memo.len(),
        sym_map: translator.sym_map,
    })
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
        Ok(CheckResult::Unknown(_)) => SolveResult::Unknown,
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
        SolveResult::Unknown => "unknown",
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

/// Outcome of a proof-carrying unsat check ([`AxeyumSolver::prove_unsat`]).
#[derive(Debug)]
pub enum ProofOutcome {
    /// Unsat, with a DRAT proof that independently re-checked (RUP+RAT).
    /// `drat_lines` is the size of the refutation.
    ProvedRechecked { drat_lines: usize },
    /// Unsat with a DRAT proof that FAILED its own re-check (should never
    /// happen; surfaced rather than swallowed).
    ProvedButRecheckFailed,
    /// The query is satisfiable, so there is no unsat proof.
    Satisfiable,
    /// The proof core exhausted its budget without deciding.
    Inconclusive,
    /// Translation or proof-export error.
    Error(String),
}

impl AxeyumSolver {
    /// Produce a DRAT-checked certificate that `asserts` are unsatisfiable,
    /// then independently re-check it. This is glaurung's proof-carrying
    /// "path infeasible" evidence -- z3 cannot supply it. Kept off the
    /// `Solver` trait (ADR-006): a concrete-type method, so the shared
    /// trait and other backends are unaffected.
    ///
    /// Scope: the DRAT certifies the CNF (clausal) layer; the term->AIG->CNF
    /// reduction is trusted unless axeyum's end-to-end faithfulness miter is
    /// additionally used.
    pub fn prove_unsat(&self, pool: &ExprPool, asserts: &[Assert]) -> ProofOutcome {
        let mut arena = TermArena::new();
        let assert_terms: Vec<TermId> = {
            let mut tr = Translator {
                pool,
                arena: &mut arena,
                memo: HashMap::new(),
                sym_map: Vec::new(),
            };
            let mut terms = Vec::with_capacity(asserts.len());
            for (e, expected) in asserts {
                match tr.translate_assert(*e, *expected) {
                    Ok(t) => terms.push(t),
                    Err(err) => return ProofOutcome::Error(format!("translate: {err}")),
                }
            }
            terms
        };
        match export_qf_bv_unsat_proof(&arena, &assert_terms) {
            Ok(UnsatProofOutcome::Proved(proof)) => match proof.recheck() {
                Ok(true) => ProofOutcome::ProvedRechecked {
                    drat_lines: proof.drat.lines().count(),
                },
                Ok(false) | Err(_) => ProofOutcome::ProvedButRecheckFailed,
            },
            Ok(UnsatProofOutcome::Satisfiable) => ProofOutcome::Satisfiable,
            Ok(UnsatProofOutcome::Inconclusive) => ProofOutcome::Inconclusive,
            Err(err) => ProofOutcome::Error(err.to_string()),
        }
    }
}

/// Translates glaurung's hash-consed BV IR into `axeyum-ir` terms, memoized
/// on `ExprId` so shared subterms are built once (preserving glaurung's
/// interning into axeyum's arena). Every `Expr` node maps to an axeyum
/// `BitVec` term; Bool is touched only at the three boundaries described in
/// `docs/axeyum-integration/02-interface-mapping.md` (Cmp lift, Ite cond,
/// assert truthiness).
struct Translator<'a> {
    pool: &'a ExprPool,
    arena: &'a mut TermArena,
    memo: HashMap<ExprId, TermId>,
    sym_map: Vec<(u32, SymbolId)>,
}

impl<'a> Translator<'a> {
    /// Build the Bool assertion term for `(e, expected)`, mirroring z3's
    /// truthiness lowering: `e != 0` when expected, `e == 0` otherwise.
    fn translate_assert(&mut self, e: ExprId, expected: bool) -> Result<TermId, IrError> {
        let t = self.translate(e)?;
        let w = self.pool.width_of(e).bits() as u32;
        let zero = self.arena.bv_const(w, 0)?;
        let is_zero = self.arena.eq(t, zero)?; // Bool: e == 0
        if expected {
            self.arena.not(is_zero) // Bool: e != 0
        } else {
            Ok(is_zero)
        }
    }

    /// Translate a glaurung `ExprId` to an axeyum `BitVec` term.
    fn translate(&mut self, id: ExprId) -> Result<TermId, IrError> {
        if let Some(&t) = self.memo.get(&id) {
            return Ok(t);
        }
        // Clone the node so the immutable pool borrow is released before we
        // mutate the arena / recurse.
        let node = self.pool.get(id).clone();
        let t = match node {
            Expr::Const { value, width } => {
                let w = width.bits() as u32;
                if w > 128 {
                    self.arena.wide_bv_const(WideUint::from_u128(value, w))
                } else {
                    // Mask to width, matching glaurung's `ExprPool::constant`
                    // and z3_backend (both drop bits above the width).
                    // axeyum's `bv_const` strictly rejects an over-wide value,
                    // so masking keeps the two backends behaviorally identical.
                    let masked = if w >= 128 {
                        value
                    } else {
                        value & ((1u128 << w) - 1)
                    };
                    self.arena.bv_const(w, masked)?
                }
            }
            Expr::Sym { id: sid, width } => {
                let w = width.bits() as u32;
                let name = ExprPool::sym_name(sid, width);
                let symid = self.arena.declare(&name, Sort::BitVec(w))?;
                self.sym_map.push((sid, symid));
                self.arena.var(symid)
            }
            Expr::Bin { op, a, b, width } => {
                // Coerce both operands to the node width, exactly as
                // z3_backend does: glaurung's lifter emits width-mismatched
                // operands and relies on the solver to normalize. axeyum
                // strictly requires a shared sort, so we MUST coerce here.
                let tw = width.bits() as u32;
                let ta = self.translate_coerced(a, tw)?;
                let tb = self.translate_coerced(b, tw)?;
                match op {
                    BinOp::Add => self.arena.bv_add(ta, tb)?,
                    BinOp::Sub => self.arena.bv_sub(ta, tb)?,
                    BinOp::Mul => self.arena.bv_mul(ta, tb)?,
                    BinOp::Div => self.arena.bv_udiv(ta, tb)?, // glaurung Div is unsigned
                    BinOp::And => self.arena.bv_and(ta, tb)?,
                    BinOp::Or => self.arena.bv_or(ta, tb)?,
                    BinOp::Xor => self.arena.bv_xor(ta, tb)?,
                    BinOp::Shl => self.arena.bv_shl(ta, tb)?,
                    BinOp::Shr => self.arena.bv_lshr(ta, tb)?, // logical
                    BinOp::Sar => self.arena.bv_ashr(ta, tb)?, // arithmetic
                }
            }
            Expr::Un { op, a, .. } => {
                let ta = self.translate(a)?;
                match op {
                    UnOp::Not => self.arena.bv_not(ta)?,
                    UnOp::Neg => self.arena.bv_neg(ta)?,
                }
            }
            Expr::Cmp { op, a, b, width } => {
                // Cmp.width is the operand (comparison) width; coerce both.
                let tw = width.bits() as u32;
                let ta = self.translate_coerced(a, tw)?;
                let tb = self.translate_coerced(b, tw)?;
                let boolt = match op {
                    CmpOp::Eq => self.arena.eq(ta, tb)?,
                    CmpOp::Ne => {
                        let e = self.arena.eq(ta, tb)?;
                        self.arena.not(e)?
                    }
                    CmpOp::Ult => self.arena.bv_ult(ta, tb)?,
                    CmpOp::Ule => self.arena.bv_ule(ta, tb)?,
                    CmpOp::Slt => self.arena.bv_slt(ta, tb)?,
                    CmpOp::Sle => self.arena.bv_sle(ta, tb)?,
                };
                // Lift Bool -> BitVec(1) so it composes like glaurung expects.
                self.bv1_of_bool(boolt)?
            }
            Expr::ZExt { a, from, to } => {
                let ta = self.translate_coerced(a, from.bits() as u32)?;
                let by = (to.bits() as u32).saturating_sub(from.bits() as u32);
                self.arena.zero_ext(by, ta)?
            }
            Expr::SExt { a, from, to } => {
                let ta = self.translate_coerced(a, from.bits() as u32)?;
                let by = (to.bits() as u32).saturating_sub(from.bits() as u32);
                self.arena.sign_ext(by, ta)?
            }
            Expr::Trunc { a, to } => {
                // Ensure the source is at least `to` bits, then take low bits.
                let tw = to.bits() as u32;
                let ta = self.translate_coerced(a, tw)?;
                self.arena.extract(tw.saturating_sub(1), 0, ta)?
            }
            Expr::Extract { a, hi, lo } => {
                // glaurung's `hi` is EXCLUSIVE (result width = hi - lo, byte
                // extract of a 64-bit value is hi=64,lo=56); axeyum/SMT
                // `extract(H,L)` is INCLUSIVE. glaurung's own z3/SMT lowering
                // uses `hi - 1` as the inclusive top index -- mirror it. Also
                // ensure the source is >= hi bits wide before extracting.
                let ta = self.translate_coerced(a, hi as u32)?;
                self.arena
                    .extract((hi as u32).saturating_sub(1), lo as u32, ta)?
            }
            Expr::Concat { hi, lo, .. } => {
                let th = self.translate(hi)?;
                let tl = self.translate(lo)?;
                // SMT-LIB concat(a,b): a is the high half. glaurung Concat{hi,lo}.
                self.arena.concat(th, tl)?
            }
            Expr::Ite { c, t, e, width } => {
                let tw = width.bits() as u32;
                let bc = self.to_bool(c)?;
                let tt = self.translate_coerced(t, tw)?;
                let te = self.translate_coerced(e, tw)?;
                self.arena.ite(bc, tt, te)?
            }
        };
        self.memo.insert(id, t);
        Ok(t)
    }

    /// Translate `id`, then coerce it to `target` bits (zero-extend if
    /// narrower, truncate low bits if wider) -- mirroring z3_backend's
    /// `coerce`, so width-mismatched operands from the lifter are normalized
    /// to a shared sort before axeyum's strict builders see them.
    fn translate_coerced(&mut self, id: ExprId, target: u32) -> Result<TermId, IrError> {
        let t = self.translate(id)?;
        let cur = self.pool.width_of(id).bits() as u32;
        self.coerce(t, cur, target)
    }

    /// Coerce term `t` (currently `cur` bits) to `target` bits.
    fn coerce(&mut self, t: TermId, cur: u32, target: u32) -> Result<TermId, IrError> {
        if cur == target {
            Ok(t)
        } else if cur < target {
            self.arena.zero_ext(target - cur, t)
        } else {
            self.arena.extract(target.saturating_sub(1), 0, t)
        }
    }

    /// Lift a Bool term to a BitVec(1): `ite(b, 1, 0)`.
    fn bv1_of_bool(&mut self, b: TermId) -> Result<TermId, IrError> {
        let one = self.arena.bv_const(1, 1)?;
        let zero = self.arena.bv_const(1, 0)?;
        self.arena.ite(b, one, zero)
    }

    /// Convert a glaurung BV condition to an axeyum Bool: `c != 0`.
    fn to_bool(&mut self, c: ExprId) -> Result<TermId, IrError> {
        let tc = self.translate(c)?;
        let w = self.pool.width_of(c).bits() as u32;
        let zero = self.arena.bv_const(w, 0)?;
        let is_zero = self.arena.eq(tc, zero)?;
        self.arena.not(is_zero)
    }
}

// ---------------------------------------------------------------------------
// P1: SMT-LIB2 text-bridge backend (reference / fallback)
// ---------------------------------------------------------------------------

/// The in-process SMT-LIB2 text-bridge backend (P1).
#[derive(Debug, Default, Clone, Copy)]
pub struct AxeyumTextSolver;

impl AxeyumTextSolver {
    pub fn new() -> Self {
        Self
    }
}

impl Solver for AxeyumTextSolver {
    fn check(&mut self, pool: &ExprPool, asserts: &[Assert]) -> SolveResult {
        let (script, names) = pipe::build_script(pool, asserts);
        let cfg = config();
        match solve_smtlib(&script, &cfg) {
            Ok(outcome) => match outcome.result {
                CheckResult::Sat(_) => SolveResult::Sat(extract_model(&script, &names, &cfg)),
                CheckResult::Unsat => SolveResult::Unsat,
                CheckResult::Unknown(_) => SolveResult::Unknown,
            },
            Err(e) => SolveResult::Error(e.to_string()),
        }
    }
}

/// Recover the assignment via `get-value` (a second solve on a Sat -- a text
/// bridge inefficiency; the native backend avoids it).
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

    // ---- helpers ----------------------------------------------------------

    /// Solve `asserts` with the native backend.
    fn solve_native(pool: &ExprPool, asserts: &[Assert]) -> SolveResult {
        AxeyumSolver::new().check(pool, asserts)
    }

    fn c(p: &mut ExprPool, value: u128, w: Width) -> ExprId {
        p.intern(Expr::Const { value, width: w })
    }
    fn bin(p: &mut ExprPool, op: BinOp, a: ExprId, b: ExprId, w: Width) -> ExprId {
        p.intern(Expr::Bin { op, a, b, width: w })
    }
    fn cmp(p: &mut ExprPool, op: CmpOp, a: ExprId, b: ExprId, w: Width) -> ExprId {
        p.intern(Expr::Cmp { op, a, b, width: w })
    }

    /// Assert `pred` (a BV1) is true; expect Sat if the predicate genuinely
    /// holds, Unsat if it does not. Takes `&ExprPool` so callers can build
    /// `pred` with `&mut p` first, then check.
    fn expect_pred(p: &ExprPool, pred: ExprId, want_true: bool) {
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
    fn direct_delta_lineage_materializes_once_then_translates_only_suffixes() {
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

        let owner = 23;
        let mut lineage = DirectDeltaLineageAxeyumSolver::default();
        assert!(matches!(
            lineage
                .check_path(owner, &root, &[(below_six, true)], 0, &[])
                .0,
            SolveResult::Sat(_)
        ));
        match lineage
            .check_path(
                owner,
                &left,
                &[(below_six, true), (x_is_five, true)],
                1,
                &[],
            )
            .0
        {
            SolveResult::Sat(model) => assert_eq!(model.values.get(&0), Some(&5)),
            other => panic!("expected direct left SAT, got {other:?}"),
        }

        // Switch to the sibling prefix and use its branch condition as a true
        // one-shot assumption: one persistent scope is popped, no assumption
        // persists, and the shared base root is never translated again.
        assert_eq!(
            lineage
                .check_path(
                    owner,
                    &right,
                    &[(below_six, true)],
                    1,
                    &[(x_is_seven, true)],
                )
                .0,
            SolveResult::Unsat
        );
        assert!(matches!(
            lineage
                .check_path(owner, &right, &[(below_six, true)], 1, &[])
                .0,
            SolveResult::Sat(_)
        ));
        assert_eq!(
            lineage.stats(),
            DirectDeltaStats {
                checks: 4,
                full_materializations: 1,
                exact_reuses: 1,
                prefix_assertions_reused: 3,
                persistent_assertions_translated: 2,
                temporary_assumptions_translated: 1,
                assertions_added: 2,
                assertions_popped: 1,
                resets_after_error: 0,
            }
        );
    }

    #[test]
    fn direct_delta_lineage_fails_closed_on_impossible_prefix() {
        let mut pool = ExprPool::new();
        let x = pool.fresh_symbol(Width::W8);
        let one = c(&mut pool, 1, Width::W8);
        let x_is_one = cmp(&mut pool, CmpOp::Eq, x, one, Width::W8);
        let assertion = (x_is_one, true);
        let owner = 29;
        let mut lineage = DirectDeltaLineageAxeyumSolver::default();

        assert!(lineage.check_path(owner, &pool, &[assertion], 0, &[]).1);
        let (invalid, synced, _) = lineage.check_path(owner, &pool, &[assertion], 2, &[]);
        assert!(!synced);
        assert!(matches!(invalid, SolveResult::Error(_)));
        assert!(!lineage.paths.contains_key(&owner));

        // Missing state never applies a naked delta. It safely rematerializes
        // the complete persistent snapshot even when the caller's retain marker
        // refers to the lost owner.
        assert!(lineage.check_path(owner, &pool, &[assertion], 1, &[]).1);
        assert_eq!(
            lineage.stats(),
            DirectDeltaStats {
                checks: 3,
                full_materializations: 2,
                exact_reuses: 0,
                prefix_assertions_reused: 0,
                persistent_assertions_translated: 2,
                temporary_assumptions_translated: 0,
                assertions_added: 2,
                assertions_popped: 0,
                resets_after_error: 1,
            }
        );
    }

    #[test]
    fn lineage_incremental_isolates_sibling_solver_state() {
        let mut root = ExprPool::new();
        let x = root.fresh_symbol(Width::W32);
        let ten = c(&mut root, 10, Width::W32);
        let below_ten = cmp(&mut root, CmpOp::Ult, x, ten, Width::W32);

        let mut left = root.clone();
        let five = c(&mut left, 5, Width::W32);
        let x_is_five = cmp(&mut left, CmpOp::Eq, x, five, Width::W32);
        let mut right = root.clone();
        let seven = c(&mut right, 7, Width::W32);
        let x_is_seven = cmp(&mut right, CmpOp::Eq, x, seven, Width::W32);

        let mut lineage = LineageIncrementalAxeyumSolver::default();
        let left_snapshot = [(below_ten, true), (x_is_five, true)];
        let right_snapshot = [(below_ten, true), (x_is_seven, true)];
        assert!(matches!(
            lineage.check_path(11, &left, &left_snapshot).0,
            SolveResult::Sat(_)
        ));
        assert!(matches!(
            lineage.check_path(12, &right, &right_snapshot).0,
            SolveResult::Sat(_)
        ));
        assert!(matches!(
            lineage.check_path(11, &left, &left_snapshot).0,
            SolveResult::Sat(_)
        ));
        assert_eq!(
            lineage
                .paths
                .get(&11)
                .unwrap()
                .stats()
                .exact_snapshot_reuses,
            1
        );
        assert_eq!(
            lineage
                .paths
                .get(&12)
                .unwrap()
                .stats()
                .exact_snapshot_reuses,
            0
        );
        assert_eq!(lineage.paths.len(), 2);
        assert!(lineage.close_path(11).is_some());
        assert!(lineage.close_path(11).is_none());
        assert_eq!(lineage.paths.len(), 1);
    }

    #[test]
    fn serial_sibling_snapshots_pop_divergence_and_replay_originals() {
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

        let left_snapshot = [(below_six, true), (x_is_five, true)];
        let right_snapshot = [(below_six, true), (x_is_seven, true)];
        let mut lineage = LineageIncrementalAxeyumSolver::default();
        let owner = 19;

        match lineage.check_path(owner, &left, &left_snapshot).0 {
            SolveResult::Sat(model) => assert_eq!(model.values.get(&0), Some(&5)),
            other => panic!("expected replayed left SAT model, got {other:?}"),
        }
        assert!(matches!(
            lineage.check_path(owner, &right, &right_snapshot).0,
            SolveResult::Unsat
        ));
        assert!(matches!(
            lineage.check_path(owner, &left, &left_snapshot).0,
            SolveResult::Sat(_)
        ));

        let stats = lineage.paths.get(&owner).unwrap().stats();
        assert_eq!(stats.checks, 3);
        assert_eq!(stats.prefix_assertions_reused, 2);
        assert_eq!(stats.assertions_added, 4);
        assert_eq!(stats.assertions_popped, 2);
        assert_eq!(lineage.paths.len(), 1);
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
    fn auto_lineage_admits_only_after_same_path_repeats() {
        let mut admission = AutoLineageAdmission::default();

        assert!(!admission.observe(11));
        assert!(!admission.observe(12));
        assert!(admission.observe(11));
        assert!(admission.observe(11));
        assert!(admission.remove(11));
        assert!(!admission.observe(11));
        assert!(!admission.remove(99));
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
    fn selected_direct_delta_adapter_reuses_prefix_and_keeps_assumptions_temporary() {
        let mut pool = ExprPool::new();
        let x = pool.fresh_symbol(Width::W32);
        let six = c(&mut pool, 6, Width::W32);
        let five = c(&mut pool, 5, Width::W32);
        let seven = c(&mut pool, 7, Width::W32);
        let below_six = cmp(&mut pool, CmpOp::Ult, x, six, Width::W32);
        let x_is_five = cmp(&mut pool, CmpOp::Eq, x, five, Width::W32);
        let x_is_seven = cmp(&mut pool, CmpOp::Eq, x, seven, Width::W32);
        let owner = 0xd1ec_7de1_7a_u64;

        let check = |asserts: &[Assert], retain_assertions, persistent_assertions| {
            check_warm_thread_local_selected(
                &pool,
                asserts,
                Some(owner),
                Some(WarmDeltaContext {
                    retain_assertions,
                    persistent_assertions,
                }),
                WarmReusePolicy::Lineage,
                true,
            )
        };

        assert!(matches!(
            check(&[(below_six, true)], 0, 1),
            SolveResult::Sat(_)
        ));
        assert!(last_direct_delta_synced());

        match check(&[(below_six, true), (x_is_five, true)], 1, 2) {
            SolveResult::Sat(model) => assert_eq!(model.values.get(&0), Some(&5)),
            other => panic!("expected direct-delta SAT, got {other:?}"),
        }
        assert!(last_direct_delta_synced());

        assert_eq!(
            check(&[(below_six, true), (x_is_seven, true)], 1, 1),
            SolveResult::Unsat
        );
        assert!(last_direct_delta_synced());
        assert!(matches!(
            check(&[(below_six, true)], 1, 1),
            SolveResult::Sat(_)
        ));
        assert!(last_direct_delta_synced());

        // Backend-local validation is fail-closed even if a caller bypasses
        // `solve_for_path_delta` and supplies an impossible partition.
        assert!(matches!(
            check(&[(below_six, true)], 1, 2),
            SolveResult::Error(_)
        ));
        assert!(!last_direct_delta_synced());
        assert!(!DIRECT_DELTA_SOLVERS.with(|lineage| lineage.borrow().has_path(owner)));
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
    fn serial_owner_lease_closes_only_after_nested_continuations() {
        let mut leases = SerialWarmOwnerLeases::default();
        assert_eq!(leases.share_with_children(7, 2), (true, 3));
        assert_eq!(leases.share_with_children(7, 2), (false, 5));
        for _ in 0..4 {
            assert_eq!(leases.release(7), SerialLeaseRelease::Retained);
        }
        assert_eq!(leases.release(7), SerialLeaseRelease::Final);
        assert_eq!(leases.release(7), SerialLeaseRelease::Untracked);
        assert!(leases.references.is_empty());
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
    fn path_owned_replay_sat_cache_hits_only_exact_sat_snapshots() {
        let policy = ReplayCheckedSatCachePolicy::new(4, 16, 128);
        let mut solver = SnapshotIncrementalAxeyumSolver::with_cache_for_test(policy);
        let mut pool = ExprPool::new();
        let x = pool.fresh_symbol(Width::W8);
        let one = c(&mut pool, 1, Width::W8);
        let two = c(&mut pool, 2, Width::W8);
        let x_is_one = cmp(&mut pool, CmpOp::Eq, x, one, Width::W8);
        let x_is_two = cmp(&mut pool, CmpOp::Eq, x, two, Width::W8);

        assert!(matches!(
            solver.check_snapshot(&pool, &[(x_is_one, true)]),
            SolveResult::Sat(_)
        ));
        assert!(matches!(
            solver.check_snapshot(&pool, &[(x_is_one, true)]),
            SolveResult::Sat(_)
        ));
        assert!(matches!(
            solver.check_snapshot(&pool, &[(x_is_one, true), (x_is_two, true)]),
            SolveResult::Unsat
        ));

        let stats = solver.replay_sat_cache_stats();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 2);
        assert_eq!(stats.insertions, 1);
        assert_eq!(stats.declined_unsat, 1);
        assert_eq!(stats.replay_failures, 0);
        assert_eq!(
            SnapshotIncrementalAxeyumSolver::new().replay_sat_cache_stats(),
            ReplayCheckedSatCacheStats::default()
        );
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
    fn prove_unsat_produces_rechecked_drat() {
        // x == 5  AND  x == 6  is unsat; expect a DRAT proof that rechecks.
        let mut p = ExprPool::new();
        let w = Width::W32;
        let x = p.fresh_symbol(w);
        let five = c(&mut p, 5, w);
        let six = c(&mut p, 6, w);
        let e5 = cmp(&mut p, CmpOp::Eq, x, five, w);
        let e6 = cmp(&mut p, CmpOp::Eq, x, six, w);
        match AxeyumSolver::new().prove_unsat(&p, &[(e5, true), (e6, true)]) {
            ProofOutcome::ProvedRechecked { drat_lines } => assert!(drat_lines > 0),
            other => panic!("expected a rechecked DRAT proof, got {other:?}"),
        }
    }

    #[test]
    fn prove_unsat_reports_satisfiable() {
        // x == 5 is sat; there is no unsat proof.
        let mut p = ExprPool::new();
        let w = Width::W32;
        let x = p.fresh_symbol(w);
        let five = c(&mut p, 5, w);
        let e5 = cmp(&mut p, CmpOp::Eq, x, five, w);
        assert!(matches!(
            AxeyumSolver::new().prove_unsat(&p, &[(e5, true)]),
            ProofOutcome::Satisfiable
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
