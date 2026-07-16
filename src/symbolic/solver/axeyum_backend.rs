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

use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use axeyum_ir::{IrError, Sort, SymbolId, TermArena, TermId, Value, WideUint};
use axeyum_solver::{
    export_qf_bv_unsat_proof, solve_smtlib, solve_smtlib_get_value, CheckResult,
    IncrementalBvSolver, IncrementalBvStats, SolverConfig, UnsatProofOutcome,
};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::ir::types::{BinOp, CmpOp, UnOp};
use crate::symbolic::expr::{Expr, ExprId, ExprPool};
use crate::symbolic::solver::{pipe, Assert, Model, SolveResult, Solver};

/// Per-solve timeout, matching the z3 backend's 250 ms budget so coverage
/// and metering behave the same regardless of which backend is compiled in.
const SOLVE_TIMEOUT: Duration = Duration::from_millis(250);
const PROFILE_DIR_ENV: &str = "GLAURUNG_AXEYUM_PROFILE_DIR";
pub(crate) const WARM_REUSE_ENV: &str = "GLAURUNG_AXEYUM_WARM_REUSE";

static PROFILE_DIR: OnceLock<Option<PathBuf>> = OnceLock::new();
static PROFILE_WRITE_LOCK: Mutex<()> = Mutex::new(());
static PROFILE_SEQUENCE: AtomicU64 = AtomicU64::new(0);
static WARM_CHECKS: AtomicU64 = AtomicU64::new(0);
static WARM_EXACT_REUSES: AtomicU64 = AtomicU64::new(0);
static WARM_PREFIX_REUSES: AtomicU64 = AtomicU64::new(0);
static WARM_ASSERTIONS_ADDED: AtomicU64 = AtomicU64::new(0);
static WARM_ASSERTIONS_POPPED: AtomicU64 = AtomicU64::new(0);
static WARM_RESETS: AtomicU64 = AtomicU64::new(0);

thread_local! {
    /// One retained snapshot adapter per explorer thread. Glaurung currently
    /// submits complete assertion snapshots rather than explicit path scopes;
    /// the adapter reconstructs the common prefix and maps it to Axeyum scopes.
    static WARM_SOLVER: RefCell<SnapshotIncrementalAxeyumSolver> =
        RefCell::new(SnapshotIncrementalAxeyumSolver::new());
}

fn config() -> SolverConfig {
    SolverConfig::new().with_timeout(SOLVE_TIMEOUT)
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
        Self {
            arena: TermArena::new(),
            solver: IncrementalBvSolver::with_config(config().with_preprocess(preprocess)),
            active: Vec::new(),
            has_snapshot: false,
            preprocess,
            stats: SnapshotReuseStats::default(),
        }
    }

    /// Returns cumulative snapshot-reuse counters.
    pub fn stats(&self) -> SnapshotReuseStats {
        self.stats
    }

    fn reset_session(&mut self) {
        self.arena = TermArena::new();
        self.solver = IncrementalBvSolver::with_config(config().with_preprocess(self.preprocess));
        self.active.clear();
        self.has_snapshot = false;
        self.stats.resets_after_error = self.stats.resets_after_error.saturating_add(1);
    }

    /// Checks one complete Glaurung assertion snapshot using retained Axeyum
    /// translation, AIG, CNF, and SAT state.
    pub fn check_snapshot(&mut self, pool: &ExprPool, asserts: &[Assert]) -> SolveResult {
        let translated = match translate_query(pool, asserts, &mut self.arena) {
            Ok(translated) => translated,
            Err(err) => return SolveResult::Error(format!("axeyum translate: {err}")),
        };
        let common = self
            .active
            .iter()
            .zip(&translated.assertions)
            .take_while(|(active, next)| active == next)
            .count();

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
        for _ in 0..pop_count {
            if !self.solver.pop() {
                self.reset_session();
                return SolveResult::Error(
                    "axeyum warm snapshot scope underflow; session reset".to_string(),
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
                self.reset_session();
                return SolveResult::Error(format!("axeyum warm push: {err}"));
            }
            if let Err(err) = self.solver.assert_configured(&mut self.arena, term) {
                self.reset_session();
                return SolveResult::Error(format!("axeyum warm assert: {err}"));
            }
            self.active.push(term);
            self.stats.assertions_added = self.stats.assertions_added.saturating_add(1);
        }
        self.has_snapshot = true;

        let checked = self.solver.check(&self.arena);
        if checked.is_err() {
            self.reset_session();
        }
        map_check_result(checked, &translated.sym_map)
    }
}

/// Whether the opt-in snapshot-to-incremental adapter is selected.
pub(crate) fn warm_reuse_enabled() -> bool {
    std::env::var_os(WARM_REUSE_ENV).is_some()
}

/// Checks through the retained per-thread snapshot adapter.
pub(crate) fn check_warm_thread_local(pool: &ExprPool, asserts: &[Assert]) -> SolveResult {
    let (result, before, after) = WARM_SOLVER.with(|solver| {
        let mut solver = solver.borrow_mut();
        let before = solver.stats();
        let result = solver.check_snapshot(pool, asserts);
        (result, before, solver.stats())
    });
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
    result
}

/// Process-wide aggregate of opt-in warm snapshot reuse across explorer
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

fn write_profile_record(output_dir: &Path, profile: &AxeyumCheckProfile) -> Result<(), String> {
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
    let mut record = profile.clone();
    record.sequence = Some(PROFILE_SEQUENCE.fetch_add(1, Ordering::Relaxed));
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

    /// Convert a glaurung BV1 condition to an axeyum Bool: `c != 0`.
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
    fn profile_writer_uses_process_isolated_jsonl() {
        let mut p = ExprPool::new();
        let x = p.fresh_symbol(Width::W8);
        let seven = c(&mut p, 7, Width::W8);
        let eq = cmp(&mut p, CmpOp::Eq, x, seven, Width::W8);
        let profiled = AxeyumSolver::new().check_profiled(&p, &[(eq, true)]);
        let output = tempfile::tempdir().unwrap();

        write_profile_record(output.path(), &profiled.profile).unwrap();
        let path = output
            .path()
            .join(format!("axeyum-profile-{}.jsonl", std::process::id()));
        let contents = std::fs::read_to_string(path).unwrap();
        let records = contents.lines().collect::<Vec<_>>();

        assert_eq!(records.len(), 1);
        let record: serde_json::Value = serde_json::from_str(records[0]).unwrap();
        assert_eq!(record["query_hash"], profiled.profile.query_hash);
        assert_eq!(record["word_policy"], "raw");
        assert_eq!(record["outcome"], "sat");
        assert_eq!(record["complete"], true);
        assert_eq!(record["process_id"], std::process::id());
        assert!(record["sequence"].as_u64().is_some());
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
}
