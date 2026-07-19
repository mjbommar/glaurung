//! SMT solver layer — a pluggable [`Solver`] trait with production backends
//! plus an optional benchmark-only neutral cell.
//!
//! Per the corrected ADR-0005 (native-first), the preferred backend is the
//! **in-process native [`z3_backend::Z3Solver`]** (feature `solver-z3`, links
//! libz3) — keeping the engine self-contained rather than shelling out. The
//! [`pipe::PipeSolver`] (SMT-LIB2 over a subprocess) is a zero-build fallback
//! for environments without a linked solver. The pure-Rust Axeyum backend is
//! product-capable; the direct Bitwuzla C API is isolated behind
//! `solver-bitwuzla` solely for topology-equivalent measurements.
//!
//! All backends consume the bit-vector [`ExprPool`](crate::symbolic::ExprPool):
//! solving needs no Python and no external protocol when `solver-z3` is on.

#[cfg(feature = "solver-axeyum")]
pub mod axeyum_backend;
#[cfg(feature = "solver-bitwuzla")]
pub mod bitwuzla_backend;
pub mod pipe;
#[cfg(feature = "solver-z3")]
pub mod z3_backend;

use std::collections::BTreeMap;

use crate::symbolic::expr::{ExprId, ExprPool};

/// A satisfying assignment: free-symbol id → concrete value.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Model {
    pub values: BTreeMap<u32, u128>,
}

/// Stable reason class for a solver nondecision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SolveUnknownReason {
    /// A backend-specific deterministic work limit was exhausted.
    ResourceLimit,
    /// The cooperative wall-clock safety cap was exhausted.
    WallTimeout,
    /// The backend declined for another reason.
    Other,
}

impl SolveUnknownReason {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::ResourceLimit => "resource-limit",
            Self::WallTimeout => "wall-timeout",
            Self::Other => "other",
        }
    }
}

/// The result of a solve attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SolveResult {
    /// Satisfiable, with a model.
    Sat(Model),
    /// Unsatisfiable.
    Unsat,
    /// The solver returned `unknown`, with a stable nondecision class.
    Unknown(SolveUnknownReason),
    /// No solver backend was available (graceful no-op).
    NoSolver,
    /// The backend was available but errored (with a message).
    Error(String),
}

/// A constraint using arbitrary-width bit-vector truthiness: `expected=true`
/// requires a nonzero value, while `expected=false` requires zero.
pub type Assert = (ExprId, bool);

/// A solver backend.
pub trait Solver {
    /// Check the conjunction of `asserts` over `pool`, returning sat/unsat/etc.
    fn check(&mut self, pool: &ExprPool, asserts: &[Assert]) -> SolveResult;
}

/// A genuinely retained solver session driven by assertion deltas.
///
/// Unlike [`Solver::check`], this contract never receives the complete active
/// snapshot. Callers explicitly mutate the retained stack, then check it. A
/// session is exclusive to one explorer owner; cloning or concurrently sharing
/// mutable backend state is outside this interface.
pub trait IncrementalSolver {
    /// Add one persistent assertion to the current scope.
    fn assert(&mut self, pool: &ExprPool, assertion: Assert) -> Result<(), String>;

    /// Open a new assertion scope.
    fn push(&mut self) -> Result<(), String>;

    /// Close the latest assertion scope, returning `false` at the base scope.
    fn pop(&mut self) -> bool;

    /// Return the number of scopes above the base scope.
    fn scope_depth(&self) -> usize;

    /// Check the currently active persistent assertions.
    fn check(&mut self) -> SolveResult;

    /// Check with temporary assumptions that do not persist after this call.
    fn check_assuming(&mut self, pool: &ExprPool, assumptions: &[Assert]) -> SolveResult;
}

use std::cell::{Cell, RefCell};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

/// Default per-function solver budget: `(max_solves, max_timeouts)`. The explorer
/// bails when either is exceeded — a deterministic ceiling on solving work that
/// bounds runtime even when a function's state space (or an obfuscated function's
/// individual solves) does not. The timeout count is the obfuscation signal: a
/// function whose formulas keep timing out is abandoned cheaply.
pub const DEFAULT_SOLVER_BUDGET: (u64, u64) = (6000, 24);
/// Default per-check solver wall used by every in-process backend.
pub const DEFAULT_CHECK_TIMEOUT_MS: u64 = 250;
const MAX_CHECK_TIMEOUT_MS: u64 = 60_000;
const CHECK_TIMEOUT_ENV: &str = "GLAURUNG_CHECK_TIMEOUT_MS";
static CHECK_TIMEOUT: OnceLock<Duration> = OnceLock::new();
const Z3_RLIMIT_ENV: &str = "GLAURUNG_Z3_RLIMIT";
const AXEYUM_PROGRESS_CHECK_LIMIT_ENV: &str = "GLAURUNG_AXEYUM_PROGRESS_CHECK_LIMIT";
const BITWUZLA_TERMINATION_POLL_LIMIT_ENV: &str = "GLAURUNG_BITWUZLA_TERMINATION_POLL_LIMIT";
static SOLVER_WORK_BUDGETS: OnceLock<SolverWorkBudgets> = OnceLock::new();

/// Backend-specific deterministic per-check work limits.
///
/// The three values intentionally retain distinct names and units. Equal
/// numbers are not equal work across solvers; reproducibility is evaluated
/// within one pinned backend, while verdict/finding parity is evaluated across
/// backends.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct SolverWorkBudgets {
    pub(crate) z3_rlimit: Option<u32>,
    pub(crate) axeyum_progress_checks: Option<u64>,
    pub(crate) bitwuzla_termination_polls: Option<u64>,
}

impl SolverWorkBudgets {
    fn from_values(
        z3_rlimit: Option<&str>,
        axeyum_progress_checks: Option<&str>,
        bitwuzla_termination_polls: Option<&str>,
    ) -> Result<Self, String> {
        let z3_rlimit = parse_solver_work_budget(Z3_RLIMIT_ENV, z3_rlimit, u64::from(u32::MAX))?
            .map(|value| u32::try_from(value).expect("Z3 work budget was range-checked"));
        Ok(Self {
            z3_rlimit,
            axeyum_progress_checks: parse_solver_work_budget(
                AXEYUM_PROGRESS_CHECK_LIMIT_ENV,
                axeyum_progress_checks,
                u64::MAX,
            )?,
            bitwuzla_termination_polls: parse_solver_work_budget(
                BITWUZLA_TERMINATION_POLL_LIMIT_ENV,
                bitwuzla_termination_polls,
                u64::MAX,
            )?,
        })
    }

    pub(crate) const fn is_complete(self) -> bool {
        self.z3_rlimit.is_some()
            && self.axeyum_progress_checks.is_some()
            && self.bitwuzla_termination_polls.is_some()
    }

    pub(crate) const fn is_active(self) -> bool {
        self.z3_rlimit.is_some()
            || self.axeyum_progress_checks.is_some()
            || self.bitwuzla_termination_polls.is_some()
    }
}

fn parse_solver_work_budget(
    name: &str,
    value: Option<&str>,
    maximum: u64,
) -> Result<Option<u64>, String> {
    let Some(value) = value else {
        return Ok(None);
    };
    let limit = value
        .parse::<u64>()
        .map_err(|_| format!("{name} must be an integer from 1 to {maximum}"))?;
    if limit == 0 || limit > maximum {
        return Err(format!("{name} must be an integer from 1 to {maximum}"));
    }
    Ok(Some(limit))
}

/// Effective process-wide deterministic work limits for the native backends.
pub(crate) fn solver_work_budgets() -> SolverWorkBudgets {
    *SOLVER_WORK_BUDGETS.get_or_init(|| {
        let z3 = std::env::var(Z3_RLIMIT_ENV).ok();
        let axeyum = std::env::var(AXEYUM_PROGRESS_CHECK_LIMIT_ENV).ok();
        let bitwuzla = std::env::var(BITWUZLA_TERMINATION_POLL_LIMIT_ENV).ok();
        SolverWorkBudgets::from_values(z3.as_deref(), axeyum.as_deref(), bitwuzla.as_deref())
            .unwrap_or_else(|error| panic!("{error}"))
    })
}

fn parse_check_timeout_ms(value: Option<&str>) -> Result<u64, String> {
    let Some(value) = value else {
        return Ok(DEFAULT_CHECK_TIMEOUT_MS);
    };
    let milliseconds = value.parse::<u64>().map_err(|_| {
        format!("{CHECK_TIMEOUT_ENV} must be an integer from 1 to {MAX_CHECK_TIMEOUT_MS}")
    })?;
    if !(1..=MAX_CHECK_TIMEOUT_MS).contains(&milliseconds) {
        return Err(format!(
            "{CHECK_TIMEOUT_ENV} must be an integer from 1 to {MAX_CHECK_TIMEOUT_MS}"
        ));
    }
    Ok(milliseconds)
}

/// Effective process-wide per-check timeout shared by native solver backends.
pub fn check_timeout() -> Duration {
    *CHECK_TIMEOUT.get_or_init(|| {
        let configured = std::env::var(CHECK_TIMEOUT_ENV).ok();
        let milliseconds =
            parse_check_timeout_ms(configured.as_deref()).unwrap_or_else(|error| panic!("{error}"));
        Duration::from_millis(milliseconds)
    })
}

/// Effective process-wide per-check timeout in milliseconds.
pub fn check_timeout_ms() -> u64 {
    u64::try_from(check_timeout().as_millis()).unwrap_or(u64::MAX)
}

thread_local! {
    /// Per-thread solver-call meter, reset before each function run.
    static SOLVE_COUNT: Cell<u64> = const { Cell::new(0) };
    /// Per-thread count of solver `unknown`/timeout results.
    static TIMEOUT_COUNT: Cell<u64> = const { Cell::new(0) };
    /// Per-thread `(max_solves, max_timeouts)` budget the explorer enforces.
    static BUDGET: Cell<(u64, u64)> = const { Cell::new(DEFAULT_SOLVER_BUDGET) };
    /// Optional per-function wall-clock budget. `None` (default) means no limit —
    /// keeping the test suite deterministic; batch callers set a few seconds so a
    /// function with slow-but-not-timing-out solves still can't stall the scan.
    static TIME_BUDGET: Cell<Option<Duration>> = const { Cell::new(None) };
    /// Per-call timing for the most recent solve on this worker. Ordered-trace
    /// capture reads it immediately after `solve`; ordinary callers ignore it.
    static LAST_SOLVE_TIMING: Cell<SolveTiming> = const { Cell::new(SolveTiming::ZERO) };
    /// Explorer-owned logical path for the current solve. Only the opt-in
    /// Axeyum lineage adapter consumes this; ordinary and snapshot solves ignore it.
    static ACTIVE_WARM_PATH: Cell<Option<u64>> = const { Cell::new(None) };
    /// Explicit persistent-prefix boundary for the opt-in direct-delta Axeyum
    /// path. `persistent_assertions` partitions the full query slice from any
    /// trailing one-shot assumptions.
    static ACTIVE_WARM_DELTA: RefCell<Option<WarmDeltaContext>> = const { RefCell::new(None) };
}

/// Copy-on-write source ancestry for one explorer path's persistent assertions.
///
/// Every append creates a distinct node whose parent is the exact prior prefix;
/// forks clone only the [`Arc`]. Pointer identity therefore proves shared source
/// ancestry even when cloned expression pools later reuse the same [`ExprId`]
/// for different nodes. No hash or depth is trusted as identity.
#[derive(Debug, Clone, Default)]
pub(crate) struct WarmAssertionPrefix(Option<Arc<WarmAssertionPrefixNode>>);

#[derive(Debug)]
struct WarmAssertionPrefixNode {
    parent: Option<Arc<WarmAssertionPrefixNode>>,
    depth: usize,
}

impl WarmAssertionPrefix {
    /// Extend this path by one persistent source assertion.
    pub(crate) fn push(&mut self) {
        self.0 = Some(Arc::new(WarmAssertionPrefixNode {
            parent: self.0.clone(),
            depth: self.depth() + 1,
        }));
    }

    /// Number of persistent source assertions represented by this prefix.
    pub(crate) fn depth(&self) -> usize {
        self.0.as_ref().map_or(0, |node| node.depth)
    }

    /// Exact common-ancestor depth of two source prefixes.
    pub(crate) fn common_depth(&self, other: &Self) -> usize {
        let mut left = self.0.clone();
        let mut right = other.0.clone();
        while node_depth(&left) > node_depth(&right) {
            left = node_parent(left);
        }
        while node_depth(&right) > node_depth(&left) {
            right = node_parent(right);
        }
        loop {
            match (&left, &right) {
                (Some(left), Some(right)) if Arc::ptr_eq(left, right) => return left.depth,
                (Some(_), Some(_)) => {
                    left = node_parent(left);
                    right = node_parent(right);
                }
                _ => return 0,
            }
        }
    }
}

fn node_depth(node: &Option<Arc<WarmAssertionPrefixNode>>) -> usize {
    node.as_ref().map_or(0, |node| node.depth)
}

fn node_parent(node: Option<Arc<WarmAssertionPrefixNode>>) -> Option<Arc<WarmAssertionPrefixNode>> {
    node.and_then(|node| node.parent.clone())
}

/// Explorer-to-backend direct-delta transition for one check.
#[derive(Debug, Clone)]
pub(crate) struct WarmDeltaContext {
    pub(crate) retain_assertions: usize,
    pub(crate) persistent_assertions: usize,
    pub(crate) persistent_prefix: WarmAssertionPrefix,
}

fn active_warm_delta() -> Option<WarmDeltaContext> {
    ACTIVE_WARM_DELTA.with(|active| active.borrow().clone())
}

/// Backend-separated timing for one solver call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SolveTiming {
    pub(crate) total_nanos: u64,
    pub(crate) z3_nanos: Option<u64>,
    pub(crate) axeyum_nanos: Option<u64>,
    pub(crate) z3_outcome: Option<SolveOutcome>,
    pub(crate) axeyum_outcome: Option<SolveOutcome>,
    pub(crate) axeyum_execution: Option<AxeyumExecutionClass>,
    pub(crate) z3_cold_nanos: Option<u64>,
    pub(crate) z3_warm_nanos: Option<u64>,
    pub(crate) axeyum_cold_nanos: Option<u64>,
    pub(crate) axeyum_warm_nanos: Option<u64>,
    pub(crate) bitwuzla_cold_nanos: Option<u64>,
    pub(crate) bitwuzla_warm_nanos: Option<u64>,
    pub(crate) z3_cold_outcome: Option<SolveOutcome>,
    pub(crate) z3_warm_outcome: Option<SolveOutcome>,
    pub(crate) axeyum_cold_outcome: Option<SolveOutcome>,
    pub(crate) axeyum_warm_outcome: Option<SolveOutcome>,
    pub(crate) bitwuzla_cold_outcome: Option<SolveOutcome>,
    pub(crate) bitwuzla_warm_outcome: Option<SolveOutcome>,
    pub(crate) z3_cold_unknown_reason: Option<SolveUnknownReason>,
    pub(crate) z3_warm_unknown_reason: Option<SolveUnknownReason>,
    pub(crate) axeyum_cold_unknown_reason: Option<SolveUnknownReason>,
    pub(crate) axeyum_warm_unknown_reason: Option<SolveUnknownReason>,
    pub(crate) bitwuzla_cold_unknown_reason: Option<SolveUnknownReason>,
    pub(crate) bitwuzla_warm_unknown_reason: Option<SolveUnknownReason>,
    pub(crate) z3_warm_execution: Option<Z3ExecutionClass>,
    pub(crate) axeyum_warm_execution: Option<AxeyumExecutionClass>,
    pub(crate) bitwuzla_warm_execution: Option<BitwuzlaExecutionClass>,
}

impl SolveTiming {
    pub(crate) const ZERO: Self = Self {
        total_nanos: 0,
        z3_nanos: None,
        axeyum_nanos: None,
        z3_outcome: None,
        axeyum_outcome: None,
        axeyum_execution: None,
        z3_cold_nanos: None,
        z3_warm_nanos: None,
        axeyum_cold_nanos: None,
        axeyum_warm_nanos: None,
        bitwuzla_cold_nanos: None,
        bitwuzla_warm_nanos: None,
        z3_cold_outcome: None,
        z3_warm_outcome: None,
        axeyum_cold_outcome: None,
        axeyum_warm_outcome: None,
        bitwuzla_cold_outcome: None,
        bitwuzla_warm_outcome: None,
        z3_cold_unknown_reason: None,
        z3_warm_unknown_reason: None,
        axeyum_cold_unknown_reason: None,
        axeyum_warm_unknown_reason: None,
        bitwuzla_cold_unknown_reason: None,
        bitwuzla_warm_unknown_reason: None,
        z3_warm_execution: None,
        axeyum_warm_execution: None,
        bitwuzla_warm_execution: None,
    };
}

const fn unknown_reason(result: &SolveResult) -> Option<SolveUnknownReason> {
    match result {
        SolveResult::Unknown(reason) => Some(*reason),
        _ => None,
    }
}

/// Stable result class for one independently timed backend invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SolveOutcome {
    Sat,
    Unsat,
    Unknown,
    NoSolver,
    Error,
}

impl SolveOutcome {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Sat => "sat",
            Self::Unsat => "unsat",
            Self::Unknown => "unknown",
            Self::NoSolver => "no-solver",
            Self::Error => "error",
        }
    }
}

impl From<&SolveResult> for SolveOutcome {
    fn from(result: &SolveResult) -> Self {
        match result {
            SolveResult::Sat(_) => Self::Sat,
            SolveResult::Unsat => Self::Unsat,
            SolveResult::Unknown(_) => Self::Unknown,
            SolveResult::NoSolver => Self::NoSolver,
            SolveResult::Error(_) => Self::Error,
        }
    }
}

/// Exact Axeyum execution population for one independently timed invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AxeyumExecutionClass {
    ColdOneShot,
    WarmSnapshot,
    WarmCreated,
    WarmRetained,
    WarmTimeoutColdRetry,
    FallbackMissingPath,
    FallbackAutoProbe,
    FallbackPathCap,
    FallbackAssertionCap,
    InvalidDirectDelta,
}

impl AxeyumExecutionClass {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::ColdOneShot => "cold-one-shot",
            Self::WarmSnapshot => "warm-snapshot",
            Self::WarmCreated => "warm-created",
            Self::WarmRetained => "warm-retained",
            Self::WarmTimeoutColdRetry => "warm-timeout-cold-retry",
            Self::FallbackMissingPath => "fallback-missing-path",
            Self::FallbackAutoProbe => "fallback-auto-probe",
            Self::FallbackPathCap => "fallback-path-cap",
            Self::FallbackAssertionCap => "fallback-assertion-cap",
            Self::InvalidDirectDelta => "invalid-direct-delta",
        }
    }
}

/// Exact persistent-session population for the fair-shadow Z3 warm cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Z3ExecutionClass {
    WarmCreated,
    WarmRetained,
    FallbackMissingDelta,
    InvalidDirectDelta,
}

/// Exact neutral Bitwuzla warm execution population for one fair-shadow cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BitwuzlaExecutionClass {
    WarmCreated,
    WarmRetained,
    FallbackMissingDelta,
    InvalidDirectDelta,
}

impl BitwuzlaExecutionClass {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::WarmCreated => "warm-created",
            Self::WarmRetained => "warm-retained",
            Self::FallbackMissingDelta => "fallback-missing-delta",
            Self::InvalidDirectDelta => "invalid-direct-delta",
        }
    }
}

impl Z3ExecutionClass {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::WarmCreated => "warm-created",
            Self::WarmRetained => "warm-retained",
            Self::FallbackMissingDelta => "fallback-missing-delta",
            Self::InvalidDirectDelta => "invalid-direct-delta",
        }
    }
}

/// Timing for the immediately preceding [`solve`] call on this worker.
pub(crate) fn last_solve_timing() -> SolveTiming {
    LAST_SOLVE_TIMING.with(Cell::get)
}

/// Whether the opt-in fair cold/warm diagnostic is active.
///
/// It emits the legacy four cells without `solver-bitwuzla` and the neutral
/// six-cell extension when all three in-process backends are compiled.
pub(crate) fn fair_shadow_enabled() -> bool {
    #[cfg(all(feature = "solver-z3", feature = "solver-axeyum"))]
    {
        std::env::var_os("GLAURUNG_FAIR_SHADOW").is_some()
    }
    #[cfg(not(all(feature = "solver-z3", feature = "solver-axeyum")))]
    {
        false
    }
}

/// Set (or clear) the per-thread per-function wall-clock budget.
pub fn set_time_budget(d: Option<Duration>) {
    TIME_BUDGET.with(|c| c.set(d));
}

/// The current per-thread per-function wall-clock budget.
pub fn time_budget() -> Option<Duration> {
    TIME_BUDGET.with(Cell::get)
}

/// Reset the per-thread solver counters (call before exploring a function).
pub fn reset_solver_meter() {
    SOLVE_COUNT.with(|c| c.set(0));
    TIMEOUT_COUNT.with(|c| c.set(0));
}

// ---------------------------------------------------------------------------
// Cross-run solver-cost instrumentation (benchmarking; not reset per function).
//
// The per-thread meters above are reset before each function; these global
// atomics accumulate across an entire analysis run so a benchmark can attribute
// wall-clock to the solver specifically (isolating it from lifting/CFG cost).
// Thread-safe so parallel scanning is counted correctly.
// ---------------------------------------------------------------------------

use std::sync::atomic::{AtomicU64, Ordering};

static TOTAL_SOLVE_COUNT: AtomicU64 = AtomicU64::new(0);
static TOTAL_SOLVE_NANOS: AtomicU64 = AtomicU64::new(0);

/// Reset the cross-run solver-cost accumulators. Call once before a run.
pub fn reset_total_solver_stats() {
    TOTAL_SOLVE_COUNT.store(0, Ordering::Relaxed);
    TOTAL_SOLVE_NANOS.store(0, Ordering::Relaxed);
}

/// `(total_solves, total_solver_nanos)` since the last reset -- the time spent
/// inside the solver backend across the whole run.
pub fn total_solver_stats() -> (u64, u64) {
    (
        TOTAL_SOLVE_COUNT.load(Ordering::Relaxed),
        TOTAL_SOLVE_NANOS.load(Ordering::Relaxed),
    )
}

// Real-query corpus capture (for axeyum's GQ1/GQ10 client-performance lane).
// When GLAURUNG_DUMP_QUERIES=<dir> is set (build with solver-z3, the trusted
// oracle), every DECIDED query is written once as `<sha256>.smt2` and its
// trusted verdict appended to `index.tsv`. Deduplicated by content hash so the
// pack is the distinct real-formula distribution, not 13k near-duplicates.
#[cfg(feature = "solver-z3")]
fn maybe_dump_query(pool: &ExprPool, asserts: &[Assert], result: &SolveResult) {
    use sha2::{Digest, Sha256};
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::sync::{Mutex, OnceLock};

    static DIR: OnceLock<Option<PathBuf>> = OnceLock::new();
    static SEEN: OnceLock<Mutex<HashMap<[u8; 32], &'static str>>> = OnceLock::new();

    let dir = DIR.get_or_init(|| std::env::var_os("GLAURUNG_DUMP_QUERIES").map(PathBuf::from));
    let Some(dir) = dir.as_ref() else { return };

    // Only capture decided queries with a trusted sat/unsat verdict.
    let verdict = match result {
        SolveResult::Sat(_) => "sat",
        SolveResult::Unsat => "unsat",
        _ => return,
    };

    let (script, _names) = pipe::build_script(pool, asserts);
    let hash: [u8; 32] = Sha256::digest(script.as_bytes()).into();
    let hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();

    // Serialize same-process publication so a query is indexed only after its
    // complete bytes are visible. Separate capture processes may append the same
    // row; the strict corpus builder reconciles duplicates and rejects verdict
    // conflicts before producing a manifest.
    let seen = SEEN.get_or_init(|| Mutex::new(HashMap::new()));
    let mut seen = seen.lock().unwrap();
    if let Some(previous) = seen.get(&hash) {
        if *previous != verdict {
            // Preserve the contradictory observation in the index so strict
            // ingestion fails closed instead of hiding oracle instability.
            if let Err(error) = append_capture_index(dir, &hex, verdict) {
                eprintln!("[glaurung-capture] failed to record verdict conflict: {error}");
            }
            eprintln!("[glaurung-capture] conflicting verdict for {hex}: {previous} vs {verdict}");
        }
        return;
    }

    if let Err(error) = publish_query_file(dir, &hex, script.as_bytes())
        .and_then(|()| append_capture_index(dir, &hex, verdict))
    {
        eprintln!("[glaurung-capture] failed to publish {hex}: {error}");
        return;
    }
    seen.insert(hash, verdict);
}

fn shadow_result_class(result: &SolveResult) -> &'static str {
    match result {
        SolveResult::Sat(_) => "sat",
        SolveResult::Unsat => "unsat",
        SolveResult::Unknown(_) => "unknown",
        SolveResult::NoSolver => "no-solver",
        SolveResult::Error(_) => "error",
    }
}

fn should_capture_shadow_split(z3: &SolveResult, axeyum: &SolveResult) -> bool {
    fn decided(result: &SolveResult) -> bool {
        matches!(result, SolveResult::Sat(_) | SolveResult::Unsat)
    }
    fn nondecided(result: &SolveResult) -> bool {
        matches!(result, SolveResult::Unknown(_) | SolveResult::Error(_))
    }

    (decided(z3) && nondecided(axeyum)) || (nondecided(z3) && decided(axeyum))
}

/// Persist exact SMT-LIB bytes only when one shadow backend decides and the
/// other returns `Unknown`/`Error`. This diagnostic path is fully opt-in and
/// does not tax ordinary or verdict-agreeing solves.
#[cfg(all(feature = "solver-z3", feature = "solver-axeyum"))]
fn maybe_dump_shadow_split(
    pool: &ExprPool,
    asserts: &[Assert],
    z3: &SolveResult,
    axeyum: &SolveResult,
) {
    use sha2::{Digest, Sha256};
    use std::collections::HashSet;
    use std::path::PathBuf;
    use std::sync::{Mutex, OnceLock};

    type ShadowSplitIdentity = ([u8; 32], &'static str, &'static str);
    type ShadowSplitSet = HashSet<ShadowSplitIdentity>;

    static DIR: OnceLock<Option<PathBuf>> = OnceLock::new();
    static SEEN: OnceLock<Mutex<ShadowSplitSet>> = OnceLock::new();

    if !should_capture_shadow_split(z3, axeyum) {
        return;
    }
    let dir =
        DIR.get_or_init(|| std::env::var_os("GLAURUNG_DUMP_SHADOW_SPLITS").map(PathBuf::from));
    let Some(dir) = dir.as_ref() else { return };

    let (script, _names) = pipe::build_script(pool, asserts);
    let hash: [u8; 32] = Sha256::digest(script.as_bytes()).into();
    let z3_class = shadow_result_class(z3);
    let axeyum_class = shadow_result_class(axeyum);
    let identity = (hash, z3_class, axeyum_class);
    let seen = SEEN.get_or_init(|| Mutex::new(HashSet::new()));
    let mut seen = seen.lock().unwrap();
    if seen.contains(&identity) {
        return;
    }
    let hex: String = hash.iter().map(|byte| format!("{byte:02x}")).collect();
    if let Err(error) =
        publish_shadow_split_bytes(dir, &hex, script.as_bytes(), z3_class, axeyum_class)
    {
        eprintln!("[glaurung-shadow-split] failed to publish {hex}: {error}");
        return;
    }
    seen.insert(identity);
}

#[cfg(feature = "solver-z3")]
fn publish_shadow_split_bytes(
    dir: &std::path::Path,
    hex: &str,
    script: &[u8],
    z3_class: &str,
    axeyum_class: &str,
) -> std::io::Result<()> {
    publish_query_file(dir, hex, script)
        .and_then(|()| append_shadow_split_index(dir, hex, z3_class, axeyum_class))
}

#[cfg(feature = "solver-z3")]
fn append_shadow_split_index(
    dir: &std::path::Path,
    hex: &str,
    z3_class: &str,
    axeyum_class: &str,
) -> std::io::Result<()> {
    use std::io::Write;

    let mut index = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("shadow-splits.tsv"))?;
    writeln!(index, "{hex}\t{z3_class}\t{axeyum_class}")
}

#[cfg(feature = "solver-z3")]
fn publish_query_file(dir: &std::path::Path, hex: &str, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::{Error, ErrorKind, Write};
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    std::fs::create_dir_all(dir)?;
    let destination = dir.join(format!("{hex}.smt2"));
    match std::fs::read(&destination) {
        Ok(existing) if existing == bytes => return Ok(()),
        Ok(_) => {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("existing query bytes do not match content hash {hex}"),
            ));
        }
        Err(error) if error.kind() != ErrorKind::NotFound => return Err(error),
        Err(_) => {}
    }

    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary = dir.join(format!(".{hex}.{}.{}.tmp", std::process::id(), sequence));
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)?;
    if let Err(error) = file.write_all(bytes) {
        let _ = std::fs::remove_file(&temporary);
        return Err(error);
    }
    drop(file);

    match std::fs::hard_link(&temporary, &destination) {
        Ok(()) => {
            std::fs::remove_file(&temporary)?;
            Ok(())
        }
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {
            std::fs::remove_file(&temporary)?;
            let existing = std::fs::read(&destination)?;
            if existing == bytes {
                Ok(())
            } else {
                Err(Error::new(
                    ErrorKind::InvalidData,
                    format!("concurrent query bytes do not match content hash {hex}"),
                ))
            }
        }
        Err(error) => {
            let _ = std::fs::remove_file(&temporary);
            Err(error)
        }
    }
}

#[cfg(feature = "solver-z3")]
fn append_capture_index(dir: &std::path::Path, hex: &str, verdict: &str) -> std::io::Result<()> {
    use std::io::Write;

    let row = format!("{hex}\t{verdict}\n");
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("index.tsv"))?;
    file.write_all(row.as_bytes())
}

// Shadow differential: when both backends are compiled and
// GLAURUNG_SHADOW_DIFF is set, every solve runs BOTH and records whether the
// sat/unsat verdicts agree (unknowns tolerated). z3 stays authoritative so
// exploration is deterministic. This tests verdict parity on the REAL query
// stream (paper claim C1) independent of model-choice divergence.
#[cfg(all(feature = "solver-z3", feature = "solver-axeyum"))]
static SHADOW_AGREE: AtomicU64 = AtomicU64::new(0);
#[cfg(all(feature = "solver-z3", feature = "solver-axeyum"))]
static SHADOW_DISAGREE: AtomicU64 = AtomicU64::new(0);
#[cfg(all(feature = "solver-z3", feature = "solver-axeyum"))]
static SHADOW_Z3_NANOS: AtomicU64 = AtomicU64::new(0);
#[cfg(all(feature = "solver-z3", feature = "solver-axeyum"))]
static SHADOW_AX_NANOS: AtomicU64 = AtomicU64::new(0);
#[cfg(all(feature = "solver-z3", feature = "solver-axeyum"))]
static FAIR_SHADOW_SEQUENCE: AtomicU64 = AtomicU64::new(0);
// Model-divergence counters: of the queries where BOTH backends return Sat,
// how many returned a DIFFERENT satisfying model. This directly measures the
// mechanism behind finding divergence (model-based concretization), distinct
// from verdict agreement.
#[cfg(all(feature = "solver-z3", feature = "solver-axeyum"))]
static SHADOW_BOTH_SAT: AtomicU64 = AtomicU64::new(0);
#[cfg(all(feature = "solver-z3", feature = "solver-axeyum"))]
static SHADOW_MODEL_DIFF: AtomicU64 = AtomicU64::new(0);
// Unknown/timeout divergence: a query one backend DECIDES (sat/unsat) but the
// other returns Unknown (e.g. z3 hitting its 250ms per-solve timeout where
// fast axeyum decides). This is a real behavioral divergence that steers
// exploration even though it is not a sat-vs-unsat disagreement.
#[cfg(all(feature = "solver-z3", feature = "solver-axeyum"))]
static SHADOW_Z3_UNK: AtomicU64 = AtomicU64::new(0);
#[cfg(all(feature = "solver-z3", feature = "solver-axeyum"))]
static SHADOW_AX_UNK: AtomicU64 = AtomicU64::new(0);
#[cfg(all(feature = "solver-z3", feature = "solver-axeyum"))]
static SHADOW_UNK_SPLIT: AtomicU64 = AtomicU64::new(0);

/// `(z3_unknown, axeyum_unknown, one_unknown_other_decided)`.
#[cfg(all(feature = "solver-z3", feature = "solver-axeyum"))]
pub fn shadow_unknown_stats() -> (u64, u64, u64) {
    (
        SHADOW_Z3_UNK.load(Ordering::Relaxed),
        SHADOW_AX_UNK.load(Ordering::Relaxed),
        SHADOW_UNK_SPLIT.load(Ordering::Relaxed),
    )
}

/// `(both_sat, model_diff)`: of queries both backends found satisfiable, how
/// many returned different models. High `model_diff` explains finding
/// divergence without any verdict disagreement.
#[cfg(all(feature = "solver-z3", feature = "solver-axeyum"))]
pub fn shadow_model_stats() -> (u64, u64) {
    (
        SHADOW_BOTH_SAT.load(Ordering::Relaxed),
        SHADOW_MODEL_DIFF.load(Ordering::Relaxed),
    )
}

/// Shadow-differential stats on the IDENTICAL query stream:
/// `(agreements, confident_disagreements, z3_total_nanos, axeyum_total_nanos)`.
/// z3 and axeyum solve the same queries, so the two nanos are directly
/// comparable (apples-to-apples, unlike two divergent single-backend runs).
#[cfg(all(feature = "solver-z3", feature = "solver-axeyum"))]
pub fn shadow_diff_stats() -> (u64, u64, u64, u64) {
    (
        SHADOW_AGREE.load(Ordering::Relaxed),
        SHADOW_DISAGREE.load(Ordering::Relaxed),
        SHADOW_Z3_NANOS.load(Ordering::Relaxed),
        SHADOW_AX_NANOS.load(Ordering::Relaxed),
    )
}

/// `(solves, timeouts)` issued on this thread since the last [`reset_solver_meter`].
pub fn solver_meter() -> (u64, u64) {
    (SOLVE_COUNT.with(Cell::get), TIMEOUT_COUNT.with(Cell::get))
}

/// Set the per-thread `(max_solves, max_timeouts)` budget the explorer enforces.
/// Lower it to scan large/obfuscated corpora faster (at some coverage cost).
pub fn set_solver_budget(max_solves: u64, max_timeouts: u64) {
    BUDGET.with(|b| b.set((max_solves, max_timeouts)));
}

/// The current per-thread solver budget.
pub fn solver_budget() -> (u64, u64) {
    BUDGET.with(Cell::get)
}

/// Solve using the best backend compiled in: native z3 when available
/// (`solver-z3`), otherwise the SMT-LIB pipe fallback. Every call is metered (see
/// [`solver_meter`]) so the explorer can bound total solving work.
pub fn solve(pool: &ExprPool, asserts: &[Assert]) -> SolveResult {
    SOLVE_COUNT.with(|c| c.set(c.get() + 1));
    let total_started = std::time::Instant::now();
    // Shadow-differential mode: run both backends, record verdict agreement,
    // return z3 authoritatively. Diagnostic only (env-gated).
    #[cfg(all(feature = "solver-z3", feature = "solver-axeyum"))]
    {
        if fair_shadow_enabled() {
            let cell_count = if cfg!(feature = "solver-bitwuzla") {
                6
            } else {
                4
            };
            let rotation = FAIR_SHADOW_SEQUENCE.fetch_add(1, Ordering::Relaxed) % cell_count;
            let mut z3_cold = None;
            let mut z3_warm = None;
            let mut axeyum_cold = None;
            let mut axeyum_warm = None;
            #[cfg(feature = "solver-bitwuzla")]
            let mut bitwuzla_cold = None;
            #[cfg(feature = "solver-bitwuzla")]
            let mut bitwuzla_warm = None;
            let mut z3_cold_nanos = 0;
            let mut z3_warm_nanos = 0;
            let mut axeyum_cold_nanos = 0;
            let mut axeyum_warm_nanos = 0;
            #[cfg(feature = "solver-bitwuzla")]
            let mut bitwuzla_cold_nanos = 0;
            #[cfg(feature = "solver-bitwuzla")]
            let mut bitwuzla_warm_nanos = 0;
            let mut z3_warm_execution = None;
            let mut axeyum_warm_execution = None;
            #[cfg(feature = "solver-bitwuzla")]
            let mut bitwuzla_warm_execution = None;
            for offset in 0..cell_count {
                match (rotation + offset) % cell_count {
                    0 => {
                        let started = std::time::Instant::now();
                        z3_cold = Some(z3_backend::Z3Solver::new().check(pool, asserts));
                        z3_cold_nanos = started.elapsed().as_nanos() as u64;
                    }
                    1 => {
                        let started = std::time::Instant::now();
                        let (result, execution) = z3_backend::check_warm_thread_local(
                            pool,
                            asserts,
                            ACTIVE_WARM_PATH.with(Cell::get),
                            active_warm_delta(),
                        );
                        z3_warm = Some(result);
                        z3_warm_execution = Some(execution);
                        z3_warm_nanos = started.elapsed().as_nanos() as u64;
                    }
                    2 => {
                        let started = std::time::Instant::now();
                        axeyum_cold =
                            Some(axeyum_backend::AxeyumSolver::new().check(pool, asserts));
                        axeyum_cold_nanos = started.elapsed().as_nanos() as u64;
                    }
                    3 => {
                        let started = std::time::Instant::now();
                        let (result, execution) = axeyum_backend::check_fair_warm_thread_local(
                            pool,
                            asserts,
                            ACTIVE_WARM_PATH.with(Cell::get),
                            active_warm_delta(),
                        );
                        axeyum_warm = Some(result);
                        axeyum_warm_execution = Some(execution);
                        axeyum_warm_nanos = started.elapsed().as_nanos() as u64;
                    }
                    #[cfg(feature = "solver-bitwuzla")]
                    4 => {
                        let started = std::time::Instant::now();
                        bitwuzla_cold =
                            Some(bitwuzla_backend::BitwuzlaSolver::new().check(pool, asserts));
                        bitwuzla_cold_nanos = started.elapsed().as_nanos() as u64;
                    }
                    #[cfg(feature = "solver-bitwuzla")]
                    5 => {
                        let started = std::time::Instant::now();
                        let (result, execution) = bitwuzla_backend::check_warm_thread_local(
                            pool,
                            asserts,
                            ACTIVE_WARM_PATH.with(Cell::get),
                            active_warm_delta(),
                        );
                        bitwuzla_warm = Some(result);
                        bitwuzla_warm_execution = Some(execution);
                        bitwuzla_warm_nanos = started.elapsed().as_nanos() as u64;
                    }
                    _ => unreachable!("fair-shadow cell index is bounded"),
                }
            }
            let rz = z3_cold.expect("fair-shadow rotation runs cold Z3 exactly once");
            let rzw = z3_warm.expect("fair-shadow rotation runs warm Z3 exactly once");
            let rac = axeyum_cold.expect("fair-shadow rotation runs cold Axeyum exactly once");
            let raw = axeyum_warm.expect("fair-shadow rotation runs warm Axeyum exactly once");
            #[cfg(feature = "solver-bitwuzla")]
            let rbc = bitwuzla_cold
                .expect("neutral fair-shadow rotation runs cold Bitwuzla exactly once");
            #[cfg(feature = "solver-bitwuzla")]
            let rbw = bitwuzla_warm
                .expect("neutral fair-shadow rotation runs warm Bitwuzla exactly once");

            let same = matches!(
                (&rz, &raw),
                (SolveResult::Sat(_), SolveResult::Sat(_))
                    | (SolveResult::Unsat, SolveResult::Unsat)
            );
            let nondecided = [&rz, &raw]
                .into_iter()
                .any(|result| matches!(result, SolveResult::Unknown(_) | SolveResult::Error(_)));
            if same || nondecided {
                SHADOW_AGREE.fetch_add(1, Ordering::Relaxed);
            } else {
                SHADOW_DISAGREE.fetch_add(1, Ordering::Relaxed);
            }
            if let (SolveResult::Sat(z3_model), SolveResult::Sat(axeyum_model)) = (&rz, &raw) {
                SHADOW_BOTH_SAT.fetch_add(1, Ordering::Relaxed);
                if z3_model.values != axeyum_model.values {
                    SHADOW_MODEL_DIFF.fetch_add(1, Ordering::Relaxed);
                }
            }
            let z3_nondecided = matches!(rz, SolveResult::Unknown(_) | SolveResult::Error(_));
            let axeyum_nondecided = matches!(raw, SolveResult::Unknown(_) | SolveResult::Error(_));
            if z3_nondecided {
                SHADOW_Z3_UNK.fetch_add(1, Ordering::Relaxed);
            }
            if axeyum_nondecided {
                SHADOW_AX_UNK.fetch_add(1, Ordering::Relaxed);
            }
            if z3_nondecided != axeyum_nondecided {
                SHADOW_UNK_SPLIT.fetch_add(1, Ordering::Relaxed);
            }
            SHADOW_Z3_NANOS.fetch_add(z3_cold_nanos, Ordering::Relaxed);
            SHADOW_AX_NANOS.fetch_add(axeyum_warm_nanos, Ordering::Relaxed);
            maybe_dump_shadow_split(pool, asserts, &rz, &raw);
            LAST_SOLVE_TIMING.with(|timing| {
                timing.set(SolveTiming {
                    total_nanos: total_started.elapsed().as_nanos() as u64,
                    // Backward-compatible aliases retain the original paired
                    // population: cold Z3 versus selected warm Axeyum.
                    z3_nanos: Some(z3_cold_nanos),
                    axeyum_nanos: Some(axeyum_warm_nanos),
                    z3_outcome: Some(SolveOutcome::from(&rz)),
                    axeyum_outcome: Some(SolveOutcome::from(&raw)),
                    axeyum_execution: axeyum_warm_execution,
                    z3_cold_nanos: Some(z3_cold_nanos),
                    z3_warm_nanos: Some(z3_warm_nanos),
                    axeyum_cold_nanos: Some(axeyum_cold_nanos),
                    axeyum_warm_nanos: Some(axeyum_warm_nanos),
                    bitwuzla_cold_nanos: {
                        #[cfg(feature = "solver-bitwuzla")]
                        {
                            Some(bitwuzla_cold_nanos)
                        }
                        #[cfg(not(feature = "solver-bitwuzla"))]
                        {
                            None
                        }
                    },
                    bitwuzla_warm_nanos: {
                        #[cfg(feature = "solver-bitwuzla")]
                        {
                            Some(bitwuzla_warm_nanos)
                        }
                        #[cfg(not(feature = "solver-bitwuzla"))]
                        {
                            None
                        }
                    },
                    z3_cold_outcome: Some(SolveOutcome::from(&rz)),
                    z3_warm_outcome: Some(SolveOutcome::from(&rzw)),
                    axeyum_cold_outcome: Some(SolveOutcome::from(&rac)),
                    axeyum_warm_outcome: Some(SolveOutcome::from(&raw)),
                    bitwuzla_cold_outcome: {
                        #[cfg(feature = "solver-bitwuzla")]
                        {
                            Some(SolveOutcome::from(&rbc))
                        }
                        #[cfg(not(feature = "solver-bitwuzla"))]
                        {
                            None
                        }
                    },
                    bitwuzla_warm_outcome: {
                        #[cfg(feature = "solver-bitwuzla")]
                        {
                            Some(SolveOutcome::from(&rbw))
                        }
                        #[cfg(not(feature = "solver-bitwuzla"))]
                        {
                            None
                        }
                    },
                    z3_cold_unknown_reason: unknown_reason(&rz),
                    z3_warm_unknown_reason: unknown_reason(&rzw),
                    axeyum_cold_unknown_reason: unknown_reason(&rac),
                    axeyum_warm_unknown_reason: unknown_reason(&raw),
                    bitwuzla_cold_unknown_reason: {
                        #[cfg(feature = "solver-bitwuzla")]
                        {
                            unknown_reason(&rbc)
                        }
                        #[cfg(not(feature = "solver-bitwuzla"))]
                        {
                            None
                        }
                    },
                    bitwuzla_warm_unknown_reason: {
                        #[cfg(feature = "solver-bitwuzla")]
                        {
                            unknown_reason(&rbw)
                        }
                        #[cfg(not(feature = "solver-bitwuzla"))]
                        {
                            None
                        }
                    },
                    z3_warm_execution,
                    axeyum_warm_execution,
                    bitwuzla_warm_execution: {
                        #[cfg(feature = "solver-bitwuzla")]
                        {
                            bitwuzla_warm_execution
                        }
                        #[cfg(not(feature = "solver-bitwuzla"))]
                        {
                            None
                        }
                    },
                });
            });
            return rz;
        }
        if std::env::var_os("GLAURUNG_SHADOW_DIFF").is_some() {
            // Time each backend on the SAME query for an apples-to-apples
            // comparison. Alternate order per call to cancel warm-cache bias.
            let z3_first = SHADOW_AGREE.load(Ordering::Relaxed) % 2 == 0;
            let (rz, ra, z3_nanos, axeyum_nanos, axeyum_execution);
            if z3_first {
                let t = std::time::Instant::now();
                rz = z3_backend::Z3Solver::new().check(pool, asserts);
                z3_nanos = t.elapsed().as_nanos() as u64;
                SHADOW_Z3_NANOS.fetch_add(z3_nanos, Ordering::Relaxed);
                let t = std::time::Instant::now();
                (ra, axeyum_execution) = if axeyum_backend::warm_reuse_enabled() {
                    axeyum_backend::check_warm_thread_local(
                        pool,
                        asserts,
                        ACTIVE_WARM_PATH.with(Cell::get),
                        active_warm_delta(),
                    )
                } else {
                    (
                        axeyum_backend::AxeyumSolver::new().check(pool, asserts),
                        AxeyumExecutionClass::ColdOneShot,
                    )
                };
                axeyum_nanos = t.elapsed().as_nanos() as u64;
                SHADOW_AX_NANOS.fetch_add(axeyum_nanos, Ordering::Relaxed);
            } else {
                let t = std::time::Instant::now();
                (ra, axeyum_execution) = if axeyum_backend::warm_reuse_enabled() {
                    axeyum_backend::check_warm_thread_local(
                        pool,
                        asserts,
                        ACTIVE_WARM_PATH.with(Cell::get),
                        active_warm_delta(),
                    )
                } else {
                    (
                        axeyum_backend::AxeyumSolver::new().check(pool, asserts),
                        AxeyumExecutionClass::ColdOneShot,
                    )
                };
                axeyum_nanos = t.elapsed().as_nanos() as u64;
                SHADOW_AX_NANOS.fetch_add(axeyum_nanos, Ordering::Relaxed);
                let t = std::time::Instant::now();
                rz = z3_backend::Z3Solver::new().check(pool, asserts);
                z3_nanos = t.elapsed().as_nanos() as u64;
                SHADOW_Z3_NANOS.fetch_add(z3_nanos, Ordering::Relaxed);
            }
            let unknown = matches!(rz, SolveResult::Unknown(_))
                || matches!(ra, SolveResult::Unknown(_))
                || matches!(rz, SolveResult::Error(_))
                || matches!(ra, SolveResult::Error(_));
            let same = matches!(
                (&rz, &ra),
                (SolveResult::Sat(_), SolveResult::Sat(_))
                    | (SolveResult::Unsat, SolveResult::Unsat)
            );
            if unknown || same {
                SHADOW_AGREE.fetch_add(1, Ordering::Relaxed);
            } else {
                SHADOW_DISAGREE.fetch_add(1, Ordering::Relaxed);
            }
            if let (SolveResult::Sat(mz), SolveResult::Sat(ma)) = (&rz, &ra) {
                SHADOW_BOTH_SAT.fetch_add(1, Ordering::Relaxed);
                if mz.values != ma.values {
                    SHADOW_MODEL_DIFF.fetch_add(1, Ordering::Relaxed);
                }
            }
            // Diagnostic: print the first few axeyum non-decided reasons so
            // we know WHY (Unknown budget vs Error translation) it punts.
            if matches!(ra, SolveResult::Unknown(_) | SolveResult::Error(_))
                && SHADOW_AX_UNK.load(Ordering::Relaxed) < 5
            {
                eprintln!(
                    "[ax-nondecided #{}] {:?}",
                    SHADOW_AX_UNK.load(Ordering::Relaxed),
                    ra
                );
            }
            let z3_unk = matches!(rz, SolveResult::Unknown(_) | SolveResult::Error(_));
            let ax_unk = matches!(ra, SolveResult::Unknown(_) | SolveResult::Error(_));
            if z3_unk {
                SHADOW_Z3_UNK.fetch_add(1, Ordering::Relaxed);
            }
            if ax_unk {
                SHADOW_AX_UNK.fetch_add(1, Ordering::Relaxed);
            }
            if z3_unk != ax_unk {
                SHADOW_UNK_SPLIT.fetch_add(1, Ordering::Relaxed);
            }
            maybe_dump_shadow_split(pool, asserts, &rz, &ra);
            LAST_SOLVE_TIMING.with(|timing| {
                timing.set(SolveTiming {
                    total_nanos: total_started.elapsed().as_nanos() as u64,
                    z3_nanos: Some(z3_nanos),
                    axeyum_nanos: Some(axeyum_nanos),
                    z3_outcome: Some(SolveOutcome::from(&rz)),
                    axeyum_outcome: Some(SolveOutcome::from(&ra)),
                    axeyum_execution: Some(axeyum_execution),
                    ..SolveTiming::ZERO
                });
            });
            return rz;
        }
    }

    // Backend priority (ADR-002): explicitly-enabled z3 (perf) > axeyum
    // (pure-Rust default) > pipe (zero-dep fallback).
    let __solve_start = std::time::Instant::now();
    #[cfg(feature = "solver-z3")]
    let (result, axeyum_execution) = (z3_backend::Z3Solver::new().check(pool, asserts), None);
    #[cfg(all(not(feature = "solver-z3"), feature = "solver-axeyum"))]
    let (result, axeyum_execution) = if axeyum_backend::warm_reuse_enabled() {
        let (result, execution) = axeyum_backend::check_warm_thread_local(
            pool,
            asserts,
            ACTIVE_WARM_PATH.with(Cell::get),
            active_warm_delta(),
        );
        (result, Some(execution))
    } else {
        (
            axeyum_backend::AxeyumSolver::new().check(pool, asserts),
            Some(AxeyumExecutionClass::ColdOneShot),
        )
    };
    #[cfg(all(not(feature = "solver-z3"), not(feature = "solver-axeyum")))]
    let (result, axeyum_execution) = (pipe::PipeSolver::new().check(pool, asserts), None);
    let __elapsed = __solve_start.elapsed().as_nanos() as u64;
    LAST_SOLVE_TIMING.with(|timing| {
        timing.set(SolveTiming {
            total_nanos: total_started.elapsed().as_nanos() as u64,
            z3_nanos: {
                #[cfg(feature = "solver-z3")]
                {
                    Some(__elapsed)
                }
                #[cfg(not(feature = "solver-z3"))]
                {
                    None
                }
            },
            axeyum_nanos: {
                #[cfg(all(not(feature = "solver-z3"), feature = "solver-axeyum"))]
                {
                    Some(__elapsed)
                }
                #[cfg(not(all(not(feature = "solver-z3"), feature = "solver-axeyum")))]
                {
                    None
                }
            },
            z3_outcome: {
                #[cfg(feature = "solver-z3")]
                {
                    Some(SolveOutcome::from(&result))
                }
                #[cfg(not(feature = "solver-z3"))]
                {
                    None
                }
            },
            axeyum_outcome: {
                #[cfg(all(not(feature = "solver-z3"), feature = "solver-axeyum"))]
                {
                    Some(SolveOutcome::from(&result))
                }
                #[cfg(not(all(not(feature = "solver-z3"), feature = "solver-axeyum")))]
                {
                    None
                }
            },
            axeyum_execution,
            ..SolveTiming::ZERO
        });
    });
    TOTAL_SOLVE_COUNT.fetch_add(1, Ordering::Relaxed);
    TOTAL_SOLVE_NANOS.fetch_add(__elapsed, Ordering::Relaxed);
    if matches!(result, SolveResult::Unknown(_)) {
        TIMEOUT_COUNT.with(|c| c.set(c.get() + 1));
    }
    #[cfg(feature = "solver-z3")]
    maybe_dump_query(pool, asserts, &result);
    result
}

/// Solve in one path-owner context with an explicit persistent-prefix delta.
///
/// The full assertion slice remains available to one-shot/Z3 controls and
/// trace capture. Only an opt-in direct-delta Axeyum session consumes the
/// partition. The returned Boolean is true exactly when that retained session
/// synchronized its persistent stack; callers must advance their retain marker
/// only then.
pub(crate) fn solve_for_path_delta(
    pool: &ExprPool,
    asserts: &[Assert],
    path_id: u64,
    retain_assertions: usize,
    persistent_assertions: usize,
    persistent_prefix: &WarmAssertionPrefix,
) -> (SolveResult, bool) {
    if retain_assertions > persistent_assertions || persistent_assertions > asserts.len() {
        return (
            SolveResult::Error(format!(
                "invalid warm delta: retain {retain_assertions}, persistent {persistent_assertions}, total {}",
                asserts.len()
            )),
            false,
        );
    }
    if persistent_prefix.depth() != persistent_assertions {
        return (
            SolveResult::Error(format!(
                "invalid warm source prefix: depth {}, persistent {persistent_assertions}",
                persistent_prefix.depth()
            )),
            false,
        );
    }
    let previous_path = ACTIVE_WARM_PATH.with(|active| active.replace(Some(path_id)));
    let previous_delta = ACTIVE_WARM_DELTA.with(|active| {
        active.borrow_mut().replace(WarmDeltaContext {
            retain_assertions,
            persistent_assertions,
            persistent_prefix: persistent_prefix.clone(),
        })
    });
    #[cfg(feature = "solver-axeyum")]
    axeyum_backend::reset_direct_delta_sync();
    let result = solve(pool, asserts);
    #[cfg(feature = "solver-axeyum")]
    let synced = axeyum_backend::last_direct_delta_synced();
    #[cfg(not(feature = "solver-axeyum"))]
    let synced = false;
    ACTIVE_WARM_DELTA.with(|active| {
        *active.borrow_mut() = previous_delta;
    });
    ACTIVE_WARM_PATH.with(|active| active.set(previous_path));
    (result, synced)
}

#[cfg(test)]
mod timeout_configuration_tests {
    use super::{
        DEFAULT_CHECK_TIMEOUT_MS, SolveUnknownReason, SolverWorkBudgets, parse_check_timeout_ms,
        parse_solver_work_budget,
    };

    #[test]
    fn check_timeout_defaults_and_accepts_a_bounded_override() {
        assert_eq!(parse_check_timeout_ms(None), Ok(DEFAULT_CHECK_TIMEOUT_MS));
        assert_eq!(parse_check_timeout_ms(Some("1000")), Ok(1000));
    }

    #[test]
    fn check_timeout_rejects_invalid_or_unbounded_overrides() {
        for value in ["", "zero", "0", "60001"] {
            assert!(parse_check_timeout_ms(Some(value)).is_err(), "{value}");
        }
    }

    #[test]
    fn solver_work_budgets_name_backend_specific_units() {
        let budgets = SolverWorkBudgets::from_values(Some("7"), Some("11"), Some("13"))
            .expect("three positive backend budgets");
        assert_eq!(budgets.z3_rlimit, Some(7));
        assert_eq!(budgets.axeyum_progress_checks, Some(11));
        assert_eq!(budgets.bitwuzla_termination_polls, Some(13));
        assert!(budgets.is_complete());
    }

    #[test]
    fn solver_work_budget_rejects_zero_invalid_and_u32_overflow() {
        for value in ["", "zero", "0"] {
            assert!(parse_solver_work_budget("TEST", Some(value), u64::MAX).is_err());
        }
        assert!(
            SolverWorkBudgets::from_values(Some("4294967296"), Some("1"), Some("1")).is_err(),
            "Z3 rlimit must fit the u32 parameter API"
        );
    }

    #[test]
    fn solver_unknown_reasons_keep_work_and_wall_exhaustion_distinct() {
        assert_eq!(SolveUnknownReason::ResourceLimit.as_str(), "resource-limit");
        assert_eq!(SolveUnknownReason::WallTimeout.as_str(), "wall-timeout");
        assert_eq!(SolveUnknownReason::Other.as_str(), "other");
    }
}

#[cfg(all(
    test,
    feature = "solver-z3",
    feature = "solver-axeyum",
    feature = "solver-bitwuzla"
))]
mod neutral_fair_shadow_tests {
    use std::sync::Mutex;

    use super::*;
    use crate::ir::types::{CmpOp, Width};
    use crate::symbolic::expr::Expr;

    static ENVIRONMENT: Mutex<()> = Mutex::new(());

    struct FairShadowEnvironment;

    impl FairShadowEnvironment {
        fn enable() -> Self {
            std::env::set_var("GLAURUNG_FAIR_SHADOW", "1");
            Self
        }
    }

    impl Drop for FairShadowEnvironment {
        fn drop(&mut self) {
            std::env::remove_var("GLAURUNG_FAIR_SHADOW");
        }
    }

    #[test]
    fn neutral_fair_shadow_executes_all_six_cells_on_one_delta() {
        let _guard = ENVIRONMENT.lock().expect("environment lock");
        let _environment = FairShadowEnvironment::enable();
        let mut pool = ExprPool::new();
        let x = pool.fresh_symbol(Width::W32);
        let one = pool.constant(Width::W32, 1);
        let equals = pool.intern(Expr::Cmp {
            op: CmpOp::Eq,
            a: x,
            b: one,
            width: Width::W32,
        });
        let mut prefix = WarmAssertionPrefix::default();
        prefix.push();
        let path_id = u64::MAX - 17;

        let (result, synchronized) =
            solve_for_path_delta(&pool, &[(equals, true)], path_id, 0, 1, &prefix);
        assert!(matches!(result, SolveResult::Sat(_)));
        assert!(synchronized);
        let timing = last_solve_timing();
        for outcome in [
            timing.z3_cold_outcome,
            timing.z3_warm_outcome,
            timing.axeyum_cold_outcome,
            timing.axeyum_warm_outcome,
            timing.bitwuzla_cold_outcome,
            timing.bitwuzla_warm_outcome,
        ] {
            assert_eq!(outcome, Some(SolveOutcome::Sat));
        }
        for nanos in [
            timing.z3_cold_nanos,
            timing.z3_warm_nanos,
            timing.axeyum_cold_nanos,
            timing.axeyum_warm_nanos,
            timing.bitwuzla_cold_nanos,
            timing.bitwuzla_warm_nanos,
        ] {
            assert!(nanos.is_some());
        }
        assert_eq!(
            timing.bitwuzla_warm_execution,
            Some(BitwuzlaExecutionClass::WarmCreated)
        );

        axeyum_backend::close_fair_warm_path(path_id);
        z3_backend::close_warm_path(path_id);
        bitwuzla_backend::close_warm_path(path_id);
    }
}

#[cfg(all(test, feature = "solver-z3"))]
mod capture_tests {
    use super::{
        SolveResult, SolveUnknownReason, append_capture_index, publish_query_file,
        publish_shadow_split_bytes, shadow_result_class, should_capture_shadow_split,
    };

    #[test]
    fn query_publication_is_idempotent_and_collision_safe() {
        let directory = tempfile::tempdir().unwrap();
        let hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        publish_query_file(directory.path(), hash, b"first").unwrap();
        publish_query_file(directory.path(), hash, b"first").unwrap();
        let error = publish_query_file(directory.path(), hash, b"second").unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(
            std::fs::read(directory.path().join(format!("{hash}.smt2"))).unwrap(),
            b"first"
        );
        assert!(std::fs::read_dir(directory.path()).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".tmp")
        }));
    }

    #[test]
    fn capture_index_appends_complete_rows() {
        let directory = tempfile::tempdir().unwrap();
        let hash = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

        append_capture_index(directory.path(), hash, "sat").unwrap();
        append_capture_index(directory.path(), hash, "unsat").unwrap();

        assert_eq!(
            std::fs::read_to_string(directory.path().join("index.tsv")).unwrap(),
            format!("{hash}\tsat\n{hash}\tunsat\n")
        );
    }

    #[test]
    fn shadow_split_capture_requires_exactly_one_nondecided_backend() {
        let sat = SolveResult::Sat(Default::default());
        let unsat = SolveResult::Unsat;
        let unknown = SolveResult::Unknown(SolveUnknownReason::Other);
        let error = SolveResult::Error("diagnostic must not enter identity".to_string());

        assert!(should_capture_shadow_split(&sat, &unknown));
        assert!(should_capture_shadow_split(&error, &unsat));
        assert!(!should_capture_shadow_split(&sat, &unsat));
        assert!(!should_capture_shadow_split(&unknown, &error));
        assert_eq!(shadow_result_class(&sat), "sat");
        assert_eq!(shadow_result_class(&unsat), "unsat");
        assert_eq!(shadow_result_class(&unknown), "unknown");
        assert_eq!(shadow_result_class(&error), "error");
    }

    #[test]
    fn shadow_split_publication_keeps_exact_bytes_and_backend_classes() {
        let directory = tempfile::tempdir().unwrap();
        let hash = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        let script = b"(set-logic QF_BV)\n(check-sat)\n";

        publish_shadow_split_bytes(directory.path(), hash, script, "sat", "unknown").unwrap();

        assert_eq!(
            std::fs::read(directory.path().join(format!("{hash}.smt2"))).unwrap(),
            script
        );
        assert_eq!(
            std::fs::read_to_string(directory.path().join("shadow-splits.tsv")).unwrap(),
            format!("{hash}\tsat\tunknown\n")
        );
    }
}
