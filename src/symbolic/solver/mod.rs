//! SMT solver layer — a pluggable [`Solver`] trait with two backends.
//!
//! Per the corrected ADR-0005 (native-first), the preferred backend is the
//! **in-process native [`z3_backend::Z3Solver`]** (feature `solver-z3`, links
//! libz3) — keeping the engine self-contained rather than shelling out. The
//! [`pipe::PipeSolver`] (SMT-LIB2 over a subprocess) is a zero-build fallback
//! for environments without a linked solver. A future pure-Rust backend
//! (bit-blast → SAT) can implement the same trait.
//!
//! All backends consume the bit-vector [`ExprPool`](crate::symbolic::ExprPool):
//! solving needs no Python and no external protocol when `solver-z3` is on.

#[cfg(feature = "solver-axeyum")]
pub mod axeyum_backend;
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

/// The result of a solve attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SolveResult {
    /// Satisfiable, with a model.
    Sat(Model),
    /// Unsatisfiable.
    Unsat,
    /// The solver returned `unknown`.
    Unknown,
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

use std::cell::Cell;
use std::time::Duration;

/// Default per-function solver budget: `(max_solves, max_timeouts)`. The explorer
/// bails when either is exceeded — a deterministic ceiling on solving work that
/// bounds runtime even when a function's state space (or an obfuscated function's
/// individual solves) does not. The timeout count is the obfuscation signal: a
/// function whose formulas keep timing out is abandoned cheaply.
pub const DEFAULT_SOLVER_BUDGET: (u64, u64) = (6000, 24);

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
}

/// Backend-separated timing for one solver call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SolveTiming {
    pub(crate) total_nanos: u64,
    pub(crate) z3_nanos: Option<u64>,
    pub(crate) axeyum_nanos: Option<u64>,
}

impl SolveTiming {
    const ZERO: Self = Self {
        total_nanos: 0,
        z3_nanos: None,
        axeyum_nanos: None,
    };
}

/// Timing for the immediately preceding [`solve`] call on this worker.
pub(crate) fn last_solve_timing() -> SolveTiming {
    LAST_SOLVE_TIMING.with(Cell::get)
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
    use std::collections::HashSet;
    use std::io::Write;
    use std::path::PathBuf;
    use std::sync::{Mutex, OnceLock};

    static DIR: OnceLock<Option<PathBuf>> = OnceLock::new();
    static SEEN: OnceLock<Mutex<HashSet<[u8; 32]>>> = OnceLock::new();

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
    {
        let seen = SEEN.get_or_init(|| Mutex::new(HashSet::new()));
        let mut s = seen.lock().unwrap();
        if !s.insert(hash) {
            return; // duplicate formula, already captured
        }
    }
    let hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
    let _ = std::fs::create_dir_all(dir);
    if std::fs::write(dir.join(format!("{hex}.smt2")), script.as_bytes()).is_ok() {
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join("index.tsv"))
        {
            let _ = writeln!(f, "{hex}\t{verdict}");
        }
    }
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
        if std::env::var_os("GLAURUNG_SHADOW_DIFF").is_some() {
            // Time each backend on the SAME query for an apples-to-apples
            // comparison. Alternate order per call to cancel warm-cache bias.
            let z3_first = SHADOW_AGREE.load(Ordering::Relaxed) % 2 == 0;
            let (rz, ra, z3_nanos, axeyum_nanos);
            if z3_first {
                let t = std::time::Instant::now();
                rz = z3_backend::Z3Solver::new().check(pool, asserts);
                z3_nanos = t.elapsed().as_nanos() as u64;
                SHADOW_Z3_NANOS.fetch_add(z3_nanos, Ordering::Relaxed);
                let t = std::time::Instant::now();
                ra = if axeyum_backend::warm_reuse_enabled() {
                    axeyum_backend::check_warm_thread_local(
                        pool,
                        asserts,
                        ACTIVE_WARM_PATH.with(Cell::get),
                    )
                } else {
                    axeyum_backend::AxeyumSolver::new().check(pool, asserts)
                };
                axeyum_nanos = t.elapsed().as_nanos() as u64;
                SHADOW_AX_NANOS.fetch_add(axeyum_nanos, Ordering::Relaxed);
            } else {
                let t = std::time::Instant::now();
                ra = if axeyum_backend::warm_reuse_enabled() {
                    axeyum_backend::check_warm_thread_local(
                        pool,
                        asserts,
                        ACTIVE_WARM_PATH.with(Cell::get),
                    )
                } else {
                    axeyum_backend::AxeyumSolver::new().check(pool, asserts)
                };
                axeyum_nanos = t.elapsed().as_nanos() as u64;
                SHADOW_AX_NANOS.fetch_add(axeyum_nanos, Ordering::Relaxed);
                let t = std::time::Instant::now();
                rz = z3_backend::Z3Solver::new().check(pool, asserts);
                z3_nanos = t.elapsed().as_nanos() as u64;
                SHADOW_Z3_NANOS.fetch_add(z3_nanos, Ordering::Relaxed);
            }
            let unknown = matches!(rz, SolveResult::Unknown)
                || matches!(ra, SolveResult::Unknown)
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
            if matches!(ra, SolveResult::Unknown | SolveResult::Error(_))
                && SHADOW_AX_UNK.load(Ordering::Relaxed) < 5
            {
                eprintln!(
                    "[ax-nondecided #{}] {:?}",
                    SHADOW_AX_UNK.load(Ordering::Relaxed),
                    ra
                );
            }
            let z3_unk = matches!(rz, SolveResult::Unknown | SolveResult::Error(_));
            let ax_unk = matches!(ra, SolveResult::Unknown | SolveResult::Error(_));
            if z3_unk {
                SHADOW_Z3_UNK.fetch_add(1, Ordering::Relaxed);
            }
            if ax_unk {
                SHADOW_AX_UNK.fetch_add(1, Ordering::Relaxed);
            }
            if z3_unk != ax_unk {
                SHADOW_UNK_SPLIT.fetch_add(1, Ordering::Relaxed);
            }
            LAST_SOLVE_TIMING.with(|timing| {
                timing.set(SolveTiming {
                    total_nanos: total_started.elapsed().as_nanos() as u64,
                    z3_nanos: Some(z3_nanos),
                    axeyum_nanos: Some(axeyum_nanos),
                });
            });
            return rz;
        }
    }

    // Backend priority (ADR-002): explicitly-enabled z3 (perf) > axeyum
    // (pure-Rust default) > pipe (zero-dep fallback).
    let __solve_start = std::time::Instant::now();
    #[cfg(feature = "solver-z3")]
    let result = z3_backend::Z3Solver::new().check(pool, asserts);
    #[cfg(all(not(feature = "solver-z3"), feature = "solver-axeyum"))]
    let result = if axeyum_backend::warm_reuse_enabled() {
        axeyum_backend::check_warm_thread_local(pool, asserts, ACTIVE_WARM_PATH.with(Cell::get))
    } else {
        axeyum_backend::AxeyumSolver::new().check(pool, asserts)
    };
    #[cfg(all(not(feature = "solver-z3"), not(feature = "solver-axeyum")))]
    let result = pipe::PipeSolver::new().check(pool, asserts);
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
        });
    });
    TOTAL_SOLVE_COUNT.fetch_add(1, Ordering::Relaxed);
    TOTAL_SOLVE_NANOS.fetch_add(__elapsed, Ordering::Relaxed);
    if matches!(result, SolveResult::Unknown) {
        TIMEOUT_COUNT.with(|c| c.set(c.get() + 1));
    }
    #[cfg(feature = "solver-z3")]
    maybe_dump_query(pool, asserts, &result);
    result
}

/// Solve in the ownership context of one explorer path.
///
/// The context is worker-local and restored after the call. It is ignored by
/// ordinary backends and by Axeyum's consecutive-snapshot policy; only the
/// explicit opt-in lineage policy uses it to select retained mutable state.
pub(crate) fn solve_for_path(pool: &ExprPool, asserts: &[Assert], path_id: u64) -> SolveResult {
    let previous = ACTIVE_WARM_PATH.with(|active| active.replace(Some(path_id)));
    let result = solve(pool, asserts);
    ACTIVE_WARM_PATH.with(|active| active.set(previous));
    result
}
