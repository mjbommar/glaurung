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

pub mod pipe;
#[cfg(feature = "solver-axeyum")]
pub mod axeyum_backend;
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

/// A constraint: a 1-bit predicate expression that must equal `expected`.
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
    // Backend priority (ADR-002): explicitly-enabled z3 (perf) > axeyum
    // (pure-Rust default) > pipe (zero-dep fallback).
    #[cfg(feature = "solver-z3")]
    let result = z3_backend::Z3Solver::new().check(pool, asserts);
    #[cfg(all(not(feature = "solver-z3"), feature = "solver-axeyum"))]
    let result = axeyum_backend::AxeyumSolver::new().check(pool, asserts);
    #[cfg(all(not(feature = "solver-z3"), not(feature = "solver-axeyum")))]
    let result = pipe::PipeSolver::new().check(pool, asserts);
    if matches!(result, SolveResult::Unknown) {
        TIMEOUT_COUNT.with(|c| c.set(c.get() + 1));
    }
    result
}
