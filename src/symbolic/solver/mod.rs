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

/// Solve using the best backend compiled in: native z3 when available
/// (`solver-z3`), otherwise the SMT-LIB pipe fallback.
pub fn solve(pool: &ExprPool, asserts: &[Assert]) -> SolveResult {
    #[cfg(feature = "solver-z3")]
    {
        return z3_backend::Z3Solver::new().check(pool, asserts);
    }
    #[cfg(not(feature = "solver-z3"))]
    {
        pipe::PipeSolver::new().check(pool, asserts)
    }
}
