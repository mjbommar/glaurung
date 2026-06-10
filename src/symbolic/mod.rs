//! Symbolic / concolic execution over the LLIR.
//!
//! This is the second backend that proves the engine's keystone: the [`Symbolic`]
//! domain implements the same [`Domain`](crate::exec::Domain) trait the concrete
//! emulator does, so the **one** interpreter (`crate::exec::interp`) produces
//! symbolic bit-vector expressions when run over it — no duplicated semantics.
//! See `docs/design/execution-engine/02-architecture/symbolic-engine.md`.
//!
//! Phase-4 status: the hash-consed bit-vector [`Expr`] IR and the [`Symbolic`]
//! domain (expression building + SMT-LIB2 rendering) are implemented. The solver
//! layer (SMT-LIB pipe / optional native Z3·Bitwuzla) and state forking /
//! exploration land in subsequent Phase-4/Phase-5 increments.

pub mod explore;
pub mod expr;
pub mod solver;
pub mod symdomain;

pub use explore::find_input_reaching;
pub use expr::{Expr, ExprId, ExprPool};
pub use solver::{solve, Model, SolveResult, Solver};
pub use symdomain::Symbolic;
