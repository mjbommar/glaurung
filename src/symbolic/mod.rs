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
pub mod ioctl;
pub(crate) mod native_trace;
#[cfg(feature = "solver-axeyum")]
pub mod ordered_replay;
pub mod ordered_trace;
pub mod solver;
pub mod symdomain;

pub use explore::{
    ApiSummary, CallModel, CanonicalModelChoiceStats, Severity, Sink, SinkKind, TaintSpec,
    canonical_model_choice_stats, find_input_reaching, find_sinks, find_sinks_stateful,
    set_call_site_summaries,
};
pub use expr::{Expr, ExprId, ExprPool};
pub use ioctl::{
    driver_api_model, find_arbitrary_writes, find_function_sinks_with_apis,
    find_function_stateful_sinks, find_ioctl_sinks, find_ioctl_sinks_with_apis, seed_irp,
    seed_tainted_args, IrpSeed,
};
pub use solver::{
    check_timeout_ms, reset_total_solver_stats, set_solver_budget, set_time_budget, solve,
    solver_budget, solver_meter, time_budget, total_solver_stats, Model, SolveResult, Solver,
    DEFAULT_SOLVER_BUDGET,
};
pub use symdomain::Symbolic;
