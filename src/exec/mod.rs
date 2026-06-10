//! Native execution engine over the LLIR.
//!
//! This is the implementation of the plan in `docs/design/execution-engine/`.
//! The keystone is [`Domain`]: a single abstract value domain over which the
//! interpreter is written **once**. The concrete emulator ([`Concrete`]) and the
//! (future) symbolic executor are two implementations of the same trait, so they
//! share all instruction semantics and can never drift apart.
//!
//! Phase 1 status: the `Domain` trait and the `Concrete` backend (bit-vector
//! arithmetic) are implemented and tested. The interpreter, register file,
//! softmmu memory, hooks, and helpers land in subsequent Phase-1 increments.

pub mod budget;
pub mod concrete;
pub mod domain;
pub mod helpers;
pub mod interp;
pub mod memory;
#[cfg(feature = "dev-oracle")]
pub mod oracle;
pub mod simproc;
pub mod state;

pub use budget::Budget;
pub use concrete::Concrete;
pub use domain::{BranchDecision, Domain};
pub use helpers::{HelperFn, HelperRegistry};
pub use interp::{Flow, Halt, Machine, Outcome};
pub use memory::Memory;
pub use simproc::{SimProcFn, SimProcRegistry};
pub use state::{RegArch, RegFile};
