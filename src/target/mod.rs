//! Canonical machine-target facts shared by lifting and analysis.
//!
//! Public binary metadata remains available through [`crate::core::binary`],
//! but internal decompiler decisions should consume one validated
//! [`TargetSpec`] instead of recomputing architecture, ABI, width, and register
//! roles independently.

pub mod abi;
mod registers;
mod spec;

pub use abi::CallConv;
pub use registers::RegisterRoles;
pub use spec::{CodeMode, OsAbi, PcRule, TargetId, TargetSpec};
