//! BasicBlock type for representing straight-line code regions.
//!
//! BasicBlock represents a fundamental unit of control flow analysis,
//! containing a sequence of instructions with a single entry point and
//! potentially multiple exit points.

use serde::{Deserialize, Serialize};
use std::fmt;

use crate::core::address::Address;
use crate::core::id::{Id, IdGenerator};

/// BasicBlock represents a straight-line code region (basic block) in control flow analysis
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BasicBlock {
    /// Unique identifier for this basic block (deterministic: binary_id + start_address)
    pub id: String,
    /// Starting address of the basic block
    pub start_address: Address,
    /// Ending address of the basic block (exclusive)
    pub end_address: Address,
    /// Number of instructions in this basic block
    pub instruction_count: u32,
    /// IDs of successor basic blocks
    pub successor_ids: Vec<String>,
    /// IDs of predecessor basic blocks
    pub predecessor_ids: Vec<String>,
}

// Note: PyO3 wrapper will be added in a separate file when Python bindings are needed
// This keeps the core Rust code free of PyO3 dependencies for testing
