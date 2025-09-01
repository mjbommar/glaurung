//! Recursive discovery of nested artifacts with budget control.

use crate::core::triage::{Budgets, ContainerChild};
use crate::triage::containers::detect_containers;

/// Simple recursion engine placeholder.
/// Currently detects immediate container children only; depth and budget are tracked for future expansion.
pub struct RecursionEngine {
    pub max_depth: usize,
}

impl Default for RecursionEngine {
    fn default() -> Self {
        Self { max_depth: 1 }
    }
}

impl RecursionEngine {
    pub fn new(max_depth: usize) -> Self {
        Self { max_depth }
    }

    /// Discover immediate children using container signatures.
    /// Budget is returned unmodified for now; future versions will decrement bytes/time.
    pub fn discover_children(
        &self,
        data: &[u8],
        _budgets: &mut Budgets,
        _depth: usize,
    ) -> Vec<ContainerChild> {
        detect_containers(data)
    }
}
