//! BasicBlock type for representing straight-line code regions.
//!
//! BasicBlock represents a fundamental unit of control flow analysis,
//! containing a sequence of instructions with a single entry point and
//! potentially multiple exit points.

#[cfg(feature = "python-ext")]
use pyo3::prelude::*;
use serde::{Deserialize, Serialize};
use std::fmt;

use crate::core::address::Address;
// Note: ID types are handled as Strings here to avoid cross-feature coupling

/// BasicBlock represents a straight-line code region (basic block) in control flow analysis
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyclass)]
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
    /// Whether relationships were explicitly provided (for entry/exit classification)
    pub relationships_known: bool,
}

impl BasicBlock {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: String,
        start_address: Address,
        end_address: Address,
        instruction_count: u32,
        successor_ids: Option<Vec<String>>,
        predecessor_ids: Option<Vec<String>>,
    ) -> Self {
        Self {
            id,
            start_address,
            end_address,
            instruction_count,
            successor_ids: successor_ids.clone().unwrap_or_default(),
            predecessor_ids: predecessor_ids.clone().unwrap_or_default(),
            relationships_known: successor_ids.is_some() || predecessor_ids.is_some(),
        }
    }

    pub fn size_bytes(&self) -> u64 {
        if self.start_address.kind != self.end_address.kind {
            return 0;
        }
        if self.start_address.space != self.end_address.space {
            return 0;
        }
        if self.end_address.value <= self.start_address.value {
            return 0;
        }
        self.end_address.value - self.start_address.value
    }

    pub fn contains_address(&self, addr: Address) -> bool {
        if addr.kind != self.start_address.kind || addr.space != self.start_address.space {
            return false;
        }
        addr.value >= self.start_address.value && addr.value < self.end_address.value
    }

    pub fn successor_count(&self) -> usize {
        self.successor_ids.len()
    }
    pub fn predecessor_count(&self) -> usize {
        self.predecessor_ids.len()
    }
    pub fn is_entry_block(&self) -> bool {
        self.relationships_known && self.predecessor_ids.is_empty()
    }
    pub fn is_exit_block(&self) -> bool {
        self.relationships_known && self.successor_ids.is_empty()
    }
    pub fn is_single_instruction(&self) -> bool {
        self.instruction_count == 1
    }
    pub fn has_successor(&self, id: &str) -> bool {
        self.successor_ids.iter().any(|s| s == id)
    }
    pub fn has_predecessor(&self, id: &str) -> bool {
        self.predecessor_ids.iter().any(|s| s == id)
    }
    pub fn add_successor(&mut self, id: String) {
        if !self.has_successor(&id) {
            self.successor_ids.push(id);
        }
    }
    pub fn remove_successor(&mut self, id: &str) {
        if let Some(pos) = self.successor_ids.iter().position(|s| s == id) {
            self.successor_ids.remove(pos);
        }
    }
    pub fn add_predecessor(&mut self, id: String) {
        if !self.has_predecessor(&id) {
            self.predecessor_ids.push(id);
        }
    }
    pub fn remove_predecessor(&mut self, id: &str) {
        if let Some(pos) = self.predecessor_ids.iter().position(|s| s == id) {
            self.predecessor_ids.remove(pos);
        }
    }

    pub fn summary(&self) -> String {
        let entry = if self.is_entry_block() { " ENTRY" } else { "" };
        let exit = if self.is_exit_block() { " EXIT" } else { "" };
        format!(
            "BB:{} {:x}-{:x} {} instrs, {} preds, {} succs{}{}",
            self.id,
            self.start_address.value,
            self.end_address.value,
            self.instruction_count,
            self.predecessor_ids.len(),
            self.successor_ids.len(),
            entry,
            exit
        )
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.start_address.kind != self.end_address.kind {
            return Err("start address and end address must have same kind".to_string());
        }
        if self.start_address.space != self.end_address.space {
            return Err("start address and end address must have same address space".to_string());
        }
        if self.end_address.value <= self.start_address.value {
            return Err("start address must be less than end address".to_string());
        }
        if self.instruction_count == 0 {
            return Err("instruction count must be > 0".to_string());
        }
        // Check duplicates in successors
        let mut seen = std::collections::HashSet::new();
        for s in &self.successor_ids {
            if !seen.insert(s) {
                return Err("duplicate successor id".to_string());
            }
        }
        Ok(())
    }
}

impl fmt::Display for BasicBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "BasicBlock '{}' ({:x}-{:x}, instrs={}, preds={}, succs={})",
            self.id,
            self.start_address.value,
            self.end_address.value,
            self.instruction_count,
            self.predecessor_ids.len(),
            self.successor_ids.len()
        )
    }
}

#[cfg(feature = "python-ext")]
#[pymethods]
impl BasicBlock {
    #[new]
    #[pyo3(signature = (id, start_address, end_address, instruction_count, successor_ids=None, predecessor_ids=None))]
    #[allow(clippy::too_many_arguments)]
    pub fn new_py(
        id: String,
        start_address: Address,
        end_address: Address,
        instruction_count: u32,
        successor_ids: Option<Vec<String>>,
        predecessor_ids: Option<Vec<String>>,
    ) -> Self {
        Self::new(
            id,
            start_address,
            end_address,
            instruction_count,
            successor_ids,
            predecessor_ids,
        )
    }

    fn __str__(&self) -> String {
        format!("{}", self)
    }

    fn __eq__(&self, other: &Self) -> bool {
        self == other
    }

    fn __hash__(&self) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        self.hash(&mut hasher);
        hasher.finish()
    }

    // Getters for fields
    #[getter]
    pub fn id(&self) -> &str {
        &self.id
    }
    #[getter]
    pub fn start_address(&self) -> Address {
        self.start_address.clone()
    }
    #[getter]
    pub fn end_address(&self) -> Address {
        self.end_address.clone()
    }
    #[getter]
    pub fn instruction_count(&self) -> u32 {
        self.instruction_count
    }
    #[getter]
    pub fn successor_ids(&self) -> Vec<String> {
        self.successor_ids.clone()
    }
    #[getter]
    pub fn predecessor_ids(&self) -> Vec<String> {
        self.predecessor_ids.clone()
    }

    // Wrappers for helper methods
    #[pyo3(name = "size_bytes")]
    fn size_bytes_py(&self) -> u64 {
        self.size_bytes()
    }
    #[pyo3(name = "contains_address")]
    fn contains_address_py(&self, addr: Address) -> bool {
        self.contains_address(addr)
    }
    #[pyo3(name = "successor_count")]
    fn successor_count_py(&self) -> usize {
        self.successor_count()
    }
    #[pyo3(name = "predecessor_count")]
    fn predecessor_count_py(&self) -> usize {
        self.predecessor_count()
    }
    #[pyo3(name = "is_entry_block")]
    fn is_entry_block_py(&self) -> bool {
        self.is_entry_block()
    }
    #[pyo3(name = "is_exit_block")]
    fn is_exit_block_py(&self) -> bool {
        self.is_exit_block()
    }
    #[pyo3(name = "is_single_instruction")]
    fn is_single_instruction_py(&self) -> bool {
        self.is_single_instruction()
    }
    #[pyo3(name = "has_successor")]
    fn has_successor_py(&self, id: &str) -> bool {
        self.has_successor(id)
    }
    #[pyo3(name = "has_predecessor")]
    fn has_predecessor_py(&self, id: &str) -> bool {
        self.has_predecessor(id)
    }
    #[pyo3(name = "add_successor")]
    fn add_successor_py(&mut self, id: String) {
        self.add_successor(id)
    }
    #[pyo3(name = "remove_successor")]
    fn remove_successor_py(&mut self, id: &str) {
        self.remove_successor(id)
    }
    #[pyo3(name = "add_predecessor")]
    fn add_predecessor_py(&mut self, id: String) {
        self.add_predecessor(id)
    }
    #[pyo3(name = "remove_predecessor")]
    fn remove_predecessor_py(&mut self, id: &str) {
        self.remove_predecessor(id)
    }
    #[pyo3(name = "summary")]
    fn summary_py(&self) -> String {
        self.summary()
    }
    #[pyo3(name = "validate")]
    fn validate_py(&self) -> PyResult<()> {
        self.validate()
            .map_err(pyo3::exceptions::PyValueError::new_err)
    }
}
