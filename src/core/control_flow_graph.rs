//! ControlFlowGraph type for representing intra-procedural control flow.
//!
//! ControlFlowGraph represents the control flow relationships between basic blocks
//! within a single function, providing the foundation for control flow analysis.

#[cfg(feature = "python-ext")]
use pyo3::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt;

/// Edge kind in control flow graph
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyclass)]
pub enum ControlFlowEdgeKind {
    /// Fallthrough to next instruction (unconditional)
    Fallthrough,
    /// Conditional or unconditional branch
    Branch,
    /// Function call (may return)
    Call,
    /// Function return (may not return)
    Return,
}

impl ControlFlowEdgeKind {
    pub fn value(&self) -> &str {
        match self {
            ControlFlowEdgeKind::Fallthrough => "fallthrough",
            ControlFlowEdgeKind::Branch => "branch",
            ControlFlowEdgeKind::Call => "call",
            ControlFlowEdgeKind::Return => "return",
        }
    }
}

/// Edge in control flow graph
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyclass)]
pub struct ControlFlowEdge {
    /// Source basic block ID
    pub from_block_id: String,
    /// Target basic block ID
    pub to_block_id: String,
    /// Edge kind
    pub kind: ControlFlowEdgeKind,
    /// Optional confidence score (0.0-1.0)
    pub confidence: Option<f32>,
}

impl ControlFlowEdge {
    pub fn new(from_block_id: String, to_block_id: String, kind: ControlFlowEdgeKind) -> Self {
        Self {
            from_block_id,
            to_block_id,
            kind,
            confidence: None,
        }
    }

    pub fn with_confidence(
        from_block_id: String,
        to_block_id: String,
        kind: ControlFlowEdgeKind,
        confidence: f32,
    ) -> Self {
        Self {
            from_block_id,
            to_block_id,
            kind,
            confidence: Some(confidence),
        }
    }
}

/// ControlFlowGraph represents intra-procedural control flow
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyclass)]
pub struct ControlFlowGraph {
    /// Optional function ID this CFG belongs to
    pub function_id: Option<String>,
    /// All basic block IDs in this graph
    pub block_ids: Vec<String>,
    /// Edges between basic blocks
    pub edges: Vec<ControlFlowEdge>,
}

impl ControlFlowGraph {
    /// Create a new empty control flow graph
    pub fn new() -> Self {
        Self {
            function_id: None,
            block_ids: Vec::new(),
            edges: Vec::new(),
        }
    }

    /// Create a new control flow graph for a specific function
    pub fn for_function(function_id: String) -> Self {
        Self {
            function_id: Some(function_id),
            block_ids: Vec::new(),
            edges: Vec::new(),
        }
    }

    /// Add a basic block to the graph
    pub fn add_block(&mut self, block_id: String) {
        if !self.block_ids.contains(&block_id) {
            self.block_ids.push(block_id);
        }
    }

    /// Add multiple basic blocks to the graph
    pub fn add_blocks(&mut self, block_ids: Vec<String>) {
        for block_id in block_ids {
            self.add_block(block_id);
        }
    }

    /// Add an edge between basic blocks
    pub fn add_edge(&mut self, edge: ControlFlowEdge) {
        // Ensure both blocks are in the graph
        self.add_block(edge.from_block_id.clone());
        self.add_block(edge.to_block_id.clone());
        self.edges.push(edge);
    }

    /// Add a simple edge
    pub fn add_simple_edge(
        &mut self,
        from_block_id: String,
        to_block_id: String,
        kind: ControlFlowEdgeKind,
    ) {
        let edge = ControlFlowEdge::new(from_block_id, to_block_id, kind);
        self.add_edge(edge);
    }

    /// Remove an edge
    pub fn remove_edge(
        &mut self,
        from_block_id: &str,
        to_block_id: &str,
        kind: ControlFlowEdgeKind,
    ) {
        self.edges.retain(|edge| {
            !(edge.from_block_id == from_block_id
                && edge.to_block_id == to_block_id
                && edge.kind == kind)
        });
    }

    /// Get all edges from a specific block
    pub fn outgoing_edges(&self, block_id: &str) -> Vec<&ControlFlowEdge> {
        self.edges
            .iter()
            .filter(|edge| edge.from_block_id == block_id)
            .collect()
    }

    /// Get all edges to a specific block
    pub fn incoming_edges(&self, block_id: &str) -> Vec<&ControlFlowEdge> {
        self.edges
            .iter()
            .filter(|edge| edge.to_block_id == block_id)
            .collect()
    }

    /// Get all successor block IDs for a given block
    pub fn successors(&self, block_id: &str) -> Vec<String> {
        self.outgoing_edges(block_id)
            .iter()
            .map(|edge| edge.to_block_id.clone())
            .collect()
    }

    /// Get all predecessor block IDs for a given block
    pub fn predecessors(&self, block_id: &str) -> Vec<String> {
        self.incoming_edges(block_id)
            .iter()
            .map(|edge| edge.from_block_id.clone())
            .collect()
    }

    /// Check if block has any predecessors
    pub fn has_predecessors(&self, block_id: &str) -> bool {
        !self.predecessors(block_id).is_empty()
    }

    /// Check if block has any successors
    pub fn has_successors(&self, block_id: &str) -> bool {
        !self.successors(block_id).is_empty()
    }

    /// Get entry blocks (blocks with no predecessors)
    pub fn entry_blocks(&self) -> Vec<String> {
        self.block_ids
            .iter()
            .filter(|block_id| !self.has_predecessors(block_id))
            .cloned()
            .collect()
    }

    /// Get exit blocks (blocks with no successors)
    pub fn exit_blocks(&self) -> Vec<String> {
        self.block_ids
            .iter()
            .filter(|block_id| !self.has_successors(block_id))
            .cloned()
            .collect()
    }

    /// Check if the graph is empty
    pub fn is_empty(&self) -> bool {
        self.block_ids.is_empty()
    }

    /// Get the number of blocks
    pub fn block_count(&self) -> usize {
        self.block_ids.len()
    }

    /// Get the number of edges
    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    /// Calculate cyclomatic complexity (M = E - N + 2P, where P=1 for connected graph)
    pub fn cyclomatic_complexity(&self) -> u32 {
        if self.block_ids.is_empty() {
            return 0;
        }

        let edges = self.edges.len() as u32;
        let nodes = self.block_ids.len() as u32;

        // For a single function CFG, P = 1 (one connected component)
        edges.saturating_sub(nodes).saturating_add(2)
    }

    /// Check if the graph has cycles
    pub fn has_cycles(&self) -> bool {
        let mut visited = HashSet::new();
        let mut recursion_stack = HashSet::new();

        for block_id in &self.block_ids {
            if !visited.contains(block_id)
                && self.has_cycle_dfs(block_id, &mut visited, &mut recursion_stack)
            {
                return true;
            }
        }
        false
    }

    fn has_cycle_dfs(
        &self,
        block_id: &str,
        visited: &mut HashSet<String>,
        recursion_stack: &mut HashSet<String>,
    ) -> bool {
        visited.insert(block_id.to_string());
        recursion_stack.insert(block_id.to_string());

        for successor in self.successors(block_id) {
            if !visited.contains(&successor) {
                if self.has_cycle_dfs(&successor, visited, recursion_stack) {
                    return true;
                }
            } else if recursion_stack.contains(&successor) {
                return true;
            }
        }

        recursion_stack.remove(block_id);
        false
    }

    /// Validate the control flow graph
    pub fn validate(&self) -> Result<(), String> {
        // Check that all edge endpoints are in block_ids
        for edge in &self.edges {
            if !self.block_ids.contains(&edge.from_block_id) {
                return Err(format!(
                    "Edge references unknown source block: {}",
                    edge.from_block_id
                ));
            }
            if !self.block_ids.contains(&edge.to_block_id) {
                return Err(format!(
                    "Edge references unknown target block: {}",
                    edge.to_block_id
                ));
            }
        }

        // Check for duplicate blocks
        let mut seen = HashSet::new();
        for block_id in &self.block_ids {
            if !seen.insert(block_id) {
                return Err(format!("Duplicate block ID: {}", block_id));
            }
        }

        // Check confidence values are valid
        for edge in &self.edges {
            if let Some(confidence) = edge.confidence {
                if !(0.0..=1.0).contains(&confidence) {
                    return Err(format!(
                        "Invalid confidence value: {} (must be 0.0-1.0)",
                        confidence
                    ));
                }
            }
        }

        Ok(())
    }

    /// Create a subgraph containing only specified blocks and their connecting edges
    pub fn subgraph(&self, block_ids: &[String]) -> Self {
        let block_set: HashSet<String> = block_ids.iter().cloned().collect();

        let filtered_edges: Vec<ControlFlowEdge> = self
            .edges
            .iter()
            .filter(|edge| {
                block_set.contains(&edge.from_block_id) && block_set.contains(&edge.to_block_id)
            })
            .cloned()
            .collect();

        Self {
            function_id: self.function_id.clone(),
            block_ids: block_ids.to_vec(),
            edges: filtered_edges,
        }
    }

    /// Get statistics about the graph
    pub fn statistics(&self) -> ControlFlowGraphStats {
        let mut edge_counts = HashMap::new();
        for edge in &self.edges {
            *edge_counts.entry(edge.kind).or_insert(0) += 1;
        }

        ControlFlowGraphStats {
            block_count: self.block_count(),
            edge_count: self.edge_count(),
            entry_blocks: self.entry_blocks().len(),
            exit_blocks: self.exit_blocks().len(),
            cyclomatic_complexity: self.cyclomatic_complexity(),
            has_cycles: self.has_cycles(),
            edge_kind_counts: edge_counts,
        }
    }
}

/// Statistics about a control flow graph
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyclass)]
pub struct ControlFlowGraphStats {
    pub block_count: usize,
    pub edge_count: usize,
    pub entry_blocks: usize,
    pub exit_blocks: usize,
    pub cyclomatic_complexity: u32,
    pub has_cycles: bool,
    pub edge_kind_counts: HashMap<ControlFlowEdgeKind, usize>,
}

impl fmt::Display for ControlFlowGraph {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ControlFlowGraph(function_id={:?}, blocks={}, edges={})",
            self.function_id,
            self.block_ids.len(),
            self.edges.len()
        )
    }
}

impl Default for ControlFlowGraph {
    fn default() -> Self {
        Self::new()
    }
}

// PyO3 bindings
#[cfg(feature = "python-ext")]
#[pymethods]
impl ControlFlowGraph {
    #[new]
    #[pyo3(signature = (function_id=None))]
    fn new_py(function_id: Option<String>) -> Self {
        match function_id {
            Some(id) => Self::for_function(id),
            None => Self::new(),
        }
    }

    fn __str__(&self) -> String {
        format!("{}", self)
    }

    fn __repr__(&self) -> String {
        format!(
            "ControlFlowGraph(function_id={:?}, block_count={}, edge_count={})",
            self.function_id,
            self.block_count(),
            self.edge_count()
        )
    }

    // Getters
    #[getter]
    fn function_id(&self) -> Option<String> {
        self.function_id.clone()
    }

    #[setter]
    fn set_function_id(&mut self, value: Option<String>) {
        self.function_id = value;
    }

    #[getter]
    fn block_ids(&self) -> Vec<String> {
        self.block_ids.clone()
    }

    #[getter]
    fn edges(&self) -> Vec<ControlFlowEdge> {
        self.edges.clone()
    }

    // Methods
    #[pyo3(name = "add_block")]
    fn add_block_py(&mut self, block_id: String) {
        self.add_block(block_id);
    }

    #[pyo3(name = "add_blocks")]
    fn add_blocks_py(&mut self, block_ids: Vec<String>) {
        self.add_blocks(block_ids);
    }

    #[pyo3(name = "add_edge")]
    fn add_edge_py(&mut self, edge: ControlFlowEdge) {
        self.add_edge(edge);
    }

    #[pyo3(name = "add_simple_edge")]
    fn add_simple_edge_py(
        &mut self,
        from_block_id: String,
        to_block_id: String,
        kind: ControlFlowEdgeKind,
    ) {
        self.add_simple_edge(from_block_id, to_block_id, kind);
    }

    #[pyo3(name = "remove_edge")]
    fn remove_edge_py(
        &mut self,
        from_block_id: String,
        to_block_id: String,
        kind: ControlFlowEdgeKind,
    ) {
        self.remove_edge(&from_block_id, &to_block_id, kind);
    }

    #[pyo3(name = "outgoing_edges")]
    fn outgoing_edges_py(&self, block_id: String) -> Vec<ControlFlowEdge> {
        self.outgoing_edges(&block_id)
            .into_iter()
            .cloned()
            .collect()
    }

    #[pyo3(name = "incoming_edges")]
    fn incoming_edges_py(&self, block_id: String) -> Vec<ControlFlowEdge> {
        self.incoming_edges(&block_id)
            .into_iter()
            .cloned()
            .collect()
    }

    #[pyo3(name = "successors")]
    fn successors_py(&self, block_id: String) -> Vec<String> {
        self.successors(&block_id)
    }

    #[pyo3(name = "predecessors")]
    fn predecessors_py(&self, block_id: String) -> Vec<String> {
        self.predecessors(&block_id)
    }

    #[pyo3(name = "has_predecessors")]
    fn has_predecessors_py(&self, block_id: String) -> bool {
        self.has_predecessors(&block_id)
    }

    #[pyo3(name = "has_successors")]
    fn has_successors_py(&self, block_id: String) -> bool {
        self.has_successors(&block_id)
    }

    #[pyo3(name = "entry_blocks")]
    fn entry_blocks_py(&self) -> Vec<String> {
        self.entry_blocks()
    }

    #[pyo3(name = "exit_blocks")]
    fn exit_blocks_py(&self) -> Vec<String> {
        self.exit_blocks()
    }

    #[pyo3(name = "is_empty")]
    fn is_empty_py(&self) -> bool {
        self.is_empty()
    }

    #[pyo3(name = "block_count")]
    fn block_count_py(&self) -> usize {
        self.block_count()
    }

    #[pyo3(name = "edge_count")]
    fn edge_count_py(&self) -> usize {
        self.edge_count()
    }

    #[pyo3(name = "cyclomatic_complexity")]
    fn cyclomatic_complexity_py(&self) -> u32 {
        self.cyclomatic_complexity()
    }

    #[pyo3(name = "has_cycles")]
    fn has_cycles_py(&self) -> bool {
        self.has_cycles()
    }

    #[pyo3(name = "validate")]
    fn validate_py(&self) -> PyResult<()> {
        self.validate()
            .map_err(pyo3::exceptions::PyValueError::new_err)
    }

    #[pyo3(name = "statistics")]
    fn statistics_py(&self) -> ControlFlowGraphStats {
        self.statistics()
    }

    #[pyo3(name = "subgraph")]
    fn subgraph_py(&self, block_ids: Vec<String>) -> Self {
        self.subgraph(&block_ids)
    }
}

// PyO3 bindings for ControlFlowEdge
#[cfg(feature = "python-ext")]
#[pymethods]
impl ControlFlowEdge {
    /// Alternate constructor with confidence (Python API)
    #[staticmethod]
    #[pyo3(name = "with_confidence")]
    fn with_confidence_py(
        from_block_id: String,
        to_block_id: String,
        kind: ControlFlowEdgeKind,
        confidence: f32,
    ) -> Self {
        crate::core::control_flow_graph::ControlFlowEdge::with_confidence(
            from_block_id,
            to_block_id,
            kind,
            confidence,
        )
    }
    #[new]
    #[pyo3(signature = (from_block_id, to_block_id, kind, confidence=None))]
    fn new_py(
        from_block_id: String,
        to_block_id: String,
        kind: ControlFlowEdgeKind,
        confidence: Option<f32>,
    ) -> Self {
        match confidence {
            Some(c) => Self::with_confidence(from_block_id, to_block_id, kind, c),
            None => Self::new(from_block_id, to_block_id, kind),
        }
    }

    fn __str__(&self) -> String {
        format!(
            "{} -> {} ({})",
            self.from_block_id,
            self.to_block_id,
            self.kind.value()
        )
    }

    fn __repr__(&self) -> String {
        format!(
            "ControlFlowEdge(from='{}', to='{}', kind={:?}, confidence={:?})",
            self.from_block_id, self.to_block_id, self.kind, self.confidence
        )
    }

    // Getters
    #[getter]
    fn from_block_id(&self) -> String {
        self.from_block_id.clone()
    }

    #[getter]
    fn to_block_id(&self) -> String {
        self.to_block_id.clone()
    }

    #[getter]
    fn kind(&self) -> ControlFlowEdgeKind {
        self.kind
    }

    #[getter]
    fn confidence(&self) -> Option<f32> {
        self.confidence
    }

    #[setter]
    fn set_confidence(&mut self, value: Option<f32>) {
        self.confidence = value;
    }
}

// PyO3 bindings for ControlFlowEdgeKind
#[cfg(feature = "python-ext")]
#[pymethods]
impl ControlFlowEdgeKind {
    #[pyo3(name = "value")]
    fn value_py(&self) -> String {
        match self {
            ControlFlowEdgeKind::Fallthrough => "fallthrough",
            ControlFlowEdgeKind::Branch => "branch",
            ControlFlowEdgeKind::Call => "call",
            ControlFlowEdgeKind::Return => "return",
        }
        .to_string()
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
}

// PyO3 bindings for ControlFlowGraphStats
#[cfg(feature = "python-ext")]
#[pymethods]
impl ControlFlowGraphStats {
    #[new]
    #[pyo3(signature = (block_count, edge_count, entry_blocks, exit_blocks, cyclomatic_complexity, has_cycles, edge_kind_counts))]
    fn new_py(
        block_count: usize,
        edge_count: usize,
        entry_blocks: usize,
        exit_blocks: usize,
        cyclomatic_complexity: u32,
        has_cycles: bool,
        edge_kind_counts: HashMap<ControlFlowEdgeKind, usize>,
    ) -> Self {
        Self {
            block_count,
            edge_count,
            entry_blocks,
            exit_blocks,
            cyclomatic_complexity,
            has_cycles,
            edge_kind_counts,
        }
    }

    fn __str__(&self) -> String {
        format!(
            "ControlFlowGraphStats(blocks={}, edges={}, complexity={}, cycles={})",
            self.block_count, self.edge_count, self.cyclomatic_complexity, self.has_cycles
        )
    }

    fn __repr__(&self) -> String {
        format!("{:?}", self)
    }

    // Getters
    #[getter]
    fn block_count(&self) -> usize {
        self.block_count
    }

    #[getter]
    fn edge_count(&self) -> usize {
        self.edge_count
    }

    #[getter]
    fn entry_blocks(&self) -> usize {
        self.entry_blocks
    }

    #[getter]
    fn exit_blocks(&self) -> usize {
        self.exit_blocks
    }

    #[getter]
    fn cyclomatic_complexity(&self) -> u32 {
        self.cyclomatic_complexity
    }

    #[getter]
    fn has_cycles(&self) -> bool {
        self.has_cycles
    }

    #[getter]
    fn edge_kind_counts(&self) -> HashMap<ControlFlowEdgeKind, usize> {
        self.edge_kind_counts.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_cfg() -> ControlFlowGraph {
        let mut cfg = ControlFlowGraph::for_function("test_func".to_string());

        // Add blocks
        cfg.add_block("entry".to_string());
        cfg.add_block("loop_header".to_string());
        cfg.add_block("loop_body".to_string());
        cfg.add_block("exit".to_string());

        // Add edges
        cfg.add_simple_edge(
            "entry".to_string(),
            "loop_header".to_string(),
            ControlFlowEdgeKind::Branch,
        );
        cfg.add_simple_edge(
            "loop_header".to_string(),
            "loop_body".to_string(),
            ControlFlowEdgeKind::Branch,
        );
        cfg.add_simple_edge(
            "loop_header".to_string(),
            "exit".to_string(),
            ControlFlowEdgeKind::Branch,
        );
        cfg.add_simple_edge(
            "loop_body".to_string(),
            "loop_header".to_string(),
            ControlFlowEdgeKind::Branch,
        );

        cfg
    }

    #[test]
    fn test_cfg_creation() {
        let cfg = ControlFlowGraph::new();
        assert!(cfg.is_empty());
        assert_eq!(cfg.block_count(), 0);
        assert_eq!(cfg.edge_count(), 0);
    }

    #[test]
    fn test_cfg_for_function() {
        let cfg = ControlFlowGraph::for_function("test_func".to_string());
        assert_eq!(cfg.function_id, Some("test_func".to_string()));
    }

    #[test]
    fn test_add_blocks_and_edges() {
        let mut cfg = ControlFlowGraph::new();
        cfg.add_block("block1".to_string());
        cfg.add_block("block2".to_string());

        let edge = ControlFlowEdge::new(
            "block1".to_string(),
            "block2".to_string(),
            ControlFlowEdgeKind::Branch,
        );
        cfg.add_edge(edge);

        assert_eq!(cfg.block_count(), 2);
        assert_eq!(cfg.edge_count(), 1);
        assert_eq!(cfg.successors("block1"), vec!["block2".to_string()]);
        assert_eq!(cfg.predecessors("block2"), vec!["block1".to_string()]);
    }

    #[test]
    fn test_entry_and_exit_blocks() {
        let cfg = create_test_cfg();

        let entry_blocks = cfg.entry_blocks();
        let exit_blocks = cfg.exit_blocks();

        assert_eq!(entry_blocks, vec!["entry".to_string()]);
        assert_eq!(exit_blocks, vec!["exit".to_string()]);
    }

    #[test]
    fn test_cyclomatic_complexity() {
        let cfg = create_test_cfg();
        // M = E - N + 2P = 4 - 4 + 2 = 2
        assert_eq!(cfg.cyclomatic_complexity(), 2);
    }

    #[test]
    fn test_has_cycles() {
        let cfg = create_test_cfg();
        assert!(cfg.has_cycles()); // loop_header -> loop_body -> loop_header

        let mut acyclic_cfg = ControlFlowGraph::new();
        acyclic_cfg.add_block("a".to_string());
        acyclic_cfg.add_block("b".to_string());
        acyclic_cfg.add_simple_edge(
            "a".to_string(),
            "b".to_string(),
            ControlFlowEdgeKind::Branch,
        );
        assert!(!acyclic_cfg.has_cycles());
    }

    #[test]
    fn test_validation() {
        let mut cfg = ControlFlowGraph::new();
        cfg.add_block("valid".to_string());

        // Valid edge
        let valid_edge = ControlFlowEdge::new(
            "valid".to_string(),
            "valid".to_string(),
            ControlFlowEdgeKind::Branch,
        );
        cfg.add_edge(valid_edge);
        assert!(cfg.validate().is_ok());

        // Invalid edge (references unknown block)
        let invalid_edge = ControlFlowEdge::new(
            "valid".to_string(),
            "invalid".to_string(),
            ControlFlowEdgeKind::Branch,
        );
        cfg.edges.push(invalid_edge);
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_statistics() {
        let cfg = create_test_cfg();
        let stats = cfg.statistics();

        assert_eq!(stats.block_count, 4);
        assert_eq!(stats.edge_count, 4);
        assert_eq!(stats.entry_blocks, 1);
        assert_eq!(stats.exit_blocks, 1);
        assert_eq!(stats.cyclomatic_complexity, 2);
        assert!(stats.has_cycles);
        assert_eq!(stats.edge_kind_counts[&ControlFlowEdgeKind::Branch], 4);
    }
}
