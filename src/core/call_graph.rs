//! CallGraph type for representing inter-procedural call relationships.
//!
//! CallGraph represents the calling relationships between functions,
//! providing the foundation for inter-procedural analysis.

#[cfg(feature = "python-ext")]
use pyo3::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt;

use crate::core::address::Address;

/// Call type for edges in the call graph
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyclass(eq, eq_int))]
pub enum CallType {
    /// Direct call (resolved function address)
    Direct,
    /// Indirect call (through pointer/function pointer)
    Indirect,
    /// Virtual call (C++/Java virtual method dispatch)
    Virtual,
    /// Tail call (caller replaced by callee)
    Tail,
}

impl CallType {
    pub fn value(&self) -> &str {
        match self {
            CallType::Direct => "direct",
            CallType::Indirect => "indirect",
            CallType::Virtual => "virtual",
            CallType::Tail => "tail",
        }
    }
}

/// Edge in call graph representing a function call
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyclass)]
pub struct CallGraphEdge {
    /// Caller function ID
    pub caller: String,
    /// Callee function ID
    pub callee: String,
    /// Call sites (addresses where this call occurs)
    pub call_sites: Vec<Address>,
    /// Type of call
    pub call_type: CallType,
    /// Optional confidence score (0.0-1.0)
    pub confidence: Option<f32>,
}

impl CallGraphEdge {
    pub fn new(caller: String, callee: String, call_type: CallType) -> Self {
        Self {
            caller,
            callee,
            call_sites: Vec::new(),
            call_type,
            confidence: None,
        }
    }

    pub fn with_call_sites(
        caller: String,
        callee: String,
        call_type: CallType,
        call_sites: Vec<Address>,
    ) -> Self {
        Self {
            caller,
            callee,
            call_sites,
            call_type,
            confidence: None,
        }
    }

    pub fn with_confidence(
        caller: String,
        callee: String,
        call_type: CallType,
        confidence: f32,
    ) -> Self {
        Self {
            caller,
            callee,
            call_sites: Vec::new(),
            call_type,
            confidence: Some(confidence),
        }
    }

    /// Add a call site to this edge
    pub fn add_call_site(&mut self, address: Address) {
        if !self.call_sites.contains(&address) {
            self.call_sites.push(address);
        }
    }

    /// Remove a call site from this edge
    pub fn remove_call_site(&mut self, address: &Address) {
        self.call_sites.retain(|site| site != address);
    }
}

/// CallGraph represents inter-procedural calling relationships
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyclass)]
pub struct CallGraph {
    /// All function IDs in this call graph
    pub nodes: Vec<String>,
    /// Edges representing function calls
    pub edges: Vec<CallGraphEdge>,
}

impl CallGraph {
    /// Create a new empty call graph
    pub fn new() -> Self {
        Self {
            nodes: Vec::new(),
            edges: Vec::new(),
        }
    }

    /// Add a function node to the graph
    pub fn add_node(&mut self, function_id: String) {
        if !self.nodes.contains(&function_id) {
            self.nodes.push(function_id);
        }
    }

    /// Add multiple function nodes to the graph
    pub fn add_nodes(&mut self, function_ids: Vec<String>) {
        for function_id in function_ids {
            self.add_node(function_id);
        }
    }

    /// Add an edge representing a function call. Does not auto-add nodes.
    pub fn add_edge(&mut self, edge: CallGraphEdge) {
        self.edges.push(edge);
    }

    /// Add a simple edge. Does not auto-add nodes.
    pub fn add_simple_edge(&mut self, caller: String, callee: String, call_type: CallType) {
        let edge = CallGraphEdge::new(caller, callee, call_type);
        self.edges.push(edge);
    }

    /// Remove an edge
    pub fn remove_edge(&mut self, caller: &str, callee: &str, call_type: CallType) {
        self.edges.retain(|edge| {
            !(edge.caller == caller && edge.callee == callee && edge.call_type == call_type)
        });
    }

    /// Get all edges from a specific caller
    pub fn outgoing_edges(&self, caller: &str) -> Vec<&CallGraphEdge> {
        self.edges
            .iter()
            .filter(|edge| edge.caller == caller)
            .collect()
    }

    /// Get all edges to a specific callee
    pub fn incoming_edges(&self, callee: &str) -> Vec<&CallGraphEdge> {
        self.edges
            .iter()
            .filter(|edge| edge.callee == callee)
            .collect()
    }

    /// Get all callees for a given caller
    pub fn callees(&self, caller: &str) -> Vec<String> {
        self.outgoing_edges(caller)
            .iter()
            .map(|edge| edge.callee.clone())
            .collect()
    }

    /// Get all callers for a given callee
    pub fn callers(&self, callee: &str) -> Vec<String> {
        self.incoming_edges(callee)
            .iter()
            .map(|edge| edge.caller.clone())
            .collect()
    }

    /// Check if function has any callees
    pub fn has_callees(&self, function_id: &str) -> bool {
        !self.callees(function_id).is_empty()
    }

    /// Check if function has any callers
    pub fn has_callers(&self, function_id: &str) -> bool {
        !self.callers(function_id).is_empty()
    }

    /// Get root functions (functions with no callers)
    pub fn root_functions(&self) -> Vec<String> {
        self.nodes
            .iter()
            .filter(|function_id| !self.has_callers(function_id))
            .cloned()
            .collect()
    }

    /// Get leaf functions (functions with no callees)
    pub fn leaf_functions(&self) -> Vec<String> {
        self.nodes
            .iter()
            .filter(|function_id| !self.has_callees(function_id))
            .cloned()
            .collect()
    }

    /// Check if the graph is empty
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Get the number of functions
    pub fn function_count(&self) -> usize {
        self.nodes.len()
    }

    /// Get the number of call edges
    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    /// Calculate call depth for a function (maximum path length from roots)
    pub fn call_depth(&self, function_id: &str) -> Option<usize> {
        if !self.nodes.contains(&function_id.to_string()) {
            return None;
        }

        let mut visited = HashSet::new();
        self.call_depth_dfs(function_id, &mut visited)
    }

    fn call_depth_dfs(&self, function_id: &str, visited: &mut HashSet<String>) -> Option<usize> {
        if visited.contains(function_id) {
            return Some(0); // Cycle detected, return 0 to avoid infinite recursion
        }

        visited.insert(function_id.to_string());

        let callers = self.callers(function_id);
        if callers.is_empty() {
            return Some(0); // Root function
        }

        let mut max_depth = 0;
        for caller in callers {
            if let Some(depth) = self.call_depth_dfs(&caller, visited) {
                max_depth = max_depth.max(depth + 1);
            }
        }

        visited.remove(function_id);
        Some(max_depth)
    }

    /// Find all call paths from start function to end function
    pub fn find_call_paths(&self, start_function: &str, end_function: &str) -> Vec<Vec<String>> {
        let mut paths = Vec::new();
        let mut current_path = Vec::new();
        let mut visited = HashSet::new();

        self.call_paths_dfs(
            start_function,
            end_function,
            &mut current_path,
            &mut visited,
            &mut paths,
        );
        paths
    }

    fn call_paths_dfs(
        &self,
        current: &str,
        target: &str,
        current_path: &mut Vec<String>,
        visited: &mut HashSet<String>,
        paths: &mut Vec<Vec<String>>,
    ) {
        current_path.push(current.to_string());
        visited.insert(current.to_string());

        if current == target {
            paths.push(current_path.clone());
        } else {
            for callee in self.callees(current) {
                if !visited.contains(&callee) {
                    self.call_paths_dfs(&callee, target, current_path, visited, paths);
                }
            }
        }

        current_path.pop();
        visited.remove(current);
    }

    /// Check if the call graph has cycles
    pub fn has_cycles(&self) -> bool {
        let mut visited = HashSet::new();
        let mut recursion_stack = HashSet::new();

        for function_id in &self.nodes {
            if !visited.contains(function_id)
                && self.has_cycle_dfs(function_id, &mut visited, &mut recursion_stack)
            {
                return true;
            }
        }
        false
    }

    fn has_cycle_dfs(
        &self,
        function_id: &str,
        visited: &mut HashSet<String>,
        recursion_stack: &mut HashSet<String>,
    ) -> bool {
        visited.insert(function_id.to_string());
        recursion_stack.insert(function_id.to_string());

        for callee in self.callees(function_id) {
            if !visited.contains(&callee) {
                if self.has_cycle_dfs(&callee, visited, recursion_stack) {
                    return true;
                }
            } else if recursion_stack.contains(&callee) {
                return true;
            }
        }

        recursion_stack.remove(function_id);
        false
    }

    /// Validate the call graph
    pub fn validate(&self) -> Result<(), String> {
        // Check that all edge endpoints are in nodes
        for edge in &self.edges {
            if !self.nodes.contains(&edge.caller) {
                return Err(format!(
                    "Edge references unknown caller function: {}",
                    edge.caller
                ));
            }
            if !self.nodes.contains(&edge.callee) {
                return Err(format!(
                    "Edge references unknown callee function: {}",
                    edge.callee
                ));
            }
        }

        // Check for duplicate nodes
        let mut seen = HashSet::new();
        for node in &self.nodes {
            if !seen.insert(node) {
                return Err(format!("Duplicate function ID: {}", node));
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

    /// Get statistics about the call graph
    pub fn statistics(&self) -> CallGraphStats {
        let mut call_type_counts = HashMap::new();
        for edge in &self.edges {
            *call_type_counts.entry(edge.call_type).or_insert(0) += 1;
        }

        let mut call_sites_per_edge = Vec::new();
        for edge in &self.edges {
            call_sites_per_edge.push(edge.call_sites.len());
        }

        CallGraphStats {
            function_count: self.function_count(),
            edge_count: self.edge_count(),
            root_functions: self.root_functions().len(),
            leaf_functions: self.leaf_functions().len(),
            has_cycles: self.has_cycles(),
            call_type_counts,
            total_call_sites: call_sites_per_edge.iter().sum(),
            average_call_sites_per_edge: if !call_sites_per_edge.is_empty() {
                call_sites_per_edge.iter().sum::<usize>() as f64 / call_sites_per_edge.len() as f64
            } else {
                0.0
            },
        }
    }

    /// Create a subgraph containing only specified functions and their connecting edges
    pub fn subgraph(&self, function_ids: &[String]) -> Self {
        let function_set: HashSet<String> = function_ids.iter().cloned().collect();

        let filtered_edges: Vec<CallGraphEdge> = self
            .edges
            .iter()
            .filter(|edge| {
                function_set.contains(&edge.caller) && function_set.contains(&edge.callee)
            })
            .cloned()
            .collect();

        Self {
            nodes: function_ids.to_vec(),
            edges: filtered_edges,
        }
    }
}

/// Statistics about a call graph
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyclass)]
pub struct CallGraphStats {
    pub function_count: usize,
    pub edge_count: usize,
    pub root_functions: usize,
    pub leaf_functions: usize,
    pub has_cycles: bool,
    pub call_type_counts: HashMap<CallType, usize>,
    pub total_call_sites: usize,
    pub average_call_sites_per_edge: f64,
}

impl fmt::Display for CallGraph {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CallGraph(functions={}, edges={})",
            self.nodes.len(),
            self.edges.len()
        )
    }
}

impl Default for CallGraph {
    fn default() -> Self {
        Self::new()
    }
}

// PyO3 bindings
#[cfg(feature = "python-ext")]
#[pymethods]
impl CallGraph {
    #[new]
    fn new_py() -> Self {
        Self::new()
    }

    fn __str__(&self) -> String {
        format!("{}", self)
    }

    fn __repr__(&self) -> String {
        format!(
            "CallGraph(function_count={}, edge_count={})",
            self.function_count(),
            self.edge_count()
        )
    }

    // Getters
    #[getter]
    fn nodes(&self) -> Vec<String> {
        self.nodes.clone()
    }

    #[getter]
    fn edges(&self) -> Vec<CallGraphEdge> {
        self.edges.clone()
    }

    // Methods
    #[pyo3(name = "add_node")]
    fn add_node_py(&mut self, function_id: String) {
        self.add_node(function_id);
    }

    #[pyo3(name = "add_nodes")]
    fn add_nodes_py(&mut self, function_ids: Vec<String>) {
        self.add_nodes(function_ids);
    }

    #[pyo3(name = "add_edge")]
    fn add_edge_py(&mut self, edge: CallGraphEdge) {
        self.add_edge(edge);
    }

    #[pyo3(name = "add_simple_edge")]
    fn add_simple_edge_py(&mut self, caller: String, callee: String, call_type: CallType) {
        self.add_simple_edge(caller, callee, call_type);
    }

    #[pyo3(name = "remove_edge")]
    fn remove_edge_py(&mut self, caller: String, callee: String, call_type: CallType) {
        self.remove_edge(&caller, &callee, call_type);
    }

    #[pyo3(name = "outgoing_edges")]
    fn outgoing_edges_py(&self, caller: String) -> Vec<CallGraphEdge> {
        self.outgoing_edges(&caller).into_iter().cloned().collect()
    }

    #[pyo3(name = "incoming_edges")]
    fn incoming_edges_py(&self, callee: String) -> Vec<CallGraphEdge> {
        self.incoming_edges(&callee).into_iter().cloned().collect()
    }

    #[pyo3(name = "callees")]
    fn callees_py(&self, caller: String) -> Vec<String> {
        self.callees(&caller)
    }

    #[pyo3(name = "callers")]
    fn callers_py(&self, callee: String) -> Vec<String> {
        self.callers(&callee)
    }

    #[pyo3(name = "has_callees")]
    fn has_callees_py(&self, function_id: String) -> bool {
        self.has_callees(&function_id)
    }

    #[pyo3(name = "has_callers")]
    fn has_callers_py(&self, function_id: String) -> bool {
        self.has_callers(&function_id)
    }

    #[pyo3(name = "root_functions")]
    fn root_functions_py(&self) -> Vec<String> {
        self.root_functions()
    }

    #[pyo3(name = "leaf_functions")]
    fn leaf_functions_py(&self) -> Vec<String> {
        self.leaf_functions()
    }

    #[pyo3(name = "is_empty")]
    fn is_empty_py(&self) -> bool {
        self.is_empty()
    }

    #[pyo3(name = "function_count")]
    fn function_count_py(&self) -> usize {
        self.function_count()
    }

    #[pyo3(name = "edge_count")]
    fn edge_count_py(&self) -> usize {
        self.edge_count()
    }

    #[pyo3(name = "call_depth")]
    fn call_depth_py(&self, function_id: String) -> Option<usize> {
        self.call_depth(&function_id)
    }

    #[pyo3(name = "has_cycles")]
    fn has_cycles_py(&self) -> bool {
        self.has_cycles()
    }

    #[pyo3(name = "find_call_paths")]
    fn find_call_paths_py(&self, start_function: String, end_function: String) -> Vec<Vec<String>> {
        self.find_call_paths(&start_function, &end_function)
    }

    #[pyo3(name = "validate")]
    fn validate_py(&self) -> PyResult<()> {
        self.validate()
            .map_err(pyo3::exceptions::PyValueError::new_err)
    }

    #[pyo3(name = "statistics")]
    fn statistics_py(&self) -> CallGraphStats {
        self.statistics()
    }

    #[pyo3(name = "subgraph")]
    fn subgraph_py(&self, function_ids: Vec<String>) -> Self {
        self.subgraph(&function_ids)
    }
}

// PyO3 bindings for CallGraphEdge
#[cfg(feature = "python-ext")]
#[pymethods]
impl CallGraphEdge {
    #[new]
    #[pyo3(signature = (caller, callee, call_type, call_sites=None, confidence=None))]
    fn new_py(
        caller: String,
        callee: String,
        call_type: CallType,
        call_sites: Option<Vec<Address>>,
        confidence: Option<f32>,
    ) -> Self {
        let mut edge = match confidence {
            Some(c) => Self::with_confidence(caller, callee, call_type, c),
            None => Self::new(caller, callee, call_type),
        };

        if let Some(sites) = call_sites {
            edge.call_sites = sites;
        }

        edge
    }

    fn __str__(&self) -> String {
        format!(
            "{} -> {} ({})",
            self.caller,
            self.callee,
            self.call_type.value()
        )
    }

    fn __repr__(&self) -> String {
        format!(
            "CallGraphEdge(caller='{}', callee='{}', call_type={:?}, call_sites={}, confidence={:?})",
            self.caller, self.callee, self.call_type, self.call_sites.len(), self.confidence
        )
    }

    // Getters
    #[getter]
    fn caller(&self) -> String {
        self.caller.clone()
    }

    #[getter]
    fn callee(&self) -> String {
        self.callee.clone()
    }

    #[getter]
    fn call_sites(&self) -> Vec<Address> {
        self.call_sites.clone()
    }

    #[getter]
    fn call_type(&self) -> CallType {
        self.call_type
    }

    #[getter]
    fn confidence(&self) -> Option<f32> {
        self.confidence
    }

    #[setter]
    fn set_confidence(&mut self, value: Option<f32>) {
        self.confidence = value;
    }

    /// Alternate constructor with call sites (Python API)
    #[staticmethod]
    #[pyo3(name = "with_call_sites")]
    fn with_call_sites_py(
        caller: String,
        callee: String,
        call_type: CallType,
        call_sites: Vec<Address>,
    ) -> Self {
        crate::core::call_graph::CallGraphEdge::with_call_sites(
            caller, callee, call_type, call_sites,
        )
    }

    // Methods
    #[pyo3(name = "add_call_site")]
    fn add_call_site_py(&mut self, address: Address) {
        self.add_call_site(address);
    }

    #[pyo3(name = "remove_call_site")]
    fn remove_call_site_py(&mut self, address: Address) {
        self.remove_call_site(&address);
    }
}

// PyO3 bindings for CallType
#[cfg(feature = "python-ext")]
#[pymethods]
impl CallType {
    #[pyo3(name = "value")]
    fn value_py(&self) -> String {
        match self {
            CallType::Direct => "direct",
            CallType::Indirect => "indirect",
            CallType::Virtual => "virtual",
            CallType::Tail => "tail",
        }
        .to_string()
    }
    fn __str__(&self) -> String {
        match self {
            CallType::Direct => "Direct",
            CallType::Indirect => "Indirect",
            CallType::Virtual => "Virtual",
            CallType::Tail => "Tail",
        }
        .to_string()
    }
    fn __repr__(&self) -> String {
        format!("CallType.{}", self.__str__())
    }
}

// PyO3 bindings for CallGraphStats
#[cfg(feature = "python-ext")]
#[pymethods]
impl CallGraphStats {
    #[new]
    #[pyo3(signature = (function_count, edge_count, root_functions, leaf_functions, has_cycles, call_type_counts, total_call_sites, average_call_sites_per_edge))]
    fn new_py(
        function_count: usize,
        edge_count: usize,
        root_functions: usize,
        leaf_functions: usize,
        has_cycles: bool,
        call_type_counts: HashMap<CallType, usize>,
        total_call_sites: usize,
        average_call_sites_per_edge: f64,
    ) -> Self {
        Self {
            function_count,
            edge_count,
            root_functions,
            leaf_functions,
            has_cycles,
            call_type_counts,
            total_call_sites,
            average_call_sites_per_edge,
        }
    }

    fn __str__(&self) -> String {
        format!(
            "CallGraphStats(functions={}, edges={}, roots={}, leaves={}, cycles={})",
            self.function_count,
            self.edge_count,
            self.root_functions,
            self.leaf_functions,
            self.has_cycles
        )
    }

    fn __repr__(&self) -> String {
        format!("{:?}", self)
    }

    // Getters
    #[getter]
    fn function_count(&self) -> usize {
        self.function_count
    }

    #[getter]
    fn edge_count(&self) -> usize {
        self.edge_count
    }

    #[getter]
    fn root_functions(&self) -> usize {
        self.root_functions
    }

    #[getter]
    fn leaf_functions(&self) -> usize {
        self.leaf_functions
    }

    #[getter]
    fn has_cycles(&self) -> bool {
        self.has_cycles
    }

    #[getter]
    fn call_type_counts(&self) -> std::collections::HashMap<String, usize> {
        let mut out = std::collections::HashMap::new();
        for (k, v) in &self.call_type_counts {
            let key = match k {
                CallType::Direct => "Direct",
                CallType::Indirect => "Indirect",
                CallType::Virtual => "Virtual",
                CallType::Tail => "Tail",
            }
            .to_string();
            out.insert(key, *v);
        }
        out
    }

    #[getter]
    fn total_call_sites(&self) -> usize {
        self.total_call_sites
    }

    #[getter]
    fn average_call_sites_per_edge(&self) -> f64 {
        self.average_call_sites_per_edge
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_call_graph() -> CallGraph {
        let mut cg = CallGraph::new();

        // Add functions
        cg.add_node("main".to_string());
        cg.add_node("func1".to_string());
        cg.add_node("func2".to_string());
        cg.add_node("func3".to_string());
        cg.add_node("helper".to_string());

        // Add call edges
        cg.add_simple_edge("main".to_string(), "func1".to_string(), CallType::Direct);
        cg.add_simple_edge("main".to_string(), "func2".to_string(), CallType::Direct);
        cg.add_simple_edge("func1".to_string(), "helper".to_string(), CallType::Direct);
        cg.add_simple_edge("func2".to_string(), "helper".to_string(), CallType::Direct);
        cg.add_simple_edge("func2".to_string(), "func3".to_string(), CallType::Direct);
        cg.add_simple_edge("helper".to_string(), "func3".to_string(), CallType::Direct);
        cg.add_simple_edge("func3".to_string(), "func1".to_string(), CallType::Direct); // Creates a cycle: func3 -> func1 -> helper -> func3

        cg
    }

    #[test]
    fn test_call_graph_creation() {
        let cg = CallGraph::new();
        assert!(cg.is_empty());
        assert_eq!(cg.function_count(), 0);
        assert_eq!(cg.edge_count(), 0);
    }

    #[test]
    fn test_add_functions_and_edges() {
        let mut cg = CallGraph::new();
        cg.add_node("caller".to_string());
        cg.add_node("callee".to_string());

        let edge = CallGraphEdge::new("caller".to_string(), "callee".to_string(), CallType::Direct);
        cg.add_edge(edge);

        assert_eq!(cg.function_count(), 2);
        assert_eq!(cg.edge_count(), 1);
        assert_eq!(cg.callees("caller"), vec!["callee".to_string()]);
        assert_eq!(cg.callers("callee"), vec!["caller".to_string()]);
    }

    #[test]
    fn test_root_and_leaf_functions() {
        let cg = create_test_call_graph();

        let root_functions = cg.root_functions();
        let leaf_functions = cg.leaf_functions();

        assert_eq!(root_functions, vec!["main".to_string()]);
        assert_eq!(leaf_functions, Vec::<String>::new()); // No leaf functions due to cycle
    }

    #[test]
    fn test_has_cycles() {
        let cg = create_test_call_graph();
        assert!(cg.has_cycles()); // func3 -> func1 -> helper -> ... creates cycle

        let mut acyclic_cg = CallGraph::new();
        acyclic_cg.add_node("a".to_string());
        acyclic_cg.add_node("b".to_string());
        acyclic_cg.add_simple_edge("a".to_string(), "b".to_string(), CallType::Direct);
        assert!(!acyclic_cg.has_cycles());
    }

    #[test]
    fn test_call_depth() {
        let cg = create_test_call_graph();

        // Check that call depth is calculated for all functions
        assert!(cg.call_depth("main").is_some());
        assert!(cg.call_depth("func1").is_some());
        assert!(cg.call_depth("helper").is_some());
    }

    #[test]
    fn test_validation() {
        let mut cg = CallGraph::new();
        cg.add_node("valid".to_string());

        // Valid edge
        let valid_edge =
            CallGraphEdge::new("valid".to_string(), "valid".to_string(), CallType::Direct);
        cg.add_edge(valid_edge);
        assert!(cg.validate().is_ok());

        // Invalid edge (references unknown function)
        let invalid_edge =
            CallGraphEdge::new("valid".to_string(), "invalid".to_string(), CallType::Direct);
        cg.edges.push(invalid_edge);
        assert!(cg.validate().is_err());
    }

    #[test]
    fn test_statistics() {
        let cg = create_test_call_graph();
        let stats = cg.statistics();

        assert_eq!(stats.function_count, 5);
        assert_eq!(stats.edge_count, 7);
        assert_eq!(stats.root_functions, 1);
        assert_eq!(stats.leaf_functions, 0);
        assert!(stats.has_cycles);
        assert_eq!(stats.call_type_counts[&CallType::Direct], 7);
    }

    #[test]
    fn test_subgraph() {
        let cg = create_test_call_graph();
        let subgraph = cg.subgraph(&[
            "main".to_string(),
            "func1".to_string(),
            "helper".to_string(),
        ]);

        assert_eq!(subgraph.function_count(), 3);
        assert_eq!(subgraph.edge_count(), 2); // main->func1, func1->helper
    }
}
