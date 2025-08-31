//! Tool metadata for tracking analysis tools and their configurations.
//!
//! ToolMetadata captures information about tools used in the analysis pipeline,
//! including their identity, version, parameters, and classification.

use pyo3::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

/// Classification of tool source types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[pyclass]
pub enum SourceKind {
    /// Static analysis tools (e.g., disassemblers, loaders)
    Static,
    /// Dynamic analysis tools (e.g., debuggers, tracers)
    Dynamic,
    /// Heuristic-based tools (e.g., pattern matchers, anomaly detectors)
    Heuristic,
    /// External tools or services (e.g., third-party analyzers)
    External,
}

#[pymethods]
impl SourceKind {
    /// Get string representation of the source kind.
    pub fn __str__(&self) -> String {
        match self {
            SourceKind::Static => "Static".to_string(),
            SourceKind::Dynamic => "Dynamic".to_string(),
            SourceKind::Heuristic => "Heuristic".to_string(),
            SourceKind::External => "External".to_string(),
        }
    }

    /// Get repr representation of the source kind.
    pub fn __repr__(&self) -> String {
        format!("SourceKind.{}", self.__str__())
    }

    /// Check equality with another SourceKind instance.
    pub fn __richcmp__(&self, other: &SourceKind, op: pyo3::basic::CompareOp) -> bool {
        match op {
            pyo3::basic::CompareOp::Eq => self == other,
            pyo3::basic::CompareOp::Ne => self != other,
            _ => false,
        }
    }
}

/// Metadata describing a tool used in the analysis pipeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[pyclass]
pub struct ToolMetadata {
    /// Unique tool name (e.g., "identify", "loader.lief", "disasm.capstone")
    pub name: String,
    /// Semantic version or git SHA
    pub version: String,
    /// Optional map of parameter names to values
    pub parameters: Option<HashMap<String, String>>,
    /// Optional classification of the tool's analysis approach
    pub source_kind: Option<SourceKind>,
}

#[pymethods]
impl ToolMetadata {
    /// Create a new ToolMetadata instance.
    ///
    /// # Arguments
    /// * `name` - Unique tool name
    /// * `version` - Semantic version or git SHA
    /// * `parameters` - Optional map of parameter names to values
    /// * `source_kind` - Optional classification of the tool's analysis approach
    ///
    /// # Returns
    /// New ToolMetadata instance
    #[new]
    #[pyo3(signature = (name, version, parameters=None, source_kind=None))]
    pub fn new(
        name: String,
        version: String,
        parameters: Option<HashMap<String, String>>,
        source_kind: Option<SourceKind>,
    ) -> PyResult<Self> {
        let metadata = Self {
            name,
            version,
            parameters,
            source_kind,
        };

        // Validate the metadata
        metadata
            .validate()
            .map_err(PyErr::new::<pyo3::exceptions::PyValueError, _>)?;
        Ok(metadata)
    }

    /// Get the tool name.
    #[getter]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the tool version.
    #[getter]
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Get the tool parameters.
    #[getter]
    pub fn parameters(&self) -> Option<&HashMap<String, String>> {
        self.parameters.as_ref()
    }

    /// Get the tool source kind.
    #[getter]
    pub fn source_kind(&self) -> Option<SourceKind> {
        self.source_kind
    }

    /// Set the tool parameters.
    #[setter]
    pub fn set_parameters(&mut self, parameters: Option<HashMap<String, String>>) {
        self.parameters = parameters;
    }

    /// Set the tool parameters (method version for Python).
    pub fn set_parameters_py(&mut self, parameters: HashMap<String, String>) {
        self.parameters = Some(parameters);
    }

    /// Set the tool source kind.
    #[setter]
    pub fn set_source_kind(&mut self, source_kind: Option<SourceKind>) {
        self.source_kind = source_kind;
    }

    /// Set the tool source kind (method version for Python).
    pub fn set_source_kind_py(&mut self, source_kind: SourceKind) {
        self.source_kind = Some(source_kind);
    }

    /// Check equality with another ToolMetadata instance.
    pub fn __richcmp__(&self, other: &ToolMetadata, op: pyo3::basic::CompareOp) -> bool {
        match op {
            pyo3::basic::CompareOp::Eq => {
                self.name == other.name
                    && self.version == other.version
                    && self.parameters == other.parameters
                    && self.source_kind == other.source_kind
            }
            pyo3::basic::CompareOp::Ne => {
                self.name != other.name
                    || self.version != other.version
                    || self.parameters != other.parameters
                    || self.source_kind != other.source_kind
            }
            _ => false,
        }
    }

    /// Get string representation of the tool metadata.
    pub fn __str__(&self) -> String {
        match &self.source_kind {
            Some(kind) => format!("{}@{} ({})", self.name, self.version, kind.__str__()),
            None => format!("{}@{}", self.name, self.version),
        }
    }

    /// Get repr representation of the tool metadata.
    pub fn __repr__(&self) -> String {
        let params_str = match &self.parameters {
            Some(params) if !params.is_empty() => format!(", parameters={:?}", params),
            _ => "".to_string(),
        };
        let kind_str = match &self.source_kind {
            Some(kind) => format!(", source_kind={}", kind.__repr__()),
            None => "".to_string(),
        };
        format!(
            "ToolMetadata(name={:?}, version={:?}{}{})",
            self.name, self.version, params_str, kind_str
        )
    }

    /// Check if the tool metadata is valid.
    ///
    /// # Returns
    /// true if valid, false otherwise
    pub fn is_valid(&self) -> bool {
        self.validate().is_ok()
    }

    /// Get a parameter value by name.
    ///
    /// # Arguments
    /// * `key` - Parameter name
    ///
    /// # Returns
    /// Parameter value if found, None otherwise
    pub fn get_parameter(&self, key: &str) -> Option<&String> {
        self.parameters.as_ref()?.get(key)
    }

    /// Set a parameter value.
    ///
    /// # Arguments
    /// * `key` - Parameter name
    /// * `value` - Parameter value
    pub fn set_parameter(&mut self, key: String, value: String) {
        self.parameters
            .get_or_insert_with(HashMap::new)
            .insert(key, value);
    }

    /// Remove a parameter.
    ///
    /// # Arguments
    /// * `key` - Parameter name to remove
    ///
    /// # Returns
    /// Previous value if the parameter existed, None otherwise
    pub fn remove_parameter(&mut self, key: &str) -> Option<String> {
        self.parameters.as_mut()?.remove(key)
    }

    /// Get the number of parameters.
    ///
    /// # Returns
    /// Number of parameters
    pub fn parameter_count(&self) -> usize {
        self.parameters.as_ref().map_or(0, |p| p.len())
    }

    /// Check if the tool has any parameters.
    ///
    /// # Returns
    /// true if parameters exist, false otherwise
    pub fn has_parameters(&self) -> bool {
        self.parameters.as_ref().is_some_and(|p| !p.is_empty())
    }

    /// Serialize to JSON string.
    ///
    /// # Returns
    /// JSON string representation
    pub fn to_json(&self) -> PyResult<String> {
        serde_json::to_string(self).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Serialization error: {}", e))
        })
    }

    /// Deserialize from JSON string.
    ///
    /// # Arguments
    /// * `json_str` - JSON string to deserialize
    ///
    /// # Returns
    /// Deserialized ToolMetadata instance
    #[staticmethod]
    pub fn from_json(json_str: &str) -> PyResult<Self> {
        serde_json::from_str(json_str).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Deserialization error: {}", e))
        })
    }

    /// Serialize to binary data.
    ///
    /// # Returns
    /// Binary representation as bytes
    pub fn to_binary(&self) -> PyResult<Vec<u8>> {
        // Use bincode with explicit configuration
        bincode::serialize(self).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                "Binary serialization error: {}",
                e
            ))
        })
    }

    /// Deserialize from binary data.
    ///
    /// # Arguments
    /// * `data` - Binary data to deserialize
    ///
    /// # Returns
    /// Deserialized ToolMetadata instance
    #[staticmethod]
    pub fn from_binary(data: Vec<u8>) -> PyResult<Self> {
        // Try deserialization and provide more detailed error info
        match bincode::deserialize(&data) {
            Ok(result) => Ok(result),
            Err(e) => {
                eprintln!("Bincode deserialization failed: {}", e);
                eprintln!("Data length: {}", data.len());
                eprintln!("Data: {:?}", &data[..std::cmp::min(data.len(), 50)]);
                Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                    "Binary deserialization error: {}",
                    e
                )))
            }
        }
    }
}

impl ToolMetadata {
    /// Validate the tool metadata.
    ///
    /// # Returns
    /// Ok(()) if valid, Err with description otherwise
    pub fn validate(&self) -> Result<(), String> {
        if self.name.trim().is_empty() {
            return Err("Tool name cannot be empty".to_string());
        }

        if self.version.trim().is_empty() {
            return Err("Tool version cannot be empty".to_string());
        }

        // Validate parameter keys and values
        if let Some(params) = &self.parameters {
            for (key, value) in params {
                if key.trim().is_empty() {
                    return Err("Parameter key cannot be empty".to_string());
                }
                if value.trim().is_empty() {
                    return Err(format!("Parameter '{}' value cannot be empty", key));
                }
            }
        }

        Ok(())
    }
}

impl fmt::Display for ToolMetadata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.__str__())
    }
}

impl fmt::Display for SourceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.__str__())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tool_metadata_creation() {
        let metadata = ToolMetadata::new(
            "disasm.capstone".to_string(),
            "5.0.1".to_string(),
            None,
            Some(SourceKind::Static),
        )
        .unwrap();

        assert_eq!(metadata.name, "disasm.capstone");
        assert_eq!(metadata.version, "5.0.1");
        assert_eq!(metadata.source_kind, Some(SourceKind::Static));
        assert!(!metadata.has_parameters());
    }

    #[test]
    fn test_tool_metadata_with_parameters() {
        let mut params = HashMap::new();
        params.insert("arch".to_string(), "x86_64".to_string());
        params.insert("syntax".to_string(), "intel".to_string());

        let metadata = ToolMetadata::new(
            "disasm.capstone".to_string(),
            "5.0.1".to_string(),
            Some(params.clone()),
            Some(SourceKind::Static),
        )
        .unwrap();

        assert_eq!(metadata.parameter_count(), 2);
        assert_eq!(metadata.get_parameter("arch"), Some(&"x86_64".to_string()));
        assert_eq!(metadata.get_parameter("syntax"), Some(&"intel".to_string()));
        assert_eq!(metadata.get_parameter("nonexistent"), None);
    }

    #[test]
    fn test_tool_metadata_validation() {
        // Valid metadata
        let valid =
            ToolMetadata::new("test.tool".to_string(), "1.0.0".to_string(), None, None).unwrap();
        assert!(valid.is_valid());

        // Invalid: empty name
        let invalid_name = ToolMetadata {
            name: "".to_string(),
            version: "1.0.0".to_string(),
            parameters: None,
            source_kind: None,
        };
        assert!(!invalid_name.is_valid());

        // Invalid: empty version
        let invalid_version = ToolMetadata {
            name: "test.tool".to_string(),
            version: "".to_string(),
            parameters: None,
            source_kind: None,
        };
        assert!(!invalid_version.is_valid());

        // Invalid: empty parameter key
        let mut params = HashMap::new();
        params.insert("".to_string(), "value".to_string());
        let invalid_param_key = ToolMetadata {
            name: "test.tool".to_string(),
            version: "1.0.0".to_string(),
            parameters: Some(params),
            source_kind: None,
        };
        assert!(!invalid_param_key.is_valid());

        // Invalid: empty parameter value
        let mut params = HashMap::new();
        params.insert("key".to_string(), "".to_string());
        let invalid_param_value = ToolMetadata {
            name: "test.tool".to_string(),
            version: "1.0.0".to_string(),
            parameters: Some(params),
            source_kind: None,
        };
        assert!(!invalid_param_value.is_valid());
    }

    #[test]
    fn test_parameter_operations() {
        let mut metadata =
            ToolMetadata::new("test.tool".to_string(), "1.0.0".to_string(), None, None).unwrap();

        // Initially no parameters
        assert!(!metadata.has_parameters());
        assert_eq!(metadata.parameter_count(), 0);

        // Add parameters
        metadata.set_parameter("arch".to_string(), "x86_64".to_string());
        metadata.set_parameter("syntax".to_string(), "intel".to_string());

        assert!(metadata.has_parameters());
        assert_eq!(metadata.parameter_count(), 2);
        assert_eq!(metadata.get_parameter("arch"), Some(&"x86_64".to_string()));

        // Remove parameter
        let removed = metadata.remove_parameter("arch");
        assert_eq!(removed, Some("x86_64".to_string()));
        assert_eq!(metadata.parameter_count(), 1);
        assert_eq!(metadata.get_parameter("arch"), None);

        // Remove non-existent parameter
        let removed = metadata.remove_parameter("nonexistent");
        assert_eq!(removed, None);
    }

    #[test]
    fn test_serialization() {
        let mut params = HashMap::new();
        params.insert("arch".to_string(), "x86_64".to_string());

        let original = ToolMetadata::new(
            "disasm.capstone".to_string(),
            "5.0.1".to_string(),
            Some(params),
            Some(SourceKind::Static),
        )
        .unwrap();

        // JSON serialization
        let json_str = original.to_json().unwrap();
        let deserialized = ToolMetadata::from_json(&json_str).unwrap();
        assert_eq!(original, deserialized);

        // Binary serialization
        let binary_data = original.to_binary().unwrap();
        let deserialized = ToolMetadata::from_binary(binary_data).unwrap();
        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_display() {
        let metadata = ToolMetadata::new(
            "disasm.capstone".to_string(),
            "5.0.1".to_string(),
            None,
            Some(SourceKind::Static),
        )
        .unwrap();

        assert_eq!(format!("{}", metadata), "disasm.capstone@5.0.1 (Static)");
        assert!(format!("{:?}", metadata).contains("ToolMetadata"));
    }

    #[test]
    fn test_source_kind_display() {
        assert_eq!(format!("{}", SourceKind::Static), "Static");
        assert_eq!(format!("{}", SourceKind::Dynamic), "Dynamic");
        assert_eq!(format!("{}", SourceKind::Heuristic), "Heuristic");
        assert_eq!(format!("{}", SourceKind::External), "External");
    }
}
