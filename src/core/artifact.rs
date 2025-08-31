//! Artifact type for typed result envelopes with caching and provenance.
//!
//! Artifacts represent the outputs of analysis tools and passes, providing
//! a standardized envelope for data with metadata about its creation,
//! dependencies, and structure.

use crate::core::tool_metadata::ToolMetadata;
use chrono::{DateTime, Utc};
use pyo3::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::fmt;

/// Typed result envelope with caching and provenance.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[pyclass]
pub struct Artifact {
    /// Unique identifier for this artifact
    pub id: String,
    /// Tool that produced this artifact
    pub tool: ToolMetadata,
    /// ISO 8601 timestamp when this artifact was created
    pub created_at: DateTime<Utc>,
    /// References to input artifacts (by ID)
    pub input_refs: Vec<String>,
    /// Schema version for data structure compatibility
    pub schema_version: String,
    /// Type of data contained (e.g., "Binary", "CFG", "Symbols")
    pub data_type: String,
    /// The actual data payload as JSON
    pub data: Value,
    /// Optional additional metadata
    pub meta: Option<HashMap<String, Value>>,
}

#[pymethods]
impl Artifact {
    /// Create a new Artifact instance.
    ///
    /// # Arguments
    /// * `id` - Unique identifier for this artifact
    /// * `tool` - Tool that produced this artifact
    /// * `data_type` - Type of data contained (e.g., "Binary", "CFG", "Symbols")
    /// * `data` - The actual data payload as JSON string
    /// * `input_refs` - Optional references to input artifacts
    /// * `schema_version` - Optional schema version (defaults to "1.0")
    /// * `meta` - Optional additional metadata as JSON string
    ///
    /// # Returns
    /// New Artifact instance
    #[new]
    #[pyo3(signature = (
        id,
        tool,
        data_type,
        data,
        input_refs=None,
        schema_version="1.0".to_string(),
        meta=None
    ))]
    pub fn new(
        id: String,
        tool: ToolMetadata,
        data_type: String,
        data: String,
        input_refs: Option<Vec<String>>,
        schema_version: String,
        meta: Option<String>,
    ) -> PyResult<Self> {
        // Parse JSON strings to Values
        let data_value: Value = serde_json::from_str(&data).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Invalid JSON for data: {}", e))
        })?;

        let meta_value = meta
            .map(|m| {
                serde_json::from_str(&m).map_err(|e| {
                    PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                        "Invalid JSON for meta: {}",
                        e
                    ))
                })
            })
            .transpose()?;

        let artifact = Self {
            id,
            tool,
            created_at: chrono::Utc::now(),
            input_refs: input_refs.unwrap_or_default(),
            schema_version,
            data_type,
            data: data_value,
            meta: meta_value,
        };

        // Validate the artifact
        artifact
            .validate()
            .map_err(PyErr::new::<pyo3::exceptions::PyValueError, _>)?;
        Ok(artifact)
    }

    /// Get the artifact ID.
    #[getter]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Get the tool that produced this artifact.
    #[getter]
    pub fn tool(&self) -> ToolMetadata {
        self.tool.clone()
    }

    /// Get the creation timestamp as ISO 8601 string.
    #[getter]
    pub fn created_at(&self) -> String {
        self.created_at.to_rfc3339()
    }

    /// Get the input artifact references.
    #[getter]
    pub fn input_refs(&self) -> Vec<String> {
        self.input_refs.clone()
    }

    /// Get the schema version.
    #[getter]
    pub fn schema_version(&self) -> &str {
        &self.schema_version
    }

    /// Get the data type.
    #[getter]
    pub fn data_type(&self) -> &str {
        &self.data_type
    }

    /// Get the data payload as JSON string.
    #[getter]
    pub fn data(&self) -> String {
        serde_json::to_string(&self.data).unwrap_or_else(|_| "{}".to_string())
    }

    /// Get the metadata as JSON string.
    #[getter]
    pub fn meta(&self) -> Option<String> {
        self.meta
            .as_ref()
            .map(|m| serde_json::to_string(m).unwrap_or_else(|_| "{}".to_string()))
    }

    /// Set the metadata from JSON string.
    #[setter]
    pub fn set_meta(&mut self, meta: Option<String>) -> PyResult<()> {
        self.meta = meta
            .map(|m| {
                serde_json::from_str(&m).map_err(|e| {
                    PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                        "Invalid JSON for meta: {}",
                        e
                    ))
                })
            })
            .transpose()?;
        Ok(())
    }

    /// Add an input reference.
    pub fn add_input_ref(&mut self, input_ref: String) {
        self.input_refs.push(input_ref);
    }

    /// Remove an input reference.
    pub fn remove_input_ref(&mut self, input_ref: &str) -> bool {
        if let Some(pos) = self.input_refs.iter().position(|r| r == input_ref) {
            self.input_refs.remove(pos);
            true
        } else {
            false
        }
    }

    /// Get the number of input references.
    pub fn input_ref_count(&self) -> usize {
        self.input_refs.len()
    }

    /// Check if the artifact has any input references.
    pub fn has_input_refs(&self) -> bool {
        !self.input_refs.is_empty()
    }

    /// Check equality with another Artifact instance.
    pub fn __richcmp__(&self, other: &Artifact, op: pyo3::basic::CompareOp) -> bool {
        match op {
            pyo3::basic::CompareOp::Eq => {
                self.id == other.id
                    && self.tool == other.tool
                    && self.input_refs == other.input_refs
                    && self.schema_version == other.schema_version
                    && self.data_type == other.data_type
                    && self.data == other.data
                    && self.meta == other.meta
                // Note: created_at is not compared for equality as it's a timestamp
            }
            pyo3::basic::CompareOp::Ne => {
                !(self.id == other.id
                    && self.tool == other.tool
                    && self.input_refs == other.input_refs
                    && self.schema_version == other.schema_version
                    && self.data_type == other.data_type
                    && self.data == other.data
                    && self.meta == other.meta)
            }
            _ => false,
        }
    }

    /// Get string representation of the artifact.
    pub fn __str__(&self) -> String {
        format!(
            "Artifact(id={}, tool={}, data_type={}, schema={})",
            self.id, self.tool, self.data_type, self.schema_version
        )
    }

    /// Get repr representation of the artifact.
    pub fn __repr__(&self) -> String {
        format!(
            "Artifact(id={:?}, tool={:?}, data_type={:?}, schema_version={:?}, input_refs={:?})",
            self.id, self.tool, self.data_type, self.schema_version, self.input_refs
        )
    }

    /// Check if the artifact is valid.
    pub fn is_valid(&self) -> bool {
        self.validate().is_ok()
    }

    /// Serialize to JSON string.
    pub fn to_json(&self) -> PyResult<String> {
        serde_json::to_string(self).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Serialization error: {}", e))
        })
    }

    /// Deserialize from JSON string.
    #[staticmethod]
    pub fn from_json(json_str: &str) -> PyResult<Self> {
        serde_json::from_str(json_str).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Deserialization error: {}", e))
        })
    }

    /// Serialize to binary data.
    pub fn to_binary(&self) -> PyResult<Vec<u8>> {
        bincode::serialize(self).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                "Binary serialization error: {}",
                e
            ))
        })
    }

    /// Deserialize from binary data.
    #[staticmethod]
    pub fn from_binary(data: Vec<u8>) -> PyResult<Self> {
        bincode::deserialize(&data).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                "Binary deserialization error: {}",
                e
            ))
        })
    }

    /// Get data as JSON string.
    pub fn data_as_json(&self) -> PyResult<String> {
        serde_json::to_string(&self.data).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Serialization error: {}", e))
        })
    }

    /// Get meta as JSON string.
    pub fn meta_as_json(&self) -> PyResult<Option<String>> {
        self.meta
            .as_ref()
            .map(|m| {
                serde_json::to_string(m).map_err(|e| {
                    PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                        "Serialization error: {}",
                        e
                    ))
                })
            })
            .transpose()
    }
}

impl Artifact {
    /// Validate the artifact.
    pub fn validate(&self) -> Result<(), String> {
        if self.id.trim().is_empty() {
            return Err("Artifact ID cannot be empty".to_string());
        }

        if self.schema_version.trim().is_empty() {
            return Err("Schema version cannot be empty".to_string());
        }

        if self.data_type.trim().is_empty() {
            return Err("Data type cannot be empty".to_string());
        }

        // Validate tool metadata
        if let Err(e) = self.tool.validate() {
            return Err(format!("Invalid tool metadata: {}", e));
        }

        // Validate input refs are not empty
        for input_ref in &self.input_refs {
            if input_ref.trim().is_empty() {
                return Err("Input reference cannot be empty".to_string());
            }
        }

        Ok(())
    }
}

impl fmt::Display for Artifact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.__str__())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::tool_metadata::{SourceKind, ToolMetadata};
    use serde_json::json;

    #[test]
    fn test_artifact_creation() {
        let tool = ToolMetadata::new(
            "test.tool".to_string(),
            "1.0.0".to_string(),
            None,
            Some(SourceKind::Static),
        )
        .unwrap();

        let data = json!({"key": "value", "number": 42});
        let input_refs = vec!["input1".to_string(), "input2".to_string()];

        let artifact = Artifact {
            id: "test-artifact".to_string(),
            tool,
            created_at: Utc::now(),
            input_refs: input_refs.clone(),
            schema_version: "1.0".to_string(),
            data_type: "TestData".to_string(),
            data: data.clone(),
            meta: None,
        };

        assert_eq!(artifact.id, "test-artifact");
        assert_eq!(artifact.tool.name, "test.tool");
        assert_eq!(artifact.input_refs, input_refs);
        assert_eq!(artifact.schema_version, "1.0");
        assert_eq!(artifact.data_type, "TestData");
        assert_eq!(artifact.data, data);
        assert!(artifact.meta.is_none());
    }

    #[test]
    fn test_artifact_validation() {
        let tool =
            ToolMetadata::new("test.tool".to_string(), "1.0.0".to_string(), None, None).unwrap();

        let data = json!({"test": true});

        // Valid artifact
        let valid = Artifact {
            id: "valid-id".to_string(),
            tool: tool.clone(),
            created_at: Utc::now(),
            input_refs: vec![],
            schema_version: "1.0".to_string(),
            data_type: "Test".to_string(),
            data: data.clone(),
            meta: None,
        };
        assert!(valid.is_valid());

        // Invalid: empty ID
        let invalid_id = Artifact {
            id: "".to_string(),
            ..valid.clone()
        };
        assert!(!invalid_id.is_valid());

        // Invalid: empty schema version
        let invalid_schema = Artifact {
            schema_version: "".to_string(),
            ..valid.clone()
        };
        assert!(!invalid_schema.is_valid());

        // Invalid: empty data type
        let invalid_data_type = Artifact {
            data_type: "".to_string(),
            ..valid.clone()
        };
        assert!(!invalid_data_type.is_valid());

        // Invalid: empty input ref
        let invalid_input_ref = Artifact {
            input_refs: vec!["".to_string()],
            ..valid.clone()
        };
        assert!(!invalid_input_ref.is_valid());
    }

    #[test]
    fn test_input_ref_operations() {
        let tool =
            ToolMetadata::new("test.tool".to_string(), "1.0.0".to_string(), None, None).unwrap();

        let mut artifact = Artifact {
            id: "test".to_string(),
            tool,
            created_at: Utc::now(),
            input_refs: vec!["input1".to_string()],
            schema_version: "1.0".to_string(),
            data_type: "Test".to_string(),
            data: json!(null),
            meta: None,
        };

        assert_eq!(artifact.input_ref_count(), 1);
        assert!(artifact.has_input_refs());

        // Add input ref
        artifact.add_input_ref("input2".to_string());
        assert_eq!(artifact.input_ref_count(), 2);
        assert_eq!(artifact.input_refs, vec!["input1", "input2"]);

        // Remove input ref
        assert!(artifact.remove_input_ref("input1"));
        assert_eq!(artifact.input_ref_count(), 1);
        assert_eq!(artifact.input_refs, vec!["input2"]);

        // Try to remove non-existent ref
        assert!(!artifact.remove_input_ref("nonexistent"));
        assert_eq!(artifact.input_ref_count(), 1);
    }

    #[test]
    fn test_serialization() {
        let tool = ToolMetadata::new(
            "test.tool".to_string(),
            "1.0.0".to_string(),
            Some([("key".to_string(), "value".to_string())].into()),
            Some(SourceKind::Static),
        )
        .unwrap();

        let meta = [("meta_key".to_string(), json!("meta_value"))].into();

        let original = Artifact {
            id: "test-artifact".to_string(),
            tool,
            created_at: Utc::now(),
            input_refs: vec!["input1".to_string()],
            schema_version: "1.0".to_string(),
            data_type: "TestData".to_string(),
            data: json!({"key": "value", "array": [1, 2, 3]}),
            meta: Some(meta),
        };

        // JSON serialization
        let json_str = original.to_json().unwrap();
        let deserialized = Artifact::from_json(&json_str).unwrap();

        // Note: created_at won't be exactly equal due to timestamp precision
        assert_eq!(original.id, deserialized.id);
        assert_eq!(original.tool, deserialized.tool);
        assert_eq!(original.input_refs, deserialized.input_refs);
        assert_eq!(original.schema_version, deserialized.schema_version);
        assert_eq!(original.data_type, deserialized.data_type);
        assert_eq!(original.data, deserialized.data);
        assert_eq!(original.meta, deserialized.meta);

        // Binary serialization
        let binary_data = original.to_binary().unwrap();
        let deserialized = Artifact::from_binary(binary_data).unwrap();

        assert_eq!(original.id, deserialized.id);
        assert_eq!(original.tool, deserialized.tool);
        assert_eq!(original.input_refs, deserialized.input_refs);
        assert_eq!(original.schema_version, deserialized.schema_version);
        assert_eq!(original.data_type, deserialized.data_type);
        assert_eq!(original.data, deserialized.data);
        assert_eq!(original.meta, deserialized.meta);
    }

    #[test]
    fn test_display() {
        let tool =
            ToolMetadata::new("test.tool".to_string(), "1.0.0".to_string(), None, None).unwrap();

        let artifact = Artifact {
            id: "test-artifact".to_string(),
            tool,
            created_at: Utc::now(),
            input_refs: vec![],
            schema_version: "1.0".to_string(),
            data_type: "TestData".to_string(),
            data: json!(null),
            meta: None,
        };

        let display_str = format!("{}", artifact);
        assert!(display_str.contains("Artifact"));
        assert!(display_str.contains("test-artifact"));
        assert!(display_str.contains("TestData"));
        assert!(display_str.contains("1.0"));
    }
}
