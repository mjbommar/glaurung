//! Tool metadata for tracking analysis tools and their configurations.

use std::collections::HashMap;
use std::fmt;

use bincode::{Decode, Encode};
use serde::{Deserialize, Serialize};

#[cfg(feature = "python-ext")]
use pyo3::prelude::*;

/// Classification of tool source types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Encode, Decode)]
#[cfg_attr(feature = "python-ext", pyclass)]
pub enum SourceKind {
    Static,
    Dynamic,
    Heuristic,
    External,
}

#[cfg(feature = "python-ext")]
#[pymethods]
impl SourceKind {
    pub fn __str__(&self) -> String {
        match self {
            SourceKind::Static => "Static".into(),
            SourceKind::Dynamic => "Dynamic".into(),
            SourceKind::Heuristic => "Heuristic".into(),
            SourceKind::External => "External".into(),
        }
    }
    pub fn __repr__(&self) -> String {
        format!("SourceKind.{}", self.__str__())
    }
    pub fn __richcmp__(&self, other: &SourceKind, op: pyo3::basic::CompareOp) -> bool {
        matches!(op, pyo3::basic::CompareOp::Eq) && self == other
            || matches!(op, pyo3::basic::CompareOp::Ne) && self != other
    }
}

/// Metadata describing a tool used in the analysis pipeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[cfg_attr(feature = "python-ext", pyclass)]
pub struct ToolMetadata {
    pub name: String,
    pub version: String,
    pub parameters: Option<HashMap<String, String>>,
    pub source_kind: Option<SourceKind>,
}

impl ToolMetadata {
    pub fn new_pure(
        name: String,
        version: String,
        parameters: Option<HashMap<String, String>>,
        source_kind: Option<SourceKind>,
    ) -> Result<Self, String> {
        let m = Self {
            name,
            version,
            parameters,
            source_kind,
        };
        m.validate()?;
        Ok(m)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.name.trim().is_empty() {
            return Err("Tool name cannot be empty".into());
        }
        if self.version.trim().is_empty() {
            return Err("Tool version cannot be empty".into());
        }
        if let Some(p) = &self.parameters {
            for (k, v) in p {
                if k.trim().is_empty() {
                    return Err("parameter key must not be empty".into());
                }
                if v.trim().is_empty() {
                    return Err("parameter value must not be empty".into());
                }
            }
        }
        Ok(())
    }

    pub fn is_valid(&self) -> bool {
        self.validate().is_ok()
    }

    pub fn to_json_string(&self) -> Result<String, crate::error::GlaurungError> {
        serde_json::to_string(self)
            .map_err(|e| crate::error::GlaurungError::Serialization(e.to_string()))
    }
    pub fn from_json_str(s: &str) -> Result<Self, crate::error::GlaurungError> {
        serde_json::from_str(s)
            .map_err(|e| crate::error::GlaurungError::Serialization(e.to_string()))
    }
    pub fn to_bincode(&self) -> Result<Vec<u8>, crate::error::GlaurungError> {
        let cfg = bincode::config::standard();
        bincode::encode_to_vec(self, cfg)
            .map_err(|e| crate::error::GlaurungError::Serialization(e.to_string()))
    }
    pub fn from_bincode(data: &[u8]) -> Result<Self, crate::error::GlaurungError> {
        let cfg = bincode::config::standard();
        let (v, _): (Self, _) = bincode::decode_from_slice(data, cfg)
            .map_err(|e| crate::error::GlaurungError::Serialization(e.to_string()))?;
        Ok(v)
    }
}

impl fmt::Display for SourceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SourceKind::Static => write!(f, "Static"),
            SourceKind::Dynamic => write!(f, "Dynamic"),
            SourceKind::Heuristic => write!(f, "Heuristic"),
            SourceKind::External => write!(f, "External"),
        }
    }
}
impl fmt::Display for ToolMetadata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.source_kind {
            Some(k) => write!(f, "{}@{} ({})", self.name, self.version, k),
            None => write!(f, "{}@{}", self.name, self.version),
        }
    }
}

#[cfg(feature = "python-ext")]
#[pymethods]
impl ToolMetadata {
    #[new]
    #[pyo3(signature = (name, version, parameters=None, source_kind=None))]
    pub fn new_py(
        name: String,
        version: String,
        parameters: Option<HashMap<String, String>>,
        source_kind: Option<SourceKind>,
    ) -> PyResult<Self> {
        Self::new_pure(name, version, parameters, source_kind)
            .map_err(pyo3::exceptions::PyValueError::new_err)
    }
    #[pyo3(name = "is_valid")]
    pub fn is_valid_py(&self) -> bool {
        self.is_valid()
    }
    // Property getters
    #[getter]
    pub fn name(&self) -> String {
        self.name.clone()
    }
    #[getter]
    pub fn version(&self) -> String {
        self.version.clone()
    }
    #[getter]
    pub fn parameters(&self) -> Option<HashMap<String, String>> {
        self.parameters.clone()
    }
    #[getter]
    pub fn source_kind(&self) -> Option<SourceKind> {
        self.source_kind
    }
    // Parameter helpers
    pub fn has_parameters(&self) -> bool {
        self.parameters.as_ref().map_or(false, |p| !p.is_empty())
    }
    pub fn parameter_count(&self) -> usize {
        self.parameters.as_ref().map_or(0, |p| p.len())
    }
    pub fn set_parameter(&mut self, key: String, value: String) {
        if self.parameters.is_none() {
            self.parameters = Some(HashMap::new());
        }
        if let Some(p) = &mut self.parameters {
            p.insert(key, value);
        }
    }
    pub fn remove_parameter(&mut self, key: String) -> Option<String> {
        self.parameters.as_mut()?.remove(&key)
    }
    pub fn set_parameters(&mut self, params: HashMap<String, String>) {
        self.parameters = Some(params);
    }
    #[pyo3(name = "set_parameters_py")]
    pub fn set_parameters_py(&mut self, params: HashMap<String, String>) {
        self.set_parameters(params);
    }
    pub fn set_source_kind(&mut self, kind: SourceKind) {
        self.source_kind = Some(kind);
    }
    // Serialization helpers expected by tests
    #[pyo3(name = "to_json")]
    pub fn to_json_py(&self) -> PyResult<String> {
        self.to_json_string()
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
    }
    #[staticmethod]
    #[pyo3(name = "from_json")]
    pub fn from_json_py(s: &str) -> PyResult<Self> {
        Self::from_json_str(s).map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
    }
    #[pyo3(name = "to_binary")]
    pub fn to_binary_py(&self) -> PyResult<Vec<u8>> {
        self.to_bincode()
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
    }
    #[staticmethod]
    #[pyo3(name = "from_binary")]
    pub fn from_binary_py(data: &[u8]) -> PyResult<Self> {
        Self::from_bincode(data).map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
    }
    // Reprs
    pub fn __str__(&self) -> String {
        format!("{}", self)
    }
    pub fn __repr__(&self) -> String {
        format!(
            "ToolMetadata(name={:?}, version={:?}, parameters={:?}, source_kind={:?})",
            self.name, self.version, self.parameters, self.source_kind
        )
    }
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
    #[pyo3(name = "set_source_kind_py")]
    pub fn set_source_kind_py(&mut self, kind: SourceKind) {
        self.source_kind = Some(kind);
    }
    #[setter]
    #[pyo3(name = "source_kind")]
    pub fn set_source_kind_prop(&mut self, value: Option<&SourceKind>) {
        self.source_kind = value.copied();
    }
    pub fn get_parameter(&self, key: &str) -> Option<String> {
        self.parameters.as_ref()?.get(key).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn roundtrip() {
        let tm =
            ToolMetadata::new_pure("tool".into(), "1.0".into(), None, Some(SourceKind::Static))
                .unwrap();
        let j = tm.to_json_string().unwrap();
        let t2 = ToolMetadata::from_json_str(&j).unwrap();
        assert_eq!(tm, t2);
        let b = tm.to_bincode().unwrap();
        let t3 = ToolMetadata::from_bincode(&b).unwrap();
        assert_eq!(tm, t3);
    }
}
