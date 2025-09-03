//! Packer detection types.

#[cfg(feature = "python-ext")]
use pyo3::prelude::*;
use serde::{Deserialize, Serialize};

/// Packer detection entry.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyclass)]
pub struct PackerMatch {
    pub name: String,
    pub confidence: f32,
}

#[cfg(feature = "python-ext")]
#[pymethods]
impl PackerMatch {
    #[new]
    pub fn new_py(name: String, confidence: f32) -> Self {
        Self { name, confidence }
    }
    #[getter]
    fn name(&self) -> String {
        self.name.clone()
    }
    #[getter]
    fn confidence(&self) -> f32 {
        self.confidence
    }
}

// Pure Rust constructors and helpers
impl PackerMatch {
    pub fn new(name: String, confidence: f32) -> Self {
        Self { name, confidence }
    }
}
