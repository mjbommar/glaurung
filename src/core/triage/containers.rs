//! Container and archive metadata types.

#[cfg(feature = "python-ext")]
use pyo3::prelude::*;
use serde::{Deserialize, Serialize};

/// Child artifact discovered within a container or overlay.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyclass)]
pub struct ContainerChild {
    pub type_name: String,
    pub offset: u64,
    pub size: u64,
    /// Optional container metadata (e.g., counts, sizes)
    pub metadata: Option<ContainerMetadata>,
    /// Optional nested children (recursion tree)
    pub children: Option<Vec<ContainerChild>>,
}

#[cfg(feature = "python-ext")]
#[pymethods]
impl ContainerChild {
    #[new]
    pub fn new_py(type_name: String, offset: u64, size: u64) -> Self {
        Self {
            type_name,
            offset,
            size,
            metadata: None,
            children: None,
        }
    }
    #[getter]
    fn type_name(&self) -> String {
        self.type_name.clone()
    }
    #[getter]
    fn offset(&self) -> u64 {
        self.offset
    }
    #[getter]
    fn size(&self) -> u64 {
        self.size
    }
    #[getter]
    fn metadata(&self) -> Option<ContainerMetadata> {
        self.metadata.clone()
    }

    #[getter]
    fn children(&self) -> Option<Vec<ContainerChild>> {
        self.children.clone()
    }
}

/// Optional metadata extracted from container formats without full extraction.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyclass)]
pub struct ContainerMetadata {
    /// Number of entries/files if known
    pub file_count: Option<u32>,
    /// Total uncompressed size if known
    pub total_uncompressed_size: Option<u64>,
    /// Total compressed size if known (archives may not expose this cheaply)
    pub total_compressed_size: Option<u64>,
}

#[cfg(feature = "python-ext")]
#[pymethods]
impl ContainerMetadata {
    #[new]
    #[pyo3(signature = (file_count=None, total_uncompressed_size=None, total_compressed_size=None))]
    pub fn new_py(
        file_count: Option<u32>,
        total_uncompressed_size: Option<u64>,
        total_compressed_size: Option<u64>,
    ) -> Self {
        Self {
            file_count,
            total_uncompressed_size,
            total_compressed_size,
        }
    }
}

// Pure Rust constructors and helpers
impl ContainerChild {
    pub fn new(type_name: String, offset: u64, size: u64) -> Self {
        Self {
            type_name,
            offset,
            size,
            metadata: None,
            children: None,
        }
    }
}
