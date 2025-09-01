//! Segment type for load-time memory mapping units.
//!
//! Segments represent load-time memory mapping units in binary analysis.
//! They correspond to program segments that are loaded into memory at runtime.

#[cfg(feature = "python-ext")]
use pyo3::prelude::*;
use serde::{Deserialize, Serialize};
use std::fmt;

use crate::core::address::{Address, AddressKind};
use crate::core::address_range::AddressRange;

/// Permission flags for memory segments
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyclass)]
pub struct Perms {
    /// Raw permission bits: read=1, write=2, execute=4
    pub bits: u8,
}

impl Perms {
    /// Create a new Perms instance (pure Rust)
    pub fn new(read: bool, write: bool, execute: bool) -> Self {
        let mut bits = 0u8;
        if read {
            bits |= 1;
        }
        if write {
            bits |= 2;
        }
        if execute {
            bits |= 4;
        }
        Self { bits }
    }

    /// Check if segment has read permission
    pub fn has_read(&self) -> bool {
        (self.bits & 1) != 0
    }

    /// Check if segment has write permission
    pub fn has_write(&self) -> bool {
        (self.bits & 2) != 0
    }

    /// Check if segment has execute permission
    pub fn has_execute(&self) -> bool {
        (self.bits & 4) != 0
    }

    /// Check if segment is readable and writable (data segment)
    pub fn is_data(&self) -> bool {
        self.has_read() && self.has_write() && !self.has_execute()
    }

    /// Check if segment is readable and executable (code segment)
    pub fn is_code(&self) -> bool {
        self.has_read() && self.has_execute() && !self.has_write()
    }

    /// Check if segment is read-only
    pub fn is_readonly(&self) -> bool {
        self.has_read() && !self.has_write() && !self.has_execute()
    }
}

#[cfg(feature = "python-ext")]
#[pymethods]
impl Perms {
    /// String representation for display
    fn __str__(&self) -> String {
        format!("{}", self)
    }

    /// Python constructor
    #[new]
    #[pyo3(signature = (read, write, execute))]
    fn new_py(read: bool, write: bool, execute: bool) -> Self {
        Self::new(read, write, execute)
    }

    // Methods exposed to Python
    #[pyo3(name = "has_read")]
    fn has_read_py(&self) -> bool {
        (self.bits & 1) != 0
    }
    #[pyo3(name = "has_write")]
    fn has_write_py(&self) -> bool {
        (self.bits & 2) != 0
    }
    #[pyo3(name = "has_execute")]
    fn has_execute_py(&self) -> bool {
        (self.bits & 4) != 0
    }
    #[pyo3(name = "is_code")]
    fn is_code_py(&self) -> bool {
        self.has_read_py() && self.has_execute_py() && !self.has_write_py()
    }
    #[pyo3(name = "is_data")]
    fn is_data_py(&self) -> bool {
        self.has_read_py() && self.has_write_py() && !self.has_execute_py()
    }
    #[pyo3(name = "is_readonly")]
    fn is_readonly_py(&self) -> bool {
        self.has_read_py() && !self.has_write_py() && !self.has_execute_py()
    }
}

impl fmt::Display for Perms {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut perms = String::new();
        perms.push(if self.has_read() { 'r' } else { '-' });
        perms.push(if self.has_write() { 'w' } else { '-' });
        perms.push(if self.has_execute() { 'x' } else { '-' });
        write!(f, "{}", perms)
    }
}

/// Load-time memory mapping unit
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyclass)]
pub struct Segment {
    /// Unique identifier for the segment
    pub id: String,
    /// Optional human-readable name
    pub name: Option<String>,
    /// Virtual address range where segment is mapped
    pub range: AddressRange,
    /// Memory permissions for the segment
    pub perms: Perms,
    /// File offset where segment data begins
    pub file_offset: Address,
    /// Optional alignment requirement
    pub alignment: Option<u64>,
}

impl Segment {
    /// Create a new Segment instance (pure Rust)
    pub fn new(
        id: String,
        range: AddressRange,
        perms: Perms,
        file_offset: Address,
        name: Option<String>,
        alignment: Option<u64>,
    ) -> Result<Self, String> {
        // Basic validation
        if file_offset.kind != AddressKind::FileOffset {
            return Err("file_offset must have AddressKind::FileOffset".to_string());
        }

        if range.start.kind != AddressKind::VA {
            return Err("range addresses must have AddressKind::VA for segments".to_string());
        }

        Ok(Self {
            id,
            name,
            range,
            perms,
            file_offset,
            alignment,
        })
    }

    /// Get the segment ID
    #[cfg(feature = "python-ext")]
    pub fn get_id(&self) -> &str {
        &self.id
    }

    /// Set the segment ID
    #[cfg(feature = "python-ext")]
    pub fn set_id(&mut self, id: String) {
        self.id = id;
    }

    /// Get the segment name
    #[cfg(feature = "python-ext")]
    pub fn get_name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Set the segment name
    #[cfg(feature = "python-ext")]
    pub fn set_name(&mut self, name: Option<String>) {
        self.name = name;
    }

    /// Get the segment range
    #[cfg(feature = "python-ext")]
    pub fn get_range(&self) -> &AddressRange {
        &self.range
    }

    /// Set the segment range
    #[cfg(feature = "python-ext")]
    pub fn set_range(&mut self, range: AddressRange) {
        self.range = range;
    }

    /// Get the segment permissions
    #[cfg(feature = "python-ext")]
    pub fn get_perms(&self) -> &Perms {
        &self.perms
    }

    /// Set the segment permissions
    #[cfg(feature = "python-ext")]
    pub fn set_perms(&mut self, perms: Perms) {
        self.perms = perms;
    }

    /// Get the file offset
    #[cfg(feature = "python-ext")]
    pub fn get_file_offset(&self) -> &Address {
        &self.file_offset
    }

    /// Set the file offset
    #[cfg(feature = "python-ext")]
    pub fn set_file_offset(&mut self, file_offset: Address) {
        self.file_offset = file_offset;
    }

    /// Get the alignment
    #[cfg(feature = "python-ext")]
    pub fn get_alignment(&self) -> Option<u64> {
        self.alignment
    }

    /// Set the alignment
    #[cfg(feature = "python-ext")]
    pub fn set_alignment(&mut self, alignment: Option<u64>) {
        self.alignment = alignment;
    }

    // String representation for display is provided in the PyO3 #[pymethods] block.

    /// Get the segment size in bytes
    pub fn size(&self) -> u64 {
        self.range.size
    }

    /// Check if segment is a code segment (readable and executable)
    pub fn is_code_segment(&self) -> bool {
        self.perms.is_code()
    }

    /// Check if segment is a data segment (readable and writable)
    pub fn is_data_segment(&self) -> bool {
        self.perms.is_data()
    }

    /// Check if segment is read-only
    pub fn is_readonly(&self) -> bool {
        self.perms.is_readonly()
    }

    /// Get a human-readable description of the segment
    pub fn description(&self) -> String {
        let perms_str = self.perms.to_string();
        let default_name = "unnamed".to_string();
        let name = self.name.as_ref().unwrap_or(&default_name);
        format!(
            "Segment '{}' ({}, size: {} bytes, perms: {})",
            name,
            self.id,
            self.size(),
            perms_str
        )
    }
}

#[cfg(feature = "python-ext")]
#[pymethods]
impl Segment {
    /// Create a new Segment instance (Python constructor)
    #[new]
    #[pyo3(signature = (id, range, perms, file_offset, name=None, alignment=None))]
    pub fn new_py(
        id: String,
        range: AddressRange,
        perms: Perms,
        file_offset: Address,
        name: Option<String>,
        alignment: Option<u64>,
    ) -> PyResult<Self> {
        Self::new(id, range, perms, file_offset, name, alignment)
            .map_err(pyo3::exceptions::PyValueError::new_err)
    }

    /// String representation for display
    fn __str__(&self) -> String {
        format!("{}", self)
    }

    // Property getters
    #[getter]
    fn id(&self) -> &str {
        &self.id
    }
    #[getter]
    fn name(&self) -> Option<String> {
        self.name.clone()
    }
    #[getter]
    fn range(&self) -> AddressRange {
        self.range.clone()
    }
    #[getter]
    fn perms(&self) -> Perms {
        self.perms
    }
    #[getter]
    fn file_offset(&self) -> Address {
        self.file_offset.clone()
    }
    #[getter]
    fn alignment(&self) -> Option<u64> {
        self.get_alignment()
    }

    // Query helpers
    #[pyo3(name = "size")]
    fn size_py(&self) -> u64 {
        self.range.size
    }
    #[pyo3(name = "is_code_segment")]
    fn is_code_segment_py(&self) -> bool {
        self.perms.is_code()
    }
    #[pyo3(name = "is_data_segment")]
    fn is_data_segment_py(&self) -> bool {
        self.perms.is_data()
    }
    #[pyo3(name = "is_readonly")]
    fn is_readonly_py(&self) -> bool {
        self.perms.is_readonly()
    }
    #[pyo3(name = "description")]
    fn description_py(&self) -> String {
        self.description()
    }
}

impl fmt::Display for Segment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let default_name = "unnamed".to_string();
        let name = self.name.as_ref().unwrap_or(&default_name);
        write!(f, "Segment '{}' ({})", name, self.id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::address::{Address, AddressKind};

    #[test]
    fn test_perms_creation() {
        let perms = Perms::new(true, false, true);
        assert!(perms.has_read());
        assert!(!perms.has_write());
        assert!(perms.has_execute());
        assert_eq!(format!("{}", perms), "r-x");
    }

    #[test]
    fn test_perms_flags() {
        let code_perms = Perms::new(true, false, true);
        assert!(code_perms.is_code());
        assert!(!code_perms.is_data());

        let data_perms = Perms::new(true, true, false);
        assert!(data_perms.is_data());
        assert!(!data_perms.is_code());

        let ro_perms = Perms::new(true, false, false);
        assert!(ro_perms.is_readonly());
    }

    #[test]
    fn test_segment_creation() {
        let start = Address::new(AddressKind::VA, 0x400000, 64, None, None).unwrap();
        let range =
            crate::core::address_range::AddressRange::new(start, 0x1000, Some(0x1000)).unwrap();
        let file_offset = Address::new(AddressKind::FileOffset, 0x1000, 64, None, None).unwrap();
        let perms = Perms::new(true, false, true);

        let segment = Segment::new(
            "text".to_string(),
            range,
            perms,
            file_offset,
            Some("code".to_string()),
            Some(0x1000),
        )
        .unwrap();

        assert_eq!(segment.id, "text");
        assert_eq!(segment.name, Some("code".to_string()));
        assert_eq!(segment.size(), 0x1000);
        assert!(segment.is_code_segment());
    }
}
