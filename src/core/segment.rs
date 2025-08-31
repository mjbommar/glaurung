//! Segment type for load-time memory mapping units.
//!
//! Segments represent load-time memory mapping units in binary analysis.
//! They correspond to program segments that are loaded into memory at runtime.

use pyo3::prelude::*;
use serde::{Deserialize, Serialize};
use std::fmt;

use crate::core::address::{Address, AddressKind};
use crate::core::address_range::AddressRange;

/// Permission flags for memory segments
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[pyclass]
pub struct Perms {
    /// Raw permission bits: read=1, write=2, execute=4
    #[pyo3(get, set)]
    pub bits: u8,
}

#[pymethods]
impl Perms {
    /// Create a new Perms instance
    #[new]
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

    /// String representation for display
    fn __str__(&self) -> String {
        format!("{}", self)
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
#[pyclass]
pub struct Segment {
    /// Unique identifier for the segment
    #[pyo3(get, set)]
    pub id: String,
    /// Optional human-readable name
    #[pyo3(get, set)]
    pub name: Option<String>,
    /// Virtual address range where segment is mapped
    #[pyo3(get, set)]
    pub range: AddressRange,
    /// Memory permissions for the segment
    #[pyo3(get, set)]
    pub perms: Perms,
    /// File offset where segment data begins
    #[pyo3(get, set)]
    pub file_offset: Address,
    /// Optional alignment requirement
    #[pyo3(get, set)]
    pub alignment: Option<u64>,
}

#[pymethods]
impl Segment {
    /// Create a new Segment instance
    #[new]
    #[pyo3(signature = (id, range, perms, file_offset, name=None, alignment=None))]
    pub fn new(
        id: String,
        range: AddressRange,
        perms: Perms,
        file_offset: Address,
        name: Option<String>,
        alignment: Option<u64>,
    ) -> PyResult<Self> {
        // Basic validation
        if file_offset.kind != AddressKind::FileOffset {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "file_offset must have AddressKind::FileOffset",
            ));
        }

        if range.start.kind != AddressKind::VA {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "range addresses must have AddressKind::VA for segments",
            ));
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

    /// String representation for display
    fn __str__(&self) -> String {
        format!("{}", self)
    }

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
