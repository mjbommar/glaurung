//! Section type for file-format organizational units.
//!
//! Sections represent file-format organizational units in binary analysis.
//! They correspond to sections in executable formats like ELF, PE, etc.

use pyo3::prelude::*;
use serde::{Deserialize, Serialize};
use std::fmt;

use crate::core::address::{Address, AddressKind};
use crate::core::address_range::AddressRange;

/// Permission flags for sections (simplified bit operations)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[pyclass]
pub struct SectionPerms {
    /// Raw permission bits: read=1, write=2, execute=4
    #[pyo3(get, set)]
    pub bits: u8,
}

#[pymethods]
impl SectionPerms {
    /// Create a new SectionPerms instance
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

    /// Check if section has read permission
    pub fn has_read(&self) -> bool {
        (self.bits & 1) != 0
    }

    /// Check if section has write permission
    pub fn has_write(&self) -> bool {
        (self.bits & 2) != 0
    }

    /// Check if section has execute permission
    pub fn has_execute(&self) -> bool {
        (self.bits & 4) != 0
    }

    /// Check if section is readable and writable (data section)
    pub fn is_data(&self) -> bool {
        self.has_read() && self.has_write() && !self.has_execute()
    }

    /// Check if section is readable and executable (code section)
    pub fn is_code(&self) -> bool {
        self.has_read() && self.has_execute() && !self.has_write()
    }

    /// Check if section is read-only
    pub fn is_readonly(&self) -> bool {
        self.has_read() && !self.has_write() && !self.has_execute()
    }
}

impl fmt::Display for SectionPerms {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut perms = String::new();
        perms.push(if self.has_read() { 'r' } else { '-' });
        perms.push(if self.has_write() { 'w' } else { '-' });
        perms.push(if self.has_execute() { 'x' } else { '-' });
        write!(f, "{}", perms)
    }
}

/// Section type as a string (simplified for now)
pub type SectionType = String;

/// File-format organizational unit
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[pyclass]
pub struct Section {
    /// Unique identifier for the section
    #[pyo3(get, set)]
    pub id: String,
    /// Section name (e.g., ".text", ".data")
    #[pyo3(get, set)]
    pub name: String,
    /// Virtual address range where section is mapped
    #[pyo3(get, set)]
    pub range: AddressRange,
    /// Optional memory permissions for the section
    #[pyo3(get, set)]
    pub perms: Option<SectionPerms>,
    /// Format-specific flags
    #[pyo3(get, set)]
    pub flags: u64,
    /// Optional section type
    #[pyo3(get, set)]
    pub section_type: Option<SectionType>,
    /// File offset where section data begins
    #[pyo3(get, set)]
    pub file_offset: Address,
}

#[pymethods]
impl Section {
    /// Create a new Section instance
    #[new]
    #[pyo3(signature = (id, name, range, file_offset, perms=None, flags=0, section_type=None))]
    pub fn new(
        id: String,
        name: String,
        range: AddressRange,
        file_offset: Address,
        perms: Option<SectionPerms>,
        flags: u64,
        section_type: Option<SectionType>,
    ) -> PyResult<Self> {
        // Basic validation
        if file_offset.kind != AddressKind::FileOffset {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "file_offset must have AddressKind::FileOffset",
            ));
        }

        // For sections, range can be VA or RVA depending on format
        if range.start.kind != AddressKind::VA && range.start.kind != AddressKind::RVA {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "range addresses must have AddressKind::VA or AddressKind::RVA for sections",
            ));
        }

        Ok(Self {
            id,
            name,
            range,
            perms,
            flags,
            section_type,
            file_offset,
        })
    }

    /// String representation for display
    fn __str__(&self) -> String {
        format!("{}", self)
    }

    /// Get the section size in bytes
    pub fn size(&self) -> u64 {
        self.range.size
    }

    /// Check if section is a code section (readable and executable)
    pub fn is_code_section(&self) -> bool {
        self.perms.as_ref().map(|p| p.is_code()).unwrap_or(false)
    }

    /// Check if section is a data section (readable and writable)
    pub fn is_data_section(&self) -> bool {
        self.perms.as_ref().map(|p| p.is_data()).unwrap_or(false)
    }

    /// Check if section is read-only
    pub fn is_readonly(&self) -> bool {
        self.perms
            .as_ref()
            .map(|p| p.is_readonly())
            .unwrap_or(false)
    }

    /// Check if section contains executable code
    pub fn is_executable(&self) -> bool {
        self.perms
            .as_ref()
            .map(|p| p.has_execute())
            .unwrap_or(false)
    }

    /// Check if section is writable
    pub fn is_writable(&self) -> bool {
        self.perms.as_ref().map(|p| p.has_write()).unwrap_or(false)
    }

    /// Get a human-readable description of the section
    pub fn description(&self) -> String {
        let perms_str = self
            .perms
            .as_ref()
            .map(|p| p.to_string())
            .unwrap_or_else(|| "---".to_string());
        let type_str = self
            .section_type
            .as_ref()
            .map(|t| t.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        format!(
            "Section '{}' ({}, size: {} bytes, perms: {}, type: {})",
            self.name,
            self.id,
            self.size(),
            perms_str,
            type_str
        )
    }
}

impl fmt::Display for Section {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Section '{}' ({})", self.name, self.id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::address::{Address, AddressKind};

    #[test]
    fn test_section_perms_creation() {
        let perms = SectionPerms::new(true, false, true);
        assert!(perms.has_read());
        assert!(!perms.has_write());
        assert!(perms.has_execute());
        assert_eq!(format!("{}", perms), "r-x");
    }

    #[test]
    fn test_section_creation() {
        let start = Address::new(AddressKind::VA, 0x400000, 64, None, None).unwrap();
        let range = AddressRange::new(start, 0x1000, Some(0x1000)).unwrap();
        let file_offset = Address::new(AddressKind::FileOffset, 0x1000, 64, None, None).unwrap();
        let perms = SectionPerms::new(true, false, true);
        let section_type = "PROGBITS".to_string();

        let section = Section::new(
            "text_section".to_string(),
            ".text".to_string(),
            range,
            file_offset,
            Some(perms),
            0x6, // ALLOC | EXEC
            Some(section_type),
        )
        .unwrap();

        assert_eq!(section.id, "text_section");
        assert_eq!(section.name, ".text");
        assert_eq!(section.size(), 0x1000);
        assert!(section.is_code_section());
    }
}
