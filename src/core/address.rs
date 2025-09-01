//! Address types for binary analysis.
//!
//! This module provides the fundamental Address and AddressKind types
//! that serve as the foundation for all location references in Glaurung.

#[cfg(feature = "python-ext")]
use pyo3::exceptions::PyValueError;
#[cfg(feature = "python-ext")]
use pyo3::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json;
use std::fmt;

/// The kind of address representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
#[cfg_attr(feature = "python-ext", pyclass(eq, eq_int))]
pub enum AddressKind {
    /// Virtual Address (runtime memory address)
    VA,
    /// Offset within the file on disk
    FileOffset,
    /// Relative Virtual Address (offset from image base)
    RVA,
    /// Physical memory address (rare, for kernel/embedded)
    Physical,
    /// Relative to some other address
    Relative,
    /// Symbolic reference that needs resolution
    Symbolic,
}

#[cfg_attr(feature = "python-ext", pymethods)]
impl AddressKind {
    /// String representation for display.
    fn __str__(&self) -> String {
        match self {
            AddressKind::VA => "VA".to_string(),
            AddressKind::RVA => "RVA".to_string(),
            AddressKind::FileOffset => "FileOffset".to_string(),
            AddressKind::Physical => "Physical".to_string(),
            AddressKind::Relative => "Relative".to_string(),
            AddressKind::Symbolic => "Symbolic".to_string(),
        }
    }

    /// Python representation.
    fn __repr__(&self) -> String {
        format!("AddressKind.{}", self.__str__())
    }
}

/// A location reference in binary analysis.
///
/// Addresses can represent different kinds of locations (virtual addresses,
/// file offsets, symbolic references, etc.) and include metadata about
/// the address space and bit width.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyclass)]
pub struct Address {
    /// The kind of address this represents
    pub kind: AddressKind,
    /// The numeric value of the address
    pub value: u64,
    /// Address space identifier (optional, defaults to "default")
    pub space: Option<String>,
    /// Bit width (16, 32, or 64)
    pub bits: u8,
    /// Symbol reference (required when kind=Symbolic)
    pub symbol_ref: Option<String>,
}

#[cfg(feature = "python-ext")]
#[pymethods]
impl Address {
    /// Create a new Address.
    ///
    /// Args:
    ///     kind: The kind of address (AddressKind)
    ///     value: The numeric value (int)
    ///     bits: Bit width (16, 32, or 64)
    ///     space: Optional address space identifier (str)
    ///     symbol_ref: Required when kind=Symbolic (str)
    ///
    /// Returns:
    ///     Address: A new Address instance
    ///
    /// Raises:
    ///     ValueError: If validation fails
    #[new]
    #[pyo3(signature = (kind, value, bits, space=None, symbol_ref=None))]
    fn new_py(
        kind: AddressKind,
        value: u64,
        bits: u8,
        space: Option<String>,
        symbol_ref: Option<String>,
    ) -> PyResult<Self> {
        Self::new(kind, value, bits, space, symbol_ref).map_err(PyValueError::new_err)
    }

    /// String representation for display.
    fn __str__(&self) -> String {
        format!("{}", self)
    }

    /// Python representation.
    fn __repr__(&self) -> String {
        let space_str = self
            .space
            .as_ref()
            .map(|s| format!(", space='{}'", s))
            .unwrap_or_default();
        let symbol_str = self
            .symbol_ref
            .as_ref()
            .map(|s| format!(", symbol_ref='{}'", s))
            .unwrap_or_default();
        format!(
            "Address(AddressKind.{}, {:#x}, {}{space_str}{symbol_str})",
            self.kind.__str__(),
            self.value,
            self.bits
        )
    }

    // Property getters for Python
    #[getter]
    pub fn kind(&self) -> AddressKind {
        self.kind
    }
    #[getter]
    pub fn value(&self) -> u64 {
        self.value
    }
    #[getter]
    pub fn space(&self) -> Option<String> {
        self.space.clone()
    }
    #[getter]
    pub fn bits(&self) -> u8 {
        self.bits
    }
    #[getter]
    pub fn symbol_ref(&self) -> Option<String> {
        self.symbol_ref.clone()
    }

    /// Add an offset to this address.
    fn __add__(&self, other: u64) -> PyResult<Self> {
        self.add(other).map_err(PyValueError::new_err)
    }

    /// Subtract an offset from this address.
    fn __sub__(&self, other: u64) -> PyResult<Self> {
        self.sub(other).map_err(PyValueError::new_err)
    }

    /// Check if the address is valid.
    fn is_valid_py(&self) -> bool {
        self.is_valid()
    }

    /// Add an offset to this address (Python method).
    fn add_py(&self, other: u64) -> PyResult<Self> {
        self.add(other).map_err(PyValueError::new_err)
    }

    /// Subtract an offset from this address (Python method).
    fn sub_py(&self, other: u64) -> PyResult<Self> {
        self.sub(other).map_err(PyValueError::new_err)
    }

    /// Convert to RVA if this is a VA.
    fn to_rva_py(&self, image_base: u64) -> PyResult<Option<Self>> {
        self.to_rva(image_base).map_err(PyValueError::new_err)
    }

    /// Convert to VA if this is an RVA.
    fn to_va_py(&self, image_base: u64) -> PyResult<Option<Self>> {
        self.to_va(image_base).map_err(PyValueError::new_err)
    }

    /// Convert FileOffset to VA (Python method).
    fn file_offset_to_va_py(&self, section_rva: u64, image_base: u64) -> PyResult<Option<Self>> {
        self.file_offset_to_va(section_rva, image_base)
            .map_err(PyValueError::new_err)
    }

    /// Convert VA to FileOffset (Python method).
    fn va_to_file_offset_py(
        &self,
        section_va: u64,
        section_file_offset: u64,
    ) -> PyResult<Option<Self>> {
        self.va_to_file_offset(section_va, section_file_offset)
            .map_err(PyValueError::new_err)
    }

    /// Serialize to JSON string (Python method).
    fn to_json_py(&self) -> PyResult<String> {
        self.to_json().map_err(PyValueError::new_err)
    }

    /// Deserialize from JSON string (Python method).
    #[staticmethod]
    fn from_json_py(json_str: &str) -> PyResult<Self> {
        Self::from_json(json_str).map_err(PyValueError::new_err)
    }

    /// Serialize to binary format (Python method).
    fn to_binary_py(&self) -> PyResult<Vec<u8>> {
        self.to_binary().map_err(PyValueError::new_err)
    }

    /// Deserialize from binary format (Python method).
    #[staticmethod]
    fn from_binary_py(data: Vec<u8>) -> PyResult<Self> {
        Self::from_binary(&data).map_err(PyValueError::new_err)
    }

    /// Less than comparison (Python method).
    fn __lt__(&self, other: &Self) -> bool {
        self < other
    }

    /// Less than or equal comparison (Python method).
    fn __le__(&self, other: &Self) -> bool {
        self <= other
    }

    /// Greater than comparison (Python method).
    fn __gt__(&self, other: &Self) -> bool {
        self > other
    }

    /// Greater than or equal comparison (Python method).
    fn __ge__(&self, other: &Self) -> bool {
        self >= other
    }

    /// Equality comparison (Python method).
    fn __eq__(&self, other: &Self) -> bool {
        self == other
    }
}

impl Address {
    /// Create a new Address.
    ///
    /// # Arguments
    /// * `kind` - The kind of address
    /// * `value` - The numeric value
    /// * `bits` - Bit width (16, 32, or 64)
    /// * `space` - Optional address space identifier
    /// * `symbol_ref` - Required when kind=Symbolic
    ///
    /// # Panics
    /// Panics if bits is not 16, 32, or 64, or if kind=Symbolic but symbol_ref is None.
    pub fn new(
        kind: AddressKind,
        value: u64,
        bits: u8,
        space: Option<String>,
        symbol_ref: Option<String>,
    ) -> Result<Self, String> {
        // Validate bits
        if ![16, 32, 64].contains(&bits) {
            return Err("bits must be 16, 32, or 64".to_string());
        }

        // Validate symbol_ref for Symbolic addresses
        if kind == AddressKind::Symbolic && symbol_ref.is_none() {
            return Err("symbol_ref is required when kind=Symbolic".to_string());
        }

        // Validate value fits in bits
        let max_value = match bits {
            16 => 0xFFFFu64,
            32 => 0xFFFF_FFFFu64,
            64 => u64::MAX,
            _ => unreachable!(), // Already validated above
        };

        if value > max_value {
            return Err(format!(
                "value {} exceeds maximum for {}-bit address ({})",
                value, bits, max_value
            ));
        }

        Ok(Address {
            kind,
            value,
            space,
            bits,
            symbol_ref,
        })
    }

    /// Check if the address is valid.
    pub fn is_valid(&self) -> bool {
        // Check bits
        if ![16, 32, 64].contains(&self.bits) {
            return false;
        }

        // Check value fits in bits
        let max_value = match self.bits {
            16 => 0xFFFFu64,
            32 => 0xFFFF_FFFFu64,
            64 => u64::MAX,
            _ => return false,
        };

        if self.value > max_value {
            return false;
        }

        // Check symbol_ref for Symbolic
        if self.kind == AddressKind::Symbolic && self.symbol_ref.is_none() {
            return false;
        }

        true
    }

    /// Add an offset to this address.
    pub fn add(&self, other: u64) -> Result<Self, String> {
        let new_value = if self.bits < 64 {
            self.value
                .checked_add(other)
                .ok_or_else(|| "addition overflow".to_string())?
        } else {
            // For 64-bit addresses, allow overflow (wrapping)
            self.value.wrapping_add(other)
        };

        Self::new(
            self.kind,
            new_value,
            self.bits,
            self.space.clone(),
            self.symbol_ref.clone(),
        )
    }

    /// Subtract an offset from this address.
    pub fn sub(&self, other: u64) -> Result<Self, String> {
        let new_value = self
            .value
            .checked_sub(other)
            .ok_or_else(|| "subtraction underflow".to_string())?;

        Self::new(
            self.kind,
            new_value,
            self.bits,
            self.space.clone(),
            self.symbol_ref.clone(),
        )
    }

    /// Convert to RVA if this is a VA.
    pub fn to_rva(&self, image_base: u64) -> Result<Option<Self>, String> {
        match self.kind {
            AddressKind::VA => {
                let rva_value = self
                    .value
                    .checked_sub(image_base)
                    .ok_or_else(|| "VA below image base".to_string())?;
                Ok(Some(Self::new(
                    AddressKind::RVA,
                    rva_value,
                    self.bits,
                    self.space.clone(),
                    self.symbol_ref.clone(),
                )?))
            }
            _ => Ok(None),
        }
    }

    /// Convert to VA if this is an RVA.
    pub fn to_va(&self, image_base: u64) -> Result<Option<Self>, String> {
        match self.kind {
            AddressKind::RVA => {
                let va_value = self
                    .value
                    .checked_add(image_base)
                    .ok_or_else(|| "VA overflow".to_string())?;
                Ok(Some(Self::new(
                    AddressKind::VA,
                    va_value,
                    self.bits,
                    self.space.clone(),
                    self.symbol_ref.clone(),
                )?))
            }
            _ => Ok(None),
        }
    }

    /// Convert to VA if this is a FileOffset (requires section mapping).
    pub fn file_offset_to_va(
        &self,
        section_rva: u64,
        image_base: u64,
    ) -> Result<Option<Self>, String> {
        match self.kind {
            AddressKind::FileOffset => {
                // Validate that the file offset is within the section bounds
                if self.value < section_rva {
                    return Ok(None);
                }

                let va_value = image_base
                    .checked_add(self.value)
                    .ok_or_else(|| "VA overflow".to_string())?;
                Ok(Some(Self::new(
                    AddressKind::VA,
                    va_value,
                    self.bits,
                    self.space.clone(),
                    self.symbol_ref.clone(),
                )?))
            }
            _ => Ok(None),
        }
    }

    /// Convert to FileOffset if this is a VA (requires section mapping).
    pub fn va_to_file_offset(
        &self,
        section_va: u64,
        section_file_offset: u64,
    ) -> Result<Option<Self>, String> {
        match self.kind {
            AddressKind::VA => {
                if self.value < section_va {
                    return Err("VA below section start".to_string());
                }
                let offset_in_section = self.value - section_va;
                let file_offset_value = section_file_offset + offset_in_section;
                Ok(Some(Self::new(
                    AddressKind::FileOffset,
                    file_offset_value,
                    self.bits,
                    self.space.clone(),
                    self.symbol_ref.clone(),
                )?))
            }
            _ => Ok(None),
        }
    }

    /// Serialize to JSON string.
    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string(self).map_err(|e| e.to_string())
    }

    /// Deserialize from JSON string.
    pub fn from_json(json_str: &str) -> Result<Self, String> {
        serde_json::from_str(json_str).map_err(|e| e.to_string())
    }

    /// Serialize to binary format.
    pub fn to_binary(&self) -> Result<Vec<u8>, String> {
        bincode::serialize(self).map_err(|e| e.to_string())
    }

    /// Deserialize from binary format.
    pub fn from_binary(data: &[u8]) -> Result<Self, String> {
        bincode::deserialize(data).map_err(|e| e.to_string())
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let space_str = self
            .space
            .as_ref()
            .map(|s| format!("@{}", s))
            .unwrap_or_default();
        let hex_value = format!("{:x}", self.value);

        match self.kind {
            AddressKind::VA => write!(f, "VA:{}{}", hex_value, space_str),
            AddressKind::RVA => write!(f, "RVA:{}{}", hex_value, space_str),
            AddressKind::FileOffset => write!(f, "FO:{}{}", hex_value, space_str),
            AddressKind::Physical => write!(f, "PA:{}{}", hex_value, space_str),
            AddressKind::Relative => write!(f, "REL:{}{}", hex_value, space_str),
            AddressKind::Symbolic => {
                write!(f, "SYM:{}{}", self.symbol_ref.as_ref().unwrap(), space_str)
            }
        }
    }
}

impl fmt::Display for AddressKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AddressKind::VA => write!(f, "VA"),
            AddressKind::RVA => write!(f, "RVA"),
            AddressKind::FileOffset => write!(f, "FileOffset"),
            AddressKind::Physical => write!(f, "Physical"),
            AddressKind::Relative => write!(f, "Relative"),
            AddressKind::Symbolic => write!(f, "Symbolic"),
        }
    }
}

impl Ord for Address {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Primary: compare by value
        match self.value.cmp(&other.value) {
            std::cmp::Ordering::Equal => {}
            ord => return ord,
        }

        // Secondary: compare by kind (arbitrary but consistent ordering)
        match self.kind.cmp(&other.kind) {
            std::cmp::Ordering::Equal => {}
            ord => return ord,
        }

        // Tertiary: compare by space (None < Some)
        match (&self.space, &other.space) {
            (None, None) => std::cmp::Ordering::Equal,
            (None, Some(_)) => std::cmp::Ordering::Less,
            (Some(_), None) => std::cmp::Ordering::Greater,
            (Some(a), Some(b)) => a.cmp(b),
        }
    }
}

impl PartialOrd for Address {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_creation() {
        let addr = Address::new(AddressKind::VA, 0x401000, 32, None, None).unwrap();
        assert_eq!(addr.kind, AddressKind::VA);
        assert_eq!(addr.value, 0x401000);
        assert_eq!(addr.bits, 32);
        assert!(addr.is_valid());
    }

    #[test]
    fn test_symbolic_address_requires_symbol_ref() {
        let result = Address::new(AddressKind::Symbolic, 0, 64, None, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_bits() {
        let result = Address::new(AddressKind::VA, 0x1000, 24, None, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_value_overflow() {
        let result = Address::new(AddressKind::VA, 0x10000, 16, None, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_arithmetic() {
        let addr = Address::new(AddressKind::VA, 0x401000, 32, None, None).unwrap();
        let result = addr.add(0x10).unwrap();
        assert_eq!(result.value, 0x401010);
        assert_eq!(result.kind, AddressKind::VA);
    }

    #[test]
    fn test_va_to_rva_conversion() {
        let va = Address::new(AddressKind::VA, 0x401000, 32, None, None).unwrap();
        let rva = va.to_rva(0x400000).unwrap().unwrap();
        assert_eq!(rva.kind, AddressKind::RVA);
        assert_eq!(rva.value, 0x1000);
    }

    #[test]
    fn test_file_offset_to_va_conversion() {
        let file_offset = Address::new(AddressKind::FileOffset, 0x1000, 32, None, None).unwrap();
        let va = file_offset
            .file_offset_to_va(0x1000, 0x400000)
            .unwrap()
            .unwrap();
        assert_eq!(va.kind, AddressKind::VA);
        assert_eq!(va.value, 0x401000);
    }

    #[test]
    fn test_va_to_file_offset_conversion() {
        let va = Address::new(AddressKind::VA, 0x401000, 32, None, None).unwrap();
        let file_offset = va.va_to_file_offset(0x400000, 0x1000).unwrap().unwrap();
        assert_eq!(file_offset.kind, AddressKind::FileOffset);
        assert_eq!(file_offset.value, 0x2000);
    }

    #[test]
    fn test_json_serialization() {
        let addr = Address::new(
            AddressKind::VA,
            0x401000,
            32,
            Some("default".to_string()),
            None,
        )
        .unwrap();
        let json_str = addr.to_json().unwrap();
        let restored = Address::from_json(&json_str).unwrap();
        assert_eq!(addr, restored);
    }

    #[test]
    fn test_binary_serialization() {
        let addr = Address::new(
            AddressKind::Symbolic,
            0,
            64,
            None,
            Some("test.dll!func".to_string()),
        )
        .unwrap();
        let binary_data = addr.to_binary().unwrap();
        let restored = Address::from_binary(&binary_data).unwrap();
        assert_eq!(addr, restored);
    }

    #[test]
    fn test_address_ordering() {
        let addr1 = Address::new(AddressKind::VA, 0x1000, 32, None, None).unwrap();
        let addr2 = Address::new(AddressKind::VA, 0x2000, 32, None, None).unwrap();
        let addr3 = Address::new(AddressKind::RVA, 0x1000, 32, None, None).unwrap();

        assert!(addr1 < addr2);
        assert!(addr2 > addr1);
        assert!(addr1 < addr3); // VA comes before RVA
    }

    #[test]
    fn test_address_sorting() {
        let mut addresses = [
            Address::new(AddressKind::RVA, 0x1000, 32, None, None).unwrap(),
            Address::new(AddressKind::VA, 0x500, 32, None, None).unwrap(),
            Address::new(AddressKind::VA, 0x1000, 32, None, None).unwrap(),
        ];

        addresses.sort();

        assert_eq!(addresses[0].value, 0x500);
        assert_eq!(addresses[1].value, 0x1000);
        assert_eq!(addresses[1].kind, AddressKind::VA);
        assert_eq!(addresses[2].value, 0x1000);
        assert_eq!(addresses[2].kind, AddressKind::RVA);
    }
}
