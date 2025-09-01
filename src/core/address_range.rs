//! AddressRange types for binary analysis.
//!
//! This module provides the AddressRange type that represents half-open
//! contiguous memory regions, fundamental for representing segments, sections,
//! functions, and other binary constructs.

use crate::core::address::Address;
#[cfg(feature = "python-ext")]
use pyo3::exceptions::PyValueError;
#[cfg(feature = "python-ext")]
use pyo3::prelude::*;
use serde::{Deserialize, Serialize};
use std::fmt;

/// A half-open contiguous memory region in binary analysis.
///
/// AddressRange represents a contiguous region of memory starting at an address
/// (inclusive) and extending for a given size (exclusive). This is the
/// fundamental building block for representing segments, sections, functions,
/// and other binary constructs that occupy contiguous memory regions.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyclass)]
pub struct AddressRange {
    /// The starting address of the range (inclusive)
    pub start: Address,
    /// The size of the range in bytes
    pub size: u64,
    /// Optional alignment requirement in bytes
    pub alignment: Option<u64>,
}

#[cfg(feature = "python-ext")]
#[pymethods]
impl AddressRange {
    /// Create a new AddressRange.
    ///
    /// Args:
    ///     start: The starting Address (inclusive)
    ///     size: The size in bytes
    ///     alignment: Optional alignment requirement in bytes
    ///
    /// Returns:
    ///     AddressRange: A new AddressRange instance
    ///
    /// Raises:
    ///     ValueError: If size is 0 or alignment is invalid
    #[new]
    #[pyo3(signature = (start, size, alignment=None))]
    fn new_py(start: Address, size: u64, alignment: Option<u64>) -> PyResult<Self> {
        Self::new(start, size, alignment).map_err(PyValueError::new_err)
    }

    /// String representation for display.
    fn __str__(&self) -> String {
        format!("{}", self)
    }

    /// Python representation.
    fn __repr__(&self) -> String {
        let alignment_str = self
            .alignment
            .map(|a| format!(", alignment={}", a))
            .unwrap_or_default();
        format!(
            "AddressRange(start={:?}, size={}{})",
            self.start, self.size, alignment_str
        )
    }
    /// Get the start address of the range (inclusive).
    #[getter]
    fn start(&self) -> Address {
        self.start.clone()
    }

    /// Get the size of the range in bytes.
    #[getter]
    fn size(&self) -> u64 {
        self.size
    }

    /// Get the alignment requirement in bytes, if any.
    #[getter]
    fn alignment(&self) -> Option<u64> {
        self.alignment
    }

    /// Get the end address of the range (exclusive).
    ///
    /// Returns:
    ///     Address: The end address (start + size)
    #[getter]
    fn end(&self) -> PyResult<Address> {
        self.end_addr().map_err(PyValueError::new_err)
    }

    /// Check if this range contains the given address.
    ///
    /// Args:
    ///     address: The address to check
    ///
    /// Returns:
    ///     bool: True if the address is within this range
    fn contains_address(&self, address: &Address) -> PyResult<bool> {
        self.contains_addr(address).map_err(PyValueError::new_err)
    }

    /// Check if the range is valid.
    fn is_valid_py(&self) -> bool {
        self.is_valid()
    }

    /// Check if this range contains the given range.
    ///
    /// Args:
    ///     other: The other AddressRange to check
    ///
    /// Returns:
    ///     bool: True if other is completely contained within this range
    fn contains_range_py(&self, other: &AddressRange) -> PyResult<bool> {
        self.contains_range(other).map_err(PyValueError::new_err)
    }

    /// Check if this range overlaps with the given range.
    ///
    /// Args:
    ///     other: The other AddressRange to check
    ///
    /// Returns:
    ///     bool: True if the ranges overlap
    fn overlaps_py(&self, other: &AddressRange) -> PyResult<bool> {
        self.overlaps_with(other).map_err(PyValueError::new_err)
    }

    /// Get the intersection of this range with another range.
    ///
    /// Args:
    ///     other: The other AddressRange
    ///
    /// Returns:
    ///     AddressRange or None: The intersection if it exists
    fn intersection_py(&self, other: &AddressRange) -> PyResult<Option<Self>> {
        self.intersection_with(other).map_err(PyValueError::new_err)
    }

    /// Check if this range overlaps with the given range.
    ///
    /// Args:
    ///     other: The other AddressRange to check
    ///
    /// Returns:
    ///     bool: True if the ranges overlap
    fn overlaps(&self, other: &AddressRange) -> PyResult<bool> {
        self.overlaps_with(other).map_err(PyValueError::new_err)
    }

    /// Get the intersection of this range with another range.
    ///
    /// Args:
    ///     other: The other AddressRange
    ///
    /// Returns:
    ///     AddressRange or None: The intersection if it exists
    fn intersection(&self, other: &AddressRange) -> PyResult<Option<Self>> {
        self.intersection_with(other).map_err(PyValueError::new_err)
    }

    /// Check if this range is empty (size = 0).
    ///
    /// Returns:
    ///     bool: True if the range is empty
    fn is_empty(&self) -> bool {
        self.size == 0
    }

    /// Get the size of the range in bytes.
    ///
    /// Returns:
    ///     int: The size in bytes
    #[getter]
    fn size_bytes(&self) -> u64 {
        self.size
    }
}

impl AddressRange {
    /// Create a new AddressRange.
    ///
    /// # Arguments
    /// * `start` - The starting address (inclusive)
    /// * `size` - The size in bytes
    /// * `alignment` - Optional alignment requirement in bytes
    ///
    /// # Errors
    /// Returns an error if size is 0, alignment is invalid, or end address would overflow
    pub fn new(start: Address, size: u64, alignment: Option<u64>) -> Result<Self, String> {
        // Validate size
        if size == 0 {
            return Err("size cannot be 0".to_string());
        }

        // Validate alignment
        if let Some(align) = alignment {
            if align == 0 || (align & (align - 1)) != 0 {
                return Err("alignment must be a positive power of 2".to_string());
            }
        }

        // For smaller bit widths, validate that end address can be created
        if start.bits < 64 {
            let _ = start
                .add(size)
                .map_err(|_| "size too large, would cause address overflow".to_string())?;
        }

        Ok(AddressRange {
            start,
            size,
            alignment,
        })
    }

    /// Get the end address of the range (exclusive).
    ///
    /// # Errors
    /// Returns an error if the end address calculation would overflow
    pub fn end_addr(&self) -> Result<Address, String> {
        self.start.add(self.size)
    }

    /// Check if the range is valid.
    pub fn is_valid(&self) -> bool {
        // Size must be non-zero
        if self.size == 0 {
            return false;
        }

        // Alignment must be valid if present
        if let Some(align) = self.alignment {
            if align == 0 || (align & (align - 1)) != 0 {
                return false;
            }
        }

        // Start address must be valid
        if !self.start.is_valid() {
            return false;
        }

        // End address must be calculable
        self.end_addr().is_ok()
    }

    /// Check if this range contains the given address.
    ///
    /// # Errors
    /// Returns an error if address comparison fails
    pub fn contains_addr(&self, address: &Address) -> Result<bool, String> {
        // Must be same address kind, space, and bits
        if address.kind != self.start.kind {
            return Ok(false);
        }

        if address.space != self.start.space {
            return Ok(false);
        }

        if address.bits != self.start.bits {
            return Ok(false);
        }

        // Check if address value is within range
        let end_addr = self.end_addr()?;
        Ok(address.value >= self.start.value && address.value < end_addr.value)
    }

    /// Check if this range contains the given range.
    ///
    /// # Errors
    /// Returns an error if range comparison fails
    pub fn contains_range(&self, other: &AddressRange) -> Result<bool, String> {
        // Must be same address kind, space, and bits
        if other.start.kind != self.start.kind
            || other.start.space != self.start.space
            || other.start.bits != self.start.bits
        {
            return Ok(false);
        }

        // Check containment
        let self_end = self.end_addr()?;
        let other_end = other.end_addr()?;

        Ok(other.start.value >= self.start.value && other_end.value <= self_end.value)
    }

    /// Check if this range overlaps with the given range.
    ///
    /// # Errors
    /// Returns an error if range comparison fails
    pub fn overlaps_with(&self, other: &AddressRange) -> Result<bool, String> {
        // Must be same address kind, space, and bits
        if other.start.kind != self.start.kind
            || other.start.space != self.start.space
            || other.start.bits != self.start.bits
        {
            return Ok(false);
        }

        // Check overlap
        let self_end = self.end_addr()?;
        let other_end = other.end_addr()?;

        Ok(self.start.value < other_end.value && other.start.value < self_end.value)
    }

    /// Get the intersection of this range with another range.
    ///
    /// # Errors
    /// Returns an error if intersection calculation fails
    pub fn intersection_with(&self, other: &AddressRange) -> Result<Option<Self>, String> {
        // Must be same address kind, space, and bits
        if other.start.kind != self.start.kind
            || other.start.space != self.start.space
            || other.start.bits != self.start.bits
        {
            return Ok(None);
        }

        let self_end = self.end_addr()?;
        let other_end = other.end_addr()?;

        // Find intersection bounds
        let intersect_start = self.start.value.max(other.start.value);
        let intersect_end = self_end.value.min(other_end.value);

        if intersect_start >= intersect_end {
            return Ok(None); // No intersection
        }

        let intersect_size = intersect_end - intersect_start;

        // Create intersection range
        let intersect_start_addr = self.start.add(intersect_start - self.start.value)?;
        let alignment = match (self.alignment, other.alignment) {
            (Some(a), Some(b)) => Some(a.max(b)), // Use stricter alignment
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        };

        Ok(Some(AddressRange::new(
            intersect_start_addr,
            intersect_size,
            alignment,
        )?))
    }
}

impl fmt::Display for AddressRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.end_addr() {
            Ok(end) => write!(f, "[{}, {})", self.start, end),
            Err(_) => write!(f, "[{}, +{})", self.start, self.size),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::address::{Address, AddressKind};

    #[test]
    fn test_address_range_creation() {
        let start = Address::new(AddressKind::VA, 0x1000, 32, None, None).unwrap();
        let range = AddressRange::new(start.clone(), 0x1000, None).unwrap();

        assert_eq!(range.start, start);
        assert_eq!(range.size, 0x1000);
        assert_eq!(range.alignment, None);
        assert!(range.is_valid());
    }

    #[test]
    fn test_address_range_zero_size() {
        let start = Address::new(AddressKind::VA, 0x1000, 32, None, None).unwrap();
        let result = AddressRange::new(start, 0, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_address_range_invalid_alignment() {
        let start = Address::new(AddressKind::VA, 0x1000, 32, None, None).unwrap();

        // Alignment of 0
        let result = AddressRange::new(start.clone(), 0x1000, Some(0));
        assert!(result.is_err());

        // Alignment not power of 2
        let result = AddressRange::new(start, 0x1000, Some(3));
        assert!(result.is_err());
    }

    #[test]
    fn test_address_range_end_address() {
        let start = Address::new(AddressKind::VA, 0x1000, 32, None, None).unwrap();
        let range = AddressRange::new(start, 0x1000, None).unwrap();

        let end = range.end_addr().unwrap();
        assert_eq!(end.value, 0x2000);
        assert_eq!(end.kind, AddressKind::VA);
    }

    #[test]
    fn test_address_range_contains_address() {
        let start = Address::new(AddressKind::VA, 0x1000, 32, None, None).unwrap();
        let range = AddressRange::new(start, 0x1000, None).unwrap();

        // Address within range
        let addr_in = Address::new(AddressKind::VA, 0x1500, 32, None, None).unwrap();
        assert!(range.contains_addr(&addr_in).unwrap());

        // Address before range
        let addr_before = Address::new(AddressKind::VA, 0x500, 32, None, None).unwrap();
        assert!(!range.contains_addr(&addr_before).unwrap());

        // Address after range
        let addr_after = Address::new(AddressKind::VA, 0x2500, 32, None, None).unwrap();
        assert!(!range.contains_addr(&addr_after).unwrap());

        // Address at start (inclusive)
        assert!(range.contains_addr(&range.start).unwrap());

        // Address at end (exclusive)
        let end_addr = range.end_addr().unwrap();
        assert!(!range.contains_addr(&end_addr).unwrap());
    }

    #[test]
    fn test_address_range_contains_range() {
        let start = Address::new(AddressKind::VA, 0x1000, 32, None, None).unwrap();
        let range = AddressRange::new(start, 0x1000, None).unwrap();

        // Completely contained range
        let sub_start = Address::new(AddressKind::VA, 0x1200, 32, None, None).unwrap();
        let sub_range = AddressRange::new(sub_start, 0x200, None).unwrap();
        assert!(range.contains_range(&sub_range).unwrap());

        // Overlapping but not contained
        let overlap_start = Address::new(AddressKind::VA, 0x800, 32, None, None).unwrap();
        let overlap_range = AddressRange::new(overlap_start, 0x1000, None).unwrap();
        assert!(!range.contains_range(&overlap_range).unwrap());

        // Different address space
        let other_start = Address::new(AddressKind::RVA, 0x1200, 32, None, None).unwrap();
        let other_range = AddressRange::new(other_start, 0x200, None).unwrap();
        assert!(!range.contains_range(&other_range).unwrap());
    }

    #[test]
    fn test_address_range_overlaps() {
        let start = Address::new(AddressKind::VA, 0x1000, 32, None, None).unwrap();
        let range = AddressRange::new(start, 0x1000, None).unwrap();

        // Overlapping range
        let overlap_start = Address::new(AddressKind::VA, 0x800, 32, None, None).unwrap();
        let overlap_range = AddressRange::new(overlap_start, 0x1000, None).unwrap();
        assert!(range.overlaps_with(&overlap_range).unwrap());

        // Non-overlapping range
        let separate_start = Address::new(AddressKind::VA, 0x3000, 32, None, None).unwrap();
        let separate_range = AddressRange::new(separate_start, 0x1000, None).unwrap();
        assert!(!range.overlaps_with(&separate_range).unwrap());

        // Adjacent ranges don't overlap
        let adjacent_start = Address::new(AddressKind::VA, 0x2000, 32, None, None).unwrap();
        let adjacent_range = AddressRange::new(adjacent_start, 0x1000, None).unwrap();
        assert!(!range.overlaps_with(&adjacent_range).unwrap());
    }

    #[test]
    fn test_address_range_intersection() {
        let start1 = Address::new(AddressKind::VA, 0x1000, 32, None, None).unwrap();
        let range1 = AddressRange::new(start1, 0x1000, None).unwrap();

        let start2 = Address::new(AddressKind::VA, 0x800, 32, None, None).unwrap();
        let range2 = AddressRange::new(start2, 0x1000, None).unwrap();

        let intersection = range1.intersection_with(&range2).unwrap().unwrap();
        assert_eq!(intersection.start.value, 0x1000);
        assert_eq!(intersection.size, 0x800);

        // No intersection
        let separate_start = Address::new(AddressKind::VA, 0x3000, 32, None, None).unwrap();
        let separate_range = AddressRange::new(separate_start, 0x1000, None).unwrap();
        assert!(range1.intersection_with(&separate_range).unwrap().is_none());
    }

    #[test]
    fn test_address_range_display() {
        let start = Address::new(AddressKind::VA, 0x1000, 32, None, None).unwrap();
        let range = AddressRange::new(start, 0x1000, None).unwrap();

        let display = format!("{}", range);
        assert!(display.contains("[VA:1000"));
        assert!(display.contains("VA:2000)"));
    }
}
