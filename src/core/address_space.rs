//! AddressSpace types for binary analysis.
//!
//! This module provides the AddressSpace type that represents named addressing
//! domains within a binary, such as default memory, overlays, stack, heap, and MMIO.

#[cfg(feature = "python-ext")]
use pyo3::exceptions::PyValueError;
#[cfg(feature = "python-ext")]
use pyo3::prelude::*;
use std::fmt;

/// The kind of address space.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "python-ext", pyclass(eq, eq_int))]
pub enum AddressSpaceKind {
    /// Default address space (standard virtual memory)
    Default,
    /// Overlay address space (overlaid on another space)
    Overlay,
    /// Stack address space
    Stack,
    /// Heap address space
    Heap,
    /// Memory-mapped I/O address space
    MMIO,
    /// Other/custom address space
    Other,
}

#[cfg(feature = "python-ext")]
#[pymethods]
impl AddressSpaceKind {
    /// String representation for display.
    fn __str__(&self) -> String {
        match self {
            AddressSpaceKind::Default => "Default".to_string(),
            AddressSpaceKind::Overlay => "Overlay".to_string(),
            AddressSpaceKind::Stack => "Stack".to_string(),
            AddressSpaceKind::Heap => "Heap".to_string(),
            AddressSpaceKind::MMIO => "MMIO".to_string(),
            AddressSpaceKind::Other => "Other".to_string(),
        }
    }

    /// Python representation.
    fn __repr__(&self) -> String {
        format!("AddressSpaceKind.{}", self.__str__())
    }
}

/// A named addressing domain within a binary.
///
/// AddressSpace represents different memory regions or addressing contexts,
/// such as the default virtual address space, overlays, stack, heap, or MMIO regions.
/// This allows for proper handling of segmented/overlay architectures and
/// different memory types.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "python-ext", pyclass)]
pub struct AddressSpace {
    /// The name of this address space
    #[cfg_attr(feature = "python-ext", pyo3(get, set))]
    pub name: String,
    /// The kind of address space this represents
    #[cfg_attr(feature = "python-ext", pyo3(get, set))]
    pub kind: AddressSpaceKind,
    /// Optional maximum size of this address space
    #[cfg_attr(feature = "python-ext", pyo3(get, set))]
    pub size: Option<u64>,
    /// Optional parent space for overlays
    #[cfg_attr(feature = "python-ext", pyo3(get, set))]
    pub base_space: Option<String>,
}

#[cfg(feature = "python-ext")]
#[pymethods]
impl AddressSpace {
    /// Create a new AddressSpace.
    ///
    /// Args:
    ///     name: The name of the address space (str)
    ///     kind: The kind of address space (AddressSpaceKind)
    ///     size: Optional maximum size in bytes (int)
    ///     base_space: Optional parent space name for overlays (str)
    ///
    /// Returns:
    ///     AddressSpace: A new AddressSpace instance
    ///
    /// Raises:
    ///     ValueError: If validation fails
    #[new]
    #[pyo3(signature = (name, kind, size=None, base_space=None))]
    fn new_py(
        name: String,
        kind: AddressSpaceKind,
        size: Option<u64>,
        base_space: Option<String>,
    ) -> PyResult<Self> {
        Self::new(name, kind, size, base_space).map_err(PyValueError::new_err)
    }

    /// String representation for display.
    fn __str__(&self) -> String {
        format!("{}", self)
    }

    /// Python representation.
    fn __repr__(&self) -> String {
        let size_str = self
            .size
            .map(|s| format!(", size={}", s))
            .unwrap_or_default();
        let base_str = self
            .base_space
            .as_ref()
            .map(|b| format!(", base_space='{}'", b))
            .unwrap_or_default();
        format!(
            "AddressSpace(name='{}', kind=AddressSpaceKind.{}{size_str}{base_str})",
            self.name,
            self.kind.__str__()
        )
    }

    /// Check if this address space is valid.
    fn is_valid_py(&self) -> bool {
        self.is_valid()
    }

    /// Check if this is an overlay address space.
    ///
    /// Returns:
    ///     bool: True if this is an overlay space
    fn is_overlay(&self) -> bool {
        self.kind == AddressSpaceKind::Overlay
    }

    /// Check if this address space has a base space.
    ///
    /// Returns:
    ///     bool: True if this space has a base_space defined
    fn has_base_space(&self) -> bool {
        self.base_space.is_some()
    }

    /// Get the effective size of this address space.
    ///
    /// Returns:
    ///     int or None: The size if defined, None otherwise
    #[getter]
    fn effective_size(&self) -> Option<u64> {
        self.size
    }
}

impl AddressSpace {
    /// Create a new AddressSpace.
    ///
    /// # Arguments
    /// * `name` - The name of the address space
    /// * `kind` - The kind of address space
    /// * `size` - Optional maximum size in bytes
    /// * `base_space` - Optional parent space name for overlays
    ///
    /// # Errors
    /// Returns an error if validation fails
    pub fn new(
        name: String,
        kind: AddressSpaceKind,
        size: Option<u64>,
        base_space: Option<String>,
    ) -> Result<Self, String> {
        // Validate name
        if name.trim().is_empty() {
            return Err("name cannot be empty or whitespace".to_string());
        }

        // Validate base_space for overlays
        if kind == AddressSpaceKind::Overlay && base_space.is_none() {
            return Err("overlay address spaces must have a base_space".to_string());
        }

        // Validate size is reasonable if provided
        if let Some(sz) = size {
            if sz == 0 {
                return Err("size cannot be 0".to_string());
            }
        }

        Ok(AddressSpace {
            name,
            kind,
            size,
            base_space,
        })
    }

    /// Check if the address space is valid.
    pub fn is_valid(&self) -> bool {
        // Name must not be empty
        if self.name.trim().is_empty() {
            return false;
        }

        // Overlay spaces must have base_space
        if self.kind == AddressSpaceKind::Overlay && self.base_space.is_none() {
            return false;
        }

        // Size must be positive if provided
        if let Some(sz) = self.size {
            if sz == 0 {
                return false;
            }
        }

        true
    }

    /// Check if this is an overlay address space (pure Rust).
    pub fn is_overlay(&self) -> bool {
        self.kind == AddressSpaceKind::Overlay
    }

    /// Check if this address space has a base space (pure Rust).
    pub fn has_base_space(&self) -> bool {
        self.base_space.is_some()
    }

    /// Get the effective size of this address space (pure Rust).
    pub fn effective_size(&self) -> Option<u64> {
        self.size
    }
}

impl fmt::Display for AddressSpace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let size_str = self
            .size
            .map(|s| format!(" (size: {})", s))
            .unwrap_or_default();
        let base_str = self
            .base_space
            .as_ref()
            .map(|b| format!(" -> {}", b))
            .unwrap_or_default();

        write!(f, "{}:{}{size_str}{base_str}", self.name, self.kind)
    }
}

impl fmt::Display for AddressSpaceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AddressSpaceKind::Default => write!(f, "Default"),
            AddressSpaceKind::Overlay => write!(f, "Overlay"),
            AddressSpaceKind::Stack => write!(f, "Stack"),
            AddressSpaceKind::Heap => write!(f, "Heap"),
            AddressSpaceKind::MMIO => write!(f, "MMIO"),
            AddressSpaceKind::Other => write!(f, "Other"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_space_creation() {
        let space = AddressSpace::new(
            "default".to_string(),
            AddressSpaceKind::Default,
            Some(0x1000000),
            None,
        )
        .unwrap();

        assert_eq!(space.name, "default");
        assert_eq!(space.kind, AddressSpaceKind::Default);
        assert_eq!(space.size, Some(0x1000000));
        assert_eq!(space.base_space, None);
        assert!(space.is_valid());
    }

    #[test]
    fn test_address_space_empty_name() {
        let result = AddressSpace::new("".to_string(), AddressSpaceKind::Default, None, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_address_space_whitespace_name() {
        let result = AddressSpace::new("   ".to_string(), AddressSpaceKind::Default, None, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_address_space_zero_size() {
        let result =
            AddressSpace::new("test".to_string(), AddressSpaceKind::Default, Some(0), None);
        assert!(result.is_err());
    }

    #[test]
    fn test_overlay_without_base_space() {
        let result = AddressSpace::new(
            "overlay1".to_string(),
            AddressSpaceKind::Overlay,
            None,
            None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_overlay_with_base_space() {
        let space = AddressSpace::new(
            "overlay1".to_string(),
            AddressSpaceKind::Overlay,
            Some(0x1000),
            Some("default".to_string()),
        )
        .unwrap();

        assert_eq!(space.name, "overlay1");
        assert_eq!(space.kind, AddressSpaceKind::Overlay);
        assert_eq!(space.base_space, Some("default".to_string()));
        assert!(space.is_valid());
        assert!(space.is_overlay());
        assert!(space.has_base_space());
    }

    #[test]
    fn test_stack_space() {
        let space = AddressSpace::new(
            "stack".to_string(),
            AddressSpaceKind::Stack,
            Some(0x100000),
            None,
        )
        .unwrap();

        assert_eq!(space.name, "stack");
        assert_eq!(space.kind, AddressSpaceKind::Stack);
        assert!(!space.is_overlay());
        assert!(!space.has_base_space());
    }

    #[test]
    fn test_heap_space() {
        let space =
            AddressSpace::new("heap".to_string(), AddressSpaceKind::Heap, None, None).unwrap();

        assert_eq!(space.name, "heap");
        assert_eq!(space.kind, AddressSpaceKind::Heap);
        assert_eq!(space.effective_size(), None);
    }

    #[test]
    fn test_mmio_space() {
        let space = AddressSpace::new(
            "mmio".to_string(),
            AddressSpaceKind::MMIO,
            Some(0x1000),
            None,
        )
        .unwrap();

        assert_eq!(space.name, "mmio");
        assert_eq!(space.kind, AddressSpaceKind::MMIO);
    }

    #[test]
    fn test_other_space() {
        let space = AddressSpace::new(
            "custom".to_string(),
            AddressSpaceKind::Other,
            Some(0x2000),
            None,
        )
        .unwrap();

        assert_eq!(space.name, "custom");
        assert_eq!(space.kind, AddressSpaceKind::Other);
    }

    #[test]
    fn test_display() {
        let space = AddressSpace::new(
            "default".to_string(),
            AddressSpaceKind::Default,
            Some(0x1000000),
            None,
        )
        .unwrap();

        let display = format!("{}", space);
        assert!(display.contains("default"));
        assert!(display.contains("Default"));
        assert!(display.contains("size: 16777216"));
    }

    #[test]
    fn test_overlay_display() {
        let space = AddressSpace::new(
            "overlay1".to_string(),
            AddressSpaceKind::Overlay,
            Some(0x1000),
            Some("default".to_string()),
        )
        .unwrap();

        let display = format!("{}", space);
        assert!(display.contains("overlay1"));
        assert!(display.contains("Overlay"));
        assert!(display.contains("-> default"));
    }
}
