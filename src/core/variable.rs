//! Variable representation for binary analysis.
//!
//! This module provides types for representing variables with their storage
//! locations, types, and liveness information as encountered in binary analysis
//! and decompilation.

use crate::core::{Address, AddressRange};
#[cfg(feature = "python-ext")]
use pyo3::prelude::*;
use serde::{Deserialize, Serialize};

/// Represents the storage location of a variable.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyclass)]
pub enum StorageLocation {
    /// Variable stored in a CPU register
    Register {
        /// Register name (e.g., "rax", "xmm0")
        name: String,
    },
    /// Variable stored on the stack
    Stack {
        /// Offset from the frame base (can be negative for parameters)
        offset: i64,
        /// Frame base register name (optional, defaults to stack pointer)
        frame_base: Option<String>,
    },
    /// Variable stored in heap memory
    Heap {
        /// Address where the variable is stored
        address: Address,
    },
    /// Variable stored at a global/static address
    Global {
        /// Address where the variable is stored
        address: Address,
    },
}

/// Represents a variable in the binary analysis system.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyclass)]
pub struct Variable {
    /// Unique identifier for this variable
    pub id: String,
    /// Human-readable name of the variable (optional)
    pub name: Option<String>,
    /// Type ID of the variable
    pub type_id: String,
    /// Storage location of the variable
    pub storage: StorageLocation,
    /// Address range where this variable is live (optional)
    pub liveness_range: Option<AddressRange>,
    /// Source of this variable information
    pub source: Option<String>,
}

impl Variable {
    /// Create a new register variable.
    pub fn new_register(
        id: String,
        name: Option<String>,
        type_id: String,
        register_name: String,
        liveness_range: Option<AddressRange>,
        source: Option<String>,
    ) -> Self {
        Self {
            id,
            name,
            type_id,
            storage: StorageLocation::Register {
                name: register_name,
            },
            liveness_range,
            source,
        }
    }

    /// Create a new stack variable.
    pub fn new_stack(
        id: String,
        name: Option<String>,
        type_id: String,
        offset: i64,
        frame_base: Option<String>,
        liveness_range: Option<AddressRange>,
        source: Option<String>,
    ) -> Self {
        Self {
            id,
            name,
            type_id,
            storage: StorageLocation::Stack { offset, frame_base },
            liveness_range,
            source,
        }
    }

    /// Create a new heap variable.
    pub fn new_heap(
        id: String,
        name: Option<String>,
        type_id: String,
        address: Address,
        liveness_range: Option<AddressRange>,
        source: Option<String>,
    ) -> Self {
        Self {
            id,
            name,
            type_id,
            storage: StorageLocation::Heap { address },
            liveness_range,
            source,
        }
    }

    /// Create a new global variable.
    pub fn new_global(
        id: String,
        name: Option<String>,
        type_id: String,
        address: Address,
        liveness_range: Option<AddressRange>,
        source: Option<String>,
    ) -> Self {
        Self {
            id,
            name,
            type_id,
            storage: StorageLocation::Global { address },
            liveness_range,
            source,
        }
    }

    /// Validate the variable for consistency.
    pub fn is_valid(&self) -> bool {
        // Check that ID is not empty
        if self.id.trim().is_empty() {
            return false;
        }

        // Check that type_id is not empty
        if self.type_id.trim().is_empty() {
            return false;
        }

        // Validate storage location
        match &self.storage {
            StorageLocation::Register { name } => {
                if name.trim().is_empty() {
                    return false;
                }
            }
            StorageLocation::Stack { frame_base, .. } => {
                if let Some(frame_base) = frame_base {
                    if frame_base.trim().is_empty() {
                        return false;
                    }
                }
            }
            StorageLocation::Heap { address } | StorageLocation::Global { address } => {
                if !address.is_valid() {
                    return false;
                }
            }
        }

        // Validate liveness range if present
        if let Some(range) = &self.liveness_range {
            if !range.is_valid() {
                return false;
            }
        }

        true
    }

    /// Check if this variable is stored in a register.
    pub fn is_register(&self) -> bool {
        matches!(self.storage, StorageLocation::Register { .. })
    }

    /// Check if this variable is stored on the stack.
    pub fn is_stack(&self) -> bool {
        matches!(self.storage, StorageLocation::Stack { .. })
    }

    /// Check if this variable is stored in heap memory.
    pub fn is_heap(&self) -> bool {
        matches!(self.storage, StorageLocation::Heap { .. })
    }

    /// Check if this variable is a global variable.
    pub fn is_global(&self) -> bool {
        matches!(self.storage, StorageLocation::Global { .. })
    }

    /// Get the register name if this is a register variable.
    pub fn register_name(&self) -> Option<&str> {
        match &self.storage {
            StorageLocation::Register { name } => Some(name),
            _ => None,
        }
    }

    /// Get the stack offset if this is a stack variable.
    pub fn stack_offset(&self) -> Option<i64> {
        match &self.storage {
            StorageLocation::Stack { offset, .. } => Some(*offset),
            _ => None,
        }
    }

    /// Get the frame base if this is a stack variable.
    pub fn frame_base(&self) -> Option<&str> {
        match &self.storage {
            StorageLocation::Stack { frame_base, .. } => frame_base.as_deref(),
            _ => None,
        }
    }

    /// Get the address if this is a heap or global variable.
    pub fn address(&self) -> Option<&Address> {
        match &self.storage {
            StorageLocation::Heap { address } | StorageLocation::Global { address } => {
                Some(address)
            }
            _ => None,
        }
    }

    /// Check if the variable is live at the given address.
    pub fn is_live_at(&self, address: &Address) -> bool {
        if let Some(range) = &self.liveness_range {
            range.contains_addr(address).unwrap_or(false)
        } else {
            // If no liveness range is specified, assume it's always live
            true
        }
    }

    /// Get the size of the variable's liveness range.
    pub fn liveness_size(&self) -> Option<u64> {
        self.liveness_range.as_ref().map(|range| range.size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{Address, AddressKind};

    #[test]
    fn test_register_variable_creation() {
        let var = Variable::new_register(
            "var1".to_string(),
            Some("local_var".to_string()),
            "int32".to_string(),
            "rax".to_string(),
            None,
            Some("decompiler".to_string()),
        );

        assert_eq!(var.id, "var1");
        assert_eq!(var.name, Some("local_var".to_string()));
        assert_eq!(var.type_id, "int32");
        assert!(var.is_register());
        assert_eq!(var.register_name(), Some("rax"));
        assert!(var.is_valid());
    }

    #[test]
    fn test_stack_variable_creation() {
        let var = Variable::new_stack(
            "var2".to_string(),
            Some("stack_var".to_string()),
            "int64".to_string(),
            -8,
            Some("rbp".to_string()),
            None,
            None,
        );

        assert!(var.is_stack());
        assert_eq!(var.stack_offset(), Some(-8));
        assert_eq!(var.frame_base(), Some("rbp"));
        assert!(var.is_valid());
    }

    #[test]
    fn test_heap_variable_creation() {
        let address = Address {
            kind: AddressKind::VA,
            value: 0x1000,
            space: None,
            bits: 64,
            symbol_ref: None,
        };

        let var = Variable::new_heap(
            "var3".to_string(),
            None,
            "ptr_int32".to_string(),
            address.clone(),
            None,
            None,
        );

        assert!(var.is_heap());
        assert_eq!(var.address(), Some(&address));
        assert!(var.is_valid());
    }

    #[test]
    fn test_global_variable_creation() {
        let address = Address {
            kind: AddressKind::VA,
            value: 0x2000,
            space: None,
            bits: 64,
            symbol_ref: None,
        };

        let var = Variable::new_global(
            "var4".to_string(),
            Some("global_var".to_string()),
            "int32".to_string(),
            address.clone(),
            None,
            Some("debug".to_string()),
        );

        assert!(var.is_global());
        assert_eq!(var.address(), Some(&address));
        assert!(var.is_valid());
    }

    #[test]
    fn test_invalid_empty_id() {
        let var = Variable::new_register(
            "".to_string(),
            None,
            "int32".to_string(),
            "rax".to_string(),
            None,
            None,
        );
        assert!(!var.is_valid());
    }

    #[test]
    fn test_invalid_empty_type_id() {
        let var = Variable::new_register(
            "var1".to_string(),
            None,
            "".to_string(),
            "rax".to_string(),
            None,
            None,
        );
        assert!(!var.is_valid());
    }

    #[test]
    fn test_invalid_empty_register_name() {
        let var = Variable::new_register(
            "var1".to_string(),
            None,
            "int32".to_string(),
            "".to_string(),
            None,
            None,
        );
        assert!(!var.is_valid());
    }

    #[test]
    fn test_liveness_check() {
        let address = Address {
            kind: AddressKind::VA,
            value: 0x1000,
            space: None,
            bits: 64,
            symbol_ref: None,
        };

        let range = AddressRange {
            start: Address {
                kind: AddressKind::VA,
                value: 0x1000,
                space: None,
                bits: 64,
                symbol_ref: None,
            },
            size: 0x100,
            alignment: None,
        };

        let var = Variable::new_register(
            "var1".to_string(),
            None,
            "int32".to_string(),
            "rax".to_string(),
            Some(range),
            None,
        );

        // Should be live at the start address
        assert!(var.is_live_at(&address));

        // Should be live within the range
        let mid_address = Address {
            kind: AddressKind::VA,
            value: 0x1050,
            space: None,
            bits: 64,
            symbol_ref: None,
        };
        assert!(var.is_live_at(&mid_address));

        // Should not be live outside the range
        let outside_address = Address {
            kind: AddressKind::VA,
            value: 0x1200,
            space: None,
            bits: 64,
            symbol_ref: None,
        };
        assert!(!var.is_live_at(&outside_address));
    }

    #[test]
    fn test_serialization() {
        let var = Variable::new_register(
            "var1".to_string(),
            Some("test_var".to_string()),
            "int32".to_string(),
            "rax".to_string(),
            None,
            Some("decompiler".to_string()),
        );

        let serialized = serde_json::to_string(&var).unwrap();
        let deserialized: Variable = serde_json::from_str(&serialized).unwrap();

        assert_eq!(var, deserialized);
    }
}

// Python bindings
#[cfg(feature = "python-ext")]
#[pymethods]
impl Variable {
    #[new]
    #[pyo3(signature = (id, type_id, storage, name=None, liveness_range=None, source=None))]
    fn new_py(
        id: String,
        type_id: String,
        storage: StorageLocation,
        name: Option<String>,
        liveness_range: Option<AddressRange>,
        source: Option<String>,
    ) -> PyResult<Self> {
        let var = Self {
            id,
            name,
            type_id,
            storage,
            liveness_range,
            source,
        };

        if !var.is_valid() {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "Invalid Variable parameters",
            ));
        }

        Ok(var)
    }

    #[staticmethod]
    fn register(
        id: String,
        name: Option<String>,
        type_id: String,
        register_name: String,
        liveness_range: Option<AddressRange>,
        source: Option<String>,
    ) -> PyResult<Self> {
        let var = Self::new_register(id, name, type_id, register_name, liveness_range, source);
        if !var.is_valid() {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "Invalid register variable parameters",
            ));
        }
        Ok(var)
    }

    #[staticmethod]
    fn stack(
        id: String,
        name: Option<String>,
        type_id: String,
        offset: i64,
        frame_base: Option<String>,
        liveness_range: Option<AddressRange>,
        source: Option<String>,
    ) -> PyResult<Self> {
        let var = Self::new_stack(
            id,
            name,
            type_id,
            offset,
            frame_base,
            liveness_range,
            source,
        );
        if !var.is_valid() {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "Invalid stack variable parameters",
            ));
        }
        Ok(var)
    }

    #[staticmethod]
    fn heap(
        id: String,
        name: Option<String>,
        type_id: String,
        address: Address,
        liveness_range: Option<AddressRange>,
        source: Option<String>,
    ) -> PyResult<Self> {
        let var = Self::new_heap(id, name, type_id, address, liveness_range, source);
        if !var.is_valid() {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "Invalid heap variable parameters",
            ));
        }
        Ok(var)
    }

    #[staticmethod]
    fn global(
        id: String,
        name: Option<String>,
        type_id: String,
        address: Address,
        liveness_range: Option<AddressRange>,
        source: Option<String>,
    ) -> PyResult<Self> {
        let var = Self::new_global(id, name, type_id, address, liveness_range, source);
        if !var.is_valid() {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "Invalid global variable parameters",
            ));
        }
        Ok(var)
    }

    fn __str__(&self) -> String {
        let name_str = self
            .name
            .as_ref()
            .map(|n| format!("'{}'", n))
            .unwrap_or_else(|| "None".to_string());
        format!(
            "Variable(id={}, name={}, type_id={})",
            self.id, name_str, self.type_id
        )
    }

    fn __repr__(&self) -> String {
        let name_str = self
            .name
            .as_ref()
            .map(|n| format!("{:?}", n))
            .unwrap_or_else(|| "None".to_string());
        format!(
            "Variable(id={:?}, name={}, type_id={:?})",
            self.id, name_str, self.type_id
        )
    }

    fn __eq__(&self, other: &Self) -> bool {
        self == other
    }

    fn __hash__(&self) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        self.hash(&mut hasher);
        hasher.finish()
    }

    // Property getters
    #[getter]
    fn get_id(&self) -> &str {
        &self.id
    }

    #[getter]
    fn get_name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    #[getter]
    fn get_type_id(&self) -> &str {
        &self.type_id
    }

    #[getter]
    fn get_storage(&self) -> StorageLocation {
        self.storage.clone()
    }

    #[getter]
    fn get_liveness_range(&self) -> Option<AddressRange> {
        self.liveness_range.clone()
    }

    #[getter]
    fn get_source(&self) -> Option<&str> {
        self.source.as_deref()
    }

    // Methods
    fn is_valid_py(&self) -> bool {
        self.is_valid()
    }

    fn is_register_py(&self) -> bool {
        self.is_register()
    }

    fn is_stack_py(&self) -> bool {
        self.is_stack()
    }

    fn is_heap_py(&self) -> bool {
        self.is_heap()
    }

    fn is_global_py(&self) -> bool {
        self.is_global()
    }

    fn register_name_py(&self) -> Option<&str> {
        self.register_name()
    }

    fn stack_offset_py(&self) -> Option<i64> {
        self.stack_offset()
    }

    fn frame_base_py(&self) -> Option<&str> {
        self.frame_base()
    }

    fn address_py(&self) -> Option<Address> {
        self.address().cloned()
    }

    fn is_live_at_py(&self, address: &Address) -> bool {
        self.is_live_at(address)
    }

    fn liveness_size_py(&self) -> Option<u64> {
        self.liveness_size()
    }

    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string(self)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))
    }

    #[staticmethod]
    fn from_json(json_str: &str) -> PyResult<Self> {
        serde_json::from_str(json_str)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))
    }
}

#[cfg(feature = "python-ext")]
#[pymethods]
impl StorageLocation {
    fn __str__(&self) -> String {
        match self {
            StorageLocation::Register { name } => format!("Register({})", name),
            StorageLocation::Stack { offset, frame_base } => {
                let frame_str = frame_base
                    .as_ref()
                    .map(|f| format!("@{}", f))
                    .unwrap_or_default();
                format!("Stack({}{})", offset, frame_str)
            }
            StorageLocation::Heap { address } => format!("Heap({})", address),
            StorageLocation::Global { address } => format!("Global({})", address),
        }
    }

    fn __repr__(&self) -> String {
        match self {
            StorageLocation::Register { name } => {
                format!("StorageLocation.Register(name={:?})", name)
            }
            StorageLocation::Stack { offset, frame_base } => {
                let frame_repr = frame_base
                    .as_ref()
                    .map(|f| format!(", frame_base={:?}", f))
                    .unwrap_or_default();
                format!("StorageLocation.Stack(offset={}{})", offset, frame_repr)
            }
            StorageLocation::Heap { address } => {
                format!("StorageLocation.Heap(address={})", address)
            }
            StorageLocation::Global { address } => {
                format!("StorageLocation.Global(address={})", address)
            }
        }
    }

    #[staticmethod]
    fn register(name: String) -> Self {
        StorageLocation::Register { name }
    }

    #[staticmethod]
    fn stack(offset: i64, frame_base: Option<String>) -> Self {
        StorageLocation::Stack { offset, frame_base }
    }

    #[staticmethod]
    fn heap(address: Address) -> Self {
        StorageLocation::Heap { address }
    }

    #[staticmethod]
    fn global(address: Address) -> Self {
        StorageLocation::Global { address }
    }
}
