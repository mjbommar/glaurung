//! Register types for CPU registers and their properties.
//!
//! This module defines the Register type and RegisterKind enum for representing
//! CPU registers across different architectures, including their relationships
//! and properties.

#[cfg(feature = "python-ext")]
use pyo3::prelude::*;
use serde::{Deserialize, Serialize};
use std::fmt;

use crate::core::address::Address;

/// Types of CPU registers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyclass)]
pub enum RegisterKind {
    /// General purpose registers (rax, rbx, etc.)
    General,
    /// Floating point registers (xmm0, ymm0, etc.)
    Float,
    /// SIMD/Vector registers (xmm, ymm, zmm)
    Vector,
    /// Status/flags registers (eflags, rflags)
    Flags,
    /// Segment registers (cs, ds, ss, es, fs, gs)
    Segment,
    /// Control registers (cr0, cr2, cr3, cr4)
    Control,
    /// Debug registers (dr0-dr7)
    Debug,
}

#[cfg_attr(feature = "python-ext", pymethods)]
impl RegisterKind {
    /// String representation for display
    fn __str__(&self) -> String {
        format!("{}", self)
    }
}

impl fmt::Display for RegisterKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RegisterKind::General => write!(f, "General"),
            RegisterKind::Float => write!(f, "Float"),
            RegisterKind::Vector => write!(f, "Vector"),
            RegisterKind::Flags => write!(f, "Flags"),
            RegisterKind::Segment => write!(f, "Segment"),
            RegisterKind::Control => write!(f, "Control"),
            RegisterKind::Debug => write!(f, "Debug"),
        }
    }
}

/// CPU register representation
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyclass)]
pub struct Register {
    /// Register name (e.g., "rax", "xmm0", "cs")
    pub name: String,
    /// Size in bits (8, 16, 32, 64, 128, 256, 512, etc.)
    pub size: u16,
    /// Type of register
    pub kind: RegisterKind,
    /// Optional memory address for memory-mapped registers
    pub address: Option<Address>,
    /// Optional parent register name (e.g., "al" parent is "rax")
    pub parent_register: Option<String>,
    /// Bit offset within parent register (for sub-registers)
    pub offset_in_parent: Option<u8>,
}

impl Register {
    /// Create a new Register instance (pure Rust)
    pub fn new(
        name: String,
        size: u16,
        kind: RegisterKind,
        address: Option<Address>,
        parent_register: Option<String>,
        offset_in_parent: Option<u8>,
    ) -> Self {
        Self {
            name,
            size,
            kind,
            address,
            parent_register,
            offset_in_parent,
        }
    }

    /// Create a general purpose register (pure Rust)
    pub fn general(name: String, size: u16) -> Self {
        Self::new(name, size, RegisterKind::General, None, None, None)
    }

    /// Create a floating point register (pure Rust)
    pub fn float(name: String, size: u16) -> Self {
        Self::new(name, size, RegisterKind::Float, None, None, None)
    }

    /// Create a vector/SIMD register (pure Rust)
    pub fn vector(name: String, size: u16) -> Self {
        Self::new(name, size, RegisterKind::Vector, None, None, None)
    }

    /// Create a flags register (pure Rust)
    pub fn flags(name: String, size: u16) -> Self {
        Self::new(name, size, RegisterKind::Flags, None, None, None)
    }

    /// Create a segment register (pure Rust)
    pub fn segment(name: String, size: u16) -> Self {
        Self::new(name, size, RegisterKind::Segment, None, None, None)
    }

    /// Create a control register (pure Rust)
    pub fn control(name: String, size: u16) -> Self {
        Self::new(name, size, RegisterKind::Control, None, None, None)
    }

    /// Create a debug register (pure Rust)
    pub fn debug(name: String, size: u16) -> Self {
        Self::new(name, size, RegisterKind::Debug, None, None, None)
    }

    /// Create a sub-register (with parent relationship) (pure Rust)
    pub fn sub_register(
        name: String,
        size: u16,
        kind: RegisterKind,
        parent_name: String,
        offset: u8,
    ) -> Self {
        Self::new(name, size, kind, None, Some(parent_name), Some(offset))
    }

    // (Removed Python-only __str__ from pure Rust impl; provided in #[pymethods])

    /// Check if this is a general purpose register
    pub fn is_general(&self) -> bool {
        self.kind == RegisterKind::General
    }
    /// Check if this is a floating point register
    pub fn is_float(&self) -> bool {
        self.kind == RegisterKind::Float
    }
    /// Check if this is a vector/SIMD register
    pub fn is_vector(&self) -> bool {
        self.kind == RegisterKind::Vector
    }
    /// Check if this is a flags register
    pub fn is_flags(&self) -> bool {
        self.kind == RegisterKind::Flags
    }
    /// Check if this is a segment register
    pub fn is_segment(&self) -> bool {
        self.kind == RegisterKind::Segment
    }
    /// Check if this is a control register
    pub fn is_control(&self) -> bool {
        self.kind == RegisterKind::Control
    }
    /// Check if this is a debug register
    pub fn is_debug(&self) -> bool {
        self.kind == RegisterKind::Debug
    }
    /// Check if this register has a parent (is a sub-register)
    pub fn has_parent(&self) -> bool {
        self.parent_register.is_some()
    }
    /// Check if this register is memory-mapped
    pub fn is_memory_mapped(&self) -> bool {
        self.address.is_some()
    }
    /// Get the size in bytes (rounded up)
    pub fn size_bytes(&self) -> usize {
        (self.size as usize).div_ceil(8)
    }
    /// Check if this register can contain the given value size
    pub fn can_contain(&self, value_size_bits: u16) -> bool {
        value_size_bits <= self.size
    }
    /// Get a summary of the register
    pub fn summary(&self) -> String {
        let mut parts = vec![
            self.name.clone(),
            format!("{}bit", self.size),
            format!("{}", self.kind),
        ];
        if let Some(parent) = &self.parent_register {
            parts.push(format!("parent:{}", parent));
        }
        if let Some(offset) = self.offset_in_parent {
            parts.push(format!("offset:{}", offset));
        }
        if self.is_memory_mapped() {
            parts.push("memory-mapped".to_string());
        }
        parts.join(" ")
    }
}

#[cfg(feature = "python-ext")]
#[pymethods]
impl Register {
    /// Create a new Register instance (Python constructor)
    #[new]
    #[pyo3(signature = (
        name,
        size,
        kind,
        address=None,
        parent_register=None,
        offset_in_parent=None
    ))]
    pub fn new_py(
        name: String,
        size: u16,
        kind: RegisterKind,
        address: Option<Address>,
        parent_register: Option<String>,
        offset_in_parent: Option<u8>,
    ) -> Self {
        Self::new(name, size, kind, address, parent_register, offset_in_parent)
    }

    /// String representation for display
    fn __str__(&self) -> String {
        format!("{}", self)
    }

    // Static factory methods for Python
    #[staticmethod]
    #[pyo3(name = "general")]
    pub fn general_py(name: String, size: u16) -> Self {
        Self::general(name, size)
    }
    #[staticmethod]
    #[pyo3(name = "float")]
    pub fn float_py(name: String, size: u16) -> Self {
        Self::float(name, size)
    }
    #[staticmethod]
    #[pyo3(name = "vector")]
    pub fn vector_py(name: String, size: u16) -> Self {
        Self::vector(name, size)
    }
    #[staticmethod]
    #[pyo3(name = "flags")]
    pub fn flags_py(name: String, size: u16) -> Self {
        Self::flags(name, size)
    }
    #[staticmethod]
    #[pyo3(name = "segment")]
    pub fn segment_py(name: String, size: u16) -> Self {
        Self::segment(name, size)
    }
    #[staticmethod]
    #[pyo3(name = "control")]
    pub fn control_py(name: String, size: u16) -> Self {
        Self::control(name, size)
    }
    #[staticmethod]
    #[pyo3(name = "debug")]
    pub fn debug_py(name: String, size: u16) -> Self {
        Self::debug(name, size)
    }
    #[staticmethod]
    #[pyo3(name = "sub_register")]
    pub fn sub_register_py(
        name: String,
        size: u16,
        kind: RegisterKind,
        parent_name: String,
        offset: u8,
    ) -> Self {
        Self::sub_register(name, size, kind, parent_name, offset)
    }

    // Property getters
    #[getter]
    fn name(&self) -> &str {
        &self.name
    }
    #[getter]
    fn size(&self) -> u16 {
        self.size
    }
    #[getter]
    fn kind(&self) -> RegisterKind {
        self.kind
    }
    #[getter]
    fn address(&self) -> Option<Address> {
        self.address.clone()
    }
    #[getter]
    fn parent_register(&self) -> Option<String> {
        self.parent_register.clone()
    }
    #[getter]
    fn offset_in_parent(&self) -> Option<u8> {
        self.offset_in_parent
    }

    // Helper wrappers (rename to avoid collision and forward to inherent methods)
    #[pyo3(name = "is_general")]
    fn is_general_py(&self) -> bool {
        Register::is_general(self)
    }
    #[pyo3(name = "is_float")]
    fn is_float_py(&self) -> bool {
        Register::is_float(self)
    }
    #[pyo3(name = "is_vector")]
    fn is_vector_py(&self) -> bool {
        Register::is_vector(self)
    }
    #[pyo3(name = "is_flags")]
    fn is_flags_py(&self) -> bool {
        Register::is_flags(self)
    }
    #[pyo3(name = "is_segment")]
    fn is_segment_py(&self) -> bool {
        Register::is_segment(self)
    }
    #[pyo3(name = "is_control")]
    fn is_control_py(&self) -> bool {
        Register::is_control(self)
    }
    #[pyo3(name = "is_debug")]
    fn is_debug_py(&self) -> bool {
        Register::is_debug(self)
    }
    #[pyo3(name = "has_parent")]
    fn has_parent_py(&self) -> bool {
        Register::has_parent(self)
    }
    #[pyo3(name = "is_memory_mapped")]
    fn is_memory_mapped_py(&self) -> bool {
        Register::is_memory_mapped(self)
    }
    #[pyo3(name = "size_bytes")]
    fn size_bytes_py(&self) -> usize {
        Register::size_bytes(self)
    }
    #[pyo3(name = "can_contain")]
    fn can_contain_py(&self, value_size_bits: u16) -> bool {
        Register::can_contain(self, value_size_bits)
    }
    #[pyo3(name = "summary")]
    fn summary_py(&self) -> String {
        Register::summary(self)
    }
}

impl fmt::Display for Register {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::address::{Address, AddressKind};

    #[test]
    fn test_register_kind_display() {
        assert_eq!(format!("{}", RegisterKind::General), "General");
        assert_eq!(format!("{}", RegisterKind::Float), "Float");
        assert_eq!(format!("{}", RegisterKind::Vector), "Vector");
        assert_eq!(format!("{}", RegisterKind::Flags), "Flags");
        assert_eq!(format!("{}", RegisterKind::Segment), "Segment");
        assert_eq!(format!("{}", RegisterKind::Control), "Control");
        assert_eq!(format!("{}", RegisterKind::Debug), "Debug");
    }

    #[test]
    fn test_register_general_creation() {
        let reg = Register::general("rax".to_string(), 64);
        assert_eq!(reg.name, "rax");
        assert_eq!(reg.size, 64);
        assert_eq!(reg.kind, RegisterKind::General);
        assert!(reg.is_general());
        assert!(!reg.has_parent());
        assert!(!reg.is_memory_mapped());
        assert_eq!(reg.size_bytes(), 8);
    }

    #[test]
    fn test_register_float_creation() {
        let reg = Register::float("xmm0".to_string(), 128);
        assert_eq!(reg.name, "xmm0");
        assert_eq!(reg.size, 128);
        assert_eq!(reg.kind, RegisterKind::Float);
        assert!(reg.is_float());
        assert_eq!(reg.size_bytes(), 16);
    }

    #[test]
    fn test_register_vector_creation() {
        let reg = Register::vector("ymm0".to_string(), 256);
        assert_eq!(reg.name, "ymm0");
        assert_eq!(reg.size, 256);
        assert_eq!(reg.kind, RegisterKind::Vector);
        assert!(reg.is_vector());
        assert_eq!(reg.size_bytes(), 32); // 256 bits = 32 bytes
    }

    #[test]
    fn test_register_flags_creation() {
        let reg = Register::flags("eflags".to_string(), 32);
        assert_eq!(reg.name, "eflags");
        assert_eq!(reg.size, 32);
        assert_eq!(reg.kind, RegisterKind::Flags);
        assert!(reg.is_flags());
    }

    #[test]
    fn test_register_segment_creation() {
        let reg = Register::segment("cs".to_string(), 16);
        assert_eq!(reg.name, "cs");
        assert_eq!(reg.size, 16);
        assert_eq!(reg.kind, RegisterKind::Segment);
        assert!(reg.is_segment());
    }

    #[test]
    fn test_register_control_creation() {
        let reg = Register::control("cr0".to_string(), 64);
        assert_eq!(reg.name, "cr0");
        assert_eq!(reg.size, 64);
        assert_eq!(reg.kind, RegisterKind::Control);
        assert!(reg.is_control());
    }

    #[test]
    fn test_register_debug_creation() {
        let reg = Register::debug("dr0".to_string(), 64);
        assert_eq!(reg.name, "dr0");
        assert_eq!(reg.size, 64);
        assert_eq!(reg.kind, RegisterKind::Debug);
        assert!(reg.is_debug());
    }

    #[test]
    fn test_register_sub_register_creation() {
        let reg = Register::sub_register(
            "al".to_string(),
            8,
            RegisterKind::General,
            "rax".to_string(),
            0,
        );
        assert_eq!(reg.name, "al");
        assert_eq!(reg.size, 8);
        assert_eq!(reg.kind, RegisterKind::General);
        assert_eq!(reg.parent_register, Some("rax".to_string()));
        assert_eq!(reg.offset_in_parent, Some(0));
        assert!(reg.has_parent());
        assert!(!reg.is_memory_mapped());
    }

    #[test]
    fn test_register_memory_mapped() {
        let address = Address::new(AddressKind::VA, 0x1000, 64, None, None).unwrap();
        let reg = Register::new(
            "mmio_reg".to_string(),
            32,
            RegisterKind::General,
            Some(address.clone()),
            None,
            None,
        );
        assert!(reg.is_memory_mapped());
        assert_eq!(reg.address, Some(address));
    }

    #[test]
    fn test_register_can_contain() {
        let reg64 = Register::general("rax".to_string(), 64);
        assert!(reg64.can_contain(32));
        assert!(reg64.can_contain(64));
        assert!(!reg64.can_contain(128));

        let reg32 = Register::general("eax".to_string(), 32);
        assert!(reg32.can_contain(16));
        assert!(reg32.can_contain(32));
        assert!(!reg32.can_contain(64));
    }

    #[test]
    fn test_register_display() {
        let reg = Register::general("rax".to_string(), 64);
        assert_eq!(format!("{}", reg), "rax");
    }

    #[test]
    fn test_register_summary() {
        let reg = Register::general("rax".to_string(), 64);
        let summary = reg.summary();
        assert!(summary.contains("rax"));
        assert!(summary.contains("64bit"));
        assert!(summary.contains("General"));

        let sub_reg = Register::sub_register(
            "al".to_string(),
            8,
            RegisterKind::General,
            "rax".to_string(),
            0,
        );
        let sub_summary = sub_reg.summary();
        assert!(sub_summary.contains("al"));
        assert!(sub_summary.contains("8bit"));
        assert!(sub_summary.contains("parent:rax"));
        assert!(sub_summary.contains("offset:0"));
    }

    #[test]
    fn test_register_equality() {
        let reg1 = Register::general("rax".to_string(), 64);
        let reg2 = Register::general("rax".to_string(), 64);
        let reg3 = Register::general("rbx".to_string(), 64);

        assert_eq!(reg1, reg2);
        assert_ne!(reg1, reg3);
    }

    #[test]
    fn test_register_clone() {
        let reg1 = Register::general("rax".to_string(), 64);
        let reg2 = reg1.clone();
        assert_eq!(reg1, reg2);
    }
}
