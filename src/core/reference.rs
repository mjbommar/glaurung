//! Reference type for representing cross-references in binary analysis.
//!
//! A Reference represents a directed relationship between code or data locations,
//! essential for building control flow graphs and call graphs.

use crate::core::address::Address;
use crate::error::GlaurungError;
use serde::{Deserialize, Serialize};

#[cfg(feature = "python-ext")]
use pyo3::prelude::*;

/// Enum representing the kind of unresolved reference target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyclass)]
pub enum UnresolvedReferenceKind {
    /// Dynamic reference resolved at runtime
    Dynamic,
    /// Indirect reference through a register or memory
    Indirect,
    /// External reference to another module/library
    External,
    /// Unknown/unclassified unresolved reference
    Unknown,
}

impl UnresolvedReferenceKind {
    pub fn as_str(&self) -> &str {
        match self {
            UnresolvedReferenceKind::Dynamic => "dynamic",
            UnresolvedReferenceKind::Indirect => "indirect",
            UnresolvedReferenceKind::External => "external",
            UnresolvedReferenceKind::Unknown => "unknown",
        }
    }
}

/// Enum representing the target of a reference.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyclass)]
pub enum ReferenceTarget {
    /// Resolved target with an Address
    Resolved(Address),
    /// Unresolved target with a kind and optional expression
    Unresolved {
        kind: UnresolvedReferenceKind,
        expression: Option<String>,
    },
}

impl ReferenceTarget {
    /// Check if the target is resolved
    pub fn is_resolved(&self) -> bool {
        matches!(self, ReferenceTarget::Resolved(_))
    }

    /// Check if the target is unresolved
    pub fn is_unresolved(&self) -> bool {
        matches!(self, ReferenceTarget::Unresolved { .. })
    }

    /// Get the resolved address if available
    pub fn resolved_address(&self) -> Option<&Address> {
        match self {
            ReferenceTarget::Resolved(addr) => Some(addr),
            ReferenceTarget::Unresolved { .. } => None,
        }
    }
}

/// Enum representing the kind of a reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyclass)]
pub enum ReferenceKind {
    /// Function call reference
    Call,
    /// Unconditional jump reference
    Jump,
    /// Conditional branch reference
    Branch,
    /// Return reference
    Return,
    /// Memory read reference
    Read,
    /// Memory write reference
    Write,
    /// Relocation reference
    Reloc,
    /// Data reference
    DataRef,
    /// Tail call reference
    Tail,
}

impl ReferenceKind {
    pub fn as_str(&self) -> &str {
        match self {
            ReferenceKind::Call => "call",
            ReferenceKind::Jump => "jump",
            ReferenceKind::Branch => "branch",
            ReferenceKind::Return => "return",
            ReferenceKind::Read => "read",
            ReferenceKind::Write => "write",
            ReferenceKind::Reloc => "reloc",
            ReferenceKind::DataRef => "data_ref",
            ReferenceKind::Tail => "tail",
        }
    }
}

/// Represents a cross-reference between code or data locations.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyclass)]
pub struct Reference {
    /// Stable identifier for the reference
    pub id: String,
    /// Source address where the reference originates
    pub from: Address,
    /// Target of the reference, either resolved or unresolved
    pub to: ReferenceTarget,
    /// Kind of the reference (e.g., Call, Jump, etc.)
    pub kind: ReferenceKind,
    /// Optional width (in bits) associated with the reference
    pub width: Option<u8>,
    /// Optional confidence (0.0 to 1.0) in the accuracy of the reference
    pub confidence: Option<f32>,
    /// Source or tool identifier that produced this reference
    pub source: String,
}

impl Reference {
    /// Create a new Reference with all parameters
    pub fn new(
        id: String,
        from: Address,
        to: ReferenceTarget,
        kind: ReferenceKind,
        width: Option<u8>,
        confidence: Option<f32>,
        source: String,
    ) -> Self {
        Reference {
            id,
            from,
            to,
            kind,
            width,
            confidence,
            source,
        }
    }

    /// Create a new resolved reference (convenience constructor)
    pub fn new_resolved(
        id: String,
        from: Address,
        to: Address,
        kind: ReferenceKind,
        source: String,
    ) -> Self {
        Reference::new(
            id,
            from,
            ReferenceTarget::Resolved(to),
            kind,
            None,
            None,
            source,
        )
    }

    /// Create a new unresolved reference (convenience constructor)
    pub fn new_unresolved(
        id: String,
        from: Address,
        unresolved_kind: UnresolvedReferenceKind,
        expression: Option<String>,
        ref_kind: ReferenceKind,
        source: String,
    ) -> Self {
        Reference::new(
            id,
            from,
            ReferenceTarget::Unresolved {
                kind: unresolved_kind,
                expression,
            },
            ref_kind,
            None,
            None,
            source,
        )
    }

    /// Check if this reference has a resolved target
    pub fn is_resolved(&self) -> bool {
        self.to.is_resolved()
    }

    /// Check if this reference has an unresolved target
    pub fn is_unresolved(&self) -> bool {
        self.to.is_unresolved()
    }

    /// Get the resolved target address if available
    pub fn resolved_target(&self) -> Option<&Address> {
        self.to.resolved_address()
    }

    /// Validate the reference
    pub fn validate(&self) -> Result<(), GlaurungError> {
        // Validate confidence range
        if let Some(conf) = self.confidence {
            if !(0.0..=1.0).contains(&conf) {
                return Err(GlaurungError::InvalidInput(
                    "Confidence must be between 0.0 and 1.0".to_string(),
                ));
            }
        }

        // Validate width
        if let Some(width) = self.width {
            if width == 0 || width > 128 {
                return Err(GlaurungError::InvalidInput(
                    "Width must be between 1 and 128 bits".to_string(),
                ));
            }
        }

        // Validate ID is not empty
        if self.id.trim().is_empty() {
            return Err(GlaurungError::InvalidInput(
                "Reference ID cannot be empty".to_string(),
            ));
        }

        // Validate source is not empty
        if self.source.trim().is_empty() {
            return Err(GlaurungError::InvalidInput(
                "Reference source cannot be empty".to_string(),
            ));
        }

        Ok(())
    }

    /// Serialize to JSON string
    pub fn to_json_string(&self) -> Result<String, GlaurungError> {
        serde_json::to_string(self).map_err(|e| GlaurungError::Serialization(e.to_string()))
    }

    /// Deserialize from JSON string
    pub fn from_json_string(json_str: &str) -> Result<Self, GlaurungError> {
        serde_json::from_str(json_str).map_err(|e| GlaurungError::Serialization(e.to_string()))
    }

    /// Serialize to binary
    pub fn to_bincode(&self) -> Result<Vec<u8>, GlaurungError> {
        bincode::serialize(self).map_err(|e| GlaurungError::Serialization(e.to_string()))
    }

    /// Deserialize from binary
    pub fn from_bincode(data: &[u8]) -> Result<Self, GlaurungError> {
        bincode::deserialize(data).map_err(|e| GlaurungError::Serialization(e.to_string()))
    }
}

#[cfg(feature = "python-ext")]
#[pymethods]
impl Reference {
    #[new]
    fn new_py(
        id: String,
        from_addr: Address,
        to: ReferenceTarget,
        kind: ReferenceKind,
        source: String,
        width: Option<u8>,
        confidence: Option<f32>,
    ) -> PyResult<Self> {
        let reference = Reference::new(id, from_addr, to, kind, width, confidence, source);
        reference
            .validate()
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
        Ok(reference)
    }

    #[staticmethod]
    fn resolved(
        id: String,
        from_addr: Address,
        to: Address,
        kind: ReferenceKind,
        source: String,
    ) -> Self {
        Reference::new_resolved(id, from_addr, to, kind, source)
    }

    #[staticmethod]
    fn unresolved(
        id: String,
        from_addr: Address,
        unresolved_kind: UnresolvedReferenceKind,
        expression: Option<String>,
        ref_kind: ReferenceKind,
        source: String,
    ) -> Self {
        Reference::new_unresolved(id, from_addr, unresolved_kind, expression, ref_kind, source)
    }

    fn __repr__(&self) -> String {
        format!(
            "Reference(id='{}', from={:#x}, kind={:?}, resolved={}, source='{}')",
            self.id,
            self.from.value,
            self.kind,
            self.is_resolved(),
            self.source
        )
    }

    fn __str__(&self) -> String {
        match &self.to {
            ReferenceTarget::Resolved(addr) => {
                format!(
                    "{}@{:#x} -> {:#x} ({})",
                    self.id,
                    self.from.value,
                    addr.value,
                    self.kind.as_str()
                )
            }
            ReferenceTarget::Unresolved { kind, .. } => {
                format!(
                    "{}@{:#x} -> {} ({})",
                    self.id,
                    self.from.value,
                    kind.as_str(),
                    self.kind.as_str()
                )
            }
        }
    }

    // Getters
    #[getter]
    fn id(&self) -> String {
        self.id.clone()
    }

    #[setter]
    fn set_id(&mut self, value: String) {
        self.id = value;
    }

    #[getter]
    fn from_addr(&self) -> Address {
        self.from.clone()
    }

    #[setter]
    fn set_from_addr(&mut self, value: Address) {
        self.from = value;
    }

    #[getter]
    fn to(&self) -> ReferenceTarget {
        self.to.clone()
    }

    #[setter]
    fn set_to(&mut self, value: ReferenceTarget) {
        self.to = value;
    }

    #[getter]
    fn kind(&self) -> ReferenceKind {
        self.kind
    }

    #[setter]
    fn set_kind(&mut self, value: ReferenceKind) {
        self.kind = value;
    }

    #[getter]
    fn width(&self) -> Option<u8> {
        self.width
    }

    #[setter]
    fn set_width(&mut self, value: Option<u8>) {
        self.width = value;
    }

    #[getter]
    fn confidence(&self) -> Option<f32> {
        self.confidence
    }

    #[setter]
    fn set_confidence(&mut self, value: Option<f32>) {
        self.confidence = value;
    }

    #[getter]
    fn source(&self) -> String {
        self.source.clone()
    }

    #[setter]
    fn set_source(&mut self, value: String) {
        self.source = value;
    }

    fn to_json(&self) -> PyResult<String> {
        self.to_json_string()
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))
    }

    #[staticmethod]
    fn from_json(json_str: &str) -> PyResult<Self> {
        Self::from_json_string(json_str)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))
    }

    fn to_binary(&self) -> PyResult<Vec<u8>> {
        self.to_bincode()
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))
    }

    #[staticmethod]
    fn from_binary(data: Vec<u8>) -> PyResult<Self> {
        Self::from_bincode(&data)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::address::AddressKind;

    #[test]
    fn test_reference_creation() {
        let from_addr = Address::new(AddressKind::VA, 0x401000, 32, None, None).unwrap();
        let to_addr = Address::new(AddressKind::VA, 0x402000, 32, None, None).unwrap();

        let reference = Reference::new_resolved(
            "ref_1".to_string(),
            from_addr.clone(),
            to_addr.clone(),
            ReferenceKind::Call,
            "test_tool".to_string(),
        );

        assert_eq!(reference.id, "ref_1");
        assert_eq!(reference.from, from_addr);
        assert!(reference.is_resolved());
        assert_eq!(reference.resolved_target().unwrap(), &to_addr);
        assert_eq!(reference.kind, ReferenceKind::Call);
        assert_eq!(reference.source, "test_tool");
    }

    #[test]
    fn test_unresolved_reference() {
        let from_addr = Address::new(AddressKind::VA, 0x401000, 32, None, None).unwrap();

        let reference = Reference::new_unresolved(
            "ref_2".to_string(),
            from_addr.clone(),
            UnresolvedReferenceKind::Indirect,
            Some("eax + 8".to_string()),
            ReferenceKind::Read,
            "test_tool".to_string(),
        );

        assert_eq!(reference.id, "ref_2");
        assert_eq!(reference.from, from_addr);
        assert!(reference.is_unresolved());
        assert!(!reference.is_resolved());
        assert_eq!(reference.kind, ReferenceKind::Read);
    }

    #[test]
    fn test_reference_validation() {
        let from_addr = Address::new(AddressKind::VA, 0x401000, 32, None, None).unwrap();
        let to_addr = Address::new(AddressKind::VA, 0x402000, 32, None, None).unwrap();

        // Valid reference
        let reference = Reference::new(
            "ref_1".to_string(),
            from_addr.clone(),
            ReferenceTarget::Resolved(to_addr.clone()),
            ReferenceKind::Call,
            Some(32),
            Some(0.95),
            "test_tool".to_string(),
        );
        assert!(reference.validate().is_ok());

        // Invalid confidence
        let invalid_ref = Reference::new(
            "ref_2".to_string(),
            from_addr.clone(),
            ReferenceTarget::Resolved(to_addr.clone()),
            ReferenceKind::Call,
            None,
            Some(1.5), // Invalid confidence > 1.0
            "test_tool".to_string(),
        );
        assert!(invalid_ref.validate().is_err());

        // Invalid width
        let invalid_ref2 = Reference::new(
            "ref_3".to_string(),
            from_addr,
            ReferenceTarget::Resolved(to_addr.clone()),
            ReferenceKind::Call,
            Some(0), // Invalid width = 0
            None,
            "test_tool".to_string(),
        );
        assert!(invalid_ref2.validate().is_err());
    }

    #[test]
    fn test_json_serialization() {
        let from_addr = Address::new(AddressKind::VA, 0x401000, 32, None, None).unwrap();
        let to_addr = Address::new(AddressKind::VA, 0x402000, 32, None, None).unwrap();

        let reference = Reference::new_resolved(
            "ref_1".to_string(),
            from_addr,
            to_addr,
            ReferenceKind::Call,
            "test_tool".to_string(),
        );

        let json = reference.to_json_string().unwrap();
        let deserialized = Reference::from_json_string(&json).unwrap();

        assert_eq!(reference, deserialized);
    }

    #[test]
    fn test_reference_target_methods() {
        let addr = Address::new(AddressKind::VA, 0x402000, 32, None, None).unwrap();

        let resolved = ReferenceTarget::Resolved(addr.clone());
        assert!(resolved.is_resolved());
        assert!(!resolved.is_unresolved());
        assert_eq!(resolved.resolved_address().unwrap(), &addr);

        let unresolved = ReferenceTarget::Unresolved {
            kind: UnresolvedReferenceKind::Dynamic,
            expression: Some("runtime_resolve".to_string()),
        };
        assert!(!unresolved.is_resolved());
        assert!(unresolved.is_unresolved());
        assert!(unresolved.resolved_address().is_none());
    }
}
