//! Error types for triage operations.

#[cfg(feature = "python-ext")]
use pyo3::prelude::*;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Standardized error kinds encountered during triage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[cfg_attr(feature = "python-ext", pyclass(eq, eq_int))]
pub enum TriageErrorKind {
    ShortRead,
    BadMagic,
    IncoherentFields,
    UnsupportedVariant,
    Truncated,
    BudgetExceeded,
    ParserMismatch,
    SnifferMismatch,
    Other,
}

#[cfg(feature = "python-ext")]
#[pymethods]
impl TriageErrorKind {
    fn __str__(&self) -> String {
        use TriageErrorKind::*;
        match self {
            ShortRead => "ShortRead",
            BadMagic => "BadMagic",
            IncoherentFields => "IncoherentFields",
            UnsupportedVariant => "UnsupportedVariant",
            Truncated => "Truncated",
            BudgetExceeded => "BudgetExceeded",
            ParserMismatch => "ParserMismatch",
            SnifferMismatch => "SnifferMismatch",
            Other => "Other",
        }
        .to_string()
    }
    fn __repr__(&self) -> String {
        format!("TriageErrorKind.{}", self.__str__())
    }
}

/// Concrete error with optional message.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyclass)]
pub struct TriageError {
    pub kind: TriageErrorKind,
    pub message: Option<String>,
}

#[cfg(feature = "python-ext")]
#[pymethods]
impl TriageError {
    #[new]
    #[pyo3(signature = (kind, message=None))]
    pub fn new_py(kind: TriageErrorKind, message: Option<String>) -> Self {
        Self { kind, message }
    }
    #[staticmethod]
    pub fn create(kind: TriageErrorKind, message: Option<String>) -> Self {
        Self { kind, message }
    }
    fn __repr__(&self) -> String {
        format!(
            "TriageError(kind={:?}, message={:?})",
            self.kind, self.message
        )
    }
    #[getter]
    fn kind(&self) -> TriageErrorKind {
        self.kind
    }
    #[getter]
    fn message(&self) -> Option<String> {
        self.message.clone()
    }
}

impl fmt::Display for TriageErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use TriageErrorKind::*;
        match self {
            ShortRead => write!(f, "ShortRead"),
            BadMagic => write!(f, "BadMagic"),
            IncoherentFields => write!(f, "IncoherentFields"),
            UnsupportedVariant => write!(f, "UnsupportedVariant"),
            Truncated => write!(f, "Truncated"),
            BudgetExceeded => write!(f, "BudgetExceeded"),
            ParserMismatch => write!(f, "ParserMismatch"),
            SnifferMismatch => write!(f, "SnifferMismatch"),
            Other => write!(f, "Other"),
        }
    }
}

// Pure Rust constructors and helpers
impl TriageError {
    pub fn new(kind: TriageErrorKind, message: Option<String>) -> Self {
        Self { kind, message }
    }
}
