//! Parser-related types for triage operations.

use super::errors::TriageError;
#[cfg(feature = "python-ext")]
use pyo3::prelude::*;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Which structured parser produced a result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyclass(eq, eq_int))]
pub enum ParserKind {
    Object,
    Goblin,
    PELite,
    Nom,
}

#[cfg(feature = "python-ext")]
#[pymethods]
impl ParserKind {
    fn __str__(&self) -> String {
        match self {
            ParserKind::Object => "Object",
            ParserKind::Goblin => "Goblin",
            ParserKind::PELite => "PELite",
            ParserKind::Nom => "Nom",
        }
        .to_string()
    }
    fn __repr__(&self) -> String {
        format!("ParserKind.{}", self.__str__())
    }
}

/// Result of attempting to parse with a specific parser.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyclass)]
pub struct ParserResult {
    pub parser: ParserKind,
    pub ok: bool,
    pub error: Option<TriageError>,
}

#[cfg(feature = "python-ext")]
#[pymethods]
impl ParserResult {
    #[new]
    pub fn new_py(parser: ParserKind, ok: bool, error: Option<TriageError>) -> Self {
        Self { parser, ok, error }
    }
}

impl fmt::Display for ParserKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParserKind::Object => write!(f, "Object"),
            ParserKind::Goblin => write!(f, "Goblin"),
            ParserKind::PELite => write!(f, "PELite"),
            ParserKind::Nom => write!(f, "Nom"),
        }
    }
}

// Pure Rust constructors and helpers
impl ParserResult {
    pub fn new(parser: ParserKind, ok: bool, error: Option<TriageError>) -> Self {
        Self { parser, ok, error }
    }
}
