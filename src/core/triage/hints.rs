//! Triage hints and confidence signal types.

#[cfg(feature = "python-ext")]
use pyo3::prelude::*;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Source of a sniffer hint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyclass(eq, eq_int))]
pub enum SnifferSource {
    Infer,
    MimeGuess,
    Other,
}

#[cfg(feature = "python-ext")]
#[pymethods]
impl SnifferSource {
    fn __str__(&self) -> String {
        match self {
            SnifferSource::Infer => "Infer".to_string(),
            SnifferSource::MimeGuess => "MimeGuess".to_string(),
            SnifferSource::Other => "Other".to_string(),
        }
    }

    fn __repr__(&self) -> String {
        format!("SnifferSource.{}", self.__str__())
    }
}

/// A single sniffer hint derived from content or extension.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyclass)]
pub struct TriageHint {
    pub source: SnifferSource,
    /// MIME type if available (e.g., from `infer`)
    pub mime: Option<String>,
    /// File extension hint if available (e.g., from `mime_guess` or path)
    pub extension: Option<String>,
    /// A coarse label/class (e.g., "zip", "pe", "image/jpeg")
    pub label: Option<String>,
}

#[cfg(feature = "python-ext")]
#[pymethods]
impl TriageHint {
    #[new]
    #[pyo3(signature = (source, mime=None, extension=None, label=None))]
    pub fn new_py(
        source: SnifferSource,
        mime: Option<String>,
        extension: Option<String>,
        label: Option<String>,
    ) -> Self {
        Self {
            source,
            mime,
            extension,
            label,
        }
    }

    #[staticmethod]
    pub fn create(
        source: SnifferSource,
        mime: Option<String>,
        extension: Option<String>,
        label: Option<String>,
    ) -> Self {
        Self {
            source,
            mime,
            extension,
            label,
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "TriageHint(source={:?}, mime={:?}, ext={:?}, label={:?})",
            self.source, self.mime, self.extension, self.label
        )
    }

    // Property getters
    #[getter]
    fn source(&self) -> SnifferSource {
        self.source
    }
    #[getter]
    fn mime(&self) -> Option<String> {
        self.mime.clone()
    }
    #[getter]
    fn extension(&self) -> Option<String> {
        self.extension.clone()
    }
    #[getter]
    fn label(&self) -> Option<String> {
        self.label.clone()
    }
}

/// A single confidence signal contribution.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyclass)]
pub struct ConfidenceSignal {
    /// Human-readable name of the signal, e.g. "header_coherence".
    pub name: String,
    /// Score contribution in [-1.0, 1.0].
    pub score: f32,
    /// Optional note or rationale.
    pub notes: Option<String>,
}

#[cfg(feature = "python-ext")]
#[pymethods]
impl ConfidenceSignal {
    #[staticmethod]
    pub fn create(name: String, score: f32, notes: Option<String>) -> Self {
        Self { name, score, notes }
    }
}

impl fmt::Display for SnifferSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SnifferSource::Infer => write!(f, "Infer"),
            SnifferSource::MimeGuess => write!(f, "MimeGuess"),
            SnifferSource::Other => write!(f, "Other"),
        }
    }
}

// Pure Rust constructors and helpers
impl TriageHint {
    pub fn new(
        source: SnifferSource,
        mime: Option<String>,
        extension: Option<String>,
        label: Option<String>,
    ) -> Self {
        Self {
            source,
            mime,
            extension,
            label,
        }
    }
}

impl ConfidenceSignal {
    pub fn new(name: String, score: f32, notes: Option<String>) -> Self {
        Self { name, score, notes }
    }
}
