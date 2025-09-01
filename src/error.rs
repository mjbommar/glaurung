//! Error types for the Glaurung binary analysis framework.
//!
//! This module provides comprehensive error handling using thiserror for
//! structured error types that can be properly converted for Python bindings.

use std::fmt;
use thiserror::Error;

/// Main error type for Glaurung operations.
#[derive(Debug, Error)]
pub enum GlaurungError {
    /// Binary format parsing errors
    #[error("Invalid binary format: {0}")]
    InvalidFormat(String),

    /// Parse error with location information
    #[error("Parse error at offset {offset:#x}: {message}")]
    ParseError { offset: u64, message: String },

    /// Analysis timeout
    #[error("Analysis timeout after {seconds}s")]
    Timeout { seconds: u64 },

    /// Resource limit exceeded
    #[error("Resource limit exceeded: {resource} ({used}/{limit})")]
    ResourceExhausted {
        resource: String,
        used: usize,
        limit: usize,
    },

    /// Invalid input data
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// Architecture not supported
    #[error("Unsupported architecture: {0}")]
    UnsupportedArchitecture(String),

    /// File I/O errors
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Serialization/deserialization errors
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Address calculation errors
    #[error("Address error: {0}")]
    AddressError(String),

    /// Symbol resolution errors
    #[error("Symbol not found: {0}")]
    SymbolNotFound(String),

    /// Pattern matching errors
    #[error("Pattern error: {0}")]
    PatternError(String),

    /// Triage pipeline errors
    #[error("Triage error: {0}")]
    TriageError(String),

    /// Generic internal error
    #[error("Internal error: {0}")]
    Internal(String),
}

/// Result type alias for Glaurung operations
pub type Result<T> = std::result::Result<T, GlaurungError>;

/// Convert Glaurung errors to PyO3 exceptions
#[cfg(feature = "python-ext")]
impl From<GlaurungError> for pyo3::PyErr {
    fn from(err: GlaurungError) -> pyo3::PyErr {
        use pyo3::exceptions::{PyException, PyIOError, PyTimeoutError, PyValueError};

        match err {
            GlaurungError::Io(e) => PyIOError::new_err(e.to_string()),
            GlaurungError::Timeout { seconds } => {
                PyTimeoutError::new_err(format!("Operation timed out after {}s", seconds))
            }
            GlaurungError::InvalidInput(msg) | GlaurungError::InvalidFormat(msg) => {
                PyValueError::new_err(msg)
            }
            _ => PyException::new_err(err.to_string()),
        }
    }
}

/// Analysis budget tracking to prevent resource exhaustion
#[derive(Debug, Clone)]
pub struct AnalysisBudget {
    /// Maximum memory in megabytes
    pub max_memory_mb: usize,
    /// Maximum time in seconds
    pub max_time_seconds: u64,
    /// Maximum recursion depth
    pub max_recursion_depth: usize,
    /// Maximum number of instructions to analyze
    pub max_instructions: usize,
}

impl Default for AnalysisBudget {
    fn default() -> Self {
        Self {
            max_memory_mb: 1024,         // 1GB default
            max_time_seconds: 300,       // 5 minutes default
            max_recursion_depth: 100,    // Reasonable recursion limit
            max_instructions: 1_000_000, // 1M instructions max
        }
    }
}

impl fmt::Display for AnalysisBudget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Budget: {}MB memory, {}s time, {} recursion, {} instructions",
            self.max_memory_mb,
            self.max_time_seconds,
            self.max_recursion_depth,
            self.max_instructions
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = GlaurungError::InvalidFormat("Unknown magic bytes".to_string());
        assert_eq!(
            err.to_string(),
            "Invalid binary format: Unknown magic bytes"
        );

        let err = GlaurungError::ParseError {
            offset: 0x1234,
            message: "Invalid header".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "Parse error at offset 0x1234: Invalid header"
        );
    }

    #[test]
    fn test_default_budget() {
        let budget = AnalysisBudget::default();
        assert_eq!(budget.max_memory_mb, 1024);
        assert_eq!(budget.max_time_seconds, 300);
        assert_eq!(budget.max_recursion_depth, 100);
        assert_eq!(budget.max_instructions, 1_000_000);
    }

    #[test]
    fn test_budget_display() {
        let budget = AnalysisBudget::default();
        let display = budget.to_string();
        assert!(display.contains("1024MB memory"));
        assert!(display.contains("300s time"));
    }
}
