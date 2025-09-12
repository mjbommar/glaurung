//! Python bindings for Glaurung binary analysis.
//!
//! This module contains all Python extension bindings, organized by functionality
//! to improve maintainability and reduce the size of lib.rs.

pub mod analysis;
pub mod core_types;
pub mod disasm;
pub mod similarity;
pub mod strings;
pub mod symbols;
pub mod triage;

use pyo3::prelude::*;

/// Register all Python bindings with the module.
///
/// This function replaces the large inline binding code that was previously
/// in lib.rs, making the codebase more maintainable.
pub fn register_python_bindings(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Register core types first (fundamental types)
    core_types::register_core_types(py, m)?;

    // Register functional modules
    triage::register_triage_bindings(py, m)?;
    strings::register_strings_bindings(py, m)?;
    analysis::register_analysis_bindings(py, m)?;
    symbols::register_symbols_bindings(py, m)?;
    disasm::register_disasm_bindings(py, m)?;
    similarity::register_similarity_bindings(py, m)?;

    Ok(())
}
