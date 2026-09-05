//! Python bindings for Glaurung binary analysis.
//!
//! This module contains all Python extension bindings, organized by functionality
//! to improve maintainability and reduce the size of lib.rs.

pub mod analysis;
pub mod core_types;
pub mod debug;
pub mod disasm;
#[cfg(feature = "exec")]
pub mod exec;
pub mod flirt;
pub mod identity;
pub mod ir;
pub mod metrics;
pub mod similarity;
pub mod source_cfg;
pub mod source_metrics;
pub mod strings;
pub mod symbols;
pub mod triage;
pub mod unpack;
pub mod winmd;

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
    // Both of these attach to the `analysis` submodule the line above
    // creates, so they must follow it.
    identity::register_identity_bindings(py, m)?;
    flirt::register_flirt_bindings(py, m)?;
    symbols::register_symbols_bindings(py, m)?;
    disasm::register_disasm_bindings(py, m)?;
    similarity::register_similarity_bindings(py, m)?;
    ir::register_ir_bindings(py, m)?;
    debug::register_debug_bindings(py, m)?;
    unpack::register_unpack_bindings(py, m)?;
    winmd::register_winmd_bindings(py, m)?;
    metrics::register_metrics_bindings(py, m)?;
    source_cfg::register_source_cfg_bindings(py, m)?;
    source_metrics::register_source_metrics_bindings(py, m)?;
    #[cfg(feature = "exec")]
    exec::register_exec_bindings(py, m)?;

    Ok(())
}
