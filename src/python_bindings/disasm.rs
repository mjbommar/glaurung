//! Python bindings for disassembly functionality.
//!
//! This module contains all Python bindings related to disassembly,
//! instruction decoding, and architecture-specific operations.

use pyo3::prelude::*;

/// Register disassembly-related Python bindings.
pub fn register_disasm_bindings(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Create disasm submodule
    let disasm_mod = pyo3::types::PyModule::new(_py, "disasm")?;

    // Register disassembly functions
    disasm_mod.add_function(wrap_pyfunction!(
        crate::disasm::py_api::disassembler_for_path_py,
        &disasm_mod
    )?)?;
    disasm_mod.add_function(wrap_pyfunction!(
        crate::disasm::py_api::disassemble_window_py,
        &disasm_mod
    )?)?;
    disasm_mod.add_function(wrap_pyfunction!(
        crate::disasm::py_api::disassemble_window_at_py,
        &disasm_mod
    )?)?;

    // Register the PyDisassembler class
    disasm_mod.add_class::<crate::disasm::py_api::PyDisassembler>()?;

    // Add disasm submodule to main module
    m.add_submodule(&disasm_mod)?;

    Ok(())
}
