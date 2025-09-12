//! Python bindings for symbol analysis functionality.
//!
//! This module contains all Python bindings related to symbol extraction,
//! analysis, and manipulation.

use pyo3::prelude::*;

/// Register symbol-related Python bindings.
pub fn register_symbols_bindings(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Create symbols submodule
    let sym_mod = pyo3::types::PyModule::new(_py, "symbols")?;

    // Register symbol functions
    sym_mod.add_function(wrap_pyfunction!(list_symbols_py, &sym_mod)?)?;
    sym_mod.add_function(wrap_pyfunction!(list_symbols_demangled_py, &sym_mod)?)?;
    sym_mod.add_function(wrap_pyfunction!(imphash_py, &sym_mod)?)?;
    sym_mod.add_function(wrap_pyfunction!(analyze_exports_py, &sym_mod)?)?;
    sym_mod.add_function(wrap_pyfunction!(analyze_env_py, &sym_mod)?)?;

    // Suspicious import utilities
    sym_mod.add_function(wrap_pyfunction!(detect_suspicious_imports_py, &sym_mod)?)?;
    sym_mod.add_function(wrap_pyfunction!(set_suspicious_imports_py, &sym_mod)?)?;
    sym_mod.add_function(wrap_pyfunction!(load_capa_apis_py, &sym_mod)?)?;

    // Add symbols submodule to main module
    m.add_submodule(&sym_mod)?;

    Ok(())
}

/// List symbols from a file.
#[pyfunction]
#[pyo3(name = "list_symbols")]
#[pyo3(signature = (path, max_read_bytes=10_485_760, max_file_size=104_857_600))]
fn list_symbols_py(
    path: String,
    max_read_bytes: u64,
    max_file_size: u64,
) -> PyResult<crate::symbols::SymbolSummary> {
    let limit = std::cmp::min(max_read_bytes, max_file_size);
    let _data = crate::triage::io::IOUtils::read_file_with_limit(&path, limit)
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!("{:?}", e)))?;

    // Call the actual function and convert tuple to SymbolSummary
    let (_all_syms, _dyn_syms, imports, exports, libs) =
        crate::symbols::list_symbols_py(path, max_read_bytes, max_file_size)?;

    Ok(crate::symbols::SymbolSummary {
        imports_count: imports.len() as u32,
        exports_count: exports.len() as u32,
        libs_count: libs.len() as u32,
        import_names: Some(imports),
        export_names: Some(exports),
        demangled_import_names: None,
        demangled_export_names: None,
        stripped: false, // TODO: detect this
        tls_used: false, // TODO: detect this
        tls_callback_count: None,
        tls_callback_vas: None,
        debug_info_present: false, // TODO: detect this
        pdb_path: None,
        suspicious_imports: None,
        entry_section: None,
        nx: None,
        aslr: None,
        relro: None,
        pie: None,
        cfg: None,
        relocations_present: None,
        rpaths: None,
        runpaths: None,
    })
}

/// List symbols with demangling from a file.
#[pyfunction]
#[pyo3(name = "list_symbols_demangled")]
#[pyo3(signature = (path, max_read_bytes=10_485_760, max_file_size=104_857_600))]
fn list_symbols_demangled_py(
    path: String,
    max_read_bytes: u64,
    max_file_size: u64,
) -> PyResult<crate::symbols::SymbolSummary> {
    let limit = std::cmp::min(max_read_bytes, max_file_size);
    let _data = crate::triage::io::IOUtils::read_file_with_limit(&path, limit)
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!("{:?}", e)))?;

    // Call the actual function and convert tuple to SymbolSummary
    let (all_syms, dyn_syms, imports, exports, libs) =
        crate::symbols::list_symbols_demangled_py(path, max_read_bytes, max_file_size)?;

    Ok(crate::symbols::SymbolSummary {
        imports_count: imports.len() as u32,
        exports_count: exports.len() as u32,
        libs_count: libs.len() as u32,
        import_names: Some(imports),
        export_names: Some(exports),
        demangled_import_names: Some(all_syms), // Use demangled versions
        demangled_export_names: Some(dyn_syms), // Use demangled versions
        stripped: false,                        // TODO: detect this
        tls_used: false,                        // TODO: detect this
        tls_callback_count: None,
        tls_callback_vas: None,
        debug_info_present: false, // TODO: detect this
        pdb_path: None,
        suspicious_imports: None,
        entry_section: None,
        nx: None,
        aslr: None,
        relro: None,
        pie: None,
        cfg: None,
        relocations_present: None,
        rpaths: None,
        runpaths: None,
    })
}

/// Calculate imphash from a file.
#[pyfunction]
#[pyo3(name = "imphash")]
#[pyo3(signature = (path, max_read_bytes=10_485_760, max_file_size=104_857_600))]
fn imphash_py(path: String, max_read_bytes: u64, max_file_size: u64) -> PyResult<Option<String>> {
    let limit = std::cmp::min(max_read_bytes, max_file_size);
    let data = crate::triage::io::IOUtils::read_file_with_limit(&path, limit)
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!("{:?}", e)))?;
    Ok(crate::symbols::analysis::imphash::pe_imphash(&data))
}

/// Analyze PE exports from a file.
#[pyfunction]
#[pyo3(name = "analyze_exports")]
#[pyo3(signature = (path, max_read_bytes=10_485_760, max_file_size=104_857_600))]
fn analyze_exports_py(
    path: String,
    max_read_bytes: u64,
    max_file_size: u64,
) -> PyResult<Option<(u32, u32, u32)>> {
    let limit = std::cmp::min(max_read_bytes, max_file_size);
    let data = crate::triage::io::IOUtils::read_file_with_limit(&path, limit)
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!("{:?}", e)))?;
    if let Some(ec) = crate::symbols::analysis::export::analyze_pe_exports(&data) {
        Ok(Some((ec.direct, ec.forwarded, ec.ordinal_only)))
    } else {
        Ok(None)
    }
}

/// Analyze binary environment from a file.
#[pyfunction]
#[pyo3(name = "analyze_env")]
#[pyo3(signature = (path, max_read_bytes=10_485_760, max_file_size=104_857_600))]
fn analyze_env_py(
    py: Python<'_>,
    path: String,
    max_read_bytes: u64,
    max_file_size: u64,
) -> PyResult<Py<PyAny>> {
    let limit = std::cmp::min(max_read_bytes, max_file_size);
    let data = crate::triage::io::IOUtils::read_file_with_limit(&path, limit)
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!("{:?}", e)))?;

    let env = crate::symbols::analysis::env::analyze_env(&data).ok_or_else(|| {
        pyo3::exceptions::PyValueError::new_err("Failed to analyze binary environment")
    })?;

    let dict = pyo3::types::PyDict::new(py);

    // Common fields
    dict.set_item("libs", env.libs)?;

    // Optional fields
    if let Some(rpaths) = env.rpaths {
        dict.set_item("rpaths", rpaths)?;
    }
    if let Some(runpaths) = env.runpaths {
        dict.set_item("runpaths", runpaths)?;
    }
    if let Some(pdb_path) = env.pdb_path {
        dict.set_item("pdb_path", pdb_path)?;
    }
    if let Some(tls_callbacks) = env.tls_callbacks {
        dict.set_item("tls_callbacks", tls_callbacks)?;
    }
    if let Some(entry_section) = env.entry_section {
        dict.set_item("entry_section", entry_section)?;
    }
    if let Some(relocations_present) = env.relocations_present {
        dict.set_item("relocations_present", relocations_present)?;
    }
    if let Some(minos) = env.minos {
        dict.set_item("minos", minos)?;
    }
    if let Some(code_signature) = env.code_signature {
        dict.set_item("code_signature", code_signature)?;
    }

    Ok(dict.into_any().unbind())
}

/// Detect suspicious imports from a list of names.
#[pyfunction]
#[pyo3(name = "detect_suspicious_imports")]
#[pyo3(signature = (names, max_out=128))]
fn detect_suspicious_imports_py(names: Vec<String>, max_out: usize) -> Vec<String> {
    crate::symbols::analysis::suspicious::detect_suspicious_imports(&names, max_out)
}

/// Set suspicious imports list.
#[pyfunction]
#[pyo3(name = "set_suspicious_imports")]
#[pyo3(signature = (names, clear=true))]
fn set_suspicious_imports_py(names: Vec<String>, clear: bool) -> usize {
    crate::symbols::analysis::suspicious::set_extra_apis(names.into_iter(), clear)
}

/// Load CAPA APIs from a file.
#[pyfunction]
#[pyo3(name = "load_capa_apis")]
#[pyo3(signature = (path, clear=false, limit=5000))]
fn load_capa_apis_py(path: String, clear: bool, limit: usize) -> PyResult<usize> {
    let p = std::path::Path::new(&path);
    crate::symbols::analysis::suspicious::load_capa_apis_from_path(p, limit, clear)
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!("{e}")))
}
