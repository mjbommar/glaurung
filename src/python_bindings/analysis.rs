//! Python bindings for analysis functionality.
//!
//! This module contains all Python bindings related to binary analysis,
//! including function discovery, CFG analysis, and entry point detection.

use pyo3::prelude::*;

/// Register analysis-related Python bindings.
pub fn register_analysis_bindings(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Create analysis submodule
    let analysis_mod = pyo3::types::PyModule::new(_py, "analysis")?;

    // Entry detection helpers
    analysis_mod.add_function(wrap_pyfunction!(detect_entry_bytes_py, &analysis_mod)?)?;
    analysis_mod.add_function(wrap_pyfunction!(detect_entry_path_py, &analysis_mod)?)?;

    // Function analysis helpers
    analysis_mod.add_function(wrap_pyfunction!(analyze_functions_bytes_py, &analysis_mod)?)?;
    analysis_mod.add_function(wrap_pyfunction!(analyze_functions_path_py, &analysis_mod)?)?;

    // VA to file offset mapping
    analysis_mod.add_function(wrap_pyfunction!(va_to_file_offset_path_py, &analysis_mod)?)?;

    // ELF-specific helpers
    analysis_mod.add_function(wrap_pyfunction!(elf_plt_map_path_py, &analysis_mod)?)?;
    analysis_mod.add_function(wrap_pyfunction!(elf_got_map_path_py, &analysis_mod)?)?;

    // PE-specific helpers
    analysis_mod.add_function(wrap_pyfunction!(pe_iat_map_path_py, &analysis_mod)?)?;

    // Mach-O-specific helpers
    analysis_mod.add_function(wrap_pyfunction!(macho_stubs_map_path_py, &analysis_mod)?)?;

    // Go pclntab walker for recovering function names from stripped Go binaries.
    analysis_mod.add_function(wrap_pyfunction!(gopclntab_names_path_py, &analysis_mod)?)?;
    // .NET CIL metadata parser for recovering method names from managed PEs.
    analysis_mod.add_function(wrap_pyfunction!(cil_methods_path_py, &analysis_mod)?)?;
    // Java classfile parser for triaging .class files and JAR contents.
    analysis_mod.add_function(wrap_pyfunction!(parse_java_class_path_py, &analysis_mod)?)?;

    // Add analysis submodule to main module
    m.add_submodule(&analysis_mod)?;

    Ok(())
}

/// Detect entry point from binary data.
#[pyfunction]
#[pyo3(name = "detect_entry_bytes")]
fn detect_entry_bytes_py(data: &[u8]) -> Option<(String, String, String, u64, Option<usize>)> {
    if let Some(info) = crate::analysis::entry::detect_entry(data) {
        let fmt = format!("{}", info.format);
        let arch = format!("{}", info.arch);
        let end = format!("{}", info.endianness);
        return Some((fmt, arch, end, info.entry_va, info.file_offset));
    }
    None
}

/// Detect entry point from file path.
#[pyfunction]
#[pyo3(name = "detect_entry_path")]
#[pyo3(signature = (path, max_read_bytes=10_485_760u64, max_file_size=104_857_600u64))]
fn detect_entry_path_py(
    path: String,
    max_read_bytes: u64,
    max_file_size: u64,
) -> PyResult<Option<(String, String, String, u64, Option<usize>)>> {
    let limit = std::cmp::min(max_read_bytes, max_file_size);
    let data = crate::triage::io::IOUtils::read_file_with_limit(&path, limit)
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!("{:?}", e)))?;
    Ok(detect_entry_bytes_py(&data))
}

/// Analyze functions from binary data.
#[pyfunction]
#[pyo3(name = "analyze_functions_bytes")]
#[pyo3(signature = (data, max_functions=16usize, max_blocks=2048usize, max_instructions=50000usize, timeout_ms=100u64))]
fn analyze_functions_bytes_py(
    data: &[u8],
    max_functions: usize,
    max_blocks: usize,
    max_instructions: usize,
    timeout_ms: u64,
) -> (
    Vec<crate::core::function::Function>,
    crate::core::call_graph::CallGraph,
) {
    let budgets = crate::analysis::cfg::Budgets {
        max_functions,
        max_blocks,
        max_instructions,
        timeout_ms,
    };
    crate::analysis::cfg::analyze_functions_bytes(data, &budgets)
}

/// Analyze functions from file path.
#[pyfunction]
#[pyo3(name = "analyze_functions_path")]
#[pyo3(signature = (path, max_read_bytes=10_485_760u64, max_file_size=104_857_600u64, max_functions=16usize, max_blocks=2048usize, max_instructions=50000usize, timeout_ms=100u64))]
fn analyze_functions_path_py(
    path: String,
    max_read_bytes: u64,
    max_file_size: u64,
    max_functions: usize,
    max_blocks: usize,
    max_instructions: usize,
    timeout_ms: u64,
) -> PyResult<(
    Vec<crate::core::function::Function>,
    crate::core::call_graph::CallGraph,
)> {
    let limit = std::cmp::min(max_read_bytes, max_file_size);
    let data = crate::triage::io::IOUtils::read_file_with_limit(&path, limit)
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!("{:?}", e)))?;
    let budgets = crate::analysis::cfg::Budgets {
        max_functions,
        max_blocks,
        max_instructions,
        timeout_ms,
    };
    Ok(crate::analysis::cfg::analyze_functions_bytes(
        &data, &budgets,
    ))
}

/// Map VA to file offset for a given file.
#[pyfunction]
#[pyo3(name = "va_to_file_offset_path")]
#[pyo3(signature = (path, va, max_read_bytes=10_485_760u64, max_file_size=104_857_600u64))]
fn va_to_file_offset_path_py(
    path: String,
    va: u64,
    max_read_bytes: u64,
    max_file_size: u64,
) -> PyResult<Option<usize>> {
    let limit = std::cmp::min(max_read_bytes, max_file_size);
    let data = crate::triage::io::IOUtils::read_file_with_limit(&path, limit)
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!("{:?}", e)))?;
    Ok(crate::analysis::entry::va_to_file_offset(&data, va))
}

/// Get ELF PLT map for a file.
#[pyfunction]
#[pyo3(name = "elf_plt_map_path")]
#[pyo3(signature = (path, max_read_bytes=10_485_760u64, max_file_size=104_857_600u64))]
fn elf_plt_map_path_py(
    path: String,
    max_read_bytes: u64,
    max_file_size: u64,
) -> PyResult<Vec<(u64, String)>> {
    let limit = std::cmp::min(max_read_bytes, max_file_size);
    let data = crate::triage::io::IOUtils::read_file_with_limit(&path, limit)
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!("{:?}", e)))?;
    Ok(crate::analysis::elf_plt::elf_plt_map(&data))
}

/// Get ELF GOT map for a file.
#[pyfunction]
#[pyo3(name = "elf_got_map_path")]
#[pyo3(signature = (path, max_read_bytes=10_485_760u64, max_file_size=104_857_600u64))]
fn elf_got_map_path_py(
    path: String,
    max_read_bytes: u64,
    max_file_size: u64,
) -> PyResult<Vec<(u64, String)>> {
    let limit = std::cmp::min(max_read_bytes, max_file_size);
    let data = crate::triage::io::IOUtils::read_file_with_limit(&path, limit)
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!("{:?}", e)))?;
    Ok(crate::analysis::elf_got::elf_got_map(&data))
}

/// Get PE IAT map for a file.
#[pyfunction]
#[pyo3(name = "pe_iat_map_path")]
#[pyo3(signature = (path, max_read_bytes=10_485_760u64, max_file_size=104_857_600u64))]
fn pe_iat_map_path_py(
    path: String,
    max_read_bytes: u64,
    max_file_size: u64,
) -> PyResult<Vec<(u64, String)>> {
    let limit = std::cmp::min(max_read_bytes, max_file_size);
    let data = crate::triage::io::IOUtils::read_file_with_limit(&path, limit)
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!("{:?}", e)))?;
    Ok(crate::analysis::pe_iat::pe_iat_map(&data))
}

/// Get Mach-O stubs/lazy-pointer/non-lazy-pointer map for a file.
#[pyfunction]
#[pyo3(name = "macho_stubs_map_path")]
#[pyo3(signature = (path, max_read_bytes=10_485_760u64, max_file_size=104_857_600u64))]
fn macho_stubs_map_path_py(
    path: String,
    max_read_bytes: u64,
    max_file_size: u64,
) -> PyResult<Vec<(u64, String)>> {
    let limit = std::cmp::min(max_read_bytes, max_file_size);
    let data = crate::triage::io::IOUtils::read_file_with_limit(&path, limit)
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!("{:?}", e)))?;
    Ok(crate::analysis::macho_stubs::macho_stubs_map(&data))
}

/// Parse a Java `.class` file and return a structured dict with the
/// class name, super class, interfaces, methods, and fields.
/// Returns None for files that don't have the 0xCAFEBABE magic.
#[pyfunction]
#[pyo3(name = "parse_java_class_path")]
#[pyo3(signature = (path, max_read_bytes=10_485_760u64, max_file_size=104_857_600u64))]
fn parse_java_class_path_py(
    py: Python<'_>,
    path: String,
    max_read_bytes: u64,
    max_file_size: u64,
) -> PyResult<Option<PyObject>> {
    let limit = std::cmp::min(max_read_bytes, max_file_size);
    let data = crate::triage::io::IOUtils::read_file_with_limit(&path, limit)
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!("{:?}", e)))?;
    match crate::analysis::java_class::parse_class(&data) {
        Ok(info) => {
            let dict = pyo3::types::PyDict::new(py);
            dict.set_item("class_name", info.class_name)?;
            dict.set_item("super_class", info.super_class)?;
            dict.set_item("interfaces", info.interfaces)?;
            dict.set_item("major_version", info.major_version)?;
            dict.set_item("minor_version", info.minor_version)?;
            dict.set_item("access_flags", info.access_flags)?;
            let methods = pyo3::types::PyList::empty(py);
            for m in info.methods {
                let mdict = pyo3::types::PyDict::new(py);
                mdict.set_item("name", m.name)?;
                mdict.set_item("descriptor", m.descriptor)?;
                mdict.set_item("access_flags", m.access_flags)?;
                methods.append(mdict)?;
            }
            dict.set_item("methods", methods)?;
            let fields = pyo3::types::PyList::empty(py);
            for f in info.fields {
                let fdict = pyo3::types::PyDict::new(py);
                fdict.set_item("name", f.name)?;
                fdict.set_item("descriptor", f.descriptor)?;
                fdict.set_item("access_flags", f.access_flags)?;
                fields.append(fdict)?;
            }
            dict.set_item("fields", fields)?;
            Ok(Some(dict.into()))
        }
        Err(crate::analysis::java_class::ClassError::BadMagic(_)) => Ok(None),
        Err(e) => Err(pyo3::exceptions::PyRuntimeError::new_err(format!(
            "java class parse failed: {:?}", e,
        ))),
    }
}

/// Walk a .NET PE assembly's CIL metadata and return every method's
/// `(rva, full_name)` pair. Returns an empty list for non-.NET PEs
/// so callers can silently fall through.
#[pyfunction]
#[pyo3(name = "cil_methods_path")]
#[pyo3(signature = (path, max_read_bytes=104_857_600u64, max_file_size=104_857_600u64))]
fn cil_methods_path_py(
    path: String,
    max_read_bytes: u64,
    max_file_size: u64,
) -> PyResult<Vec<(u32, String)>> {
    let limit = std::cmp::min(max_read_bytes, max_file_size);
    let data = crate::triage::io::IOUtils::read_file_with_limit(&path, limit)
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!("{:?}", e)))?;
    match crate::analysis::cil_metadata::extract_cil_methods(&data) {
        Ok(methods) => Ok(methods.into_iter().map(|m| (m.rva, m.name)).collect()),
        Err(crate::analysis::cil_metadata::CilError::NoCom) => Ok(Vec::new()),
        Err(e) => Err(pyo3::exceptions::PyRuntimeError::new_err(format!(
            "cil parse failed: {:?}", e,
        ))),
    }
}

/// Walk a Go binary's `.gopclntab` and return every recovered
/// `(entry_va, name)` pair. Returns an empty list if the section is
/// missing (i.e. not a Go binary) or if the format is unsupported.
/// Errors only on truly malformed sections.
#[pyfunction]
#[pyo3(name = "gopclntab_names_path")]
#[pyo3(signature = (path, max_read_bytes=104_857_600u64, max_file_size=104_857_600u64))]
fn gopclntab_names_path_py(
    path: String,
    max_read_bytes: u64,
    max_file_size: u64,
) -> PyResult<Vec<(u64, String)>> {
    let limit = std::cmp::min(max_read_bytes, max_file_size);
    let data = crate::triage::io::IOUtils::read_file_with_limit(&path, limit)
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!("{:?}", e)))?;
    match crate::analysis::gopclntab::extract_go_functions(&data) {
        Ok(funcs) => Ok(funcs.into_iter().map(|f| (f.entry_va, f.name)).collect()),
        // Non-Go or unsupported magic = empty result. Truncation is a real
        // error worth surfacing.
        Err(crate::analysis::gopclntab::GoPclnError::NoSection) => Ok(Vec::new()),
        Err(crate::analysis::gopclntab::GoPclnError::UnknownMagic(_)) => Ok(Vec::new()),
        Err(e) => Err(pyo3::exceptions::PyRuntimeError::new_err(format!(
            "gopclntab parse failed: {:?}", e,
        ))),
    }
}
