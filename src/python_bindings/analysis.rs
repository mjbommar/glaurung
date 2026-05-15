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
    analysis_mod.add_function(wrap_pyfunction!(parse_java_class_bytes_py, &analysis_mod)?)?;
    analysis_mod.add_function(wrap_pyfunction!(index_java_archive_path_py, &analysis_mod)?)?;
    analysis_mod.add_function(wrap_pyfunction!(
        index_java_archive_bytes_py,
        &analysis_mod
    )?)?;
    // Lua bytecode recognizer / source-name extractor.
    analysis_mod.add_function(wrap_pyfunction!(parse_lua_bytecode_path_py, &analysis_mod)?)?;

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

/// Parse a Lua bytecode file (.luac or LuaJIT) and return a
/// structured dict with version, format, source filename (if
/// present), and engine kind. Returns None for non-Lua files.
#[pyfunction]
#[pyo3(name = "parse_lua_bytecode_path")]
#[pyo3(signature = (path, max_read_bytes=10_485_760u64, max_file_size=104_857_600u64))]
fn parse_lua_bytecode_path_py(
    py: Python<'_>,
    path: String,
    max_read_bytes: u64,
    max_file_size: u64,
) -> PyResult<Option<Py<PyAny>>> {
    let limit = std::cmp::min(max_read_bytes, max_file_size);
    let data = crate::triage::io::IOUtils::read_file_with_limit(&path, limit)
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!("{:?}", e)))?;
    use crate::analysis::lua_bytecode::{parse_lua, LuaError, LuaKind};
    match parse_lua(&data) {
        Ok(info) => {
            let dict = pyo3::types::PyDict::new(py);
            let kind_str = match info.kind {
                LuaKind::Lua51 => "Lua 5.1",
                LuaKind::Lua52 => "Lua 5.2",
                LuaKind::Lua53 => "Lua 5.3",
                LuaKind::Lua54 => "Lua 5.4",
                LuaKind::LuaJit => "LuaJIT",
                LuaKind::Unknown(_) => "unknown",
            };
            dict.set_item("kind", kind_str)?;
            dict.set_item("format", info.format)?;
            dict.set_item("source", info.source)?;
            dict.set_item("little_endian", info.little_endian)?;
            Ok(Some(dict.into()))
        }
        Err(LuaError::BadMagic) => Ok(None),
        Err(e) => Err(pyo3::exceptions::PyRuntimeError::new_err(format!(
            "lua parse failed: {:?}",
            e,
        ))),
    }
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
) -> PyResult<Option<Py<PyAny>>> {
    let limit = std::cmp::min(max_read_bytes, max_file_size);
    let data = crate::triage::io::IOUtils::read_file_with_limit(&path, limit)
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!("{:?}", e)))?;
    parse_java_class_bytes_inner(py, &data)
}

/// Parse Java `.class` bytes and return a structured dict with the
/// class name, super class, interfaces, methods, and fields.
/// Returns None for data that doesn't have the 0xCAFEBABE magic.
#[pyfunction]
#[pyo3(name = "parse_java_class_bytes")]
fn parse_java_class_bytes_py(py: Python<'_>, data: &[u8]) -> PyResult<Option<Py<PyAny>>> {
    parse_java_class_bytes_inner(py, data)
}

fn parse_java_class_bytes_inner(py: Python<'_>, data: &[u8]) -> PyResult<Option<Py<PyAny>>> {
    match crate::analysis::java_class::parse_class(data) {
        Ok(info) => java_class_info_to_py(py, info).map(Some),
        Err(crate::analysis::java_class::ClassError::BadMagic(_)) => Ok(None),
        Err(e) => Err(pyo3::exceptions::PyRuntimeError::new_err(format!(
            "java class parse failed: {:?}",
            e,
        ))),
    }
}

fn java_class_info_to_py(
    py: Python<'_>,
    info: crate::analysis::java_class::ClassInfo,
) -> PyResult<Py<PyAny>> {
    let dict = pyo3::types::PyDict::new(py);
    dict.set_item("class_name", info.class_name)?;
    dict.set_item("super_class", info.super_class)?;
    dict.set_item("source_file", info.source_file)?;
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
        mdict.set_item("exceptions", m.exceptions)?;
        mdict.set_item("code", java_code_to_py(py, m.code)?)?;
        methods.append(mdict)?;
    }
    dict.set_item("methods", methods)?;
    let fields = pyo3::types::PyList::empty(py);
    for f in info.fields {
        let fdict = pyo3::types::PyDict::new(py);
        fdict.set_item("name", f.name)?;
        fdict.set_item("descriptor", f.descriptor)?;
        fdict.set_item("access_flags", f.access_flags)?;
        fdict.set_item("exceptions", f.exceptions)?;
        fdict.set_item("code", java_code_to_py(py, f.code)?)?;
        fields.append(fdict)?;
    }
    dict.set_item("fields", fields)?;
    Ok(dict.into())
}

fn java_code_to_py(
    py: Python<'_>,
    code: Option<crate::analysis::java_class::JavaCode>,
) -> PyResult<Py<PyAny>> {
    let Some(code) = code else {
        return Ok(py.None());
    };
    let dict = pyo3::types::PyDict::new(py);
    dict.set_item("max_stack", code.max_stack)?;
    dict.set_item("max_locals", code.max_locals)?;
    dict.set_item("code_length", code.code_length)?;
    dict.set_item("exception_table_len", code.exception_table_len)?;
    dict.set_item("attributes_count", code.attributes_count)?;
    let line_numbers = pyo3::types::PyList::empty(py);
    for line in code.line_numbers {
        let ldict = pyo3::types::PyDict::new(py);
        ldict.set_item("start_pc", line.start_pc)?;
        ldict.set_item("line_number", line.line_number)?;
        line_numbers.append(ldict)?;
    }
    dict.set_item("line_numbers", line_numbers)?;
    let local_variables = pyo3::types::PyList::empty(py);
    for local in code.local_variables {
        let ldict = pyo3::types::PyDict::new(py);
        ldict.set_item("start_pc", local.start_pc)?;
        ldict.set_item("length", local.length)?;
        ldict.set_item("name", local.name)?;
        ldict.set_item("descriptor", local.descriptor)?;
        ldict.set_item("index", local.index)?;
        local_variables.append(ldict)?;
    }
    dict.set_item("local_variables", local_variables)?;
    let local_variable_types = pyo3::types::PyList::empty(py);
    for local_type in code.local_variable_types {
        let ldict = pyo3::types::PyDict::new(py);
        ldict.set_item("start_pc", local_type.start_pc)?;
        ldict.set_item("length", local_type.length)?;
        ldict.set_item("name", local_type.name)?;
        ldict.set_item("signature", local_type.signature)?;
        ldict.set_item("index", local_type.index)?;
        local_variable_types.append(ldict)?;
    }
    dict.set_item("local_variable_types", local_variable_types)?;
    let instructions = pyo3::types::PyList::empty(py);
    for instruction in code.instructions {
        let idict = pyo3::types::PyDict::new(py);
        idict.set_item("bci", instruction.bci)?;
        idict.set_item("opcode", instruction.opcode)?;
        idict.set_item("mnemonic", instruction.mnemonic)?;
        idict.set_item("operands", instruction.operands)?;
        idict.set_item("length", instruction.length)?;
        instructions.append(idict)?;
    }
    dict.set_item("instructions", instructions)?;
    let xrefs = pyo3::types::PyList::empty(py);
    for xref in code.xrefs {
        let xdict = pyo3::types::PyDict::new(py);
        xdict.set_item("bci", xref.bci)?;
        xdict.set_item("opcode", xref.opcode)?;
        xdict.set_item("kind", xref.kind)?;
        xdict.set_item("owner", xref.owner)?;
        xdict.set_item("name", xref.name)?;
        xdict.set_item("descriptor", xref.descriptor)?;
        xdict.set_item("target", xref.target)?;
        xdict.set_item("string_value", xref.string_value)?;
        xrefs.append(xdict)?;
    }
    dict.set_item("xrefs", xrefs)?;
    Ok(dict.into())
}

/// Index a Java JAR/ZIP archive and return central-directory metadata.
/// Returns None for data that is not a ZIP/JAR archive.
#[pyfunction]
#[pyo3(name = "index_java_archive_path")]
#[pyo3(signature = (path, max_entries=4096usize, max_read_bytes=268_435_456u64, max_file_size=1_073_741_824u64))]
fn index_java_archive_path_py(
    py: Python<'_>,
    path: String,
    max_entries: usize,
    max_read_bytes: u64,
    max_file_size: u64,
) -> PyResult<Option<Py<PyAny>>> {
    let limit = std::cmp::min(max_read_bytes, max_file_size);
    let data = crate::triage::io::IOUtils::read_file_with_limit(&path, limit)
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!("{:?}", e)))?;
    index_java_archive_bytes_inner(py, &data, max_entries)
}

/// Index Java JAR/ZIP archive bytes and return central-directory metadata.
/// Returns None for data that is not a ZIP/JAR archive.
#[pyfunction]
#[pyo3(name = "index_java_archive_bytes")]
#[pyo3(signature = (data, max_entries=4096usize))]
fn index_java_archive_bytes_py(
    py: Python<'_>,
    data: &[u8],
    max_entries: usize,
) -> PyResult<Option<Py<PyAny>>> {
    index_java_archive_bytes_inner(py, data, max_entries)
}

fn index_java_archive_bytes_inner(
    py: Python<'_>,
    data: &[u8],
    max_entries: usize,
) -> PyResult<Option<Py<PyAny>>> {
    match crate::analysis::java_jar::index_jar(data, max_entries) {
        Ok(index) => java_jar_index_to_py(py, index).map(Some),
        Err(crate::analysis::java_jar::JavaJarError::NotZip) => Ok(None),
        Err(e) => Err(pyo3::exceptions::PyRuntimeError::new_err(format!(
            "java archive index failed: {:?}",
            e,
        ))),
    }
}

fn java_jar_index_to_py(
    py: Python<'_>,
    index: crate::analysis::java_jar::JavaJarIndex,
) -> PyResult<Py<PyAny>> {
    let dict = pyo3::types::PyDict::new(py);
    dict.set_item("entry_count", index.entry_count)?;
    dict.set_item("total_compressed_size", index.total_compressed_size)?;
    dict.set_item("total_uncompressed_size", index.total_uncompressed_size)?;
    dict.set_item("directory_count", index.directory_count)?;
    dict.set_item("class_count", index.class_count)?;
    dict.set_item("resource_count", index.resource_count)?;
    dict.set_item("nested_archive_count", index.nested_archive_count)?;
    dict.set_item("multi_release_class_count", index.multi_release_class_count)?;
    dict.set_item("multi_release_versions", index.multi_release_versions)?;
    dict.set_item("signature_file_count", index.signature_file_count)?;
    dict.set_item("signed", index.signed)?;
    dict.set_item("maven_metadata_count", index.maven_metadata_count)?;
    dict.set_item("service_descriptor_count", index.service_descriptor_count)?;
    dict.set_item("module_info_present", index.module_info_present)?;
    dict.set_item("zip_slip_entry_count", index.zip_slip_entry_count)?;
    dict.set_item("truncated", index.truncated)?;
    dict.set_item("zip64_locator_present", index.zip64_locator_present)?;
    let entries = pyo3::types::PyList::empty(py);
    for entry in index.entries {
        let edict = pyo3::types::PyDict::new(py);
        edict.set_item("entry_name", entry.entry_name)?;
        edict.set_item("compressed_size", entry.compressed_size)?;
        edict.set_item("uncompressed_size", entry.uncompressed_size)?;
        edict.set_item("compression_method", entry.compression_method)?;
        edict.set_item("crc32", entry.crc32)?;
        edict.set_item("local_header_offset", entry.local_header_offset)?;
        edict.set_item("is_dir", entry.is_dir)?;
        edict.set_item("is_class", entry.is_class)?;
        edict.set_item("is_resource", entry.is_resource)?;
        edict.set_item("is_nested_archive", entry.is_nested_archive)?;
        edict.set_item("is_multi_release_class", entry.is_multi_release_class)?;
        edict.set_item("multi_release_version", entry.multi_release_version)?;
        edict.set_item("is_signature_file", entry.is_signature_file)?;
        edict.set_item("is_maven_metadata", entry.is_maven_metadata)?;
        edict.set_item("is_service_descriptor", entry.is_service_descriptor)?;
        edict.set_item("is_module_info", entry.is_module_info)?;
        edict.set_item("is_zip_slip", entry.is_zip_slip)?;
        entries.append(edict)?;
    }
    dict.set_item("entries", entries)?;
    Ok(dict.into())
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
            "cil parse failed: {:?}",
            e,
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
            "gopclntab parse failed: {:?}",
            e,
        ))),
    }
}
