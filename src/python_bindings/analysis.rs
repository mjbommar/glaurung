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
    analysis_mod.add_function(wrap_pyfunction!(pe_list_resources_path_py, &analysis_mod)?)?;
    analysis_mod.add_function(wrap_pyfunction!(pe_list_resources_bytes_py, &analysis_mod)?)?;

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

/// List PE resource metadata for a file.
#[pyfunction]
#[pyo3(name = "pe_list_resources_path")]
#[pyo3(signature = (path, max_read_bytes=104_857_600u64, max_file_size=104_857_600u64, max_resources=4096usize, max_resource_depth=32usize, max_resource_data_bytes=1_048_576usize, preview_bytes=16usize))]
fn pe_list_resources_path_py(
    py: Python<'_>,
    path: String,
    max_read_bytes: u64,
    max_file_size: u64,
    max_resources: usize,
    max_resource_depth: usize,
    max_resource_data_bytes: usize,
    preview_bytes: usize,
) -> PyResult<Py<PyAny>> {
    let limit = std::cmp::min(max_read_bytes, max_file_size);
    let data = crate::triage::io::IOUtils::read_file_with_limit(&path, limit)
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!("{:?}", e)))?;
    pe_list_resources_bytes_inner(
        py,
        &data,
        max_resources,
        max_resource_depth,
        max_resource_data_bytes,
        preview_bytes,
    )
}

/// List PE resource metadata for bytes.
#[pyfunction]
#[pyo3(name = "pe_list_resources_bytes")]
#[pyo3(signature = (data, max_resources=4096usize, max_resource_depth=32usize, max_resource_data_bytes=1_048_576usize, preview_bytes=16usize))]
fn pe_list_resources_bytes_py(
    py: Python<'_>,
    data: &[u8],
    max_resources: usize,
    max_resource_depth: usize,
    max_resource_data_bytes: usize,
    preview_bytes: usize,
) -> PyResult<Py<PyAny>> {
    pe_list_resources_bytes_inner(
        py,
        data,
        max_resources,
        max_resource_depth,
        max_resource_data_bytes,
        preview_bytes,
    )
}

fn pe_list_resources_bytes_inner(
    py: Python<'_>,
    data: &[u8],
    max_resources: usize,
    max_resource_depth: usize,
    max_resource_data_bytes: usize,
    preview_bytes: usize,
) -> PyResult<Py<PyAny>> {
    let mut options = crate::formats::pe::ParseOptions::default();
    options.max_resources = max_resources;
    options.max_resource_depth = max_resource_depth;
    options.max_resource_data_bytes = max_resource_data_bytes;

    let parser = crate::formats::pe::PeParser::with_options(data, options)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("{}", e)))?;
    let resources = parser
        .resources()
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("{}", e)))?;

    pe_resources_to_py(py, resources, preview_bytes)
}

fn pe_resources_to_py(
    py: Python<'_>,
    resources: &crate::formats::pe::ResourceDirectory<'_>,
    preview_bytes: usize,
) -> PyResult<Py<PyAny>> {
    let dict = pyo3::types::PyDict::new(py);
    dict.set_item("leaf_count", resources.leaf_count())?;
    dict.set_item("total_directories", resources.total_directories)?;
    dict.set_item("total_named_entries", resources.total_named_entries)?;
    dict.set_item("total_id_entries", resources.total_id_entries)?;
    dict.set_item("total_entries", resources.total_entries)?;
    dict.set_item("max_depth", resources.max_depth)?;
    dict.set_item("resource_bytes_total", resource_bytes_total(resources))?;
    dict.set_item("warnings", resources.warnings.clone())?;
    dict.set_item("stop_reasons", resources.stop_reasons.clone())?;
    dict.set_item("truncated", !resources.stop_reasons.is_empty())?;

    let by_type = pyo3::types::PyDict::new(py);
    for (type_name, count) in resources_by_type(resources) {
        by_type.set_item(type_name, count)?;
    }
    dict.set_item("resources_by_type", by_type)?;

    let entries = pyo3::types::PyList::empty(py);
    for resource in &resources.resources {
        let rdict = pyo3::types::PyDict::new(py);
        let resource_type = pe_resource_type_label(resource);
        let preview_len = resource.data.len().min(preview_bytes);
        rdict.set_item("type_id", resource.type_id.as_id())?;
        rdict.set_item("type_name", resource.type_name.clone())?;
        rdict.set_item("type", resource_type)?;
        rdict.set_item("name_id", resource.name.as_id())?;
        rdict.set_item("name", resource.name.as_name())?;
        rdict.set_item("language_id", resource.language_id)?;
        rdict.set_item("language", resource.language.as_name())?;
        rdict.set_item("code_page", resource.code_page)?;
        rdict.set_item("data_rva", resource.data_rva)?;
        rdict.set_item("data_offset", resource.data_offset)?;
        rdict.set_item("size", resource.size)?;
        rdict.set_item("section_name", resource.section_name.clone())?;
        rdict.set_item("entropy", resource.entropy)?;
        rdict.set_item("sha256", resource.sha256.clone())?;
        rdict.set_item("magic", resource.magic.clone())?;
        rdict.set_item("preview_hex", hex::encode(&resource.data[..preview_len]))?;
        rdict.set_item("warnings", resource.warnings.clone())?;
        entries.append(rdict)?;
    }
    dict.set_item("resources", entries)?;
    Ok(dict.into())
}

fn pe_resource_type_label(resource: &crate::formats::pe::ResourceDataEntry<'_>) -> String {
    if let Some(type_name) = &resource.type_name {
        return type_name.clone();
    }
    if let Some(name) = resource.type_id.as_name() {
        return name.to_string();
    }
    if let Some(id) = resource.type_id.as_id() {
        return format!("id:{}", id);
    }
    "unknown".to_string()
}

fn resource_bytes_total(resources: &crate::formats::pe::ResourceDirectory<'_>) -> u64 {
    resources
        .resources
        .iter()
        .map(|resource| resource.size as u64)
        .sum()
}

fn resources_by_type(
    resources: &crate::formats::pe::ResourceDirectory<'_>,
) -> std::collections::BTreeMap<String, usize> {
    let mut counts = std::collections::BTreeMap::new();
    for resource in &resources.resources {
        *counts.entry(pe_resource_type_label(resource)).or_insert(0) += 1;
    }
    counts
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
    dict.set_item("signature", info.signature)?;
    dict.set_item("attribute_count", info.attribute_names.len())?;
    dict.set_item("attribute_names", info.attribute_names)?;
    dict.set_item("is_deprecated", info.is_deprecated)?;
    dict.set_item("is_synthetic", info.is_synthetic)?;
    dict.set_item(
        "runtime_visible_type_annotation_count",
        info.runtime_visible_type_annotation_count,
    )?;
    dict.set_item(
        "runtime_invisible_type_annotation_count",
        info.runtime_invisible_type_annotation_count,
    )?;
    dict.set_item(
        "type_annotation_count",
        info.runtime_visible_type_annotation_count + info.runtime_invisible_type_annotation_count,
    )?;
    dict.set_item(
        "source_debug_extension_length",
        info.source_debug_extension_length,
    )?;
    dict.set_item(
        "source_debug_extension_sha256",
        info.source_debug_extension_sha256,
    )?;
    dict.set_item(
        "constant_pool",
        java_constant_pool_summary_to_py(py, info.constant_pool)?,
    )?;
    dict.set_item("annotations", java_annotations_to_py(py, info.annotations)?)?;
    dict.set_item(
        "inner_classes",
        java_inner_classes_to_py(py, info.inner_classes)?,
    )?;
    dict.set_item(
        "enclosing_method",
        java_enclosing_method_to_py(py, info.enclosing_method)?,
    )?;
    dict.set_item("nest_host", info.nest_host)?;
    dict.set_item("nest_members", info.nest_members)?;
    dict.set_item(
        "record_components",
        java_record_components_to_py(py, info.record_components)?,
    )?;
    dict.set_item("permitted_subclasses", info.permitted_subclasses)?;
    dict.set_item("module", java_module_info_to_py(py, info.module)?)?;
    dict.set_item("bootstrap_method_count", info.bootstrap_method_count)?;
    dict.set_item(
        "bootstrap_methods",
        java_bootstrap_methods_to_py(py, info.bootstrap_methods)?,
    )?;
    dict.set_item("interfaces", info.interfaces)?;
    dict.set_item("major_version", info.major_version)?;
    dict.set_item("minor_version", info.minor_version)?;
    dict.set_item("access_flags", info.access_flags)?;
    let methods = pyo3::types::PyList::empty(py);
    for m in info.methods {
        let mdict = pyo3::types::PyDict::new(py);
        mdict.set_item("name", m.name)?;
        mdict.set_item("descriptor", m.descriptor)?;
        mdict.set_item("signature", m.signature)?;
        mdict.set_item("access_flags", m.access_flags)?;
        mdict.set_item("attribute_count", m.attribute_names.len())?;
        mdict.set_item("attribute_names", m.attribute_names)?;
        mdict.set_item("is_deprecated", m.is_deprecated)?;
        mdict.set_item("is_synthetic", m.is_synthetic)?;
        mdict.set_item(
            "runtime_visible_type_annotation_count",
            m.runtime_visible_type_annotation_count,
        )?;
        mdict.set_item(
            "runtime_invisible_type_annotation_count",
            m.runtime_invisible_type_annotation_count,
        )?;
        mdict.set_item(
            "type_annotation_count",
            m.runtime_visible_type_annotation_count + m.runtime_invisible_type_annotation_count,
        )?;
        mdict.set_item(
            "constant_value",
            java_constant_value_to_py(py, m.constant_value)?,
        )?;
        mdict.set_item("exceptions", m.exceptions)?;
        mdict.set_item("annotations", java_annotations_to_py(py, m.annotations)?)?;
        mdict.set_item(
            "method_parameters",
            java_method_parameters_to_py(py, m.method_parameters)?,
        )?;
        mdict.set_item(
            "parameter_annotations",
            java_parameter_annotations_to_py(py, m.parameter_annotations)?,
        )?;
        mdict.set_item(
            "annotation_default",
            java_annotation_value_option_to_py(py, m.annotation_default)?,
        )?;
        mdict.set_item("code", java_code_to_py(py, m.code)?)?;
        methods.append(mdict)?;
    }
    dict.set_item("methods", methods)?;
    let fields = pyo3::types::PyList::empty(py);
    for f in info.fields {
        let fdict = pyo3::types::PyDict::new(py);
        fdict.set_item("name", f.name)?;
        fdict.set_item("descriptor", f.descriptor)?;
        fdict.set_item("signature", f.signature)?;
        fdict.set_item("access_flags", f.access_flags)?;
        fdict.set_item("attribute_count", f.attribute_names.len())?;
        fdict.set_item("attribute_names", f.attribute_names)?;
        fdict.set_item("is_deprecated", f.is_deprecated)?;
        fdict.set_item("is_synthetic", f.is_synthetic)?;
        fdict.set_item(
            "runtime_visible_type_annotation_count",
            f.runtime_visible_type_annotation_count,
        )?;
        fdict.set_item(
            "runtime_invisible_type_annotation_count",
            f.runtime_invisible_type_annotation_count,
        )?;
        fdict.set_item(
            "type_annotation_count",
            f.runtime_visible_type_annotation_count + f.runtime_invisible_type_annotation_count,
        )?;
        fdict.set_item(
            "constant_value",
            java_constant_value_to_py(py, f.constant_value)?,
        )?;
        fdict.set_item("exceptions", f.exceptions)?;
        fdict.set_item("annotations", java_annotations_to_py(py, f.annotations)?)?;
        fdict.set_item(
            "method_parameters",
            java_method_parameters_to_py(py, f.method_parameters)?,
        )?;
        fdict.set_item(
            "parameter_annotations",
            java_parameter_annotations_to_py(py, f.parameter_annotations)?,
        )?;
        fdict.set_item(
            "annotation_default",
            java_annotation_value_option_to_py(py, f.annotation_default)?,
        )?;
        fdict.set_item("code", java_code_to_py(py, f.code)?)?;
        fields.append(fdict)?;
    }
    dict.set_item("fields", fields)?;
    Ok(dict.into())
}

fn java_inner_classes_to_py(
    py: Python<'_>,
    inner_classes: Vec<crate::analysis::java_class::JavaInnerClass>,
) -> PyResult<Py<PyAny>> {
    let out = pyo3::types::PyList::empty(py);
    for inner in inner_classes {
        let idict = pyo3::types::PyDict::new(py);
        idict.set_item("inner_class", inner.inner_class)?;
        idict.set_item("outer_class", inner.outer_class)?;
        idict.set_item("inner_name", inner.inner_name)?;
        idict.set_item("access_flags", inner.access_flags)?;
        out.append(idict)?;
    }
    Ok(out.into())
}

fn java_enclosing_method_to_py(
    py: Python<'_>,
    enclosing_method: Option<crate::analysis::java_class::JavaEnclosingMethod>,
) -> PyResult<Py<PyAny>> {
    let Some(enclosing_method) = enclosing_method else {
        return Ok(py.None());
    };
    let dict = pyo3::types::PyDict::new(py);
    dict.set_item("class_name", enclosing_method.class_name)?;
    dict.set_item("method_name", enclosing_method.method_name)?;
    dict.set_item("method_descriptor", enclosing_method.method_descriptor)?;
    Ok(dict.into())
}

fn java_record_components_to_py(
    py: Python<'_>,
    record_components: Vec<crate::analysis::java_class::JavaRecordComponent>,
) -> PyResult<Py<PyAny>> {
    let out = pyo3::types::PyList::empty(py);
    for component in record_components {
        let cdict = pyo3::types::PyDict::new(py);
        cdict.set_item("name", component.name)?;
        cdict.set_item("descriptor", component.descriptor)?;
        cdict.set_item("signature", component.signature)?;
        cdict.set_item(
            "annotations",
            java_annotations_to_py(py, component.annotations)?,
        )?;
        out.append(cdict)?;
    }
    Ok(out.into())
}

fn java_module_info_to_py(
    py: Python<'_>,
    module: Option<crate::analysis::java_class::JavaModuleInfo>,
) -> PyResult<Py<PyAny>> {
    let Some(module) = module else {
        return Ok(py.None());
    };
    let dict = pyo3::types::PyDict::new(py);
    dict.set_item("name", module.name)?;
    dict.set_item("flags", module.flags)?;
    dict.set_item("version", module.version)?;

    let requires = pyo3::types::PyList::empty(py);
    for require in module.requires {
        let rdict = pyo3::types::PyDict::new(py);
        rdict.set_item("module", require.module)?;
        rdict.set_item("flags", require.flags)?;
        rdict.set_item("version", require.version)?;
        requires.append(rdict)?;
    }
    dict.set_item("requires", requires)?;

    let exports = pyo3::types::PyList::empty(py);
    for export in module.exports {
        let edict = pyo3::types::PyDict::new(py);
        edict.set_item("package", export.package)?;
        edict.set_item("flags", export.flags)?;
        edict.set_item("targets", export.targets)?;
        exports.append(edict)?;
    }
    dict.set_item("exports", exports)?;

    let opens = pyo3::types::PyList::empty(py);
    for open in module.opens {
        let odict = pyo3::types::PyDict::new(py);
        odict.set_item("package", open.package)?;
        odict.set_item("flags", open.flags)?;
        odict.set_item("targets", open.targets)?;
        opens.append(odict)?;
    }
    dict.set_item("opens", opens)?;
    dict.set_item("uses", module.uses)?;
    dict.set_item("packages", module.packages)?;
    dict.set_item("main_class", module.main_class)?;

    let provides = pyo3::types::PyList::empty(py);
    for provide in module.provides {
        let pdict = pyo3::types::PyDict::new(py);
        pdict.set_item("service", provide.service)?;
        pdict.set_item("implementations", provide.implementations)?;
        provides.append(pdict)?;
    }
    dict.set_item("provides", provides)?;
    Ok(dict.into())
}

fn java_constant_pool_summary_to_py(
    py: Python<'_>,
    summary: crate::analysis::java_class::JavaConstantPoolSummary,
) -> PyResult<Py<PyAny>> {
    let dict = pyo3::types::PyDict::new(py);
    dict.set_item("total_slots", summary.total_slots)?;
    dict.set_item("populated_entries", summary.populated_entries)?;
    dict.set_item("empty_slots", summary.empty_slots)?;
    dict.set_item("utf8_count", summary.utf8_count)?;
    dict.set_item("integer_count", summary.integer_count)?;
    dict.set_item("float_count", summary.float_count)?;
    dict.set_item("long_count", summary.long_count)?;
    dict.set_item("double_count", summary.double_count)?;
    dict.set_item("class_count", summary.class_count)?;
    dict.set_item("string_count", summary.string_count)?;
    dict.set_item("fieldref_count", summary.fieldref_count)?;
    dict.set_item("methodref_count", summary.methodref_count)?;
    dict.set_item(
        "interface_methodref_count",
        summary.interface_methodref_count,
    )?;
    dict.set_item("name_and_type_count", summary.name_and_type_count)?;
    dict.set_item("method_handle_count", summary.method_handle_count)?;
    dict.set_item("method_type_count", summary.method_type_count)?;
    dict.set_item("dynamic_count", summary.dynamic_count)?;
    dict.set_item("invoke_dynamic_count", summary.invoke_dynamic_count)?;
    dict.set_item("module_count", summary.module_count)?;
    dict.set_item("package_count", summary.package_count)?;
    dict.set_item("other_count", summary.other_count)?;
    Ok(dict.into())
}

fn java_bootstrap_methods_to_py(
    py: Python<'_>,
    bootstrap_methods: Vec<crate::analysis::java_class::JavaBootstrapMethod>,
) -> PyResult<Py<PyAny>> {
    let out = pyo3::types::PyList::empty(py);
    for method in bootstrap_methods {
        let mdict = pyo3::types::PyDict::new(py);
        mdict.set_item(
            "bootstrap_method_ref_index",
            method.bootstrap_method_ref_index,
        )?;
        mdict.set_item("reference_kind", method.reference_kind)?;
        mdict.set_item("reference_kind_name", method.reference_kind_name)?;
        mdict.set_item("reference_owner", method.reference_owner)?;
        mdict.set_item("reference_name", method.reference_name)?;
        mdict.set_item("reference_descriptor", method.reference_descriptor)?;
        mdict.set_item("reference_target", method.reference_target)?;
        mdict.set_item("argument_count", method.argument_count)?;
        mdict.set_item("arguments", method.arguments)?;
        out.append(mdict)?;
    }
    Ok(out.into())
}

fn java_annotations_to_py(
    py: Python<'_>,
    annotations: Vec<crate::analysis::java_class::JavaAnnotation>,
) -> PyResult<Py<PyAny>> {
    let out = pyo3::types::PyList::empty(py);
    for annotation in annotations {
        let adict = pyo3::types::PyDict::new(py);
        adict.set_item("visibility", annotation.visibility)?;
        adict.set_item("descriptor", annotation.descriptor)?;
        let elements = pyo3::types::PyList::empty(py);
        for element in annotation.elements {
            let edict = pyo3::types::PyDict::new(py);
            edict.set_item("name", element.name)?;
            edict.set_item("value", java_annotation_value_to_py(py, element.value)?)?;
            elements.append(edict)?;
        }
        adict.set_item("elements", elements)?;
        out.append(adict)?;
    }
    Ok(out.into())
}

fn java_method_parameters_to_py(
    py: Python<'_>,
    parameters: Vec<crate::analysis::java_class::JavaMethodParameter>,
) -> PyResult<Py<PyAny>> {
    let out = pyo3::types::PyList::empty(py);
    for parameter in parameters {
        let pdict = pyo3::types::PyDict::new(py);
        pdict.set_item("name", parameter.name)?;
        pdict.set_item("access_flags", parameter.access_flags)?;
        out.append(pdict)?;
    }
    Ok(out.into())
}

fn java_parameter_annotations_to_py(
    py: Python<'_>,
    parameter_annotations: Vec<crate::analysis::java_class::JavaParameterAnnotations>,
) -> PyResult<Py<PyAny>> {
    let out = pyo3::types::PyList::empty(py);
    for parameter in parameter_annotations {
        let pdict = pyo3::types::PyDict::new(py);
        pdict.set_item("parameter_index", parameter.parameter_index)?;
        pdict.set_item(
            "annotations",
            java_annotations_to_py(py, parameter.annotations)?,
        )?;
        out.append(pdict)?;
    }
    Ok(out.into())
}

fn java_annotation_value_option_to_py(
    py: Python<'_>,
    value: Option<crate::analysis::java_class::JavaAnnotationValue>,
) -> PyResult<Py<PyAny>> {
    let Some(value) = value else {
        return Ok(py.None());
    };
    java_annotation_value_to_py(py, value)
}

fn java_annotation_value_to_py(
    py: Python<'_>,
    value: crate::analysis::java_class::JavaAnnotationValue,
) -> PyResult<Py<PyAny>> {
    let dict = pyo3::types::PyDict::new(py);
    dict.set_item("tag", value.tag)?;
    dict.set_item("kind", value.kind.clone())?;
    if let Some(const_value) = value.value {
        dict.set_item("value", const_value)?;
    }
    if let Some(type_name) = value.type_name {
        dict.set_item("type_name", type_name)?;
    }
    if let Some(const_name) = value.const_name {
        dict.set_item("const_name", const_name)?;
    }
    if value.kind == "array" {
        let values = pyo3::types::PyList::empty(py);
        for item in value.values {
            values.append(java_annotation_value_to_py(py, item)?)?;
        }
        dict.set_item("values", values)?;
    }
    Ok(dict.into())
}

fn java_constant_value_to_py(
    py: Python<'_>,
    value: Option<crate::analysis::java_class::JavaConstantValue>,
) -> PyResult<Py<PyAny>> {
    let Some(value) = value else {
        return Ok(py.None());
    };
    let dict = pyo3::types::PyDict::new(py);
    dict.set_item("kind", value.kind)?;
    dict.set_item("value", value.value)?;
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
    let exception_handlers = pyo3::types::PyList::empty(py);
    for handler in code.exception_handlers {
        let hdict = pyo3::types::PyDict::new(py);
        hdict.set_item("start_pc", handler.start_pc)?;
        hdict.set_item("end_pc", handler.end_pc)?;
        hdict.set_item("handler_pc", handler.handler_pc)?;
        hdict.set_item("catch_type", handler.catch_type)?;
        exception_handlers.append(hdict)?;
    }
    dict.set_item("exception_handlers", exception_handlers)?;
    dict.set_item("attributes_count", code.attributes_count)?;
    dict.set_item("attribute_count", code.attribute_names.len())?;
    dict.set_item("attribute_names", code.attribute_names)?;
    dict.set_item("instruction_count", code.instruction_count)?;
    dict.set_item("unknown_instruction_count", code.unknown_instruction_count)?;
    dict.set_item("stack_map_frame_count", code.stack_map_frame_count)?;
    dict.set_item(
        "runtime_visible_type_annotation_count",
        code.runtime_visible_type_annotation_count,
    )?;
    dict.set_item(
        "runtime_invisible_type_annotation_count",
        code.runtime_invisible_type_annotation_count,
    )?;
    dict.set_item(
        "type_annotation_count",
        code.runtime_visible_type_annotation_count + code.runtime_invisible_type_annotation_count,
    )?;
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
