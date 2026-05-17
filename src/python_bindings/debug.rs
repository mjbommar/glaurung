//! Python bindings for debug-info ingestion (#178).
//!
//! Exposes `glaurung.debug.extract_dwarf_types(path)` so the
//! Python-side type_db importer can pull authoritative struct/enum/
//! typedef shapes from a binary's DWARF and persist them with
//! `set_by="dwarf"` provenance.

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};

use crate::debug::dwarf::{extract_dwarf_types, DwarfType, DwarfTypeKind};
use crate::symbols::pdb::{
    PdbBuildProvenance, PdbFieldSummary, PdbFunctionPrototype, PdbIngestor, PdbStructLayout,
};

pub fn register_debug_bindings(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    let debug_mod = pyo3::types::PyModule::new(py, "debug")?;
    debug_mod.add_function(wrap_pyfunction!(extract_dwarf_types_path_py, &debug_mod)?)?;
    debug_mod.add_function(wrap_pyfunction!(analyze_pe_pdb_cache_path_py, &debug_mod)?)?;
    m.add_submodule(&debug_mod)?;
    Ok(())
}

fn _kind_str(k: DwarfTypeKind) -> &'static str {
    match k {
        DwarfTypeKind::Struct => "struct",
        DwarfTypeKind::Union => "union",
        DwarfTypeKind::Enum => "enum",
        DwarfTypeKind::Typedef => "typedef",
    }
}

fn _type_to_dict<'py>(py: Python<'py>, t: &DwarfType) -> PyResult<Bound<'py, PyDict>> {
    let d = PyDict::new(py);
    d.set_item("kind", _kind_str(t.kind))?;
    d.set_item("name", &t.name)?;
    d.set_item("byte_size", t.byte_size)?;
    d.set_item("source_file", t.source_file.clone())?;
    let fields = pyo3::types::PyList::empty(py);
    for f in &t.fields {
        let fd = PyDict::new(py);
        fd.set_item("offset", f.offset)?;
        fd.set_item("name", &f.name)?;
        fd.set_item("c_type", &f.c_type)?;
        fd.set_item("size", f.size)?;
        fields.append(fd)?;
    }
    d.set_item("fields", fields)?;
    let variants = pyo3::types::PyList::empty(py);
    for v in &t.variants {
        let vd = PyDict::new(py);
        vd.set_item("name", &v.name)?;
        vd.set_item("value", v.value)?;
        variants.append(vd)?;
    }
    d.set_item("variants", variants)?;
    d.set_item("typedef_target", t.typedef_target.clone())?;
    Ok(d)
}

fn _provenance_to_dict<'py>(
    py: Python<'py>,
    provenance: &PdbBuildProvenance,
) -> PyResult<Bound<'py, PyDict>> {
    let d = PyDict::new(py);
    d.set_item("binary_sha256", &provenance.binary_sha256)?;
    d.set_item("pdb_name", &provenance.pdb_name)?;
    d.set_item("pdb_guid", &provenance.pdb_guid)?;
    d.set_item("pdb_age", provenance.pdb_age)?;
    d.set_item("pdb_guid_age", &provenance.pdb_guid_age)?;
    Ok(d)
}

fn _pdb_field_to_dict<'py>(
    py: Python<'py>,
    field: &PdbFieldSummary,
) -> PyResult<Bound<'py, PyDict>> {
    let d = PyDict::new(py);
    d.set_item("ordinal", field.ordinal)?;
    d.set_item("name", &field.name)?;
    d.set_item("byte_offset", field.byte_offset)?;
    d.set_item("type_name", field.type_name.clone())?;
    d.set_item("type_kind", field.type_kind.clone())?;
    d.set_item("type_index", field.type_index)?;
    d.set_item("bit_size", field.bit_size)?;
    d.set_item("bit_position", field.bit_position)?;
    d.set_item("bit_underlying_type_index", field.bit_underlying_type_index)?;
    Ok(d)
}

fn _pdb_layout_to_dict<'py>(
    py: Python<'py>,
    layout: &PdbStructLayout,
) -> PyResult<Bound<'py, PyDict>> {
    let d = PyDict::new(py);
    d.set_item("name", &layout.name)?;
    d.set_item("kind", &layout.kind)?;
    d.set_item("byte_size", layout.byte_size)?;
    d.set_item("field_count", layout.field_count)?;
    let fields = PyList::empty(py);
    for field in &layout.fields {
        fields.append(_pdb_field_to_dict(py, field)?)?;
    }
    d.set_item("fields", fields)?;
    if let Some(provenance) = &layout.provenance {
        d.set_item("provenance", _provenance_to_dict(py, provenance)?)?;
    } else {
        d.set_item("provenance", py.None())?;
    }
    Ok(d)
}

fn _pdb_prototype_to_dict<'py>(
    py: Python<'py>,
    prototype: &PdbFunctionPrototype,
) -> PyResult<Bound<'py, PyDict>> {
    let d = PyDict::new(py);
    d.set_item("type_index", prototype.type_index)?;
    d.set_item("kind", &prototype.kind)?;
    d.set_item("return_type_index", prototype.return_type_index)?;
    d.set_item("return_type_name", prototype.return_type_name.clone())?;
    d.set_item("argument_count", prototype.argument_count)?;
    d.set_item(
        "argument_type_indices",
        prototype.argument_type_indices.clone(),
    )?;
    d.set_item("argument_type_names", prototype.argument_type_names.clone())?;
    d.set_item("calling_convention", prototype.calling_convention)?;
    d.set_item("class_type_index", prototype.class_type_index)?;
    d.set_item("this_pointer_type_index", prototype.this_pointer_type_index)?;
    if let Some(provenance) = &prototype.provenance {
        d.set_item("provenance", _provenance_to_dict(py, provenance)?)?;
    } else {
        d.set_item("provenance", py.None())?;
    }
    Ok(d)
}

#[pyfunction]
#[pyo3(name = "extract_dwarf_types_path")]
fn extract_dwarf_types_path_py<'py>(
    py: Python<'py>,
    path: String,
) -> PyResult<Vec<Bound<'py, PyDict>>> {
    let bytes = std::fs::read(&path)
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!("{}: {}", path, e)))?;
    let types = extract_dwarf_types(&bytes);
    types.iter().map(|t| _type_to_dict(py, t)).collect()
}

#[pyfunction]
#[pyo3(name = "analyze_pe_pdb_cache_path")]
fn analyze_pe_pdb_cache_path_py<'py>(
    py: Python<'py>,
    pe_path: String,
    cache_dir: String,
    struct_names: Vec<String>,
) -> PyResult<Bound<'py, PyDict>> {
    let names = struct_names.iter().map(String::as_str).collect::<Vec<_>>();
    let analysis = PdbIngestor::analyze_pe_cache(&pe_path, &cache_dir, &names)
        .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(error.to_string()))?;
    let d = PyDict::new(py);
    let Some(analysis) = analysis else {
        d.set_item("cache_hit", false)?;
        return Ok(d);
    };

    d.set_item("cache_hit", true)?;
    d.set_item("pe_path", analysis.pe_path.display().to_string())?;
    d.set_item("pdb_path", analysis.pdb_path.display().to_string())?;
    let codeview = PyDict::new(py);
    codeview.set_item("pdb_path", &analysis.codeview.pdb_path)?;
    codeview.set_item("pdb_name", &analysis.codeview.pdb_name)?;
    codeview.set_item("pdb_guid", &analysis.codeview.guid_string)?;
    codeview.set_item("pdb_age", analysis.codeview.age)?;
    codeview.set_item("pdb_guid_age", analysis.codeview.guid_age_key())?;
    d.set_item("codeview", codeview)?;
    d.set_item("provenance", _provenance_to_dict(py, &analysis.provenance)?)?;

    let layouts = PyList::empty(py);
    for layout in &analysis.struct_layouts {
        layouts.append(_pdb_layout_to_dict(py, layout)?)?;
    }
    d.set_item("struct_layouts", layouts)?;

    let prototypes = PyList::empty(py);
    for prototype in &analysis.function_prototypes {
        prototypes.append(_pdb_prototype_to_dict(py, prototype)?)?;
    }
    d.set_item("function_prototypes", prototypes)?;
    Ok(d)
}
