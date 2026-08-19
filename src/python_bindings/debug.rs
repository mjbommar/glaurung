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
    PdbBuildProvenance, PdbFieldSummary, PdbFunctionPrototype, PdbIngestor, PdbPublicSymbol,
    PdbStructLayout,
};

pub fn register_debug_bindings(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    let debug_mod = pyo3::types::PyModule::new(py, "debug")?;
    debug_mod.add_function(wrap_pyfunction!(extract_dwarf_types_path_py, &debug_mod)?)?;
    debug_mod.add_function(wrap_pyfunction!(
        extract_dwarf_signatures_path_py,
        &debug_mod
    )?)?;
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

fn _pdb_public_symbol_to_dict<'py>(
    py: Python<'py>,
    symbol: &PdbPublicSymbol,
) -> PyResult<Bound<'py, PyDict>> {
    let d = PyDict::new(py);
    d.set_item("name", &symbol.name)?;
    d.set_item("rva", symbol.rva)?;
    d.set_item("va", symbol.va)?;
    d.set_item("code", symbol.code)?;
    d.set_item("function", symbol.function)?;
    d.set_item("managed", symbol.managed)?;
    d.set_item("msil", symbol.msil)?;
    if let Some(provenance) = &symbol.provenance {
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
    d.set_item("image_base", analysis.image_base)?;
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

    let public_symbols = PyList::empty(py);
    for symbol in &analysis.public_symbols {
        public_symbols.append(_pdb_public_symbol_to_dict(py, symbol)?)?;
    }
    d.set_item("public_symbols", public_symbols)?;
    Ok(d)
}

/// One [`crate::debug::dwarf_signatures::DwarfType`] as the harness's dict.
///
/// The shape is the one `tools/diff_decompile.py` already consumes, so the
/// switch from its pyelftools reader to this one is a change of SOURCE and not
/// of vocabulary: `{'k':'int','w':N,'s':bool}`, `{'k':'float','w':4|8}`,
/// `{'k':'ptr','p':pointee,'const':bool}`, `{'k':'self_ptr','w':N}`,
/// `{'k':'struct','w':bytes,'fields':[{'name':…,'off':N,'t':desc}]}`,
/// `{'k':'void'}`.
///
/// An INTEGER pointee additionally carries the legacy `pw`/`ps` keys. Those
/// mean "integer of this width/signedness" to every existing reader of a
/// manifest override, so a float pointee deliberately does not claim them — it
/// would be read as an integer buffer.
fn _signature_type_to_dict<'py>(
    py: Python<'py>,
    ty: &crate::debug::dwarf_signatures::DwarfType,
) -> PyResult<Bound<'py, PyDict>> {
    use crate::debug::dwarf_signatures::DwarfType as T;

    let d = PyDict::new(py);
    match ty {
        T::Void => {
            d.set_item("k", "void")?;
        }
        T::Int { width, signed } => {
            d.set_item("k", "int")?;
            d.set_item("w", *width)?;
            d.set_item("s", *signed)?;
        }
        T::Float { width } => {
            d.set_item("k", "float")?;
            d.set_item("w", *width)?;
        }
        T::SelfPointer { width } => {
            d.set_item("k", "self_ptr")?;
            d.set_item("w", *width)?;
        }
        T::Pointer { pointee, konst } => {
            d.set_item("k", "ptr")?;
            let inner = _signature_type_to_dict(py, pointee)?;
            d.set_item("p", &inner)?;
            d.set_item("const", *konst)?;
            if let T::Int { width, signed } = pointee.as_ref() {
                d.set_item("pw", *width)?;
                d.set_item("ps", *signed)?;
            }
        }
        T::Struct {
            byte_size,
            fields,
            name,
        }
        | T::Union {
            byte_size,
            fields,
            name,
        } => {
            // The KIND is what tells the harness whether the members are laid
            // out in sequence or share one storage; everything else about the
            // two is identical, which is why they share this arm.
            d.set_item(
                "k",
                if matches!(ty, T::Union { .. }) {
                    "union"
                } else {
                    "struct"
                },
            )?;
            d.set_item("w", *byte_size)?;
            // Emitted only when present, matching the reader this replaces: a
            // by-value aggregate has no `name` key at all there.
            if let Some(name) = name {
                d.set_item("name", name)?;
            }
            let items = pyo3::types::PyList::empty(py);
            for field in fields {
                let entry = PyDict::new(py);
                entry.set_item("name", &field.name)?;
                entry.set_item("off", field.offset)?;
                entry.set_item("t", _signature_type_to_dict(py, &field.ty)?)?;
                items.append(entry)?;
            }
            d.set_item("fields", items)?;
        }
        T::Array { element, count } => {
            d.set_item("k", "array")?;
            d.set_item("n", *count)?;
            d.set_item("e", _signature_type_to_dict(py, element)?)?;
        }
    }
    Ok(d)
}

#[pyfunction]
#[pyo3(name = "extract_dwarf_signatures_path")]
fn extract_dwarf_signatures_path_py<'py>(
    py: Python<'py>,
    path: String,
) -> PyResult<Vec<Bound<'py, PyDict>>> {
    let bytes = std::fs::read(&path)
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!("{}: {}", path, e)))?;
    crate::debug::dwarf_signatures::extract_dwarf_signatures(&bytes)
        .iter()
        .map(|signature| {
            let d = PyDict::new(py);
            d.set_item("name", &signature.name)?;
            d.set_item("va", signature.va)?;
            let params = pyo3::types::PyList::empty(py);
            for parameter in &signature.parameters {
                params.append(_signature_type_to_dict(py, parameter)?)?;
            }
            d.set_item("params", params)?;
            d.set_item("ret", _signature_type_to_dict(py, &signature.result)?)?;
            Ok(d)
        })
        .collect()
}
