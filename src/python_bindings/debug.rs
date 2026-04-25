//! Python bindings for debug-info ingestion (#178).
//!
//! Exposes `glaurung.debug.extract_dwarf_types(path)` so the
//! Python-side type_db importer can pull authoritative struct/enum/
//! typedef shapes from a binary's DWARF and persist them with
//! `set_by="dwarf"` provenance.

use pyo3::prelude::*;
use pyo3::types::PyDict;

use crate::debug::dwarf::{extract_dwarf_types, DwarfType, DwarfTypeKind};

pub fn register_debug_bindings(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    let debug_mod = pyo3::types::PyModule::new(py, "debug")?;
    debug_mod.add_function(wrap_pyfunction!(extract_dwarf_types_path_py, &debug_mod)?)?;
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
