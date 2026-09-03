//! Python bindings for `crate::flirt` -- signature extraction and matching.
//!
//! The one function here exists so `tools/build_flirt_library.py` can derive
//! variant-byte masks from a `.a` archive's relocation tables without
//! reimplementing ELF, Mach-O and COFF relocation parsing in Python. The
//! derivation itself lives in `src/flirt/archive.rs`; this is a thin
//! marshalling layer over it.

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};

/// Extract masked signatures from every object member of an `ar` archive.
///
/// Args:
///     path: Path to a `.a` (or `.lib`) archive of unlinked objects.
///     pattern_len: Pattern length in bytes. Defaults to 32, as FLIRT uses.
///     min_function_len: Skip symbols smaller than this. Defaults to 8.
///     min_fixed_bytes: Skip signatures comparing fewer than this many bytes
///         after masking. Defaults to 16; see `ArchiveOptions` for the
///         measurement behind that number.
///
/// Returns:
///     A list of dicts, one per function, with the keys ``name``,
///     ``prologue_hex``, ``mask_hex``, ``crc16``, ``crc_len``,
///     ``function_len``, ``refs`` (a list of ``{offset, name}``),
///     ``source_binary``, ``member``, ``address`` and ``masked_bytes``. The
///     first eight are exactly the on-disk signature schema; the last three
///     are provenance used to distinguish aliases from ambiguity.
///
/// Raises:
///     OSError: the file cannot be read.
///     ValueError: the file is not an `ar` archive.
#[pyfunction]
#[pyo3(
    name = "flirt_signatures_from_archive_path",
    signature = (path, pattern_len = 32, min_function_len = 8, min_fixed_bytes = 16)
)]
fn flirt_signatures_from_archive_path_py(
    py: Python<'_>,
    path: &str,
    pattern_len: usize,
    min_function_len: u64,
    min_fixed_bytes: usize,
) -> PyResult<Py<PyList>> {
    let data = std::fs::read(path)?;
    let options = crate::flirt::archive::ArchiveOptions {
        pattern_len,
        min_function_len,
        min_fixed_bytes,
        ..Default::default()
    };
    let sigs = py
        .detach(|| crate::flirt::archive::signatures_from_archive(&data, &options))
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;

    let rows = PyList::empty(py);
    for sig in sigs {
        let d = PyDict::new(py);
        d.set_item("name", &sig.entry.name)?;
        d.set_item("prologue_hex", &sig.entry.prologue_hex)?;
        d.set_item("mask_hex", &sig.entry.mask_hex)?;
        d.set_item("crc16", sig.entry.crc16)?;
        d.set_item("crc_len", sig.entry.crc_len)?;
        d.set_item("function_len", sig.entry.function_len)?;
        let refs = PyList::empty(py);
        for r in &sig.entry.refs {
            let rd = PyDict::new(py);
            rd.set_item("offset", r.offset)?;
            rd.set_item("name", &r.name)?;
            refs.append(rd)?;
        }
        d.set_item("refs", refs)?;
        d.set_item("source_binary", &sig.entry.source_binary)?;
        d.set_item("member", &sig.member)?;
        d.set_item("address", sig.address)?;
        d.set_item("masked_bytes", sig.masked_bytes)?;
        rows.append(d)?;
    }
    Ok(rows.unbind())
}

/// Register the FLIRT bindings onto the existing `analysis` submodule.
///
/// Must run **after** `analysis::register_analysis_bindings`.
pub fn register_flirt_bindings(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    let analysis_mod = m.getattr("analysis")?;
    let analysis_mod = analysis_mod.downcast::<PyModule>()?;
    analysis_mod.add_function(wrap_pyfunction!(
        flirt_signatures_from_archive_path_py,
        analysis_mod
    )?)?;
    Ok(())
}
