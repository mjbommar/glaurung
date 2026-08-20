//! Python bindings for static unpacking.
//!
//! Two calls, kept separate because they answer different questions and one of
//! them keeps working when the other cannot:
//!
//! `describe_path`
//!     What the packer's own container says — original size, method, filter.
//!     Available on every UPX image, including ones we cannot decompress.
//! `unpack_path`
//!     The original bytes, verified against the checksum the packer recorded.
//!     Raises with a specific reason rather than returning an approximation.

use pyo3::prelude::*;

/// Register unpacking-related Python bindings.
pub fn register_unpack_bindings(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    let unpack_mod = pyo3::types::PyModule::new(py, "unpack")?;
    unpack_mod.add_function(wrap_pyfunction!(describe_path_py, &unpack_mod)?)?;
    unpack_mod.add_function(wrap_pyfunction!(unpack_path_py, &unpack_mod)?)?;
    m.add("unpack", &unpack_mod)?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("glaurung._native.unpack", &unpack_mod)?;
    Ok(())
}

fn read(path: &str) -> PyResult<Vec<u8>> {
    std::fs::read(path).map_err(|e| pyo3::exceptions::PyIOError::new_err(format!("{path}: {e}")))
}

/// What a packed image says about itself, without decompressing it.
///
/// Args:
///     path: file to inspect.
///
/// Returns:
///     A dict with `packer`, `original_size`, `method`, `filter`, `format`,
///     `version`, `level` and `block_size`, or `None` if the file is not a
///     packed image we recognise.
#[pyfunction]
#[pyo3(name = "describe_path")]
fn describe_path_py(py: Python<'_>, path: String) -> PyResult<Option<Py<PyAny>>> {
    let data = read(&path)?;
    let Ok(header) = crate::unpack::upx::parse_header(&data) else {
        return Ok(None);
    };
    let d = pyo3::types::PyDict::new(py);
    d.set_item("packer", "UPX")?;
    d.set_item("original_size", header.original_size)?;
    d.set_item("method", header.method)?;
    d.set_item("filter", header.filter)?;
    d.set_item("format", header.format)?;
    d.set_item("version", header.version)?;
    d.set_item("level", header.level)?;
    d.set_item("block_size", header.block_size)?;
    d.set_item("stub_size", header.stub_size)?;
    Ok(Some(d.into_any().unbind()))
}

/// Statically unpack a packed image, writing the original beside it.
///
/// Args:
///     path: the packed file.
///     out_path: where to write the recovered original; when omitted the bytes
///         are returned and nothing is written.
///
/// Returns:
///     A dict with `packer`, `original_entry`, `blocks`, `size` and — when
///     `out_path` was not given — `bytes`.
///
/// Raises:
///     ValueError: the image is packed but could not be recovered, with the
///         specific reason. Never returns an unverified approximation.
///     LookupError: the file is not a packed image we recognise.
#[pyfunction]
#[pyo3(name = "unpack_path")]
#[pyo3(signature = (path, out_path=None))]
fn unpack_path_py(py: Python<'_>, path: String, out_path: Option<String>) -> PyResult<Py<PyAny>> {
    let data = read(&path)?;
    let recovered = match crate::unpack::recover(&data) {
        Ok(Some(r)) => r,
        Ok(None) => {
            return Err(pyo3::exceptions::PyLookupError::new_err(format!(
                "{path}: not a packed image this build recognises"
            )))
        }
        Err(failure) => {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "{path}: packed with {} but not unpacked: {}",
                failure.packer, failure.reason
            )))
        }
    };
    let d = pyo3::types::PyDict::new(py);
    d.set_item("packer", recovered.packer)?;
    d.set_item("original_entry", recovered.original_entry)?;
    d.set_item("blocks", recovered.blocks)?;
    d.set_item("size", recovered.bytes.len())?;
    match out_path {
        Some(out) => {
            std::fs::write(&out, &recovered.bytes)
                .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!("{out}: {e}")))?;
            d.set_item("written_to", out)?;
        }
        None => {
            d.set_item("bytes", pyo3::types::PyBytes::new(py, &recovered.bytes))?;
        }
    }
    Ok(d.into_any().unbind())
}
