//! Python bindings for Windows metadata extraction.

use pyo3::prelude::*;
use std::path::PathBuf;

#[pyfunction]
#[pyo3(name = "export_winmd_prototypes_json")]
pub fn export_winmd_prototypes_json_py(path: String) -> PyResult<String> {
    let export = crate::winmd::export_winmd_prototypes(&PathBuf::from(&path))
        .map_err(|err| pyo3::exceptions::PyValueError::new_err(format!("{err:#}")))?;
    serde_json::to_string(&export).map_err(|err| {
        pyo3::exceptions::PyValueError::new_err(format!(
            "failed to serialize WinMD prototype export: {err}"
        ))
    })
}

pub fn register_winmd_bindings(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    let sub = PyModule::new(m.py(), "winmd")?;
    sub.add_function(wrap_pyfunction!(export_winmd_prototypes_json_py, &sub)?)?;
    m.add_submodule(&sub)?;
    Ok(())
}
