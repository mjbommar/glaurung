//! Python bindings for the C source front end's Joern-parity CFGs.
//!
//! The consumer is `tools/source_cfg_parity.py`, which scores our CFG of a
//! stored decompiled `.c` against DecBench's published Joern CFG. That harness
//! wants `networkx` graphs, but nothing here knows about `networkx`: the Rust
//! side hands back plain lists and bools, and `python/glaurung/source_cfg.py`
//! does the adaptation. Keeping the boundary here means the extension imports
//! cleanly in an environment that has never installed a graph library.

use pyo3::prelude::*;
use pyo3::types::PyDict;

/// Every scoreable function CFG in one translation unit of C text.
///
/// Returns `{function name: {"nodes", "edges", "entry", "exit", "degenerate"}}`
/// -- the same five fields [`crate::csource::joern::ParityCfg::to_json`] writes,
/// in the shape DecBench's serialized source CFGs use, so a caller can pair the
/// two without a translation table.
///
/// Total on every input, matching [`crate::csource::joern::parity_cfgs`]: a
/// partly-recovered file yields the functions it did recover rather than
/// raising, because a front end that lost one function must not look like one
/// that lost the file.
#[pyfunction]
#[pyo3(name = "parity_cfgs")]
pub fn parity_cfgs_py<'py>(py: Python<'py>, text: &str) -> PyResult<Bound<'py, PyDict>> {
    // Parsing a preprocessed translation unit is milliseconds-to-seconds of
    // pure Rust with no Python object access, so it has no business holding
    // the GIL while the harness runs providers over a whole tree.
    let cfgs = py.detach(|| crate::csource::joern::parity_cfgs(text));

    let out = PyDict::new(py);
    for (name, cfg) in cfgs {
        let entry = PyDict::new(py);
        entry.set_item("nodes", cfg.nodes)?;
        entry.set_item("edges", cfg.edges)?;
        entry.set_item("entry", cfg.entry)?;
        entry.set_item("exit", cfg.exit)?;
        entry.set_item("degenerate", cfg.degenerate)?;
        out.set_item(name, entry)?;
    }
    Ok(out)
}

/// Whether DecBench scores a function of this name at all (F-15).
///
/// Exposed alongside the CFGs so a caller filtering its own name set uses the
/// same blacklist the export does, rather than reimplementing it in Python.
#[pyfunction]
#[pyo3(name = "is_scoreable_name")]
pub fn is_scoreable_name_py(name: &str) -> bool {
    crate::csource::joern::is_scoreable_name(name)
}

/// Register the `csource` submodule on the extension root.
pub fn register_source_cfg_bindings(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    let sub = PyModule::new(m.py(), "csource")?;
    sub.add_function(wrap_pyfunction!(parity_cfgs_py, &sub)?)?;
    sub.add_function(wrap_pyfunction!(is_scoreable_name_py, &sub)?)?;
    m.add_submodule(&sub)?;
    Ok(())
}
