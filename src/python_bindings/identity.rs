//! Python bindings for `crate::identity` -- the function-identity schemes.
//!
//! Each scheme in `src/identity/` answers a different "what is this function?"
//! question and writes a row into the `.glaurung` project's
//! `function_identity(scheme, identity)` table. This file is the one Python
//! entry point for all of them, so the schemes stay independent in Rust and
//! arrive in Python under one namespace.
//!
//! The functions are added to the existing `glaurung.analysis` submodule
//! rather than a new one: the callers are analysis callers, and
//! `analyze_functions_path` already lives there.
//!
//! # Section layout
//!
//! Each scheme owns a delimited section below and does not reach into another
//! one. Adding a scheme means adding a section and one `add_function` line in
//! [`register_identity_bindings`].

use pyo3::prelude::*;
use pyo3::types::PyList;

// ===========================================================================
// SECTION: warp -- WARP-compatible function GUIDs (src/identity/warp.rs)
// ===========================================================================

/// One WARP constraint: a GUID, an optional signed offset, and what it means.
#[pyclass(name = "WarpConstraint", module = "glaurung.analysis", frozen)]
#[derive(Clone)]
pub struct PyWarpConstraint {
    /// The constraint GUID, as a lowercase hyphenated UUID string.
    #[pyo3(get)]
    pub guid: String,
    /// Signed byte offset relative to the constrained function's entry, or
    /// `None` where no offset is meaningful (WARP's "unrelated").
    #[pyo3(get)]
    pub offset: Option<i64>,
    /// `"callee"`, `"caller"` or `"adjacent"`.
    #[pyo3(get)]
    pub kind: String,
    /// The name the constraint was derived from, when one was known. Never
    /// part of the GUID -- a stripped build must agree with a symbolised one.
    #[pyo3(get)]
    pub label: Option<String>,
}

#[pymethods]
impl PyWarpConstraint {
    fn __repr__(&self) -> String {
        match self.offset {
            Some(off) => format!("WarpConstraint({}, {}, {off:+})", self.kind, self.guid),
            None => format!("WarpConstraint({}, {}, unrelated)", self.kind, self.guid),
        }
    }
}

/// One function's WARP identity.
#[pyclass(name = "WarpFunction", module = "glaurung.analysis", frozen)]
#[derive(Clone)]
pub struct PyWarpFunction {
    /// The function GUID, as a lowercase hyphenated UUID string. This is the
    /// value written into `function_identity` under scheme
    /// `warp-function-guid-v1`.
    #[pyo3(get)]
    pub guid: String,
    /// The entry VA the identity was computed at. A label, not part of the
    /// identity.
    #[pyo3(get)]
    pub entry_va: u64,
    /// The name discovery gave the function.
    #[pyo3(get)]
    pub name: String,
    /// Block GUIDs in the order they were hashed: highest start VA first.
    #[pyo3(get)]
    pub block_guids: Vec<String>,
    /// Callee, caller and adjacency constraints.
    #[pyo3(get)]
    pub constraints: Vec<PyWarpConstraint>,
}

#[pymethods]
impl PyWarpFunction {
    fn __repr__(&self) -> String {
        format!(
            "WarpFunction({} at {:#x}, {} blocks, {} constraints)",
            self.guid,
            self.entry_va,
            self.block_guids.len(),
            self.constraints.len()
        )
    }
}

/// Compute a WARP-compatible GUID for every function discovered in `path`.
///
/// Args:
///     path: Path to an executable or object file.
///
/// Returns:
///     A list of :class:`WarpFunction`, sorted by entry VA.
///
/// Raises:
///     OSError: the file cannot be read.
///     ValueError: the file is not a parseable object, or its architecture has
///         no relocatable-instruction rule yet (x86 and x86-64 only today).
#[pyfunction]
#[pyo3(name = "warp_function_guids_path", signature = (path))]
fn warp_function_guids_path_py(py: Python<'_>, path: &str) -> PyResult<Py<PyList>> {
    let data = std::fs::read(path)?;
    let functions = py
        .detach(|| crate::identity::warp::warp_functions_from_bytes(&data))
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
    let rows: Vec<PyWarpFunction> = functions
        .into_iter()
        .map(|f| PyWarpFunction {
            guid: f.guid.to_string(),
            entry_va: f.entry_va,
            name: f.name,
            block_guids: f.blocks.iter().map(|b| b.guid.to_string()).collect(),
            constraints: f
                .constraints
                .into_iter()
                .map(|c| PyWarpConstraint {
                    guid: c.guid.to_string(),
                    offset: c.offset,
                    kind: c.kind.as_str().to_string(),
                    label: c.label,
                })
                .collect(),
        })
        .collect();
    PyList::new(py, rows).map(|l| l.unbind())
}

/// The `scheme` string WARP identities are stored under.
#[pyfunction]
#[pyo3(name = "warp_scheme")]
fn warp_scheme_py() -> &'static str {
    crate::identity::warp::SCHEME
}

// ===========================================================================
// END SECTION: warp
// ===========================================================================

/// Register the identity bindings onto the existing `analysis` submodule.
///
/// Must run **after** `analysis::register_analysis_bindings`, which is what
/// creates and attaches that submodule.
pub fn register_identity_bindings(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    let analysis_mod = m.getattr("analysis")?;
    let analysis_mod = analysis_mod.downcast::<PyModule>()?;

    analysis_mod.add_class::<PyWarpFunction>()?;
    analysis_mod.add_class::<PyWarpConstraint>()?;
    analysis_mod.add_function(wrap_pyfunction!(warp_function_guids_path_py, analysis_mod)?)?;
    analysis_mod.add_function(wrap_pyfunction!(warp_scheme_py, analysis_mod)?)?;

    Ok(())
}
