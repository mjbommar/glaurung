//! Python bindings for `crate::identity`: content-derived function identity.
//!
//! Everything here lands on the existing `glaurung.analysis` submodule rather
//! than a new one, because that is where a caller already looks for "tell me
//! about the functions in this file".
//!
//! # File layout
//!
//! Three identity schemes are built on separate lanes and each owns a section
//! of this file, delimited by the banner comments below. Add to your own
//! section; do not interleave.

use pyo3::prelude::*;
use pyo3::types::PyModule;

/// Attach every identity binding to the `analysis` submodule of `m`.
///
/// Must run after [`crate::python_bindings::analysis::register_analysis_bindings`],
/// which is what creates that submodule. Fetching it back rather than creating a
/// second one keeps `glaurung.analysis` a single namespace: two `PyModule::new`
/// calls with the same name produce two unrelated objects, and the second
/// `add_submodule` silently wins.
pub fn register_identity_bindings(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    let analysis = m.getattr("analysis")?;
    let analysis = analysis.downcast::<PyModule>().map_err(|_| {
        pyo3::exceptions::PyRuntimeError::new_err(
            "glaurung.analysis is not a module; identity bindings must be \
             registered after register_analysis_bindings",
        )
    })?;

    // --- begin CFR section (lane: identity/cfr) ---------------------------
    analysis.add_class::<CfrSignature>()?;
    analysis.add_function(wrap_pyfunction!(cfr_signatures_path, analysis)?)?;
    analysis.add_function(wrap_pyfunction!(cfr_similarity, analysis)?)?;
    analysis.add_function(wrap_pyfunction!(cfr_distance, analysis)?)?;
    analysis.add("CFR_SCHEME", crate::identity::cfr::CFR_SCHEME)?;
    // --- end CFR section ---------------------------------------------------

    // --- begin structural section (lane: identity/structural) --------------
    // --- end structural section --------------------------------------------

    // --- begin WARP section (lane: identity/warp) --------------------------
    // --- end WARP section --------------------------------------------------

    Ok(())
}

// ===========================================================================
// begin CFR section (lane: identity/cfr)
// ===========================================================================

/// One function's Canonical Function Representation.
///
/// The `features` list is the sorted `(hash, count)` multiset; `digest` is its
/// hex identity, which is what the `function_identity` table stores under
/// `scheme`. `version` is the `(major, minor, settings)` triple: two signatures
/// with different majors or different settings describe different quotients and
/// must not be compared, which `cfr_similarity` enforces by answering 0.0.
#[pyclass(module = "glaurung.analysis", name = "CfrSignature")]
#[derive(Clone)]
pub struct CfrSignature {
    /// Entry virtual address of the function.
    #[pyo3(get)]
    pub entry_va: u64,
    /// Symbol name where the image has one. Never part of the signature.
    #[pyo3(get)]
    pub name: Option<String>,
    #[pyo3(get)]
    pub block_count: usize,
    #[pyo3(get)]
    pub instruction_count: usize,
    /// SSA values the width pass examined.
    #[pyo3(get)]
    pub width_total: usize,
    /// Of those, the ones left without a derived width.
    #[pyo3(get)]
    pub width_unknown: usize,
    /// `(major, minor, settings)`.
    #[pyo3(get)]
    pub version: (u16, u16, u32),
    /// Sorted `(feature hash, occurrence count)` pairs.
    #[pyo3(get)]
    pub features: Vec<(u32, u16)>,
    /// Hex BLAKE3 digest over the version triple and the feature list.
    #[pyo3(get)]
    pub digest: String,
    /// The `function_identity` scheme name this digest belongs to.
    #[pyo3(get)]
    pub scheme: String,
    inner: crate::identity::cfr::CfrSignature,
}

#[pymethods]
impl CfrSignature {
    fn __repr__(&self) -> String {
        format!(
            "CfrSignature(entry_va={:#x}, name='{}', blocks={}, features={}, \
             digest={}...)",
            self.entry_va,
            self.name.as_deref().unwrap_or("<unnamed>"),
            self.block_count,
            self.features.len(),
            &self.digest[..16.min(self.digest.len())]
        )
    }

    /// Total feature occurrences: a size proxy, and the reason a tiny function
    /// cannot reach a confident match.
    fn total_count(&self) -> u64 {
        self.inner.total_count()
    }

    /// Weighted cosine against another signature, in `[0, 1]`.
    fn cosine(&self, other: &CfrSignature) -> f64 {
        crate::identity::cfr::cosine(&self.inner, &other.inner, None)
    }

    /// The induced distance `sqrt(k(a,a) + k(b,b) - 2 k(a,b))`.
    fn distance(&self, other: &CfrSignature) -> f64 {
        crate::identity::cfr::distance(&self.inner, &other.inner, None)
    }
}

impl From<crate::identity::cfr::FunctionCfr> for CfrSignature {
    fn from(entry: crate::identity::cfr::FunctionCfr) -> Self {
        let version = entry.signature.version;
        CfrSignature {
            entry_va: entry.entry_va,
            name: entry.name,
            block_count: entry.block_count,
            instruction_count: entry.instruction_count,
            width_total: entry.width_census.total,
            width_unknown: entry.width_census.unknown,
            version: (version.major, version.minor, version.settings),
            features: entry.signature.features.clone(),
            digest: entry.signature.identity(),
            scheme: crate::identity::cfr::CFR_SCHEME.to_string(),
            inner: entry.signature,
        }
    }
}

/// Compute a CFR signature for every discovered function in `path`.
///
/// `nosize` collapses every width class of four bytes and up, which is the one
/// switch that lets a 32-bit build match its 64-bit sibling. It is part of the
/// version triple, so signatures computed with it are not comparable with
/// signatures computed without it.
///
/// The remaining arguments are the ordinary function-discovery budgets, spelled
/// the same way `analyze_functions_path` spells them.
#[pyfunction]
#[pyo3(name = "cfr_signatures_path")]
#[pyo3(signature = (path, nosize=false, max_functions=0usize, max_blocks=2048usize, max_instructions=50000usize, timeout_ms=100u64, total_timeout_ms=0u64))]
fn cfr_signatures_path(
    path: String,
    nosize: bool,
    max_functions: usize,
    max_blocks: usize,
    max_instructions: usize,
    timeout_ms: u64,
    total_timeout_ms: u64,
) -> PyResult<Vec<CfrSignature>> {
    let budgets = crate::analysis::cfg::Budgets {
        max_functions,
        max_blocks,
        max_instructions,
        timeout_ms,
        total_timeout_ms,
    };
    let settings = crate::identity::cfr::CfrSettings { nosize };
    let signatures =
        crate::identity::cfr::signatures_for_path(std::path::Path::new(&path), settings, &budgets)
            .map_err(|error| pyo3::exceptions::PyValueError::new_err(error.to_string()))?;
    Ok(signatures.into_iter().map(CfrSignature::from).collect())
}

/// Weighted cosine similarity between two CFR signatures, in `[0, 1]`.
///
/// `0.0` when the two were computed under incomparable versions, when either is
/// empty, or when they share no feature. That is deliberately the same answer:
/// an unanswerable comparison and a comparison with no evidence are both "no",
/// and neither should read as "distant but related".
#[pyfunction]
#[pyo3(name = "cfr_similarity")]
fn cfr_similarity(a: &CfrSignature, b: &CfrSignature) -> f64 {
    crate::identity::cfr::cosine(&a.inner, &b.inner, None)
}

/// The metric distance between two CFR signatures.
///
/// `sqrt(k(a,a) + k(b,b) - 2 k(a,b))` over the positive semi-definite
/// Weisfeiler-Lehman kernel, so it obeys the triangle inequality exactly and can
/// index a corpus. Unlike the cosine it is not bounded, and it grows with the
/// size of the functions involved.
#[pyfunction]
#[pyo3(name = "cfr_distance")]
fn cfr_distance(a: &CfrSignature, b: &CfrSignature) -> f64 {
    crate::identity::cfr::distance(&a.inner, &b.inner, None)
}

// ===========================================================================
// end CFR section
// ===========================================================================
