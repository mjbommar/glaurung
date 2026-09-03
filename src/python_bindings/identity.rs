//! Python bindings for `crate::identity`: the function-identity ladder.
//!
//! Everything here lands on the existing `glaurung.analysis` submodule rather
//! than a new one. The identity schemes are consumed alongside
//! `analyze_functions_path`, by the same callers, and a second submodule would
//! only make the import line longer.
//!
//! # Section ownership
//!
//! This file is shared between the identity lanes (`structural`, `warp`,
//! `cfr`, `gate`, `values`). Each keeps its additions inside its own clearly
//! marked section, and [`register_identity_bindings`] registers each section's
//! items in its own block, so two lanes adding functions at once is a trivial
//! merge rather than a conflict in the middle of a function body.

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};

// ===========================================================================
// SECTION: structural (L1) -- owned by the identity/structural lane
// ===========================================================================

use crate::identity::structural::{
    ranking_similarity, structural_signatures, StructuralSignature as RustStructuralSignature,
    SCHEME as STRUCTURAL_SCHEME,
};

/// Structural invariants of one function: the L1 rung of the identity ladder.
///
/// Every field is read-only. A signature is a measurement of the bytes, not an
/// annotation on them, so there is no setter and no `set_by` anywhere near it;
/// recomputing must overwrite, and mutating one in place would produce a row
/// that claims to describe a function it no longer describes.
///
/// The formulas are documented on the Rust type
/// (`crate::identity::structural::StructuralSignature`) and, for an analyst,
/// in `docs/reference/function-identity-structural.md`.
#[pyclass(name = "StructuralSignature", module = "glaurung.analysis", frozen)]
#[derive(Clone)]
pub struct PyStructuralSignature {
    inner: RustStructuralSignature,
}

#[pymethods]
impl PyStructuralSignature {
    /// Entry virtual address of the function this describes.
    #[getter]
    fn entry_va(&self) -> u64 {
        self.inner.entry_va
    }

    /// The discoverer's name for the function.
    #[getter]
    fn name(&self) -> &str {
        &self.inner.name
    }

    /// BinDiff MD-index with BFS levels taken from the entry block.
    #[getter]
    fn md_index_top_down(&self) -> f64 {
        self.inner.md_index_top_down
    }

    /// BinDiff MD-index with BFS levels taken from the exit blocks.
    #[getter]
    fn md_index_bottom_up(&self) -> f64 {
        self.inner.md_index_bottom_up
    }

    /// BinDiff MD-index with weights `{2,3,5,7,0,0}`, so levels drop out.
    #[getter]
    fn md_index_relaxed(&self) -> f64 {
        self.inner.md_index_relaxed
    }

    /// Small Primes Product over normalized mnemonics, modulo `2**64`.
    #[getter]
    fn mnemonic_spp(&self) -> u64 {
        self.inner.mnemonic_spp
    }

    /// Basic blocks in the recovered CFG.
    #[getter]
    fn basic_blocks(&self) -> u32 {
        self.inner.basic_blocks
    }

    /// Distinct control-flow edges.
    #[getter]
    fn edges(&self) -> u32 {
        self.inner.edges
    }

    /// Edges whose target dominates their source.
    #[getter]
    fn back_edges(&self) -> u32 {
        self.inner.back_edges
    }

    /// Distinct natural-loop headers.
    #[getter]
    fn loops(&self) -> u32 {
        self.inner.loops
    }

    /// Strongly connected components, trivial ones included.
    #[getter]
    fn strongly_connected_components(&self) -> u32 {
        self.inner.strongly_connected_components
    }

    /// McCabe complexity, `E - N + 2`.
    #[getter]
    fn cyclomatic_complexity(&self) -> u32 {
        self.inner.cyclomatic_complexity
    }

    /// Instructions decoded across the function's blocks.
    #[getter]
    fn instructions(&self) -> u32 {
        self.inner.instructions
    }

    /// Calls whose target is an immediate operand.
    #[getter]
    fn calls_out_direct(&self) -> u32 {
        self.inner.calls_out_direct
    }

    /// Calls through a register or memory operand.
    #[getter]
    fn calls_out_indirect(&self) -> u32 {
        self.inner.calls_out_indirect
    }

    /// Distinct callers, per the call graph. Zero when none was computed.
    #[getter]
    fn callers_in(&self) -> u32 {
        self.inner.callers_in
    }

    /// Large non-address constants, ascending, with multiplicity.
    #[getter]
    fn rare_constants(&self) -> Vec<u64> {
        self.inner.rare_constants.clone()
    }

    /// Distinct referenced addresses holding a NUL-terminated printable run.
    #[getter]
    fn string_refs(&self) -> u32 {
        self.inner.string_refs
    }

    /// Blocks absorbed into cycles: `basic_blocks - strongly_connected_components`.
    #[getter]
    fn cyclic_blocks(&self) -> u32 {
        self.inner.cyclic_blocks()
    }

    /// Every field as a plain dict, keyed by the attribute name.
    ///
    /// The key set is the column set of the KB's `function_structural` table,
    /// in the same order, so a writer can build its parameter tuple straight
    /// from this without a second mapping to keep in sync.
    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let d = PyDict::new(py);
        d.set_item("entry_va", self.inner.entry_va)?;
        d.set_item("name", &self.inner.name)?;
        d.set_item("md_index_top_down", self.inner.md_index_top_down)?;
        d.set_item("md_index_bottom_up", self.inner.md_index_bottom_up)?;
        d.set_item("md_index_relaxed", self.inner.md_index_relaxed)?;
        d.set_item("mnemonic_spp", self.inner.mnemonic_spp)?;
        d.set_item("basic_blocks", self.inner.basic_blocks)?;
        d.set_item("edges", self.inner.edges)?;
        d.set_item("back_edges", self.inner.back_edges)?;
        d.set_item("loops", self.inner.loops)?;
        d.set_item(
            "strongly_connected_components",
            self.inner.strongly_connected_components,
        )?;
        d.set_item("cyclomatic_complexity", self.inner.cyclomatic_complexity)?;
        d.set_item("instructions", self.inner.instructions)?;
        d.set_item("calls_out_direct", self.inner.calls_out_direct)?;
        d.set_item("calls_out_indirect", self.inner.calls_out_indirect)?;
        d.set_item("callers_in", self.inner.callers_in)?;
        d.set_item("string_refs", self.inner.string_refs)?;
        d.set_item("rare_constants", self.inner.rare_constants.clone())?;
        Ok(d)
    }

    fn __repr__(&self) -> String {
        format!(
            "StructuralSignature(name={:?}, entry_va={:#x}, blocks={}, edges={}, md={:.6})",
            self.inner.name,
            self.inner.entry_va,
            self.inner.basic_blocks,
            self.inner.edges,
            self.inner.md_index_top_down,
        )
    }
}

/// Compute an L1 structural signature for every function discovered in `path`.
///
/// The budget keywords are exactly `analyze_functions_path`'s and mean the same
/// things; the defaults are widened for `max_blocks`, `max_instructions` and
/// `timeout_ms` because a truncated CFG produces a signature that silently
/// describes a smaller function than the one on disk. A caller that wants
/// discovery's own defaults should pass them explicitly.
///
/// Returns the signatures sorted by entry address.
#[pyfunction]
#[pyo3(name = "structural_signatures_path")]
#[pyo3(signature = (
    path,
    max_read_bytes = 104_857_600u64,
    max_file_size = 104_857_600u64,
    max_functions = 0usize,
    max_blocks = 8192usize,
    max_instructions = 500_000usize,
    timeout_ms = 5_000u64,
    total_timeout_ms = 0u64,
))]
#[allow(clippy::too_many_arguments)]
fn structural_signatures_path_py(
    py: Python<'_>,
    path: String,
    max_read_bytes: u64,
    max_file_size: u64,
    max_functions: usize,
    max_blocks: usize,
    max_instructions: usize,
    timeout_ms: u64,
    total_timeout_ms: u64,
) -> PyResult<Vec<PyStructuralSignature>> {
    let limit = std::cmp::min(max_read_bytes, max_file_size);
    let data = crate::triage::io::IOUtils::read_file_with_limit(&path, limit)
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!("{:?}", e)))?;
    let budgets = crate::analysis::cfg::Budgets {
        max_functions,
        max_blocks,
        max_instructions,
        timeout_ms,
        total_timeout_ms,
    };
    // Discovery plus a full re-decode of every function is long enough that
    // holding the GIL would freeze the calling interpreter; nothing crossing
    // into the closure is GIL-bound.
    let signatures = py.detach(|| {
        let (funcs, cg) = crate::analysis::cfg::analyze_functions_bytes(&data, &budgets);
        structural_signatures(&data, &funcs, Some(&cg))
    });
    Ok(signatures
        .into_iter()
        .map(|inner| PyStructuralSignature { inner })
        .collect())
}

/// Rank how alike two structural signatures are, in `[0.0, 1.0]`.
///
/// BinDiff's count blend and MD-index agreement, plus a mnemonic-SPP and a
/// rare-constant term. The weights and the reasoning are on the Rust function
/// `crate::identity::structural::ranking_similarity`. Symmetric, 1.0 against
/// itself, and **not** a metric -- do not use it as an index distance.
#[pyfunction]
#[pyo3(name = "structural_ranking_similarity")]
fn structural_ranking_similarity_py(a: &PyStructuralSignature, b: &PyStructuralSignature) -> f64 {
    ranking_similarity(&a.inner, &b.inner)
}

/// Register the structural (L1) additions on `analysis_mod`.
fn register_structural(analysis_mod: &Bound<'_, PyModule>) -> PyResult<()> {
    analysis_mod.add_class::<PyStructuralSignature>()?;
    analysis_mod.add_function(wrap_pyfunction!(
        structural_signatures_path_py,
        analysis_mod
    )?)?;
    analysis_mod.add_function(wrap_pyfunction!(
        structural_ranking_similarity_py,
        analysis_mod
    )?)?;
    analysis_mod.add("STRUCTURAL_SCHEME", STRUCTURAL_SCHEME)?;
    Ok(())
}

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

/// Register the WARP (L0) additions on `analysis_mod`.
fn register_warp(analysis_mod: &Bound<'_, PyModule>) -> PyResult<()> {
    analysis_mod.add_class::<PyWarpFunction>()?;
    analysis_mod.add_class::<PyWarpConstraint>()?;
    analysis_mod.add_function(wrap_pyfunction!(warp_function_guids_path_py, analysis_mod)?)?;
    analysis_mod.add_function(wrap_pyfunction!(warp_scheme_py, analysis_mod)?)?;
    Ok(())
}

// ===========================================================================
// SECTION: cfr (L2) -- owned by the identity/cfr lane
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
    /// Rebuild a signature from a stored `(feature_hash, count)` list.
    ///
    /// This is the index side of the boundary: `feature_vector.features` in a
    /// `.glaurung` project holds exactly this list, and a stored vector has to
    /// come back as a real signature to be scored by the same code that scores
    /// a freshly computed one. The positional facts a computed signature
    /// carries -- `entry_va`, `name`, `block_count`, `instruction_count`, the
    /// width census -- are not in the vector and are **not** invented here;
    /// they read back as zero and `None`. The vector, the digest and the
    /// version triple are complete, which is everything the metric consumes.
    ///
    /// Args:
    ///     features: `(feature_hash, count)` pairs. Order and duplicates do
    ///         not matter: they are re-sorted and re-counted, which is also
    ///         what makes the digest independent of how the caller stored them.
    ///     nosize: The CFR setting the features were computed under. Part of
    ///         the version triple, so getting it wrong produces a signature
    ///         that compares 0.0 against everything rather than one that
    ///         silently compares wrongly.
    ///     normalize: Whether the peephole normaliser was on when the features
    ///         were computed. The other bit of the version triple, and it
    ///         fails the same way: a normalised vector reconstructed as a
    ///         plain one compares 0.0 against every plain signature in the
    ///         corpus and against every normalised one too.
    #[staticmethod]
    #[pyo3(signature = (features, nosize=false, normalize=false))]
    fn from_features(features: Vec<(u32, u16)>, nosize: bool, normalize: bool) -> Self {
        let version = crate::identity::cfr::CfrVersion::current(
            crate::identity::cfr::CfrSettings { nosize, normalize },
        );
        let mut raw: Vec<u32> = Vec::new();
        for (feature, count) in features {
            for _ in 0..count.max(1) {
                raw.push(feature);
            }
        }
        let inner = crate::identity::cfr::CfrSignature::from_features(version, &raw);
        CfrSignature {
            entry_va: 0,
            name: None,
            block_count: 0,
            instruction_count: 0,
            width_total: 0,
            width_unknown: 0,
            version: (version.major, version.minor, version.settings),
            features: inner.features.clone(),
            digest: inner.identity(),
            scheme: crate::identity::cfr::CFR_SCHEME.to_string(),
            inner,
        }
    }

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
    ///
    /// `weights` is a :class:`CfrWeights` corpus table, or `None` for the
    /// uniform weighting every published unweighted CFR number was measured
    /// under.
    #[pyo3(signature = (other, weights=None))]
    fn cosine(&self, other: &CfrSignature, weights: Option<&CfrWeights>) -> f64 {
        crate::identity::cfr::cosine(&self.inner, &other.inner, weights_arg(weights))
    }

    /// The induced distance `sqrt(k(a,a) + k(b,b) - 2 k(a,b))`.
    #[pyo3(signature = (other, weights=None))]
    fn distance(&self, other: &CfrSignature, weights: Option<&CfrWeights>) -> f64 {
        crate::identity::cfr::distance(&self.inner, &other.inner, weights_arg(weights))
    }

    /// BSim's significance ("Confidence" in Ghidra's UI) against another
    /// signature.
    ///
    /// Open-ended and negative for a poor match. Bounded above by
    /// :meth:`self_significance`, which is roughly proportional to size, so a
    /// small function cannot reach a confident score however well it matches.
    #[pyo3(signature = (other, weights=None))]
    fn significance(&self, other: &CfrSignature, weights: Option<&CfrWeights>) -> f64 {
        crate::identity::cfr::significance(&self.inner, &other.inner, weights_arg(weights))
    }

    /// The largest significance any match to this signature could reach.
    #[pyo3(signature = (weights=None))]
    fn self_significance(&self, weights: Option<&CfrWeights>) -> f64 {
        crate::identity::cfr::self_significance(&self.inner, weights_arg(weights))
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

/// A frozen corpus TF-IDF table over CFR features.
///
/// Built from the signatures of a corpus with
/// :func:`cfr_build_weights`, or rebuilt from stored rows with
/// :meth:`CfrWeights.from_entries`. Immutable once built: a weight that changed
/// under a caller would change every score computed against it, and the
/// `weights_id` would then name a table that no longer exists.
///
/// Pass one to `cfr_similarity`, `cfr_distance` or `cfr_confidence` to weight
/// the comparison; pass `None` for the uniform weighting every published
/// unweighted CFR number was measured under.
#[pyclass(module = "glaurung.analysis", name = "CfrWeights", frozen)]
#[derive(Clone)]
pub struct CfrWeights {
    inner: crate::identity::cfr::CorpusWeights,
}

#[pymethods]
impl CfrWeights {
    /// Rebuild a weight table from its stored `feature_weight` entries.
    ///
    /// `entries` is `[(feature_hash, doc_count), ...]`; the weights are
    /// recomputed from `documents` rather than trusted from the caller, so a
    /// table read back out of a database cannot disagree with one built from
    /// the corpus it was counted over.
    ///
    /// Args:
    ///     documents: Functions counted into the table -- the ``N`` in
    ///         ``ln((N + 1) / (df + 1))``.
    ///     entries: ``(feature_hash, doc_count)`` pairs.
    ///     nosize: The CFR setting the counted signatures were computed under.
    ///         Part of the table's identity: a table counted over ``nosize``
    ///         signatures must not weight plain ones.
    ///     normalize: Whether the counted signatures were computed with the
    ///         peephole normaliser on. Also part of the table's identity, and
    ///         for a sharper reason than ``nosize``: normalisation changes the
    ///         feature vocabulary, so a table counted over plain vectors
    ///         weights features the normalised representation does not
    ///         produce.
    #[staticmethod]
    #[pyo3(signature = (documents, entries, nosize=false, normalize=false))]
    fn from_entries(
        documents: u64,
        entries: Vec<(u32, u64)>,
        nosize: bool,
        normalize: bool,
    ) -> Self {
        let version = crate::identity::cfr::CfrVersion::current(
            crate::identity::cfr::CfrSettings { nosize, normalize },
        );
        let rows = entries
            .into_iter()
            .map(|(feature, doc_count)| {
                (
                    feature,
                    crate::identity::cfr::FeatureWeight {
                        doc_count,
                        bucket: crate::identity::cfr::weights::quantise(
                            crate::identity::cfr::weights::raw_idf(documents, doc_count),
                        ),
                    },
                )
            })
            .collect();
        CfrWeights {
            inner: crate::identity::cfr::CorpusWeights::from_parts(version, documents, rows),
        }
    }

    /// The stable name of this table.
    ///
    /// Changes whenever the CFR version, the quantisation parameters, the
    /// corpus size or any single weight changes, which is what makes it safe to
    /// key stored scores on.
    #[getter]
    fn weights_id(&self) -> &str {
        self.inner.weights_id()
    }

    /// Functions counted into the table.
    #[getter]
    fn documents(&self) -> u64 {
        self.inner.documents()
    }

    /// The CFR `(major, minor, settings)` triple the table was counted under.
    #[getter]
    fn version(&self) -> (u16, u16, u32) {
        let version = self.inner.version();
        (version.major, version.minor, version.settings)
    }

    /// The weight an unlisted feature gets: the largest the corpus can express.
    #[getter]
    fn max_idf(&self) -> f64 {
        self.inner.unlisted_weight()
    }

    /// Distinct features the table carries a weight for.
    fn __len__(&self) -> usize {
        self.inner.len()
    }

    /// The weight of one feature, in nats.
    fn idf(&self, feature: u32) -> f64 {
        use crate::identity::cfr::Weights as _;
        self.inner.idf(feature)
    }

    /// Every row, ascending by feature hash, as
    /// `(feature_hash, doc_count, weight)`.
    ///
    /// This is the order the `feature_weight` KB table wants and the order the
    /// `weights_id` is hashed in.
    fn entries(&self) -> Vec<(u32, u64, f64)> {
        self.inner
            .iter()
            .map(|(hash, row)| (hash, row.doc_count, row.weight()))
            .collect()
    }

    fn __repr__(&self) -> String {
        format!(
            "CfrWeights(weights_id='{}', documents={}, features={})",
            self.inner.weights_id(),
            self.inner.documents(),
            self.inner.len()
        )
    }
}

/// Count a corpus of signatures into a TF-IDF weight table.
///
/// Args:
///     signatures: The corpus. Signatures whose version is not comparable with
///         the first one's are refused rather than counted, so a list that
///         mixes ``nosize`` and plain signatures does not silently produce a
///         table that is wrong for both.
///     min_doc_count: Features seen in fewer functions than this are left
///         *out* of the table rather than given a weight. Leaving one out is
///         not the same as zeroing it: an absent feature falls through to the
///         corpus maximum, which is the right answer for something the corpus
///         saw once.
///     nosize: The CFR setting the corpus was computed under.
///     normalize: Whether the corpus was computed with the peephole normaliser
///         on. A table counted over one representation must not weight the
///         other; this is the bit that says which.
///
/// Returns:
///     The frozen table.
#[pyfunction]
#[pyo3(name = "cfr_build_weights")]
#[pyo3(signature = (signatures, min_doc_count=1u64, nosize=false, normalize=false))]
fn cfr_build_weights(
    signatures: Vec<PyRef<'_, CfrSignature>>,
    min_doc_count: u64,
    nosize: bool,
    normalize: bool,
) -> CfrWeights {
    let version = crate::identity::cfr::CfrVersion::current(
        crate::identity::cfr::CfrSettings { nosize, normalize },
    );
    let mut builder = crate::identity::cfr::WeightsBuilder::new(version);
    for signature in &signatures {
        builder.observe(&signature.inner);
    }
    CfrWeights {
        inner: builder.build(min_doc_count),
    }
}

/// Compute a CFR signature for every discovered function in `path`.
///
/// `nosize` collapses every width class of four bytes and up, which is the one
/// switch that lets a 32-bit build match its 64-bit sibling. It is part of the
/// version triple, so signatures computed with it are not comparable with
/// signatures computed without it.
///
/// `normalize` runs the unsound local peephole normaliser
/// (`src/identity/cfr/normalize/`) over a **copy** of each lifted function
/// before hashing: opcode collapse, constant folding and copy propagation,
/// local CSE, dead-store and redundant-write elimination, comparison-polarity
/// canonicalisation and strength-reduction canonical forms. It closes part of
/// the cross-optimisation gap and is off by default. Like `nosize` it is a bit
/// in the version triple, so a normalised signature answers `0.0` against an
/// unnormalised one rather than a low score. Nothing it computes reaches the
/// decompiler.
///
/// The remaining arguments are the ordinary function-discovery budgets, spelled
/// the same way `analyze_functions_path` spells them -- with one deliberate
/// difference. `timeout_ms` is a *wall clock* on one function's block walk, and
/// `analyze_functions_path` defaults it to 100. A wall clock inside an identity
/// function means the digest of a binary depends on how busy the machine was:
/// a truncated discovery is a different graph, and the failure is silent. So the
/// default here is effectively no ceiling. A caller who would rather have a
/// bounded answer than a reproducible one passes a real number and gets one.
#[pyfunction]
#[pyo3(name = "cfr_signatures_path")]
#[pyo3(signature = (path, nosize=false, normalize=false, max_functions=0usize, max_blocks=2048usize, max_instructions=50000usize, timeout_ms=3_600_000u64, total_timeout_ms=0u64))]
fn cfr_signatures_path(
    path: String,
    nosize: bool,
    normalize: bool,
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
    let settings = crate::identity::cfr::CfrSettings { nosize, normalize };
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
#[pyo3(signature = (a, b, weights=None))]
fn cfr_similarity(a: &CfrSignature, b: &CfrSignature, weights: Option<&CfrWeights>) -> f64 {
    crate::identity::cfr::cosine(&a.inner, &b.inner, weights_arg(weights))
}

/// The metric distance between two CFR signatures.
///
/// `sqrt(k(a,a) + k(b,b) - 2 k(a,b))` over the positive semi-definite
/// Weisfeiler-Lehman kernel, so it obeys the triangle inequality exactly and can
/// index a corpus. Unlike the cosine it is not bounded, and it grows with the
/// size of the functions involved.
#[pyfunction]
#[pyo3(name = "cfr_distance")]
#[pyo3(signature = (a, b, weights=None))]
fn cfr_distance(a: &CfrSignature, b: &CfrSignature, weights: Option<&CfrWeights>) -> f64 {
    crate::identity::cfr::distance(&a.inner, &b.inner, weights_arg(weights))
}

/// The cosine and BSim's significance together, which is how a match should be
/// reported: neither number answers the question on its own.
///
/// Returns a dict with `cosine`, `significance`, `self_significance`,
/// `saturation` (the fraction of the available significance this match used)
/// and `false_positive_one_in` -- the last of which is `None` below BSim's
/// lowest published anchor, where Ghidra's own help page says the
/// correspondence between a confidence score and a false-positive rate does not
/// hold.
#[pyfunction]
#[pyo3(name = "cfr_confidence")]
#[pyo3(signature = (a, b, weights=None))]
fn cfr_confidence<'py>(
    py: Python<'py>,
    a: &CfrSignature,
    b: &CfrSignature,
    weights: Option<&CfrWeights>,
) -> PyResult<Bound<'py, PyDict>> {
    let confidence = crate::identity::cfr::confidence(&a.inner, &b.inner, weights_arg(weights));
    let out = PyDict::new(py);
    out.set_item("cosine", confidence.cosine)?;
    out.set_item("significance", confidence.significance)?;
    out.set_item("self_significance", confidence.self_significance)?;
    out.set_item("saturation", confidence.saturation())?;
    out.set_item("is_confident", confidence.is_confident())?;
    out.set_item("false_positive_one_in", confidence.false_positive_one_in())?;
    Ok(out)
}

/// Borrow a Python weight table as the Rust trait object the metric takes.
fn weights_arg(weights: Option<&CfrWeights>) -> Option<&dyn crate::identity::cfr::Weights> {
    weights.map(|w| &w.inner as &dyn crate::identity::cfr::Weights)
}

/// Register the CFR (L2) additions on `analysis_mod`.
fn register_cfr(analysis_mod: &Bound<'_, PyModule>) -> PyResult<()> {
    analysis_mod.add_class::<CfrSignature>()?;
    analysis_mod.add_class::<CfrWeights>()?;
    analysis_mod.add_function(wrap_pyfunction!(cfr_signatures_path, analysis_mod)?)?;
    analysis_mod.add_function(wrap_pyfunction!(cfr_similarity, analysis_mod)?)?;
    analysis_mod.add_function(wrap_pyfunction!(cfr_distance, analysis_mod)?)?;
    analysis_mod.add_function(wrap_pyfunction!(cfr_confidence, analysis_mod)?)?;
    analysis_mod.add_function(wrap_pyfunction!(cfr_build_weights, analysis_mod)?)?;
    analysis_mod.add("CFR_SCHEME", crate::identity::cfr::CFR_SCHEME)?;
    analysis_mod.add(
        "CFR_CONFIDENT_SIGNIFICANCE",
        crate::identity::cfr::CONFIDENT_SIGNIFICANCE,
    )?;
    Ok(())
}

// ===========================================================================
// SECTION: gate -- the BinaryFuse8 membership gate (src/identity/gate.rs)
// ===========================================================================

use pyo3::types::PyBytes;

/// Build a serialized BinaryFuse8 membership gate over `identities`.
///
/// This is `identity_filter.filter` in
/// `docs/history/program-measures-2026-09-02/03-schema.sql` section 7: one
/// gate per `(scheme, architecture)`, built from every identity string a
/// scheme produces (a `siglib_function.identity` column, or a survey's whole
/// computed set). Duplicate strings are removed before construction.
///
/// Args:
///     identities: The identity strings to build the gate from. Must be
///         non-empty.
///
/// Returns:
///     The serialized gate, in the format [`identity_gate_contains`] and
///     `glaurung.analysis.identity_gate_n_keys` read: an 8-byte key count,
///     then the xorf descriptor, then the fingerprint bytes.
///
/// Raises:
///     ValueError: `identities` is empty, or xorf's construction failed
///         (in practice, a `u64` hash collision between two distinct
///         identity strings -- astronomically unlikely at any corpus size
///         this project will reach).
#[pyfunction]
#[pyo3(name = "identity_gate_build", signature = (identities))]
fn identity_gate_build_py<'py>(
    py: Python<'py>,
    identities: Vec<String>,
) -> PyResult<Bound<'py, PyBytes>> {
    let gate = py
        .detach(|| crate::identity::gate::IdentityGate::build(identities))
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
    Ok(PyBytes::new(py, &gate.to_bytes()))
}

/// Query a serialized gate for `identity`, without copying its fingerprint
/// bytes.
///
/// `False` is definitive: `identity` is not present in the set the gate was
/// built from, and no exact or masked lookup is needed. `True` means "go do
/// the real lookup" -- BinaryFuse8's published false-positive rate is under
/// 0.4%, so a hit is not a match by itself.
///
/// Args:
///     blob: A gate produced by [`identity_gate_build`].
///     identity: The identity string to test.
///
/// Returns:
///     Whether `identity` might be a member.
///
/// Raises:
///     ValueError: `blob` is shorter than a valid gate can be.
#[pyfunction]
#[pyo3(name = "identity_gate_contains", signature = (blob, identity))]
fn identity_gate_contains_py(blob: &[u8], identity: &str) -> PyResult<bool> {
    let view = crate::identity::gate::IdentityGateRef::from_bytes(blob)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
    Ok(view.contains(identity))
}

/// The number of distinct identities `blob` was built from, read from the
/// gate's own header rather than recomputed.
///
/// Raises:
///     ValueError: `blob` is shorter than a valid gate can be.
#[pyfunction]
#[pyo3(name = "identity_gate_n_keys", signature = (blob))]
fn identity_gate_n_keys_py(blob: &[u8]) -> PyResult<usize> {
    let view = crate::identity::gate::IdentityGateRef::from_bytes(blob)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
    Ok(view.n_keys())
}

/// Register the membership-gate additions on `analysis_mod`.
fn register_gate(analysis_mod: &Bound<'_, PyModule>) -> PyResult<()> {
    analysis_mod.add_function(wrap_pyfunction!(identity_gate_build_py, analysis_mod)?)?;
    analysis_mod.add_function(wrap_pyfunction!(identity_gate_contains_py, analysis_mod)?)?;
    analysis_mod.add_function(wrap_pyfunction!(identity_gate_n_keys_py, analysis_mod)?)?;
    analysis_mod.add("IDENTITY_GATE_KIND", crate::identity::gate::KIND)?;
    Ok(())
}

// ===========================================================================
// SECTION: values (L3) -- owned by the identity/values lane
//
// `python-ext` implies `exec`, so this section needs no feature gate of its
// own; `crate::identity::values` is always present in a build that has PyO3.
// ===========================================================================

/// One function's value fingerprint: the multiset of numbers it computes.
///
/// `values` is the sorted `(element, count)` list. For an ordinary computed
/// value the element **is** the number, sign-extended to 64 bits and read as
/// two's complement, so a fingerprint is readable rather than opaque: an
/// element of `0xffffffffffffffff` is the integer -1. Branch-condition
/// elements are hashed into a high band and are not readable that way.
///
/// `version` is the `(major, minor, settings)` triple; two fingerprints with
/// different majors or different settings describe different quotients and
/// must not be compared, which `value_similarity` enforces by answering 0.0.
#[pyclass(module = "glaurung.analysis", name = "ValueFingerprint")]
#[derive(Clone)]
pub struct ValueFingerprint {
    /// Entry virtual address of the function.
    #[pyo3(get)]
    pub entry_va: u64,
    /// Symbol name where the image has one. Never part of the fingerprint.
    #[pyo3(get)]
    pub name: Option<String>,
    #[pyo3(get)]
    pub block_count: usize,
    #[pyo3(get)]
    pub instruction_count: usize,
    /// Instructions retired across every seed's run.
    #[pyo3(get)]
    pub steps: u64,
    /// How many of the runs reached a return.
    #[pyo3(get)]
    pub returned_runs: u8,
    /// How many exhausted the instruction budget.
    #[pyo3(get)]
    pub budget_exhausted_runs: u8,
    /// True when every run hit the budget *and* nothing survived the filters:
    /// the coverage failure worth counting separately from a short run.
    #[pyo3(get)]
    pub starved: bool,
    /// Values the filters removed as addresses (rules F1 to F4).
    #[pyo3(get)]
    pub addresses_filtered: usize,
    /// `(major, minor, settings)`.
    #[pyo3(get)]
    pub version: (u16, u16, u32),
    /// Sorted `(element, occurrence count)` pairs.
    #[pyo3(get)]
    pub values: Vec<(u64, u32)>,
    /// Hex BLAKE3 digest over the version triple and the element list.
    #[pyo3(get)]
    pub digest: String,
    /// The `function_identity` scheme name this digest belongs to.
    #[pyo3(get)]
    pub scheme: String,
    inner: crate::identity::values::ValueFingerprint,
}

#[pymethods]
impl ValueFingerprint {
    fn __repr__(&self) -> String {
        format!(
            "ValueFingerprint(entry_va={:#x}, name='{}', values={}, digest={}...)",
            self.entry_va,
            self.name.as_deref().unwrap_or("<unnamed>"),
            self.values.len(),
            &self.digest[..16.min(self.digest.len())]
        )
    }

    /// Total element occurrences, counts included.
    fn total_count(&self) -> u64 {
        self.inner.total_count()
    }

    /// vSim's Equation 2: weighted Jaccard over the element sets, in `[0, 1]`.
    fn similarity(&self, other: &ValueFingerprint) -> f64 {
        crate::identity::values::weighted_jaccard_set(&self.inner, &other.inner, None)
    }

    /// The multiset form, which uses the occurrence counts.
    fn similarity_with_counts(&self, other: &ValueFingerprint) -> f64 {
        crate::identity::values::weighted_jaccard(&self.inner, &other.inner, None)
    }

    /// The induced metric distance, `1 - J_w` over the multiset form.
    fn distance(&self, other: &ValueFingerprint) -> f64 {
        crate::identity::values::distance(&self.inner, &other.inner, None)
    }
}

impl From<crate::identity::values::FunctionValues> for ValueFingerprint {
    fn from(entry: crate::identity::values::FunctionValues) -> Self {
        let version = entry.fingerprint.version;
        ValueFingerprint {
            entry_va: entry.entry_va,
            name: entry.name,
            block_count: entry.block_count,
            instruction_count: entry.instruction_count,
            steps: entry.stats.steps,
            returned_runs: entry.stats.returned,
            budget_exhausted_runs: entry.stats.budget_exhausted,
            starved: entry.stats.budget_exhausted_before_any_value,
            addresses_filtered: entry.stats.filter.addresses_removed(),
            version: (version.major, version.minor, version.settings),
            values: entry.fingerprint.values.clone(),
            digest: entry.fingerprint.identity(),
            scheme: crate::identity::values::VALUE_SCHEME.to_string(),
            inner: entry.fingerprint,
        }
    }
}

/// Compute a value fingerprint for every discovered function in `path`.
///
/// The function is run under `seeds` fixed initial states, each bounded by
/// `max_steps` retired LLIR instructions; every register write and memory
/// store is recorded, the addresses are filtered out, and what is left is
/// normalised to width-free signed integers.
///
/// `site_cap` bounds how many distinct values one instruction may contribute
/// per run, which is what keeps a long loop from drowning the fingerprint.
/// `filter` turns the address rules off (the published ablation); `branch_conditions`
/// drops the `(comparison, constant)` elements; `role_seeds` gives each
/// uninitialised register its own trial value instead of the one the run
/// shares. All six are part of the version triple, so a fingerprint computed
/// under different settings answers 0.0 against one computed under these.
///
/// **x86-64 only.** The interpreter this drives has an x86-64 register file;
/// anything else raises rather than producing a fingerprint over a register
/// file that does not match the code.
///
/// The remaining arguments are the function-discovery budgets, spelled as
/// `cfr_signatures_path` spells them and defaulted the same way: `timeout_ms`
/// is a wall clock on one function's block walk, and a wall clock inside an
/// identity function means the digest depends on how busy the machine was.
#[pyfunction]
#[pyo3(name = "value_fingerprints_path")]
#[pyo3(signature = (path, seeds=3u8, max_steps=20_000u32, site_cap=4u8, filter=true, branch_conditions=true, role_seeds=false, max_functions=0usize, max_blocks=2048usize, max_instructions=50000usize, timeout_ms=3_600_000u64, total_timeout_ms=0u64))]
#[allow(clippy::too_many_arguments)]
fn value_fingerprints_path(
    path: String,
    seeds: u8,
    max_steps: u32,
    site_cap: u8,
    filter: bool,
    branch_conditions: bool,
    role_seeds: bool,
    max_functions: usize,
    max_blocks: usize,
    max_instructions: usize,
    timeout_ms: u64,
    total_timeout_ms: u64,
) -> PyResult<Vec<ValueFingerprint>> {
    let budgets = crate::analysis::cfg::Budgets {
        max_functions,
        max_blocks,
        max_instructions,
        timeout_ms,
        total_timeout_ms,
    };
    let settings = crate::identity::values::ValueSettings {
        seeds,
        max_steps,
        site_cap,
        filter,
        branch_conditions,
        role_seeds,
    };
    let rows = crate::identity::values::fingerprints_for_path(
        std::path::Path::new(&path),
        settings,
        &budgets,
    )
    .map_err(|error| pyo3::exceptions::PyValueError::new_err(error.to_string()))?;
    Ok(rows.into_iter().map(ValueFingerprint::from).collect())
}

/// Weighted Jaccard similarity between two value fingerprints, in `[0, 1]`.
///
/// vSim's Equation 2, over the element sets. `0.0` when the two were computed
/// under incomparable settings, when either is empty, or when they share no
/// element -- deliberately the same answer, because an unanswerable comparison
/// and a comparison with no evidence are both "no".
#[pyfunction]
#[pyo3(name = "value_similarity")]
fn value_similarity(a: &ValueFingerprint, b: &ValueFingerprint) -> f64 {
    crate::identity::values::weighted_jaccard_set(&a.inner, &b.inner, None)
}

/// The metric distance between two value fingerprints, `1 - J_w`.
///
/// The Ruzicka distance over the weighted multisets: symmetric, zero exactly
/// on equal fingerprints, and obeying the triangle inequality, so it can index
/// a corpus.
#[pyfunction]
#[pyo3(name = "value_distance")]
fn value_distance(a: &ValueFingerprint, b: &ValueFingerprint) -> f64 {
    crate::identity::values::distance(&a.inner, &b.inner, None)
}

/// Register the value-fingerprint (L3) additions on `analysis_mod`.
fn register_values(analysis_mod: &Bound<'_, PyModule>) -> PyResult<()> {
    analysis_mod.add_class::<ValueFingerprint>()?;
    analysis_mod.add_function(wrap_pyfunction!(value_fingerprints_path, analysis_mod)?)?;
    analysis_mod.add_function(wrap_pyfunction!(value_similarity, analysis_mod)?)?;
    analysis_mod.add_function(wrap_pyfunction!(value_distance, analysis_mod)?)?;
    analysis_mod.add("VALUE_SCHEME", crate::identity::values::VALUE_SCHEME)?;
    Ok(())
}

// ===========================================================================
// SECTION: registration
// ===========================================================================

/// Attach every identity binding to the already-registered `analysis` submodule.
///
/// Must run after `analysis::register_analysis_bindings`, which is what creates
/// and attaches that submodule; `register_python_bindings` orders them.
pub fn register_identity_bindings(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    let analysis_mod = m.getattr("analysis")?.downcast_into::<PyModule>()?;
    register_structural(&analysis_mod)?;
    register_warp(&analysis_mod)?;
    register_cfr(&analysis_mod)?;
    register_gate(&analysis_mod)?;
    register_values(&analysis_mod)?;
    Ok(())
}
