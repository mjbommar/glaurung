//! Python bindings for `crate::identity`: the function-identity ladder.
//!
//! Everything here lands on the existing `glaurung.analysis` submodule rather
//! than a new one. The identity schemes are consumed alongside
//! `analyze_functions_path`, by the same callers, and a second submodule would
//! only make the import line longer.
//!
//! # Section ownership
//!
//! This file is shared between the four identity lanes (`structural`, `warp`,
//! `cfr`, `rerank`). Each keeps its additions inside its own clearly marked
//! section, and
//! [`register_identity_bindings`] registers each section's items in its own
//! block, so two lanes adding functions at once is a trivial merge rather than
//! a conflict in the middle of a function body.

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

/// Register the CFR (L2) additions on `analysis_mod`.
fn register_cfr(analysis_mod: &Bound<'_, PyModule>) -> PyResult<()> {
    analysis_mod.add_class::<CfrSignature>()?;
    analysis_mod.add_function(wrap_pyfunction!(cfr_signatures_path, analysis_mod)?)?;
    analysis_mod.add_function(wrap_pyfunction!(cfr_similarity, analysis_mod)?)?;
    analysis_mod.add_function(wrap_pyfunction!(cfr_distance, analysis_mod)?)?;
    analysis_mod.add("CFR_SCHEME", crate::identity::cfr::CFR_SCHEME)?;
    Ok(())
}

// ===========================================================================
// SECTION: rerank -- owned by the identity/rerank lane
// ===========================================================================

/// Re-rank per-function candidate lists using call-graph and library context.
///
/// The RevDecode decode (`glaurung::identity::rerank`, USENIX Security 2025):
/// a Viterbi pass over a layered graph whose layers are the query binary's
/// unknown functions and whose nodes are each function's top-K candidates. It
/// is **not a matcher** -- it takes candidate lists some other scheme produced
/// and returns better-ordered ones, so every identifier below is an opaque
/// integer the caller assigns.
///
/// Args:
///     queries: One entry per unknown function, as
///         ``(query_id, order_key, [(reference_id, similarity), ...])``.
///         ``order_key`` fixes the layer order -- pass the entry VA, which is
///         what the paper orders on. ``similarity`` must be in ``[0, 1]``.
///     query_calls: ``(caller_query_id, callee_query_id)`` pairs in the query
///         binary. A missing edge is *no evidence*, never evidence against, so
///         an incomplete call graph degrades the result rather than corrupting
///         it.
///     reference_calls: the same, between reference-corpus functions.
///     reference_groups: ``(reference_id, group_id)``. A group is a library, a
///         package or any partition whose members a compiler would emit
///         together. A reference function with no group earns no adjacency
///         reward and no library score.
///     top_k: candidates per layer. Ties at the boundary are all admitted.
///     similarity_weight, confidence_weight, library_weight, adjacency_weight,
///         call_weight: per-term weights on the edge.
///     adjacency_same_group: the reward for two candidates from one library.
///         RevDecode Alg. 1's constant.
///     no_match_similarity: the score a candidate must beat to outrank "no
///         match", or ``None`` to leave that node out.
///     sigmoid: re-spread the similarities through a logistic before they enter
///         the weight. The paper does this; our similarities are already in
///         ``[0, 1]``, so it is off by default.
///
/// Returns:
///     One ``(query_id, [(reference_id, score), ...])`` per query, best first.
///     A ``reference_id`` of ``None`` is the "no match" node: candidates below
///     it have less contextual support than an empty answer.
///
/// The defaults are the **measured** configuration, not the paper's:
/// ``adjacency_weight`` and ``library_weight`` are ``0.0``. Both terms are the
/// paper's own and both are implemented; they are off because in the sweep
/// behind ``docs/reference/function-identity-rerank.md`` they moved 8 of 40
/// measured cells up and 31 down, by as much as 0.225 MRR10, while the
/// call-graph term moved 16 up, 0 down, and cost no query a rank in any of
/// them. Pass ``adjacency_weight=1.0,
/// library_weight=1.0`` to reproduce RevDecode's own configuration -- and read
/// that table before doing so.
#[pyfunction]
#[pyo3(name = "rerank_candidates")]
#[pyo3(signature = (
    queries,
    query_calls = Vec::new(),
    reference_calls = Vec::new(),
    reference_groups = Vec::new(),
    top_k = 10usize,
    similarity_weight = 1.0,
    confidence_weight = 1.0,
    library_weight = 0.0,
    adjacency_weight = 0.0,
    call_weight = 1.0,
    adjacency_same_group = 0.7,
    no_match_similarity = Some(0.0),
    sigmoid = None,
))]
#[allow(clippy::too_many_arguments)]
fn rerank_candidates(
    queries: Vec<(u32, u64, Vec<(u32, f64)>)>,
    query_calls: Vec<(u32, u32)>,
    reference_calls: Vec<(u32, u32)>,
    reference_groups: Vec<(u32, u32)>,
    top_k: usize,
    similarity_weight: f64,
    confidence_weight: f64,
    library_weight: f64,
    adjacency_weight: f64,
    call_weight: f64,
    adjacency_same_group: f64,
    no_match_similarity: Option<f64>,
    sigmoid: Option<(f64, f64)>,
) -> Vec<(u32, Vec<(Option<u32>, f64)>)> {
    use crate::identity::rerank;

    let layered: Vec<rerank::QueryFunction> = queries
        .into_iter()
        .map(|(id, order_key, candidates)| rerank::QueryFunction {
            id,
            order_key,
            candidates: candidates
                .into_iter()
                .map(|(reference, similarity)| rerank::Candidate::new(reference, similarity))
                .collect(),
        })
        .collect();

    let mut context = rerank::CallContext::new();
    for (caller, callee) in query_calls {
        context.add_query_call(caller, callee);
    }
    for (caller, callee) in reference_calls {
        context.add_reference_call(caller, callee);
    }
    for (reference, group) in reference_groups {
        context.set_reference_group(reference, group);
    }

    let settings = rerank::RerankSettings {
        top_k,
        similarity_weight,
        confidence_weight,
        library_weight,
        adjacency_weight,
        call_weight,
        adjacency_same_group,
        no_match_similarity,
        normalization: match sigmoid {
            Some((centre, steepness)) => rerank::Normalization::Sigmoid { centre, steepness },
            None => rerank::Normalization::Identity,
        },
    };

    rerank::rerank(&layered, &context, &settings)
        .layers
        .into_iter()
        .map(|layer| {
            (
                layer.query,
                layer
                    .ranked
                    .into_iter()
                    .map(|c| (c.reference, c.score))
                    .collect(),
            )
        })
        .collect()
}

/// Register the re-rank post-pass on `analysis_mod`.
fn register_rerank(analysis_mod: &Bound<'_, PyModule>) -> PyResult<()> {
    analysis_mod.add_function(wrap_pyfunction!(rerank_candidates, analysis_mod)?)?;
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
    register_rerank(&analysis_mod)?;
    Ok(())
}
