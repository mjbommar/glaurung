//! Python bindings for the native decompiler-quality metrics.
//!
//! [`crate::metrics`] holds three metrics that were built against DecBench's
//! Python reference and validated case-for-case against it: `type_match`
//! (T-3/T-6/T-7), `byte_match` (B-5..B-8) and the control-skeleton tree
//! distance. Until this module existed none of them could be called from
//! Python, so every harness that wanted one --- `tools/metric_stratify.py`,
//! `tools/metric_mutation.py`, `tools/source_cfg_parity.py` --- imported the
//! reference implementation instead. A metric nobody can call is not coverage.
//!
//! The boundary is the one [`crate::python_bindings::source_cfg`] draws, for
//! the same reason: Rust hands back plain lists, dicts, floats and `None`, and
//! nothing Python-shaped is ever passed *into* `src/metrics/`. The metric code
//! is a validated port; it must stay callable, testable and diffable against
//! the reference without a Python interpreter anywhere near it.
//!
//! Two invariants of [`crate::metrics`] are load-bearing at this boundary and
//! are reproduced here deliberately.
//!
//! * **An abstention is `None`, never `0.0`.** `tree_edit_distance` abstains
//!   above [`crate::metrics::tree_distance::MAX_SKELETON_NODES`] and
//!   `score_lines`/`diff_lines` abstain above
//!   [`crate::metrics::byte_match::MAX_DIFF_LINES`]. Both surface as Python
//!   `None`. Collapsing either into a score would put a made-up number into a
//!   shared denominator, which is the rot `docs/design/metrics-research/` was
//!   written to prevent. A capstone failure, by contrast, is a real error and
//!   raises.
//! * **Determinism.** Every collection returned here comes from a `Vec` or a
//!   `BTreeMap`, so no hash iteration order reaches Python and repeated calls
//!   on the same input produce byte-identical output.

use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyDict;

use crate::metrics::byte_match::{self, AsmTarget, DiffOp};
use crate::metrics::tree_distance as td;
use crate::metrics::type_match::{self as tm, DecompiledVar, GroundTruthVar};

// --- tree distance ----------------------------------------------------------

/// One function's control skeleton, opaque and immutable.
///
/// Opaque because the skeleton is an *input* to a distance, not a report: the
/// Zhang--Shasha DP reads post-order kinds, leftmost-leaf indexes and keyroots
/// together, and a caller that rebuilt one field at a time in Python could
/// hand back a triple that is not a tree. Building it here once and passing
/// the handle around also means an `n`-way comparison parses each side once
/// rather than `n` times, which is what a stratified report over a corpus
/// actually does.
///
/// Immutable (`frozen`) for the same reason a
/// [`crate::python_bindings::identity::PyStructuralSignature`] is: it is a
/// measurement of a text, and a mutated one would claim to describe source it
/// no longer describes.
#[pyclass(name = "Skeleton", module = "glaurung._native.metrics", frozen)]
#[derive(Clone)]
pub struct PySkeleton {
    inner: td::Skeleton,
}

#[pymethods]
impl PySkeleton {
    /// Node count --- the denominator of [`skeleton_score_py`] on the source
    /// side.
    fn __len__(&self) -> usize {
        self.inner.len()
    }

    /// The deepest nesting reached, in nodes.
    ///
    /// Reported rather than used: it is the factor that bounds the keyroot
    /// count and therefore the distance's runtime, so a harness that wants to
    /// know why one cell was slow can read it.
    #[getter]
    fn depth(&self) -> u32 {
        self.inner.depth()
    }

    /// How many Zhang--Shasha keyroots the skeleton has.
    #[getter]
    fn keyroot_count(&self) -> usize {
        self.inner.keyroot_count()
    }

    /// Whether the projection hit its step budget and stopped early.
    ///
    /// Exposed because a truncated skeleton still yields a distance, and a
    /// caller aggregating over a corpus has to be able to exclude one rather
    /// than discovering later that a number came from half a function.
    #[getter]
    fn truncated(&self) -> bool {
        self.inner.truncated()
    }

    /// Whether the skeleton contains no control flow.
    ///
    /// This is the 27%-of-corpus class every CFG-derived metric collapses into
    /// a single value (`docs/design/metrics-research/what-ged-measures.md`),
    /// and the reason this metric exists, so selecting it must not require
    /// re-deriving "branchless" in Python from a rendered string.
    #[getter]
    fn is_branchless(&self) -> bool {
        self.inner.is_branchless()
    }

    /// The node kinds in post-order, by name.
    fn kinds(&self) -> Vec<&'static str> {
        self.inner.kinds().iter().map(|k| k.name()).collect()
    }

    /// How many nodes of each kind the skeleton has, kinds in discriminant
    /// order.
    ///
    /// From a `BTreeMap`, so the insertion order of the returned dict is
    /// stable across runs and machines.
    fn census<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let out = PyDict::new(py);
        for (kind, count) in self.inner.census() {
            out.set_item(kind.name(), count)?;
        }
        Ok(out)
    }

    /// The skeleton as a parenthesised expression, root first --- `(if (then
    /// return))`.
    ///
    /// The reviewable form, and the one every Rust test expectation in
    /// [`crate::metrics::tree_distance`] is written in, so a Python-side
    /// expectation can be written the same way and compared by eye.
    fn render(&self) -> String {
        self.inner.render()
    }

    /// Structural equality: same kinds in the same shape.
    fn __eq__(&self, other: &Self) -> bool {
        self.inner == other.inner
    }

    /// Consistent with [`PySkeleton::__eq__`]: equal skeletons render
    /// identically, so hashing the rendering cannot separate them.
    fn __hash__(&self) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        self.inner.render().hash(&mut hasher);
        hasher.finish()
    }

    fn __repr__(&self) -> String {
        format!(
            "Skeleton(nodes={}, depth={}, branchless={})",
            self.inner.len(),
            self.inner.depth(),
            self.inner.is_branchless()
        )
    }
}

/// Project every function definition in a C translation unit onto its control
/// skeleton, by name.
///
/// Returns `{function name: Skeleton}`. Total on every input, like
/// [`crate::csource::joern::parity_cfgs`]: a file the front end only partly
/// recovered yields the functions it did recover rather than raising, and a
/// file with two definitions of one name keeps the last --- the same rule the
/// parity CFGs use, so the two maps have the same keys for the same input and
/// a caller can pair them without a translation table.
#[pyfunction]
#[pyo3(name = "skeletons")]
pub fn skeletons_py<'py>(py: Python<'py>, text: &str) -> PyResult<Bound<'py, PyDict>> {
    // Parsing plus projection is pure Rust over a borrowed `str` with no
    // Python object access, and a corpus run does it tens of thousands of
    // times; there is no reason for it to hold the interpreter.
    let projected = py.detach(|| td::skeletons(text));

    let out = PyDict::new(py);
    for (name, skeleton) in projected {
        out.set_item(name, PySkeleton { inner: skeleton })?;
    }
    Ok(out)
}

/// The ordered tree edit distance between two control skeletons, or `None`
/// when either exceeds `MAX_SKELETON_NODES`.
///
/// Zhang--Shasha with unit costs. Zero exactly on identical trees, symmetric,
/// and triangle-obeying.
///
/// `None` is an **abstention**, not a zero: the pair was too large to score,
/// which is a different fact from "the trees are maximally far apart" and must
/// stay distinguishable in whatever the caller aggregates.
#[pyfunction]
#[pyo3(name = "tree_edit_distance")]
pub fn tree_edit_distance_py(py: Python<'_>, a: &PySkeleton, b: &PySkeleton) -> Option<u32> {
    py.detach(|| td::tree_edit_distance(&a.inner, &b.inner))
}

/// `1 - TED / len(source)`, clamped to `[0, 1]`, or `None` when the distance
/// abstained.
///
/// The denominator is the **source** skeleton deliberately: one that included
/// the decompiled side could be inflated by emitting more code. The clamp is
/// where the honesty is --- a decompiled skeleton more than twice the source's
/// size saturates at `0.0`, so the raw distance from
/// [`tree_edit_distance_py`] should be published beside this number rather
/// than instead of it.
#[pyfunction]
#[pyo3(name = "skeleton_score")]
pub fn skeleton_score_py(
    py: Python<'_>,
    source: &PySkeleton,
    decompiled: &PySkeleton,
) -> Option<f64> {
    py.detach(|| td::skeleton_score(&source.inner, &decompiled.inner))
}

// --- byte match -------------------------------------------------------------

/// The five capstone targets `byte_match` disassembles with, by name.
///
/// A closed set of names rather than raw capstone constants at the Python
/// boundary, because [`AsmTarget`] is itself deliberately closed: the
/// reference selects its AL-zeroing peephole by comparing the whole
/// `(arch, mode)` tuple, so a caller must not be able to invent a sixth
/// combination here that the reference never produced.
fn parse_target(target: &str) -> PyResult<AsmTarget> {
    match target {
        "x86_32" => Ok(AsmTarget::X86_32),
        "x86_64" => Ok(AsmTarget::X86_64),
        "arm" => Ok(AsmTarget::Arm),
        "arm_thumb" => Ok(AsmTarget::ArmThumb),
        "arm64" => Ok(AsmTarget::Arm64),
        other => Err(PyValueError::new_err(format!(
            "unknown asm target {other:?}; expected one of \
             'x86_32', 'x86_64', 'arm', 'arm_thumb', 'arm64'"
        ))),
    }
}

/// The name [`parse_target`] accepts for a target.
fn target_name(target: AsmTarget) -> &'static str {
    match target {
        AsmTarget::X86_32 => "x86_32",
        AsmTarget::X86_64 => "x86_64",
        AsmTarget::Arm => "arm",
        AsmTarget::ArmThumb => "arm_thumb",
        AsmTarget::Arm64 => "arm64",
    }
}

/// Disassemble `data` at `address` into normalized assembly lines (B-5).
///
/// `target` is one of `'x86_32'`, `'x86_64'`, `'arm'`, `'arm_thumb'`,
/// `'arm64'`. Each surviving instruction becomes `"{mnemonic} {normalized
/// operands}"`; `nop` is dropped at every width, and on `x86_64` only, an
/// `al`-zeroing instruction immediately before a `call` is dropped.
///
/// Decoding stops at the first byte capstone cannot decode --- a truncated
/// listing, not an error, which is capstone's own behaviour and the
/// reference's. A capstone *failure* (it would not open the decoder, or it
/// rejected the buffer) raises `RuntimeError`: unlike an over-cap diff, that
/// is not an abstention but a broken call, and returning an empty listing for
/// it would score as "the function disassembles to nothing".
#[pyfunction]
#[pyo3(name = "disassemble_lines")]
#[pyo3(signature = (data, address, target))]
pub fn disassemble_lines_py(
    py: Python<'_>,
    data: &[u8],
    address: u64,
    target: &str,
) -> PyResult<Vec<String>> {
    let target = parse_target(target)?;
    py.detach(|| byte_match::disassemble_lines(data, address, target))
        .map_err(|e| PyRuntimeError::new_err(e.to_string()))
}

/// The capstone `(CS_ARCH_*, CS_MODE_*)` constants a target name corresponds
/// to.
///
/// Exposed so a harness replaying a recorded DecBench cell --- which stores
/// those two integers verbatim --- addresses the same target this module
/// disassembles with, instead of maintaining a second copy of the mapping.
#[pyfunction]
#[pyo3(name = "capstone_ids")]
pub fn capstone_ids_py(target: &str) -> PyResult<(u32, u32)> {
    Ok(parse_target(target)?.capstone_ids())
}

/// The target name for a pair of capstone constants, or `None` for a pair
/// DecBench's `binfmt.capstone_arch_mode` never returns.
///
/// The inverse of [`capstone_ids_py`], and `None` rather than an exception
/// because "this recorded cell is on an architecture we do not score" is an
/// ordinary answer when sweeping a corpus.
#[pyfunction]
#[pyo3(name = "asm_target")]
pub fn asm_target_py(arch: u32, mode: u32) -> Option<&'static str> {
    AsmTarget::from_capstone_ids(arch, mode).map(target_name)
}

/// Normalize one instruction's operand text, which is what B-6 specifies.
///
/// PC-relative memory references collapse to `[reg+X]` and branch/PC-relative
/// immediates blank to `X`, so that a function's listing does not differ from
/// its recompilation merely because the two landed at different addresses.
/// Exposed for harnesses that already hold a disassembly and need only the
/// normalization half.
#[pyfunction]
#[pyo3(name = "normalize_operands")]
pub fn normalize_operands_py(mnemonic: &str, op_str: &str) -> String {
    byte_match::normalize_operands(mnemonic, op_str)
}

/// Score two normalized assembly listings (B-8).
///
/// Returns `{'similarity', 'changed_lines', 'a_only', 'shared', 'b_only'}`, or
/// `None` when the pair exceeds `MAX_DIFF_LINES` or the diff exhausts its
/// work budget.
///
/// `similarity` is `shared / (a_only + shared + b_only)`: the denominator is
/// `len(a) + len(b) - shared` rather than `max(len(a), len(b))`, so a short
/// answer against a long function is punished by its shortness as well as by
/// its wrongness. Two empty listings score `1.0` --- that is the reference's
/// first branch, reproduced deliberately.
///
/// `None` is an abstention. A caller must leave it out of a mean rather than
/// counting it as `0.0`, or the denominator stops being shared.
#[pyfunction]
#[pyo3(name = "score_lines")]
pub fn score_lines_py<'py>(
    py: Python<'py>,
    a: Vec<String>,
    b: Vec<String>,
) -> PyResult<Option<Bound<'py, PyDict>>> {
    // Both listings are copied out of Python while the GIL is held, then the
    // Myers diff runs without it: on the corpus this is milliseconds per pair
    // and thousands of pairs per report.
    let scored = py.detach(|| byte_match::score_lines(&a, &b));

    let Some(score) = scored else {
        return Ok(None);
    };
    let out = PyDict::new(py);
    out.set_item("similarity", score.similarity)?;
    out.set_item("changed_lines", score.changed_lines)?;
    out.set_item("a_only", score.diff.a_only)?;
    out.set_item("shared", score.diff.shared)?;
    out.set_item("b_only", score.diff.b_only)?;
    Ok(Some(out))
}

/// Diff two normalized assembly listings into runs (B-7).
///
/// Returns `[(op, length), ...]` in document order, where `op` is `'delete'`
/// (in `a` only), `'equal'` or `'insert'` (in `b` only), or `None` on the same
/// abstention as [`score_lines_py`].
///
/// Only run lengths are carried, not the lines: B-8 needs counts, and keeping
/// the text would double the memory of a diff over a 4,500-line function for
/// no consumer.
#[pyfunction]
#[pyo3(name = "diff_lines")]
pub fn diff_lines_py(
    py: Python<'_>,
    a: Vec<String>,
    b: Vec<String>,
) -> Option<Vec<(&'static str, usize)>> {
    let chunks = py.detach(|| byte_match::diff_lines(&a, &b))?;
    Some(
        chunks
            .into_iter()
            .map(|chunk| {
                let op = match chunk.op {
                    DiffOp::Delete => "delete",
                    DiffOp::Equal => "equal",
                    DiffOp::Insert => "insert",
                };
                (op, chunk.len)
            })
            .collect(),
    )
}

// --- type match -------------------------------------------------------------

/// One ground-truth variable: what the debug information says the source
/// really declared.
///
/// `types` must already be normalized --- build it with
/// [`ground_truth_forms_py`]. The reference normalizes the ground-truth side
/// **once, by the producer**, over possibly several DWARF spellings of one
/// type, and takes their union; that union is not the output of any single
/// normalization call, so it cannot be recomputed here from a raw spelling
/// without changing what is matched.
#[pyclass(name = "GroundTruthVar", module = "glaurung._native.metrics", frozen)]
#[derive(Clone)]
pub struct PyGroundTruthVar {
    inner: GroundTruthVar,
}

#[pymethods]
impl PyGroundTruthVar {
    /// Build one ground-truth variable.
    ///
    /// Args mirror the reference's ground-truth dict exactly, minus its
    /// redundant `is_arg` flag: `arg_index` being present *is* `is_arg`.
    #[new]
    #[pyo3(signature = (name, types, rbp_offsets, size, arg_index=None))]
    fn new(
        name: String,
        types: Vec<String>,
        rbp_offsets: Vec<i64>,
        size: u64,
        arg_index: Option<u32>,
    ) -> Self {
        Self {
            inner: GroundTruthVar {
                name,
                types,
                rbp_offsets,
                size,
                arg_index,
            },
        }
    }

    /// The source-level name, or `''` when the debug entry carried none.
    ///
    /// Empty is meaningful: an anonymous ground-truth variable skips the name
    /// pass entirely and can only be matched by argument position or offset.
    #[getter]
    fn name(&self) -> &str {
        &self.inner.name
    }

    /// The already-normalized spellings this variable's type is equivalent to.
    #[getter]
    fn types(&self) -> Vec<String> {
        self.inner.types.clone()
    }

    /// Frame-relative stack offsets this variable occupies.
    ///
    /// Empty means the variable had a location but not a stack one --- a
    /// register-resident local, the common case at `-O2`.
    #[getter]
    fn rbp_offsets(&self) -> Vec<i64> {
        self.inner.rbp_offsets.clone()
    }

    /// The type's size in bytes, from the debug information.
    #[getter]
    fn size(&self) -> u64 {
        self.inner.size
    }

    /// The formal-parameter position, or `None` if this is not an argument.
    #[getter]
    fn arg_index(&self) -> Option<u32> {
        self.inner.arg_index
    }

    fn __repr__(&self) -> String {
        format!(
            "GroundTruthVar(name={:?}, types={:?}, rbp_offsets={:?}, size={}, arg_index={:?})",
            self.inner.name,
            self.inner.types,
            self.inner.rbp_offsets,
            self.inner.size,
            self.inner.arg_index
        )
    }
}

/// One variable a decompiler claims to have recovered.
///
/// `type_spelling` is the **raw** spelling, un-normalized on purpose: T-3's
/// width-only rule inspects the spelling itself (is it `undefined4`? does it
/// contain a `*`?), and normalization is lossy for that question ---
/// `undefined4` already normalizes to include `int`, so a pre-normalized form
/// could not tell a decompiler that committed to `int` apart from one that
/// only recovered four bytes.
#[pyclass(name = "DecompiledVar", module = "glaurung._native.metrics", frozen)]
#[derive(Clone)]
pub struct PyDecompiledVar {
    inner: DecompiledVar,
}

#[pymethods]
impl PyDecompiledVar {
    /// Build one decompiled variable.
    ///
    /// `stack_offset`, `size` and `arg_index` are all optional because real
    /// backends omit them: `None` for `stack_offset` covers both "not a stack
    /// variable" and "a stack variable whose offset only survives in the
    /// name", which [`effective_offset_py`] separates.
    #[new]
    #[pyo3(signature = (name, type_spelling, stack_offset=None, size=None, arg_index=None))]
    fn new(
        name: String,
        type_spelling: String,
        stack_offset: Option<i64>,
        size: Option<u64>,
        arg_index: Option<u32>,
    ) -> Self {
        Self {
            inner: DecompiledVar {
                name,
                type_spelling,
                stack_offset,
                size,
                arg_index,
            },
        }
    }

    /// The decompiler's name for the variable, or `''`.
    #[getter]
    fn name(&self) -> &str {
        &self.inner.name
    }

    /// The type spelling exactly as the decompiler emitted it.
    #[getter]
    fn type_spelling(&self) -> &str {
        &self.inner.type_spelling
    }

    /// The decompiler's own frame-relative offset, if it reported one.
    #[getter]
    fn stack_offset(&self) -> Option<i64> {
        self.inner.stack_offset
    }

    /// The decompiler's own size in bytes, if it reported one.
    ///
    /// Load-bearing for T-3: 1, 2, 4 or 8 *overrides* the width implied by the
    /// type spelling.
    #[getter]
    fn size(&self) -> Option<u64> {
        self.inner.size
    }

    /// The ABI argument position the decompiler placed this variable at.
    #[getter]
    fn arg_index(&self) -> Option<u32> {
        self.inner.arg_index
    }

    fn __repr__(&self) -> String {
        format!(
            "DecompiledVar(name={:?}, type_spelling={:?}, stack_offset={:?}, size={:?}, arg_index={:?})",
            self.inner.name,
            self.inner.type_spelling,
            self.inner.stack_offset,
            self.inner.size,
            self.inner.arg_index
        )
    }
}

/// The ground-truth forms of a type's spellings: T-1's normalization, unioned,
/// sorted and deduplicated.
///
/// Pass every DWARF spelling of one variable's type (a typedef chain reports
/// both `__int32_t` and `int`) and store the result in
/// [`PyGroundTruthVar`]'s `types`. Sorted rather than set-ordered because the
/// reference feeds this list into a cache key, and an unstable order there
/// once cost it 77% of its disk cache.
#[pyfunction]
#[pyo3(name = "ground_truth_forms")]
pub fn ground_truth_forms_py(spellings: Vec<String>) -> Vec<String> {
    let borrowed: Vec<&str> = spellings.iter().map(String::as_str).collect();
    tm::ground_truth_forms(&borrowed)
}

/// The stack offset to treat a decompiled variable as living at, or `None` if
/// it does not appear to be a stack variable at all.
///
/// A structured `stack_offset` wins outright; otherwise a Ghidra/IDA-style
/// `local_1c` or `var_20` name is mined for the displacement it encodes.
/// Exposed because a caller assembling its own calibration input has to use
/// exactly this rule --- feeding raw `stack_offset`s to
/// [`binary_calibration_shift_py`] silently drops every name-encoded slot,
/// which is most of two of the three major backends.
#[pyfunction]
#[pyo3(name = "effective_offset")]
pub fn effective_offset_py(var: &PyDecompiledVar) -> Option<i64> {
    tm::effective_offset(&var.inner)
}

/// Score one function's recovered variables against its ground truth (T-6/T-7).
///
/// Returns the ten fields of the reference's `MetricValue.metadata` plus the
/// `score` computed from them:
/// `{'true_positives', 'false_positives', 'false_negatives', 'shift',
/// 'matched_by_arg', 'matched_by_offset', 'matched_by_name', 'gt_vars',
/// 'decomp_vars', 'gt_stack_vars', 'decomp_stack_vars', 'gt_arg_vars',
/// 'score'}`.
///
/// `score` is `tp / (tp + fp + fn)`, which is **recall over ground-truth
/// variables**, not a Jaccard: the reference counts `fn` over ground-truth
/// variables no pass decided, so inventing extra decompiled variables is free
/// except where one shadows a real one. `0.0` on empty ground truth, which the
/// reference never scores and which should be filtered by the caller rather
/// than read as bad type recovery.
///
/// `calibration_shift` is the binary-wide shift from
/// [`binary_calibration_shift_py`], or `None` to start from zero; either way
/// the per-function shift may override it, and `shift` in the result reports
/// which was actually used.
#[pyfunction]
#[pyo3(name = "match_structured")]
#[pyo3(signature = (ground_truth, decompiled, calibration_shift=None))]
pub fn match_structured_py<'py>(
    py: Python<'py>,
    ground_truth: Vec<PyGroundTruthVar>,
    decompiled: Vec<PyDecompiledVar>,
    calibration_shift: Option<i128>,
) -> PyResult<Bound<'py, PyDict>> {
    // Unwrapped into owned Rust values first so the matching itself never
    // touches a Python object -- that is what lets the GIL go, and it is also
    // what keeps `src/metrics/type_match.rs` free of PyO3.
    let gt: Vec<GroundTruthVar> = ground_truth.into_iter().map(|v| v.inner).collect();
    let dec: Vec<DecompiledVar> = decompiled.into_iter().map(|v| v.inner).collect();
    let matched = py.detach(|| tm::match_structured(&gt, &dec, calibration_shift));

    let out = PyDict::new(py);
    out.set_item("true_positives", matched.true_positives)?;
    out.set_item("false_positives", matched.false_positives)?;
    out.set_item("false_negatives", matched.false_negatives)?;
    out.set_item("shift", matched.shift)?;
    out.set_item("matched_by_arg", matched.matched_by_arg)?;
    out.set_item("matched_by_offset", matched.matched_by_offset)?;
    out.set_item("matched_by_name", matched.matched_by_name)?;
    out.set_item("gt_vars", matched.gt_vars)?;
    out.set_item("decomp_vars", matched.decomp_vars)?;
    out.set_item("gt_stack_vars", matched.gt_stack_vars)?;
    out.set_item("decomp_stack_vars", matched.decomp_stack_vars)?;
    out.set_item("gt_arg_vars", matched.gt_arg_vars)?;
    out.set_item("score", matched.score())?;
    Ok(out)
}

/// The single offset shift (T-5) that best reconciles a whole binary's
/// decompiled stack offsets with DWARF's, or `None` when there is nothing to
/// calibrate.
///
/// `functions` is a list of `(ground_truth, decompiled)` pairs, one per
/// function of the binary. Functions where either side has no offsets are
/// dropped, exactly as the reference drops them.
///
/// Calling this once per binary and passing the result to every
/// [`match_structured_py`] on it is not an optimization: IDA numbers stack
/// slots from the frame *bottom*, so its gap to DWARF is a per-function
/// constant of roughly the frame size, and without a binary-wide shift every
/// such slot scores as a miss and the backend's type recovery collapses for
/// reasons that have nothing to do with types.
#[pyfunction]
#[pyo3(name = "binary_calibration_shift")]
pub fn binary_calibration_shift_py(
    py: Python<'_>,
    functions: Vec<(Vec<PyGroundTruthVar>, Vec<PyDecompiledVar>)>,
) -> Option<i128> {
    let owned: Vec<(Vec<GroundTruthVar>, Vec<DecompiledVar>)> = functions
        .into_iter()
        .map(|(gt, dec)| {
            (
                gt.into_iter().map(|v| v.inner).collect(),
                dec.into_iter().map(|v| v.inner).collect(),
            )
        })
        .collect();
    py.detach(|| {
        let borrowed: Vec<(&[GroundTruthVar], &[DecompiledVar])> = owned
            .iter()
            .map(|(gt, dec)| (gt.as_slice(), dec.as_slice()))
            .collect();
        tm::binary_calibration_shift(&borrowed)
    })
}

/// Register the `metrics` submodule on the extension root.
pub fn register_metrics_bindings(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    let sub = PyModule::new(m.py(), "metrics")?;

    sub.add_class::<PySkeleton>()?;
    sub.add_class::<PyGroundTruthVar>()?;
    sub.add_class::<PyDecompiledVar>()?;

    sub.add_function(wrap_pyfunction!(skeletons_py, &sub)?)?;
    sub.add_function(wrap_pyfunction!(tree_edit_distance_py, &sub)?)?;
    sub.add_function(wrap_pyfunction!(skeleton_score_py, &sub)?)?;

    sub.add_function(wrap_pyfunction!(disassemble_lines_py, &sub)?)?;
    sub.add_function(wrap_pyfunction!(capstone_ids_py, &sub)?)?;
    sub.add_function(wrap_pyfunction!(asm_target_py, &sub)?)?;
    sub.add_function(wrap_pyfunction!(normalize_operands_py, &sub)?)?;
    sub.add_function(wrap_pyfunction!(score_lines_py, &sub)?)?;
    sub.add_function(wrap_pyfunction!(diff_lines_py, &sub)?)?;

    sub.add_function(wrap_pyfunction!(ground_truth_forms_py, &sub)?)?;
    sub.add_function(wrap_pyfunction!(effective_offset_py, &sub)?)?;
    sub.add_function(wrap_pyfunction!(match_structured_py, &sub)?)?;
    sub.add_function(wrap_pyfunction!(binary_calibration_shift_py, &sub)?)?;

    // The two abstention thresholds, so a caller can tell in advance which
    // pairs it will get `None` for instead of discovering it mid-report, and
    // the projection version, so a cached skeleton can be invalidated when the
    // alphabet changes.
    sub.add("MAX_SKELETON_NODES", td::MAX_SKELETON_NODES)?;
    sub.add("SKELETON_VERSION", td::SKELETON_VERSION)?;
    sub.add("MAX_DIFF_LINES", byte_match::MAX_DIFF_LINES)?;

    m.add_submodule(&sub)?;
    Ok(())
}
