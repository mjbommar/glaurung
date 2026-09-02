//! The plug point: one trait every function-identity scheme implements, so the
//! protocol in [`crate::metrics`] scores all of them the same way.
//!
//! # Why a trait and not four bespoke tests
//!
//! `docs/research/program-measures-2026-09-02.md` proposes four rungs of an
//! identity ladder (WARP GUIDs, structural invariants, the CFR feature vector,
//! value fingerprints). The one thing that makes them comparable is being
//! scored by the same driver over the same filtered corpus with the same
//! negative sampling. If each scheme brings its own harness, the numbers stop
//! being comparable the moment one of them takes a shortcut -- which is the
//! specific failure the protocol document names ("the same tool, SAFE, scores
//! MRR 0.918 and 0.17 in two published papers on different protocols").
//!
//! # Adding a scheme
//!
//! Implement [`Scheme`] over your signature type and add a test that calls
//! `crate::metrics::evaluate`. The slots below say exactly what the three
//! in-flight lanes should write.

use std::fmt;

use glaurung::identity::structural::code_facts_from_function_bytes;

use crate::corpus::FunctionSample;

/// Why a scheme could not produce a signature for one sample.
///
/// Extraction is allowed to fail -- a lifter can refuse a function, an
/// architecture can be unsupported -- but it must SAY it failed rather than
/// return a degenerate signature that scores as "similar to everything".
/// [`crate::metrics::evaluate`] counts the failures and prints them next to
/// every result, because a scheme that silently drops half the corpus is not
/// beating one that handles all of it.
#[derive(Debug, Clone)]
pub struct SchemeError {
    pub reason: String,
}

impl SchemeError {
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}

impl fmt::Display for SchemeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.reason)
    }
}

impl std::error::Error for SchemeError {}

/// One way of answering "what is this function".
///
/// Contract, enforced by the property tests in `main.rs`:
///
/// * `extract` is **deterministic** -- the same sample gives the same
///   signature, in this process and the next one.
/// * `similarity` is **symmetric** and lands in `[0, 1]`, with `1.0` reserved
///   for signatures the scheme considers identical.
/// * `similarity(a, a) == 1.0` for every extractable sample (identity on the
///   quotient; see the metric axioms in
///   `docs/research/program-measures-2026-09-02/02-program-measures-foundations.md`).
///
/// A scheme is free to return the same signature for two different functions;
/// that is a collision and the harness measures it, rather than forbidding it.
pub trait Scheme {
    /// The scheme's per-function signature. Opaque to the driver.
    type Sig: Send + Sync;

    /// A stable identifier. Used as the JSON report's filename, so it must be
    /// filesystem-safe, and as the `scheme` column value if the results are
    /// ever persisted.
    fn name(&self) -> &str;

    /// One-line description of what the scheme keys on, printed with results.
    fn description(&self) -> &str;

    fn extract(&self, sample: &FunctionSample) -> Result<Self::Sig, SchemeError>;

    fn similarity(&self, a: &Self::Sig, b: &Self::Sig) -> f64;
}

/// Context-triggered piecewise hashing over the function's bytes, the digest
/// already shipped in `glaurung::similarity`.
///
/// This is here to be **retro-scored**, not to be recommended. The protocol
/// document is explicit that byte-level digests keep one role (file-level
/// near-duplicates) and that CTPH must not be extended to functions;
/// `tests/similarity_retrieval.rs` measured it at 0.32% top-1 over the whole
/// gcc corpus. Running it through this harness puts that result on the same
/// filtered denominators and the same task taxonomy as everything that
/// follows, so the schemes on the way in have a floor to clear that is stated
/// in the same units.
///
/// `CtphConfig::default()` is deliberate: it is what
/// `ctph_recommended_params(len)` returns for any input under 16 KiB, i.e. the
/// configuration every function-sized input actually gets in production.
pub struct CtphScheme {
    config: glaurung::similarity::CtphConfig,
}

impl Default for CtphScheme {
    fn default() -> Self {
        Self {
            config: glaurung::similarity::CtphConfig::default(),
        }
    }
}

impl Scheme for CtphScheme {
    type Sig = String;

    fn name(&self) -> &str {
        "ctph"
    }

    fn description(&self) -> &str {
        "context-triggered piecewise hash over function bytes (glaurung::similarity, default config)"
    }

    fn extract(&self, sample: &FunctionSample) -> Result<String, SchemeError> {
        if sample.bytes.is_empty() {
            return Err(SchemeError::new("empty function body"));
        }
        Ok(glaurung::similarity::ctph_hash(&sample.bytes, &self.config))
    }

    fn similarity(&self, a: &String, b: &String) -> f64 {
        glaurung::similarity::ctph_similarity(a, b)
    }
}

/// L1 structural invariants (`glaurung::identity::structural`): MD-index
/// (top-down, bottom-up, relaxed), mnemonic small-primes product,
/// block/edge/loop/SCC counts and cyclomatic complexity, over the CFG
/// `glaurung::analysis::cfg` already discovered.
///
/// # What this scheme sees, and what it does not
///
/// `FunctionSample` carries exactly what discovery returns for one function:
/// its own byte range, plus blocks and index-form edges. That is enough for
/// the graph half of a [`StructuralSignature`] outright --
/// [`glaurung::identity::structural::CfgShape`] is built from block start
/// addresses and edge pairs, nothing else -- and for the instruction-count
/// term, already summed by discovery into each block's `instruction_count`.
/// Two terms need a re-decode of the function's own bytes: mnemonic SPP and
/// the rare-constant multiset. [`code_facts_from_function_bytes`] is the
/// accessor added to `src/identity/structural/code.rs` for exactly this --
/// see its doc comment for what it cannot do without a surrounding image
/// (mask a constant that is really a pointer, detect string references).
/// [`ranking_similarity`] never reads `string_refs`, `calls_out_direct`,
/// `calls_out_indirect` or `callers_in`, so none of that costs the score
/// anything; `callers_in` is fixed at 0 because this harness scores one
/// function at a time with no call graph in view -- the field's own
/// documented reading of a zero.
///
/// A sample with no discovered blocks is refused rather than scored as an
/// empty shape: an empty [`StructuralSignature`] would compare as "similar to
/// every other empty one", which is exactly the degenerate-signature failure
/// [`SchemeError`] exists to make visible instead of silent.
///
/// # Backend cache
///
/// `code_facts_from_function_bytes` takes a caller-built `&mut
/// registry::Backend` rather than building one itself, because
/// `registry::for_arch` is a real cost on the Capstone-backed architectures
/// and `extract` is called once per function -- thousands of times per corpus
/// slice. `StructuralScheme` holds one backend per `(Architecture,
/// Endianness)` pair, built the first time that combination is seen and
/// reused for every function after, the same discipline `ImageCode` uses
/// within one image. Measured effect on Cisco Dataset-1 (six architectures,
/// 2,441 samples): rebuilding a backend on every call reads ~1.4 ms/function;
/// this brings a single-architecture slice back down to the same tens of
/// microseconds `mnemonic_spp` and `rare_constants` alone would cost.
#[derive(Default)]
pub struct StructuralScheme {
    backends: std::cell::RefCell<
        std::collections::HashMap<
            (
                glaurung::core::disassembler::Architecture,
                glaurung::core::binary::Endianness,
            ),
            glaurung::disasm::registry::Backend,
        >,
    >,
}

impl Scheme for StructuralScheme {
    type Sig = glaurung::identity::structural::StructuralSignature;

    fn name(&self) -> &str {
        "structural"
    }

    fn description(&self) -> &str {
        "L1 structural invariants: MD-index (top-down/bottom-up/relaxed), \
         mnemonic small-primes product, block/edge/loop/SCC counts, over the \
         discovered CFG (glaurung::identity::structural)"
    }

    fn extract(&self, sample: &FunctionSample) -> Result<Self::Sig, SchemeError> {
        if sample.blocks.is_empty() {
            return Err(SchemeError::new("no basic blocks in this sample"));
        }
        let block_vas: Vec<u64> = sample.blocks.iter().map(|b| b.start_va).collect();
        let edges: Vec<(u64, u64)> = sample
            .edges
            .iter()
            .filter_map(|&(from, to)| {
                let f = *block_vas.get(from)?;
                let t = *block_vas.get(to)?;
                Some((f, t))
            })
            .collect();
        let shape = glaurung::identity::structural::CfgShape::new(&block_vas, &edges, sample.va);

        let ranges: Vec<(u64, u64)> = sample
            .blocks
            .iter()
            .map(|b| (b.start_va, b.end_va))
            .collect();

        let key = (sample.arch.architecture, sample.arch.endianness);
        let mut backends = self.backends.borrow_mut();
        if !backends.contains_key(&key) {
            let Some(backend) = glaurung::disasm::registry::for_arch(key.0, key.1) else {
                return Err(SchemeError::new(format!(
                    "no disassembler backend for {:?}/{:?}",
                    key.0, key.1
                )));
            };
            backends.insert(key, backend);
        }
        let backend = backends.get_mut(&key).expect("just inserted above");
        let facts = code_facts_from_function_bytes(&sample.bytes, sample.va, &ranges, backend);

        Ok(
            glaurung::identity::structural::StructuralSignature::from_parts(
                sample.va,
                sample.name.clone(),
                &shape,
                &facts,
                0,
            ),
        )
    }

    fn similarity(&self, a: &Self::Sig, b: &Self::Sig) -> f64 {
        glaurung::identity::structural::ranking_similarity(a, b)
    }
}

// ---------------------------------------------------------------------------
// Slots for the two schemes still to come.
//
// Each is a `Scheme` impl of maybe twenty lines plus a test that calls
// `crate::metrics::evaluate(&scheme, corpus, &tasks)`. Nothing else in this
// file or in `metrics.rs` has to change. Deliberately NOT stubbed out as
// `todo!()` types: an empty impl that compiles is an impl that can be
// forgotten, and a scheme that extracts nothing would score 0.0 across the
// board and look like a measurement rather than an absence.
//
// * `warp` -- `src/identity/warp.rs`, the L0 rung. `Sig` is a `uuid::Uuid`
//   (UUIDv5 over relocation-masked basic-block bytes). `similarity` is exact
//   equality, 1.0 or 0.0, so its Recall@1 IS its coverage: expect a very high
//   score on the XO/XC diagonal it can reach and zero everywhere else, and
//   read the pool size before believing either. Needs `image_path` and `va` to
//   re-read the image for its relocation table.
//
// * `cfr` -- `src/identity/cfr/`, the L2 rung. `Sig` is the sorted
//   `(u32 feature_hash, u16 count)` multiset. `similarity` is BSim's
//   merge-join cosine with `min(cA, cB)^2` in the numerator. Needs
//   `image_path` and `va` so it can lift the function to LLIR; a TF-IDF
//   weighting needs a corpus count table, which is a second pass over the
//   slice before scoring and belongs in the impl, not in the driver.
// ---------------------------------------------------------------------------
