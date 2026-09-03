//! The plug point: one trait every function-identity scheme implements, so the
//! protocol in [`crate::metrics`] scores all of them the same way.
//!
//! # Why a trait and not four bespoke tests
//!
//! `docs/history/program-measures-2026-09-02.md` proposes four rungs of an
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
///   `docs/history/program-measures-2026-09-02/02-program-measures-foundations.md`).
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
// L2, the Canonical Function Representation (`glaurung::identity::cfr`).
//
// Two schemes over one implementation, because the only thing that differs
// between them is the weight table and the whole question this lane exists to
// answer is what that table is worth. `cfr` is `UniformWeights`, which is what
// every published unweighted CFR number was measured under; `cfr-weighted`
// carries a corpus TF-IDF table counted over the training half of the same
// corpus. Both extract identically -- weighting changes the metric, never the
// representation -- so a difference between their rows is the weighting and
// nothing else.
// ---------------------------------------------------------------------------

/// Images whose signatures are kept in memory at once by [`CfrScheme`].
///
/// A CFR signature costs one lift, one SSA pass and one Weisfeiler-Lehman
/// relabelling *per function*, and `Scheme::extract` is called once per sample
/// -- thousands of times per slice, and again for every task. Signing one
/// function at a time would re-open and re-parse its image every call. So the
/// whole image is signed on the first sample that names it and the result is
/// kept.
///
/// Four is enough because the driver walks samples in ground-truth-label order
/// and a label starts with the fixture (in-house) or the library (Dataset-1),
/// so consecutive samples overwhelmingly come from the same image. It is a
/// bound on memory, not a tuning parameter: a cache of one would be nearly as
/// fast and a cache of everything would hold every signature of every binary in
/// the corpus at once.
const CFR_IMAGE_CACHE: usize = 4;

/// The Canonical Function Representation: a Weisfeiler-Lehman feature multiset
/// over the operator-typed SSA dataflow graph and the degree-labelled CFG,
/// compared with BSim's merge-join cosine.
///
/// # What it needs from a sample
///
/// `image_path` and `va`, and nothing else. Unlike CTPH and `structural` it
/// does not read `bytes` or `blocks`: it re-opens the image and lifts, because
/// the representation is over LLIR after SSA and the harness's `FunctionSample`
/// carries no IR. That is also why it is the only scheme here that can fail for
/// a whole architecture -- see below.
///
/// # Where it must fail rather than answer
///
/// `src/ir/lift/` covers x86, x86-64, ARM and AArch64; `disasm::registry`
/// reaches MIPS only through Capstone. On a MIPS slice this scheme therefore
/// has no signature to give, and [`crate::corpus::SampleArch::is_liftable`] is
/// the switch it consults so that extraction *fails* -- visibly, counted, and
/// printed next to the result -- instead of returning an empty vector that
/// would score 0.0 against everything and read as a measurement.
pub struct CfrScheme {
    name: &'static str,
    description: String,
    settings: glaurung::identity::cfr::CfrSettings,
    weights: Option<glaurung::identity::cfr::CorpusWeights>,
    /// Refuse every sample in the training half, so both the queries and the
    /// pool are the half no weight table has counted. See
    /// [`cfr_in_training_half`]. It applies to the unweighted control too --
    /// two rows over two different populations are not a comparison.
    held_out_only: bool,
    cache: std::cell::RefCell<CfrImageCache>,
}

#[derive(Default)]
struct CfrImageCache {
    /// `image path -> (entry VA -> signature)`, for the last
    /// [`CFR_IMAGE_CACHE`] images asked about.
    images: Vec<(
        std::path::PathBuf,
        std::sync::Arc<std::collections::BTreeMap<u64, glaurung::identity::cfr::CfrSignature>>,
    )>,
}

impl CfrImageCache {
    fn get(
        &mut self,
        path: &std::path::Path,
    ) -> Option<
        std::sync::Arc<std::collections::BTreeMap<u64, glaurung::identity::cfr::CfrSignature>>,
    > {
        let position = self.images.iter().position(|(p, _)| p == path)?;
        // Move to the back, so the eviction below drops the least recently
        // asked-for image rather than the oldest inserted one.
        let entry = self.images.remove(position);
        let signatures = std::sync::Arc::clone(&entry.1);
        self.images.push(entry);
        Some(signatures)
    }

    fn insert(
        &mut self,
        path: std::path::PathBuf,
        signatures: std::collections::BTreeMap<u64, glaurung::identity::cfr::CfrSignature>,
    ) -> std::sync::Arc<std::collections::BTreeMap<u64, glaurung::identity::cfr::CfrSignature>>
    {
        let signatures = std::sync::Arc::new(signatures);
        self.images.push((path, std::sync::Arc::clone(&signatures)));
        while self.images.len() > CFR_IMAGE_CACHE {
            self.images.remove(0);
        }
        signatures
    }
}

impl Default for CfrScheme {
    fn default() -> Self {
        Self::unweighted(glaurung::identity::cfr::CfrSettings::default())
    }
}

impl CfrScheme {
    /// The CFR under uniform weights: every feature counts the same.
    pub fn unweighted(settings: glaurung::identity::cfr::CfrSettings) -> Self {
        CfrScheme {
            name: "cfr",
            description: "L2 Canonical Function Representation: Weisfeiler-Lehman \
                          feature multiset over the operator-typed SSA dataflow graph \
                          and the degree-labelled CFG, BSim merge-join cosine, uniform \
                          weights (glaurung::identity::cfr)"
                .to_string(),
            settings,
            weights: None,
            held_out_only: false,
            cache: std::cell::RefCell::new(CfrImageCache::default()),
        }
    }

    /// The unweighted CFR restricted to the held-out half: the **control** the
    /// weighted row is compared against.
    ///
    /// It exists because the weighted row is scored on half the corpus, and a
    /// weighted number on half a corpus set beside an unweighted number on all
    /// of it is not a delta -- the pools differ, the negatives differ, and the
    /// twin joins differ. This scheme is byte-for-byte the same extraction and
    /// the same population as `cfr-weighted`, differing only in the weight
    /// table, which is the one variable the comparison is about.
    pub fn unweighted_held_out(settings: glaurung::identity::cfr::CfrSettings) -> Self {
        CfrScheme {
            name: "cfr-heldout",
            description: "L2 Canonical Function Representation, uniform weights, \
                          scored on the held-out half of the corpus: the control for \
                          `cfr-weighted` (glaurung::identity::cfr)"
                .to_string(),
            settings,
            weights: None,
            held_out_only: true,
            cache: std::cell::RefCell::new(CfrImageCache::default()),
        }
    }

    /// The CFR under a corpus TF-IDF table.
    ///
    /// The table's `weights_id` goes into the scheme description and therefore
    /// into the JSON report, because a weighted number without the name of the
    /// table it was weighted by is not reproducible.
    pub fn weighted(
        settings: glaurung::identity::cfr::CfrSettings,
        weights: glaurung::identity::cfr::CorpusWeights,
    ) -> Self {
        let description = format!(
            "L2 Canonical Function Representation, TF-IDF weighted: same features as \
             `cfr`, scored under corpus weight table {} ({} documents, {} weighted \
             features)",
            weights.weights_id(),
            weights.documents(),
            weights.len()
        );
        CfrScheme {
            name: "cfr-weighted",
            description,
            settings,
            weights: Some(weights),
            held_out_only: true,
            cache: std::cell::RefCell::new(CfrImageCache::default()),
        }
    }

    fn weights(&self) -> Option<&dyn glaurung::identity::cfr::Weights> {
        self.weights
            .as_ref()
            .map(|w| w as &dyn glaurung::identity::cfr::Weights)
    }

    /// BSim's significance for one pair, which the cosine cannot express.
    ///
    /// Not part of the [`Scheme`] contract -- that trait's `similarity` must
    /// land in `[0, 1]` and this is open-ended -- so it is offered here for the
    /// tests that measure the confidence itself.
    pub fn significance(
        &self,
        a: &glaurung::identity::cfr::CfrSignature,
        b: &glaurung::identity::cfr::CfrSignature,
    ) -> f64 {
        glaurung::identity::cfr::significance(a, b, self.weights())
    }

    /// The largest significance any match to `a` could reach.
    pub fn self_significance(&self, a: &glaurung::identity::cfr::CfrSignature) -> f64 {
        glaurung::identity::cfr::self_significance(a, self.weights())
    }
}

/// Sign every function in one image, keyed by entry VA.
///
/// Uses [`crate::corpus::harness_budgets`] rather than `Budgets::default()`,
/// for the reason that function documents: a per-function wall clock makes a
/// signature depend on how busy the machine was, and a truncated discovery is a
/// different graph.
fn cfr_sign_image(
    path: &std::path::Path,
    settings: glaurung::identity::cfr::CfrSettings,
) -> Result<std::collections::BTreeMap<u64, glaurung::identity::cfr::CfrSignature>, SchemeError> {
    let budgets = crate::corpus::harness_budgets();
    let signed = glaurung::identity::cfr::signatures_for_path(path, settings, &budgets)
        .map_err(|error| SchemeError::new(format!("{}: {error}", path.display())))?;
    Ok(signed
        .into_iter()
        .map(|entry| (entry.entry_va, entry.signature))
        .collect())
}

impl Scheme for CfrScheme {
    type Sig = std::sync::Arc<glaurung::identity::cfr::CfrSignature>;

    fn name(&self) -> &str {
        self.name
    }

    fn description(&self) -> &str {
        &self.description
    }

    fn extract(&self, sample: &FunctionSample) -> Result<Self::Sig, SchemeError> {
        if self.held_out_only && cfr_in_training_half(&sample.fixture, &sample.name) {
            // Refused rather than filtered out of the corpus, because the
            // driver already treats an unextractable sample correctly: it
            // leaves the pool (`global_pool_size` is the *usable* pool), it
            // cannot be drawn as a negative, and it is counted and printed.
            // Half of `extraction_failures` on a `cfr-heldout` or
            // `cfr-weighted` row is this split, not a coverage problem.
            return Err(SchemeError::new(
                "in the training half; this scheme scores the held-out half only",
            ));
        }
        if !sample.arch.is_liftable() {
            return Err(SchemeError::new(format!(
                "{:?} has no LLIR lifter, so the CFR has nothing to canonicalise",
                sample.arch.architecture
            )));
        }
        let mut cache = self.cache.borrow_mut();
        let signatures = match cache.get(&sample.image_path) {
            Some(signatures) => signatures,
            None => {
                let signed = cfr_sign_image(&sample.image_path, self.settings)?;
                cache.insert(sample.image_path.clone(), signed)
            }
        };
        let signature = signatures.get(&sample.va).ok_or_else(|| {
            SchemeError::new(format!(
                "no CFR signature at {:#x} in {}: the lifter refused this \
                 function, or discovery did not reach it",
                sample.va,
                sample.image_path.display()
            ))
        })?;
        if signature.is_empty() {
            // An empty vector scores 0.0 against everything, which is
            // indistinguishable from a scheme that carries nothing. Say so.
            return Err(SchemeError::new(format!(
                "empty CFR vector at {:#x} in {}",
                sample.va,
                sample.image_path.display()
            )));
        }
        Ok(std::sync::Arc::new(signature.clone()))
    }

    fn similarity(&self, a: &Self::Sig, b: &Self::Sig) -> f64 {
        glaurung::identity::cfr::cosine(a, b, self.weights())
    }
}

/// Seed for the training / held-out split of a corpus.
///
/// The golden-ratio constant SplitMix64 is usually seeded with, mixed with the
/// string below so this split cannot accidentally coincide with the negative
/// sampler's stream (`crate::metrics::sample_negatives` uses the same
/// generator). A shared stream would make "which functions train the weights"
/// correlated with "which negatives are drawn", and the correlation would be
/// invisible.
const CFR_SPLIT_SEED: u64 = 0x9E37_79B9_7F4A_7C15;

/// The half of the corpus a weight table may be counted over.
///
/// # Why a split at all
///
/// BSim counts its IDF over the whole corpus it later searches, and so does
/// every TF-IDF retrieval system: a document frequency is a property of the
/// collection, not a fitted parameter. Measuring that way here would still be
/// defensible. It is not what this does, because the question the harness is
/// asked is "what is the weighting worth", and a table that has counted the
/// exact function being retrieved has seen the answer -- weakly, but the
/// weakness would be impossible to bound from the outside.
///
/// So the split is stricter than production: the weight table is counted over
/// one half and every reported number is scored on the other. The consequence
/// is that these rows *understate* what the weighting is worth in a deployment
/// that indexes what it searches.
///
/// # The rule
///
/// SplitMix64 over the ground-truth label `(fixture, name)`, seeded from
/// [`CFR_SPLIT_SEED`]. Keying on the label rather than on the sample means a
/// function is in training or held out **in every slice at once** -- the same
/// function at `-O0` and at `-O2` never lands on opposite sides, which is the
/// leak that would matter most on a cross-optimisation task.
///
/// What it does not separate: two different functions from the same source
/// file. For an IDF table -- a frequency count over features, with no fitted
/// parameter and no capacity to memorise -- that is a much milder concern than
/// it would be for a learned model, and it is stated rather than smoothed over.
pub fn cfr_in_training_half(fixture: &str, name: &str) -> bool {
    let mut state = CFR_SPLIT_SEED;
    for byte in fixture
        .as_bytes()
        .iter()
        .chain(b"\0")
        .chain(name.as_bytes())
    {
        state = state
            .wrapping_add(u64::from(*byte))
            .wrapping_mul(0x9E37_79B9_7F4A_7C15);
        state ^= state >> 31;
    }
    // Finalise with SplitMix64's mixer so adjacent labels do not land on
    // adjacent bits.
    let mut z = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^= z >> 31;
    z & 1 == 0
}

/// Count a TF-IDF table over the training half of `samples`.
///
/// Returns `None` when nothing in the training half could be signed at all,
/// which is the MIPS case: a table over zero documents weights every feature at
/// the corpus maximum and is worse than no table, so the caller must see the
/// absence rather than a degenerate object.
pub fn cfr_train_weights<'a, I>(
    samples: I,
    settings: glaurung::identity::cfr::CfrSettings,
) -> Option<glaurung::identity::cfr::CorpusWeights>
where
    I: Iterator<Item = &'a FunctionSample>,
{
    let extractor = CfrScheme::unweighted(settings);
    let version = glaurung::identity::cfr::CfrVersion::current(settings);
    let mut builder = glaurung::identity::cfr::WeightsBuilder::new(version);
    for sample in samples {
        if !cfr_in_training_half(&sample.fixture, &sample.name) {
            continue;
        }
        if let Ok(signature) = extractor.extract(sample) {
            builder.observe(&signature);
        }
    }
    if builder.documents() == 0 {
        return None;
    }
    Some(builder.build(1))
}

// ---------------------------------------------------------------------------
// Slot for the scheme still to come.
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
// * `cfr` -- **landed**, above: `CfrScheme`, in three configurations
//   (`unweighted`, `unweighted_held_out`, `weighted`).
// ---------------------------------------------------------------------------
