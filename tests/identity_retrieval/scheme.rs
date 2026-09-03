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
//! `crate::metrics::evaluate`. Four are implemented -- [`CtphScheme`],
//! [`StructuralScheme`], [`CfrScheme`] and `ValueScheme` (the last behind the
//! `exec` feature, because it drives the interpreter) -- and the comment at
//! the foot of this file says what the one still to come should write.

use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;

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

/// L2, the Canonical Function Representation (`glaurung::identity::cfr`):
/// a Weisfeiler-Lehman feature multiset over the operator-typed SSA dataflow
/// graph and the degree-labelled CFG, compared with BSim's merge-join cosine.
///
/// # Why this one needs the image and the others do not
///
/// CTPH reads the function's bytes and the structural scheme reads its blocks
/// and edges; both are already in a [`FunctionSample`]. The CFR is computed
/// over *lifted LLIR in SSA form*, which needs the whole image: relocation
/// targets, the PLT map that resolves an external callee's name, whether an
/// address is mapped. So this scheme opens the image the sample came from and
/// asks `glaurung::identity::cfr::signatures_for_path` for every function in
/// it at once, then answers by entry address.
///
/// That is the *same* extraction `tests/identity_cfr_retrieval.rs` measures, on
/// purpose: two ways of computing one representation is two numbers that will
/// eventually disagree. The two files then differ only in protocol -- this one
/// reports AUC and MRR10 over Marcelli's task taxonomy and over Cisco
/// Dataset-1, the other reports Recall@1 with the published duplicate filter.
///
/// # The image cache
///
/// [`CACHED_IMAGES`] images are held at a time, evicted oldest-first. The
/// corpus loaders sort samples by `(fixture, name)`, and one fixture is one
/// image, so a linear pass over a slice touches each image once; the driver
/// walks the pool slice and then the query slice, so two entries would do and
/// four is slack against a task that interleaves them. A cache miss is a whole
/// image's discovery plus a lift of every function in it, which is why the
/// extraction cost this scheme reports is dominated by whichever samples
/// happened to be first in their image.
///
/// A sample whose image cannot be signed at all -- no modelled calling
/// convention for the target, which is the case for some of Dataset-1's
/// architectures -- fails with a [`SchemeError`] naming it, so the driver
/// counts and prints it rather than scoring an empty signature against
/// everything.
pub struct CfrScheme {
    settings: glaurung::identity::cfr::CfrSettings,
    name: String,
    cache: std::cell::RefCell<
        std::collections::VecDeque<(
            PathBuf,
            BTreeMap<u64, glaurung::identity::cfr::CfrSignature>,
        )>,
    >,
}

/// Images held in [`CfrScheme`]'s cache at once.
const CACHED_IMAGES: usize = 4;

impl CfrScheme {
    /// The plain canonical form, no peephole normaliser. The floor.
    pub fn plain() -> Self {
        Self::with(glaurung::identity::cfr::CfrSettings::default(), "cfr")
    }

    /// With the unsound local peephole normaliser
    /// (`src/identity/cfr/normalize/`, plan item 8) run over a copy of each
    /// lifted function before hashing.
    pub fn normalized() -> Self {
        Self::with(
            glaurung::identity::cfr::CfrSettings {
                normalize: true,
                ..Default::default()
            },
            "cfr-normalized",
        )
    }

    fn with(settings: glaurung::identity::cfr::CfrSettings, name: &str) -> Self {
        Self {
            settings,
            name: name.to_string(),
            cache: std::cell::RefCell::new(std::collections::VecDeque::new()),
        }
    }
}

impl Scheme for CfrScheme {
    type Sig = glaurung::identity::cfr::CfrSignature;

    fn name(&self) -> &str {
        &self.name
    }

    fn description(&self) -> &str {
        if self.settings.normalize {
            "L2 CFR: Weisfeiler-Lehman multiset over the SSA dataflow graph and \
             the degree-labelled CFG, with the unsound local peephole \
             normaliser (glaurung::identity::cfr, normalize=true)"
        } else {
            "L2 CFR: Weisfeiler-Lehman multiset over the SSA dataflow graph and \
             the degree-labelled CFG (glaurung::identity::cfr)"
        }
    }

    fn extract(&self, sample: &FunctionSample) -> Result<Self::Sig, SchemeError> {
        let mut cache = self.cache.borrow_mut();
        if !cache.iter().any(|(path, _)| path == &sample.image_path) {
            let signatures = glaurung::identity::cfr::signatures_for_path(
                &sample.image_path,
                self.settings,
                &crate::corpus::harness_budgets(),
            )
            .map_err(|error| {
                SchemeError::new(format!("{}: {error}", sample.image_path.display()))
            })?;
            let by_va: BTreeMap<u64, Self::Sig> = signatures
                .into_iter()
                .map(|entry| (entry.entry_va, entry.signature))
                .collect();
            if cache.len() >= CACHED_IMAGES {
                cache.pop_front();
            }
            cache.push_back((sample.image_path.clone(), by_va));
        }
        let (_, by_va) = cache
            .iter()
            .find(|(path, _)| path == &sample.image_path)
            .expect("just inserted above");
        match by_va.get(&sample.va) {
            // An empty signature compares as "no answer" to everything, which
            // is indistinguishable from a genuinely featureless function; say
            // so instead.
            Some(signature) if !signature.is_empty() => Ok(signature.clone()),
            Some(_) => Err(SchemeError::new(format!(
                "no CFR features at {:#x} in {}",
                sample.va,
                sample.image_path.display()
            ))),
            None => Err(SchemeError::new(format!(
                "discovery found no function at {:#x} in {}",
                sample.va,
                sample.image_path.display()
            ))),
        }
    }

    fn similarity(&self, a: &Self::Sig, b: &Self::Sig) -> f64 {
        glaurung::identity::cfr::cosine(a, b, None)
    }
}

// ===========================================================================
// SECTION: values (L3) -- owned by the identity/values lane
// ===========================================================================

/// L3, vSim-style value fingerprints (`glaurung::identity::values`): the
/// multiset of numbers a function computes under bounded execution of the
/// LLIR, compared by weighted Jaccard.
///
/// # What this scheme sees, and what it costs
///
/// Like [`CfrScheme`] it needs the whole image, and for more reasons: the
/// lifter, the PLT map that names an external callee, whether an address is
/// mapped (filter rules F1/F2), and the read-only bytes an initialised load
/// should read. So it opens the image the sample came from and asks
/// `glaurung::identity::values::fingerprints_for_path` for every function in
/// it at once, then answers by entry address.
///
/// Unlike [`CfrScheme`] the cache is **unbounded**, deliberately. A cache miss
/// here is not a lift, it is `seeds x max_steps` interpreted instructions for
/// every function in the image; at four cached images a task that interleaves
/// query and pool slices would re-run the interpreter over whole binaries. The
/// fingerprints themselves are small (a sorted `(u64, u32)` list), so holding
/// one image's worth per fixture is cheaper in every dimension.
///
/// # x86-64 only
///
/// `fingerprints_for_path` refuses anything else, so on Cisco Dataset-1 the
/// ARM, MIPS and 32-bit x86 slices fail extraction with a [`SchemeError`]
/// naming the architecture. That is counted and printed rather than scored,
/// which is the whole reason `extract` is fallible.
#[cfg(feature = "exec")]
pub struct ValueScheme {
    settings: glaurung::identity::values::ValueSettings,
    name: String,
    description: String,
    /// vSim's Equation 2 is over element *sets*; the multiset form uses the
    /// counts. Which one is right is a measurement, so it is a field.
    use_counts: bool,
    /// Document-frequency weights, present only after [`ValueScheme::prime`].
    weights: std::cell::RefCell<Option<glaurung::identity::values::OccurrenceWeights>>,
    weighted: bool,
    cache: std::cell::RefCell<
        std::collections::HashMap<
            PathBuf,
            Result<BTreeMap<u64, glaurung::identity::values::ValueFingerprint>, String>,
        >,
    >,
}

#[cfg(feature = "exec")]
impl ValueScheme {
    /// The default rule set, unweighted, vSim's set-form Jaccard. The floor.
    pub fn plain() -> Self {
        Self::with(
            glaurung::identity::values::ValueSettings::default(),
            "values",
            false,
            false,
        )
    }

    /// The same fingerprints, weighted by corpus document frequency. Needs
    /// [`ValueScheme::prime`] before it is scored; without it the weights stay
    /// uniform.
    pub fn weighted() -> Self {
        Self::with(
            glaurung::identity::values::ValueSettings::default(),
            "values-weighted",
            false,
            true,
        )
    }

    /// The ablation vSim's Table IV reports at 0.09 Recall@1: the address
    /// filters off, everything else identical.
    pub fn unfiltered() -> Self {
        Self::with(
            glaurung::identity::values::ValueSettings {
                filter: false,
                ..Default::default()
            },
            "values-unfiltered",
            false,
            false,
        )
    }

    /// An arbitrary configuration, for the exploratory sweep.
    pub fn tuned(
        settings: glaurung::identity::values::ValueSettings,
        name: &str,
        use_counts: bool,
    ) -> Self {
        Self::with(settings, name, use_counts, false)
    }

    fn with(
        settings: glaurung::identity::values::ValueSettings,
        name: &str,
        use_counts: bool,
        weighted: bool,
    ) -> Self {
        let description = format!(
            "L3 value fingerprints: bounded concrete execution over the LLIR, \
             {} seeds x {} steps, site cap {}, filter {}, branch conditions {}, \
             {} weighted Jaccard (glaurung::identity::values)",
            settings.seed_count(),
            settings.max_steps,
            settings.site_cap_used(),
            if settings.filter { "on" } else { "OFF" },
            if settings.branch_conditions {
                "on"
            } else {
                "off"
            },
            if use_counts { "multiset" } else { "set" },
        );
        ValueScheme {
            settings,
            name: name.to_string(),
            description,
            use_counts,
            weights: std::cell::RefCell::new(None),
            weighted,
            cache: std::cell::RefCell::new(std::collections::HashMap::new()),
        }
    }

    /// Extract every sample once and build the document-frequency table.
    ///
    /// Explicit rather than lazy, and called by the driver before scoring,
    /// because a table that filled up as `evaluate` walked the corpus would
    /// make every score depend on the order the driver happened to visit
    /// samples in. That is the class of hidden order dependence this harness
    /// already had to remove once, from CFG discovery.
    pub fn prime<'a>(&self, samples: impl Iterator<Item = &'a FunctionSample>) {
        // A no-op for the unweighted configurations, and that is load-bearing:
        // priming warms the image cache, so a scheme that did not need weights
        // and was primed anyway would report an extraction cost of a Vec clone
        // instead of the interpreter run it actually pays.
        if !self.weighted {
            return;
        }
        let fingerprints: Vec<glaurung::identity::values::ValueFingerprint> = samples
            .filter_map(|sample| self.extract(sample).ok())
            .collect();
        *self.weights.borrow_mut() = Some(
            glaurung::identity::values::OccurrenceWeights::from_fingerprints(fingerprints.iter()),
        );
    }

    /// Extraction coverage over a set of samples, for the cost table.
    ///
    /// Returns `(functions measured, mean instructions retired per function,
    /// fraction of runs that hit the instruction budget, fraction of functions
    /// whose runs ALL hit it before producing a value, fraction of harvested
    /// values the address rules removed)`. The middle two are different
    /// questions: a long function that hits the budget after harvesting two
    /// hundred values is a fingerprint, and one that hits it having harvested
    /// nothing is a hole. The last one is what says whether the filter
    /// ablation could have moved anything.
    pub fn coverage<'a>(
        &self,
        samples: impl Iterator<Item = &'a FunctionSample>,
    ) -> (usize, f64, f64, f64, f64) {
        let budgets = crate::corpus::harness_budgets();
        let mut measured = 0usize;
        let mut steps = 0u64;
        let mut runs = 0u64;
        let mut budget_hits = 0u64;
        let mut observed = 0u64;
        let mut addresses = 0u64;
        let mut starved = 0usize;
        let mut by_va: BTreeMap<(PathBuf, u64), glaurung::identity::values::HarvestStats> =
            BTreeMap::new();
        let mut seen_images: std::collections::BTreeSet<PathBuf> =
            std::collections::BTreeSet::new();
        for sample in samples {
            if seen_images.insert(sample.image_path.clone()) {
                let Ok(rows) = glaurung::identity::values::fingerprints_for_path(
                    &sample.image_path,
                    self.settings,
                    &budgets,
                ) else {
                    continue;
                };
                for row in rows {
                    by_va.insert((sample.image_path.clone(), row.entry_va), row.stats);
                }
            }
            if let Some(stats) = by_va.get(&(sample.image_path.clone(), sample.va)) {
                measured += 1;
                steps += stats.steps;
                runs += u64::from(stats.seeds);
                budget_hits += u64::from(stats.budget_exhausted);
                observed += stats.filter.seen as u64;
                addresses += stats.filter.addresses_removed() as u64;
                if stats.budget_exhausted_before_any_value {
                    starved += 1;
                }
            }
        }
        if measured == 0 {
            return (0, 0.0, 0.0, 0.0, 0.0);
        }
        (
            measured,
            steps as f64 / measured as f64,
            budget_hits as f64 / runs.max(1) as f64,
            starved as f64 / measured as f64,
            addresses as f64 / observed.max(1) as f64,
        )
    }
}

#[cfg(feature = "exec")]
impl Scheme for ValueScheme {
    type Sig = glaurung::identity::values::ValueFingerprint;

    fn name(&self) -> &str {
        &self.name
    }

    fn description(&self) -> &str {
        &self.description
    }

    fn extract(&self, sample: &FunctionSample) -> Result<Self::Sig, SchemeError> {
        let mut cache = self.cache.borrow_mut();
        if !cache.contains_key(&sample.image_path) {
            let entry = glaurung::identity::values::fingerprints_for_path(
                &sample.image_path,
                self.settings,
                &crate::corpus::harness_budgets(),
            )
            .map(|rows| {
                rows.into_iter()
                    .map(|row| (row.entry_va, row.fingerprint))
                    .collect::<BTreeMap<_, _>>()
            })
            .map_err(|error| format!("{}: {error}", sample.image_path.display()));
            cache.insert(sample.image_path.clone(), entry);
        }
        match cache.get(&sample.image_path).expect("just inserted above") {
            Err(reason) => Err(SchemeError::new(reason.clone())),
            Ok(by_va) => match by_va.get(&sample.va) {
                // An empty fingerprint compares as "no answer" to everything,
                // which is indistinguishable from a function that genuinely
                // computes nothing; say so instead.
                Some(fingerprint) if !fingerprint.is_empty() => Ok(fingerprint.clone()),
                Some(_) => Err(SchemeError::new(format!(
                    "no values harvested at {:#x} in {}",
                    sample.va,
                    sample.image_path.display()
                ))),
                None => Err(SchemeError::new(format!(
                    "discovery found no function at {:#x} in {}",
                    sample.va,
                    sample.image_path.display()
                ))),
            },
        }
    }

    fn similarity(&self, a: &Self::Sig, b: &Self::Sig) -> f64 {
        let table = self.weights.borrow();
        let weights: Option<&dyn glaurung::identity::values::Weights> = table
            .as_ref()
            .map(|w| w as &dyn glaurung::identity::values::Weights);
        if self.use_counts {
            glaurung::identity::values::weighted_jaccard(a, b, weights)
        } else {
            glaurung::identity::values::weighted_jaccard_set(a, b, weights)
        }
    }
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
// `cfr` is no longer a slot: it is [`CfrScheme`] above, in both its plain and
// its peephole-normalised configuration. A TF-IDF weighting still needs a
// corpus count table, which is a second pass over the slice before scoring and
// belongs in that impl rather than in the driver.
//
// Nor is `values`: it is `ValueScheme` above, which does take that second pass
// (`ValueScheme::prime`) and so is the worked example of where corpus weights
// belong.
// ---------------------------------------------------------------------------
