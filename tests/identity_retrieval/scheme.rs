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

// ---------------------------------------------------------------------------
// Slots for the three schemes being built in parallel with this harness.
//
// Each is a `Scheme` impl of maybe twenty lines plus a test that calls
// `crate::metrics::evaluate(&scheme, corpus, &tasks)`. Nothing else in this
// file or in `metrics.rs` has to change. Deliberately NOT stubbed out as
// `todo!()` types: an empty impl that compiles is an impl that can be
// forgotten, and a scheme that extracts nothing would score 0.0 across the
// board and look like a measurement rather than an absence.
//
// * `structural` -- `src/identity/structural.rs`, the L1 rung. `Sig` is the
//   invariant tuple (MD-index top-down/bottom-up/relaxed, small-primes product
//   over normalized mnemonics, block/edge/loop/SCC counts, call degree).
//   `similarity` is a normalized distance over that tuple. Everything it needs
//   is already on `FunctionSample`: `blocks`, `edges`, `bytes`.
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
