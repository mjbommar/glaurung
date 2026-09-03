//! Function-identity retrieval harness: plan items 1 and 9 of
//! `docs/history/program-measures-2026-09-02.md`.
//!
//! # What this is for
//!
//! Four function-identity schemes are being built (WARP GUIDs, L1 structural
//! invariants, the CFR feature vector, L3 value fingerprints). Nothing can
//! rank them, or say whether any of them beats what already ships, without a
//! protocol that produces comparable numbers. This file is that protocol,
//! implemented over the matched-build fixture corpus and applied first to
//! CTPH -- the digest already in `glaurung::similarity` -- so the schemes
//! arriving later have a measured floor to clear rather than an anecdote.
//!
//! # How to run it
//!
//! ```text
//! # Default lane. Under ~90s once the corpus is loaded.
//! cargo test --test identity_retrieval
//!
//! # From a worktree, or any checkout whose fixture build directory is empty:
//! GLAURUNG_IDENTITY_CORPUS=/path/to/tests/decompiler_fixtures/build \
//!   cargo test --test identity_retrieval
//!
//! # The cross-architecture and cross-bitness lanes, over Marcelli's
//! # Dataset-1 (docs/development/corpora.md says how to fetch it):
//! GLAURUNG_CISCO_CORPUS=~/.cache/glaurung/corpora/cisco-talos-dataset1 \
//!   cargo test --test identity_retrieval
//!
//! # The full sweep: every task against the whole corpus, plus the metric
//! # axiom suite over sampled triples. Minutes, not seconds.
//! cargo test --test identity_retrieval -- --ignored --nocapture
//! ```
//!
//! # Two corpora
//!
//! The in-house fixture matrix (`corpus.rs`) varies compiler and optimisation
//! and nothing else. **Cisco Talos Dataset-1** (`cisco.rs`, plan item 9) varies
//! architecture, bitness, compiler, compiler version and optimisation, which is
//! where the XA and XB lanes come from -- and it is the corpus whose published
//! tables our numbers are meant to sit beside. Both are scored by the same
//! driver in `metrics.rs`, deliberately: two harnesses that reimplement the
//! protocol are two harnesses that will disagree about a denominator.
//!
//! Add `-- --nocapture` to see the per-task lines; every measured number is
//! printed with its pool size and its free-variable set whether or not the
//! ratchet fires. A JSON report lands in `target/identity-eval/<scheme>.json`.
//!
//! # The ratchets
//!
//! Every constant in this file was READ OFF A RUN before it was written down,
//! the discipline `tests/similarity_retrieval.rs` established. A number may
//! only tighten: falling below the floor is a regression, and rising more than
//! [`RATCHET_SLACK`] above it fails too, because a ratchet that has silently
//! fallen behind reality has stopped reporting regressions.
//!
//! # What is deliberately NOT here
//!
//! No threshold on "is this the same function". A raw similarity score has no
//! natural cut-off and any constant invented here would be a number to argue
//! about; retrieval has none of that problem and is the question an analyst
//! actually asks.

mod cisco;
mod corpus;
mod metrics;
mod rerank;
mod scheme;
mod tasks;

use corpus::{Corpus, MIN_BASIC_BLOCKS};
use metrics::{SchemeReport, NEGATIVES_PER_POSITIVE};
use scheme::{CfrScheme, CtphScheme, Scheme, StructuralScheme};
use tasks::TASKS;

/// How far above its floor a measurement may drift before this file demands
/// the floor be raised.
///
/// Same value and same reasoning as `tests/similarity_retrieval.rs`: a ratchet
/// two percentage points behind reality is no longer a ratchet.
const RATCHET_SLACK: f64 = 0.02;

// ---------------------------------------------------------------------------
// Measured ratchets for CTPH under this protocol.
//
// Produced by one run against the 206-fixture corpus on 2026-09-02, with the
// published filters applied (see `corpus::FilterCounts`) and ties resolved
// pessimistically. These numbers are NOT comparable to the ones in
// `tests/similarity_retrieval.rs`: that file scores every named text symbol
// with first-wins tie handling, this one scores only functions of
// MIN_BASIC_BLOCKS blocks or more with ties counted against the twin. The
// filters are the reason -- a number computed without them is not comparable
// to a published one, and a number computed WITH them is not comparable to one
// computed without.
// ---------------------------------------------------------------------------

/// XO (gcc O0 -> gcc O2), AUC over 389 positive and 38,900 sampled-negative
/// pairs, pool 410.
///
/// **Measured: 0.5015.** Chance is 0.5000. Fifteen ten-thousandths of signal.
/// The mean positive pair scores 0.0003 and the mean negative 0.0001: at
/// function granularity two CTPH digests essentially never share a block,
/// whether or not they are the same function, so the separation is real,
/// positive, and worth nothing. This is the published behaviour of the
/// representation class, not a defect in the implementation -- and it is the
/// floor the L1/L2 schemes have to clear.
const CTPH_XO_GCC_MIN_AUC: f64 = 0.5015;

/// XO (gcc O0 -> gcc O2), Recall@1 against 100 sampled negatives.
///
/// **Measured: 0.0051 (2 of 389).** Chance at 101 candidates is 0.0099, so
/// CTPH is retrieving the right answer at HALF the rate a coin would -- which
/// is what pessimistic tie handling reports for a score that is zero almost
/// everywhere. Reading it as "worse than chance" would be wrong; reading it as
/// "carries no rankable information" is right.
const CTPH_XO_GCC_MIN_RECALL_AT_1: f64 = 0.005141;

/// XM (gcc O0 -> clang O2), AUC. Both compilation variables free: the hardest
/// task this corpus can express, and the one the protocol document says byte
/// digests collapse on.
///
/// **Measured: 0.5025** over 365 positives, pool 377. Note it is not WORSE
/// than XO's 0.5015: the digest is carrying so little that neither
/// transformation can make it carry less. `tests/similarity_retrieval.rs`
/// records the same non-effect at top-1.
const CTPH_XM_MIN_AUC: f64 = 0.5025;

/// XM, Recall@1 against the whole clang O2 pool of 377.
///
/// **Measured: 0.005479 (2 of 365)**, chance 0.002653. Pinned at the truncated
/// value, not the rounded one: `2/365` is `0.0054794...`, and a ratchet
/// written as `0.0055` is a ratchet the current code fails.
const CTPH_XM_MIN_GLOBAL_RECALL_AT_1: f64 = 0.005479;

/// Ceiling on the mean `extract` cost, microseconds per function.
///
/// **Measured: 41.2 us/function over 1,787 samples, DEBUG profile.** TikNib is
/// 20-1030 us; report 01 (3.8) says a design that cannot hit that order is not
/// usable for a 6,000-function kernel diff, and CTPH sits inside it even
/// unoptimised.
///
/// This one is a **ceiling, not a ratchet**, and deliberately loose: it is a
/// wall-clock number on a shared developer machine, where the recorded
/// experience in CLAUDE.md is that timing baselines record false failures
/// under load. A tight floor here would fail for reasons that have nothing to
/// do with the code. It still catches the class of change that matters -- an
/// extraction that becomes an order of magnitude more expensive.
const CTPH_MAX_EXTRACTION_US: f64 = 400.0;

// ---------------------------------------------------------------------------
// Measured ratchets for `structural` under this protocol. Read off the run
// recorded in `docs/development/identity-measurement.md` (2026-09-02, debug
// profile). Same discipline as the CTPH constants above: read off a run,
// never guessed.
// ---------------------------------------------------------------------------

/// XO (gcc O0 -> gcc O2), AUC over 389 scored queries, pool 410.
///
/// **Measured: 0.753603.** Structural counts (edge/block/instruction ratios)
/// and the MD-index both survive an optimisation-level change far better than
/// either byte digest does -- CTPH is 0.5015 on the same task.
///
/// CTPH computes purely from `sample.bytes`, which discovery's *filtering*
/// (kept/dropped) can affect but its *shape* never can. `structural` reads
/// the discovered CFG itself -- block and edge counts, the MD-index -- and
/// `analysis::cfg`'s per-function walk carries a wall-clock budget
/// (`Budgets::timeout_ms`/`total_timeout_ms`; see CLAUDE.md, "Baseline regen
/// needs a quiet machine"), which used to make this scheme **not
/// bit-reproducible run to run** the way CTPH's ratchets are (sixteen repeated
/// runs of `structural_full_sweep`, 2026-09-02, debug profile,
/// otherwise-idle machine, landed between **0.752733 and 0.753918**). That
/// was traced to `Budgets::default().timeout_ms` (100ms), a *per-function*
/// clock whose firing point depends on CPU contention rather than on the
/// bytes analysed (`docs/design/cfg-discovery-determinism-2026-09-02.md`).
/// The harness now calls [`crate::corpus::harness_budgets`], which sets
/// `timeout_ms` to `u64::MAX` so the clock can never fire; three repeated
/// runs afterward reproduced **0.753603** bit for bit on every task in this
/// file, and the margin discipline below is kept only as a cushion against
/// legitimate future scheme changes, not against measurement noise.
const STRUCTURAL_XO_GCC_MIN_AUC: f64 = 0.750000;

/// XC-O2 (gcc O2 -> clang O2), AUC and MRR10 over 357 scored queries, pool
/// 377.
///
/// **Sixteen runs: AUC in [0.723691, 0.724972], MRR10 in [0.238081,
/// 0.239065].** In the same band as the Python structural fingerprint's
/// XC-O2 (AUC 0.7287, MRR10 0.2241) -- a CFG-shape scheme and a
/// token-normalised one land on the same compiler-swap ceiling by different
/// routes. Floors set below the observed minimum; see
/// [`STRUCTURAL_XO_GCC_MIN_AUC`] for why this scheme's ratchets carry margin
/// that CTPH's do not.
const STRUCTURAL_XC_O2_MIN_AUC: f64 = 0.720000;
const STRUCTURAL_XC_O2_MIN_MRR10: f64 = 0.230000;

/// XM (gcc O0 -> clang O2), AUC over 365 scored queries, pool 377. Both
/// compilation variables free -- the task every token-level representation in
/// the literature collapses on.
///
/// **Sixteen runs: AUC in [0.702408, 0.704658].** This is the number that
/// matters most: unlike the Python structural fingerprint (XM AUC 0.5150,
/// essentially chance), `structural` does NOT collapse here, in any of the
/// sixteen runs. Block/edge/instruction count ratios and the MD-index depend
/// on the recovered CFG shape rather than on a mnemonic n-gram, so a
/// simultaneous compiler-and-optimisation change moves them less than it
/// moves a token-level signal. Floor set below the observed minimum.
const STRUCTURAL_XM_MIN_AUC: f64 = 0.695000;

/// Ceiling on the mean `extract` cost, microseconds per function, shared by
/// both corpora.
///
/// **Measured, in-house: 223-655 us/function over 1,787 x86-64 samples,
/// DEBUG profile, across sixteen-plus runs.** **Measured, Dataset-1: 693-1388
/// us/function over 2,441 samples spanning six architectures, three runs.**
/// The Cisco number is higher for a real reason, not a regression: several of
/// its architectures resolve through `disasm::capstone` rather than
/// `disasm::iced`, and `StructuralScheme` builds one backend per
/// `(Architecture, Endianness)` pair the first time it is seen -- a
/// nine-configuration slice therefore pays for four-plus Capstone backend
/// constructions where the in-house corpus pays for one Iced backend, ever.
/// A release build should be several times faster (`maturin develop
/// --release` / `cargo test --release`), per CLAUDE.md's note that a debug
/// profile is not what ships. Inside TikNib's 20-1030 us band on the in-house
/// corpus even unoptimised, and costlier than CTPH's 41.2 us because this
/// scheme re-decodes the function's instruction stream (for the mnemonic SPP
/// and the rare-constant multiset) where CTPH only rolls a hash over raw
/// bytes. Deliberately loose for the same reason `CTPH_MAX_EXTRACTION_US` is:
/// wall clock on a shared developer machine.
const STRUCTURAL_MAX_EXTRACTION_US: f64 = 2500.0;

// ---------------------------------------------------------------------------
// L2 CFR ratchets, plan items 4 and 5 of
// `docs/history/program-measures-2026-09-02.md`. Every value below was read
// off the release run of 2026-09-02 recorded in
// `docs/development/identity-measurement.md`, then floored a little under it
// -- never predicted, and never rounded up from a four-decimal print.
// ---------------------------------------------------------------------------

/// The CFR's XO-gcc AUC over the whole corpus, no normaliser, uniform weights.
///
/// **Measured 0.7569.** Above `structural`'s 0.7536 by a hair, which is the
/// least interesting comparison in this file: the interesting ones are the two
/// lever rows -- the normaliser (0.7583 on the same population) and the
/// weighting (0.8592 on the held-out half) -- because cross-optimisation is
/// where both were predicted to help most and where both do.
const CFR_XO_GCC_MIN_AUC: f64 = 0.7568;

/// XO (gcc O0 -> gcc O2) Recall@1 for the plain CFR, 100 sampled negatives.
///
/// **Measured: 0.1799** (70 of 389) against 0.0099 chance. The number in
/// `tests/identity_cfr_retrieval.rs` for the same representation on the same
/// corpus is 0.1496, and the difference is entirely the filter set: that file
/// drops functions whose canonical form is shared with another in the slice,
/// this one does not, and it samples its negatives with a seeded draw rather
/// than by nearest size. Neither number is wrong and neither is comparable to
/// the other -- which is exactly the failure the protocol document names.
const CFR_XO_GCC_MIN_RECALL_AT_1: f64 = 0.1799;

/// XO (gcc O0 -> gcc O2) MRR10 for the plain CFR.
///
/// **Measured: 0.2543.** FunctionSimSearch's published ceiling is MRR10 0.26,
/// and this is a whole representation class above the token fingerprint that
/// sits in FunctionSimSearch territory -- on the hardest of the four in-house
/// lanes.
const CFR_XO_GCC_MIN_MRR10: f64 = 0.2542;

/// The CFR's XC-O2 AUC over the whole corpus, uniform weights.
///
/// **Measured 0.8921**, against `structural`'s 0.7238 and the Python
/// fingerprint's 0.7287 on the identical task. A compiler swap at a fixed
/// optimisation level is precisely what the mask list erases -- register
/// allocation, instruction selection, block order -- so this is the cell the
/// representation was designed for and the one it should win by the most.
const CFR_XC_O2_MIN_AUC: f64 = 0.8920;

/// **Measured 0.5688**, against `structural`'s 0.2381 and FunctionSimSearch's
/// published 0.26 ceiling for token-shaped representations.
const CFR_XC_O2_MIN_MRR10: f64 = 0.560000;

/// The CFR's XM AUC over the whole corpus, uniform weights.
///
/// **Measured 0.7296**, against `structural`'s 0.7026. The bar the previous
/// version of `docs/development/identity-measurement.md` set for a new scheme
/// was "beats 0.70" on this task, and this clears it -- narrowly, unweighted.
/// Weighted, on the held-out half, XM reaches 0.8131.
const CFR_XM_MIN_AUC: f64 = 0.7295;

/// Extraction ceiling, deliberately loose for two reasons rather than one.
///
/// The usual one first: this is wall clock on a shared developer machine,
/// where a tight floor fails for reasons unrelated to the code. The second is
/// specific to this scheme. **Measured 1,810 us/function in a release build**
/// -- already an order of magnitude past TikNib's published 20-1030 us band,
/// because the CFR is the only scheme here that lifts to LLIR and runs SSA
/// rather than reading bytes or a discovered CFG. The ordinary gate
/// (`cargo test --features python-ext`) is a *debug* build, where the same
/// work is roughly ten times slower, and this constant has to admit both.
///
/// A ceiling that admits a 30x range is not a performance gate; it is a
/// tripwire for an extraction that becomes another order of magnitude more
/// expensive. The real number, with its profile named, belongs in the docs
/// table, and it is there.
const CFR_MAX_EXTRACTION_US: f64 = 60_000.0;

// --- The normaliser lever (plan item 8), whole corpus, uniform weights. Every
// value read off the release run of 2026-09-02, same corpus and same driver as
// the plain rows above, so the two differ by the normaliser and nothing else.

/// XO AUC with the normaliser. **Measured: 0.7583**, against 0.7569 plain.
const CFR_NORM_XO_GCC_MIN_AUC: f64 = 0.7582;
/// XO Recall@1 with the normaliser.
///
/// **Measured: 0.2031** (79 of 389), against 0.1799 (70 of 389) plain: nine
/// more functions retrieved, +2.32 percentage points, a 12.9% relative gain.
/// This is the same movement `tests/identity_cfr_retrieval.rs` reports as
/// 14.96% -> 17.60% under its own filter set, measured a second way.
const CFR_NORM_XO_GCC_MIN_RECALL_AT_1: f64 = 0.2030;
/// XO MRR10 with the normaliser. **Measured: 0.2657**, against 0.2543 plain.
const CFR_NORM_XO_GCC_MIN_MRR10: f64 = 0.2656;
/// XC (O2) AUC with the normaliser.
///
/// **Measured: 0.8856**, against 0.8921 plain -- a *loss* of 0.0065, while the
/// same lane's Recall@1 rises from 0.5014 to 0.5182 and its MRR10 from 0.5688
/// to 0.5790. Both directions are recorded because both are real: the
/// normaliser makes the top of the ranking better and the whole-distribution
/// separation slightly worse on the cross-compiler lane, and a lane summary
/// that quoted only the metric that improved would be choosing its evidence.
/// The XC-O0 lane moves the same way (Recall@1 0.8706 -> 0.8624, AUC
/// unchanged at 0.9663).
const CFR_NORM_XC_O2_MIN_AUC: f64 = 0.8855;
/// XM AUC with the normaliser. **Measured: 0.7329**, against 0.7296 plain.
const CFR_NORM_XM_MIN_AUC: f64 = 0.7328;

/// The weighted CFR's AUC floor per task, on the held-out half.
///
/// **Read off the release run of 2026-09-02.** The population is the half of
/// the corpus the weight table never counted (see
/// `scheme::cfr_in_training_half`), so these denominators are roughly half the
/// unweighted lane's and the rows are not comparable with `CFR_*_MIN_AUC`
/// above -- the row they *are* comparable with is `cfr-heldout`, which
/// `cfr_weighting_ratchets` prints beside each of these.
///
/// The deltas that run printed, unweighted -> weighted:
///
/// | Task | AUC | MRR10 | R@1 |
/// |---|---|---|---|
/// | XO-gcc | 0.7800 -> 0.8592 (+0.079) | 0.2549 -> 0.5080 (+0.253) | 0.1872 -> 0.4064 (+0.219) |
/// | XO-clang | 0.7419 -> 0.8152 (+0.073) | 0.1829 -> 0.3729 (+0.190) | 0.1124 -> 0.2809 (+0.169) |
/// | XC-O0 | 0.9679 -> 0.9938 (+0.026) | 0.9501 -> 0.9557 (+0.006) | 0.9253 -> 0.9253 (0.000) |
/// | XC-O2 | 0.8935 -> 0.9461 (+0.053) | 0.5681 -> 0.6549 (+0.087) | 0.5116 -> 0.5698 (+0.058) |
/// | XM | 0.7625 -> 0.8131 (+0.051) | 0.1984 -> 0.4232 (+0.225) | 0.1243 -> 0.3333 (+0.209) |
///
/// The plan's hypothesis was that weighting lifts **XO** most, and it does, on
/// every metric: the largest AUC gain (+0.079) and the largest ranking gains
/// (+0.253 MRR10, +0.219 Recall@1). The mechanism is visible in the two
/// already-strong cells: XC-O0 was at 0.968 unweighted and had almost nothing
/// left to gain, while XO was at 0.780 and the features that separate a
/// function from its `-O2` twin's neighbours are exactly the rare ones a
/// uniform weighting drowns in `mov`-shaped noise.
const CFR_WEIGHTED_MIN_AUC: &[(&str, f64)] = &[
    ("XO-gcc", 0.852000),
    ("XO-clang", 0.808000),
    ("XC-O0", 0.988000),
    ("XC-O2", 0.939000),
    ("XM", 0.806000),
];

/// The **normalised AND weighted** CFR's AUC floor per task, on the held-out
/// half: the fourth cell of the 2x2, and the row this integration branch
/// exists to produce.
///
/// The two levers were built on separate branches and are independent by
/// construction -- `normalize` rewrites the lifted function before the graph is
/// built, so it changes the REPRESENTATION; a TF-IDF table changes the METRIC
/// over whichever representation it was counted on. Nothing about either
/// mechanism predicts how they compose, which is why the cell is measured
/// rather than argued: a weighting counted over normalised vectors is counting
/// a different feature vocabulary, and normalisation collapses some rare
/// features into common ones, which is exactly the sort of interaction that can
/// eat a rarity weighting's advantage.
///
/// The weight table for this row is counted over the training half **with the
/// normaliser on**, under its own `CfrVersion` -- see
/// `scheme::cfr_train_weights`. Applying the unnormalised table here would
/// weight a vocabulary the normalised representation does not produce.
///
/// Floors read off the release run of 2026-09-02 recorded in
/// `docs/reference/function-identity-cfr.md`, on the same held-out population
/// as `CFR_WEIGHTED_MIN_AUC` (identical `scored` counts, asserted by
/// `the_two_cfr_levers_compose`), so the two tables are directly comparable.
///
/// What that run says, weighted -> normalised+weighted:
///
/// | Task | AUC | MRR10 | R@1 |
/// |---|---|---|---|
/// | XO-gcc | 0.8592 -> 0.8717 (+0.013) | 0.5080 -> 0.4928 (-0.015) | 0.4064 -> 0.3904 (-0.016) |
/// | XO-clang | 0.8152 -> 0.8342 (+0.019) | 0.3729 -> 0.3919 (+0.019) | 0.2809 -> 0.2921 (+0.011) |
/// | XC-O0 | 0.9938 -> 0.9942 (+0.000) | 0.9557 -> 0.9581 (+0.002) | 0.9253 -> 0.9336 (+0.008) |
/// | XC-O2 | 0.9461 -> 0.9487 (+0.003) | 0.6549 -> 0.6723 (+0.017) | 0.5698 -> 0.5930 (+0.023) |
/// | XM | 0.8131 -> 0.8390 (+0.026) | 0.4232 -> 0.4405 (+0.017) | 0.3333 -> 0.3503 (+0.017) |
///
/// **The levers compose on AUC on all five tasks, and the sum is smaller than
/// the parts.** The weighting alone is worth +0.079 AUC on XO-gcc and the
/// normaliser alone is worth -0.003 on the same cell; together they are +0.092,
/// so the normaliser's contribution is larger in the presence of the weighting
/// than on its own. The mechanism is the one the weighting section already
/// describes: normalisation folds lifter boilerplate into fewer, commoner
/// features, and an IDF table is exactly the thing that stops common features
/// from costing anything -- so each lever removes some of the noise the other
/// one has to survive.
///
/// **And the one cell where they do not compose is recorded rather than
/// dropped.** On XO-gcc the combined row's *ranking* metrics are slightly
/// worse than the weighting alone (MRR10 -0.015, R@1 -0.016: three fewer
/// functions retrieved at rank 1 of 187) while its AUC is better. That is the
/// same shape the normaliser lane already reported on XC-O2 unweighted, in the
/// other direction, and it has the same reading: AUC is whole-distribution
/// separation and R@1 is the top of the ranking, and a rewrite that pulls the
/// bulk of the negatives away can still shuffle the first few candidates. Four
/// of the five tasks improve on every metric; this one does not, and a summary
/// that quoted only AUC would be choosing its evidence.
const CFR_NORM_WEIGHTED_MIN_AUC: &[(&str, f64)] = &[
    ("XO-gcc", 0.864000),
    ("XO-clang", 0.827000),
    ("XC-O0", 0.988000),
    ("XC-O2", 0.941000),
    ("XM", 0.832000),
];

/// The CFR's measured Dataset-1 AUC floor per task, uniform weights over the
/// whole corpus.
///
/// **Read off the release run of 2026-09-02**, nine configurations of gcc 9
/// and clang 9 over the three `nmap`-project libraries, `testing` split,
/// sampled pool 101 throughout. Set beside `structural`'s floors, which are
/// the numbers this scheme had to beat:
///
/// | Task | `structural` | `cfr` |
/// |---|---|---|
/// | XO | 0.8283 | **0.9127** |
/// | XC | 0.8851 | **0.9638** |
/// | XM | 0.8045 | **0.8806** |
/// | XB | 0.8985 | **0.9353** |
/// | XA-arm64 | 0.9486 | 0.9131 |
///
/// Four of the five improve, and the one that does not is the cell a
/// CFG-shape scheme was already strongest on. Read against Marcelli's Table 3
/// the XC cell (0.964) is above every published row including GMN + BoW
/// opcodes (0.85), on a much smaller query set -- 65 scored queries against
/// his 50k pairs -- so it is comparable in kind and not in confidence
/// interval.
const CISCO_CFR_MIN_AUC: &[(&str, f64)] = &[
    ("XO", 0.905000),
    ("XC", 0.956000),
    ("XM", 0.873000),
    ("XB", 0.928000),
    ("XA-arm64", 0.906000),
];

/// Dataset-1 tasks the CFR scores, but on too few twins to quote.
///
/// The same two rows CTPH and `structural` cannot quote, for the same reason:
/// the selection CSV samples about a tenth of each binary's functions
/// independently, so the *twin join* between two slices is small even though
/// the slices are not.
const CISCO_CFR_UNDERPOWERED_TASKS: &[&str] = &["XA+XB-arm32", "XA+XO"];

/// Dataset-1 tasks whose pool the LLIR lifter cannot reach at all.
///
/// `src/ir/lift/` covers x86, x86-64, ARM and AArch64; `disasm::registry`
/// reaches MIPS only through Capstone. So on these two slices the CFR has no
/// signature to give, and `CfrScheme::extract` refuses rather than returning
/// an empty vector -- which would score 0.0 against everything and read as a
/// measured failure instead of a coverage hole.
///
/// This is the one place in this file where a *zero* is the assertion. CTPH
/// scored these rows at exactly 0.5000 (chance) and `structural` at 0.574 and
/// 0.552; the CFR scores them not at all, and that difference is the honest
/// one. If a MIPS lifter ever lands, `cisco_cfr_retrieval_ratchets` fires and
/// says to promote them.
const CISCO_CFR_UNLIFTABLE_TASKS: &[&str] = &["XA-mips64", "XA+XB-mips32"];

/// CTPH's measured AUC floor on each Cisco Dataset-1 task.
///
/// **Read off a run, not predicted.** Every value here is the truncated
/// measurement from the run recorded in
/// `docs/development/identity-measurement.md`, over the nine-configuration,
/// three-library default slice of the `testing` split. Sampled pool is 101
/// throughout, so chance Recall@1 is 0.0099 and chance AUC is 0.5000.
///
/// A table rather than one constant per task because there are nine of them
/// and a per-task constant would be nine near-identical doc comments; the task
/// names are checked against `cisco::TASKS` by the test that reads this, so a
/// task renamed on one side fails rather than silently stops being ratcheted.
/// Reading them: **only XC (0.5402) is meaningfully off chance**, and it is
/// the single-free-variable case Marcelli's Table 3 shows byte hashes doing
/// best on (Catalog1-128 scores 0.86 on the compiler axis). Everything with an
/// architecture free is 0.5000 to four decimals -- CTPH is not near chance
/// there, it is *exactly* chance, because two digests over two instruction
/// sets never share a block and the pessimistic tie rule then ranks every
/// candidate ahead of the twin. That is the shape of the result the protocol
/// document predicts, now measured on the corpus the prediction came from.

const CISCO_CTPH_MIN_AUC: &[(&str, f64)] = &[
    // Marginally BELOW chance: mean negative 0.0001 against mean positive
    // 0.0000. Worth seeing rather than clamping.
    ("XO", 0.499),
    ("XC", 0.540220),
    ("XM", 0.512110),
    ("XB", 0.499722),
    ("XA-arm64", 0.5),
    ("XA-mips64", 0.499824),
    ("XA+XB-mips32", 0.5),
];

/// Dataset-1 tasks whose twin join is too small for the row to be quoted.
///
/// The selection CSV samples each binary independently, so how many queries a
/// task scores is a property of Marcelli's sampling and not of the scheme. The
/// two here are the tasks that cross an architecture *and* a second variable,
/// where the surviving overlap is smallest. They still run, and their numbers
/// are still printed and written to JSON with `underpowered: true`; they are
/// simply not ratcheted.
const CISCO_UNDERPOWERED_TASKS: &[&str] = &["XA+XB-arm32", "XA+XO"];

/// `structural`'s measured AUC floor on each (stable) Dataset-1 task, read
/// off four-plus repeated runs recorded in
/// `docs/development/identity-measurement.md` (2026-09-02, debug profile, the
/// nine-configuration default slice). Floored with a small margin below the
/// observed minimum, same discipline as the in-house constants above -- XO,
/// XC, XM, XB and XA-arm64 were bit-identical or near-identical across every
/// run (spread under 0.0003), so the margin here is smaller than the
/// in-house one.
///
/// Reading it against CTPH's table just above: every row here clears CTPH's
/// by 0.3 to 0.45 AUC, including the two architecture-free rows CTPH could not
/// separate from chance at all. **XA-arm64 (0.9486)** is the standout -- a
/// CFG's shape (block/edge counts, MD-index, loop structure) survives an
/// instruction-set change far better than either a byte digest or a mnemonic
/// n-gram, because neither of those two representations transfers across an
/// ISA at all.
///
/// **XA-mips64 and XA+XB-mips32 were un-exempted on 2026-09-02** (see
/// `docs/design/cfg-discovery-determinism-2026-09-02.md` and
/// [`crate::corpus::harness_budgets`]): the run-to-run spread that put them in
/// [`CISCO_STRUCTURAL_NOISY_TASKS`] was `analysis::cfg`'s per-function
/// wall-clock budget, not a property of MIPS discovery itself. With the
/// harness's `timeout_ms` fixed at `u64::MAX`, three repeated runs of
/// `cisco_structural_full_sweep` landed on the exact same `f64` --
/// `0.5741782086795937` (XA-mips64) and `0.5524480968858132`
/// (XA+XB-mips32) -- bit for bit, not just to four decimals. Floors below are
/// truncated with the same small margin as every other row now that there is
/// a real minimum to floor, not a noise band to dodge.
const CISCO_STRUCTURAL_MIN_AUC: &[(&str, f64)] = &[
    ("XO", 0.826000),
    ("XC", 0.883000),
    ("XM", 0.802000),
    ("XB", 0.896000),
    ("XA-arm64", 0.946000),
    ("XA-mips64", 0.572000),
    ("XA+XB-mips32", 0.550000),
];

/// Dataset-1 tasks that are powered (>= `MIN_SCORED_FOR_A_MEASUREMENT`
/// queries) but whose measured AUC varies, run to run, by more than
/// [`RATCHET_SLACK`] -- so no fixed floor can satisfy both
/// `assert_ratchet`'s bounds without either flaking on a low run or
/// complaining "raise the ratchet" on a high one.
///
/// **Empty as of 2026-09-02.** Previously `["XA-mips64", "XA+XB-mips32"]`:
/// `XA-mips64` measured over three repeated runs of `cisco_structural_
/// full_sweep` at AUC 0.581433, 0.587764, 0.604009 -- a spread of 0.0226,
/// wider than `RATCHET_SLACK` (0.02) itself; `XA+XB-mips32` similarly spread
/// 0.573209-0.585727 across four runs. That was never a property of MIPS
/// discovery -- it was `analysis::cfg`'s per-function wall-clock budget
/// (`Budgets::timeout_ms`, restarted at every seed) racing CPU contention on
/// a shared machine, diagnosed in
/// `docs/design/cfg-discovery-determinism-2026-09-02.md`. The harness now
/// calls [`crate::corpus::harness_budgets`] instead of `Budgets::default()`,
/// which sets `timeout_ms` to `u64::MAX` so the clock can never fire; three
/// repeated runs of `cisco_structural_full_sweep` afterwards produced the
/// exact same `f64` for both tasks, not merely the same four decimals. They
/// moved to [`CISCO_STRUCTURAL_MIN_AUC`] with floors read off that run. This
/// constant is kept (empty) rather than deleted, and the loop below over it
/// with the length-accounting `assert_eq!` after it, so a future scheme that
/// reintroduces genuine run-to-run noise on some other task has a named place
/// to land instead of a silently unratcheted task.
const CISCO_STRUCTURAL_NOISY_TASKS: &[&str] = &[];

/// Load the corpus, or print the skip and return `None`.
fn load() -> Option<&'static Corpus> {
    corpus::corpus()
}

/// Score CTPH over every supported task, once, shared by the tests below.
fn ctph_report() -> Option<&'static SchemeReport> {
    use std::sync::OnceLock;
    static REPORT: OnceLock<Option<SchemeReport>> = OnceLock::new();
    REPORT
        .get_or_init(|| {
            let corpus = load()?;
            let scheme = CtphScheme::default();
            let report = metrics::evaluate(&scheme, corpus, TASKS);
            eprintln!(
                "\n=== scheme {} -- {} ===",
                report.scheme, report.description
            );
            eprintln!(
                "extraction {:.2} us/function over {} samples",
                report.extraction_us_per_function, report.extraction_samples
            );
            for result in &report.results {
                eprintln!("{}", result.line());
            }
            if let Some(path) = report.write_json(&metrics::report_dir()) {
                eprintln!("report: {}", path.display());
            }
            Some(report)
        })
        .as_ref()
}

/// The corpus must be big enough for any of the numbers below to mean
/// anything, and its filters must actually have removed something.
///
/// A filter that removes nothing is a filter that is not running -- the
/// specific way a "protocol-compliant" harness stops being comparable while
/// every test stays green.
#[test]
fn corpus_loads_with_the_published_filters_applied() {
    let Some(corpus) = load() else { return };

    let f = corpus.filters;
    assert!(
        f.considered >= 2_000,
        "only {} named text symbols across four slices of 206 fixtures; the \
         corpus is truncated, not filtered",
        f.considered
    );
    assert!(
        f.dropped_small > 0,
        "the <{MIN_BASIC_BLOCKS}-block filter removed nothing out of {} \
         candidates. Either CFG discovery returned no blocks (check \
         `dropped_no_cfg` = {}) or the filter is not running.",
        f.considered,
        f.dropped_no_cfg
    );
    // NOT asserted: that the PLT/CRT filter removed something. It removes
    // exactly zero here, because these are single-translation-unit shared
    // objects whose `.symtab` has no `@plt` names and whose CRT symbols carry
    // `st_size == 0` -- they are counted as `skipped_unsized` and never reach
    // the filter. `corpus::tests::plt_and_crt_names_are_recognised` tests the
    // rule directly so its zero here is evidence about the CORPUS rather than
    // about the filter.
    assert!(
        f.skipped_unsized > 0,
        "no zero-sized text symbols across four slices; gcc and clang both \
         emit `frame_dummy` and `register_tm_clones` that way, so the symbol \
         walk is not seeing what it should"
    );
    assert!(
        f.kept >= 400,
        "only {} functions survived the filters, out of {} considered. Every \
         metric below is computed on that population, and at this size the \
         strata cannot be split.",
        f.kept,
        f.considered
    );

    // Every slice must be usable on its own: a task whose pool is a handful of
    // functions reports a pool size that makes its own numbers meaningless.
    for slice in corpus.slices() {
        assert!(
            slice.samples.len() >= 80,
            "{}/{} kept only {} functions: {}",
            slice.compiler,
            slice.opt,
            slice.samples.len(),
            slice.filters.summary()
        );
    }
}

/// Ground truth must be a real join, and the negative sampler must have room
/// to draw the pool the metrics claim.
#[test]
fn ground_truth_join_and_negative_pool_are_sound() {
    let Some(report) = ctph_report() else { return };

    for result in &report.results {
        assert!(
            result.scored > 0,
            "{}: no query had a twin in the pool. The (fixture, name) join is \
             broken, not the scheme. Conditions: {}",
            result.task_name,
            result.conditions
        );
        // The sampled-pool metrics say "1 twin + 100 negatives". If the pool
        // cannot supply 100 distinct negatives that claim is false and R@50
        // in particular becomes meaningless.
        assert!(
            result.global_pool_size > NEGATIVES_PER_POSITIVE,
            "{}: pool of {} cannot supply {} distinct negatives, so the \
             reported sampled pool size of {} is a fiction",
            result.task_name,
            result.global_pool_size,
            NEGATIVES_PER_POSITIVE,
            result.sampled_pool_size
        );
    }

    // The strata must partition the XM queries: if one is empty its row is a
    // zero that looks like a measurement.
    let xm = report.result("XM").expect("XM ran");
    let strata: usize = ["XM-S", "XM-M", "XM-L"]
        .iter()
        .filter_map(|n| report.result(n))
        .map(|r| r.queries_in_scope)
        .sum();
    assert_eq!(
        strata, xm.queries_in_scope,
        "the three size strata hold {strata} queries but XM holds {}; the \
         bands do not partition the query set",
        xm.queries_in_scope
    );

    // The five whole-corpus tasks must each be powered enough to quote. Only
    // XM-L is not, and it must stay flagged rather than quietly becoming a row
    // someone reads as a result.
    for name in ["XO-gcc", "XO-clang", "XC-O0", "XC-O2", "XM"] {
        let r = report.result(name).expect("task ran");
        assert!(
            !r.underpowered(),
            "{name} scored only {} queries, below {}: {}",
            r.scored,
            metrics::MIN_SCORED_FOR_A_MEASUREMENT,
            r.line()
        );
    }
    let xm_l = report.result("XM-L").expect("XM-L ran");
    assert!(
        xm_l.underpowered(),
        "XM-L now scores {} queries, at or above {}. That is a real \
         improvement in corpus coverage: quote the row, drop this assertion, \
         and add XM-L to the powered list above.",
        xm_l.scored,
        metrics::MIN_SCORED_FOR_A_MEASUREMENT
    );
}

/// A scheme must recognise a function as itself, and its similarity must be
/// symmetric and bounded.
///
/// These are the metric axioms the protocol document asks to ship with the
/// first hash (identity on the quotient, symmetry, range). They are cheap,
/// they are the properties every downstream index assumes, and they hold for a
/// scheme that is otherwise useless -- which is why they are separate from the
/// retrieval numbers rather than folded into them.
#[test]
fn ctph_obeys_the_similarity_axioms() {
    let Some(corpus) = load() else { return };
    let scheme = CtphScheme::default();
    let Some(slice) = corpus.slice("gcc", "O0") else {
        return;
    };
    assert!(slice.samples.len() >= 80);

    let mut checked = 0usize;
    for (i, a) in slice.samples.iter().enumerate() {
        let Ok(sig_a) = scheme.extract(a) else {
            continue;
        };
        let self_score = scheme.similarity(&sig_a, &sig_a);
        assert!(
            (self_score - 1.0).abs() < 1e-9,
            "{}::{} does not match itself: {self_score}",
            a.fixture,
            a.name
        );
        // Symmetry and range against the next sample in the sorted slice: a
        // fixed, deterministic partner rather than a sampled one.
        if let Some(b) = slice.samples.get(i + 1) {
            if let Ok(sig_b) = scheme.extract(b) {
                let ab = scheme.similarity(&sig_a, &sig_b);
                let ba = scheme.similarity(&sig_b, &sig_a);
                assert!(
                    (ab - ba).abs() < 1e-12,
                    "asymmetric: {}::{} vs {}::{} scored {ab} and {ba}",
                    a.fixture,
                    a.name,
                    b.fixture,
                    b.name
                );
                assert!(
                    (0.0..=1.0).contains(&ab),
                    "score {ab} outside [0, 1] for {}::{} vs {}::{}",
                    a.fixture,
                    a.name,
                    b.fixture,
                    b.name
                );
                checked += 1;
            }
        }
    }
    assert!(
        checked >= 80,
        "only {checked} axiom checks ran; extraction is failing across the slice"
    );
}

/// Extraction must be deterministic across calls.
///
/// A signature that varies run to run makes every ratchet in this file flaky
/// rather than wrong, which is far harder to diagnose. `HashMap` iteration
/// order and an unseeded RNG are the two usual sources; this catches both
/// within one process, and the JSON report catches the across-process case by
/// being diffable.
#[test]
fn ctph_extraction_is_deterministic() {
    let Some(corpus) = load() else { return };
    let scheme = CtphScheme::default();
    let Some(slice) = corpus.slice("gcc", "O2") else {
        return;
    };
    let mut checked = 0usize;
    for sample in slice.samples.iter().take(200) {
        let (Ok(first), Ok(second)) = (scheme.extract(sample), scheme.extract(sample)) else {
            continue;
        };
        assert_eq!(
            first, second,
            "{}::{} extracted two different signatures",
            sample.fixture, sample.name
        );
        checked += 1;
    }
    assert!(checked >= 80, "only {checked} determinism checks ran");
}

/// The CTPH ratchets: what the shipped byte digest actually scores under this
/// protocol.
#[test]
fn ctph_retrieval_ratchets() {
    let Some(report) = ctph_report() else { return };

    let xo = report.result("XO-gcc").expect("XO-gcc ran");
    assert_ratchet("XO-gcc AUC", xo.auc, CTPH_XO_GCC_MIN_AUC, &xo.line());
    assert_ratchet(
        "XO-gcc Recall@1",
        xo.recall(1),
        CTPH_XO_GCC_MIN_RECALL_AT_1,
        &xo.line(),
    );

    let xm = report.result("XM").expect("XM ran");
    assert_ratchet("XM AUC", xm.auc, CTPH_XM_MIN_AUC, &xm.line());
    assert_ratchet(
        "XM global Recall@1",
        xm.global_recall_at_1,
        CTPH_XM_MIN_GLOBAL_RECALL_AT_1,
        &xm.line(),
    );

    assert!(
        report.extraction_us_per_function <= CTPH_MAX_EXTRACTION_US,
        "CTPH extraction cost {:.2} us/function over {} samples, ceiling \
         {CTPH_MAX_EXTRACTION_US:.2}",
        report.extraction_us_per_function,
        report.extraction_samples
    );
}

// ---------------------------------------------------------------------------
// L1 structural invariants (`glaurung::identity::structural`), plan item 2 of
// `docs/history/program-measures-2026-09-02.md`, scored under the same
// protocol as CTPH above. Numbers below were read off a run on 2026-09-02;
// see `docs/development/identity-measurement.md` for the full table.
// ---------------------------------------------------------------------------

/// Score `structural` over every supported task, once, shared by the tests
/// below.
fn structural_report() -> Option<&'static SchemeReport> {
    use std::sync::OnceLock;
    static REPORT: OnceLock<Option<SchemeReport>> = OnceLock::new();
    REPORT
        .get_or_init(|| {
            let corpus = load()?;
            let scheme = StructuralScheme::default();
            let report = metrics::evaluate(&scheme, corpus, TASKS);
            eprintln!(
                "\n=== scheme {} -- {} ===",
                report.scheme, report.description
            );
            eprintln!(
                "extraction {:.2} us/function over {} samples",
                report.extraction_us_per_function, report.extraction_samples
            );
            for result in &report.results {
                eprintln!("{}", result.line());
            }
            if let Some(path) = report.write_json(&metrics::report_dir()) {
                eprintln!("report: {}", path.display());
            }
            Some(report)
        })
        .as_ref()
}

/// Same axiom suite as `ctph_obeys_the_similarity_axioms`, over `structural`.
#[test]
fn structural_obeys_the_similarity_axioms() {
    let Some(corpus) = load() else { return };
    let scheme = StructuralScheme::default();
    let Some(slice) = corpus.slice("gcc", "O0") else {
        return;
    };
    assert!(slice.samples.len() >= 80);

    let mut checked = 0usize;
    for (i, a) in slice.samples.iter().enumerate() {
        let Ok(sig_a) = scheme.extract(a) else {
            continue;
        };
        let self_score = scheme.similarity(&sig_a, &sig_a);
        assert!(
            (self_score - 1.0).abs() < 1e-9,
            "{}::{} does not match itself: {self_score}",
            a.fixture,
            a.name
        );
        if let Some(b) = slice.samples.get(i + 1) {
            if let Ok(sig_b) = scheme.extract(b) {
                let ab = scheme.similarity(&sig_a, &sig_b);
                let ba = scheme.similarity(&sig_b, &sig_a);
                assert!(
                    (ab - ba).abs() < 1e-12,
                    "asymmetric: {}::{} vs {}::{} scored {ab} and {ba}",
                    a.fixture,
                    a.name,
                    b.fixture,
                    b.name
                );
                assert!(
                    (0.0..=1.0).contains(&ab),
                    "score {ab} outside [0, 1] for {}::{} vs {}::{}",
                    a.fixture,
                    a.name,
                    b.fixture,
                    b.name
                );
                checked += 1;
            }
        }
    }
    assert!(
        checked >= 80,
        "only {checked} axiom checks ran; extraction is failing across the slice"
    );
}

/// Extraction must be deterministic across calls, same discipline as CTPH's.
#[test]
fn structural_extraction_is_deterministic() {
    let Some(corpus) = load() else { return };
    let scheme = StructuralScheme::default();
    let Some(slice) = corpus.slice("gcc", "O2") else {
        return;
    };
    let mut checked = 0usize;
    for sample in slice.samples.iter().take(200) {
        let (Ok(first), Ok(second)) = (scheme.extract(sample), scheme.extract(sample)) else {
            continue;
        };
        assert_eq!(
            first, second,
            "{}::{} extracted two different signatures",
            sample.fixture, sample.name
        );
        checked += 1;
    }
    assert!(checked >= 80, "only {checked} determinism checks ran");
}

/// The `structural` ratchets: MD-index plus mnemonic SPP over the discovered
/// CFG, measured on 2026-09-02 (debug profile).
///
/// Reads far ahead of CTPH on every task -- the CFG shape survives a compiler
/// swap and, more weakly, an optimisation-level swap -- and, unlike the
/// Python structural fingerprint, does not collapse on XM: MD-index and block
/// counts still carry signal when both variables are free, because neither
/// term depends on token-level normalization the way a mnemonic n-gram does.
#[test]
fn structural_retrieval_ratchets() {
    let Some(report) = structural_report() else {
        return;
    };

    let xo = report.result("XO-gcc").expect("XO-gcc ran");
    assert_ratchet("XO-gcc AUC", xo.auc, STRUCTURAL_XO_GCC_MIN_AUC, &xo.line());

    let xc = report.result("XC-O2").expect("XC-O2 ran");
    assert_ratchet("XC-O2 AUC", xc.auc, STRUCTURAL_XC_O2_MIN_AUC, &xc.line());
    assert_ratchet(
        "XC-O2 MRR10",
        xc.mrr10,
        STRUCTURAL_XC_O2_MIN_MRR10,
        &xc.line(),
    );

    let xm = report.result("XM").expect("XM ran");
    assert_ratchet("XM AUC", xm.auc, STRUCTURAL_XM_MIN_AUC, &xm.line());

    assert!(
        report.extraction_us_per_function <= STRUCTURAL_MAX_EXTRACTION_US,
        "structural extraction cost {:.2} us/function over {} samples, \
         ceiling {STRUCTURAL_MAX_EXTRACTION_US:.2}",
        report.extraction_us_per_function,
        report.extraction_samples
    );
}

// ---------------------------------------------------------------------------
// L3 value fingerprints (`glaurung::identity::values`), plan item 12.
//
// The scheme runs the concrete interpreter, so this whole section is behind
// the `exec` feature -- `cargo test --features python-ext` builds it and a
// bare `cargo test` does not.
//
// Every constant below was read off a run before it was written down.
// ---------------------------------------------------------------------------

#[cfg(feature = "exec")]
fn values_report() -> Option<&'static SchemeReport> {
    use std::sync::OnceLock;
    static REPORT: OnceLock<Option<SchemeReport>> = OnceLock::new();
    REPORT
        .get_or_init(|| run_values(scheme::ValueScheme::plain()))
        .as_ref()
}

#[cfg(feature = "exec")]
fn values_unfiltered_report() -> Option<&'static SchemeReport> {
    use std::sync::OnceLock;
    static REPORT: OnceLock<Option<SchemeReport>> = OnceLock::new();
    REPORT
        .get_or_init(|| run_values(scheme::ValueScheme::unfiltered()))
        .as_ref()
}

#[cfg(feature = "exec")]
fn values_weighted_report() -> Option<&'static SchemeReport> {
    use std::sync::OnceLock;
    static REPORT: OnceLock<Option<SchemeReport>> = OnceLock::new();
    REPORT
        .get_or_init(|| run_values(scheme::ValueScheme::weighted()))
        .as_ref()
}

/// Prime the scheme over the whole corpus (which fills its cache and, for the
/// weighted configuration, its document-frequency table) and then score it.
#[cfg(feature = "exec")]
fn run_values(scheme: scheme::ValueScheme) -> Option<SchemeReport> {
    let corpus = load()?;
    scheme.prime(corpus.slices().flat_map(|slice| slice.samples.iter()));
    let report = metrics::evaluate(&scheme, corpus, TASKS);
    eprintln!(
        "\n=== scheme {} -- {} ===",
        report.scheme, report.description
    );
    eprintln!(
        "extraction {:.2} us/function over {} samples",
        report.extraction_us_per_function, report.extraction_samples
    );
    for result in &report.results {
        eprintln!("{}", result.line());
    }
    if let Some(path) = report.write_json(&metrics::report_dir()) {
        eprintln!("report: {}", path.display());
    }
    Some(report)
}

#[cfg(feature = "exec")]
#[test]
fn values_obey_the_similarity_axioms() {
    let Some(corpus) = load() else { return };
    let scheme = scheme::ValueScheme::plain();
    let Some(slice) = corpus.slice("gcc", "O0") else {
        return;
    };
    let mut checked = 0usize;
    for (index, sample) in slice.samples.iter().take(120).enumerate() {
        let Ok(left) = scheme.extract(sample) else {
            continue;
        };
        let self_score = scheme.similarity(&left, &left);
        assert!(
            (self_score - 1.0).abs() < 1e-9,
            "similarity(a, a) = {self_score} at sample {index}"
        );
        for other in slice.samples.iter().skip(index + 1).take(3) {
            let Ok(right) = scheme.extract(other) else {
                continue;
            };
            let forward = scheme.similarity(&left, &right);
            let backward = scheme.similarity(&right, &left);
            assert!(
                (forward - backward).abs() < 1e-9,
                "asymmetric at {index}: {forward} vs {backward}"
            );
            assert!(
                (0.0..=1.0).contains(&forward),
                "similarity out of range at {index}: {forward}"
            );
            checked += 1;
        }
    }
    assert!(checked >= 50, "only {checked} pairs checked");
    eprintln!("values axioms: {checked} pairs");
}

/// Bounded *execution* is the one thing in the identity ladder that could
/// plausibly not be a pure function of the bytes, so this is checked over
/// freshly built schemes rather than over one cache.
#[cfg(feature = "exec")]
#[test]
fn values_extraction_is_deterministic() {
    let Some(corpus) = load() else { return };
    let Some(slice) = corpus.slice("gcc", "O2") else {
        return;
    };
    let first = scheme::ValueScheme::plain();
    let second = scheme::ValueScheme::plain();
    let mut checked = 0usize;
    for sample in slice.samples.iter().take(120) {
        let (Ok(left), Ok(right)) = (first.extract(sample), second.extract(sample)) else {
            continue;
        };
        assert_eq!(
            left.digest, right.digest,
            "values is not deterministic on {}::{}",
            sample.fixture, sample.name
        );
        checked += 1;
    }
    assert!(checked >= 50, "only {checked} samples checked");
}

/// The whole sweep, no ratchet in the way: every configuration, the cost, the
/// budget-exhaustion fraction, and the filter ablation side by side.
///
/// `--ignored` because it extracts the corpus once per configuration, which is
/// minutes rather than seconds. This is the command that produces the table in
/// `docs/reference/function-identity-values.md`.
#[cfg(feature = "exec")]
#[test]
#[ignore = "extracts the corpus once per configuration; minutes"]
fn values_full_sweep() {
    use glaurung::identity::values::ValueSettings;

    let Some(corpus) = load() else { return };
    let base = ValueSettings::default();
    let configurations: Vec<(&str, ValueSettings, bool)> = vec![
        ("values", base, false),
        ("values-multiset", base, true),
        (
            "values-unfiltered",
            ValueSettings {
                filter: false,
                ..base
            },
            false,
        ),
        (
            "values-nobranch",
            ValueSettings {
                branch_conditions: false,
                ..base
            },
            false,
        ),
        (
            "values-roleseeds",
            ValueSettings {
                role_seeds: true,
                ..base
            },
            false,
        ),
        ("values-1seed", ValueSettings { seeds: 1, ..base }, false),
        ("values-5seeds", ValueSettings { seeds: 5, ..base }, false),
        (
            "values-cap1",
            ValueSettings {
                site_cap: 1,
                ..base
            },
            false,
        ),
    ];

    for (name, settings, use_counts) in configurations {
        let scheme = scheme::ValueScheme::tuned(settings, name, use_counts);
        scheme.prime(corpus.slices().flat_map(|slice| slice.samples.iter()));
        let report = metrics::evaluate(&scheme, corpus, TASKS);
        eprintln!("\n=== {name} ({}) ===", report.description);
        eprintln!(
            "extraction {:.2} us/function over {} samples, profile {}",
            report.extraction_us_per_function, report.extraction_samples, report.profile
        );
        eprintln!("| Task | Free variables | Scored | Global pool | AUC | MRR10 | R@1 | R@5 | R@10 | R@50 |");
        eprintln!("|---|---|---|---|---|---|---|---|---|---|");
        for result in &report.results {
            eprintln!(
                "| {} | {} | {} | {} | {:.4} | {:.4} | {:.4} | {:.4} | {:.4} | {:.4} |",
                result.task_name,
                result.conditions,
                result.scored,
                result.global_pool_size,
                result.auc,
                result.mrr10,
                result.recall(1),
                result.recall(5),
                result.recall(10),
                result.recall(50),
            );
        }
        report.write_json(&metrics::report_dir());
    }

    // Cost and coverage, once, under the default settings, on a scheme with a
    // cold cache: this is the number that says what an extraction costs, and
    // the one in the reports above is a cache hit.
    let scheme = scheme::ValueScheme::plain();
    let started = std::time::Instant::now();
    let (measured, mean_steps, budget_hits, starved, addresses) =
        scheme.coverage(corpus.slices().flat_map(|slice| slice.samples.iter()));
    let elapsed = started.elapsed();
    eprintln!(
        "\ncoverage: {measured} functions, {mean_steps:.0} instructions retired per function \
         (all seeds); {budget_hits:.4} of runs hit the instruction budget, {starved:.4} of \
         functions hit it before producing any value; the address rules removed {addresses:.4} \
         of harvested values; {:.0} us/function cold, over whole images",
        elapsed.as_secs_f64() * 1e6 / measured.max(1) as f64
    );
}

// ---------------------------------------------------------------------------
// Measured ratchets for the value fingerprints.
//
// Read off a RELEASE run on 2026-09-03 over the 1,787-function fixture corpus,
// with the same filters, the same seeded 100-negative draw and the same
// pessimistic tie rule as every other scheme in this file. Sampled pool 101
// (chance R@1 0.0099) throughout.
// ---------------------------------------------------------------------------

/// XO (gcc O0 -> gcc O2) AUC.
///
/// **Measured: 0.9059** over 389 scored queries, global pool 410. CTPH reads
/// 0.5015 on this lane, `structural` 0.7536 and the plain CFR 0.7569.
#[cfg(feature = "exec")]
const VALUES_XO_GCC_MIN_AUC: f64 = 0.9058;
/// XO (gcc O0 -> gcc O2) Recall@1, 100 sampled negatives.
///
/// **Measured: 0.5219** (203 of 389) against 0.0099 chance -- and against the
/// CFR's 0.1799 and the structural invariants' 0.1183 on the identical rows.
/// This is the cross-optimisation lane, the one the protocol document names as
/// the hardest of the four the in-house corpus expresses, and the value
/// fingerprint retrieves the right function first on more than half of it.
#[cfg(feature = "exec")]
const VALUES_XO_GCC_MIN_RECALL_AT_1: f64 = 0.5218;
/// XO (gcc O0 -> gcc O2) MRR10. **Measured: 0.6274**, against the CFR's 0.2543
/// and FunctionSimSearch's published 0.26 ceiling for token representations.
#[cfg(feature = "exec")]
const VALUES_XO_GCC_MIN_MRR10: f64 = 0.6273;
/// XC (gcc O2 -> clang O2) AUC. **Measured: 0.9056** over 357 queries, against
/// the CFR's 0.8921.
#[cfg(feature = "exec")]
const VALUES_XC_O2_MIN_AUC: f64 = 0.9055;
/// XM (gcc O0 -> clang O2) AUC.
///
/// **Measured: 0.8518** over 365 queries: both compilation variables free, the
/// hardest task this corpus expresses. CTPH reads 0.5025, `structural` 0.7026,
/// the CFR 0.7296.
#[cfg(feature = "exec")]
const VALUES_XM_MIN_AUC: f64 = 0.8517;
/// XM Recall@1. **Measured: 0.4055** (148 of 365).
#[cfg(feature = "exec")]
const VALUES_XM_MIN_RECALL_AT_1: f64 = 0.4054;

#[cfg(feature = "exec")]
#[test]
fn values_retrieval_ratchets() {
    let Some(report) = values_report() else {
        return;
    };

    let xo = report.result("XO-gcc").expect("XO-gcc ran");
    assert_ratchet(
        "values XO-gcc AUC",
        xo.auc,
        VALUES_XO_GCC_MIN_AUC,
        &xo.line(),
    );
    assert_ratchet(
        "values XO-gcc Recall@1",
        xo.recall(1),
        VALUES_XO_GCC_MIN_RECALL_AT_1,
        &xo.line(),
    );
    assert_ratchet(
        "values XO-gcc MRR10",
        xo.mrr10,
        VALUES_XO_GCC_MIN_MRR10,
        &xo.line(),
    );

    let xc = report.result("XC-O2").expect("XC-O2 ran");
    assert_ratchet("values XC-O2 AUC", xc.auc, VALUES_XC_O2_MIN_AUC, &xc.line());

    let xm = report.result("XM").expect("XM ran");
    assert_ratchet("values XM AUC", xm.auc, VALUES_XM_MIN_AUC, &xm.line());
    assert_ratchet(
        "values XM Recall@1",
        xm.recall(1),
        VALUES_XM_MIN_RECALL_AT_1,
        &xm.line(),
    );
}

/// The document-frequency weighting is measured, not assumed.
///
/// vSim weights every element by `1 / ln(Occ(v) + 1)` and its ablation reports
/// the weights as worth having. Ours is scored beside the unweighted lane
/// rather than adopted: the weighting is only as good as the corpus the table
/// came from, and this corpus is 1,787 functions.
#[cfg(feature = "exec")]
#[test]
fn the_corpus_weighting_is_reported_beside_the_unweighted_lane() {
    let (Some(plain), Some(weighted)) = (values_report(), values_weighted_report()) else {
        return;
    };
    eprintln!("\nvalues vs values-weighted, in-house corpus");
    eprintln!(
        "{:<8} {:>8} {:>8}   {:>8} {:>8}   {:>8} {:>8}   {:>7}",
        "task", "AUC", "AUC'", "MRR10", "MRR10'", "R@1", "R@1'", "scored"
    );
    for result in &plain.results {
        let Some(other) = weighted.result(&result.task_name) else {
            continue;
        };
        eprintln!(
            "{:<8} {:8.4} {:8.4}   {:8.4} {:8.4}   {:8.4} {:8.4}   {:>7}",
            result.task_name,
            result.auc,
            other.auc,
            result.mrr10,
            other.mrr10,
            result.recall(1),
            other.recall(1),
            result.scored,
        );
    }
}

/// The ablation vSim's Table IV reports, on our corpus and our protocol.
#[cfg(feature = "exec")]
#[test]
fn the_filter_is_worth_measuring_and_the_delta_is_recorded() {
    let (Some(filtered), Some(unfiltered)) = (values_report(), values_unfiltered_report()) else {
        return;
    };
    eprintln!("\nvalues vs values-unfiltered, in-house corpus");
    eprintln!(
        "{:<8} {:>8} {:>8}   {:>8} {:>8}   {:>8} {:>8}   {:>7}",
        "task", "AUC", "AUC'", "MRR10", "MRR10'", "R@1", "R@1'", "scored"
    );
    for result in &filtered.results {
        let Some(other) = unfiltered.result(&result.task_name) else {
            continue;
        };
        eprintln!(
            "{:<8} {:8.4} {:8.4}   {:8.4} {:8.4}   {:8.4} {:8.4}   {:>7}{}",
            result.task_name,
            result.auc,
            other.auc,
            result.mrr10,
            other.mrr10,
            result.recall(1),
            other.recall(1),
            result.scored,
            if result.underpowered() {
                "  (underpowered)"
            } else {
                ""
            }
        );
    }
}

// ---------------------------------------------------------------------------
// Cisco Talos Dataset-1: the XA (cross-architecture) and XB (cross-bitness)
// lanes, and CTPH retro-scored on them.
//
// Every constant below was read off the run recorded in
// `docs/development/identity-measurement.md`, on the corpus described in
// `docs/development/corpora.md`. They are floors on a scheme the protocol
// document says should be at chance, and they are: the point of pinning them
// is that the LANE exists and cannot silently stop running, not that the
// numbers are good.
// ---------------------------------------------------------------------------

/// Score CTPH over every Dataset-1 task, once, shared by the tests below.
fn cisco_ctph_report() -> Option<&'static SchemeReport> {
    use std::sync::OnceLock;
    static REPORT: OnceLock<Option<SchemeReport>> = OnceLock::new();
    REPORT
        .get_or_init(|| {
            let corpus = cisco::corpus()?;
            let scheme = CtphScheme::default();
            let report = cisco::evaluate(&scheme, corpus, cisco::TASKS);
            eprintln!("\n=== {} -- {} ===", report.scheme, report.corpus_name);
            eprintln!(
                "extraction {:.2} us/function over {} samples ({} profile)",
                report.extraction_us_per_function, report.extraction_samples, report.profile
            );
            for note in &report.coverage_notes {
                eprintln!("coverage: {note}");
            }
            for result in &report.results {
                eprintln!("{}", result.line());
            }
            if let Some(path) = report.write_json(&metrics::report_dir()) {
                eprintln!("report: {}", path.display());
            }
            Some(report)
        })
        .as_ref()
}

/// The Dataset-1 corpus must load the shape it claims: nine configurations,
/// three instruction-set families, both bitnesses, and pools big enough to
/// rank in.
#[test]
fn cisco_corpus_loads_all_six_architectures_it_claims() {
    let Some(corpus) = cisco::corpus() else {
        return;
    };

    let loaded: Vec<&cisco::Config> = corpus.slices().map(|(c, _)| c).collect();
    assert_eq!(
        loaded.len(),
        cisco::DEFAULT_CONFIGS.len(),
        "asked for {} configurations, loaded {}: a configuration that matched \
         no selection row produces no slice, and every task that names it is \
         then silently skipped",
        cisco::DEFAULT_CONFIGS.len(),
        loaded.len()
    );

    let families: std::collections::BTreeSet<&str> =
        loaded.iter().map(|c| c.arch.family()).collect();
    assert_eq!(
        families,
        std::collections::BTreeSet::from(["arm", "mips", "x86"]),
        "the point of this corpus is the architectures the in-house one lacks; \
         it loaded {families:?}"
    );
    let bitnesses: std::collections::BTreeSet<u8> = loaded.iter().map(|c| c.arch.bits).collect();
    assert_eq!(
        bitnesses,
        std::collections::BTreeSet::from([32, 64]),
        "no cross-bitness lane is possible without both widths"
    );

    // The published filters must have removed something, and the survivors
    // must be enough to draw a 100-negative pool from.
    let f = corpus.filters;
    assert!(
        f.considered >= 1_000,
        "only {} selection rows reached the filters across {} images; the \
         corpus is truncated, not filtered",
        f.considered,
        corpus.images
    );
    // The <5-block filter MUST remove nothing here, and that zero is a
    // positive result rather than a suspicious one: upstream's
    // `flowchart_Dataset-1.csv` is defined as the functions with at least five
    // basic blocks and the selection CSV is drawn from it, so a nonzero count
    // would mean this loader is reading a population that is not Marcelli's.
    assert_eq!(
        f.dropped_small,
        0,
        "the <{MIN_BASIC_BLOCKS}-block filter removed {} rows. Every row of \
         the selection CSV comes from a flowchart file upstream already \
         filtered at that threshold, so a nonzero count means the loader is \
         not reading the published population: {}",
        f.dropped_small,
        f.summary()
    );
    assert!(
        f.dropped_duplicate > 0,
        "the (name, normalized instruction hash) dedupe removed nothing out \
         of {} rows. Three binaries of one project share helpers, so zero here \
         means the hash is not decoding -- which is exactly what a wrong \
         SampleArch would look like: {}",
        f.considered,
        f.summary()
    );

    // Our own CFG recovery against IDA's, on the same functions. This is not a
    // filter and moves no denominator; it is asserted because it is the most
    // interesting number the lane produces and it must not silently become
    // zero (which would mean the comparison stopped running) or total.
    let worst = corpus
        .cfg_disagreements
        .iter()
        .map(|(c, n)| (c.label(), *n))
        .max_by_key(|(_, n)| *n);
    let (worst_label, worst_n) = worst.expect("at least one slice loaded");
    assert!(
        worst_n > 0,
        "no slice disagrees with IDA on block count at all. On the recorded \
         run MIPS32 disagreed on 86% of its functions; a flat zero means the \
         comparison is not being computed."
    );
    assert!(
        corpus
            .cfg_disagreements
            .iter()
            .any(|(c, n)| c.arch.family() == "x86" && *n * 10 < f.kept),
        "every x86 slice disagrees with IDA on more than a tenth of its \
         functions; on the recorded run x86-64 disagreed on 0-3%. Worst slice \
         overall is {worst_label} at {worst_n}."
    );
    for (config, slice) in corpus.slices() {
        assert!(
            slice.samples.len() > NEGATIVES_PER_POSITIVE,
            "{} kept only {} functions, so it cannot supply {} distinct \
             negatives and every ranking number over it would be a fiction: {}",
            config.label(),
            slice.samples.len(),
            NEGATIVES_PER_POSITIVE,
            slice.filters.summary()
        );
    }
}

/// Every Dataset-1 task must have a real twin join and a real negative pool,
/// and the negatives must obey the task's constraint.
#[test]
fn cisco_tasks_have_sound_ground_truth_and_constrained_negatives() {
    let Some(report) = cisco_ctph_report() else {
        return;
    };
    let Some(corpus) = cisco::corpus() else {
        return;
    };

    assert_eq!(
        report.results.len(),
        cisco::TASKS.len(),
        "{} of {} tasks produced a result; a task whose slice is missing is \
         skipped silently by `evaluate`",
        report.results.len(),
        cisco::TASKS.len()
    );

    for result in &report.results {
        assert!(
            result.scored > 0,
            "{}: no query had a twin in the pool. The (library, func_name) \
             join is broken, not the scheme. Conditions: {}",
            result.task_name,
            result.conditions
        );
        assert!(
            result.global_pool_size > NEGATIVES_PER_POSITIVE,
            "{}: pool of {} cannot supply {} distinct negatives",
            result.task_name,
            result.global_pool_size,
            NEGATIVES_PER_POSITIVE
        );
    }

    // Negative-sampling discipline, checked structurally rather than trusted:
    // every candidate in a task's pool slice shares that slice's whole
    // configuration, so a negative cannot differ from the positive in a
    // variable the task holds fixed. This is the "in XO, the negative shares
    // the architecture" rule Marcelli names as a frequent source of inflated
    // published results.
    for task in cisco::TASKS {
        let pool = corpus.slice(&task.pool).expect("task pool loaded");
        for sample in &pool.samples {
            assert_eq!(
                (sample.arch, sample.compiler, sample.opt),
                (task.pool.arch, task.pool.compiler, task.pool.opt),
                "{}: a candidate in the pool slice does not share the pool's \
                 configuration, so a negative drawn from it could vary a \
                 variable the task holds fixed",
                task.name
            );
        }
    }
}

/// CTPH on Dataset-1: the measured floor for the XA and XB lanes.
///
/// These are the first numbers this repository has for either task. They are
/// at chance, which is what the protocol document predicts for a byte digest
/// with several free variables -- and what makes them useful is that a scheme
/// arriving later has a lane to be better on, in the same units, over the same
/// pools.
#[test]
fn cisco_ctph_retrieval_ratchets() {
    let Some(report) = cisco_ctph_report() else {
        return;
    };

    for (task, floor) in CISCO_CTPH_MIN_AUC {
        let r = report.result(task).unwrap_or_else(|| {
            panic!(
                "{task} did not run; the ratchet table and cisco::TASKS have \
                 drifted apart"
            )
        });
        assert!(
            !r.underpowered(),
            "{task} is ratcheted but scored only {} queries, below {}. A \
             ratchet on a row that may not be quoted is a ratchet on noise: \
             either the corpus shrank, or the row belongs in \
             CISCO_UNDERPOWERED_TASKS.\n{}",
            r.scored,
            metrics::MIN_SCORED_FOR_A_MEASUREMENT,
            r.line()
        );
        assert_ratchet(&format!("{task} AUC"), r.auc, *floor, &r.line());
    }

    // The complement, checked rather than assumed: every task NOT ratcheted
    // must still be under the measurement threshold. When one of them gains
    // enough twins to cross it, this fires and says to promote it -- which is
    // the only mechanism that stops the ratchet table quietly covering less
    // and less of the lane.
    for task in CISCO_UNDERPOWERED_TASKS {
        let r = report.result(task).expect("task ran");
        assert!(
            r.underpowered(),
            "{task} now scores {} queries, at or above {}. That is a real \
             improvement in corpus coverage: quote the row, move it into \
             CISCO_CTPH_MIN_AUC with its measured floor, and drop it from \
             CISCO_UNDERPOWERED_TASKS.\n{}",
            r.scored,
            metrics::MIN_SCORED_FOR_A_MEASUREMENT,
            r.line()
        );
    }
    assert_eq!(
        CISCO_CTPH_MIN_AUC.len() + CISCO_UNDERPOWERED_TASKS.len(),
        cisco::TASKS.len(),
        "{} tasks run but only {} are accounted for by the two tables above; \
         a task in neither is a lane nothing checks",
        cisco::TASKS.len(),
        CISCO_CTPH_MIN_AUC.len() + CISCO_UNDERPOWERED_TASKS.len()
    );

    assert!(
        report.extraction_us_per_function <= CTPH_MAX_EXTRACTION_US,
        "CTPH extraction cost {:.2} us/function over {} samples on Dataset-1, \
         ceiling {CTPH_MAX_EXTRACTION_US:.2}",
        report.extraction_us_per_function,
        report.extraction_samples
    );
}

// ---------------------------------------------------------------------------
// `structural` on Dataset-1: the XA and XB lanes CTPH could not carry.
// ---------------------------------------------------------------------------

/// Score `structural` over every Dataset-1 task, once, shared by the tests
/// below.
fn cisco_structural_report() -> Option<&'static SchemeReport> {
    use std::sync::OnceLock;
    static REPORT: OnceLock<Option<SchemeReport>> = OnceLock::new();
    REPORT
        .get_or_init(|| {
            let corpus = cisco::corpus()?;
            let scheme = StructuralScheme::default();
            let report = cisco::evaluate(&scheme, corpus, cisco::TASKS);
            eprintln!("\n=== {} -- {} ===", report.scheme, report.corpus_name);
            eprintln!(
                "extraction {:.2} us/function over {} samples ({} profile)",
                report.extraction_us_per_function, report.extraction_samples, report.profile
            );
            for note in &report.coverage_notes {
                eprintln!("coverage: {note}");
            }
            for result in &report.results {
                eprintln!("{}", result.line());
            }
            if let Some(path) = report.write_json(&metrics::report_dir()) {
                eprintln!("report: {}", path.display());
            }
            Some(report)
        })
        .as_ref()
}

/// `structural` on Dataset-1: the measured floor for the XA and XB lanes,
/// read off the same run recorded in `docs/development/identity-measurement.md`.
#[test]
fn cisco_structural_retrieval_ratchets() {
    let Some(report) = cisco_structural_report() else {
        return;
    };

    for (task, floor) in CISCO_STRUCTURAL_MIN_AUC {
        let r = report.result(task).unwrap_or_else(|| {
            panic!(
                "{task} did not run; the ratchet table and cisco::TASKS have \
                 drifted apart"
            )
        });
        assert!(
            !r.underpowered(),
            "{task} is ratcheted but scored only {} queries, below {}.\n{}",
            r.scored,
            metrics::MIN_SCORED_FOR_A_MEASUREMENT,
            r.line()
        );
        assert_ratchet(&format!("{task} AUC"), r.auc, *floor, &r.line());
    }

    for task in CISCO_UNDERPOWERED_TASKS {
        let r = report.result(task).expect("task ran");
        assert!(
            r.underpowered(),
            "{task} now scores {} queries, at or above {}. Quote the row and \
             move it into CISCO_STRUCTURAL_MIN_AUC.\n{}",
            r.scored,
            metrics::MIN_SCORED_FOR_A_MEASUREMENT,
            r.line()
        );
    }

    // The noisy tasks must still be powered (that is WHY they need a
    // documented exemption rather than the ordinary underpowered path) and
    // must still print every run, so a real regression on them is at least
    // visible even though it is not gated.
    for task in CISCO_STRUCTURAL_NOISY_TASKS {
        let r = report.result(task).unwrap_or_else(|| {
            panic!("{task} did not run; CISCO_STRUCTURAL_NOISY_TASKS has drifted from cisco::TASKS")
        });
        assert!(
            !r.underpowered(),
            "{task} scored only {} queries, below {}: it belongs in \
             CISCO_UNDERPOWERED_TASKS, not CISCO_STRUCTURAL_NOISY_TASKS.\n{}",
            r.scored,
            metrics::MIN_SCORED_FOR_A_MEASUREMENT,
            r.line()
        );
        eprintln!("NOISY (not ratcheted): {}", r.line());
    }

    assert_eq!(
        CISCO_STRUCTURAL_MIN_AUC.len()
            + CISCO_UNDERPOWERED_TASKS.len()
            + CISCO_STRUCTURAL_NOISY_TASKS.len(),
        cisco::TASKS.len(),
        "{} tasks run but only {} are accounted for by the three tables above",
        cisco::TASKS.len(),
        CISCO_STRUCTURAL_MIN_AUC.len()
            + CISCO_UNDERPOWERED_TASKS.len()
            + CISCO_STRUCTURAL_NOISY_TASKS.len()
    );

    assert!(
        report.extraction_us_per_function <= STRUCTURAL_MAX_EXTRACTION_US,
        "structural extraction cost {:.2} us/function over {} samples on \
         Dataset-1, ceiling {STRUCTURAL_MAX_EXTRACTION_US:.2}",
        report.extraction_us_per_function,
        report.extraction_samples
    );
}

/// The full `structural` Dataset-1 sweep, with markdown rows for the docs
/// table.
///
/// `GLAURUNG_CISCO_CORPUS=... cargo test --features python-ext --test
/// identity_retrieval -- --ignored --nocapture cisco_structural`
#[test]
#[ignore = "full Dataset-1 sweep: minutes. GLAURUNG_CISCO_CORPUS=... cargo test --features python-ext --test identity_retrieval -- --ignored --nocapture cisco_structural"]
fn cisco_structural_full_sweep() {
    let Some(report) = cisco_structural_report() else {
        return;
    };
    eprintln!("\n--- markdown rows for docs/development/identity-measurement.md ---");
    eprintln!(
        "| Task | Free variables | Scored | Pool (sampled / global) | AUC | \
         MRR10 | R@1 | R@5 | R@10 | R@50 | Global R@1 |"
    );
    eprintln!("|---|---|---|---|---|---|---|---|---|---|---|");
    for r in &report.results {
        eprintln!(
            "| {} | {} | {} | {} / {} | {:.4} | {:.4} | {:.4} | {:.4} | {:.4} | {:.4} | {:.4} |",
            r.task_name,
            r.conditions,
            r.scored,
            r.sampled_pool_size,
            r.global_pool_size,
            r.auc,
            r.mrr10,
            r.recall(1),
            r.recall(5),
            r.recall(10),
            r.recall(50),
            r.global_recall_at_1,
        );
    }
    eprintln!(
        "\nextraction {:.2} us/function over {} samples ({})",
        report.extraction_us_per_function, report.extraction_samples, report.profile
    );
}

/// Marcelli's published ranking pools must have the shape his protocol
/// describes: four tasks, 200 queries each, exactly 100 negatives per query.
///
/// This is a check on the GROUND TRUTH, not on any scheme, and it is cheap
/// (the two CSVs are 192 KB and 19 MB). It matters because
/// `docs/development/identity-measurement.md` quotes Marcelli's Tables 3 and 4
/// next to our own rows, and that comparison is only legitimate if his pool
/// discipline is what we think it is -- 100 negatives per positive is the
/// number our own sampler was set to match.
#[test]
fn published_ranking_pools_hold_one_hundred_negatives_per_positive() {
    let Some(pool) = cisco::published_pairs() else {
        return;
    };

    let sizes = pool.task_sizes();
    assert_eq!(
        sizes.keys().cloned().collect::<Vec<String>>(),
        vec![
            "XA".to_string(),
            "XC".to_string(),
            "XC+XB".to_string(),
            "XM".to_string()
        ],
        "the published ranking pools name tasks {:?}",
        sizes.keys().collect::<Vec<_>>()
    );
    for (task, count) in &sizes {
        assert_eq!(
            *count, 200,
            "published pool {task} holds {count} queries, not the 200 the \
             paper's ranking protocol describes"
        );
    }

    for query in &pool.queries {
        assert_eq!(
            query.negatives.len(),
            NEGATIVES_PER_POSITIVE,
            "published query {}@{:#x} in task {} has {} negatives; our own \
             sampler is set to {} to match this",
            query.query_name,
            query.query_fva,
            query.task,
            query.negatives.len(),
            NEGATIVES_PER_POSITIVE
        );
    }

    // The reachability statement that keeps the docs honest: these pools are
    // measured over binaries this repository does not load by default.
    let loaded: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let (full, total) = pool.coverage(&loaded);
    assert_eq!(
        full, 0,
        "coverage against an empty loaded set must be zero, or the coverage \
         computation is not looking at the loaded set at all"
    );
    eprintln!(
        "published ranking pools: {total} queries over {} distinct binaries; \
         scoring them verbatim means loading all of those, which is why the \
         default lane samples its own negatives under the same 100:1 rule \
         instead.",
        pool.referenced_idbs().len()
    );
}

/// The full Dataset-1 sweep, with the markdown rows for the docs table.
///
/// `GLAURUNG_CISCO_CORPUS=... cargo test --test identity_retrieval -- --ignored
/// --nocapture cisco`
#[test]
#[ignore = "full Dataset-1 sweep: minutes. GLAURUNG_CISCO_CORPUS=... cargo test --test identity_retrieval -- --ignored --nocapture"]
fn cisco_full_sweep() {
    let Some(corpus) = cisco::corpus() else {
        return;
    };
    eprintln!("cisco filters: {}", corpus.filters.summary());
    for (config, slice) in corpus.slices() {
        eprintln!(
            "  {}: {} functions, {}",
            config.label(),
            slice.samples.len(),
            slice.filters.summary()
        );
    }
    let Some(report) = cisco_ctph_report() else {
        return;
    };
    eprintln!("\n--- markdown rows for docs/development/identity-measurement.md ---");
    eprintln!(
        "| Task | Free variables | Scored | Pool (sampled / global) | AUC | \
         MRR10 | R@1 | R@5 | R@10 | R@50 | Global R@1 |"
    );
    eprintln!("|---|---|---|---|---|---|---|---|---|---|---|");
    for r in &report.results {
        eprintln!(
            "| {} | {} | {} | {} / {} | {:.4} | {:.4} | {:.4} | {:.4} | {:.4} | {:.4} | {:.4} |",
            r.task_name,
            r.conditions,
            r.scored,
            r.sampled_pool_size,
            r.global_pool_size,
            r.auc,
            r.mrr10,
            r.recall(1),
            r.recall(5),
            r.recall(10),
            r.recall(50),
            r.global_recall_at_1,
        );
    }
    eprintln!(
        "\nextraction {:.2} us/function over {} samples ({})",
        report.extraction_us_per_function, report.extraction_samples, report.profile
    );
}

/// Print a report to stderr and write its JSON, then hand it back.
///
/// Every scheme's `*_report()` did this inline; the CFR adds three more
/// reports and three more copies of it would be three more places for the
/// printed form and the stored form to drift apart.
fn print_report(report: SchemeReport) -> SchemeReport {
    eprintln!(
        "\n=== scheme {} -- {} ===",
        report.scheme, report.description
    );
    eprintln!(
        "extraction {:.2} us/function over {} samples ({})",
        report.extraction_us_per_function, report.extraction_samples, report.profile
    );
    for result in &report.results {
        eprintln!("{}", result.line());
    }
    if let Some(path) = report.write_json(&metrics::report_dir()) {
        eprintln!("report: {}", path.display());
    }
    report
}

/// The markdown rows `docs/development/identity-measurement.md` holds, so the
/// table in the docs is copied from a run rather than typed.
fn print_markdown_rows(title: &str, report: &SchemeReport) {
    eprintln!("\n--- markdown rows for docs/development/identity-measurement.md: {title} ---");
    eprintln!(
        "| Task | Free variables | Scored | Pool (sampled / global) | AUC | \
         MRR10 | R@1 | R@5 | R@10 | R@50 | Global R@1 |"
    );
    eprintln!("|---|---|---|---|---|---|---|---|---|---|---|");
    for r in &report.results {
        eprintln!(
            "| {} | {} | {} | {} / {} | {:.4} | {:.4} | {:.4} | {:.4} | {:.4} | {:.4} | {:.4} |",
            r.task_name,
            r.conditions,
            r.scored,
            r.sampled_pool_size,
            r.global_pool_size,
            r.auc,
            r.mrr10,
            r.recall(1),
            r.recall(5),
            r.recall(10),
            r.recall(50),
            r.global_recall_at_1,
        );
    }
    eprintln!(
        "extraction {:.2} us/function over {} samples ({})",
        report.extraction_us_per_function, report.extraction_samples, report.profile
    );
}

/// Assert a measured number against its floor, in both directions.
///
/// Six decimals, not four. Several of these numbers are small integer ratios
/// (`2/365`), and a floor transcribed from a four-decimal print is rounded UP
/// as often as down -- which fails immediately, on the run that produced it.
fn assert_ratchet(what: &str, measured: f64, floor: f64, context: &str) {
    eprintln!("{what}: {measured:.6} (ratchet {floor:.6})");
    assert!(
        measured >= floor,
        "{what} fell to {measured:.6}, ratchet {floor:.6}.\n{context}"
    );
    assert!(
        measured <= floor + RATCHET_SLACK,
        "{what} improved to {measured:.6}, more than {RATCHET_SLACK:.2} above \
         the ratchet {floor:.6} -- good news. Raise the constant in \
         tests/identity_retrieval/main.rs in the same commit, or the \
         improvement is unprotected.\n{context}"
    );
}

// ---------------------------------------------------------------------------
// L2, the Canonical Function Representation, plan items 4, 5 and 8 of
// `docs/history/program-measures-2026-09-02.md`.
//
// TWO independent levers, so six scored rows -- two whole-corpus rows that are
// comparable with the CTPH and `structural` rows above, and a 2x2 over one
// population that is the actual experiment:
//
//   whole corpus, comparable with the schemes above
//     `cfr`                       no normaliser, uniform weights
//     `cfr-normalized`            normaliser on, uniform weights
//
//   held-out half, the 2x2 -- one population, four cells
//     `cfr-heldout`               no normaliser, uniform weights   (control)
//     `cfr-normalized-heldout`    normaliser on,  uniform weights
//     `cfr-weighted`              no normaliser, TF-IDF
//     `cfr-normalized-weighted`   normaliser on,  TF-IDF
//
// The 2x2 is scored on the held-out half throughout, including the two
// unweighted cells that would not otherwise need a split. That is deliberate:
// a weighted number on half a corpus set beside an unweighted number on all of
// it is not a delta -- the pools differ, the negatives differ, the twin joins
// differ -- and a four-cell table whose cells sat on two different populations
// would be worse still, because the interaction is the one thing it is being
// read for.
// ---------------------------------------------------------------------------

/// Score the unweighted CFR over the whole corpus, once.
fn cfr_report() -> Option<&'static SchemeReport> {
    use std::sync::OnceLock;
    static REPORT: OnceLock<Option<SchemeReport>> = OnceLock::new();
    REPORT
        .get_or_init(|| {
            let corpus = load()?;
            let scheme = CfrScheme::default();
            Some(print_report(metrics::evaluate(&scheme, corpus, TASKS)))
        })
        .as_ref()
}

/// Score the peephole-normalised CFR over the whole corpus, once.
fn cfr_normalized_report() -> Option<&'static SchemeReport> {
    use std::sync::OnceLock;
    static REPORT: OnceLock<Option<SchemeReport>> = OnceLock::new();
    REPORT
        .get_or_init(|| {
            let corpus = load()?;
            let scheme = CfrScheme::normalized();
            Some(print_report(metrics::evaluate(&scheme, corpus, TASKS)))
        })
        .as_ref()
}

/// The four held-out rows: the 2x2 over `(normalize, weights)`.
///
/// One population, four cells, so every pairwise difference in the table is
/// the lever(s) that moved and not the denominator.
pub struct CfrLeverMatrix {
    /// No normaliser, uniform weights. The control.
    pub plain: SchemeReport,
    /// Normaliser on, uniform weights.
    pub normalized: SchemeReport,
    /// No normaliser, TF-IDF over the training half.
    pub weighted: SchemeReport,
    /// Both levers: normaliser on, TF-IDF counted over normalised vectors.
    pub normalized_weighted: SchemeReport,
}

/// Score all four held-out rows, once.
///
/// Two weight tables, not one. The `normalize` bit is part of `CfrVersion` and
/// therefore of `weights_id`, so a table counted over unnormalised vectors
/// describes a different feature vocabulary than the normalised representation
/// produces; applying it across the lever would weight features that are no
/// longer there and leave the ones that replaced them unweighted. Each
/// weighted cell gets the table counted under its own settings, over the same
/// training half.
fn cfr_lever_matrix() -> Option<&'static CfrLeverMatrix> {
    use std::sync::OnceLock;
    static REPORTS: OnceLock<Option<CfrLeverMatrix>> = OnceLock::new();
    REPORTS
        .get_or_init(|| {
            let corpus = load()?;
            let plain_settings = glaurung::identity::cfr::CfrSettings::default();
            let norm_settings = CfrScheme::normalized_settings();
            let plain_weights = scheme::cfr_train_weights(
                corpus.slices().flat_map(|slice| slice.samples.iter()),
                plain_settings,
            )?;
            let norm_weights = scheme::cfr_train_weights(
                corpus.slices().flat_map(|slice| slice.samples.iter()),
                norm_settings,
            )?;
            for (what, table) in [
                ("unnormalised", &plain_weights),
                ("normalised", &norm_weights),
            ] {
                eprintln!(
                    "\n=== CFR weight table ({what}) {} : {} documents (training \
                     half), {} weighted features ===",
                    table.weights_id(),
                    table.documents(),
                    table.len()
                );
            }
            Some(CfrLeverMatrix {
                plain: print_report(metrics::evaluate(
                    &CfrScheme::unweighted_held_out(plain_settings),
                    corpus,
                    TASKS,
                )),
                normalized: print_report(metrics::evaluate(
                    &CfrScheme::unweighted_held_out(norm_settings),
                    corpus,
                    TASKS,
                )),
                weighted: print_report(metrics::evaluate(
                    &CfrScheme::weighted(plain_settings, plain_weights),
                    corpus,
                    TASKS,
                )),
                normalized_weighted: print_report(metrics::evaluate(
                    &CfrScheme::weighted(norm_settings, norm_weights),
                    corpus,
                    TASKS,
                )),
            })
        })
        .as_ref()
}

/// The same axiom suite the other schemes get: identity on the quotient,
/// symmetry, and a score inside `[0, 1]`.
#[test]
fn cfr_obeys_the_similarity_axioms() {
    let Some(corpus) = load() else { return };
    let scheme = CfrScheme::default();
    let Some(slice) = corpus.slice("gcc", "O0") else {
        return;
    };

    let mut checked = 0usize;
    for (i, a) in slice.samples.iter().enumerate().take(300) {
        let Ok(sig_a) = scheme.extract(a) else {
            continue;
        };
        let self_score = scheme.similarity(&sig_a, &sig_a);
        assert!(
            (self_score - 1.0).abs() < 1e-9,
            "{}::{} does not match itself: {self_score}",
            a.fixture,
            a.name
        );
        if let Some(b) = slice.samples.get(i + 1) {
            if let Ok(sig_b) = scheme.extract(b) {
                let ab = scheme.similarity(&sig_a, &sig_b);
                let ba = scheme.similarity(&sig_b, &sig_a);
                assert!((ab - ba).abs() < 1e-12, "asymmetric: {ab} vs {ba}");
                assert!((0.0..=1.0).contains(&ab), "score {ab} outside [0, 1]");
                checked += 1;
            }
        }
    }
    assert!(
        checked >= 80,
        "only {checked} axiom checks ran; CFR extraction is failing across the slice"
    );
}

/// The self-significance bound, on real functions rather than constructed
/// vectors.
///
/// `min(cA, cB)^2 <= cA^2` termwise and both of BSim's penalties are
/// non-negative, so `significance(a, b) <= min(selfsig(a), selfsig(b))` is a
/// theorem. A violation would mean the weight table can return a negative
/// weight, which would also mean the kernel is no longer positive
/// semi-definite and the distance no longer obeys the triangle inequality --
/// so this is the cheapest possible check on the property the whole index
/// design rests on.
#[test]
fn cfr_significance_is_bounded_by_self_significance() {
    let Some(corpus) = load() else { return };
    let settings = glaurung::identity::cfr::CfrSettings::default();
    let Some(weights) = scheme::cfr_train_weights(
        corpus.slices().flat_map(|slice| slice.samples.iter()),
        settings,
    ) else {
        return;
    };
    let scheme = CfrScheme::weighted(settings, weights);
    let Some(slice) = corpus.slice("gcc", "O0") else {
        return;
    };
    let signatures: Vec<_> = slice
        .samples
        .iter()
        .filter_map(|sample| scheme.extract(sample).ok())
        .take(60)
        .collect();
    assert!(signatures.len() >= 20, "too few signatures to check");

    let mut checked = 0usize;
    let mut confident = 0usize;
    for a in &signatures {
        let self_a = scheme.self_significance(a);
        for b in &signatures {
            let significance = scheme.significance(a, b);
            let bound = self_a.min(scheme.self_significance(b));
            assert!(
                significance <= bound + 1e-9,
                "significance {significance} exceeds the self-significance bound {bound}"
            );
            if significance >= glaurung::identity::cfr::CONFIDENT_SIGNIFICANCE {
                confident += 1;
            }
            checked += 1;
        }
    }
    assert!(checked >= 400);
    // At least the diagonal must be confident, or the threshold is
    // unreachable on real functions and the number is decorative.
    assert!(
        confident >= signatures.len() / 2,
        "only {confident} of {checked} pairs cleared \
         {} significance; a threshold nothing reaches is not a threshold",
        glaurung::identity::cfr::CONFIDENT_SIGNIFICANCE
    );
}

/// Extraction must be deterministic across calls, same discipline as the other
/// schemes' -- and with the normaliser on as well as off, because a peephole
/// rewriter that depended on iteration order is the newest thing here that
/// could break it. A canonical form that moved between two calls in one
/// process would not be an identity.
#[test]
fn cfr_extraction_is_deterministic() {
    let Some(corpus) = load() else { return };
    let Some(slice) = corpus.slice("gcc", "O2") else {
        return;
    };
    for scheme in [CfrScheme::plain(), CfrScheme::normalized()] {
        let mut checked = 0usize;
        for sample in slice.samples.iter().take(150) {
            let (Ok(first), Ok(second)) = (scheme.extract(sample), scheme.extract(sample)) else {
                continue;
            };
            assert_eq!(
                first.digest,
                second.digest,
                "{} signed {}::{} twice to two different digests",
                scheme.name(),
                sample.fixture,
                sample.name
            );
            checked += 1;
        }
        assert!(
            checked >= 80,
            "only {checked} determinism checks ran for {}",
            scheme.name()
        );
    }
}

/// The training / held-out split must be a function of the label and of
/// nothing else, and it must be roughly balanced.
///
/// A split that depended on slice order or on a hash seed that moved would
/// make every weighted number in this file unreproducible, and a split that
/// put 95% of the corpus on one side would make the control row underpowered
/// while looking exactly like a fair one.
#[test]
fn the_cfr_training_split_is_stable_and_balanced() {
    let Some(corpus) = load() else { return };
    let mut training = 0usize;
    let mut held_out = 0usize;
    for slice in corpus.slices() {
        for sample in &slice.samples {
            if scheme::cfr_in_training_half(&sample.fixture, &sample.name) {
                training += 1;
            } else {
                held_out += 1;
            }
        }
    }
    let total = training + held_out;
    assert!(total > 500, "corpus too small to split: {total}");
    let share = training as f64 / total as f64;
    assert!(
        (0.40..=0.60).contains(&share),
        "training half is {training}/{total} = {share:.3}, which is not a half"
    );

    // The same label must land on the same side every time it is asked, and
    // in every slice: that is what stops a function's -O0 build training the
    // table that scores its -O2 build.
    for slice in corpus.slices() {
        for sample in slice.samples.iter().take(50) {
            let first = scheme::cfr_in_training_half(&sample.fixture, &sample.name);
            let again = scheme::cfr_in_training_half(&sample.fixture, &sample.name);
            assert_eq!(first, again);
        }
    }
    // ...and it must actually depend on the label.
    assert_ne!(
        scheme::cfr_in_training_half("a", "b"),
        (0..64)
            .map(|i| scheme::cfr_in_training_half("a", &format!("b{i}")))
            .all(|x| x),
        "the split assigns every label the same way"
    );
}

/// The unweighted CFR over the whole corpus: comparable with the CTPH and
/// `structural` rows above, and the floor the weighting has to move.
#[test]
fn cfr_retrieval_ratchets() {
    let Some(report) = cfr_report() else { return };

    let xo = report.result("XO-gcc").expect("XO-gcc ran");
    assert_ratchet("cfr XO-gcc AUC", xo.auc, CFR_XO_GCC_MIN_AUC, &xo.line());
    assert_ratchet(
        "cfr XO-gcc Recall@1",
        xo.recall(1),
        CFR_XO_GCC_MIN_RECALL_AT_1,
        &xo.line(),
    );
    assert_ratchet(
        "cfr XO-gcc MRR10",
        xo.mrr10,
        CFR_XO_GCC_MIN_MRR10,
        &xo.line(),
    );

    let xc = report.result("XC-O2").expect("XC-O2 ran");
    assert_ratchet("cfr XC-O2 AUC", xc.auc, CFR_XC_O2_MIN_AUC, &xc.line());
    assert_ratchet("cfr XC-O2 MRR10", xc.mrr10, CFR_XC_O2_MIN_MRR10, &xc.line());

    let xm = report.result("XM").expect("XM ran");
    assert_ratchet("cfr XM AUC", xm.auc, CFR_XM_MIN_AUC, &xm.line());

    assert!(
        report.extraction_us_per_function <= CFR_MAX_EXTRACTION_US,
        "CFR extraction cost {:.2} us/function over {} samples, ceiling \
         {CFR_MAX_EXTRACTION_US:.2} ({})",
        report.extraction_us_per_function,
        report.extraction_samples,
        report.profile
    );
}

/// What the TF-IDF table is worth: the weighted row against the unweighted
/// control, over the identical held-out population.
///
/// The plan's hypothesis is that weighting lifts **XO** most, because
/// cross-optimisation is where two builds of one function agree on their rare
/// structure and disagree on their common structure -- exactly the case a
/// rarity weighting is for. The assertion below is on the measured deltas, not
/// on the hypothesis: it pins each task's weighted floor, and separately
/// asserts that the weighting does not make any task *worse* by more than the
/// ratchet slack, which is the failure a weight table can plausibly produce and
/// which no per-task floor would catch on its own.
#[test]
fn cfr_weighting_ratchets() {
    let Some(matrix) = cfr_lever_matrix() else {
        return;
    };
    let (control, weighted) = (&matrix.plain, &matrix.weighted);

    for (task, floor) in CFR_WEIGHTED_MIN_AUC {
        let r = weighted
            .result(task)
            .unwrap_or_else(|| panic!("{task} did not run"));
        assert!(
            !r.underpowered(),
            "{task} is ratcheted but scored only {} queries, below {}.\n{}",
            r.scored,
            metrics::MIN_SCORED_FOR_A_MEASUREMENT,
            r.line()
        );
        assert_ratchet(
            &format!("cfr-weighted {task} AUC"),
            r.auc,
            *floor,
            &r.line(),
        );
    }

    eprintln!("\n--- weighted vs unweighted, held-out half, in-house corpus ---");
    let mut regressed = Vec::new();
    for (task, _) in CFR_WEIGHTED_MIN_AUC {
        let (Some(before), Some(after)) = (control.result(task), weighted.result(task)) else {
            continue;
        };
        eprintln!(
            "{task}: AUC {:.4} -> {:.4} ({:+.4}), MRR10 {:.4} -> {:.4} ({:+.4}), \
             R@1 {:.4} -> {:.4} ({:+.4}), scored {} of {} pool",
            before.auc,
            after.auc,
            after.auc - before.auc,
            before.mrr10,
            after.mrr10,
            after.mrr10 - before.mrr10,
            before.recall(1),
            after.recall(1),
            after.recall(1) - before.recall(1),
            after.scored,
            after.global_pool_size,
        );
        assert_eq!(
            before.scored, after.scored,
            "{task}: the control and the weighted row must score the identical \
             population, or the delta is not a delta"
        );
        if after.auc < before.auc - RATCHET_SLACK {
            regressed.push(format!("{task}: AUC {:.6} -> {:.6}", before.auc, after.auc));
        }
    }
    assert!(
        regressed.is_empty(),
        "the TF-IDF table made these tasks worse by more than {RATCHET_SLACK}: {}",
        regressed.join("; ")
    );
}

/// The normaliser lever on the whole corpus: the row `cfr` is read against.
#[test]
fn normalized_cfr_retrieval_ratchets() {
    let Some(report) = cfr_normalized_report() else {
        return;
    };

    let xo = report.result("XO-gcc").expect("XO-gcc ran");
    assert_ratchet(
        "cfr-normalized XO-gcc AUC",
        xo.auc,
        CFR_NORM_XO_GCC_MIN_AUC,
        &xo.line(),
    );
    assert_ratchet(
        "cfr-normalized XO-gcc Recall@1",
        xo.recall(1),
        CFR_NORM_XO_GCC_MIN_RECALL_AT_1,
        &xo.line(),
    );
    assert_ratchet(
        "cfr-normalized XO-gcc MRR10",
        xo.mrr10,
        CFR_NORM_XO_GCC_MIN_MRR10,
        &xo.line(),
    );

    let xc = report.result("XC-O2").expect("XC-O2 ran");
    assert_ratchet(
        "cfr-normalized XC-O2 AUC",
        xc.auc,
        CFR_NORM_XC_O2_MIN_AUC,
        &xc.line(),
    );

    let xm = report.result("XM").expect("XM ran");
    assert_ratchet(
        "cfr-normalized XM AUC",
        xm.auc,
        CFR_NORM_XM_MIN_AUC,
        &xm.line(),
    );
}

/// The comparison the normaliser lane exists to make, task by task, in one
/// place: both schemes, same corpus, same driver, same negatives.
///
/// The assertion is deliberately weak -- the normaliser must not make the
/// *cross-optimisation* lane worse -- because a per-task "must improve" would
/// be a ratchet on eight numbers whose individual movements are single
/// functions. The table it prints is the deliverable.
#[test]
fn the_normaliser_is_not_a_regression_on_the_cross_optimisation_lane() {
    let (Some(plain), Some(normalised)) = (cfr_report(), cfr_normalized_report()) else {
        return;
    };
    eprintln!("\ncfr vs cfr-normalized, in-house corpus, whole corpus");
    eprintln!(
        "{:<8} {:>8} {:>8}   {:>8} {:>8}   {:>8} {:>8}   {:>7}",
        "task", "AUC", "AUC'", "MRR10", "MRR10'", "R@1", "R@1'", "scored"
    );
    for result in &plain.results {
        let Some(other) = normalised.result(&result.task_name) else {
            continue;
        };
        eprintln!(
            "{:<8} {:8.4} {:8.4}   {:8.4} {:8.4}   {:8.4} {:8.4}   {:>7}{}",
            result.task_name,
            result.auc,
            other.auc,
            result.mrr10,
            other.mrr10,
            result.recall(1),
            other.recall(1),
            result.scored,
            if result.underpowered() {
                "  (underpowered)"
            } else {
                ""
            }
        );
    }

    let plain_xo = plain.result("XO-gcc").expect("XO-gcc ran");
    let normalised_xo = normalised.result("XO-gcc").expect("XO-gcc ran");
    assert!(
        normalised_xo.recall(1) >= plain_xo.recall(1),
        "the normaliser lowered XO Recall@1 from {:.4} to {:.4}",
        plain_xo.recall(1),
        normalised_xo.recall(1)
    );
}

/// **The 2x2**: what the two levers are worth apart, and what they are worth
/// together, over one population.
///
/// This is the row the integration branch exists to produce. The two lanes were
/// developed separately -- the normaliser changes the representation, the
/// TF-IDF table changes the metric -- and nothing about either mechanism says
/// how they compose. Normalisation collapses rare features into common ones,
/// which is precisely the material a rarity weighting trades on, so the
/// interaction could plausibly be sub-additive; it is measured here rather than
/// assumed.
///
/// The floors in [`CFR_NORM_WEIGHTED_MIN_AUC`] are read off a run. The extra
/// assertion is that the combined cell is not *worse* than either single lever
/// by more than [`RATCHET_SLACK`] -- the failure a bad interaction would
/// actually produce, and one no per-task floor catches on its own.
#[test]
fn the_two_cfr_levers_compose() {
    let Some(matrix) = cfr_lever_matrix() else {
        return;
    };

    eprintln!("\n--- CFR lever 2x2, held-out half, in-house corpus ---");
    eprintln!(
        "| Task | Scored | Pool (sampled / global) | AUC plain | AUC norm | \
         AUC wtd | AUC norm+wtd |"
    );
    eprintln!("|---|---|---|---|---|---|---|");
    for result in &matrix.plain.results {
        let task = &result.task_name;
        let (Some(n), Some(w), Some(nw)) = (
            matrix.normalized.result(task),
            matrix.weighted.result(task),
            matrix.normalized_weighted.result(task),
        ) else {
            continue;
        };
        eprintln!(
            "| {} | {} | {} / {} | {:.4} | {:.4} | {:.4} | {:.4} |{}",
            task,
            result.scored,
            result.sampled_pool_size,
            result.global_pool_size,
            result.auc,
            n.auc,
            w.auc,
            nw.auc,
            if result.underpowered() {
                "  (underpowered)"
            } else {
                ""
            }
        );
    }
    eprintln!(
        "\n| Task | MRR10 plain | MRR10 norm | MRR10 wtd | MRR10 norm+wtd | \
         R@1 plain | R@1 norm | R@1 wtd | R@1 norm+wtd |"
    );
    eprintln!("|---|---|---|---|---|---|---|---|---|");
    for result in &matrix.plain.results {
        let task = &result.task_name;
        let (Some(n), Some(w), Some(nw)) = (
            matrix.normalized.result(task),
            matrix.weighted.result(task),
            matrix.normalized_weighted.result(task),
        ) else {
            continue;
        };
        eprintln!(
            "| {} | {:.4} | {:.4} | {:.4} | {:.4} | {:.4} | {:.4} | {:.4} | {:.4} |",
            task,
            result.mrr10,
            n.mrr10,
            w.mrr10,
            nw.mrr10,
            result.recall(1),
            n.recall(1),
            w.recall(1),
            nw.recall(1),
        );
    }

    // Every cell must score the identical population, or none of the above is
    // a comparison.
    for result in &matrix.plain.results {
        let task = &result.task_name;
        for (label, other) in [
            ("cfr-normalized-heldout", &matrix.normalized),
            ("cfr-weighted", &matrix.weighted),
            ("cfr-normalized-weighted", &matrix.normalized_weighted),
        ] {
            let Some(other) = other.result(task) else {
                continue;
            };
            assert_eq!(
                result.scored, other.scored,
                "{task}: {label} scored {} queries against the control's {}; \
                 four cells over four populations is not a 2x2",
                other.scored, result.scored
            );
        }
    }

    for (task, floor) in CFR_NORM_WEIGHTED_MIN_AUC {
        let r = matrix
            .normalized_weighted
            .result(task)
            .unwrap_or_else(|| panic!("{task} did not run"));
        assert!(
            !r.underpowered(),
            "{task} is ratcheted but scored only {} queries, below {}.\n{}",
            r.scored,
            metrics::MIN_SCORED_FOR_A_MEASUREMENT,
            r.line()
        );
        assert_ratchet(
            &format!("cfr-normalized-weighted {task} AUC"),
            r.auc,
            *floor,
            &r.line(),
        );
    }

    let mut regressed = Vec::new();
    for (task, _) in CFR_NORM_WEIGHTED_MIN_AUC {
        let Some(both) = matrix.normalized_weighted.result(task) else {
            continue;
        };
        for (label, single) in [
            ("the weighting alone", matrix.weighted.result(task)),
            ("the normaliser alone", matrix.normalized.result(task)),
        ] {
            let Some(single) = single else { continue };
            if both.auc < single.auc - RATCHET_SLACK {
                regressed.push(format!(
                    "{task}: {label} reads AUC {:.6}, both levers {:.6}",
                    single.auc, both.auc
                ));
            }
        }
    }
    assert!(
        regressed.is_empty(),
        "composing the two levers cost more than {RATCHET_SLACK} against a \
         single lever on: {}",
        regressed.join("; ")
    );
}

/// Every CFR number on the in-house corpus, no ratchet in the way, with the
/// weighted-vs-unweighted deltas printed as markdown rows for the docs.
///
/// `cargo test --features python-ext --test identity_retrieval -- --ignored
/// --nocapture cfr`
#[test]
#[ignore = "full CFR sweep: minutes. cargo test --features python-ext --test identity_retrieval -- --ignored --nocapture cfr_full_sweep"]
fn cfr_full_sweep() {
    let Some(report) = cfr_report() else { return };
    print_markdown_rows("cfr (uniform weights, whole corpus)", report);
    if let Some(normalized) = cfr_normalized_report() {
        print_markdown_rows("cfr-normalized (uniform weights, whole corpus)", normalized);
    }
    let Some(matrix) = cfr_lever_matrix() else {
        return;
    };
    let (control, weighted) = (&matrix.plain, &matrix.weighted);
    print_markdown_rows("cfr-heldout (uniform weights, held-out half)", control);
    print_markdown_rows(
        "cfr-normalized-heldout (normalised, uniform weights, held-out half)",
        &matrix.normalized,
    );
    print_markdown_rows("cfr-weighted (TF-IDF, held-out half)", weighted);
    print_markdown_rows(
        "cfr-normalized-weighted (normalised + TF-IDF, held-out half)",
        &matrix.normalized_weighted,
    );

    eprintln!("\n| Task | Scored | Pool | AUC unw. | AUC wtd. | d AUC | MRR10 unw. | MRR10 wtd. | d MRR10 | R@1 unw. | R@1 wtd. | d R@1 |");
    eprintln!("|---|---|---|---|---|---|---|---|---|---|---|---|");
    for result in &weighted.results {
        let Some(before) = control.result(&result.task_name) else {
            continue;
        };
        eprintln!(
            "| {} | {} | {} | {:.4} | {:.4} | {:+.4} | {:.4} | {:.4} | {:+.4} | {:.4} | {:.4} | {:+.4} |",
            result.task_name,
            result.scored,
            result.global_pool_size,
            before.auc,
            result.auc,
            result.auc - before.auc,
            before.mrr10,
            result.mrr10,
            result.mrr10 - before.mrr10,
            before.recall(1),
            result.recall(1),
            result.recall(1) - before.recall(1),
        );
    }
}

// ---------------------------------------------------------------------------
// The CFR on Dataset-1: the XA, XB and XA+XB lanes, and the two MIPS rows the
// lifter cannot reach at all.
// ---------------------------------------------------------------------------

/// Score the unweighted and weighted CFR over every Dataset-1 task, once.
///
/// Returns `(unweighted whole corpus, unweighted held-out, weighted held-out)`
/// -- the same three rows as the in-house lane and for the same reason: the
/// first is comparable with the CTPH and `structural` rows, and the last two
/// are the delta over one population.
#[allow(clippy::type_complexity)]
fn cisco_cfr_reports() -> Option<&'static (SchemeReport, SchemeReport, SchemeReport)> {
    use std::sync::OnceLock;
    static REPORTS: OnceLock<Option<(SchemeReport, SchemeReport, SchemeReport)>> = OnceLock::new();
    REPORTS
        .get_or_init(|| {
            let corpus = cisco::corpus()?;
            let settings = glaurung::identity::cfr::CfrSettings::default();
            let weights = scheme::cfr_train_weights(
                corpus.slices().flat_map(|(_, slice)| slice.samples.iter()),
                settings,
            )?;
            eprintln!(
                "\n=== Dataset-1 CFR weight table {} : {} documents (training \
                 half), {} weighted features ===",
                weights.weights_id(),
                weights.documents(),
                weights.len()
            );
            let plain = CfrScheme::default();
            let control = CfrScheme::unweighted_held_out(settings);
            let treatment = CfrScheme::weighted(settings, weights);
            Some((
                print_report(cisco::evaluate(&plain, corpus, cisco::TASKS)),
                print_report(cisco::evaluate(&control, corpus, cisco::TASKS)),
                print_report(cisco::evaluate(&treatment, corpus, cisco::TASKS)),
            ))
        })
        .as_ref()
}

/// The CFR's Dataset-1 floors, and the two rows it must refuse.
///
/// The refusal is the point of half this test. `src/ir/lift/` covers x86,
/// x86-64, ARM and AArch64 and reaches MIPS not at all, so on the two MIPS
/// slices this scheme has no signature to give. A scheme that answered anyway
/// -- with an empty vector, scoring 0.0 against everything -- would produce a
/// row that looks exactly like a measurement and is a coverage hole. So
/// [`CISCO_CFR_UNLIFTABLE_TASKS`] asserts those rows score *zero* queries, and
/// if a MIPS lifter ever lands this test fires and says to promote them.
#[test]
fn cisco_cfr_retrieval_ratchets() {
    let Some((plain, control, weighted)) = cisco_cfr_reports() else {
        return;
    };

    for (task, floor) in CISCO_CFR_MIN_AUC {
        let r = plain
            .result(task)
            .unwrap_or_else(|| panic!("{task} did not run"));
        assert!(
            !r.underpowered(),
            "{task} is ratcheted but scored only {} queries, below {}.\n{}",
            r.scored,
            metrics::MIN_SCORED_FOR_A_MEASUREMENT,
            r.line()
        );
        assert_ratchet(&format!("cisco cfr {task} AUC"), r.auc, *floor, &r.line());
    }

    for task in CISCO_CFR_UNDERPOWERED_TASKS {
        let r = plain
            .result(task)
            .unwrap_or_else(|| panic!("{task} did not run"));
        assert!(
            r.underpowered(),
            "{task} now scores {} queries, at or above {}. Quote the row and \
             move it into CISCO_CFR_MIN_AUC.\n{}",
            r.scored,
            metrics::MIN_SCORED_FOR_A_MEASUREMENT,
            r.line()
        );
    }

    for task in CISCO_CFR_UNLIFTABLE_TASKS {
        let r = plain
            .result(task)
            .unwrap_or_else(|| panic!("{task} did not run"));
        assert_eq!(
            r.scored,
            0,
            "{task} scored {} queries, but its pool is a MIPS slice and \
             `src/ir/lift/` has no MIPS lifter. Either a lifter landed -- in \
             which case quote the row and move this task into \
             CISCO_CFR_MIN_AUC -- or the scheme is answering where it should \
             be refusing.\n{}",
            r.scored,
            r.line()
        );
    }
    assert_eq!(
        CISCO_CFR_MIN_AUC.len()
            + CISCO_CFR_UNDERPOWERED_TASKS.len()
            + CISCO_CFR_UNLIFTABLE_TASKS.len(),
        cisco::TASKS.len(),
        "{} Dataset-1 tasks run but only {} are accounted for; a task in none \
         of the three tables is a lane nothing checks",
        cisco::TASKS.len(),
        CISCO_CFR_MIN_AUC.len()
            + CISCO_CFR_UNDERPOWERED_TASKS.len()
            + CISCO_CFR_UNLIFTABLE_TASKS.len()
    );

    eprintln!("\n--- weighted vs unweighted, held-out half, Dataset-1 ---");
    for (task, _) in CISCO_CFR_MIN_AUC {
        let (Some(before), Some(after)) = (control.result(task), weighted.result(task)) else {
            continue;
        };
        eprintln!(
            "{task}: AUC {:.4} -> {:.4} ({:+.4}), MRR10 {:.4} -> {:.4} ({:+.4}), \
             R@1 {:.4} -> {:.4} ({:+.4}), scored {} of {} pool",
            before.auc,
            after.auc,
            after.auc - before.auc,
            before.mrr10,
            after.mrr10,
            after.mrr10 - before.mrr10,
            before.recall(1),
            after.recall(1),
            after.recall(1) - before.recall(1),
            after.scored,
            after.global_pool_size,
        );
        assert_eq!(
            before.scored, after.scored,
            "{task}: the control and the weighted row must score the identical \
             population"
        );
    }
}

/// Every Dataset-1 CFR number, with the weighted-vs-unweighted deltas as
/// markdown rows.
///
/// `GLAURUNG_CISCO_CORPUS=... cargo test --features python-ext --test
/// identity_retrieval -- --ignored --nocapture cisco_cfr_full_sweep`
#[test]
#[ignore = "full Dataset-1 CFR sweep: minutes. GLAURUNG_CISCO_CORPUS=... cargo test --features python-ext --test identity_retrieval -- --ignored --nocapture cisco_cfr_full_sweep"]
fn cisco_cfr_full_sweep() {
    let Some((plain, control, weighted)) = cisco_cfr_reports() else {
        return;
    };
    print_markdown_rows("Dataset-1 cfr (uniform weights, whole corpus)", plain);
    print_markdown_rows("Dataset-1 cfr-heldout (uniform weights)", control);
    print_markdown_rows("Dataset-1 cfr-weighted (TF-IDF)", weighted);

    eprintln!("\n| Task | Scored | Pool | AUC unw. | AUC wtd. | d AUC | MRR10 unw. | MRR10 wtd. | d MRR10 | R@1 unw. | R@1 wtd. | d R@1 |");
    eprintln!("|---|---|---|---|---|---|---|---|---|---|---|---|");
    for result in &weighted.results {
        let Some(before) = control.result(&result.task_name) else {
            continue;
        };
        eprintln!(
            "| {} | {} | {} | {:.4} | {:.4} | {:+.4} | {:.4} | {:.4} | {:+.4} | {:.4} | {:.4} | {:+.4} |",
            result.task_name,
            result.scored,
            result.global_pool_size,
            before.auc,
            result.auc,
            result.auc - before.auc,
            before.mrr10,
            result.mrr10,
            result.mrr10 - before.mrr10,
            before.recall(1),
            result.recall(1),
            result.recall(1) - before.recall(1),
        );
    }
}

/// The full sweep: every task's every number printed, and the JSON report
/// written, with no ratchet in the way.
///
/// `cargo test --test identity_retrieval -- --ignored --nocapture`
///
/// This is what to run when a new scheme lands, when regenerating the results
/// table in `docs/development/identity-measurement.md`, or when a ratchet
/// fires and the question is which task moved.
#[test]
#[ignore = "full sweep: minutes. cargo test --test identity_retrieval -- --ignored --nocapture"]
fn full_sweep() {
    let Some(corpus) = load() else { return };
    eprintln!("corpus filters: {}", corpus.filters.summary());
    for slice in corpus.slices() {
        eprintln!(
            "  {}/{}: {} functions, {}",
            slice.compiler,
            slice.opt,
            slice.samples.len(),
            slice.filters.summary()
        );
    }
    let Some(report) = ctph_report() else { return };
    eprintln!("\n--- markdown rows for docs/development/identity-measurement.md ---");
    eprintln!(
        "| Task | Free variables | Scored | Pool (sampled / global) | AUC | \
         MRR10 | R@1 | R@5 | R@10 | R@50 | Global R@1 |"
    );
    eprintln!("|---|---|---|---|---|---|---|---|---|---|---|");
    for r in &report.results {
        eprintln!(
            "| {} | {} | {} | {} / {} | {:.4} | {:.4} | {:.4} | {:.4} | {:.4} | {:.4} | {:.4} |",
            r.task_name,
            r.conditions,
            r.scored,
            r.sampled_pool_size,
            r.global_pool_size,
            r.auc,
            r.mrr10,
            r.recall(1),
            r.recall(5),
            r.recall(10),
            r.recall(50),
            r.global_recall_at_1,
        );
    }
    eprintln!(
        "\nextraction {:.2} us/function over {} samples",
        report.extraction_us_per_function, report.extraction_samples
    );
}

/// The full `structural` in-house sweep, with markdown rows for the docs
/// table.
///
/// `cargo test --features python-ext --test identity_retrieval -- --ignored
/// --nocapture structural_full_sweep`
#[test]
#[ignore = "full sweep: minutes. cargo test --features python-ext --test identity_retrieval -- --ignored --nocapture structural_full_sweep"]
fn structural_full_sweep() {
    let Some(corpus) = load() else { return };
    eprintln!("corpus filters: {}", corpus.filters.summary());
    for slice in corpus.slices() {
        eprintln!(
            "  {}/{}: {} functions, {}",
            slice.compiler,
            slice.opt,
            slice.samples.len(),
            slice.filters.summary()
        );
    }
    let Some(report) = structural_report() else {
        return;
    };
    eprintln!("\n--- markdown rows for docs/development/identity-measurement.md ---");
    eprintln!(
        "| Task | Free variables | Scored | Pool (sampled / global) | AUC | \
         MRR10 | R@1 | R@5 | R@10 | R@50 | Global R@1 |"
    );
    eprintln!("|---|---|---|---|---|---|---|---|---|---|---|");
    for r in &report.results {
        eprintln!(
            "| {} | {} | {} | {} / {} | {:.4} | {:.4} | {:.4} | {:.4} | {:.4} | {:.4} | {:.4} |",
            r.task_name,
            r.conditions,
            r.scored,
            r.sampled_pool_size,
            r.global_pool_size,
            r.auc,
            r.mrr10,
            r.recall(1),
            r.recall(5),
            r.recall(10),
            r.recall(50),
            r.global_recall_at_1,
        );
    }
    eprintln!(
        "\nextraction {:.2} us/function over {} samples",
        report.extraction_us_per_function, report.extraction_samples
    );
}

// ---------------------------------------------------------------------------
// The normaliser lever on Cisco Talos Dataset-1.
//
// Both configurations, plain and peephole-normalised, over the three tasks
// plan item 8 names: XO, XC and XM. These are `#[ignore]`d and the reason is
// cost, not taste: the CFR's extraction is a whole-image discovery plus a lift
// of every function in that image, which on Dataset-1's real binaries is
// orders of magnitude more work than the CTPH and structural schemes this file
// runs by default. The lane exists, the command that runs it is in the
// attribute, and the numbers it produced are recorded in
// `docs/reference/function-identity-cfr.md`.
//
// The weighting's Dataset-1 rows are `cisco_cfr_reports` above; this lane is
// the other lever, and the two are kept apart because they cost minutes each.
// ---------------------------------------------------------------------------

/// The three Dataset-1 tasks this lane runs, which are the ones plan item 8
/// names. `XB` and the `XA-*` lanes are deliberately excluded: they cost the
/// same again, and a local peephole rewriter has nothing to say about a change
/// of instruction set that the mask list does not already say.
fn cisco_cfr_tasks() -> Vec<cisco::CiscoTask> {
    cisco::TASKS
        .iter()
        .filter(|task| matches!(task.name, "XO" | "XC" | "XM"))
        .copied()
        .collect()
}

fn run_cisco_cfr(scheme: CfrScheme) -> Option<SchemeReport> {
    let corpus = cisco::corpus()?;
    let report = cisco::evaluate(&scheme, corpus, &cisco_cfr_tasks());
    eprintln!("\n=== {} -- {} ===", report.scheme, report.corpus_name);
    eprintln!(
        "extraction {:.2} us/function over {} samples ({} profile)",
        report.extraction_us_per_function, report.extraction_samples, report.profile
    );
    for note in &report.coverage_notes {
        eprintln!("coverage: {note}");
    }
    for result in &report.results {
        eprintln!("{}", result.line());
    }
    if let Some(path) = report.write_json(&metrics::report_dir()) {
        eprintln!("report: {}", path.display());
    }
    Some(report)
}

/// `cargo test --release --features python-ext --test identity_retrieval -- \
///   --ignored --nocapture cisco_cfr_xo_xc_xm`
#[test]
#[ignore = "Dataset-1 CFR: lifts every function of every image. Minutes. GLAURUNG_CISCO_CORPUS must be set."]
fn cisco_cfr_xo_xc_xm() {
    let Some(plain) = run_cisco_cfr(CfrScheme::plain()) else {
        return;
    };
    let Some(normalised) = run_cisco_cfr(CfrScheme::normalized()) else {
        return;
    };
    eprintln!("\ncfr vs cfr-normalized, Cisco Dataset-1");
    eprintln!(
        "{:<6} {:>8} {:>8}   {:>8} {:>8}   {:>8} {:>8}   {:>7} {:>7}",
        "task", "AUC", "AUC'", "MRR10", "MRR10'", "R@1", "R@1'", "scored", "fail"
    );
    for result in &plain.results {
        let Some(other) = normalised.result(&result.task_name) else {
            continue;
        };
        eprintln!(
            "{:<6} {:8.4} {:8.4}   {:8.4} {:8.4}   {:8.4} {:8.4}   {:>7} {:>7}{}",
            result.task_name,
            result.auc,
            other.auc,
            result.mrr10,
            other.mrr10,
            result.recall(1),
            other.recall(1),
            result.scored,
            result.extraction_failures,
            if result.underpowered() {
                "  (underpowered)"
            } else {
                ""
            }
        );
    }
    // No ratchet: an `#[ignore]`d lane cannot regress in CI, so a floor here
    // would be a floor nothing checks. What this lane must do is RUN -- a
    // scheme that refused every Dataset-1 sample would print an empty table
    // and look like a measurement.
    for result in &plain.results {
        assert!(
            result.scored > 0,
            "{}: nothing scored. Either the twin join is broken or the CFR \
             refused every sample ({} extraction failures).",
            result.task_name,
            result.extraction_failures
        );
    }
}

// ---------------------------------------------------------------------------
// Value fingerprints on Cisco Dataset-1.
//
// x86-64 lanes only, and that is a property of the scheme rather than of the
// corpus: `glaurung::identity::values` drives the concrete interpreter, whose
// register file is x86-64 (`glaurung::exec::Machine::new`). Running an ARM64
// or a MIPS function through it would not fail loudly -- it would read every
// register as zero and produce a fingerprint that looked like a measurement --
// so `fingerprints_for_path` refuses the architecture instead, and the XB,
// XA-* and XA+XO lanes fail extraction on every pool sample. They are asserted
// to fail, below, rather than quietly omitted.
// ---------------------------------------------------------------------------

/// The Dataset-1 tasks whose query AND pool are both x86-64.
#[cfg(feature = "exec")]
const CISCO_X86_64_TASKS: &[&str] = &["XO", "XC", "XM"];

/// `cargo test --release --features exec --test identity_retrieval -- \
///   --ignored --nocapture cisco_values`
#[cfg(feature = "exec")]
#[test]
#[ignore = "Dataset-1 values: runs the interpreter over every function of every image. Minutes. GLAURUNG_CISCO_CORPUS must be set."]
fn cisco_values_x86_64_lanes() {
    let Some(corpus) = cisco::corpus() else {
        return;
    };
    let scheme = scheme::ValueScheme::plain();
    let report = cisco::evaluate(&scheme, corpus, cisco::TASKS);
    eprintln!(
        "\n=== scheme {} on Cisco Dataset-1 -- {} ===",
        report.scheme, report.description
    );
    eprintln!(
        "extraction {:.2} us/function over {} samples ({} profile)",
        report.extraction_us_per_function, report.extraction_samples, report.profile
    );
    eprintln!(
        "| Task | Free variables | Scored | Global pool | AUC | MRR10 | R@1 | \
         R@5 | R@10 | Extract fail |"
    );
    eprintln!("|---|---|---|---|---|---|---|---|---|---|");
    for result in &report.results {
        eprintln!(
            "| {} | {} | {} | {} | {:.4} | {:.4} | {:.4} | {:.4} | {:.4} | {} |",
            result.task_name,
            result.conditions,
            result.scored,
            result.global_pool_size,
            result.auc,
            result.mrr10,
            result.recall(1),
            result.recall(5),
            result.recall(10),
            result.extraction_failures,
        );
    }
    if let Some(path) = report.write_json(&metrics::report_dir()) {
        eprintln!("report: {}", path.display());
    }

    for result in &report.results {
        if CISCO_X86_64_TASKS.contains(&result.task_name.as_str()) {
            assert!(
                result.scored > 0,
                "{}: nothing scored on an x86-64 lane. Either the twin join is \
                 broken or the scheme refused every sample ({} extraction \
                 failures).",
                result.task_name,
                result.extraction_failures
            );
        } else {
            // The cross-architecture lanes must fail LOUDLY: an unsupported
            // architecture that scored anything would mean the interpreter had
            // run x86-64 semantics over ARM or MIPS bytes.
            assert_eq!(
                result.scored, 0,
                "{} scored {} queries, but its pool is not x86-64 and this \
                 scheme cannot fingerprint it",
                result.task_name, result.scored
            );
        }
    }
}

// ---------------------------------------------------------------------------
// The RevDecode-style re-rank (plan item 10).
//
// Not a scheme -- a post-pass over the candidate lists a scheme produced, so it
// is scored by `rerank.rs` against the same twin join, the same seeded negative
// draw and the same pessimistic tie rule, before and after. Every constant
// below was read off a run before it was written down.
// ---------------------------------------------------------------------------

use glaurung::identity::rerank::RerankSettings;
use rerank::{PoolLane, RerankReport};

/// Run one `(scheme, settings, lane)` triple over the in-house tasks and print
/// it.
fn rerank_report<S: Scheme>(
    scheme: &S,
    settings: &RerankSettings,
    label: &str,
    lane: PoolLane,
) -> Option<RerankReport> {
    let corpus = load()?;
    let report = rerank::evaluate(scheme, corpus, TASKS, settings, label, lane);
    eprintln!(
        "\n=== rerank: {} / {} / {} lane -- {} ({}) ===",
        report.scheme,
        report.settings_label,
        report.lane.label(),
        report.corpus_name,
        report.profile
    );
    for comparison in &report.comparisons {
        eprintln!("{}", comparison.line());
    }
    if let Some(path) = report.write_json(&metrics::report_dir()) {
        eprintln!("report: {}", path.display());
    }
    Some(report)
}

/// The null hypothesis, asserted rather than assumed.
///
/// With every context term off and the "no match" node removed, the decode must
/// return the underlying scheme's own ordering, rank for rank -- and those ranks
/// must be the ones `metrics::evaluate_slices` computes, because the two files
/// implement the same twin join twice and a drift between them would show up as
/// a re-rank "improvement".
///
/// This is the test that makes every other number on this lane attributable. If
/// the machinery moved rankings on its own, nothing measured under the full
/// settings could be blamed on context.
#[test]
fn the_rerank_is_a_no_op_without_context() {
    let Some(corpus) = load() else { return };
    let Some(baseline) = structural_report() else {
        return;
    };
    let settings = RerankSettings {
        no_match_similarity: None,
        ..RerankSettings::similarity_only()
    };
    let report = rerank::evaluate(
        &StructuralScheme::default(),
        corpus,
        TASKS,
        &settings,
        "similarity-only",
        PoolLane::Sampled,
    );
    assert!(!report.comparisons.is_empty(), "no tasks ran");
    for comparison in &report.comparisons {
        let reference = baseline
            .result(&comparison.task_name)
            .expect("every task in TASKS is scored by both drivers");
        assert_eq!(
            comparison.scored,
            reference.scored,
            "{}: the re-rank driver scored a different population than \
             metrics::evaluate_slices ({} vs {}). The two reimplement the same \
             twin join; a difference here invalidates every before/after number \
             on this lane.\n{}",
            comparison.task_name,
            comparison.scored,
            reference.scored,
            comparison.line()
        );
        assert!(
            (comparison.baseline_mrr10 - reference.mrr10).abs() < 1e-12,
            "{}: baseline MRR10 {:.9} from rerank.rs vs {:.9} from metrics.rs",
            comparison.task_name,
            comparison.baseline_mrr10,
            reference.mrr10
        );
        assert!(
            (comparison.baseline_recall_at_1 - reference.recall(1)).abs() < 1e-12,
            "{}: baseline R@1 {:.9} from rerank.rs vs {:.9} from metrics.rs",
            comparison.task_name,
            comparison.baseline_recall_at_1,
            reference.recall(1)
        );
        assert_eq!(
            comparison.improved,
            0,
            "{}: {} queries improved with every context term OFF. The decode is \
             moving rankings on its own, so nothing it does with context on can \
             be attributed to context.\n{}",
            comparison.task_name,
            comparison.improved,
            comparison.line()
        );
        assert_eq!(
            comparison.worsened,
            0,
            "{}: {} queries worsened with every context term off.\n{}",
            comparison.task_name,
            comparison.worsened,
            comparison.line()
        );
    }
}

/// The context the decode gets to see, measured before any ranking is.
///
/// A re-rank that improves nothing because the graph it was handed was empty
/// and one that improves nothing because context does not help look identical
/// in an MRR10 column. This asserts the graph is not empty: the corpus's
/// discovered call edges reach the scored population, and layer-adjacent pairs
/// with a call relation between them exist at all.
#[test]
fn the_decode_sees_a_non_empty_call_graph() {
    let Some(report) = rerank_report(
        &StructuralScheme::default(),
        &RerankSettings::call_graph_only(),
        "call-graph-only",
        PoolLane::Sampled,
    ) else {
        return;
    };
    let xo = report.comparison("XO-gcc").expect("XO-gcc ran");
    eprintln!("{}", xo.line());
    assert!(
        xo.query_call_edges >= RERANK_XO_GCC_MIN_QUERY_CALL_EDGES,
        "XO-gcc: only {} call edges between scored query functions, floor {}. \
         The decode's call term cannot fire on a graph this thin, so a null \
         result on this lane would say nothing about the algorithm.\n{}",
        xo.query_call_edges,
        RERANK_XO_GCC_MIN_QUERY_CALL_EDGES,
        xo.line()
    );
    assert!(
        xo.reference_call_edges >= RERANK_XO_GCC_MIN_REFERENCE_CALL_EDGES,
        "XO-gcc: only {} call edges in the reference pool, floor {}.\n{}",
        xo.reference_call_edges,
        RERANK_XO_GCC_MIN_REFERENCE_CALL_EDGES,
        xo.line()
    );
}

/// Call edges between two *scored query* functions on XO-gcc. Read off a run
/// (10 on 2026-09-03), floored well below it: this is a "the graph is not
/// empty" assertion, not a measurement of the corpus.
const RERANK_XO_GCC_MIN_QUERY_CALL_EDGES: usize = 1;
/// Call edges between two pool functions on XO-gcc. Read off a run (15).
const RERANK_XO_GCC_MIN_REFERENCE_CALL_EDGES: usize = 1;

/// **The measured property that decides how this stage should be configured.**
///
/// The call-agreement term did not cost a single query a rank in any of the 40
/// `(scheme x task x corpus x lane)` cells swept on 2026-09-03 -- two schemes,
/// eight in-house tasks and four Dataset-1 tasks, on both the sampled and the
/// global candidate lane. RevDecode's own provenance terms did, heavily; the
/// measured table in `docs/reference/function-identity-rerank.md` has both.
///
/// This is an empirical property and not a theorem: a call reward can in
/// principle promote a wrong candidate over a correct one. Which is exactly why
/// it is a test. If it fires, the finding has changed and the reference page
/// needs re-measuring -- do not relax the assertion.
#[test]
fn the_call_graph_term_never_costs_a_rank() {
    for lane in [PoolLane::Sampled, PoolLane::Global] {
        let Some(report) = rerank_report(
            &StructuralScheme::default(),
            &RerankSettings::call_graph_only(),
            "call-graph-only",
            lane,
        ) else {
            return;
        };
        for comparison in &report.comparisons {
            assert_eq!(
                comparison.worsened,
                0,
                "{} ({} lane): the call-agreement term demoted {} of {} twins. \
                 That has never happened in a measured sweep; the reference \
                 page's recommendation to run this term by default rests on \
                 it.\n{}",
                comparison.task_name,
                lane.label(),
                comparison.worsened,
                comparison.scored,
                comparison.line()
            );
        }
    }
}

/// The one lane the call graph measurably moves, ratcheted.
///
/// XC-O0 is where the in-house corpus has call edges to spare (50 between
/// scored query functions, against 5 on most other tasks), and it is the only
/// in-house row where the term moves more than a couple of queries. Both
/// numbers were read off a release run on 2026-09-03 and are the same in debug:
/// the decode is integer- and total-order-driven, so only the extraction cost
/// differs between profiles.
#[test]
fn structural_rerank_ratchets() {
    let Some(report) = rerank_report(
        &StructuralScheme::default(),
        &RerankSettings::call_graph_only(),
        "call-graph-only",
        PoolLane::Sampled,
    ) else {
        return;
    };
    let xc = report.comparison("XC-O0").expect("XC-O0 ran");
    assert_ratchet(
        "XC-O0 re-ranked MRR10",
        xc.reranked_mrr10,
        RERANK_STRUCTURAL_XC_O0_MIN_MRR10,
        &xc.line(),
    );
    assert_ratchet(
        "XC-O0 re-ranked R@1",
        xc.reranked_recall_at_1,
        RERANK_STRUCTURAL_XC_O0_MIN_RECALL_AT_1,
        &xc.line(),
    );
    assert!(
        xc.reranked_mrr10 > xc.baseline_mrr10,
        "XC-O0: the decode did not beat its own input ({:.6} -> {:.6}). A \
         re-rank that cannot improve the row it was measured on is not a \
         re-rank.\n{}",
        xc.baseline_mrr10,
        xc.reranked_mrr10,
        xc.line()
    );
}

/// `structural` XC-O0, sampled lane, call-graph-only, from 0.582359.
const RERANK_STRUCTURAL_XC_O0_MIN_MRR10: f64 = 0.595187;
/// ...and its Recall@1, from 0.472279.
const RERANK_STRUCTURAL_XC_O0_MIN_RECALL_AT_1: f64 = 0.490759;

/// The full re-rank sweep: every scheme, every ablation, both corpora.
///
/// `cargo test --release --features python-ext --test identity_retrieval -- \
///   --ignored --nocapture rerank_full_sweep`
#[test]
#[ignore = "full re-rank sweep: every scheme x every ablation. Minutes."]
fn rerank_full_sweep() {
    let presets: [(&str, RerankSettings); 5] = [
        ("similarity-only", RerankSettings::similarity_only()),
        ("call-graph-only", RerankSettings::call_graph_only()),
        ("adjacency-only", RerankSettings::adjacency_only()),
        ("paper", RerankSettings::revdecode_paper()),
        // The paper normalises raw similarities with a sigmoid before they
        // enter the weight, and its adjacency constant (0.7) is calibrated
        // against scores spread over the whole of [0, 1] by that step. Our
        // similarities are already in [0, 1] but occupy a narrow band, so the
        // same constant is a far larger prior here than there. This preset is
        // the experiment that says whether re-spreading the scores recovers
        // the paper's balance -- see the measured table in
        // docs/reference/function-identity-rerank.md.
        (
            "paper-sigmoid",
            RerankSettings {
                normalization: glaurung::identity::rerank::Normalization::Sigmoid {
                    centre: 0.5,
                    steepness: 8.0,
                },
                ..RerankSettings::revdecode_paper()
            },
        ),
    ];

    let lanes = [PoolLane::Sampled, PoolLane::Global];

    eprintln!("\n--- in-house fixture matrix ---");
    for lane in lanes {
        for (label, settings) in &presets {
            rerank_report(&StructuralScheme::default(), settings, label, lane);
        }
        for (label, settings) in &presets {
            rerank_report(&CfrScheme::plain(), settings, label, lane);
        }
    }

    let Some(cisco_corpus) = cisco::corpus() else {
        eprintln!("SKIP: no Cisco corpus; set GLAURUNG_CISCO_CORPUS.");
        return;
    };
    let cisco_tasks: Vec<cisco::CiscoTask> = cisco::TASKS
        .iter()
        .filter(|t| matches!(t.name, "XO" | "XC" | "XB" | "XA-arm64"))
        .copied()
        .collect();
    eprintln!("\n--- Cisco Talos Dataset-1 ---");
    for lane in lanes {
        for (label, settings) in &presets {
            let report = rerank::evaluate_cisco(
                &StructuralScheme::default(),
                cisco_corpus,
                &cisco_tasks,
                settings,
                label,
                lane,
            );
            eprintln!(
                "\n=== rerank: {} / {} / {} lane -- {} ({}) ===",
                report.scheme,
                report.settings_label,
                report.lane.label(),
                report.corpus_name,
                report.profile
            );
            for comparison in &report.comparisons {
                eprintln!("{}", comparison.line());
            }
            report.write_json(&metrics::report_dir());
        }
    }
}
