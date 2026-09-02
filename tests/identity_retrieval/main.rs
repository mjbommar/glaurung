//! Function-identity retrieval harness: the measurement plan item 1 of
//! `docs/research/program-measures-2026-09-02.md`.
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
//! # The full sweep: every task against the whole corpus, plus the metric
//! # axiom suite over sampled triples. Minutes, not seconds.
//! cargo test --test identity_retrieval -- --ignored --nocapture
//! ```
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

mod corpus;
mod metrics;
mod scheme;
mod tasks;

use corpus::{Corpus, MIN_BASIC_BLOCKS};
use metrics::{SchemeReport, NEGATIVES_PER_POSITIVE};
use scheme::{CtphScheme, Scheme};
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
