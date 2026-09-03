//! `src/identity/cfr/` measured against labeled ground truth, and its metric
//! axioms checked on real functions.
//!
//! # Where the labels come from
//!
//! `tests/decompiler_fixtures/build/` holds the same C sources compiled by two
//! compilers at two optimisation levels with symbol tables intact, so
//! `(fixture, function name)` is a free and exact label. A **positive pair** is
//! `bisect` in `13_loop_early_exit-gcc-O0.so` and `bisect` in
//! `13_loop_early_exit-gcc-O2.so`: same source, different register allocation,
//! different instruction selection, unrolled loops, inlined callees. A
//! **negative pair** is two different functions.
//!
//! The directory is gitignored and produced by the fixture harness, so a fresh
//! checkout legitimately has none of it. Every lane below then prints a SKIP and
//! returns, rather than passing vacuously. Set `GLAURUNG_FIXTURE_BUILD_DIR` to
//! point at a populated one elsewhere.
//!
//! # The protocol, and why the denominators are stated
//!
//! No retrieval number is comparable to anything unless it states the pool size
//! and the set of free compilation variables -- SAFE is published at MRR 0.918
//! and at 0.17 on two protocols. So each lane below names its pool and its free
//! variables, and the ratchets are two-sided: a measurement that drifts far
//! *above* its floor fails too, because a ratchet that has fallen behind reality
//! has stopped reporting regressions.
//!
//! Three published filters exist, and the lanes below differ in how many they
//! apply -- which is stated per lane, because the filter set moves the number
//! more than anything else in this file:
//!
//! * Functions with fewer than [`MIN_BLOCKS`] basic blocks are dropped
//!   everywhere. They carry too little structure for any representation to
//!   retrieve, and they are mostly PLT thunks and CRT boilerplate.
//! * Names are deduplicated within a binary, everywhere.
//! * **Duplicates by name and hash** are dropped in the two size-matched lanes,
//!   which follow the published protocol. This one matters enormously here:
//!   `__do_global_dtors_aux` is the same CRT function in all 206 fixtures, so
//!   it produces 206 byte-identical signatures and asking which one a query
//!   means is a question with no answer. It is a third of the unfiltered query
//!   set. The whole-slice lane deliberately does NOT apply it, so its number
//!   stays comparable with `tests/similarity_retrieval.rs`, which does not
//!   either.
//!
//! # Size matching
//!
//! "Whichever candidate is closest in length" must not be a winning strategy, so
//! the 100 negatives offered against each positive are the candidates *nearest
//! the query in size*. Size here is the LLIR instruction count, not the byte
//! length: that is the quantity the representation actually sees, and it is the
//! harder matching to defeat.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use glaurung::analysis::cfg::Budgets;
use glaurung::identity::cfr::{cosine, distance, signatures_for_path, CfrSettings, CfrSignature};

// ---------------------------------------------------------------------------
// Measured ratchets.
//
// Every constant here was read off a run before it was written down. They are
// unweighted -- `UniformWeights`, no TF-IDF corpus table, which is a later
// lane -- so each is a floor the weighting is expected to raise.
// ---------------------------------------------------------------------------

/// Published filter: functions below this many basic blocks are dropped from
/// both the query set and the pool.
const MIN_BLOCKS: usize = 5;

/// Negatives offered against each positive.
const NEGATIVES: usize = 100;

/// Discovery budgets for a *measurement*, which are not the shipped defaults.
///
/// `Budgets::default()` carries `timeout_ms: 100` -- a wall clock on one
/// function's block walk. On an idle machine no fixture function comes close to
/// it; under a full `cargo test` run with twenty-four test binaries in flight it
/// fires, discovery is truncated for whichever functions lost the race, and the
/// measured Recall@1 moves. That is not a hypothetical: this lane passed alone
/// and failed inside the full suite until the ceiling was lifted here.
///
/// A measurement harness must not carry a wall-clock ceiling at all. The
/// instruction and block ceilings stay, because they are deterministic
/// functions of the input.
fn measurement_budgets() -> Budgets {
    Budgets {
        timeout_ms: u64::MAX,
        total_timeout_ms: 0,
        ..Budgets::default()
    }
}

/// How far above its floor a measurement may drift before this file demands the
/// floor be raised.
const RATCHET_SLACK: f64 = 0.05;

/// Recall@1 retrieving a gcc -O0 function among its true gcc -O2 twin plus 100
/// size-matched negatives. One free variable: the optimisation level.
///
/// **Measured 2026-09-02: 51/341 = 14.96%**, against a 0.99% chance baseline --
/// fifteen times chance. It is the weakest of the three lanes and that is the
/// expected shape: `-O0` to `-O2` changes the *graph*, not only its spelling.
/// Unrolling duplicates a loop body, inlining merges two functions into one,
/// and the mask list can do nothing about either. Inlining is the field's
/// unsolved failure -- roughly 82 to 84 percent of the best tools' failures
/// involve it, and Marcelli's benchmark disables it to sidestep the problem.
const MIN_RECALL_AT_1_CROSS_OPT: f64 = 0.1495;

/// Recall@1 retrieving a gcc -O2 function among its clang -O2 twin plus 100
/// size-matched negatives. One free variable: the compiler.
///
/// **Measured 2026-09-02: 148/309 = 47.90%**, against 0.99% chance. Three times
/// the cross-optimisation number, and the contrast is the whole argument for
/// canonicalising over an IR: gcc and clang at the same optimisation level make
/// the *same program* out of the same source and differ in register allocation,
/// instruction selection and block order -- which is precisely the list the
/// projection erases.
const MIN_RECALL_AT_1_CROSS_COMPILER: f64 = 0.4789;

/// Recall@1 with the WHOLE gcc -O2 slice as the pool and no duplicate filter.
///
/// **Measured 2026-09-02: 44/594 = 7.41%** against a 0.16% chance baseline, on
/// 594 queries and 610 candidates. The comparable number is
/// `tests/similarity_retrieval.rs`'s **0.32%** for CTPH on 924 queries against
/// 1,096 candidates: same corpus, same task, no duplicate filter on either
/// side. Twenty-three times the byte digest, and still nowhere near a tool you
/// would point at a stripped binary unassisted -- which is what the TF-IDF
/// weighting, the rare-feature index and the peephole normaliser are for.
const MIN_RECALL_AT_1_GLOBAL_POOL: f64 = 0.0740;

/// Fraction of gcc -O0 functions whose canonical form is *byte-identical* to
/// their gcc -O2 twin's, after duplicates are dropped.
///
/// **Measured 2026-09-02: 2/341 = 0.59%.** This is identity-on-the-quotient
/// measured rather than asserted, and the number is deliberately recorded even
/// though it is tiny: it says the quotient almost never erases an entire
/// optimisation level, so the cosine is doing the work and the exact-digest
/// lookup is a `-O0`-to-`-O0` tool.
///
/// Before duplicates were dropped this lane read 208/594 = 35%, and every one
/// of those 206 extra hits was the same piece of CRT boilerplate. That gap is
/// the clearest illustration in this file of why the filter set has to be
/// stated with the number.
const MIN_EXACT_QUOTIENT_MATCH: f64 = 0.0058;

/// Highest acceptable rate of SSA values left without a derived width.
///
/// **Measured 2026-09-02: 8,033 of 362,980 = 2.21%** over the gcc -O0 slice.
/// The residue is dominated by bare constant materialisations, whose width is
/// genuinely undetermined until something consumes them, and by values feeding
/// only unlifted instructions.
const MAX_WIDTH_UNKNOWN_RATE: f64 = 0.0225;

// ---------------------------------------------------------------------------

fn build_dir() -> PathBuf {
    // The corpus is gitignored, so a worktree that did not build it can be
    // pointed at one that did.
    if let Ok(directory) = std::env::var("GLAURUNG_FIXTURE_BUILD_DIR") {
        return PathBuf::from(directory);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("decompiler_fixtures")
        .join("build")
}

/// One labeled function and its canonical representation.
#[derive(Clone)]
struct Func {
    fixture: String,
    name: String,
    /// LLIR instructions, the size the representation sees.
    size: usize,
    blocks: usize,
    signature: CfrSignature,
}

impl Func {
    fn label(&self) -> (&str, &str) {
        (&self.fixture, &self.name)
    }
}

/// Width-inference diagnostics accumulated while loading a slice.
#[derive(Default, Clone, Copy)]
struct Census {
    total: usize,
    unknown: usize,
}

/// Load one `(compiler, opt-level)` slice, sorted by label.
///
/// The sort is load-bearing rather than cosmetic: `read_dir` order varies
/// between machines, and a total order on the pool is what keeps a tie from
/// making the measured accuracy wander.
fn load_slice(compiler: &str, opt: &str, settings: CfrSettings) -> Option<(Vec<Func>, Census)> {
    let directory = build_dir();
    let suffix = format!("-{compiler}-{opt}.so");
    let budgets = measurement_budgets();
    let mut out: Vec<Func> = Vec::new();
    let mut census = Census::default();

    let mut paths: Vec<(String, PathBuf)> = Vec::new();
    for entry in std::fs::read_dir(&directory).ok()? {
        let Ok(entry) = entry else { continue };
        let file_name = entry.file_name();
        let file_name = file_name.to_string_lossy();
        let Some(fixture) = file_name.strip_suffix(&suffix) else {
            continue;
        };
        paths.push((fixture.to_string(), entry.path()));
    }
    paths.sort();

    for (fixture, path) in paths {
        let Ok(signatures) = signatures_for_path(&path, settings, &budgets) else {
            continue;
        };
        let mut seen: BTreeSet<String> = BTreeSet::new();
        for entry in signatures {
            census.total += entry.width_census.total;
            census.unknown += entry.width_census.unknown;
            let Some(name) = entry.name.clone() else {
                continue;
            };
            if name.is_empty() || entry.block_count < MIN_BLOCKS || !seen.insert(name.clone()) {
                continue;
            }
            if entry.signature.is_empty() {
                continue;
            }
            out.push(Func {
                fixture: fixture.clone(),
                name,
                size: entry.instruction_count,
                blocks: entry.block_count,
                signature: entry.signature,
            });
        }
    }
    out.sort_by(|a, b| (&a.fixture, &a.name).cmp(&(&b.fixture, &b.name)));
    (!out.is_empty()).then_some((out, census))
}

/// Load a query slice and a candidate slice, or explain the skip.
fn load_pair(
    query: (&str, &str),
    candidate: (&str, &str),
    settings: CfrSettings,
) -> Option<(Vec<Func>, Vec<Func>, Census)> {
    match (
        load_slice(query.0, query.1, settings),
        load_slice(candidate.0, candidate.1, settings),
    ) {
        (Some((a, census)), Some((b, _))) => Some((a, b, census)),
        _ => {
            eprintln!(
                "SKIP: {} is empty or absent. It is gitignored and built by the \
                 fixture harness; see docs/development/decompiler-testing.md, or \
                 set GLAURUNG_FIXTURE_BUILD_DIR.",
                build_dir().display()
            );
            None
        }
    }
}

/// Drop every function whose canonical form is shared with another function in
/// the same slice.
///
/// A repeated digest is not a failure of the representation -- it is CRT
/// boilerplate that genuinely is the same function in every fixture -- but a
/// retrieval question with 206 identical correct answers has no answer, and
/// leaving them in measures the corpus's composition rather than the matcher.
fn drop_corpus_duplicates(functions: Vec<Func>) -> (Vec<Func>, usize) {
    let mut counts: BTreeMap<[u8; 32], usize> = BTreeMap::new();
    for function in &functions {
        *counts.entry(function.signature.digest).or_insert(0) += 1;
    }
    let before = functions.len();
    let kept: Vec<Func> = functions
        .into_iter()
        .filter(|function| counts[&function.signature.digest] == 1)
        .collect();
    let dropped = before - kept.len();
    (kept, dropped)
}

/// The `NEGATIVES` candidates nearest `query` in size, excluding its own label.
fn size_matched_negatives<'a>(query: &Func, pool: &'a [Func]) -> Vec<&'a Func> {
    let mut ranked: Vec<&Func> = pool
        .iter()
        .filter(|candidate| candidate.label() != query.label())
        .collect();
    ranked.sort_by(|a, b| {
        let left = a.size.abs_diff(query.size);
        let right = b.size.abs_diff(query.size);
        left.cmp(&right).then_with(|| a.label().cmp(&b.label()))
    });
    ranked.truncate(NEGATIVES);
    ranked
}

/// Whether the true twin strictly outscores every candidate offered against it.
///
/// A tie is a miss, on purpose: a representation that scores everything equally
/// must land at zero rather than at chance-by-accident.
fn positive_wins(query: &Func, positive: &Func, negatives: &[&Func]) -> bool {
    let target = cosine(&query.signature, &positive.signature, None);
    if target <= 0.0 {
        return false;
    }
    negatives
        .iter()
        .all(|negative| cosine(&query.signature, &negative.signature, None) < target)
}

fn assert_ratchet(what: &str, hits: usize, scored: usize, chance: f64, floor: f64) {
    let accuracy = hits as f64 / scored.max(1) as f64;
    let line = format!(
        "{what}: {hits}/{scored} = {accuracy:.4} Recall@1 (chance {chance:.4}, \
         ratchet {floor:.4})"
    );
    eprintln!("{line}");
    assert!(accuracy >= floor, "{line}\nRETRIEVAL REGRESSION.");
    assert!(
        accuracy <= floor + RATCHET_SLACK,
        "{line}\nThat is more than {RATCHET_SLACK:.2} above the ratchet -- good \
         news. Raise the constant in tests/identity_cfr_retrieval.rs to \
         {accuracy:.4} in the same commit, or the improvement is unprotected."
    );
}

/// Cross-optimisation retrieval: gcc -O0 against gcc -O2, 100 size-matched
/// negatives per positive. One free compilation variable.
#[test]
fn o0_functions_retrieve_their_o2_twin_against_size_matched_negatives() {
    let Some((queries, pool, _)) = load_pair(("gcc", "O0"), ("gcc", "O2"), CfrSettings::default())
    else {
        return;
    };
    let (queries, dropped_queries) = drop_corpus_duplicates(queries);
    let (pool, dropped_pool) = drop_corpus_duplicates(pool);
    let by_label: BTreeMap<(&str, &str), &Func> =
        pool.iter().map(|func| (func.label(), func)).collect();
    let (mut hits, mut scored) = (0usize, 0usize);
    for query in &queries {
        let Some(positive) = by_label.get(&query.label()) else {
            continue;
        };
        let negatives = size_matched_negatives(query, &pool);
        if negatives.len() < NEGATIVES {
            continue;
        }
        scored += 1;
        if positive_wins(query, positive, &negatives) {
            hits += 1;
        }
    }
    eprintln!(
        "pool: {} gcc -O0 queries ({dropped_queries} duplicates dropped), {} gcc \
         -O2 candidates ({dropped_pool} dropped), {} blocks minimum",
        queries.len(),
        pool.len(),
        MIN_BLOCKS
    );
    assert_ratchet(
        "XO gcc -O0 -> gcc -O2, 1 + 100 candidates",
        hits,
        scored,
        1.0 / (NEGATIVES + 1) as f64,
        MIN_RECALL_AT_1_CROSS_OPT,
    );
}

/// Cross-compiler retrieval: gcc -O2 against clang -O2, same optimisation
/// level. One free compilation variable.
#[test]
fn gcc_functions_retrieve_their_clang_twin_against_size_matched_negatives() {
    let Some((queries, pool, _)) =
        load_pair(("gcc", "O2"), ("clang", "O2"), CfrSettings::default())
    else {
        return;
    };
    let (queries, dropped_queries) = drop_corpus_duplicates(queries);
    let (pool, dropped_pool) = drop_corpus_duplicates(pool);
    let by_label: BTreeMap<(&str, &str), &Func> =
        pool.iter().map(|func| (func.label(), func)).collect();
    let (mut hits, mut scored) = (0usize, 0usize);
    for query in &queries {
        let Some(positive) = by_label.get(&query.label()) else {
            continue;
        };
        let negatives = size_matched_negatives(query, &pool);
        if negatives.len() < NEGATIVES {
            continue;
        }
        scored += 1;
        if positive_wins(query, positive, &negatives) {
            hits += 1;
        }
    }
    eprintln!(
        "pool: {} gcc -O2 queries ({dropped_queries} duplicates dropped), {} \
         clang -O2 candidates ({dropped_pool} dropped), {} blocks minimum",
        queries.len(),
        pool.len(),
        MIN_BLOCKS
    );
    assert_ratchet(
        "XC gcc -O2 -> clang -O2, 1 + 100 candidates",
        hits,
        scored,
        1.0 / (NEGATIVES + 1) as f64,
        MIN_RECALL_AT_1_CROSS_COMPILER,
    );
}

/// The hard version: the whole gcc -O2 slice is the pool. This is the number
/// directly comparable to `tests/similarity_retrieval.rs`, which measured CTPH
/// at 0.0032 on the same task with an unfiltered pool.
#[test]
fn o0_functions_retrieve_their_o2_twin_from_the_whole_slice() {
    let Some((queries, pool, _)) = load_pair(("gcc", "O0"), ("gcc", "O2"), CfrSettings::default())
    else {
        return;
    };
    let by_label: BTreeMap<(&str, &str), &Func> =
        pool.iter().map(|func| (func.label(), func)).collect();
    let all: Vec<&Func> = pool.iter().collect();
    let (mut hits, mut scored) = (0usize, 0usize);
    let mut misses: Vec<String> = Vec::new();
    for query in &queries {
        let Some(positive) = by_label.get(&query.label()) else {
            continue;
        };
        scored += 1;
        let negatives: Vec<&Func> = all
            .iter()
            .copied()
            .filter(|candidate| candidate.label() != query.label())
            .collect();
        if positive_wins(query, positive, &negatives) {
            hits += 1;
        } else if misses.len() < 5 {
            misses.push(format!("  {}::{}", query.fixture, query.name));
        }
    }
    eprintln!(
        "pool: {} gcc -O0 queries, {} gcc -O2 candidates; first misses:\n{}",
        queries.len(),
        pool.len(),
        misses.join("\n")
    );
    assert_ratchet(
        "XO gcc -O0 -> gcc -O2, whole slice",
        hits,
        scored,
        1.0 / pool.len().max(1) as f64,
        MIN_RECALL_AT_1_GLOBAL_POOL,
    );
}

/// The width-inference `Unknown` rate over the corpus.
///
/// This is the diagnostic the pass exists to make measurable: a width it could
/// not derive is a node whose only label content is the operation.
#[test]
fn width_inference_resolves_most_of_the_corpus() {
    let Some((_, _, census)) = load_pair(("gcc", "O0"), ("gcc", "O2"), CfrSettings::default())
    else {
        return;
    };
    let rate = census.unknown as f64 / census.total.max(1) as f64;
    eprintln!(
        "width inference: {}/{} SSA values unresolved = {rate:.4} over the gcc \
         -O0 slice",
        census.unknown, census.total
    );
    assert!(
        rate <= MAX_WIDTH_UNKNOWN_RATE,
        "width inference resolved less of the corpus than the ratchet allows: \
         {rate:.4} > {MAX_WIDTH_UNKNOWN_RATE:.4}"
    );
}

/// The metric axioms, on real functions rather than constructed vectors.
///
/// Symmetry and identity are checked over every sampled pair; the triangle
/// inequality over sampled triples. The sampling is a fixed-seed linear
/// congruential generator, not `rand`, so the same triples are checked on every
/// machine and a failure is reproducible from the printed indices alone.
#[test]
fn the_induced_distance_satisfies_the_metric_axioms_on_real_functions() {
    check_metric_axioms(CfrSettings::default(), "unnormalised");
}

/// The same axioms with the peephole normaliser on.
///
/// The normaliser is unsound *as semantics*; it must not be unsound *as a
/// metric*. It changes which features a function has and nothing about how two
/// feature multisets are compared, so symmetry, identity on the quotient and
/// the triangle inequality have to survive it exactly -- and a lane whose
/// distance stopped being a metric would stop being indexable, which is the
/// whole reason the CFR is a Weisfeiler-Lehman kernel rather than a graph edit
/// distance.
#[test]
fn the_induced_distance_still_satisfies_the_metric_axioms_when_normalised() {
    check_metric_axioms(normalized(), "normalised");
}

fn check_metric_axioms(settings: CfrSettings, label: &str) {
    let Some((left, right, _)) = load_pair(("gcc", "O0"), ("gcc", "O2"), settings) else {
        return;
    };
    let mut population: Vec<&Func> = left.iter().chain(right.iter()).collect();
    population.sort_by_key(|func| (func.fixture.clone(), func.name.clone(), func.blocks));
    assert!(
        population.len() >= 50,
        "corpus too small to sample triples: {} functions",
        population.len()
    );

    // Numerical Recipes' LCG; deterministic across platforms, and adequate for
    // picking indices.
    let mut state: u64 = 0x0123_4567_89ab_cdef;
    let mut next = |bound: usize| -> usize {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        ((state >> 33) as usize) % bound
    };

    let mut checked = 0usize;
    for _ in 0..5_000 {
        let (i, j, k) = (
            next(population.len()),
            next(population.len()),
            next(population.len()),
        );
        let (a, b, c) = (population[i], population[j], population[k]);
        let ab = distance(&a.signature, &b.signature, None);
        let ba = distance(&b.signature, &a.signature, None);
        assert!(
            (ab - ba).abs() < 1e-9,
            "symmetry failed at ({i}, {j}): {ab} vs {ba}"
        );
        assert!(ab >= 0.0, "negative distance at ({i}, {j}): {ab}");
        assert!(
            distance(&a.signature, &a.signature, None) < 1e-9,
            "identity failed at {i}"
        );
        let ac = distance(&a.signature, &c.signature, None);
        let bc = distance(&b.signature, &c.signature, None);
        assert!(
            ac <= ab + bc + 1e-6,
            "triangle inequality failed at ({i}, {j}, {k}): \
             d(a,c)={ac} > d(a,b)+d(b,c)={}",
            ab + bc
        );
        checked += 1;
    }
    eprintln!(
        "metric axioms ({label}): {checked} triples over {} real functions",
        population.len()
    );
}

/// Two spellings of one function land at distance zero when the canonical form
/// erases everything that differs -- and the corpus says how often that happens.
///
/// This is the identity-on-the-quotient axiom measured rather than asserted: it
/// reports the exact-match rate across an optimisation level, which is the
/// fraction of the corpus for which the quotient is doing its whole job.
#[test]
fn some_o0_functions_are_bit_identical_to_their_o2_twin_under_the_quotient() {
    let Some((queries, pool, _)) = load_pair(("gcc", "O0"), ("gcc", "O2"), CfrSettings::default())
    else {
        return;
    };
    let (queries, _) = drop_corpus_duplicates(queries);
    let (pool, _) = drop_corpus_duplicates(pool);
    let by_label: BTreeMap<(&str, &str), &Func> =
        pool.iter().map(|func| (func.label(), func)).collect();
    let (mut identical, mut scored) = (0usize, 0usize);
    for query in &queries {
        let Some(positive) = by_label.get(&query.label()) else {
            continue;
        };
        scored += 1;
        if query.signature.digest == positive.signature.digest {
            identical += 1;
        }
    }
    let rate = identical as f64 / scored.max(1) as f64;
    eprintln!("exact quotient match across -O0/-O2: {identical}/{scored} = {rate:.4}");
    assert!(
        rate >= MIN_EXACT_QUOTIENT_MATCH,
        "the quotient erases the -O0/-O2 difference for {rate:.4} of the corpus, \
         below the {MIN_EXACT_QUOTIENT_MATCH:.4} ratchet"
    );
    assert!(
        rate <= MIN_EXACT_QUOTIENT_MATCH + RATCHET_SLACK,
        "{rate:.4} is more than {RATCHET_SLACK:.2} above the ratchet -- raise \
         MIN_EXACT_QUOTIENT_MATCH in the same commit"
    );
}

/// Sanity: the corpus is the one this file thinks it is.
#[test]
fn the_corpus_is_large_enough_to_measure() {
    let Some((functions, _)) = load_slice("gcc", "O0", CfrSettings::default()) else {
        eprintln!("SKIP: {} is empty or absent.", build_dir().display());
        return;
    };
    assert!(
        functions.len() >= 50,
        "only {} gcc -O0 functions of at least {MIN_BLOCKS} blocks; the fixture \
         matrix should yield hundreds",
        functions.len()
    );
}

/// Guard against a silently unpopulated corpus in CI.
#[allow(dead_code)]
fn corpus_present() -> bool {
    Path::new(&build_dir()).is_dir()
}

// ===========================================================================
// SECTION: the peephole normaliser (plan item 8)
//
// Every lane above, re-run with `CfrSettings::normalize` set, plus the two
// diagnostics the plan asks for: how much of the corpus the normaliser moves
// at all, and what each pass is worth on its own. The unnormalised numbers are
// the floors directly above, measured on the same corpus, in the same process,
// under the same filters -- so the delta is a delta and not two protocols.
// ===========================================================================

/// The settings the normalised lanes measure under.
fn normalized() -> CfrSettings {
    CfrSettings {
        normalize: true,
        ..CfrSettings::default()
    }
}

/// `(hits, scored)` for a size-matched lane.
///
/// This is the body the size-matched tests share, extracted so a normalised
/// lane cannot accidentally become a different protocol from the unnormalised
/// one it is compared against.
fn score_size_matched(queries: &[Func], pool: &[Func]) -> (usize, usize) {
    let by_label: BTreeMap<(&str, &str), &Func> =
        pool.iter().map(|func| (func.label(), func)).collect();
    let (mut hits, mut scored) = (0usize, 0usize);
    for query in queries {
        let Some(positive) = by_label.get(&query.label()) else {
            continue;
        };
        let negatives = size_matched_negatives(query, pool);
        if negatives.len() < NEGATIVES {
            continue;
        }
        scored += 1;
        if positive_wins(query, positive, &negatives) {
            hits += 1;
        }
    }
    (hits, scored)
}

/// `(hits, scored)` with the whole pool slice as the candidate set.
fn score_whole_slice(queries: &[Func], pool: &[Func]) -> (usize, usize) {
    let by_label: BTreeMap<(&str, &str), &Func> =
        pool.iter().map(|func| (func.label(), func)).collect();
    let all: Vec<&Func> = pool.iter().collect();
    let (mut hits, mut scored) = (0usize, 0usize);
    for query in queries {
        let Some(positive) = by_label.get(&query.label()) else {
            continue;
        };
        scored += 1;
        let negatives: Vec<&Func> = all
            .iter()
            .copied()
            .filter(|candidate| candidate.label() != query.label())
            .collect();
        if positive_wins(query, positive, &negatives) {
            hits += 1;
        }
    }
    (hits, scored)
}

/// Load a pair of slices, drop duplicates on both sides, score the size-matched
/// lane. The unit both the normalised lanes and the ablation use.
fn size_matched_lane(
    query: (&str, &str),
    candidate: (&str, &str),
    settings: CfrSettings,
) -> Option<(usize, usize, usize, usize)> {
    let (queries, pool, _) = load_pair(query, candidate, settings)?;
    let (queries, _) = drop_corpus_duplicates(queries);
    let (pool, _) = drop_corpus_duplicates(pool);
    let (hits, scored) = score_size_matched(&queries, &pool);
    Some((hits, scored, queries.len(), pool.len()))
}

// ---------------------------------------------------------------------------
// Measured ratchets under `normalize = true`.
//
// Read off a release run on 2026-09-02 before they were written down, exactly
// as the unnormalised constants above were.
// ---------------------------------------------------------------------------

/// Recall@1, XO gcc -O0 -> gcc -O2, size-matched, **with the normaliser**.
///
/// **Measured 2026-09-02: 60/341 = 17.60%**, against 51/341 = 14.96%
/// unnormalised on the same 341 queries in the same process. That is +2.64
/// percentage points, or a 17.6% relative gain, on the lane the normaliser
/// exists for -- and it is a gain in the *hardest* direction, because `-O0` to
/// `-O2` changes the graph rather than its spelling.
///
/// See `docs/reference/function-identity-cfr.md`, "Normalisation", for the
/// table this sits in and for the per-pass ablation.
const MIN_RECALL_AT_1_CROSS_OPT_NORMALIZED: f64 = 0.1759;

/// Recall@1, XC gcc -O2 -> clang -O2, size-matched, with the normaliser.
///
/// **Measured 2026-09-02: 155/309 = 50.16%**, against 148/309 = 47.90%
/// unnormalised. +2.26 points. Smaller in relative terms than the XO gain,
/// which is the expected shape: the projection already erases most of what
/// separates gcc from clang at one optimisation level, so there is less left
/// for a peephole rewriter to take.
const MIN_RECALL_AT_1_CROSS_COMPILER_NORMALIZED: f64 = 0.5015;

/// Recall@1, XO gcc -O0 -> gcc -O2, whole slice, with the normaliser.
///
/// **Measured 2026-09-02: 51/594 = 8.59%**, against 44/594 = 7.41%
/// unnormalised, on 594 queries and 610 candidates. This is the number
/// comparable with `tests/similarity_retrieval.rs`'s 0.32% for CTPH: the
/// normalised CFR is now twenty-seven times the byte digest rather than
/// twenty-three.
const MIN_RECALL_AT_1_GLOBAL_POOL_NORMALIZED: f64 = 0.0858;

/// Fraction of gcc -O0 functions whose feature multiset the normaliser moves.
///
/// **Measured 2026-09-02: 710/710 = 100.00%.** Cranelift measures 1.13 e-nodes
/// per e-class after rewriting, which the research synthesis reads as "limited
/// algebraic variation to recover" and uses to argue against building an
/// e-graph canonicaliser. That prediction does not transfer: asked of a
/// peephole rewriter over *lifted x86* rather than over a compiler's own SSA,
/// the answer is that every single function of five blocks or more has
/// something to normalise. The reason is that the two are not measuring the
/// same thing -- Cranelift's number is about *algebraic* variation in an IR a
/// compiler front end produced, and most of what fires here is lifter and
/// calling-convention boilerplate: the `lea` expansion's constant seed, the
/// stack round-trip every `-O0` local performs, the width-suffixed intrinsic
/// name. A high changed-form fraction is therefore not the same claim as a
/// high retrieval gain, and the two numbers above are the ones that say what
/// the change is worth.
///
/// The floor is 0.99 rather than 1.0 so that adding one fixture whose only
/// function normalises to itself is a fact rather than a failure.
const MIN_CHANGED_FORM_FRACTION: f64 = 0.99;

#[test]
fn normalized_o0_functions_retrieve_their_o2_twin_against_size_matched_negatives() {
    let Some((hits, scored, queries, pool)) =
        size_matched_lane(("gcc", "O0"), ("gcc", "O2"), normalized())
    else {
        return;
    };
    eprintln!("pool: {queries} gcc -O0 queries, {pool} gcc -O2 candidates, normalised");
    assert_ratchet(
        "XO gcc -O0 -> gcc -O2, 1 + 100 candidates, NORMALISED",
        hits,
        scored,
        1.0 / (NEGATIVES + 1) as f64,
        MIN_RECALL_AT_1_CROSS_OPT_NORMALIZED,
    );
}

#[test]
fn normalized_gcc_functions_retrieve_their_clang_twin_against_size_matched_negatives() {
    let Some((hits, scored, queries, pool)) =
        size_matched_lane(("gcc", "O2"), ("clang", "O2"), normalized())
    else {
        return;
    };
    eprintln!("pool: {queries} gcc -O2 queries, {pool} clang -O2 candidates, normalised");
    assert_ratchet(
        "XC gcc -O2 -> clang -O2, 1 + 100 candidates, NORMALISED",
        hits,
        scored,
        1.0 / (NEGATIVES + 1) as f64,
        MIN_RECALL_AT_1_CROSS_COMPILER_NORMALIZED,
    );
}

#[test]
fn normalized_o0_functions_retrieve_their_o2_twin_from_the_whole_slice() {
    let Some((queries, pool, _)) = load_pair(("gcc", "O0"), ("gcc", "O2"), normalized()) else {
        return;
    };
    let (hits, scored) = score_whole_slice(&queries, &pool);
    eprintln!(
        "pool: {} gcc -O0 queries, {} gcc -O2 candidates, normalised",
        queries.len(),
        pool.len()
    );
    assert_ratchet(
        "XO gcc -O0 -> gcc -O2, whole slice, NORMALISED",
        hits,
        scored,
        1.0 / pool.len().max(1) as f64,
        MIN_RECALL_AT_1_GLOBAL_POOL_NORMALIZED,
    );
}

/// How much of the corpus the normaliser moves at all.
///
/// Compares the **feature multisets**, not the digests: the digest carries the
/// settings word, so a normalised and an unnormalised signature of the same
/// function differ in their digests whether or not a single feature moved.
#[test]
fn the_normaliser_moves_a_measured_fraction_of_the_corpus() {
    let (Some((plain, _)), Some((canonical, _))) = (
        load_slice("gcc", "O0", CfrSettings::default()),
        load_slice("gcc", "O0", normalized()),
    ) else {
        eprintln!("SKIP: {} is empty or absent.", build_dir().display());
        return;
    };
    let by_label: BTreeMap<(&str, &str), &Func> =
        canonical.iter().map(|func| (func.label(), func)).collect();
    let (mut moved, mut compared) = (0usize, 0usize);
    for function in &plain {
        let Some(other) = by_label.get(&function.label()) else {
            continue;
        };
        compared += 1;
        if function.signature.features != other.signature.features {
            moved += 1;
        }
    }
    let fraction = moved as f64 / compared.max(1) as f64;
    eprintln!(
        "normaliser moved the canonical form of {moved}/{compared} = {fraction:.4} of the \
         gcc -O0 slice"
    );
    assert!(
        fraction >= MIN_CHANGED_FORM_FRACTION,
        "the normaliser moved {fraction:.4} of the corpus, below the \
         {MIN_CHANGED_FORM_FRACTION:.4} ratchet -- the passes have stopped firing"
    );
}

/// The per-pass ablation on the cross-optimisation lane, which is the lane the
/// normaliser exists for.
///
/// Fourteen configurations: none, each pass alone, each pass removed from the
/// full set, and the full set. Printed as a table with its denominators; the
/// only assertion is that the "none" row reproduces the unnormalised floor
/// exactly, which is what proves the ablation is measuring the passes rather
/// than the harness.
///
/// `#[ignore]`d because fourteen configurations means fourteen loads of two
/// 206-binary slices -- half a minute in a release build and many minutes in
/// the debug profile `cargo test` uses by default. It is a diagnostic that
/// answers "what is each pass worth", not a ratchet; the ratchets are the three
/// lanes above, and the numbers this printed are in
/// `docs/reference/function-identity-cfr.md`.
#[test]
#[ignore = "14 corpus loads. cargo test --release --features python-ext --test identity_cfr_retrieval -- --ignored --nocapture ablation"]
fn the_per_pass_ablation_on_the_cross_optimisation_lane() {
    use glaurung::identity::cfr::normalize::{with_passes, Passes};

    let Some((baseline_hits, baseline_scored, _, _)) =
        size_matched_lane(("gcc", "O0"), ("gcc", "O2"), CfrSettings::default())
    else {
        return;
    };

    let mut rows: Vec<(String, usize, usize)> = Vec::new();
    let measure = |label: String, passes: Passes, rows: &mut Vec<(String, usize, usize)>| {
        let outcome = with_passes(passes, || {
            size_matched_lane(("gcc", "O0"), ("gcc", "O2"), normalized())
        });
        if let Some((hits, scored, _, _)) = outcome {
            rows.push((label, hits, scored));
        }
    };

    measure("none".to_string(), Passes::NONE, &mut rows);
    for (pass, name) in Passes::ALL {
        measure(format!("only {name}"), pass, &mut rows);
    }
    for (pass, name) in Passes::ALL {
        measure(
            format!("all but {name}"),
            Passes::everything().without(pass),
            &mut rows,
        );
    }
    measure("all".to_string(), Passes::everything(), &mut rows);

    eprintln!(
        "\nXO gcc -O0 -> gcc -O2, 1 + {NEGATIVES} candidates, per-pass ablation\n\
         unnormalised baseline: {baseline_hits}/{baseline_scored} = {:.4}",
        baseline_hits as f64 / baseline_scored.max(1) as f64
    );
    for (label, hits, scored) in &rows {
        eprintln!(
            "  {label:<20} {hits}/{scored} = {:.4}",
            *hits as f64 / (*scored).max(1) as f64
        );
    }

    let (_, none_hits, none_scored) = &rows[0];
    assert_eq!(
        (*none_hits, *none_scored),
        (baseline_hits, baseline_scored),
        "the empty pass set did not reproduce the unnormalised lane, so the \
         ablation is measuring something other than the passes"
    );
}
