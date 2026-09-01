//! `src/similarity/` against labeled ground truth from the fixture matrix.
//!
//! # Why this file exists
//!
//! The similarity module shipped with two tests: one asserting a digest starts
//! with `"8:4:"`, one asserting the score is symmetric and lies in `[0, 1]`.
//! Both of those pass for a function that returns a constant. Nothing in the
//! tree asked whether the digest can tell two pieces of code apart, so the
//! component was **unfalsifiable** -- it could have been broken for its whole
//! life and every test would still have been green.
//!
//! # Where the labels come from
//!
//! `tests/decompiler_fixtures/build/` holds the same 206 C sources compiled by
//! two compilers at two optimisation levels, symbol tables intact. That makes
//! `(fixture, function name)` a free and exact label:
//!
//! * **Positive pair** -- `bisect` in `13_loop_early_exit-gcc-O0.so` and
//!   `bisect` in `13_loop_early_exit-gcc-O2.so`. Same semantics, different
//!   bytes: different register allocation, different instruction selection,
//!   unrolled loops, inlined callees.
//! * **Negative pair** -- two *different* functions. The negative test below
//!   samples them **size-matched**, so "the answer is whichever candidate is
//!   closest in length" is not a winning strategy.
//!
//! # The framing is retrieval, not thresholding
//!
//! A raw score has no natural cut-off, and any single threshold invented here
//! would be a number to argue about. Ranking has none of that problem: for
//! each -O0 function we rank -O2 candidates and ask whether the true match
//! came first. That is the question an analyst actually asks ("what is this
//! function"), it needs no tuning constant, and the chance baseline falls
//! straight out of the pool size.
//!
//! # The numbers below were MEASURED, and they are bad
//!
//! Every constant in this file was read off a run before it was written down.
//! At the sizes a function body has, CTPH is barely above chance -- see the
//! per-constant notes. A low pinned number that can only be tightened is the
//! deliverable here; a comfortable number that was guessed would not be.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use glaurung::similarity::{ctph_hash, ctph_similarity, CtphConfig};
use object::{Object, ObjectSection, ObjectSymbol, SymbolKind};

// ---------------------------------------------------------------------------
// Measured ratchets.
//
// All four were produced by one run of this file against the 206-fixture
// corpus (1,097 gcc -O0 functions, 1,096 gcc -O2) on 2026-08-31, using
// `CtphConfig::default()` -- which is also what
// `ctph_recommended_params(len)` returns for anything under 16 KiB, i.e. the
// configuration every function-sized input actually gets.
//
// A sweep over ten other `(window, digest, precision)` triples was run at the
// same time and did NOT rescue the numbers: the best global-pool top-1 any
// configuration reached was ~1.8% (`window=4, digest=2`), and the best
// same-binary top-1 was ~25.6%. The failure is the algorithm at this input
// size, not the parameters, so the ratchets are pinned at the shipped
// configuration rather than at a tuned one.
// ---------------------------------------------------------------------------

/// Top-1 accuracy retrieving a gcc -O0 function among ALL gcc -O2 functions.
///
/// **Measured: 3/924 = 0.32%.** Chance, with 1,096 candidates, is 0.09%. So
/// the digest is doing something -- about three and a half times chance --
/// and that something is nowhere near usable. Anything in the KB that ranks a
/// whole candidate library by this score is ranking noise.
const MIN_TOP1_GLOBAL_POOL: f64 = 0.0032;

/// Top-1 accuracy when the candidate pool is only the same fixture's -O2
/// build: a mean of 8.3 candidates rather than a thousand.
///
/// **Measured: 181/898 = 20.2%.** Chance at that pool size is 12.0%. Eight
/// percentage points of signal over chance, on the easiest version of the
/// task there is.
const MIN_TOP1_SAME_BINARY: f64 = 0.2015;

/// Top-1 accuracy retrieving a gcc -O2 function among the same fixture's
/// clang -O2 functions. Cross-compiler, same optimisation level.
///
/// **Measured: 181/875 = 20.7%**, chance 12.8%. Note what this says: swapping
/// compilers costs the digest *nothing* relative to swapping optimisation
/// levels (20.2%). Both tiers land in the same place because the score is
/// carrying so little information that neither transformation makes it worse.
const MIN_TOP1_CROSS_COMPILER: f64 = 0.2068;

/// How far the mean positive-pair score must sit above the mean size-matched
/// negative-pair score.
///
/// **Measured: 0.0027 positive against 0.0007 negative, separation 0.0020.**
/// Both means are within a rounding error of zero: at function granularity
/// two digests essentially never share a block, whether or not they are the
/// same function. The separation is real and positive, which is the only
/// reason this file can assert anything at all about scores.
const MIN_POSITIVE_NEGATIVE_SEPARATION: f64 = 0.0019;

/// Fraction of functions whose digest is shared with a function that has
/// **different bytes** -- a true collision, not two copies of one helper.
///
/// Every such pair is a function the engine can never retrieve correctly, so
/// this is a hard ceiling rather than a statistical one.
const MAX_DIGEST_COLLISION_RATE: f64 = 0.0;

/// How far above its floor a measurement may drift before this file demands
/// the floor be raised.
///
/// A ratchet that has silently fallen two percentage points behind reality has
/// stopped reporting regressions, which is the failure mode these constants
/// exist to prevent.
const RATCHET_SLACK: f64 = 0.02;

// ---------------------------------------------------------------------------

fn build_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("decompiler_fixtures")
        .join("build")
}

/// One labeled function: its bytes, and the label they are known by.
#[derive(Clone)]
struct Func {
    /// Fixture stem, e.g. `13_loop_early_exit`. Half of the ground-truth key.
    fixture: String,
    /// Symbol name, e.g. `bisect`. The other half.
    name: String,
    bytes: Vec<u8>,
    digest: String,
}

impl Func {
    fn label(&self) -> (&str, &str) {
        (&self.fixture, &self.name)
    }
    fn size(&self) -> usize {
        self.bytes.len()
    }
}

/// Extract every sized, named text symbol from one object file.
///
/// Zero-sized symbols are the CRT boilerplate (`_init`, `frame_dummy`,
/// `register_tm_clones`); they carry no extent, so there is nothing to hash.
/// Symbols appear in both `.symtab` and `.dynsym`, hence the dedupe by name.
fn functions_of(path: &Path, fixture: &str, cfg: &CtphConfig) -> Vec<Func> {
    let Ok(data) = std::fs::read(path) else {
        return Vec::new();
    };
    let Ok(obj) = object::File::parse(&*data) else {
        return Vec::new();
    };
    let mut seen: BTreeMap<String, Func> = BTreeMap::new();
    for sym in obj.symbols() {
        if sym.kind() != SymbolKind::Text || sym.size() == 0 {
            continue;
        }
        let Ok(name) = sym.name() else { continue };
        if name.is_empty() || seen.contains_key(name) {
            continue;
        }
        let Some(index) = sym.section_index() else {
            continue;
        };
        let Ok(section) = obj.section_by_index(index) else {
            continue;
        };
        let Ok(Some(bytes)) = section.data_range(sym.address(), sym.size()) else {
            continue;
        };
        seen.insert(
            name.to_string(),
            Func {
                fixture: fixture.to_string(),
                name: name.to_string(),
                bytes: bytes.to_vec(),
                digest: ctph_hash(bytes, cfg),
            },
        );
    }
    seen.into_values().collect()
}

/// Load one `(compiler, opt-level)` slice of the fixture matrix, sorted.
///
/// The sort is load-bearing, not cosmetic. Most pairs in this corpus score
/// exactly 0.0, so the ranking is a sea of ties, and `read_dir` order varies
/// between machines and runs. Without a total order on the pool the measured
/// accuracy would wander and the ratchets below would be flaky rather than
/// wrong -- much harder to diagnose.
///
/// Returns `None` when `tests/decompiler_fixtures/build/` has not been
/// populated. That directory is gitignored and produced by the fixture
/// harness, so a fresh checkout legitimately has no corpus -- but the caller
/// must SAY so rather than silently reporting a vacuous pass.
fn load_slice(compiler: &str, opt: &str, cfg: &CtphConfig) -> Option<Vec<Func>> {
    let dir = build_dir();
    let suffix = format!("-{compiler}-{opt}.so");
    let mut out = Vec::new();
    for entry in std::fs::read_dir(&dir).ok()? {
        let Ok(entry) = entry else { continue };
        let file_name = entry.file_name();
        let file_name = file_name.to_string_lossy();
        let Some(fixture) = file_name.strip_suffix(&suffix) else {
            continue;
        };
        out.extend(functions_of(&entry.path(), fixture, cfg));
    }
    out.sort_by(|a, b| (&a.fixture, &a.name).cmp(&(&b.fixture, &b.name)));
    (!out.is_empty()).then_some(out)
}

/// Load a query slice and a candidate slice, or explain the skip.
fn load_pair(q: (&str, &str), c: (&str, &str)) -> Option<(Vec<Func>, Vec<Func>)> {
    let cfg = CtphConfig::default();
    match (load_slice(q.0, q.1, &cfg), load_slice(c.0, c.1, &cfg)) {
        (Some(a), Some(b)) => Some((a, b)),
        _ => {
            eprintln!(
                "SKIP: {} is empty or absent. It is gitignored and built by \
                 the fixture harness; see docs/development/decompiler-testing.md.",
                build_dir().display()
            );
            None
        }
    }
}

/// Rank `candidates` for `query` and return the best-scoring one.
///
/// Ties keep the FIRST candidate, and the pools are sorted, so a digest that
/// scores everything 0.0 always answers with the alphabetically first
/// candidate. That is the pessimistic choice on purpose: a degenerate
/// implementation lands at chance rather than accidentally well.
fn top1<'a>(query: &Func, candidates: &[&'a Func]) -> Option<&'a Func> {
    let mut best: Option<(&Func, f64)> = None;
    for cand in candidates {
        let score = ctph_similarity(&query.digest, &cand.digest);
        match best {
            Some((_, b)) if score <= b => {}
            _ => best = Some((cand, score)),
        }
    }
    best.map(|(f, _)| f)
}

/// Assert a measured accuracy against its floor, in both directions.
fn assert_ratchet(
    what: &str,
    hits: usize,
    scored: usize,
    chance: f64,
    floor: f64,
    misses: &[String],
) {
    let accuracy = hits as f64 / scored as f64;
    let line = format!(
        "{what}: {hits}/{scored} = {accuracy:.4} top-1 (chance {chance:.4}, \
         ratchet {floor:.4})"
    );
    eprintln!("{line}");
    assert!(
        accuracy >= floor,
        "{line}\nRETRIEVAL REGRESSION. Examples of what was retrieved \
         instead of the true twin:\n{}",
        misses.join("\n")
    );
    assert!(
        accuracy <= floor + RATCHET_SLACK,
        "{line}\nThat is more than {RATCHET_SLACK:.2} above the ratchet -- \
         good news. Raise the constant in tests/similarity_retrieval.rs to \
         {accuracy:.4} in the same commit, or the improvement is unprotected."
    );
}

/// Retrieval across optimisation levels, with the whole corpus as the pool.
///
/// The honest, hard version of the task: ~1,100 candidates, so chance is under
/// a tenth of a percent and length alone is nearly useless because hundreds of
/// functions in the pool are within a few bytes of each other.
#[test]
fn o0_functions_retrieve_their_o2_twin_from_the_whole_corpus() {
    let Some((queries, pool)) = load_pair(("gcc", "O0"), ("gcc", "O2")) else {
        return;
    };
    assert!(
        queries.len() >= 200 && pool.len() >= 200,
        "corpus too small to measure retrieval: {} queries against {} \
         candidates. Expected roughly 1,100 of each from 206 fixtures.",
        queries.len(),
        pool.len()
    );

    let truth: BTreeSet<(&str, &str)> = pool.iter().map(Func::label).collect();
    let all: Vec<&Func> = pool.iter().collect();
    let mut hits = 0usize;
    let mut scored = 0usize;
    let mut misses: Vec<String> = Vec::new();
    for q in &queries {
        // Only score queries whose twin is present. A function -O2 inlined
        // away has no right answer, and counting it as a miss would measure
        // the compiler rather than us.
        if !truth.contains(&q.label()) {
            continue;
        }
        scored += 1;
        match top1(q, &all) {
            Some(best) if best.label() == q.label() => hits += 1,
            Some(best) => {
                if misses.len() < 10 {
                    misses.push(format!(
                        "  {}::{} ({} bytes) -> {}::{} ({} bytes)",
                        q.fixture,
                        q.name,
                        q.size(),
                        best.fixture,
                        best.name,
                        best.size()
                    ));
                }
            }
            None => {}
        }
    }

    assert!(
        scored >= 200,
        "only {scored} of {} queries had a twin in the -O2 pool; the label \
         join is broken, not the similarity engine",
        queries.len()
    );
    assert_ratchet(
        "gcc O0 -> gcc O2, global pool",
        hits,
        scored,
        1.0 / pool.len() as f64,
        MIN_TOP1_GLOBAL_POOL,
        &misses,
    );
}

/// The same question with a realistically small pool: rank only the functions
/// in the matching binary's own -O2 build.
///
/// This is the shape of query the KB actually issues when it has a candidate
/// library and wants to name one function, and the tier where a usable score
/// is at least plausible.
#[test]
fn o0_functions_retrieve_their_o2_twin_within_one_binary() {
    let Some((queries, pool)) = load_pair(("gcc", "O0"), ("gcc", "O2")) else {
        return;
    };
    let (hits, scored, mean_pool, misses) = same_binary_retrieval(&queries, &pool);
    eprintln!("[mean same-binary pool {mean_pool:.1}]");
    assert_ratchet(
        "gcc O0 -> gcc O2, same-binary pool",
        hits,
        scored,
        1.0 / mean_pool,
        MIN_TOP1_SAME_BINARY,
        &misses,
    );
}

/// Cross-compiler retrieval at a fixed optimisation level.
///
/// gcc and clang agree on what the function must compute and on nothing else:
/// different instruction selection, different register allocation, different
/// idioms for the same loop. A byte-structure digest has the least to work
/// with here, which is exactly why the tier is worth pinning separately --
/// a change that helps the same-compiler case can quietly destroy this one.
#[test]
fn cross_compiler_retrieval_within_one_binary() {
    let Some((queries, pool)) = load_pair(("gcc", "O2"), ("clang", "O2")) else {
        return;
    };
    let (hits, scored, mean_pool, misses) = same_binary_retrieval(&queries, &pool);
    eprintln!("[mean same-binary pool {mean_pool:.1}]");
    assert_ratchet(
        "gcc O2 -> clang O2, same-binary pool",
        hits,
        scored,
        1.0 / mean_pool,
        MIN_TOP1_CROSS_COMPILER,
        &misses,
    );
}

/// Shared driver for the two same-binary tiers.
///
/// Returns `(hits, scored, mean pool size, example misses)`.
fn same_binary_retrieval(queries: &[Func], pool: &[Func]) -> (usize, usize, f64, Vec<String>) {
    let mut by_fixture: BTreeMap<&str, Vec<&Func>> = BTreeMap::new();
    for f in pool {
        by_fixture.entry(f.fixture.as_str()).or_default().push(f);
    }

    let mut hits = 0usize;
    let mut scored = 0usize;
    let mut pool_sizes = 0usize;
    let mut misses: Vec<String> = Vec::new();
    for q in queries {
        let Some(candidates) = by_fixture.get(q.fixture.as_str()) else {
            continue;
        };
        // A pool of one is not a retrieval task; it is a tautology. And a
        // query whose twin is absent has no right answer.
        if candidates.len() < 2 || !candidates.iter().any(|c| c.name == q.name) {
            continue;
        }
        scored += 1;
        pool_sizes += candidates.len();
        match top1(q, candidates) {
            Some(best) if best.name == q.name => hits += 1,
            Some(best) => {
                if misses.len() < 10 {
                    misses.push(format!(
                        "  {}: {} ({} bytes) -> {} ({} bytes), pool of {}",
                        q.fixture,
                        q.name,
                        q.size(),
                        best.name,
                        best.size(),
                        candidates.len()
                    ));
                }
            }
            None => {}
        }
    }

    assert!(
        scored >= 200,
        "only {scored} same-binary retrieval tasks were constructed from {} \
         queries and {} candidates; expected roughly a thousand. The label \
         join is broken, not the similarity engine.",
        queries.len(),
        pool.len()
    );
    let mean_pool = pool_sizes as f64 / scored as f64;
    (hits, scored, mean_pool, misses)
}

/// Positive pairs must, on average, score above **size-matched** negatives.
///
/// Size matching is the whole point. Without it a digest that encoded nothing
/// but length would look like a working similarity engine, because a 400-byte
/// function really is more likely to be the twin of another 400-byte function.
/// Every negative sampled here is within 10% of its positive's length, so the
/// separation this test measures cannot be explained by size.
#[test]
fn positive_pairs_outscore_size_matched_negatives() {
    let Some((o0, o2)) = load_pair(("gcc", "O0"), ("gcc", "O2")) else {
        return;
    };
    let by_label: BTreeMap<(&str, &str), &Func> = o2.iter().map(|f| (f.label(), f)).collect();

    let mut positives: Vec<f64> = Vec::new();
    let mut negatives: Vec<f64> = Vec::new();
    for q in &o0 {
        let Some(twin) = by_label.get(&q.label()) else {
            continue;
        };
        positives.push(ctph_similarity(&q.digest, &twin.digest));

        // The size-matched negative: the -O2 function closest in length to the
        // true twin that is NOT the true twin. Deterministic over the sorted
        // pool, so a failure here is reproducible without a seed.
        let target = twin.size() as i64;
        let mut best: Option<(&Func, i64)> = None;
        for cand in &o2 {
            if cand.label() == q.label() {
                continue;
            }
            let delta = (cand.size() as i64 - target).abs();
            if best.is_none_or(|(_, d)| delta < d) {
                best = Some((cand, delta));
            }
        }
        if let Some((neg, delta)) = best {
            // Keep it only if it really is size matched; a fixture whose twin
            // has a unique length would otherwise smuggle in an easy negative.
            if delta * 10 <= target.max(1) {
                negatives.push(ctph_similarity(&q.digest, &neg.digest));
            }
        }
    }

    assert!(
        positives.len() >= 200 && negatives.len() >= 200,
        "not enough labeled pairs: {} positive, {} size-matched negative",
        positives.len(),
        negatives.len()
    );

    let mean = |v: &[f64]| v.iter().sum::<f64>() / v.len() as f64;
    let pos = mean(&positives);
    let neg = mean(&negatives);
    let separation = pos - neg;
    eprintln!(
        "positive mean {pos:.4} (n={}), size-matched negative mean {neg:.4} \
         (n={}), separation {separation:.4} (ratchet \
         {MIN_POSITIVE_NEGATIVE_SEPARATION:.4})",
        positives.len(),
        negatives.len()
    );
    assert!(
        separation >= MIN_POSITIVE_NEGATIVE_SEPARATION,
        "same-function pairs scored {pos:.4} on average and size-matched \
         different-function pairs scored {neg:.4}: separation {separation:.4}, \
         ratchet {MIN_POSITIVE_NEGATIVE_SEPARATION:.4}. A separation at or \
         below zero would mean the digest carries no signal about what the \
         code DOES, and anything ranking by it is ranking noise."
    );
    assert!(
        separation <= MIN_POSITIVE_NEGATIVE_SEPARATION + RATCHET_SLACK,
        "separation improved to {separation:.4}; raise \
         MIN_POSITIVE_NEGATIVE_SEPARATION in the same commit."
    );
}

/// A digest must recognise a function as itself, and must not equate two
/// functions whose bytes differ.
///
/// The cheapest sanity property in the file, and the one that would catch a
/// truncating or constant-folding regression in `ctph_hash` before any of the
/// statistical tests above got a chance to drift.
///
/// Note the collision definition: two *different* fixtures often contain a
/// byte-identical helper, and those legitimately share a digest. Only pairs
/// whose BYTES differ are counted, which is what makes a non-zero rate a
/// genuine defect rather than a property of the corpus.
#[test]
fn identical_bytes_score_one_and_distinct_functions_do_not() {
    let cfg = CtphConfig::default();
    let Some(funcs) = load_slice("gcc", "O0", &cfg) else {
        eprintln!("SKIP: {} is empty or absent.", build_dir().display());
        return;
    };
    assert!(funcs.len() >= 200, "corpus too small: {}", funcs.len());

    for f in &funcs {
        let s = ctph_similarity(&f.digest, &f.digest);
        assert!(
            (s - 1.0).abs() < 1e-9,
            "{}::{} does not match itself: {s}",
            f.fixture,
            f.name
        );
    }

    let mut first_seen: BTreeMap<&str, &Func> = BTreeMap::new();
    let mut collisions: Vec<String> = Vec::new();
    for f in &funcs {
        match first_seen.get(f.digest.as_str()) {
            Some(other) if other.bytes != f.bytes => collisions.push(format!(
                "  {}::{} ({} bytes) == {}::{} ({} bytes) -> {}",
                f.fixture,
                f.name,
                f.size(),
                other.fixture,
                other.name,
                other.size(),
                f.digest
            )),
            Some(_) => {}
            None => {
                first_seen.insert(&f.digest, f);
            }
        }
    }
    let rate = collisions.len() as f64 / funcs.len() as f64;
    eprintln!(
        "digest collisions between functions with DIFFERENT bytes: {}/{} = {rate:.4}",
        collisions.len(),
        funcs.len()
    );
    assert!(
        rate <= MAX_DIGEST_COLLISION_RATE,
        "{} of {} functions share a digest with a function whose bytes differ \
         ({rate:.4}, ratchet {MAX_DIGEST_COLLISION_RATE:.4}). Every one is a \
         function the engine can never retrieve correctly:\n{}",
        collisions.len(),
        funcs.len(),
        collisions
            .iter()
            .take(10)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}
