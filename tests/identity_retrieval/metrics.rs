//! The scoring driver: AUC, MRR10, Recall@k, a global-pool lane and
//! extraction cost, computed identically for every [`Scheme`].
//!
//! # Every number carries its conditions
//!
//! `docs/history/program-measures-2026-09-02.md`: "No number from this work
//! is comparable to anything unless it states the pool size and the set of
//! free compilation variables. The same tool, SAFE, scores MRR 0.918 and 0.17
//! in two published papers on different protocols." So [`TaskResult`] has no
//! way to be printed or serialised without its pool sizes and its
//! free-variable string; the formatting lives here rather than at the call
//! sites so no caller can drop them.
//!
//! # Ties are resolved pessimistically, and that is a choice
//!
//! A candidate that scores exactly what the true twin scores is counted as
//! ranking AHEAD of it. This is stricter than
//! `tests/similarity_retrieval.rs`, which sorts the pool and keeps the first
//! candidate on a tie: under that rule a scheme that scores every pair 0.0
//! lands at chance, which credits it with luck it does not have. Under the
//! rule here it lands at zero, which is what "this representation cannot
//! separate anything" should look like. The chance line is still printed next
//! to every result so the two can be read together.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::corpus::{Corpus, FunctionSample, Slice};
use crate::scheme::Scheme;
use crate::tasks::{Stratum, Task, UNSUPPORTED_TASKS};

/// Negatives sampled per positive for the ranking metrics.
///
/// Marcelli's protocol: "MRR10 + Recall@1 with 100 negatives per positive".
/// The ranked pool is therefore 101 candidates and chance Recall@1 is 1/101.
pub const NEGATIVES_PER_POSITIVE: usize = 100;

/// Below this many scored queries, a task's numbers are reported but must not
/// be ratcheted or quoted.
///
/// Measured reason: `XM-L` (>100 basic blocks) has **3** scored queries on
/// this corpus. Its Recall@1 can only be 0, 1/3, 2/3 or 1, so it carries about
/// one and a half bits and moves by a third of its range if a single fixture
/// gains a block. A row like that is not a measurement, and printing it
/// without saying so is how a harness manufactures a result.
pub const MIN_SCORED_FOR_A_MEASUREMENT: usize = 30;

/// `k` values for the Recall@k curve.
///
/// Marcelli shows models that tie on AUC diverge sharply on ranking, which is
/// why the curve is reported and not only `@1`. `50` is the last useful rung
/// against 101 candidates.
pub const RECALL_KS: [usize; 4] = [1, 5, 10, 50];

/// Seed for the negative sampler.
///
/// The PRNG is **SplitMix64** (Steele, Lea and Flood, 2014), chosen because it
/// is eight lines, has no dependency, and produces the same stream on every
/// platform and every Rust version -- none of which is true of
/// `std::hash::RandomState` or of a `rand` thread RNG. The per-query stream is
/// seeded from this constant mixed with the task name and the query's index in
/// the sorted query list, so the negatives for a given (task, query) are the
/// same on every machine and do not move when an unrelated task is added.
pub const NEGATIVE_SAMPLING_SEED: u64 = 0x9E37_79B9_7F4A_7C15;

/// SplitMix64. One call advances `state` and returns a well-mixed `u64`.
fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

fn fnv1a(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for b in bytes {
        hash ^= u64::from(*b);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// One task's measurement, with everything needed to interpret it.
#[derive(Clone, Debug)]
pub struct TaskResult {
    pub task_name: String,
    pub conditions: String,
    /// Queries that survived the filters and the stratum.
    pub queries_in_scope: usize,
    /// Queries that had a twin in the pool and an extractable signature on
    /// both sides. This is the denominator of every metric below.
    pub scored: usize,
    /// Size of the full candidate pool (the global-pool lane).
    pub global_pool_size: usize,
    /// Size of the sampled ranking pool: 1 twin + [`NEGATIVES_PER_POSITIVE`].
    pub sampled_pool_size: usize,
    /// Queries or candidates whose signature could not be extracted.
    pub extraction_failures: usize,
    pub auc: f64,
    pub mrr10: f64,
    /// Recall@k over the sampled pool, keyed by k.
    pub recall_at_k: BTreeMap<usize, f64>,
    /// Recall@1 against the entire pool slice.
    pub global_recall_at_1: f64,
    /// MRR10 against the entire pool slice.
    pub global_mrr10: f64,
    /// Mean positive-pair score, and mean negative-pair score.
    pub mean_positive_score: f64,
    pub mean_negative_score: f64,
}

impl TaskResult {
    pub fn recall(&self, k: usize) -> f64 {
        self.recall_at_k.get(&k).copied().unwrap_or(0.0)
    }

    /// True when too few queries were scored for the row to mean anything.
    pub fn underpowered(&self) -> bool {
        self.scored < MIN_SCORED_FOR_A_MEASUREMENT
    }

    /// Chance Recall@1 over the sampled pool.
    pub fn sampled_chance(&self) -> f64 {
        1.0 / self.sampled_pool_size.max(1) as f64
    }

    /// Chance Recall@1 over the global pool.
    pub fn global_chance(&self) -> f64 {
        1.0 / self.global_pool_size.max(1) as f64
    }

    /// The one-line form. Pool sizes and free variables are not optional.
    pub fn line(&self) -> String {
        let recalls: Vec<String> = RECALL_KS
            .iter()
            .map(|k| format!("R@{k} {:.4}", self.recall(*k)))
            .collect();
        format!(
            "{:<8}{} {} | scored {}/{} | pool {} (+{} global) | AUC {:.4} \
             MRR10 {:.4} {} | global R@1 {:.4} (chance {:.4}) | sampled chance {:.4} | \
             mean pos {:.4} neg {:.4} | extract fail {}",
            self.task_name,
            if self.underpowered() {
                " [UNDERPOWERED]"
            } else {
                ""
            },
            self.conditions,
            self.scored,
            self.queries_in_scope,
            self.sampled_pool_size,
            self.global_pool_size,
            self.auc,
            self.mrr10,
            recalls.join(" "),
            self.global_recall_at_1,
            self.global_chance(),
            self.sampled_chance(),
            self.mean_positive_score,
            self.mean_negative_score,
            self.extraction_failures,
        )
    }

    fn to_json(&self) -> serde_json::Value {
        let recalls: serde_json::Map<String, serde_json::Value> = self
            .recall_at_k
            .iter()
            .map(|(k, v)| (k.to_string(), serde_json::json!(v)))
            .collect();
        serde_json::json!({
            "task": self.task_name,
            "conditions": self.conditions,
            "queries_in_scope": self.queries_in_scope,
            "scored": self.scored,
            "underpowered": self.underpowered(),
            "sampled_pool_size": self.sampled_pool_size,
            "global_pool_size": self.global_pool_size,
            "extraction_failures": self.extraction_failures,
            "auc": self.auc,
            "mrr10": self.mrr10,
            "recall_at_k": recalls,
            "global_recall_at_1": self.global_recall_at_1,
            "global_mrr10": self.global_mrr10,
            "sampled_chance_recall_at_1": self.sampled_chance(),
            "global_chance_recall_at_1": self.global_chance(),
            "mean_positive_score": self.mean_positive_score,
            "mean_negative_score": self.mean_negative_score,
        })
    }
}

/// Everything one scheme scored, plus the cost of producing it.
#[derive(Clone, Debug)]
pub struct SchemeReport {
    pub scheme: String,
    pub description: String,
    pub results: Vec<TaskResult>,
    /// Mean wall-clock microseconds for one `extract` call, over every sample
    /// in the corpus.
    ///
    /// TikNib is 0.02-1.03 ms per function; a design that cannot hit that
    /// order is not usable for a 6,000-function kernel diff (report 01 (3.8)).
    pub extraction_us_per_function: f64,
    pub extraction_samples: usize,
    pub corpus_root: PathBuf,
    pub corpus_load_seconds: f64,
    /// The published filters and what they removed, so a reader of the JSON
    /// can tell whether two reports share a denominator.
    pub corpus_filters: crate::corpus::FilterCounts,
    /// `(slice label, opt, kept)` per slice. The label is `gcc/O0` for the
    /// in-house corpus and `x64-gcc-9-O2` for the Cisco one.
    pub slice_sizes: Vec<(String, String, usize)>,
    /// Which corpus produced this report. Two reports over different corpora
    /// are not comparable row for row, and the filename alone does not say so.
    pub corpus_name: String,
    /// Tasks the corpus cannot express, and why. Written into the JSON next to
    /// the tasks that ran, so an absent lane is a stated gap rather than an
    /// unexamined one.
    pub unsupported_tasks: Vec<(String, String)>,
    /// Per-scheme coverage notes: what the scheme could not reach on this
    /// corpus and why, e.g. an IR scheme on the MIPS slices. Distinct from
    /// `extraction_failures`, which counts; this says what the count means.
    pub coverage_notes: Vec<String>,
    /// `"debug"` or `"release"`.
    ///
    /// The extraction cost is meaningless without it. `cargo test` builds
    /// debug, and CLAUDE.md records a case where debug and release profiles of
    /// this codebase disagreed on where the time went by a factor of fifty.
    pub profile: &'static str,
}

impl SchemeReport {
    pub fn result(&self, task_name: &str) -> Option<&TaskResult> {
        self.results.iter().find(|r| r.task_name == task_name)
    }

    /// Write `target/identity-eval/<scheme>.json`.
    ///
    /// Best effort: a harness that cannot create its report directory should
    /// still report its numbers, so the path is returned and a failure is
    /// printed rather than panicking mid-measurement.
    pub fn write_json(&self, dir: &Path) -> Option<PathBuf> {
        if let Err(e) = std::fs::create_dir_all(dir) {
            eprintln!("could not create {}: {e}", dir.display());
            return None;
        }
        let unsupported: Vec<serde_json::Value> = self
            .unsupported_tasks
            .iter()
            .map(|(name, why)| serde_json::json!({ "task": name, "why": why }))
            .collect();
        let doc = serde_json::json!({
            "scheme": self.scheme,
            "description": self.description,
            "protocol": "docs/development/identity-measurement.md",
            "corpus": self.corpus_name,
            "coverage_notes": self.coverage_notes,
            "corpus_root": self.corpus_root.display().to_string(),
            "corpus_load_seconds": self.corpus_load_seconds,
            "corpus_filters": self.corpus_filters.to_json(),
            "corpus_slices": self.slice_sizes.iter().map(|(c, o, n)| {
                serde_json::json!({ "compiler": c, "opt": o, "kept": n })
            }).collect::<Vec<_>>(),
            "build_profile": self.profile,
            "min_scored_for_a_measurement": MIN_SCORED_FOR_A_MEASUREMENT,
            "negatives_per_positive": NEGATIVES_PER_POSITIVE,
            "negative_sampling_prng": "SplitMix64",
            "negative_sampling_seed": NEGATIVE_SAMPLING_SEED,
            "tie_handling": "pessimistic: a candidate tied with the twin ranks ahead of it",
            "extraction_us_per_function": self.extraction_us_per_function,
            "extraction_samples": self.extraction_samples,
            "tasks": self.results.iter().map(TaskResult::to_json).collect::<Vec<_>>(),
            "unsupported_tasks": unsupported,
        });
        let path = dir.join(format!("{}.json", self.scheme));
        match serde_json::to_string_pretty(&doc)
            .map_err(|e| e.to_string())
            .and_then(|s| std::fs::write(&path, s).map_err(|e| e.to_string()))
        {
            Ok(()) => Some(path),
            Err(e) => {
                eprintln!("could not write {}: {e}", path.display());
                None
            }
        }
    }
}

/// The default report directory, `target/identity-eval/`.
pub fn report_dir() -> PathBuf {
    // `CARGO_TARGET_DIR` is what a worktree or a CI cache actually sets; the
    // manifest-relative `target/` is the fallback, not the assumption.
    match std::env::var_os("CARGO_TARGET_DIR") {
        Some(dir) => PathBuf::from(dir).join("identity-eval"),
        None => PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("identity-eval"),
    }
}

/// Score one scheme over a list of tasks.
pub fn evaluate<S: Scheme>(scheme: &S, corpus: &Corpus, tasks: &[Task]) -> SchemeReport {
    let (extraction_us, extraction_samples) = measure_extraction_cost(scheme, corpus);
    let mut results = Vec::new();
    for task in tasks {
        let (Some(queries), Some(pool)) = (
            corpus.slice(task.query.0, task.query.1),
            corpus.slice(task.pool.0, task.pool.1),
        ) else {
            continue;
        };
        results.push(evaluate_task(scheme, task, queries, pool));
    }
    SchemeReport {
        scheme: scheme.name().to_string(),
        description: scheme.description().to_string(),
        results,
        extraction_us_per_function: extraction_us,
        extraction_samples,
        corpus_root: corpus.root.clone(),
        corpus_load_seconds: corpus.load_seconds,
        corpus_filters: corpus.filters,
        // The JSON field this becomes is named `compiler`, so it holds the
        // compiler and not `Slice::label()` ("gcc/O0"), which is what it used
        // to hold. `test_python_and_rust_harnesses_agree_on_the_corpus` joins
        // the two harnesses' populations on `(compiler, opt)` and could never
        // match a key; the check that exists to notice the two lanes filtering
        // different populations could not itself run. `cisco.rs` builds its
        // own `slice_sizes` and is unaffected -- there a slice really is
        // identified by its five-dimensional label.
        slice_sizes: corpus
            .slices()
            .map(|s| (s.compiler.to_string(), s.opt.to_string(), s.samples.len()))
            .collect(),
        corpus_name: "glaurung fixture matrix (tests/decompiler_fixtures/build)".to_string(),
        unsupported_tasks: UNSUPPORTED_TASKS
            .iter()
            .map(|(n, w)| (n.to_string(), w.to_string()))
            .collect(),
        coverage_notes: Vec::new(),
        profile: build_profile(),
    }
}

/// `"debug"` or `"release"`, from the compile-time flag.
///
/// Not a cosmetic label: CLAUDE.md records the two profiles of this codebase
/// disagreeing about where time goes by a factor of fifty, and every extraction
/// cost in a report is meaningless without it.
pub fn build_profile() -> &'static str {
    if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    }
}

/// Mean microseconds per `extract` call, over every sample in the corpus.
///
/// Timed with the corpus already in memory, so this measures the scheme and
/// not the filesystem. A scheme that re-reads its image from disk pays that
/// cost here, which is correct: it is a cost the scheme chose.
fn measure_extraction_cost<S: Scheme>(scheme: &S, corpus: &Corpus) -> (f64, usize) {
    let mut total = std::time::Duration::ZERO;
    let mut count = 0usize;
    for slice in corpus.slices() {
        for sample in &slice.samples {
            let started = std::time::Instant::now();
            let sig = scheme.extract(sample);
            total += started.elapsed();
            count += 1;
            // Keep the result alive across the timer so the optimiser cannot
            // delete the work being measured.
            std::hint::black_box(&sig);
        }
    }
    if count == 0 {
        return (0.0, 0);
    }
    (total.as_secs_f64() * 1e6 / count as f64, count)
}

fn evaluate_task<S: Scheme>(scheme: &S, task: &Task, queries: &Slice, pool: &Slice) -> TaskResult {
    evaluate_slices(
        scheme,
        task.name,
        &task.conditions(),
        task.stratum,
        queries,
        pool,
    )
}

/// Score one query slice against one pool slice.
///
/// The whole of the protocol lives here -- the twin join, the seeded negative
/// draw, pessimistic ties, the sampled and global lanes -- and it takes the
/// task's identity as three plain values rather than a [`Task`]. That is what
/// lets `cisco.rs` express tasks over a five-dimensional configuration key
/// (architecture, bitness, compiler, version, optimisation) without a second
/// copy of the scoring code: two harnesses that reimplement the protocol are
/// two harnesses that will disagree about a denominator, which is the exact
/// comparability failure this file exists to prevent.
pub fn evaluate_slices<S: Scheme>(
    scheme: &S,
    task_name: &str,
    conditions: &str,
    stratum: Option<Stratum>,
    queries: &Slice,
    pool: &Slice,
) -> TaskResult {
    let mut extraction_failures = 0usize;

    // Signatures for the whole pool once, not once per query.
    let pool_sigs: Vec<Option<S::Sig>> = pool
        .samples
        .iter()
        .map(|s| match scheme.extract(s) {
            Ok(sig) => Some(sig),
            Err(_) => None,
        })
        .collect();
    extraction_failures += pool_sigs.iter().filter(|s| s.is_none()).count();

    let usable_pool: Vec<usize> = (0..pool.samples.len())
        .filter(|i| pool_sigs[*i].is_some())
        .collect();
    let pool_by_label: BTreeMap<(&str, &str), usize> = usable_pool
        .iter()
        .map(|i| (pool.samples[*i].label(), *i))
        .collect();

    let in_scope: Vec<&FunctionSample> = queries
        .samples
        .iter()
        .filter(|s| stratum.is_none_or(|st| st.contains(s)))
        .collect();

    let mut positive_scores: Vec<f64> = Vec::new();
    let mut negative_scores: Vec<f64> = Vec::new();
    let mut sampled_ranks: Vec<usize> = Vec::new();
    let mut global_ranks: Vec<usize> = Vec::new();

    for (query_index, query) in in_scope.iter().enumerate() {
        let Some(&twin_index) = pool_by_label.get(&query.label()) else {
            // A function the other build inlined away has no right answer;
            // counting it as a miss would measure the compiler, not us.
            continue;
        };
        let query_sig = match scheme.extract(query) {
            Ok(sig) => sig,
            Err(_) => {
                extraction_failures += 1;
                continue;
            }
        };
        let twin_sig = pool_sigs[twin_index]
            .as_ref()
            .expect("usable_pool only holds extractable indices");
        let positive = scheme.similarity(&query_sig, twin_sig);

        let negatives = sample_negatives(task_name, query_index, query, &usable_pool, pool);
        let mut ahead = 0usize;
        for &neg_index in &negatives {
            let neg_sig = pool_sigs[neg_index]
                .as_ref()
                .expect("usable_pool only holds extractable indices");
            let score = scheme.similarity(&query_sig, neg_sig);
            negative_scores.push(score);
            // Pessimistic ties: `>=`, not `>`.
            if score >= positive {
                ahead += 1;
            }
        }
        positive_scores.push(positive);
        sampled_ranks.push(ahead + 1);

        // Global-pool lane: the same query against every usable candidate.
        let mut global_ahead = 0usize;
        for &cand_index in &usable_pool {
            if cand_index == twin_index {
                continue;
            }
            let cand_sig = pool_sigs[cand_index]
                .as_ref()
                .expect("usable_pool only holds extractable indices");
            if scheme.similarity(&query_sig, cand_sig) >= positive {
                global_ahead += 1;
            }
        }
        global_ranks.push(global_ahead + 1);
    }

    let scored = sampled_ranks.len();
    let mut recall_at_k = BTreeMap::new();
    for k in RECALL_KS {
        recall_at_k.insert(k, recall(&sampled_ranks, k));
    }

    TaskResult {
        task_name: task_name.to_string(),
        conditions: conditions.to_string(),
        queries_in_scope: in_scope.len(),
        scored,
        global_pool_size: usable_pool.len(),
        sampled_pool_size: NEGATIVES_PER_POSITIVE + 1,
        extraction_failures,
        auc: auc(&positive_scores, &negative_scores),
        mrr10: mrr(&sampled_ranks, 10),
        recall_at_k,
        global_recall_at_1: recall(&global_ranks, 1),
        global_mrr10: mrr(&global_ranks, 10),
        mean_positive_score: mean(&positive_scores),
        mean_negative_score: mean(&negative_scores),
    }
}

/// Draw [`NEGATIVES_PER_POSITIVE`] distinct non-twin candidates from the pool.
///
/// Deterministic: the stream is SplitMix64 seeded from
/// [`NEGATIVE_SAMPLING_SEED`], the task name and the query's index, so the
/// same (task, query) draws the same negatives on every machine, and adding a
/// task does not move an existing one's numbers. Excluded are every candidate
/// sharing the query's label -- there is at most one after the dedupe filter,
/// but the check is by label rather than by index so a corpus with duplicates
/// still cannot smuggle the right answer in as a negative.
///
/// When the pool is smaller than the requested count, every usable candidate
/// is returned and the caller's `sampled_pool_size` overstates the pool. That
/// case is asserted against in `main.rs` rather than silently tolerated.
pub(crate) fn sample_negatives(
    task_name: &str,
    query_index: usize,
    query: &FunctionSample,
    usable_pool: &[usize],
    pool: &Slice,
) -> Vec<usize> {
    let eligible: Vec<usize> = usable_pool
        .iter()
        .copied()
        .filter(|i| pool.samples[*i].label() != query.label())
        .collect();
    if eligible.len() <= NEGATIVES_PER_POSITIVE {
        return eligible;
    }
    let mut state = NEGATIVE_SAMPLING_SEED
        ^ fnv1a(task_name.as_bytes())
        ^ (query_index as u64).wrapping_mul(0x2545_F491_4F6C_DD1D);
    let mut chosen: BTreeSet<usize> = BTreeSet::new();
    // Rejection sampling without replacement. Bounded: the loop draws at most
    // 64x the target before giving up, which cannot happen for a pool more
    // than ~1.5x the sample size and is asserted against in `main.rs`.
    let mut draws = 0usize;
    while chosen.len() < NEGATIVES_PER_POSITIVE && draws < NEGATIVES_PER_POSITIVE * 64 {
        let pick = (splitmix64(&mut state) % eligible.len() as u64) as usize;
        chosen.insert(eligible[pick]);
        draws += 1;
    }
    chosen.into_iter().collect()
}

/// Recall@k: the fraction of queries whose twin ranked at `k` or better.
pub(crate) fn recall(ranks: &[usize], k: usize) -> f64 {
    if ranks.is_empty() {
        return 0.0;
    }
    ranks.iter().filter(|r| **r <= k).count() as f64 / ranks.len() as f64
}

/// Mean reciprocal rank, truncated at `cutoff` (MRR10 for `cutoff = 10`).
pub(crate) fn mrr(ranks: &[usize], cutoff: usize) -> f64 {
    if ranks.is_empty() {
        return 0.0;
    }
    let total: f64 = ranks
        .iter()
        .map(|r| if *r <= cutoff { 1.0 / *r as f64 } else { 0.0 })
        .sum();
    total / ranks.len() as f64
}

fn mean(values: &[f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    values.iter().sum::<f64>() / values.len() as f64
}

/// AUC as the Mann-Whitney U statistic: the probability that a random positive
/// pair outscores a random negative pair, with ties counted as half.
///
/// Computed from mid-ranks rather than by enumerating pairs, so it is
/// `O(n log n)` rather than `O(n_pos * n_neg)`. 0.5 is chance; a value below
/// 0.5 means the scheme ranks the wrong answer higher, which is worse than
/// useless and worth seeing rather than clamping.
fn auc(positives: &[f64], negatives: &[f64]) -> f64 {
    if positives.is_empty() || negatives.is_empty() {
        return 0.0;
    }
    let mut all: Vec<(f64, bool)> = positives
        .iter()
        .map(|s| (*s, true))
        .chain(negatives.iter().map(|s| (*s, false)))
        .collect();
    all.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));

    let mut rank_sum_positive = 0.0f64;
    let mut i = 0usize;
    while i < all.len() {
        let mut j = i;
        while j + 1 < all.len() && all[j + 1].0 == all[i].0 {
            j += 1;
        }
        // Mid-rank for the whole tie group, 1-based.
        let mid = (i + j) as f64 / 2.0 + 1.0;
        for entry in &all[i..=j] {
            if entry.1 {
                rank_sum_positive += mid;
            }
        }
        i = j + 1;
    }

    let n_pos = positives.len() as f64;
    let n_neg = negatives.len() as f64;
    (rank_sum_positive - n_pos * (n_pos + 1.0) / 2.0) / (n_pos * n_neg)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The AUC of a perfect separation is 1.0, of a reversed one 0.0, and of
    /// a total tie 0.5. Without this the statistic could be off by a constant
    /// and every reported number would move together, which is exactly the
    /// error a corpus measurement cannot detect on its own.
    #[test]
    fn auc_endpoints_are_exact() {
        assert_eq!(auc(&[1.0, 0.9], &[0.1, 0.2]), 1.0);
        assert_eq!(auc(&[0.1, 0.2], &[1.0, 0.9]), 0.0);
        assert_eq!(auc(&[0.5, 0.5], &[0.5, 0.5]), 0.5);
        // Half the negatives tied with the positive: 1 clear win, 1 half.
        assert_eq!(auc(&[0.5], &[0.4, 0.5]), 0.75);
    }

    #[test]
    fn mrr_and_recall_agree_with_their_definitions() {
        let ranks = vec![1, 2, 11, 4];
        assert_eq!(recall(&ranks, 1), 0.25);
        assert_eq!(recall(&ranks, 5), 0.75);
        assert_eq!(recall(&ranks, 50), 1.0);
        // 1/1 + 1/2 + 0 (rank 11 is past the cutoff) + 1/4, over 4.
        assert!((mrr(&ranks, 10) - (1.0 + 0.5 + 0.0 + 0.25) / 4.0).abs() < 1e-12);
    }

    /// The negative sampler must give the same answer twice. A seeded PRNG
    /// that consults a `HashMap` iteration order somewhere would pass every
    /// other test in this file and make the ratchets flaky.
    #[test]
    fn splitmix64_stream_is_fixed() {
        let mut a = NEGATIVE_SAMPLING_SEED;
        let mut b = NEGATIVE_SAMPLING_SEED;
        let first: Vec<u64> = (0..8).map(|_| splitmix64(&mut a)).collect();
        let second: Vec<u64> = (0..8).map(|_| splitmix64(&mut b)).collect();
        assert_eq!(first, second);
        // Pinned against an independent implementation of SplitMix64 run over
        // the same seed, so a refactor of the mixing constants shows up as a
        // failing test rather than as silently different negatives (which
        // would move every ratchet in this harness at once, with nothing to
        // attribute the movement to).
        assert_eq!(
            &first[..4],
            &[
                0x6e78_9e6a_a1b9_65f4_u64,
                0x06c4_5d18_8009_454f,
                0xf88b_b8a8_724c_81ec,
                0x1b39_896a_51a8_749b,
            ]
        );
    }
}
