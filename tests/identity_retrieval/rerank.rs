//! The re-rank post-pass, scored against the same protocol the schemes are.
//!
//! Plan item 10 of `docs/history/program-measures-2026-09-02.md`.
//! [`glaurung::identity::rerank`] takes candidate lists and returns better
//! ordered ones; this file produces those lists from a [`Scheme`] exactly the
//! way [`crate::metrics::evaluate_slices`] does, hands them to the decode, and
//! reports the before and after side by side with the fraction of queries whose
//! rank moved each way.
//!
//! # Why a post-pass and not a `Scheme`
//!
//! A `Scheme` answers `similarity(a, b)` for one pair, with nothing else in
//! view. That is the whole reason the re-rank exists -- it uses context a
//! per-pair comparison cannot see -- so it cannot be expressed as one. It
//! wraps the *driver*, not the scheme, and works over any `S: Scheme` without
//! knowing which.
//!
//! # The before and the after are the same rank rule
//!
//! Both halves use `metrics.rs`'s pessimistic tie rule: a candidate scoring at
//! least what the twin scores ranks ahead of it. A before/after comparison
//! whose two halves resolve ties differently would report the tie rule as an
//! improvement. Two consequences are worth stating:
//!
//! * The baseline ranks this file computes are **identical** to the ones
//!   `evaluate_slices` computes, and `main.rs` asserts that against a live run
//!   rather than trusting the reimplementation.
//! * A twin the decode never admitted into its top-K keeps its baseline rank
//!   unchanged, which is exact rather than conservative: the admission rule
//!   extends over ties at the boundary, so a twin that missed it has at least
//!   `top_k` candidates scoring strictly better and therefore already ranked
//!   past `top_k`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use glaurung::identity::rerank::{
    rerank, CallContext, Candidate, QueryFunction, QueryId, ReferenceId, RerankSettings,
};

use crate::corpus::{FunctionSample, Slice};
use crate::metrics::{
    build_profile, mrr, recall, sample_negatives, MIN_SCORED_FOR_A_MEASUREMENT,
    NEGATIVES_PER_POSITIVE,
};
use crate::scheme::Scheme;
use crate::tasks::Stratum;

/// Which candidate universe the decode is handed.
///
/// **This choice changes what the adjacency term can mean, and it is the
/// single most load-bearing decision on this lane.**
///
/// [`PoolLane::Sampled`] is Marcelli's protocol and the one every other number
/// in this harness is computed under: 100 negatives per positive, drawn
/// *independently for each query*. Two consecutive layers therefore see two
/// nearly disjoint random subsets of the corpus. A provenance-agreement term
/// rewards any two candidates from the same library, so under this protocol it
/// is far more likely to reward a coincidence between two large libraries'
/// negatives than the one true pair -- the twins are often the only two
/// representatives of their own library in their respective draws.
///
/// [`PoolLane::Global`] is RevDecode's own setting: every layer ranks against
/// the *same* candidate universe, the whole pool slice. This is the lane on
/// which a provenance term is being asked the question the paper asks it.
///
/// The call-agreement term is insensitive to the difference, because it needs a
/// specific edge between two specific reference functions rather than a shared
/// attribute; that is visible in the measured table, where it never regresses on
/// either lane.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PoolLane {
    /// 1 twin + [`NEGATIVES_PER_POSITIVE`], drawn per query with the harness's
    /// seeded sampler.
    Sampled,
    /// Every extractable candidate in the pool slice, shared by every query.
    Global,
}

impl PoolLane {
    pub fn label(self) -> &'static str {
        match self {
            PoolLane::Sampled => "sampled",
            PoolLane::Global => "global",
        }
    }
}

/// One task, scored before and after the decode.
#[derive(Clone, Debug)]
pub struct RerankComparison {
    pub task_name: String,
    pub conditions: String,
    pub lane: PoolLane,
    /// Which [`RerankSettings`] preset produced the "after" column.
    pub settings_label: String,
    pub scored: usize,
    pub sampled_pool_size: usize,
    pub global_pool_size: usize,
    pub top_k: usize,
    pub baseline_mrr10: f64,
    pub baseline_recall_at_1: f64,
    pub reranked_mrr10: f64,
    pub reranked_recall_at_1: f64,
    /// Queries whose twin ranked strictly better after the decode.
    pub improved: usize,
    /// Strictly worse.
    pub worsened: usize,
    pub unchanged: usize,
    /// Call edges the decode could see between two *scored query* functions.
    pub query_call_edges: usize,
    /// Call edges between two candidate-eligible *pool* functions.
    pub reference_call_edges: usize,
    /// Consecutive layer pairs with a call relation between them -- the pairs
    /// on which the call-agreement term can fire at all.
    ///
    /// A term that never fires and a term that fires and finds nothing look
    /// identical in a summary metric, and only the first is a reason to change
    /// the layer order.
    pub adjacent_related_pairs: usize,
    /// Consecutive layer pairs in total.
    pub adjacent_pairs: usize,
    pub relaxations: u64,
    pub decode_seconds: f64,
}

impl RerankComparison {
    pub fn underpowered(&self) -> bool {
        self.scored < MIN_SCORED_FOR_A_MEASUREMENT
    }

    pub fn improved_fraction(&self) -> f64 {
        fraction(self.improved, self.scored)
    }

    pub fn worsened_fraction(&self) -> f64 {
        fraction(self.worsened, self.scored)
    }

    /// The one-line form. Pool sizes and free variables are not optional here
    /// either.
    pub fn line(&self) -> String {
        format!(
            "{:<8}{} {} | {} | {} lane | scored {} | pool {} (of {} usable) | top-K {} | \
             MRR10 {:.4} -> {:.4} ({:+.4}) | R@1 {:.4} -> {:.4} ({:+.4}) | \
             improved {} ({:.1}%) worsened {} ({:.1}%) unchanged {} | \
             call edges q{} r{} | related layer pairs {}/{} | \
             relaxations {} in {:.3}s",
            self.task_name,
            if self.underpowered() {
                " [UNDERPOWERED]"
            } else {
                ""
            },
            self.conditions,
            self.settings_label,
            self.lane.label(),
            self.scored,
            self.sampled_pool_size,
            self.global_pool_size,
            self.top_k,
            self.baseline_mrr10,
            self.reranked_mrr10,
            self.reranked_mrr10 - self.baseline_mrr10,
            self.baseline_recall_at_1,
            self.reranked_recall_at_1,
            self.reranked_recall_at_1 - self.baseline_recall_at_1,
            self.improved,
            100.0 * self.improved_fraction(),
            self.worsened,
            100.0 * self.worsened_fraction(),
            self.unchanged,
            self.query_call_edges,
            self.reference_call_edges,
            self.adjacent_related_pairs,
            self.adjacent_pairs,
            self.relaxations,
            self.decode_seconds,
        )
    }

    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "task": self.task_name,
            "conditions": self.conditions,
            "settings": self.settings_label,
            "lane": self.lane.label(),
            "scored": self.scored,
            "underpowered": self.underpowered(),
            "sampled_pool_size": self.sampled_pool_size,
            "global_pool_size": self.global_pool_size,
            "top_k": self.top_k,
            "baseline_mrr10": self.baseline_mrr10,
            "baseline_recall_at_1": self.baseline_recall_at_1,
            "reranked_mrr10": self.reranked_mrr10,
            "reranked_recall_at_1": self.reranked_recall_at_1,
            "improved": self.improved,
            "worsened": self.worsened,
            "unchanged": self.unchanged,
            "improved_fraction": self.improved_fraction(),
            "worsened_fraction": self.worsened_fraction(),
            "query_call_edges": self.query_call_edges,
            "reference_call_edges": self.reference_call_edges,
            "adjacent_related_pairs": self.adjacent_related_pairs,
            "adjacent_pairs": self.adjacent_pairs,
            "relaxations": self.relaxations,
            "decode_seconds": self.decode_seconds,
        })
    }
}

fn fraction(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        return 0.0;
    }
    numerator as f64 / denominator as f64
}

/// Every task one `(scheme, settings)` pair was scored on.
#[derive(Clone, Debug)]
pub struct RerankReport {
    pub scheme: String,
    pub lane: PoolLane,
    pub settings_label: String,
    pub corpus_name: String,
    pub comparisons: Vec<RerankComparison>,
    pub profile: &'static str,
}

impl RerankReport {
    pub fn comparison(&self, task_name: &str) -> Option<&RerankComparison> {
        self.comparisons.iter().find(|c| c.task_name == task_name)
    }

    /// Write `target/identity-eval/rerank-<scheme>-<settings>.json`.
    pub fn write_json(&self, dir: &Path) -> Option<PathBuf> {
        if let Err(e) = std::fs::create_dir_all(dir) {
            eprintln!("could not create {}: {e}", dir.display());
            return None;
        }
        let doc = serde_json::json!({
            "stage": "rerank",
            "algorithm": "glaurung::identity::rerank (RevDecode, USENIX Security 2025)",
            "reference": "docs/reference/function-identity-rerank.md",
            "protocol": "docs/development/identity-measurement.md",
            "scheme": self.scheme,
            "settings": self.settings_label,
            "lane": self.lane.label(),
            "corpus": self.corpus_name,
            "build_profile": self.profile,
            "negatives_per_positive": match self.lane {
                PoolLane::Sampled => serde_json::json!(NEGATIVES_PER_POSITIVE),
                PoolLane::Global => serde_json::Value::Null,
            },
            "tie_handling": "pessimistic, both before and after",
            "tasks": self.comparisons.iter()
                .map(RerankComparison::to_json)
                .collect::<Vec<_>>(),
        });
        let corpus_tag = if self.corpus_name.starts_with("Cisco") {
            "cisco"
        } else {
            "inhouse"
        };
        let path = dir.join(format!(
            "rerank-{corpus_tag}-{}-{}-{}.json",
            self.scheme,
            self.settings_label,
            self.lane.label()
        ));
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

/// One query that survived the twin join, with the candidate list the scheme
/// produced for it.
struct ScoredQuery {
    /// Index into `queries.samples`.
    sample_index: usize,
    /// The pool index of the true twin.
    twin: usize,
    /// `(pool index, similarity)`, unordered.
    candidates: Vec<(usize, f64)>,
    baseline_rank: usize,
}

/// Score one query slice against one pool slice, before and after the decode.
///
/// The twin join, the seeded negative draw and the pessimistic tie rule are
/// `metrics.rs`'s, reached through [`sample_negatives`] rather than copied, so
/// the two files cannot drift into sampling different negatives.
#[allow(clippy::too_many_arguments)]
pub fn compare_slices<S: Scheme>(
    scheme: &S,
    task_name: &str,
    conditions: &str,
    stratum: Option<Stratum>,
    queries: &Slice,
    pool: &Slice,
    settings: &RerankSettings,
    settings_label: &str,
    lane: PoolLane,
) -> RerankComparison {
    let pool_sigs: Vec<Option<S::Sig>> = pool
        .samples
        .iter()
        .map(|s| scheme.extract(s).ok())
        .collect();
    let usable_pool: Vec<usize> = (0..pool.samples.len())
        .filter(|i| pool_sigs[*i].is_some())
        .collect();
    let pool_by_label: BTreeMap<(&str, &str), usize> = usable_pool
        .iter()
        .map(|i| (pool.samples[*i].label(), *i))
        .collect();

    let in_scope: Vec<usize> = (0..queries.samples.len())
        .filter(|i| stratum.is_none_or(|st| st.contains(&queries.samples[*i])))
        .collect();

    let mut scored: Vec<ScoredQuery> = Vec::new();
    for (query_index, &sample_index) in in_scope.iter().enumerate() {
        let query = &queries.samples[sample_index];
        let Some(&twin) = pool_by_label.get(&query.label()) else {
            continue;
        };
        let Ok(query_sig) = scheme.extract(query) else {
            continue;
        };
        let twin_sig = pool_sigs[twin]
            .as_ref()
            .expect("usable_pool only holds extractable indices");
        let positive = scheme.similarity(&query_sig, twin_sig);

        // `query_index` is the position in the in-scope list, which is what
        // `evaluate_slices` passes; using the sample index instead would draw
        // different negatives and make the two lanes incomparable.
        let negatives: Vec<usize> = match lane {
            PoolLane::Sampled => {
                sample_negatives(task_name, query_index, query, &usable_pool, pool)
            }
            // Every candidate sharing the query's label is excluded, exactly as
            // the sampler does: there is at most one after the dedupe filter,
            // but the check is by label rather than by index so a corpus with
            // duplicates cannot smuggle the right answer in as a negative.
            PoolLane::Global => usable_pool
                .iter()
                .copied()
                .filter(|&i| pool.samples[i].label() != query.label())
                .collect(),
        };
        let mut candidates = Vec::with_capacity(negatives.len() + 1);
        candidates.push((twin, positive));
        let mut ahead = 0usize;
        for &negative in &negatives {
            let sig = pool_sigs[negative]
                .as_ref()
                .expect("usable_pool only holds extractable indices");
            let score = scheme.similarity(&query_sig, sig);
            if score >= positive {
                ahead += 1;
            }
            candidates.push((negative, score));
        }
        scored.push(ScoredQuery {
            sample_index,
            twin,
            candidates,
            baseline_rank: ahead + 1,
        });
    }

    let context = build_context(&scored, queries, pool, &usable_pool);
    let layered = build_queries(&scored, queries);

    let started = std::time::Instant::now();
    let decoded = rerank(&layered, &context, settings);
    let decode_seconds = started.elapsed().as_secs_f64();

    let by_query: BTreeMap<QueryId, &_> = decoded
        .layers
        .iter()
        .map(|layer| (layer.query, layer))
        .collect();

    let mut baseline_ranks = Vec::with_capacity(scored.len());
    let mut reranked_ranks = Vec::with_capacity(scored.len());
    let (mut improved, mut worsened, mut unchanged) = (0usize, 0usize, 0usize);
    for (id, query) in scored.iter().enumerate() {
        let baseline = query.baseline_rank;
        let reranked = by_query
            .get(&(id as QueryId))
            .and_then(|layer| layer.pessimistic_rank(query.twin as ReferenceId))
            // Not admitted into the top-K, so the decode never saw it and
            // cannot have moved it.
            .unwrap_or(baseline);
        match reranked.cmp(&baseline) {
            std::cmp::Ordering::Less => improved += 1,
            std::cmp::Ordering::Greater => worsened += 1,
            std::cmp::Ordering::Equal => unchanged += 1,
        }
        baseline_ranks.push(baseline);
        reranked_ranks.push(reranked);
    }

    // How often the call term can fire: consecutive layers whose two query
    // functions have a call relation either way.
    let layer_order: Vec<QueryId> = decoded.layers.iter().map(|l| l.query).collect();
    let adjacent_pairs = layer_order.len().saturating_sub(1);
    let adjacent_related_pairs = layer_order
        .windows(2)
        .filter(|w| context.query_pair_is_related(w[0], w[1]))
        .count();

    RerankComparison {
        task_name: task_name.to_string(),
        conditions: conditions.to_string(),
        lane,
        settings_label: settings_label.to_string(),
        scored: scored.len(),
        sampled_pool_size: match lane {
            PoolLane::Sampled => NEGATIVES_PER_POSITIVE + 1,
            PoolLane::Global => usable_pool.len(),
        },
        global_pool_size: usable_pool.len(),
        top_k: settings.top_k,
        baseline_mrr10: mrr(&baseline_ranks, 10),
        baseline_recall_at_1: recall(&baseline_ranks, 1),
        reranked_mrr10: mrr(&reranked_ranks, 10),
        reranked_recall_at_1: recall(&reranked_ranks, 1),
        improved,
        worsened,
        unchanged,
        query_call_edges: context.query_call_count(),
        reference_call_edges: context.reference_call_count(),
        adjacent_related_pairs,
        adjacent_pairs,
        relaxations: decoded.relaxations,
        decode_seconds,
    }
}

/// The layers: one per scored query, ordered by `(image, entry VA)`.
///
/// RevDecode orders layers by the unknown functions' memory offsets, on the
/// argument that a compiler places one translation unit's functions
/// contiguously. This corpus is many small images rather than one large one, so
/// the order is image first and VA within it -- which is the same argument, and
/// keeps every image's functions in one contiguous run of layers.
///
/// Nothing special happens at an image boundary and nothing needs to: both
/// pairwise terms are zero across it (different image, so different library and
/// no call edge), and adding a constant to every edge into a layer changes no
/// ordering within that layer.
fn build_queries(scored: &[ScoredQuery], queries: &Slice) -> Vec<QueryFunction> {
    let mut order: Vec<(usize, &PathBuf, u64)> = scored
        .iter()
        .enumerate()
        .map(|(id, q)| {
            let sample = &queries.samples[q.sample_index];
            (id, &sample.image_path, sample.va)
        })
        .collect();
    order.sort_by(|a, b| a.1.cmp(b.1).then(a.2.cmp(&b.2)));
    let position: BTreeMap<usize, u64> = order
        .iter()
        .enumerate()
        .map(|(rank, (id, _, _))| (*id, rank as u64))
        .collect();

    scored
        .iter()
        .enumerate()
        .map(|(id, query)| QueryFunction {
            id: id as QueryId,
            order_key: position[&id],
            candidates: query
                .candidates
                .iter()
                .map(|(pool_index, similarity)| {
                    Candidate::new(*pool_index as ReferenceId, *similarity)
                })
                .collect(),
        })
        .collect()
}

/// The context: both call graphs and the library partition.
///
/// A call target is a raw VA, meaningful only inside its own image, so every
/// lookup is keyed by `(image path, VA)`. The library partition is by image,
/// which on this corpus is also the translation unit -- RevDecode approximates
/// its compilation units from DWARF for the same reason.
fn build_context(
    scored: &[ScoredQuery],
    queries: &Slice,
    pool: &Slice,
    usable_pool: &[usize],
) -> CallContext {
    let mut context = CallContext::new();

    let query_at: BTreeMap<(&PathBuf, u64), QueryId> = scored
        .iter()
        .enumerate()
        .map(|(id, q)| {
            let sample = &queries.samples[q.sample_index];
            ((&sample.image_path, sample.va), id as QueryId)
        })
        .collect();
    for (id, query) in scored.iter().enumerate() {
        let sample = &queries.samples[query.sample_index];
        for callee in &sample.callees {
            if let Some(&target) = query_at.get(&(&sample.image_path, *callee)) {
                if target != id as QueryId {
                    context.add_query_call(id as QueryId, target);
                }
            }
        }
    }

    let reference_at: BTreeMap<(&PathBuf, u64), ReferenceId> = usable_pool
        .iter()
        .map(|&index| {
            let sample = &pool.samples[index];
            ((&sample.image_path, sample.va), index as ReferenceId)
        })
        .collect();
    let mut groups: BTreeMap<&PathBuf, u32> = BTreeMap::new();
    for &index in usable_pool {
        let sample: &FunctionSample = &pool.samples[index];
        let next = groups.len() as u32;
        let group = *groups.entry(&sample.image_path).or_insert(next);
        context.set_reference_group(index as ReferenceId, group);
        for callee in &sample.callees {
            if let Some(&target) = reference_at.get(&(&sample.image_path, *callee)) {
                if target != index as ReferenceId {
                    context.add_reference_call(index as ReferenceId, target);
                }
            }
        }
    }

    context
}

/// Score one scheme over a list of in-house tasks.
pub fn evaluate<S: Scheme>(
    scheme: &S,
    corpus: &crate::corpus::Corpus,
    tasks: &[crate::tasks::Task],
    settings: &RerankSettings,
    settings_label: &str,
    lane: PoolLane,
) -> RerankReport {
    let comparisons = tasks
        .iter()
        .filter_map(|task| {
            let (Some(queries), Some(pool)) = (
                corpus.slice(task.query.0, task.query.1),
                corpus.slice(task.pool.0, task.pool.1),
            ) else {
                return None;
            };
            Some(compare_slices(
                scheme,
                task.name,
                &task.conditions(),
                task.stratum,
                queries,
                pool,
                settings,
                settings_label,
                lane,
            ))
        })
        .collect();
    RerankReport {
        scheme: scheme.name().to_string(),
        lane,
        settings_label: settings_label.to_string(),
        corpus_name: "glaurung fixture matrix (tests/decompiler_fixtures/build)".to_string(),
        comparisons,
        profile: build_profile(),
    }
}

/// Score one scheme over a list of Cisco Dataset-1 tasks.
pub fn evaluate_cisco<S: Scheme>(
    scheme: &S,
    corpus: &crate::cisco::CiscoCorpus,
    tasks: &[crate::cisco::CiscoTask],
    settings: &RerankSettings,
    settings_label: &str,
    lane: PoolLane,
) -> RerankReport {
    let comparisons = tasks
        .iter()
        .filter_map(|task| {
            let (Some(queries), Some(pool)) = (corpus.slice(&task.query), corpus.slice(&task.pool))
            else {
                return None;
            };
            Some(compare_slices(
                scheme,
                task.name,
                &task.conditions(),
                None,
                queries,
                pool,
                settings,
                settings_label,
                lane,
            ))
        })
        .collect();
    RerankReport {
        scheme: scheme.name().to_string(),
        lane,
        settings_label: settings_label.to_string(),
        corpus_name: "Cisco Talos Dataset-1".to_string(),
        comparisons,
        profile: build_profile(),
    }
}
