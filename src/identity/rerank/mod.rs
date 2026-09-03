//! RevDecode-style context re-ranking: a Viterbi decode over a layered
//! candidate graph.
//!
//! Plan item 10 of `docs/history/program-measures-2026-09-02.md`, after Ren,
//! Che, Gilman, De Carli and Walls, "RevDecode: Enhancing Binary Function
//! Matching with Context-Aware Graph Representations and Relevance Decoding"
//! (USENIX Security 2025).
//!
//! # What it is, and what it is not
//!
//! This is **not a matcher**. It takes the candidate lists some other scheme
//! already produced -- [`crate::identity::structural`],
//! [`crate::identity::cfr`], WARP, or anything else that can score a query
//! function against a reference corpus -- and re-orders them using context the
//! per-function matcher never sees: which query function calls which, which
//! reference function calls which, and which reference functions came from the
//! same library. Nothing here computes a similarity; the similarities arrive as
//! plain `f64`s in [`Candidate`].
//!
//! It is a **dynamic program**, not a model. There is no training, no random
//! seed and no floating-point tolerance in the control flow: every ordering
//! decision is a `BTree` key or an explicit total order, so the same input
//! gives byte-identical output on every machine.
//!
//! # The graph
//!
//! One **layer** per query function, in a caller-chosen deterministic order
//! ([`QueryFunction::order_key`], entry VA in every caller we ship). One
//! **node** per candidate in that query's top-K list, plus one **"no match"**
//! node per layer -- the paper's *uncertain* node, which exists so an
//! incomplete corpus can be answered with "nothing here is it" rather than with
//! the least bad wrong answer. A start node before the first layer and an end
//! node after the last.
//!
//! Every node in layer `j-1` has an edge to every node in layer `j`. The edge
//! weight is a sum of terms, each in `[0, 1]` and each separately weighted by
//! [`RerankSettings`]:
//!
//! | Term | Depends on | In the paper |
//! |---|---|---|
//! | similarity | the destination candidate | yes |
//! | confidence | the destination candidate | yes (TF-IDF, Eq. 7) |
//! | library | the destination candidate's library | yes (Eq. 8) |
//! | adjacency | both endpoints' libraries | yes (Alg. 1) |
//! | call agreement | both endpoints, and both call graphs | **ours** |
//!
//! The forward pass solves `W(v) = max_u [W(u) + w(u, v)]` layer by layer; the
//! backward pass computes the same quantity towards the end node; their sum is
//! the weight of the best path *through* each node, and that is the re-ranking
//! key.
//!
//! # Where this departs from the paper
//!
//! Recorded here and in `docs/reference/function-identity-rerank.md`; none of
//! them is silent.
//!
//! 1. **A call-agreement term is added.** RevDecode's contextual edge term is
//!    *adjacency*: candidates are rewarded for coming from the same library,
//!    version, optimisation level and compilation unit as each other, and the
//!    layers are ordered by memory offset because compilers place a translation
//!    unit's functions contiguously. That is provenance agreement, not a call
//!    graph. We keep it ([`CallContext::set_reference_group`]) and add the term
//!    the plan item asks for: if query `A` calls query `B` and candidate `a`
//!    calls candidate `b` in the reference corpus, the pair is rewarded.
//! 2. **The confidence term is optional and no scheme supplies it yet.** The
//!    paper's confidence score is a TF-IDF sum over shared minus unique
//!    features (Eq. 7), which needs the matcher's feature multisets and a
//!    corpus count table -- neither of which crosses the harness's `Scheme`
//!    boundary, where a comparison is one `f64`. [`Candidate::confidence`] is
//!    the socket for it; when it is `None` the term contributes nothing.
//! 3. **The "no match" node is an explicit threshold, not a derived one.** The
//!    paper sets the uncertain node's similarity to the layer maximum and its
//!    confidence to 85% of self-confidence, so its power comes almost entirely
//!    from the confidence term we do not have. Reproducing only the first half
//!    would give a node that can never win. Instead
//!    [`RerankSettings::no_match_similarity`] is the score a candidate must
//!    beat, stated in the same units as the similarities; the default `0.0`
//!    keeps the node in the graph (so the structure is faithful and a caller
//!    can raise it) while never displacing a candidate that scores above zero.
//! 4. **The backward pass is the standard best-path-through-a-node score.**
//!    The paper's ranking phase walks back from the end node, collects a
//!    separate ranking from each rank-one node and merges them by best rank.
//!    `W_forward(v) + W_backward(v)` is the weight of the heaviest path
//!    through `v`, which yields exactly the same rank-one set (asserted in
//!    `tests`), gives every node a total order rather than a merged one, and
//!    is `O(layers * K^2)` in one more sweep.
//! 5. **Adjacency has one grouping level, not four.** Alg. 1 adds 0.7 for the
//!    same library, then 0.03 / 0.02 / 0.05 for version, optimisation level
//!    and compilation unit. A candidate pool drawn from one corpus slice fixes
//!    version and optimisation by construction, and we have no compilation-unit
//!    key that is not the library key, so only the 0.7 term is modelled --
//!    [`RerankSettings::adjacency_same_group`], the paper's constant.
//! 6. **No GPU.** Sections 4 and 5 of the paper are a parallel implementation
//!    of the same recurrence. The cost here is `layers * K^2` f64 additions.
//! 7. **The default turns the paper's two provenance terms off.** Not a change
//!    to the algorithm -- both are implemented, and
//!    [`RerankSettings::revdecode_paper`] runs them -- but a change to what a
//!    caller gets without asking, and it is measured rather than assumed. See
//!    the note on [`Default`].
//!
//! # Cost
//!
//! `O(sum_j K_{j-1} * K_j)` edge relaxations, twice (forward and backward), and
//! `O(sum_j K_j log K_j)` for the final sort. [`RerankResult::relaxations`]
//! reports the exact count so a caller can assert the bound.

mod context;
mod decode;
mod graph;

#[cfg(test)]
mod tests;

pub use context::{CallContext, GroupId};
pub use decode::{LayerRanking, RankedCandidate, RerankResult};
pub use graph::{Candidate, QueryFunction, QueryId, ReferenceId};

/// How a raw similarity is mapped into the edge weight.
///
/// The paper applies sigmoid normalisation to "emphasise small differences in
/// scores near the centre of the range while suppressing extreme values". Our
/// [`Candidate::similarity`] contract is already `[0, 1]` -- the harness
/// `Scheme` trait enforces it -- so there are no outliers to suppress, and
/// [`Normalization::Identity`] is the default. [`Normalization::Sigmoid`] is
/// kept because the paper's argument is about *spread*, not range, and a
/// scheme whose scores all bunch near zero is a real case.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Normalization {
    /// Use the similarity as given, clamped into `[0, 1]`.
    Identity,
    /// `1 / (1 + exp(-steepness * (s - centre)))`.
    Sigmoid { centre: f64, steepness: f64 },
}

impl Normalization {
    /// Map one similarity into `[0, 1]`.
    pub fn apply(self, similarity: f64) -> f64 {
        match self {
            Normalization::Identity => similarity.clamp(0.0, 1.0),
            Normalization::Sigmoid { centre, steepness } => {
                1.0 / (1.0 + (-steepness * (similarity - centre)).exp())
            }
        }
    }
}

/// Every knob, with the paper's constants where the paper has one.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RerankSettings {
    /// Candidates per layer.
    ///
    /// Ten, because a re-rank that has to reach past the tenth candidate is
    /// re-ranking noise: MRR10 and every Recall@k a retrieval protocol reports
    /// live inside the first ten. **Ties at the boundary are all admitted**, so
    /// a layer whose eleventh candidate scores exactly what its tenth scores
    /// carries more than `top_k` nodes -- otherwise an arbitrary index
    /// tie-break, rather than the decode, would decide which candidate got a
    /// chance.
    pub top_k: usize,
    /// Weight on the destination candidate's similarity.
    pub similarity_weight: f64,
    /// Weight on the destination candidate's [`Candidate::confidence`], when it
    /// has one.
    pub confidence_weight: f64,
    /// Weight on the destination candidate's library-uniqueness score.
    pub library_weight: f64,
    /// Weight on provenance agreement between the two endpoints.
    pub adjacency_weight: f64,
    /// Weight on call-graph agreement between the two endpoints.
    pub call_weight: f64,
    /// The adjacency score for two candidates from the same library. RevDecode
    /// Alg. 1's constant, tuned by its authors on 30 synthetic firmware samples
    /// against cumulative DCG.
    pub adjacency_same_group: f64,
    /// The "no match" node's similarity, or `None` to leave the node out.
    ///
    /// `Some(0.0)` by default: the node is present, and wins a layer only when
    /// every real candidate's edge scores no better than an empty answer.
    pub no_match_similarity: Option<f64>,
    pub normalization: Normalization,
}

/// The default settings are the **measured** ones and not the paper's:
/// similarity and call agreement on, RevDecode's two provenance terms off.
/// See [`RerankSettings::revdecode_paper`] for the faithful configuration and
/// for why it is available and named rather than automatic.
impl Default for RerankSettings {
    fn default() -> Self {
        Self {
            adjacency_weight: 0.0,
            library_weight: 0.0,
            ..Self::revdecode_paper()
        }
    }
}

impl RerankSettings {
    /// RevDecode's own configuration: every term the paper has, at the paper's
    /// constants.
    ///
    /// It is deliberately **not** [`Default`], because it is measurably worse
    /// on both of our corpora -- it moves 8 of 40 measured cells up and 31
    /// down, by as much as 0.225 MRR10, against 16 up and 0 down for the
    /// call-agreement term alone. The reasons are in
    /// `docs/reference/function-identity-rerank.md`; the short version is that
    /// Alg. 1's 0.7 constant was calibrated for firmware-sized libraries
    /// against sigmoid-spread similarities, and neither holds here. A default
    /// that loses on thirty-one of forty measured cells is a trap, so the
    /// faithful configuration is available and named rather than automatic.
    ///
    /// Faithful, and measurably worse than [`Default`] on both of our corpora.
    /// Use it to reproduce the paper's design, or on a corpus whose libraries
    /// are large enough for a provenance prior to mean something.
    pub fn revdecode_paper() -> Self {
        Self {
            top_k: 10,
            similarity_weight: 1.0,
            confidence_weight: 1.0,
            library_weight: 1.0,
            adjacency_weight: 1.0,
            call_weight: 1.0,
            adjacency_same_group: 0.7,
            no_match_similarity: Some(0.0),
            normalization: Normalization::Identity,
        }
    }

    /// Similarity only: every context term off.
    ///
    /// The null hypothesis. A re-rank under these settings reproduces the input
    /// ordering exactly, which is what makes any movement under any other
    /// settings attributable to context rather than to the machinery.
    pub fn similarity_only() -> Self {
        Self {
            confidence_weight: 0.0,
            library_weight: 0.0,
            adjacency_weight: 0.0,
            call_weight: 0.0,
            ..Self::revdecode_paper()
        }
    }

    /// Similarity plus the call-graph agreement term, with RevDecode's
    /// provenance terms off. Identical to [`Default`]; spelled out so an
    /// ablation table can name what it ran.
    pub fn call_graph_only() -> Self {
        Self::default()
    }

    /// Similarity plus RevDecode's provenance terms, with the call-graph term
    /// off. The paper's configuration, minus the confidence score.
    pub fn adjacency_only() -> Self {
        Self {
            confidence_weight: 0.0,
            call_weight: 0.0,
            ..Self::revdecode_paper()
        }
    }
}

/// Re-rank every query's candidate list against the others.
///
/// `queries` may arrive in any order; layers are built in `(order_key, id)`
/// order, which is a total order, so the layer sequence is fixed by the input
/// rather than by the caller's `Vec` order.
pub fn rerank(
    queries: &[QueryFunction],
    context: &CallContext,
    settings: &RerankSettings,
) -> RerankResult {
    let layers = graph::build_layers(queries, settings);
    decode::decode(&layers, context, settings)
}
