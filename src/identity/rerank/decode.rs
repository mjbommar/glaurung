//! The decode: a forward Viterbi pass, a backward pass, and the ranking.
//!
//! # The recurrence
//!
//! RevDecode Eq. 1-3, with `W(v_start) = 0` and every edge into the end node
//! weighted zero:
//!
//! ```text
//! W(v_{i,1}) = w(start, v_{i,1})
//! W(v_{i,j}) = max_k [ W(v_{k,j-1}) + w(v_{k,j-1}, v_{i,j}) ]
//! ```
//!
//! and its mirror towards the end, `B(v_{i,n}) = 0` and
//! `B(v_{i,j}) = max_k [ w(v_{i,j}, v_{k,j+1}) + B(v_{k,j+1}) ]`.
//!
//! `W(v) + B(v)` is the weight of the heaviest path through `v`. Its maximum
//! over a layer is the weight of the maximum-weight path through the whole
//! graph, so the nodes attaining it are exactly the paper's rank-one set --
//! and unlike the paper's merged backward walk it also orders every other node
//! by how much weight is lost by routing through it, which is precisely "the
//! proximity of the candidates to that path" the paper's ranking phase is
//! after.

use std::cmp::Ordering;

use super::context::CallContext;
use super::graph::{Layer, Node, QueryId, ReferenceId};
use super::RerankSettings;

/// One candidate after re-ranking.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RankedCandidate {
    /// `None` is the "no match" node. Candidates below it in the list have less
    /// contextual support than an empty answer.
    pub reference: Option<ReferenceId>,
    /// `W(v) + B(v)`: the weight of the heaviest path through this node.
    pub score: f64,
    /// The similarity the underlying matcher gave, unchanged.
    pub similarity: f64,
}

/// One query function's re-ranked candidate list.
#[derive(Clone, Debug, PartialEq)]
pub struct LayerRanking {
    pub query: QueryId,
    /// Best first, under the total order `compare_nodes` in this module:
    /// score, then the matcher's own similarity, then the reference id, with
    /// the "no match" node last among equals.
    pub ranked: Vec<RankedCandidate>,
}

impl LayerRanking {
    /// The pessimistic rank of one reference in this layer: `1 +` the number of
    /// *other* nodes scoring at least as well.
    ///
    /// Pessimistic because that is the rule `tests/identity_retrieval` scores
    /// under, and a before/after comparison whose two halves use different tie
    /// rules is not a comparison. `None` when the reference is not in the
    /// layer.
    pub fn pessimistic_rank(&self, reference: ReferenceId) -> Option<usize> {
        let target = self
            .ranked
            .iter()
            .find(|c| c.reference == Some(reference))?;
        let ahead = self
            .ranked
            .iter()
            .filter(|c| c.reference != Some(reference) && c.score >= target.score)
            .count();
        Some(ahead + 1)
    }

    /// The rank-one set: every node on a maximum-weight path.
    pub fn best(&self) -> Vec<RankedCandidate> {
        let Some(top) = self.ranked.first() else {
            return Vec::new();
        };
        self.ranked
            .iter()
            .take_while(|c| c.score == top.score)
            .copied()
            .collect()
    }
}

/// Everything the decode produced.
#[derive(Clone, Debug, PartialEq)]
pub struct RerankResult {
    /// One entry per layer, in layer order.
    pub layers: Vec<LayerRanking>,
    /// The weight of the maximum-weight path through the whole graph.
    pub best_path_weight: f64,
    /// Edge relaxations performed, forward and backward passes together.
    ///
    /// Reported rather than merely bounded so the complexity claim
    /// (`2 * sum_j K_{j-1} * K_j`) is a measured assertion in the tests instead
    /// of a comment.
    pub relaxations: u64,
}

/// The edge weight `w(u, v)` between a node in `from_layer` and one in
/// `to_layer`.
///
/// The destination-only terms (similarity, confidence, library) are what a
/// per-function matcher already knows. The pairwise terms (adjacency, call
/// agreement) are the context, and they are the only reason a decode can
/// disagree with the matcher.
fn edge_weight(
    from: Option<(QueryId, &Node)>,
    to: (QueryId, &Node),
    context: &CallContext,
    settings: &RerankSettings,
) -> f64 {
    let (to_query, to_node) = to;
    let mut weight = settings.similarity_weight * to_node.normalized;
    if let Some(confidence) = to_node.confidence {
        weight += settings.confidence_weight * confidence;
    }
    if let Some(reference) = to_node.reference {
        weight += settings.library_weight * context.library_score(reference);
    }
    let (Some((from_query, from_node)), Some(to_reference)) = (from, to_node.reference) else {
        // Either this is a start edge, or the destination is the "no match"
        // node, which by construction has no library and no call relation.
        return weight;
    };
    let Some(from_reference) = from_node.reference else {
        return weight;
    };
    weight += settings.adjacency_weight
        * context.adjacency_score(from_reference, to_reference, settings.adjacency_same_group);
    weight += settings.call_weight
        * context.call_agreement(from_query, to_query, from_reference, to_reference);
    weight
}

/// The total order candidates are ranked by.
///
/// Score first; then the underlying matcher's similarity, so a decode that
/// cannot separate two nodes falls back to what the matcher said rather than to
/// an index; then the reference id, with the "no match" node last among equals,
/// because a real answer and an admission of ignorance that score identically
/// should not be resolved in favour of the admission.
fn compare_nodes(a: &RankedCandidate, b: &RankedCandidate) -> Ordering {
    b.score
        .total_cmp(&a.score)
        .then(b.similarity.total_cmp(&a.similarity))
        .then_with(|| match (a.reference, b.reference) {
            (Some(x), Some(y)) => x.cmp(&y),
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (None, None) => Ordering::Equal,
        })
}

pub(super) fn decode(
    layers: &[Layer],
    context: &CallContext,
    settings: &RerankSettings,
) -> RerankResult {
    let mut relaxations = 0u64;

    // Forward: W(v).
    let mut forward: Vec<Vec<f64>> = Vec::with_capacity(layers.len());
    for (index, layer) in layers.iter().enumerate() {
        let mut row = Vec::with_capacity(layer.nodes.len());
        for node in &layer.nodes {
            if index == 0 {
                row.push(edge_weight(None, (layer.query, node), context, settings));
                continue;
            }
            let previous = &layers[index - 1];
            let mut best = f64::NEG_INFINITY;
            for (k, from_node) in previous.nodes.iter().enumerate() {
                let w = forward[index - 1][k]
                    + edge_weight(
                        Some((previous.query, from_node)),
                        (layer.query, node),
                        context,
                        settings,
                    );
                relaxations += 1;
                if w > best {
                    best = w;
                }
            }
            // An empty previous layer cannot happen while the "no match" node
            // is enabled, but a caller who disabled it and passed a query with
            // no candidates would otherwise poison every later layer with
            // -inf. Treat an unreachable predecessor as weight zero: the layer
            // simply contributes nothing to the path.
            row.push(if best.is_finite() {
                best
            } else {
                edge_weight(None, (layer.query, node), context, settings)
            });
        }
        forward.push(row);
    }

    // Backward: B(v).
    let mut backward: Vec<Vec<f64>> = layers.iter().map(|l| vec![0.0; l.nodes.len()]).collect();
    for index in (0..layers.len().saturating_sub(1)).rev() {
        let next = &layers[index + 1];
        for (i, from_node) in layers[index].nodes.iter().enumerate() {
            let mut best = f64::NEG_INFINITY;
            for (k, to_node) in next.nodes.iter().enumerate() {
                let w = edge_weight(
                    Some((layers[index].query, from_node)),
                    (next.query, to_node),
                    context,
                    settings,
                ) + backward[index + 1][k];
                relaxations += 1;
                if w > best {
                    best = w;
                }
            }
            backward[index][i] = if best.is_finite() { best } else { 0.0 };
        }
    }

    let mut best_path_weight = f64::NEG_INFINITY;
    let mut ranked_layers = Vec::with_capacity(layers.len());
    for (index, layer) in layers.iter().enumerate() {
        let mut ranked: Vec<RankedCandidate> = layer
            .nodes
            .iter()
            .enumerate()
            .map(|(i, node)| RankedCandidate {
                reference: node.reference,
                score: forward[index][i] + backward[index][i],
                similarity: node.similarity,
            })
            .collect();
        ranked.sort_by(compare_nodes);
        if let Some(top) = ranked.first() {
            if top.score > best_path_weight {
                best_path_weight = top.score;
            }
        }
        ranked_layers.push(LayerRanking {
            query: layer.query,
            ranked,
        });
    }

    RerankResult {
        layers: ranked_layers,
        best_path_weight: if best_path_weight.is_finite() {
            best_path_weight
        } else {
            0.0
        },
        relaxations,
    }
}
