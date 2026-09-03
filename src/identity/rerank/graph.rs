//! The layered candidate graph: one layer per query function, one node per
//! candidate, plus the "no match" node.

use super::{Normalization, RerankSettings};

/// A query function's identity for the life of one re-rank.
///
/// Opaque to this module. Callers use an index into their own query list; the
/// harness uses the index into the sorted query slice.
pub type QueryId = u32;

/// A reference-corpus function's identity for the life of one re-rank.
///
/// Opaque here too. The harness uses the candidate's index in the pool slice;
/// a KB-backed caller would use a `function_identity` row id.
pub type ReferenceId = u32;

/// One candidate match for one query function, as some other scheme scored it.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Candidate {
    pub reference: ReferenceId,
    /// The underlying matcher's similarity, in `[0, 1]`.
    pub similarity: f64,
    /// RevDecode's confidence score (Eq. 7), if the matcher can supply one.
    ///
    /// `None` in every caller we ship; see departure 2 in the module docs.
    pub confidence: Option<f64>,
}

impl Candidate {
    pub fn new(reference: ReferenceId, similarity: f64) -> Self {
        Self {
            reference,
            similarity,
            confidence: None,
        }
    }

    pub fn with_confidence(mut self, confidence: f64) -> Self {
        self.confidence = Some(confidence);
        self
    }
}

/// One query function and everything the underlying matcher said about it.
#[derive(Clone, Debug, PartialEq)]
pub struct QueryFunction {
    pub id: QueryId,
    /// What fixes this function's layer position. RevDecode orders layers by
    /// the unknown functions' memory offsets, on the argument that a compiler
    /// places a translation unit's functions contiguously; every caller we ship
    /// passes the entry VA for that reason.
    pub order_key: u64,
    /// Candidates in any order. The layer keeps the best `top_k` by similarity.
    pub candidates: Vec<Candidate>,
}

/// One node of the layered graph.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) struct Node {
    /// `None` for the "no match" node.
    pub reference: Option<ReferenceId>,
    /// The raw similarity, kept for the tie-break and for reporting.
    pub similarity: f64,
    /// The normalised similarity that enters the edge weight.
    pub normalized: f64,
    pub confidence: Option<f64>,
}

/// One layer: a query function and its admitted candidates.
#[derive(Clone, Debug, PartialEq)]
pub(super) struct Layer {
    pub query: QueryId,
    pub nodes: Vec<Node>,
}

/// Build the layers in `(order_key, id)` order, each holding its query's best
/// `top_k` candidates plus the "no match" node.
///
/// Selection is by `(similarity descending, reference ascending)`, and **every
/// candidate tied with the last admitted one is admitted too**. Without that a
/// layer whose candidates all score alike would have its membership decided by
/// the arbitrary `reference` tie-break, and the decode would then get credit
/// for promoting whichever candidate that arbitrary rule happened to let in.
pub(super) fn build_layers(queries: &[QueryFunction], settings: &RerankSettings) -> Vec<Layer> {
    let mut ordered: Vec<&QueryFunction> = queries.iter().collect();
    ordered.sort_by_key(|q| (q.order_key, q.id));

    ordered
        .into_iter()
        .map(|query| {
            let mut candidates = query.candidates.clone();
            candidates.sort_by(|a, b| {
                b.similarity
                    .total_cmp(&a.similarity)
                    .then(a.reference.cmp(&b.reference))
            });
            let admitted = admitted_count(&candidates, settings.top_k);

            let mut nodes: Vec<Node> = candidates[..admitted]
                .iter()
                .map(|c| Node {
                    reference: Some(c.reference),
                    similarity: c.similarity,
                    normalized: settings.normalization.apply(c.similarity),
                    confidence: c.confidence,
                })
                .collect();
            if let Some(threshold) = settings.no_match_similarity {
                nodes.push(Node {
                    reference: None,
                    similarity: threshold,
                    // The "no match" node is not a candidate whose score a
                    // matcher produced, so it is not normalised with the
                    // matcher's scores; the threshold is stated directly in
                    // weight units. `Identity` makes the two the same thing,
                    // which is why the default normalisation is the honest one.
                    normalized: Normalization::Identity.apply(threshold),
                    confidence: None,
                });
            }
            Layer {
                query: query.id,
                nodes,
            }
        })
        .collect()
}

/// How many of the sorted candidates are admitted: `top_k`, extended over every
/// candidate tied with the `top_k`-th.
fn admitted_count(sorted: &[Candidate], top_k: usize) -> usize {
    if sorted.len() <= top_k {
        return sorted.len();
    }
    if top_k == 0 {
        return 0;
    }
    let boundary = sorted[top_k - 1].similarity;
    let mut end = top_k;
    while end < sorted.len() && sorted[end].similarity == boundary {
        end += 1;
    }
    end
}
