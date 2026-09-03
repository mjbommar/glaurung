//! Hand-built layered graphs with known optimal paths.
//!
//! Every graph here is small enough to solve by hand or by brute force, which
//! is the point: a decode measured only on a corpus is a decode whose
//! arithmetic nobody has checked. The corpus measurement lives in
//! `tests/identity_retrieval/`.

use super::*;

/// Three queries, three candidates each, no context at all.
fn plain_queries() -> Vec<QueryFunction> {
    vec![
        QueryFunction {
            id: 0,
            order_key: 0x1000,
            candidates: vec![
                Candidate::new(10, 0.9),
                Candidate::new(11, 0.5),
                Candidate::new(12, 0.1),
            ],
        },
        QueryFunction {
            id: 1,
            order_key: 0x2000,
            candidates: vec![
                Candidate::new(20, 0.8),
                Candidate::new(21, 0.6),
                Candidate::new(22, 0.2),
            ],
        },
        QueryFunction {
            id: 2,
            order_key: 0x3000,
            candidates: vec![
                Candidate::new(30, 0.7),
                Candidate::new(31, 0.4),
                Candidate::new(32, 0.3),
            ],
        },
    ]
}

fn references(ranking: &LayerRanking) -> Vec<Option<ReferenceId>> {
    ranking.ranked.iter().map(|c| c.reference).collect()
}

/// With every context term off, the decode must return exactly the matcher's
/// own ordering.
///
/// This is the null hypothesis for every measured number: if the machinery
/// moved rankings on its own, no movement under the full settings could be
/// attributed to context.
#[test]
fn similarity_only_reproduces_the_input_ordering() {
    let queries = plain_queries();
    let result = rerank(
        &queries,
        &CallContext::new(),
        &RerankSettings::similarity_only(),
    );
    assert_eq!(result.layers.len(), 3);
    assert_eq!(
        references(&result.layers[0]),
        vec![Some(10), Some(11), Some(12), None]
    );
    assert_eq!(
        references(&result.layers[1]),
        vec![Some(20), Some(21), Some(22), None]
    );
    assert_eq!(
        references(&result.layers[2]),
        vec![Some(30), Some(31), Some(32), None]
    );
}

/// Layers are ordered by `order_key`, not by the caller's `Vec` order.
#[test]
fn layer_order_follows_the_order_key() {
    let mut queries = plain_queries();
    queries.reverse();
    let result = rerank(
        &queries,
        &CallContext::new(),
        &RerankSettings::similarity_only(),
    );
    assert_eq!(
        result.layers.iter().map(|l| l.query).collect::<Vec<_>>(),
        vec![0, 1, 2]
    );
}

/// **The case the whole stage exists for.** The matcher's top-1 is wrong, and
/// the call graph fixes it.
///
/// Query 0 calls query 1. The matcher likes `10` best for query 0 (0.90 against
/// `11`'s 0.80) and `21` best for query 1 (0.90 against `20`'s 0.80). But in
/// the reference corpus it is `11` that calls `20`; `10` calls nothing. Two
/// wrong top-1 answers, and the only consistent pair is the pair the matcher
/// ranked second in both layers.
#[test]
fn call_graph_context_overturns_a_wrong_top_one() {
    let queries = vec![
        QueryFunction {
            id: 0,
            order_key: 0x1000,
            candidates: vec![Candidate::new(10, 0.90), Candidate::new(11, 0.80)],
        },
        QueryFunction {
            id: 1,
            order_key: 0x2000,
            candidates: vec![Candidate::new(20, 0.80), Candidate::new(21, 0.90)],
        },
    ];

    let mut context = CallContext::new();
    context.add_query_call(0, 1);
    context.add_reference_call(11, 20);

    // Without context, the matcher's order stands.
    let plain = rerank(&queries, &context, &RerankSettings::similarity_only());
    assert_eq!(plain.layers[0].ranked[0].reference, Some(10));
    assert_eq!(plain.layers[1].ranked[0].reference, Some(21));

    // With it, the consistent pair wins both layers. The call term is worth
    // 1.0 and the similarity gap is 0.10 each way, so the decode prefers
    // (11, 20) by 0.80.
    let decoded = rerank(&queries, &context, &RerankSettings::call_graph_only());
    assert_eq!(decoded.layers[0].ranked[0].reference, Some(11));
    assert_eq!(decoded.layers[1].ranked[0].reference, Some(20));
    assert_eq!(decoded.layers[0].pessimistic_rank(11), Some(1));
    assert_eq!(decoded.layers[0].pessimistic_rank(10), Some(2));
}

/// A call agreement in the *wrong direction* is worth nothing.
///
/// Query 0 calls query 1; in the corpus `21` calls `11`, the reverse. Nothing
/// is rewarded and the matcher's order stands. Without this the term would be
/// a "these two are related somehow" bonus, which is a much weaker claim than
/// the one the module documents.
#[test]
fn call_agreement_is_directional() {
    let queries = vec![
        QueryFunction {
            id: 0,
            order_key: 0x1000,
            candidates: vec![Candidate::new(10, 0.90), Candidate::new(11, 0.80)],
        },
        QueryFunction {
            id: 1,
            order_key: 0x2000,
            candidates: vec![Candidate::new(20, 0.80), Candidate::new(21, 0.90)],
        },
    ];
    let mut context = CallContext::new();
    context.add_query_call(0, 1);
    context.add_reference_call(21, 11);

    let decoded = rerank(&queries, &context, &RerankSettings::call_graph_only());
    assert_eq!(decoded.layers[0].ranked[0].reference, Some(10));
    assert_eq!(decoded.layers[1].ranked[0].reference, Some(21));
}

/// Mutual recursion reproduced in one direction only is worth half a point.
#[test]
fn one_of_two_query_directions_scores_a_half() {
    let context = {
        let mut c = CallContext::new();
        c.add_query_call(0, 1);
        c.add_query_call(1, 0);
        c.add_reference_call(11, 20);
        c
    };
    assert_eq!(context.call_agreement(0, 1, 11, 20), 0.5);
    context_both_directions();
}

fn context_both_directions() {
    let mut c = CallContext::new();
    c.add_query_call(0, 1);
    c.add_query_call(1, 0);
    c.add_reference_call(11, 20);
    c.add_reference_call(20, 11);
    assert_eq!(c.call_agreement(0, 1, 11, 20), 1.0);
}

/// **The case where "no match" must win.** Every candidate is a weak,
/// context-free guess and the corpus does not contain the function.
///
/// The threshold is set to 0.5; the best candidate scores 0.30, has no library
/// and no call relation, so nothing lifts it above an empty answer.
#[test]
fn no_match_wins_when_nothing_has_support() {
    let queries = vec![
        QueryFunction {
            id: 0,
            order_key: 0x1000,
            candidates: vec![Candidate::new(10, 0.30), Candidate::new(11, 0.20)],
        },
        QueryFunction {
            id: 1,
            order_key: 0x2000,
            candidates: vec![Candidate::new(20, 0.25), Candidate::new(21, 0.10)],
        },
    ];
    let settings = RerankSettings {
        no_match_similarity: Some(0.5),
        ..RerankSettings::call_graph_only()
    };
    let decoded = rerank(&queries, &CallContext::new(), &settings);
    assert_eq!(decoded.layers[0].ranked[0].reference, None);
    assert_eq!(decoded.layers[1].ranked[0].reference, None);

    // ...and a candidate with real contextual support beats the same
    // threshold. Query 0 calls query 1 and `11 -> 20` reproduces it, worth a
    // full point on top of 0.20.
    let mut context = CallContext::new();
    context.add_query_call(0, 1);
    context.add_reference_call(11, 20);
    let supported = rerank(&queries, &context, &settings);
    assert_eq!(supported.layers[0].ranked[0].reference, Some(11));
    assert_eq!(supported.layers[1].ranked[0].reference, Some(20));
}

/// At the default threshold of 0.0 the node is in the graph and never wins
/// against a candidate scoring above zero. This is the configuration every
/// measured number in the docs was produced under.
#[test]
fn the_default_no_match_node_never_displaces_a_scoring_candidate() {
    let queries = plain_queries();
    let decoded = rerank(&queries, &CallContext::new(), &RerankSettings::default());
    for layer in &decoded.layers {
        assert_eq!(layer.ranked.last().expect("non-empty").reference, None);
    }
}

/// RevDecode's adjacency: two candidates from the same library reinforce each
/// other, and that is enough to overturn a wrong top-1 with no call edge in
/// sight.
#[test]
fn adjacency_prefers_a_consistent_library() {
    let queries = vec![
        QueryFunction {
            id: 0,
            order_key: 0x1000,
            candidates: vec![Candidate::new(10, 0.90), Candidate::new(11, 0.60)],
        },
        QueryFunction {
            id: 1,
            order_key: 0x2000,
            candidates: vec![Candidate::new(20, 0.90), Candidate::new(21, 0.60)],
        },
    ];
    let mut context = CallContext::new();
    // `11` and `21` are the same library; `10` and `20` are two different ones.
    context.set_reference_group(10, 1);
    context.set_reference_group(20, 2);
    context.set_reference_group(11, 3);
    context.set_reference_group(21, 3);

    // The library term is off here so the adjacency term is measured alone --
    // and the two genuinely pull against each other. With `library_weight` at
    // its default this exact graph goes the other way: `10` and `20` sit in
    // singleton libraries and score 0.75 apiece under Eq. 8, while `11` and
    // `21` share one and score 0.50, so 0.50 of library advantage plus 0.60 of
    // similarity advantage outweighs the 0.70 adjacency reward. That is not a
    // bug in either term; it is what "a candidate from a rare library is
    // stronger evidence" means when the rare library is a singleton, and it is
    // why the measured table reports the ablations separately.
    let settings = RerankSettings {
        library_weight: 0.0,
        ..RerankSettings::adjacency_only()
    };
    let decoded = rerank(&queries, &context, &settings);
    assert_eq!(decoded.layers[0].ranked[0].reference, Some(11));
    assert_eq!(decoded.layers[1].ranked[0].reference, Some(21));

    let with_library = rerank(&queries, &context, &RerankSettings::adjacency_only());
    assert_eq!(with_library.layers[0].ranked[0].reference, Some(10));
}

/// RevDecode Eq. 8, checked against the arithmetic rather than against itself.
#[test]
fn library_score_is_one_minus_the_library_share() {
    let mut context = CallContext::new();
    for reference in 0..8u32 {
        context.set_reference_group(reference, u32::from(reference >= 2));
    }
    assert_eq!(context.corpus_functions(), 8);
    // Group 0 holds 2 of 8, group 1 holds 6 of 8.
    assert_eq!(context.library_score(0), 1.0 - 2.0 / 8.0);
    assert_eq!(context.library_score(7), 1.0 - 6.0 / 8.0);
    // An unknown provenance is no evidence, not maximum evidence.
    assert_eq!(context.library_score(99), 0.0);
}

/// Every candidate tied with the `top_k`-th is admitted, so no arbitrary
/// tie-break decides who gets a chance at re-ranking.
#[test]
fn boundary_ties_are_all_admitted() {
    let candidates: Vec<Candidate> = (0..20u32).map(|i| Candidate::new(i, 0.5)).collect();
    let queries = vec![QueryFunction {
        id: 0,
        order_key: 0,
        candidates,
    }];
    let decoded = rerank(&queries, &CallContext::new(), &RerankSettings::default());
    // 20 tied candidates plus the "no match" node.
    assert_eq!(decoded.layers[0].ranked.len(), 21);
    // ...and every one of them is still tied, so the pessimistic rank of each
    // is 20: the decode had no context and invented no separation.
    assert_eq!(decoded.layers[0].pessimistic_rank(0), Some(20));
}

/// Below the boundary, `top_k` truncates.
#[test]
fn top_k_truncates_a_clearly_ordered_layer() {
    let candidates: Vec<Candidate> = (0..20u32)
        .map(|i| Candidate::new(i, 1.0 - f64::from(i) / 100.0))
        .collect();
    let queries = vec![QueryFunction {
        id: 0,
        order_key: 0,
        candidates,
    }];
    let settings = RerankSettings {
        top_k: 4,
        ..RerankSettings::default()
    };
    let decoded = rerank(&queries, &CallContext::new(), &settings);
    assert_eq!(decoded.layers[0].ranked.len(), 5);
    assert_eq!(
        references(&decoded.layers[0]),
        vec![Some(0), Some(1), Some(2), Some(3), None]
    );
}

/// Brute force: enumerate every path through a small graph, and check that the
/// DP's best weight and its rank-one set agree with the definitions.
///
/// This is the test that says the backward-pass simplification (departure 4 in
/// the module docs) is a simplification and not a change: the rank-one set
/// computed as `argmax(W + B)` is exactly the set of nodes lying on some
/// maximum-weight path.
#[test]
fn the_dp_agrees_with_brute_force_enumeration() {
    let queries = plain_queries();
    let mut context = CallContext::new();
    context.set_reference_group(10, 1);
    context.set_reference_group(11, 2);
    context.set_reference_group(12, 2);
    context.set_reference_group(20, 2);
    context.set_reference_group(21, 1);
    context.set_reference_group(22, 3);
    context.set_reference_group(30, 3);
    context.set_reference_group(31, 2);
    context.set_reference_group(32, 1);
    context.add_query_call(0, 2);
    context.add_query_call(1, 2);
    context.add_reference_call(11, 30);
    context.add_reference_call(21, 31);
    let settings = RerankSettings::default();

    let decoded = rerank(&queries, &context, &settings);

    // Re-derive every path weight from the layer contents alone.
    let layers: Vec<(QueryId, Vec<(Option<ReferenceId>, f64, Option<f64>)>)> = decoded
        .layers
        .iter()
        .map(|layer| {
            let mut nodes: Vec<(Option<ReferenceId>, f64, Option<f64>)> = layer
                .ranked
                .iter()
                .map(|c| (c.reference, c.similarity, None))
                .collect();
            nodes.sort_by(|a, b| b.1.total_cmp(&a.1).then(a.0.cmp(&b.0)));
            (layer.query, nodes)
        })
        .collect();

    let weight_of = |from: Option<(QueryId, (Option<ReferenceId>, f64, Option<f64>))>,
                     to: (QueryId, (Option<ReferenceId>, f64, Option<f64>))|
     -> f64 {
        let (to_query, (to_ref, to_sim, _)) = to;
        let mut w = settings.normalization.apply(to_sim);
        if let Some(r) = to_ref {
            w += context.library_score(r);
        }
        if let (Some((from_query, (Some(from_ref), _, _))), Some(to_ref)) = (from, to_ref) {
            w += context.adjacency_score(from_ref, to_ref, settings.adjacency_same_group);
            w += context.call_agreement(from_query, to_query, from_ref, to_ref);
        }
        w
    };

    let mut best = f64::NEG_INFINITY;
    let mut on_best: Vec<Vec<Option<ReferenceId>>> = vec![Vec::new(); layers.len()];
    let counts: Vec<usize> = layers.iter().map(|(_, n)| n.len()).collect();
    let total: usize = counts.iter().product();
    for encoded in 0..total {
        let mut picks = Vec::with_capacity(counts.len());
        let mut rest = encoded;
        for count in &counts {
            picks.push(rest % count);
            rest /= count;
        }
        let mut weight = 0.0;
        for (index, pick) in picks.iter().enumerate() {
            let from = index
                .checked_sub(1)
                .map(|p| (layers[p].0, layers[p].1[picks[p]]));
            weight += weight_of(from, (layers[index].0, layers[index].1[*pick]));
        }
        if weight > best {
            best = weight;
            on_best = vec![Vec::new(); layers.len()];
        }
        if weight == best {
            for (index, pick) in picks.iter().enumerate() {
                let reference = layers[index].1[*pick].0;
                if !on_best[index].contains(&reference) {
                    on_best[index].push(reference);
                }
            }
        }
    }

    assert!(
        (decoded.best_path_weight - best).abs() < 1e-12,
        "DP best {} vs brute force {best}",
        decoded.best_path_weight
    );
    for (index, layer) in decoded.layers.iter().enumerate() {
        let mut dp_best: Vec<Option<ReferenceId>> =
            layer.best().iter().map(|c| c.reference).collect();
        dp_best.sort();
        let mut enumerated = on_best[index].clone();
        enumerated.sort();
        assert_eq!(
            dp_best, enumerated,
            "layer {index}: rank-one set disagrees with brute force"
        );
    }
}

/// Byte-identical output on a repeat run, and independent of the order the
/// caller happened to build its `Vec`s in.
#[test]
fn the_decode_is_deterministic() {
    let queries = plain_queries();
    let mut context = CallContext::new();
    context.add_query_call(0, 1);
    context.add_reference_call(11, 20);
    context.set_reference_group(10, 1);
    context.set_reference_group(20, 1);

    let first = rerank(&queries, &context, &RerankSettings::default());
    let second = rerank(&queries, &context, &RerankSettings::default());
    assert_eq!(first, second);

    // Same input, different insertion order, same answer.
    let mut shuffled = queries.clone();
    shuffled.reverse();
    for query in &mut shuffled {
        query.candidates.reverse();
    }
    let mut rebuilt = CallContext::new();
    rebuilt.set_reference_group(20, 1);
    rebuilt.set_reference_group(10, 1);
    rebuilt.add_reference_call(11, 20);
    rebuilt.add_query_call(0, 1);
    let third = rerank(&shuffled, &rebuilt, &RerankSettings::default());
    assert_eq!(first, third);
}

/// The cost claim, asserted rather than commented: `2 * sum_j K_{j-1} * K_j`
/// edge relaxations, which is bounded by `2 * layers * K^2`.
#[test]
fn relaxations_are_bounded_by_layers_times_k_squared() {
    let k = 10usize;
    let layers = 40usize;
    let queries: Vec<QueryFunction> = (0..layers)
        .map(|j| QueryFunction {
            id: j as QueryId,
            order_key: (j as u64) * 0x100,
            candidates: (0..k)
                .map(|i| {
                    Candidate::new(
                        (j * 100 + i) as ReferenceId,
                        1.0 - (i as f64) / (k as f64) / 2.0,
                    )
                })
                .collect(),
        })
        .collect();
    let decoded = rerank(&queries, &CallContext::new(), &RerankSettings::default());

    // Each layer carries K candidates plus the "no match" node.
    let per_layer = (k + 1) * (k + 1);
    let expected = 2 * (layers - 1) * per_layer;
    assert_eq!(decoded.relaxations, expected as u64);
    assert!(decoded.relaxations <= (2 * layers * per_layer) as u64);
}

/// A single layer decodes to the matcher's own order and performs no
/// relaxations at all: with no neighbour there is no context, and the stage
/// must not pretend otherwise.
#[test]
fn one_layer_is_a_no_op() {
    let queries = vec![QueryFunction {
        id: 7,
        order_key: 0,
        candidates: vec![Candidate::new(1, 0.2), Candidate::new(2, 0.9)],
    }];
    let decoded = rerank(&queries, &CallContext::new(), &RerankSettings::default());
    assert_eq!(decoded.relaxations, 0);
    assert_eq!(references(&decoded.layers[0]), vec![Some(2), Some(1), None]);
}

/// An empty input is an empty result, not a panic.
#[test]
fn no_queries_decodes_to_nothing() {
    let decoded = rerank(&[], &CallContext::new(), &RerankSettings::default());
    assert!(decoded.layers.is_empty());
    assert_eq!(decoded.best_path_weight, 0.0);
    assert_eq!(decoded.relaxations, 0);
}

/// A confidence score, when a matcher supplies one, enters the weight.
#[test]
fn confidence_enters_the_weight_when_it_is_supplied() {
    let queries = vec![QueryFunction {
        id: 0,
        order_key: 0,
        candidates: vec![
            Candidate::new(1, 0.60),
            Candidate::new(2, 0.50).with_confidence(0.9),
        ],
    }];
    let settings = RerankSettings {
        library_weight: 0.0,
        ..RerankSettings::default()
    };
    let decoded = rerank(&queries, &CallContext::new(), &settings);
    assert_eq!(decoded.layers[0].ranked[0].reference, Some(2));
}

/// Sigmoid normalisation is monotone and lands in `[0, 1]`, which is all the
/// decode needs of it.
#[test]
fn sigmoid_normalisation_is_monotone() {
    let sigmoid = Normalization::Sigmoid {
        centre: 0.5,
        steepness: 8.0,
    };
    let mut previous = f64::NEG_INFINITY;
    for step in 0..=20 {
        let value = sigmoid.apply(f64::from(step) / 20.0);
        assert!((0.0..=1.0).contains(&value));
        assert!(value > previous);
        previous = value;
    }
    assert!((sigmoid.apply(0.5) - 0.5).abs() < 1e-12);
}
