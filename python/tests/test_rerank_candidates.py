"""The RevDecode-style candidate re-rank, through its Python surface.

The algorithm's own properties -- the maximum-weight path, the rank-one set
against brute-force enumeration, the ``layers * K^2`` relaxation bound -- are
asserted on the Rust side in ``src/identity/rerank/tests.rs``, and the corpus
measurement lives in ``tests/identity_retrieval/rerank.rs``. What is checked
here is what crosses the boundary: that the argument shapes are the ones the
docstring promises, that context reaches the decode, and that the "no match"
node is reachable from Python.

The reference page is ``docs/reference/function-identity-rerank.md``.
"""

from __future__ import annotations

from glaurung import analysis

# Query 0 calls query 1. The matcher's top-1 is `10` for query 0 and `21` for
# query 1, and both are wrong: in the reference corpus it is `11` that calls
# `20`. The only consistent pair is the one the matcher ranked second twice.
TWO_LAYERS = [
    (0, 0x1000, [(10, 0.90), (11, 0.80)]),
    (1, 0x2000, [(20, 0.80), (21, 0.90)]),
]

# Everything but the similarity term, so a test reads what it says it reads.
CONTEXT_OFF = {
    "confidence_weight": 0.0,
    "library_weight": 0.0,
    "adjacency_weight": 0.0,
    "call_weight": 0.0,
}


def _order(ranked: list[tuple[int | None, float]]) -> list[int | None]:
    return [reference for reference, _score in ranked]


def test_without_context_the_matcher_ordering_stands() -> None:
    """The null hypothesis. With every context term off the decode is a no-op."""
    result = analysis.rerank_candidates(TWO_LAYERS, **CONTEXT_OFF)
    assert [query for query, _ in result] == [0, 1]
    assert _order(result[0][1]) == [10, 11, None]
    assert _order(result[1][1]) == [21, 20, None]


def test_call_graph_context_overturns_a_wrong_top_one() -> None:
    """The case the stage exists for, reached through the binding."""
    weights = dict(CONTEXT_OFF)
    weights.pop("call_weight")
    result = analysis.rerank_candidates(
        TWO_LAYERS,
        query_calls=[(0, 1)],
        reference_calls=[(11, 20)],
        **weights,
    )
    assert _order(result[0][1])[0] == 11
    assert _order(result[1][1])[0] == 20


def test_a_call_edge_in_the_wrong_direction_is_worth_nothing() -> None:
    """The term rewards a reproduced direction, not a relation of any kind."""
    weights = dict(CONTEXT_OFF)
    weights.pop("call_weight")
    result = analysis.rerank_candidates(
        TWO_LAYERS,
        query_calls=[(0, 1)],
        reference_calls=[(21, 11)],
        **weights,
    )
    assert _order(result[0][1])[0] == 10
    assert _order(result[1][1])[0] == 21


def test_the_no_match_node_is_reachable_and_can_win() -> None:
    """``None`` is the paper's *uncertain* node: nothing here is the answer."""
    weak = [(0, 0, [(1, 0.30), (2, 0.20)])]
    result = analysis.rerank_candidates(weak, no_match_similarity=0.5, **CONTEXT_OFF)
    assert _order(result[0][1]) == [None, 1, 2]

    # Removing the node removes the option, rather than burying it.
    without = analysis.rerank_candidates(weak, no_match_similarity=None, **CONTEXT_OFF)
    assert _order(without[0][1]) == [1, 2]


def test_adjacency_prefers_two_candidates_from_one_library() -> None:
    """RevDecode Alg. 1, with the library-uniqueness term held out.

    Both terms are the paper's and they pull against each other here: `10` and
    `20` are singleton libraries, so Eq. 8 scores them higher than the shared
    library `11` and `21` come from. The measured table records the same
    interaction on real corpora.
    """
    queries = [
        (0, 0x1000, [(10, 0.90), (11, 0.60)]),
        (1, 0x2000, [(20, 0.90), (21, 0.60)]),
    ]
    groups = [(10, 1), (20, 2), (11, 3), (21, 3)]
    result = analysis.rerank_candidates(
        queries,
        reference_groups=groups,
        confidence_weight=0.0,
        library_weight=0.0,
        call_weight=0.0,
    )
    assert _order(result[0][1])[0] == 11
    assert _order(result[1][1])[0] == 21


def test_top_k_truncates_and_layers_follow_the_order_key() -> None:
    candidates = [(i, 1.0 - i / 100.0) for i in range(20)]
    queries = [(7, 0x2000, candidates), (3, 0x1000, candidates)]
    result = analysis.rerank_candidates(queries, top_k=4, **CONTEXT_OFF)
    assert [query for query, _ in result] == [3, 7]
    for _query, ranked in result:
        assert _order(ranked) == [0, 1, 2, 3, None]


def test_the_decode_is_deterministic_across_calls() -> None:
    first = analysis.rerank_candidates(
        TWO_LAYERS, query_calls=[(0, 1)], reference_calls=[(11, 20)]
    )
    second = analysis.rerank_candidates(
        TWO_LAYERS, query_calls=[(0, 1)], reference_calls=[(11, 20)]
    )
    assert first == second


def test_an_empty_query_list_decodes_to_nothing() -> None:
    assert analysis.rerank_candidates([]) == []
