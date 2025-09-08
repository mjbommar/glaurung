"""Python helpers for CTPH clustering built atop native similarity module."""

from __future__ import annotations

from typing import Iterable, List

import glaurung._native as _native  # type: ignore

# Re-export native CTPH primitives for convenience
ctph_hash_bytes = _native.similarity.ctph_hash_bytes
ctph_hash_path = _native.similarity.ctph_hash_path
ctph_similarity = _native.similarity.ctph_similarity
ctph_recommended_params = _native.similarity.ctph_recommended_params
ctph_pairwise_matrix = _native.similarity.ctph_pairwise_matrix
ctph_top_k = _native.similarity.ctph_top_k


def cluster_single_linkage(
    digests: Iterable[str], threshold: float = 0.85, max_pairs: int = 250_000
) -> List[List[int]]:
    """Single-linkage clustering for CTPH digests.

    Returns clusters as lists of indices into the input sequence.
    Pairs with similarity >= threshold are linked, and connected components
    are output as clusters. Budgeted by `max_pairs` to cap O(n^2).
    """

    ds = list(digests)
    n = len(ds)
    parent = list(range(n))
    rank = [0] * n

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: int, b: int) -> None:
        ra, rb = find(a), find(b)
        if ra == rb:
            return
        if rank[ra] < rank[rb]:
            parent[ra] = rb
        elif rank[ra] > rank[rb]:
            parent[rb] = ra
        else:
            parent[rb] = ra
            rank[ra] += 1

    pairs = _native.similarity.ctph_pairwise_matrix(ds, max_pairs)
    for i, j, s in pairs:
        if s >= threshold:
            union(i, j)

    comp: dict[int, list[int]] = {}
    for i in range(n):
        r = find(i)
        comp.setdefault(r, []).append(i)
    return list(comp.values())
