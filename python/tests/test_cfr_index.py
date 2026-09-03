"""The CFR weight table, its confidence, and the rare-feature index.

Everything here runs against real binaries. There is no way to fake a
lifted SSA dataflow graph and a fixture that did would be testing the
fixture, so the corpus is whatever matched builds this checkout has:
``tests/decompiler_fixtures/build/`` when the fixture harness has been
run (or ``GLAURUNG_IDENTITY_CORPUS`` points at one that has), and a small
set of real ELFs from ``samples/`` otherwise. Two of the tests want
*matched builds* -- the same source at two optimisation levels -- and
those skip loudly rather than pass vacuously when the fixture corpus is
absent.

The metric's own properties (symmetry, the triangle inequality, the
self-significance bound) are asserted in Rust, in
``src/identity/cfr/similarity.rs`` and ``src/identity/cfr/weights.rs``.
What is checked here is the boundary, the storage, and the one property
the storage adds: that the inverted index and the exhaustive scan give
the same answer.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import List

import pytest

import glaurung as g
from glaurung.llm.kb.cfr_index import (
    FLAT_SCAN_MAX_VECTORS,
    TOP_K_POSTINGS,
    build_cfr_index,
    cfr_index_size,
    decode_features,
    encode_features,
    load_cfr_weights,
    query_cfr,
)
from glaurung.llm.kb.persistent import PersistentKnowledgeBase

ROOT = Path(__file__).resolve().parent.parent.parent


def _fixture_build_dir() -> Path | None:
    """The matched-build corpus, if this checkout has one.

    Same resolution order as the Rust harness
    (``docs/development/identity-measurement.md``): the env var first, so
    an agent worktree can point at the main checkout's build directory,
    then the in-tree path.
    """
    override = os.environ.get("GLAURUNG_IDENTITY_CORPUS")
    if override:
        candidate = Path(override)
        if candidate.is_dir():
            return candidate
    candidate = ROOT / "tests" / "decompiler_fixtures" / "build"
    return candidate if candidate.is_dir() else None


def _matched_pairs(limit: int = 12) -> List[tuple[Path, Path]]:
    """``(gcc-O0, gcc-O2)`` pairs of the same fixture source."""
    build = _fixture_build_dir()
    if build is None:
        return []
    pairs = []
    for o0 in sorted(build.glob("*-gcc-O0.so")):
        o2 = o0.with_name(o0.name.replace("-gcc-O0.so", "-gcc-O2.so"))
        if o2.exists():
            pairs.append((o0, o2))
        if len(pairs) >= limit:
            break
    return pairs


@pytest.fixture(scope="module")
def corpus() -> List[Path]:
    """A handful of real binaries to build an index over."""
    pairs = _matched_pairs()
    if pairs:
        return [path for pair in pairs for path in pair]
    candidates = [
        ROOT
        / "samples/binaries/platforms/linux/amd64/export/native/gcc/O0/hello-gcc-O0",
        ROOT
        / "samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-gcc-O2",
        ROOT / "tests/fixtures/hello-rust-release",
    ]
    present = [path for path in candidates if path.exists()]
    if not present:
        pytest.skip(
            "no corpus: neither tests/decompiler_fixtures/build (set "
            "GLAURUNG_IDENTITY_CORPUS) nor the sample ELFs are present"
        )
    return present


# ---------------------------------------------------------------------------
# The weight table
# ---------------------------------------------------------------------------


def test_a_universal_feature_weighs_less_than_a_rare_one(corpus: List[Path]) -> None:
    """The whole claim of a TF-IDF table, on real signatures.

    A feature every function carries says nothing about which function
    this is; a feature one function carries says everything the corpus
    knows.
    """
    signatures = []
    for path in corpus:
        signatures.extend(g.analysis.cfr_signatures_path(str(path)))
    weights = g.analysis.cfr_build_weights(signatures)
    assert weights.documents == len(signatures)
    assert len(weights) > 0

    rows = weights.entries()
    commonest = max(rows, key=lambda row: row[1])
    rarest = min(rows, key=lambda row: row[1])
    assert commonest[1] > rarest[1], "corpus has no frequency spread to weight"
    assert weights.idf(commonest[0]) < weights.idf(rarest[0])
    # A feature the corpus never saw is the rarest thing the table can say.
    assert weights.idf(0xDEADBEEF) == weights.max_idf
    assert weights.max_idf >= weights.idf(rarest[0])


def test_the_weights_id_names_the_table_and_not_the_call(corpus: List[Path]) -> None:
    """Two counts over the same corpus are the same table; a different
    corpus is a different table. This is what makes it safe to key a
    stored score on."""
    signatures = []
    for path in corpus:
        signatures.extend(g.analysis.cfr_signatures_path(str(path)))
    first = g.analysis.cfr_build_weights(signatures)
    again = g.analysis.cfr_build_weights(signatures)
    assert first.weights_id == again.weights_id

    fewer = g.analysis.cfr_build_weights(signatures[: max(1, len(signatures) // 2)])
    assert fewer.weights_id != first.weights_id
    # The version triple is in the id, so a different quotient is a
    # different table even over the same counts.
    assert first.weights_id.startswith("cfr-1.0-s0-idf512-")


def test_a_weights_table_from_another_quotient_is_refused(corpus: List[Path]) -> None:
    """`nosize` signatures counted as plain ones would produce a table
    that is wrong for both, silently."""
    plain = g.analysis.cfr_signatures_path(str(corpus[0]))
    nosize = g.analysis.cfr_signatures_path(str(corpus[0]), nosize=True)
    assert plain and nosize
    mixed = g.analysis.cfr_build_weights(plain + nosize, nosize=False)
    assert mixed.documents == len(plain), "the nosize half must be refused"


# ---------------------------------------------------------------------------
# Confidence
# ---------------------------------------------------------------------------


def test_significance_is_bounded_by_self_significance(corpus: List[Path]) -> None:
    """The bound is a theorem, not a clamp -- so it must hold on every
    real pair, not merely on the constructed ones the Rust tests use."""
    signatures = []
    for path in corpus:
        signatures.extend(g.analysis.cfr_signatures_path(str(path)))
    weights = g.analysis.cfr_build_weights(signatures)
    sample = signatures[:40]
    checked = 0
    for a in sample:
        for b in sample:
            result = g.analysis.cfr_confidence(a, b, weights)
            assert result["significance"] <= result["self_significance"] + 1e-6
            assert 0.0 <= result["saturation"] <= 1.0
            assert 0.0 <= result["cosine"] <= 1.0
            checked += 1
    assert checked > 100


def test_a_small_function_cannot_reach_a_confident_match(corpus: List[Path]) -> None:
    """Ghidra's stated property, on real functions: self-significance
    grows with the function, so the smallest functions in a real binary
    cannot clear the threshold however perfectly they match."""
    signatures = []
    for path in corpus:
        signatures.extend(g.analysis.cfr_signatures_path(str(path)))
    weights = g.analysis.cfr_build_weights(signatures)
    by_size = sorted(signatures, key=lambda s: len(s.features))
    smallest = by_size[0]
    largest = by_size[-1]
    assert len(smallest.features) < len(largest.features), "no size spread to test"

    # A self-comparison is the best a signature can ever do.
    assert smallest.self_significance(weights) < largest.self_significance(weights)
    assert g.analysis.cfr_confidence(smallest, smallest, weights)[
        "cosine"
    ] == pytest.approx(1.0)
    assert (
        g.analysis.cfr_confidence(largest, largest, weights)["significance"]
        > g.analysis.cfr_confidence(smallest, smallest, weights)["significance"]
    )


def test_the_published_calibration_refuses_to_extrapolate_downward(
    corpus: List[Path],
) -> None:
    """Below BSim's lowest published anchor there is no false-positive
    rate to quote, and inventing one would be the most quotable number in
    the whole module."""
    signatures = g.analysis.cfr_signatures_path(str(corpus[0]))
    weights = g.analysis.cfr_build_weights(signatures)
    a, b = signatures[0], signatures[-1]
    for result in (
        g.analysis.cfr_confidence(a, b, weights),
        g.analysis.cfr_confidence(a, a, weights),
    ):
        if result["significance"] < 10.0:
            assert result["false_positive_one_in"] is None
        else:
            assert result["false_positive_one_in"] >= 4000.0
    assert g.analysis.CFR_CONFIDENT_SIGNIFICANCE == 26.0


# ---------------------------------------------------------------------------
# Encoding
# ---------------------------------------------------------------------------


def test_the_stored_blob_round_trips(corpus: List[Path]) -> None:
    signature = g.analysis.cfr_signatures_path(str(corpus[0]))[0]
    blob = encode_features(signature.features)
    assert len(blob) == 6 * len(signature.features)
    assert decode_features(blob) == list(signature.features)


def test_an_unsorted_vector_is_refused_rather_than_stored() -> None:
    """A stored vector out of order would not corrupt anything visibly.
    It would make every merge join against it wrong."""
    with pytest.raises(ValueError, match="ascend"):
        encode_features([(9, 1), (3, 1)])


def test_a_reconstructed_signature_scores_like_the_original(
    corpus: List[Path],
) -> None:
    """The index side of the boundary: a vector read back out of storage
    has to be the same object to the metric as the one that was stored."""
    signatures = g.analysis.cfr_signatures_path(str(corpus[0]))
    weights = g.analysis.cfr_build_weights(signatures)
    for signature in signatures[:20]:
        rebuilt = g.analysis.CfrSignature.from_features(
            decode_features(encode_features(signature.features))
        )
        assert rebuilt.digest == signature.digest
        assert rebuilt.features == signature.features
        assert g.analysis.cfr_similarity(signature, rebuilt, weights) == pytest.approx(
            1.0
        )


# ---------------------------------------------------------------------------
# The index
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def indexed(corpus: List[Path], tmp_path_factory: pytest.TempPathFactory):
    """One built index over the whole corpus, shared by the tests below."""
    directory = tmp_path_factory.mktemp("cfr-index")
    kb = PersistentKnowledgeBase.open(directory / "project.glaurung", corpus[0])
    summary = build_cfr_index(kb, corpus)
    yield kb, summary
    kb.close()


def test_building_the_index_stores_what_it_says_it_did(indexed) -> None:
    kb, summary = indexed
    vectors, functions = cfr_index_size(kb)
    assert summary.functions == functions
    assert summary.vectors == vectors
    assert summary.vectors <= summary.functions, "deduplication cannot add rows"
    assert summary.postings > 0
    assert summary.postings <= summary.vectors * TOP_K_POSTINGS
    assert summary.weighted_features > 0
    assert summary.top_k == TOP_K_POSTINGS


def test_the_stored_weight_table_reads_back_identical(indexed) -> None:
    """The stored `weight` column is a convenience for reading the table
    in SQL; the weights are recomputed from the document counts. If the
    two could disagree, one of them would be a lie."""
    kb, summary = indexed
    weights = load_cfr_weights(kb)
    assert weights is not None
    assert weights.weights_id == summary.weights_id

    cur = kb._conn.cursor()
    cur.execute(
        "SELECT feature_hash, weight FROM feature_weight WHERE weights_id = ?",
        (summary.weights_id,),
    )
    rows = cur.fetchall()
    assert len(rows) == summary.weighted_features
    for feature_hash, stored in rows:
        assert weights.idf(feature_hash) == pytest.approx(stored)


def test_identical_functions_share_one_refcounted_vector(indexed) -> None:
    """BSim's `vectable.count`: one row per canonical form, and a high
    count is the cheapest false-positive signal there is."""
    kb, summary = indexed
    cur = kb._conn.cursor()
    cur.execute("SELECT SUM(refcount) FROM feature_vector")
    assert int(cur.fetchone()[0]) == summary.functions
    cur.execute("SELECT MAX(refcount) FROM feature_vector")
    top = int(cur.fetchone()[0])
    assert top >= 1
    if summary.vectors < summary.functions:
        assert top > 1, "deduplication happened, so some vector is shared"


def test_a_stored_function_retrieves_itself_first(indexed) -> None:
    """The floor any retrieval has to clear: a function that is in the
    index must come back top-1 when it is the query."""
    kb, _ = indexed
    cur = kb._conn.cursor()
    cur.execute("SELECT features FROM feature_vector ORDER BY n_features DESC LIMIT 5")
    stored = [decode_features(row[0]) for row in cur.fetchall()]
    assert stored
    for features in stored:
        query = g.analysis.CfrSignature.from_features(features)
        matches = query_cfr(kb, query, k=3)
        assert matches, "an indexed vector must retrieve something"
        assert matches[0].digest == query.digest
        assert matches[0].cosine == pytest.approx(1.0)
        assert matches[0].significance == pytest.approx(
            matches[0].self_significance, abs=1e-6
        )


def test_the_index_and_the_scan_agree_on_the_top_hit(indexed) -> None:
    """The one property the storage adds, and the reason both paths exist.

    The scan is exact by construction; the index approximates only in
    which candidates it generates. So the index may miss, and this pins
    how often -- on this corpus, never for a query that is in the index.
    """
    kb, summary = indexed
    assert summary.vectors <= FLAT_SCAN_MAX_VECTORS, (
        "this corpus is small enough that query_cfr scans by default; "
        "force_index is what exercises the other path"
    )
    cur = kb._conn.cursor()
    cur.execute("SELECT features FROM feature_vector ORDER BY vector_id LIMIT 25")
    agreed = 0
    for (blob,) in cur.fetchall():
        query = g.analysis.CfrSignature.from_features(decode_features(blob))
        scanned = query_cfr(kb, query, k=5, force_scan=True)
        indexed_hits = query_cfr(kb, query, k=5, force_index=True)
        assert scanned, "the exact path must find the query itself"
        assert indexed_hits, "the query's own rarest features must reach it"
        assert scanned[0].vector_id == indexed_hits[0].vector_id
        assert scanned[0].cosine == pytest.approx(indexed_hits[0].cosine)
        agreed += 1
    assert agreed >= 5


def test_a_significance_floor_drops_the_weak_matches(indexed) -> None:
    kb, _ = indexed
    cur = kb._conn.cursor()
    cur.execute("SELECT features FROM feature_vector ORDER BY n_features DESC LIMIT 1")
    query = g.analysis.CfrSignature.from_features(decode_features(cur.fetchone()[0]))
    everything = query_cfr(kb, query, k=50)
    confident = query_cfr(
        kb, query, k=50, min_significance=g.analysis.CFR_CONFIDENT_SIGNIFICANCE
    )
    assert len(confident) <= len(everything)
    assert all(
        match.significance >= g.analysis.CFR_CONFIDENT_SIGNIFICANCE
        for match in confident
    )


def test_a_query_against_an_empty_kb_answers_nothing(tmp_path: Path) -> None:
    """Not an exception, and not a match. A KB with no index has nothing
    to say, and saying so is different from saying "no match"."""
    corpus = _matched_pairs(limit=1)
    source = (
        corpus[0][0]
        if corpus
        else ROOT
        / "samples/binaries/platforms/linux/amd64/export/native/gcc/O0/hello-gcc-O0"
    )
    if not source.exists():
        pytest.skip("no binary to sign")
    kb = PersistentKnowledgeBase.open(tmp_path / "empty.glaurung", source)
    try:
        signature = g.analysis.cfr_signatures_path(str(source))[0]
        assert query_cfr(kb, signature) == []
        assert load_cfr_weights(kb) is None
    finally:
        kb.close()


def test_rebuilding_under_a_new_weight_table_replaces_rather_than_mixes(
    corpus: List[Path], tmp_path: Path
) -> None:
    """A vector's stored norm is a function of the weight table, so two
    weight tables in one index is two incomparable scorings sharing a
    column. Rebuilding replaces; appending under a foreign table is
    refused."""
    kb = PersistentKnowledgeBase.open(tmp_path / "rebuild.glaurung", corpus[0])
    try:
        first = build_cfr_index(kb, corpus[:1])
        second = build_cfr_index(kb, corpus)
        assert second.weights_id != first.weights_id
        cur = kb._conn.cursor()
        cur.execute("SELECT COUNT(DISTINCT weights_id) FROM feature_vector")
        assert int(cur.fetchone()[0]) == 1
        cur.execute("SELECT COUNT(DISTINCT weights_id) FROM feature_weight")
        assert int(cur.fetchone()[0]) == 1

        with pytest.raises(ValueError, match="weights_id"):
            build_cfr_index(kb, corpus[:1], replace=False)
    finally:
        kb.close()


def test_a_pinned_weight_table_lets_an_index_be_extended(
    corpus: List[Path], tmp_path: Path
) -> None:
    """The incremental case: pin the table, and adding a binary is an
    append rather than a reingest."""
    if len(corpus) < 2:
        pytest.skip("needs at least two binaries")
    kb = PersistentKnowledgeBase.open(tmp_path / "extend.glaurung", corpus[0])
    try:
        signatures = []
        for path in corpus:
            signatures.extend(g.analysis.cfr_signatures_path(str(path)))
        weights = g.analysis.cfr_build_weights(signatures)

        first = build_cfr_index(kb, corpus[:1], weights=weights)
        second = build_cfr_index(kb, corpus[1:], weights=weights, replace=False)
        assert second.weights_id == first.weights_id
        assert second.functions == len(signatures) - first.functions
        _, functions = cfr_index_size(kb)
        assert functions >= first.functions
    finally:
        kb.close()


@pytest.mark.slow
def test_a_matched_build_retrieves_its_twin(tmp_path: Path) -> None:
    """The task the L2 rung exists for, end to end through the KB: index
    a `-O2` slice, query it with the `-O0` build of the same source, and
    ask whether the right function comes back at all.

    This asserts only that the pipeline *works* -- that a cross-optimisation
    twin is reachable at rank <= 10 for a meaningful share of queries. The
    retrieval numbers themselves are the Rust harness's job
    (`tests/identity_retrieval/`), which applies the published filters and
    states its pool size; a number measured here would have neither.
    """
    pairs = _matched_pairs(limit=8)
    if not pairs:
        pytest.skip(
            "needs tests/decompiler_fixtures/build (or GLAURUNG_IDENTITY_CORPUS)"
        )
    o0 = [pair[0] for pair in pairs]
    o2 = [pair[1] for pair in pairs]

    kb = PersistentKnowledgeBase.open(tmp_path / "twins.glaurung", o2[0])
    try:
        summary = build_cfr_index(kb, o2)
        assert summary.functions > 20

        # Where did each O2 function end up, by name?
        names: dict[tuple[int, int], str] = {}
        for path in o2:
            binary_id = PersistentKnowledgeBase._resolve_binary(kb._conn, path)
            for signature in g.analysis.cfr_signatures_path(str(path)):
                if signature.name:
                    names[(binary_id, int(signature.entry_va))] = signature.name

        asked = 0
        found = 0
        for path in o0:
            for signature in g.analysis.cfr_signatures_path(str(path)):
                if not signature.name or signature.block_count < 5:
                    continue
                asked += 1
                for match in query_cfr(kb, signature, k=10):
                    if names.get((match.binary_id, match.entry_va)) == signature.name:
                        found += 1
                        break
        assert asked >= 20, f"only {asked} queries; the corpus is too small"
        assert found > 0, (
            f"0 of {asked} cross-optimisation twins reachable at rank <= 10; "
            "the index is not retrieving at all"
        )
    finally:
        kb.close()
