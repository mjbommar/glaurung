"""The CFR feature vectors and their rare-feature inverted index.

``function_identity`` stores one *digest* per function: an exact key that
answers "same canonical form or not". This module stores the object
behind that digest -- the sorted ``(feature_hash, count)`` multiset --
plus the corpus TF-IDF table that weights it and an inverted index that
makes "which function in this corpus is most like the one I am holding"
answerable without comparing against every stored vector.

The representation, the metric and the confidence are Rust
(``src/identity/cfr/``, documented in
``docs/reference/function-identity-cfr.md``); this module is storage,
retrieval and nothing else. It computes no weights and no scores of its
own: :func:`build_cfr_index` calls ``glaurung.analysis.cfr_build_weights``
and :func:`query_cfr` calls ``glaurung.analysis.cfr_confidence``, so a
stored score and a score computed in memory cannot drift apart.

The schema is section 4 of
``docs/history/program-measures-2026-09-02/03-schema.sql``.

Deduplicated and refcounted
---------------------------
``feature_vector`` holds one row per *distinct* canonical form and
``function_vector`` points at it, which is BSim's ``vectable.count`` /
``desctable.id_signature`` split. On a library-heavy corpus this is a
large saving and it is also the cheapest false-positive signal there is:
a vector with a refcount of two hundred is CRT boilerplate, and a match
against it means nothing.

Why a rebuild rather than an append
-----------------------------------
The IDF of a feature is a property of the *whole* corpus, so adding one
binary changes every weight and therefore every stored norm. BSim freezes
its weight scheme at database creation and documents that it "cannot be
changed without reingesting"; :func:`build_cfr_index` does the same by
recomputing the table over everything it is given and replacing the index
under a new ``weights_id``. To index incrementally, pass a
``weights`` table built elsewhere -- from a library corpus, say -- and the
weights stay fixed while binaries are added.

Storage sizes are stated where they are chosen: see
:data:`TOP_K_POSTINGS` and :data:`FLAT_SCAN_MAX_VECTORS`.
"""

from __future__ import annotations

import sqlite3
import struct
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, Iterable, List, Optional, Sequence, Tuple

from .persistent import PersistentKnowledgeBase

if TYPE_CHECKING:  # pragma: no cover - types only
    # Imported for annotations only. At runtime every entry point does its own
    # `import glaurung as g` inside the function body, so this module stays
    # importable without the extension being loaded first -- the same
    # discipline `function_identity.py` uses.
    from glaurung.analysis import CfrSignature, CfrWeights

#: How many of a vector's rarest features go into the inverted index.
#:
#: The postings table is what turns retrieval from a scan into a set of
#: index seeks, and its size is ``K`` rows per stored vector regardless of
#: how large the functions are -- so the index is linear in the corpus and
#: independent of function size, which a full postings list is not (a
#: 900-feature function would contribute 900 rows, and the commonest
#: features would contribute the longest and least useful lists).
#:
#: ``32`` is the choice, and the reasoning is the AllPairs prefix filter's:
#: candidates are generated from the query's *rarest* features because a
#: rare feature's posting list is short and its evidence is high, and two
#: functions that are genuinely the same overwhelmingly share more than one
#: of their rarest features. It is a recall/cost trade with a measured
#: floor -- ``test_cfr_index.py`` scores the index against the exhaustive
#: scan on the fixture corpus and pins the agreement, so lowering K cannot
#: silently cost recall.
#:
#: Note what K does *not* affect: nothing is scored from the index. It
#: generates candidates and every candidate is then rescored exactly
#: against its full stored vector, so K trades recall for time and never
#: precision.
TOP_K_POSTINGS = 32

#: Vector count at or below which :func:`query_cfr` scans every vector
#: instead of consulting the index.
#:
#: The research synthesis is blunt about this: "Flat scan until about 1e5
#: to 1e6 vectors. Ghidra's own embedded BSim backend has no LSH index at
#: all; it is an exact hash plus a linear scan. A six-thousand-function
#: kernel diff needs no index." A scan is also *exact* -- it cannot miss a
#: match the index's candidate generation would have dropped -- so below
#: this size the cheaper answer is also the better one.
#:
#: ``query_cfr(..., force_index=True)`` takes the index anyway, which is
#: how the two paths are compared on a corpus small enough to hold both.
FLAT_SCAN_MAX_VECTORS = 100_000

#: ``feature_vector.features`` is this format, repeated ``n_features``
#: times: a little-endian ``(u32 hash, u16 count)`` pair, ascending by
#: hash. It is the Rust ``CfrSignature.features`` encoding byte for byte,
#: which is BSim's ``1:545c6155`` list and which is what makes the
#: comparison an ``O(n + m)`` merge join rather than a set intersection.
_FEATURE_STRUCT = struct.Struct("<IH")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS cfr_weight_table (
    weights_id   TEXT PRIMARY KEY,
    cfr_major    INTEGER NOT NULL,
    cfr_minor    INTEGER NOT NULL,
    cfr_settings INTEGER NOT NULL,
    documents    INTEGER NOT NULL,
    n_features   INTEGER NOT NULL,
    top_k        INTEGER NOT NULL,
    built_at     INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS feature_weight (
    weights_id   TEXT NOT NULL,
    feature_hash INTEGER NOT NULL,
    doc_count    INTEGER NOT NULL,
    weight       REAL NOT NULL,
    PRIMARY KEY (weights_id, feature_hash)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS feature_vector (
    vector_id   INTEGER PRIMARY KEY,
    vector_hash TEXT NOT NULL UNIQUE,
    n_features  INTEGER NOT NULL,
    total_count INTEGER NOT NULL,
    norm        REAL NOT NULL,
    weights_id  TEXT NOT NULL,
    features    BLOB NOT NULL,
    refcount    INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS function_vector (
    binary_id INTEGER NOT NULL,
    entry_va  INTEGER NOT NULL,
    vector_id INTEGER NOT NULL REFERENCES feature_vector(vector_id),
    PRIMARY KEY (binary_id, entry_va)
);
CREATE INDEX IF NOT EXISTS idx_function_vector_vec
    ON function_vector(vector_id);

CREATE TABLE IF NOT EXISTS feature_posting (
    feature_hash INTEGER NOT NULL,
    vector_id    INTEGER NOT NULL REFERENCES feature_vector(vector_id),
    PRIMARY KEY (feature_hash, vector_id)
) WITHOUT ROWID;
"""


def _ensure(conn: sqlite3.Connection) -> None:
    """Create this module's tables. Idempotent; runs on every entry point."""
    conn.executescript(_SCHEMA)


# ---------------------------------------------------------------------------
# Encoding
# ---------------------------------------------------------------------------


def encode_features(features: Sequence[Tuple[int, int]]) -> bytes:
    """Pack a sorted ``(hash, count)`` multiset into the stored blob.

    Args:
        features: Pairs ascending by hash, as
            ``glaurung.analysis.CfrSignature.features`` produces them.

    Returns:
        ``len(features) * 6`` bytes, little-endian.

    Raises:
        ValueError: The pairs are not ascending by hash. Storing an
            unsorted vector would not corrupt anything visibly -- it would
            silently make every merge join against it wrong, which is
            worse.
    """
    out = bytearray(len(features) * _FEATURE_STRUCT.size)
    previous = -1
    for index, (feature_hash, count) in enumerate(features):
        if feature_hash <= previous:
            raise ValueError(
                f"features must ascend by hash; {feature_hash} follows {previous}"
            )
        previous = feature_hash
        _FEATURE_STRUCT.pack_into(
            out, index * _FEATURE_STRUCT.size, feature_hash, count
        )
    return bytes(out)


def decode_features(blob: bytes) -> List[Tuple[int, int]]:
    """Unpack a stored blob back into ``(hash, count)`` pairs."""
    if len(blob) % _FEATURE_STRUCT.size:
        raise ValueError(
            f"feature blob of {len(blob)} bytes is not a whole number of "
            f"{_FEATURE_STRUCT.size}-byte entries"
        )
    return [
        _FEATURE_STRUCT.unpack_from(blob, offset)
        for offset in range(0, len(blob), _FEATURE_STRUCT.size)
    ]


# ---------------------------------------------------------------------------
# Results
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CfrMatch:
    """One scored candidate from :func:`query_cfr`.

    ``cosine`` says how alike and ``significance`` says whether it is a
    coincidence; neither answers the question alone, which is why BSim
    returns both from one comparison and why this carries both.
    """

    binary_id: int
    entry_va: int
    vector_id: int
    #: The stored vector's CFR digest. Equal to the query's iff the two
    #: have the same canonical form.
    digest: str
    cosine: float
    #: BSim's significance ("Confidence" in Ghidra's UI). Open-ended, and
    #: negative for a poor match.
    significance: float
    #: The largest significance this pair could have produced.
    self_significance: float
    #: ``None`` below BSim's lowest published anchor, where Ghidra's own
    #: help page says the correspondence to a false-positive rate does not
    #: hold.
    false_positive_one_in: Optional[float]
    #: How many functions in the index share this exact vector. A high
    #: number is the cheapest false-positive signal there is: a match
    #: against boilerplate that occurs two hundred times means nothing.
    refcount: int


@dataclass(frozen=True)
class CfrIndexSummary:
    """What :func:`build_cfr_index` did."""

    weights_id: str
    #: Binaries signed.
    binaries: int
    #: Functions with a stored vector.
    functions: int
    #: Distinct canonical forms among them.
    vectors: int
    #: Features the weight table carries.
    weighted_features: int
    #: Rows in ``feature_posting``.
    postings: int
    #: Functions the signer produced no features for, and which are
    #: therefore absent rather than stored empty.
    skipped_empty: int
    top_k: int


# ---------------------------------------------------------------------------
# Building
# ---------------------------------------------------------------------------


def build_cfr_index(
    kb: PersistentKnowledgeBase,
    binaries: Iterable[str | Path],
    *,
    weights: Optional["CfrWeights"] = None,
    nosize: bool = False,
    min_doc_count: int = 1,
    top_k: int = TOP_K_POSTINGS,
    replace: bool = True,
) -> CfrIndexSummary:
    """Sign every function in ``binaries``, weight them, and index them.

    Each binary is registered in the project file if it is not there
    already, so the index spans builds and libraries rather than the one
    binary ``kb`` happens to be open on -- which is the whole point of an
    L2 index.

    Args:
        kb: An open knowledge base. Its own binary need not be among
            ``binaries``.
        binaries: Paths to sign.
        weights: A ``glaurung.analysis.CfrWeights`` to use unchanged. Pass
            one to add binaries to an existing index without moving every
            stored weight; pass ``None`` (the default) to count a fresh
            table over exactly the binaries given.
        nosize: The CFR ``nosize`` setting. Part of the signature's version
            triple, so an index must not mix the two. Ignored when
            ``weights`` is given, which already carries a setting.
        min_doc_count: Features seen in fewer functions than this are left
            out of the weight table rather than weighted. They fall through
            to the corpus maximum, which is the right answer for something
            seen once; leaving them out only saves rows.
        top_k: Rarest features per vector to put in ``feature_posting``.
            See :data:`TOP_K_POSTINGS`.
        replace: Clear the existing index first. The default, and the
            correct behaviour whenever the weight table is recounted --
            vectors stored under an old ``weights_id`` carry norms that no
            longer mean anything. Pass ``False`` only alongside an explicit
            ``weights``.

    Returns:
        A :class:`CfrIndexSummary`.

    Raises:
        ValueError: ``replace`` is ``False`` and the stored index was built
            under a different ``weights_id``, which would leave two
            incomparable scorings in one table.
    """
    import glaurung as g

    _ensure(kb._conn)
    paths = [Path(p) for p in binaries]

    signed: List[Tuple[int, "CfrSignature"]] = []
    skipped_empty = 0
    for path in paths:
        binary_id = PersistentKnowledgeBase._resolve_binary(kb._conn, path)
        for signature in g.analysis.cfr_signatures_path(str(path), nosize=nosize):
            if not signature.features:
                # An empty vector compares as "no answer" to everything, so
                # storing one would put a row in the index that can never be
                # retrieved and can never be ruled out.
                skipped_empty += 1
                continue
            signed.append((binary_id, signature))

    if weights is None:
        weights = g.analysis.cfr_build_weights(
            [signature for _, signature in signed],
            min_doc_count=int(min_doc_count),
            nosize=nosize,
        )
    weights_id = weights.weights_id

    cur = kb._conn.cursor()
    stored_id = _stored_weights_id(cur)
    if replace:
        _clear_index(cur)
    elif stored_id is not None and stored_id != weights_id:
        raise ValueError(
            f"the stored index was built under weights_id {stored_id!r} and "
            f"this call would add rows scored under {weights_id!r}; rebuild "
            "with replace=True, or pass the stored table as `weights`"
        )

    _write_weight_table(cur, weights, top_k=top_k)

    vector_ids: Dict[str, int] = {}
    postings = 0
    for binary_id, signature in signed:
        digest = signature.digest
        vector_id = vector_ids.get(digest)
        if vector_id is None:
            cur.execute(
                "SELECT vector_id FROM feature_vector WHERE vector_hash = ?",
                (digest,),
            )
            row = cur.fetchone()
            if row is not None:
                vector_id = int(row[0])
            else:
                norm = signature.self_significance(weights)
                cur.execute(
                    "INSERT INTO feature_vector "
                    "(vector_hash, n_features, total_count, norm, weights_id, "
                    " features, refcount) VALUES (?, ?, ?, ?, ?, ?, 0)",
                    (
                        digest,
                        len(signature.features),
                        int(signature.total_count()),
                        float(norm),
                        weights_id,
                        encode_features(signature.features),
                    ),
                )
                vector_id = int(cur.lastrowid or 0)
                postings += _write_postings(
                    cur, vector_id, signature.features, weights, top_k
                )
            vector_ids[digest] = vector_id
        cur.execute(
            "INSERT OR REPLACE INTO function_vector "
            "(binary_id, entry_va, vector_id) VALUES (?, ?, ?)",
            (binary_id, int(signature.entry_va), vector_id),
        )

    # Refcounts are recomputed from `function_vector` rather than
    # incremented as rows are inserted: `INSERT OR REPLACE` above makes a
    # re-index idempotent, and an incremented counter would not be.
    cur.execute(
        "UPDATE feature_vector SET refcount = ("
        "  SELECT COUNT(*) FROM function_vector "
        "  WHERE function_vector.vector_id = feature_vector.vector_id)"
    )
    kb._conn.commit()

    cur.execute("SELECT COUNT(*) FROM feature_vector")
    vectors = int(cur.fetchone()[0])
    cur.execute("SELECT COUNT(*) FROM feature_posting")
    posting_rows = int(cur.fetchone()[0])
    return CfrIndexSummary(
        weights_id=weights_id,
        binaries=len(paths),
        functions=len(signed),
        vectors=vectors,
        weighted_features=len(weights),
        postings=posting_rows,
        skipped_empty=skipped_empty,
        top_k=top_k,
    )


def _stored_weights_id(cur: sqlite3.Cursor) -> Optional[str]:
    cur.execute(
        "SELECT weights_id FROM cfr_weight_table ORDER BY built_at DESC LIMIT 1"
    )
    row = cur.fetchone()
    return None if row is None else str(row[0])


def _clear_index(cur: sqlite3.Cursor) -> None:
    for table in (
        "feature_posting",
        "function_vector",
        "feature_vector",
        "feature_weight",
        "cfr_weight_table",
    ):
        cur.execute(f"DELETE FROM {table}")


def _write_weight_table(
    cur: sqlite3.Cursor, weights: "CfrWeights", *, top_k: int
) -> None:
    entries = weights.entries()
    weights_id = weights.weights_id
    major, minor, settings = weights.version
    cur.execute(
        "INSERT OR REPLACE INTO cfr_weight_table "
        "(weights_id, cfr_major, cfr_minor, cfr_settings, documents, "
        " n_features, top_k, built_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            weights_id,
            int(major),
            int(minor),
            int(settings),
            int(weights.documents),
            len(entries),
            int(top_k),
            int(time.time()),
        ),
    )
    cur.executemany(
        "INSERT OR REPLACE INTO feature_weight "
        "(weights_id, feature_hash, doc_count, weight) VALUES (?, ?, ?, ?)",
        [
            (weights_id, int(feature_hash), int(doc_count), float(weight))
            for feature_hash, doc_count, weight in entries
        ],
    )


def _rarest_features(
    features: Sequence[Tuple[int, int]], weights: "CfrWeights", top_k: int
) -> List[int]:
    """The ``top_k`` highest-IDF feature hashes of one vector.

    Ties break on the hash, ascending, so the choice is a function of the
    vector and the table and of nothing else -- an index whose contents
    depended on dict ordering would answer differently on two machines
    holding the same corpus.
    """
    scored = [
        (-weights.idf(feature_hash), feature_hash) for feature_hash, _count in features
    ]
    scored.sort()
    return [feature_hash for _, feature_hash in scored[:top_k]]


def _write_postings(
    cur: sqlite3.Cursor,
    vector_id: int,
    features: Sequence[Tuple[int, int]],
    weights: "CfrWeights",
    top_k: int,
) -> int:
    rows = [
        (int(feature_hash), vector_id)
        for feature_hash in _rarest_features(features, weights, top_k)
    ]
    cur.executemany(
        "INSERT OR REPLACE INTO feature_posting (feature_hash, vector_id) "
        "VALUES (?, ?)",
        rows,
    )
    return len(rows)


# ---------------------------------------------------------------------------
# Reading back
# ---------------------------------------------------------------------------


def load_cfr_weights(
    kb: PersistentKnowledgeBase, weights_id: Optional[str] = None
) -> Optional["CfrWeights"]:
    """Rebuild the stored weight table as a ``glaurung.analysis.CfrWeights``.

    The weights are recomputed from the stored document counts rather than
    read from the ``weight`` column, so a table read back cannot disagree
    with one built from the corpus it was counted over. The ``weight``
    column is kept because it is what makes the table readable in SQL, and
    :func:`stored_weights_agree` is the test that the two never diverge.

    Returns ``None`` when the KB holds no index.
    """
    import glaurung as g

    _ensure(kb._conn)
    cur = kb._conn.cursor()
    if weights_id is None:
        weights_id = _stored_weights_id(cur)
        if weights_id is None:
            return None
    cur.execute(
        "SELECT documents, cfr_settings FROM cfr_weight_table WHERE weights_id = ?",
        (weights_id,),
    )
    row = cur.fetchone()
    if row is None:
        return None
    documents, settings = int(row[0]), int(row[1])
    cur.execute(
        "SELECT feature_hash, doc_count FROM feature_weight "
        "WHERE weights_id = ? ORDER BY feature_hash",
        (weights_id,),
    )
    entries = [(int(h), int(d)) for h, d in cur.fetchall()]
    return g.analysis.CfrWeights.from_entries(
        documents, entries, nosize=bool(settings & 1)
    )


def cfr_index_size(kb: PersistentKnowledgeBase) -> Tuple[int, int]:
    """``(stored vectors, indexed functions)``."""
    _ensure(kb._conn)
    cur = kb._conn.cursor()
    cur.execute("SELECT COUNT(*) FROM feature_vector")
    vectors = int(cur.fetchone()[0])
    cur.execute("SELECT COUNT(*) FROM function_vector")
    functions = int(cur.fetchone()[0])
    return vectors, functions


# ---------------------------------------------------------------------------
# Querying
# ---------------------------------------------------------------------------


def query_cfr(
    kb: PersistentKnowledgeBase,
    signature: "CfrSignature",
    k: int = 10,
    *,
    min_significance: Optional[float] = None,
    force_index: bool = False,
    force_scan: bool = False,
    candidate_limit: int = 4096,
) -> List[CfrMatch]:
    """The ``k`` functions in the index most like ``signature``.

    Two retrieval paths, and which one runs is a property of the corpus
    size rather than a tuning knob:

    * **Flat scan**, at or below :data:`FLAT_SCAN_MAX_VECTORS` stored
      vectors. Every vector is rescored. Exact by construction -- it cannot
      miss a match -- and Ghidra's own embedded backend does the same thing
      for the same reason.
    * **Inverted index**, above that. Candidates come from the postings of
      the query's own highest-IDF features, ordered so the rarest are
      consulted first, and are then rescored exactly. Candidate generation
      is the only approximation: a true match sharing none of the query's
      rarest features with any of *its* rarest features is missed.

    Both paths score identically, so a result never depends on which ran
    except through that one omission.

    Args:
        kb: An open knowledge base holding an index.
        signature: A ``glaurung.analysis.CfrSignature``.
        k: How many matches to return.
        min_significance: Drop matches below this BSim significance.
            ``glaurung.analysis.CFR_CONFIDENT_SIGNIFICANCE`` is about one
            false positive in 100,000 on BSim's published calibration.
        force_index: Take the index path whatever the corpus size. This is
            how the two paths are compared on a corpus small enough to hold
            both, and it is what ``test_cfr_index.py`` uses.
        force_scan: Take the scan path whatever the corpus size.
        candidate_limit: Stop generating candidates after this many distinct
            vectors. A bound on work, not on correctness: the rarest
            features are consulted first, so what a low limit drops is the
            weakest evidence.

    Returns:
        Up to ``k`` :class:`CfrMatch`, best first. Ties break on
        significance and then on ``vector_id``, so the order is total and
        reproducible.

    Raises:
        ValueError: Both ``force_index`` and ``force_scan`` were given.
    """
    import glaurung as g

    if force_index and force_scan:
        raise ValueError("force_index and force_scan are mutually exclusive")
    _ensure(kb._conn)
    weights = load_cfr_weights(kb)
    if weights is None:
        return []

    cur = kb._conn.cursor()
    vectors, _ = cfr_index_size(kb)
    use_index = force_index or (not force_scan and vectors > FLAT_SCAN_MAX_VECTORS)

    if use_index:
        candidates = _candidates_from_postings(cur, signature, weights, candidate_limit)
        if not candidates:
            return []
        placeholders = ",".join("?" * len(candidates))
        cur.execute(
            "SELECT vector_id, vector_hash, features, refcount FROM feature_vector "
            f"WHERE vector_id IN ({placeholders})",
            candidates,
        )
    else:
        cur.execute(
            "SELECT vector_id, vector_hash, features, refcount FROM feature_vector"
        )

    scored: List[Tuple[float, float, int, str, int, Dict[str, Any]]] = []
    for vector_id, digest, blob, refcount in cur.fetchall():
        candidate = g.analysis.CfrSignature.from_features(
            decode_features(blob), nosize=bool(weights.version[2] & 1)
        )
        result = g.analysis.cfr_confidence(signature, candidate, weights)
        if min_significance is not None and result["significance"] < min_significance:
            continue
        scored.append(
            (
                result["cosine"],
                result["significance"],
                int(vector_id),
                str(digest),
                int(refcount),
                result,
            )
        )

    scored.sort(key=lambda row: (-row[0], -row[1], row[2]))
    out: List[CfrMatch] = []
    for cosine, significance, vector_id, digest, refcount, result in scored[:k]:
        cur.execute(
            "SELECT binary_id, entry_va FROM function_vector "
            "WHERE vector_id = ? ORDER BY binary_id, entry_va LIMIT 1",
            (vector_id,),
        )
        row = cur.fetchone()
        binary_id, entry_va = (0, 0) if row is None else (int(row[0]), int(row[1]))
        out.append(
            CfrMatch(
                binary_id=binary_id,
                entry_va=entry_va,
                vector_id=vector_id,
                digest=digest,
                cosine=cosine,
                significance=significance,
                self_significance=result["self_significance"],
                false_positive_one_in=result["false_positive_one_in"],
                refcount=refcount,
            )
        )
    return out


def _candidates_from_postings(
    cur: sqlite3.Cursor,
    signature: "CfrSignature",
    weights: "CfrWeights",
    candidate_limit: int,
) -> List[int]:
    """Vector ids reachable from the query's rarest features, rarest first.

    Ordered by ascending corpus frequency, which is what the research
    synthesis means by "ordered by ascending corpus frequency so a prefix
    is the rarest tokens": consulting the rarest feature first means a
    truncated candidate set has dropped the weakest evidence rather than an
    arbitrary slice of it.
    """
    query_features = list(signature.features)
    ordered = _rarest_features(query_features, weights, len(query_features))
    seen: Dict[int, None] = {}
    for feature_hash in ordered:
        cur.execute(
            "SELECT vector_id FROM feature_posting WHERE feature_hash = ? "
            "ORDER BY vector_id",
            (int(feature_hash),),
        )
        for (vector_id,) in cur.fetchall():
            if vector_id not in seen:
                seen[int(vector_id)] = None
        if len(seen) >= candidate_limit:
            break
    return list(seen)[:candidate_limit]
