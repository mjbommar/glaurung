"""L1 structural invariants, persisted as scalars.

``function_identity`` stores a *digest* -- one opaque string that answers
"same or not". This table stores the numbers behind the question
"how far apart", which is what ranking a changed-function list needs:
the three BinDiff MD-indices, the small-primes product over mnemonics,
and the block / edge / loop / SCC / call counts. Every column is an
integer or a real, so every one of them is B-tree indexable and no
approximate-nearest-neighbour structure is involved anywhere.

The formulas, their sources and what each one is invariant to live in
``docs/analysis/function-identity-structural.md`` and on the Rust type
(``src/identity/structural/``). This module is storage and lookup only;
it computes nothing itself beyond calling the native binding.

No ``set_by``, on purpose
-------------------------
Every annotation table in ``xref_db`` carries ``set_by`` because an
annotation is an assertion someone made and "manual always wins". A
structural signature is a *measurement of the bytes*: there is no
analyst opinion to outrank, recomputing must overwrite unconditionally,
and a column inviting someone to hand-write an MD-index would be a
column inviting someone to lie about one. ``function_identity`` makes
the same choice for the same reason.

Storing a ``u64`` in a signed column
------------------------------------
SQLite's INTEGER is a signed 64-bit value and the SPP is unsigned, so
values at or above ``2**63`` are stored as their two's-complement
negative and mapped back on read. :func:`_spp_to_db` and
:func:`_spp_from_db` are the only two places that know this; everything
above them sees a plain unsigned integer.
"""

from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple

from .persistent import PersistentKnowledgeBase

#: The scheme these rows were computed under. Must track
#: ``glaurung.analysis.STRUCTURAL_SCHEME``; a mismatch means the stored
#: rows were written by a different definition of the invariants and
#: have to be recomputed rather than compared.
STRUCTURAL_L1_V1 = "glaurung-structural-l1-v1"

#: Diaphora's rarity gate, verbatim: a feature is usable as an identity
#: only when it occurs at most twice on *each* side. Two is not one --
#: it admits the common "this function and its cold clone" pair -- but
#: it excludes the thunk shapes that occur hundreds of times and would
#: otherwise pair at random.
RARE_MAX_OCCURRENCES = 2

#: Diaphora's companion gate, ``nodes > 5``. A four-block function has
#: too few distinct MD-index values available to it for equality to mean
#: anything; the rarity count alone does not catch this because a small
#: shape can still be rare *in one binary* by accident.
RARE_MIN_BLOCKS = 6

#: Decimal places an MD-index is rounded to before it is used as a
#: dictionary key. The value is a sum of sorted reciprocals and is
#: reproducible bit for bit within one build, but a stored REAL that has
#: been through a different float printer (a JSON export, another SQLite
#: version's formatting) can differ in the last place. Twelve places is
#: far below any real difference between two distinct CFG shapes -- the
#: smallest per-edge term for a plausible graph is around 0.02 -- and far
#: above the last-place noise.
MD_INDEX_KEY_PLACES = 12

_COLUMNS: Tuple[str, ...] = (
    "entry_va",
    "name",
    "md_index_top_down",
    "md_index_bottom_up",
    "md_index_relaxed",
    "mnemonic_spp",
    "basic_blocks",
    "edges",
    "back_edges",
    "loops",
    "strongly_connected_components",
    "cyclomatic_complexity",
    "instructions",
    "calls_out_direct",
    "calls_out_indirect",
    "callers_in",
    "string_refs",
    "rare_constants_json",
)

_SCHEMA = """
-- L1 structural invariants, one row per discovered function.
--
-- Keyed (binary_id, entry_va) with no scheme in the key: a function has
-- exactly one set of structural invariants under the scheme this build
-- computes, and a scheme change means recomputing the table rather than
-- accumulating a second generation beside the first. `scheme` is kept as
-- a plain column so a reader can tell which definition wrote the row.
CREATE TABLE IF NOT EXISTS function_structural (
    binary_id INTEGER NOT NULL,
    entry_va INTEGER NOT NULL,
    scheme TEXT NOT NULL,
    name TEXT NOT NULL,
    md_index_top_down REAL NOT NULL,
    md_index_bottom_up REAL NOT NULL,
    md_index_relaxed REAL NOT NULL,
    -- Two's-complement of the u64 product; see the module docstring.
    mnemonic_spp INTEGER NOT NULL,
    basic_blocks INTEGER NOT NULL,
    edges INTEGER NOT NULL,
    back_edges INTEGER NOT NULL,
    loops INTEGER NOT NULL,
    strongly_connected_components INTEGER NOT NULL,
    cyclomatic_complexity INTEGER NOT NULL,
    instructions INTEGER NOT NULL,
    calls_out_direct INTEGER NOT NULL,
    calls_out_indirect INTEGER NOT NULL,
    callers_in INTEGER NOT NULL,
    string_refs INTEGER NOT NULL,
    -- JSON array of the rare-constant multiset, ascending. A JSON column
    -- rather than a side table: it is read whole or not at all, capped at
    -- 64 entries by the producer, and never joined on.
    rare_constants_json TEXT NOT NULL,
    set_at INTEGER,
    PRIMARY KEY (binary_id, entry_va)
);
-- The two lookups the diff pass makes: "which functions in the other
-- build share this MD-index" and "which share this mnemonic product".
CREATE INDEX IF NOT EXISTS idx_function_structural_md
    ON function_structural(md_index_top_down, md_index_bottom_up);
CREATE INDEX IF NOT EXISTS idx_function_structural_spp
    ON function_structural(mnemonic_spp);
CREATE INDEX IF NOT EXISTS idx_function_structural_binary
    ON function_structural(binary_id);
"""


@dataclass(frozen=True)
class StructuralSignatureRow:
    """One ``(binary_id, entry_va)`` row of structural invariants.

    Mirrors the native ``glaurung.analysis.StructuralSignature`` field
    for field, plus the two key columns. Frozen because a row describes
    a specific set of bytes; changing one in place produces a row that
    claims to describe a function it no longer describes.
    """

    binary_id: int
    entry_va: int
    name: str
    md_index_top_down: float
    md_index_bottom_up: float
    md_index_relaxed: float
    mnemonic_spp: int
    basic_blocks: int
    edges: int
    back_edges: int
    loops: int
    strongly_connected_components: int
    cyclomatic_complexity: int
    instructions: int
    calls_out_direct: int
    calls_out_indirect: int
    callers_in: int
    string_refs: int
    rare_constants: Tuple[int, ...] = ()
    scheme: str = STRUCTURAL_L1_V1

    def md_index_key(self) -> Tuple[float, float, float]:
        """The quantised MD-index triple used as a rematch key.

        Rounded to :data:`MD_INDEX_KEY_PLACES` so a value that has been
        through a different float printer still lands in the same
        bucket. All three variants participate: two functions can agree
        on the relaxed index while differing in where their exits sit,
        and pairing those would be a wrong answer that looked confident.
        """
        return (
            round(self.md_index_top_down, MD_INDEX_KEY_PLACES),
            round(self.md_index_bottom_up, MD_INDEX_KEY_PLACES),
            round(self.md_index_relaxed, MD_INDEX_KEY_PLACES),
        )

    def is_rarity_eligible(self) -> bool:
        """Is this function big enough for MD-index equality to mean
        something? Diaphora's ``nodes > 5``."""
        return self.basic_blocks >= RARE_MIN_BLOCKS


# ---------------------------------------------------------------------------
# u64 <-> signed INTEGER
# ---------------------------------------------------------------------------

_U64 = 1 << 64
_I64_MAX = (1 << 63) - 1


def _spp_to_db(value: int) -> int:
    """Map an unsigned 64-bit product onto SQLite's signed INTEGER."""
    value &= _U64 - 1
    return value - _U64 if value > _I64_MAX else value


def _spp_from_db(value: int) -> int:
    """Undo :func:`_spp_to_db`."""
    return value + _U64 if value < 0 else value


# ---------------------------------------------------------------------------
# Computing
# ---------------------------------------------------------------------------


def row_from_signature(sig, *, binary_id: int = 0) -> StructuralSignatureRow:
    """Convert one native ``glaurung.analysis.StructuralSignature``.

    Separate from :func:`compute_structural_signatures` because a caller
    that already holds the native objects -- the diff pass does, because
    it also needs them for ``structural_ranking_similarity`` -- must not
    have to run discovery a second time to get the storable form.
    """
    return StructuralSignatureRow(
        binary_id=int(binary_id),
        entry_va=int(sig.entry_va),
        name=str(sig.name),
        md_index_top_down=float(sig.md_index_top_down),
        md_index_bottom_up=float(sig.md_index_bottom_up),
        md_index_relaxed=float(sig.md_index_relaxed),
        mnemonic_spp=int(sig.mnemonic_spp),
        basic_blocks=int(sig.basic_blocks),
        edges=int(sig.edges),
        back_edges=int(sig.back_edges),
        loops=int(sig.loops),
        strongly_connected_components=int(sig.strongly_connected_components),
        cyclomatic_complexity=int(sig.cyclomatic_complexity),
        instructions=int(sig.instructions),
        calls_out_direct=int(sig.calls_out_direct),
        calls_out_indirect=int(sig.calls_out_indirect),
        callers_in=int(sig.callers_in),
        string_refs=int(sig.string_refs),
        rare_constants=tuple(int(c) for c in sig.rare_constants),
    )


def compute_structural_signatures(
    binary_path: str,
    **budgets: int,
) -> Dict[int, StructuralSignatureRow]:
    """Compute every discovered function's structural signature.

    Returns ``{entry_va: row}`` with ``binary_id`` left at ``0`` -- these
    are not yet bound to a KB row. ``budgets`` is forwarded verbatim to
    ``glaurung.analysis.structural_signatures_path``; see that function
    for the keyword names and their defaults.
    """
    import glaurung as g

    out: Dict[int, StructuralSignatureRow] = {}
    for sig in g.analysis.structural_signatures_path(str(binary_path), **budgets):
        row = row_from_signature(sig)
        out[row.entry_va] = row
    return out


# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------


def _ensure(conn: sqlite3.Connection) -> None:
    """Create ``function_structural`` and its indexes if they are missing.

    Idempotent, runs on every entry point, and deliberately owns its own
    DDL rather than joining ``xref_db``'s schema script: nothing in
    ``xref_db`` reads this table, and a computed-facts table has no
    business in the file that defines the annotation tables' provenance
    rules.
    """
    conn.executescript(_SCHEMA)


def _row_params(binary_id: int, row: StructuralSignatureRow, now: int) -> tuple:
    return (
        int(binary_id),
        int(row.entry_va),
        row.scheme,
        row.name,
        float(row.md_index_top_down),
        float(row.md_index_bottom_up),
        float(row.md_index_relaxed),
        _spp_to_db(int(row.mnemonic_spp)),
        int(row.basic_blocks),
        int(row.edges),
        int(row.back_edges),
        int(row.loops),
        int(row.strongly_connected_components),
        int(row.cyclomatic_complexity),
        int(row.instructions),
        int(row.calls_out_direct),
        int(row.calls_out_indirect),
        int(row.callers_in),
        int(row.string_refs),
        json.dumps(list(row.rare_constants)),
        now,
    )


_INSERT = (
    "INSERT OR REPLACE INTO function_structural "
    "(binary_id, entry_va, scheme, name, md_index_top_down, md_index_bottom_up, "
    " md_index_relaxed, mnemonic_spp, basic_blocks, edges, back_edges, loops, "
    " strongly_connected_components, cyclomatic_complexity, instructions, "
    " calls_out_direct, calls_out_indirect, callers_in, string_refs, "
    " rare_constants_json, set_at) "
    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
)

_SELECT = (
    "SELECT binary_id, entry_va, scheme, name, md_index_top_down, "
    " md_index_bottom_up, md_index_relaxed, mnemonic_spp, basic_blocks, edges, "
    " back_edges, loops, strongly_connected_components, cyclomatic_complexity, "
    " instructions, calls_out_direct, calls_out_indirect, callers_in, "
    " string_refs, rare_constants_json "
    "FROM function_structural"
)


def _from_db_row(r: Sequence) -> StructuralSignatureRow:
    return StructuralSignatureRow(
        binary_id=int(r[0]),
        entry_va=int(r[1]),
        scheme=str(r[2]),
        name=str(r[3]),
        md_index_top_down=float(r[4]),
        md_index_bottom_up=float(r[5]),
        md_index_relaxed=float(r[6]),
        mnemonic_spp=_spp_from_db(int(r[7])),
        basic_blocks=int(r[8]),
        edges=int(r[9]),
        back_edges=int(r[10]),
        loops=int(r[11]),
        strongly_connected_components=int(r[12]),
        cyclomatic_complexity=int(r[13]),
        instructions=int(r[14]),
        calls_out_direct=int(r[15]),
        calls_out_indirect=int(r[16]),
        callers_in=int(r[17]),
        string_refs=int(r[18]),
        rare_constants=tuple(int(c) for c in json.loads(r[19] or "[]")),
    )


def set_function_structural(
    kb: PersistentKnowledgeBase,
    row: StructuralSignatureRow,
) -> None:
    """Store one function's structural signature in the KB's current binary.

    Overwrites unconditionally. There is no ``set_by`` and no manual
    precedence: this is a measurement, and a stale measurement is worse
    than a fresh one.
    """
    _ensure(kb._conn)
    kb._conn.execute(_INSERT, _row_params(kb.binary_id, row, int(time.time())))
    kb._conn.commit()


def index_function_structural(
    kb: PersistentKnowledgeBase,
    binary_path: str,
    **budgets: int,
) -> int:
    """Compute and store a signature for every function in ``binary_path``.

    Idempotent: re-running refreshes the rows in place. Returns the
    number of signatures stored.
    """
    _ensure(kb._conn)
    rows = compute_structural_signatures(binary_path, **budgets)
    now = int(time.time())
    kb._conn.executemany(
        _INSERT,
        [_row_params(kb.binary_id, r, now) for r in rows.values()],
    )
    kb._conn.commit()
    return len(rows)


def is_indexed(kb: PersistentKnowledgeBase) -> bool:
    """True when this binary has at least one stored structural signature."""
    _ensure(kb._conn)
    cur = kb._conn.execute(
        "SELECT 1 FROM function_structural WHERE binary_id = ? LIMIT 1",
        (kb.binary_id,),
    )
    return cur.fetchone() is not None


# ---------------------------------------------------------------------------
# Lookup
# ---------------------------------------------------------------------------


def get_function_structural(
    kb: PersistentKnowledgeBase,
    entry_va: int,
) -> Optional[StructuralSignatureRow]:
    """One function's stored signature, or ``None``."""
    _ensure(kb._conn)
    cur = kb._conn.execute(
        _SELECT + " WHERE binary_id = ? AND entry_va = ?",
        (kb.binary_id, int(entry_va)),
    )
    r = cur.fetchone()
    return _from_db_row(r) if r is not None else None


def list_function_structural(
    kb: PersistentKnowledgeBase,
    *,
    binary_id: Optional[int] = None,
) -> List[StructuralSignatureRow]:
    """Every stored signature for one binary, ascending by entry address."""
    _ensure(kb._conn)
    cur = kb._conn.execute(
        _SELECT + " WHERE binary_id = ? ORDER BY entry_va",
        (kb.binary_id if binary_id is None else int(binary_id),),
    )
    return [_from_db_row(r) for r in cur.fetchall()]


def find_by_md_index(
    kb: PersistentKnowledgeBase,
    row: StructuralSignatureRow,
    *,
    binary_id: Optional[int] = None,
) -> List[StructuralSignatureRow]:
    """Every stored row whose quantised MD-index triple equals ``row``'s.

    The equality is done in Python over the quantised keys rather than
    in SQL over the raw REALs, because SQL equality on a float is exact
    and the whole point of :data:`MD_INDEX_KEY_PLACES` is that it should
    not be. The index on ``(md_index_top_down, md_index_bottom_up)``
    still does the work: the range scan below narrows to the neighbours
    before the quantised comparison runs.
    """
    _ensure(kb._conn)
    eps = 10.0 ** (-MD_INDEX_KEY_PLACES) * 10.0
    cur = kb._conn.execute(
        _SELECT + " WHERE binary_id = ? AND md_index_top_down BETWEEN ? AND ? "
        "ORDER BY entry_va",
        (
            kb.binary_id if binary_id is None else int(binary_id),
            row.md_index_top_down - eps,
            row.md_index_top_down + eps,
        ),
    )
    want = row.md_index_key()
    return [
        candidate
        for candidate in (_from_db_row(r) for r in cur.fetchall())
        if candidate.md_index_key() == want
    ]


# ---------------------------------------------------------------------------
# Rarity gating (Diaphora's rule)
# ---------------------------------------------------------------------------


def rarity_counts(
    rows: Sequence[StructuralSignatureRow],
) -> Dict[Tuple[float, float, float], int]:
    """How many functions in ``rows`` carry each MD-index key.

    The denominator for the rarity gate. Counted over the WHOLE binary,
    not over whichever subset a caller happens to be pairing: a shape
    that occurs 400 times is not made rare by the fact that only two of
    those 400 are currently unmatched.
    """
    counts: Dict[Tuple[float, float, float], int] = {}
    for row in rows:
        key = row.md_index_key()
        counts[key] = counts.get(key, 0) + 1
    return counts


def rare_by_md_index(
    rows: Sequence[StructuralSignatureRow],
    *,
    max_occurrences: int = RARE_MAX_OCCURRENCES,
    min_blocks: int = RARE_MIN_BLOCKS,
) -> Dict[Tuple[float, float, float], List[StructuralSignatureRow]]:
    """The MD-index keys that are rare enough to serve as an identity.

    Diaphora's rule, restated: a feature identifies a function only when
    it is globally rare (``HAVING count(*) <= 2``) and the function is
    big enough for the feature to carry information (``nodes > 5``).
    Keys failing either gate are absent from the result -- they are not
    returned with a flag, because every caller of this function wants the
    same thing and an "unusable identity" that has to be filtered again
    downstream is an invitation to forget.

    Rows for one key come back ascending by entry address.
    """
    counts = rarity_counts(rows)
    out: Dict[Tuple[float, float, float], List[StructuralSignatureRow]] = {}
    for row in rows:
        if not row.is_rarity_eligible() or row.basic_blocks < min_blocks:
            continue
        key = row.md_index_key()
        if counts[key] > max_occurrences:
            continue
        out.setdefault(key, []).append(row)
    for bucket in out.values():
        bucket.sort(key=lambda r: r.entry_va)
    return out
