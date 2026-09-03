"""Signature-library provenance and match auditing (item 7 of the identity
ladder's execution plan, ``docs/history/program-measures-2026-09-02.md``).

Four tables, exactly sections 1, 2, 7 and 8 of
``docs/history/program-measures-2026-09-02/03-schema.sql``:

``siglib``
    One row per signature library, keyed ``(name, version, variant,
    architecture, platform)`` -- Ghidra FunctionID's ``LibrariesTable`` with
    WARP's ``Target`` bolted on. No exact or masked scheme crosses an
    optimisation level, so a corpus spanning gcc and clang across ``-O0`` to
    ``-O3`` is not one library; it is N libraries sharing a name, and
    ``variant`` is what tells them apart.

``siglib_function``
    What we match *against*: one row per known-library function, deduplicated
    on ``(siglib_id, scheme, identity, name)`` the way BSim dedups
    ``vectable``. ``base_name`` is FunctionID's grouping key -- the demangled
    name with its namespace and leading underscores stripped -- and
    ``occurrences`` is Lumina's "popularity", the cheapest false-positive
    signal available.

``identity_filter``
    A serialized :mod:`glaurung.analysis` BinaryFuse8 gate
    (``identity_gate_build``/``identity_gate_contains``), one row per
    ``(scheme, architecture)``. Consulted before any ``siglib_function``
    lookup: a negative is definitive.

``function_match``
    What a match pass concluded, auditable and re-rankable without
    recompute. ``evidence`` names which level resolved it (``flirt-L1``
    through ``flirt-L4``, ``warp-guid``, ``warp-constraint``);
    ``ambiguous = 1`` means more than one candidate survived and **no name
    was applied** -- "no name beats a wrong name" all the way down to this
    table.

See ``docs/reference/function-signature-libraries.md``'s "Provenance and the
membership gate" section for the wiring this module performs end to end:
:func:`ingest_flirt_library` records the shipped ``mathlib`` library's
provenance, :func:`match_flirt_library` and :func:`match_warp_library` are
the two match paths that write :func:`record_function_match` rows.
"""

from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence

from .persistent import PersistentKnowledgeBase

#: `identity_filter.kind` / what `glaurung.analysis.identity_gate_build`
#: produces. Tracked here rather than hard-coded at each call site so a
#: second gate implementation (there is exactly one planned: none) would
#: only need to change in one place.
GATE_KIND = "binary-fuse-8"

#: `siglib_function.scheme` for FLIRT masked-pattern identities -- must track
#: `glaurung.analysis.FLIRT_MASKED_PATTERN_SCHEME` / `crate::flirt::MASKED_PATTERN_SCHEME`.
#: Not a `function_identity` scheme: a masked pattern is not an equality key,
#: it is gate/provenance input. See `src/flirt/mod.rs`'s module docs.
FLIRT_MASKED_PATTERN_V1 = "flirt-masked-pattern-v1"

#: `siglib_function.scheme` for WARP function GUIDs -- the same string
#: `function_identity.WARP_FUNCTION_GUID_V1` and
#: `glaurung.analysis.warp_scheme()` use. A GUID *is* an equality key (it is
#: the L0 rung), so this scheme lives in `function_identity` too; a library
#: function under this scheme is simply a GUID known in advance.
WARP_FUNCTION_GUID_V1 = "warp-function-guid-v1"

#: `siglib` stores `platform` as `""` rather than `NULL` internally.
#: SQLite's UNIQUE constraint treats two NULLs as distinct, which would make
#: `get_or_create_siglib` insert a fresh row every time `platform` is omitted
#: -- exactly the identity-drift this table exists to prevent. `""` and
#: `None` are the same platform as far as this module's callers are
#: concerned; the round trip is only at the storage boundary.
_NO_PLATFORM = ""

_SCHEMA = """
-- Section 1: signature libraries. Ghidra FID's LibrariesTable + WARP's Target.
CREATE TABLE IF NOT EXISTS siglib (
    siglib_id     INTEGER PRIMARY KEY,
    name          TEXT NOT NULL,
    version       TEXT,
    variant       TEXT,
    architecture  TEXT NOT NULL,
    platform      TEXT NOT NULL DEFAULT '',
    source_sha256 TEXT,
    ingest_date   INTEGER,
    UNIQUE (name, version, variant, architecture, platform)
);

-- Section 2: library-side function records, what we MATCH AGAINST.
CREATE TABLE IF NOT EXISTS siglib_function (
    sigfn_id     INTEGER PRIMARY KEY,
    siglib_id    INTEGER NOT NULL REFERENCES siglib(siglib_id),
    scheme       TEXT NOT NULL,
    identity     TEXT NOT NULL,
    name         TEXT NOT NULL,
    base_name    TEXT,
    n_units      INTEGER,
    n_bytes      INTEGER,
    prototype    TEXT,
    payload      BLOB,
    occurrences  INTEGER NOT NULL DEFAULT 1,
    UNIQUE (siglib_id, scheme, identity, name)
);
CREATE INDEX IF NOT EXISTS idx_siglib_function_lookup
    ON siglib_function(scheme, identity);
CREATE INDEX IF NOT EXISTS idx_siglib_function_basename
    ON siglib_function(base_name);
CREATE INDEX IF NOT EXISTS idx_siglib_function_siglib
    ON siglib_function(siglib_id);

-- Section 7: "is this identity in ANY known library" gate, one serialized
-- BinaryFuse8 filter per (scheme, architecture). Query before touching
-- siglib_function; a negative is definitive.
CREATE TABLE IF NOT EXISTS identity_filter (
    scheme       TEXT NOT NULL,
    architecture TEXT NOT NULL,
    kind         TEXT NOT NULL,
    n_keys       INTEGER NOT NULL,
    built_at     INTEGER NOT NULL,
    filter       BLOB NOT NULL,
    PRIMARY KEY (scheme, architecture)
);

-- Section 8: match results, auditable and re-rankable without recompute.
CREATE TABLE IF NOT EXISTS function_match (
    binary_id  INTEGER NOT NULL,
    entry_va   INTEGER NOT NULL,
    scheme     TEXT NOT NULL,
    sigfn_id   INTEGER REFERENCES siglib_function(sigfn_id),
    score      REAL,
    confidence REAL,
    rank       INTEGER NOT NULL,
    ambiguous  INTEGER NOT NULL DEFAULT 0,
    evidence   TEXT,
    set_at     INTEGER,
    PRIMARY KEY (binary_id, entry_va, scheme, rank)
);
CREATE INDEX IF NOT EXISTS idx_function_match_sigfn
    ON function_match(sigfn_id);
"""


def _ensure(conn: sqlite3.Connection) -> None:
    """Create this module's four tables and indexes if missing.

    Owns its own DDL rather than joining `xref_db`'s schema script, the same
    choice `function_structural.py` makes: nothing in `xref_db` reads these
    tables, and provenance/matching has no business in the file that defines
    annotation provenance rules.
    """
    conn.executescript(_SCHEMA)


# ---------------------------------------------------------------------------
# base_name: FunctionID's grouping key
# ---------------------------------------------------------------------------


def base_name_of(name: str) -> str:
    """The demangled name with its namespace and leading underscores
    stripped -- Ghidra FunctionID's grouping key for "Multiple Matches".

    Demangling failures (the name is not mangled, or the bridge is
    unavailable) fall back to ``name`` itself, so a plain C symbol like
    ``mathlib_add`` round-trips unchanged. Namespace stripping keeps only
    the last ``::``-separated component and drops a parameter list, so an
    Itanium ``ns::Class::method(int)`` groups under ``method``.
    """
    demangled = name
    try:
        import glaurung as g

        result = g.strings.demangle_text(name)
    except Exception:
        result = None
    if result:
        demangled = result[0]
    base = demangled.rsplit("::", 1)[-1]
    base = base.split("(", 1)[0]
    stripped = base.lstrip("_")
    return stripped if stripped else base


# ---------------------------------------------------------------------------
# siglib
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Siglib:
    """One ``siglib`` row."""

    siglib_id: int
    name: str
    version: Optional[str]
    variant: Optional[str]
    architecture: str
    platform: Optional[str]
    source_sha256: Optional[str]
    ingest_date: Optional[int]


def _siglib_from_row(r: Sequence) -> Siglib:
    return Siglib(
        siglib_id=int(r[0]),
        name=str(r[1]),
        version=r[2],
        variant=r[3],
        architecture=str(r[4]),
        platform=(r[5] or None),
        source_sha256=r[6],
        ingest_date=r[7],
    )


def get_siglib(
    kb: PersistentKnowledgeBase,
    *,
    name: str,
    version: Optional[str],
    variant: Optional[str],
    architecture: str,
    platform: Optional[str] = None,
) -> Optional[Siglib]:
    """The ``siglib`` row for this exact key, or ``None``."""
    _ensure(kb._conn)
    cur = kb._conn.execute(
        "SELECT siglib_id, name, version, variant, architecture, platform, "
        "source_sha256, ingest_date FROM siglib "
        "WHERE name = ? AND version IS ? AND variant IS ? AND architecture = ? "
        "AND platform = ?",
        (name, version, variant, architecture, platform or _NO_PLATFORM),
    )
    row = cur.fetchone()
    return _siglib_from_row(row) if row is not None else None


def get_or_create_siglib(
    kb: PersistentKnowledgeBase,
    *,
    name: str,
    version: Optional[str] = None,
    variant: Optional[str] = None,
    architecture: str,
    platform: Optional[str] = None,
    source_sha256: Optional[str] = None,
) -> int:
    """Return the ``siglib_id`` for this key, creating the row if needed.

    Idempotent on ``(name, version, variant, architecture, platform)``.
    Re-ingesting the same library key never creates a second ``siglib`` row;
    ``source_sha256`` is refreshed in place, since a rebuild that changed the
    input is exactly the case worth recording.
    """
    _ensure(kb._conn)
    existing = get_siglib(
        kb,
        name=name,
        version=version,
        variant=variant,
        architecture=architecture,
        platform=platform,
    )
    if existing is not None:
        if source_sha256 is not None and source_sha256 != existing.source_sha256:
            kb._conn.execute(
                "UPDATE siglib SET source_sha256 = ?, ingest_date = ? WHERE siglib_id = ?",
                (source_sha256, int(time.time()), existing.siglib_id),
            )
            kb._conn.commit()
        return existing.siglib_id
    cur = kb._conn.execute(
        "INSERT INTO siglib (name, version, variant, architecture, platform, "
        "source_sha256, ingest_date) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            name,
            version,
            variant,
            architecture,
            platform or _NO_PLATFORM,
            source_sha256,
            int(time.time()),
        ),
    )
    kb._conn.commit()
    return int(cur.lastrowid or 0)


# ---------------------------------------------------------------------------
# siglib_function
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SiglibFunction:
    """One ``siglib_function`` row."""

    sigfn_id: int
    siglib_id: int
    scheme: str
    identity: str
    name: str
    base_name: Optional[str]
    n_units: Optional[int]
    n_bytes: Optional[int]
    prototype: Optional[str]
    occurrences: int


_SIGFN_COLUMNS = (
    "sigfn_id, siglib_id, scheme, identity, name, base_name, n_units, "
    "n_bytes, prototype, occurrences"
)


def _sigfn_from_row(r: Sequence) -> SiglibFunction:
    return SiglibFunction(
        sigfn_id=int(r[0]),
        siglib_id=int(r[1]),
        scheme=str(r[2]),
        identity=str(r[3]),
        name=str(r[4]),
        base_name=r[5],
        n_units=r[6],
        n_bytes=r[7],
        prototype=r[8],
        occurrences=int(r[9]),
    )


def add_siglib_function(
    kb: PersistentKnowledgeBase,
    siglib_id: int,
    *,
    scheme: str,
    identity: str,
    name: str,
    base_name: Optional[str] = None,
    n_units: Optional[int] = None,
    n_bytes: Optional[int] = None,
    prototype: Optional[str] = None,
    payload: Optional[bytes] = None,
    occurrences: int = 1,
) -> int:
    """Insert or update one library function record.

    Idempotent on ``(siglib_id, scheme, identity, name)``: re-ingesting the
    same signature bumps ``occurrences`` (Lumina's popularity counter, BSim's
    ``vectable.count``) rather than duplicating the row.
    """
    _ensure(kb._conn)
    if base_name is None:
        base_name = base_name_of(name)
    cur = kb._conn.execute(
        "SELECT sigfn_id, occurrences FROM siglib_function "
        "WHERE siglib_id = ? AND scheme = ? AND identity = ? AND name = ?",
        (siglib_id, scheme, identity, name),
    )
    row = cur.fetchone()
    if row is not None:
        sigfn_id, prior_occurrences = int(row[0]), int(row[1])
        kb._conn.execute(
            "UPDATE siglib_function SET occurrences = ?, base_name = ?, "
            "n_units = ?, n_bytes = ?, prototype = ?, payload = ? "
            "WHERE sigfn_id = ?",
            (
                prior_occurrences + int(occurrences),
                base_name,
                n_units,
                n_bytes,
                prototype,
                payload,
                sigfn_id,
            ),
        )
        kb._conn.commit()
        return sigfn_id
    cur = kb._conn.execute(
        "INSERT INTO siglib_function (siglib_id, scheme, identity, name, "
        "base_name, n_units, n_bytes, prototype, payload, occurrences) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            siglib_id,
            scheme,
            identity,
            name,
            base_name,
            n_units,
            n_bytes,
            prototype,
            payload,
            int(occurrences),
        ),
    )
    kb._conn.commit()
    return int(cur.lastrowid or 0)


def list_siglib_functions(
    kb: PersistentKnowledgeBase,
    siglib_id: int,
    *,
    scheme: Optional[str] = None,
) -> List[SiglibFunction]:
    """Every function record for one library, optionally scoped to a scheme."""
    _ensure(kb._conn)
    if scheme is None:
        cur = kb._conn.execute(
            f"SELECT {_SIGFN_COLUMNS} FROM siglib_function WHERE siglib_id = ? "
            "ORDER BY name",
            (siglib_id,),
        )
    else:
        cur = kb._conn.execute(
            f"SELECT {_SIGFN_COLUMNS} FROM siglib_function "
            "WHERE siglib_id = ? AND scheme = ? ORDER BY name",
            (siglib_id, scheme),
        )
    return [_sigfn_from_row(r) for r in cur.fetchall()]


def find_siglib_functions(
    kb: PersistentKnowledgeBase,
    *,
    scheme: str,
    identity: str,
    siglib_id: Optional[int] = None,
) -> List[SiglibFunction]:
    """Every library function carrying ``identity`` under ``scheme``.

    This is the equality lookup a gate hit precedes: more than one row means
    a genuine collision (two known functions share an identity), which the
    caller must report as ambiguous rather than resolve by guessing.
    """
    _ensure(kb._conn)
    if siglib_id is None:
        cur = kb._conn.execute(
            f"SELECT {_SIGFN_COLUMNS} FROM siglib_function "
            "WHERE scheme = ? AND identity = ? ORDER BY name",
            (scheme, identity),
        )
    else:
        cur = kb._conn.execute(
            f"SELECT {_SIGFN_COLUMNS} FROM siglib_function "
            "WHERE siglib_id = ? AND scheme = ? AND identity = ? ORDER BY name",
            (siglib_id, scheme, identity),
        )
    return [_sigfn_from_row(r) for r in cur.fetchall()]


# ---------------------------------------------------------------------------
# Ingesting the FLIRT library file
# ---------------------------------------------------------------------------


@dataclass
class IngestSummary:
    """What :func:`ingest_flirt_library` did."""

    siglib_id: int = 0
    functions_ingested: int = 0
    functions_skipped: int = 0


def _masked_pattern_hex(prologue_hex: str, mask_hex: Optional[str]) -> str:
    """The [`FLIRT_MASKED_PATTERN_V1`] identity: the pattern with every
    variant byte forced to zero, hex encoded. Mirrors
    ``build_flirt_library.py::_masked_pattern`` and
    ``src/flirt/mod.rs``'s ``FlirtSignature::masked_pattern_hex`` exactly --
    three independent implementations of the same equivalence would be worse
    than a shared one, but the pattern is small enough here that a fourth
    (pure-Python, no native call) is worth it for the case this module has
    no compiled library object to query.
    """
    if not mask_hex:
        return prologue_hex
    pattern = bytes.fromhex(prologue_hex)
    mask = bytes.fromhex(mask_hex)
    return bytes(p & m for p, m in zip(pattern, mask)).hex()


def ingest_flirt_library(
    kb: PersistentKnowledgeBase,
    flirt_library_path: str,
    *,
    source_sha256: Optional[str] = None,
) -> IngestSummary:
    """Record a FLIRT-style signature library's provenance in the KB.

    Reads the file's ``library`` key for the ``siglib`` row
    (``(name, version, variant, architecture)``) and inserts one
    ``siglib_function`` row per entry under :data:`FLIRT_MASKED_PATTERN_V1`,
    keyed by the masked-pattern identity so it can also seed
    :func:`build_identity_filter`.

    Either format is accepted -- a JSON library or a ``gsig/1`` container --
    and the container is read through
    :func:`glaurung.analysis.flirt_library_to_json_str`, i.e. through the
    reader that wrote it, never by parsing container bytes here.

    Args:
        kb: The knowledge base to record into.
        flirt_library_path: A JSON or ``gsig/1`` signature library.
        source_sha256: Override the recorded provenance hash. By default it
            is the SHA-256 of the file **as it sits on disk**, which is what a
            content-addressed distribution keys a blob by -- so a library and
            the container built from it record different hashes, as they
            should: they are different blobs of the same content.

    Returns:
        What was ingested.

    Raises:
        ValueError: the file has no ``library`` key. A schema-version-1 file
            (exact prologues, no provenance) cannot be ingested: there is no
            key to file it under.
    """
    import hashlib
    import json
    from pathlib import Path

    import glaurung as g

    raw = Path(flirt_library_path).read_bytes()
    data = json.loads(g.analysis.flirt_library_to_json_str(flirt_library_path))
    library = data.get("library")
    if not library:
        raise ValueError(
            f"{flirt_library_path} carries no 'library' key (schema version "
            f"{data.get('schema_version')!r}); build it with --archive so it "
            "has a (name, version, variant, arch) key to file provenance under"
        )
    if source_sha256 is None:
        source_sha256 = hashlib.sha256(raw).hexdigest()

    siglib_id = get_or_create_siglib(
        kb,
        name=library["name"],
        version=library.get("version"),
        variant=library.get("variant"),
        architecture=library["arch"],
        source_sha256=source_sha256,
    )

    summary = IngestSummary(siglib_id=siglib_id)
    for entry in data.get("entries", []):
        prologue_hex = entry.get("prologue_hex")
        if not prologue_hex:
            summary.functions_skipped += 1
            continue
        identity = _masked_pattern_hex(prologue_hex, entry.get("mask_hex"))
        name = entry["name"]
        add_siglib_function(
            kb,
            siglib_id,
            scheme=FLIRT_MASKED_PATTERN_V1,
            identity=identity,
            name=name,
            base_name=base_name_of(name),
            n_bytes=entry.get("function_len"),
        )
        summary.functions_ingested += 1
    return summary


# ---------------------------------------------------------------------------
# The BinaryFuse8 membership gate
# ---------------------------------------------------------------------------


@dataclass
class GateStats:
    """Probe counters for one match pass's use of the gate.

    Mirrors ``crate::identity::gate::GateStats``: the gate's value
    proposition is "a negative is definitive", so what matters is how many
    probes it answered before a `siglib_function` lookup ran.
    """

    probes: int = 0
    negatives: int = 0

    def record(self, present: bool) -> None:
        self.probes += 1
        if not present:
            self.negatives += 1

    @property
    def negative_rate(self) -> float:
        return 0.0 if self.probes == 0 else self.negatives / self.probes


@dataclass
class GateBuildSummary:
    """What :func:`build_identity_filter` did."""

    scheme: str
    architecture: str
    n_keys: int
    bits_per_key: float


def build_identity_filter(
    kb: PersistentKnowledgeBase,
    *,
    scheme: str,
    architecture: str,
) -> GateBuildSummary:
    """Build and store a BinaryFuse8 gate over every known identity for
    ``(scheme, architecture)``.

    The identity universe is every ``siglib_function.identity`` row whose
    own ``scheme`` matches and whose owning ``siglib.architecture`` matches
    -- "is this in ANY known library", not a survey of one library alone.

    Raises:
        ValueError: no ``siglib_function`` rows exist for this
            ``(scheme, architecture)`` yet; a gate over zero identities is
            refused natively rather than silently rejecting everything.
    """
    import glaurung as g

    _ensure(kb._conn)
    cur = kb._conn.execute(
        "SELECT DISTINCT sf.identity FROM siglib_function sf "
        "JOIN siglib s ON s.siglib_id = sf.siglib_id "
        "WHERE sf.scheme = ? AND s.architecture = ?",
        (scheme, architecture),
    )
    identities = [str(r[0]) for r in cur.fetchall()]
    if not identities:
        raise ValueError(
            f"no siglib_function rows for scheme={scheme!r} "
            f"architecture={architecture!r}; ingest a library first"
        )
    blob = g.analysis.identity_gate_build(identities)
    n_keys = g.analysis.identity_gate_n_keys(blob)
    bits_per_key = (len(blob) * 8.0) / n_keys if n_keys else 0.0
    kb._conn.execute(
        "INSERT OR REPLACE INTO identity_filter "
        "(scheme, architecture, kind, n_keys, built_at, filter) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (scheme, architecture, GATE_KIND, n_keys, int(time.time()), blob),
    )
    kb._conn.commit()
    return GateBuildSummary(
        scheme=scheme,
        architecture=architecture,
        n_keys=n_keys,
        bits_per_key=bits_per_key,
    )


def get_identity_filter(
    kb: PersistentKnowledgeBase,
    *,
    scheme: str,
    architecture: str,
) -> Optional[bytes]:
    """The raw gate bytes for ``(scheme, architecture)``, or ``None`` if
    none has been built."""
    _ensure(kb._conn)
    cur = kb._conn.execute(
        "SELECT filter FROM identity_filter WHERE scheme = ? AND architecture = ?",
        (scheme, architecture),
    )
    row = cur.fetchone()
    return bytes(row[0]) if row is not None else None


def gate_contains(
    kb: PersistentKnowledgeBase,
    *,
    scheme: str,
    architecture: str,
    identity: str,
    stats: Optional[GateStats] = None,
) -> Optional[bool]:
    """Consult the ``(scheme, architecture)`` gate for ``identity``.

    Returns ``None`` -- "no gate, no opinion" -- when none has been built for
    this ``(scheme, architecture)``; a caller must treat that as "cannot
    skip the lookup", never as a negative. When a gate exists, ``False`` is
    definitive.
    """
    blob = get_identity_filter(kb, scheme=scheme, architecture=architecture)
    if blob is None:
        return None
    import glaurung as g

    present = bool(g.analysis.identity_gate_contains(blob, identity))
    if stats is not None:
        stats.record(present)
    return present


# ---------------------------------------------------------------------------
# function_match
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FunctionMatch:
    """One ``function_match`` row."""

    binary_id: int
    entry_va: int
    scheme: str
    sigfn_id: Optional[int]
    score: Optional[float]
    confidence: Optional[float]
    rank: int
    ambiguous: bool
    evidence: Optional[str]


def _match_from_row(r: Sequence) -> FunctionMatch:
    return FunctionMatch(
        binary_id=int(r[0]),
        entry_va=int(r[1]),
        scheme=str(r[2]),
        sigfn_id=r[3],
        score=r[4],
        confidence=r[5],
        rank=int(r[6]),
        ambiguous=bool(r[7]),
        evidence=r[8],
    )


def record_function_match(
    kb: PersistentKnowledgeBase,
    *,
    entry_va: int,
    scheme: str,
    sigfn_id: Optional[int] = None,
    score: Optional[float] = None,
    confidence: Optional[float] = None,
    rank: int = 1,
    ambiguous: bool = False,
    evidence: Optional[str] = None,
    binary_id: Optional[int] = None,
) -> None:
    """Store one match result for one function in the KB's current binary.

    ``ambiguous = True`` and ``evidence = None`` must travel together --
    "no name beats a wrong name" -- but this is not enforced here beyond
    documentation, because a caller recording *why* something is ambiguous
    (a future evidence value naming the collision) should not have to fight
    the setter to do it. What every caller in this module does is: ambiguous
    rows get ``evidence=None``.
    """
    _ensure(kb._conn)
    kb._conn.execute(
        "INSERT OR REPLACE INTO function_match "
        "(binary_id, entry_va, scheme, sigfn_id, score, confidence, rank, "
        " ambiguous, evidence, set_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            kb.binary_id if binary_id is None else int(binary_id),
            int(entry_va),
            scheme,
            sigfn_id,
            score,
            confidence,
            int(rank),
            1 if ambiguous else 0,
            evidence,
            int(time.time()),
        ),
    )
    kb._conn.commit()


def list_function_matches(
    kb: PersistentKnowledgeBase,
    entry_va: int,
    *,
    scheme: Optional[str] = None,
    binary_id: Optional[int] = None,
) -> List[FunctionMatch]:
    """Every recorded match for one function, best rank first."""
    _ensure(kb._conn)
    bid = kb.binary_id if binary_id is None else int(binary_id)
    if scheme is None:
        cur = kb._conn.execute(
            "SELECT binary_id, entry_va, scheme, sigfn_id, score, confidence, "
            "rank, ambiguous, evidence FROM function_match "
            "WHERE binary_id = ? AND entry_va = ? ORDER BY scheme, rank",
            (bid, int(entry_va)),
        )
    else:
        cur = kb._conn.execute(
            "SELECT binary_id, entry_va, scheme, sigfn_id, score, confidence, "
            "rank, ambiguous, evidence FROM function_match "
            "WHERE binary_id = ? AND entry_va = ? AND scheme = ? ORDER BY rank",
            (bid, int(entry_va), scheme),
        )
    return [_match_from_row(r) for r in cur.fetchall()]


# ---------------------------------------------------------------------------
# Match paths: FLIRT and WARP against a siglib
# ---------------------------------------------------------------------------


@dataclass
class MatchSummary:
    """What one match pass against a ``siglib`` did."""

    scheme: str = ""
    candidates: int = 0
    gate_stats: GateStats = field(default_factory=GateStats)
    matched: int = 0
    ambiguous: int = 0


def match_flirt_library(
    kb: PersistentKnowledgeBase,
    binary_path: str,
    *,
    siglib_id: int,
    flirt_library_path: str,
    gate_architecture: Optional[str] = None,
) -> MatchSummary:
    """Match every function in ``binary_path`` against one FLIRT library and
    record ``function_match`` rows.

    Runs ``glaurung.analysis.flirt_match_functions_with_evidence_path`` (the
    same masked/CRC/reference escalation ``apply_flirt_overrides`` uses, but
    over every discovered function and carrying which level resolved each
    verdict) and maps each resulting name back to this ``siglib``'s
    ``siglib_function`` rows. A name the library file produced but this
    ``siglib_id`` does not carry (a stale ingest) is recorded as ambiguous
    with no ``sigfn_id`` rather than silently dropped, since the point of
    this table is not to lose that mismatch.

    If a gate has been built for
    (:data:`FLIRT_MASKED_PATTERN_V1`, ``gate_architecture``), every unique
    match is cross-checked against it first: since the matched candidate's
    bytes, once masked by the winning signature, are *by construction* that
    signature's own masked-pattern identity, this can only ever be a
    positive -- so unlike the WARP path below it does not skip the
    ``siglib_function`` lookup, it verifies the gate's own no-false-negative
    guarantee against real data and counts the probe in
    :attr:`MatchSummary.gate_stats`.
    """
    import glaurung as g

    raw = g.analysis.flirt_match_functions_with_evidence_path(
        str(binary_path), str(flirt_library_path)
    )
    functions = list_siglib_functions(kb, siglib_id, scheme=FLIRT_MASKED_PATTERN_V1)
    by_name: Dict[str, List[SiglibFunction]] = {}
    for f in functions:
        by_name.setdefault(f.name, []).append(f)
    identity_by_name = {f.name: f.identity for f in functions}

    summary = MatchSummary(scheme=FLIRT_MASKED_PATTERN_V1, candidates=len(raw))
    for m in raw:
        entry_va = int(m["entry_va"])
        if m["ambiguous"]:
            for rank, name in enumerate(sorted(m["names"]), start=1):
                candidates = by_name.get(
                    name,
                    [
                        SiglibFunction(
                            0,
                            siglib_id,
                            FLIRT_MASKED_PATTERN_V1,
                            "",
                            name,
                            None,
                            None,
                            None,
                            None,
                            0,
                        )
                    ],
                )
                for sigfn in candidates:
                    record_function_match(
                        kb,
                        entry_va=entry_va,
                        scheme=FLIRT_MASKED_PATTERN_V1,
                        sigfn_id=sigfn.sigfn_id or None,
                        rank=rank,
                        ambiguous=True,
                        evidence=None,
                    )
            summary.ambiguous += 1
            continue

        name = m["names"][0]
        candidates = by_name.get(name)
        if not candidates:
            continue
        identity = identity_by_name.get(name)
        if gate_architecture is not None and identity is not None:
            gate_contains(
                kb,
                scheme=FLIRT_MASKED_PATTERN_V1,
                architecture=gate_architecture,
                identity=identity,
                stats=summary.gate_stats,
            )
        sigfn = candidates[0]
        record_function_match(
            kb,
            entry_va=entry_va,
            scheme=FLIRT_MASKED_PATTERN_V1,
            sigfn_id=sigfn.sigfn_id,
            score=1.0,
            confidence=1.0,
            rank=1,
            ambiguous=False,
            evidence=m["evidence"],
        )
        summary.matched += 1
    return summary


def match_warp_library(
    kb: PersistentKnowledgeBase,
    binary_path: str,
    *,
    siglib_id: int,
    gate_architecture: Optional[str] = None,
) -> MatchSummary:
    """Match every function in ``binary_path`` against one WARP-scheme
    library and record ``function_match`` rows.

    For each discovered function's WARP GUID: if a gate exists for
    (:data:`WARP_FUNCTION_GUID_V1`, ``gate_architecture``) and rejects the
    GUID, the ``siglib_function`` lookup is skipped entirely and the
    rejection is counted in :attr:`MatchSummary.gate_stats` -- this is the
    gate's real pre-lookup role, unlike the FLIRT path's post-hoc check,
    because a WARP GUID is directly and exactly comparable to a library
    entry with no masking step to resolve first.

    A GUID with exactly one ``siglib_function`` row is `evidence="warp-guid"`.
    More than one distinct name sharing a GUID is a genuine collision --
    WARP deliberately never prunes those -- and is recorded ambiguous with
    no name applied, one row per candidate.
    """
    import glaurung as g

    functions = g.analysis.warp_function_guids_path(str(binary_path))
    summary = MatchSummary(scheme=WARP_FUNCTION_GUID_V1, candidates=len(functions))
    for fn in functions:
        guid = str(fn.guid)
        if gate_architecture is not None:
            present = gate_contains(
                kb,
                scheme=WARP_FUNCTION_GUID_V1,
                architecture=gate_architecture,
                identity=guid,
                stats=summary.gate_stats,
            )
            if present is False:
                continue
        candidates = find_siglib_functions(
            kb, scheme=WARP_FUNCTION_GUID_V1, identity=guid, siglib_id=siglib_id
        )
        if not candidates:
            continue
        names = sorted({c.name for c in candidates})
        entry_va = int(fn.entry_va)
        if len(names) > 1:
            for rank, sigfn in enumerate(candidates, start=1):
                record_function_match(
                    kb,
                    entry_va=entry_va,
                    scheme=WARP_FUNCTION_GUID_V1,
                    sigfn_id=sigfn.sigfn_id,
                    rank=rank,
                    ambiguous=True,
                    evidence=None,
                )
            summary.ambiguous += 1
            continue
        sigfn = candidates[0]
        record_function_match(
            kb,
            entry_va=entry_va,
            scheme=WARP_FUNCTION_GUID_V1,
            sigfn_id=sigfn.sigfn_id,
            score=1.0,
            confidence=1.0,
            rank=1,
            ambiguous=False,
            evidence="warp-guid",
        )
        summary.matched += 1
    return summary


def ingest_warp_library(
    kb: PersistentKnowledgeBase,
    binary_path: str,
    *,
    siglib_id: int,
    name_prefix: str,
) -> int:
    """Record one WARP-scheme ``siglib_function`` row per function in
    ``binary_path`` whose name starts with ``name_prefix``.

    Used to seed a library's WARP identities from a *linked* binary that
    carries the library's own symbol names (e.g. one of
    ``tests/fixtures/flirt/``'s two relink fixtures for ``mathlib``):
    WARP GUIDs are exact and relocation-masked already, so a GUID computed
    from one link layout is valid provenance for matching any other layout
    of the same source. Functions not matching ``name_prefix`` (driver code,
    libc thunks pulled in by the link) are not library members and are
    skipped.

    Returns the number of rows ingested.
    """
    import glaurung as g

    ingested = 0
    for fn in g.analysis.warp_function_guids_path(str(binary_path)):
        if not fn.name.startswith(name_prefix):
            continue
        add_siglib_function(
            kb,
            siglib_id,
            scheme=WARP_FUNCTION_GUID_V1,
            identity=str(fn.guid),
            name=fn.name,
            base_name=base_name_of(fn.name),
            n_units=len(fn.block_guids),
        )
        ingested += 1
    return ingested
