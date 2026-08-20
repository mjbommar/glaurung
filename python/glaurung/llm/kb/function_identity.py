"""Content-derived function identity, so annotations survive a recompile.

Every other key in the KB is ``(binary_id, absolute VA)``, and both
halves of it move when the binary is rebuilt: ``binary_id`` is the
SHA-256 of the whole file, so a recompile silently inserts a fresh
``binaries`` row, and the stored VAs point at whatever code now lives
there. The result is not an error -- it is zero rows. The analyst's
names, comments, prototypes and stack variables are still in the
``.glaurung`` file, under the previous ``binary_id``, reachable by
nothing.

This module adds the missing half of the key: a string derived from what
the function *is* rather than from where it happens to sit.

Scheme, not hash
----------------
The ``function_identity`` table stores ``(scheme, identity)`` rather than
a single hash column, and ``identity`` is TEXT. That is deliberate:
:data:`STRUCTURAL_V1` is what we can compute today, but
``docs/design/whole-binary-serialization-2026-08-20.md`` recommends
adopting Vector35's WARP function GUID (Apache-2.0; a UUIDv5 over
relocation-masked basic blocks) as the eventual identity, and its values
are UUID strings. A WARP GUID is a new ``scheme`` value written into the
same column -- not a schema change, not a migration, and not a second
table. A function may carry several identities at once; the primary key
is ``(binary_id, entry_va, scheme)``.

What the identity cannot do
---------------------------
It is a *structural* digest, so two genuinely different functions that
compile to the same shape share it. Identical PLT thunks are the
everyday case. Nothing here resolves that ambiguity by guessing:
:func:`port_annotations` refuses to carry an annotation across when
either side of a match is not unique, and says so in its summary. A
silently wrong port is worse than no port.
"""

from __future__ import annotations

import re
import sqlite3
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .persistent import PersistentKnowledgeBase


#: Our own structural digest -- ``structural_fingerprint.py``'s 16-hex
#: SHA-256 over normalized instruction tokens plus the CFG edge set.
#: Namespaced because the column is meant to hold other schemes' values
#: too; a WARP function GUID would land here as e.g.
#: ``"warp-function-guid-v1"``.
STRUCTURAL_V1 = "glaurung-structural-v1"

#: Names that encode the address they were generated at. Porting one to
#: a different build produces a name that is not merely useless but
#: actively wrong -- ``sub_1180`` sitting at 0x11a7.
_PLACEHOLDER_NAME = re.compile(r"^(sub|fn|func|loc)_[0-9a-fA-F]+$")

_PROTO_COLUMNS = (
    "function_name",
    "return_type",
    "params_json",
    "is_variadic",
    "module",
    "calling_convention",
    "source",
    "source_kind",
    "source_package",
    "source_version",
    "confidence",
    "provenance_json",
    "semantics_json",
    "semantic_provenance_json",
    "set_by",
)


@dataclass(frozen=True)
class FunctionIdentity:
    """One ``(binary_id, entry_va, scheme)`` row."""

    binary_id: int
    entry_va: int
    scheme: str
    identity: str
    n_blocks: Optional[int] = None


@dataclass
class PortSummary:
    """What :func:`port_annotations` did, and what it declined to do.

    Every "declined" counter exists so a caller can tell an empty port
    apart from a port that had nothing to carry. ``matched`` counts
    function pairs; the rest count individual annotations.
    """

    source_binary_id: int = 0
    target_binary_id: int = 0
    scheme: str = STRUCTURAL_V1
    #: Identities present in the source build.
    source_functions: int = 0
    #: Identities present in the target build.
    target_functions: int = 0
    #: Identities present in both AND unique on both sides.
    matched: int = 0
    #: Identities present in both but not unique on one or both sides.
    ambiguous: int = 0
    names: int = 0
    comments: int = 0
    prototypes: int = 0
    stack_vars: int = 0
    #: Source names that encode their own old address (``sub_1180``).
    names_skipped_placeholder: int = 0
    #: Target already carried an analyst annotation; manual wins.
    names_skipped_manual: int = 0
    comments_skipped_manual: int = 0
    prototypes_skipped_manual: int = 0
    stack_vars_skipped_manual: int = 0
    #: Source comments that do not sit at a known function entry. Their
    #: offset from any entry is a BYTE offset, and the whole point of a
    #: structural identity is that byte offsets are allowed to move --
    #: so there is no sound way to place them in the new build. Reported
    #: rather than silently dropped, because this is the one annotation
    #: class the port genuinely cannot carry.
    comments_skipped_non_entry: int = 0
    #: Functions whose annotations were carried, as (source_va, target_va).
    pairs: List[Tuple[int, int]] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Computing identities
# ---------------------------------------------------------------------------


def compute_identities(
    binary_path: str,
    *,
    scheme: str = STRUCTURAL_V1,
) -> Dict[int, FunctionIdentity]:
    """Compute every discovered function's identity in ``binary_path``.

    Returns ``{entry_va: FunctionIdentity}`` with ``binary_id`` left at
    ``0`` -- these are not yet bound to a KB row. Functions with no basic
    blocks (bodiless thunks) get no identity and are simply absent.

    Raises ``ValueError`` for an unknown ``scheme``: silently returning
    an empty map would look exactly like a binary with no functions.
    """
    if scheme != STRUCTURAL_V1:
        raise ValueError(
            f"unknown identity scheme {scheme!r}; this build can compute "
            f"only {STRUCTURAL_V1!r} (other schemes may be stored by "
            "whoever can compute them)"
        )

    import glaurung as g

    from .structural_fingerprint import (
        build_va_table,
        resolve_iat_map,
        structural_fingerprint,
    )

    funcs, _ = g.analysis.analyze_functions_path(str(binary_path))
    with open(binary_path, "rb") as f:
        data = f.read()
    # `build_va_table` is PE-only and returns [] elsewhere, which selects
    # the slower per-block path inside `structural_fingerprint`. Only ask
    # for a disassembler when the fast path can actually be taken.
    va_table, _ = build_va_table(data)
    iat_by_va = resolve_iat_map(str(binary_path))
    try:
        disassembler = (
            g.disasm.disassembler_for_path(str(binary_path)) if va_table else None
        )
    except Exception:
        disassembler = None

    out: Dict[int, FunctionIdentity] = {}
    for func in funcs:
        try:
            fs = structural_fingerprint(
                func=func,
                path=str(binary_path),
                iat_by_va=iat_by_va,
                data=data,
                va_table=va_table,
                disassembler=disassembler,
            )
        except Exception:
            fs = None
        if fs is None or not fs.fingerprint:
            continue
        entry_va = int(func.entry_point.value)
        out[entry_va] = FunctionIdentity(
            binary_id=0,
            entry_va=entry_va,
            scheme=scheme,
            identity=fs.fingerprint,
            n_blocks=fs.stats[0] if fs.stats else None,
        )
    return out


# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------


def _ensure(conn: sqlite3.Connection) -> None:
    """The identity table lives in ``xref_db``'s schema script alongside
    every other annotation table; this just runs it."""
    from . import xref_db

    xref_db._ensure_schema(conn)


def set_function_identity(
    kb: PersistentKnowledgeBase,
    entry_va: int,
    identity: str,
    *,
    scheme: str = STRUCTURAL_V1,
    n_blocks: Optional[int] = None,
) -> None:
    """Store one identity for one function in the KB's current binary.

    Unlike the annotation setters there is no ``set_by`` and no manual
    precedence: an identity is a measurement of the bytes, not an
    assertion about them. Recomputing it must overwrite.
    """
    if not identity:
        raise ValueError(f"refusing to store an empty identity for {entry_va:#x}")
    _ensure(kb._conn)
    cur = kb._conn.cursor()
    cur.execute(
        "INSERT OR REPLACE INTO function_identity "
        "(binary_id, entry_va, scheme, identity, n_blocks, set_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (
            kb.binary_id,
            int(entry_va),
            scheme,
            identity,
            None if n_blocks is None else int(n_blocks),
            int(time.time()),
        ),
    )
    kb._conn.commit()


def index_function_identities(
    kb: PersistentKnowledgeBase,
    binary_path: str,
    *,
    scheme: str = STRUCTURAL_V1,
) -> int:
    """Compute and store an identity for every function in ``binary_path``.

    Idempotent: re-running refreshes the rows in place. Returns the
    number of identities stored.
    """
    _ensure(kb._conn)
    identities = compute_identities(binary_path, scheme=scheme)
    now = int(time.time())
    cur = kb._conn.cursor()
    cur.executemany(
        "INSERT OR REPLACE INTO function_identity "
        "(binary_id, entry_va, scheme, identity, n_blocks, set_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        [
            (kb.binary_id, r.entry_va, r.scheme, r.identity, r.n_blocks, now)
            for r in identities.values()
        ],
    )
    kb._conn.commit()
    return len(identities)


def is_indexed(
    kb: PersistentKnowledgeBase,
    *,
    scheme: str = STRUCTURAL_V1,
) -> bool:
    """True when this binary has at least one stored identity."""
    _ensure(kb._conn)
    cur = kb._conn.cursor()
    cur.execute(
        "SELECT 1 FROM function_identity WHERE binary_id = ? AND scheme = ? LIMIT 1",
        (kb.binary_id, scheme),
    )
    return cur.fetchone() is not None


# ---------------------------------------------------------------------------
# Lookup
# ---------------------------------------------------------------------------


def _row(r: tuple) -> FunctionIdentity:
    return FunctionIdentity(
        binary_id=r[0], entry_va=r[1], scheme=r[2], identity=r[3], n_blocks=r[4]
    )


def get_function_identity(
    kb: PersistentKnowledgeBase,
    entry_va: int,
    *,
    scheme: str = STRUCTURAL_V1,
) -> Optional[FunctionIdentity]:
    """The stored identity of one function in the KB's current binary."""
    _ensure(kb._conn)
    cur = kb._conn.cursor()
    cur.execute(
        "SELECT binary_id, entry_va, scheme, identity, n_blocks "
        "FROM function_identity "
        "WHERE binary_id = ? AND entry_va = ? AND scheme = ?",
        (kb.binary_id, int(entry_va), scheme),
    )
    row = cur.fetchone()
    return _row(row) if row is not None else None


def list_function_identities(
    kb: PersistentKnowledgeBase,
    *,
    scheme: str = STRUCTURAL_V1,
    binary_id: Optional[int] = None,
) -> List[FunctionIdentity]:
    """Every stored identity for one binary (the KB's own by default)."""
    _ensure(kb._conn)
    cur = kb._conn.cursor()
    cur.execute(
        "SELECT binary_id, entry_va, scheme, identity, n_blocks "
        "FROM function_identity WHERE binary_id = ? AND scheme = ? "
        "ORDER BY entry_va",
        (kb.binary_id if binary_id is None else int(binary_id), scheme),
    )
    return [_row(r) for r in cur.fetchall()]


def find_by_identity(
    kb: PersistentKnowledgeBase,
    identity: str,
    *,
    scheme: str = STRUCTURAL_V1,
    binary_id: Optional[int] = None,
) -> List[Tuple[int, int]]:
    """Every ``(binary_id, entry_va)`` in the project file carrying
    ``identity``.

    This is the lookup the VA key cannot do -- it crosses ``binary_id``
    on purpose, which is what makes it useful after a recompile. Pass
    ``binary_id`` to scope it to one build. May return more than one row:
    identity is structural, and structure repeats.
    """
    _ensure(kb._conn)
    cur = kb._conn.cursor()
    if binary_id is None:
        cur.execute(
            "SELECT binary_id, entry_va FROM function_identity "
            "WHERE scheme = ? AND identity = ? ORDER BY binary_id, entry_va",
            (scheme, identity),
        )
    else:
        cur.execute(
            "SELECT binary_id, entry_va FROM function_identity "
            "WHERE scheme = ? AND identity = ? AND binary_id = ? "
            "ORDER BY entry_va",
            (scheme, identity, int(binary_id)),
        )
    return [(int(a), int(b)) for a, b in cur.fetchall()]


def resolve_entry_va(
    kb: PersistentKnowledgeBase,
    identity: str,
    *,
    scheme: str = STRUCTURAL_V1,
) -> Optional[int]:
    """Where does the function with ``identity`` live in *this* binary?

    ``None`` when it is absent, and ``None`` when it is ambiguous -- an
    address that might be one of two functions is not an answer. Use
    :func:`find_by_identity` when you want to see the collision.
    """
    hits = find_by_identity(kb, identity, scheme=scheme, binary_id=kb.binary_id)
    return hits[0][1] if len(hits) == 1 else None


# ---------------------------------------------------------------------------
# Porting annotations across a recompile
# ---------------------------------------------------------------------------


def _unique_by_identity(rows: List[FunctionIdentity]) -> Tuple[Dict[str, int], set]:
    """Split ``rows`` into ``{identity: entry_va}`` for the identities
    that occur exactly once, plus the set that occur more than once."""
    seen: Dict[str, int] = {}
    dupes: set = set()
    for r in rows:
        if r.identity in seen:
            dupes.add(r.identity)
            continue
        seen[r.identity] = r.entry_va
    for d in dupes:
        seen.pop(d, None)
    return seen, dupes


def port_annotations(
    kb: PersistentKnowledgeBase,
    *,
    source_binary_id: int,
    scheme: str = STRUCTURAL_V1,
    set_by: Optional[str] = None,
) -> PortSummary:
    """Carry annotations from an earlier build of the same program onto
    the binary this KB is open on, matching functions by identity.

    ``kb`` must be open on the NEW binary; ``source_binary_id`` names the
    old one inside the same project file (see
    :meth:`PersistentKnowledgeBase.list_binaries`). Both builds must have
    been through :func:`index_function_identities` first.

    Provenance is **preserved, not downgraded**: a name the analyst typed
    by hand comes across as ``manual``. Downgrading it to ``"ported"``
    would leave it outranked by the next automatic pass, which silently
    undoes the analyst's work -- the exact failure this module exists to
    prevent. Pass ``set_by`` to override for every ported row. The port
    is something a person asks for, not something a pass does on its own.

    Nothing is overwritten: an annotation already marked ``manual`` in
    the target always wins over a ported one, and every such refusal is
    counted in the returned :class:`PortSummary`.
    """
    from . import xref_db

    _ensure(kb._conn)
    if int(source_binary_id) == int(kb.binary_id):
        raise ValueError(
            f"source_binary_id {source_binary_id} is the binary this KB is "
            "already open on; a port needs two different builds"
        )

    src_rows = list_function_identities(kb, scheme=scheme, binary_id=source_binary_id)
    dst_rows = list_function_identities(kb, scheme=scheme, binary_id=kb.binary_id)
    summary = PortSummary(
        source_binary_id=int(source_binary_id),
        target_binary_id=int(kb.binary_id),
        scheme=scheme,
        source_functions=len(src_rows),
        target_functions=len(dst_rows),
    )
    if not src_rows or not dst_rows:
        return summary

    src_by_id, src_dupes = _unique_by_identity(src_rows)
    dst_by_id, dst_dupes = _unique_by_identity(dst_rows)

    src_all = {r.identity for r in src_rows}
    dst_all = {r.identity for r in dst_rows}
    summary.ambiguous = len((src_dupes | dst_dupes) & src_all & dst_all)

    cur = kb._conn.cursor()
    for identity, src_va in sorted(src_by_id.items(), key=lambda kv: kv[1]):
        dst_va = dst_by_id.get(identity)
        if dst_va is None:
            continue
        summary.matched += 1
        summary.pairs.append((src_va, dst_va))

        # --- name -------------------------------------------------------
        cur.execute(
            "SELECT canonical, aliases_json, set_by, demangled, flavor "
            "FROM function_names WHERE binary_id = ? AND entry_va = ?",
            (source_binary_id, src_va),
        )
        name_row = cur.fetchone()
        target_name: Optional[str] = None
        if name_row is not None:
            canonical = name_row[0]
            if _PLACEHOLDER_NAME.match(canonical or ""):
                # `sub_1180` names the address it was generated at, and
                # that address means something else now.
                summary.names_skipped_placeholder += 1
            else:
                existing = xref_db.get_function_name(kb, dst_va)
                if existing is not None and existing.set_by == "manual":
                    summary.names_skipped_manual += 1
                    target_name = existing.canonical
                else:
                    import json

                    xref_db.set_function_name(
                        kb,
                        dst_va,
                        canonical,
                        set_by=set_by or (name_row[2] or "ported"),
                        aliases=json.loads(name_row[1] or "[]"),
                    )
                    if name_row[3] or name_row[4]:
                        xref_db.set_demangled(kb, dst_va, name_row[3], name_row[4])
                    summary.names += 1
                    target_name = canonical
        else:
            existing = xref_db.get_function_name(kb, dst_va)
            target_name = existing.canonical if existing is not None else None

        # --- comment at the entry VA -----------------------------------
        cur.execute(
            "SELECT body, set_by FROM comments WHERE binary_id = ? AND va = ?",
            (source_binary_id, src_va),
        )
        comment_row = cur.fetchone()
        if comment_row is not None:
            cur.execute(
                "SELECT set_by FROM comments WHERE binary_id = ? AND va = ?",
                (kb.binary_id, dst_va),
            )
            tgt = cur.fetchone()
            if tgt is not None and tgt[0] == "manual":
                summary.comments_skipped_manual += 1
            else:
                xref_db.set_comment(
                    kb,
                    dst_va,
                    comment_row[0],
                    set_by=set_by or (comment_row[1] or "ported"),
                )
                summary.comments += 1

        # --- prototype (keyed by NAME, not VA -- see the schema note) ---
        if name_row is not None and target_name:
            summary.prototypes += _port_prototype(
                kb,
                cur,
                source_binary_id=int(source_binary_id),
                source_name=name_row[0],
                target_name=target_name,
                set_by=set_by,
                summary=summary,
            )

        # --- stack variables (frame-relative offsets, so VA-safe) -------
        cur.execute(
            "SELECT offset, name, c_type, use_count, set_by "
            "FROM stack_frame_vars WHERE binary_id = ? AND function_va = ?",
            (source_binary_id, src_va),
        )
        for offset, var_name, c_type, use_count, var_set_by in cur.fetchall():
            existing_var = xref_db.get_stack_var(kb, dst_va, offset)
            if existing_var is not None and existing_var.set_by == "manual":
                summary.stack_vars_skipped_manual += 1
                continue
            xref_db.set_stack_var(
                kb,
                dst_va,
                offset,
                var_name,
                c_type=c_type,
                use_count=int(use_count or 0),
                set_by=set_by or (var_set_by or "ported"),
            )
            summary.stack_vars += 1

    # Comments that sit anywhere other than a function entry cannot be
    # placed in the new build at all. Count them so an analyst can see
    # what did not come across instead of discovering it later.
    cur.execute(
        "SELECT COUNT(*) FROM comments WHERE binary_id = ? AND va NOT IN "
        "(SELECT entry_va FROM function_identity "
        " WHERE binary_id = ? AND scheme = ?)",
        (source_binary_id, source_binary_id, scheme),
    )
    summary.comments_skipped_non_entry = int(cur.fetchone()[0] or 0)

    return summary


def _port_prototype(
    kb: PersistentKnowledgeBase,
    cur: sqlite3.Cursor,
    *,
    source_binary_id: int,
    source_name: str,
    target_name: str,
    set_by: Optional[str],
    summary: PortSummary,
) -> int:
    """Copy one prototype row across, re-keying it onto ``target_name``.

    ``function_prototypes`` is keyed by name rather than by ``entry_va``,
    so it does not follow the function on its own -- and if the analyst
    renamed the function in the new build, the old prototype has to be
    re-filed under the new name or it is orphaned twice over.
    """
    from . import xref_db

    cur.execute(
        f"SELECT {','.join(_PROTO_COLUMNS)} FROM function_prototypes "
        "WHERE binary_id = ? AND function_name = ?",
        (source_binary_id, source_name),
    )
    row = cur.fetchone()
    if row is None:
        return 0
    existing = xref_db.get_function_prototype(kb, target_name)
    if existing is not None and existing.set_by == "manual":
        summary.prototypes_skipped_manual += 1
        return 0
    proto = xref_db._prototype_from_row(row)
    xref_db.set_function_prototype(
        kb,
        target_name,
        proto.return_type,
        proto.params,
        is_variadic=proto.is_variadic,
        set_by=set_by or (proto.set_by or "ported"),
        module=proto.module,
        calling_convention=proto.calling_convention,
        source=proto.source,
        source_kind=proto.source_kind,
        source_package=proto.source_package,
        source_version=proto.source_version,
        confidence=proto.confidence,
        provenance=proto.provenance or None,
        semantics=proto.semantics or None,
        semantic_provenance=proto.semantic_provenance or None,
    )
    return 1
