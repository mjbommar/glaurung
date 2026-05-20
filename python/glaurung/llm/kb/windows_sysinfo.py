"""Windows NtQuerySystemInformation dispatch facts.

The generic xref table says "caller calls helper"; this module gives the
Windows syscall-dispatch layer a first-class, queryable table that ties known
SystemInformationClass values to helper functions when PDB/function names and
call xrefs are available.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass

from . import xref_db
from .persistent import PersistentKnowledgeBase


_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS windows_sysinfo_dispatch (
    binary_id INTEGER NOT NULL,
    information_class INTEGER NOT NULL,
    information_class_name TEXT NOT NULL,
    syscall_name TEXT NOT NULL,
    dispatcher_va INTEGER,
    dispatcher_name TEXT,
    callsite_va INTEGER NOT NULL,
    helper_va INTEGER NOT NULL,
    helper_name TEXT NOT NULL,
    selector_source TEXT NOT NULL,
    confidence REAL NOT NULL,
    evidence_json TEXT NOT NULL DEFAULT '{}',
    indexed_at INTEGER NOT NULL,
    PRIMARY KEY (binary_id, information_class, helper_va, callsite_va)
);
CREATE INDEX IF NOT EXISTS idx_windows_sysinfo_dispatch_class
    ON windows_sysinfo_dispatch(binary_id, information_class);
CREATE INDEX IF NOT EXISTS idx_windows_sysinfo_dispatch_helper
    ON windows_sysinfo_dispatch(binary_id, helper_va);
CREATE INDEX IF NOT EXISTS idx_windows_sysinfo_dispatch_callsite
    ON windows_sysinfo_dispatch(binary_id, callsite_va);
"""


@dataclass(frozen=True)
class SysinfoClassSeed:
    information_class: int
    information_class_name: str
    syscall_name: str
    helper_names: tuple[str, ...]
    dispatcher_names: tuple[str, ...] = ("ExpQuerySystemInformation",)
    selector_source: str = "known_windows_sysinfo_class"
    confidence: float = 0.82


@dataclass(frozen=True)
class SysinfoDispatchFact:
    information_class: int
    information_class_name: str
    syscall_name: str
    dispatcher_va: int | None
    dispatcher_name: str | None
    callsite_va: int | None
    helper_va: int
    helper_name: str
    selector_source: str
    confidence: float
    evidence: dict


KNOWN_SYSINFO_CLASS_SEEDS: tuple[SysinfoClassSeed, ...] = (
    SysinfoClassSeed(
        information_class=222,
        information_class_name="SystemBuildVersionInformation",
        syscall_name="NtQuerySystemInformationEx",
        helper_names=("CmQueryBuildVersionInformation",),
    ),
    SysinfoClassSeed(
        information_class=253,
        information_class_name="SystemProcessInformationExtension",
        syscall_name="NtQuerySystemInformation",
        helper_names=("ExpGetProcessInformation",),
    ),
)


def ensure_schema(kb: PersistentKnowledgeBase) -> None:
    xref_db._ensure_schema(kb._conn)
    kb._conn.executescript(_SCHEMA_SQL)
    kb._conn.commit()


def index_sysinfo_dispatch_facts(
    kb: PersistentKnowledgeBase,
    *,
    force: bool = False,
) -> int:
    """Persist known NtQuerySystemInformation class-to-helper facts.

    The pass is intentionally conservative. It only emits rows for known
    Windows information-class helpers that are present in function names, and
    it attaches exact callsites when the project xref table contains them.
    """

    ensure_schema(kb)
    cur = kb._conn.cursor()
    if force:
        cur.execute(
            "DELETE FROM windows_sysinfo_dispatch WHERE binary_id = ?",
            (kb.binary_id,),
        )

    rows: list[tuple] = []
    now = int(time.time())
    for seed in KNOWN_SYSINFO_CLASS_SEEDS:
        helpers = _function_name_rows(kb, seed.helper_names)
        for helper_va, helper_name in helpers:
            cur.execute(
                "DELETE FROM windows_sysinfo_dispatch "
                "WHERE binary_id = ? AND information_class = ? AND helper_va = ?",
                (kb.binary_id, seed.information_class, helper_va),
            )
            callsites = _callsite_rows(kb, helper_va, seed.dispatcher_names)
            if not callsites:
                callsites = [(None, None, None)]
            for callsite_va, dispatcher_va, dispatcher_name in callsites:
                evidence = {
                    "seed": seed.selector_source,
                    "helper_names": list(seed.helper_names),
                    "dispatcher_names": list(seed.dispatcher_names),
                    "has_project_call_xref": callsite_va is not None,
                }
                confidence = seed.confidence + (
                    0.08 if callsite_va is not None else 0.0
                )
                rows.append(
                    (
                        kb.binary_id,
                        seed.information_class,
                        seed.information_class_name,
                        seed.syscall_name,
                        dispatcher_va,
                        dispatcher_name,
                        callsite_va if callsite_va is not None else -1,
                        helper_va,
                        helper_name,
                        seed.selector_source,
                        min(confidence, 0.95),
                        json.dumps(evidence, sort_keys=True),
                        now,
                    )
                )

    cur.executemany(
        """
INSERT OR REPLACE INTO windows_sysinfo_dispatch
(binary_id, information_class, information_class_name, syscall_name,
 dispatcher_va, dispatcher_name, callsite_va, helper_va, helper_name,
 selector_source, confidence, evidence_json, indexed_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
""",
        rows,
    )
    kb._conn.commit()
    return row_count(kb)


def list_sysinfo_dispatch_facts(
    kb: PersistentKnowledgeBase,
    *,
    information_class: int | None = None,
    helper_name: str | None = None,
    limit: int = 64,
) -> list[SysinfoDispatchFact]:
    ensure_schema(kb)
    clauses = ["binary_id = ?"]
    params: list[object] = [kb.binary_id]
    if information_class is not None:
        clauses.append("information_class = ?")
        params.append(int(information_class))
    if helper_name is not None:
        clauses.append("LOWER(helper_name) LIKE ?")
        params.append(f"%{helper_name.lower()}%")
    params.append(int(limit))
    rows = kb._conn.execute(
        f"""
SELECT information_class, information_class_name, syscall_name,
       dispatcher_va, dispatcher_name, callsite_va, helper_va, helper_name,
       selector_source, confidence, evidence_json
FROM windows_sysinfo_dispatch
WHERE {" AND ".join(clauses)}
ORDER BY information_class, helper_va, COALESCE(callsite_va, 0)
LIMIT ?
""",
        params,
    ).fetchall()
    return [_row_to_fact(row) for row in rows]


def row_count(kb: PersistentKnowledgeBase) -> int:
    ensure_schema(kb)
    row = kb._conn.execute(
        "SELECT COUNT(*) FROM windows_sysinfo_dispatch WHERE binary_id = ?",
        (kb.binary_id,),
    ).fetchone()
    return int(row[0]) if row else 0


def _function_name_rows(
    kb: PersistentKnowledgeBase,
    names: tuple[str, ...],
) -> list[tuple[int, str]]:
    clauses = []
    params: list[object] = []
    for name in names:
        needle = name.lower()
        clauses.append("(LOWER(canonical) = ? OR LOWER(canonical) LIKE ?)")
        params.extend([needle, f"%!{needle}", f"%{needle}"])
        clauses[-1] = (
            "(LOWER(canonical) = ? OR LOWER(canonical) LIKE ? "
            "OR LOWER(canonical) LIKE ?)"
        )
    rows = kb._conn.execute(
        "SELECT entry_va, canonical FROM function_names "
        f"WHERE binary_id = ? AND ({' OR '.join(clauses)}) "
        "ORDER BY entry_va",
        [kb.binary_id, *params],
    ).fetchall()
    return [(int(row[0]), str(row[1])) for row in rows]


def _callsite_rows(
    kb: PersistentKnowledgeBase,
    helper_va: int,
    dispatcher_names: tuple[str, ...],
) -> list[tuple[int | None, int | None, str | None]]:
    rows = kb._conn.execute(
        """
SELECT x.src_va, x.src_function_va, fn.canonical
FROM xrefs x
LEFT JOIN function_names fn
  ON fn.binary_id = x.binary_id AND fn.entry_va = x.src_function_va
WHERE x.binary_id = ? AND x.kind = 'call' AND x.dst_va = ?
ORDER BY x.src_va
""",
        (kb.binary_id, helper_va),
    ).fetchall()
    dispatcher_needles = tuple(name.lower() for name in dispatcher_names)
    preferred: list[tuple[int | None, int | None, str | None]] = []
    fallback: list[tuple[int | None, int | None, str | None]] = []
    for callsite_va, dispatcher_va, dispatcher_name in rows:
        item = (
            int(callsite_va),
            int(dispatcher_va) if dispatcher_va is not None else None,
            str(dispatcher_name) if dispatcher_name is not None else None,
        )
        canonical = (item[2] or "").lower()
        if canonical in dispatcher_needles or any(
            canonical.endswith(f"!{needle}") for needle in dispatcher_needles
        ):
            preferred.append(item)
        else:
            fallback.append(item)
    return preferred or fallback


def _row_to_fact(row: tuple) -> SysinfoDispatchFact:
    try:
        evidence = json.loads(str(row[10] or "{}"))
    except json.JSONDecodeError:
        evidence = {}
    return SysinfoDispatchFact(
        information_class=int(row[0]),
        information_class_name=str(row[1]),
        syscall_name=str(row[2]),
        dispatcher_va=int(row[3]) if row[3] is not None else None,
        dispatcher_name=str(row[4]) if row[4] is not None else None,
        callsite_va=None if int(row[5]) < 0 else int(row[5]),
        helper_va=int(row[6]),
        helper_name=str(row[7]),
        selector_source=str(row[8]),
        confidence=float(row[9]),
        evidence=evidence if isinstance(evidence, dict) else {},
    )
