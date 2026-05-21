from __future__ import annotations

import json
import sqlite3
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Edge, Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


SymbolRangeStatus = Literal[
    "pdata_exact",
    "symbol_adjacency",
    "inside_pdata",
    "contained_label",
    "unbounded_symbol",
    "call_target_only",
    "no_boundary",
]
SymbolRangeStatusFilter = Literal[
    "all",
    "pdata_exact",
    "symbol_adjacency",
    "inside_pdata",
    "contained_label",
    "unbounded_symbol",
    "call_target_only",
    "no_boundary",
]


class ProjectSymbolRangeFact(BaseModel):
    binary_id: int | None = None
    entry_va: int
    entry: str
    name: str
    demangled: str | None = None
    set_by: str | None = None
    flavor: str | None = None
    end_va: int | None = None
    end: str | None = None
    size: int | None = None
    range_status: SymbolRangeStatus
    range_source: str | None = None
    confidence: float = Field(ge=0.0, le=1.0)
    boundary_sources: list[str] = Field(default_factory=list)
    range_detail: dict[str, Any] = Field(default_factory=dict)
    pdata_relation: str = "none"
    containing_pdata_start_va: int | None = None
    containing_pdata_start: str | None = None
    containing_pdata_end_va: int | None = None
    containing_pdata_end: str | None = None
    previous_symbol_va: int | None = None
    previous_symbol: str | None = None
    previous_symbol_name: str | None = None
    next_symbol_va: int | None = None
    next_symbol: str | None = None
    next_symbol_name: str | None = None
    chunk_kinds: list[str] = Field(default_factory=list)
    reason_codes: list[str] = Field(default_factory=list)
    security_relevance: list[str] = Field(default_factory=list)
    review_priority: int = Field(ge=0)


class WindowsProjectSymbolRangeFactsArgs(BaseModel):
    project_path: str = Field(..., description="Path to a .glaurung SQLite project.")
    binary_id: int | None = Field(None, description="Optional binary_id filter.")
    name_contains: str | None = Field(
        None,
        description="Optional case-insensitive symbol/name substring filter.",
    )
    range_status: SymbolRangeStatusFilter = Field(
        "all",
        description="Optional range-status filter.",
    )
    include_unbounded: bool = Field(
        True,
        description="If false, omit symbols without an end VA.",
    )
    min_confidence: float = Field(0.0, ge=0.0, le=1.0)
    max_rows: int = Field(128, ge=0, le=4096)
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact symbol-range evidence node.",
    )


class WindowsProjectSymbolRangeFactsResult(BaseModel):
    project_path: str
    binary_id: int | None = None
    symbol_count: int
    filtered_count: int
    returned_count: int
    ranged_count: int
    unbounded_count: int
    exact_pdata_count: int
    inside_pdata_count: int
    adjacency_count: int
    conflict_count: int
    facts: list[ProjectSymbolRangeFact]
    coverage: list[str] = Field(default_factory=list)
    missing_capabilities: list[str] = Field(default_factory=list)
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsProjectSymbolRangeFactsTool(
    MemoryTool[
        WindowsProjectSymbolRangeFactsArgs,
        WindowsProjectSymbolRangeFactsResult,
    ]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_project_symbol_range_facts",
                description=(
                    "Audit PDB/public function symbol ranges in a .glaurung "
                    "project by joining function_names with .pdata, symbol "
                    "adjacency, containing ranges, and chunk facts."
                ),
                tags=("windows", "pe", "project", "pdb", "symbols", "boundaries"),
            ),
            WindowsProjectSymbolRangeFactsArgs,
            WindowsProjectSymbolRangeFactsResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsProjectSymbolRangeFactsArgs,
    ) -> WindowsProjectSymbolRangeFactsResult:
        project_path = Path(args.project_path).expanduser()
        if not project_path.exists():
            raise ValueError(f"{project_path}: .glaurung project does not exist")

        conn = sqlite3.connect(f"file:{project_path}?mode=ro", uri=True)
        try:
            present = _present_tables(conn)
            binary_id = (
                args.binary_id
                if args.binary_id is not None
                else _first_binary_id(conn, present)
            )
            names = _load_names(conn, present, binary_id)
            boundaries = _load_boundaries(conn, present, binary_id)
            chunks = _load_chunk_kinds(conn, present, binary_id)
            facts_all = _facts(names, boundaries, chunks, binary_id)
        finally:
            conn.close()

        filtered = [fact for fact in facts_all if _include_fact(fact, args)]
        filtered.sort(key=_sort_key)
        returned = filtered[: args.max_rows] if args.max_rows else []
        result = WindowsProjectSymbolRangeFactsResult(
            project_path=str(project_path),
            binary_id=binary_id,
            symbol_count=len(facts_all),
            filtered_count=len(filtered),
            returned_count=len(returned),
            ranged_count=sum(1 for fact in filtered if fact.end_va is not None),
            unbounded_count=sum(1 for fact in filtered if fact.end_va is None),
            exact_pdata_count=sum(
                1 for fact in filtered if fact.range_status == "pdata_exact"
            ),
            inside_pdata_count=sum(
                1
                for fact in filtered
                if fact.range_status in {"inside_pdata", "contained_label"}
            ),
            adjacency_count=sum(
                1 for fact in filtered if fact.range_status == "symbol_adjacency"
            ),
            conflict_count=sum(
                1
                for fact in filtered
                if "boundary_source_conflict" in fact.reason_codes
            ),
            facts=returned,
            coverage=_coverage(present, filtered),
            missing_capabilities=_missing(present, facts_all, filtered),
            notes=[
                "symbol-range facts are functionization and navigation evidence, not vulnerability evidence",
                "symbol adjacency is conservative review metadata; decompile and xref validation are still required",
            ],
        )

        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_project_symbol_range_facts",
                    props={
                        "project_path": result.project_path,
                        "binary_id": result.binary_id,
                        "symbol_count": result.symbol_count,
                        "ranged_count": result.ranged_count,
                        "unbounded_count": result.unbounded_count,
                    },
                )
            )
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))
            result = result.model_copy(update={"evidence_node_id": node.id})

        return result


class _NameRow(BaseModel):
    entry_va: int
    name: str
    set_by: str | None = None
    demangled: str | None = None
    flavor: str | None = None


class _BoundaryRow(BaseModel):
    entry_va: int
    end_va: int | None = None
    size: int | None = None
    source: str
    confidence: float
    name: str | None = None
    detail: dict[str, Any] = Field(default_factory=dict)


def _present_tables(conn: sqlite3.Connection) -> set[str]:
    return {
        str(row[0])
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
    }


def _first_binary_id(conn: sqlite3.Connection, present: set[str]) -> int | None:
    if "binaries" not in present:
        return None
    row = conn.execute(
        "SELECT binary_id FROM binaries ORDER BY binary_id LIMIT 1"
    ).fetchone()
    return int(row[0]) if row else None


def _load_names(
    conn: sqlite3.Connection,
    present: set[str],
    binary_id: int | None,
) -> list[_NameRow]:
    if "function_names" not in present:
        return []
    clauses: list[str] = []
    params: list[object] = []
    if binary_id is not None:
        clauses.append("binary_id = ?")
        params.append(binary_id)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    rows = conn.execute(
        f"""
SELECT entry_va, canonical, set_by, demangled, flavor
FROM function_names
{where}
ORDER BY entry_va
LIMIT 100000
""",
        params,
    ).fetchall()
    return [
        _NameRow(
            entry_va=int(row[0]),
            name=str(row[1]),
            set_by=str(row[2]) if row[2] is not None else None,
            demangled=str(row[3]) if row[3] is not None else None,
            flavor=str(row[4]) if row[4] is not None else None,
        )
        for row in rows
    ]


def _load_boundaries(
    conn: sqlite3.Connection,
    present: set[str],
    binary_id: int | None,
) -> list[_BoundaryRow]:
    if "function_boundaries" not in present:
        return []
    clauses: list[str] = []
    params: list[object] = []
    if binary_id is not None:
        clauses.append("binary_id = ?")
        params.append(binary_id)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    rows = conn.execute(
        f"""
SELECT entry_va, end_va, size, source, confidence, name, detail_json
FROM function_boundaries
{where}
ORDER BY entry_va, confidence DESC, source
LIMIT 200000
""",
        params,
    ).fetchall()
    return [
        _BoundaryRow(
            entry_va=int(row[0]),
            end_va=int(row[1]) if row[1] is not None else None,
            size=int(row[2]) if row[2] is not None else None,
            source=str(row[3]),
            confidence=float(row[4]),
            name=str(row[5]) if row[5] is not None else None,
            detail=_json_obj(row[6]),
        )
        for row in rows
    ]


def _load_chunk_kinds(
    conn: sqlite3.Connection,
    present: set[str],
    binary_id: int | None,
) -> dict[int, list[str]]:
    if "function_chunk_facts" not in present:
        return {}
    clauses: list[str] = []
    params: list[object] = []
    if binary_id is not None:
        clauses.append("binary_id = ?")
        params.append(binary_id)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    rows = conn.execute(
        f"""
SELECT owner_entry_va, chunk_start_va, chunk_kind
FROM function_chunk_facts
{where}
ORDER BY chunk_start_va, chunk_kind
LIMIT 200000
""",
        params,
    ).fetchall()
    out: dict[int, list[str]] = {}
    for owner_raw, start_raw, kind_raw in rows:
        kind = str(kind_raw)
        for value in (owner_raw, start_raw):
            if value is None:
                continue
            out.setdefault(int(value), [])
            if kind not in out[int(value)]:
                out[int(value)].append(kind)
    return out


def _facts(
    names: list[_NameRow],
    boundaries: list[_BoundaryRow],
    chunks: dict[int, list[str]],
    binary_id: int | None,
) -> list[ProjectSymbolRangeFact]:
    by_entry: dict[int, list[_BoundaryRow]] = {}
    pdata = [item for item in boundaries if item.source == "pdata" and item.end_va]
    for item in boundaries:
        by_entry.setdefault(item.entry_va, []).append(item)

    out: list[ProjectSymbolRangeFact] = []
    for idx, name in enumerate(names):
        exact = by_entry.get(name.entry_va, [])
        best = _best_boundary(exact)
        exact_pdata = next((item for item in exact if item.source == "pdata"), None)
        containing_pdata = _containing_pdata(pdata, name.entry_va)
        previous_name = names[idx - 1] if idx > 0 else None
        next_name = names[idx + 1] if idx + 1 < len(names) else None
        status = _status(best, exact_pdata, containing_pdata)
        reason_codes = _reason_codes(
            name=name,
            best=best,
            exact=exact,
            exact_pdata=exact_pdata,
            containing_pdata=containing_pdata,
            next_name=next_name,
            status=status,
            chunk_kinds=chunks.get(name.entry_va, []),
        )
        security_relevance = _security_relevance(
            status, reason_codes, chunks.get(name.entry_va, [])
        )
        end_va = best.end_va if best is not None else None
        out.append(
            ProjectSymbolRangeFact(
                binary_id=binary_id,
                entry_va=name.entry_va,
                entry=hex(name.entry_va),
                name=name.name,
                demangled=name.demangled,
                set_by=name.set_by,
                flavor=name.flavor,
                end_va=end_va,
                end=_hex(end_va) if end_va is not None else None,
                size=(end_va - name.entry_va)
                if end_va is not None and end_va > name.entry_va
                else None,
                range_status=status,
                range_source=best.source if best is not None else None,
                confidence=best.confidence if best is not None else 0.0,
                boundary_sources=_dedupe([item.source for item in exact]),
                range_detail=dict(best.detail) if best is not None else {},
                pdata_relation=_pdata_relation(exact_pdata, containing_pdata),
                containing_pdata_start_va=(
                    containing_pdata.entry_va if containing_pdata is not None else None
                ),
                containing_pdata_start=(
                    _hex(containing_pdata.entry_va)
                    if containing_pdata is not None
                    else None
                ),
                containing_pdata_end_va=(
                    containing_pdata.end_va if containing_pdata is not None else None
                ),
                containing_pdata_end=(
                    _hex(containing_pdata.end_va)
                    if containing_pdata is not None
                    and containing_pdata.end_va is not None
                    else None
                ),
                previous_symbol_va=(
                    previous_name.entry_va if previous_name is not None else None
                ),
                previous_symbol=(
                    _hex(previous_name.entry_va) if previous_name is not None else None
                ),
                previous_symbol_name=previous_name.name if previous_name else None,
                next_symbol_va=next_name.entry_va if next_name is not None else None,
                next_symbol=_hex(next_name.entry_va) if next_name is not None else None,
                next_symbol_name=next_name.name if next_name else None,
                chunk_kinds=chunks.get(name.entry_va, []),
                reason_codes=reason_codes,
                security_relevance=security_relevance,
                review_priority=_priority(status, reason_codes, security_relevance),
            )
        )
    return out


def _best_boundary(boundaries: list[_BoundaryRow]) -> _BoundaryRow | None:
    if not boundaries:
        return None
    return sorted(boundaries, key=_boundary_sort_key)[0]


def _boundary_sort_key(item: _BoundaryRow) -> tuple[int, int, float, str]:
    source_priority = {
        "pdata": 0,
        "pdb": 1,
        "pdb_symbol_adjacency": 2,
        "pdb_public_inside_pdata": 3,
        "function_name_symbol_adjacency": 4,
        "function_name": 5,
        "label_inside_pdata": 6,
        "call_target": 8,
    }.get(item.source, 7)
    has_no_end = 1 if item.end_va is None else 0
    return (source_priority, has_no_end, -item.confidence, item.source)


def _containing_pdata(boundaries: list[_BoundaryRow], va: int) -> _BoundaryRow | None:
    matches = [
        item
        for item in boundaries
        if item.end_va is not None and item.entry_va < va < item.end_va
    ]
    if not matches:
        return None
    return sorted(
        matches, key=lambda item: (item.end_va - item.entry_va, -item.confidence)
    )[0]


def _status(
    best: _BoundaryRow | None,
    exact_pdata: _BoundaryRow | None,
    containing_pdata: _BoundaryRow | None,
) -> SymbolRangeStatus:
    if best is None:
        return "no_boundary"
    if exact_pdata is not None and best.entry_va == exact_pdata.entry_va:
        return "pdata_exact"
    if best.source in {"pdb_public_inside_pdata", "label_inside_pdata"}:
        return "inside_pdata"
    if containing_pdata is not None:
        return "contained_label"
    if best.end_va is None and best.source == "call_target":
        return "call_target_only"
    if best.end_va is None:
        return "unbounded_symbol"
    if (
        best.source in {"pdb_symbol_adjacency", "function_name_symbol_adjacency"}
        or best.detail.get("range_source") == "symbol_adjacency"
    ):
        return "symbol_adjacency"
    return "unbounded_symbol" if best.end_va is None else "symbol_adjacency"


def _reason_codes(
    *,
    name: _NameRow,
    best: _BoundaryRow | None,
    exact: list[_BoundaryRow],
    exact_pdata: _BoundaryRow | None,
    containing_pdata: _BoundaryRow | None,
    next_name: _NameRow | None,
    status: SymbolRangeStatus,
    chunk_kinds: list[str],
) -> list[str]:
    reasons: list[str] = [f"range_status:{status}"]
    if name.set_by:
        reasons.append(f"symbol_source:{name.set_by}")
    if best is None:
        reasons.append("missing_function_boundary")
    else:
        reasons.append(f"boundary_source:{best.source}")
        range_source = best.detail.get("range_source")
        if isinstance(range_source, str):
            reasons.append(f"range_source:{range_source}")
        if best.end_va is None:
            reasons.append("missing_range_end")
        elif next_name is not None and best.end_va == next_name.entry_va:
            reasons.append("range_ends_at_next_symbol")
        elif next_name is not None and best.end_va > next_name.entry_va:
            reasons.append("range_contains_next_symbol")
    end_values = {item.end_va for item in exact}
    if len(end_values) > 1:
        reasons.append("boundary_source_conflict")
    if exact_pdata is not None:
        reasons.append("exact_pdata_boundary")
    if containing_pdata is not None:
        reasons.append("symbol_inside_pdata_boundary")
    for kind in chunk_kinds:
        reasons.append(f"chunk_kind:{kind}")
    return _dedupe(reasons)


def _security_relevance(
    status: SymbolRangeStatus,
    reason_codes: list[str],
    chunk_kinds: list[str],
) -> list[str]:
    relevance: list[str] = []
    if status == "symbol_adjacency":
        relevance.append("public_symbol_range")
    if status in {"inside_pdata", "contained_label"}:
        relevance.append("split_body_or_funclet_review")
    if status in {"unbounded_symbol", "call_target_only", "no_boundary"}:
        relevance.append("function_range_missing")
    if "boundary_source_conflict" in reason_codes:
        relevance.append("function_range_conflict")
    if any("thunk" in kind for kind in chunk_kinds):
        relevance.append("thunk_range")
    if any("funclet" in kind for kind in chunk_kinds):
        relevance.append("exception_funclet")
    return _dedupe(relevance)


def _priority(
    status: SymbolRangeStatus,
    reason_codes: list[str],
    security_relevance: list[str],
) -> int:
    priority = 38
    if status in {"unbounded_symbol", "call_target_only", "no_boundary"}:
        priority += 20
    if status in {"inside_pdata", "contained_label"}:
        priority += 16
    if status == "symbol_adjacency":
        priority += 8
    if "boundary_source_conflict" in reason_codes:
        priority += 18
    if "range_contains_next_symbol" in reason_codes:
        priority += 12
    if security_relevance:
        priority += 8
    return priority


def _pdata_relation(
    exact_pdata: _BoundaryRow | None,
    containing_pdata: _BoundaryRow | None,
) -> str:
    if exact_pdata is not None:
        return "exact"
    if containing_pdata is not None:
        return "inside"
    return "none"


def _include_fact(
    fact: ProjectSymbolRangeFact,
    args: WindowsProjectSymbolRangeFactsArgs,
) -> bool:
    if args.range_status != "all" and fact.range_status != args.range_status:
        return False
    if not args.include_unbounded and fact.end_va is None:
        return False
    if fact.confidence < args.min_confidence:
        return False
    if args.name_contains:
        needle = args.name_contains.lower()
        haystack = " ".join(
            value
            for value in (
                fact.name,
                fact.demangled,
                fact.set_by,
                fact.flavor,
                fact.range_source,
            )
            if value
        ).lower()
        if needle not in haystack:
            return False
    return True


def _coverage(
    present: set[str],
    facts: list[ProjectSymbolRangeFact],
) -> list[str]:
    coverage = [f"{table}_present" for table in sorted(present)]
    if any(fact.range_status == "pdata_exact" for fact in facts):
        coverage.append("exact_pdata_ranges")
    if any(fact.range_status == "symbol_adjacency" for fact in facts):
        coverage.append("symbol_adjacency_ranges")
    if any(fact.range_status in {"inside_pdata", "contained_label"} for fact in facts):
        coverage.append("inside_pdata_symbol_ranges")
    if any(fact.chunk_kinds for fact in facts):
        coverage.append("function_chunk_range_hints")
    return _dedupe(coverage)


def _missing(
    present: set[str],
    facts_all: list[ProjectSymbolRangeFact],
    filtered: list[ProjectSymbolRangeFact],
) -> list[str]:
    missing: list[str] = []
    if "function_names" not in present:
        missing.append("function_names")
    if "function_boundaries" not in present:
        missing.append("function_boundaries")
    if "function_chunk_facts" not in present:
        missing.append("function_chunk_facts")
    if not facts_all:
        missing.append("symbol_range_facts")
    if facts_all and not filtered:
        missing.append("matching_symbol_range_facts")
    if any(fact.end_va is None for fact in filtered):
        missing.append("bounded_ranges_for_all_symbols")
    return missing


def _sort_key(fact: ProjectSymbolRangeFact) -> tuple[int, int, str]:
    return (-fact.review_priority, fact.entry_va, fact.name)


def _json_obj(value: Any) -> dict[str, Any]:
    if not value:
        return {}
    try:
        parsed = json.loads(str(value))
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _hex(value: int | None) -> str | None:
    return None if value is None else hex(value)


def _dedupe(values: Sequence[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value and value not in seen:
            seen.add(value)
            out.append(value)
    return out


def build_tool() -> WindowsProjectSymbolRangeFactsTool:
    return WindowsProjectSymbolRangeFactsTool()
