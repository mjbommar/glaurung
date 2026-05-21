from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Edge, Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


ProjectFunctionStartState = Literal[
    "strict_function",
    "thunk",
    "chunk_or_funclet",
    "contained_in_function",
    "xref_candidate",
    "symbol_only",
    "no_evidence",
]
ProjectFunctionStartConfidence = Literal["high", "medium", "low", "unknown"]


class WindowsProjectFunctionStartExplainArgs(BaseModel):
    project_path: str = Field(..., description="Path to a .glaurung SQLite project.")
    binary_id: int | None = Field(None, description="Optional binary_id filter.")
    va: int | None = Field(
        None,
        description="Virtual address to explain. Use va, address, or symbol.",
    )
    address: str | None = Field(
        None,
        description="Hex virtual address to explain, such as 0x180033b20.",
    )
    symbol: str | None = Field(
        None,
        description="Function symbol/name to resolve and explain.",
    )
    max_rows: int = Field(16, ge=0, le=128)
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact project function-start evidence node.",
    )


class ProjectFunctionStartTarget(BaseModel):
    va: int | None = None
    address: str | None = None
    symbol: str | None = None
    demangled: str | None = None
    resolution: list[str] = Field(default_factory=list)


class ProjectFunctionNameFact(BaseModel):
    entry_va: int
    address: str
    canonical: str
    demangled: str | None = None
    aliases: list[str] = Field(default_factory=list)
    set_by: str | None = None
    flavor: str | None = None


class ProjectFunctionBoundaryFact(BaseModel):
    entry_va: int
    address: str
    end_va: int | None = None
    end: str | None = None
    size: int | None = None
    source: str
    confidence: float = Field(ge=0.0, le=1.0)
    name: str | None = None
    detail: dict[str, Any] = Field(default_factory=dict)


class ProjectFunctionChunkFact(BaseModel):
    owner_entry_va: int | None = None
    owner_entry: str | None = None
    chunk_start_va: int
    chunk_start: str
    chunk_end_va: int | None = None
    chunk_end: str | None = None
    chunk_size: int | None = None
    chunk_kind: str
    relation_kind: str
    target_va: int | None = None
    target: str | None = None
    target_name: str | None = None
    source: str
    confidence: float = Field(ge=0.0, le=1.0)
    name: str | None = None
    detail: dict[str, Any] = Field(default_factory=dict)


class ProjectFunctionXrefFact(BaseModel):
    src_va: int
    src: str
    dst_va: int
    dst: str
    kind: str
    src_function_va: int | None = None
    src_function: str | None = None
    src_function_name: str | None = None
    dst_function_name: str | None = None
    relation: str


class ProjectFunctionCommentFact(BaseModel):
    va: int
    address: str
    body: str
    set_by: str | None = None


class WindowsProjectFunctionStartExplainResult(BaseModel):
    project_path: str
    binary_id: int | None = None
    target: ProjectFunctionStartTarget
    final_state: ProjectFunctionStartState
    confidence: ProjectFunctionStartConfidence
    reason_codes: list[str] = Field(default_factory=list)
    recommended_action: str
    names: list[ProjectFunctionNameFact] = Field(default_factory=list)
    exact_boundaries: list[ProjectFunctionBoundaryFact] = Field(default_factory=list)
    containing_boundaries: list[ProjectFunctionBoundaryFact] = Field(
        default_factory=list
    )
    chunks: list[ProjectFunctionChunkFact] = Field(default_factory=list)
    refs_to: list[ProjectFunctionXrefFact] = Field(default_factory=list)
    refs_from: list[ProjectFunctionXrefFact] = Field(default_factory=list)
    comments: list[ProjectFunctionCommentFact] = Field(default_factory=list)
    coverage: list[str] = Field(default_factory=list)
    missing_capabilities: list[str] = Field(default_factory=list)
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsProjectFunctionStartExplainTool(
    MemoryTool[
        WindowsProjectFunctionStartExplainArgs,
        WindowsProjectFunctionStartExplainResult,
    ]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_project_function_start_explain",
                description=(
                    "Explain why a VA or symbol is a Windows project function "
                    "start, thunk, chunk, contained label, or xref-derived "
                    "candidate using persisted .glaurung facts."
                ),
                tags=(
                    "windows",
                    "pe",
                    "project",
                    "functions",
                    "boundaries",
                    "xrefs",
                ),
            ),
            WindowsProjectFunctionStartExplainArgs,
            WindowsProjectFunctionStartExplainResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsProjectFunctionStartExplainArgs,
    ) -> WindowsProjectFunctionStartExplainResult:
        project_path = Path(args.project_path).expanduser()
        if not project_path.exists():
            raise ValueError(f"{project_path}: .glaurung project does not exist")

        conn = sqlite3.connect(f"file:{project_path}?mode=ro", uri=True)
        try:
            present = _present_tables(conn)
            binary_id = args.binary_id or _first_binary_id(conn, present)
            target = _resolve_target(conn, present, binary_id, args)
            va = target.va
            if va is None:
                result = _empty_result(project_path, binary_id, target, present)
            else:
                names = _names_at(conn, present, binary_id, va, args.max_rows)
                exact = _exact_boundaries(conn, present, binary_id, va, args.max_rows)
                containing = _containing_boundaries(
                    conn, present, binary_id, va, args.max_rows
                )
                chunks = _chunks_for_va(conn, present, binary_id, va, args.max_rows)
                refs_to = _xrefs_to(conn, present, binary_id, va, args.max_rows)
                refs_from = _xrefs_from(conn, present, binary_id, va, args.max_rows)
                comments = _comments_at(conn, present, binary_id, va, args.max_rows)
                result = _result(
                    project_path=project_path,
                    binary_id=binary_id,
                    present=present,
                    target=target,
                    names=names,
                    exact_boundaries=exact,
                    containing_boundaries=containing,
                    chunks=chunks,
                    refs_to=refs_to,
                    refs_from=refs_from,
                    comments=comments,
                )
        finally:
            conn.close()

        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_project_function_start_explain",
                    props={
                        "project_path": result.project_path,
                        "binary_id": result.binary_id,
                        "va": result.target.va,
                        "symbol": result.target.symbol,
                        "final_state": result.final_state,
                        "confidence": result.confidence,
                        "recommended_action": result.recommended_action,
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))
            result = result.model_copy(update={"evidence_node_id": evidence_node_id})

        return result


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


def _resolve_target(
    conn: sqlite3.Connection,
    present: set[str],
    binary_id: int | None,
    args: WindowsProjectFunctionStartExplainArgs,
) -> ProjectFunctionStartTarget:
    va = _parse_va(args.va, args.address)
    if va is not None:
        names = _names_at(conn, present, binary_id, va, 1)
        return ProjectFunctionStartTarget(
            va=va,
            address=_hex(va),
            symbol=names[0].canonical if names else args.symbol,
            demangled=names[0].demangled if names else None,
            resolution=["explicit_va"],
        )
    if args.symbol:
        return _resolve_symbol(conn, present, binary_id, args.symbol)
    raise ValueError("one of va, address, or symbol is required")


def _resolve_symbol(
    conn: sqlite3.Connection,
    present: set[str],
    binary_id: int | None,
    symbol: str,
) -> ProjectFunctionStartTarget:
    if "function_names" not in present:
        return ProjectFunctionStartTarget(
            symbol=symbol,
            resolution=["missing_function_names"],
        )
    clauses = [
        "(canonical = ? OR demangled = ? OR canonical LIKE ? OR demangled LIKE ?)"
    ]
    params: list[object] = [symbol, symbol, f"%{symbol}%", f"%{symbol}%"]
    if binary_id is not None:
        clauses.append("binary_id = ?")
        params.append(binary_id)
    rows = conn.execute(
        "SELECT entry_va, canonical, demangled FROM function_names "
        f"WHERE {' AND '.join(clauses)} ORDER BY "
        "CASE WHEN canonical = ? OR demangled = ? THEN 0 ELSE 1 END, entry_va",
        (*params, symbol, symbol),
    ).fetchall()
    if not rows:
        return ProjectFunctionStartTarget(
            symbol=symbol,
            resolution=["unresolved_symbol"],
        )
    exact = [row for row in rows if _symbol_exact(row, symbol)]
    selected_rows = exact or rows
    if len(selected_rows) > 1:
        raise ValueError(f"symbol {symbol!r} matched multiple function names")
    row = selected_rows[0]
    va = int(row[0])
    return ProjectFunctionStartTarget(
        va=va,
        address=_hex(va),
        symbol=str(row[1]),
        demangled=str(row[2]) if row[2] is not None else None,
        resolution=["symbol", "function_names"],
    )


def _symbol_exact(row: tuple, symbol: str) -> bool:
    values = [str(row[1])]
    if row[2] is not None:
        values.append(str(row[2]))
    for value in values:
        if value == symbol:
            return True
        short = value.rsplit("!", 1)[-1]
        if short == symbol:
            return True
    return False


def _parse_va(va: int | None, address: str | None) -> int | None:
    if va is not None and address is not None:
        parsed = _parse_hex_or_int(address)
        if parsed != va:
            raise ValueError(f"va {va:#x} does not match address {address!r}")
        return va
    if va is not None:
        if va < 0:
            raise ValueError("va must be non-negative")
        return va
    if address is not None:
        return _parse_hex_or_int(address)
    return None


def _parse_hex_or_int(value: Any) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip().lower()
        return int(text, 16 if text.startswith("0x") else 10)
    raise ValueError(f"cannot parse VA from {value!r}")


def _names_at(
    conn: sqlite3.Connection,
    present: set[str],
    binary_id: int | None,
    va: int,
    limit: int,
) -> list[ProjectFunctionNameFact]:
    if "function_names" not in present or limit == 0:
        return []
    clauses = ["entry_va = ?"]
    params: list[object] = [va]
    if binary_id is not None:
        clauses.append("binary_id = ?")
        params.append(binary_id)
    rows = conn.execute(
        "SELECT entry_va, canonical, aliases_json, set_by, demangled, flavor "
        "FROM function_names "
        f"WHERE {' AND '.join(clauses)} ORDER BY entry_va LIMIT ?",
        (*params, limit),
    ).fetchall()
    return [_name_fact(row) for row in rows]


def _exact_boundaries(
    conn: sqlite3.Connection,
    present: set[str],
    binary_id: int | None,
    va: int,
    limit: int,
) -> list[ProjectFunctionBoundaryFact]:
    if "function_boundaries" not in present or limit == 0:
        return []
    clauses = ["entry_va = ?"]
    params: list[object] = [va]
    if binary_id is not None:
        clauses.append("binary_id = ?")
        params.append(binary_id)
    rows = conn.execute(
        "SELECT entry_va, end_va, size, source, confidence, name, detail_json "
        "FROM function_boundaries "
        f"WHERE {' AND '.join(clauses)} "
        "ORDER BY confidence DESC, source LIMIT ?",
        (*params, limit),
    ).fetchall()
    return [_boundary_fact(row) for row in rows]


def _containing_boundaries(
    conn: sqlite3.Connection,
    present: set[str],
    binary_id: int | None,
    va: int,
    limit: int,
) -> list[ProjectFunctionBoundaryFact]:
    if "function_boundaries" not in present or limit == 0:
        return []
    clauses = ["entry_va < ?", "end_va > ?"]
    params: list[object] = [va, va]
    if binary_id is not None:
        clauses.append("binary_id = ?")
        params.append(binary_id)
    rows = conn.execute(
        "SELECT entry_va, end_va, size, source, confidence, name, detail_json "
        "FROM function_boundaries "
        f"WHERE {' AND '.join(clauses)} "
        "ORDER BY confidence DESC, entry_va DESC LIMIT ?",
        (*params, limit),
    ).fetchall()
    return [_boundary_fact(row) for row in rows]


def _chunks_for_va(
    conn: sqlite3.Connection,
    present: set[str],
    binary_id: int | None,
    va: int,
    limit: int,
) -> list[ProjectFunctionChunkFact]:
    if "function_chunk_facts" not in present or limit == 0:
        return []
    clauses = [
        """
        (
            owner_entry_va = ?
            OR chunk_start_va = ?
            OR target_va = ?
            OR (
                chunk_end_va IS NOT NULL
                AND chunk_start_va <= ?
                AND chunk_end_va > ?
            )
        )
        """
    ]
    params: list[object] = [va, va, va, va, va]
    if binary_id is not None:
        clauses.append("binary_id = ?")
        params.append(binary_id)
    rows = conn.execute(
        "SELECT owner_entry_va, chunk_start_va, chunk_end_va, chunk_size, "
        "chunk_kind, relation_kind, target_va, target_name, source, "
        "confidence, name, detail_json FROM function_chunk_facts "
        f"WHERE {' AND '.join(clauses)} "
        "ORDER BY chunk_start_va, confidence DESC, chunk_kind LIMIT ?",
        (*params, limit),
    ).fetchall()
    return [_chunk_fact(row) for row in rows]


def _xrefs_to(
    conn: sqlite3.Connection,
    present: set[str],
    binary_id: int | None,
    va: int,
    limit: int,
) -> list[ProjectFunctionXrefFact]:
    if "xrefs" not in present or limit == 0:
        return []
    clauses = ["x.dst_va = ?"]
    params: list[object] = [va]
    if binary_id is not None:
        clauses.append("x.binary_id = ?")
        params.append(binary_id)
    return _xref_rows(
        conn,
        present,
        clauses,
        params,
        "ref_to",
        "x.src_va, x.dst_va, x.kind, x.src_function_va",
        "x.src_va, x.kind",
        limit,
    )


def _xrefs_from(
    conn: sqlite3.Connection,
    present: set[str],
    binary_id: int | None,
    va: int,
    limit: int,
) -> list[ProjectFunctionXrefFact]:
    if "xrefs" not in present or limit == 0:
        return []
    clauses = ["(x.src_function_va = ? OR x.src_va = ?)"]
    params: list[object] = [va, va]
    if binary_id is not None:
        clauses.append("x.binary_id = ?")
        params.append(binary_id)
    return _xref_rows(
        conn,
        present,
        clauses,
        params,
        "ref_from",
        "x.src_va, x.dst_va, x.kind, x.src_function_va",
        "x.src_va, x.dst_va, x.kind",
        limit,
    )


def _xref_rows(
    conn: sqlite3.Connection,
    present: set[str],
    clauses: list[str],
    params: list[object],
    relation: str,
    select_columns: str,
    order_by: str,
    limit: int,
) -> list[ProjectFunctionXrefFact]:
    if "function_names" in present:
        joins = """
LEFT JOIN function_names src_fn
  ON src_fn.binary_id = x.binary_id AND src_fn.entry_va = x.src_function_va
LEFT JOIN function_names dst_fn
  ON dst_fn.binary_id = x.binary_id AND dst_fn.entry_va = x.dst_va
"""
        name_columns = "src_fn.canonical, dst_fn.canonical"
    else:
        joins = ""
        name_columns = "NULL, NULL"
    rows = conn.execute(
        f"""
SELECT {select_columns}, {name_columns}
FROM xrefs x
{joins}
WHERE {" AND ".join(clauses)}
ORDER BY {order_by}
LIMIT ?
""",
        (*params, limit),
    ).fetchall()
    out: list[ProjectFunctionXrefFact] = []
    for row in rows:
        src_va = int(row[0])
        dst_va = int(row[1])
        src_func = int(row[3]) if row[3] is not None else None
        out.append(
            ProjectFunctionXrefFact(
                src_va=src_va,
                src=_hex(src_va),
                dst_va=dst_va,
                dst=_hex(dst_va),
                kind=str(row[2]),
                src_function_va=src_func,
                src_function=_hex(src_func) if src_func is not None else None,
                src_function_name=str(row[4]) if row[4] is not None else None,
                dst_function_name=str(row[5]) if row[5] is not None else None,
                relation=relation,
            )
        )
    return out


def _comments_at(
    conn: sqlite3.Connection,
    present: set[str],
    binary_id: int | None,
    va: int,
    limit: int,
) -> list[ProjectFunctionCommentFact]:
    if "comments" not in present or limit == 0:
        return []
    clauses = ["va = ?"]
    params: list[object] = [va]
    if binary_id is not None:
        clauses.append("binary_id = ?")
        params.append(binary_id)
    rows = conn.execute(
        "SELECT va, body, set_by FROM comments "
        f"WHERE {' AND '.join(clauses)} ORDER BY va LIMIT ?",
        (*params, limit),
    ).fetchall()
    return [
        ProjectFunctionCommentFact(
            va=int(row[0]),
            address=_hex(int(row[0])),
            body=str(row[1]),
            set_by=str(row[2]) if row[2] is not None else None,
        )
        for row in rows
    ]


def _name_fact(row: tuple) -> ProjectFunctionNameFact:
    aliases = _json_list(row[2])
    va = int(row[0])
    return ProjectFunctionNameFact(
        entry_va=va,
        address=_hex(va),
        canonical=str(row[1]),
        aliases=[str(item) for item in aliases],
        set_by=str(row[3]) if row[3] is not None else None,
        demangled=str(row[4]) if row[4] is not None else None,
        flavor=str(row[5]) if row[5] is not None else None,
    )


def _boundary_fact(row: tuple) -> ProjectFunctionBoundaryFact:
    va = int(row[0])
    end_va = int(row[1]) if row[1] is not None else None
    return ProjectFunctionBoundaryFact(
        entry_va=va,
        address=_hex(va),
        end_va=end_va,
        end=_hex(end_va) if end_va is not None else None,
        size=int(row[2]) if row[2] is not None else None,
        source=str(row[3]),
        confidence=float(row[4]),
        name=str(row[5]) if row[5] is not None else None,
        detail=_json_obj(row[6]),
    )


def _chunk_fact(row: tuple) -> ProjectFunctionChunkFact:
    owner = int(row[0]) if row[0] is not None else None
    start = int(row[1])
    end = int(row[2]) if row[2] is not None else None
    target = int(row[6]) if row[6] is not None else None
    return ProjectFunctionChunkFact(
        owner_entry_va=owner,
        owner_entry=_hex(owner) if owner is not None else None,
        chunk_start_va=start,
        chunk_start=_hex(start),
        chunk_end_va=end,
        chunk_end=_hex(end) if end is not None else None,
        chunk_size=int(row[3]) if row[3] is not None else None,
        chunk_kind=str(row[4]),
        relation_kind=str(row[5]),
        target_va=target,
        target=_hex(target) if target is not None else None,
        target_name=str(row[7]) if row[7] is not None else None,
        source=str(row[8]),
        confidence=float(row[9]),
        name=str(row[10]) if row[10] is not None else None,
        detail=_json_obj(row[11]),
    )


def _result(
    *,
    project_path: Path,
    binary_id: int | None,
    present: set[str],
    target: ProjectFunctionStartTarget,
    names: list[ProjectFunctionNameFact],
    exact_boundaries: list[ProjectFunctionBoundaryFact],
    containing_boundaries: list[ProjectFunctionBoundaryFact],
    chunks: list[ProjectFunctionChunkFact],
    refs_to: list[ProjectFunctionXrefFact],
    refs_from: list[ProjectFunctionXrefFact],
    comments: list[ProjectFunctionCommentFact],
) -> WindowsProjectFunctionStartExplainResult:
    state = _state(names, exact_boundaries, containing_boundaries, chunks, refs_to)
    reason_codes = _reason_codes(
        state, names, exact_boundaries, containing_boundaries, chunks, refs_to, comments
    )
    return WindowsProjectFunctionStartExplainResult(
        project_path=str(project_path),
        binary_id=binary_id,
        target=target,
        final_state=state,
        confidence=_confidence(state, reason_codes),
        reason_codes=reason_codes,
        recommended_action=_recommended_action(state, reason_codes),
        names=names,
        exact_boundaries=exact_boundaries,
        containing_boundaries=containing_boundaries,
        chunks=chunks,
        refs_to=refs_to,
        refs_from=refs_from,
        comments=comments,
        coverage=_coverage(
            present,
            names,
            exact_boundaries,
            containing_boundaries,
            chunks,
            refs_to,
            refs_from,
            comments,
        ),
        missing_capabilities=_missing(
            present, names, exact_boundaries, chunks, refs_to, target
        ),
        notes=[
            "project function-start explanation uses persisted .glaurung facts; re-run bootstrap if expected tables are missing",
            "this is boundary evidence for triage, not vulnerability evidence",
        ],
    )


def _empty_result(
    project_path: Path,
    binary_id: int | None,
    target: ProjectFunctionStartTarget,
    present: set[str],
) -> WindowsProjectFunctionStartExplainResult:
    return WindowsProjectFunctionStartExplainResult(
        project_path=str(project_path),
        binary_id=binary_id,
        target=target,
        final_state="no_evidence",
        confidence="unknown",
        reason_codes=["unresolved_target"],
        recommended_action="resolve_va_or_symbol_before_boundary_review",
        coverage=[f"{table}_present" for table in sorted(present)],
        missing_capabilities=_table_missing(present) + ["target_resolution"],
        notes=[
            "symbol did not resolve to a project function address",
            "this is boundary evidence for triage, not vulnerability evidence",
        ],
    )


def _state(
    names: list[ProjectFunctionNameFact],
    exact: list[ProjectFunctionBoundaryFact],
    containing: list[ProjectFunctionBoundaryFact],
    chunks: list[ProjectFunctionChunkFact],
    refs_to: list[ProjectFunctionXrefFact],
) -> ProjectFunctionStartState:
    kinds = {chunk.chunk_kind for chunk in chunks}
    has_thunk = bool(kinds & {"jump_thunk", "adjustor_thunk", "import_thunk"})
    has_chunk = bool(
        kinds
        & {
            "split_body_candidate",
            "exception_funclet_candidate",
            "chained_unwind_chunk",
            "exception_handler_chunk",
            "tail_jump_target",
            "shared_tail_candidate",
        }
    )
    if has_thunk:
        return "thunk"
    if exact:
        return "strict_function"
    if has_chunk:
        return "chunk_or_funclet"
    if containing:
        return "contained_in_function"
    if any(ref.kind in {"call", "jump"} for ref in refs_to):
        return "xref_candidate"
    if names:
        return "symbol_only"
    return "no_evidence"


def _reason_codes(
    state: ProjectFunctionStartState,
    names: list[ProjectFunctionNameFact],
    exact: list[ProjectFunctionBoundaryFact],
    containing: list[ProjectFunctionBoundaryFact],
    chunks: list[ProjectFunctionChunkFact],
    refs_to: list[ProjectFunctionXrefFact],
    comments: list[ProjectFunctionCommentFact],
) -> list[str]:
    codes: list[str] = [state]
    if names:
        codes.append("function_name")
    if any(name.set_by == "pdb" for name in names):
        codes.append("pdb_function_name")
    if any(name.set_by == "manual" for name in names):
        codes.append("manual_function_name")
    for item in exact:
        codes.append(f"boundary:{item.source}")
        if item.end_va is not None:
            codes.append("bounded_range")
    if containing:
        codes.append("contained_by_boundary")
        for item in containing[:3]:
            codes.append(f"contained_by:{item.source}")
    for chunk in chunks:
        codes.append(f"chunk:{chunk.chunk_kind}")
        codes.append(f"relation:{chunk.relation_kind}")
    if any(ref.kind == "call" for ref in refs_to):
        codes.append("incoming_call_xref")
    if any(ref.kind == "jump" for ref in refs_to):
        codes.append("incoming_jump_xref")
    if comments:
        codes.append("comment_present")
    if state == "no_evidence":
        codes.append("no_project_boundary_evidence")
    return _dedupe(codes)


def _confidence(
    state: ProjectFunctionStartState,
    reason_codes: list[str],
) -> ProjectFunctionStartConfidence:
    if state == "strict_function":
        if "boundary:pdata" in reason_codes or "pdb_function_name" in reason_codes:
            return "high"
        return "medium"
    if state == "thunk":
        return "high" if "incoming_jump_xref" in reason_codes else "medium"
    if state in {"chunk_or_funclet", "contained_in_function"}:
        return "medium"
    if state == "xref_candidate":
        return "low"
    if state == "symbol_only":
        return "low"
    return "unknown"


def _recommended_action(
    state: ProjectFunctionStartState,
    reason_codes: list[str],
) -> str:
    if state == "strict_function":
        return "keep_function_start"
    if state == "thunk":
        if "chunk:import_thunk" in reason_codes:
            return "preserve_import_thunk_and_resolve_target"
        return "preserve_or_collapse_thunk_after_target_review"
    if state == "chunk_or_funclet":
        return "review_body_split_funclet_or_shared_tail_relation"
    if state == "contained_in_function":
        return "keep_as_label_or_promote_split_candidate_with_more_evidence"
    if state == "xref_candidate":
        return "promote_candidate_only_after_bytes_and_range_validation"
    if state == "symbol_only":
        return "run_project_boundary_and_chunk_indexing"
    return "collect_boundary_xref_or_symbol_evidence"


def _coverage(
    present: set[str],
    names: list[ProjectFunctionNameFact],
    exact: list[ProjectFunctionBoundaryFact],
    containing: list[ProjectFunctionBoundaryFact],
    chunks: list[ProjectFunctionChunkFact],
    refs_to: list[ProjectFunctionXrefFact],
    refs_from: list[ProjectFunctionXrefFact],
    comments: list[ProjectFunctionCommentFact],
) -> list[str]:
    coverage: list[str] = []
    if "function_names" in present:
        coverage.append("function_names")
    if names:
        coverage.append("function_name_match")
    if "function_boundaries" in present:
        coverage.append("function_boundaries")
    if exact:
        coverage.append("exact_boundary")
    if containing:
        coverage.append("containing_boundary")
    if "function_chunk_facts" in present:
        coverage.append("function_chunk_facts")
    if chunks:
        coverage.append("chunk_match")
    if refs_to or refs_from:
        coverage.append("xrefs")
    if refs_to:
        coverage.append("refs_to")
    if refs_from:
        coverage.append("refs_from")
    if comments:
        coverage.append("comments")
    return coverage


def _missing(
    present: set[str],
    names: list[ProjectFunctionNameFact],
    exact: list[ProjectFunctionBoundaryFact],
    chunks: list[ProjectFunctionChunkFact],
    refs_to: list[ProjectFunctionXrefFact],
    target: ProjectFunctionStartTarget,
) -> list[str]:
    missing = _table_missing(present)
    if target.va is None:
        missing.append("target_resolution")
    if not names:
        missing.append("function_name_match")
    if not exact:
        missing.append("exact_function_boundary")
    if not chunks:
        missing.append("function_chunk_match")
    if not refs_to:
        missing.append("incoming_xrefs")
    return _dedupe(missing)


def _table_missing(present: set[str]) -> list[str]:
    required = {
        "function_names",
        "function_boundaries",
        "function_chunk_facts",
        "xrefs",
    }
    return [f"{table}_table" for table in sorted(required - present)]


def _json_obj(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if value is None:
        return {}
    try:
        raw = json.loads(str(value))
    except Exception:
        return {}
    return raw if isinstance(raw, dict) else {}


def _json_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if value is None:
        return []
    try:
        raw = json.loads(str(value))
    except Exception:
        return []
    return raw if isinstance(raw, list) else []


def _hex(va: int | None) -> str:
    return f"0x{int(va or 0):x}"


def _dedupe(items: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def build_tool() -> WindowsProjectFunctionStartExplainTool:
    return WindowsProjectFunctionStartExplainTool()
