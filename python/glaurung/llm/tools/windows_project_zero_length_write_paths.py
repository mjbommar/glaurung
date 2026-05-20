from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

import glaurung as g

from ..context import MemoryContext
from ..kb.models import Edge, Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .windows_api_contract_primitives import (
    WindowsApiContractPrimitivesArgs,
    WindowsApiContractPrimitivesTool,
)


class ZeroLengthWritePath(BaseModel):
    callsite_va: int
    caller_va: int | None = None
    caller_name: str | None = None
    callee_va: int
    callee_name: str | None = None
    zero_arg_index: int
    zero_arg_expression: str | None = None
    path_condition_roles: list[str] = Field(default_factory=list)
    write_primitive_kinds: list[str] = Field(default_factory=list)
    write_evidence: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)
    provenance: list[str] = Field(default_factory=list)


class WindowsProjectZeroLengthWritePathsArgs(BaseModel):
    binary_path: str = Field(
        ..., description="Path to the PE binary backing the project."
    )
    project_path: str = Field(..., description="Path to a .glaurung SQLite project.")
    callsite_va: int | None = Field(None, description="Optional exact callsite filter.")
    callee_name: str | None = Field(
        None, description="Optional callee-name substring filter."
    )
    binary_id: int | None = Field(None, description="Optional binary_id filter.")
    max_paths: int = Field(32, ge=0, description="Maximum paths to return.")
    max_blocks: int = Field(1024, ge=1, description="Decompiler block budget.")
    max_instructions: int = Field(
        50_000, ge=1, description="Decompiler instruction budget."
    )
    timeout_ms: int = Field(5_000, ge=1, description="Decompiler timeout.")
    pdb_cache: str = Field("", description="Optional PDB cache for decompile names.")
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact zero-length path evidence node to the KB.",
    )


class WindowsProjectZeroLengthWritePathsResult(BaseModel):
    binary_path: str
    project_path: str
    path_count: int
    paths: list[ZeroLengthWritePath]
    coverage: list[str] = Field(default_factory=list)
    missing_capabilities: list[str] = Field(default_factory=list)
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsProjectZeroLengthWritePathsTool(
    MemoryTool[
        WindowsProjectZeroLengthWritePathsArgs,
        WindowsProjectZeroLengthWritePathsResult,
    ]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_project_zero_length_write_paths",
                description=(
                    "Join persisted callsite argument snapshots, nearby path "
                    "conditions, and callee write/copy primitives to flag "
                    "class-253-style zero-length paths into write-capable helpers."
                ),
                tags=("windows", "pe", "project", "callsites", "contracts", "rules"),
            ),
            WindowsProjectZeroLengthWritePathsArgs,
            WindowsProjectZeroLengthWritePathsResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsProjectZeroLengthWritePathsArgs,
    ) -> WindowsProjectZeroLengthWritePathsResult:
        binary_path = Path(args.binary_path)
        project_path = Path(args.project_path)
        if not binary_path.exists():
            raise ValueError(f"{binary_path}: PE binary does not exist")
        if not project_path.exists():
            raise ValueError(f"{project_path}: .glaurung project does not exist")

        candidates = _query_candidates(args)
        paths: list[ZeroLengthWritePath] = []
        primitive_tool = WindowsApiContractPrimitivesTool()
        for candidate in candidates:
            text, source = _decompile_callee(binary_path, candidate, args)
            if not text:
                continue
            primitive_result = primitive_tool.run(
                ctx,
                kb,
                WindowsApiContractPrimitivesArgs(
                    pseudocode=text,
                    max_blocks=args.max_blocks,
                    max_instructions=args.max_instructions,
                    timeout_ms=args.timeout_ms,
                    pdb_cache=args.pdb_cache,
                ),
            )
            writes = [
                item
                for item in primitive_result.primitives
                if item.kind
                in {
                    "pointer_write",
                    "return_length_write",
                    "user_buffer_copy",
                    "string_conversion_copy",
                }
            ]
            if not writes:
                continue
            paths.append(_path(candidate, writes, source))
            if len(paths) >= args.max_paths:
                break

        coverage = _coverage(paths)
        missing = _missing_capabilities(candidates, paths)
        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_project_zero_length_write_paths",
                    props={
                        "binary_path": str(binary_path),
                        "project_path": str(project_path),
                        "candidate_count": len(candidates),
                        "path_count": len(paths),
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))

        return WindowsProjectZeroLengthWritePathsResult(
            binary_path=str(binary_path),
            project_path=str(project_path),
            path_count=len(paths),
            paths=paths,
            coverage=coverage,
            missing_capabilities=missing,
            evidence_node_id=evidence_node_id,
            notes=[
                "zero-length write paths are static triage proof: a zero/null "
                "argument reaches a helper whose decompiled body contains a "
                "write/copy primitive; runtime exploitability is not implied"
            ],
        )


def _query_candidates(
    args: WindowsProjectZeroLengthWritePathsArgs,
) -> list[dict[str, Any]]:
    conn = sqlite3.connect(f"file:{args.project_path}?mode=ro", uri=True)
    try:
        present = _present_tables(conn)
        if not {"xrefs", "callsite_argument_facts"}.issubset(present):
            return []
        binary_id = args.binary_id or _first_binary_id(conn, present)
        clauses = [
            "x.kind = 'call'",
            "a.callsite_va = x.src_va",
            "a.binary_id = x.binary_id",
            "(a.value_role = 'zero_or_null' OR a.expression IN ('0', '0x0', 'NULL', 'null'))",
        ]
        params: list[object] = []
        if binary_id is not None:
            clauses.append("x.binary_id = ?")
            params.append(binary_id)
        if args.callsite_va is not None:
            clauses.append("x.src_va = ?")
            params.append(int(args.callsite_va))
        if args.callee_name is not None and "function_names" not in present:
            return []
        if args.callee_name is not None:
            clauses.append("LOWER(callee.canonical) LIKE ?")
            params.append(f"%{args.callee_name.lower()}%")
        caller_select = "caller.canonical" if "function_names" in present else "NULL"
        callee_select = "callee.canonical" if "function_names" in present else "NULL"
        function_name_joins = (
            """
LEFT JOIN function_names caller
  ON caller.binary_id = x.binary_id AND caller.entry_va = x.src_function_va
LEFT JOIN function_names callee
  ON callee.binary_id = x.binary_id AND callee.entry_va = x.dst_va
"""
            if "function_names" in present
            else ""
        )
        boundary_select = "fb.end_va" if "function_boundaries" in present else "NULL"
        boundary_join = (
            """
LEFT JOIN function_boundaries fb
  ON fb.binary_id = x.binary_id AND fb.entry_va = x.dst_va
"""
            if "function_boundaries" in present
            else ""
        )
        query = f"""
SELECT x.binary_id, x.src_va, x.src_function_va, {caller_select},
       x.dst_va, {callee_select}, a.argument_index, a.expression,
       {boundary_select}
FROM xrefs x
JOIN callsite_argument_facts a
  ON a.binary_id = x.binary_id AND a.callsite_va = x.src_va
{function_name_joins}{boundary_join}
WHERE {" AND ".join(clauses)}
ORDER BY x.src_va, a.argument_index
LIMIT ?
"""
        params.append(int(args.max_paths * 4 if args.max_paths else 0))
        rows = conn.execute(query, params).fetchall()
        return [_candidate_from_row(conn, present, row) for row in rows]
    finally:
        conn.close()


def _candidate_from_row(
    conn: sqlite3.Connection,
    present: set[str],
    row: tuple,
) -> dict[str, Any]:
    callsite_va = int(row[1])
    path_condition_roles: list[str] = []
    if "callsite_path_conditions" in present:
        path_condition_roles = [
            str(item[0])
            for item in conn.execute(
                "SELECT condition_role FROM callsite_path_conditions "
                "WHERE binary_id = ? AND callsite_va = ? ORDER BY branch_va",
                (int(row[0]), callsite_va),
            ).fetchall()
        ]
    return {
        "binary_id": int(row[0]),
        "callsite_va": callsite_va,
        "caller_va": int(row[2]) if row[2] is not None else None,
        "caller_name": str(row[3]) if row[3] is not None else None,
        "callee_va": int(row[4]),
        "callee_name": str(row[5]) if row[5] is not None else None,
        "zero_arg_index": int(row[6]),
        "zero_arg_expression": str(row[7]) if row[7] is not None else None,
        "callee_end_va": int(row[8]) if row[8] is not None else None,
        "path_condition_roles": path_condition_roles,
    }


def _decompile_callee(
    binary_path: Path,
    candidate: dict[str, Any],
    args: WindowsProjectZeroLengthWritePathsArgs,
) -> tuple[str, str]:
    callee_va = int(candidate["callee_va"])
    end_va = candidate.get("callee_end_va")
    try:
        ir = getattr(g, "ir")
        if isinstance(end_va, int) and end_va > callee_va:
            return (
                ir.decompile_range_at(
                    str(binary_path),
                    callee_va,
                    callee_va,
                    end_va,
                    max_blocks=args.max_blocks,
                    max_instructions=args.max_instructions,
                    timeout_ms=args.timeout_ms,
                    style="c",
                    pdb_cache=args.pdb_cache,
                ),
                "glaurung_decompiler_explicit_range",
            )
        return (
            ir.decompile_at(
                str(binary_path),
                callee_va,
                max_blocks=args.max_blocks,
                max_instructions=args.max_instructions,
                timeout_ms=args.timeout_ms,
                style="c",
                pdb_cache=args.pdb_cache,
            ),
            "glaurung_decompiler",
        )
    except Exception:
        return "", "glaurung_decompiler_failed"


def _path(
    candidate: dict[str, Any],
    writes: list[Any],
    source: str,
) -> ZeroLengthWritePath:
    kinds = sorted({str(item.kind) for item in writes})
    evidence = [str(item.snippet) for item in writes[:4]]
    confidence = 0.78
    if "zero_length_or_null_gate" in candidate["path_condition_roles"]:
        confidence += 0.08
    if "user_buffer_copy" in kinds or "string_conversion_copy" in kinds:
        confidence += 0.06
    return ZeroLengthWritePath(
        callsite_va=int(candidate["callsite_va"]),
        caller_va=candidate["caller_va"],
        caller_name=candidate["caller_name"],
        callee_va=int(candidate["callee_va"]),
        callee_name=candidate["callee_name"],
        zero_arg_index=int(candidate["zero_arg_index"]),
        zero_arg_expression=candidate["zero_arg_expression"],
        path_condition_roles=list(candidate["path_condition_roles"]),
        write_primitive_kinds=kinds,
        write_evidence=evidence,
        confidence=min(confidence, 0.92),
        provenance=[
            "callsite_argument_facts",
            "project_call_xref",
            "callsite_path_conditions",
            source,
            "windows_api_contract_primitives",
        ],
    )


def _coverage(paths: list[ZeroLengthWritePath]) -> list[str]:
    if not paths:
        return []
    coverage = [
        "zero_length_argument_facts",
        "project_call_xrefs",
        "callee_write_primitives",
    ]
    if any(path.path_condition_roles for path in paths):
        coverage.append("callsite_path_conditions")
    return coverage


def _missing_capabilities(
    candidates: list[dict[str, Any]],
    paths: list[ZeroLengthWritePath],
) -> list[str]:
    missing: list[str] = []
    if not candidates:
        missing.append("zero_length_argument_facts")
    if candidates and not paths:
        missing.append("callee_write_primitives")
    if paths and not any(path.path_condition_roles for path in paths):
        missing.append("callsite_path_conditions")
    return missing


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


def build_tool() -> WindowsProjectZeroLengthWritePathsTool:
    return WindowsProjectZeroLengthWritePathsTool()
