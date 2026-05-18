from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Edge, Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


class ProjectBranchConditionFact(BaseModel):
    function_va: int
    block_id: str
    block_start_va: int | None = None
    block_end_va: int | None = None
    branch_va: int
    branch_mnemonic: str
    branch_operands: list[str] = Field(default_factory=list)
    compare_va: int | None = None
    compare_mnemonic: str | None = None
    compare_operands: list[str] = Field(default_factory=list)
    condition_kind: str
    inverse_condition_kind: str | None = None
    target_predicate: str | None = None
    fallthrough_predicate: str | None = None
    target_block_id: str | None = None
    fallthrough_block_id: str | None = None
    on_supplied_path: bool | None = None


class WindowsProjectBranchConditionFactsArgs(BaseModel):
    project_path: str = Field(..., description="Path to a .glaurung SQLite project.")
    function_va: int | None = Field(None, description="Optional function VA filter.")
    block_id: str | None = Field(None, description="Optional CFG block id filter.")
    branch_va: int | None = Field(None, description="Optional branch instruction VA filter.")
    condition_kind: str | None = Field(
        None,
        description="Optional condition class filter, e.g. equal or unsigned_less.",
    )
    path_block_ids: list[str] = Field(
        default_factory=list,
        description="Optional path block ids; when set, return only facts on that path.",
    )
    max_rows: int = Field(32, ge=0, description="Maximum branch facts to return.")
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact branch-condition evidence node to the KB.",
    )


class WindowsProjectBranchConditionFactsResult(BaseModel):
    project_path: str
    facts: list[ProjectBranchConditionFact]
    scanned_fact_count: int
    returned_fact_count: int
    coverage: list[str] = Field(default_factory=list)
    missing_capabilities: list[str] = Field(default_factory=list)
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsProjectBranchConditionFactsTool(
    MemoryTool[
        WindowsProjectBranchConditionFactsArgs,
        WindowsProjectBranchConditionFactsResult,
    ]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_project_branch_condition_facts",
                description=(
                    "Query persisted .glaurung branch-condition facts, including "
                    "conditional branch mnemonics and nearby cmp/test operands."
                ),
                tags=("windows", "pe", "project", "cfg", "branches", "conditions"),
            ),
            WindowsProjectBranchConditionFactsArgs,
            WindowsProjectBranchConditionFactsResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsProjectBranchConditionFactsArgs,
    ) -> WindowsProjectBranchConditionFactsResult:
        result = _query(args)

        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_project_branch_condition_facts",
                    props={
                        "project_path": result.project_path,
                        "function_va": args.function_va,
                        "block_id": args.block_id,
                        "branch_va": args.branch_va,
                        "fact_count": result.returned_fact_count,
                    },
                )
            )
            result.evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))

        return result


def _query(
    args: WindowsProjectBranchConditionFactsArgs,
) -> WindowsProjectBranchConditionFactsResult:
    project_path = Path(args.project_path)
    missing: list[str] = []
    notes = [
        "branch facts are simple disassembly-backed predicates; full IR flag-flow is not implied"
    ]
    if not project_path.exists():
        return WindowsProjectBranchConditionFactsResult(
            project_path=args.project_path,
            facts=[],
            scanned_fact_count=0,
            returned_fact_count=0,
            missing_capabilities=["project_file"],
            notes=[f"{project_path}: .glaurung project does not exist"],
        )

    try:
        conn = sqlite3.connect(f"file:{project_path}?mode=ro", uri=True)
    except sqlite3.Error as exc:
        return WindowsProjectBranchConditionFactsResult(
            project_path=args.project_path,
            facts=[],
            scanned_fact_count=0,
            returned_fact_count=0,
            missing_capabilities=["project_open"],
            notes=[f"failed to open project: {exc}"],
        )
    try:
        present = {
            str(row[0])
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
        if "cfg_branch_facts" not in present:
            missing.append("branch_conditions")
            return WindowsProjectBranchConditionFactsResult(
                project_path=args.project_path,
                facts=[],
                scanned_fact_count=0,
                returned_fact_count=0,
                missing_capabilities=missing,
                notes=notes,
            )
        scanned = _count_all(conn, args)
        facts = _facts(conn, args, present)
    finally:
        conn.close()

    coverage = ["branch_conditions"] if scanned else []
    if not scanned:
        missing.append("matching_branch_conditions")
    return WindowsProjectBranchConditionFactsResult(
        project_path=args.project_path,
        facts=facts,
        scanned_fact_count=scanned,
        returned_fact_count=len(facts),
        coverage=coverage,
        missing_capabilities=missing,
        notes=notes,
    )


def _count_all(
    conn: sqlite3.Connection,
    args: WindowsProjectBranchConditionFactsArgs,
) -> int:
    where, params = _where(args)
    sql = "SELECT COUNT(*) FROM cfg_branch_facts b" + where
    return int(conn.execute(sql, params).fetchone()[0])


def _facts(
    conn: sqlite3.Connection,
    args: WindowsProjectBranchConditionFactsArgs,
    present: set[str],
) -> list[ProjectBranchConditionFact]:
    if args.max_rows == 0:
        return []
    path_filter = set(args.path_block_ids)
    where, params = _where(args)
    if path_filter:
        placeholders = ",".join("?" for _ in path_filter)
        where = (where + " AND " if where else " WHERE ") + f"b.block_id IN ({placeholders})"
        params.extend(sorted(path_filter))
    join = ""
    select_block = "NULL, NULL"
    if "basic_blocks" in present:
        join = (
            " LEFT JOIN basic_blocks bb ON bb.binary_id = b.binary_id "
            "AND bb.function_va = b.function_va AND bb.block_id = b.block_id"
        )
        select_block = "bb.start_va, bb.end_va"
    params.append(args.max_rows)
    rows = conn.execute(
        "SELECT b.function_va, b.block_id, "
        f"{select_block}, "
        "b.branch_va, b.branch_mnemonic, b.branch_operands_json, "
        "b.compare_va, b.compare_mnemonic, b.compare_operands_json, "
        "b.condition_kind, b.target_block_id, b.fallthrough_block_id "
        f"FROM cfg_branch_facts b{join}{where} "
        "ORDER BY b.function_va, b.branch_va LIMIT ?",
        params,
    ).fetchall()
    return [
        _fact_from_row(row, path_filter)
        for row in rows
    ]


def _fact_from_row(
    row: tuple,
    path_filter: set[str],
) -> ProjectBranchConditionFact:
    compare_mnemonic = str(row[8]) if row[8] is not None else None
    compare_operands = _json_list(row[9])
    condition_kind = str(row[10])
    inverse_condition_kind = _inverse_condition_kind(condition_kind)
    return ProjectBranchConditionFact(
        function_va=int(row[0]),
        block_id=str(row[1]),
        block_start_va=int(row[2]) if row[2] is not None else None,
        block_end_va=int(row[3]) if row[3] is not None else None,
        branch_va=int(row[4]),
        branch_mnemonic=str(row[5]),
        branch_operands=_json_list(row[6]),
        compare_va=int(row[7]) if row[7] is not None else None,
        compare_mnemonic=compare_mnemonic,
        compare_operands=compare_operands,
        condition_kind=condition_kind,
        inverse_condition_kind=inverse_condition_kind,
        target_predicate=_predicate_text(
            compare_mnemonic,
            compare_operands,
            condition_kind,
        ),
        fallthrough_predicate=_predicate_text(
            compare_mnemonic,
            compare_operands,
            inverse_condition_kind,
        ),
        target_block_id=str(row[11]) if row[11] is not None else None,
        fallthrough_block_id=str(row[12]) if row[12] is not None else None,
        on_supplied_path=(str(row[1]) in path_filter) if path_filter else None,
    )


def _where(args: WindowsProjectBranchConditionFactsArgs) -> tuple[str, list[object]]:
    clauses = []
    params: list[object] = []
    if args.function_va is not None:
        clauses.append("b.function_va = ?")
        params.append(args.function_va)
    if args.block_id is not None:
        clauses.append("b.block_id = ?")
        params.append(args.block_id)
    if args.branch_va is not None:
        clauses.append("b.branch_va = ?")
        params.append(args.branch_va)
    if args.condition_kind is not None:
        clauses.append("b.condition_kind = ?")
        params.append(args.condition_kind)
    return (" WHERE " + " AND ".join(clauses) if clauses else ""), params


def _json_list(raw: object) -> list[str]:
    try:
        value = json.loads(str(raw or "[]"))
    except json.JSONDecodeError:
        return []
    if not isinstance(value, list):
        return []
    return [str(item) for item in value]


def _inverse_condition_kind(condition_kind: str | None) -> str | None:
    if condition_kind is None:
        return None
    return {
        "equal": "not_equal",
        "not_equal": "equal",
        "unsigned_greater": "unsigned_less_equal",
        "unsigned_greater_equal": "unsigned_less",
        "unsigned_less": "unsigned_greater_equal",
        "unsigned_less_equal": "unsigned_greater",
        "signed_greater": "signed_less_equal",
        "signed_greater_equal": "signed_less",
        "signed_less": "signed_greater_equal",
        "signed_less_equal": "signed_greater",
        "overflow": "not_overflow",
        "not_overflow": "overflow",
        "signed": "not_signed",
        "not_signed": "signed",
        "parity": "not_parity",
        "not_parity": "parity",
    }.get(condition_kind)


def _predicate_text(
    compare_mnemonic: str | None,
    compare_operands: list[str],
    condition_kind: str | None,
) -> str | None:
    if not compare_mnemonic or not condition_kind:
        return None
    if compare_mnemonic == "test" and len(compare_operands) >= 2:
        lhs = compare_operands[0]
        rhs = compare_operands[1]
        value = lhs if lhs == rhs else f"({lhs} & {rhs})"
        return _predicate_from_operands(value, "0", condition_kind)
    if compare_mnemonic == "cmp" and len(compare_operands) >= 2:
        return _predicate_from_operands(compare_operands[0], compare_operands[1], condition_kind)
    expression = _flag_result_expression(compare_mnemonic, compare_operands)
    if expression is not None:
        return _predicate_from_operands(expression, "0", condition_kind)
    return None


def _flag_result_expression(
    compare_mnemonic: str,
    compare_operands: list[str],
) -> str | None:
    if compare_mnemonic in {"and", "or", "xor", "sub", "add"} and len(compare_operands) >= 2:
        op = {
            "and": "&",
            "or": "|",
            "xor": "^",
            "sub": "-",
            "add": "+",
        }[compare_mnemonic]
        return f"({compare_operands[0]} {op} {compare_operands[1]})"
    if compare_mnemonic == "inc" and compare_operands:
        return f"({compare_operands[0]} + 1)"
    if compare_mnemonic == "dec" and compare_operands:
        return f"({compare_operands[0]} - 1)"
    return None


def _predicate_from_operands(lhs: str, rhs: str, condition_kind: str) -> str | None:
    op = {
        "equal": "==",
        "not_equal": "!=",
        "unsigned_greater": ">u",
        "unsigned_greater_equal": ">=u",
        "unsigned_less": "<u",
        "unsigned_less_equal": "<=u",
        "signed_greater": ">s",
        "signed_greater_equal": ">=s",
        "signed_less": "<s",
        "signed_less_equal": "<=s",
    }.get(condition_kind)
    if op is None:
        return None
    return f"{lhs} {op} {rhs}"


def build_tool() -> WindowsProjectBranchConditionFactsTool:
    return WindowsProjectBranchConditionFactsTool()
