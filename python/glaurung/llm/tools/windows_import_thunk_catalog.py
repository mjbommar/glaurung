from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Edge, Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .windows_function_start_explain import (
    DEFAULT_COMPARISON,
    DEFAULT_DIAGNOSTICS,
    FunctionStartState,
    _StartContext,
    _load_json_list,
    _resolve_path,
)


ThunkShape = Literal[
    "any",
    "rex_import_jump",
    "import_jump",
    "jmp_rel32",
    "unknown_thunk",
]
HistoricalDiagnosticKind = Literal["missing", "extra", "none"]


class WindowsImportThunkCatalogArgs(BaseModel):
    comparison_path: str | None = Field(
        None,
        description=(
            "Path to a Glaurung/Ghidra comparison JSON. Defaults to the "
            "30-file post-tiny-stub-gate dashboard in docs/windows-port."
        ),
    )
    diagnostics_path: str | None = Field(
        None,
        description=(
            "Path to per-address diagnostics JSON. Defaults to the 30-file "
            "diagnostics artifact in docs/windows-port."
        ),
    )
    file: str = Field(
        ...,
        description="Binary filename or unique path substring from the comparison artifact.",
    )
    shape: ThunkShape = Field(
        "any",
        description="Optional thunk-shape filter.",
    )
    max_rows: int = Field(
        64,
        ge=0,
        le=512,
        description="Maximum catalog rows to return.",
    )
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact import-thunk catalog evidence node.",
    )


class ImportThunkCatalogRow(BaseModel):
    file: str
    va: int
    address: str
    shape: ThunkShape
    current_state: FunctionStartState
    historical_diagnostic_kind: HistoricalDiagnosticKind
    in_glaurung: bool
    in_ghidra: bool
    ghidra_thunk: bool
    bytes_hex: str | None = None
    reason_codes: list[str] = Field(default_factory=list)
    recommended_action: str


class WindowsImportThunkCatalogResult(BaseModel):
    comparison_path: str
    diagnostics_path: str
    file: str
    total_ghidra_thunks: int
    total_missing_thunks: int
    total_catalog_rows: int
    returned_rows: int
    rows: list[ImportThunkCatalogRow]
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsImportThunkCatalogTool(
    MemoryTool[WindowsImportThunkCatalogArgs, WindowsImportThunkCatalogResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_import_thunk_catalog",
                description=(
                    "Catalog Windows import/IAT thunk-shaped function starts "
                    "from Glaurung/Ghidra comparison artifacts, including "
                    "recovered padded REX import jumps and remaining thunk gaps."
                ),
                tags=("windows", "pe", "ghidra", "thunk", "iat"),
            ),
            WindowsImportThunkCatalogArgs,
            WindowsImportThunkCatalogResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsImportThunkCatalogArgs,
    ) -> WindowsImportThunkCatalogResult:
        comparison_path = _resolve_path(args.comparison_path, DEFAULT_COMPARISON)
        diagnostics_path = _resolve_path(args.diagnostics_path, DEFAULT_DIAGNOSTICS)
        comparison = _select_row(_load_json_list(comparison_path), args.file)
        diagnostics = _select_row(_load_json_list(diagnostics_path), args.file)
        all_rows = _catalog_rows(comparison, diagnostics)
        filtered = [
            row for row in all_rows if args.shape == "any" or row.shape == args.shape
        ][: args.max_rows]

        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_import_thunk_catalog",
                    props={
                        "file": comparison.get("file"),
                        "shape": args.shape,
                        "returned_rows": len(filtered),
                        "total_ghidra_thunks": _ghidra_thunk_count(comparison),
                        "total_missing_thunks": _missing_thunk_count(comparison),
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))

        return WindowsImportThunkCatalogResult(
            comparison_path=str(comparison_path),
            diagnostics_path=str(diagnostics_path),
            file=str(comparison.get("file") or Path(str(comparison.get("path"))).name),
            total_ghidra_thunks=_ghidra_thunk_count(comparison),
            total_missing_thunks=_missing_thunk_count(comparison),
            total_catalog_rows=len(all_rows),
            returned_rows=len(filtered),
            rows=filtered,
            evidence_node_id=evidence_node_id,
            notes=[
                "Thunk catalog rows are functionization evidence, not import resolution proof."
            ],
        )


def _select_row(rows: list[dict], file_filter: str) -> dict:
    needle = file_filter.lower()
    exact = [
        row
        for row in rows
        if str(row.get("file") or "").lower() == needle
        or Path(str(row.get("path") or "")).name.lower() == needle
    ]
    if len(exact) == 1:
        return exact[0]
    matches = [
        row
        for row in rows
        if needle in str(row.get("file") or "").lower()
        or needle in str(row.get("path") or "").lower()
    ]
    if len(matches) == 1:
        return matches[0]
    if not matches and not exact:
        raise ValueError(f"no row matches file filter {file_filter!r}")
    raise ValueError(f"file filter {file_filter!r} matched multiple rows")


def _catalog_rows(comparison: dict, diagnostics: dict) -> list[ImportThunkCatalogRow]:
    rows_by_va: dict[int, ImportThunkCatalogRow] = {}
    for kind in ("missing", "extra"):
        historical_kind: HistoricalDiagnosticKind = (
            "missing" if kind == "missing" else "extra"
        )
        for entry in diagnostics.get(kind) or []:
            if not _looks_thunkish(entry):
                continue
            va = int(entry.get("va") or 0)
            if va <= 0:
                continue
            rows_by_va[va] = _catalog_row(
                comparison,
                diagnostics,
                va,
                historical_kind,
            )
    for function in comparison.get("ghidra", {}).get("functions") or []:
        if not function.get("thunk"):
            continue
        va = int(str(function.get("entry")), 16)
        rows_by_va.setdefault(va, _catalog_row(comparison, diagnostics, va, "none"))
    return sorted(
        rows_by_va.values(),
        key=lambda row: (_shape_rank(row.shape), row.va),
    )


def _catalog_row(
    comparison: dict,
    diagnostics: dict,
    va: int,
    historical_kind: HistoricalDiagnosticKind,
) -> ImportThunkCatalogRow:
    explained = _StartContext.from_rows(
        comparison,
        diagnostics,
        va,
        max_refs=4,
    ).to_result()
    shape = _shape(
        None if explained.bytes is None else explained.bytes.hex,
        explained.ghidra.thunk if explained.ghidra else False,
    )
    return ImportThunkCatalogRow(
        file=explained.file,
        va=explained.va,
        address=explained.address,
        shape=shape,
        current_state=explained.final_state,
        historical_diagnostic_kind=historical_kind,
        in_glaurung=explained.in_glaurung_function,
        in_ghidra=explained.in_ghidra,
        ghidra_thunk=False if explained.ghidra is None else explained.ghidra.thunk,
        bytes_hex=None if explained.bytes is None else explained.bytes.hex,
        reason_codes=explained.reason_codes,
        recommended_action=_recommended_action(explained.final_state),
    )


def _looks_thunkish(entry: dict) -> bool:
    ghidra = entry.get("ghidra") or {}
    if ghidra.get("thunk"):
        return True
    return _shape((entry.get("bytes") or {}).get("hex"), False) != "unknown_thunk"


def _shape(hex_bytes: str | None, ghidra_thunk: bool) -> ThunkShape:
    head = str(hex_bytes or "").lower()
    if head.startswith("48ff25"):
        return "rex_import_jump"
    if head.startswith("ff25"):
        return "import_jump"
    if head.startswith("e9"):
        return "jmp_rel32"
    if ghidra_thunk:
        return "unknown_thunk"
    return "unknown_thunk"


def _shape_rank(shape: ThunkShape) -> int:
    return {
        "rex_import_jump": 0,
        "import_jump": 1,
        "jmp_rel32": 2,
        "unknown_thunk": 3,
        "any": 4,
    }[shape]


def _recommended_action(state: FunctionStartState) -> str:
    if state == "strict_function":
        return "keep_thunk_function"
    if state == "ghidra_only":
        return "promote_or_classify_thunk"
    if state == "glaurung_only":
        return "verify_thunk_or_demote_candidate"
    return "inspect_thunk_context"


def _ghidra_thunk_count(comparison: dict) -> int:
    return int(
        (comparison.get("ghidra", {}).get("metrics") or {}).get("thunk_functions") or 0
    )


def _missing_thunk_count(comparison: dict) -> int:
    return int((comparison.get("address_gap") or {}).get("missing_thunks") or 0)


def build_tool() -> WindowsImportThunkCatalogTool:
    return WindowsImportThunkCatalogTool()
