from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Edge, Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .windows_surface_metadata import _resolve_metadata_path


class WindowsOperationMetadataArgs(BaseModel):
    sinks_path: str | None = Field(
        None,
        description="Path to ASB data/kg/pe-sinks.yaml. Defaults to ASB_REPO or sibling repo.",
    )
    symbol: str | None = Field(
        None,
        description="Optional operation symbol filter, e.g. RtlCopyMemory or IoCompleteRequest.",
    )
    sink_kind: str | None = Field(
        None,
        description="Optional operation kind filter, e.g. copy, free, completion, lock.",
    )
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact operation-metadata evidence node to the KB.",
    )


class OperationArgRole(BaseModel):
    index: int
    role: str


class OperationRecord(BaseModel):
    id: str
    symbols: list[str]
    sink_kind: str
    effects: list[str] = Field(default_factory=list)
    arg_roles: list[OperationArgRole] = Field(default_factory=list)
    required_gates: list[str] = Field(default_factory=list)
    notes: str | None = None


class WindowsOperationMetadataResult(BaseModel):
    sinks_path: str
    symbol: str | None = None
    sink_kind: str | None = None
    operations: list[OperationRecord]
    operation_count_total: int
    evidence_node_id: str | None = None


class WindowsOperationMetadataTool(
    MemoryTool[WindowsOperationMetadataArgs, WindowsOperationMetadataResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_operation_metadata",
                description=(
                    "Load ASB Windows PE operation/sink metadata and optionally "
                    "filter by symbol or operation kind."
                ),
                tags=("windows", "pe", "metadata", "sinks", "operations"),
            ),
            WindowsOperationMetadataArgs,
            WindowsOperationMetadataResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsOperationMetadataArgs,
    ) -> WindowsOperationMetadataResult:
        sinks_path = _resolve_metadata_path(args.sinks_path, "data/kg/pe-sinks.yaml")
        operations = [_operation_record(entry, sinks_path) for entry in _load_yaml_list(sinks_path)]
        operation_count_total = len(operations)

        if args.symbol:
            operations = [op for op in operations if args.symbol in op.symbols]
        if args.sink_kind:
            operations = [op for op in operations if op.sink_kind == args.sink_kind]

        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_operation_metadata",
                    props={
                        "symbol": args.symbol,
                        "sink_kind": args.sink_kind,
                        "operation_matches": len(operations),
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))

        return WindowsOperationMetadataResult(
            sinks_path=str(sinks_path),
            symbol=args.symbol,
            sink_kind=args.sink_kind,
            operations=operations,
            operation_count_total=operation_count_total,
            evidence_node_id=evidence_node_id,
        )


def _load_yaml_list(path: Path) -> list[dict[str, Any]]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    if not isinstance(raw, list):
        raise ValueError(f"{path}: expected top-level list")
    out: list[dict[str, Any]] = []
    for idx, entry in enumerate(raw):
        if not isinstance(entry, dict):
            raise ValueError(f"{path}: operation entry {idx} is not a mapping")
        out.append(entry)
    return out


def _operation_record(entry: dict[str, Any], path: Path) -> OperationRecord:
    return OperationRecord(
        id=_required_str(entry, "id", path),
        symbols=_required_str_list(entry, "symbols", path),
        sink_kind=_required_str(entry, "sink_kind", path),
        effects=[str(x) for x in entry.get("effects") or []],
        arg_roles=_arg_roles(entry.get("arg_roles"), path, entry.get("id")),
        required_gates=[str(x) for x in entry.get("required_gates") or []],
        notes=entry.get("notes"),
    )


def _arg_roles(raw: Any, path: Path, owner: Any) -> list[OperationArgRole]:
    if not isinstance(raw, dict) or not raw:
        raise ValueError(f"{path}: operation {owner!r} missing non-empty arg_roles")
    roles = []
    for key, value in raw.items():
        roles.append(OperationArgRole(index=int(key), role=str(value)))
    return sorted(roles, key=lambda role: role.index)


def _required_str(entry: dict[str, Any], key: str, path: Path) -> str:
    value = entry.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{path}: missing required string field {key!r}")
    return value


def _required_str_list(entry: dict[str, Any], key: str, path: Path) -> list[str]:
    values = entry.get(key)
    if not isinstance(values, list) or not values:
        raise ValueError(f"{path}: missing non-empty list field {key!r}")
    return [str(v) for v in values if str(v)]


def build_tool() -> MemoryTool[
    WindowsOperationMetadataArgs, WindowsOperationMetadataResult
]:
    return WindowsOperationMetadataTool()
