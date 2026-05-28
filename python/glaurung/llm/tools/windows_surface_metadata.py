from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Node, NodeKind, Edge
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


class WindowsSurfaceMetadataArgs(BaseModel):
    sources_path: str | None = Field(
        None,
        description="Path to ASB data/kg/pe-sources.yaml. Defaults to ASB_REPO or sibling repo.",
    )
    gates_path: str | None = Field(
        None,
        description="Path to ASB data/kg/pe-gates.yaml. Defaults to ASB_REPO or sibling repo.",
    )
    symbol: str | None = Field(
        None,
        description="Optional symbol name filter, e.g. NtQuerySystemInformation or ProbeForWrite.",
    )
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact metadata evidence node to the in-memory KB.",
    )


class SourceRole(BaseModel):
    index: int | None = None
    expression: str | None = None
    role: str
    paired_length: int | str | None = None
    selector: int | str | None = None


class SourceRecord(BaseModel):
    id: str
    surface: str
    symbols: list[str]
    attacker_class: str
    roles: list[SourceRole]
    notes: str | None = None


class GateRecord(BaseModel):
    id: str
    symbols: list[str]
    gate_kind: str
    proves: list[str] = Field(default_factory=list)
    required_conditions: list[str] = Field(default_factory=list)
    invalid_when: list[str] = Field(default_factory=list)
    notes: str | None = None


class WindowsSurfaceMetadataResult(BaseModel):
    sources_path: str
    gates_path: str
    symbol: str | None = None
    sources: list[SourceRecord]
    gates: list[GateRecord]
    source_count_total: int
    gate_count_total: int
    evidence_node_id: str | None = None


class WindowsSurfaceMetadataTool(
    MemoryTool[WindowsSurfaceMetadataArgs, WindowsSurfaceMetadataResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_surface_metadata",
                description=(
                    "Load ASB Windows PE source/gate metadata and optionally "
                    "filter it by symbol name."
                ),
                tags=("windows", "pe", "metadata", "surface", "gates"),
            ),
            WindowsSurfaceMetadataArgs,
            WindowsSurfaceMetadataResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsSurfaceMetadataArgs,
    ) -> WindowsSurfaceMetadataResult:
        sources_path = _resolve_metadata_path(args.sources_path, "data/kg/pe-sources.yaml")
        gates_path = _resolve_metadata_path(args.gates_path, "data/kg/pe-gates.yaml")
        sources = [_source_record(e, sources_path) for e in _load_yaml_list(sources_path)]
        gates = [_gate_record(e, gates_path) for e in _load_yaml_list(gates_path)]
        source_count_total = len(sources)
        gate_count_total = len(gates)

        if args.symbol:
            needle = args.symbol
            sources = [s for s in sources if needle in s.symbols]
            gates = [g for g in gates if needle in g.symbols]

        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_surface_metadata",
                    props={
                        "symbol": args.symbol,
                        "source_matches": len(sources),
                        "gate_matches": len(gates),
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))

        return WindowsSurfaceMetadataResult(
            sources_path=str(sources_path),
            gates_path=str(gates_path),
            symbol=args.symbol,
            sources=sources,
            gates=gates,
            source_count_total=source_count_total,
            gate_count_total=gate_count_total,
            evidence_node_id=evidence_node_id,
        )


def _resolve_metadata_path(raw_path: str | None, rel_path: str) -> Path:
    if raw_path:
        path = Path(raw_path).expanduser()
        if path.exists():
            return path
        raise FileNotFoundError(path)

    candidates: list[Path] = []
    asb_repo = os.environ.get("ASB_REPO")
    if asb_repo:
        candidates.append(Path(asb_repo).expanduser() / rel_path)

    glaurung_root = Path(__file__).resolve().parents[4]
    candidates.extend(
        [
            glaurung_root.parent / "agentic-security-bot" / rel_path,
            Path.cwd().parent / "agentic-security-bot" / rel_path,
        ]
    )
    for candidate in candidates:
        if candidate.exists():
            return candidate
    searched = ", ".join(str(c) for c in candidates)
    raise FileNotFoundError(f"could not find {rel_path}; searched: {searched}")


def _load_yaml_list(path: Path) -> list[dict[str, Any]]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    if not isinstance(raw, list):
        raise ValueError(f"{path}: expected top-level list")
    for idx, entry in enumerate(raw):
        if not isinstance(entry, dict):
            raise ValueError(f"{path}: entry {idx} is not a mapping")
    return raw


def _source_record(entry: dict[str, Any], path: Path) -> SourceRecord:
    roles = entry.get("roles") or []
    if not isinstance(roles, list) or not roles:
        raise ValueError(f"{path}: source {entry.get('id')!r} has no roles")
    return SourceRecord(
        id=_required_str(entry, "id", path),
        surface=_required_str(entry, "surface", path),
        symbols=_required_str_list(entry, "symbols", path),
        attacker_class=_required_str(entry, "attacker_class", path),
        roles=[_source_role(role, path, entry.get("id")) for role in roles],
        notes=entry.get("notes"),
    )


def _gate_record(entry: dict[str, Any], path: Path) -> GateRecord:
    return GateRecord(
        id=_required_str(entry, "id", path),
        symbols=_required_str_list(entry, "symbols", path),
        gate_kind=_required_str(entry, "gate_kind", path),
        proves=[str(x) for x in entry.get("proves") or []],
        required_conditions=[str(x) for x in entry.get("required_conditions") or []],
        invalid_when=[str(x) for x in entry.get("invalid_when") or []],
        notes=entry.get("notes"),
    )


def _source_role(raw: Any, path: Path, owner: Any) -> SourceRole:
    if not isinstance(raw, dict):
        raise ValueError(f"{path}: role for {owner!r} is not a mapping")
    if "index" in raw and "expression" in raw:
        raise ValueError(f"{path}: role for {owner!r} has both index and expression")
    role = raw.get("role")
    if not isinstance(role, str) or not role:
        raise ValueError(f"{path}: role for {owner!r} missing role")
    return SourceRole(
        index=int(raw["index"]) if raw.get("index") is not None else None,
        expression=str(raw["expression"]) if raw.get("expression") is not None else None,
        role=role,
        paired_length=raw.get("paired_length"),
        selector=raw.get("selector"),
    )


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


def build_tool() -> MemoryTool[WindowsSurfaceMetadataArgs, WindowsSurfaceMetadataResult]:
    return WindowsSurfaceMetadataTool()
