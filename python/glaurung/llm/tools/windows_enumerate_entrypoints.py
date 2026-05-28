from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field

import glaurung as g

from ..context import MemoryContext
from ..kb.models import Edge, Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .windows_surface_metadata import _resolve_metadata_path


SymbolCategory = Literal["all", "dynamic", "imports", "exports"]


class WindowsEnumerateEntrypointsArgs(BaseModel):
    sources_path: str | None = Field(
        None,
        description="Path to ASB data/kg/pe-sources.yaml. Defaults to ASB_REPO or sibling repo.",
    )
    surfaces: list[str] = Field(
        default_factory=list,
        description="Optional source surface filters, e.g. syscall or ioctl.",
    )
    include_absent: bool = Field(
        True,
        description="Include metadata entrypoints that are not present in the current binary symbols.",
    )
    max_entrypoints: int | None = Field(
        None,
        description="Optional output cap after filtering.",
    )
    add_to_kb: bool = Field(
        False,
        description="Add a compact entrypoint enumeration evidence node to the KB.",
    )


class EntrypointRole(BaseModel):
    index: int | None = None
    expression: str | None = None
    role: str
    paired_length: int | str | None = None
    selector: int | str | None = None


class BinarySymbolEvidence(BaseModel):
    name: str
    category: SymbolCategory


class WindowsEntrypoint(BaseModel):
    source_id: str
    surface: str
    symbol: str
    attacker_class: str
    roles: list[EntrypointRole]
    present_in_binary: bool
    symbol_evidence: list[BinarySymbolEvidence] = Field(default_factory=list)
    va: int | None = None
    confidence: float = Field(ge=0.0, le=1.0)
    provenance: list[str] = Field(default_factory=list)
    notes: str | None = None


class WindowsEnumerateEntrypointsResult(BaseModel):
    sources_path: str
    entrypoints: list[WindowsEntrypoint]
    source_count_total: int
    present_count: int
    evidence_node_id: str | None = None


class WindowsEnumerateEntrypointsTool(
    MemoryTool[WindowsEnumerateEntrypointsArgs, WindowsEnumerateEntrypointsResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_enumerate_entrypoints",
                description=(
                    "Enumerate Windows PE attacker-surface entrypoints from ASB "
                    "source metadata and join them to current binary symbols "
                    "when available."
                ),
                tags=("windows", "pe", "entrypoints", "metadata", "surface"),
            ),
            WindowsEnumerateEntrypointsArgs,
            WindowsEnumerateEntrypointsResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsEnumerateEntrypointsArgs,
    ) -> WindowsEnumerateEntrypointsResult:
        sources_path = _resolve_metadata_path(args.sources_path, "data/kg/pe-sources.yaml")
        sources = _load_sources(sources_path)
        symbol_inventory = _collect_binary_symbols(ctx)
        address_map = _collect_symbol_addresses(ctx)
        surfaces = {surface.lower() for surface in args.surfaces}

        entrypoints: list[WindowsEntrypoint] = []
        for source in sources:
            surface = _required_str(source, "surface", sources_path)
            if surfaces and surface.lower() not in surfaces:
                continue
            for symbol in _str_list(source.get("symbols")):
                evidence = _symbol_evidence(symbol, symbol_inventory)
                present = bool(evidence)
                if not present and not args.include_absent:
                    continue
                entrypoints.append(
                    WindowsEntrypoint(
                        source_id=_required_str(source, "id", sources_path),
                        surface=surface,
                        symbol=symbol,
                        attacker_class=_required_str(
                            source, "attacker_class", sources_path
                        ),
                        roles=_roles(source, sources_path),
                        present_in_binary=present,
                        symbol_evidence=evidence,
                        va=_lookup_symbol_va(symbol, address_map),
                        confidence=0.85 if present else 0.55,
                        provenance=_provenance(present),
                        notes=str(source.get("notes") or "") or None,
                    )
                )
                if (
                    args.max_entrypoints is not None
                    and len(entrypoints) >= args.max_entrypoints
                ):
                    break
            if args.max_entrypoints is not None and len(entrypoints) >= args.max_entrypoints:
                break

        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_enumerate_entrypoints",
                    props={
                        "entrypoint_count": len(entrypoints),
                        "present_count": sum(1 for e in entrypoints if e.present_in_binary),
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))

        return WindowsEnumerateEntrypointsResult(
            sources_path=str(sources_path),
            entrypoints=entrypoints,
            source_count_total=len(sources),
            present_count=sum(1 for e in entrypoints if e.present_in_binary),
            evidence_node_id=evidence_node_id,
        )


def _load_sources(path: Path) -> list[dict[str, Any]]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    if not isinstance(raw, list):
        raise ValueError(f"{path}: expected top-level list")
    out: list[dict[str, Any]] = []
    for idx, entry in enumerate(raw):
        if not isinstance(entry, dict):
            raise ValueError(f"{path}: source entry {idx} is not a mapping")
        out.append(entry)
    return out


def _collect_binary_symbols(
    ctx: MemoryContext,
) -> dict[SymbolCategory, set[str]]:
    try:
        summary = g.symbols.list_symbols_demangled(
            ctx.file_path,
            ctx.budgets.max_read_bytes,
            ctx.budgets.max_file_size,
        )
    except Exception:
        return {"all": set(), "dynamic": set(), "imports": set(), "exports": set()}

    if isinstance(summary, tuple):
        all_syms, dyn_syms, imports, exports, _libs = summary
        return {
            "all": {str(s) for s in all_syms},
            "dynamic": {str(s) for s in dyn_syms},
            "imports": {str(s) for s in imports},
            "exports": {str(s) for s in exports},
        }

    imports = set(_iter_attr_symbols(summary, "import_names"))
    imports.update(_iter_attr_symbols(summary, "demangled_import_names"))
    exports = set(_iter_attr_symbols(summary, "export_names"))
    exports.update(_iter_attr_symbols(summary, "demangled_export_names"))
    dynamic = imports | exports
    all_syms = set(_iter_attr_symbols(summary, "names")) | dynamic
    return {"all": all_syms, "dynamic": dynamic, "imports": imports, "exports": exports}


def _collect_symbol_addresses(ctx: MemoryContext) -> dict[str, int]:
    try:
        symbol_address_map = getattr(g.symbols, "symbol_address_map")
        pairs = symbol_address_map(
            ctx.file_path,
            ctx.budgets.max_read_bytes,
            ctx.budgets.max_file_size,
        )
    except Exception:
        return {}
    out: dict[str, int] = {}
    for va, name in pairs:
        for key in _symbol_keys(str(name)):
            out.setdefault(key, int(va))
    return out


def _symbol_evidence(
    symbol: str,
    inventory: dict[SymbolCategory, set[str]],
) -> list[BinarySymbolEvidence]:
    out: list[BinarySymbolEvidence] = []
    for category in ("exports", "imports", "dynamic", "all"):
        matches = _find_matching_symbols(symbol, inventory[category])
        out.extend(
            BinarySymbolEvidence(name=name, category=category) for name in sorted(matches)
        )
    return out


def _find_matching_symbols(symbol: str, candidates: set[str]) -> set[str]:
    wanted = set(_symbol_keys(symbol))
    matches = set()
    for candidate in candidates:
        if wanted & set(_symbol_keys(candidate)):
            matches.add(candidate)
    return matches


def _lookup_symbol_va(symbol: str, address_map: dict[str, int]) -> int | None:
    for key in _symbol_keys(symbol):
        if key in address_map:
            return address_map[key]
    return None


def _symbol_keys(symbol: str) -> list[str]:
    raw = symbol.strip()
    if not raw:
        return []
    suffix = raw.rsplit("!", 1)[-1].rsplit("::", 1)[-1]
    return [raw.lower(), suffix.lower()]


def _roles(source: dict[str, Any], path: Path) -> list[EntrypointRole]:
    raw_roles = source.get("roles") or []
    if not isinstance(raw_roles, list) or not raw_roles:
        raise ValueError(f"{path}: source {source.get('id')!r} has no roles")
    roles: list[EntrypointRole] = []
    for role in raw_roles:
        if not isinstance(role, dict):
            raise ValueError(f"{path}: role for {source.get('id')!r} is not a mapping")
        roles.append(
            EntrypointRole(
                index=int(role["index"]) if role.get("index") is not None else None,
                expression=str(role["expression"])
                if role.get("expression") is not None
                else None,
                role=_required_str(role, "role", path),
                paired_length=role.get("paired_length"),
                selector=role.get("selector"),
            )
        )
    return roles


def _provenance(present: bool) -> list[str]:
    provenance = ["asb_pe_source_metadata"]
    if present:
        provenance.append("binary_symbol_table")
    return provenance


def _iter_attr_symbols(obj: Any, attr: str) -> list[str]:
    values = getattr(obj, attr, None) or []
    return [str(value) for value in values if str(value)]


def _str_list(raw: Any) -> list[str]:
    if not isinstance(raw, list):
        return []
    return [str(value) for value in raw if str(value)]


def _required_str(entry: dict[str, Any], key: str, path: Path) -> str:
    value = entry.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{path}: missing required string field {key!r}")
    return value


def build_tool() -> MemoryTool[
    WindowsEnumerateEntrypointsArgs, WindowsEnumerateEntrypointsResult
]:
    return WindowsEnumerateEntrypointsTool()
