from __future__ import annotations

from pydantic import BaseModel, Field

import glaurung as g

from ..context import MemoryContext
from ..kb import xref_db
from ..kb.models import Node, NodeKind, Edge
from ..kb.persistent import PersistentKnowledgeBase
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


class PeIatMapArgs(BaseModel):
    add_to_kb: bool = True
    enrich: bool = True
    include_symbol_imports_if_iat_empty: bool = True


class PrototypeParam(BaseModel):
    name: str
    c_type: str
    role: str | None = None


class IatEntry(BaseModel):
    va: int | None = None
    name: str
    module: str | None = None
    prototype: str | None = None
    return_type: str | None = None
    params: list[PrototypeParam] = Field(default_factory=list)
    calling_convention: str | None = None
    source: str | None = None
    source_kind: str | None = None
    source_package: str | None = None
    source_version: str | None = None
    confidence: float | None = None
    api_class: str | None = None
    risk_tags: list[str] = Field(default_factory=list)
    param_roles: dict[str, str] = Field(default_factory=dict)
    import_source: str = "iat"


class PeIatMapResult(BaseModel):
    entries: list[IatEntry]
    evidence_node_id: str | None = None


class PeIatMapTool(MemoryTool[PeIatMapArgs, PeIatMapResult]):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="map_pe_iat",
                description="Extract PE IAT map and optionally import into KB.",
                tags=("symbols", "pe", "kb"),
            ),
            PeIatMapArgs,
            PeIatMapResult,
        )

    def run(
        self, ctx: MemoryContext, kb: KnowledgeBase, args: PeIatMapArgs
    ) -> PeIatMapResult:
        entries: list[IatEntry] = []
        ev_id = None
        prototype_catalog = (
            _prototype_catalog_for_path(ctx.file_path) if args.enrich else {}
        )
        try:
            pe_iat_map_path = getattr(g, "analysis").pe_iat_map_path
            pairs = pe_iat_map_path(
                ctx.file_path, ctx.budgets.max_read_bytes, ctx.budgets.max_file_size
            )
            for va, name in pairs:
                entries.append(
                    _enriched_entry(
                        name=str(name),
                        va=int(va),
                        prototype_catalog=prototype_catalog,
                        import_source="iat",
                    )
                )
        except Exception:
            entries = []
        if not entries and args.include_symbol_imports_if_iat_empty:
            for name in _symbol_import_names(ctx):
                entries.append(
                    _enriched_entry(
                        name=name,
                        va=None,
                        prototype_catalog=prototype_catalog,
                        import_source="symbol_import",
                    )
                )
        if args.add_to_kb and entries:
            ev = kb.add_node(Node(kind=NodeKind.evidence, label="map_pe_iat"))
            ev_id = ev.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=ev.id, kind="has_evidence"))
            for e in entries:
                n = kb.add_node(
                    Node(
                        kind=NodeKind.import_sym,
                        label=e.name,
                        props=e.model_dump(exclude_none=True),
                    )
                )
                kb.add_edge(Edge(src=ev.id, dst=n.id, kind="iat_entry"))
        return PeIatMapResult(entries=entries, evidence_node_id=ev_id)


def _prototype_catalog_for_path(path: str) -> dict[str, xref_db.FunctionPrototype]:
    bundles = PersistentKnowledgeBase.stdlib_bundles_for_binary(path)[
        "prototype_bundles"
    ]
    return xref_db.load_stdlib_prototype_catalog(bundles=bundles)


def _symbol_import_names(ctx: MemoryContext) -> list[str]:
    try:
        list_symbols_demangled = getattr(g.symbols, "list_symbols_demangled")
        summary = list_symbols_demangled(
            ctx.file_path,
            ctx.budgets.max_read_bytes,
            ctx.budgets.max_file_size,
        )
    except Exception:
        return []
    out: list[str] = []
    for name in list(summary.import_names or []) + list(
        summary.demangled_import_names or []
    ):
        clean = _clean_import_name(str(name))
        if clean and clean not in out:
            out.append(clean)
    return out


def _clean_import_name(name: str) -> str:
    clean = name.strip()
    if clean.startswith("__imp_"):
        clean = clean[6:]
    if "@" in clean and not clean.endswith("@plt"):
        clean = clean.split("@", 1)[0]
    if clean.endswith("@plt"):
        clean = clean[:-4]
    return clean


def _enriched_entry(
    *,
    name: str,
    va: int | None,
    prototype_catalog: dict[str, xref_db.FunctionPrototype],
    import_source: str,
) -> IatEntry:
    clean = _clean_import_name(name)
    proto = prototype_catalog.get(clean) or prototype_catalog.get(name)
    if proto is None:
        return IatEntry(va=va, name=clean or name, import_source=import_source)
    param_roles = {
        param.name: param.role for param in proto.params if param.role is not None
    }
    return IatEntry(
        va=va,
        name=clean or name,
        module=proto.module,
        prototype=proto.render(),
        return_type=proto.return_type,
        params=[
            PrototypeParam(name=p.name, c_type=p.c_type, role=p.role)
            for p in proto.params
        ],
        calling_convention=proto.calling_convention,
        source=proto.source,
        source_kind=proto.source_kind,
        source_package=proto.source_package,
        source_version=proto.source_version,
        confidence=proto.confidence,
        api_class=proto.semantics.get("api_class") if proto.semantics else None,
        risk_tags=proto.risk_tags,
        param_roles=param_roles,
        import_source=import_source,
    )


def build_tool() -> MemoryTool[PeIatMapArgs, PeIatMapResult]:
    return PeIatMapTool()
