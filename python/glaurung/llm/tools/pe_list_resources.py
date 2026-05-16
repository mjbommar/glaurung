from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, Field

import glaurung as g

from ..context import MemoryContext
from ..kb.models import Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


class PeListResourcesArgs(BaseModel):
    path: str | None = Field(None, description="Path to the PE file")
    type_filter: str | None = Field(
        None, description="Optional resource type name or numeric ID filter"
    )
    name_filter: str | None = Field(
        None, description="Optional resource name or numeric ID filter"
    )
    language_id: int | None = Field(None, description="Optional language ID filter")
    min_size: int | None = Field(None, ge=0)
    max_size: int | None = Field(None, ge=0)
    limit: int = Field(256, ge=0)
    max_resources_scan: int = Field(4096, ge=0)
    max_resource_depth: int = Field(32, ge=0)
    max_resource_data_bytes: int = Field(1_048_576, ge=0)
    preview_bytes: int = Field(16, ge=0, le=256)
    add_to_kb: bool = True


class PeResourceSummary(BaseModel):
    resource_type: str
    type_id: int | None = None
    type_name: str | None = None
    name_id: int | None = None
    name: str | None = None
    language_id: int | None = None
    code_page: int
    data_rva: int
    data_offset: int
    size: int
    section_name: str | None = None
    entropy: float
    sha256: str
    magic: str
    preview_hex: str
    warnings: list[str] = Field(default_factory=list)
    evidence: str


class PeListResourcesResult(BaseModel):
    path: str
    leaf_count: int = 0
    matched_resource_count: int = 0
    total_directories: int = 0
    max_depth: int = 0
    resource_bytes_total: int = 0
    resources_by_type: dict[str, int] = Field(default_factory=dict)
    resources: list[PeResourceSummary] = Field(default_factory=list)
    truncated: bool = False
    warnings: list[str] = Field(default_factory=list)
    stop_reasons: list[str] = Field(default_factory=list)


class PeListResourcesTool(MemoryTool[PeListResourcesArgs, PeListResourcesResult]):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="pe_list_resources",
                description=(
                    "List Windows PE resources with type/name/language anchors, "
                    "offsets, hashes, entropy, magic classification, previews, "
                    "filters, budgets, and KB evidence nodes."
                ),
                tags=("pe", "resource", "windows", "kb"),
            ),
            PeListResourcesArgs,
            PeListResourcesResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: PeListResourcesArgs,
    ) -> PeListResourcesResult:
        path = Path(args.path or ctx.file_path)
        try:
            raw = g.analysis.pe_list_resources_path(
                str(path),
                ctx.budgets.max_read_bytes,
                ctx.budgets.max_file_size,
                args.max_resources_scan,
                args.max_resource_depth,
                args.max_resource_data_bytes,
                args.preview_bytes,
            )
        except Exception as exc:
            return PeListResourcesResult(
                path=str(path),
                warnings=[str(exc)],
                stop_reasons=["input_not_pe_or_unparseable"],
            )

        result = PeListResourcesResult(
            path=str(path),
            leaf_count=int(raw.get("leaf_count", 0)),
            total_directories=int(raw.get("total_directories", 0)),
            max_depth=int(raw.get("max_depth", 0)),
            resource_bytes_total=int(raw.get("resource_bytes_total", 0)),
            resources_by_type=dict(raw.get("resources_by_type", {})),
            truncated=bool(raw.get("truncated", False)),
            warnings=list(raw.get("warnings", [])),
            stop_reasons=list(raw.get("stop_reasons", [])),
        )

        for item in raw.get("resources", []):
            if not _matches(item, args):
                continue
            if len(result.resources) >= args.limit:
                result.truncated = True
                result.stop_reasons.append("limit")
                break
            summary = _summary_from_native(item)
            result.resources.append(summary)
            result.matched_resource_count += 1
            if args.add_to_kb:
                _add_resource_node(kb, path, summary)

        result.stop_reasons = list(dict.fromkeys(result.stop_reasons))
        return result


def _matches(item: dict, args: PeListResourcesArgs) -> bool:
    if args.type_filter is not None:
        wanted = args.type_filter.strip().lower()
        type_values = {
            str(item.get("type_id") or "").lower(),
            str(item.get("type_name") or "").lower(),
            str(item.get("type") or "").lower(),
        }
        if wanted not in type_values:
            return False
    if args.name_filter is not None:
        wanted = args.name_filter.strip().lower()
        name_values = {
            str(item.get("name_id") or "").lower(),
            str(item.get("name") or "").lower(),
        }
        if wanted not in name_values:
            return False
    if args.language_id is not None and item.get("language_id") != args.language_id:
        return False
    size = int(item.get("size") or 0)
    if args.min_size is not None and size < args.min_size:
        return False
    return not (args.max_size is not None and size > args.max_size)


def _summary_from_native(item: dict) -> PeResourceSummary:
    resource_type = str(item.get("type") or item.get("type_name") or "unknown")
    name_id = item.get("name_id")
    name = item.get("name")
    language_id = item.get("language_id")
    evidence = _evidence_label(
        resource_type,
        int(name_id) if isinstance(name_id, int) else name,
        int(language_id) if isinstance(language_id, int) else None,
        item.get("section_name"),
        int(item.get("data_offset") or 0),
    )
    return PeResourceSummary(
        resource_type=resource_type,
        type_id=item.get("type_id"),
        type_name=item.get("type_name"),
        name_id=name_id,
        name=name,
        language_id=language_id,
        code_page=int(item.get("code_page") or 0),
        data_rva=int(item.get("data_rva") or 0),
        data_offset=int(item.get("data_offset") or 0),
        size=int(item.get("size") or 0),
        section_name=item.get("section_name"),
        entropy=float(item.get("entropy") or 0.0),
        sha256=str(item.get("sha256") or ""),
        magic=str(item.get("magic") or "unknown"),
        preview_hex=str(item.get("preview_hex") or ""),
        warnings=list(item.get("warnings") or []),
        evidence=evidence,
    )


def _evidence_label(
    resource_type: str,
    name: int | str | None,
    language_id: int | None,
    section_name: str | None,
    data_offset: int,
) -> str:
    name_text = str(name) if name is not None else "unknown"
    language_text = f"0x{language_id:04x}" if language_id is not None else "unknown"
    section_text = section_name or "unknown"
    return f"{resource_type}/{name_text}/{language_text} @ {section_text}:0x{data_offset:x}"


def _add_resource_node(
    kb: KnowledgeBase,
    path: Path,
    resource: PeResourceSummary,
) -> None:
    kb.add_node(
        Node(
            kind=NodeKind.pe_resource,
            label=resource.evidence,
            props={
                "tool": "pe_list_resources",
                "path": str(path),
                **resource.model_dump(),
            },
            tags=["pe", "resource", resource.resource_type.lower(), resource.magic],
        )
    )


def build_tool() -> MemoryTool[PeListResourcesArgs, PeListResourcesResult]:
    return PeListResourcesTool()
