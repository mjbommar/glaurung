from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from pydantic import BaseModel, Field

import glaurung as g

from ..context import MemoryContext
from ..kb.models import Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


class PeDecodeVersionInfoArgs(BaseModel):
    path: str | None = Field(None, description="Path to the PE file")
    language_id: int | None = Field(
        None, description="Optional VERSIONINFO language ID"
    )
    max_payload_bytes: int = Field(65_536, ge=0)
    add_to_kb: bool = True


class PeVersionInfoResult(BaseModel):
    path: str
    found: bool = False
    evidence: str | None = None
    fixed_file_info: dict[str, int | str] = Field(default_factory=dict)
    file_version: str | None = None
    product_version: str | None = None
    file_flags: int | None = None
    file_os: str | None = None
    file_type: str | None = None
    file_subtype: int | None = None
    strings: dict[str, str] = Field(default_factory=dict)
    translations: list[dict[str, int]] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    stop_reasons: list[str] = Field(default_factory=list)


@dataclass
class _VersionNode:
    key: str
    value_length: int
    value_type: int
    value: bytes
    children: list["_VersionNode"] = field(default_factory=list)


class PeDecodeVersionInfoTool(MemoryTool[PeDecodeVersionInfoArgs, PeVersionInfoResult]):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="pe_decode_version_info",
                description=(
                    "Decode a Windows PE VERSIONINFO resource into fixed file "
                    "version fields, string tables, and translations."
                ),
                tags=("pe", "resource", "version", "windows", "kb"),
            ),
            PeDecodeVersionInfoArgs,
            PeVersionInfoResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: PeDecodeVersionInfoArgs,
    ) -> PeVersionInfoResult:
        path = Path(args.path or ctx.file_path)
        try:
            resource = g.analysis.pe_view_resource_path(
                str(path),
                type_filter="versioninfo",
                language_id=args.language_id,
                max_read_bytes=ctx.budgets.max_read_bytes,
                max_file_size=ctx.budgets.max_file_size,
                max_payload_bytes=args.max_payload_bytes,
            )
        except Exception as exc:
            return PeVersionInfoResult(
                path=str(path),
                warnings=[str(exc)],
                stop_reasons=["input_not_pe_or_unparseable"],
            )
        if resource is None:
            return PeVersionInfoResult(
                path=str(path), stop_reasons=["version_info_not_found"]
            )
        data = resource.get("data")
        if not isinstance(data, bytes):
            return PeVersionInfoResult(
                path=str(path),
                evidence=resource.get("evidence"),
                stop_reasons=["version_info_payload_not_available"],
            )

        result = _decode_version_info(str(path), data)
        result.found = True
        result.evidence = resource.get("evidence")
        result.warnings.extend(resource.get("warnings") or [])
        if args.add_to_kb:
            _add_version_node(kb, path, result)
        return result


def _decode_version_info(path: str, data: bytes) -> PeVersionInfoResult:
    result = PeVersionInfoResult(path=path)
    try:
        root, _ = _parse_version_node(data, 0, len(data))
    except ValueError as exc:
        result.warnings.append(f"version_info_parse_error:{exc}")
        return result

    if root.key != "VS_VERSION_INFO":
        result.warnings.append(f"unexpected_version_root:{root.key}")
    fixed = _decode_fixed_file_info(root.value)
    if fixed:
        result.fixed_file_info = fixed
        result.file_version = _version_string(
            int(fixed["file_version_ms"]), int(fixed["file_version_ls"])
        )
        result.product_version = _version_string(
            int(fixed["product_version_ms"]), int(fixed["product_version_ls"])
        )
        result.file_flags = int(fixed["file_flags"])
        result.file_os = _file_os_label(int(fixed["file_os"]))
        result.file_type = _file_type_label(int(fixed["file_type"]))
        result.file_subtype = int(fixed["file_subtype"])
    else:
        result.warnings.append("missing_or_invalid_fixed_file_info")

    result.strings = _collect_version_strings(root)
    result.translations = _collect_translations(root)
    return result


def _parse_version_node(
    data: bytes, offset: int, limit: int
) -> tuple[_VersionNode, int]:
    if offset + 6 > limit:
        raise ValueError("truncated_node_header")
    length = _u16(data, offset)
    value_length = _u16(data, offset + 2)
    value_type = _u16(data, offset + 4)
    if length < 6:
        raise ValueError("invalid_node_length")
    end = offset + length
    if end > limit or end > len(data):
        raise ValueError("node_length_exceeds_parent")

    cursor = offset + 6
    key_start = cursor
    while cursor + 2 <= end:
        if _u16(data, cursor) == 0:
            break
        cursor += 2
    else:
        raise ValueError("unterminated_key")
    key = data[key_start:cursor].decode("utf-16le", errors="replace")
    cursor += 2
    cursor = _align4_value(cursor)

    value_bytes = value_length * 2 if value_type == 1 else value_length
    value_end = min(cursor + value_bytes, end)
    value = data[cursor:value_end]
    cursor = _align4_value(value_end)

    children: list[_VersionNode] = []
    while cursor + 6 <= end:
        child_length = _u16(data, cursor)
        if child_length == 0:
            break
        child, next_cursor = _parse_version_node(data, cursor, end)
        if next_cursor <= cursor:
            break
        children.append(child)
        cursor = _align4_value(next_cursor)

    return _VersionNode(key, value_length, value_type, value, children), end


def _decode_fixed_file_info(value: bytes) -> dict[str, int] | None:
    if len(value) < 52:
        return None
    fields = [_u32(value, index * 4) for index in range(13)]
    if fields[0] != 0xFEEF04BD:
        return None
    names = [
        "signature",
        "struct_version",
        "file_version_ms",
        "file_version_ls",
        "product_version_ms",
        "product_version_ls",
        "file_flags_mask",
        "file_flags",
        "file_os",
        "file_type",
        "file_subtype",
        "file_date_ms",
        "file_date_ls",
    ]
    return dict(zip(names, fields, strict=True))


def _collect_version_strings(root: _VersionNode) -> dict[str, str]:
    strings: dict[str, str] = {}
    for string_file_info in _children_named(root, "StringFileInfo"):
        for table in string_file_info.children:
            for entry in table.children:
                if entry.value_type != 1:
                    continue
                strings[entry.key] = _decode_utf16_value(entry.value)
    return strings


def _collect_translations(root: _VersionNode) -> list[dict[str, int]]:
    translations: list[dict[str, int]] = []
    for var_file_info in _children_named(root, "VarFileInfo"):
        for entry in _children_named(var_file_info, "Translation"):
            value = entry.value
            for offset in range(0, len(value) - 3, 4):
                translations.append(
                    {
                        "language_id": _u16(value, offset),
                        "code_page": _u16(value, offset + 2),
                    }
                )
    return translations


def _children_named(node: _VersionNode, key: str) -> list[_VersionNode]:
    return [child for child in node.children if child.key == key]


def _decode_utf16_value(value: bytes) -> str:
    text = value.decode("utf-16le", errors="replace")
    return text.rstrip("\0")


def _version_string(ms: int, ls: int) -> str:
    return f"{(ms >> 16) & 0xFFFF}.{ms & 0xFFFF}.{(ls >> 16) & 0xFFFF}.{ls & 0xFFFF}"


def _file_os_label(value: int) -> str:
    labels = {
        0x00010000: "dos",
        0x00040000: "nt",
        0x00040004: "nt_windows32",
    }
    return labels.get(value, f"0x{value:08x}")


def _file_type_label(value: int) -> str:
    labels = {
        0x00000001: "application",
        0x00000002: "dll",
        0x00000003: "driver",
        0x00000004: "font",
        0x00000005: "vxd",
        0x00000007: "static_library",
    }
    return labels.get(value, f"0x{value:08x}")


def _align4_value(value: int) -> int:
    return (value + 3) & ~3


def _u16(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 2], "little")


def _u32(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 4], "little")


def _add_version_node(
    kb: KnowledgeBase,
    path: Path,
    result: PeVersionInfoResult,
) -> None:
    kb.add_node(
        Node(
            kind=NodeKind.pe_resource,
            label=result.evidence or "PE VERSIONINFO",
            props={
                "tool": "pe_decode_version_info",
                "path": str(path),
                **result.model_dump(),
            },
            tags=["pe", "resource", "versioninfo"],
        )
    )


def build_tool() -> MemoryTool[PeDecodeVersionInfoArgs, PeVersionInfoResult]:
    return PeDecodeVersionInfoTool()
