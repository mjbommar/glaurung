from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


class JavaListResourcesArgs(BaseModel):
    path: str | None = Field(None, description="Path to the JAR/ZIP archive")
    prefix: str | None = Field(None, description="Optional archive path prefix")
    extension: str | None = Field(None, description="Optional extension filter")
    name_filter: str | None = Field(None, description="Optional substring filter")
    include_classes: bool = False
    max_entries_scan: int = Field(100_000, ge=1)
    limit: int = Field(512, ge=0)
    magic_read_bytes: int = Field(64, ge=0, le=4096)


class JavaResourceSummary(BaseModel):
    entry_name: str
    directory: str
    file_name: str
    extension: str
    size: int
    compressed_size: int
    compression: str
    crc32: str
    sha256: str | None = None
    magic: str
    is_class: bool = False
    is_manifest: bool = False
    is_service_descriptor: bool = False
    is_signature_file: bool = False
    is_multi_release: bool = False
    magic_extension_mismatch: bool = False


class JavaListResourcesResult(BaseModel):
    archive_path: str
    entry_count_scanned: int = 0
    matched_resource_count: int = 0
    resources: list[JavaResourceSummary] = Field(default_factory=list)
    truncated: bool = False
    stop_reasons: list[str] = Field(default_factory=list)


class JavaListResourcesTool(MemoryTool[JavaListResourcesArgs, JavaListResourcesResult]):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="java_list_resources",
                description=(
                    "List JAR/ZIP resources with size, compression, magic-byte "
                    "classification, Java metadata flags, and KB evidence."
                ),
                tags=("java", "jar", "resource", "kb"),
            ),
            JavaListResourcesArgs,
            JavaListResourcesResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: JavaListResourcesArgs,
    ) -> JavaListResourcesResult:
        archive_path = Path(args.path or ctx.file_path)
        if not zipfile.is_zipfile(archive_path):
            return JavaListResourcesResult(
                archive_path=str(archive_path),
                stop_reasons=["input_not_zip"],
            )

        result = JavaListResourcesResult(archive_path=str(archive_path))
        with zipfile.ZipFile(archive_path) as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                result.entry_count_scanned += 1
                if result.entry_count_scanned > args.max_entries_scan:
                    result.truncated = True
                    result.stop_reasons.append("max_entries_scan")
                    break
                if not args.include_classes and info.filename.endswith(".class"):
                    continue
                if not _matches(info.filename, args):
                    continue
                if len(result.resources) >= args.limit:
                    result.truncated = True
                    result.stop_reasons.append("limit")
                    break
                data = zf.read(info)
                sample = data[: args.magic_read_bytes]
                summary = _resource_summary(info, data, sample)
                result.resources.append(summary)
                result.matched_resource_count += 1
                _add_resource_node(kb, archive_path, summary)
        result.stop_reasons = list(dict.fromkeys(result.stop_reasons))
        return result


def _matches(entry_name: str, args: JavaListResourcesArgs) -> bool:
    if args.prefix and not entry_name.startswith(args.prefix):
        return False
    if args.extension:
        ext = args.extension if args.extension.startswith(".") else f".{args.extension}"
        if not entry_name.lower().endswith(ext.lower()):
            return False
    return not (args.name_filter and args.name_filter not in entry_name)


def _resource_summary(
    info: zipfile.ZipInfo,
    data: bytes,
    sample: bytes,
) -> JavaResourceSummary:
    entry_name = info.filename
    directory, _, file_name = entry_name.rpartition("/")
    extension = _extension(file_name)
    magic = _classify_magic(sample)
    return JavaResourceSummary(
        entry_name=entry_name,
        directory=directory,
        file_name=file_name,
        extension=extension,
        size=info.file_size,
        compressed_size=info.compress_size,
        compression=_compression_name(info.compress_type),
        crc32=f"{info.CRC:08x}",
        sha256=hashlib.sha256(data).hexdigest(),
        magic=magic,
        is_class=entry_name.endswith(".class") or magic == "java_class",
        is_manifest=entry_name.upper() == "META-INF/MANIFEST.MF",
        is_service_descriptor=entry_name.startswith("META-INF/services/"),
        is_signature_file=_is_signature_file(entry_name),
        is_multi_release=entry_name.startswith("META-INF/versions/"),
        magic_extension_mismatch=_magic_extension_mismatch(extension, magic),
    )


def _classify_magic(data: bytes) -> str:
    stripped = data.lstrip()
    if data.startswith(b"\xca\xfe\xba\xbe"):
        return "java_class"
    if data.startswith(b"PK\x03\x04"):
        return "zip"
    if data.startswith(b"\x1f\x8b"):
        return "gzip"
    if (
        data.startswith(b"\x78\x01")
        or data.startswith(b"\x78\x9c")
        or data.startswith(b"\x78\xda")
    ):
        return "zlib"
    if data.startswith(b"\x7fELF"):
        return "elf"
    if data.startswith(b"MZ"):
        return "pe"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if data.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if data.startswith(b"GIF87a") or data.startswith(b"GIF89a"):
        return "gif"
    if stripped.startswith(b"{") or stripped.startswith(b"["):
        return "json_like"
    if stripped.startswith(b"<"):
        return "xml_like"
    if _looks_text(stripped):
        return "text"
    return "binary" if data else "empty"


def _looks_text(data: bytes) -> bool:
    if not data:
        return False
    printable = sum(1 for byte in data if byte in {9, 10, 13} or 32 <= byte <= 126)
    return printable / len(data) >= 0.85


def _extension(file_name: str) -> str:
    suffix = Path(file_name).suffix.lower()
    return suffix[1:] if suffix.startswith(".") else suffix


def _compression_name(value: int) -> str:
    if value == zipfile.ZIP_STORED:
        return "stored"
    if value == zipfile.ZIP_DEFLATED:
        return "deflated"
    if value == zipfile.ZIP_BZIP2:
        return "bzip2"
    if value == zipfile.ZIP_LZMA:
        return "lzma"
    return f"zip_method_{value}"


def _is_signature_file(entry_name: str) -> bool:
    upper = entry_name.upper()
    return upper.startswith("META-INF/") and upper.endswith(
        (".SF", ".RSA", ".DSA", ".EC")
    )


def _magic_extension_mismatch(extension: str, magic: str) -> bool:
    expected = {
        "class": "java_class",
        "jar": "zip",
        "zip": "zip",
        "gz": "gzip",
        "png": "png",
        "jpg": "jpeg",
        "jpeg": "jpeg",
        "gif": "gif",
        "json": "json_like",
        "xml": "xml_like",
    }
    return extension in expected and expected[extension] != magic


def _add_resource_node(
    kb: KnowledgeBase,
    archive_path: Path,
    resource: JavaResourceSummary,
) -> None:
    kb.add_node(
        Node(
            kind=NodeKind.java_resource,
            label=resource.entry_name,
            props={
                "tool": "java_list_resources",
                "archive_path": str(archive_path),
                **resource.model_dump(),
            },
            tags=["java", "resource", resource.magic],
        )
    )


def build_tool() -> MemoryTool[JavaListResourcesArgs, JavaListResourcesResult]:
    return JavaListResourcesTool()
