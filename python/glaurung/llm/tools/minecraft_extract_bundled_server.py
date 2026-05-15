from __future__ import annotations

import hashlib
import io
import zipfile
from pathlib import Path

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


class MinecraftExtractBundledServerArgs(BaseModel):
    path: str | None = Field(None, description="Path to a Minecraft server bundler JAR")
    out_dir: str | None = Field(
        None,
        description="Output/cache directory; defaults to tmp/glaurung-java-cache",
    )
    version: str | None = Field(None, description="Preferred Minecraft version entry")
    refresh: bool = False


class MinecraftExtractBundledServerResult(BaseModel):
    outer_path: str
    nested_entry: str
    extracted_path: str
    from_cache: bool
    sha256: str
    size: int
    class_count: int
    resource_count: int
    archive_node_id: str | None = None


class MinecraftExtractBundledServerTool(
    MemoryTool[
        MinecraftExtractBundledServerArgs,
        MinecraftExtractBundledServerResult,
    ]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="minecraft_extract_bundled_server",
                description=(
                    "Extract the nested gameplay server JAR from a vanilla "
                    "Minecraft bundler server JAR and annotate it for Java analysis."
                ),
                tags=("java", "minecraft", "server", "jar", "kb"),
            ),
            MinecraftExtractBundledServerArgs,
            MinecraftExtractBundledServerResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: MinecraftExtractBundledServerArgs,
    ) -> MinecraftExtractBundledServerResult:
        outer_path = Path(args.path or ctx.file_path)
        outer_digest = _sha256_file(outer_path)
        if not zipfile.is_zipfile(outer_path):
            return MinecraftExtractBundledServerResult(
                outer_path=str(outer_path),
                nested_entry="",
                extracted_path="",
                from_cache=False,
                sha256=outer_digest,
                size=outer_path.stat().st_size,
                class_count=0,
                resource_count=0,
                archive_node_id=None,
            )

        with zipfile.ZipFile(outer_path) as zf:
            nested_entry = _select_server_entry(zf.namelist(), args.version)
            data = zf.read(nested_entry)

        inner_sha256 = hashlib.sha256(data).hexdigest()
        out_root = Path(args.out_dir or "tmp/glaurung-java-cache")
        extracted_path = (
            out_root
            / "minecraft"
            / "bundles"
            / outer_digest[:16]
            / Path(nested_entry).name
        )
        from_cache = (
            extracted_path.exists()
            and not args.refresh
            and _sha256_file(extracted_path) == inner_sha256
        )
        if not from_cache:
            extracted_path.parent.mkdir(parents=True, exist_ok=True)
            tmp_path = extracted_path.with_suffix(extracted_path.suffix + ".tmp")
            tmp_path.write_bytes(data)
            tmp_path.replace(extracted_path)

        class_count, resource_count = _count_inner_entries(data)
        archive_node = kb.add_node(
            Node(
                kind=NodeKind.java_archive,
                label=extracted_path.name,
                text=(
                    "Extracted nested Minecraft server gameplay JAR "
                    f"from {outer_path.name}."
                ),
                props={
                    "tool": "minecraft_extract_bundled_server",
                    "outer_path": str(outer_path),
                    "nested_entry": nested_entry,
                    "path": str(extracted_path),
                    "sha256": inner_sha256,
                    "size": len(data),
                    "class_count": class_count,
                    "resource_count": resource_count,
                },
                tags=["java", "minecraft", "server", "bundled-server"],
            )
        )
        return MinecraftExtractBundledServerResult(
            outer_path=str(outer_path),
            nested_entry=nested_entry,
            extracted_path=str(extracted_path),
            from_cache=from_cache,
            sha256=inner_sha256,
            size=len(data),
            class_count=class_count,
            resource_count=resource_count,
            archive_node_id=archive_node.id,
        )


def _select_server_entry(names: list[str], version: str | None) -> str:
    candidates = [
        name
        for name in names
        if name.startswith("META-INF/versions/")
        and name.endswith(".jar")
        and Path(name).name.startswith("server-")
    ]
    if version:
        version_matches = [
            name
            for name in candidates
            if name.startswith(f"META-INF/versions/{version}/")
        ]
        if version_matches:
            return sorted(version_matches)[0]
    if not candidates:
        raise ValueError("No bundled server JAR found under META-INF/versions/")
    return sorted(candidates)[0]


def _count_inner_entries(data: bytes) -> tuple[int, int]:
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        class_count = 0
        resource_count = 0
        for info in zf.infolist():
            if info.is_dir():
                continue
            if info.filename.endswith(".class"):
                class_count += 1
            else:
                resource_count += 1
    return class_count, resource_count


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


def build_tool() -> MemoryTool[
    MinecraftExtractBundledServerArgs,
    MinecraftExtractBundledServerResult,
]:
    return MinecraftExtractBundledServerTool()
