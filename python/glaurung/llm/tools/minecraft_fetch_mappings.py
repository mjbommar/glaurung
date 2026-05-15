from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


DEFAULT_VERSION_MANIFEST_URL = (
    "https://piston-meta.mojang.com/mc/game/version_manifest_v2.json"
)


class MinecraftFetchMappingsArgs(BaseModel):
    version: str | None = Field(
        None,
        description="Minecraft version id, for example 1.20.1",
    )
    side: Literal["client", "server"] | None = Field(
        None, description="Mapping side to fetch from version metadata"
    )
    source: Literal["auto", "mojang"] = "auto"
    manifest_url: str = Field(
        DEFAULT_VERSION_MANIFEST_URL,
        description="Minecraft version manifest URL; override for tests/offline mirrors",
    )
    cache_dir: str | None = Field(
        None,
        description="Cache root; defaults to tmp/glaurung-java-cache",
    )
    refresh: bool = False
    timeout_seconds: float = Field(30.0, gt=0, le=300)


class MinecraftFetchMappingsResult(BaseModel):
    version: str
    side: Literal["client", "server"]
    source: str
    namespace: str
    format: str
    mapping_path: str
    cache_key: str
    download_url: str
    version_metadata_url: str
    from_cache: bool
    advertised_sha1: str | None
    advertised_size: int | None
    sha1: str
    sha256: str
    size: int
    verified_sha1: bool
    verified_size: bool
    class_count: int
    field_count: int
    method_count: int
    mapping_node_id: str | None = None


class MinecraftFetchMappingsTool(
    MemoryTool[MinecraftFetchMappingsArgs, MinecraftFetchMappingsResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="minecraft_fetch_mappings",
                description=(
                    "Fetch and verify Minecraft mapping files from version metadata, "
                    "cache them, index ProGuard-style mapping counts, and annotate the KB."
                ),
                tags=("java", "minecraft", "mapping", "deobfuscation", "kb"),
            ),
            MinecraftFetchMappingsArgs,
            MinecraftFetchMappingsResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: MinecraftFetchMappingsArgs,
    ) -> MinecraftFetchMappingsResult:
        source = "mojang" if args.source == "auto" else args.source
        version = args.version
        side = args.side
        if version is None or side is None:
            return MinecraftFetchMappingsResult(
                version=version or "",
                side=side or "client",
                source=source,
                namespace="mojang_official",
                format="proguard",
                mapping_path="",
                cache_key="",
                download_url="",
                version_metadata_url="",
                from_cache=False,
                advertised_sha1=None,
                advertised_size=None,
                sha1="",
                sha256="",
                size=0,
                verified_sha1=False,
                verified_size=False,
                class_count=0,
                field_count=0,
                method_count=0,
                mapping_node_id=None,
            )

        resolved = _resolve_mojang_mapping(
            version=version,
            side=side,
            manifest_url=args.manifest_url,
            timeout_seconds=args.timeout_seconds,
        )
        cache_root = Path(args.cache_dir or "tmp/glaurung-java-cache")
        mapping_path = _mapping_cache_path(
            cache_root=cache_root,
            source=source,
            version=version,
            side=side,
        )
        from_cache = mapping_path.exists() and not args.refresh
        if not from_cache:
            data = _read_url(resolved.url, args.timeout_seconds)
            mapping_path.parent.mkdir(parents=True, exist_ok=True)
            tmp_path = mapping_path.with_suffix(mapping_path.suffix + ".tmp")
            tmp_path.write_bytes(data)
            tmp_path.replace(mapping_path)

        data = mapping_path.read_bytes()
        size = len(data)
        sha1 = hashlib.sha1(data).hexdigest()
        sha256 = hashlib.sha256(data).hexdigest()
        verified_sha1 = resolved.sha1 is None or sha1 == resolved.sha1
        verified_size = resolved.size is None or size == resolved.size
        if not verified_sha1:
            raise ValueError(
                f"Mapping sha1 mismatch for {args.version} {args.side}: "
                f"expected {resolved.sha1}, got {sha1}"
            )
        if not verified_size:
            raise ValueError(
                f"Mapping size mismatch for {args.version} {args.side}: "
                f"expected {resolved.size}, got {size}"
            )

        counts = _count_proguard_entries(data)
        cache_key = str(mapping_path.relative_to(cache_root))
        text = (
            f"Minecraft mappings fetched: source={source}, version={version}, "
            f"side={side}, format=proguard, classes={counts.class_count}, "
            f"fields={counts.field_count}, methods={counts.method_count}."
        )
        mapping_node = kb.add_node(
            Node(
                kind=NodeKind.java_mapping,
                label=f"{source}:{args.version}:{args.side}",
                text=text,
                props={
                    "tool": "minecraft_fetch_mappings",
                    "version": version,
                    "side": side,
                    "source": source,
                    "namespace": "mojang_official",
                    "format": "proguard",
                    "mapping_path": str(mapping_path),
                    "cache_key": cache_key,
                    "download_url": resolved.url,
                    "version_metadata_url": resolved.version_metadata_url,
                    "sha1": sha1,
                    "sha256": sha256,
                    "size": size,
                    "class_count": counts.class_count,
                    "field_count": counts.field_count,
                    "method_count": counts.method_count,
                },
                tags=["java", "minecraft", "mapping", "deobfuscation"],
            )
        )

        return MinecraftFetchMappingsResult(
            version=version,
            side=side,
            source=source,
            namespace="mojang_official",
            format="proguard",
            mapping_path=str(mapping_path),
            cache_key=cache_key,
            download_url=resolved.url,
            version_metadata_url=resolved.version_metadata_url,
            from_cache=from_cache,
            advertised_sha1=resolved.sha1,
            advertised_size=resolved.size,
            sha1=sha1,
            sha256=sha256,
            size=size,
            verified_sha1=verified_sha1,
            verified_size=verified_size,
            class_count=counts.class_count,
            field_count=counts.field_count,
            method_count=counts.method_count,
            mapping_node_id=mapping_node.id,
        )


@dataclass(frozen=True)
class _ResolvedMapping:
    url: str
    version_metadata_url: str
    sha1: str | None
    size: int | None


@dataclass(frozen=True)
class _MappingCounts:
    class_count: int
    field_count: int
    method_count: int


def _resolve_mojang_mapping(
    *,
    version: str,
    side: Literal["client", "server"],
    manifest_url: str,
    timeout_seconds: float,
) -> _ResolvedMapping:
    manifest = _read_json_url(manifest_url, timeout_seconds)
    versions = manifest.get("versions")
    if not isinstance(versions, list):
        raise ValueError("Minecraft version manifest does not contain a versions list")

    version_metadata_url: str | None = None
    for entry in versions:
        if isinstance(entry, dict) and entry.get("id") == version:
            url = entry.get("url")
            if isinstance(url, str):
                version_metadata_url = url
            break
    if version_metadata_url is None:
        raise ValueError(f"Minecraft version {version!r} not found in manifest")

    version_metadata = _read_json_url(version_metadata_url, timeout_seconds)
    downloads = version_metadata.get("downloads")
    if not isinstance(downloads, dict):
        raise ValueError(f"Minecraft version {version!r} metadata has no downloads")
    key = f"{side}_mappings"
    item = downloads.get(key)
    if not isinstance(item, dict):
        raise ValueError(
            f"Minecraft version {version!r} metadata has no {key!r} download"
        )
    url = item.get("url")
    if not isinstance(url, str):
        raise ValueError(f"Minecraft version {version!r} {key!r} download has no URL")
    sha1 = item.get("sha1")
    size = item.get("size")
    return _ResolvedMapping(
        url=url,
        version_metadata_url=version_metadata_url,
        sha1=sha1 if isinstance(sha1, str) else None,
        size=size if isinstance(size, int) else None,
    )


def _read_json_url(url: str, timeout_seconds: float) -> dict[str, Any]:
    data = _read_url(url, timeout_seconds)
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise ValueError(f"Unable to parse JSON from {url}") from e
    if not isinstance(value, dict):
        raise ValueError(f"JSON payload from {url} is not an object")
    return value


def _read_url(url: str, timeout_seconds: float) -> bytes:
    parsed = urlparse(url)
    request: str | Request
    if parsed.scheme in {"http", "https"}:
        request = Request(url, headers={"User-Agent": "glaurung/0"})
    else:
        request = url
    with urlopen(request, timeout=timeout_seconds) as response:
        return response.read()


def _mapping_cache_path(
    *,
    cache_root: Path,
    source: str,
    version: str,
    side: str,
) -> Path:
    return (
        cache_root
        / "minecraft"
        / "mappings"
        / _safe_component(source)
        / _safe_component(version)
        / f"{_safe_component(side)}.txt"
    )


def _safe_component(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in value)


def _count_proguard_entries(data: bytes) -> _MappingCounts:
    class_count = 0
    field_count = 0
    method_count = 0
    text = data.decode("utf-8", errors="replace")
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line[0].isspace():
            if " -> " not in line:
                continue
            lhs = line.rsplit(" -> ", 1)[0].strip()
            if "(" in lhs and ")" in lhs:
                method_count += 1
            else:
                field_count += 1
        elif " -> " in line and line.rstrip().endswith(":"):
            class_count += 1
    return _MappingCounts(
        class_count=class_count,
        field_count=field_count,
        method_count=method_count,
    )


def build_tool() -> MemoryTool[
    MinecraftFetchMappingsArgs, MinecraftFetchMappingsResult
]:
    return MinecraftFetchMappingsTool()
