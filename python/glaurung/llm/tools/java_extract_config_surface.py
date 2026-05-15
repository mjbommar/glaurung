from __future__ import annotations

import hashlib
import json
import re
import tomllib
import zipfile
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


class JavaExtractConfigSurfaceArgs(BaseModel):
    path: str | None = Field(None, description="Path to the JAR/ZIP archive")
    config_roots: list[str] = Field(default_factory=list)
    include_embedded_resources: bool = True
    include_manifests: bool = True
    include_service_descriptors: bool = True
    max_config_files: int = Field(2_000, ge=0)
    max_value_chars: int = Field(512, ge=0)


class JavaConfigBinding(BaseModel):
    path: str
    key: str
    value: str | None
    value_kind: str
    redacted_value_hash: str | None = None
    source_type: str
    parser: str


class JavaExtractConfigSurfaceResult(BaseModel):
    archive_path: str
    config_roots: list[str]
    scanned_file_count: int
    binding_count: int
    bindings: list[JavaConfigBinding]
    truncated: bool = False


class JavaExtractConfigSurfaceTool(
    MemoryTool[JavaExtractConfigSurfaceArgs, JavaExtractConfigSurfaceResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="java_extract_config_surface",
                description=(
                    "Extract Java archive config and metadata surface from manifests, "
                    "ServiceLoader descriptors, properties, JSON, TOML, XML, and "
                    "caller-supplied config roots with secret redaction."
                ),
                tags=("java", "jar", "config", "resource", "kb"),
            ),
            JavaExtractConfigSurfaceArgs,
            JavaExtractConfigSurfaceResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: JavaExtractConfigSurfaceArgs,
    ) -> JavaExtractConfigSurfaceResult:
        path = Path(args.path or ctx.file_path)
        bindings: list[JavaConfigBinding] = []
        scanned_file_count = 0
        truncated = False

        if not zipfile.is_zipfile(path):
            return JavaExtractConfigSurfaceResult(
                archive_path=str(path),
                config_roots=args.config_roots,
                scanned_file_count=0,
                binding_count=0,
                bindings=[],
                truncated=False,
            )

        with zipfile.ZipFile(path) as zf:
            if args.include_manifests:
                scanned_file_count += _append_manifest_bindings(
                    bindings, zf, args.max_value_chars
                )
            if args.include_service_descriptors:
                scanned_file_count += _append_service_bindings(
                    bindings, zf, args.max_value_chars
                )
            if args.include_embedded_resources:
                for info in zf.infolist():
                    if info.is_dir() or not _looks_like_config_path(info.filename):
                        continue
                    if scanned_file_count >= args.max_config_files:
                        truncated = True
                        break
                    scanned_file_count += 1
                    raw = zf.read(info)
                    bindings.extend(
                        _parse_config_bytes(
                            path_label=info.filename,
                            raw=raw,
                            source_type="embedded_resource",
                            max_value_chars=args.max_value_chars,
                        )
                    )

        for root_text in args.config_roots:
            root = Path(root_text)
            if not root.exists():
                continue
            files = (
                [root]
                if root.is_file()
                else [p for p in root.rglob("*") if p.is_file()]
            )
            for file_path in files:
                if not _looks_like_config_path(file_path.name):
                    continue
                if scanned_file_count >= args.max_config_files:
                    truncated = True
                    break
                scanned_file_count += 1
                bindings.extend(
                    _parse_config_bytes(
                        path_label=str(file_path),
                        raw=file_path.read_bytes(),
                        source_type="external_config",
                        max_value_chars=args.max_value_chars,
                    )
                )

        for binding in bindings:
            _add_config_node(kb, path, binding)

        return JavaExtractConfigSurfaceResult(
            archive_path=str(path),
            config_roots=args.config_roots,
            scanned_file_count=scanned_file_count,
            binding_count=len(bindings),
            bindings=bindings,
            truncated=truncated,
        )


def _append_manifest_bindings(
    bindings: list[JavaConfigBinding],
    zf: zipfile.ZipFile,
    max_value_chars: int,
) -> int:
    try:
        raw = zf.read("META-INF/MANIFEST.MF")
    except KeyError:
        return 0
    attrs = _parse_manifest(raw.decode("utf-8", errors="replace"))
    for key, value in attrs.items():
        bindings.append(
            _binding(
                path="META-INF/MANIFEST.MF",
                key=key,
                value=value,
                source_type="manifest",
                parser="manifest",
                max_value_chars=max_value_chars,
            )
        )
    return 1


def _append_service_bindings(
    bindings: list[JavaConfigBinding],
    zf: zipfile.ZipFile,
    max_value_chars: int,
) -> int:
    count = 0
    for info in zf.infolist():
        if info.is_dir() or not info.filename.startswith("META-INF/services/"):
            continue
        count += 1
        service_name = info.filename.removeprefix("META-INF/services/")
        providers = [
            line.split("#", 1)[0].strip()
            for line in zf.read(info).decode("utf-8", errors="replace").splitlines()
        ]
        providers = [provider for provider in providers if provider]
        bindings.append(
            _binding(
                path=info.filename,
                key=f"service:{service_name}",
                value=",".join(providers),
                source_type="service_descriptor",
                parser="serviceloader",
                max_value_chars=max_value_chars,
            )
        )
    return count


def _parse_config_bytes(
    *,
    path_label: str,
    raw: bytes,
    source_type: str,
    max_value_chars: int,
) -> list[JavaConfigBinding]:
    suffix = Path(path_label).suffix.lower()
    text = raw.decode("utf-8", errors="replace")
    if suffix in {".properties", ".props"}:
        pairs = _parse_properties(text)
        parser = "properties"
    elif suffix == ".json" or path_label.endswith(".mod.json"):
        pairs = _flatten_mapping(_parse_json(text))
        parser = "json"
    elif suffix == ".toml":
        pairs = _flatten_mapping(_parse_toml(text))
        parser = "toml"
    elif suffix == ".xml":
        pairs = _parse_xml_shallow(text)
        parser = "xml"
    else:
        pairs = {}
        parser = "unknown"
    return [
        _binding(
            path=path_label,
            key=key,
            value=value,
            source_type=source_type,
            parser=parser,
            max_value_chars=max_value_chars,
        )
        for key, value in pairs.items()
    ]


def _parse_manifest(text: str) -> dict[str, str]:
    lines: list[str] = []
    for raw_line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        if raw_line.startswith(" ") and lines:
            lines[-1] += raw_line[1:]
        elif raw_line:
            lines.append(raw_line)
    attrs: dict[str, str] = {}
    for line in lines:
        key, sep, value = line.partition(":")
        if sep:
            attrs[key] = value.strip()
    return attrs


def _parse_properties(text: str) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", "!")):
            continue
        key, sep, value = line.partition("=")
        if not sep:
            key, sep, value = line.partition(":")
        if sep:
            out[key.strip()] = value.strip()
    return out


def _parse_json(text: str) -> Any:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {}


def _parse_toml(text: str) -> Any:
    try:
        return tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return {}


def _flatten_mapping(value: Any, prefix: str = "") -> dict[str, Any]:
    out: dict[str, Any] = {}
    if isinstance(value, dict):
        for key, item in value.items():
            child_key = f"{prefix}.{key}" if prefix else str(key)
            out.update(_flatten_mapping(item, child_key))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            child_key = f"{prefix}[{index}]"
            out.update(_flatten_mapping(item, child_key))
    elif prefix:
        out[prefix] = value
    return out


def _parse_xml_shallow(text: str) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for match in re.finditer(r"<([A-Za-z_][\w.-]*)>([^<>]+)</\1>", text):
        out[match.group(1)] = match.group(2).strip()
    return out


def _binding(
    *,
    path: str,
    key: str,
    value: Any,
    source_type: str,
    parser: str,
    max_value_chars: int,
) -> JavaConfigBinding:
    value_text = _value_to_text(value)
    if _should_redact(key, value_text):
        return JavaConfigBinding(
            path=path,
            key=key,
            value=None,
            value_kind="redacted",
            redacted_value_hash=hashlib.sha256(value_text.encode("utf-8")).hexdigest(),
            source_type=source_type,
            parser=parser,
        )
    if len(value_text) > max_value_chars:
        value_text = value_text[:max_value_chars]
        value_kind = "truncated"
    else:
        value_kind = _value_kind(value)
    return JavaConfigBinding(
        path=path,
        key=key,
        value=value_text,
        value_kind=value_kind,
        source_type=source_type,
        parser=parser,
    )


def _value_to_text(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "null"
    return str(value)


def _value_kind(value: Any) -> str:
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, int | float):
        return "number"
    if value is None:
        return "null"
    return "string"


def _should_redact(key: str, value: str) -> bool:
    lowered = key.lower()
    if any(word in lowered for word in ("digest", "checksum", "hash", "signature")):
        return False
    if any(
        word in lowered for word in ("token", "secret", "password", "passwd", "api_key")
    ):
        return True
    return value.startswith(
        ("AKIA", "ghp_", "github_pat_", "sk-", "xoxb-", "xoxp-", "AIza")
    )


def _looks_like_config_path(path: str) -> bool:
    lowered = path.lower()
    return lowered.endswith(
        (
            ".properties",
            ".props",
            ".json",
            ".toml",
            ".xml",
        )
    )


def _add_config_node(
    kb: KnowledgeBase,
    archive_path: Path,
    binding: JavaConfigBinding,
) -> None:
    kb.add_node(
        Node(
            kind=NodeKind.java_config_key,
            label=f"{binding.path}:{binding.key}",
            props={
                "tool": "java_extract_config_surface",
                "archive_path": str(archive_path),
                **binding.model_dump(),
            },
            tags=["java", "config", binding.source_type],
        )
    )


def build_tool() -> MemoryTool[
    JavaExtractConfigSurfaceArgs, JavaExtractConfigSurfaceResult
]:
    return JavaExtractConfigSurfaceTool()
