from __future__ import annotations

import json
import tomllib
import zipfile
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


class MinecraftDetectArchiveArgs(BaseModel):
    path: str | None = Field(None, description="Path to the JAR/ZIP archive")


class MinecraftDetectArchiveResult(BaseModel):
    archive_path: str
    is_minecraft: bool
    loader: str
    side: str
    minecraft_version: str | None = None
    protocol_version: int | None = None
    world_version: int | None = None
    java_version: int | None = None
    stable: bool | None = None
    manifest_main_class: str | None = None
    forge_mod_ids: list[str] = Field(default_factory=list)
    fabric_mod_id: str | None = None
    mixin_config_count: int = 0
    coremod_count: int = 0
    bundler_format: str | None = None
    bundled_server_entries: list[str] = Field(default_factory=list)
    mapping_recommended: bool = False
    preferred_mapping_source: str | None = None
    rationale: str
    note_node_id: str | None = None


class MinecraftDetectArchiveTool(
    MemoryTool[MinecraftDetectArchiveArgs, MinecraftDetectArchiveResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="minecraft_detect_archive",
                description=(
                    "Detect Minecraft archive metadata, loader, side, version, "
                    "and mapping/de-obfuscation hints."
                ),
                tags=("java", "minecraft", "deobfuscation", "annotation", "kb"),
            ),
            MinecraftDetectArchiveArgs,
            MinecraftDetectArchiveResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: MinecraftDetectArchiveArgs,
    ) -> MinecraftDetectArchiveResult:
        path = Path(args.path or ctx.file_path)
        if not zipfile.is_zipfile(path):
            return MinecraftDetectArchiveResult(
                archive_path=str(path),
                is_minecraft=False,
                loader="unknown",
                side="unknown",
                rationale="Input is not a ZIP/JAR archive.",
            )

        with zipfile.ZipFile(path) as zf:
            names = set(zf.namelist())
            manifest_attrs = _manifest_attrs(zf)
            manifest_main_class = manifest_attrs.get("Main-Class")
            bundler_format = manifest_attrs.get("Bundler-Format")
            version_info = _read_json(zf, "version.json")
            mods_toml = _read_toml(zf, "META-INF/mods.toml")
            fabric_mod = _read_json(zf, "fabric.mod.json")
            mixin_config_count = sum(
                1
                for name in names
                if "mixin" in name.lower() and name.endswith(".json")
            )
            coremod_count = sum(1 for name in names if name.startswith("coremods/"))
            bundled_server_entries = _bundled_server_entries(names)

        forge_mod_ids = _forge_mod_ids(mods_toml)
        fabric_mod_id = fabric_mod.get("id") if fabric_mod else None
        loader = _loader(version_info, mods_toml, fabric_mod)
        side = _side(path.name, manifest_main_class, names, loader)
        is_minecraft = bool(
            version_info
            or forge_mod_ids
            or fabric_mod_id
            or any(
                name.startswith(("assets/minecraft/", "data/minecraft/"))
                for name in names
            )
        )
        minecraft_version = _version_id(version_info)
        mapping_recommended = is_minecraft and bool(minecraft_version)
        preferred_mapping_source = "mojang" if mapping_recommended else None
        rationale = _rationale(
            is_minecraft=is_minecraft,
            loader=loader,
            side=side,
            minecraft_version=minecraft_version,
            java_version=_int_or_none(version_info.get("java_version"))
            if version_info
            else None,
            protocol_version=(
                _int_or_none(version_info.get("protocol_version"))
                if version_info
                else None
            ),
            forge_mod_ids=forge_mod_ids,
            fabric_mod_id=fabric_mod_id,
            coremod_count=coremod_count,
            bundled_server_entries=bundled_server_entries,
            mapping_recommended=mapping_recommended,
        )
        note = kb.add_node(
            Node(
                kind=NodeKind.note,
                label=f"Minecraft archive: {loader}/{side}",
                text=rationale,
                props={
                    "tool": "minecraft_detect_archive",
                    "archive_path": str(path),
                    "loader": loader,
                    "side": side,
                    "minecraft_version": minecraft_version,
                    "mapping_recommended": mapping_recommended,
                    "preferred_mapping_source": preferred_mapping_source,
                    "bundler_format": bundler_format,
                    "bundled_server_entries": bundled_server_entries,
                },
                tags=["java", "minecraft", "deobfuscation", "annotation"],
            )
        )
        return MinecraftDetectArchiveResult(
            archive_path=str(path),
            is_minecraft=is_minecraft,
            loader=loader,
            side=side,
            minecraft_version=minecraft_version,
            protocol_version=(
                _int_or_none(version_info.get("protocol_version"))
                if version_info
                else None
            ),
            world_version=(
                _int_or_none(version_info.get("world_version"))
                if version_info
                else None
            ),
            java_version=(
                _int_or_none(version_info.get("java_version")) if version_info else None
            ),
            stable=version_info.get("stable") if version_info else None,
            manifest_main_class=manifest_main_class,
            forge_mod_ids=forge_mod_ids,
            fabric_mod_id=fabric_mod_id,
            mixin_config_count=mixin_config_count,
            coremod_count=coremod_count,
            bundler_format=bundler_format,
            bundled_server_entries=bundled_server_entries,
            mapping_recommended=mapping_recommended,
            preferred_mapping_source=preferred_mapping_source,
            rationale=rationale,
            note_node_id=note.id,
        )


def _read_json(zf: zipfile.ZipFile, name: str) -> dict[str, Any]:
    try:
        return json.loads(zf.read(name).decode("utf-8"))
    except (KeyError, json.JSONDecodeError, UnicodeDecodeError):
        return {}


def _read_toml(zf: zipfile.ZipFile, name: str) -> dict[str, Any]:
    try:
        return tomllib.loads(zf.read(name).decode("utf-8"))
    except (KeyError, tomllib.TOMLDecodeError, UnicodeDecodeError):
        return {}


def _manifest_attrs(zf: zipfile.ZipFile) -> dict[str, str]:
    try:
        text = zf.read("META-INF/MANIFEST.MF").decode("utf-8", errors="replace")
    except KeyError:
        return {}
    lines: list[str] = []
    for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        if line.startswith(" ") and lines:
            lines[-1] += line[1:]
        elif line:
            lines.append(line)
    attrs: dict[str, str] = {}
    for line in lines:
        key, sep, value = line.partition(":")
        if sep:
            attrs[key] = value.strip()
    return attrs


def _forge_mod_ids(mods_toml: dict[str, Any]) -> list[str]:
    mods = mods_toml.get("mods", [])
    if not isinstance(mods, list):
        return []
    ids: list[str] = []
    for mod in mods:
        if isinstance(mod, dict) and isinstance(mod.get("modId"), str):
            ids.append(mod["modId"])
    return ids


def _bundled_server_entries(names: set[str]) -> list[str]:
    return sorted(
        name
        for name in names
        if name.startswith("META-INF/versions/")
        and name.endswith(".jar")
        and Path(name).name.startswith("server-")
    )


def _loader(
    version_info: dict[str, Any],
    mods_toml: dict[str, Any],
    fabric_mod: dict[str, Any],
) -> str:
    if fabric_mod:
        return "fabric"
    mod_loader = mods_toml.get("modLoader")
    if isinstance(mod_loader, str):
        lowered = mod_loader.lower()
        if "neoforge" in lowered:
            return "neoforge"
        if "fml" in lowered or "forge" in lowered:
            return "forge"
    if version_info:
        return "vanilla"
    return "unknown"


def _side(
    file_name: str,
    manifest_main_class: str | None,
    names: set[str],
    loader: str,
) -> str:
    haystack = " ".join(part for part in (file_name, manifest_main_class or "")).lower()
    if loader in {"forge", "neoforge"} and "universal" in haystack:
        return "universal"
    if "client" in haystack:
        return "client"
    if "server" in haystack or "dedicatedserver" in haystack:
        return "server"
    if any(name.startswith("assets/minecraft/") for name in names):
        return "client"
    return "unknown"


def _version_id(version_info: dict[str, Any]) -> str | None:
    value = version_info.get("id") or version_info.get("name")
    return value if isinstance(value, str) else None


def _int_or_none(value: Any) -> int | None:
    return value if isinstance(value, int) else None


def _rationale(
    *,
    is_minecraft: bool,
    loader: str,
    side: str,
    minecraft_version: str | None,
    java_version: int | None,
    protocol_version: int | None,
    forge_mod_ids: list[str],
    fabric_mod_id: str | None,
    coremod_count: int,
    bundled_server_entries: list[str],
    mapping_recommended: bool,
) -> str:
    if not is_minecraft:
        return "No Minecraft archive metadata was detected."
    parts = [f"Minecraft archive detected: loader={loader}, side={side}."]
    if minecraft_version:
        parts.append(f"Version={minecraft_version}.")
    if java_version is not None:
        parts.append(f"Java runtime target={java_version}.")
    if protocol_version is not None:
        parts.append(f"Protocol={protocol_version}.")
    if forge_mod_ids:
        parts.append(f"Forge mods={', '.join(forge_mod_ids)}.")
    if fabric_mod_id:
        parts.append(f"Fabric mod id={fabric_mod_id}.")
    if coremod_count:
        parts.append(f"Coremod resources={coremod_count}.")
    if bundled_server_entries:
        parts.append(f"Bundled server entries={len(bundled_server_entries)}.")
    if mapping_recommended:
        parts.append("Use Mojang mappings before semantic analysis.")
    return " ".join(parts)


def build_tool() -> MemoryTool[
    MinecraftDetectArchiveArgs, MinecraftDetectArchiveResult
]:
    return MinecraftDetectArchiveTool()
