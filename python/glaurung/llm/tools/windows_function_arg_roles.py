from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .windows_surface_metadata import _resolve_metadata_path


class WindowsFunctionArgRolesArgs(BaseModel):
    function_name: str = Field(
        ...,
        description="Function or entry-point symbol to classify, e.g. NtDeviceIoControlFile.",
    )
    c_prototype: str | None = Field(
        None,
        description="Optional C prototype used for best-effort role inference.",
    )
    sources_path: str | None = Field(
        None,
        description="Path to ASB data/kg/pe-sources.yaml. Defaults to ASB_REPO or sibling repo.",
    )
    include_unmatched_prototype_args: bool = Field(
        True,
        description="Include heuristic roles for prototype args not covered by source metadata.",
    )


class ArgumentRoleEvidence(BaseModel):
    index: int | None = None
    expression: str | None = None
    name: str | None = None
    role: str
    paired_length: int | str | None = None
    selector: int | str | None = None
    confidence: float = Field(ge=0.0, le=1.0)
    provenance: str
    reason: str


class SourceRoleMatch(BaseModel):
    source_id: str
    surface: str
    attacker_class: str
    symbols: list[str]
    roles: list[ArgumentRoleEvidence]


class WindowsFunctionArgRolesResult(BaseModel):
    function_name: str
    sources_path: str
    source_matches: list[SourceRoleMatch]
    prototype_roles: list[ArgumentRoleEvidence]
    combined_roles: list[ArgumentRoleEvidence]
    confidence: float = Field(ge=0.0, le=1.0)
    notes: list[str] = Field(default_factory=list)


class WindowsFunctionArgRolesTool(
    MemoryTool[WindowsFunctionArgRolesArgs, WindowsFunctionArgRolesResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_function_arg_roles",
                description=(
                    "Classify Windows function arguments by security role using "
                    "ASB source metadata and optional C-prototype heuristics."
                ),
                tags=("windows", "pe", "metadata", "arguments", "sources"),
            ),
            WindowsFunctionArgRolesArgs,
            WindowsFunctionArgRolesResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsFunctionArgRolesArgs,
    ) -> WindowsFunctionArgRolesResult:
        sources_path = _resolve_metadata_path(args.sources_path, "data/kg/pe-sources.yaml")
        entries = _load_source_entries(sources_path)
        source_matches = [
            _source_match(entry)
            for entry in entries
            if args.function_name in _str_list(entry.get("symbols"))
        ]
        prototype_roles = _prototype_roles(args.c_prototype) if args.c_prototype else []
        combined_roles = _merge_roles(
            source_matches,
            prototype_roles,
            include_unmatched=args.include_unmatched_prototype_args,
        )
        notes: list[str] = []
        if not source_matches:
            notes.append("no ASB source metadata matched the function name")
        if args.c_prototype is None:
            notes.append("no prototype supplied; result is metadata-only")
        elif not prototype_roles:
            notes.append("prototype supplied but no role-like arguments were inferred")

        confidence = 0.85 if source_matches else (0.45 if prototype_roles else 0.0)
        return WindowsFunctionArgRolesResult(
            function_name=args.function_name,
            sources_path=str(sources_path),
            source_matches=source_matches,
            prototype_roles=prototype_roles,
            combined_roles=combined_roles,
            confidence=confidence,
            notes=notes,
        )


def _load_source_entries(path: Path) -> list[dict[str, Any]]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    if not isinstance(raw, list):
        raise ValueError(f"{path}: expected top-level list")
    entries: list[dict[str, Any]] = []
    for idx, entry in enumerate(raw):
        if not isinstance(entry, dict):
            raise ValueError(f"{path}: source entry {idx} is not a mapping")
        entries.append(entry)
    return entries


def _source_match(entry: dict[str, Any]) -> SourceRoleMatch:
    roles = []
    for role in entry.get("roles") or []:
        if not isinstance(role, dict):
            continue
        roles.append(
            ArgumentRoleEvidence(
                index=_int_or_none(role.get("index")),
                expression=str(role["expression"])
                if role.get("expression") is not None
                else None,
                role=str(role.get("role") or "unknown"),
                paired_length=role.get("paired_length"),
                selector=role.get("selector"),
                confidence=0.9,
                provenance="asb_pe_source_metadata",
                reason=f"role from source catalogue {entry.get('id')}",
            )
        )
    return SourceRoleMatch(
        source_id=str(entry.get("id") or ""),
        surface=str(entry.get("surface") or ""),
        attacker_class=str(entry.get("attacker_class") or ""),
        symbols=_str_list(entry.get("symbols")),
        roles=roles,
    )


def _prototype_roles(c_prototype: str) -> list[ArgumentRoleEvidence]:
    params = _parse_parameters(c_prototype)
    roles: list[ArgumentRoleEvidence] = []
    for idx, param in enumerate(params):
        role, reason = _role_from_param(param)
        if role is None:
            continue
        roles.append(
            ArgumentRoleEvidence(
                index=idx,
                name=param["name"],
                role=role,
                confidence=0.45,
                provenance="prototype_heuristic",
                reason=reason,
            )
        )
    return roles


def _parse_parameters(c_prototype: str) -> list[dict[str, str]]:
    match = re.search(r"\((?P<params>.*)\)", c_prototype, flags=re.S)
    if not match:
        return []
    raw = match.group("params").strip()
    if not raw or raw == "void":
        return []
    params = []
    for piece in _split_params(raw):
        text = " ".join(piece.replace("\n", " ").split())
        text = re.sub(r"\b(?:_In_|_Out_|_Inout_|OPTIONAL|CONST)\b", "", text)
        text = " ".join(text.split())
        if not text:
            continue
        name_match = re.search(r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?:\[[^]]*\])?$", text)
        if not name_match:
            continue
        name = name_match.group("name")
        params.append({"name": name, "text": text})
    return params


def _split_params(raw: str) -> list[str]:
    out: list[str] = []
    depth = 0
    start = 0
    for idx, ch in enumerate(raw):
        if ch in "([":
            depth += 1
        elif ch in ")]" and depth:
            depth -= 1
        elif ch == "," and depth == 0:
            out.append(raw[start:idx].strip())
            start = idx + 1
    out.append(raw[start:].strip())
    return out


def _role_from_param(param: dict[str, str]) -> tuple[str | None, str]:
    name = param["name"].lower()
    text = param["text"].lower()
    if any(token in name for token in ("class", "informationclass", "code")):
        return "selector", "parameter name looks like selector or class discriminator"
    if any(token in name for token in ("length", "size", "count", "cb")):
        return "length", "parameter name looks like a size/count"
    if "handle" in name:
        return "handle", "parameter name looks like a handle"
    if "flags" in name or name == "flag":
        return "flags", "parameter name looks like flags"
    if "callback" in name or "routine" in name:
        return "callback", "parameter name looks like callback/routine pointer"
    if "return" in name and ("length" in name or "size" in name):
        return "return_length", "parameter name looks like returned length"
    if any(token in name for token in ("buffer", "buf", "data", "information")):
        if "*" in text or "pvoid" in text or "ptr" in text:
            return "buffer", "pointer-like parameter name looks like a data buffer"
    return None, "no role heuristic matched"


def _merge_roles(
    source_matches: list[SourceRoleMatch],
    prototype_roles: list[ArgumentRoleEvidence],
    *,
    include_unmatched: bool,
) -> list[ArgumentRoleEvidence]:
    merged: list[ArgumentRoleEvidence] = []
    covered_indexes: set[int] = set()
    for match in source_matches:
        for role in match.roles:
            merged.append(role)
            if role.index is not None:
                covered_indexes.add(role.index)
    if include_unmatched:
        for role in prototype_roles:
            if role.index is None or role.index not in covered_indexes:
                merged.append(role)
    return merged


def _str_list(raw: Any) -> list[str]:
    if not isinstance(raw, list):
        return []
    return [str(item) for item in raw if str(item)]


def _int_or_none(raw: Any) -> int | None:
    if raw is None:
        return None
    return int(raw)


def build_tool() -> MemoryTool[
    WindowsFunctionArgRolesArgs, WindowsFunctionArgRolesResult
]:
    return WindowsFunctionArgRolesTool()
