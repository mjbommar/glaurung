from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

import glaurung as g

from ..kb.models import Node, NodeKind
from ..kb.store import KnowledgeBase
from .java_proguard_mappings import (
    ProguardClassMapping,
    ProguardMappings,
    parse_proguard_mappings,
)


class JavaXrefRecord(BaseModel):
    xref_id: str
    archive_path: str
    entry_name: str
    source_class_name: str
    source_method_name: str
    source_method_descriptor: str
    bci: int
    line_number: int | None = None
    opcode: int | None = None
    kind: str
    owner: str
    name: str
    descriptor: str
    target: str
    string_value: str | None = None
    mapped_source_class_name: str | None = None
    mapped_source_method_names: list[str] = Field(default_factory=list)
    mapped_source_method_descriptors: list[str] = Field(default_factory=list)
    mapped_owner: str | None = None
    mapped_names: list[str] = Field(default_factory=list)
    mapped_descriptor: str | None = None


class JavaXrefScanResult(BaseModel):
    archive_path: str
    class_count: int
    parsed_class_count: int
    parse_error_count: int
    xref_count: int
    xrefs: list[JavaXrefRecord] = Field(default_factory=list)
    truncated: bool = False


def scan_xrefs(
    *,
    archive_path: Path,
    kb: KnowledgeBase,
    tool_name: str,
    max_classes: int,
    max_xrefs: int,
    source_class_name: str | None = None,
    source_method_name: str | None = None,
    source_method_descriptor: str | None = None,
    target_owner: str | None = None,
    target_name: str | None = None,
    target_descriptor: str | None = None,
    kind: str | None = None,
    mapping_path: Path | None = None,
) -> JavaXrefScanResult:
    xrefs: list[JavaXrefRecord] = []
    class_count = 0
    parsed_class_count = 0
    parse_error_count = 0
    truncated = False
    java_analysis = getattr(g, "analysis")
    mappings = (
        parse_proguard_mappings(mapping_path) if mapping_path is not None else None
    )
    class_filter = (
        _class_candidates(mappings, source_class_name) if source_class_name else None
    )

    if not zipfile.is_zipfile(archive_path):
        return JavaXrefScanResult(
            archive_path=str(archive_path),
            class_count=0,
            parsed_class_count=0,
            parse_error_count=1,
            xref_count=0,
            xrefs=[],
        )

    with zipfile.ZipFile(archive_path) as zf:
        for info in zf.infolist():
            if info.is_dir() or not info.filename.endswith(".class"):
                continue
            entry_class_name = info.filename.removesuffix(".class")
            if class_filter is not None and entry_class_name not in class_filter:
                continue
            class_count += 1
            if class_count > max_classes:
                truncated = True
                break
            try:
                parsed = java_analysis.parse_java_class_bytes(zf.read(info))
            except RuntimeError:
                parse_error_count += 1
                continue
            if parsed is None:
                parse_error_count += 1
                continue
            parsed_class_count += 1
            parsed_class_name = str(parsed["class_name"])
            source_class_mapping = _lookup_class_mapping(mappings, parsed_class_name)
            for method in parsed["methods"]:
                if not isinstance(method, dict):
                    continue
                if source_method_name is not None and not _method_name_matches(
                    mappings=mappings,
                    class_mapping=source_class_mapping,
                    method=method,
                    method_name=source_method_name,
                ):
                    continue
                if (
                    source_method_descriptor is not None
                    and not _method_descriptor_matches(
                        mappings=mappings,
                        class_mapping=source_class_mapping,
                        method=method,
                        method_descriptor=source_method_descriptor,
                    )
                ):
                    continue
                code = method.get("code")
                if not isinstance(code, dict):
                    continue
                line_numbers = _line_numbers(code)
                for xref in code.get("xrefs", []):
                    if not isinstance(xref, dict):
                        continue
                    if not _xref_matches(
                        xref,
                        target_owner=target_owner,
                        target_name=target_name,
                        target_descriptor=target_descriptor,
                        kind=kind,
                        mappings=mappings,
                    ):
                        continue
                    record = _record(
                        archive_path=archive_path,
                        entry_name=info.filename,
                        class_name=parsed_class_name,
                        method=method,
                        xref=xref,
                        line_numbers=line_numbers,
                        mappings=mappings,
                        source_class_mapping=source_class_mapping,
                    )
                    xrefs.append(record)
                    _add_xref_node(kb, tool_name, record)
                    if len(xrefs) >= max_xrefs:
                        truncated = True
                        return JavaXrefScanResult(
                            archive_path=str(archive_path),
                            class_count=class_count,
                            parsed_class_count=parsed_class_count,
                            parse_error_count=parse_error_count,
                            xref_count=len(xrefs),
                            xrefs=xrefs,
                            truncated=truncated,
                        )

    return JavaXrefScanResult(
        archive_path=str(archive_path),
        class_count=class_count,
        parsed_class_count=parsed_class_count,
        parse_error_count=parse_error_count,
        xref_count=len(xrefs),
        xrefs=xrefs,
        truncated=truncated,
    )


def _xref_matches(
    xref: dict[str, Any],
    *,
    target_owner: str | None,
    target_name: str | None,
    target_descriptor: str | None,
    kind: str | None,
    mappings: ProguardMappings | None,
) -> bool:
    owner = str(xref.get("owner", ""))
    name = str(xref.get("name", ""))
    descriptor = str(xref.get("descriptor", ""))
    _, mapped_names, mapped_descriptor = _member_mapping_annotation(
        mappings=mappings,
        owner=owner,
        kind=str(xref.get("kind", "")),
        name=name,
        descriptor=descriptor,
    )
    owner_matches = target_owner is None or owner in _class_candidates(
        mappings,
        target_owner or owner,
    )
    name_matches = (
        target_name is None or name == target_name or target_name in mapped_names
    )
    descriptor_matches = (
        target_descriptor is None
        or descriptor == target_descriptor
        or mapped_descriptor == target_descriptor
    )
    return all(
        (
            kind is None or str(xref.get("kind", "")) == kind,
            owner_matches,
            name_matches,
            descriptor_matches,
        )
    )


def _record(
    *,
    archive_path: Path,
    entry_name: str,
    class_name: str,
    method: dict[str, Any],
    xref: dict[str, Any],
    line_numbers: list[dict[str, int]],
    mappings: ProguardMappings | None,
    source_class_mapping: ProguardClassMapping | None,
) -> JavaXrefRecord:
    bci = int(xref.get("bci", 0))
    source_method_name = str(method["name"])
    source_method_descriptor = str(method["descriptor"])
    owner = str(xref.get("owner", ""))
    name = str(xref.get("name", ""))
    descriptor = str(xref.get("descriptor", ""))
    kind = str(xref.get("kind", ""))
    key = (
        f"{archive_path}:{entry_name}:{class_name}:"
        f"{source_method_name}:{source_method_descriptor}:"
        f"{bci}:{kind}:{owner}:{name}:{descriptor}"
    )
    string_value = xref.get("string_value")
    opcode = xref.get("opcode")
    mapped_owner, mapped_names, mapped_descriptor = _member_mapping_annotation(
        mappings=mappings,
        owner=owner,
        kind=kind,
        name=name,
        descriptor=descriptor,
    )
    return JavaXrefRecord(
        xref_id=hashlib.sha256(key.encode("utf-8")).hexdigest()[:16],
        archive_path=str(archive_path),
        entry_name=entry_name,
        source_class_name=class_name,
        source_method_name=source_method_name,
        source_method_descriptor=source_method_descriptor,
        bci=bci,
        line_number=_line_number_for_bci(line_numbers, bci),
        opcode=opcode if isinstance(opcode, int) else None,
        kind=kind,
        owner=owner,
        name=name,
        descriptor=descriptor,
        target=str(xref.get("target", "")),
        string_value=string_value if isinstance(string_value, str) else None,
        mapped_source_class_name=(
            source_class_mapping.official_name
            if source_class_mapping is not None
            else None
        ),
        mapped_source_method_names=_mapped_method_names(
            mappings=mappings,
            class_mapping=source_class_mapping,
            method_name=source_method_name,
            descriptor=source_method_descriptor,
        ),
        mapped_source_method_descriptors=_mapped_method_descriptors(
            mappings=mappings,
            class_mapping=source_class_mapping,
            method_name=source_method_name,
            descriptor=source_method_descriptor,
        ),
        mapped_owner=mapped_owner,
        mapped_names=mapped_names,
        mapped_descriptor=mapped_descriptor,
    )


def _add_xref_node(kb: KnowledgeBase, tool_name: str, record: JavaXrefRecord) -> None:
    kb.add_node(
        Node(
            kind=NodeKind.java_xref,
            label=(
                f"{record.source_class_name}#{record.source_method_name}"
                f"{record.source_method_descriptor}@{record.bci} -> {record.target}"
            ),
            props={
                "tool": tool_name,
                **record.model_dump(),
            },
            tags=["java", "xref", record.kind],
        )
    )


def _line_numbers(code: dict[str, Any]) -> list[dict[str, int]]:
    return [
        {"start_pc": int(item["start_pc"]), "line_number": int(item["line_number"])}
        for item in code.get("line_numbers", [])
        if isinstance(item, dict)
        and isinstance(item.get("start_pc"), int)
        and isinstance(item.get("line_number"), int)
    ]


def _line_number_for_bci(
    line_numbers: list[dict[str, int]],
    bci: int | None,
) -> int | None:
    if bci is None:
        return None
    current: int | None = None
    for item in sorted(line_numbers, key=lambda value: int(value["start_pc"])):
        if int(item["start_pc"]) > bci:
            break
        current = int(item["line_number"])
    return current


def _internal(class_name: str) -> str:
    return class_name.removesuffix(".class").replace(".", "/")


def _class_candidates(
    mappings: ProguardMappings | None,
    class_name: str,
) -> set[str]:
    candidates = {_internal(class_name)}
    class_mapping = _lookup_class_mapping(mappings, class_name)
    if class_mapping is not None:
        candidates.add(_internal(class_mapping.obfuscated_name))
        candidates.add(_internal(class_mapping.official_name))
    return candidates


def _lookup_class_mapping(
    mappings: ProguardMappings | None,
    class_name: str,
) -> ProguardClassMapping | None:
    if mappings is None:
        return None
    class_mapping, _ = mappings.lookup_class(class_name)
    return class_mapping


def _method_name_matches(
    *,
    mappings: ProguardMappings | None,
    class_mapping: ProguardClassMapping | None,
    method: dict[str, Any],
    method_name: str,
) -> bool:
    if str(method["name"]) == method_name:
        return True
    return method_name in _mapped_method_names(
        mappings=mappings,
        class_mapping=class_mapping,
        method_name=str(method["name"]),
        descriptor=str(method["descriptor"]),
    )


def _mapped_method_names(
    *,
    mappings: ProguardMappings | None,
    class_mapping: ProguardClassMapping | None,
    method_name: str,
    descriptor: str,
) -> list[str]:
    if (
        mappings is None
        or class_mapping is None
        or method_name in {"<init>", "<clinit>"}
    ):
        return []
    return [
        member.official_name
        for member in mappings.matching_member_mappings(
            class_mapping,
            kind="method",
            obfuscated_name=method_name,
            descriptor=descriptor,
        )
    ]


def _mapped_method_descriptors(
    *,
    mappings: ProguardMappings | None,
    class_mapping: ProguardClassMapping | None,
    method_name: str,
    descriptor: str,
) -> list[str]:
    if (
        mappings is None
        or class_mapping is None
        or method_name in {"<init>", "<clinit>"}
    ):
        return []
    return [
        official_descriptor
        for member in mappings.matching_member_mappings(
            class_mapping,
            kind="method",
            obfuscated_name=method_name,
            descriptor=descriptor,
        )
        if (official_descriptor := mappings.official_descriptor_for(member)) is not None
    ]


def _method_descriptor_matches(
    *,
    mappings: ProguardMappings | None,
    class_mapping: ProguardClassMapping | None,
    method: dict[str, Any],
    method_descriptor: str,
) -> bool:
    raw_descriptor = str(method["descriptor"])
    if raw_descriptor == method_descriptor:
        return True
    if mappings is None or class_mapping is None:
        return False
    for member in mappings.matching_member_mappings(
        class_mapping,
        kind="method",
        obfuscated_name=str(method["name"]),
        descriptor=raw_descriptor,
    ):
        if mappings.official_descriptor_for(member) == method_descriptor:
            return True
    return False


def _member_mapping_annotation(
    *,
    mappings: ProguardMappings | None,
    owner: str,
    kind: str,
    name: str,
    descriptor: str,
) -> tuple[str | None, list[str], str | None]:
    if mappings is None or not owner:
        return None, [], None
    class_mapping = _lookup_class_mapping(mappings, owner)
    if class_mapping is None:
        return None, [], None
    if kind not in {"field", "method", "interface_method"}:
        return class_mapping.official_name, [], None
    member_kind = "field" if kind == "field" else "method"
    if member_kind == "method" and name in {"<init>", "<clinit>"}:
        return class_mapping.official_name, [], None
    members = mappings.matching_member_mappings(
        class_mapping,
        kind=member_kind,
        obfuscated_name=name,
        descriptor=descriptor,
    )
    mapped_descriptor = (
        mappings.official_descriptor_for(members[0]) if members else None
    )
    return (
        class_mapping.official_name,
        [member.official_name for member in members],
        mapped_descriptor,
    )
