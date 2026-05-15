from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

import glaurung as g

from ..kb.models import Node, NodeKind
from ..kb.store import KnowledgeBase


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
) -> JavaXrefScanResult:
    xrefs: list[JavaXrefRecord] = []
    class_count = 0
    parsed_class_count = 0
    parse_error_count = 0
    truncated = False
    java_analysis = getattr(g, "analysis")
    class_filter = _internal(source_class_name) if source_class_name else None

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
            if class_filter is not None and entry_class_name != class_filter:
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
            for method in parsed["methods"]:
                if not isinstance(method, dict):
                    continue
                if (
                    source_method_name is not None
                    and str(method["name"]) != source_method_name
                ):
                    continue
                if (
                    source_method_descriptor is not None
                    and str(method["descriptor"]) != source_method_descriptor
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
                    ):
                        continue
                    record = _record(
                        archive_path=archive_path,
                        entry_name=info.filename,
                        class_name=str(parsed["class_name"]),
                        method=method,
                        xref=xref,
                        line_numbers=line_numbers,
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
) -> bool:
    return all(
        (
            kind is None or str(xref.get("kind", "")) == kind,
            target_owner is None
            or str(xref.get("owner", "")) == _internal(target_owner),
            target_name is None or str(xref.get("name", "")) == target_name,
            target_descriptor is None
            or str(xref.get("descriptor", "")) == target_descriptor,
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
