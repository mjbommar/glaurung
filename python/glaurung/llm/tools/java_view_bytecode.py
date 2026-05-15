from __future__ import annotations

import zipfile
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field

import glaurung as g

from ..context import MemoryContext
from ..kb.models import Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .java_proguard_mappings import (
    ProguardClassMapping,
    ProguardMappings,
    parse_proguard_mappings,
)


class JavaViewBytecodeArgs(BaseModel):
    path: str | None = Field(None, description="Path to the JAR/ZIP archive")
    class_name: str | None = Field(
        None,
        description="Class name in internal, dotted, obfuscated, or official namespace",
    )
    method_name: str | None = Field(
        None,
        description="Method name in obfuscated or mapped namespace",
    )
    method_descriptor: str | None = Field(
        None,
        description="Optional JVM method descriptor such as (I)I",
    )
    mapping_path: str | None = Field(
        None,
        description="Optional ProGuard/Mojang mapping file for de-obfuscation",
    )
    include_xrefs: bool = True
    bci_start: int | None = Field(None, ge=0)
    bci_end: int | None = Field(None, ge=0)
    max_classes_scan: int = Field(50_000, ge=1)
    max_instructions: int = Field(512, ge=1)


class JavaBytecodeInstruction(BaseModel):
    bci: int
    line_number: int | None = None
    opcode: int
    mnemonic: str
    operands: list[str] = Field(default_factory=list)
    length: int


class JavaBytecodeXref(BaseModel):
    bci: int
    line_number: int | None = None
    opcode: int | None = None
    kind: str
    owner: str
    name: str
    descriptor: str
    target: str
    string_value: str | None = None


class JavaViewBytecodeResult(BaseModel):
    archive_path: str
    class_found: bool
    method_found: bool
    matched_by: Literal["input", "official", "obfuscated", "none"]
    entry_name: str | None = None
    class_name: str | None = None
    dotted_class_name: str | None = None
    mapped_class_name: str | None = None
    method_name: str | None = None
    mapped_method_names: list[str] = Field(default_factory=list)
    mapped_method_signatures: list[str] = Field(default_factory=list)
    method_descriptor: str | None = None
    max_stack: int | None = None
    max_locals: int | None = None
    code_length: int | None = None
    instructions: list[JavaBytecodeInstruction] = Field(default_factory=list)
    xrefs: list[JavaBytecodeXref] = Field(default_factory=list)
    truncated: bool = False
    bytecode_node_id: str | None = None


class JavaViewBytecodeTool(MemoryTool[JavaViewBytecodeArgs, JavaViewBytecodeResult]):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="java_view_bytecode",
                description=(
                    "View JVM bytecode instructions for a selected Java method, "
                    "including BCI, opcode, mnemonic, operands, line anchors, "
                    "xrefs, and optional ProGuard/Mojang mapping context."
                ),
                tags=("java", "bytecode", "disassembly", "mapping", "kb"),
            ),
            JavaViewBytecodeArgs,
            JavaViewBytecodeResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: JavaViewBytecodeArgs,
    ) -> JavaViewBytecodeResult:
        archive_path = Path(args.path or ctx.file_path)
        if args.class_name is None or args.method_name is None:
            return JavaViewBytecodeResult(
                archive_path=str(archive_path),
                class_found=False,
                method_found=False,
                matched_by="none",
            )
        if not zipfile.is_zipfile(archive_path):
            return JavaViewBytecodeResult(
                archive_path=str(archive_path),
                class_found=False,
                method_found=False,
                matched_by="none",
            )

        mappings = (
            parse_proguard_mappings(Path(args.mapping_path))
            if args.mapping_path is not None
            else None
        )
        class_mapping, mapping_match = _lookup_class_mapping(mappings, args.class_name)
        matched_by: Literal["input", "official", "obfuscated", "none"] = (
            mapping_match if mapping_match != "none" else "input"
        )
        target_names = _candidate_class_names(args.class_name, class_mapping)
        java_analysis = getattr(g, "analysis")

        class_count = 0
        with zipfile.ZipFile(archive_path) as zf:
            for info in zf.infolist():
                if info.is_dir() or not info.filename.endswith(".class"):
                    continue
                class_count += 1
                if class_count > args.max_classes_scan:
                    break
                entry_class_name = info.filename.removesuffix(".class")
                if entry_class_name not in target_names:
                    continue
                parsed = java_analysis.parse_java_class_bytes(zf.read(info))
                if parsed is None:
                    continue
                method = _select_method(
                    parsed=parsed,
                    mappings=mappings,
                    class_mapping=class_mapping,
                    method_name=args.method_name,
                    method_descriptor=args.method_descriptor,
                )
                if method is None:
                    return JavaViewBytecodeResult(
                        archive_path=str(archive_path),
                        class_found=True,
                        method_found=False,
                        matched_by=matched_by,
                        entry_name=info.filename,
                        class_name=str(parsed["class_name"]),
                        dotted_class_name=_dotted(str(parsed["class_name"])),
                        mapped_class_name=(
                            class_mapping.official_name
                            if class_mapping is not None
                            else None
                        ),
                    )
                return _result_for_method(
                    kb=kb,
                    archive_path=archive_path,
                    entry_name=info.filename,
                    parsed=parsed,
                    method=method,
                    mappings=mappings,
                    class_mapping=class_mapping,
                    matched_by=matched_by,
                    include_xrefs=args.include_xrefs,
                    bci_start=args.bci_start,
                    bci_end=args.bci_end,
                    max_instructions=args.max_instructions,
                )

        return JavaViewBytecodeResult(
            archive_path=str(archive_path),
            class_found=False,
            method_found=False,
            matched_by="none",
        )


def _result_for_method(
    *,
    kb: KnowledgeBase,
    archive_path: Path,
    entry_name: str,
    parsed: dict[str, Any],
    method: dict[str, Any],
    mappings: ProguardMappings | None,
    class_mapping: ProguardClassMapping | None,
    matched_by: Literal["input", "official", "obfuscated", "none"],
    include_xrefs: bool,
    bci_start: int | None,
    bci_end: int | None,
    max_instructions: int,
) -> JavaViewBytecodeResult:
    class_name = str(parsed["class_name"])
    code = method.get("code")
    if not isinstance(code, dict):
        return JavaViewBytecodeResult(
            archive_path=str(archive_path),
            class_found=True,
            method_found=False,
            matched_by=matched_by,
            entry_name=entry_name,
            class_name=class_name,
            dotted_class_name=_dotted(class_name),
            mapped_class_name=(
                class_mapping.official_name if class_mapping is not None else None
            ),
        )

    line_numbers = _line_numbers(code)
    raw_instructions = [
        instruction
        for instruction in code.get("instructions", [])
        if isinstance(instruction, dict)
        and _bci_in_range(int(instruction.get("bci", 0)), bci_start, bci_end)
    ]
    truncated = len(raw_instructions) > max_instructions
    instructions = [
        _instruction_summary(instruction, line_numbers)
        for instruction in raw_instructions[:max_instructions]
    ]
    xrefs = (
        [
            _xref_summary(xref, line_numbers)
            for xref in code.get("xrefs", [])
            if isinstance(xref, dict)
            and _bci_in_range(int(xref.get("bci", 0)), bci_start, bci_end)
        ]
        if include_xrefs
        else []
    )
    mapped_method_members = _mapped_method_members(
        mappings=mappings,
        class_mapping=class_mapping,
        method=method,
    )
    bytecode_node = kb.add_node(
        Node(
            kind=NodeKind.java_bytecode,
            label=(
                f"{class_mapping.official_name if class_mapping else _dotted(class_name)}#"
                f"{mapped_method_members[0].official_name if mapped_method_members else method['name']}"
                f"{method['descriptor']}"
            ),
            props={
                "tool": "java_view_bytecode",
                "archive_path": str(archive_path),
                "entry_name": entry_name,
                "class_name": class_name,
                "mapped_class_name": (
                    class_mapping.official_name if class_mapping is not None else None
                ),
                "method_name": str(method["name"]),
                "mapped_method_names": [
                    member.official_name for member in mapped_method_members
                ],
                "method_descriptor": str(method["descriptor"]),
                "instruction_count": len(instructions),
                "xref_count": len(xrefs),
                "truncated": truncated,
                "bci_start": bci_start,
                "bci_end": bci_end,
            },
            tags=["java", "bytecode", "disassembly"],
        )
    )

    return JavaViewBytecodeResult(
        archive_path=str(archive_path),
        class_found=True,
        method_found=True,
        matched_by=matched_by,
        entry_name=entry_name,
        class_name=class_name,
        dotted_class_name=_dotted(class_name),
        mapped_class_name=(
            class_mapping.official_name if class_mapping is not None else None
        ),
        method_name=str(method["name"]),
        mapped_method_names=[member.official_name for member in mapped_method_members],
        mapped_method_signatures=[
            member.official_signature for member in mapped_method_members
        ],
        method_descriptor=str(method["descriptor"]),
        max_stack=int(code["max_stack"]),
        max_locals=int(code["max_locals"]),
        code_length=int(code["code_length"]),
        instructions=instructions,
        xrefs=xrefs,
        truncated=truncated,
        bytecode_node_id=bytecode_node.id,
    )


def _select_method(
    *,
    parsed: dict[str, Any],
    mappings: ProguardMappings | None,
    class_mapping: ProguardClassMapping | None,
    method_name: str,
    method_descriptor: str | None,
) -> dict[str, Any] | None:
    for method in parsed["methods"]:
        if not isinstance(method, dict):
            continue
        if (
            method_descriptor is not None
            and str(method["descriptor"]) != method_descriptor
        ):
            continue
        if str(method["name"]) == method_name:
            return method
        mapped_names = [
            member.official_name
            for member in _mapped_method_members(
                mappings=mappings,
                class_mapping=class_mapping,
                method=method,
            )
        ]
        if method_name in mapped_names:
            return method
    return None


def _instruction_summary(
    instruction: dict[str, Any],
    line_numbers: list[dict[str, int]],
) -> JavaBytecodeInstruction:
    bci = int(instruction["bci"])
    operands = instruction.get("operands", [])
    return JavaBytecodeInstruction(
        bci=bci,
        line_number=_line_number_for_bci(line_numbers, bci),
        opcode=int(instruction["opcode"]),
        mnemonic=str(instruction["mnemonic"]),
        operands=[str(operand) for operand in operands if isinstance(operand, str)],
        length=int(instruction["length"]),
    )


def _xref_summary(
    xref: dict[str, Any],
    line_numbers: list[dict[str, int]],
) -> JavaBytecodeXref:
    bci = int(xref["bci"])
    opcode = xref.get("opcode")
    string_value = xref.get("string_value")
    return JavaBytecodeXref(
        bci=bci,
        line_number=_line_number_for_bci(line_numbers, bci),
        opcode=opcode if isinstance(opcode, int) else None,
        kind=str(xref.get("kind", "")),
        owner=str(xref.get("owner", "")),
        name=str(xref.get("name", "")),
        descriptor=str(xref.get("descriptor", "")),
        target=str(xref.get("target", "")),
        string_value=string_value if isinstance(string_value, str) else None,
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


def _bci_in_range(
    bci: int,
    bci_start: int | None,
    bci_end: int | None,
) -> bool:
    if bci_start is not None and bci < bci_start:
        return False
    return not (bci_end is not None and bci > bci_end)


def _lookup_class_mapping(
    mappings: ProguardMappings | None,
    class_name: str,
) -> tuple[ProguardClassMapping | None, Literal["official", "obfuscated", "none"]]:
    if mappings is None:
        return None, "none"
    return mappings.lookup_class(class_name)


def _mapped_method_members(
    *,
    mappings: ProguardMappings | None,
    class_mapping: ProguardClassMapping | None,
    method: dict[str, Any],
) -> list[Any]:
    if mappings is None or class_mapping is None:
        return []
    return mappings.matching_member_mappings(
        class_mapping,
        kind="method",
        obfuscated_name=str(method["name"]),
        descriptor=str(method["descriptor"]),
    )


def _candidate_class_names(
    class_name: str,
    class_mapping: ProguardClassMapping | None,
) -> set[str]:
    candidates = {_internal(class_name)}
    if class_mapping is not None:
        candidates.add(_internal(class_mapping.obfuscated_name))
        candidates.add(_internal(class_mapping.official_name))
    return candidates


def _internal(class_name: str) -> str:
    return class_name.removesuffix(".class").replace(".", "/")


def _dotted(class_name: str) -> str:
    return class_name.replace("/", ".")


def build_tool() -> MemoryTool[JavaViewBytecodeArgs, JavaViewBytecodeResult]:
    return JavaViewBytecodeTool()
