from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Edge, Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .windows_function_start_explain import (
    DEFAULT_COMPARISON,
    DEFAULT_DIAGNOSTICS,
    CodePointerRef,
    Confidence,
    FunctionStartState,
    WindowsFunctionStartExplainArgs,
    WindowsFunctionStartExplainTool,
)


DataRefVerdict = Literal[
    "accept_function_start",
    "keep_candidate",
    "reject_function_start",
    "not_data_ref_start",
]


class WindowsDataRefConfidenceArgs(BaseModel):
    comparison_path: str | None = Field(
        None,
        description=(
            "Path to a Glaurung/Ghidra comparison JSON. Defaults to the "
            "30-file post-tiny-stub-gate dashboard in docs/windows-port."
        ),
    )
    diagnostics_path: str | None = Field(
        None,
        description=(
            "Path to per-address diagnostics JSON. Defaults to the 30-file "
            "diagnostics artifact in docs/windows-port."
        ),
    )
    file: str = Field(
        ...,
        description="Binary filename or unique path substring from the comparison artifact.",
    )
    va: int | None = Field(
        None,
        description="Virtual address to classify. Use either va or address.",
    )
    address: str | None = Field(
        None,
        description="Hex virtual address to classify, such as 0x1400074b0.",
    )
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact data-ref confidence evidence node.",
    )


class DataRefConfidenceRef(BaseModel):
    source_va: int | None = None
    source: str | None = None
    pointer_va: int | None = None
    pointer: str | None = None
    target_va: int
    target: str
    section: str | None = None
    slot_size: int | None = None
    table_index: int | None = None
    table_length: int | None = None
    confidence: str | None = None
    relocation_backed: bool | None = None
    detail: str | None = None


class WindowsDataRefConfidenceResult(BaseModel):
    file: str
    path: str
    va: int
    address: str
    final_state: FunctionStartState
    verdict: DataRefVerdict
    confidence: Confidence
    data_ref_seeded: bool
    reason_codes: list[str] = Field(default_factory=list)
    refs: list[DataRefConfidenceRef] = Field(default_factory=list)
    bytes_hex: str | None = None
    recommended_action: str
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsDataRefConfidenceTool(
    MemoryTool[WindowsDataRefConfidenceArgs, WindowsDataRefConfidenceResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_data_ref_confidence",
                description=(
                    "Explain confidence for a Windows data-reference function "
                    "start using table provenance, section mutability, padding "
                    "gates, and function-start state."
                ),
                tags=("windows", "pe", "data-ref", "function-start", "confidence"),
            ),
            WindowsDataRefConfidenceArgs,
            WindowsDataRefConfidenceResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsDataRefConfidenceArgs,
    ) -> WindowsDataRefConfidenceResult:
        explain_tool = WindowsFunctionStartExplainTool()
        explained = explain_tool.run(
            ctx,
            kb,
            WindowsFunctionStartExplainArgs(
                comparison_path=args.comparison_path or str(DEFAULT_COMPARISON),
                diagnostics_path=args.diagnostics_path or str(DEFAULT_DIAGNOSTICS),
                file=args.file,
                va=args.va,
                address=args.address,
                max_refs=16,
            ),
        )
        refs = _data_ref_refs(explained)
        data_ref_seeded = "data_ref" in explained.seed_kinds or bool(refs)
        reason_codes = _reason_codes(explained.reason_codes, refs, data_ref_seeded)
        verdict = _verdict(explained.final_state, data_ref_seeded, reason_codes)
        confidence = _confidence(verdict, reason_codes)
        result = WindowsDataRefConfidenceResult(
            file=explained.file,
            path=explained.path,
            va=explained.va,
            address=explained.address,
            final_state=explained.final_state,
            verdict=verdict,
            confidence=confidence,
            data_ref_seeded=data_ref_seeded,
            reason_codes=reason_codes,
            refs=refs,
            bytes_hex=None if explained.bytes is None else explained.bytes.hex,
            recommended_action=_recommended_action(verdict),
            notes=[
                "Data-reference confidence is boundary evidence, not a vulnerability claim."
            ],
        )

        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_data_ref_confidence",
                    props={
                        "file": result.file,
                        "address": result.address,
                        "verdict": result.verdict,
                        "confidence": result.confidence,
                        "data_ref_seeded": result.data_ref_seeded,
                    },
                )
            )
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))
            result = result.model_copy(update={"evidence_node_id": node.id})

        return result


def _data_ref_refs(explained: object) -> list[DataRefConfidenceRef]:
    refs: list[DataRefConfidenceRef] = []
    for ref in getattr(explained, "code_pointer_refs", []) or []:
        if isinstance(ref, CodePointerRef):
            refs.append(
                DataRefConfidenceRef(
                    pointer_va=ref.pointer_va,
                    pointer=ref.pointer,
                    target_va=ref.target_va,
                    target=ref.target,
                    section=ref.section,
                    slot_size=ref.slot_size,
                    table_index=ref.table_index,
                    table_length=ref.table_length,
                    confidence=ref.confidence,
                    relocation_backed=ref.relocation_backed,
                )
            )
    for prov in getattr(explained, "provenance", []) or []:
        if getattr(prov, "kind", None) != "data_ref":
            continue
        parsed = _parse_provenance_detail(
            getattr(prov, "detail", None),
            getattr(explained, "va", 0),
            getattr(explained, "address", "0x0"),
        )
        parsed.source_va = getattr(prov, "source_va", None)
        parsed.source = getattr(prov, "source", None) or _hex(parsed.source_va)
        if not _already_has_ref(refs, parsed):
            refs.append(parsed)
    return refs


def _parse_provenance_detail(
    detail: str | None,
    target_va: int,
    target: str,
) -> DataRefConfidenceRef:
    parsed = DataRefConfidenceRef(
        target_va=int(target_va),
        target=target,
        detail=detail,
    )
    if not detail:
        return parsed
    match = re.match(
        r"^pe_code_pointer:(?P<section>[^:]+):slot(?P<slot>\d+):"
        r"table(?P<table>\d+):len(?P<length>\d+):(?P<confidence>[^:]+)$",
        detail,
    )
    if not match:
        return parsed
    parsed.section = match.group("section")
    parsed.slot_size = int(match.group("slot"))
    parsed.table_index = int(match.group("table"))
    parsed.table_length = int(match.group("length"))
    parsed.confidence = match.group("confidence")
    return parsed


def _already_has_ref(
    refs: list[DataRefConfidenceRef],
    candidate: DataRefConfidenceRef,
) -> bool:
    for ref in refs:
        if (
            ref.target_va == candidate.target_va
            and ref.section == candidate.section
            and ref.table_index == candidate.table_index
            and ref.table_length == candidate.table_length
        ):
            return True
    return False


def _reason_codes(
    start_reason_codes: list[str],
    refs: list[DataRefConfidenceRef],
    data_ref_seeded: bool,
) -> list[str]:
    codes: list[str] = []
    if data_ref_seeded:
        codes.append("data_ref_seed")
    for code in start_reason_codes:
        if code in {
            "padding_run",
            "code_pointer_ref",
            "glaurung_only",
            "strict_function",
            "data_ref_seed",
            "data_ref_provenance",
        }:
            codes.append(code)
    if refs:
        codes.append("code_pointer_table")
    for ref in refs:
        if ref.section in {".rdata", "rdata"}:
            codes.append("read_only_table_section")
        elif ref.section in {".data", "data"}:
            codes.append("writable_table_section")
        if ref.table_length is not None:
            if ref.table_length >= 16:
                codes.append("long_table")
            elif ref.table_length <= 2:
                codes.append("short_table")
            else:
                codes.append("small_table")
        if ref.slot_size in {4, 8}:
            codes.append("pointer_sized_slot")
        if ref.confidence:
            codes.append(f"{ref.confidence}_table_confidence")
        if ref.relocation_backed is True:
            codes.append("relocation_backed")
        elif ref.relocation_backed is False:
            codes.append("not_relocation_backed")
    if "padding_run" not in codes:
        codes.append("not_padding")
    return _dedupe(codes)


def _verdict(
    final_state: FunctionStartState,
    data_ref_seeded: bool,
    reason_codes: list[str],
) -> DataRefVerdict:
    if not data_ref_seeded:
        return "not_data_ref_start"
    if "padding_run" in reason_codes:
        return "reject_function_start"
    if final_state == "strict_function" and (
        "read_only_table_section" in reason_codes or "long_table" in reason_codes
    ):
        return "accept_function_start"
    return "keep_candidate"


def _confidence(verdict: DataRefVerdict, reason_codes: list[str]) -> Confidence:
    if verdict in {"accept_function_start", "reject_function_start"}:
        return "high"
    if "code_pointer_table" in reason_codes:
        return "medium"
    if verdict == "not_data_ref_start":
        return "low"
    return "unknown"


def _recommended_action(verdict: DataRefVerdict) -> str:
    if verdict == "accept_function_start":
        return "keep_data_ref_function_start"
    if verdict == "reject_function_start":
        return "demote_to_rejected_start"
    if verdict == "not_data_ref_start":
        return "use_function_start_explain"
    return "keep_as_candidate_pending_boundary_evidence"


def _hex(value: int | None) -> str | None:
    return None if value is None else f"0x{int(value):x}"


def _dedupe(values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value and value not in seen:
            seen.add(value)
            out.append(value)
    return out


def build_tool() -> WindowsDataRefConfidenceTool:
    return WindowsDataRefConfidenceTool()
