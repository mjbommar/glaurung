from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Edge, Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .windows_api_contract_primitives import (
    ApiContractPrimitive,
    WindowsApiContractPrimitivesArgs,
    WindowsApiContractPrimitivesTool,
)


RuleSeverity = Literal["review", "low", "medium", "high"]


class ApiContractRuleFinding(BaseModel):
    rule_id: str
    severity: RuleSeverity
    line: int
    summary: str
    evidence: list[str] = Field(default_factory=list)
    primitive_kinds: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)


class WindowsApiContractRuleScanArgs(WindowsApiContractPrimitivesArgs):
    max_findings: int = Field(64, ge=1, description="Maximum rule findings to return.")
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact rule-scan evidence node to the KB.",
    )


class WindowsApiContractRuleScanResult(BaseModel):
    function_va: int | None = None
    findings: list[ApiContractRuleFinding]
    primitive_count: int
    primitive_counts: dict[str, int]
    pseudocode_source: str
    coverage: list[str] = Field(default_factory=list)
    missing_capabilities: list[str] = Field(default_factory=list)
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsApiContractRuleScanTool(
    MemoryTool[WindowsApiContractRuleScanArgs, WindowsApiContractRuleScanResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_api_contract_rule_scan",
                description=(
                    "Run deterministic defensive Windows API contract rules over "
                    "contract primitives: selector forwarding, zero-length probe "
                    "boundaries, error-status continuation to writes, and "
                    "user-pointer writes without a probe primitive."
                ),
                tags=("windows", "pe", "contracts", "rules", "pseudocode"),
            ),
            WindowsApiContractRuleScanArgs,
            WindowsApiContractRuleScanResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsApiContractRuleScanArgs,
    ) -> WindowsApiContractRuleScanResult:
        primitive_result = WindowsApiContractPrimitivesTool().run(
            ctx,
            kb,
            WindowsApiContractPrimitivesArgs(
                pseudocode=args.pseudocode,
                binary_path=args.binary_path,
                function_va=args.function_va,
                range_start=args.range_start,
                range_end=args.range_end,
                max_blocks=args.max_blocks,
                max_instructions=args.max_instructions,
                timeout_ms=args.timeout_ms,
                pdb_cache=args.pdb_cache,
                max_primitives=args.max_primitives,
                add_to_kb=False,
            ),
        )
        findings = _rule_findings(
            primitive_result.primitives,
            max_findings=args.max_findings,
        )

        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_api_contract_rule_scan",
                    props={
                        "function_va": args.function_va,
                        "finding_count": len(findings),
                        "primitive_counts": primitive_result.primitive_counts,
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))

        notes = [
            "rule findings are triage signals from local primitives; they are not vulnerability proof",
            *primitive_result.notes,
        ]
        return WindowsApiContractRuleScanResult(
            function_va=args.function_va,
            findings=findings,
            primitive_count=len(primitive_result.primitives),
            primitive_counts=primitive_result.primitive_counts,
            pseudocode_source=primitive_result.pseudocode_source,
            coverage=primitive_result.coverage,
            missing_capabilities=primitive_result.missing_capabilities,
            evidence_node_id=evidence_node_id,
            notes=notes,
        )


def _rule_findings(
    primitives: list[ApiContractPrimitive],
    *,
    max_findings: int,
) -> list[ApiContractRuleFinding]:
    findings: list[ApiContractRuleFinding] = []
    findings.extend(_selector_forwarding_findings(primitives))
    findings.extend(_selector_global_table_to_string_copy_findings(primitives))
    findings.extend(_zero_length_probe_findings(primitives))
    findings.extend(_error_status_then_write_findings(primitives))
    findings.extend(_user_pointer_write_without_probe_findings(primitives))
    findings.sort(key=lambda item: (item.line, item.rule_id))
    return _dedupe_findings(findings)[:max_findings]


def _selector_forwarding_findings(
    primitives: list[ApiContractPrimitive],
) -> list[ApiContractRuleFinding]:
    selector_lines = [item for item in primitives if item.kind == "selector_dispatch"]
    forwards = [item for item in primitives if item.kind == "syscall_argument_forward"]
    if not selector_lines or not forwards:
        return []
    pointer_forwards = [
        item
        for item in forwards
        if any(
            role
            in {
                "user_pointer",
                "input_buffer",
                "output_buffer",
                "return_length",
                "pointer",
            }
            for role in item.roles.values()
        )
    ]
    return [
        ApiContractRuleFinding(
            rule_id="selector_routes_pointer_to_helper",
            severity="medium",
            line=item.line,
            summary=(
                "selector-controlled path forwards pointer-like syscall/API "
                "arguments into a helper"
            ),
            evidence=[selector_lines[0].snippet, item.snippet],
            primitive_kinds=["selector_dispatch", "syscall_argument_forward"],
            confidence=min(0.80, (selector_lines[0].confidence + item.confidence) / 2),
        )
        for item in pointer_forwards
    ]


def _selector_global_table_to_string_copy_findings(
    primitives: list[ApiContractPrimitive],
) -> list[ApiContractRuleFinding]:
    selector_lines = [item for item in primitives if item.kind == "selector_dispatch"]
    indexed_tables = [
        item
        for item in selector_lines
        if item.roles.get("table") == "selector_indexed_table"
        or "table" in item.reason.lower()
    ]
    string_sinks = [
        item for item in primitives if item.kind == "string_conversion_copy"
    ]
    if not selector_lines or not indexed_tables or not string_sinks:
        return []
    findings: list[ApiContractRuleFinding] = []
    first_selector = selector_lines[0]
    first_table = indexed_tables[0]
    for sink in string_sinks:
        if sink.line <= first_selector.line:
            continue
        findings.append(
            ApiContractRuleFinding(
                rule_id="selector_global_table_to_string_copy",
                severity="high",
                line=sink.line,
                summary=(
                    "selector-controlled global/table value reaches a Windows "
                    "string conversion/copy sink"
                ),
                evidence=[first_selector.snippet, first_table.snippet, sink.snippet],
                primitive_kinds=[
                    "selector_dispatch",
                    "selector_dispatch",
                    "string_conversion_copy",
                ],
                confidence=min(
                    0.86,
                    (
                        first_selector.confidence
                        + first_table.confidence
                        + sink.confidence
                    )
                    / 3,
                ),
            )
        )
    return findings


def _zero_length_probe_findings(
    primitives: list[ApiContractPrimitive],
) -> list[ApiContractRuleFinding]:
    probes = [
        item
        for item in primitives
        if item.kind in {"probe_for_read", "probe_for_write"}
        and item.roles.get("length") == "length"
    ]
    zero_checks = [
        item
        for item in primitives
        if item.kind == "length_comparison" and "zero boundary" in item.reason
    ]
    if not probes or not zero_checks:
        return []
    findings: list[ApiContractRuleFinding] = []
    for probe in probes:
        nearest = min(zero_checks, key=lambda item: abs(item.line - probe.line))
        if abs(nearest.line - probe.line) > 12:
            continue
        findings.append(
            ApiContractRuleFinding(
                rule_id="zero_length_probe_boundary",
                severity="review",
                line=probe.line,
                summary=(
                    "probe length is variable and nearby logic has a zero-length boundary"
                ),
                evidence=[nearest.snippet, probe.snippet],
                primitive_kinds=[nearest.kind, probe.kind],
                confidence=min(0.70, (nearest.confidence + probe.confidence) / 2),
            )
        )
    return findings


def _error_status_then_write_findings(
    primitives: list[ApiContractPrimitive],
) -> list[ApiContractRuleFinding]:
    errors = [item for item in primitives if item.kind == "error_status_assignment"]
    writes = [
        item
        for item in primitives
        if item.kind in {"pointer_write", "return_length_write", "user_buffer_copy"}
    ]
    gates = [item for item in primitives if item.kind == "ntstatus_gate"]
    findings: list[ApiContractRuleFinding] = []
    for error in errors:
        next_gate_line = min(
            (gate.line for gate in gates if gate.line > error.line),
            default=10**9,
        )
        for write in writes:
            if not (
                error.line < write.line < next_gate_line
                and write.line - error.line <= 12
            ):
                continue
            rule_id = (
                "return_length_write_after_error_status"
                if write.kind == "return_length_write"
                else "write_after_error_status"
            )
            findings.append(
                ApiContractRuleFinding(
                    rule_id=rule_id,
                    severity="medium",
                    line=write.line,
                    summary=(
                        "execution appears to continue from an error-status assignment "
                        "to a pointer/copy write before an NTSTATUS gate"
                    ),
                    evidence=[error.snippet, write.snippet],
                    primitive_kinds=[error.kind, write.kind],
                    confidence=min(0.76, (error.confidence + write.confidence) / 2),
                )
            )
    return findings


def _user_pointer_write_without_probe_findings(
    primitives: list[ApiContractPrimitive],
) -> list[ApiContractRuleFinding]:
    has_probe = any(
        item.kind in {"probe_for_read", "probe_for_write"} for item in primitives
    )
    if has_probe:
        return []
    findings: list[ApiContractRuleFinding] = []
    for item in primitives:
        if item.kind not in {
            "pointer_write",
            "return_length_write",
            "user_buffer_copy",
            "string_conversion_copy",
        }:
            continue
        roles = set(item.roles.values())
        if roles and not roles.intersection(
            {
                "user_pointer",
                "input_buffer",
                "output_buffer",
                "return_length",
                "pointer",
            }
        ):
            continue
        findings.append(
            ApiContractRuleFinding(
                rule_id="user_pointer_write_without_probe",
                severity="review",
                line=item.line,
                summary=(
                    "pointer-like write/copy appears in a function with no local "
                    "ProbeForRead/ProbeForWrite primitive"
                ),
                evidence=[item.snippet],
                primitive_kinds=[item.kind],
                confidence=min(0.58, item.confidence),
            )
        )
    return findings


def _dedupe_findings(
    findings: list[ApiContractRuleFinding],
) -> list[ApiContractRuleFinding]:
    out: list[ApiContractRuleFinding] = []
    seen: set[tuple[str, int, str]] = set()
    for finding in findings:
        key = (finding.rule_id, finding.line, finding.summary)
        if key in seen:
            continue
        seen.add(key)
        out.append(finding)
    return out


def build_tool() -> MemoryTool[
    WindowsApiContractRuleScanArgs,
    WindowsApiContractRuleScanResult,
]:
    return WindowsApiContractRuleScanTool()
