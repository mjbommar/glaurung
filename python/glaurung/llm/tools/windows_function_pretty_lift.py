from __future__ import annotations

import re
from collections import Counter
from functools import lru_cache
from pathlib import Path
from typing import Iterable, Literal, TypedDict

from pydantic import BaseModel, Field

import glaurung as g

from ..context import MemoryContext
from ..kb.models import Edge, Node, NodeKind
from ..kb.persistent import PersistentKnowledgeBase
from ..kb.store import KnowledgeBase
from ..kb import windows_boundaries, xref_db
from .base import MemoryTool, ToolMeta
from .windows_api_contract_primitives import (
    ApiContractPrimitive,
    _calls as _primitive_calls,
    _extract_primitives,
    _parameters,
    _split_args,
)


FindingSeverity = Literal["info", "warning", "error", "critical"]


class LiftArgumentRole(BaseModel):
    original_name: str
    semantic_name: str
    c_type: str
    role: str
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[str] = Field(default_factory=list)


class LiftFact(BaseModel):
    kind: str
    key: str
    value: str
    line: int | None = None
    snippet: str | None = None
    confidence: float = Field(ge=0.0, le=1.0, default=0.7)
    inferred: bool = False


class SelectorTableFact(BaseModel):
    index_expression: str
    table_expression: str
    table_name: str
    count_expression: str | None = None
    count_name: str | None = None
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[str] = Field(default_factory=list)


class StringCopyFact(BaseModel):
    call_name: str
    dst_expression: str
    dst_offset: int | None = None
    dst_length_expression: str
    dst_length: int | None = None
    src_expression: str
    src_offset: int | None = None
    line: int
    snippet: str
    confidence: float = Field(ge=0.0, le=1.0)


class OutputWriteFact(BaseModel):
    lhs_expression: str
    output_offset: int | None = None
    rhs_expression: str
    source_offset: int | None = None
    line: int
    snippet: str
    confidence: float = Field(ge=0.0, le=1.0)


class MemoryAccessFact(BaseModel):
    kind: Literal["read", "write"]
    expression: str
    base: str | None = None
    offset: int | None = None
    index: str | None = None
    scale: int | None = None
    absolute_address: int | None = None
    width_bits: int | None = None
    role: str
    line: int
    snippet: str
    confidence: float = Field(ge=0.0, le=1.0)


class FieldOffsetGroupFact(BaseModel):
    base: str
    role: str
    read_offsets: list[int] = Field(default_factory=list)
    write_offsets: list[int] = Field(default_factory=list)
    access_count: int
    max_offset: int | None = None
    line_start: int
    line_end: int
    confidence: float = Field(ge=0.0, le=1.0)


class DataReferenceFact(BaseModel):
    kind: Literal[
        "global_address",
        "global_memory",
        "global_count",
        "selector_table_load",
        "absolute_call",
        "callback_pointer",
        "function_pointer_table",
        "jump_table",
        "import_thunk",
        "vtable_dispatch",
    ]
    expression: str
    address: int | None = None
    base: str | None = None
    offset: int | None = None
    index: str | None = None
    scale: int | None = None
    target_symbol: str | None = None
    role: str
    line: int
    snippet: str
    confidence: float = Field(ge=0.0, le=1.0)


class PathConditionFact(BaseModel):
    role: str
    expression: str
    lhs_expression: str | None = None
    operator: str | None = None
    rhs_expression: str | None = None
    condition_kind: str
    flag_name: str | None = None
    target_label: str | None = None
    line: int
    branch_line: int | None = None
    snippet: str
    confidence: float = Field(ge=0.0, le=1.0)


class LoopSummaryFact(BaseModel):
    loop_label: str
    header_line: int
    backedge_line: int
    body_line_start: int
    body_line_end: int
    condition_expression: str | None = None
    exit_label: str | None = None
    calls: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)


class PrototypeParameterFact(BaseModel):
    index: int
    name: str
    c_type: str
    role: str | None = None


class PrototypeFact(BaseModel):
    symbol: str
    prototype: str
    return_type: str | None = None
    parameters: list[PrototypeParameterFact] = Field(default_factory=list)
    is_variadic: bool = False
    source: str
    module: str | None = None
    calling_convention: str | None = None
    confidence: float = Field(ge=0.0, le=1.0)
    provenance: list[str] = Field(default_factory=list)


class EntryAbiArgumentFact(BaseModel):
    index: int
    abi_location: Literal["register", "stack"]
    register_name: str | None = None
    stack_offset: int | None = None
    original_name: str
    semantic_name: str
    c_type: str
    role: str | None = None
    source: str
    confidence: float = Field(ge=0.0, le=1.0)


class CallSiteArgumentFact(BaseModel):
    index: int
    expression: str
    abi_location: Literal["register", "stack"]
    register_name: str | None = None
    stack_offset: int | None = None
    parameter_name: str | None = None
    c_type: str | None = None
    role: str | None = None
    source: str
    confidence: float = Field(ge=0.0, le=1.0)


class CallSiteFact(BaseModel):
    order: int
    call_name: str
    original_name: str
    arguments: list[str] = Field(default_factory=list)
    argument_facts: list[CallSiteArgumentFact] = Field(default_factory=list)
    line: int
    snippet: str
    return_value_used: bool = False
    return_target: str | None = None
    role: str
    prototype: PrototypeFact | None = None
    confidence: float = Field(ge=0.0, le=1.0)


class UnknownSectionFact(BaseModel):
    kind: Literal["unknown_operation", "unresolved_symbol"]
    label: str
    reason: str
    line: int
    snippet: str
    confidence: float = Field(ge=0.0, le=1.0)


class WindowsFunctionLiftPacket(BaseModel):
    binary_path: str | None = None
    function_va: int | None = None
    address: str | None = None
    function_name: str
    raw_pseudocode: str
    pseudocode_source: str
    argument_roles: dict[str, LiftArgumentRole] = Field(default_factory=dict)
    facts: list[LiftFact] = Field(default_factory=list)
    primitives: list[ApiContractPrimitive] = Field(default_factory=list)
    primitive_counts: dict[str, int] = Field(default_factory=dict)
    call_counts: dict[str, int] = Field(default_factory=dict)
    call_sites: list[CallSiteFact] = Field(default_factory=list)
    entry_abi_arguments: list[EntryAbiArgumentFact] = Field(default_factory=list)
    unknown_sections: list[UnknownSectionFact] = Field(default_factory=list)
    function_prototype: PrototypeFact | None = None
    call_prototypes: list[PrototypeFact] = Field(default_factory=list)
    selector_table: SelectorTableFact | None = None
    string_copies: list[StringCopyFact] = Field(default_factory=list)
    output_writes: list[OutputWriteFact] = Field(default_factory=list)
    memory_accesses: list[MemoryAccessFact] = Field(default_factory=list)
    field_offset_groups: list[FieldOffsetGroupFact] = Field(default_factory=list)
    data_references: list[DataReferenceFact] = Field(default_factory=list)
    path_conditions: list[PathConditionFact] = Field(default_factory=list)
    loop_summaries: list[LoopSummaryFact] = Field(default_factory=list)
    output_size: int | None = None
    return_statuses: list[str] = Field(default_factory=list)
    required_facts: list[str] = Field(default_factory=list)
    coverage: list[str] = Field(default_factory=list)
    missing_capabilities: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class PrettyLift(BaseModel):
    function_name: str
    prototype: str
    pseudocode: str
    confidence: float = Field(ge=0.0, le=1.0)
    quality_score: float = Field(0.0, ge=0.0, le=1.0)
    assumptions: list[str] = Field(default_factory=list)
    evidence_line_map: dict[int, list[str]] = Field(default_factory=dict)


class PrettyLiftValidationFinding(BaseModel):
    severity: FindingSeverity
    fact: str
    message: str
    evidence: list[str] = Field(default_factory=list)


class PrettyLiftValidation(BaseModel):
    valid: bool
    quality_score: float = Field(ge=0.0, le=1.0)
    preserved_facts: list[str] = Field(default_factory=list)
    missing_facts: list[str] = Field(default_factory=list)
    findings: list[PrettyLiftValidationFinding] = Field(default_factory=list)


class WindowsFunctionPrettyLiftArgs(BaseModel):
    pseudocode: str | None = Field(
        None,
        description="Optional Glaurung decompiler text to packetize and prettify.",
    )
    binary_path: str | None = Field(
        None,
        description="Optional PE path. Defaults to the active context file.",
    )
    project_path: str | None = Field(
        None,
        description="Optional .glaurung project path for function names.",
    )
    function_va: int | None = Field(
        None,
        description="Function entry VA when decompiling from a binary.",
    )
    range_start: int | None = Field(
        None,
        description="Optional explicit range start for decompile_range_at.",
    )
    range_end: int | None = Field(
        None,
        description="Optional explicit range end for decompile_range_at.",
    )
    function_name: str | None = Field(
        None,
        description="Optional trusted symbol/name to use in the pretty lift.",
    )
    pdb_cache: str = Field("", description="Optional Microsoft PDB cache path.")
    max_blocks: int = Field(1024, ge=1, description="Decompiler block budget.")
    max_instructions: int = Field(
        50_000, ge=1, description="Decompiler instruction budget."
    )
    timeout_ms: int = Field(5_000, ge=1, description="Decompiler timeout.")
    candidate_pretty_pseudocode: str | None = Field(
        None,
        description="Optional model-produced C-like lift to validate instead of the deterministic renderer.",
    )
    candidate_prototype: str | None = Field(
        None,
        description="Optional prototype for candidate_pretty_pseudocode.",
    )
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact pretty-lift evidence node.",
    )


class WindowsFunctionPrettyLiftResult(BaseModel):
    packet: WindowsFunctionLiftPacket
    pretty_lift: PrettyLift
    validation: PrettyLiftValidation
    evidence_node_id: str | None = None


class WindowsFunctionPrettyLiftTool(
    MemoryTool[WindowsFunctionPrettyLiftArgs, WindowsFunctionPrettyLiftResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_function_pretty_lift",
                description=(
                    "Build an evidence-backed Windows function lift packet, "
                    "render cleaner C-like pseudocode, and validate that the "
                    "pretty lift preserves calls, constants, writes, and "
                    "security-relevant primitives."
                ),
                tags=("windows", "pe", "decompile", "llm", "lift"),
            ),
            WindowsFunctionPrettyLiftArgs,
            WindowsFunctionPrettyLiftResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsFunctionPrettyLiftArgs,
    ) -> WindowsFunctionPrettyLiftResult:
        text, source, scan_notes = _scan_text(ctx, args)
        function_name = _resolve_function_name(args, text)
        packet = build_lift_packet(
            text,
            function_name=function_name,
            function_va=args.function_va,
            binary_path=args.binary_path or str(ctx.file_path),
            project_path=args.project_path,
            source=source,
            notes=scan_notes,
        )

        if args.candidate_pretty_pseudocode:
            pretty = PrettyLift(
                function_name=packet.function_name,
                prototype=args.candidate_prototype
                or _default_prototype(packet, packet.function_name),
                pseudocode=args.candidate_pretty_pseudocode,
                confidence=0.55,
                assumptions=[
                    "candidate pretty lift supplied externally; validator checked deterministic facts"
                ],
            )
        else:
            pretty = render_pretty_lift(packet)
        validation = validate_pretty_lift(packet, pretty)
        pretty = pretty.model_copy(update={"quality_score": validation.quality_score})

        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_function_pretty_lift",
                    props={
                        "function_va": packet.function_va,
                        "function_name": packet.function_name,
                        "pseudocode_source": packet.pseudocode_source,
                        "quality_score": validation.quality_score,
                        "valid": validation.valid,
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))

        return WindowsFunctionPrettyLiftResult(
            packet=packet,
            pretty_lift=pretty,
            validation=validation,
            evidence_node_id=evidence_node_id,
        )


def build_lift_packet(
    pseudocode: str,
    *,
    function_name: str,
    function_va: int | None = None,
    binary_path: str | None = None,
    project_path: str | None = None,
    source: str = "supplied_pseudocode",
    notes: list[str] | None = None,
) -> WindowsFunctionLiftPacket:
    parameters = _parameters(pseudocode)
    primitives = _extract_primitives(
        pseudocode,
        parameters,
        source=source,
        max_primitives=512,
    )
    primitive_counts = Counter(str(item.kind) for item in primitives)
    call_counts = _call_counts(pseudocode)
    project_prototypes = _project_prototypes(project_path, binary_path)
    aliases = _assignment_aliases(pseudocode)
    var_constants = _variable_constants(pseudocode)
    output_var = _output_buffer_var(pseudocode)
    output_size = _output_size(pseudocode)
    argument_roles = _argument_roles(
        pseudocode,
        aliases=aliases,
        output_var=output_var,
        output_size=output_size,
        function_name=function_name,
    )
    function_prototype = _prototype_fact_for_symbol(
        function_name,
        project_prototypes=project_prototypes,
        kind="function",
    )
    entry_abi_arguments = _entry_abi_argument_facts(
        function_prototype=function_prototype,
        argument_roles=argument_roles,
    )
    import_thunk_aliases = _import_thunk_call_aliases(pseudocode)
    call_prototypes = _call_prototype_facts(
        call_counts,
        project_prototypes=project_prototypes,
        extra_symbols=import_thunk_aliases.values(),
    )
    call_sites = _call_site_facts(
        pseudocode,
        call_prototypes=call_prototypes,
        import_thunk_aliases=import_thunk_aliases,
    )
    call_prototypes = _merge_call_prototypes(
        call_prototypes,
        [
            site.prototype
            for site in call_sites
            if site.prototype is not None and site.prototype.source == "inferred_local"
        ],
    )
    unknown_sections = _unknown_section_facts(pseudocode)
    selector_table = _selector_table_fact(pseudocode, function_name=function_name)
    string_copies = _string_copy_facts(pseudocode, var_constants=var_constants)
    output_writes = _output_write_facts(pseudocode, output_var=output_var)
    memory_accesses = _memory_access_facts(
        pseudocode,
        output_var=output_var,
        selector_table=selector_table,
    )
    field_offset_groups = _field_offset_group_facts(memory_accesses)
    data_references = _data_reference_facts(
        pseudocode,
        memory_accesses=memory_accesses,
        selector_table=selector_table,
    )
    path_conditions = _path_condition_facts(
        pseudocode,
        argument_roles=argument_roles,
        output_size=output_size,
        selector_table=selector_table,
    )
    loop_summaries = _loop_summary_facts(pseudocode)
    return_statuses = _return_statuses(
        function_name=function_name,
        output_size=output_size,
        selector_table=selector_table,
    )
    facts = _facts(
        argument_roles=argument_roles,
        function_prototype=function_prototype,
        entry_abi_arguments=entry_abi_arguments,
        call_prototypes=call_prototypes,
        selector_table=selector_table,
        string_copies=string_copies,
        output_writes=output_writes,
        memory_accesses=memory_accesses,
        field_offset_groups=field_offset_groups,
        data_references=data_references,
        path_conditions=path_conditions,
        loop_summaries=loop_summaries,
        output_size=output_size,
        return_statuses=return_statuses,
        call_counts=call_counts,
        call_sites=call_sites,
        unknown_sections=unknown_sections,
    )
    required_facts = _required_facts(
        call_counts=call_counts,
        call_sites=call_sites,
        output_size=output_size,
        string_copies=string_copies,
        output_writes=output_writes,
        field_offset_groups=field_offset_groups,
        data_references=data_references,
        return_statuses=return_statuses,
    )
    coverage, missing = _coverage(
        pseudocode=pseudocode,
        primitives=primitives,
        argument_roles=argument_roles,
        function_prototype=function_prototype,
        entry_abi_arguments=entry_abi_arguments,
        call_prototypes=call_prototypes,
        call_sites=call_sites,
        unknown_sections=unknown_sections,
        selector_table=selector_table,
        string_copies=string_copies,
        output_writes=output_writes,
        memory_accesses=memory_accesses,
        field_offset_groups=field_offset_groups,
        data_references=data_references,
        path_conditions=path_conditions,
        loop_summaries=loop_summaries,
        output_size=output_size,
    )
    return WindowsFunctionLiftPacket(
        binary_path=binary_path,
        function_va=function_va,
        address=f"0x{function_va:x}" if function_va is not None else None,
        function_name=function_name,
        raw_pseudocode=pseudocode,
        pseudocode_source=source,
        argument_roles=argument_roles,
        facts=facts,
        primitives=primitives,
        primitive_counts={str(k): int(v) for k, v in primitive_counts.items()},
        call_counts={str(k): int(v) for k, v in call_counts.items()},
        call_sites=call_sites,
        entry_abi_arguments=entry_abi_arguments,
        unknown_sections=unknown_sections,
        function_prototype=function_prototype,
        call_prototypes=call_prototypes,
        selector_table=selector_table,
        string_copies=string_copies,
        output_writes=output_writes,
        memory_accesses=memory_accesses,
        field_offset_groups=field_offset_groups,
        data_references=data_references,
        path_conditions=path_conditions,
        loop_summaries=loop_summaries,
        output_size=output_size,
        return_statuses=return_statuses,
        required_facts=required_facts,
        coverage=coverage,
        missing_capabilities=missing,
        notes=(notes or [])
        + [
            "pretty lift is an evidence-backed analyst view, not a replacement for raw IR"
        ],
    )


def render_pretty_lift(packet: WindowsFunctionLiftPacket) -> PrettyLift:
    if _looks_like_selector_table_string_lift(packet):
        return _render_selector_table_string_lift(packet)
    if _looks_like_syscall_stub(packet):
        return _render_syscall_stub(packet)
    if _looks_like_bool_status_wrapper(packet):
        return _render_bool_status_wrapper(packet)
    if _looks_like_ioctl_wrapper(packet):
        return _render_ioctl_wrapper(packet)
    if _looks_like_guarded_callback(packet):
        return _render_guarded_callback(packet)
    if packet.unknown_sections or packet.loop_summaries:
        return _render_generic_lift(packet)
    if _looks_like_simple_forwarder(packet):
        return _render_simple_forwarder(packet)
    if _looks_like_call_sequence(packet):
        return _render_call_sequence(packet)
    return _render_generic_lift(packet)


def validate_pretty_lift(
    packet: WindowsFunctionLiftPacket,
    pretty_lift: PrettyLift,
) -> PrettyLiftValidation:
    text = pretty_lift.pseudocode
    lowered = text.lower()
    preserved: list[str] = []
    missing: list[str] = []
    findings: list[PrettyLiftValidationFinding] = []

    if not packet.raw_pseudocode.strip():
        missing.append("raw_pseudocode")
        findings.append(
            PrettyLiftValidationFinding(
                severity="error",
                fact="raw_pseudocode",
                message="no raw Glaurung pseudocode was available to validate the pretty lift",
            )
        )

    if packet.missing_capabilities and "raw_pseudocode" in packet.missing_capabilities:
        missing.append("raw_pseudocode")

    for call_name, expected_count in packet.call_counts.items():
        if call_name.lower() in _CONTROL_CALLS:
            continue
        if expected_count <= 0:
            continue
        actual = len(re.findall(rf"\b{re.escape(call_name)}\s*\(", text))
        fact = f"calls:{call_name}"
        if actual > 0:
            preserved.append(fact)
            if actual < expected_count and call_name == "CmpQueryDowncastString":
                findings.append(
                    PrettyLiftValidationFinding(
                        severity="warning",
                        fact=fact,
                        message=(
                            f"pretty lift shows {actual} {call_name} call(s), "
                            f"raw IR has {expected_count}"
                        ),
                    )
                )
        elif call_name in {"memset", "CmpQueryDowncastString"}:
            missing.append(fact)
            findings.append(
                PrettyLiftValidationFinding(
                    severity="error",
                    fact=fact,
                    message=f"pretty lift omitted required call {call_name}",
                )
            )

    ordered_sites = _orderable_call_sites(packet)
    if len(ordered_sites) >= 2 and len({site.call_name for site in ordered_sites}) >= 2:
        if _call_order_preserved(text, ordered_sites):
            preserved.append("call_order")
        else:
            missing.append("call_order")
            findings.append(
                PrettyLiftValidationFinding(
                    severity="error",
                    fact="call_order",
                    message="pretty lift reordered or omitted the recovered call sequence",
                    evidence=[site.snippet for site in ordered_sites[:8]],
                )
            )

    for site in packet.call_sites:
        if site.return_target is not None:
            fact = f"call_site_return:{_call_site_key(site)}:{site.return_target}"
            if _call_site_return_target_preserved(text, site):
                preserved.append(fact)
            else:
                missing.append(fact)
                findings.append(
                    PrettyLiftValidationFinding(
                        severity="warning",
                        fact=fact,
                        message=(
                            "pretty lift omitted the recovered call return target"
                        ),
                        evidence=[site.snippet],
                    )
                )
        for argument in site.argument_facts:
            fact = (
                f"call_site_argument:{_call_site_key(site)}:"
                f"{_call_site_argument_key(argument)}"
            )
            if _call_site_argument_preserved(text, argument):
                preserved.append(fact)
                continue
            if not _is_required_call_site_argument(argument):
                continue
            missing.append(fact)
            findings.append(
                PrettyLiftValidationFinding(
                    severity="error",
                    fact=fact,
                    message=(
                        "pretty lift omitted a required prototype-backed "
                        "callsite argument"
                    ),
                    evidence=[site.snippet],
                )
            )

    if packet.output_size is not None:
        fact = f"constant:{_hex(packet.output_size)}"
        if _contains_int(text, packet.output_size):
            preserved.append(fact)
        else:
            missing.append(fact)
            findings.append(
                PrettyLiftValidationFinding(
                    severity="error",
                    fact=fact,
                    message="pretty lift omitted the output-size gate/return length constant",
                )
            )

    for write in packet.output_writes:
        if not _is_required_output_write(write):
            continue
        fact = f"output_write:{_output_write_key(write)}"
        if _output_write_preserved(text, write):
            preserved.append(fact)
            continue
        missing.append(fact)
        findings.append(
            PrettyLiftValidationFinding(
                severity="error",
                fact=fact,
                message="pretty lift omitted a required output-buffer write",
                evidence=[write.snippet],
            )
        )

    for copy in packet.string_copies:
        if copy.dst_offset is not None:
            fact = f"dst_offset:{_hex(copy.dst_offset)}"
            if _contains_int(text, copy.dst_offset):
                preserved.append(fact)
            else:
                findings.append(
                    PrettyLiftValidationFinding(
                        severity="warning",
                        fact=fact,
                        message="pretty lift omitted a string-copy destination offset",
                        evidence=[copy.snippet],
                    )
                )
        if copy.dst_length is not None:
            fact = f"length:{_hex(copy.dst_length)}"
            if _contains_int(text, copy.dst_length):
                preserved.append(fact)

    for access in packet.memory_accesses:
        if not _is_required_memory_access(access):
            continue
        fact = f"memory_access:{_memory_access_key(access)}"
        if _memory_access_preserved(text, access):
            preserved.append(fact)
            continue
        missing.append(fact)
        findings.append(
            PrettyLiftValidationFinding(
                severity="error",
                fact=fact,
                message="pretty lift omitted a required memory access offset or address",
                evidence=[access.snippet],
            )
        )

    for group in packet.field_offset_groups:
        if not _is_required_field_offset_group(group):
            continue
        fact = f"field_offset_group:{_field_offset_group_key(group)}"
        if _field_offset_group_preserved(text, group):
            preserved.append(fact)
            continue
        missing.append(fact)
        findings.append(
            PrettyLiftValidationFinding(
                severity="error",
                fact=fact,
                message="pretty lift omitted a required field-offset group",
                evidence=[
                    (
                        f"reads={','.join(_hex(v) for v in group.read_offsets)}; "
                        f"writes={','.join(_hex(v) for v in group.write_offsets)}"
                    )
                ],
            )
        )

    for condition in packet.path_conditions:
        if not _is_required_path_condition(condition):
            continue
        fact = f"path_condition:{_path_condition_key(condition)}"
        if _path_condition_preserved(text, condition, packet):
            preserved.append(fact)
            continue
        missing.append(fact)
        findings.append(
            PrettyLiftValidationFinding(
                severity="error",
                fact=fact,
                message="pretty lift omitted a required guard/path condition",
                evidence=[condition.snippet],
            )
        )

    for argument in packet.entry_abi_arguments:
        fact = f"entry_abi_argument:{_entry_abi_argument_key(argument)}"
        if _entry_abi_argument_preserved(text, argument):
            preserved.append(fact)
            continue
        missing.append(fact)
        findings.append(
            PrettyLiftValidationFinding(
                severity="warning",
                fact=fact,
                message="pretty lift omitted a recovered function-entry argument name/type",
                evidence=[
                    f"{argument.c_type} {argument.semantic_name}",
                    _entry_abi_argument_key(argument),
                ],
            )
        )

    for primitive in packet.primitives:
        if not _is_required_api_contract_primitive(primitive):
            continue
        fact = f"api_contract_primitive:{_api_contract_primitive_key(primitive)}"
        if _api_contract_primitive_preserved(text, primitive):
            preserved.append(fact)
            continue
        missing.append(fact)
        findings.append(
            PrettyLiftValidationFinding(
                severity="error",
                fact=fact,
                message=(
                    "pretty lift omitted a required API contract source/sink primitive"
                ),
                evidence=[primitive.snippet],
            )
        )

    for section in packet.unknown_sections:
        fact = f"unknown_section:{_unknown_section_key(section)}"
        if _unknown_section_preserved(text, section):
            preserved.append(fact)
            continue
        missing.append(fact)
        findings.append(
            PrettyLiftValidationFinding(
                severity="error",
                fact=fact,
                message="pretty lift omitted an explicit unknown/unresolved section",
                evidence=[section.snippet],
            )
        )

    for ref in packet.data_references:
        if not _is_required_data_reference(ref):
            continue
        fact = f"data_reference:{_data_reference_key(ref)}"
        if _data_reference_preserved(text, ref):
            preserved.append(fact)
            continue
        missing.append(fact)
        findings.append(
            PrettyLiftValidationFinding(
                severity="error",
                fact=fact,
                message="pretty lift omitted a required data/table reference fact",
                evidence=[ref.snippet],
            )
        )

    for loop in packet.loop_summaries:
        fact = f"loop_summary:{_loop_summary_key(loop)}"
        if _loop_summary_preserved(text, loop):
            preserved.append(fact)
            continue
        missing.append(fact)
        findings.append(
            PrettyLiftValidationFinding(
                severity="error",
                fact=fact,
                message="pretty lift omitted a recovered loop/backedge summary",
                evidence=[f"{loop.loop_label}: backedge line {loop.backedge_line}"],
            )
        )

    for status in packet.return_statuses:
        fact = f"status:{status}"
        if status.lower() in lowered:
            preserved.append(fact)
        elif status != "STATUS_SUCCESS":
            findings.append(
                PrettyLiftValidationFinding(
                    severity="warning",
                    fact=fact,
                    message=f"pretty lift omitted inferred return status {status}",
                )
            )

    raw_artifacts = {
        "raw_goto": r"\bgoto\s+",
        "ghidra_split_unaff": r"\bunaff_",
        "ghidra_split_fun": r"\bFUN_[0-9a-fA-F]+",
        "glaurung_flag_tmp": r"%[a-z][A-Za-z0-9_]*",
        "glaurung_memory_syntax": r"\*&?\[|&\[",
    }
    for fact, pattern in raw_artifacts.items():
        if re.search(pattern, text):
            findings.append(
                PrettyLiftValidationFinding(
                    severity="warning",
                    fact=fact,
                    message="pretty lift still exposes low-level decompiler artifact",
                )
            )
        else:
            preserved.append(f"no_artifact:{fact}")

    for required in packet.required_facts:
        if required not in preserved and required not in missing:
            if required.startswith("calls:") and required.split(":", 1)[1] in text:
                preserved.append(required)

    score = 1.0
    for finding in findings:
        if finding.severity == "critical":
            score -= 0.40
        elif finding.severity == "error":
            score -= 0.22
        elif finding.severity == "warning":
            score -= 0.05
    score = min(score, pretty_lift.confidence + 0.15)
    score = max(0.0, min(1.0, score))
    valid = not any(finding.severity in {"error", "critical"} for finding in findings)
    return PrettyLiftValidation(
        valid=valid,
        quality_score=score,
        preserved_facts=_dedupe(preserved),
        missing_facts=_dedupe(missing),
        findings=findings,
    )


def _scan_text(
    ctx: MemoryContext,
    args: WindowsFunctionPrettyLiftArgs,
) -> tuple[str, str, list[str]]:
    notes: list[str] = []
    if args.pseudocode:
        return args.pseudocode, "supplied_pseudocode", notes
    if args.function_va is None:
        return "", "none", ["no pseudocode or function_va supplied"]
    binary_path = Path(args.binary_path or ctx.file_path).expanduser()
    try:
        ir = getattr(g, "ir")
        if args.range_start is not None and args.range_end is not None:
            text = ir.decompile_range_at(
                str(binary_path),
                int(args.function_va),
                int(args.range_start),
                int(args.range_end),
                max_blocks=int(args.max_blocks),
                max_instructions=int(args.max_instructions),
                timeout_ms=int(args.timeout_ms),
                style="c",
                pdb_cache=args.pdb_cache,
            )
            return text, "glaurung_decompiler_explicit_range", notes
        text = ir.decompile_at(
            str(binary_path),
            int(args.function_va),
            max_blocks=int(args.max_blocks),
            max_instructions=int(args.max_instructions),
            timeout_ms=int(args.timeout_ms),
            style="c",
            pdb_cache=args.pdb_cache,
        )
        if not text.strip() and args.project_path:
            fallback = _decompile_project_boundary_range(binary_path, args)
            if fallback is not None:
                notes.append(
                    "decompile_at returned empty; used project function-boundary range fallback"
                )
                return fallback, "glaurung_decompiler_project_boundary_range", notes
        if not text.strip() and args.pdb_cache:
            fallback = _decompile_pdb_public_range(binary_path, args)
            if fallback is not None:
                notes.append(
                    "decompile_at returned empty; used PDB public-symbol range fallback"
                )
                return fallback, "glaurung_decompiler_pdb_public_range", notes
        return text, "glaurung_decompiler", notes
    except Exception as exc:
        notes.append(f"decompile failed: {exc}")
        if args.project_path:
            fallback = _decompile_project_boundary_range(binary_path, args)
            if fallback is not None and fallback.strip():
                notes.append(
                    "decompile_at failed; used project function-boundary range fallback"
                )
                return fallback, "glaurung_decompiler_project_boundary_range", notes
        if args.pdb_cache:
            fallback = _decompile_pdb_public_range(binary_path, args)
            if fallback is not None and fallback.strip():
                notes.append(
                    "decompile_at failed; used PDB public-symbol range fallback"
                )
                return fallback, "glaurung_decompiler_pdb_public_range", notes
        return "", "glaurung_decompiler_failed", notes


def _decompile_project_boundary_range(
    binary_path: Path,
    args: WindowsFunctionPrettyLiftArgs,
) -> str | None:
    if args.function_va is None or not args.project_path:
        return None
    project_path = Path(args.project_path).expanduser()
    if not project_path.exists():
        return None
    try:
        kb = PersistentKnowledgeBase.open(project_path)
        try:
            boundary = windows_boundaries.boundary_for_entry(kb, int(args.function_va))
        finally:
            kb.close()
    except Exception:
        return None
    if boundary is None or boundary.end_va is None:
        return None
    current = int(args.function_va)
    range_end = int(boundary.end_va)
    if range_end <= current or range_end - current > 0x20000:
        return None
    try:
        ir = getattr(g, "ir")
        return ir.decompile_range_at(
            str(binary_path),
            current,
            current,
            range_end,
            max_blocks=int(args.max_blocks),
            max_instructions=int(args.max_instructions),
            timeout_ms=int(args.timeout_ms),
            style="c",
            pdb_cache=args.pdb_cache,
        )
    except Exception:
        return None


def _decompile_pdb_public_range(
    binary_path: Path,
    args: WindowsFunctionPrettyLiftArgs,
) -> str | None:
    if args.function_va is None or not args.pdb_cache:
        return None
    try:
        analysis = g.debug.analyze_pe_pdb_cache_path(  # ty: ignore[unresolved-attribute]
            str(binary_path),
            args.pdb_cache,
            [],
        )
    except Exception:
        return None
    public_symbols = (
        analysis.get("public_symbols", []) if isinstance(analysis, dict) else []
    )
    function_vas = sorted(
        {
            int(row["va"])
            for row in public_symbols
            if isinstance(row, dict)
            and row.get("function")
            and isinstance(row.get("va"), int)
        }
    )
    if not function_vas:
        return None
    current = int(args.function_va)
    if current not in set(function_vas):
        return None
    index = function_vas.index(current)
    if index + 1 >= len(function_vas):
        return None
    range_end = function_vas[index + 1]
    if range_end <= current or range_end - current > 0x20000:
        return None
    try:
        ir = getattr(g, "ir")
        return ir.decompile_range_at(
            str(binary_path),
            current,
            current,
            range_end,
            max_blocks=int(args.max_blocks),
            max_instructions=int(args.max_instructions),
            timeout_ms=int(args.timeout_ms),
            style="c",
            pdb_cache=args.pdb_cache,
        )
    except Exception:
        return None


def _resolve_function_name(args: WindowsFunctionPrettyLiftArgs, text: str) -> str:
    if args.function_name:
        return args.function_name
    if args.project_path and args.function_va is not None:
        path = Path(args.project_path).expanduser()
        if path.exists():
            kb = PersistentKnowledgeBase.open(
                path,
                binary_path=args.binary_path,
            )
            try:
                name = xref_db.get_function_name(kb, int(args.function_va))
                if name is not None:
                    return name.display
            finally:
                kb.close()
    match = re.search(r"\bfn\s+([A-Za-z_][A-Za-z0-9_.$@]*)", text)
    if match:
        return match.group(1)
    if args.function_va is not None:
        return f"sub_{args.function_va:x}"
    return "sub_unknown"


_CONTROL_CALLS = {"if", "switch", "sizeof", "return", "push", "pop", "unknown"}


def _call_counts(text: str) -> Counter[str]:
    counts: Counter[str] = Counter()
    for raw_line in text.splitlines():
        line = raw_line.strip()
        for name, _args in _primitive_calls(line):
            if name.lower() in _CONTROL_CALLS:
                continue
            counts[name] += 1
    return counts


def _assignment_aliases(text: str) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for raw_line in text.splitlines():
        match = re.match(
            r"\s*(?P<lhs>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<rhs>arg\d+)\s*;",
            raw_line,
        )
        if match:
            aliases[match.group("lhs")] = match.group("rhs")
    return aliases


def _import_thunk_call_aliases(text: str) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for raw_line in text.splitlines():
        match = re.match(
            r"\s*(?P<lhs>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*\*&\[\s*"
            r"(?P<thunk>[_A-Za-z][_A-Za-z0-9]*)\s*\]\s*;",
            raw_line,
        )
        if not match:
            continue
        target = _import_thunk_symbol(match.group("thunk"))
        if target is None:
            continue
        aliases[_clean_symbol_name(match.group("lhs"))] = _clean_symbol_name(target)
    return aliases


def _variable_constants(text: str) -> dict[str, int]:
    constants: dict[str, int] = {}
    for raw_line in text.splitlines():
        match = re.match(
            r"\s*(?P<lhs>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<value>0x[0-9A-Fa-f]+|\d+)\s*;",
            raw_line,
        )
        if match:
            value = _parse_int(match.group("value"))
            if value is not None:
                constants[match.group("lhs")] = value
    return constants


def _output_buffer_var(text: str) -> str | None:
    for raw_line in text.splitlines():
        for name, args in _primitive_calls(raw_line.strip()):
            if name.lower() != "memset":
                continue
            call_args = _split_args(args)
            if call_args:
                return call_args[0].strip()
    for raw_line in text.splitlines():
        match = re.search(r"&\[(?P<base>var\d+)(?:[+][^\]]+)?\]\s*=", raw_line)
        if match:
            return match.group("base")
    return None


def _output_size(text: str) -> int | None:
    candidates: list[int] = []
    for raw_line in text.splitlines():
        for pattern in (
            r"arg3\s+u?(?:==|<|<=|>=|>)\s*(0x[0-9A-Fa-f]+|\d+)",
            r"&\[[^\]]+\]\s*=\s*(0x[0-9A-Fa-f]+|\d+)\s*;",
        ):
            for match in re.finditer(pattern, raw_line):
                value = _parse_int(match.group(1))
                if value is not None and 16 <= value <= 1_048_576:
                    candidates.append(value)
    if not candidates:
        return None
    return max(candidates)


def _argument_roles(
    text: str,
    *,
    aliases: dict[str, str],
    output_var: str | None,
    output_size: int | None,
    function_name: str,
) -> dict[str, LiftArgumentRole]:
    roles: dict[str, LiftArgumentRole] = {}

    def add(
        original: str,
        semantic: str,
        c_type: str,
        role: str,
        confidence: float,
        evidence: str,
    ) -> None:
        roles[original] = LiftArgumentRole(
            original_name=original,
            semantic_name=semantic,
            c_type=c_type,
            role=role,
            confidence=confidence,
            evidence=[evidence],
        )

    if re.search(r"\*&\[\s*arg0\s*\]", text):
        add(
            "arg0",
            "QueryIndex",
            "const ULONG *",
            "selector_input_pointer",
            0.84,
            "raw IR dereferences arg0 to obtain selector/index",
        )
    if re.search(r"arg1\s+u?(?:==|!=|<|>|<=|>=)\s*4\b", text):
        add(
            "arg1",
            "QueryLength",
            "ULONG",
            "input_length",
            0.86,
            "raw IR compares arg1 against sizeof(ULONG)",
        )
    if output_var is not None:
        source_arg = aliases.get(output_var)
        if source_arg:
            add(
                source_arg,
                "OutputBuffer",
                "void *",
                "output_buffer",
                0.88,
                f"raw IR aliases {output_var} to {source_arg} and writes through it",
            )
    if output_size is not None and re.search(r"arg3\s+u?(?:==|<|<=|>|>=)", text):
        add(
            "arg3",
            "OutputLength",
            "ULONG",
            "output_length",
            0.84,
            "raw IR compares arg3 with output size and passes it to memset",
        )
    if "stack_1" in text and re.search(r"ret\s*=\s*stack_1\s*;\s*\n\s*&\[ret\]", text):
        add(
            "stack_1",
            "ReturnLength",
            "ULONG *",
            "return_length",
            0.75,
            "raw IR reloads stack_1 and writes the returned byte count",
        )
    if function_name == "CmQueryBuildVersionInformation":
        roles.setdefault(
            "stack_previous_mode",
            LiftArgumentRole(
                original_name="stack_previous_mode",
                semantic_name="PreviousMode",
                c_type="KPROCESSOR_MODE",
                role="mode",
                confidence=0.45,
                evidence=["inferred from Windows kernel helper convention"],
            ),
        )
    return roles


def _entry_abi_argument_facts(
    *,
    function_prototype: PrototypeFact | None,
    argument_roles: dict[str, LiftArgumentRole],
) -> list[EntryAbiArgumentFact]:
    facts: dict[int, EntryAbiArgumentFact] = {}
    roles_by_index: dict[int, LiftArgumentRole] = {}
    roles_by_semantic: dict[str, LiftArgumentRole] = {}
    for role in argument_roles.values():
        index = _argument_role_index(role.original_name)
        if index is not None:
            roles_by_index[index] = role
        roles_by_semantic[role.semantic_name.lower()] = role

    if function_prototype is not None:
        for parameter in function_prototype.parameters:
            role = roles_by_index.get(parameter.index) or roles_by_semantic.get(
                parameter.name.lower()
            )
            location, register_name, stack_offset = _entry_abi_location(parameter.index)
            original_name = (
                role.original_name if role else _entry_original_name(parameter.index)
            )
            semantic_name = role.semantic_name if role else parameter.name
            c_type = role.c_type if role else parameter.c_type
            role_name = role.role if role else parameter.role
            source = (
                f"{function_prototype.source}+argument_role"
                if role
                else function_prototype.source
            )
            confidence = max(
                function_prototype.confidence,
                role.confidence if role else 0.0,
            )
            facts[parameter.index] = EntryAbiArgumentFact(
                index=parameter.index,
                abi_location=location,
                register_name=register_name,
                stack_offset=stack_offset,
                original_name=original_name,
                semantic_name=semantic_name,
                c_type=c_type,
                role=role_name,
                source=source,
                confidence=min(confidence, 0.95),
            )

    for index, role in roles_by_index.items():
        if index in facts:
            continue
        location, register_name, stack_offset = _entry_abi_location(index)
        facts[index] = EntryAbiArgumentFact(
            index=index,
            abi_location=location,
            register_name=register_name,
            stack_offset=stack_offset,
            original_name=role.original_name,
            semantic_name=role.semantic_name,
            c_type=role.c_type,
            role=role.role,
            source="argument_role",
            confidence=role.confidence,
        )

    return [facts[index] for index in sorted(facts)]


def _argument_role_index(original_name: str) -> int | None:
    match = re.fullmatch(r"arg(?P<index>\d+)", original_name)
    if match:
        return int(match.group("index"))
    match = re.fullmatch(r"stack_(?P<index>\d+)", original_name)
    if match:
        return 4 + max(0, int(match.group("index")) - 1)
    return None


def _entry_original_name(index: int) -> str:
    if index < 4:
        return f"arg{index}"
    return f"stack_arg{index}"


def _entry_abi_location(
    index: int,
) -> tuple[Literal["register", "stack"], str | None, int | None]:
    registers = ("rcx", "rdx", "r8", "r9")
    if index < len(registers):
        return "register", registers[index], None
    return "stack", None, 0x20 + ((index - 4) * 8)


def _entry_abi_argument_key(argument: EntryAbiArgumentFact) -> str:
    if argument.abi_location == "register" and argument.register_name:
        return f"{argument.index}:{argument.register_name}"
    if argument.stack_offset is not None:
        return f"{argument.index}:stack+{_hex(argument.stack_offset)}"
    return f"{argument.index}:{argument.abi_location}"


def _project_prototypes(
    project_path: str | None,
    binary_path: str | None,
) -> dict[str, PrototypeFact]:
    if not project_path:
        return {}
    path = Path(project_path).expanduser()
    if not path.exists():
        return {}
    out: dict[str, PrototypeFact] = {}
    try:
        kb = PersistentKnowledgeBase.open(
            path,
            binary_path=binary_path,
            auto_load_stdlib=False,
        )
    except Exception:
        return {}
    try:
        for prototype in xref_db.list_function_prototypes(kb):
            fact = _prototype_fact_from_xref(prototype, source="project")
            out[prototype.function_name.lower()] = fact
    finally:
        kb.close()
    return out


def _call_prototype_facts(
    call_counts: Counter[str],
    *,
    project_prototypes: dict[str, PrototypeFact],
    extra_symbols: Iterable[str] = (),
) -> list[PrototypeFact]:
    facts: list[PrototypeFact] = []
    seen: set[str] = set()
    for symbol in [*call_counts, *extra_symbols]:
        prototype = _prototype_fact_for_symbol(
            symbol,
            project_prototypes=project_prototypes,
            kind="callee",
        )
        if prototype is None:
            continue
        key = prototype.symbol.lower()
        if key in seen:
            continue
        seen.add(key)
        facts.append(prototype)
    return facts


def _merge_call_prototypes(
    existing: list[PrototypeFact],
    inferred: list[PrototypeFact],
) -> list[PrototypeFact]:
    out = list(existing)
    seen = {prototype.symbol.lower() for prototype in out}
    for prototype in inferred:
        key = prototype.symbol.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(prototype)
    return out


def _call_site_facts(
    text: str,
    *,
    call_prototypes: list[PrototypeFact],
    import_thunk_aliases: dict[str, str],
) -> list[CallSiteFact]:
    facts: list[CallSiteFact] = []
    prototype_by_name: dict[str, PrototypeFact] = {}
    for prototype in call_prototypes:
        prototype_by_name[prototype.symbol.lower()] = prototype
        for candidate in _prototype_name_candidates(prototype.symbol):
            prototype_by_name.setdefault(candidate.lower(), prototype)
    for line_no, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("fn "):
            continue
        lhs, _rhs = _assignment_sides(line)
        equals_index = line.find("=")
        for name, args in _primitive_calls(line):
            lowered = name.lower()
            if lowered in _CONTROL_CALLS:
                continue
            call_index = line.find(name)
            call_name = _clean_symbol_name(name)
            normalized_thunk_name = _import_thunk_symbol(name) or _import_thunk_symbol(
                call_name
            )
            resolved_call_name = normalized_thunk_name or import_thunk_aliases.get(
                call_name, call_name
            )
            prototype = (
                prototype_by_name.get(resolved_call_name.lower())
                or prototype_by_name.get(call_name.lower())
                or prototype_by_name.get(name.lower())
            )
            call_arguments = _split_args(args)
            if prototype is None:
                prototype = _inferred_local_prototype_for_call(
                    resolved_call_name,
                    call_arguments,
                )
            return_value_used = bool(
                lhs is not None and equals_index >= 0 and call_index > equals_index
            )
            facts.append(
                CallSiteFact(
                    order=len(facts),
                    call_name=resolved_call_name,
                    original_name=name,
                    arguments=call_arguments,
                    argument_facts=_call_site_argument_facts(
                        call_arguments,
                        prototype=prototype,
                    ),
                    line=line_no,
                    snippet=line,
                    return_value_used=return_value_used,
                    return_target=lhs if return_value_used else None,
                    role=_call_site_role(resolved_call_name, prototype),
                    prototype=prototype,
                    confidence=0.82 if prototype is not None else 0.72,
                )
            )
    return facts


def _call_site_argument_facts(
    arguments: list[str],
    *,
    prototype: PrototypeFact | None,
) -> list[CallSiteArgumentFact]:
    facts: list[CallSiteArgumentFact] = []
    for index, expression in enumerate(arguments):
        parameter = (
            prototype.parameters[index]
            if prototype is not None and index < len(prototype.parameters)
            else None
        )
        location, register_name, stack_offset = _entry_abi_location(index)
        facts.append(
            CallSiteArgumentFact(
                index=index,
                expression=expression,
                abi_location=location,
                register_name=register_name,
                stack_offset=stack_offset,
                parameter_name=parameter.name if parameter else None,
                c_type=parameter.c_type if parameter else None,
                role=parameter.role if parameter else None,
                source=prototype.source if prototype and parameter else "raw_callsite",
                confidence=0.86 if parameter else 0.68,
            )
        )
    return facts


def _inferred_local_prototype_for_call(
    call_name: str,
    arguments: list[str],
) -> PrototypeFact | None:
    if not arguments or not _can_infer_local_prototype(call_name):
        return None
    params: list[PrototypeParameterFact] = []
    role_count = 0
    for index, expression in enumerate(arguments):
        role = _inferred_call_argument_role(expression)
        if role is not None:
            role_count += 1
        params.append(
            PrototypeParameterFact(
                index=index,
                name=_inferred_call_parameter_name(expression, role, index),
                c_type=_inferred_call_parameter_type(expression, role),
                role=role,
            )
        )
    if role_count == 0:
        return None
    return_type = "NTSTATUS" if _looks_status_returning_call(call_name) else "void"
    rendered_params = ", ".join(f"{param.c_type} {param.name}" for param in params)
    return PrototypeFact(
        symbol=call_name,
        prototype=f"{return_type} {call_name}({rendered_params or 'void'})",
        return_type=return_type,
        parameters=params,
        source="inferred_local",
        confidence=min(0.48 + 0.07 * role_count, 0.72),
        provenance=["callsite_argument_name_role_inference"],
    )


def _can_infer_local_prototype(call_name: str) -> bool:
    lowered = call_name.lower()
    if lowered in _CONTROL_CALLS:
        return False
    if lowered in {"ret", "callback", "function", "callee"}:
        return False
    if re.fullmatch(r"(?:arg|var|stack_)\d+", lowered):
        return False
    return bool(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", call_name))


def _inferred_call_argument_role(expression: str) -> str | None:
    normalized = re.sub(r"[^A-Za-z0-9_]", "", expression).lower()
    if not normalized:
        return None
    if "returnlength" in normalized or "bytesreturned" in normalized:
        return "return_length"
    if "ioctl" in normalized or "controlcode" in normalized:
        return "ioctl_code"
    if re.search(r"(?:length|len|size|bytes|count)$", normalized):
        return "length"
    if "output" in normalized or normalized in {"out", "dst", "dest", "destination"}:
        return "output_buffer"
    if "input" in normalized or normalized in {"in", "src", "source"}:
        return "input_buffer"
    if "buffer" in normalized or normalized.endswith("buf"):
        return "buffer"
    if "handle" in normalized:
        return "handle"
    if "irp" in normalized:
        return "irp"
    if "mdl" in normalized:
        return "mdl"
    if "mode" in normalized:
        return "access_mode"
    if "privilege" in normalized:
        return "privilege"
    return None


def _inferred_call_parameter_name(
    expression: str,
    role: str | None,
    index: int,
) -> str:
    identifier = _identifier_from_expression(expression)
    if identifier is not None and not re.fullmatch(
        r"(?:arg|var|stack_)\d+", identifier
    ):
        return identifier
    by_role = {
        "return_length": "ReturnLength",
        "ioctl_code": "IoControlCode",
        "length": "Length",
        "output_buffer": "OutputBuffer",
        "input_buffer": "InputBuffer",
        "buffer": "Buffer",
        "handle": "Handle",
        "irp": "Irp",
        "mdl": "Mdl",
        "access_mode": "AccessMode",
        "privilege": "Privilege",
    }
    if role in by_role:
        return by_role[role]
    return f"Arg{index}"


def _identifier_from_expression(expression: str) -> str | None:
    cleaned = expression.strip().lstrip("&*").strip()
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", cleaned):
        return cleaned
    return None


def _inferred_call_parameter_type(
    expression: str,
    role: str | None,
) -> str:
    if role == "return_length":
        return "ULONG *"
    if role in {"output_buffer", "input_buffer", "buffer"}:
        return "void *"
    if role in {"length", "ioctl_code"}:
        return "ULONG"
    if role == "handle":
        return "HANDLE"
    if role == "irp":
        return "PIRP"
    if role == "mdl":
        return "PMDL"
    if role == "access_mode":
        return "KPROCESSOR_MODE"
    if role == "privilege":
        return "LUID"
    if expression.strip().startswith("&"):
        return "void *"
    return "uintptr_t"


def _looks_status_returning_call(call_name: str) -> bool:
    return call_name.startswith(("Nt", "Zw", "Io", "Rtl", "Se", "Ob", "Mm"))


def _call_site_role(call_name: str, prototype: PrototypeFact | None) -> str:
    lowered = call_name.lower()
    if prototype is not None:
        return "typed_api_call"
    if lowered in {"memcpy", "memmove", "memset", "rtlcopymemory"}:
        return "memory_operation"
    if lowered.startswith(("nt", "zw")):
        return "ntapi_call"
    if lowered.startswith(("rtl", "io", "ex", "ob", "alpc", "etw", "wpp")):
        return "windows_api_call"
    return "direct_call"


def _call_site_key(site: CallSiteFact) -> str:
    return f"{site.order}:{site.call_name}:{site.line}"


def _call_site_argument_key(argument: CallSiteArgumentFact) -> str:
    if argument.abi_location == "register" and argument.register_name:
        return f"{argument.index}:{argument.register_name}"
    if argument.stack_offset is not None:
        return f"{argument.index}:stack+{_hex(argument.stack_offset)}"
    return f"{argument.index}:{argument.abi_location}"


_REQUIRED_CALL_SITE_ARGUMENT_ROLES = {
    "access_mode",
    "buffer",
    "handle",
    "input_buffer",
    "input_length",
    "ioctl_code",
    "irp",
    "length",
    "mdl",
    "mode",
    "object",
    "output_buffer",
    "output_length",
    "privilege",
    "return_length",
    "selector_input_pointer",
}


def _is_required_call_site_argument(argument: CallSiteArgumentFact) -> bool:
    return argument.role in _REQUIRED_CALL_SITE_ARGUMENT_ROLES


def _call_site_return_target_preserved(text: str, site: CallSiteFact) -> bool:
    if site.return_target is None:
        return False
    target = site.return_target.strip()
    if not target:
        return False
    if re.search(rf"\b{re.escape(target)}\b", text):
        return True
    return bool(
        re.search(
            rf"\b(?:status|result|return_value)\s*=\s*"
            rf"{re.escape(site.call_name)}\s*\(",
            text,
            flags=re.IGNORECASE,
        )
    )


_UNKNOWN_OPERATION_RE = re.compile(r"\bunknown\s*\(\s*(?P<what>[^)]*)\)")
_UNRESOLVED_SYMBOL_RE = re.compile(r"\b(?:FUN|SUB|sub|unaff)_[0-9A-Fa-f_]+\b")


def _unknown_section_facts(text: str) -> list[UnknownSectionFact]:
    facts: list[UnknownSectionFact] = []
    seen: set[tuple[str, str, int]] = set()

    def add(fact: UnknownSectionFact) -> None:
        key = (fact.kind, fact.label, fact.line)
        if key in seen:
            return
        seen.add(key)
        facts.append(fact)

    for line_no, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        for match in _UNKNOWN_OPERATION_RE.finditer(line):
            what = match.group("what").strip()
            if what.lower() in {"syscall", "int3", "int 3", "__debugbreak"}:
                continue
            label = f"unknown({what})" if what else "unknown()"
            add(
                UnknownSectionFact(
                    kind="unknown_operation",
                    label=label,
                    reason="raw IR contains an unsupported operation marker",
                    line=line_no,
                    snippet=line,
                    confidence=0.82,
                )
            )
        for match in _UNRESOLVED_SYMBOL_RE.finditer(line):
            label = match.group(0)
            if label.startswith("sub_"):
                continue
            add(
                UnknownSectionFact(
                    kind="unresolved_symbol",
                    label=label,
                    reason="decompiler emitted an unresolved synthetic symbol",
                    line=line_no,
                    snippet=line,
                    confidence=0.70,
                )
            )
    return facts


def _unknown_section_key(section: UnknownSectionFact) -> str:
    return f"{section.kind}:{section.label}"


def _unknown_section_preserved(text: str, section: UnknownSectionFact) -> bool:
    if section.label in text:
        return True
    lowered = text.lower()
    return section.kind == "unknown_operation" and bool(
        re.search(r"\b(?:unsupported|unresolved)\b", lowered)
    )


def _orderable_call_sites(packet: WindowsFunctionLiftPacket) -> list[CallSiteFact]:
    ignored = {"__security_check_cookie", "memset", "memcpy", "memmove"}
    out: list[CallSiteFact] = []
    for site in packet.call_sites:
        lowered = site.call_name.lower()
        if (
            lowered in _CONTROL_CALLS
            or site.call_name in ignored
            or lowered.startswith("wpp_")
        ):
            continue
        out.append(site)
    return out


def _call_order_preserved(text: str, sites: list[CallSiteFact]) -> bool:
    cursor = 0
    for site in sites:
        match = re.search(
            rf"\b{re.escape(site.call_name)}\s*\(",
            text[cursor:],
        )
        if match is None:
            return False
        cursor += match.end()
    return True


def _call_site_argument_preserved(
    text: str,
    argument: CallSiteArgumentFact,
) -> bool:
    if argument.parameter_name and re.search(
        rf"\b{re.escape(argument.parameter_name)}\b",
        text,
    ):
        return True
    return bool(re.search(rf"\b{re.escape(argument.expression)}\b", text))


def _prototype_fact_for_symbol(
    symbol: str,
    *,
    project_prototypes: dict[str, PrototypeFact],
    kind: Literal["function", "callee"],
) -> PrototypeFact | None:
    for candidate in _prototype_name_candidates(symbol):
        project = project_prototypes.get(candidate.lower())
        if project is not None:
            return project.model_copy(
                update={
                    "symbol": _clean_symbol_name(candidate),
                    "provenance": [*project.provenance, f"{kind}_project_lookup"],
                }
            )
    manual = _manual_prototype_fact(symbol)
    if manual is not None:
        return manual.model_copy(
            update={"provenance": [*manual.provenance, f"{kind}_manual_contract"]}
        )
    catalog = _stdlib_prototype_catalog()
    for candidate in _prototype_name_candidates(symbol):
        prototype = catalog.get(candidate.lower())
        if prototype is not None:
            return prototype.model_copy(
                update={
                    "symbol": _clean_symbol_name(candidate),
                    "provenance": [*prototype.provenance, f"{kind}_stdlib_lookup"],
                }
            )
    return None


def _prototype_name_candidates(symbol: str) -> list[str]:
    return _symbol_name_variants(symbol)


def _symbol_name_variants(symbol: str | None) -> list[str]:
    if not symbol:
        return []
    cleaned = _clean_symbol_name(symbol)
    base_values = [symbol.strip(), cleaned]
    if "!" in symbol:
        base_values.append(symbol.rsplit("!", 1)[-1].strip())
    out: list[str] = []
    for value in base_values:
        if not value:
            continue
        out.append(value)
        suffix = value.rsplit("!", 1)[-1].rsplit("::", 1)[-1].strip()
        if suffix:
            out.append(suffix)
        for prefix in ("__imp__", "__imp_", "_imp_", "imp_", "j_", "thunk_"):
            if suffix.startswith(prefix) and len(suffix) > len(prefix):
                out.append(suffix.removeprefix(prefix))
        if suffix.endswith("$thunk") and len(suffix) > len("$thunk"):
            out.append(suffix.removesuffix("$thunk"))
        if suffix.startswith("__imp_") and "@@" in suffix:
            out.append(suffix.removeprefix("__imp_").split("@@", 1)[0])
    return _dedupe(out)


@lru_cache(maxsize=1)
def _stdlib_prototype_catalog() -> dict[str, PrototypeFact]:
    catalog = xref_db.load_stdlib_prototype_catalog(
        bundles=["stdlib-winapi-protos", "stdlib-libc-protos"]
    )
    out: dict[str, PrototypeFact] = {}
    for name, prototype in catalog.items():
        fact = _prototype_fact_from_xref(prototype, source="stdlib")
        out[name.lower()] = fact
    return out


def _prototype_fact_from_xref(
    prototype: xref_db.FunctionPrototype,
    *,
    source: str,
) -> PrototypeFact:
    return PrototypeFact(
        symbol=prototype.function_name,
        prototype=prototype.render(),
        return_type=prototype.return_type,
        parameters=[
            PrototypeParameterFact(
                index=index,
                name=param.name,
                c_type=param.c_type,
                role=param.role or _inferred_prototype_param_role(param),
            )
            for index, param in enumerate(prototype.params)
        ],
        is_variadic=prototype.is_variadic,
        source=source,
        module=prototype.module,
        calling_convention=prototype.calling_convention,
        confidence=prototype.confidence if prototype.confidence is not None else 0.82,
        provenance=[
            value
            for value in (
                prototype.set_by,
                prototype.source_kind,
                prototype.source_package,
            )
            if value
        ],
    )


def _inferred_prototype_param_role(param: xref_db.FunctionParam) -> str | None:
    name = param.name.lower()
    c_type = param.c_type.lower()
    combined = f"{name} {c_type}"
    if "returnlength" in name or "bytesreturned" in name or "resultlength" in name:
        return "return_length"
    if re.search(r"(?:length|size|bytes|count)$", name):
        return "length"
    if "output" in name and ("buffer" in name or "*" in c_type):
        return "output_buffer"
    if "input" in name and ("buffer" in name or "*" in c_type):
        return "input_buffer"
    if "ioctl" in name or "controlcode" in name:
        return "ioctl_code"
    if "handle" in combined or c_type.strip() == "handle":
        return "handle"
    if "irp" in combined:
        return "irp"
    if "mdl" in combined:
        return "mdl"
    if "accessmode" in name or "previousmode" in name or "requestormode" in name:
        return "access_mode"
    if "privilege" in name:
        return "privilege"
    return None


def _manual_prototype_fact(symbol: str) -> PrototypeFact | None:
    name = _clean_symbol_name(symbol)
    if name == "CmQueryBuildVersionInformation":
        return _prototype_fact_from_parts(
            symbol=name,
            return_type="NTSTATUS",
            params=[
                ("QueryIndex", "const ULONG *", "selector_input_pointer"),
                ("QueryLength", "ULONG", "input_length"),
                ("OutputBuffer", "void *", "output_buffer"),
                ("OutputLength", "ULONG", "output_length"),
                ("ReturnLength", "ULONG *", "return_length"),
                ("PreviousMode", "KPROCESSOR_MODE", "mode"),
            ],
            source="inferred",
            confidence=0.84,
            provenance=["cm_query_build_version_shape"],
        )
    if name == "CmpQueryDowncastString":
        return _prototype_fact_from_parts(
            symbol=name,
            return_type="NTSTATUS",
            params=[
                ("Destination", "void *", "dst"),
                ("DestinationLength", "ULONG", "dst_length"),
                ("SourceUnicodeString", "const void *", "src_unicode_string"),
            ],
            source="curated",
            confidence=0.72,
            provenance=["windows_string_conversion_wrapper"],
        )
    if name == "RtlSetLastWin32Error":
        return _prototype_fact_from_parts(
            symbol=name,
            return_type="void",
            params=[("Win32Error", "ULONG", "error_code")],
            source="curated",
            confidence=0.70,
            provenance=["ntdll_status_wrapper_contract"],
        )
    return None


def _prototype_fact_from_parts(
    *,
    symbol: str,
    return_type: str,
    params: list[tuple[str, str, str | None]],
    source: str,
    confidence: float,
    provenance: list[str],
) -> PrototypeFact:
    parameters = [
        PrototypeParameterFact(index=index, name=name, c_type=c_type, role=role)
        for index, (name, c_type, role) in enumerate(params)
    ]
    rendered_params = ", ".join(
        f"{param.c_type} {param.name}".strip() for param in parameters
    )
    return PrototypeFact(
        symbol=symbol,
        prototype=f"{return_type} {symbol}({rendered_params or 'void'})",
        return_type=return_type,
        parameters=parameters,
        source=source,
        confidence=confidence,
        provenance=provenance,
    )


def _selector_table_fact(
    text: str,
    *,
    function_name: str,
) -> SelectorTableFact | None:
    table_expr = None
    for raw_line in text.splitlines():
        match = re.match(
            r"\s*(?:var\d+)\s*=\s*(?P<addr>0x[0-9A-Fa-f]+)\s*;",
            raw_line,
        )
        if match:
            table_expr = match.group("addr")
        if table_expr and re.search(r"=\s*\*&\[[^\]]+\+\s*ret\s*\*\s*8\]", raw_line):
            table_name = f"global_table_{table_expr}"
            count_name = None
            if function_name == "CmQueryBuildVersionInformation":
                table_name = "CmpLayerVersions"
                count_name = "CmpLayerVersionCount"
            return SelectorTableFact(
                index_expression="index",
                table_expression=table_expr,
                table_name=table_name,
                count_expression=None,
                count_name=count_name,
                confidence=0.82 if count_name else 0.68,
                evidence=[raw_line.strip()],
            )
    return None


def _string_copy_facts(
    text: str,
    *,
    var_constants: dict[str, int],
) -> list[StringCopyFact]:
    facts: list[StringCopyFact] = []
    for line_no, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        for name, args in _primitive_calls(line):
            if name.lower() != "cmpquerydowncaststring":
                continue
            call_args = _split_args(args)
            if len(call_args) < 3:
                continue
            dst_offset = _plus_offset(call_args[0])
            src_offset = _plus_offset(call_args[2])
            dst_length = _resolve_length(call_args[1], var_constants)
            facts.append(
                StringCopyFact(
                    call_name=name,
                    dst_expression=call_args[0],
                    dst_offset=dst_offset,
                    dst_length_expression=call_args[1],
                    dst_length=dst_length,
                    src_expression=call_args[2],
                    src_offset=src_offset,
                    line=line_no,
                    snippet=line,
                    confidence=0.82,
                )
            )
    return facts


def _output_write_facts(
    text: str,
    *,
    output_var: str | None,
) -> list[OutputWriteFact]:
    if output_var is None:
        return []
    facts: list[OutputWriteFact] = []
    pattern = re.compile(
        rf"\s*&\[\s*{re.escape(output_var)}(?P<offset>\s*\+\s*(?:0x[0-9A-Fa-f]+|\d+))?\s*\]"
        r"(?:\s*/\*.*?\*/)?\s*=\s*(?P<rhs>[^;]+)\s*;"
    )
    ret_source_offset: int | None = None
    for line_no, raw_line in enumerate(text.splitlines(), start=1):
        ret_source = re.match(
            r"\s*ret\s*=\s*\*&\[\s*var0(?P<offset>\s*\+\s*(?:0x[0-9A-Fa-f]+|\d+))?\s*\]",
            raw_line,
        )
        if ret_source:
            ret_source_offset = 0
            if ret_source.group("offset"):
                parsed = _parse_int(ret_source.group("offset").replace("+", "").strip())
                ret_source_offset = parsed if parsed is not None else None
            continue
        match = pattern.match(raw_line)
        if not match:
            continue
        offset = 0
        if match.group("offset"):
            parsed = _parse_int(match.group("offset").replace("+", "").strip())
            offset = parsed if parsed is not None else 0
        facts.append(
            OutputWriteFact(
                lhs_expression=match.group(0).split("=", 1)[0].strip(),
                output_offset=offset,
                rhs_expression=match.group("rhs").strip(),
                source_offset=ret_source_offset
                if match.group("rhs").strip() == "ret"
                else None,
                line=line_no,
                snippet=raw_line.strip(),
                confidence=0.72,
            )
        )
    return facts


def _output_write_key(write: OutputWriteFact) -> str:
    offset = write.output_offset if write.output_offset is not None else 0
    return f"offset:{_hex(offset)}"


def _is_required_output_write(write: OutputWriteFact) -> bool:
    return write.output_offset is not None


def _output_write_preserved(text: str, write: OutputWriteFact) -> bool:
    if write.output_offset is None:
        return False
    if write.output_offset != 0 and _contains_int(text, write.output_offset):
        return True
    if write.output_offset == 0 and re.search(r"\bWRITE_FIELD\s*\(", text):
        return True
    return bool(
        re.search(
            rf"\bOutputBuffer\b.*\+\s*{re.escape(_hex(write.output_offset))}",
            text,
        )
    )


_MEMORY_EXPR_RE = re.compile(r"(?P<prefix>\*?&)?\[\s*(?P<body>[^\]]+?)\s*\]")
_C_TYPED_DEREF_RE = re.compile(
    r"\*\s*\(\s*(?P<c_type>[^()]+?)\s*\*\s*\)\s*"
    r"\(?\s*(?P<body>[^;)=]+)\s*\)?"
)
_STACK_SLOT_RE = re.compile(r"\bstack_\d+\b")


class _MemoryExpressionShape(TypedDict):
    base: str | None
    offset: int | None
    index: str | None
    scale: int | None
    absolute_address: int | None


def _memory_access_facts(
    text: str,
    *,
    output_var: str | None,
    selector_table: SelectorTableFact | None,
) -> list[MemoryAccessFact]:
    facts: list[MemoryAccessFact] = []
    seen: set[tuple[str, int, str]] = set()

    def add(access: MemoryAccessFact) -> None:
        key = (_memory_access_key(access), access.line, access.snippet)
        if key in seen:
            return
        seen.add(key)
        facts.append(access)

    for line_no, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("fn ") or line in {"{", "}"}:
            continue
        lhs, rhs = _assignment_sides(line)
        for match in _MEMORY_EXPR_RE.finditer(line):
            expression = match.group(0)
            if lhs is not None and match.start() < line.find("="):
                kind: Literal["read", "write"] = "write"
            elif match.group("prefix") == "*&":
                kind = "read"
            else:
                continue
            shape = _parse_memory_expression_body(match.group("body"))
            if shape is None:
                continue
            add(
                MemoryAccessFact(
                    kind=kind,
                    expression=expression,
                    base=shape["base"],
                    offset=shape["offset"],
                    index=shape["index"],
                    scale=shape["scale"],
                    absolute_address=shape["absolute_address"],
                    width_bits=_width_bits_from_memory_context(
                        expression=expression,
                        line=line,
                    ),
                    role=_memory_access_role(
                        base=shape["base"],
                        absolute_address=shape["absolute_address"],
                        index=shape["index"],
                        scale=shape["scale"],
                        output_var=output_var,
                        selector_table=selector_table,
                    ),
                    line=line_no,
                    snippet=line,
                    confidence=_memory_access_confidence(
                        base=shape["base"],
                        absolute_address=shape["absolute_address"],
                        index=shape["index"],
                    ),
                )
            )
        for match in _C_TYPED_DEREF_RE.finditer(line):
            expression = match.group(0)
            if lhs is not None and match.start() < line.find("="):
                kind = "write"
            else:
                kind = "read"
            shape = _parse_memory_expression_body(match.group("body"))
            if shape is None:
                continue
            add(
                MemoryAccessFact(
                    kind=kind,
                    expression=expression,
                    base=shape["base"],
                    offset=shape["offset"],
                    index=shape["index"],
                    scale=shape["scale"],
                    absolute_address=shape["absolute_address"],
                    width_bits=_width_bits_from_c_type(match.group("c_type")),
                    role=_memory_access_role(
                        base=shape["base"],
                        absolute_address=shape["absolute_address"],
                        index=shape["index"],
                        scale=shape["scale"],
                        output_var=output_var,
                        selector_table=selector_table,
                    ),
                    line=line_no,
                    snippet=line,
                    confidence=min(
                        _memory_access_confidence(
                            base=shape["base"],
                            absolute_address=shape["absolute_address"],
                            index=shape["index"],
                        )
                        + 0.08,
                        0.88,
                    ),
                )
            )
        if lhs is not None and _STACK_SLOT_RE.fullmatch(lhs):
            add(
                MemoryAccessFact(
                    kind="write",
                    expression=lhs,
                    base=lhs,
                    offset=0,
                    role="stack_slot",
                    line=line_no,
                    snippet=line,
                    confidence=0.72,
                )
            )
        if rhs is not None:
            for stack_match in _STACK_SLOT_RE.finditer(rhs):
                name = stack_match.group(0)
                add(
                    MemoryAccessFact(
                        kind="read",
                        expression=name,
                        base=name,
                        offset=0,
                        role="stack_slot",
                        line=line_no,
                        snippet=line,
                        confidence=0.72,
                    )
                )
    return facts


def _assignment_sides(line: str) -> tuple[str | None, str | None]:
    if "=" not in line:
        return None, None
    lhs, rhs = line.split("=", 1)
    lhs = lhs.strip()
    rhs = rhs.rsplit(";", 1)[0].strip()
    return lhs, rhs


def _parse_memory_expression_body(body: str) -> _MemoryExpressionShape | None:
    expr = re.sub(r"\s+", "", body.strip())
    expr = expr.strip("()")
    absolute = _parse_int(expr)
    if absolute is not None:
        return {
            "base": None,
            "offset": None,
            "index": None,
            "scale": None,
            "absolute_address": absolute,
        }
    indexed_offset = re.fullmatch(
        r"(?P<base>[A-Za-z_][A-Za-z0-9_]*)\+"
        r"(?P<index>[A-Za-z_][A-Za-z0-9_]*)\*"
        r"(?P<scale>0x[0-9A-Fa-f]+|\d+)"
        r"(?P<offset>[+-](?:0x[0-9A-Fa-f]+|\d+))?",
        expr,
    )
    if indexed_offset:
        scale = _parse_int(indexed_offset.group("scale"))
        offset = _parse_signed_int(indexed_offset.group("offset") or "0")
        return {
            "base": indexed_offset.group("base"),
            "offset": offset,
            "index": indexed_offset.group("index"),
            "scale": scale,
            "absolute_address": None,
        }
    offset_indexed = re.fullmatch(
        r"(?P<base>[A-Za-z_][A-Za-z0-9_]*)"
        r"(?P<offset>[+-](?:0x[0-9A-Fa-f]+|\d+))\+"
        r"(?P<index>[A-Za-z_][A-Za-z0-9_]*)\*"
        r"(?P<scale>0x[0-9A-Fa-f]+|\d+)",
        expr,
    )
    if offset_indexed:
        scale = _parse_int(offset_indexed.group("scale"))
        offset = _parse_signed_int(offset_indexed.group("offset"))
        return {
            "base": offset_indexed.group("base"),
            "offset": offset,
            "index": offset_indexed.group("index"),
            "scale": scale,
            "absolute_address": None,
        }
    indexed = re.fullmatch(
        r"(?P<base>[A-Za-z_][A-Za-z0-9_]*)\+(?P<index>[A-Za-z_][A-Za-z0-9_]*)\*(?P<scale>0x[0-9A-Fa-f]+|\d+)",
        expr,
    )
    if indexed:
        scale = _parse_int(indexed.group("scale"))
        return {
            "base": indexed.group("base"),
            "offset": None,
            "index": indexed.group("index"),
            "scale": scale,
            "absolute_address": None,
        }
    plus = re.fullmatch(
        r"(?P<base>[A-Za-z_][A-Za-z0-9_]*)(?P<offset>[+-](?:0x[0-9A-Fa-f]+|\d+))",
        expr,
    )
    if plus:
        offset = _parse_signed_int(plus.group("offset"))
        return {
            "base": plus.group("base"),
            "offset": offset,
            "index": None,
            "scale": None,
            "absolute_address": None,
        }
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", expr):
        return {
            "base": expr,
            "offset": 0,
            "index": None,
            "scale": None,
            "absolute_address": None,
        }
    return None


def _width_bits_from_memory_context(
    *,
    expression: str,
    line: str,
) -> int | None:
    typed = re.search(
        rf"\*\s*\(\s*(?P<c_type>[^()]+?)\s*\*\s*\)\s*"
        rf"\(?\s*{re.escape(expression)}\s*\)?",
        line,
    )
    if typed:
        return _width_bits_from_c_type(typed.group("c_type"))
    return None


def _width_bits_from_c_type(c_type: str) -> int | None:
    lowered = re.sub(r"\s+", " ", c_type.strip().lower())
    if "*" in lowered or lowered in {"pvoid", "void *", "uintptr_t", "size_t"}:
        return 64
    if any(token in lowered for token in ("uint64", "int64", "ulonglong", "qword")):
        return 64
    if any(token in lowered for token in ("uint32", "int32", "ulong", "dword")):
        return 32
    if any(token in lowered for token in ("uint16", "int16", "ushort", "word")):
        return 16
    if any(token in lowered for token in ("uint8", "int8", "uchar", "byte", "char")):
        return 8
    return None


def _memory_access_role(
    *,
    base: str | int | None,
    absolute_address: str | int | None,
    index: str | int | None,
    scale: str | int | None,
    output_var: str | None,
    selector_table: SelectorTableFact | None,
) -> str:
    base_name = base if isinstance(base, str) else None
    if absolute_address is not None:
        return "global"
    if base_name is not None and base_name.startswith("stack_"):
        return "stack_slot"
    if base_name is not None and output_var is not None and base_name == output_var:
        return "output_buffer"
    if index is not None and (
        selector_table is not None or (isinstance(scale, int) and scale in {4, 8})
    ):
        return "selector_table"
    if base_name is not None and base_name.startswith("arg"):
        return "argument_memory"
    return "memory"


def _memory_access_confidence(
    *,
    base: str | int | None,
    absolute_address: str | int | None,
    index: str | int | None,
) -> float:
    if absolute_address is not None:
        return 0.74
    if isinstance(base, str) and base.startswith("stack_"):
        return 0.72
    if index is not None:
        return 0.76
    return 0.70


def _memory_access_key(access: MemoryAccessFact) -> str:
    if access.absolute_address is not None:
        return f"{access.kind}:{_hex(access.absolute_address)}"
    if access.base is None:
        return f"{access.kind}:{access.expression}"
    if access.index is not None and access.scale is not None:
        key = f"{access.kind}:{access.base}+{access.index}*{access.scale}"
        if access.offset is not None and access.offset != 0:
            sign = "+" if access.offset >= 0 else "-"
            key += f"{sign}{_hex(abs(access.offset))}"
        return key
    offset = access.offset
    if offset is not None and offset != 0:
        sign = "+" if offset >= 0 else "-"
        return f"{access.kind}:{access.base}{sign}{_hex(abs(offset))}"
    return f"{access.kind}:{access.base}"


def _is_required_memory_access(access: MemoryAccessFact) -> bool:
    if access.role == "global":
        return access.absolute_address is not None
    if access.role in {"argument_memory", "output_buffer"}:
        return (
            access.kind == "write" and access.offset is not None and access.offset != 0
        )
    return False


def _memory_access_preserved(text: str, access: MemoryAccessFact) -> bool:
    if access.absolute_address is not None:
        return _contains_int(text, access.absolute_address)
    if access.offset is not None and access.offset != 0:
        return _contains_int(text, abs(access.offset))
    if access.role == "output_buffer":
        return "OutputBuffer" in text
    if access.base is not None:
        return re.search(rf"\b{re.escape(access.base)}\b", text) is not None
    return False


def _field_offset_group_facts(
    memory_accesses: list[MemoryAccessFact],
) -> list[FieldOffsetGroupFact]:
    grouped: dict[tuple[str, str], list[MemoryAccessFact]] = {}
    for access in memory_accesses:
        if access.base is None or access.offset is None:
            continue
        if access.base.startswith("stack_"):
            continue
        grouped.setdefault((access.base, access.role), []).append(access)

    facts: list[FieldOffsetGroupFact] = []
    for (base, role), accesses in sorted(grouped.items()):
        read_offsets = sorted(
            {
                int(access.offset)
                for access in accesses
                if access.kind == "read" and access.offset is not None
            }
        )
        write_offsets = sorted(
            {
                int(access.offset)
                for access in accesses
                if access.kind == "write" and access.offset is not None
            }
        )
        offsets = [*read_offsets, *write_offsets]
        if not offsets:
            continue
        facts.append(
            FieldOffsetGroupFact(
                base=base,
                role=role,
                read_offsets=read_offsets,
                write_offsets=write_offsets,
                access_count=len(accesses),
                max_offset=max(offsets),
                line_start=min(access.line for access in accesses),
                line_end=max(access.line for access in accesses),
                confidence=_field_offset_group_confidence(role, offsets),
            )
        )
    return facts


def _field_offset_group_confidence(role: str, offsets: list[int]) -> float:
    if role == "output_buffer":
        return 0.78
    if len(set(offsets)) >= 3:
        return 0.72
    if role == "argument_memory":
        return 0.68
    return 0.62


def _field_offset_group_key(group: FieldOffsetGroupFact) -> str:
    return f"{group.base}:{group.role}"


def _is_required_field_offset_group(group: FieldOffsetGroupFact) -> bool:
    offsets = {*group.read_offsets, *group.write_offsets}
    if group.role == "output_buffer":
        return len(group.write_offsets) >= 2
    if group.role in {"memory", "selector_table"}:
        return group.confidence >= 0.70 and len(group.read_offsets) >= 2
    return group.confidence >= 0.70 and len(offsets) >= 3


def _field_offset_group_preserved(text: str, group: FieldOffsetGroupFact) -> bool:
    lowered = text.lower()
    role_tokens = {
        "argument_memory": ("arg", "field", "offset"),
        "memory": ("field", "read_field", "version"),
        "output_buffer": ("outputbuffer", "write_field", "output"),
        "selector_table": ("selector", "table", "index"),
    }
    tokens = role_tokens.get(group.role, ("field", "offset"))
    if not any(token in lowered for token in tokens):
        return False
    if group.max_offset is not None and group.max_offset != 0:
        return _contains_int(text, group.max_offset)
    offsets = sorted({*group.read_offsets, *group.write_offsets})
    nonzero_offsets = [offset for offset in offsets if offset != 0]
    if not nonzero_offsets:
        return True
    required_count = min(2, len(nonzero_offsets))
    return sum(1 for offset in nonzero_offsets if _contains_int(text, offset)) >= (
        required_count
    )


_GLOBAL_ASSIGNMENT_RE = re.compile(
    r"\s*(?P<lhs>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<addr>0x[0-9A-Fa-f]+)\s*;"
)
_ABSOLUTE_CALL_RE = re.compile(r"\b(?P<addr>0x[0-9A-Fa-f]+)\s*\(")
_CALLBACK_POINTER_OFFSETS = {0x20, 0x28, 0x30, 0x38, 0x40}


def _data_reference_facts(
    text: str,
    *,
    memory_accesses: list[MemoryAccessFact],
    selector_table: SelectorTableFact | None,
) -> list[DataReferenceFact]:
    facts: list[DataReferenceFact] = []
    seen: set[str] = set()
    indexed_bases = {
        access.base
        for access in memory_accesses
        if access.base is not None
        and access.index is not None
        and access.scale is not None
    }
    indexed_selectors = {
        access.index
        for access in memory_accesses
        if access.index is not None and access.scale is not None
    }

    def add(fact: DataReferenceFact) -> None:
        key = _data_reference_key(fact)
        if key in seen:
            return
        seen.add(key)
        facts.append(fact)

    absolute_call_lines: list[int] = []
    indirect_call_lines: dict[str, list[int]] = {}
    indirect_jump_lines: dict[str, list[int]] = {}
    for line_no, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        for count_ref in _global_count_reference_facts_from_line(
            line,
            line_no=line_no,
            indexed_selectors=indexed_selectors,
            selector_table=selector_table,
        ):
            add(count_ref)
        assignment = _GLOBAL_ASSIGNMENT_RE.match(line)
        if assignment:
            address = _parse_int(assignment.group("addr"))
            lhs = assignment.group("lhs")
            if address is not None and _looks_like_global_address(address):
                is_table = lhs in indexed_bases or (
                    selector_table is not None
                    and selector_table.table_expression.lower()
                    == assignment.group("addr").lower()
                )
                add(
                    DataReferenceFact(
                        kind="global_address",
                        expression=assignment.group("addr"),
                        address=address,
                        base=lhs,
                        role="global_table_candidate" if is_table else "global_address",
                        line=line_no,
                        snippet=line,
                        confidence=0.78 if is_table else 0.70,
                    )
                )
        for call in _ABSOLUTE_CALL_RE.finditer(line):
            address = _parse_int(call.group("addr"))
            if address is None or not _looks_like_global_address(address):
                continue
            absolute_call_lines.append(line_no)
            add(
                DataReferenceFact(
                    kind="absolute_call",
                    expression=f"{call.group('addr')}()",
                    address=address,
                    role="absolute_indirect_call",
                    line=line_no,
                    snippet=line,
                    confidence=0.74,
                )
            )
        for name, _args in _primitive_calls(line):
            if name.lower() in _CONTROL_CALLS:
                continue
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
                indirect_call_lines.setdefault(name, []).append(line_no)
        for jump in _GOTO_RE.finditer(line):
            target = jump.group("label")
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", target):
                indirect_jump_lines.setdefault(target, []).append(line_no)

    for access in memory_accesses:
        if access.absolute_address is not None:
            add(
                DataReferenceFact(
                    kind="global_memory",
                    expression=access.expression,
                    address=access.absolute_address,
                    role="global_memory",
                    line=access.line,
                    snippet=access.snippet,
                    confidence=access.confidence,
                )
            )
        if (
            access.base is not None
            and access.index is not None
            and access.scale is not None
        ):
            role = (
                "selector_table" if access.role == "selector_table" else "indexed_table"
            )
            add(
                DataReferenceFact(
                    kind="selector_table_load",
                    expression=access.expression,
                    base=access.base,
                    offset=access.offset,
                    index=access.index,
                    scale=access.scale,
                    role=role,
                    line=access.line,
                    snippet=access.snippet,
                    confidence=max(access.confidence, 0.76),
                )
            )
            lhs, _rhs = _assignment_sides(access.snippet)
            if lhs is not None and _is_table_value_called(
                lhs,
                load_line=access.line,
                indirect_call_lines=indirect_call_lines,
            ):
                add(
                    DataReferenceFact(
                        kind="function_pointer_table",
                        expression=access.expression,
                        base=access.base,
                        offset=access.offset,
                        index=access.index,
                        scale=access.scale,
                        role="function_pointer_table_call",
                        line=access.line,
                        snippet=access.snippet,
                        confidence=max(access.confidence, 0.78),
                    )
                )
            if lhs is not None and _is_table_value_jumped(
                lhs,
                load_line=access.line,
                indirect_jump_lines=indirect_jump_lines,
            ):
                add(
                    DataReferenceFact(
                        kind="jump_table",
                        expression=access.expression,
                        base=access.base,
                        offset=access.offset,
                        index=access.index,
                        scale=access.scale,
                        role="jump_table_dispatch",
                        line=access.line,
                        snippet=access.snippet,
                        confidence=max(access.confidence, 0.76),
                    )
                )
        if _is_import_thunk_access(access):
            lhs, _rhs = _assignment_sides(access.snippet)
            is_called = lhs is not None and _is_table_value_called(
                lhs,
                load_line=access.line,
                indirect_call_lines=indirect_call_lines,
            )
            add(
                DataReferenceFact(
                    kind="import_thunk",
                    expression=access.expression,
                    base=access.base,
                    offset=access.offset,
                    target_symbol=_import_thunk_symbol(access.base or ""),
                    role="import_thunk_call" if is_called else "import_thunk_load",
                    line=access.line,
                    snippet=access.snippet,
                    confidence=0.86 if is_called else 0.78,
                )
            )
        if _is_vtable_dispatch_access(access, indirect_call_lines):
            add(
                DataReferenceFact(
                    kind="vtable_dispatch",
                    expression=access.expression,
                    base=access.base,
                    offset=access.offset,
                    role="vtable_method_call",
                    line=access.line,
                    snippet=access.snippet,
                    confidence=0.72,
                )
            )
        if _is_callback_pointer_access(access, absolute_call_lines):
            add(
                DataReferenceFact(
                    kind="callback_pointer",
                    expression=access.expression,
                    base=access.base,
                    offset=access.offset,
                    role="callback_pointer_load",
                    line=access.line,
                    snippet=access.snippet,
                    confidence=0.66,
                )
            )
    return facts


def _is_table_value_called(
    value_name: str,
    *,
    load_line: int,
    indirect_call_lines: dict[str, list[int]],
) -> bool:
    return any(
        0 <= call_line - load_line <= 8
        for call_line in indirect_call_lines.get(value_name, [])
    )


def _is_table_value_jumped(
    value_name: str,
    *,
    load_line: int,
    indirect_jump_lines: dict[str, list[int]],
) -> bool:
    return any(
        0 <= jump_line - load_line <= 8
        for jump_line in indirect_jump_lines.get(value_name, [])
    )


def _is_import_thunk_access(access: MemoryAccessFact) -> bool:
    return (
        access.kind == "read"
        and access.base is not None
        and access.offset in {None, 0}
        and _import_thunk_symbol(access.base) is not None
    )


def _import_thunk_symbol(base: str) -> str | None:
    suffix = base.rsplit("!", 1)[-1].rsplit("::", 1)[-1].strip()
    if not suffix:
        return None
    for prefix in ("__imp__", "__imp_", "_imp_", "imp_", "j_", "thunk_"):
        if suffix.startswith(prefix) and len(suffix) > len(prefix):
            return _clean_symbol_name(suffix.removeprefix(prefix))
    if suffix.endswith("$thunk") and len(suffix) > len("$thunk"):
        return _clean_symbol_name(suffix.removesuffix("$thunk"))
    if suffix.startswith("__imp_") and "@@" in suffix:
        return _clean_symbol_name(suffix.removeprefix("__imp_").split("@@", 1)[0])
    return None


def _is_vtable_dispatch_access(
    access: MemoryAccessFact,
    indirect_call_lines: dict[str, list[int]],
) -> bool:
    if access.kind != "read" or access.base is None or access.offset is None:
        return False
    if access.index is not None or access.absolute_address is not None:
        return False
    if access.offset <= 0:
        return False
    lhs, _rhs = _assignment_sides(access.snippet)
    if lhs is None:
        return False
    if not _is_table_value_called(
        lhs,
        load_line=access.line,
        indirect_call_lines=indirect_call_lines,
    ):
        return False
    return access.role in {"argument_memory", "memory"}


def _is_callback_pointer_access(
    access: MemoryAccessFact,
    absolute_call_lines: list[int],
) -> bool:
    if not absolute_call_lines:
        return False
    if access.kind != "read" or access.base is None:
        return False
    if access.offset not in _CALLBACK_POINTER_OFFSETS:
        return False
    if access.role not in {"memory", "argument_memory"}:
        return False
    return any(abs(access.line - call_line) <= 8 for call_line in absolute_call_lines)


def _data_reference_key(ref: DataReferenceFact) -> str:
    if ref.kind == "global_count":
        key = f"{ref.kind}:{ref.expression}"
        if ref.index is not None:
            return f"{key}:{ref.index}"
        if ref.role == "global_count_load":
            return f"{key}:load"
        return key
    if ref.address is not None:
        return f"{ref.kind}:{_hex(ref.address)}"
    if ref.base is not None and ref.index is not None and ref.scale is not None:
        key = f"{ref.kind}:{ref.base}+{ref.index}*{ref.scale}"
        if ref.offset is not None and ref.offset != 0:
            sign = "+" if ref.offset >= 0 else "-"
            key += f"{sign}{_hex(abs(ref.offset))}"
        return key
    if ref.base is not None and ref.offset is not None:
        if ref.offset == 0:
            return f"{ref.kind}:{ref.base}"
        sign = "+" if ref.offset >= 0 else "-"
        return f"{ref.kind}:{ref.base}{sign}{_hex(abs(ref.offset))}"
    return f"{ref.kind}:{ref.expression}"


_REQUIRED_DATA_REFERENCE_KINDS = {
    "absolute_call",
    "callback_pointer",
    "function_pointer_table",
    "import_thunk",
    "jump_table",
    "vtable_dispatch",
}


def _is_required_data_reference(ref: DataReferenceFact) -> bool:
    if ref.kind == "global_count":
        return ref.role == "selector_bound_count"
    return ref.kind in _REQUIRED_DATA_REFERENCE_KINDS


def _data_reference_preserved(text: str, ref: DataReferenceFact) -> bool:
    lowered = text.lower()
    if ref.kind == "global_count":
        if ref.expression and ref.expression in text:
            return True
        if ref.index and ref.index.lower() in lowered and "count" in lowered:
            return True
        if ref.target_symbol and ref.target_symbol in text and "count" in lowered:
            return True
    if ref.target_symbol and re.search(rf"\b{re.escape(ref.target_symbol)}\b", text):
        return True
    if ref.expression and ref.expression in text:
        return True
    if ref.address is not None and _contains_int(text, ref.address):
        return True
    if ref.base and re.search(rf"\b{re.escape(ref.base)}\b", text):
        return True
    if ref.kind in {"function_pointer_table", "jump_table"}:
        return (
            ref.index is not None
            and ref.index.lower() in lowered
            and any(
                token in lowered
                for token in ("dispatch", "function pointer", "jump table", "table")
            )
        )
    if ref.kind == "vtable_dispatch":
        return any(token in lowered for token in ("vtable", "virtual", "method"))
    if ref.kind == "callback_pointer":
        return "callback" in lowered
    return False


_GLOBAL_COUNT_TOKEN_RE = re.compile(
    r"\b(?P<name>[A-Za-z_.$][A-Za-z0-9_.$]*"
    r"(?:Count|Limit|Maximum|Max|Entries|EntryCount|NumberOfEntries))\b"
)
_COUNT_ASSIGNMENT_RE = re.compile(
    r"^\s*(?P<lhs>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
    r"(?P<count>[A-Za-z_.$][A-Za-z0-9_.$]*)\s*;"
)


def _global_count_reference_facts_from_line(
    line: str,
    *,
    line_no: int,
    indexed_selectors: set[str],
    selector_table: SelectorTableFact | None,
) -> list[DataReferenceFact]:
    out: list[DataReferenceFact] = []
    condition = _condition_expression_from_line(line)
    if condition:
        for name in _global_count_tokens(condition):
            selector = _selector_in_condition(
                condition,
                indexed_selectors=indexed_selectors,
                selector_table=selector_table,
            )
            out.append(
                DataReferenceFact(
                    kind="global_count",
                    expression=name,
                    base=name,
                    index=selector,
                    target_symbol=_global_count_target_symbol(name, selector_table),
                    role="selector_bound_count" if selector else "global_count",
                    line=line_no,
                    snippet=line,
                    confidence=0.82 if selector else 0.70,
                )
            )
    assignment = _COUNT_ASSIGNMENT_RE.match(line)
    if assignment:
        name = assignment.group("count")
        if _looks_like_global_count_name(name):
            out.append(
                DataReferenceFact(
                    kind="global_count",
                    expression=name,
                    base=name,
                    target_symbol=_global_count_target_symbol(name, selector_table),
                    role="global_count_load",
                    line=line_no,
                    snippet=line,
                    confidence=0.68,
                )
            )
    return out


def _condition_expression_from_line(line: str) -> str | None:
    if_match = re.search(r"\bif\s*\((?P<condition>.*)\)", line)
    if if_match:
        return if_match.group("condition").strip()
    flag_match = _FLAG_ASSIGNMENT_RE.match(line)
    if flag_match:
        return flag_match.group("expr").strip()
    return None


def _global_count_tokens(expression: str) -> list[str]:
    return _dedupe(
        [
            match.group("name")
            for match in _GLOBAL_COUNT_TOKEN_RE.finditer(expression)
            if _looks_like_global_count_name(match.group("name"))
        ]
    )


def _looks_like_global_count_name(name: str) -> bool:
    lowered = name.lower()
    if lowered in {"count", "max", "maximum", "entries"}:
        return False
    return bool(
        re.search(
            r"(?:count|limit|maximum|max|entries|entrycount|numberofentries)$",
            lowered,
        )
    )


def _selector_in_condition(
    condition: str,
    *,
    indexed_selectors: set[str],
    selector_table: SelectorTableFact | None,
) -> str | None:
    tokens = set(_identifier_tokens(condition.lower()))
    for selector in sorted(indexed_selectors):
        if selector.lower() in tokens:
            return selector
    if selector_table is not None:
        selector = selector_table.index_expression
        if selector.lower() in tokens:
            return selector
    for token in _identifier_tokens(condition):
        if re.search(r"(?:index|selector|class|code)$", token, flags=re.I):
            return token
    return None


def _global_count_target_symbol(
    count_name: str,
    selector_table: SelectorTableFact | None,
) -> str | None:
    if selector_table is None:
        return None
    if (
        selector_table.count_name
        and count_name.lower() == selector_table.count_name.lower()
    ):
        return selector_table.table_name
    table_prefix = selector_table.table_name.lower().rstrip("s")
    if count_name.lower().startswith(table_prefix):
        return selector_table.table_name
    return None


def _looks_like_global_address(value: int) -> bool:
    return value >= 0x10000


_FLAG_ASSIGNMENT_RE = re.compile(
    r"\s*(?P<flag>%[A-Za-z_][A-Za-z0-9_]*)\s*=\s*\((?P<expr>[^;]+)\)\s*;"
)
_IF_RE = re.compile(r"\s*if\s*\(\s*(?P<condition>.*)\)\s*\{(?P<body>[^}]*)")
_CONDITION_RE = re.compile(
    r"(?P<lhs>.+?)\s*(?P<operator>u<=|u>=|u<|u>|==|!=|<=|>=|<|>)\s*(?P<rhs>.+)"
)


def _path_condition_facts(
    text: str,
    *,
    argument_roles: dict[str, LiftArgumentRole],
    output_size: int | None,
    selector_table: SelectorTableFact | None,
) -> list[PathConditionFact]:
    facts: list[PathConditionFact] = []
    seen: set[tuple[str, int, int | None]] = set()
    flag_facts: dict[str, PathConditionFact] = {}
    lines = text.splitlines()

    def add(fact: PathConditionFact) -> None:
        key = (_path_condition_key(fact), fact.line, fact.branch_line)
        if key in seen:
            return
        seen.add(key)
        facts.append(fact)

    for line_no, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line:
            continue
        flag_match = _FLAG_ASSIGNMENT_RE.match(line)
        if flag_match:
            fact = _path_condition_from_expression(
                flag_match.group("expr"),
                line_no=line_no,
                snippet=line,
                flag_name=flag_match.group("flag"),
                argument_roles=argument_roles,
                output_size=output_size,
                selector_table=selector_table,
            )
            if fact is not None:
                flag_facts[flag_match.group("flag")] = fact
            continue
        if_match = _IF_RE.match(line)
        if not if_match:
            continue
        condition = if_match.group("condition").strip()
        target = _branch_target(line, lines, line_no)
        source_fact = flag_facts.get(condition)
        if source_fact is not None:
            add(
                source_fact.model_copy(
                    update={
                        "target_label": target,
                        "branch_line": line_no,
                        "snippet": f"{source_fact.snippet} -> {line}",
                    }
                )
            )
            continue
        fact = _path_condition_from_expression(
            condition,
            line_no=line_no,
            snippet=line,
            flag_name=None,
            argument_roles=argument_roles,
            output_size=output_size,
            selector_table=selector_table,
        )
        if fact is not None:
            add(
                fact.model_copy(update={"target_label": target, "branch_line": line_no})
            )
    return facts


def _path_condition_from_expression(
    expression: str,
    *,
    line_no: int,
    snippet: str,
    flag_name: str | None,
    argument_roles: dict[str, LiftArgumentRole],
    output_size: int | None,
    selector_table: SelectorTableFact | None,
) -> PathConditionFact | None:
    normalized = _strip_outer_parens(expression.strip())
    match = _CONDITION_RE.fullmatch(normalized)
    if not match:
        return _path_condition_from_boolean_expression(
            normalized,
            line_no=line_no,
            snippet=snippet,
            flag_name=flag_name,
            argument_roles=argument_roles,
        )
    lhs = _strip_outer_parens(match.group("lhs").strip())
    rhs = _strip_outer_parens(match.group("rhs").strip())
    operator = match.group("operator")
    condition_kind = _condition_kind(operator)
    role, confidence = _path_condition_role(
        lhs=lhs,
        operator=operator,
        rhs=rhs,
        condition_kind=condition_kind,
        argument_roles=argument_roles,
        output_size=output_size,
        selector_table=selector_table,
    )
    return PathConditionFact(
        role=role,
        expression=normalized,
        lhs_expression=lhs,
        operator=operator,
        rhs_expression=rhs,
        condition_kind=condition_kind,
        flag_name=flag_name,
        line=line_no,
        snippet=snippet,
        confidence=confidence,
    )


def _path_condition_from_boolean_expression(
    expression: str,
    *,
    line_no: int,
    snippet: str,
    flag_name: str | None,
    argument_roles: dict[str, LiftArgumentRole],
) -> PathConditionFact | None:
    normalized = _strip_outer_parens(expression.strip())
    negated = normalized.startswith("!")
    probe = _strip_outer_parens(normalized.removeprefix("!").strip())
    status_macro = _status_macro_condition(
        probe,
        normalized=normalized,
        negated=negated,
        line_no=line_no,
        snippet=snippet,
        flag_name=flag_name,
    )
    if status_macro is not None:
        return status_macro
    for name, _args in _primitive_calls(probe):
        cleaned = _clean_symbol_name(name)
        lowered = cleaned.lower()
        if lowered in {
            "sesingleprivilegecheck",
            "seprivilegecheck",
            "seaccesscheck",
        }:
            return PathConditionFact(
                role="privilege_gate",
                expression=normalized,
                lhs_expression=cleaned,
                operator="!" if negated else "truthy",
                rhs_expression=None,
                condition_kind="negated_boolean_call" if negated else "boolean_call",
                flag_name=flag_name,
                line=line_no,
                snippet=snippet,
                confidence=0.82,
            )
        if lowered in {
            "exgetpreviousmode",
            "kegetpreviousmode",
            "iogetrequestormode",
        }:
            return PathConditionFact(
                role="mode_gate",
                expression=normalized,
                lhs_expression=cleaned,
                operator="!" if negated else "truthy",
                rhs_expression=None,
                condition_kind="negated_boolean_call" if negated else "boolean_call",
                flag_name=flag_name,
                line=line_no,
                snippet=snippet,
                confidence=0.78,
            )
    if _looks_like_status_token(probe, argument_roles):
        return PathConditionFact(
            role="status_gate",
            expression=normalized,
            lhs_expression=probe,
            operator="!" if negated else "truthy",
            rhs_expression=None,
            condition_kind="negated_status_value" if negated else "status_value",
            flag_name=flag_name,
            line=line_no,
            snippet=snippet,
            confidence=0.64,
        )
    return None


def _path_condition_role(
    *,
    lhs: str,
    operator: str,
    rhs: str,
    condition_kind: str,
    argument_roles: dict[str, LiftArgumentRole],
    output_size: int | None,
    selector_table: SelectorTableFact | None,
) -> tuple[str, float]:
    normalized = f"{lhs} {rhs}".lower()
    role_text = _path_condition_role_text(
        (lhs, rhs),
        argument_roles=argument_roles,
    )
    if _looks_like_privilege_condition(normalized):
        return "privilege_gate", 0.82
    if _looks_like_mode_condition(normalized):
        return "mode_gate", 0.78
    if _looks_like_status_condition(lhs, rhs):
        return "status_gate", 0.78
    if _looks_like_bounds_condition(
        lhs=lhs,
        operator=operator,
        rhs=rhs,
        role_text=role_text,
    ):
        return "bounds_gate", 0.82
    if _is_null_or_zero_literal(lhs) or _is_null_or_zero_literal(rhs):
        return "zero_length_or_null_gate", 0.76
    if _looks_like_selector_condition(
        lhs=lhs,
        rhs=rhs,
        selector_table=selector_table,
    ):
        return "selector_gate", 0.74 if selector_table is None else 0.80
    if (
        "length" in role_text
        or re.search(r"\b(?:len|length|size|cb|bytes)\b", normalized)
        or (output_size is not None and _condition_references_value(rhs, output_size))
    ):
        return "length_gate", 0.78
    if condition_kind in {
        "unsigned_less",
        "unsigned_less_equal",
        "unsigned_greater",
        "unsigned_greater_equal",
    }:
        return "range_gate", 0.64
    if operator in {"<", "<=", ">", ">="}:
        return "range_gate", 0.60
    return "compare_gate", 0.54


def _condition_kind(operator: str) -> str:
    return {
        "==": "equal",
        "!=": "not_equal",
        "u<": "unsigned_less",
        "u<=": "unsigned_less_equal",
        "u>": "unsigned_greater",
        "u>=": "unsigned_greater_equal",
        "<": "signed_less",
        "<=": "signed_less_equal",
        ">": "signed_greater",
        ">=": "signed_greater_equal",
    }.get(operator, "compare")


def _looks_like_privilege_condition(expression: str) -> bool:
    return any(
        token in expression
        for token in (
            "privilege",
            "sesingleprivilegecheck",
            "seprivilegecheck",
            "seaccesscheck",
            "access_status",
        )
    )


def _looks_like_mode_condition(expression: str) -> bool:
    return any(
        token in expression
        for token in (
            "previousmode",
            "requestormode",
            "usermode",
            "kernelmode",
            "access_mode",
        )
    ) or bool(re.search(r"\bmode\b", expression))


def _branch_target(line: str, lines: list[str], line_no: int) -> str | None:
    for candidate in (line, lines[line_no].strip() if line_no < len(lines) else ""):
        match = re.search(
            r"\bgoto\s+(?P<label>[A-Za-z_.$][A-Za-z0-9_.$]*)\s*;", candidate
        )
        if match:
            return match.group("label")
    return None


_LABEL_RE = re.compile(r"^\s*(?P<label>[A-Za-z_.$][A-Za-z0-9_.$]*)\s*:\s*$")
_GOTO_RE = re.compile(r"\bgoto\s+(?P<label>[A-Za-z_.$][A-Za-z0-9_.$]*)\s*;")


def _loop_summary_facts(text: str) -> list[LoopSummaryFact]:
    lines = text.splitlines()
    label_lines: dict[str, int] = {}
    for line_no, raw_line in enumerate(lines, start=1):
        match = _LABEL_RE.match(raw_line.strip())
        if match:
            label_lines[match.group("label")] = line_no

    facts: list[LoopSummaryFact] = []
    seen: set[tuple[str, int]] = set()
    for line_no, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        for match in _GOTO_RE.finditer(line):
            label = match.group("label")
            header_line = label_lines.get(label)
            if header_line is None or header_line >= line_no:
                continue
            key = (label, line_no)
            if key in seen:
                continue
            seen.add(key)
            condition, exit_label = _loop_exit_condition(
                lines,
                label,
                header_line=header_line,
                backedge_line=line_no,
            )
            facts.append(
                LoopSummaryFact(
                    loop_label=label,
                    header_line=header_line,
                    backedge_line=line_no,
                    body_line_start=header_line + 1,
                    body_line_end=line_no - 1,
                    condition_expression=condition,
                    exit_label=exit_label,
                    calls=_loop_body_calls(lines, header_line, line_no),
                    confidence=0.76 if condition else 0.66,
                )
            )
    return facts


def _loop_exit_condition(
    lines: list[str],
    loop_label: str,
    *,
    header_line: int,
    backedge_line: int,
) -> tuple[str | None, str | None]:
    flag_exprs: dict[str, str] = {}
    best: tuple[str | None, str | None] = (None, None)
    for raw_line in lines[header_line:backedge_line]:
        line = raw_line.strip()
        flag = _FLAG_ASSIGNMENT_RE.match(line)
        if flag:
            flag_exprs[flag.group("flag")] = flag.group("expr").strip()
            continue
        if_match = _IF_RE.match(line)
        if not if_match:
            continue
        target = _GOTO_RE.search(line)
        if target is None or target.group("label") == loop_label:
            continue
        condition = if_match.group("condition").strip()
        condition = condition.removeprefix("!").strip()
        best = (flag_exprs.get(condition, condition), target.group("label"))
    return best


def _loop_body_calls(
    lines: list[str],
    header_line: int,
    backedge_line: int,
) -> list[str]:
    calls: list[str] = []
    for raw_line in lines[header_line:backedge_line]:
        for name, _args in _primitive_calls(raw_line.strip()):
            if name.lower() in _CONTROL_CALLS:
                continue
            calls.append(_clean_symbol_name(name))
    return _dedupe(calls)


def _loop_summary_key(loop: LoopSummaryFact) -> str:
    return f"{loop.loop_label}:{loop.backedge_line}"


def _loop_summary_preserved(text: str, loop: LoopSummaryFact) -> bool:
    lowered = text.lower()
    if "loop summaries" in lowered or loop.loop_label in text:
        return True
    if not re.search(r"\b(?:for|while|do)\b", lowered):
        return False
    if loop.condition_expression and _loop_condition_tokens_preserved(
        text,
        loop.condition_expression,
    ):
        return True
    return bool(loop.calls) and all(call in text for call in loop.calls[:3])


def _loop_condition_tokens_preserved(text: str, condition: str) -> bool:
    tokens = [
        token
        for token in re.findall(r"[A-Za-z_][A-Za-z0-9_]*|0x[0-9A-Fa-f]+|\d+", condition)
        if not token.startswith("%")
    ]
    if not tokens:
        return False
    return all(re.search(rf"\b{re.escape(token)}\b", text) for token in tokens[:4])


def _path_condition_key(fact: PathConditionFact) -> str:
    lhs = fact.lhs_expression or "unknown"
    op = fact.operator or "?"
    rhs = fact.rhs_expression or "unknown"
    return f"{fact.role}:{lhs}:{op}:{rhs}"


def _is_required_path_condition(condition: PathConditionFact) -> bool:
    if condition.role in {
        "status_gate",
        "zero_length_or_null_gate",
        "selector_gate",
        "mode_gate",
        "privilege_gate",
        "bounds_gate",
    }:
        return True
    if condition.role == "length_gate":
        return True
    if condition.role == "range_gate":
        return _parse_signed_int(condition.rhs_expression or "") is not None
    return False


def _path_condition_preserved(
    text: str,
    condition: PathConditionFact,
    packet: WindowsFunctionLiftPacket,
) -> bool:
    lowered = text.lower()
    lhs = condition.lhs_expression or ""
    rhs = condition.rhs_expression or ""
    semantic = _semantic_name_for_expression(packet, lhs)
    rhs_value = _parse_signed_int(rhs)
    if rhs_value is not None:
        if _contains_int(text, abs(rhs_value)):
            return True
        if rhs_value == 4 and "sizeof(ulong)" in lowered:
            return True
        if rhs_value < 0 and _signed_hex(rhs_value).lower() in lowered:
            return True
    if condition.role == "zero_length_or_null_gate":
        has_null_or_zero = "null" in lowered or re.search(r"\b0\b", text) is not None
        return has_null_or_zero and (
            semantic is None or semantic in text or lhs in text
        )
    if condition.role in {"length_gate", "range_gate"}:
        if semantic is not None and semantic in text:
            return True
    if condition.role == "bounds_gate":
        return _loop_condition_tokens_preserved(
            text,
            condition.expression,
        ) or any(
            token in lowered
            for token in ("bounds", "limit", "offset", "length", "size", "end")
        )
    if condition.role == "status_gate":
        return "status" in lowered or "nt_success" in lowered
    if condition.role == "selector_gate":
        return any(token in lowered for token in ("index", "selector", "class"))
    if condition.role == "mode_gate":
        return any(
            token in lowered
            for token in (
                "mode",
                "previousmode",
                "requestormode",
                "usermode",
                "kernelmode",
            )
        )
    if condition.role == "privilege_gate":
        return any(
            token in lowered for token in ("privilege", "accesscheck", "access_denied")
        )
    return False


def _entry_abi_argument_preserved(
    text: str,
    argument: EntryAbiArgumentFact,
) -> bool:
    lowered = text.lower()
    if argument.semantic_name and argument.semantic_name.lower() in lowered:
        return True
    if argument.original_name and re.search(
        rf"\b{re.escape(argument.original_name)}\b",
        text,
    ):
        return True
    if argument.role and argument.role.lower() in lowered:
        return True
    return _format_parameter(argument.c_type, argument.semantic_name) in text


_REQUIRED_API_CONTRACT_PRIMITIVES = {
    "probe_for_read",
    "probe_for_write",
    "user_buffer_copy",
    "string_conversion_copy",
    "ioctl_call",
    "pool_allocation",
    "pool_free",
    "registry_query",
    "registry_write",
    "object_reference",
    "object_release",
    "irp_access",
    "mdl_access",
    "alpc_message",
    "trace_emit",
    "callback_registration",
    "callback_dispatch",
    "requestor_mode_read",
    "privilege_check",
    "token_reference",
    "token_query",
    "token_release",
}


def _is_required_api_contract_primitive(primitive: ApiContractPrimitive) -> bool:
    if str(primitive.kind) not in _REQUIRED_API_CONTRACT_PRIMITIVES:
        return False
    return _api_contract_primitive_call_name(primitive) is not None


def _api_contract_primitive_key(primitive: ApiContractPrimitive) -> str:
    call_name = _api_contract_primitive_call_name(primitive) or "unknown"
    return f"{primitive.kind}:{call_name}"


def _api_contract_primitive_call_name(
    primitive: ApiContractPrimitive,
) -> str | None:
    for name, _args in _primitive_calls(primitive.snippet):
        if name.lower() in _CONTROL_CALLS:
            continue
        return _clean_symbol_name(name)
    return None


def _api_contract_primitive_preserved(
    text: str,
    primitive: ApiContractPrimitive,
) -> bool:
    call_name = _api_contract_primitive_call_name(primitive)
    if call_name and re.search(rf"\b{re.escape(call_name)}\s*\(", text):
        return True

    lowered = text.lower()
    kind = str(primitive.kind)
    if kind == "user_buffer_copy":
        return bool(
            re.search(r"\b(?:memcpy|memmove|rtlcopymemory|copy_memory)\s*\(", lowered)
        )
    if kind == "string_conversion_copy":
        return "string" in lowered and any(
            token in lowered for token in ("copy", "convert", "conversion")
        )
    if kind in {"probe_for_read", "probe_for_write"}:
        return "probe" in lowered and any(
            role in lowered for role in ("user", "read", "write")
        )
    if kind in {"registry_query", "registry_write"}:
        return "registry" in lowered or "zwqueryvaluekey" in lowered
    if kind in {"ioctl_call", "alpc_message", "callback_dispatch"}:
        return any(
            token in lowered
            for token in ("ioctl", "alpc", "callback", "deviceiocontrol")
        )
    if kind in {"requestor_mode_read", "privilege_check"}:
        return any(
            token in lowered
            for token in ("previousmode", "requestormode", "privilege", "accesscheck")
        )
    if kind in {"token_reference", "token_query", "token_release"}:
        return "token" in lowered
    if kind in {"pool_allocation", "pool_free"}:
        return "pool" in lowered or "allocate" in lowered or "free" in lowered
    if kind in {"object_reference", "object_release"}:
        return "object" in lowered and any(
            token in lowered for token in ("reference", "dereference", "release")
        )
    if kind in {"irp_access", "mdl_access"}:
        return "irp" in lowered or "mdl" in lowered
    if kind == "trace_emit":
        return "trace" in lowered or "etw" in lowered or "wpp" in lowered
    if kind == "callback_registration":
        return "callback" in lowered and any(
            token in lowered for token in ("register", "notify", "routine")
        )
    return False


def _semantic_name_for_expression(
    packet: WindowsFunctionLiftPacket,
    expression: str,
) -> str | None:
    role = packet.argument_roles.get(expression)
    if role is not None:
        return role.semantic_name
    return None


def _strip_outer_parens(value: str) -> str:
    text = value.strip()
    while text.startswith("(") and text.endswith(")") and _balanced_parens(text[1:-1]):
        text = text[1:-1].strip()
    return text


def _balanced_parens(value: str) -> bool:
    depth = 0
    for char in value:
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth < 0:
                return False
    return depth == 0


def _is_zero_literal(value: str) -> bool:
    parsed = _parse_signed_int(value)
    return parsed == 0


def _is_null_or_zero_literal(value: str) -> bool:
    text = value.strip().lower()
    if text in {"null", "nullptr"}:
        return True
    if re.fullmatch(r"\(\s*(?:void\s*\*)?\s*0\s*\)", text):
        return True
    return _is_zero_literal(value)


def _status_macro_condition(
    expression: str,
    *,
    normalized: str,
    negated: bool,
    line_no: int,
    snippet: str,
    flag_name: str | None,
) -> PathConditionFact | None:
    match = re.fullmatch(
        r"(?P<macro>NT_SUCCESS|NT_ERROR|NT_WARNING|NT_INFORMATION)\s*"
        r"\(\s*(?P<arg>.+?)\s*\)",
        expression,
        re.IGNORECASE,
    )
    if match is None:
        return None
    macro = match.group("macro").upper()
    arg = _strip_outer_parens(match.group("arg").strip())
    operator = f"!{macro}" if negated else macro
    return PathConditionFact(
        role="status_gate",
        expression=normalized,
        lhs_expression=arg,
        operator=operator,
        rhs_expression=None,
        condition_kind="status_macro_false" if negated else "status_macro_true",
        flag_name=flag_name,
        line=line_no,
        snippet=snippet,
        confidence=0.86 if macro == "NT_SUCCESS" else 0.80,
    )


def _looks_like_status_token(
    expression: str,
    argument_roles: dict[str, LiftArgumentRole],
) -> bool:
    lowered = expression.lower()
    if re.search(r"\b(?:status|ntstatus|hr|hresult)\b", lowered):
        return True
    for role in argument_roles.values():
        if role.original_name == expression and "status" in role.role.lower():
            return True
        if role.semantic_name.lower() == lowered and "status" in role.role.lower():
            return True
    return False


def _path_condition_role_text(
    expressions: tuple[str, str],
    *,
    argument_roles: dict[str, LiftArgumentRole],
) -> str:
    text = " ".join(expressions).lower()
    tokens = set(_identifier_tokens(text))
    roles: list[str] = []
    for name, role in argument_roles.items():
        semantic = role.semantic_name.lower()
        if name.lower() in tokens or semantic in tokens or semantic in text:
            roles.append(f"{name} {role.semantic_name} {role.role}".lower())
    return " ".join(roles)


def _identifier_tokens(expression: str) -> list[str]:
    return re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", expression)


def _looks_like_status_condition(lhs: str, rhs: str) -> bool:
    haystack = f"{lhs} {rhs}".lower()
    if re.search(r"\bSTATUS_[A-Za-z0-9_]+\b", f"{lhs} {rhs}"):
        return True
    if "status" in haystack or "ntstatus" in haystack:
        return True
    if rhs.strip().lower() == "ret":
        parsed_lhs = _parse_signed_int(lhs)
        return parsed_lhs is not None and parsed_lhs < 0
    if lhs.strip().lower() != "ret":
        return False
    parsed = _parse_signed_int(rhs)
    return parsed is not None and parsed < 0


def _looks_like_bounds_condition(
    *,
    lhs: str,
    operator: str,
    rhs: str,
    role_text: str,
) -> bool:
    if operator not in {"u<", "u<=", "u>", "u>=", "<", "<=", ">", ">="}:
        return False
    if not (
        _expression_has_extent_arithmetic(lhs) or _expression_has_extent_arithmetic(rhs)
    ):
        return False
    combined = f"{lhs} {rhs} {role_text}".lower()
    return _expression_mentions_extent_or_limit(combined)


def _expression_has_extent_arithmetic(expression: str) -> bool:
    if "+" not in expression and "-" not in expression:
        return False
    return len(_identifier_tokens(expression)) >= 2 or bool(
        re.search(r"\b0x[0-9a-fA-F]+|\b\d+\b", expression)
    )


def _expression_mentions_extent_or_limit(expression: str) -> bool:
    return bool(
        re.search(
            r"\b(?:len|length|size|cb|bytes|count|offset|limit|max|maximum|"
            r"end|output|input|buffer)\b",
            expression,
        )
    )


def _looks_like_selector_condition(
    *,
    lhs: str,
    rhs: str,
    selector_table: SelectorTableFact | None,
) -> bool:
    normalized = f"{lhs} {rhs}".lower()
    if selector_table is not None and re.search(
        r"\b(?:index|selector|class|arg0|ret)\b", normalized
    ):
        return True
    if any(
        token in normalized
        for token in (
            "informationclass",
            "infoclass",
            "queryclass",
            "selector",
            "systeminformationclass",
        )
    ):
        return True
    if re.search(
        r"\b(?:info_class|class|minorfunction|majorfunction|ioctl|controlcode|"
        r"functioncode)\b",
        normalized,
    ):
        return True
    if re.search(r"\barg0\b", normalized):
        rhs_value = _parse_signed_int(rhs)
        lhs_value = _parse_signed_int(lhs)
        return (rhs_value is not None and rhs_value <= 0x1000) or (
            lhs_value is not None and lhs_value <= 0x1000
        )
    return False


def _condition_references_value(expression: str, value: int) -> bool:
    parsed = _parse_signed_int(expression)
    return parsed == value


def _return_statuses(
    *,
    function_name: str,
    output_size: int | None,
    selector_table: SelectorTableFact | None,
) -> list[str]:
    statuses = ["STATUS_SUCCESS"]
    if output_size is not None:
        statuses.append("STATUS_INFO_LENGTH_MISMATCH")
    if selector_table is not None and function_name == "CmQueryBuildVersionInformation":
        statuses.append("STATUS_NO_MORE_ENTRIES")
    return statuses


def _facts(
    *,
    argument_roles: dict[str, LiftArgumentRole],
    function_prototype: PrototypeFact | None,
    entry_abi_arguments: list[EntryAbiArgumentFact],
    call_prototypes: list[PrototypeFact],
    selector_table: SelectorTableFact | None,
    string_copies: list[StringCopyFact],
    output_writes: list[OutputWriteFact],
    memory_accesses: list[MemoryAccessFact],
    field_offset_groups: list[FieldOffsetGroupFact],
    data_references: list[DataReferenceFact],
    path_conditions: list[PathConditionFact],
    loop_summaries: list[LoopSummaryFact],
    output_size: int | None,
    return_statuses: list[str],
    call_counts: Counter[str],
    call_sites: list[CallSiteFact],
    unknown_sections: list[UnknownSectionFact],
) -> list[LiftFact]:
    facts: list[LiftFact] = []
    for role in argument_roles.values():
        facts.append(
            LiftFact(
                kind="argument_role",
                key=role.original_name,
                value=f"{role.semantic_name}:{role.role}",
                confidence=role.confidence,
                snippet=role.evidence[0] if role.evidence else None,
            )
        )
    if function_prototype is not None:
        facts.append(
            LiftFact(
                kind="function_prototype",
                key=function_prototype.symbol,
                value=function_prototype.prototype,
                confidence=function_prototype.confidence,
                snippet="; ".join(function_prototype.provenance) or None,
            )
        )
    for argument in entry_abi_arguments:
        facts.append(
            LiftFact(
                kind="entry_abi_argument",
                key=_entry_abi_argument_key(argument),
                value=f"{argument.semantic_name}:{argument.role or 'unknown'}",
                confidence=argument.confidence,
                snippet=f"{argument.c_type} {argument.semantic_name}",
            )
        )
    for prototype in call_prototypes:
        facts.append(
            LiftFact(
                kind="call_prototype",
                key=prototype.symbol,
                value=prototype.prototype,
                confidence=prototype.confidence,
                snippet="; ".join(prototype.provenance) or None,
            )
        )
    if selector_table is not None:
        facts.append(
            LiftFact(
                kind="selector_table",
                key=selector_table.table_expression,
                value=selector_table.table_name,
                confidence=selector_table.confidence,
                snippet=selector_table.evidence[0] if selector_table.evidence else None,
            )
        )
    for call_name, count in call_counts.items():
        facts.append(
            LiftFact(
                kind="call_count",
                key=call_name,
                value=str(count),
                confidence=0.9,
            )
        )
    for site in call_sites:
        facts.append(
            LiftFact(
                kind="call_site",
                key=_call_site_key(site),
                value=",".join(site.arguments),
                line=site.line,
                snippet=site.snippet,
                confidence=site.confidence,
            )
        )
        if site.return_target is not None:
            facts.append(
                LiftFact(
                    kind="call_site_return",
                    key=_call_site_key(site),
                    value=site.return_target,
                    line=site.line,
                    snippet=site.snippet,
                    confidence=site.confidence,
                )
            )
        for argument in site.argument_facts:
            value = argument.expression
            if argument.parameter_name:
                value = (
                    f"{argument.expression}->{argument.parameter_name}:"
                    f"{argument.role or 'unknown'}"
                )
            facts.append(
                LiftFact(
                    kind="call_site_argument",
                    key=f"{_call_site_key(site)}:{_call_site_argument_key(argument)}",
                    value=value,
                    line=site.line,
                    snippet=site.snippet,
                    confidence=argument.confidence,
                )
            )
    for section in unknown_sections:
        facts.append(
            LiftFact(
                kind="unknown_section",
                key=_unknown_section_key(section),
                value=section.reason,
                line=section.line,
                snippet=section.snippet,
                confidence=section.confidence,
            )
        )
    for copy in string_copies:
        facts.append(
            LiftFact(
                kind="string_copy",
                key=f"{copy.call_name}:{copy.line}",
                value=copy.snippet,
                line=copy.line,
                snippet=copy.snippet,
                confidence=copy.confidence,
            )
        )
    for write in output_writes:
        facts.append(
            LiftFact(
                kind="output_write",
                key=f"offset:{_hex(write.output_offset or 0)}",
                value=write.rhs_expression,
                line=write.line,
                snippet=write.snippet,
                confidence=write.confidence,
            )
        )
    for access in memory_accesses:
        value = access.role
        if access.width_bits is not None:
            value = f"{value};width_bits={access.width_bits}"
        facts.append(
            LiftFact(
                kind="memory_access",
                key=_memory_access_key(access),
                value=value,
                line=access.line,
                snippet=access.snippet,
                confidence=access.confidence,
            )
        )
    for group in field_offset_groups:
        facts.append(
            LiftFact(
                kind="field_offset_group",
                key=_field_offset_group_key(group),
                value=(
                    "reads="
                    + ",".join(_hex(offset) for offset in group.read_offsets)
                    + ";writes="
                    + ",".join(_hex(offset) for offset in group.write_offsets)
                ),
                line=group.line_start,
                confidence=group.confidence,
            )
        )
    for ref in data_references:
        facts.append(
            LiftFact(
                kind="data_reference",
                key=_data_reference_key(ref),
                value=ref.role,
                line=ref.line,
                snippet=ref.snippet,
                confidence=ref.confidence,
            )
        )
    for condition in path_conditions:
        facts.append(
            LiftFact(
                kind="path_condition",
                key=_path_condition_key(condition),
                value=condition.expression,
                line=condition.line,
                snippet=condition.snippet,
                confidence=condition.confidence,
            )
        )
    for loop in loop_summaries:
        facts.append(
            LiftFact(
                kind="loop_summary",
                key=_loop_summary_key(loop),
                value=loop.condition_expression or "unconditional_backedge",
                line=loop.header_line,
                confidence=loop.confidence,
            )
        )
    if output_size is not None:
        facts.append(
            LiftFact(
                kind="constant",
                key="output_size",
                value=_hex(output_size),
                confidence=0.86,
            )
        )
    for status in return_statuses:
        facts.append(
            LiftFact(
                kind="return_status",
                key=status,
                value=status,
                confidence=0.72 if status != "STATUS_SUCCESS" else 0.82,
                inferred=status != "STATUS_SUCCESS",
            )
        )
    return facts


def _required_facts(
    *,
    call_counts: Counter[str],
    call_sites: list[CallSiteFact],
    output_size: int | None,
    string_copies: list[StringCopyFact],
    output_writes: list[OutputWriteFact],
    field_offset_groups: list[FieldOffsetGroupFact],
    data_references: list[DataReferenceFact],
    return_statuses: list[str],
) -> list[str]:
    facts: list[str] = []
    for call_name in ("memset", "CmpQueryDowncastString"):
        if call_counts.get(call_name):
            facts.append(f"calls:{call_name}")
    for site in call_sites:
        if site.return_target is not None:
            facts.append(
                f"call_site_return:{_call_site_key(site)}:{site.return_target}"
            )
        for argument in site.argument_facts:
            if _is_required_call_site_argument(argument):
                facts.append(
                    f"call_site_argument:{_call_site_key(site)}:"
                    f"{_call_site_argument_key(argument)}"
                )
    if output_size is not None:
        facts.append(f"constant:{_hex(output_size)}")
    for write in output_writes:
        if _is_required_output_write(write):
            facts.append(f"output_write:{_output_write_key(write)}")
    for group in field_offset_groups:
        if _is_required_field_offset_group(group):
            facts.append(f"field_offset_group:{_field_offset_group_key(group)}")
    for ref in data_references:
        if _is_required_data_reference(ref):
            facts.append(f"data_reference:{_data_reference_key(ref)}")
    for copy in string_copies:
        if copy.dst_offset is not None:
            facts.append(f"dst_offset:{_hex(copy.dst_offset)}")
        if copy.dst_length is not None:
            facts.append(f"length:{_hex(copy.dst_length)}")
    facts.extend(f"status:{status}" for status in return_statuses)
    return _dedupe(facts)


def _coverage(
    *,
    pseudocode: str,
    primitives: list[ApiContractPrimitive],
    argument_roles: dict[str, LiftArgumentRole],
    function_prototype: PrototypeFact | None,
    entry_abi_arguments: list[EntryAbiArgumentFact],
    call_prototypes: list[PrototypeFact],
    call_sites: list[CallSiteFact],
    unknown_sections: list[UnknownSectionFact],
    selector_table: SelectorTableFact | None,
    string_copies: list[StringCopyFact],
    output_writes: list[OutputWriteFact],
    memory_accesses: list[MemoryAccessFact],
    field_offset_groups: list[FieldOffsetGroupFact],
    data_references: list[DataReferenceFact],
    path_conditions: list[PathConditionFact],
    loop_summaries: list[LoopSummaryFact],
    output_size: int | None,
) -> tuple[list[str], list[str]]:
    coverage: list[str] = []
    missing: list[str] = []
    if pseudocode.strip():
        coverage.append("raw_pseudocode")
    else:
        missing.append("raw_pseudocode")
    if primitives:
        coverage.append("api_contract_primitives")
    else:
        missing.append("api_contract_primitives")
    if argument_roles:
        coverage.append("argument_roles")
    else:
        missing.append("argument_roles")
    if function_prototype is not None:
        coverage.append("function_prototype")
    else:
        missing.append("function_prototype")
    if entry_abi_arguments:
        coverage.append("entry_abi_arguments")
    else:
        missing.append("entry_abi_arguments")
    if call_prototypes:
        coverage.append("call_prototypes")
    else:
        missing.append("call_prototypes")
    if call_sites:
        coverage.append("call_sites")
    else:
        missing.append("call_sites")
    if any(site.argument_facts for site in call_sites):
        coverage.append("call_site_arguments")
    else:
        missing.append("call_site_arguments")
    if any(site.return_target is not None for site in call_sites):
        coverage.append("call_site_returns")
    else:
        missing.append("call_site_returns")
    if unknown_sections:
        coverage.append("unknown_sections")
    else:
        missing.append("unknown_sections")
    if selector_table is not None:
        coverage.append("selector_table")
    else:
        missing.append("selector_table")
    if string_copies:
        coverage.append("string_copy_sinks")
    else:
        missing.append("string_copy_sinks")
    if output_writes:
        coverage.append("output_writes")
    else:
        missing.append("output_writes")
    if memory_accesses:
        coverage.append("memory_accesses")
    else:
        missing.append("memory_accesses")
    if field_offset_groups:
        coverage.append("field_offset_groups")
    else:
        missing.append("field_offset_groups")
    if data_references:
        coverage.append("data_references")
    else:
        missing.append("data_references")
    if path_conditions:
        coverage.append("path_conditions")
    else:
        missing.append("path_conditions")
    if loop_summaries:
        coverage.append("loop_summaries")
    else:
        missing.append("loop_summaries")
    if output_size is not None:
        coverage.append("output_size")
    else:
        missing.append("output_size")
    return _dedupe(coverage), _dedupe(missing)


def _looks_like_selector_table_string_lift(packet: WindowsFunctionLiftPacket) -> bool:
    return bool(
        packet.selector_table is not None
        and packet.string_copies
        and packet.argument_roles.get("arg2")
    )


def _looks_like_syscall_stub(packet: WindowsFunctionLiftPacket) -> bool:
    return (
        "unknown(syscall)" in packet.raw_pseudocode and _syscall_id(packet) is not None
    )


def _render_syscall_stub(packet: WindowsFunctionLiftPacket) -> PrettyLift:
    name = packet.function_name
    syscall_id = _syscall_id(packet)
    prototype, args = _known_syscall_signature(name)
    if prototype is None:
        prototype = f"NTSTATUS {name}(void)"
        args = "/* original syscall arguments */"
    lines = [
        prototype,
        "{",
        f"    /* syscall number {_hex(syscall_id or 0)} recovered from the ntdll stub */",
        f"    return SYSCALL_{syscall_id or 0}({args});",
        "}",
    ]
    return PrettyLift(
        function_name=name,
        prototype=prototype,
        pseudocode="\n".join(lines),
        confidence=0.78,
        assumptions=[
            "syscall ABI argument names are supplied from the known Nt* API contract when available",
            "SYSCALL_n is a readable stand-in for the raw syscall instruction",
        ],
    )


def _looks_like_bool_status_wrapper(packet: WindowsFunctionLiftPacket) -> bool:
    text = packet.raw_pseudocode
    return bool(
        "RtlSetLastWin32Error" in text
        and re.search(r"\bret\s*=\s*1\s*;", text)
        and re.search(r"\bret\s*=\s*0\s*;", text)
    )


def _render_bool_status_wrapper(packet: WindowsFunctionLiftPacket) -> PrettyLift:
    name = packet.function_name
    calls = _nontrivial_call_names(packet)
    primary = next((call for call in calls if call != "RtlSetLastWin32Error"), "callee")
    error_values = _ret_compare_constants(packet.raw_pseudocode)
    error_lines = []
    for value in error_values:
        error_lines.extend(
            [
                f"    if (status == {_signed_hex(value)}) {{",
                "        RtlSetLastWin32Error(1150);",
                "        return FALSE;",
                "    }",
            ]
        )
    if not error_lines:
        error_lines = [
            "    if (!NT_SUCCESS(status)) {",
            "        return FALSE;",
            "    }",
        ]
    prototype = f"BOOL {name}(/* original arguments */)"
    lines = [
        prototype,
        "{",
        f"    NTSTATUS status = {primary}(/* original arguments */);",
        "",
        *error_lines,
        "    return TRUE;",
        "}",
    ]
    return PrettyLift(
        function_name=name,
        prototype=prototype,
        pseudocode="\n".join(lines),
        confidence=0.72,
        assumptions=[
            "argument forwarding was not recovered, so original arguments are summarized",
            "numeric NTSTATUS comparisons are preserved because symbolic names were not proven",
        ],
    )


def _looks_like_ioctl_wrapper(packet: WindowsFunctionLiftPacket) -> bool:
    return "NtDeviceIoControlFile" in packet.call_counts


def _render_ioctl_wrapper(packet: WindowsFunctionLiftPacket) -> PrettyLift:
    name = packet.function_name
    prototype = f"NTSTATUS {name}(/* recovered wrapper arguments */)"
    lines = [
        prototype,
        "{",
        "    IO_STATUS_BLOCK iosb;",
        "",
        "    return NtDeviceIoControlFile(",
        "        KsecDeviceHandle,",
        "        NULL,",
        "        NULL,",
        "        NULL,",
        "        &iosb,",
        "        IoControlCode,",
        "        InputBuffer,",
        "        InputLength,",
        "        OutputBuffer,",
        "        OutputLength);",
        "}",
    ]
    return PrettyLift(
        function_name=name,
        prototype=prototype,
        pseudocode="\n".join(lines),
        confidence=0.70,
        assumptions=[
            "IOCTL parameter names are inferred from NtDeviceIoControlFile convention",
            "exact stack/register argument mapping is not fully recovered in the current IR",
        ],
    )


def _looks_like_guarded_callback(packet: WindowsFunctionLiftPacket) -> bool:
    text = packet.raw_pseudocode
    return bool(
        not packet.call_counts
        and len(text.splitlines()) <= 32
        and re.search(r"ret\s*=\s*\*&\[[^\]]+\]\s*;", text)
        and re.search(r"0x[0-9a-fA-F]+\s*\(\)\s*;", text)
    )


def _render_guarded_callback(packet: WindowsFunctionLiftPacket) -> PrettyLift:
    name = packet.function_name
    callback = _first_indirect_absolute_call(packet.raw_pseudocode) or "callback"
    prototype = f"NTSTATUS {name}(/* original arguments */)"
    lines = [
        prototype,
        "{",
        "    void (*callback)(void);",
        "",
        "    callback = READ_GLOBAL_CALLBACK();",
        "    if (callback == NULL) {",
        "        return STATUS_SUCCESS;",
        "    }",
        f"    {callback}(/* original arguments */);",
        "    return STATUS_SUCCESS;",
        "}",
    ]
    return PrettyLift(
        function_name=name,
        prototype=prototype,
        pseudocode="\n".join(lines),
        confidence=0.66,
        assumptions=[
            "global callback identity is not resolved yet; raw absolute call target is preserved",
            "success return is inferred from the short guarded callback shape",
        ],
    )


def _looks_like_simple_forwarder(packet: WindowsFunctionLiftPacket) -> bool:
    calls = _nontrivial_call_names(packet)
    if len(calls) != 1:
        return False
    text = packet.raw_pseudocode
    return "unknown(syscall)" not in text and len(text.splitlines()) <= 32


def _render_simple_forwarder(packet: WindowsFunctionLiftPacket) -> PrettyLift:
    name = packet.function_name
    site = next(iter(_orderable_call_sites(packet)), None)
    callee = site.call_name if site is not None else _nontrivial_call_names(packet)[0]
    call_arguments = (
        _render_call_arguments(site, empty_placeholder="/* original arguments */")
        if site is not None
        else "/* original arguments */"
    )
    prototype = f"NTSTATUS {name}(/* original arguments */)"
    lines = [
        prototype,
        "{",
    ]
    if packet.path_conditions:
        lines.extend(
            [
                "    /* Path conditions:",
                *_render_path_conditions(packet.path_conditions),
                "     */",
                "",
            ]
        )
    required_refs = [
        ref for ref in packet.data_references if _is_required_data_reference(ref)
    ]
    if required_refs:
        lines.extend(
            [
                "    /* Required data references:",
                *_render_data_references(required_refs),
                "     */",
                "",
            ]
        )
    lines.extend(
        [
            f"    return {callee}({call_arguments});",
            "}",
        ]
    )
    assumptions = [
        "wrapper argument mapping was not recovered; the direct callee is preserved"
    ]
    if site is not None and site.prototype is not None and site.arguments:
        assumptions = [
            "callee argument names are rendered from the recovered callsite prototype"
        ]
    return PrettyLift(
        function_name=name,
        prototype=prototype,
        pseudocode="\n".join(lines),
        confidence=0.68,
        assumptions=assumptions,
    )


def _render_selector_table_string_lift(
    packet: WindowsFunctionLiftPacket,
) -> PrettyLift:
    name = packet.function_name
    prototype = _default_prototype(packet, name)
    output_size = packet.output_size or 0
    size_expr = _hex(output_size) if output_size else "required_size"
    table = packet.selector_table
    if table is None:
        table_name = "selector_table"
        count_name = "selector_table_count"
    else:
        table_name = table.table_name
        count_name = table.count_name or f"{table_name}Count"
    assumptions = [
        "argument names are inferred from selector-table/output-buffer usage",
        "structure field names are intentionally left as byte offsets unless backed by symbols",
    ]
    if any(
        copy.dst_length_expression.startswith("(var") for copy in packet.string_copies
    ):
        assumptions.append(
            "some string lengths are inferred through constant propagation from the 0x80 scratch length"
        )

    lines = [
        f"{prototype}",
        "{",
        "    ULONG index;",
        "    const void *version;",
        "",
        "    (void)PreviousMode;",
        "",
        f"    if (QueryLength != sizeof(ULONG) || OutputLength < {size_expr}) {{",
        "        if (ReturnLength != NULL) {",
        "            *ReturnLength = 0;",
        "        }",
        "        return STATUS_INFO_LENGTH_MISMATCH;",
        "    }",
        "",
        "    index = *QueryIndex;",
        f"    if (index >= {count_name}) {{",
        "        if (ReturnLength != NULL) {",
        "            *ReturnLength = 0;",
        "        }",
        "        return STATUS_NO_MORE_ENTRIES;",
        "    }",
        "",
        f"    version = {table_name}[index];",
        "    memset(OutputBuffer, 0, OutputLength);",
    ]
    lines.extend(_render_output_writes(packet.output_writes, count_name=count_name))
    if packet.string_copies:
        lines.append("")
        for copy in packet.string_copies:
            dst = _offset_expr("OutputBuffer", copy.dst_offset)
            src = _offset_expr("version", copy.src_offset)
            length = _length_expr(copy)
            lines.append(f"    {copy.call_name}({dst}, {length}, {src});")
    lines.extend(
        [
            "",
            "    if (ReturnLength != NULL) {",
            f"        *ReturnLength = {size_expr};",
            "    }",
            "    return STATUS_SUCCESS;",
            "}",
        ]
    )
    evidence_line_map = _line_map_for_rendered(lines, packet)
    return PrettyLift(
        function_name=name,
        prototype=prototype,
        pseudocode="\n".join(lines),
        confidence=0.90,
        assumptions=assumptions,
        evidence_line_map=evidence_line_map,
    )


def _looks_like_call_sequence(packet: WindowsFunctionLiftPacket) -> bool:
    return len(_ordered_nontrivial_calls(packet.raw_pseudocode)) >= 2


def _render_call_sequence(packet: WindowsFunctionLiftPacket) -> PrettyLift:
    name = packet.function_name
    sites = _orderable_call_sites(packet)
    calls = [site.call_name for site in sites] or _ordered_nontrivial_calls(
        packet.raw_pseudocode
    )
    prototype = f"NTSTATUS {name}(/* original arguments */)"
    lines = [
        prototype,
        "{",
        "    NTSTATUS status = STATUS_SUCCESS;",
        "",
    ]
    if packet.path_conditions:
        lines.extend(
            [
                "    /* Path conditions:",
                *_render_path_conditions(packet.path_conditions),
                "     */",
                "",
            ]
        )
    for offset, call in enumerate(calls[:12]):
        site = sites[offset] if offset < len(sites) else None
        arguments = (
            _render_call_arguments(site, empty_placeholder="/* recovered arguments */")
            if site is not None
            else "/* recovered arguments */"
        )
        lines.append(f"    status = {call}({arguments});")
    if len(calls) > 12:
        lines.append(f"    /* {len(calls) - 12} additional calls omitted from view */")
    lines.extend(["", "    return status;", "}"])
    return PrettyLift(
        function_name=name,
        prototype=prototype,
        pseudocode="\n".join(lines),
        confidence=0.58,
        assumptions=[
            "call order is preserved, but branch conditions and exact arguments still require raw IR",
            "return value is summarized as the last status-like call result",
        ],
    )


def _render_generic_lift(packet: WindowsFunctionLiftPacket) -> PrettyLift:
    name = packet.function_name
    prototype = _default_prototype(packet, name)
    lines = [
        f"{prototype}",
        "{",
        "    /* No high-confidence semantic renderer matched this function yet. */",
        "    /* Preserved calls: "
        + ", ".join(f"{name}={count}" for name, count in packet.call_counts.items())
        + " */",
    ]
    if packet.loop_summaries:
        lines.extend(
            [
                "    /* Loop summaries:",
                *_render_loop_summaries(packet.loop_summaries),
                "     */",
            ]
        )
    if packet.path_conditions:
        lines.extend(
            [
                "    /* Path conditions:",
                *_render_path_conditions(packet.path_conditions),
                "     */",
            ]
        )
    if packet.unknown_sections:
        lines.extend(
            [
                "    /* Unknowns requiring analyst review:",
                *_render_unknown_sections(packet.unknown_sections),
                "     */",
            ]
        )
    lines.append("}")
    return PrettyLift(
        function_name=name,
        prototype=prototype,
        pseudocode="\n".join(lines),
        confidence=0.35,
        assumptions=["generic lift preserves summary facts only"],
    )


def _render_loop_summaries(loops: list[LoopSummaryFact]) -> list[str]:
    rendered: list[str] = []
    for loop in loops[:12]:
        calls = ", ".join(loop.calls) if loop.calls else "no recovered calls"
        condition = loop.condition_expression or "unconditional backedge"
        rendered.append(
            "     * - "
            f"{loop.loop_label}: condition={condition}; "
            f"backedge=line {loop.backedge_line}; calls={calls}"
        )
    return rendered


def _render_path_conditions(conditions: list[PathConditionFact]) -> list[str]:
    rendered: list[str] = []
    for condition in conditions[:12]:
        target = f" -> {condition.target_label}" if condition.target_label else ""
        rendered.append(f"     * - {condition.role}: {condition.expression}{target}")
    return rendered


def _render_data_references(refs: list[DataReferenceFact]) -> list[str]:
    rendered: list[str] = []
    for ref in refs[:12]:
        if ref.kind == "global_count":
            selector = f" bounds {ref.index}" if ref.index else ""
            target = f" for {ref.target_symbol}" if ref.target_symbol else ""
            rendered.append(f"     * - {ref.role}: {ref.expression}{selector}{target}")
            continue
        rendered.append(f"     * - {ref.kind}: {ref.expression}")
    return rendered


def _render_unknown_sections(sections: list[UnknownSectionFact]) -> list[str]:
    return [
        f"     * - {section.kind} line {section.line}: {section.label}"
        for section in sections[:12]
    ]


def _syscall_id(packet: WindowsFunctionLiftPacket) -> int | None:
    match = re.search(r"\bret\s*=\s*(0x[0-9A-Fa-f]+|\d+)\s*;", packet.raw_pseudocode)
    if not match:
        return None
    return _parse_int(match.group(1))


def _known_syscall_signature(function_name: str) -> tuple[str | None, str]:
    signatures = {
        "NtQuerySystemInformation": (
            "NTSTATUS NtQuerySystemInformation(\n"
            "    SYSTEM_INFORMATION_CLASS SystemInformationClass,\n"
            "    void *SystemInformation,\n"
            "    ULONG SystemInformationLength,\n"
            "    ULONG *ReturnLength)",
            "SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength",
        ),
        "NtQuerySystemInformationEx": (
            "NTSTATUS NtQuerySystemInformationEx(\n"
            "    SYSTEM_INFORMATION_CLASS SystemInformationClass,\n"
            "    void *InputBuffer,\n"
            "    ULONG InputBufferLength,\n"
            "    void *SystemInformation,\n"
            "    ULONG SystemInformationLength,\n"
            "    ULONG *ReturnLength)",
            (
                "SystemInformationClass, InputBuffer, InputBufferLength, "
                "SystemInformation, SystemInformationLength, ReturnLength"
            ),
        ),
    }
    return signatures.get(function_name, (None, ""))


def _nontrivial_call_names(packet: WindowsFunctionLiftPacket) -> list[str]:
    ignored = {"__security_check_cookie", "memset", "memcpy", "memmove"}
    out: list[str] = []
    for name in packet.call_counts:
        lowered = name.lower()
        if lowered in _CONTROL_CALLS or name in ignored or lowered.startswith("wpp_"):
            continue
        out.append(_clean_symbol_name(name))
    return out


def _render_call_arguments(
    site: CallSiteFact,
    *,
    empty_placeholder: str,
) -> str:
    if not site.arguments:
        return empty_placeholder
    rendered: list[str] = []
    for index, argument in enumerate(site.arguments):
        fact = site.argument_facts[index] if index < len(site.argument_facts) else None
        if (
            fact is not None
            and fact.parameter_name is not None
            and _is_renameable_call_argument(argument)
        ):
            rendered.append(fact.parameter_name)
        else:
            rendered.append(argument)
    return ", ".join(rendered)


def _is_renameable_call_argument(argument: str) -> bool:
    return bool(re.fullmatch(r"(?:arg|var|stack_)[A-Za-z0-9_]+", argument.strip()))


def _ordered_nontrivial_calls(text: str) -> list[str]:
    ignored = {"__security_check_cookie", "memset", "memcpy", "memmove"}
    calls: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        for name, _args in _primitive_calls(line):
            lowered = name.lower()
            if (
                lowered in _CONTROL_CALLS
                or name in ignored
                or lowered.startswith("wpp_")
            ):
                continue
            calls.append(_clean_symbol_name(name))
    return calls


def _clean_symbol_name(name: str) -> str:
    original = name
    name = name.lstrip("?")
    if "@@" in name:
        name = name.split("@@", 1)[0]
    if "@" in name:
        parts = [part for part in name.split("@") if part]
        if len(parts) >= 2:
            name = "_".join(reversed(parts[:2]))
        elif parts:
            name = parts[0]
    name = re.sub(r"[^A-Za-z0-9_]", "_", name)
    name = re.sub(r"_+", "_", name).strip("_")
    if not name or not re.match(r"[A-Za-z_]", name):
        stable = sum((idx + 1) * ord(ch) for idx, ch in enumerate(original))
        return f"symbol_{stable & 0xFFFFFFFF:x}"
    return name


def _ret_compare_constants(text: str) -> list[int]:
    values: list[int] = []
    for match in re.finditer(r"\bret\s*==\s*(-?0x[0-9A-Fa-f]+|-?\d+)", text):
        value = _parse_signed_int(match.group(1))
        if value is not None:
            values.append(value)
    return values


def _parse_signed_int(value: str) -> int | None:
    text = value.strip()
    if text.startswith("-0x"):
        parsed = _parse_int(text[1:])
        return -parsed if parsed is not None else None
    return _parse_int(text)


def _signed_hex(value: int) -> str:
    if value < 0:
        return f"-{_hex(abs(value))}"
    return _hex(value)


def _first_indirect_absolute_call(text: str) -> str | None:
    match = re.search(r"\b(0x[0-9A-Fa-f]+)\s*\(\)\s*;", text)
    if not match:
        return None
    return match.group(1)


def _default_prototype(packet: WindowsFunctionLiftPacket, name: str) -> str:
    entry_prototype = _entry_abi_prototype(packet, name)
    if entry_prototype is not None:
        return entry_prototype
    query_index_role = packet.argument_roles.get("arg0")
    if name == "CmQueryBuildVersionInformation" or (
        packet.selector_table is not None
        and bool(packet.string_copies)
        and query_index_role is not None
        and query_index_role.semantic_name == "QueryIndex"
    ):
        return (
            f"NTSTATUS {name}(\n"
            "    const ULONG *QueryIndex,\n"
            "    ULONG QueryLength,\n"
            "    void *OutputBuffer,\n"
            "    ULONG OutputLength,\n"
            "    ULONG *ReturnLength,\n"
            "    KPROCESSOR_MODE PreviousMode)"
        )
    return f"NTSTATUS {name}(void)"


def _entry_abi_prototype(
    packet: WindowsFunctionLiftPacket,
    name: str,
) -> str | None:
    if packet.function_prototype is None or not packet.entry_abi_arguments:
        return None
    return_type = (
        packet.function_prototype.return_type
        if packet.function_prototype and packet.function_prototype.return_type
        else "NTSTATUS"
    )
    arguments = sorted(packet.entry_abi_arguments, key=lambda argument: argument.index)
    if not arguments:
        return f"{return_type} {name}(void)"
    lines = [f"{return_type} {name}("]
    for offset, argument in enumerate(arguments):
        suffix = "," if offset + 1 < len(arguments) else ")"
        lines.append(
            f"    {_format_parameter(argument.c_type, argument.semantic_name)}{suffix}"
        )
    return "\n".join(lines)


def _format_parameter(c_type: str, name: str) -> str:
    c_type = " ".join(c_type.split())
    if c_type.endswith("*"):
        return f"{c_type}{name}"
    return f"{c_type} {name}".strip()


def _render_output_writes(
    writes: list[OutputWriteFact],
    *,
    count_name: str,
) -> list[str]:
    if not writes:
        return []
    rendered: list[str] = [
        "",
        "    /* Fixed scalar fields recovered from output-buffer writes. */",
    ]
    known = {
        0x0: "(USHORT)index",
        0x2: f"(USHORT){count_name}",
    }
    for write in writes:
        offset = write.output_offset
        if offset is None:
            continue
        if offset in known:
            value = known[offset]
        elif write.rhs_expression == "ret" and write.source_offset is not None:
            value = f"READ_FIELD(version, {_hex(write.source_offset)})"
        elif write.rhs_expression == "ret":
            value = "READ_FIELD(version, unknown_offset)"
        else:
            value = write.rhs_expression
        rendered.append(f"    WRITE_FIELD(OutputBuffer, {_hex(offset)}, {value});")
    return rendered


def _line_map_for_rendered(
    lines: list[str],
    packet: WindowsFunctionLiftPacket,
) -> dict[int, list[str]]:
    out: dict[int, list[str]] = {}
    for idx, line in enumerate(lines, start=1):
        refs: list[str] = []
        if "QueryLength" in line or "OutputLength" in line:
            refs.extend(
                fact.key
                for fact in packet.facts
                if fact.kind in {"argument_role", "constant"}
            )
        if "CmpQueryDowncastString" in line:
            refs.extend(
                f"string_copy:{copy.line}"
                for copy in packet.string_copies
                if _line_matches_copy(line, copy)
            )
        if "WRITE_FIELD" in line:
            refs.extend(
                f"output_write:{write.line}"
                for write in packet.output_writes
                if write.output_offset is not None
                and _contains_int(line, write.output_offset)
            )
        if refs:
            out[idx] = _dedupe(refs)
    return out


def _line_matches_copy(line: str, copy: StringCopyFact) -> bool:
    return copy.dst_offset is None or _contains_int(line, copy.dst_offset)


def _offset_expr(base: str, offset: int | None) -> str:
    if offset is None or offset == 0:
        return f"(uint8_t *){base}"
    return f"(uint8_t *){base} + {_hex(offset)}"


def _length_expr(copy: StringCopyFact) -> str:
    if copy.dst_length is not None:
        return _hex(copy.dst_length)
    return copy.dst_length_expression


def _plus_offset(expr: str) -> int | None:
    match = re.search(r"\+\s*(0x[0-9A-Fa-f]+|\d+)\s*\)?\s*$", expr.strip())
    if not match:
        return (
            0
            if re.search(r"\b(?:var\d+|arg\d+|version|OutputBuffer)\b", expr)
            else None
        )
    return _parse_int(match.group(1))


def _resolve_length(expr: str, var_constants: dict[str, int]) -> int | None:
    expr = expr.strip()
    direct = _parse_int(expr)
    if direct is not None:
        return direct
    if expr in var_constants:
        return var_constants[expr]
    match = re.match(
        r"\(\s*(?P<var>[A-Za-z_][A-Za-z0-9_]*)\s*-\s*(?P<delta>0x[0-9A-Fa-f]+|\d+)\s*\)",
        expr,
    )
    if not match:
        return None
    base = var_constants.get(match.group("var"))
    if base is None and "var4" in var_constants:
        base = var_constants["var4"]
    delta = _parse_int(match.group("delta"))
    if base is None or delta is None:
        return None
    return max(0, base - delta)


def _parse_int(value: str) -> int | None:
    try:
        return int(value.strip(), 0)
    except ValueError:
        return None


def _hex(value: int) -> str:
    return f"0x{int(value):x}"


def _contains_int(text: str, value: int) -> bool:
    patterns = {
        str(int(value)),
        _hex(value),
        _hex(value).upper().replace("X", "x"),
    }
    return any(
        re.search(rf"(?<![A-Za-z0-9_]){re.escape(item)}(?![A-Za-z0-9_])", text)
        for item in patterns
    )


def _dedupe(values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value and value not in seen:
            seen.add(value)
            out.append(value)
    return out


def build_tool() -> MemoryTool[
    WindowsFunctionPrettyLiftArgs,
    WindowsFunctionPrettyLiftResult,
]:
    return WindowsFunctionPrettyLiftTool()
