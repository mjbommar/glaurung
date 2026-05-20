from __future__ import annotations

import re
from collections import Counter
from pathlib import Path
from typing import Literal, TypeAlias

from pydantic import BaseModel, Field

import glaurung as g

from ..context import MemoryContext
from ..kb.models import Edge, Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


PrimitiveKind = Literal[
    "probe_for_read",
    "probe_for_write",
    "user_buffer_copy",
    "return_length_write",
    "ntstatus_gate",
    "length_comparison",
    "selector_dispatch",
    "pointer_write",
    "string_conversion_copy",
    "error_status_assignment",
    "syscall_argument_forward",
    "ioctl_call",
    "pool_allocation",
    "pool_free",
    "registry_query",
    "registry_write",
    "object_reference",
    "object_release",
    "irp_access",
    "ioctl_stack_parameter",
    "irp_buffer_access",
    "mdl_access",
    "wdf_request_buffer_access",
    "alpc_message",
    "trace_emit",
    "callback_registration",
    "callback_dispatch",
    "requestor_mode_read",
    "privilege_check",
    "token_reference",
    "token_query",
    "token_release",
]

ContractLayout: TypeAlias = tuple[
    PrimitiveKind,
    tuple[tuple[str, int], ...],
    float,
    str,
    str,
]


class ApiContractParameter(BaseModel):
    index: int
    name: str
    declaration: str
    role: str | None = None
    role_reason: str | None = None


class ApiContractPrimitive(BaseModel):
    kind: PrimitiveKind
    line: int
    snippet: str
    expressions: list[str] = Field(default_factory=list)
    roles: dict[str, str] = Field(default_factory=dict)
    confidence: float = Field(ge=0.0, le=1.0)
    reason: str
    provenance: list[str] = Field(default_factory=list)


class WindowsApiContractPrimitivesArgs(BaseModel):
    pseudocode: str | None = Field(
        None,
        description="Optional decompiler output or source-like text to scan.",
    )
    binary_path: str | None = Field(
        None,
        description="Optional PE path. Defaults to the active context file.",
    )
    function_va: int | None = Field(
        None,
        description="Optional function VA to decompile when pseudocode is omitted.",
    )
    range_start: int | None = Field(
        None,
        description="Optional explicit function range start for decompilation.",
    )
    range_end: int | None = Field(
        None,
        description="Optional explicit function range end for decompilation.",
    )
    max_blocks: int = Field(512, ge=1, description="Decompiler block budget.")
    max_instructions: int = Field(
        20_000, ge=1, description="Decompiler instruction budget."
    )
    timeout_ms: int = Field(2_000, ge=1, description="Decompiler timeout.")
    pdb_cache: str = Field(
        "",
        description="Optional Microsoft-style PDB cache directory for decompile names.",
    )
    max_primitives: int = Field(256, ge=1, description="Maximum primitives to return.")
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact primitive-extraction evidence node to the KB.",
    )


class WindowsApiContractPrimitivesResult(BaseModel):
    function_va: int | None = None
    parameters: list[ApiContractParameter]
    primitives: list[ApiContractPrimitive]
    primitive_counts: dict[str, int]
    pseudocode_source: str
    coverage: list[str] = Field(default_factory=list)
    missing_capabilities: list[str] = Field(default_factory=list)
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsApiContractPrimitivesTool(
    MemoryTool[WindowsApiContractPrimitivesArgs, WindowsApiContractPrimitivesResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_api_contract_primitives",
                description=(
                    "Extract low-level Windows API contract primitives from "
                    "decompiler/source-like text: probes, user-buffer copies, "
                    "ReturnLength writes, NTSTATUS gates, length checks, "
                    "selector dispatch, IOCTLs, pool/registry/object/IRP/MDL "
                    "contracts, callbacks, security boundary APIs, and "
                    "syscall-argument forwarding."
                ),
                tags=("windows", "pe", "contracts", "pseudocode", "rules"),
            ),
            WindowsApiContractPrimitivesArgs,
            WindowsApiContractPrimitivesResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsApiContractPrimitivesArgs,
    ) -> WindowsApiContractPrimitivesResult:
        text, source, notes = _scan_text(ctx, args)
        parameters = _parameters(text)
        primitives = _extract_primitives(
            text,
            parameters,
            source=source,
            max_primitives=args.max_primitives,
        )
        counts: Counter[str] = Counter(str(primitive.kind) for primitive in primitives)
        coverage: list[str] = sorted(counts)
        if counts.get("string_conversion_copy"):
            coverage.append("string_conversion_sinks")
        missing = _missing_capabilities(counts, source)
        primitive_counts = {str(kind): int(count) for kind, count in counts.items()}

        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_api_contract_primitives",
                    props={
                        "function_va": args.function_va,
                        "pseudocode_source": source,
                        "primitive_counts": primitive_counts,
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))

        notes.append(
            "contract primitives are conservative text/decompiler facts; path proof needs CFG/IR correlation"
        )
        return WindowsApiContractPrimitivesResult(
            function_va=args.function_va,
            parameters=parameters,
            primitives=primitives,
            primitive_counts=primitive_counts,
            pseudocode_source=source,
            coverage=coverage,
            missing_capabilities=missing,
            evidence_node_id=evidence_node_id,
            notes=notes,
        )


def _scan_text(
    ctx: MemoryContext,
    args: WindowsApiContractPrimitivesArgs,
) -> tuple[str, str, list[str]]:
    notes: list[str] = []
    if args.pseudocode:
        return args.pseudocode, "supplied_pseudocode", notes
    if args.function_va is None:
        notes.append("no pseudocode or function_va supplied")
        return "", "none", notes
    binary_path = Path(args.binary_path or ctx.file_path)
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
        return text, "glaurung_decompiler", notes
    except Exception as exc:
        notes.append(f"decompile failed: {exc}")
        return "", "glaurung_decompiler_failed", notes


def _extract_primitives(
    text: str,
    parameters: list[ApiContractParameter],
    *,
    source: str,
    max_primitives: int,
) -> list[ApiContractPrimitive]:
    primitives: list[ApiContractPrimitive] = []
    parameter_roles = {param.name: param.role for param in parameters if param.role}
    selector_seen = False
    for line_no, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        primitives.extend(_probe_primitives(line, line_no, source))
        primitives.extend(_copy_primitives(line, line_no, source))
        primitives.extend(_ioctl_primitives(line, line_no, source))
        primitives.extend(_pool_primitives(line, line_no, source))
        primitives.extend(_registry_primitives(line, line_no, source))
        primitives.extend(_object_primitives(line, line_no, source))
        primitives.extend(_irp_mdl_primitives(line, line_no, source))
        primitives.extend(_ioctl_stack_parameter_primitives(line, line_no, source))
        primitives.extend(_irp_buffer_access_primitives(line, line_no, source))
        primitives.extend(_wdf_request_primitives(line, line_no, source))
        primitives.extend(_alpc_primitives(line, line_no, source))
        primitives.extend(_trace_primitives(line, line_no, source))
        primitives.extend(_callback_primitives(line, line_no, source))
        primitives.extend(_security_primitives(line, line_no, source))
        primitives.extend(_status_primitives(line, line_no, source))
        primitives.extend(_length_primitives(line, line_no, source))
        selector_primitives = _selector_primitives(line, line_no, source, selector_seen)
        if selector_primitives:
            selector_seen = True
            primitives.extend(selector_primitives)
        primitives.extend(_write_primitives(line, line_no, source))
        primitives.extend(
            _forward_primitives(line, line_no, source, parameters, parameter_roles)
        )
        if len(primitives) >= max_primitives:
            return _dedupe_primitives(primitives[:max_primitives])
    return _dedupe_primitives(primitives)


def _probe_primitives(
    line: str,
    line_no: int,
    source: str,
) -> list[ApiContractPrimitive]:
    out: list[ApiContractPrimitive] = []
    for name, args in _calls(line):
        lowered = name.lower()
        if lowered not in {"probeforread", "probeforwrite"}:
            continue
        call_args = _split_args(args)
        roles: dict[str, str] = {}
        expressions: list[str] = []
        if call_args:
            roles["pointer"] = _expr_role(call_args[0])
            expressions.append(call_args[0])
        if len(call_args) > 1:
            roles["length"] = _expr_role(call_args[1])
            expressions.append(call_args[1])
        if len(call_args) > 2:
            roles["alignment"] = _expr_role(call_args[2])
            expressions.append(call_args[2])
        out.append(
            ApiContractPrimitive(
                kind="probe_for_write"
                if lowered.endswith("write")
                else "probe_for_read",
                line=line_no,
                snippet=line,
                expressions=expressions,
                roles=roles,
                confidence=0.92,
                reason=f"{name} call models user pointer probing",
                provenance=[source, "call_name"],
            )
        )
    return out


def _copy_primitives(
    line: str,
    line_no: int,
    source: str,
) -> list[ApiContractPrimitive]:
    names = {
        "memcpy",
        "memmove",
        "rtlcopybytes",
        "rtlcopymemory",
        "mmcopymemory",
        "copy_to_user",
        "copy_from_user",
    }
    string_sinks = {
        "rtlunicodestringtoansistring": (("dst", 0), ("src", 1), ("allocate", 2)),
        "rtlunicodestringtoutf8string": (("dst", 0), ("src", 1), ("allocate", 2)),
        "rtlansistringtounicodestring": (("dst", 0), ("src", 1), ("allocate", 2)),
        "rtloemstringtounicodestring": (("dst", 0), ("src", 1), ("allocate", 2)),
        "rtlunicodestringtooemstring": (("dst", 0), ("src", 1), ("allocate", 2)),
        "rtlunicodetoutf8n": (
            ("dst", 0),
            ("dst_length", 1),
            ("return_length", 2),
            ("src", 3),
            ("src_length", 4),
        ),
        "rtlutf8tounicoden": (
            ("dst", 0),
            ("dst_length", 1),
            ("return_length", 2),
            ("src", 3),
            ("src_length", 4),
        ),
        "rtlunicodetomultibyten": (
            ("dst", 0),
            ("dst_length", 1),
            ("return_length", 2),
            ("src", 3),
            ("src_length", 4),
        ),
        "rtlmultibytetounicoden": (
            ("dst", 0),
            ("dst_length", 1),
            ("return_length", 2),
            ("src", 3),
            ("src_length", 4),
        ),
        "rtlunicodetooemn": (
            ("dst", 0),
            ("dst_length", 1),
            ("return_length", 2),
            ("src", 3),
            ("src_length", 4),
        ),
        "rtloemtounicoden": (
            ("dst", 0),
            ("dst_length", 1),
            ("return_length", 2),
            ("src", 3),
            ("src_length", 4),
        ),
        # Known Windows kernel wrapper used by CmQueryBuildVersionInformation:
        # CmpQueryDowncastString(dst, dst_len, unicode_string_src).
        "cmpquerydowncaststring": (
            ("dst", 0),
            ("dst_length", 1),
            ("src_unicode_string", 2),
        ),
    }
    out: list[ApiContractPrimitive] = []
    for name, args in _calls(line):
        lowered = name.lower()
        if lowered in string_sinks:
            call_args = _split_args(args)
            roles: dict[str, str] = {}
            expressions: list[str] = []
            for role_name, index in string_sinks[lowered]:
                if len(call_args) <= index:
                    continue
                roles[role_name] = _expr_role(call_args[index])
                expressions.append(call_args[index])
            out.append(
                ApiContractPrimitive(
                    kind="string_conversion_copy",
                    line=line_no,
                    snippet=line,
                    expressions=expressions,
                    roles=roles,
                    confidence=0.86 if lowered != "cmpquerydowncaststring" else 0.78,
                    reason=(
                        f"{name} is a Windows string conversion/copy sink"
                        if lowered != "cmpquerydowncaststring"
                        else f"{name} wrapper forwards to a Windows string conversion/copy sink"
                    ),
                    provenance=[
                        source,
                        "windows_string_conversion_sink",
                    ],
                )
            )
            continue
        if lowered not in names:
            continue
        call_args = _split_args(args)
        roles: dict[str, str] = {}
        expressions: list[str] = []
        for role_name, index in (("dst", 0), ("src", 1), ("length", 2)):
            if len(call_args) > index:
                roles[role_name] = _expr_role(call_args[index])
                expressions.append(call_args[index])
        out.append(
            ApiContractPrimitive(
                kind="user_buffer_copy",
                line=line_no,
                snippet=line,
                expressions=expressions,
                roles=roles,
                confidence=0.78,
                reason=f"{name} call is a copy/memory-transfer primitive",
                provenance=[source, "copy_call_name"],
            )
        )
    return out


def _ioctl_primitives(
    line: str,
    line_no: int,
    source: str,
) -> list[ApiContractPrimitive]:
    layouts = {
        "ntdeviceiocontrolfile": (
            ("handle", 0),
            ("io_status", 4),
            ("ioctl_code", 5),
            ("input_buffer", 6),
            ("input_length", 7),
            ("output_buffer", 8),
            ("output_length", 9),
        ),
        "zwdeviceiocontrolfile": (
            ("handle", 0),
            ("io_status", 4),
            ("ioctl_code", 5),
            ("input_buffer", 6),
            ("input_length", 7),
            ("output_buffer", 8),
            ("output_length", 9),
        ),
        "deviceiocontrol": (
            ("handle", 0),
            ("ioctl_code", 1),
            ("input_buffer", 2),
            ("input_length", 3),
            ("output_buffer", 4),
            ("output_length", 5),
            ("bytes_returned", 6),
        ),
        "iobuilddeviceiocontrolrequest": (
            ("ioctl_code", 0),
            ("device_object", 1),
            ("input_buffer", 2),
            ("input_length", 3),
            ("output_buffer", 4),
            ("output_length", 5),
            ("internal_device_ioctl", 6),
            ("io_status", 8),
        ),
    }
    out: list[ApiContractPrimitive] = []
    for name, args in _calls(line):
        layout = layouts.get(name.lower())
        if layout is None:
            continue
        call_args = _split_args(args)
        roles: dict[str, str] = {}
        expressions: list[str] = []
        for role_name, index in layout:
            if len(call_args) <= index:
                continue
            roles[role_name] = _expr_role(call_args[index])
            expressions.append(call_args[index])
        out.append(
            ApiContractPrimitive(
                kind="ioctl_call",
                line=line_no,
                snippet=line,
                expressions=expressions,
                roles=roles,
                confidence=0.84,
                reason=f"{name} carries IOCTL code plus input/output buffer contract",
                provenance=[source, "windows_ioctl_call_name"],
            )
        )
    return out


def _pool_primitives(
    line: str,
    line_no: int,
    source: str,
) -> list[ApiContractPrimitive]:
    alloc_layouts = {
        "exallocatepool": (("pool_type", 0), ("size", 1)),
        "exallocatepoolwithtag": (("pool_type", 0), ("size", 1), ("tag", 2)),
        "exallocatepoolwithquota": (("pool_type", 0), ("size", 1)),
        "exallocatepoolwithquotatag": (("pool_type", 0), ("size", 1), ("tag", 2)),
        "exallocatepoolzero": (("pool_type", 0), ("size", 1), ("tag", 2)),
        "exallocatepool2": (("flags", 0), ("size", 1), ("tag", 2)),
        "exallocatepool3": (("flags", 0), ("size", 1), ("tag", 2)),
    }
    free_layouts = {
        "exfreepool": (("pointer", 0),),
        "exfreepoolwithtag": (("pointer", 0), ("tag", 1)),
    }
    out: list[ApiContractPrimitive] = []
    for name, args in _calls(line):
        lowered = name.lower()
        kind: PrimitiveKind
        layout = alloc_layouts.get(lowered)
        confidence = 0.82
        reason = f"{name} allocates Windows pool memory"
        provenance = "windows_pool_allocation_call_name"
        if layout is None:
            layout = free_layouts.get(lowered)
            kind = "pool_free"
            confidence = 0.80
            reason = f"{name} frees Windows pool memory"
            provenance = "windows_pool_free_call_name"
        else:
            kind = "pool_allocation"
        if layout is None:
            continue
        call_args = _split_args(args)
        roles: dict[str, str] = {}
        expressions: list[str] = []
        for role_name, index in layout:
            if len(call_args) <= index:
                continue
            roles[role_name] = _pool_expr_role(role_name, call_args[index])
            expressions.append(call_args[index])
        out.append(
            ApiContractPrimitive(
                kind=kind,
                line=line_no,
                snippet=line,
                expressions=expressions,
                roles=roles,
                confidence=confidence,
                reason=reason,
                provenance=[source, provenance],
            )
        )
    return out


def _layout_call_primitives(
    line: str,
    line_no: int,
    source: str,
    layouts: dict[str, ContractLayout],
) -> list[ApiContractPrimitive]:
    out: list[ApiContractPrimitive] = []
    for name, args in _calls(line):
        layout = layouts.get(name.lower())
        if layout is None:
            continue
        kind, fields, confidence, reason, provenance = layout
        call_args = _split_args(args)
        roles: dict[str, str] = {}
        expressions: list[str] = []
        for role_name, index in fields:
            if len(call_args) <= index:
                continue
            roles[role_name] = _contract_expr_role(role_name, call_args[index])
            expressions.append(call_args[index])
        out.append(
            ApiContractPrimitive(
                kind=kind,
                line=line_no,
                snippet=line,
                expressions=expressions,
                roles=roles,
                confidence=confidence,
                reason=f"{name} {reason}",
                provenance=[source, provenance],
            )
        )
    return out


def _registry_primitives(
    line: str,
    line_no: int,
    source: str,
) -> list[ApiContractPrimitive]:
    layouts: dict[str, ContractLayout] = {
        "ntqueryvaluekey": (
            "registry_query",
            (
                ("key_handle", 0),
                ("value_name", 1),
                ("info_class", 2),
                ("key_value_information", 3),
                ("length", 4),
                ("result_length", 5),
            ),
            0.84,
            "queries registry value data into caller-controlled output storage",
            "windows_registry_query_call_name",
        ),
        "zwqueryvaluekey": (
            "registry_query",
            (
                ("key_handle", 0),
                ("value_name", 1),
                ("info_class", 2),
                ("key_value_information", 3),
                ("length", 4),
                ("result_length", 5),
            ),
            0.84,
            "queries registry value data into caller-controlled output storage",
            "windows_registry_query_call_name",
        ),
        "ntsetvaluekey": (
            "registry_write",
            (
                ("key_handle", 0),
                ("value_name", 1),
                ("title_index", 2),
                ("value_type", 3),
                ("value_data", 4),
                ("length", 5),
            ),
            0.82,
            "writes caller-provided bytes into a registry value",
            "windows_registry_write_call_name",
        ),
        "zwsetvaluekey": (
            "registry_write",
            (
                ("key_handle", 0),
                ("value_name", 1),
                ("title_index", 2),
                ("value_type", 3),
                ("value_data", 4),
                ("length", 5),
            ),
            0.82,
            "writes caller-provided bytes into a registry value",
            "windows_registry_write_call_name",
        ),
        "rtlqueryregistryvalues": (
            "registry_query",
            (
                ("relative_to", 0),
                ("path", 1),
                ("query_table", 2),
                ("context", 3),
                ("environment", 4),
            ),
            0.76,
            "uses an RTL query table to read registry values",
            "windows_rtl_registry_query_call_name",
        ),
        "rtlwriteregistryvalue": (
            "registry_write",
            (
                ("relative_to", 0),
                ("path", 1),
                ("value_name", 2),
                ("value_type", 3),
                ("value_data", 4),
                ("length", 5),
            ),
            0.76,
            "writes bytes through the RTL registry helper",
            "windows_rtl_registry_write_call_name",
        ),
    }
    return _layout_call_primitives(line, line_no, source, layouts)


def _object_primitives(
    line: str,
    line_no: int,
    source: str,
) -> list[ApiContractPrimitive]:
    layouts: dict[str, ContractLayout] = {
        "obreferenceobjectbyhandle": (
            "object_reference",
            (
                ("handle", 0),
                ("desired_access", 1),
                ("object_type", 2),
                ("access_mode", 3),
                ("object", 4),
                ("handle_information", 5),
            ),
            0.84,
            "translates a handle into a referenced kernel object pointer",
            "windows_object_reference_call_name",
        ),
        "obreferenceobjectbypointer": (
            "object_reference",
            (
                ("object_pointer", 0),
                ("desired_access", 1),
                ("object_type", 2),
                ("access_mode", 3),
            ),
            0.80,
            "takes a reference on an existing kernel object pointer",
            "windows_object_reference_call_name",
        ),
        "obreferenceobjectbyname": (
            "object_reference",
            (
                ("object_name", 0),
                ("attributes", 1),
                ("access_state", 2),
                ("desired_access", 3),
                ("object_type", 4),
                ("access_mode", 5),
                ("parse_context", 6),
                ("object", 7),
            ),
            0.82,
            "resolves an object-manager name to a referenced object pointer",
            "windows_object_reference_call_name",
        ),
        "obdereferenceobject": (
            "object_release",
            (("object_pointer", 0),),
            0.78,
            "drops a kernel object reference",
            "windows_object_release_call_name",
        ),
    }
    return _layout_call_primitives(line, line_no, source, layouts)


def _irp_mdl_primitives(
    line: str,
    line_no: int,
    source: str,
) -> list[ApiContractPrimitive]:
    layouts: dict[str, ContractLayout] = {
        "iogetcurrentirpstacklocation": (
            "irp_access",
            (("irp", 0),),
            0.82,
            "reads the current IO_STACK_LOCATION from an IRP",
            "windows_irp_access_call_name",
        ),
        "iocompleterequest": (
            "irp_access",
            (("irp", 0), ("priority_boost", 1)),
            0.76,
            "completes an IRP and hands ownership back to the IO manager",
            "windows_irp_access_call_name",
        ),
        "ioskipcurrentirpstacklocation": (
            "irp_access",
            (("irp", 0),),
            0.74,
            "mutates IRP stack traversal state",
            "windows_irp_access_call_name",
        ),
        "iocopycurrentirpstacklocationtonext": (
            "irp_access",
            (("irp", 0),),
            0.74,
            "copies current IRP stack location to the next stack slot",
            "windows_irp_access_call_name",
        ),
        "ioallocatemdl": (
            "mdl_access",
            (
                ("virtual_address", 0),
                ("length", 1),
                ("secondary_buffer", 2),
                ("charge_quota", 3),
                ("irp", 4),
            ),
            0.82,
            "creates an MDL that describes caller-provided virtual memory",
            "windows_mdl_access_call_name",
        ),
        "mmprobeandlockpages": (
            "mdl_access",
            (("mdl", 0), ("access_mode", 1), ("operation", 2)),
            0.86,
            "probes and locks the pages described by an MDL",
            "windows_mdl_access_call_name",
        ),
        "mmgetsystemaddressformdlsafe": (
            "mdl_access",
            (("mdl", 0), ("priority", 1)),
            0.84,
            "maps MDL-described pages into system address space",
            "windows_mdl_access_call_name",
        ),
        "mmunlockpages": (
            "mdl_access",
            (("mdl", 0),),
            0.78,
            "unlocks pages described by an MDL",
            "windows_mdl_access_call_name",
        ),
    }
    return _layout_call_primitives(line, line_no, source, layouts)


def _ioctl_stack_parameter_primitives(
    line: str,
    line_no: int,
    source: str,
) -> list[ApiContractPrimitive]:
    field_roles = {
        "IoControlCode": "ioctl_code",
        "InputBufferLength": "input_length",
        "OutputBufferLength": "output_length",
        "Type3InputBuffer": "type3_input_buffer",
    }
    roles: dict[str, str] = {}
    expressions: list[str] = []
    pattern = re.compile(
        r"(?P<expr>[A-Za-z_][A-Za-z0-9_]*"
        r"(?:->|\.)Parameters(?:->|\.)DeviceIoControl(?:->|\.)"
        r"(?P<field>IoControlCode|InputBufferLength|OutputBufferLength|"
        r"Type3InputBuffer))",
        re.IGNORECASE,
    )
    for match in pattern.finditer(line):
        field = _canonical_field_name(match.group("field"), field_roles)
        if field is None:
            continue
        role_name = field_roles[field]
        expr = match.group("expr")
        roles[role_name] = _contract_expr_role(role_name, expr)
        expressions.append(expr)
    if not roles:
        return []
    return [
        ApiContractPrimitive(
            kind="ioctl_stack_parameter",
            line=line_no,
            snippet=line,
            expressions=expressions,
            roles=roles,
            confidence=0.82,
            reason=(
                "IO_STACK_LOCATION DeviceIoControl fields expose IOCTL selector, "
                "buffer, and length contract"
            ),
            provenance=[source, "io_stack_device_ioctl_field"],
        )
    ]


def _irp_buffer_access_primitives(
    line: str,
    line_no: int,
    source: str,
) -> list[ApiContractPrimitive]:
    field_roles = {
        "AssociatedIrp.SystemBuffer": "system_buffer",
        "UserBuffer": "user_buffer",
        "MdlAddress": "mdl_address",
        "RequestorMode": "requestor_mode",
        "IoStatus.Information": "io_status_information",
    }
    roles: dict[str, str] = {}
    expressions: list[str] = []
    pattern = re.compile(
        r"(?P<expr>[A-Za-z_][A-Za-z0-9_]*(?:->|\.)(?P<field>"
        r"AssociatedIrp(?:->|\.)SystemBuffer|UserBuffer|MdlAddress|"
        r"RequestorMode|IoStatus(?:->|\.)Information))",
        re.IGNORECASE,
    )
    for match in pattern.finditer(line):
        field = _canonical_irp_field(match.group("field"), field_roles)
        if field is None:
            continue
        role_name = field_roles[field]
        expr = match.group("expr")
        roles[role_name] = _contract_expr_role(role_name, expr)
        expressions.append(expr)
    if not roles:
        return []
    return [
        ApiContractPrimitive(
            kind="irp_buffer_access",
            line=line_no,
            snippet=line,
            expressions=expressions,
            roles=roles,
            confidence=0.80,
            reason=(
                "IRP field access exposes buffered/direct/neither I/O data, "
                "requestor mode, or returned byte count"
            ),
            provenance=[source, "irp_contract_field"],
        )
    ]


def _wdf_request_primitives(
    line: str,
    line_no: int,
    source: str,
) -> list[ApiContractPrimitive]:
    layouts: dict[str, ContractLayout] = {
        "wdfrequestretrieveinputbuffer": (
            "wdf_request_buffer_access",
            (
                ("request", 0),
                ("minimum_required_size", 1),
                ("input_buffer", 2),
                ("input_length", 3),
            ),
            0.84,
            "retrieves a framework request input buffer and optional length",
            "windows_wdf_request_buffer_call_name",
        ),
        "wdfrequestretrieveoutputbuffer": (
            "wdf_request_buffer_access",
            (
                ("request", 0),
                ("minimum_required_size", 1),
                ("output_buffer", 2),
                ("output_length", 3),
            ),
            0.84,
            "retrieves a framework request output buffer and optional length",
            "windows_wdf_request_buffer_call_name",
        ),
        "wdfrequestretrieveunsafeuserinputbuffer": (
            "wdf_request_buffer_access",
            (
                ("request", 0),
                ("minimum_required_size", 1),
                ("input_buffer", 2),
                ("input_length", 3),
            ),
            0.86,
            "retrieves a METHOD_NEITHER user input buffer from a framework request",
            "windows_wdf_request_user_buffer_call_name",
        ),
        "wdfrequestretrieveunsafeuseroutputbuffer": (
            "wdf_request_buffer_access",
            (
                ("request", 0),
                ("minimum_required_size", 1),
                ("output_buffer", 2),
                ("output_length", 3),
            ),
            0.86,
            "retrieves a METHOD_NEITHER user output buffer from a framework request",
            "windows_wdf_request_user_buffer_call_name",
        ),
        "wdfrequestgetparameters": (
            "ioctl_stack_parameter",
            (("request", 0), ("parameters", 1)),
            0.76,
            "retrieves WDF request parameters, including DeviceIoControl metadata",
            "windows_wdf_request_parameters_call_name",
        ),
    }
    return _layout_call_primitives(line, line_no, source, layouts)


def _alpc_primitives(
    line: str,
    line_no: int,
    source: str,
) -> list[ApiContractPrimitive]:
    layouts: dict[str, ContractLayout] = {
        "ntalpcsendwaitreceiveport": (
            "alpc_message",
            (
                ("port_handle", 0),
                ("flags", 1),
                ("send_message", 2),
                ("send_attributes", 3),
                ("receive_message", 4),
                ("receive_buffer_length", 5),
                ("receive_attributes", 6),
                ("timeout", 7),
            ),
            0.86,
            "sends and optionally receives ALPC messages across a port boundary",
            "windows_alpc_message_call_name",
        ),
        "zwalpcsendwaitreceiveport": (
            "alpc_message",
            (
                ("port_handle", 0),
                ("flags", 1),
                ("send_message", 2),
                ("send_attributes", 3),
                ("receive_message", 4),
                ("receive_buffer_length", 5),
                ("receive_attributes", 6),
                ("timeout", 7),
            ),
            0.86,
            "sends and optionally receives ALPC messages across a port boundary",
            "windows_alpc_message_call_name",
        ),
        "alpcsendwaitreceiveport": (
            "alpc_message",
            (
                ("port_handle", 0),
                ("flags", 1),
                ("send_message", 2),
                ("send_attributes", 3),
                ("receive_message", 4),
                ("receive_buffer_length", 5),
                ("receive_attributes", 6),
                ("timeout", 7),
            ),
            0.82,
            "kernel helper sends and optionally receives ALPC messages",
            "windows_alpc_message_call_name",
        ),
    }
    return _layout_call_primitives(line, line_no, source, layouts)


def _trace_primitives(
    line: str,
    line_no: int,
    source: str,
) -> list[ApiContractPrimitive]:
    layouts: dict[str, ContractLayout] = {
        "etwwrite": (
            "trace_emit",
            (
                ("provider", 0),
                ("event_descriptor", 1),
                ("user_data_count", 2),
                ("user_data", 3),
            ),
            0.74,
            "emits ETW event data",
            "windows_trace_emit_call_name",
        ),
        "etwwriteex": (
            "trace_emit",
            (
                ("provider", 0),
                ("event_descriptor", 1),
                ("filter", 2),
                ("flags", 3),
                ("activity_id", 4),
                ("related_activity_id", 5),
                ("user_data_count", 6),
                ("user_data", 7),
            ),
            0.74,
            "emits ETW event data with extended metadata",
            "windows_trace_emit_call_name",
        ),
        "etwwritetransfer": (
            "trace_emit",
            (
                ("provider", 0),
                ("event_descriptor", 1),
                ("activity_id", 2),
                ("related_activity_id", 3),
                ("user_data_count", 4),
                ("user_data", 5),
            ),
            0.74,
            "emits ETW event data with activity correlation",
            "windows_trace_emit_call_name",
        ),
        "wpptracemessage": (
            "trace_emit",
            (("logger_handle", 0), ("message_flags", 1), ("guid", 2), ("message", 3)),
            0.70,
            "emits WPP trace data",
            "windows_trace_emit_call_name",
        ),
    }
    return _layout_call_primitives(line, line_no, source, layouts)


def _callback_primitives(
    line: str,
    line_no: int,
    source: str,
) -> list[ApiContractPrimitive]:
    layouts: dict[str, ContractLayout] = {
        "pssetcreateprocessnotifyroutine": (
            "callback_registration",
            (("callback", 0), ("remove", 1)),
            0.86,
            "registers or unregisters a process notification callback",
            "windows_callback_registration_call_name",
        ),
        "pssetloadimagenotifyroutine": (
            "callback_registration",
            (("callback", 0),),
            0.84,
            "registers an image-load notification callback",
            "windows_callback_registration_call_name",
        ),
        "pssetcreatethreadnotifyroutine": (
            "callback_registration",
            (("callback", 0),),
            0.84,
            "registers a thread notification callback",
            "windows_callback_registration_call_name",
        ),
        "exregistercallback": (
            "callback_registration",
            (("callback_object", 0), ("callback", 1), ("context", 2)),
            0.84,
            "registers a callback routine on an executive callback object",
            "windows_callback_registration_call_name",
        ),
        "excreatecallback": (
            "callback_registration",
            (
                ("callback_object", 0),
                ("object_attributes", 1),
                ("create", 2),
                ("allow_multiple_callbacks", 3),
            ),
            0.78,
            "creates or opens an executive callback object",
            "windows_callback_registration_call_name",
        ),
        "keusermodecallback": (
            "callback_dispatch",
            (
                ("api_number", 0),
                ("input_buffer", 1),
                ("input_length", 2),
                ("output_buffer", 3),
                ("output_length", 4),
            ),
            0.88,
            "dispatches a win32k-style user-mode callback with input/output buffers",
            "windows_callback_dispatch_call_name",
        ),
        "exnotifycallback": (
            "callback_dispatch",
            (("callback_object", 0), ("argument1", 1), ("argument2", 2)),
            0.82,
            "dispatches an executive callback object notification",
            "windows_callback_dispatch_call_name",
        ),
    }
    return _layout_call_primitives(line, line_no, source, layouts)


def _security_primitives(
    line: str,
    line_no: int,
    source: str,
) -> list[ApiContractPrimitive]:
    layouts: dict[str, ContractLayout] = {
        "exgetpreviousmode": (
            "requestor_mode_read",
            (),
            0.86,
            "reads the current thread previous-mode trust boundary",
            "windows_requestor_mode_call_name",
        ),
        "kegetpreviousmode": (
            "requestor_mode_read",
            (),
            0.84,
            "reads the current thread previous-mode trust boundary",
            "windows_requestor_mode_call_name",
        ),
        "iogetrequestormode": (
            "requestor_mode_read",
            (("irp", 0),),
            0.88,
            "reads the IRP requestor-mode trust boundary",
            "windows_requestor_mode_call_name",
        ),
        "sesingleprivilegecheck": (
            "privilege_check",
            (("privilege", 0), ("access_mode", 1)),
            0.90,
            "checks one privilege under a caller access mode",
            "windows_privilege_check_call_name",
        ),
        "seprivilegecheck": (
            "privilege_check",
            (("privilege", 0), ("security_context", 1), ("access_mode", 2)),
            0.90,
            "checks a privilege set against a subject security context",
            "windows_privilege_check_call_name",
        ),
        "seaccesscheck": (
            "privilege_check",
            (
                ("security_descriptor", 0),
                ("subject_security_context", 1),
                ("subject_context_locked", 2),
                ("desired_access", 3),
                ("previously_granted_access", 4),
                ("privilege_set", 5),
                ("generic_mapping", 6),
                ("access_mode", 7),
                ("granted_access", 8),
                ("access_status", 9),
            ),
            0.86,
            "checks an access mask against a security descriptor and subject",
            "windows_access_check_call_name",
        ),
        "psreferenceprimarytoken": (
            "token_reference",
            (("process", 0),),
            0.86,
            "takes a referenced primary token from a process",
            "windows_token_reference_call_name",
        ),
        "psreferenceimpersonationtoken": (
            "token_reference",
            (
                ("thread", 0),
                ("copy_on_open", 1),
                ("effective_only", 2),
                ("impersonation_level", 3),
            ),
            0.84,
            "takes a referenced impersonation token from a thread",
            "windows_token_reference_call_name",
        ),
        "sequeryinformationtoken": (
            "token_query",
            (("token", 0), ("information_class", 1), ("token_information", 2)),
            0.86,
            "queries security token information into caller storage",
            "windows_token_query_call_name",
        ),
        "psgetcurrentprocesstoken": (
            "token_query",
            (),
            0.72,
            "reads the current process token pointer",
            "windows_token_query_call_name",
        ),
        "psgetcurrentthreadtoken": (
            "token_query",
            (),
            0.72,
            "reads the current thread token pointer",
            "windows_token_query_call_name",
        ),
        "psdereferenceprimarytoken": (
            "token_release",
            (("token", 0),),
            0.84,
            "drops a primary token reference",
            "windows_token_release_call_name",
        ),
        "psdereferenceimpersonationtoken": (
            "token_release",
            (("token", 0),),
            0.84,
            "drops an impersonation token reference",
            "windows_token_release_call_name",
        ),
    }
    return _layout_call_primitives(line, line_no, source, layouts)


def _status_primitives(
    line: str,
    line_no: int,
    source: str,
) -> list[ApiContractPrimitive]:
    out: list[ApiContractPrimitive] = []
    if re.search(
        r"\bif\s*\([^)]*(?:NT_SUCCESS|NT_ERROR|NT_WARNING|status|Status)[^)]*\)", line
    ):
        out.append(
            ApiContractPrimitive(
                kind="ntstatus_gate",
                line=line_no,
                snippet=line,
                expressions=[_condition_expr(line)],
                roles={"condition": "status"},
                confidence=0.70,
                reason="conditional branch gates on NTSTATUS-like value",
                provenance=[source, "status_condition_regex"],
            )
        )
    if re.search(
        r"\b(?:status|Status|ntstatus|NtStatus)\s*=\s*(?:STATUS_|0xC[0-9A-Fa-f]{7})",
        line,
    ):
        out.append(
            ApiContractPrimitive(
                kind="error_status_assignment",
                line=line_no,
                snippet=line,
                expressions=[line],
                roles={"status": "error_status"},
                confidence=0.72,
                reason="line assigns an NTSTATUS error value",
                provenance=[source, "status_assignment_regex"],
            )
        )
    return out


def _length_primitives(
    line: str,
    line_no: int,
    source: str,
) -> list[ApiContractPrimitive]:
    glaurung_compare = re.search(
        r"^\s*%[A-Za-z0-9_]+\s*=\s*\((?P<condition>arg\d+\s+u?(?:==|!=|<=|>=|<|>)\s+(?:0x[0-9A-Fa-f]+|\d+))\)\s*;",
        line,
    )
    if glaurung_compare:
        condition = glaurung_compare.group("condition")
        zero = bool(re.search(r"(?:==|<=|<)\s*0\b", condition))
        return [
            ApiContractPrimitive(
                kind="length_comparison",
                line=line_no,
                snippet=line,
                expressions=[condition],
                roles={"length": "length"},
                confidence=0.62,
                reason=(
                    "Glaurung IR compares positional API argument to a constant"
                    + (" and includes zero boundary" if zero else "")
                ),
                provenance=[source, "glaurung_arg_constant_compare"],
            )
        ]
    if not re.search(
        r"\b[A-Za-z0-9_]*(?:len|length|size|cb|bytes)[A-Za-z0-9_]*\b",
        line,
        flags=re.I,
    ):
        return []
    condition = _condition_expr(line)
    if not condition:
        return []
    if not (
        re.search(r"(?:==|!=|<=|>=|<|>)\s*(?:0|sizeof|\d+)", condition)
        or re.search(r"!\s*[A-Za-z_][A-Za-z0-9_]*", condition)
    ):
        return []
    zero = bool(re.search(r"(?:==|<=)\s*0\b|!\s*[A-Za-z_][A-Za-z0-9_]*", condition))
    return [
        ApiContractPrimitive(
            kind="length_comparison",
            line=line_no,
            snippet=line,
            expressions=[condition],
            roles={"length": "length"},
            confidence=0.74,
            reason="length/size-like condition"
            + (" includes zero boundary" if zero else ""),
            provenance=[source, "length_condition_regex"],
        )
    ]


def _selector_primitives(
    line: str,
    line_no: int,
    source: str,
    selector_seen: bool,
) -> list[ApiContractPrimitive]:
    out: list[ApiContractPrimitive] = []
    switch_match = re.search(r"\bswitch\s*\((?P<selector>[^)]*)\)", line)
    if switch_match:
        selector = switch_match.group("selector").strip()
        out.append(
            ApiContractPrimitive(
                kind="selector_dispatch",
                line=line_no,
                snippet=line,
                expressions=[selector],
                roles={"selector": _expr_role(selector)},
                confidence=0.86,
                reason="switch dispatch on selector/class-like expression",
                provenance=[source, "switch_regex"],
            )
        )
    elif selector_seen and re.match(r"case\s+[^:]+:", line):
        out.append(
            ApiContractPrimitive(
                kind="selector_dispatch",
                line=line_no,
                snippet=line,
                expressions=[line.rstrip(":")],
                roles={"case": "selector_case"},
                confidence=0.64,
                reason="case label inside selector dispatch",
                provenance=[source, "case_regex"],
            )
        )
    elif re.search(
        r"\b(?:informationclass|infoclass|selector|class)\b", line, flags=re.I
    ):
        condition = _condition_expr(line)
        if condition and re.search(r"==|!=|<=|>=|<|>", condition):
            out.append(
                ApiContractPrimitive(
                    kind="selector_dispatch",
                    line=line_no,
                    snippet=line,
                    expressions=[condition],
                    roles={"selector": "selector"},
                    confidence=0.66,
                    reason="conditional compares selector/class-like value",
                    provenance=[source, "selector_condition_regex"],
                )
            )
    elif re.match(r"[A-Za-z_][A-Za-z0-9_.$@]*\s*=\s*\*&\[\s*arg0\s*\]\s*;?$", line):
        out.append(
            ApiContractPrimitive(
                kind="selector_dispatch",
                line=line_no,
                snippet=line,
                expressions=[line.split("=", 1)[0].strip()],
                roles={"selector": "selector"},
                confidence=0.64,
                reason="Glaurung IR reads a selector-like value from the first API input argument",
                provenance=[source, "glaurung_arg0_selector_read"],
            )
        )
    elif selector_seen and re.search(
        r"=\s*\*&\[[^\]]+\+\s*[A-Za-z_][A-Za-z0-9_.$@]*\s*\*\s*(?:4|8|0x4|0x8)\s*\]",
        line,
    ):
        out.append(
            ApiContractPrimitive(
                kind="selector_dispatch",
                line=line_no,
                snippet=line,
                expressions=[line],
                roles={"table": "selector_indexed_table"},
                confidence=0.68,
                reason="selector-controlled value indexes a pointer-sized global/table load",
                provenance=[source, "glaurung_selector_indexed_table"],
            )
        )
    return out


def _write_primitives(
    line: str,
    line_no: int,
    source: str,
) -> list[ApiContractPrimitive]:
    lhs = _assignment_lhs(line)
    if lhs is None:
        return []
    role = _expr_role(lhs)
    kind: PrimitiveKind = (
        "return_length_write" if role == "return_length" else "pointer_write"
    )
    confidence = 0.80 if kind == "return_length_write" else 0.62
    return [
        ApiContractPrimitive(
            kind=kind,
            line=line_no,
            snippet=line,
            expressions=[lhs],
            roles={"lhs": role},
            confidence=confidence,
            reason="assignment writes through pointer-like or indexed expression",
            provenance=[source, "write_lhs_regex"],
        )
    ]


def _forward_primitives(
    line: str,
    line_no: int,
    source: str,
    parameters: list[ApiContractParameter],
    parameter_roles: dict[str, str],
) -> list[ApiContractPrimitive]:
    ignored = {
        "if",
        "switch",
        "return",
        "sizeof",
        "probeforread",
        "probeforwrite",
        "rtlcopymemory",
        "rtlcopybytes",
        "memcpy",
        "memmove",
    }
    out: list[ApiContractPrimitive] = []
    param_names = {param.name for param in parameters}
    pointer_roles = {"user_pointer", "input_buffer", "output_buffer", "return_length"}
    for name, args in _calls(line):
        if name.lower() in ignored:
            continue
        call_args = _split_args(args)
        forwarded: list[str] = []
        roles: dict[str, str] = {}
        for index, expr in enumerate(call_args):
            matches = _matched_parameter_names(expr, param_names)
            for matched in matches:
                role = parameter_roles.get(matched) or _expr_role(matched)
                if role in pointer_roles or role == "length":
                    forwarded.append(expr)
                    roles[f"arg{index}"] = role
        if not forwarded:
            continue
        out.append(
            ApiContractPrimitive(
                kind="syscall_argument_forward",
                line=line_no,
                snippet=line,
                expressions=forwarded,
                roles=roles,
                confidence=0.63,
                reason=f"{name} forwards syscall/API parameters into a helper call",
                provenance=[source, "parameter_forward_regex"],
            )
        )
    return out


def _parameters(text: str) -> list[ApiContractParameter]:
    match = re.search(
        r"\b[A-Za-z_][A-Za-z0-9_:\s\*]+?\s+[A-Za-z_][A-Za-z0-9_!:.$@]*\s*\((?P<params>[^)]*)\)\s*\{",
        text,
        flags=re.S,
    )
    if not match:
        return []
    out: list[ApiContractParameter] = []
    for index, declaration in enumerate(_split_args(match.group("params"))):
        if declaration.strip().lower() == "void":
            continue
        name_match = re.search(r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*$", declaration)
        if not name_match:
            continue
        name = name_match.group("name")
        role, reason = _parameter_role(name, declaration)
        out.append(
            ApiContractParameter(
                index=index,
                name=name,
                declaration=declaration.strip(),
                role=role,
                role_reason=reason,
            )
        )
    return out


def _parameter_role(name: str, declaration: str) -> tuple[str | None, str | None]:
    haystack = f"{name} {declaration}".lower()
    if "returnlength" in haystack or "return_length" in haystack:
        return "return_length", "parameter name/type looks like ReturnLength pointer"
    if (
        "informationclass" in haystack
        or "infoclass" in haystack
        or "selector" in haystack
    ):
        return "selector", "parameter name looks like selector/class discriminator"
    if re.search(
        r"\b[A-Za-z0-9_]*(?:len|length|size|cb|bytes)[A-Za-z0-9_]*\b", haystack
    ):
        return "length", "parameter name/type looks like byte length"
    if "output" in haystack or re.search(r"\bout\b|outbuffer", haystack):
        return "output_buffer", "parameter name/type looks like output buffer"
    if "input" in haystack or re.search(r"\bin\b|inbuffer", haystack):
        return "input_buffer", "parameter name/type looks like input buffer"
    if "user" in haystack:
        return "user_pointer", "parameter name/type carries user-pointer hint"
    if "*" in declaration or "pvoid" in haystack or "buffer" in haystack:
        return "pointer", "parameter type/name looks pointer-like"
    return None, None


_CONTROL_CALL_NAMES = {"if", "while", "switch", "for", "return"}


def _calls(line: str) -> list[tuple[str, str]]:
    calls: list[tuple[str, str]] = []
    for match in re.finditer(
        r"\b(?P<name>[A-Za-z_][A-Za-z0-9_!:.$@]*)\s*\((?P<args>[^;{}]*)\)",
        line,
    ):
        name = match.group("name")
        args = match.group("args")
        if name.lower() in _CONTROL_CALL_NAMES:
            calls.extend(_calls(args))
            continue
        calls.append((name, args))
    return calls


def _split_args(value: str) -> list[str]:
    parts: list[str] = []
    depth = 0
    start = 0
    for idx, ch in enumerate(value):
        if ch in "([{":
            depth += 1
        elif ch in ")]}" and depth:
            depth -= 1
        elif ch == "," and depth == 0:
            parts.append(value[start:idx].strip())
            start = idx + 1
    tail = value[start:].strip()
    if tail:
        parts.append(tail)
    return parts


def _expr_role(expr: str) -> str:
    haystack = expr.lower()
    if "returnlength" in haystack or "return_length" in haystack:
        return "return_length"
    if (
        "informationclass" in haystack
        or "infoclass" in haystack
        or "selector" in haystack
    ):
        return "selector"
    if re.search(
        r"\b[A-Za-z0-9_]*(?:len|length|size|cb|bytes)[A-Za-z0-9_]*\b", haystack
    ):
        return "length"
    if "output" in haystack or re.search(r"\bout\b|outbuffer", haystack):
        return "output_buffer"
    if "input" in haystack or re.search(r"\bin\b|inbuffer", haystack):
        return "input_buffer"
    if "user" in haystack:
        return "user_pointer"
    if "*" in expr or "->" in expr or "[" in expr or expr.startswith("&"):
        return "pointer"
    return "value"


def _pool_expr_role(role_name: str, expr: str) -> str:
    if role_name == "size":
        return "length"
    if role_name == "pointer":
        return "pointer"
    if role_name in {"flags", "pool_type", "tag"}:
        return "value"
    return _expr_role(expr)


def _contract_expr_role(role_name: str, expr: str) -> str:
    semantic_roles = {
        "input_buffer": "input_buffer",
        "send_message": "input_buffer",
        "value_data": "input_buffer",
        "output_buffer": "output_buffer",
        "type3_input_buffer": "input_buffer",
        "system_buffer": "input_output_buffer",
        "user_buffer": "user_pointer",
        "key_value_information": "output_buffer",
        "receive_message": "output_buffer",
        "return_length": "return_length",
        "result_length": "return_length",
        "output_length": "return_length",
        "io_status_information": "return_length",
        "length": "length",
        "input_length": "length",
        "minimum_required_size": "length",
        "receive_buffer_length": "length",
        "user_data_count": "length",
        "object": "output_object",
        "object_pointer": "object",
        "callback_object": "object",
        "irp": "irp",
        "request": "request",
        "parameters": "output_object",
        "mdl": "mdl",
        "mdl_address": "mdl",
        "callback": "callback",
        "access_mode": "access_mode",
        "requestor_mode": "access_mode",
        "privilege": "privilege",
        "privilege_set": "privilege",
        "security_context": "security_context",
        "subject_security_context": "security_context",
        "security_descriptor": "security_descriptor",
        "token": "token",
        "token_information": "output_buffer",
        "process": "process",
        "thread": "thread",
        "api_number": "selector",
        "event_descriptor": "trace_descriptor",
        "provider": "trace_provider",
        "ioctl_code": "value",
    }
    if role_name in semantic_roles:
        return semantic_roles[role_name]
    if role_name.endswith("_handle") or role_name in {"handle", "logger_handle"}:
        return "handle"
    if role_name in {
        "flags",
        "access_mode",
        "desired_access",
        "operation",
        "priority",
        "priority_boost",
        "remove",
        "value_type",
        "info_class",
    }:
        return "value"
    return _expr_role(expr)


def _canonical_field_name(
    field: str,
    known: dict[str, str],
) -> str | None:
    lowered = field.lower()
    for candidate in known:
        if candidate.lower() == lowered:
            return candidate
    return None


def _canonical_irp_field(
    field: str,
    known: dict[str, str],
) -> str | None:
    normalized = field.replace("->", ".").lower()
    for candidate in known:
        if candidate.lower() == normalized:
            return candidate
    return None


def _condition_expr(line: str) -> str:
    match = re.search(r"\bif\s*\((?P<condition>.*)\)", line)
    if match:
        return match.group("condition").strip()
    return ""


def _assignment_lhs(line: str) -> str | None:
    glaurung_match = re.match(
        r"\s*(?P<lhs>(?:\*?&)?\[[^\]]+\])\s*(?:=|\+=|-=|\+\+|--)",
        line,
    )
    if glaurung_match:
        return glaurung_match.group("lhs").replace(" ", "")
    match = re.match(
        r"(?:\+\+|--)?\s*(?P<lhs>"
        r"\*+\s*\(?\s*[A-Za-z_][A-Za-z0-9_.$@]*(?:->\w+)?"
        r"|\(?\s*\*[A-Za-z_][A-Za-z0-9_.$@]*\)?"
        r"|[A-Za-z_][A-Za-z0-9_.$@]*\s*\[[^\]]+\]"
        r"|[A-Za-z_][A-Za-z0-9_.$@]*->\w+"
        r")\s*(?:=|\+=|-=|\+\+|--)",
        line,
    )
    if match:
        return match.group("lhs").strip()
    return None


def _matched_parameter_names(expr: str, names: set[str]) -> list[str]:
    return [
        name
        for name in sorted(names, key=lambda value: len(value), reverse=True)
        if re.search(rf"\b{re.escape(name)}\b", expr)
    ]


def _dedupe_primitives(
    primitives: list[ApiContractPrimitive],
) -> list[ApiContractPrimitive]:
    out: list[ApiContractPrimitive] = []
    seen: set[tuple[str, int, str]] = set()
    for primitive in primitives:
        key = (primitive.kind, primitive.line, primitive.snippet)
        if key in seen:
            continue
        seen.add(key)
        out.append(primitive)
    return out


def _missing_capabilities(counts: Counter[str], source: str) -> list[str]:
    missing: list[str] = []
    if source in {"none", "glaurung_decompiler_failed"}:
        missing.append("pseudocode")
    if not (counts.get("probe_for_read") or counts.get("probe_for_write")):
        missing.append("probe_primitives")
    if not counts.get("length_comparison"):
        missing.append("length_gates")
    if not counts.get("selector_dispatch"):
        missing.append("selector_dispatch")
    if not (counts.get("pointer_write") or counts.get("return_length_write")):
        missing.append("pointer_writes")
    return missing


def build_tool() -> MemoryTool[
    WindowsApiContractPrimitivesArgs,
    WindowsApiContractPrimitivesResult,
]:
    return WindowsApiContractPrimitivesTool()
