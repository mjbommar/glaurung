from __future__ import annotations

import re
import struct
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Edge, Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


ServiceTableKind = Literal["native", "win32k", "unknown"]
SyscallDispatchKind = Literal[
    "text_syscall",
    "x64_syscall",
    "x64_syscall_int2e_fallback",
    "unknown",
]


class WindowsSyscallStubFact(BaseModel):
    syscall_number: int
    syscall_hex: str
    user_stub_symbol: str
    user_stub_module: str | None = None
    service_table: ServiceTableKind
    line: int
    rva: int | None = None
    va: int | None = None
    file_offset: int | None = None
    byte_offset: int | None = None
    section_name: str | None = None
    snippet: str
    byte_pattern: str | None = None
    dispatch_kind: SyscallDispatchKind = "unknown"
    stub_shape: str = "unknown"
    has_kuser_shared_data_gate: bool = False
    has_int2e_fallback: bool = False
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[str] = Field(default_factory=list)


class WindowsSyscallStubAtlasArgs(BaseModel):
    binary_path: str | None = Field(
        None,
        description=(
            "Optional PE binary path. When supplied, scan named exports and "
            "optionally executable sections for x64 syscall-stub byte patterns."
        ),
    )
    pseudocode: str = Field(
        "",
        description=(
            "Source-like or Glaurung-lifted syscall stub text. Supports "
            "`ret = imm; unknown(syscall);`, `eax = imm; syscall`, and "
            "`mov eax, imm; syscall` shapes."
        ),
    )
    raw_bytes_hex: str | None = Field(
        None,
        description=(
            "Optional raw x64 stub bytes as hex. Supports common "
            "`mov r10, rcx; mov eax, imm32; ...; syscall; ret` shapes."
        ),
    )
    user_stub_module: str | None = Field(
        None,
        description="Optional source module, for example ntdll.dll or win32u.dll.",
    )
    service_table: ServiceTableKind = Field(
        "unknown",
        description="Optional expected service table kind for emitted rows.",
    )
    raw_base_offset: int = Field(
        0,
        ge=0,
        description="Base file/RVA offset to add to raw-byte stub offsets.",
    )
    raw_base_rva: int | None = Field(
        None,
        ge=0,
        description="Optional base RVA to add to raw-byte stub offsets.",
    )
    raw_base_va: int | None = Field(
        None,
        ge=0,
        description="Optional base VA to add to raw-byte stub offsets.",
    )
    scan_executable_sections: bool = Field(
        False,
        description=(
            "If true, scan executable PE sections in addition to named exports. "
            "Section scans emit anonymous sub_<rva> rows."
        ),
    )
    max_binary_bytes: int = Field(
        268_435_456,
        ge=1,
        description="Maximum PE bytes to read when binary_path is supplied.",
    )
    max_stubs: int = Field(4096, ge=1, description="Maximum syscall rows to return.")
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact syscall-atlas evidence node to the KB.",
    )


class WindowsSyscallStubAtlasResult(BaseModel):
    syscall_count: int
    stubs: list[WindowsSyscallStubFact]
    coverage: list[str] = Field(default_factory=list)
    missing_capabilities: list[str] = Field(default_factory=list)
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsSyscallStubAtlasTool(
    MemoryTool[WindowsSyscallStubAtlasArgs, WindowsSyscallStubAtlasResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_syscall_stub_atlas",
                description=(
                    "Materialize a user-mode Windows syscall-stub atlas from "
                    "lifted ntdll/win32u text: syscall number, stub symbol, "
                    "module, and service-table family."
                ),
                tags=("windows", "pe", "syscall", "ssdt", "atlas"),
            ),
            WindowsSyscallStubAtlasArgs,
            WindowsSyscallStubAtlasResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsSyscallStubAtlasArgs,
    ) -> WindowsSyscallStubAtlasResult:
        module = args.user_stub_module
        if module is None and args.binary_path:
            module = Path(args.binary_path).name
        stubs = _extract_syscall_stubs(
            args.pseudocode,
            binary_path=args.binary_path,
            raw_bytes_hex=args.raw_bytes_hex,
            module=module,
            service_table=args.service_table,
            raw_base_offset=args.raw_base_offset,
            raw_base_rva=args.raw_base_rva,
            raw_base_va=args.raw_base_va,
            scan_executable_sections=args.scan_executable_sections,
            max_binary_bytes=args.max_binary_bytes,
            max_stubs=args.max_stubs,
        )
        coverage = ["syscall_stubs"] if stubs else []
        if any(stub.byte_pattern for stub in stubs):
            coverage.append("raw_syscall_stub_bytes")
        if any(stub.dispatch_kind != "unknown" for stub in stubs):
            coverage.append("syscall_dispatch_shape")
        if any(stub.has_kuser_shared_data_gate for stub in stubs):
            coverage.append("kuser_shared_data_syscall_gate")
        if any(stub.has_int2e_fallback for stub in stubs):
            coverage.append("int2e_fallback")
        if any(stub.file_offset is not None for stub in stubs):
            coverage.append("pe_syscall_stub_bytes")
        if any(
            stub.file_offset is not None and stub.user_stub_symbol for stub in stubs
        ):
            coverage.append("export_named_syscall_stubs")
        if any(stub.user_stub_symbol.startswith(("Nt", "Zw")) for stub in stubs):
            coverage.append("native_syscall_names")
        if any(stub.user_stub_symbol.startswith(("NtUser", "NtGdi")) for stub in stubs):
            coverage.append("win32k_syscall_names")
        if any(stub.service_table == "native" for stub in stubs):
            coverage.append("native_syscall_numbers")
        if any(stub.service_table == "win32k" for stub in stubs):
            coverage.append("win32k_syscall_numbers")
        missing = [] if stubs else ["syscall_stubs"]

        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_syscall_stub_atlas",
                    props={
                        "binary_path": args.binary_path,
                        "user_stub_module": module,
                        "service_table": args.service_table,
                        "syscall_count": len(stubs),
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))

        return WindowsSyscallStubAtlasResult(
            syscall_count=len(stubs),
            stubs=stubs,
            coverage=coverage,
            missing_capabilities=missing,
            evidence_node_id=evidence_node_id,
            notes=[
                "syscall stub atlas rows identify user-mode service numbers; "
                "kernel SSDT handler resolution and live table comparison are separate steps"
            ],
        )


_FUNCTION_RE = re.compile(
    r"\b(?:fn\s+|[A-Za-z_][A-Za-z0-9_\s*]+\s+)(?P<name>[A-Za-z_][A-Za-z0-9_.$@!]*)\s*(?:\(|\{)"
)
_SYSCALL_ID_ASSIGNMENT_RE = re.compile(
    r"\b(?:ret|eax|rax)\s*=\s*(?P<value>0x[0-9A-Fa-f]+|\d+)\s*;"
)
_MOV_EAX_RE = re.compile(
    r"\bmov(?:\s+|\()e?ax\s*,\s*(?P<value>0x[0-9A-Fa-f]+|\d+)",
    re.IGNORECASE,
)


def _extract_syscall_stubs(
    text: str,
    *,
    binary_path: str | None = None,
    raw_bytes_hex: str | None = None,
    module: str | None,
    service_table: ServiceTableKind,
    raw_base_offset: int = 0,
    raw_base_rva: int | None = None,
    raw_base_va: int | None = None,
    scan_executable_sections: bool = False,
    max_binary_bytes: int,
    max_stubs: int,
) -> list[WindowsSyscallStubFact]:
    stubs: list[WindowsSyscallStubFact] = []
    seen: set[tuple[str, int]] = set()
    if binary_path:
        for stub in _extract_binary_syscall_stubs(
            Path(binary_path),
            module=module,
            service_table=service_table,
            scan_executable_sections=scan_executable_sections,
            max_binary_bytes=max_binary_bytes,
            max_stubs=max_stubs,
        ):
            stubs.append(stub)
            seen.add((stub.user_stub_symbol.lower(), stub.syscall_number))
            if len(stubs) >= max_stubs:
                return stubs

    if raw_bytes_hex:
        for stub in _extract_raw_syscall_stubs(
            raw_bytes_hex,
            module=module,
            service_table=service_table,
            raw_base_offset=raw_base_offset,
            raw_base_rva=raw_base_rva,
            raw_base_va=raw_base_va,
            max_stubs=max_stubs,
        ):
            key = (stub.user_stub_symbol.lower(), stub.syscall_number)
            if key in seen:
                continue
            stubs.append(stub)
            seen.add(key)
            if len(stubs) >= max_stubs:
                return stubs

    current_symbol = "sub_unknown"
    pending_number: int | None = None
    pending_line = 0
    pending_snippet = ""
    for line_no, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        function = _FUNCTION_RE.search(line)
        if function is not None:
            current_symbol = _clean_symbol(function.group("name"))
            pending_number = None
            pending_line = 0
            pending_snippet = ""
        number = _syscall_number_assignment(line)
        if number is not None:
            pending_number = number
            pending_line = line_no
            pending_snippet = line
        if "syscall" not in line.lower() or pending_number is None:
            continue
        symbol = current_symbol
        key = (symbol.lower(), pending_number)
        if key in seen:
            continue
        seen.add(key)
        stubs.append(
            WindowsSyscallStubFact(
                syscall_number=pending_number,
                syscall_hex=f"0x{pending_number:x}",
                user_stub_symbol=symbol,
                user_stub_module=module,
                service_table=_infer_service_table(
                    symbol,
                    module=module,
                    fallback=service_table,
                ),
                line=line_no,
                snippet=line if line_no != pending_line else pending_snippet,
                dispatch_kind="text_syscall",
                stub_shape="lifted_assignment_syscall",
                confidence=_syscall_stub_confidence(symbol, line, pending_snippet),
                evidence=[pending_snippet, line] if line != pending_snippet else [line],
            )
        )
        if len(stubs) >= max_stubs:
            break
    return stubs


def _extract_raw_syscall_stubs(
    raw_bytes_hex: str,
    *,
    module: str | None,
    service_table: ServiceTableKind,
    raw_base_offset: int,
    raw_base_rva: int | None = None,
    raw_base_va: int | None = None,
    raw_symbol: str | None = None,
    section_name: str | None = None,
    max_stubs: int,
) -> list[WindowsSyscallStubFact]:
    data = _decode_hex_bytes(raw_bytes_hex)
    return _extract_syscall_stubs_from_bytes(
        data,
        module=module,
        service_table=service_table,
        raw_base_offset=raw_base_offset,
        raw_base_rva=raw_base_rva,
        raw_base_va=raw_base_va,
        raw_symbol=raw_symbol,
        section_name=section_name,
        max_stubs=max_stubs,
    )


def _extract_syscall_stubs_from_bytes(
    data: bytes,
    *,
    module: str | None,
    service_table: ServiceTableKind,
    raw_base_offset: int,
    raw_base_rva: int | None = None,
    raw_base_va: int | None = None,
    raw_symbol: str | None = None,
    section_name: str | None = None,
    max_stubs: int,
) -> list[WindowsSyscallStubFact]:
    stubs: list[WindowsSyscallStubFact] = []
    seen_offsets: set[int] = set()
    for mov_eax_offset in range(max(0, len(data) - 4)):
        if data[mov_eax_offset] != 0xB8:
            continue
        syscall_offset = _find_bytes(data, b"\x0f\x05", mov_eax_offset + 5, 48)
        if syscall_offset is None:
            continue
        ret_offset = _find_bytes(data, b"\xc3", syscall_offset + 2, 8)
        if ret_offset is None:
            continue
        stub_offset = _stub_start_for_mov_eax(data, mov_eax_offset)
        if stub_offset in seen_offsets:
            continue
        seen_offsets.add(stub_offset)
        syscall_number = int.from_bytes(
            data[mov_eax_offset + 1 : mov_eax_offset + 5],
            "little",
            signed=False,
        )
        absolute_offset = raw_base_offset + stub_offset
        stub_rva = None if raw_base_rva is None else raw_base_rva + stub_offset
        stub_va = None if raw_base_va is None else raw_base_va + stub_offset
        symbol = raw_symbol or (
            f"sub_{stub_rva:x}" if stub_rva is not None else f"sub_{absolute_offset:x}"
        )
        shape = _classify_raw_syscall_stub(
            data,
            stub_offset=stub_offset,
            mov_eax_offset=mov_eax_offset,
            syscall_offset=syscall_offset,
            ret_offset=ret_offset,
        )
        snippet_bytes = data[stub_offset : min(len(data), shape.end_offset + 1)]
        snippet = snippet_bytes.hex(" ")
        stubs.append(
            WindowsSyscallStubFact(
                syscall_number=syscall_number,
                syscall_hex=f"0x{syscall_number:x}",
                user_stub_symbol=symbol,
                user_stub_module=module,
                service_table=_infer_service_table(
                    symbol,
                    module=module,
                    fallback=service_table,
                ),
                line=0,
                rva=stub_rva,
                va=stub_va,
                file_offset=absolute_offset,
                byte_offset=absolute_offset,
                section_name=section_name,
                snippet=snippet,
                byte_pattern=snippet,
                dispatch_kind=shape.dispatch_kind,
                stub_shape=shape.stub_shape,
                has_kuser_shared_data_gate=shape.has_kuser_shared_data_gate,
                has_int2e_fallback=shape.has_int2e_fallback,
                confidence=_raw_syscall_stub_confidence(
                    data,
                    stub_offset=stub_offset,
                    mov_eax_offset=mov_eax_offset,
                ),
                evidence=[
                    f"offset=0x{absolute_offset:x}",
                    f"mov_eax=0x{raw_base_offset + mov_eax_offset:x}",
                    f"syscall=0x{raw_base_offset + syscall_offset:x}",
                    f"shape={shape.stub_shape}",
                    snippet,
                ],
            )
        )
        if len(stubs) >= max_stubs:
            break
    return stubs


class _PeSection(BaseModel):
    name: str
    rva: int
    virtual_size: int
    raw_size: int
    raw_pointer: int
    characteristics: int

    @property
    def executable(self) -> bool:
        return bool(self.characteristics & 0x2000_0000)

    def contains_rva(self, rva: int) -> bool:
        span = max(self.virtual_size, self.raw_size)
        return self.rva <= rva < self.rva + span

    def file_offset_for_rva(self, rva: int) -> int | None:
        if not self.contains_rva(rva):
            return None
        return self.raw_pointer + (rva - self.rva)


class _PeExport(BaseModel):
    name: str
    rva: int
    file_offset: int
    va: int
    section_name: str | None = None


class _RawSyscallStubShape(BaseModel):
    dispatch_kind: SyscallDispatchKind
    stub_shape: str
    has_kuser_shared_data_gate: bool
    has_int2e_fallback: bool
    end_offset: int


class _PeView(BaseModel):
    data: bytes
    image_base: int
    export_rva: int
    export_size: int
    sections: list[_PeSection]
    exports: list[_PeExport]


def _extract_binary_syscall_stubs(
    path: Path,
    *,
    module: str | None,
    service_table: ServiceTableKind,
    scan_executable_sections: bool,
    max_binary_bytes: int,
    max_stubs: int,
) -> list[WindowsSyscallStubFact]:
    if not path.exists():
        raise ValueError(f"{path}: PE binary does not exist")
    data = path.read_bytes()
    if len(data) > max_binary_bytes:
        raise ValueError(
            f"{path}: PE binary is {len(data)} bytes, above max_binary_bytes={max_binary_bytes}"
        )
    view = _parse_pe_view(data)
    if view is None:
        return []

    stubs: list[WindowsSyscallStubFact] = []
    seen: set[tuple[int | None, int | None, str]] = set()
    for export in view.exports:
        chunk = view.data[export.file_offset : export.file_offset + 96]
        for stub in _extract_syscall_stubs_from_bytes(
            chunk,
            module=module,
            service_table=service_table,
            raw_base_offset=export.file_offset,
            raw_base_rva=export.rva,
            raw_base_va=export.va,
            raw_symbol=export.name,
            section_name=export.section_name,
            max_stubs=1,
        ):
            key = (stub.rva, stub.syscall_number, stub.user_stub_symbol.lower())
            if key in seen:
                continue
            seen.add(key)
            stubs.append(stub)
            if len(stubs) >= max_stubs:
                return stubs

    if not scan_executable_sections:
        return stubs

    for section in view.sections:
        if not section.executable or section.raw_size <= 0:
            continue
        start = section.raw_pointer
        end = min(len(view.data), section.raw_pointer + section.raw_size)
        if start >= end:
            continue
        for stub in _extract_syscall_stubs_from_bytes(
            view.data[start:end],
            module=module,
            service_table=service_table,
            raw_base_offset=start,
            raw_base_rva=section.rva,
            raw_base_va=view.image_base + section.rva,
            section_name=section.name,
            max_stubs=max_stubs - len(stubs),
        ):
            key = (stub.rva, stub.syscall_number, stub.user_stub_symbol.lower())
            if key in seen:
                continue
            seen.add(key)
            stubs.append(stub)
            if len(stubs) >= max_stubs:
                return stubs
    return stubs


def _parse_pe_view(data: bytes) -> _PeView | None:
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    pe_off = _read_u32(data, 0x3C)
    if (
        pe_off is None
        or pe_off + 24 > len(data)
        or data[pe_off : pe_off + 4] != b"PE\0\0"
    ):
        return None
    coff = pe_off + 4
    section_count = _read_u16(data, coff + 2)
    optional_size = _read_u16(data, coff + 16)
    if section_count is None or optional_size is None:
        return None
    optional = coff + 20
    if optional + optional_size > len(data):
        return None
    magic = _read_u16(data, optional)
    if magic == 0x20B:
        image_base = _read_u64(data, optional + 24)
        number_of_rva_and_sizes = _read_u32(data, optional + 108)
        data_directory = optional + 112
    elif magic == 0x10B:
        image_base = _read_u32(data, optional + 28)
        number_of_rva_and_sizes = _read_u32(data, optional + 92)
        data_directory = optional + 96
    else:
        return None
    if image_base is None or not number_of_rva_and_sizes:
        return None
    export_rva = _read_u32(data, data_directory) or 0
    export_size = _read_u32(data, data_directory + 4) or 0
    sections = _parse_pe_sections(data, optional + optional_size, section_count)
    exports = _parse_pe_named_exports(
        data,
        image_base=int(image_base),
        sections=sections,
        export_rva=export_rva,
        export_size=export_size,
    )
    return _PeView(
        data=data,
        image_base=int(image_base),
        export_rva=export_rva,
        export_size=export_size,
        sections=sections,
        exports=exports,
    )


def _parse_pe_sections(
    data: bytes,
    section_table: int,
    section_count: int,
) -> list[_PeSection]:
    sections: list[_PeSection] = []
    for index in range(min(section_count, 4096)):
        off = section_table + index * 40
        if off + 40 > len(data):
            break
        raw_name = data[off : off + 8].split(b"\0", 1)[0]
        virtual_size = _read_u32(data, off + 8) or 0
        rva = _read_u32(data, off + 12) or 0
        raw_size = _read_u32(data, off + 16) or 0
        raw_pointer = _read_u32(data, off + 20) or 0
        characteristics = _read_u32(data, off + 36) or 0
        sections.append(
            _PeSection(
                name=raw_name.decode("ascii", errors="replace"),
                rva=rva,
                virtual_size=virtual_size,
                raw_size=raw_size,
                raw_pointer=raw_pointer,
                characteristics=characteristics,
            )
        )
    return sections


def _parse_pe_named_exports(
    data: bytes,
    *,
    image_base: int,
    sections: list[_PeSection],
    export_rva: int,
    export_size: int,
) -> list[_PeExport]:
    if export_rva == 0 or export_size == 0:
        return []
    export_off = _rva_to_file_offset(sections, export_rva)
    if export_off is None or export_off + 40 > len(data):
        return []
    function_count = _read_u32(data, export_off + 0x14) or 0
    name_count = _read_u32(data, export_off + 0x18) or 0
    functions_rva = _read_u32(data, export_off + 0x1C) or 0
    names_rva = _read_u32(data, export_off + 0x20) or 0
    ordinals_rva = _read_u32(data, export_off + 0x24) or 0
    functions_off = _rva_to_file_offset(sections, functions_rva)
    names_off = _rva_to_file_offset(sections, names_rva)
    ordinals_off = _rva_to_file_offset(sections, ordinals_rva)
    if functions_off is None or names_off is None or ordinals_off is None:
        return []

    exports: list[_PeExport] = []
    export_end = export_rva + export_size
    for index in range(min(name_count, 100_000)):
        name_rva = _read_u32(data, names_off + index * 4)
        ordinal_index = _read_u16(data, ordinals_off + index * 2)
        if name_rva is None or ordinal_index is None or ordinal_index >= function_count:
            continue
        function_rva = _read_u32(data, functions_off + int(ordinal_index) * 4)
        if function_rva is None or function_rva == 0:
            continue
        if export_rva <= function_rva < export_end:
            continue
        name_off = _rva_to_file_offset(sections, name_rva)
        function_off = _rva_to_file_offset(sections, function_rva)
        if name_off is None or function_off is None:
            continue
        name = _read_c_string(data, name_off, max_len=512)
        if not name:
            continue
        section = _section_for_rva(sections, function_rva)
        exports.append(
            _PeExport(
                name=name,
                rva=function_rva,
                file_offset=function_off,
                va=image_base + function_rva,
                section_name=None if section is None else section.name,
            )
        )
    return exports


def _rva_to_file_offset(sections: list[_PeSection], rva: int) -> int | None:
    for section in sections:
        offset = section.file_offset_for_rva(rva)
        if offset is not None:
            return offset
    return None


def _section_for_rva(sections: list[_PeSection], rva: int) -> _PeSection | None:
    for section in sections:
        if section.contains_rva(rva):
            return section
    return None


def _read_c_string(data: bytes, offset: int, *, max_len: int) -> str | None:
    if offset >= len(data):
        return None
    end = data.find(b"\0", offset, min(len(data), offset + max_len))
    if end < 0:
        return None
    return data[offset:end].decode("ascii", errors="replace")


def _read_u16(data: bytes, offset: int) -> int | None:
    if offset < 0 or offset + 2 > len(data):
        return None
    return struct.unpack_from("<H", data, offset)[0]


def _read_u32(data: bytes, offset: int) -> int | None:
    if offset < 0 or offset + 4 > len(data):
        return None
    return struct.unpack_from("<I", data, offset)[0]


def _read_u64(data: bytes, offset: int) -> int | None:
    if offset < 0 or offset + 8 > len(data):
        return None
    return struct.unpack_from("<Q", data, offset)[0]


def _decode_hex_bytes(raw_bytes_hex: str) -> bytes:
    cleaned = raw_bytes_hex.replace("\\x", " ")
    byte_tokens = re.findall(r"\b[0-9A-Fa-f]{2}\b", cleaned)
    if not byte_tokens:
        compact = re.sub(r"[^0-9A-Fa-f]", "", raw_bytes_hex)
        if len(compact) % 2 != 0:
            compact = compact[:-1]
        byte_tokens = [
            compact[index : index + 2] for index in range(0, len(compact), 2)
        ]
    return bytes(int(token, 16) for token in byte_tokens if token)


def _find_bytes(data: bytes, needle: bytes, start: int, window: int) -> int | None:
    end = min(len(data), start + window)
    found = data.find(needle, start, end)
    return found if found >= 0 else None


def _stub_start_for_mov_eax(data: bytes, mov_eax_offset: int) -> int:
    mov_r10_rcx = b"\x4c\x8b\xd1"
    prefix_start = max(0, mov_eax_offset - 8)
    prefix = data[prefix_start:mov_eax_offset]
    relative = prefix.rfind(mov_r10_rcx)
    if relative >= 0:
        return prefix_start + relative
    return mov_eax_offset


def _classify_raw_syscall_stub(
    data: bytes,
    *,
    stub_offset: int,
    mov_eax_offset: int,
    syscall_offset: int,
    ret_offset: int,
) -> _RawSyscallStubShape:
    stub_window = data[stub_offset : min(len(data), ret_offset + 16)]
    pre_syscall = data[mov_eax_offset + 5 : syscall_offset]
    has_kuser_gate = b"\xf6\x04\x25\x08\x03\xfe\x7f\x01" in pre_syscall
    fallback = data.find(
        b"\xcd\x2e\xc3", ret_offset + 1, min(len(data), ret_offset + 12)
    )
    has_int2e_fallback = fallback >= 0
    end_offset = fallback + 2 if has_int2e_fallback else ret_offset

    if has_kuser_gate and has_int2e_fallback:
        shape = "x64_mov_r10_mov_eax_kuser_gate_syscall_int2e"
    elif has_kuser_gate:
        shape = "x64_mov_r10_mov_eax_kuser_gate_syscall"
    elif data[stub_offset:mov_eax_offset] == b"\x4c\x8b\xd1":
        shape = "x64_mov_r10_mov_eax_syscall"
    elif stub_window.startswith(b"\xb8"):
        shape = "x64_mov_eax_syscall"
    else:
        shape = "x64_embedded_mov_eax_syscall"

    return _RawSyscallStubShape(
        dispatch_kind=(
            "x64_syscall_int2e_fallback" if has_int2e_fallback else "x64_syscall"
        ),
        stub_shape=shape,
        has_kuser_shared_data_gate=has_kuser_gate,
        has_int2e_fallback=has_int2e_fallback,
        end_offset=end_offset,
    )


def _syscall_number_assignment(line: str) -> int | None:
    for pattern in (_SYSCALL_ID_ASSIGNMENT_RE, _MOV_EAX_RE):
        match = pattern.search(line)
        if match is None:
            continue
        return int(match.group("value"), 0)
    return None


def _infer_service_table(
    symbol: str,
    *,
    module: str | None,
    fallback: ServiceTableKind,
) -> ServiceTableKind:
    lowered_module = (module or "").lower()
    if symbol.startswith(("NtUser", "NtGdi")) or "win32u" in lowered_module:
        return "win32k"
    if symbol.startswith(("Nt", "Zw")) or "ntdll" in lowered_module:
        return "native"
    return fallback


def _syscall_stub_confidence(
    symbol: str, syscall_line: str, assignment_line: str
) -> float:
    confidence = 0.76
    if symbol.startswith(("Nt", "Zw")):
        confidence += 0.08
    if "unknown(syscall)" in syscall_line.lower() or re.search(
        r"\bsyscall\b",
        syscall_line,
        re.IGNORECASE,
    ):
        confidence += 0.08
    if assignment_line:
        confidence += 0.04
    return min(confidence, 0.96)


def _raw_syscall_stub_confidence(
    data: bytes,
    *,
    stub_offset: int,
    mov_eax_offset: int,
) -> float:
    confidence = 0.86
    if data[stub_offset:mov_eax_offset] == b"\x4c\x8b\xd1":
        confidence += 0.06
    return min(confidence, 0.96)


def _clean_symbol(symbol: str) -> str:
    symbol = symbol.rsplit("!", 1)[-1]
    symbol = symbol.lstrip("?")
    return re.sub(r"[^A-Za-z0-9_.$@]", "_", symbol).strip("_") or "sub_unknown"


def build_tool() -> WindowsSyscallStubAtlasTool:
    return WindowsSyscallStubAtlasTool()
