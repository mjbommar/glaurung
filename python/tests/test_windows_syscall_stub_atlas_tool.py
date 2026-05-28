from __future__ import annotations

from pathlib import Path

import glaurung as g
import pytest

from glaurung.llm.agents.memory_agent import create_memory_agent
from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind
from glaurung.llm.tools.windows_syscall_stub_atlas import build_tool


FIXTURE_NTDLL = Path("tests/fixtures/msvc-pdb/ntdll.dll")


def _ctx(tmp_path: Path) -> MemoryContext:
    path = tmp_path / "ntdll.dll"
    path.write_bytes(b"MZ")
    artifact = g.triage.analyze_bytes(b"MZ")
    ctx = MemoryContext(file_path=str(path), artifact=artifact)
    import_triage(ctx.kb, artifact, str(path))
    return ctx


def _write_pe_with_exported_syscall_stub(tmp_path: Path) -> Path:
    path = tmp_path / "ntdll-export-stub.dll"
    data = bytearray(0x800)
    data[0:2] = b"MZ"
    data[0x3C:0x40] = (0x80).to_bytes(4, "little")
    data[0x80:0x84] = b"PE\0\0"
    coff = 0x84
    data[coff : coff + 2] = (0x8664).to_bytes(2, "little")
    data[coff + 2 : coff + 4] = (2).to_bytes(2, "little")
    data[coff + 16 : coff + 18] = (0xF0).to_bytes(2, "little")
    data[coff + 18 : coff + 20] = (0x2022).to_bytes(2, "little")

    optional = coff + 20
    data[optional : optional + 2] = (0x20B).to_bytes(2, "little")
    data[optional + 24 : optional + 32] = (0x180000000).to_bytes(8, "little")
    data[optional + 32 : optional + 36] = (0x1000).to_bytes(4, "little")
    data[optional + 36 : optional + 40] = (0x200).to_bytes(4, "little")
    data[optional + 56 : optional + 60] = (0x3000).to_bytes(4, "little")
    data[optional + 60 : optional + 64] = (0x200).to_bytes(4, "little")
    data[optional + 108 : optional + 112] = (16).to_bytes(4, "little")
    data[optional + 112 : optional + 116] = (0x2000).to_bytes(4, "little")
    data[optional + 116 : optional + 120] = (0x200).to_bytes(4, "little")

    section = optional + 0xF0
    data[section : section + 8] = b".text\0\0\0"
    data[section + 8 : section + 12] = (0x200).to_bytes(4, "little")
    data[section + 12 : section + 16] = (0x1000).to_bytes(4, "little")
    data[section + 16 : section + 20] = (0x200).to_bytes(4, "little")
    data[section + 20 : section + 24] = (0x200).to_bytes(4, "little")
    data[section + 36 : section + 40] = (0x60000020).to_bytes(4, "little")

    edata = section + 40
    data[edata : edata + 8] = b".edata\0\0"
    data[edata + 8 : edata + 12] = (0x200).to_bytes(4, "little")
    data[edata + 12 : edata + 16] = (0x2000).to_bytes(4, "little")
    data[edata + 16 : edata + 20] = (0x200).to_bytes(4, "little")
    data[edata + 20 : edata + 24] = (0x400).to_bytes(4, "little")
    data[edata + 36 : edata + 40] = (0x40000040).to_bytes(4, "little")

    data[0x200:0x20B] = bytes.fromhex("4c 8b d1 b8 36 00 00 00 0f 05 c3")

    export_dir = 0x400
    data[export_dir + 16 : export_dir + 20] = (1).to_bytes(4, "little")
    data[export_dir + 20 : export_dir + 24] = (1).to_bytes(4, "little")
    data[export_dir + 24 : export_dir + 28] = (1).to_bytes(4, "little")
    data[export_dir + 28 : export_dir + 32] = (0x2040).to_bytes(4, "little")
    data[export_dir + 32 : export_dir + 36] = (0x2050).to_bytes(4, "little")
    data[export_dir + 36 : export_dir + 40] = (0x2060).to_bytes(4, "little")
    data[0x440:0x444] = (0x1000).to_bytes(4, "little")
    data[0x450:0x454] = (0x2070).to_bytes(4, "little")
    data[0x460:0x462] = (0).to_bytes(2, "little")
    data[0x470 : 0x470 + 25] = b"NtQuerySystemInformation\0"

    path.write_bytes(data)
    return path


def test_windows_syscall_stub_atlas_extracts_glaurung_syscall_stubs(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            user_stub_module="ntdll.dll",
            pseudocode="""
fn NtQuerySystemInformation {
    ret = 54;
    unknown(syscall);
    return;
}
fn NtQuerySystemInformationEx {
    ret = 0x16c;
    unknown(syscall);
    return;
}
""",
            add_to_kb=True,
        ),
    )

    assert result.syscall_count == 2
    assert [(stub.user_stub_symbol, stub.syscall_number) for stub in result.stubs] == [
        ("NtQuerySystemInformation", 54),
        ("NtQuerySystemInformationEx", 0x16C),
    ]
    assert all(stub.service_table == "native" for stub in result.stubs)
    assert all(stub.dispatch_kind == "text_syscall" for stub in result.stubs)
    assert all(stub.stub_shape == "lifted_assignment_syscall" for stub in result.stubs)
    assert result.stubs[0].syscall_hex == "0x36"
    assert "syscall_stubs" in result.coverage
    assert "syscall_dispatch_shape" in result.coverage
    assert "native_syscall_names" in result.coverage
    assert result.evidence_node_id is not None
    assert any(
        node.kind == NodeKind.evidence and node.label == "windows_syscall_stub_atlas"
        for node in ctx.kb.nodes()
    )


def test_windows_syscall_stub_atlas_extracts_assembly_win32u_stubs(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            user_stub_module="win32u.dll",
            pseudocode="""
NTSTATUS NtUserGetThreadState(void)
{
    mov eax, 0x1002
    syscall
}
""",
        ),
    )

    assert result.syscall_count == 1
    stub = result.stubs[0]
    assert stub.user_stub_symbol == "NtUserGetThreadState"
    assert stub.syscall_number == 0x1002
    assert stub.service_table == "win32k"
    assert stub.dispatch_kind == "text_syscall"
    assert "win32k_syscall_names" in result.coverage


def test_windows_syscall_stub_atlas_extracts_raw_x64_stub_bytes(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            user_stub_module="ntdll.dll",
            raw_base_offset=0x180001000,
            raw_bytes_hex=(
                "4c 8b d1 b8 36 00 00 00 "
                "f6 04 25 08 03 fe 7f 01 "
                "75 03 0f 05 c3 cd 2e c3"
            ),
        ),
    )

    assert result.syscall_count == 1
    stub = result.stubs[0]
    assert stub.syscall_number == 0x36
    assert stub.syscall_hex == "0x36"
    assert stub.service_table == "native"
    assert stub.byte_offset == 0x180001000
    assert stub.user_stub_symbol == "sub_180001000"
    assert stub.byte_pattern is not None
    assert "4c 8b d1 b8 36 00 00 00" in stub.byte_pattern
    assert "cd 2e c3" in stub.byte_pattern
    assert stub.dispatch_kind == "x64_syscall_int2e_fallback"
    assert stub.stub_shape == "x64_mov_r10_mov_eax_kuser_gate_syscall_int2e"
    assert stub.has_kuser_shared_data_gate is True
    assert stub.has_int2e_fallback is True
    assert "kuser_shared_data_syscall_gate" in result.coverage
    assert "int2e_fallback" in result.coverage
    assert "native_syscall_numbers" in result.coverage


def test_windows_syscall_stub_atlas_scans_named_pe_exports(
    tmp_path: Path,
) -> None:
    binary = _write_pe_with_exported_syscall_stub(tmp_path)
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(binary_path=str(binary), add_to_kb=True),
    )

    assert result.syscall_count == 1
    stub = result.stubs[0]
    assert stub.user_stub_symbol == "NtQuerySystemInformation"
    assert stub.syscall_number == 0x36
    assert stub.rva == 0x1000
    assert stub.va == 0x180001000
    assert stub.file_offset == 0x200
    assert stub.section_name == ".text"
    assert stub.byte_pattern == "4c 8b d1 b8 36 00 00 00 0f 05 c3"
    assert stub.dispatch_kind == "x64_syscall"
    assert stub.stub_shape == "x64_mov_r10_mov_eax_syscall"
    assert stub.has_kuser_shared_data_gate is False
    assert stub.has_int2e_fallback is False
    assert "pe_syscall_stub_bytes" in result.coverage
    assert "export_named_syscall_stubs" in result.coverage
    assert "native_syscall_names" in result.coverage
    assert result.evidence_node_id is not None


def test_windows_syscall_stub_atlas_scans_real_ntdll_fixture(
    tmp_path: Path,
) -> None:
    if not FIXTURE_NTDLL.exists():
        pytest.skip("ntdll fixture missing")
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(binary_path=str(FIXTURE_NTDLL), max_stubs=4096),
    )

    by_name = {stub.user_stub_symbol: stub for stub in result.stubs}
    assert result.syscall_count >= 500
    assert by_name["NtQuerySystemInformation"].syscall_number == 54
    assert by_name["NtQuerySystemInformation"].syscall_hex == "0x36"
    assert by_name["NtQuerySystemInformationEx"].syscall_number == 364
    assert by_name["NtQuerySystemInformationEx"].syscall_hex == "0x16c"
    assert by_name["NtQuerySystemInformation"].va is not None
    assert by_name["NtQuerySystemInformation"].file_offset is not None
    assert "pe_syscall_stub_bytes" in result.coverage
    assert "export_named_syscall_stubs" in result.coverage
    assert "native_syscall_numbers" in result.coverage


def test_windows_syscall_stub_atlas_raw_bytes_rejects_mov_without_syscall(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(raw_bytes_hex="4c 8b d1 b8 36 00 00 00 c3"),
    )

    assert result.syscall_count == 0
    assert result.missing_capabilities == ["syscall_stubs"]


def test_windows_syscall_stub_atlas_reports_missing_without_stubs(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(pseudocode="fn Helper { return; }"),
    )

    assert result.syscall_count == 0
    assert result.coverage == []
    assert result.missing_capabilities == ["syscall_stubs"]


def test_memory_agent_registers_windows_syscall_stub_atlas() -> None:
    agent = create_memory_agent(model="test")

    assert "windows_syscall_stub_atlas" in agent._function_toolset.tools
