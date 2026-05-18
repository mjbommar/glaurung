from __future__ import annotations

from pathlib import Path

import glaurung as g

from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind
from glaurung.llm.tools import windows_enumerate_entrypoints as entrypoints_tool


def _ctx(tmp_path: Path) -> MemoryContext:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"MZ")
    artifact = g.triage.analyze_bytes(b"MZ")
    ctx = MemoryContext(file_path=str(path), artifact=artifact)
    import_triage(ctx.kb, artifact, str(path))
    return ctx


def _write_sources(tmp_path: Path) -> Path:
    sources = tmp_path / "pe-sources.yaml"
    sources.write_text(
        """
- id: nt_query_system_information
  surface: syscall
  symbols: [NtQuerySystemInformation, ZwQuerySystemInformation]
  attacker_class: windows-local-user
  roles:
    - index: 0
      role: selector
    - index: 1
      role: inout_buffer
      paired_length: 2
      selector: 0
- id: irp_device_control_buffers
  surface: ioctl
  symbols: [IRP_MJ_DEVICE_CONTROL]
  attacker_class: windows-local-user
  roles:
    - expression: IoStack->Parameters.DeviceIoControl.IoControlCode
      role: selector
""",
        encoding="utf-8",
    )
    return sources


class _SymbolSummary:
    import_names = ["ntdll.dll!NtQuerySystemInformation"]
    export_names = ["DriverEntry"]
    demangled_import_names = []
    demangled_export_names = []
    names = []


def test_windows_enumerate_entrypoints_joins_binary_symbol_evidence(
    monkeypatch,
    tmp_path: Path,
) -> None:
    sources = _write_sources(tmp_path)
    ctx = _ctx(tmp_path)
    tool = entrypoints_tool.build_tool()
    monkeypatch.setattr(
        entrypoints_tool.g.symbols,
        "list_symbols_demangled",
        lambda *args: _SymbolSummary(),
    )
    monkeypatch.setattr(
        entrypoints_tool.g.symbols,
        "symbol_address_map",
        lambda *args: [(0x14001000, "NtQuerySystemInformation")],
        raising=False,
    )

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            sources_path=str(sources),
            surfaces=["syscall"],
            add_to_kb=True,
        ),
    )

    assert result.source_count_total == 2
    assert result.present_count == 1
    assert [entry.symbol for entry in result.entrypoints] == [
        "NtQuerySystemInformation",
        "ZwQuerySystemInformation",
    ]
    present = result.entrypoints[0]
    assert present.present_in_binary is True
    assert present.va == 0x14001000
    assert present.symbol_evidence[0].name == "ntdll.dll!NtQuerySystemInformation"
    assert "binary_symbol_table" in present.provenance
    assert present.roles[1].role == "inout_buffer"
    assert result.evidence_node_id is not None
    assert any(
        node.kind == NodeKind.evidence and node.label == "windows_enumerate_entrypoints"
        for node in ctx.kb.nodes()
    )


def test_windows_enumerate_entrypoints_can_return_present_only(
    monkeypatch,
    tmp_path: Path,
) -> None:
    sources = _write_sources(tmp_path)
    ctx = _ctx(tmp_path)
    tool = entrypoints_tool.build_tool()
    monkeypatch.setattr(
        entrypoints_tool.g.symbols,
        "list_symbols_demangled",
        lambda *args: _SymbolSummary(),
    )
    monkeypatch.setattr(
        entrypoints_tool.g.symbols,
        "symbol_address_map",
        lambda *args: [(0x14001000, "NtQuerySystemInformation")],
        raising=False,
    )

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            sources_path=str(sources),
            surfaces=["syscall"],
            include_absent=False,
        ),
    )

    assert [entry.symbol for entry in result.entrypoints] == [
        "NtQuerySystemInformation"
    ]
    assert result.present_count == 1


def test_memory_agent_registers_windows_enumerate_entrypoints() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "windows_enumerate_entrypoints" in agent._function_toolset.tools
