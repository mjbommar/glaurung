from __future__ import annotations

from pathlib import Path

import glaurung as g

from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.tools.windows_function_arg_roles import build_tool


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
    - index: 2
      role: length
    - index: 3
      role: return_length
""",
        encoding="utf-8",
    )
    return sources


def test_windows_function_arg_roles_joins_source_metadata_and_prototype(
    tmp_path: Path,
) -> None:
    sources = _write_sources(tmp_path)
    tool = build_tool()
    ctx = _ctx(tmp_path)

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            function_name="NtQuerySystemInformation",
            sources_path=str(sources),
            c_prototype=(
                "NTSTATUS NtQuerySystemInformation("
                "SYSTEM_INFORMATION_CLASS SystemInformationClass, "
                "PVOID SystemInformation, ULONG SystemInformationLength, "
                "PULONG ReturnLength);"
            ),
        ),
    )

    assert result.confidence == 0.85
    assert result.source_matches[0].source_id == "nt_query_system_information"
    assert result.source_matches[0].attacker_class == "windows-local-user"
    assert [role.role for role in result.combined_roles] == [
        "selector",
        "inout_buffer",
        "length",
        "return_length",
    ]
    assert {role.provenance for role in result.combined_roles} == {
        "asb_pe_source_metadata"
    }


def test_windows_function_arg_roles_falls_back_to_prototype_heuristics(
    tmp_path: Path,
) -> None:
    sources = _write_sources(tmp_path)
    tool = build_tool()
    ctx = _ctx(tmp_path)

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            function_name="CustomDispatch",
            sources_path=str(sources),
            c_prototype=(
                "NTSTATUS CustomDispatch(HANDLE FileHandle, ULONG IoControlCode, "
                "PVOID InputBuffer, ULONG InputBufferLength, ULONG Flags);"
            ),
        ),
    )

    assert result.source_matches == []
    assert result.confidence == 0.45
    assert "no ASB source metadata matched the function name" in result.notes
    assert [(role.index, role.role) for role in result.combined_roles] == [
        (0, "handle"),
        (1, "selector"),
        (2, "buffer"),
        (3, "length"),
        (4, "flags"),
    ]
    assert {role.provenance for role in result.combined_roles} == {
        "prototype_heuristic"
    }


def test_memory_agent_registers_windows_function_arg_roles() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "windows_function_arg_roles" in agent._function_toolset.tools
