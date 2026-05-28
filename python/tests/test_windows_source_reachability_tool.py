from __future__ import annotations

from pathlib import Path

import glaurung as g

from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind
from glaurung.llm.tools.windows_source_reachability import build_tool


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
- id: nt_device_io_control_file
  surface: syscall
  symbols: [NtDeviceIoControlFile, ZwDeviceIoControlFile]
  attacker_class: windows-local-user
  roles:
    - index: 0
      role: handle
    - index: 5
      role: selector
    - index: 8
      role: output_buffer
      paired_length: 9
      selector: 5
- id: irp_device_control_buffers
  surface: ioctl
  symbols: [IRP_MJ_DEVICE_CONTROL]
  attacker_class: windows-local-user
  roles:
    - expression: IoStack->Parameters.DeviceIoControl.IoControlCode
      role: selector
    - expression: Irp->UserBuffer
      role: output_buffer
      paired_length: IoStack->Parameters.DeviceIoControl.OutputBufferLength
""",
        encoding="utf-8",
    )
    return sources


def _write_surfaces(tmp_path: Path) -> Path:
    surfaces = tmp_path / "pe-surfaces.yaml"
    surfaces.write_text(
        """
- id: syscall
  boundary: user_kernel
  attacker_classes: [windows-local-user]
  validation_requirements: [syscall_table_membership, argument_roles]
  ranking_weight: 90
- id: ioctl
  boundary: device_control
  attacker_classes: [windows-local-user, windows-appcontainer]
  validation_requirements: [device_object_acl, ioctl_access_bits]
  ranking_weight: 85
""",
        encoding="utf-8",
    )
    return surfaces


def test_windows_source_reachability_joins_surface_context(tmp_path: Path) -> None:
    sources = _write_sources(tmp_path)
    surfaces = _write_surfaces(tmp_path)
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            sources_path=str(sources),
            surfaces_path=str(surfaces),
            symbol="NtDeviceIoControlFile",
        ),
    )

    assert result.source_count_total == 2
    assert result.surface_count_total == 2
    assert [record.source_id for record in result.records] == [
        "nt_device_io_control_file"
    ]
    record = result.records[0]
    assert record.source_surface == "syscall"
    assert record.surface_boundary == "user_kernel"
    assert record.attacker_class_consistent is True
    assert "argument_roles" in record.validation_requirements
    assert {role.role for role in record.roles} >= {"handle", "selector"}
    assert "metadata only" in result.notes[0]


def test_windows_source_reachability_filters_by_surface_attacker_and_adds_evidence(
    tmp_path: Path,
) -> None:
    sources = _write_sources(tmp_path)
    surfaces = _write_surfaces(tmp_path)
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            sources_path=str(sources),
            surfaces_path=str(surfaces),
            surface_id="ioctl",
            attacker_class="windows-appcontainer",
            add_to_kb=True,
        ),
    )

    assert [record.source_id for record in result.records] == [
        "irp_device_control_buffers"
    ]
    assert result.records[0].source_attacker_class == "windows-local-user"
    assert "windows-appcontainer" in result.records[0].surface_attacker_classes
    assert result.evidence_node_id is not None
    assert any(
        node.kind == NodeKind.evidence
        and node.label == "windows_source_reachability"
        for node in ctx.kb.nodes()
    )


def test_windows_source_reachability_reports_unknown_surface(tmp_path: Path) -> None:
    sources = tmp_path / "pe-sources.yaml"
    sources.write_text(
        """
- id: bad_source
  surface: missing_surface
  symbols: [BadSource]
  attacker_class: windows-local-user
  roles:
    - index: 0
      role: selector
""",
        encoding="utf-8",
    )
    surfaces = _write_surfaces(tmp_path)
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(sources_path=str(sources), surfaces_path=str(surfaces)),
    )

    assert result.records[0].attacker_class_consistent is False
    assert "unknown surface" in result.records[0].notes[0]


def test_memory_agent_registers_windows_source_reachability() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "windows_source_reachability" in agent._function_toolset.tools
