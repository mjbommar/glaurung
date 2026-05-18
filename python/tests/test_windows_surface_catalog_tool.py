from __future__ import annotations

from pathlib import Path

import glaurung as g

from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind
from glaurung.llm.tools.windows_surface_catalog import build_tool


def _ctx(tmp_path: Path) -> MemoryContext:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"MZ")
    artifact = g.triage.analyze_bytes(b"MZ")
    ctx = MemoryContext(file_path=str(path), artifact=artifact)
    import_triage(ctx.kb, artifact, str(path))
    return ctx


def _write_surfaces(tmp_path: Path) -> Path:
    surfaces = tmp_path / "pe-surfaces.yaml"
    surfaces.write_text(
        """
- id: syscall
  boundary: user_kernel
  attacker_classes: [windows-local-user]
  validation_requirements: [syscall_table_membership, argument_roles]
  ranking_weight: 90
  notes: Native syscall boundary.
- id: network
  boundary: remote_network
  attacker_classes: [windows-network]
  validation_requirements: [listening_service_or_protocol, packet_field_roles]
  ranking_weight: 100
  notes: Remote parser boundary.
- id: ioctl
  boundary: device_control
  attacker_classes: [windows-local-user, windows-appcontainer]
  validation_requirements: [device_object_acl, ioctl_access_bits]
  ranking_weight: 85
  notes: Device control boundary.
""",
        encoding="utf-8",
    )
    return surfaces


def _write_sources(tmp_path: Path) -> Path:
    sources = tmp_path / "pe-sources.yaml"
    sources.write_text(
        """
- id: nt_query_system_information
  surface: syscall
  symbols: [NtQuerySystemInformation]
  attacker_class: windows-local-user
  roles:
    - index: 0
      role: selector
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


def _write_build_corpus(tmp_path: Path) -> Path:
    corpus = tmp_path / "pe-build-corpus.yaml"
    corpus.write_text(
        """
- id: ntoskrnl
  filename: ntoskrnl.exe
  binary_kind: kernel
  priority: critical
  scan_roles: [syscall_dispatch]
  surfaces: [syscall, ioctl]
  architectures: [x64]
  corpus_globs: ["windows-11-x64/**/ntoskrnl.exe"]
  project_globs: ["**/ntoskrnl*.glaurung"]
- id: tcpip
  filename: tcpip.sys
  binary_kind: driver
  priority: critical
  scan_roles: [network_parser]
  surfaces: [network]
  architectures: [x64]
  corpus_globs: ["windows-11-x64/**/tcpip.sys"]
  project_globs: ["**/tcpip*.glaurung"]
""",
        encoding="utf-8",
    )
    return corpus


def test_windows_surface_catalog_filters_and_joins_references(tmp_path: Path) -> None:
    surfaces = _write_surfaces(tmp_path)
    sources = _write_sources(tmp_path)
    corpus = _write_build_corpus(tmp_path)
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            surfaces_path=str(surfaces),
            sources_path=str(sources),
            build_corpus_path=str(corpus),
            attacker_class="windows-local-user",
        ),
    )

    assert result.surface_count_total == 3
    assert [surface.id for surface in result.surfaces] == ["syscall", "ioctl"]
    syscall = result.surfaces[0]
    assert syscall.boundary == "user_kernel"
    assert {ref.kind for ref in syscall.references} == {
        "source",
        "build_corpus_target",
    }
    assert any(ref.id == "nt_query_system_information" for ref in syscall.references)
    assert any(ref.symbols_or_filename == ["ntoskrnl.exe"] for ref in syscall.references)
    assert "not per-function proof" in result.notes[0]


def test_windows_surface_catalog_can_add_evidence_node(tmp_path: Path) -> None:
    surfaces = _write_surfaces(tmp_path)
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            surfaces_path=str(surfaces),
            surface_id="network",
            min_ranking_weight=95,
            add_to_kb=True,
        ),
    )

    assert [surface.id for surface in result.surfaces] == ["network"]
    assert result.evidence_node_id is not None
    assert any(
        node.kind == NodeKind.evidence and node.label == "windows_surface_catalog"
        for node in ctx.kb.nodes()
    )


def test_memory_agent_registers_windows_surface_catalog() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "windows_surface_catalog" in agent._function_toolset.tools
