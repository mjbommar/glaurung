from __future__ import annotations

from pathlib import Path

import glaurung as g

from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind
from glaurung.llm.tools.windows_target_surface_profile import build_tool


def _ctx(tmp_path: Path) -> MemoryContext:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"MZ")
    artifact = g.triage.analyze_bytes(b"MZ")
    ctx = MemoryContext(file_path=str(path), artifact=artifact)
    import_triage(ctx.kb, artifact, str(path))
    return ctx


def _write_manifest(tmp_path: Path) -> Path:
    manifest = tmp_path / "pe-build-corpus.yaml"
    manifest.write_text(
        """
- id: cldflt
  filename: cldflt.sys
  binary_kind: driver
  priority: critical
  scan_roles: [cloud_filter_driver, placeholder_lifecycle]
  surfaces: [cloud_filter, file_system_filter, local_file, registry]
  architectures: [x64]
  corpus_globs: ["windows-11-x64/**/cldflt.sys"]
  project_globs: ["**/cldflt*.glaurung"]
  notes: Cloud Files minifilter target.
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
    return manifest


def _write_surfaces(tmp_path: Path) -> Path:
    surfaces = tmp_path / "pe-surfaces.yaml"
    surfaces.write_text(
        """
- id: cloud_filter
  boundary: cloud_file_provider
  attacker_classes: [windows-local-user, windows-appcontainer]
  validation_requirements: [cloud_filter_registration, placeholder_or_reparse_point_control]
  ranking_weight: 87
  notes: Cloud Files placeholder surface.
- id: file_system_filter
  boundary: file_system_filter
  attacker_classes: [windows-local-user, windows-admin-or-service]
  validation_requirements: [filter_manager_registration, callback_operation_class]
  ranking_weight: 83
  notes: Minifilter callback surface.
- id: local_file
  boundary: file_parser
  attacker_classes: [windows-local-user]
  validation_requirements: [file_open_path, file_acl]
  ranking_weight: 72
- id: registry
  boundary: registry
  attacker_classes: [windows-local-user, windows-admin-or-service]
  validation_requirements: [key_acl, value_type_and_length]
  ranking_weight: 62
- id: network
  boundary: remote_network
  attacker_classes: [windows-network]
  validation_requirements: [listening_service_or_protocol]
  ranking_weight: 100
""",
        encoding="utf-8",
    )
    return surfaces


def test_windows_target_surface_profile_joins_target_surfaces(tmp_path: Path) -> None:
    manifest = _write_manifest(tmp_path)
    surfaces = _write_surfaces(tmp_path)
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            manifest_path=str(manifest),
            surfaces_path=str(surfaces),
            filename="cldflt.sys",
        ),
    )

    assert result.target_count_total == 2
    assert result.surface_count_total == 5
    assert [profile.target_id for profile in result.profiles] == ["cldflt"]
    profile = result.profiles[0]
    assert profile.max_ranking_weight == 87
    assert "windows-appcontainer" in profile.attacker_classes
    assert "placeholder_or_reparse_point_control" in profile.validation_requirements
    assert [surface.id for surface in profile.surfaces][:2] == [
        "cloud_filter",
        "file_system_filter",
    ]
    assert "prioritization context" in result.notes[0]


def test_windows_target_surface_profile_filters_and_adds_evidence(
    tmp_path: Path,
) -> None:
    manifest = _write_manifest(tmp_path)
    surfaces = _write_surfaces(tmp_path)
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            manifest_path=str(manifest),
            surfaces_path=str(surfaces),
            surface_id="network",
            min_ranking_weight=95,
            add_to_kb=True,
        ),
    )

    assert [profile.target_id for profile in result.profiles] == ["tcpip"]
    assert result.profiles[0].max_ranking_weight == 100
    assert result.evidence_node_id is not None
    assert any(
        node.kind == NodeKind.evidence
        and node.label == "windows_target_surface_profile"
        for node in ctx.kb.nodes()
    )


def test_memory_agent_registers_windows_target_surface_profile() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "windows_target_surface_profile" in agent._function_toolset.tools
