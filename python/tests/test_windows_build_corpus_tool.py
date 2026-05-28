from __future__ import annotations

from pathlib import Path

import glaurung as g

from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind
from glaurung.llm.tools.windows_build_corpus import build_tool


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
- id: ntoskrnl
  filename: ntoskrnl.exe
  binary_kind: kernel
  priority: critical
  scan_roles: [syscall_dispatch, object_lifecycle]
  surfaces: [syscall, ioctl]
  architectures: [x64]
  corpus_globs: ["windows-11-x64/**/ntoskrnl.exe"]
  project_globs: ["**/ntoskrnl*.glaurung"]
  notes: Core kernel target.
- id: tcpip
  filename: tcpip.sys
  binary_kind: driver
  priority: critical
  scan_roles: [network_parser, timer_callback]
  surfaces: [network, local_socket]
  architectures: [x64]
  corpus_globs: ["windows-11-x64/**/tcpip.sys"]
  project_globs: ["**/tcpip*.glaurung"]
  notes: Network stack target.
""",
        encoding="utf-8",
    )
    return manifest


def _write_corpus(tmp_path: Path) -> tuple[Path, Path]:
    corpus_root = tmp_path / "corpus"
    nt_path = corpus_root / "windows-11-x64" / "26100" / "System32" / "ntoskrnl.exe"
    tcp_path = (
        corpus_root
        / "windows-11-x64"
        / "26100"
        / "System32"
        / "drivers"
        / "tcpip.sys"
    )
    nt_path.parent.mkdir(parents=True)
    tcp_path.parent.mkdir(parents=True)
    nt_path.write_bytes(b"MZnt")
    tcp_path.write_bytes(b"MZtcp")

    project_root = tmp_path / "projects"
    project_root.mkdir()
    (project_root / "ntoskrnl-26100.glaurung").write_bytes(b"sqlite")
    return corpus_root, project_root


def test_windows_build_corpus_filters_and_resolves_paths(tmp_path: Path) -> None:
    manifest = _write_manifest(tmp_path)
    corpus_root, project_root = _write_corpus(tmp_path)
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            manifest_path=str(manifest),
            corpus_root=str(corpus_root),
            project_root=str(project_root),
            surface="syscall",
        ),
    )

    assert result.target_count_total == 2
    assert [target.id for target in result.targets] == ["ntoskrnl"]
    target = result.targets[0]
    assert target.filename == "ntoskrnl.exe"
    assert target.corpus_matches[0].relative_path.endswith("ntoskrnl.exe")
    assert target.corpus_matches[0].size_bytes == 4
    assert target.project_matches[0].relative_path == "ntoskrnl-26100.glaurung"
    assert "scan-target manifest" in result.notes[0]


def test_windows_build_corpus_can_add_evidence_node(tmp_path: Path) -> None:
    manifest = _write_manifest(tmp_path)
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            manifest_path=str(manifest),
            filename="tcpip.sys",
            add_to_kb=True,
        ),
    )

    assert [target.id for target in result.targets] == ["tcpip"]
    assert result.evidence_node_id is not None
    assert any(
        node.kind == NodeKind.evidence and node.label == "windows_build_corpus"
        for node in ctx.kb.nodes()
    )


def test_memory_agent_registers_windows_build_corpus() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "windows_build_corpus" in agent._function_toolset.tools
