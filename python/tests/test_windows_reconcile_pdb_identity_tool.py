from __future__ import annotations

import struct
from pathlib import Path

import glaurung as g

from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind
from glaurung.llm.tools.windows_reconcile_pdb_identity import build_tool


GUID_RAW = bytes.fromhex("33221100554477668899aabbccddeeff")
GUID_TEXT = "00112233445566778899AABBCCDDEEFF"


def _ctx(tmp_path: Path) -> MemoryContext:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"MZ")
    artifact = g.triage.analyze_bytes(b"MZ")
    ctx = MemoryContext(file_path=str(path), artifact=artifact)
    import_triage(ctx.kb, artifact, str(path))
    return ctx


def _write_pe_with_rsds(tmp_path: Path, pdb_path: str = r"C:\symbols\sample.pdb") -> Path:
    pe = tmp_path / "sample.sys"
    pe.write_bytes(b"MZ" + b"\x00" * 32 + b"RSDS" + GUID_RAW + struct.pack("<I", 1) + pdb_path.encode() + b"\x00")
    return pe


def _write_manifest(tmp_path: Path, guid_age: str = f"{GUID_TEXT}1") -> Path:
    manifest = tmp_path / "pe-identity-manifest.yaml"
    manifest.write_text(
        f"""
- id: win11_ltsc_sample
  target_id: sample
  build_label: win11-ltsc-v4
  build_number: "26100.1742"
  architecture: x64
  binary_filename: sample.sys
  expected_pdb_name: sample.pdb
  codeview_guid_age: {guid_age}
  cache_status: cached
  symbol_cache_path: /cache/sample.pdb/{guid_age}/sample.pdb
  identity_sources: [unit_test]
  fact_coverage: [pdb_public_symbols]
  missing_facts: [pdb_type_layouts]
""",
        encoding="utf-8",
    )
    return manifest


def test_windows_reconcile_pdb_identity_matches_manifest_and_cache(
    tmp_path: Path,
) -> None:
    pe = _write_pe_with_rsds(tmp_path)
    cache = tmp_path / "cache"
    pdb = cache / "sample.pdb" / f"{GUID_TEXT}1" / "sample.pdb"
    pdb.parent.mkdir(parents=True)
    pdb.write_bytes(b"not a real pdb")
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            pe_path=str(pe),
            pdb_cache_dir=str(cache),
            identity_path=str(_write_manifest(tmp_path)),
            target_id="sample",
            analyze_types=False,
            add_to_kb=True,
        ),
    )

    assert result.codeview is not None
    assert result.codeview.pdb_name == "sample.pdb"
    assert result.codeview.pdb_guid_age == f"{GUID_TEXT}1"
    assert result.cache.cache_status == "cached"
    assert result.cache.resolved_pdb_path == str(pdb)
    assert result.manifest.status == "match"
    assert result.manifest.record is not None
    assert result.evidence_node_id is not None
    assert any(
        node.kind == NodeKind.evidence
        and node.label == "windows_reconcile_pdb_identity"
        for node in ctx.kb.nodes()
    )


def test_windows_reconcile_pdb_identity_reports_manifest_drift(
    tmp_path: Path,
) -> None:
    pe = _write_pe_with_rsds(tmp_path)
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            pe_path=str(pe),
            identity_path=str(_write_manifest(tmp_path, guid_age="DEADBEEF1")),
            target_id="sample",
            analyze_types=False,
        ),
    )

    assert result.manifest.status == "guid_age_mismatch"
    assert any("GUID+age" in issue for issue in result.manifest.issues)
    assert "missing_from_cache" == result.cache.cache_status or result.cache.cache_status == "unknown"


def test_memory_agent_registers_windows_reconcile_pdb_identity() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "windows_reconcile_pdb_identity" in agent._function_toolset.tools
