from __future__ import annotations

from pathlib import Path

import pytest
import yaml

import glaurung as g
from glaurung.llm.agents.windows_patch_diff_review import (
    WindowsPatchDiffReviewConfig,
    run_windows_patch_diff_review,
)
from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind
from glaurung.llm.tools.windows_patch_function_identity_extract import build_tool
from glaurung.llm.tools.windows_pdb_identity_manifest import (
    WindowsPdbIdentityManifestArgs,
)


_SWITCHY_V1 = Path("samples/binaries/platforms/linux/amd64/synthetic/switchy-c-gcc-O2")
_SWITCHY_V2 = Path(
    "samples/binaries/platforms/linux/amd64/synthetic/switchy-c-gcc-O2-v2"
)


def _need(path: Path) -> Path:
    if not path.exists():
        pytest.skip(f"missing path {path}")
    return path


def _ctx(tmp_path: Path) -> MemoryContext:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"MZ")
    artifact = g.triage.analyze_bytes(b"MZ")
    ctx = MemoryContext(file_path=str(path), artifact=artifact)
    import_triage(ctx.kb, artifact, str(path))
    return ctx


def _write_pdb_identity_manifest(tmp_path: Path) -> Path:
    manifest = tmp_path / "pe-identity-manifest.yaml"
    manifest.write_text(
        """
- id: switchy_v2_pdb
  target_id: switchy
  build_label: unit-v2
  build_number: "2"
  architecture: x64
  binary_filename: switchy-c-gcc-O2-v2
  expected_pdb_name: switchy.pdb
  codeview_guid_age: ABCDEF0123456789ABCDEF0123456789:1
  cache_status: cached
  symbol_cache_path: /symbols/switchy.pdb/ABCDEF0123456789ABCDEF01234567891/switchy.pdb
  identity_sources: [codeview, public_symbol_cache]
  fact_coverage: [cached_pdb, pdb_symbols]
  missing_facts: [pdb_type_layouts]
""",
        encoding="utf-8",
    )
    return manifest


def test_windows_patch_function_identity_extract_writes_review_manifest(
    tmp_path: Path,
) -> None:
    a = _need(_SWITCHY_V1)
    b = _need(_SWITCHY_V2)
    ctx = _ctx(tmp_path)
    tool = build_tool()
    output_path = tmp_path / "function-identities.yaml"

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            binary_a=str(a),
            binary_b=str(b),
            pdb_identity_manifest=WindowsPdbIdentityManifestArgs(
                identity_path=str(_write_pdb_identity_manifest(tmp_path)),
                target_id="switchy",
                binary_filename=b.name,
                cache_status="cached",
            ),
            identity_output_path=str(output_path),
            add_to_kb=True,
        ),
    )

    assert result.identity_count >= 1
    assert result.pdb_identity_record_count == 1
    assert result.identity_output_path == str(output_path)
    identities = yaml.safe_load(output_path.read_text(encoding="utf-8"))
    assert isinstance(identities, list)
    assert identities
    assert any(identity["function"] == "dispatch" for identity in identities)
    dispatch = next(
        identity for identity in identities if identity["function"] == "dispatch"
    )
    assert dispatch["match_basis"] == "pdb_backed"
    assert dispatch["similarity_algorithm"] == "size_ratio_body_hash"
    assert "windows_pdb_identity_manifest" in dispatch["evidence"]
    review = run_windows_patch_diff_review(
        WindowsPatchDiffReviewConfig(
            binary_a=str(a),
            binary_b=str(b),
            function_identity_path=str(output_path),
            max_items=10,
        )
    )
    assert "windows_patch_function_identity_manifest" in review.tool_sequence
    dispatch_items = [
        item for item in review.review_items if item.function == "dispatch"
    ]
    assert dispatch_items
    assert "pdb_backed_identity" in dispatch_items[0].match_basis
    assert "similarity_algorithm:size_ratio_body_hash" in dispatch_items[0].match_basis
    assert result.evidence_node_id is not None
    assert any(
        node.kind == NodeKind.evidence
        and node.label == "windows_patch_function_identity_extract"
        for node in ctx.kb.nodes()
    )


def test_windows_patch_function_identity_extract_uses_external_similarity_manifest(
    tmp_path: Path,
) -> None:
    a = _need(_SWITCHY_V1)
    b = _need(_SWITCHY_V2)
    ctx = _ctx(tmp_path)
    tool = build_tool()
    similarity_manifest = tmp_path / "bsim-similarity.yaml"
    similarity_manifest.write_text(
        """
similarities:
- function: dispatch
  matched_function: dispatch
  similarity_score: 0.99
  similarity_algorithm: ghidra_bsim_export
  evidence:
  - bsim-cache:unit
""",
        encoding="utf-8",
    )
    output_path = tmp_path / "function-identities.yaml"

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            binary_a=str(a),
            binary_b=str(b),
            external_similarity_manifest_path=str(similarity_manifest),
            min_similarity_score=0.9,
            identity_output_path=str(output_path),
        ),
    )

    assert result.external_similarity_record_count == 1
    assert result.external_similarity_manifest_path == str(similarity_manifest)
    identities = yaml.safe_load(output_path.read_text(encoding="utf-8"))
    dispatch = next(
        identity for identity in identities if identity["function"] == "dispatch"
    )
    assert dispatch["match_basis"] == "similarity_backed"
    assert dispatch["similarity_score"] == 0.99
    assert dispatch["similarity_algorithm"] == "ghidra_bsim_export"
    assert "external_similarity_manifest" in dispatch["evidence"]
    assert "similarity_algorithm:ghidra_bsim_export" in dispatch["evidence"]
    review = run_windows_patch_diff_review(
        WindowsPatchDiffReviewConfig(
            binary_a=str(a),
            binary_b=str(b),
            function_identity_path=str(output_path),
            max_items=10,
        )
    )
    dispatch_item = next(
        item for item in review.review_items if item.function == "dispatch"
    )
    assert "similarity_algorithm:ghidra_bsim_export" in dispatch_item.match_basis


def test_memory_agent_registers_windows_patch_function_identity_extract() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "windows_patch_function_identity_extract" in agent._function_toolset.tools
