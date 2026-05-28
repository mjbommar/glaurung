from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

import glaurung as g

from glaurung.cli.main import GlaurungCLI
from glaurung.llm.agents.memory_agent import create_memory_agent
from glaurung.llm.agents.windows_patch_diff_review import (
    WindowsPatchDiffReviewConfig,
    run_windows_patch_diff_review,
)
from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind
from glaurung.llm.tools.windows_function_similarity_manifest import build_tool
from glaurung.llm.tools.windows_patch_function_identity_extract import (
    build_tool as build_identity_extract_tool,
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


def test_windows_function_similarity_manifest_feeds_patch_identity(
    tmp_path: Path,
) -> None:
    a = _need(_SWITCHY_V1)
    b = _need(_SWITCHY_V2)
    ctx = _ctx(tmp_path)
    tool = build_tool()
    similarity_path = tmp_path / "glaurung-similarity.yaml"

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            binary_a=str(a),
            binary_b=str(b),
            output_path=str(similarity_path),
            min_similarity_score=0.1,
            add_to_kb=True,
        ),
    )

    assert result.similarity_record_count >= 1
    assert result.output_path == str(similarity_path)
    assert "function_similarity_manifest" in result.coverage
    assert "opcode_ngram_similarity" in result.coverage
    by_function = {item.function: item for item in result.similarities}
    assert "dispatch" in by_function
    dispatch = by_function["dispatch"]
    assert dispatch.matched_function == "dispatch"
    assert dispatch.status == "changed"
    assert dispatch.similarity_algorithm == "glaurung_opcode_3gram"
    assert 0.0 < dispatch.similarity_score <= 1.0
    assert dispatch.opcode_ngram_jaccard is not None
    payload = yaml.safe_load(similarity_path.read_text(encoding="utf-8"))
    assert isinstance(payload["similarities"], list)
    assert any(row["function"] == "dispatch" for row in payload["similarities"])
    assert result.evidence_node_id is not None
    assert any(
        node.kind == NodeKind.evidence
        and node.label == "windows_function_similarity_manifest"
        for node in ctx.kb.nodes()
    )

    identity_path = tmp_path / "function-identities.yaml"
    identity_tool = build_identity_extract_tool()
    identity = identity_tool.run(
        ctx,
        ctx.kb,
        identity_tool.input_model(
            binary_a=str(a),
            binary_b=str(b),
            external_similarity_manifest_path=str(similarity_path),
            identity_output_path=str(identity_path),
            min_similarity_score=0.1,
        ),
    )
    dispatch_identity = next(
        item for item in identity.identities if item.function == "dispatch"
    )
    assert dispatch_identity.match_basis == "similarity_backed"
    assert dispatch_identity.similarity_algorithm == "glaurung_opcode_3gram"
    review = run_windows_patch_diff_review(
        WindowsPatchDiffReviewConfig(
            binary_a=str(a),
            binary_b=str(b),
            function_identity_path=str(identity_path),
            max_items=10,
        )
    )
    dispatch_item = next(
        item for item in review.review_items if item.function == "dispatch"
    )
    assert "similarity_algorithm:glaurung_opcode_3gram" in dispatch_item.match_basis


def test_memory_agent_registers_windows_function_similarity_manifest() -> None:
    agent = create_memory_agent(model="test")

    assert "windows_function_similarity_manifest" in agent._function_toolset.tools


def test_windows_function_similarity_manifest_cli_json(
    tmp_path: Path,
    capsys,
) -> None:
    a = _need(_SWITCHY_V1)
    b = _need(_SWITCHY_V2)
    output_path = tmp_path / "glaurung-similarity.yaml"

    rc = GlaurungCLI().run(
        [
            "windows",
            "function-similarity-manifest",
            "--binary-a",
            str(a),
            "--binary-b",
            str(b),
            "--output-path",
            str(output_path),
            "--min-similarity-score",
            "0.1",
            "--format",
            "json",
        ]
    )

    assert rc == 0
    output = json.loads(capsys.readouterr().out)
    assert output["similarity_record_count"] >= 1
    assert output["output_path"] == str(output_path)
    assert any(item["function"] == "dispatch" for item in output["similarities"])
