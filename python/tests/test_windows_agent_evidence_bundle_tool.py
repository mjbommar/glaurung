from __future__ import annotations

from pathlib import Path

import glaurung as g

from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind
from glaurung.llm.tools.windows_agent_evidence_bundle import (
    WindowsEvidenceCoverage,
    WindowsEvidenceReference,
    WindowsEvidenceSubject,
    build_tool,
)


def _ctx(tmp_path: Path) -> MemoryContext:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"MZ")
    artifact = g.triage.analyze_bytes(b"MZ")
    ctx = MemoryContext(file_path=str(path), artifact=artifact)
    import_triage(ctx.kb, artifact, str(path))
    return ctx


def test_windows_agent_evidence_bundle_normalizes_addresses_and_adds_kb(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            claim_level="functionization_review_not_vulnerability",
            subject=WindowsEvidenceSubject(
                kind="functionization",
                file="win11-webservices.dll",
                va=0x180009440,
            ),
            source_tools=["windows_function_start_explain"],
            evidence_refs=[
                WindowsEvidenceReference(
                    kind="address",
                    source="windows_function_start_explain",
                    summary="jmp rel32 thunk candidate",
                    address=0x180009440,
                    reason_codes=["jmp_rel32", "ghidra_only"],
                    provenance=["regression-diagnostics"],
                )
            ],
            coverage=WindowsEvidenceCoverage(
                ghidra_missing_entries=1041,
                ghidra_extra_entries=3116,
            ),
            blockers=["address-level review still required"],
            add_to_kb=True,
        ),
    )

    bundle = result.bundle
    assert bundle.bundle_id.startswith("win-evidence-")
    assert bundle.claim_level == "functionization_review_not_vulnerability"
    assert bundle.subject.va_hex == "0x180009440"
    assert bundle.evidence_refs[0].address_hex == "0x180009440"
    assert bundle.coverage.ghidra_missing_entries == 1041
    assert result.evidence_node_id is not None
    assert any(
        node.kind == NodeKind.evidence and node.label == "windows_agent_evidence_bundle"
        for node in ctx.kb.nodes()
    )


def test_memory_agent_registers_windows_agent_evidence_bundle() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "windows_agent_evidence_bundle" in agent._function_toolset.tools
