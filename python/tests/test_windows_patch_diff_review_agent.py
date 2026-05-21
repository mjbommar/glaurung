from __future__ import annotations

from pathlib import Path

import pytest

from glaurung.llm.agents.windows_patch_diff_review import (
    WindowsPatchFunctionIdentity,
    WindowsPatchDiffReviewConfig,
    run_windows_patch_diff_review,
)
from glaurung.llm.tools.windows_pdb_identity_manifest import (
    WindowsPdbIdentityManifestArgs,
)
from glaurung.llm.kb import xref_db
from glaurung.llm.kb.persistent import PersistentKnowledgeBase


_SWITCHY_V1 = Path("samples/binaries/platforms/linux/amd64/synthetic/switchy-c-gcc-O2")
_SWITCHY_V2 = Path(
    "samples/binaries/platforms/linux/amd64/synthetic/switchy-c-gcc-O2-v2"
)


def _need(path: Path) -> Path:
    if not path.exists():
        pytest.skip(f"missing path {path}")
    return path


def _write_seeds(tmp_path: Path) -> Path:
    seeds = tmp_path / "pe-vulnerability-seeds.yaml"
    seeds.write_text(
        """
- id: dispatch_bounds_seed
  public_ids: [TEST-0001]
  title: Dispatch bounds seed
  target_id: switchy
  component: switchy
  functions: [dispatch, missing_seed_function]
  surfaces: [local_file]
  attacker_classes: [windows-local-user]
  invariant_family: validation
  primitive: selector_dispatch_without_bounds_gate
  source_roles: [selector]
  expected_gates: [selector_bounded]
  expected_sinks: [case_dispatch]
  diff_signals: [added_selector_bounds_check]
  validation_requirements: [prove_selector_reachability]
  references:
    - kind: other
      title: Synthetic seed
      url: https://example.test/seed
""",
        encoding="utf-8",
    )
    return seeds


def _write_metadata(tmp_path: Path) -> tuple[Path, Path]:
    gates = tmp_path / "pe-gates.yaml"
    gates.write_text(
        """
- id: probeforwrite
  symbols: [ProbeForWrite]
  gate_kind: user_pointer
  proves: [user_pointer_write_range_valid]
  required_conditions: [call_dominates_write_sink]
  invalid_when: [length_is_zero]
""",
        encoding="utf-8",
    )
    sinks = tmp_path / "pe-sinks.yaml"
    sinks.write_text(
        """
- id: rtl_copy_memory
  symbols: [RtlCopyMemory, memcpy]
  sink_kind: copy
  effects: [writes_destination_range, reads_source_range]
  arg_roles:
    0: destination_buffer
    1: source_buffer
    2: byte_count
  required_gates: [destination_range_valid, byte_count_bounded]
""",
        encoding="utf-8",
    )
    return gates, sinks


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


def _project(tmp_path: Path, name: str) -> Path:
    binary = tmp_path / f"{name}.sys"
    binary.write_bytes(b"MZ" + b"\0" * 512)
    project = tmp_path / f"{name}.glaurung"
    kb = PersistentKnowledgeBase.open(project, binary_path=binary)
    kb.close()
    return project


def _seed_project_prototypes(before: Path, after: Path) -> None:
    before_kb = PersistentKnowledgeBase.open(before)
    try:
        xref_db.set_function_prototype(
            before_kb,
            "dispatch",
            "NTSTATUS",
            [
                xref_db.FunctionParam("Irp", "PIRP", role="irp"),
                xref_db.FunctionParam("Length", "ULONG", role="length"),
            ],
            calling_convention="NTAPI",
            set_by="manual",
            semantics={"risk_tags": ["ioctl"], "roles": {"Length": "length"}},
        )
    finally:
        before_kb.close()

    after_kb = PersistentKnowledgeBase.open(after)
    try:
        xref_db.set_function_prototype(
            after_kb,
            "dispatch",
            "NTSTATUS",
            [
                xref_db.FunctionParam("Irp", "PIRP", role="irp"),
                xref_db.FunctionParam("OutputBuffer", "PVOID", role="out_buffer"),
                xref_db.FunctionParam("OutputBufferLength", "ULONG", role="length"),
            ],
            calling_convention="NTAPI",
            set_by="manual",
            semantics={
                "risk_tags": ["ioctl", "user_buffer"],
                "roles": {
                    "OutputBuffer": "out_buffer",
                    "OutputBufferLength": "length",
                },
            },
        )
    finally:
        after_kb.close()


def test_windows_patch_diff_review_ranks_seed_changed_function(
    tmp_path: Path,
) -> None:
    a = _need(_SWITCHY_V1)
    b = _need(_SWITCHY_V2)

    result = run_windows_patch_diff_review(
        WindowsPatchDiffReviewConfig(
            binary_a=str(a),
            binary_b=str(b),
            seeds_path=str(_write_seeds(tmp_path)),
            public_id="TEST-0001",
            pdb_backed=True,
            max_items=10,
        )
    )

    assert result.claim_level == "patch_diff_review_not_finding"
    assert result.binary_diff.changed > 0
    assert result.seed_triage is not None
    assert result.seed_triage.matched_seed_count == 1
    top = result.review_items[0]
    assert top.kind == "seed_function_change"
    assert top.function == "dispatch"
    assert "seed_function_name_match" in top.match_basis
    assert "pdb_backed_identity" in top.match_basis
    assert "public_seed_overlap_not_finding" in top.reason_codes
    assert result.evidence_bundle.claim_level == "triage_evidence_bundle_not_finding"
    assert "windows_seed_binary_diff_triage" in result.tool_sequence


def test_windows_patch_diff_review_preserves_low_confidence_with_boundary_blockers(
    tmp_path: Path,
) -> None:
    a = _need(_SWITCHY_V1)
    b = _need(_SWITCHY_V2)
    gates, sinks = _write_metadata(tmp_path)

    result = run_windows_patch_diff_review(
        WindowsPatchDiffReviewConfig(
            binary_a=str(a),
            binary_b=str(b),
            gates_path=str(gates),
            sinks_path=str(sinks),
            before_pseudocode="""
NTSTATUS Handler(void *out, void *src, ULONG len) {
    RtlCopyMemory(out, src, 128);
    return STATUS_SUCCESS;
}
""",
            after_pseudocode="""
NTSTATUS Handler(void *out, void *src, ULONG len) {
    ProbeForWrite(out, len, 1);
    RtlCopyMemory(out, src, 256);
    return STATUS_BUFFER_OVERFLOW;
}
""",
            functionization_blockers=["function_boundary_mismatch"],
            max_items=20,
        )
    )

    security_items = [
        item for item in result.review_items if item.kind == "security_fact_delta"
    ]
    assert security_items
    assert all(item.confidence <= 0.45 for item in result.review_items)
    assert any(
        "function_boundary_mismatch" in item.reason_codes
        for item in result.review_items
    )
    assert result.security_facts is not None
    assert any(delta.fact_kind == "gate" for delta in result.security_facts.deltas)
    assert result.evidence_bundle.blockers == ["function_boundary_mismatch"]


def test_windows_patch_diff_review_uses_per_function_identity_facts() -> None:
    a = _need(_SWITCHY_V1)
    b = _need(_SWITCHY_V2)

    result = run_windows_patch_diff_review(
        WindowsPatchDiffReviewConfig(
            binary_a=str(a),
            binary_b=str(b),
            function_identities=[
                WindowsPatchFunctionIdentity(
                    function="dispatch",
                    match_basis="pdb_backed",
                    pdb_symbol="?dispatch@@YAHH@Z",
                    pdb_guid_age="ABCDEF0123456789ABCDEF0123456789:1",
                    similarity_score=0.94,
                    similarity_algorithm="bsim",
                    evidence=["public PDB match", "BSim high similarity"],
                )
            ],
            max_items=10,
        )
    )

    dispatch_items = [
        item for item in result.review_items if item.function == "dispatch"
    ]
    assert dispatch_items
    item = dispatch_items[0]
    assert "pdb_backed_identity" in item.match_basis
    assert "similarity_backed_function_match" in item.match_basis
    assert "similarity_algorithm:bsim" in item.match_basis
    assert item.confidence >= 0.9
    assert "identity:pdb_backed" in item.reason_codes
    assert "provided_windows_patch_function_identity" in result.tool_sequence
    assert "per_function_patch_identity" in (
        result.evidence_bundle.coverage.fact_coverage
    )


def test_windows_patch_diff_review_ranks_project_prototype_deltas(
    tmp_path: Path,
) -> None:
    a = _need(_SWITCHY_V1)
    b = _need(_SWITCHY_V2)
    before_project = _project(tmp_path, "before")
    after_project = _project(tmp_path, "after")
    _seed_project_prototypes(before_project, after_project)

    result = run_windows_patch_diff_review(
        WindowsPatchDiffReviewConfig(
            binary_a=str(a),
            binary_b=str(b),
            before_project_path=str(before_project),
            after_project_path=str(after_project),
            max_items=20,
        )
    )

    assert result.prototype_diff is not None
    assert result.prototype_diff.changed_count == 1
    assert "windows_project_prototype_diff" in result.tool_sequence
    assert "project_prototype_deltas" in result.evidence_bundle.coverage.fact_coverage
    assert result.evidence_bundle.subject.attributes["prototype_delta_count"] == 1
    proto_items = [
        item
        for item in result.review_items
        if item.kind == "prototype_delta" and item.function == "dispatch"
    ]
    assert proto_items
    item = proto_items[0]
    assert "project_prototype_diff" in item.match_basis
    assert "security_relevant_prototype_delta" in item.match_basis
    assert "parameter_role_delta" in item.reason_codes
    assert "pointer_or_buffer_parameter_delta" in item.reason_codes
    assert item.next_tool == "windows_sink_to_gate_review"


def test_windows_patch_diff_review_loads_function_identity_manifest(
    tmp_path: Path,
) -> None:
    a = _need(_SWITCHY_V1)
    b = _need(_SWITCHY_V2)
    identity_path = tmp_path / "function-identities.yaml"
    identity_path.write_text(
        """
- function: dispatch
  status: changed
  match_basis: similarity_backed
  pdb_symbol: "?dispatch@@YAHH@Z"
  pdb_guid_age: ABCDEF0123456789ABCDEF0123456789:1
  similarity_score: 0.91
  similarity_algorithm: bsim
  evidence:
    - persisted BSim match
    - PDB symbol identity
""",
        encoding="utf-8",
    )

    result = run_windows_patch_diff_review(
        WindowsPatchDiffReviewConfig(
            binary_a=str(a),
            binary_b=str(b),
            function_identity_path=str(identity_path),
            max_items=10,
        )
    )

    assert result.function_identity_count == 1
    assert "windows_patch_function_identity_manifest" in result.tool_sequence
    dispatch_items = [
        item for item in result.review_items if item.function == "dispatch"
    ]
    assert dispatch_items
    item = dispatch_items[0]
    assert "similarity_backed_function_match" in item.match_basis
    assert "similarity_algorithm:bsim" in item.match_basis
    assert "identity:similarity_backed" in item.reason_codes


def test_windows_patch_diff_review_invokes_pdb_identity_manifest(
    tmp_path: Path,
) -> None:
    a = _need(_SWITCHY_V1)
    b = _need(_SWITCHY_V2)

    result = run_windows_patch_diff_review(
        WindowsPatchDiffReviewConfig(
            binary_a=str(a),
            binary_b=str(b),
            pdb_identity_manifest=WindowsPdbIdentityManifestArgs(
                identity_path=str(_write_pdb_identity_manifest(tmp_path)),
                target_id="switchy",
                binary_filename=_SWITCHY_V2.name,
                cache_status="cached",
            ),
            max_items=10,
        )
    )

    assert result.pdb_identity_record_count == 1
    assert result.pdb_identity_manifest_path is not None
    assert result.function_identity_count >= 1
    assert "windows_pdb_identity_manifest" in result.tool_sequence
    dispatch_items = [
        item for item in result.review_items if item.function == "dispatch"
    ]
    assert dispatch_items
    item = dispatch_items[0]
    assert "pdb_backed_identity" in item.match_basis
    assert "identity:pdb_backed" in item.reason_codes
    assert item.confidence >= 0.9
    assert "per_function_patch_identity" in (
        result.evidence_bundle.coverage.fact_coverage
    )
