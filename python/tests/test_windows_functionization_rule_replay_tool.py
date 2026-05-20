from __future__ import annotations

import json
from pathlib import Path

import glaurung as g

from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind
from glaurung.llm.tools.windows_functionization_rule_replay import build_tool


FIXTURES = "python/tests/fixtures/windows/functionization_rule_fixtures.yaml"


def _ctx(tmp_path: Path) -> MemoryContext:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"MZ")
    artifact = g.triage.analyze_bytes(b"MZ")
    ctx = MemoryContext(file_path=str(path), artifact=artifact)
    import_triage(ctx.kb, artifact, str(path))
    return ctx


def _row(
    file: str,
    *,
    seed_counts: dict[str, int] | None = None,
    missing: int = 0,
    extra: int = 0,
    missing_thunks: int = 0,
) -> dict[str, object]:
    return {
        "file": file,
        "glaurung": {"stats": {"seed_kind_counts": seed_counts or {}}},
        "address_gap": {
            "missing_entries": missing,
            "extra_entries": extra,
            "missing_thunks": missing_thunks,
        },
    }


def _write_dashboard(tmp_path: Path) -> Path:
    path = tmp_path / "glaurung-vs-ghidra.json"
    rows = [
        _row(
            "windows-update-amd-xilinx-xrt_coreutil.dll",
            seed_counts={"data_ref": 5, "tiny_stub": 11},
            extra=13,
        ),
        _row("windows-update-SurfacePenBleLcAddrAdaptationDriver.sys"),
        _row("win11-webservices.dll", missing=19, extra=4, missing_thunks=3),
        _row("win11-SyncInfrastructureps.dll", extra=1),
    ]
    path.write_text(json.dumps(rows), encoding="utf-8")
    return path


def _write_unsupported_fixtures(tmp_path: Path) -> Path:
    path = tmp_path / "unsupported-functionization-fixtures.yaml"
    path.write_text(
        """
- rule_id: win-pe-future-functionization-rule
  kind: future_rule
  seed_class: future_seed
  source_files:
  - present.dll
  cases:
  - id: future_case
    kind: positive
    fixture: future fixture
    expected_state: strict_function
    expected: future rule is not implemented yet
    rationale: exercises unsupported rule accounting
""",
        encoding="utf-8",
    )
    return path


def _write_concrete_byte_fixtures(tmp_path: Path) -> Path:
    path = tmp_path / "concrete-functionization-fixtures.yaml"
    path.write_text(
        """
- rule_id: win-pe-tiny-stub-provenance-gate
  kind: tiny_stub_precision_gate
  seed_class: tiny_stub
  cases:
  - id: xor_eax_ret_without_provenance
    kind: negative
    fixture: synthetic bytes
    address: "0x140001000"
    bytes_hex: "31 c0 c3"
    expected_state: candidate_or_label
    expected: unreferenced xor eax/eax return helper is not strict
    rationale: concrete bytes guard for tiny stub over-promotion
- rule_id: win-pe-import-thunk-shape-catalog
  kind: import_thunk_recall_guard
  seed_class: thunk
  cases:
  - id: rex_ff25_with_import_target
    kind: positive
    fixture: synthetic bytes
    address: "0x140002000"
    bytes_hex: "48 ff 25 00 00 00 00"
    has_import_target: true
    expected_state: strict_function
    expected: import thunk with target is strict
    rationale: concrete bytes guard for padded import thunk recall
- rule_id: win-pe-data-ref-padding-boundary-gate
  kind: data_ref_precision_gate
  seed_class: data_ref
  cases:
  - id: cc_padding_run_rejected
    kind: negative
    fixture: synthetic bytes
    address: "0x140003000"
    bytes_hex: "cc cc cc cc"
    expected_state: label_or_rejected_start
    expected: padding bytes are not functions
    rationale: concrete bytes guard for padding data-ref false positives
- rule_id: win-pe-tail-jump-thunk-boundary-gate
  kind: tail_jump_thunk_precision_gate
  seed_class: tail_jump_thunk
  cases:
  - id: rel32_tail_jump_with_xref
    kind: positive
    fixture: synthetic bytes
    address: "0x140004000"
    bytes_hex: "e9 34 12 00 00"
    has_xref: true
    expected_state: strict_function
    expected: direct tail-jump thunk with xref is strict
    rationale: concrete bytes guard for tail-jump thunk recall
  - id: rel32_tail_jump_without_provenance
    kind: negative
    fixture: synthetic bytes
    address: "0x140004100"
    bytes_hex: "e9 34 12 00 00"
    expected_state: candidate_or_label
    expected: direct tail-jump shape alone is not strict
    rationale: concrete bytes guard for branch-byte over-promotion
""",
        encoding="utf-8",
    )
    return path


def _write_native_replay_fixtures(tmp_path: Path) -> Path:
    path = tmp_path / "native-functionization-fixtures.yaml"
    path.write_text(
        """
- rule_id: win-pe-tiny-stub-provenance-gate
  kind: native_function_start_replay
  seed_class: trusted_pdata
  cases:
  - id: surfacepen_entrypoint_is_native_function
    kind: positive
    binary_path: samples/binaries/platforms/windows/vendor/realworld/windows-update-SurfacePenBleLcAddrAdaptationDriver.sys
    address: "0x140006a30"
    expected_state: strict_function
    expected_seed_kind: entrypoint
    expected: native Glaurung emits the address as a function start
    rationale: real vendored PE replay checks analyzer output, not just byte classifiers
  - id: ze_loader_simd_missing_start_stays_candidate
    kind: negative
    binary_path: samples/binaries/platforms/windows/vendor/realworld/windows-update-intel-npu-ze_loader.dll
    address: "0x180033b20"
    expected_state: candidate_or_label
    expected_seed_kind: none
    expected: native Glaurung does not emit this SIMD-headed Ghidra-only address
    rationale: negative real PE replay checks scanner demotion behavior
""",
        encoding="utf-8",
    )
    return path


def test_windows_functionization_rule_replay_passes_checked_in_fixture_yaml(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    comparison = _write_dashboard(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            fixtures_path=FIXTURES,
            comparison_path=str(comparison),
            add_to_kb=True,
        ),
    )

    assert result.fixture_count == 6
    assert result.case_count == 13
    assert result.passed_count == 13
    assert result.failed_count == 0
    assert result.unsupported_count == 0
    assert "not a scanner code change" in result.notes[0]
    assert result.evidence_node_id is not None
    assert any(
        node.kind == NodeKind.evidence
        and node.label == "windows_functionization_rule_replay"
        for node in ctx.kb.nodes()
    )
    assert {
        fixture.rule_id: {case.signal for case in fixture.cases}
        for fixture in result.fixtures
    } == {
        "win-pe-data-ref-padding-boundary-gate": {
            "data_ref_padding_fixture_covered",
            "surfacepen_callback_table_parity",
        },
        "win-pe-tiny-stub-provenance-gate": {"tiny_stub_precision_fixture_covered"},
        "win-pe-internal-start-body-split-candidates": {
            "body_split_recall_fixture_covered",
            "shared_epilogue_control_fixture_covered",
        },
        "win-pe-import-thunk-shape-catalog": {
            "import_thunk_recall_fixture_covered",
            "synthetic_negative_thunk_shape_present",
        },
        "win-pe-tail-jump-thunk-boundary-gate": {"concrete_bytes_replay"},
        "win-pe-native-function-start-replay": {
            "native_glaurung_function_start_replay"
        },
    }
    native_cases = next(
        fixture
        for fixture in result.fixtures
        if fixture.rule_id == "win-pe-native-function-start-replay"
    ).cases
    assert all(case.native_replay for case in native_cases)
    assert any(
        "seed_kind:entrypoint" in case.native_reason_codes for case in native_cases
    )
    assert any("seed_kind:none" in case.native_reason_codes for case in native_cases)
    assert any(
        code.startswith("scan_rejection:")
        for case in native_cases
        for code in case.native_reason_codes
    )
    assert any(
        detail.startswith("native_scan_rejection_counts=")
        for case in native_cases
        for detail in case.details
    )


def test_windows_functionization_rule_replay_marks_unknown_rules_unsupported(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    fixtures = _write_unsupported_fixtures(tmp_path)
    comparison = tmp_path / "dashboard.json"
    comparison.write_text(
        json.dumps([_row("present.dll", seed_counts={"future_seed": 1})]),
        encoding="utf-8",
    )
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            fixtures_path=str(fixtures),
            comparison_path=str(comparison),
        ),
    )

    assert result.fixture_count == 1
    assert result.case_count == 1
    assert result.passed_count == 0
    assert result.failed_count == 0
    assert result.unsupported_count == 1
    assert result.fixtures[0].cases[0].status == "unsupported"
    assert result.fixtures[0].cases[0].signal == "unsupported_rule_id"


def test_windows_functionization_rule_replay_checks_concrete_bytes(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    fixtures = _write_concrete_byte_fixtures(tmp_path)
    comparison = tmp_path / "dashboard.json"
    comparison.write_text("[]", encoding="utf-8")
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            fixtures_path=str(fixtures),
            comparison_path=str(comparison),
        ),
    )

    assert result.fixture_count == 4
    assert result.case_count == 5
    assert result.passed_count == 5
    assert all(
        case.scanner_replay for fixture in result.fixtures for case in fixture.cases
    )
    assert {
        case.case_id: case.details
        for fixture in result.fixtures
        for case in fixture.cases
    }["rex_ff25_with_import_target"] == [
        "expected_state=strict_function",
        "actual_state=strict_function",
        "reason=rip_relative_import_thunk_with_target",
        "bytes=48 ff 25 00 00 00 00",
        "address=0x140002000",
    ]
    details_by_case = {
        case.case_id: case.details
        for fixture in result.fixtures
        for case in fixture.cases
    }
    assert details_by_case["rel32_tail_jump_with_xref"][2] == (
        "reason=tail_jump_thunk_with_boundary_provenance"
    )
    assert details_by_case["rel32_tail_jump_without_provenance"][2] == (
        "reason=tail_jump_thunk_without_provenance"
    )


def test_windows_functionization_rule_replay_checks_native_analyzer_output(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    fixtures = _write_native_replay_fixtures(tmp_path)
    comparison = tmp_path / "dashboard.json"
    comparison.write_text("[]", encoding="utf-8")
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            fixtures_path=str(fixtures),
            comparison_path=str(comparison),
        ),
    )

    cases = {case.case_id: case for case in result.fixtures[0].cases}
    positive = cases["surfacepen_entrypoint_is_native_function"]
    assert positive.native_replay is True
    assert positive.binary_path is not None
    assert positive.binary_path.endswith("SurfacePenBleLcAddrAdaptationDriver.sys")
    assert positive.signal == "native_glaurung_function_start_replay"
    assert positive.status == "passed"
    assert any(detail == "actual_state=strict_function" for detail in positive.details)
    assert "seed_kind:entrypoint" in positive.native_reason_codes
    assert "seed_detail:initial_seed" in positive.native_reason_codes
    assert any(detail == "expected_seed_kind=entrypoint" for detail in positive.details)
    negative = cases["ze_loader_simd_missing_start_stays_candidate"]
    assert negative.native_replay is True
    assert negative.status == "passed"
    assert "native_state:candidate_or_label" in negative.native_reason_codes
    assert "seed_kind:none" in negative.native_reason_codes
    assert "native_head:simd" in negative.native_reason_codes
    assert "expected_seed_kind=none" in negative.details
    assert any(detail.startswith("native_head_hex=0f10") for detail in negative.details)


def test_windows_functionization_rule_replay_surfaces_address_rejection_records(
    tmp_path: Path,
) -> None:
    binary_path = Path(
        "samples/binaries/platforms/windows/vendor/realworld/"
        "windows-update-SurfacePenBleLcAddrAdaptationDriver.sys"
    )
    _functions, _callgraph, stats = g.analysis.analyze_functions_path_with_stats(  # ty: ignore[unresolved-attribute]
        str(binary_path),
        max_functions=0,
    )
    rejection = next(
        item
        for item in stats["scan_rejections"]
        if item["reason"] == "body_overlap:tiny_stub"
    )
    fixtures = tmp_path / "native-address-rejection-fixtures.yaml"
    fixtures.write_text(
        f"""
- rule_id: win-pe-native-function-start-replay
  kind: native_function_start_replay
  seed_class: tiny_stub
  cases:
  - id: body_overlap_rejection_has_address_record
    kind: negative
    binary_path: {binary_path}
    address: "0x{int(rejection["va"]):x}"
    expected_state: candidate_or_label
    expected_seed_kind: none
    expected: native replay surfaces the scanner gate that rejected this VA
    rationale: checks per-address scanner rejection records, not only aggregate counts
""",
        encoding="utf-8",
    )
    ctx = _ctx(tmp_path)
    comparison = tmp_path / "dashboard.json"
    comparison.write_text("[]", encoding="utf-8")
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            fixtures_path=str(fixtures),
            comparison_path=str(comparison),
        ),
    )

    case = result.fixtures[0].cases[0]
    assert case.status == "passed"
    assert (
        "scan_rejection_at_address:body_overlap:tiny_stub" in case.native_reason_codes
    )
    assert any(
        detail.startswith("native_address_scan_rejections=body_overlap:tiny_stub")
        for detail in case.details
    )


def test_memory_agent_registers_windows_functionization_rule_replay() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "windows_functionization_rule_replay" in agent._function_toolset.tools
