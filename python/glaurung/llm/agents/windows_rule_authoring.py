"""Deterministic Windows rule-authoring workflow."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

import glaurung as g
import yaml
from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.adapters import import_triage
from ..tools.windows_agent_evidence_bundle import (
    WindowsEvidenceBundle,
    WindowsEvidenceCoverage,
    WindowsEvidenceSubject,
    evidence_ref,
    make_windows_evidence_bundle,
)
from ..tools.windows_function_boundary_diff import (
    WindowsFunctionBoundaryDiffArgs,
    WindowsFunctionBoundaryDiffRow,
    WindowsFunctionBoundaryDiffTool,
)


RuleTestKind = Literal["positive", "negative", "metric_guard"]
RuleWorkItemKind = Literal[
    "tiny_stub_precision_gate",
    "import_thunk_recall_guard",
    "data_ref_precision_gate",
    "body_split_recall_guard",
    "tail_jump_thunk_precision_gate",
    "seed_class_metric",
    "native_function_start_replay",
]
RuleReplayExpectedState = Literal[
    "strict_function",
    "candidate_or_label",
    "label_or_rejected_start",
    "body_split_candidate",
    "metric_guard",
]


class WindowsRuleTestProposal(BaseModel):
    kind: RuleTestKind
    name: str
    fixture: str
    expected: str
    rationale: str


class WindowsSeedClassMetricProposal(BaseModel):
    seed_class: str
    metric: str
    current_value: float
    target: str
    files: list[str] = Field(default_factory=list)
    rationale: str


class WindowsRuleAuthoringWorkItem(BaseModel):
    rank: int
    kind: RuleWorkItemKind
    rule_id: str
    priority: int = Field(ge=0)
    seed_class: str
    problem_statement: str
    proposed_rule: str
    proposed_tests: list[WindowsRuleTestProposal]
    metrics: list[WindowsSeedClassMetricProposal] = Field(default_factory=list)
    source_files: list[str] = Field(default_factory=list)
    implementation_scope: list[str] = Field(default_factory=list)
    non_goals: list[str] = Field(default_factory=list)


class WindowsRuleReplayCase(BaseModel):
    id: str
    kind: RuleTestKind
    fixture: str = ""
    expected_state: RuleReplayExpectedState
    expected: str
    rationale: str
    binary_path: str | None = None
    address: str | None = None
    bytes_hex: str | None = None
    has_xref: bool = False
    has_table_provenance: bool = False
    has_pdata: bool = False
    has_import_target: bool = False
    expected_seed_kind: str | None = None


class WindowsRuleReplayFixture(BaseModel):
    rule_id: str
    kind: RuleWorkItemKind
    seed_class: str
    source_files: list[str] = Field(default_factory=list)
    implementation_scope: list[str] = Field(default_factory=list)
    non_goals: list[str] = Field(default_factory=list)
    cases: list[WindowsRuleReplayCase]


class WindowsRuleAuthoringConfig(BaseModel):
    comparison_path: str = Field(
        "docs/windows-port/glaurung_vs_ghidra_vendor_windows_30_after_tiny_stub_gate.json"
    )
    max_boundary_rows: int = Field(12, ge=1, le=128)
    max_work_items: int = Field(8, ge=1, le=64)
    min_precision_extra: int = Field(50, ge=0)
    materialize_fixtures: bool = Field(
        False,
        description=(
            "If true, write replay YAML for proposed scanner/functionization "
            "rules. The default remains dry-run to avoid implicit tree changes."
        ),
    )
    fixture_output_path: str = Field(
        "python/tests/fixtures/windows/functionization_rule_fixtures.yaml",
        description="Where materialized rule replay fixtures should be written.",
    )
    checked_in_fixture_path: str = Field(
        "python/tests/fixtures/windows/functionization_rule_fixtures.yaml",
        description="Checked-in replay YAML to compare against generated work items.",
    )


class WindowsRuleAuthoringResult(BaseModel):
    claim_level: str = "rule_authoring_plan_not_code_change"
    work_items: list[WindowsRuleAuthoringWorkItem]
    seed_class_metrics: list[WindowsSeedClassMetricProposal]
    replay_fixtures: list[WindowsRuleReplayFixture]
    materialized_fixture_path: str | None = None
    fixtures_written: bool = False
    materialized_fixture_count: int = 0
    materialized_case_count: int = 0
    checked_in_fixture_path: str
    checked_in_fixture_count: int
    checked_in_case_count: int
    checked_in_fixture_drift: list[str] = Field(default_factory=list)
    tool_sequence: list[str]
    evidence_bundle: WindowsEvidenceBundle
    notes: list[str] = Field(default_factory=list)


def run_windows_rule_authoring(
    config: WindowsRuleAuthoringConfig,
) -> WindowsRuleAuthoringResult:
    ctx = _ctx()
    boundary = WindowsFunctionBoundaryDiffTool().run(
        ctx,
        ctx.kb,
        WindowsFunctionBoundaryDiffArgs(
            comparison_path=config.comparison_path,
            sort_by="extra",
            min_extra=config.min_precision_extra,
            max_rows=config.max_boundary_rows,
        ),
    )
    missing = WindowsFunctionBoundaryDiffTool().run(
        ctx,
        ctx.kb,
        WindowsFunctionBoundaryDiffArgs(
            comparison_path=config.comparison_path,
            sort_by="missing",
            min_missing=1,
            max_rows=config.max_boundary_rows,
        ),
    )
    work_items = _work_items(
        precision_rows=boundary.rows,
        recall_rows=missing.rows,
        max_work_items=config.max_work_items,
    )
    metrics = _dedupe_metrics(
        [metric for item in work_items for metric in item.metrics]
    )
    replay_fixtures = _replay_fixtures(work_items)
    checked_in_fixtures = _load_optional_replay_fixtures(
        Path(config.checked_in_fixture_path)
    )
    fixture_drift = _fixture_drift(replay_fixtures, checked_in_fixtures)
    notes = [
        "Rule-authoring output is a test-first implementation plan, not a code change.",
        "Production scanner changes should be made only after the proposed positive and negative tests exist.",
    ]
    if fixture_drift:
        notes.append("checked-in replay fixtures drift from generated work items")
    materialized_path: str | None = None
    if config.materialize_fixtures:
        path = Path(config.fixture_output_path)
        materialize_windows_rule_replay_fixtures(path, replay_fixtures)
        materialized_path = str(path)
        notes.append(f"wrote replay fixtures to {path}")
    tool_sequence = [
        "windows_function_boundary_diff:precision",
        "windows_function_boundary_diff:recall",
    ]
    return WindowsRuleAuthoringResult(
        work_items=work_items,
        seed_class_metrics=metrics,
        replay_fixtures=replay_fixtures,
        materialized_fixture_path=materialized_path,
        fixtures_written=config.materialize_fixtures,
        materialized_fixture_count=len(replay_fixtures),
        materialized_case_count=sum(len(fixture.cases) for fixture in replay_fixtures),
        checked_in_fixture_path=config.checked_in_fixture_path,
        checked_in_fixture_count=len(checked_in_fixtures),
        checked_in_case_count=sum(
            len(fixture.cases) for fixture in checked_in_fixtures
        ),
        checked_in_fixture_drift=fixture_drift,
        tool_sequence=tool_sequence,
        evidence_bundle=_evidence_bundle(
            config=config,
            work_items=work_items,
            metrics=metrics,
            replay_fixtures=replay_fixtures,
            checked_in_fixtures=checked_in_fixtures,
            fixture_drift=fixture_drift,
            tool_sequence=tool_sequence,
            notes=notes,
        ),
        notes=notes,
    )


def _work_items(
    *,
    precision_rows: list[WindowsFunctionBoundaryDiffRow],
    recall_rows: list[WindowsFunctionBoundaryDiffRow],
    max_work_items: int,
) -> list[WindowsRuleAuthoringWorkItem]:
    items: list[WindowsRuleAuthoringWorkItem] = []
    items.extend(_tiny_stub_items(precision_rows))
    items.extend(_data_ref_items(precision_rows))
    items.extend(_import_thunk_items(recall_rows))
    items.extend(_body_split_items(recall_rows))
    items.sort(key=lambda item: (-item.priority, item.rule_id))
    items = items[:max_work_items]
    for idx, item in enumerate(items, start=1):
        item.rank = idx
    return items


def _tiny_stub_items(
    rows: list[WindowsFunctionBoundaryDiffRow],
) -> list[WindowsRuleAuthoringWorkItem]:
    targets = [
        row
        for row in rows
        if row.seed_kind_counts.get("tiny_stub", 0) >= 100
        and (
            "npu" in row.file.lower()
            or "xrt" in row.file.lower()
            or row.extra_entries >= 500
        )
    ]
    if not targets:
        return []
    files = [row.file for row in targets[:5]]
    extra_total = sum(row.extra_entries for row in targets)
    tiny_total = sum(row.seed_kind_counts.get("tiny_stub", 0) for row in targets)
    return [
        WindowsRuleAuthoringWorkItem(
            rank=0,
            kind="tiny_stub_precision_gate",
            rule_id="win-pe-tiny-stub-provenance-gate",
            priority=900 + min(extra_total, 500),
            seed_class="tiny_stub",
            problem_statement=(
                "Weak tiny-stub starts remain the largest functionization precision "
                f"risk across {', '.join(files)}."
            ),
            proposed_rule=(
                "Promote tiny_stub starts only when a direct xref, table/code-pointer "
                "provenance, import-thunk shape, export, or trusted boundary fact is "
                "present; otherwise emit a code label or candidate start."
            ),
            proposed_tests=[
                WindowsRuleTestProposal(
                    kind="negative",
                    name="npu_xrt_unreferenced_tiny_stub_stays_candidate",
                    fixture="windows-update-intel-npu-npu_d3d12_umd.dll and xrt_coreutil.dll samples",
                    expected="unreferenced tiny_stub addresses are candidates or labels, not strict functions",
                    rationale="guards the NPU/XRT over-promotion class before scanner edits",
                ),
                WindowsRuleTestProposal(
                    kind="positive",
                    name="referenced_adjustor_or_return_helper_stays_function",
                    fixture="Dism/Realtek referenced tiny helper samples",
                    expected="tiny helpers with xref/table provenance remain promoted",
                    rationale="prevents precision work from losing useful Ghidra-parity starts",
                ),
                WindowsRuleTestProposal(
                    kind="metric_guard",
                    name="tiny_stub_seed_precision_dashboard",
                    fixture="30-file Ghidra stress suite",
                    expected="track tiny_stub extra_entries and Ghidra recall together",
                    rationale="rule must lower false positives without hiding recall loss",
                ),
            ],
            metrics=[
                WindowsSeedClassMetricProposal(
                    seed_class="tiny_stub",
                    metric="extra_entries_on_precision_stress_files",
                    current_value=float(extra_total),
                    target="monotonically lower without increasing Ghidra-only starts by more than reviewed budget",
                    files=files,
                    rationale=(
                        f"{tiny_total} tiny_stub seeds are present on the selected precision rows"
                    ),
                )
            ],
            source_files=files,
            implementation_scope=[
                "function-start seed classifier",
                "candidate/label/function state mapping",
                "Ghidra parity dashboard seed-class metrics",
            ],
            non_goals=[
                "do not blindly suppress all tiny helpers",
                "do not treat Ghidra-only public seeds as vulnerability findings",
            ],
        )
    ]


def _data_ref_items(
    rows: list[WindowsFunctionBoundaryDiffRow],
) -> list[WindowsRuleAuthoringWorkItem]:
    targets = [
        row
        for row in rows
        if row.seed_kind_counts.get("data_ref", 0) >= 20 and row.extra_entries >= 50
    ]
    if not targets:
        return []
    files = [row.file for row in targets[:5]]
    return [
        WindowsRuleAuthoringWorkItem(
            rank=0,
            kind="data_ref_precision_gate",
            rule_id="win-pe-data-ref-padding-boundary-gate",
            priority=650 + sum(row.extra_entries for row in targets[:3]),
            seed_class="data_ref",
            problem_statement=(
                "Data-reference function starts need padding, alignment, and table-consistency gates."
            ),
            proposed_rule=(
                "Promote data_ref starts only when target alignment, executable section, "
                "non-padding prior bytes, and multi-entry table consistency agree."
            ),
            proposed_tests=[
                WindowsRuleTestProposal(
                    kind="negative",
                    name="netwtw_padding_run_data_ref_not_function",
                    fixture="NETwtw10.sys padding-run data-ref addresses",
                    expected="padding-run data refs remain labels or rejected starts",
                    rationale="guards concrete adjacent cc-padding false positives",
                ),
                WindowsRuleTestProposal(
                    kind="positive",
                    name="surfacepen_callback_table_still_promotes",
                    fixture="SurfacePenBleLcAddrAdaptationDriver callback table",
                    expected="high-confidence callback-table targets stay strict functions",
                    rationale="preserves the known data-ref recall win",
                ),
            ],
            metrics=[
                WindowsSeedClassMetricProposal(
                    seed_class="data_ref",
                    metric="data_ref_extra_entries",
                    current_value=float(sum(row.extra_entries for row in targets)),
                    target="zero padding-run strict functions on NETwtw-like fixtures",
                    files=files,
                    rationale="data_ref precision must be tracked separately from tiny_stub",
                )
            ],
            source_files=files,
            implementation_scope=["data-ref confidence gates", "padding-run detection"],
            non_goals=[
                "do not demote multi-entry callback tables with strong provenance"
            ],
        )
    ]


def _import_thunk_items(
    rows: list[WindowsFunctionBoundaryDiffRow],
) -> list[WindowsRuleAuthoringWorkItem]:
    targets = [row for row in rows if row.missing_thunks > 0]
    if not targets:
        return []
    files = [row.file for row in targets[:5]]
    missing_thunks = sum(row.missing_thunks for row in targets)
    return [
        WindowsRuleAuthoringWorkItem(
            rank=0,
            kind="import_thunk_recall_guard",
            rule_id="win-pe-import-thunk-shape-catalog",
            priority=500 + missing_thunks,
            seed_class="thunk",
            problem_statement="No-.pdata import thunks still appear in Ghidra-only starts.",
            proposed_rule=(
                "Catalog and promote bounded import/IAT thunk shapes such as "
                "ff 25, 48 ff 25, and mov/jmp wrappers with import target provenance."
            ),
            proposed_tests=[
                WindowsRuleTestProposal(
                    kind="positive",
                    name="padded_rex_ff25_import_thunks_promote",
                    fixture="DismCore, WDScore, NetSetupAPI thunk samples",
                    expected="known IAT thunks are strict functions with import target names",
                    rationale="closes high-confidence Ghidra recall gaps",
                ),
                WindowsRuleTestProposal(
                    kind="negative",
                    name="non_import_indirect_jump_not_thunk",
                    fixture="synthetic jmp [rip+imm32] without import target",
                    expected="shape without import provenance is a candidate, not strict thunk",
                    rationale="prevents shape-only over-promotion",
                ),
            ],
            metrics=[
                WindowsSeedClassMetricProposal(
                    seed_class="thunk",
                    metric="missing_ghidra_thunks",
                    current_value=float(missing_thunks),
                    target="all reviewed import-thunk misses explained or promoted",
                    files=files,
                    rationale="thunk recall is a narrow high-confidence metric",
                )
            ],
            source_files=files,
            implementation_scope=["import thunk catalog", "IAT target provenance"],
            non_goals=["do not classify arbitrary indirect jumps as imports"],
        )
    ]


def _body_split_items(
    rows: list[WindowsFunctionBoundaryDiffRow],
) -> list[WindowsRuleAuthoringWorkItem]:
    targets = [
        row
        for row in rows
        if row.missing_entries >= 40
        and any("body_split" in tool for tool in row.next_tools)
    ]
    if not targets:
        return []
    files = [row.file for row in targets[:5]]
    return [
        WindowsRuleAuthoringWorkItem(
            rank=0,
            kind="body_split_recall_guard",
            rule_id="win-pe-internal-start-body-split-candidates",
            priority=450 + sum(row.missing_entries for row in targets[:3]),
            seed_class="direct_call_body_split",
            problem_statement=(
                "Ghidra-like starts inside broad vtable/.pdata owners need split candidates."
            ),
            proposed_rule=(
                "When a strong internal start has xref/table/prologue/thunk evidence, "
                "emit a body-split candidate and require review before owner-body absorption."
            ),
            proposed_tests=[
                WindowsRuleTestProposal(
                    kind="positive",
                    name="webservices_internal_method_split_candidate",
                    fixture="Win10/Win11 webservices.dll body-overmerge samples",
                    expected="internal Ghidra-like starts become body-split candidates",
                    rationale="targets the largest OS-side recall gap",
                ),
                WindowsRuleTestProposal(
                    kind="negative",
                    name="shared_epilogue_stays_label",
                    fixture="SyncInfrastructure/acledit zero-return epilogues",
                    expected="shared epilogues remain code labels, not split functions",
                    rationale="prevents local-label promotion regressions",
                ),
            ],
            metrics=[
                WindowsSeedClassMetricProposal(
                    seed_class="direct_call_body_split",
                    metric="body_overlap_missing_entries",
                    current_value=float(sum(row.missing_entries for row in targets)),
                    target="reviewed body-overlap starts classified as split candidates or labels",
                    files=files,
                    rationale="body splitting is a recall metric separate from seed discovery",
                )
            ],
            source_files=files,
            implementation_scope=[
                "function body split candidates",
                "owner overlap reporting",
            ],
            non_goals=["do not split shared epilogues without boundary evidence"],
        )
    ]


def _replay_fixtures(
    work_items: list[WindowsRuleAuthoringWorkItem],
) -> list[WindowsRuleReplayFixture]:
    fixtures = [
        WindowsRuleReplayFixture(
            rule_id=item.rule_id,
            kind=item.kind,
            seed_class=item.seed_class,
            source_files=item.source_files,
            implementation_scope=item.implementation_scope,
            non_goals=item.non_goals,
            cases=[
                WindowsRuleReplayCase(
                    id=test.name,
                    kind=test.kind,
                    fixture=test.fixture,
                    expected_state=_expected_state(item.kind, test),
                    expected=test.expected,
                    rationale=test.rationale,
                )
                for test in item.proposed_tests
            ],
        )
        for item in work_items
    ]
    fixtures.append(_tail_jump_thunk_replay_fixture())
    fixtures.append(_native_function_start_replay_fixture())
    return fixtures


def _tail_jump_thunk_replay_fixture() -> WindowsRuleReplayFixture:
    return WindowsRuleReplayFixture(
        rule_id="win-pe-tail-jump-thunk-boundary-gate",
        kind="tail_jump_thunk_precision_gate",
        seed_class="tail_jump_thunk",
        implementation_scope=[
            "direct tail-jump thunk recognition",
            "boundary provenance gate",
        ],
        non_goals=[
            "do not promote every branch target as a function",
            "do not treat import thunks as tail-jump thunks",
        ],
        cases=[
            WindowsRuleReplayCase(
                id="direct_rel32_tail_jump_with_xref_promotes",
                kind="positive",
                fixture="synthetic jmp rel32 thunk",
                address="0x140004000",
                bytes_hex="e9 34 12 00 00",
                has_xref=True,
                expected_state="strict_function",
                expected=(
                    "direct tail-jump thunk with caller provenance is a strict function"
                ),
                rationale="preserves common Ghidra/IDA tail-call thunk boundaries",
            ),
            WindowsRuleReplayCase(
                id="unreferenced_tail_jump_shape_stays_candidate",
                kind="negative",
                fixture="synthetic unreferenced jmp rel32 bytes",
                address="0x140004100",
                bytes_hex="e9 34 12 00 00",
                expected_state="candidate_or_label",
                expected="shape-only tail jump is a candidate or label",
                rationale=(
                    "prevents branch-byte over-promotion without boundary evidence"
                ),
            ),
        ],
    )


def _native_function_start_replay_fixture() -> WindowsRuleReplayFixture:
    return WindowsRuleReplayFixture(
        rule_id="win-pe-native-function-start-replay",
        kind="native_function_start_replay",
        seed_class="native_analyzer",
        implementation_scope=[
            "native Glaurung function discovery",
            "seed provenance reason codes",
            "emitted and non-emitted real-PE starts",
        ],
        non_goals=[
            "do not require Ghidra to agree with every native replay address",
        ],
        cases=[
            WindowsRuleReplayCase(
                id="surfacepen_entrypoint_is_native_function",
                kind="positive",
                binary_path=(
                    "samples/binaries/platforms/windows/vendor/realworld/"
                    "windows-update-SurfacePenBleLcAddrAdaptationDriver.sys"
                ),
                address="0x140006a30",
                expected_state="strict_function",
                expected_seed_kind="entrypoint",
                expected="native Glaurung emits the address as a function start",
                rationale=(
                    "checks native promotion and seed provenance on a vendored driver"
                ),
            ),
            WindowsRuleReplayCase(
                id="ze_loader_simd_missing_start_stays_candidate",
                kind="negative",
                binary_path=(
                    "samples/binaries/platforms/windows/vendor/realworld/"
                    "windows-update-intel-npu-ze_loader.dll"
                ),
                address="0x180033b20",
                expected_state="candidate_or_label",
                expected_seed_kind="none",
                expected=(
                    "native Glaurung does not emit this SIMD-headed Ghidra-only address"
                ),
                rationale=("checks native demotion behavior on a real vendored DLL"),
            ),
        ],
    )


def _expected_state(
    kind: RuleWorkItemKind,
    test: WindowsRuleTestProposal,
) -> RuleReplayExpectedState:
    if test.kind == "metric_guard":
        return "metric_guard"
    if kind == "body_split_recall_guard":
        return (
            "body_split_candidate" if test.kind == "positive" else "candidate_or_label"
        )
    if kind == "data_ref_precision_gate" and test.kind == "negative":
        return "label_or_rejected_start"
    if kind in {"tiny_stub_precision_gate", "import_thunk_recall_guard"}:
        return "strict_function" if test.kind == "positive" else "candidate_or_label"
    return "strict_function" if test.kind == "positive" else "candidate_or_label"


def materialize_windows_rule_replay_fixtures(
    path: Path,
    fixtures: list[WindowsRuleReplayFixture],
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = [fixture.model_dump(mode="json") for fixture in fixtures]
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")


def load_windows_rule_replay_fixtures(
    path: str
    | Path = "python/tests/fixtures/windows/functionization_rule_fixtures.yaml",
) -> list[WindowsRuleReplayFixture]:
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or []
    if not isinstance(raw, list):
        raise ValueError(f"{path}: expected top-level fixture list")
    return [WindowsRuleReplayFixture.model_validate(entry) for entry in raw]


def _load_optional_replay_fixtures(path: Path) -> list[WindowsRuleReplayFixture]:
    if not path.exists():
        return []
    return load_windows_rule_replay_fixtures(path)


def _fixture_drift(
    generated: list[WindowsRuleReplayFixture],
    checked_in: list[WindowsRuleReplayFixture],
) -> list[str]:
    generated_by_rule = {fixture.rule_id: fixture for fixture in generated}
    checked_by_rule = {fixture.rule_id: fixture for fixture in checked_in}
    drift: list[str] = []
    for rule_id in sorted(set(generated_by_rule) - set(checked_by_rule)):
        drift.append(f"missing checked-in fixture: {rule_id}")
    for rule_id in sorted(set(checked_by_rule) - set(generated_by_rule)):
        drift.append(f"stale checked-in fixture: {rule_id}")
    for rule_id in sorted(set(generated_by_rule) & set(checked_by_rule)):
        generated_cases = {
            case.id: case.expected_state for case in generated_by_rule[rule_id].cases
        }
        checked_cases = {
            case.id: case.expected_state for case in checked_by_rule[rule_id].cases
        }
        for case_id in sorted(set(generated_cases) - set(checked_cases)):
            drift.append(f"missing checked-in case: {rule_id}/{case_id}")
        for case_id in sorted(set(checked_cases) - set(generated_cases)):
            drift.append(f"stale checked-in case: {rule_id}/{case_id}")
        for case_id in sorted(set(generated_cases) & set(checked_cases)):
            if generated_cases[case_id] != checked_cases[case_id]:
                drift.append(
                    "checked-in expected-state drift: "
                    f"{rule_id}/{case_id} "
                    f"{checked_cases[case_id]} != {generated_cases[case_id]}"
                )
    return drift


def _dedupe_metrics(
    metrics: list[WindowsSeedClassMetricProposal],
) -> list[WindowsSeedClassMetricProposal]:
    out: list[WindowsSeedClassMetricProposal] = []
    seen: set[tuple[str, str]] = set()
    for metric in metrics:
        key = (metric.seed_class, metric.metric)
        if key not in seen:
            seen.add(key)
            out.append(metric)
    return out


def _evidence_bundle(
    *,
    config: WindowsRuleAuthoringConfig,
    work_items: list[WindowsRuleAuthoringWorkItem],
    metrics: list[WindowsSeedClassMetricProposal],
    replay_fixtures: list[WindowsRuleReplayFixture],
    checked_in_fixtures: list[WindowsRuleReplayFixture],
    fixture_drift: list[str],
    tool_sequence: list[str],
    notes: list[str],
) -> WindowsEvidenceBundle:
    return make_windows_evidence_bundle(
        claim_level="triage_evidence_bundle_not_finding",
        subject=WindowsEvidenceSubject(
            kind="generic",
            attributes={
                "comparison_path": config.comparison_path,
                "work_item_count": len(work_items),
                "metric_count": len(metrics),
                "replay_fixture_count": len(replay_fixtures),
                "replay_case_count": sum(
                    len(fixture.cases) for fixture in replay_fixtures
                ),
                "checked_in_fixture_path": config.checked_in_fixture_path,
                "checked_in_fixture_count": len(checked_in_fixtures),
                "checked_in_case_count": sum(
                    len(fixture.cases) for fixture in checked_in_fixtures
                ),
                "checked_in_fixture_drift_count": len(fixture_drift),
                "fixture_output_path": config.fixture_output_path,
                "fixtures_written": config.materialize_fixtures,
            },
        ),
        source_tools=["windows_function_boundary_diff"],
        tool_sequence=tool_sequence,
        evidence_refs=[
            evidence_ref(
                kind="tool_result",
                source="windows_rule_authoring",
                summary=f"{item.rule_id}: {item.problem_statement}",
                reason_codes=[item.kind, item.seed_class],
                provenance=item.source_files,
            )
            for item in work_items[:16]
        ],
        coverage=WindowsEvidenceCoverage(
            fact_coverage=[
                *(metric.metric for metric in metrics),
                "functionization_rule_replay_fixtures",
            ],
            missing_facts=fixture_drift,
        ),
        blockers=fixture_drift,
        reason_codes=[item.kind for item in work_items],
        next_actions=[test.name for item in work_items for test in item.proposed_tests],
        notes=notes,
    )


def _ctx() -> MemoryContext:
    artifact = g.triage.analyze_bytes(b"MZ")
    ctx = MemoryContext(file_path="<windows-rule-authoring>", artifact=artifact)
    import_triage(ctx.kb, artifact, "<windows-rule-authoring>")
    return ctx
