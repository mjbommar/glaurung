from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal

import yaml
import glaurung as g
from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Edge, Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


ReplayCaseStatus = Literal["passed", "failed", "unsupported"]


class WindowsFunctionizationRuleReplayArgs(BaseModel):
    fixtures_path: str = Field(
        "python/tests/fixtures/windows/functionization_rule_fixtures.yaml",
        description="Checked-in functionization rule replay YAML.",
    )
    comparison_path: str = Field(
        "docs/windows-port/glaurung_vs_ghidra_vendor_windows_30_after_tiny_stub_gate.json",
        description="Cached Glaurung-vs-Ghidra Windows comparison dashboard.",
    )
    max_fixtures: int = Field(64, ge=0, le=512)
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact functionization-rule replay evidence node.",
    )


class WindowsFunctionizationRuleReplayCase(BaseModel):
    rule_id: str
    case_id: str
    kind: str
    expected_state: str
    status: ReplayCaseStatus
    signal: str
    scanner_replay: bool = False
    native_replay: bool = False
    address: str | None = None
    bytes_hex: str | None = None
    binary_path: str | None = None
    native_reason_codes: list[str] = Field(default_factory=list)
    details: list[str] = Field(default_factory=list)


class WindowsFunctionizationRuleReplayFixture(BaseModel):
    rule_id: str
    seed_class: str
    case_count: int
    passed_count: int
    failed_count: int
    unsupported_count: int
    cases: list[WindowsFunctionizationRuleReplayCase]


class WindowsFunctionizationRuleReplayResult(BaseModel):
    fixtures_path: str
    comparison_path: str
    fixture_count: int
    case_count: int
    passed_count: int
    failed_count: int
    unsupported_count: int
    fixtures: list[WindowsFunctionizationRuleReplayFixture]
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsFunctionizationRuleReplayTool(
    MemoryTool[
        WindowsFunctionizationRuleReplayArgs,
        WindowsFunctionizationRuleReplayResult,
    ]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_functionization_rule_replay",
                description=(
                    "Replay checked-in Windows functionization rule fixtures "
                    "against the cached Ghidra/Glaurung dashboard and report "
                    "whether each fixture is covered by deterministic evidence."
                ),
                tags=("windows", "pe", "functionization", "fixtures", "replay"),
            ),
            WindowsFunctionizationRuleReplayArgs,
            WindowsFunctionizationRuleReplayResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsFunctionizationRuleReplayArgs,
    ) -> WindowsFunctionizationRuleReplayResult:
        fixtures_path = Path(args.fixtures_path)
        comparison_path = Path(args.comparison_path)
        raw_fixtures = _load_yaml_list(fixtures_path)[: args.max_fixtures]
        rows = _rows_by_file(comparison_path)
        fixtures = [_replay_fixture(fixture, rows) for fixture in raw_fixtures]
        cases = [case for fixture in fixtures for case in fixture.cases]

        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_functionization_rule_replay",
                    props={
                        "fixtures_path": str(fixtures_path),
                        "comparison_path": str(comparison_path),
                        "fixture_count": len(fixtures),
                        "case_count": len(cases),
                        "passed_count": sum(case.status == "passed" for case in cases),
                        "failed_count": sum(case.status == "failed" for case in cases),
                        "unsupported_count": sum(
                            case.status == "unsupported" for case in cases
                        ),
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))

        return WindowsFunctionizationRuleReplayResult(
            fixtures_path=str(fixtures_path),
            comparison_path=str(comparison_path),
            fixture_count=len(fixtures),
            case_count=len(cases),
            passed_count=sum(case.status == "passed" for case in cases),
            failed_count=sum(case.status == "failed" for case in cases),
            unsupported_count=sum(case.status == "unsupported" for case in cases),
            fixtures=fixtures,
            evidence_node_id=evidence_node_id,
            notes=[
                "functionization rule replay checks fixture/dashboard coverage; "
                "it is not a scanner code change or vulnerability verdict",
                "cases with bytes_hex use deterministic concrete-byte replay "
                "instead of dashboard-only coverage signals",
                "cases with binary_path and address replay native Glaurung "
                "function discovery on the named PE and check emitted starts",
            ],
        )


def _load_yaml_list(path: Path) -> list[dict[str, Any]]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    if not isinstance(raw, list):
        raise ValueError(f"{path}: expected top-level fixture list")
    return [entry for entry in raw if isinstance(entry, dict)]


def _rows_by_file(path: Path) -> dict[str, dict[str, Any]]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ValueError(f"{path}: expected comparison row list")
    rows: dict[str, dict[str, Any]] = {}
    for row in raw:
        if isinstance(row, dict) and isinstance(row.get("file"), str):
            rows[str(row["file"])] = row
    return rows


def _replay_fixture(
    fixture: dict[str, Any],
    rows: dict[str, dict[str, Any]],
) -> WindowsFunctionizationRuleReplayFixture:
    rule_id = str(fixture.get("rule_id") or "")
    seed_class = str(fixture.get("seed_class") or "")
    cases = [
        _replay_case(rule_id, seed_class, fixture, case, rows)
        for case in fixture.get("cases") or []
        if isinstance(case, dict)
    ]
    return WindowsFunctionizationRuleReplayFixture(
        rule_id=rule_id,
        seed_class=seed_class,
        case_count=len(cases),
        passed_count=sum(case.status == "passed" for case in cases),
        failed_count=sum(case.status == "failed" for case in cases),
        unsupported_count=sum(case.status == "unsupported" for case in cases),
        cases=cases,
    )


def _replay_case(
    rule_id: str,
    seed_class: str,
    fixture: dict[str, Any],
    case: dict[str, Any],
    rows: dict[str, dict[str, Any]],
) -> WindowsFunctionizationRuleReplayCase:
    case_id = str(case.get("id") or "")
    expected_state = str(case.get("expected_state") or "")
    status, signal, details, reason_codes = _case_signal(
        rule_id, seed_class, fixture, case, rows
    )
    return WindowsFunctionizationRuleReplayCase(
        rule_id=rule_id,
        case_id=case_id,
        kind=str(case.get("kind") or ""),
        expected_state=expected_state,
        status=status,
        signal=signal,
        scanner_replay=bool(case.get("bytes_hex")),
        native_replay=bool(case.get("binary_path")),
        address=str(case.get("address")) if case.get("address") is not None else None,
        bytes_hex=str(case.get("bytes_hex"))
        if case.get("bytes_hex") is not None
        else None,
        binary_path=str(case.get("binary_path"))
        if case.get("binary_path") is not None
        else None,
        native_reason_codes=reason_codes,
        details=details,
    )


def _case_signal(
    rule_id: str,
    seed_class: str,
    fixture: dict[str, Any],
    case: dict[str, Any],
    rows: dict[str, dict[str, Any]],
) -> tuple[ReplayCaseStatus, str, list[str], list[str]]:
    native_signal = _native_case_signal(case)
    if native_signal is not None:
        return native_signal
    scanner_signal = _scanner_case_signal(rule_id, case)
    if scanner_signal is not None:
        status, signal, details = scanner_signal
        return status, signal, details, []
    source_files = [str(value) for value in fixture.get("source_files") or []]
    case_text = " ".join(
        str(case.get(key) or "") for key in ("id", "fixture", "expected")
    ).lower()
    selected = [rows[name] for name in source_files if name in rows]
    if not selected and "synthetic" not in case_text:
        return "failed", "source_files_not_in_dashboard", source_files, []

    if rule_id == "win-pe-tiny-stub-provenance-gate":
        return (*_tiny_stub_signal(seed_class, selected), [])
    if rule_id == "win-pe-data-ref-padding-boundary-gate":
        return (*_data_ref_signal(case_text, selected, rows), [])
    if rule_id == "win-pe-import-thunk-shape-catalog":
        return (*_import_thunk_signal(case_text, selected), [])
    if rule_id == "win-pe-internal-start-body-split-candidates":
        return (*_body_split_signal(case_text, selected, rows), [])
    return "unsupported", "unsupported_rule_id", [rule_id], []


def _native_case_signal(
    case: dict[str, Any],
) -> tuple[ReplayCaseStatus, str, list[str], list[str]] | None:
    binary_path_text = case.get("binary_path")
    if not isinstance(binary_path_text, str) or not binary_path_text.strip():
        return None
    expected_state = str(case.get("expected_state") or "")
    address_text = str(case.get("address") or "")
    if not address_text:
        return "failed", "native_replay_missing_address", [binary_path_text], []
    try:
        address = int(address_text, 16) if address_text.startswith("0x") else int(address_text)
    except ValueError as exc:
        return "failed", "native_replay_invalid_address", [str(exc)], []
    binary_path = Path(binary_path_text)
    if not binary_path.exists():
        return "failed", "native_replay_missing_binary", [str(binary_path)], []

    max_functions = int(case.get("native_max_functions") or 0)
    functions, _callgraph, stats = g.analysis.analyze_functions_path_with_stats(  # ty: ignore[unresolved-attribute]
        str(binary_path),
        max_functions=max_functions,
    )
    entry_vas = {int(function.entry_point.value) for function in functions}
    seed_kind = _native_seed_kind(stats, address)
    provenance = _native_seed_provenance(stats, address)
    code_labels = _native_code_labels(stats, address)
    scan_rejections = _native_scan_rejections(stats, address)
    head = _native_head_bytes(binary_path, address)
    actual_state = "strict_function" if address in entry_vas else "candidate_or_label"
    reason_codes = _native_reason_codes(
        actual_state=actual_state,
        seed_kind=seed_kind,
        provenance=provenance,
        code_labels=code_labels,
        scan_rejections=scan_rejections,
        head=head,
        stats=stats,
    )
    status: ReplayCaseStatus = (
        "passed" if _state_matches_expected(actual_state, expected_state) else "failed"
    )
    expected_seed_kind = case.get("expected_seed_kind")
    normalized_expected_seed = (
        None
        if expected_seed_kind is None or str(expected_seed_kind).lower() == "none"
        else str(expected_seed_kind)
    )
    if expected_seed_kind is not None and normalized_expected_seed != seed_kind:
        status = "failed"
        reason_codes.append("expected_seed_kind_mismatch")
    details = [
        f"expected_state={expected_state}",
        f"actual_state={actual_state}",
        f"address={address_text}",
        f"binary_path={binary_path}",
        f"native_function_count={len(functions)}",
        f"native_seed_kind={seed_kind or 'none'}",
        f"native_truncated={bool(stats.get('truncated'))}",
        f"native_head_hex={head.hex() if head is not None else 'unmapped'}",
        "native_address_scan_rejections="
        + _format_native_address_scan_rejections(scan_rejections),
        "native_scan_rejection_counts=" + _format_native_scan_rejections(stats),
        "native_reason_codes=" + ",".join(reason_codes),
    ]
    if expected_seed_kind is not None:
        details.append(f"expected_seed_kind={expected_seed_kind}")
    return status, "native_glaurung_function_start_replay", details, reason_codes


def _native_seed_kind(stats: dict[str, Any], address: int) -> str | None:
    for item in stats.get("function_seed_kinds") or []:
        if not isinstance(item, dict):
            continue
        if int(item.get("va") or -1) == address:
            kind = item.get("kind")
            return str(kind) if kind is not None else None
    return None


def _native_seed_provenance(
    stats: dict[str, Any],
    address: int,
) -> list[dict[str, Any]]:
    return [
        item
        for item in stats.get("seed_provenance") or []
        if isinstance(item, dict) and int(item.get("target_va") or -1) == address
    ]


def _native_code_labels(
    stats: dict[str, Any],
    address: int,
) -> list[dict[str, Any]]:
    return [
        item
        for item in stats.get("code_labels") or []
        if isinstance(item, dict) and int(item.get("va") or -1) == address
    ]


def _native_scan_rejections(
    stats: dict[str, Any],
    address: int,
) -> list[dict[str, Any]]:
    return [
        item
        for item in stats.get("scan_rejections") or []
        if isinstance(item, dict) and int(item.get("va") or -1) == address
    ]


def _native_reason_codes(
    *,
    actual_state: str,
    seed_kind: str | None,
    provenance: list[dict[str, Any]],
    code_labels: list[dict[str, Any]],
    scan_rejections: list[dict[str, Any]],
    head: bytes | None,
    stats: dict[str, Any],
) -> list[str]:
    codes = [f"native_state:{actual_state}"]
    if seed_kind:
        codes.append(f"seed_kind:{seed_kind}")
    else:
        codes.append("seed_kind:none")
    for item in provenance[:8]:
        kind = item.get("kind")
        detail = item.get("detail")
        if kind:
            codes.append(f"seed_provenance_kind:{kind}")
        if detail:
            codes.append(f"seed_detail:{detail}")
    for item in code_labels[:8]:
        kind = item.get("kind")
        function_va = item.get("function_va")
        if kind:
            codes.append(f"code_label_kind:{kind}")
        if function_va is not None:
            codes.append(f"code_label_owner:0x{int(function_va):x}")
    for item in scan_rejections[:8]:
        reason = item.get("reason")
        source_va = item.get("source_va")
        if reason:
            codes.append(f"scan_rejection_at_address:{reason}")
        if source_va is not None:
            codes.append(f"scan_rejection_source:0x{int(source_va):x}")
    if bool(stats.get("truncated")):
        codes.append("native_analysis_truncated")
    scan_rejection_counts = stats.get("scan_rejection_counts") or {}
    if isinstance(scan_rejection_counts, dict):
        for reason, count in sorted(scan_rejection_counts.items())[:12]:
            if int(count or 0) > 0:
                codes.append(f"scan_rejection:{reason}")
    if head is None:
        codes.append("native_head_unmapped")
    else:
        if _is_simd_head(head):
            codes.append("native_head:simd")
        if _is_padding_run(head):
            codes.append("native_head:padding")
        if _is_tiny_return_helper(head):
            codes.append("native_head:tiny_return_helper")
        if head.startswith(b"\x48\xff\x25") or head.startswith(b"\xff\x25"):
            codes.append("native_head:indirect_jump_thunk_shape")
    return _dedupe(codes)


def _format_native_address_scan_rejections(
    scan_rejections: list[dict[str, Any]],
) -> str:
    parts: list[str] = []
    for item in scan_rejections[:16]:
        reason = str(item.get("reason") or "unknown")
        detail = str(item.get("detail") or "")
        source_va = item.get("source_va")
        if source_va is not None:
            reason = f"{reason}@0x{int(source_va):x}"
        parts.append(f"{reason}:{detail}" if detail else reason)
    return ",".join(parts) if parts else "none"


def _format_native_scan_rejections(stats: dict[str, Any]) -> str:
    scan_rejections = stats.get("scan_rejection_counts") or {}
    if not isinstance(scan_rejections, dict):
        return "none"
    parts = [
        f"{reason}:{count}"
        for reason, count in sorted(scan_rejections.items())
        if int(count or 0) > 0
    ]
    return ",".join(parts[:16]) if parts else "none"


def _native_head_bytes(binary_path: Path, address: int) -> bytes | None:
    try:
        offset = g.analysis.va_to_file_offset_path(  # ty: ignore[unresolved-attribute]
            str(binary_path),
            address,
        )
    except Exception:
        return None
    if offset is None:
        return None
    data = binary_path.read_bytes()
    start = int(offset)
    return data[start : start + 16]


def _scanner_case_signal(
    rule_id: str,
    case: dict[str, Any],
) -> tuple[ReplayCaseStatus, str, list[str]] | None:
    bytes_hex = case.get("bytes_hex")
    if not isinstance(bytes_hex, str) or not bytes_hex.strip():
        return None
    expected_state = str(case.get("expected_state") or "")
    address = str(case.get("address") or "")
    try:
        blob = bytes.fromhex("".join(bytes_hex.split()))
    except ValueError as exc:
        return "failed", "concrete_bytes_invalid_hex", [str(exc)]
    actual_state, reason = _scanner_replay_state(rule_id, case, blob)
    status: ReplayCaseStatus = (
        "passed" if _state_matches_expected(actual_state, expected_state) else "failed"
    )
    details = [
        f"expected_state={expected_state}",
        f"actual_state={actual_state}",
        f"reason={reason}",
        f"bytes={bytes_hex}",
    ]
    if address:
        details.append(f"address={address}")
    return status, "concrete_bytes_replay", details


def _scanner_replay_state(
    rule_id: str,
    case: dict[str, Any],
    blob: bytes,
) -> tuple[str, str]:
    if rule_id == "win-pe-import-thunk-shape-catalog":
        if blob.startswith(b"\x48\xff\x25") or blob.startswith(b"\xff\x25"):
            if bool(case.get("has_import_target")):
                return "strict_function", "rip_relative_import_thunk_with_target"
            return "candidate_or_label", "rip_relative_indirect_jump_without_import"
        return "candidate_or_label", "not_import_thunk_shape"
    if rule_id == "win-pe-tiny-stub-provenance-gate":
        if _is_tiny_return_helper(blob):
            if bool(case.get("has_xref")) or bool(case.get("has_table_provenance")):
                return "strict_function", "tiny_return_helper_with_provenance"
            return "candidate_or_label", "tiny_return_helper_without_provenance"
        return "candidate_or_label", "not_tiny_return_helper"
    if rule_id == "win-pe-data-ref-padding-boundary-gate":
        if _is_padding_run(blob):
            return "label_or_rejected_start", "padding_run_bytes"
        if bool(case.get("has_table_provenance")):
            return "strict_function", "data_ref_with_table_provenance"
        return "candidate_or_label", "data_ref_without_table_provenance"
    if rule_id == "win-pe-internal-start-body-split-candidates":
        if bool(case.get("shared_epilogue")):
            return "candidate_or_label", "shared_epilogue_control"
        if bool(case.get("owner_function")) and bool(case.get("has_xref")):
            return "body_split_candidate", "internal_start_with_owner_and_xref"
        return "candidate_or_label", "internal_start_without_split_evidence"
    return "candidate_or_label", "unsupported_concrete_rule"


def _state_matches_expected(actual_state: str, expected_state: str) -> bool:
    if actual_state == expected_state:
        return True
    acceptable = {
        "candidate_or_label": {"candidate_or_label", "candidate", "label"},
        "label_or_rejected_start": {
            "label_or_rejected_start",
            "label",
            "rejected_start",
        },
    }
    return actual_state in acceptable.get(expected_state, set())


def _is_tiny_return_helper(blob: bytes) -> bool:
    return blob in {
        b"\xc3",
        b"\x31\xc0\xc3",
        b"\x33\xc0\xc3",
    } or (len(blob) >= 3 and blob[0] == 0xC2)


def _is_padding_run(blob: bytes) -> bool:
    return bool(blob) and all(byte in {0x00, 0x90, 0xCC} for byte in blob)


def _is_simd_head(blob: bytes) -> bool:
    return (
        len(blob) >= 2
        and blob[0] == 0x0F
        and blob[1] in {0x10, 0x11, 0x28, 0x29, 0x6F, 0x7F}
    ) or bool(blob and blob[0] in {0xC4, 0xC5, 0x62})


def _tiny_stub_signal(
    seed_class: str,
    rows: list[dict[str, Any]],
) -> tuple[ReplayCaseStatus, str, list[str]]:
    tiny_total = sum(_seed_count(row, seed_class) for row in rows)
    extra_total = sum(_gap(row, "extra_entries") for row in rows)
    if tiny_total > 0 and extra_total > 0:
        return (
            "passed",
            "tiny_stub_precision_fixture_covered",
            [f"tiny_stub_seeds={tiny_total}", f"extra_entries={extra_total}"],
        )
    return "failed", "tiny_stub_signal_absent", [f"tiny_stub_seeds={tiny_total}"]


def _data_ref_signal(
    case_text: str,
    rows: list[dict[str, Any]],
    rows_by_file: dict[str, dict[str, Any]],
) -> tuple[ReplayCaseStatus, str, list[str]]:
    if "surfacepen" in case_text:
        row = rows_by_file.get("windows-update-SurfacePenBleLcAddrAdaptationDriver.sys")
        if (
            row
            and _gap(row, "missing_entries") == 0
            and _gap(row, "extra_entries") == 0
        ):
            return "passed", "surfacepen_callback_table_parity", [_row_summary(row)]
        return "failed", "surfacepen_callback_table_not_parity", []
    data_ref_total = sum(_seed_count(row, "data_ref") for row in rows)
    if data_ref_total > 0:
        return (
            "passed",
            "data_ref_padding_fixture_covered",
            [f"data_ref_seeds={data_ref_total}"],
        )
    return "failed", "data_ref_signal_absent", []


def _import_thunk_signal(
    case_text: str,
    rows: list[dict[str, Any]],
) -> tuple[ReplayCaseStatus, str, list[str]]:
    if "synthetic" in case_text:
        return "passed", "synthetic_negative_thunk_shape_present", []
    missing_thunks = sum(_gap(row, "missing_thunks") for row in rows)
    if missing_thunks > 0:
        return (
            "passed",
            "import_thunk_recall_fixture_covered",
            [f"missing_thunks={missing_thunks}"],
        )
    return "failed", "import_thunk_gap_absent", []


def _body_split_signal(
    case_text: str,
    rows: list[dict[str, Any]],
    rows_by_file: dict[str, dict[str, Any]],
) -> tuple[ReplayCaseStatus, str, list[str]]:
    if "syncinfrastructure" in case_text or "acledit" in case_text:
        controls = [
            rows_by_file.get("win11-SyncInfrastructureps.dll"),
            rows_by_file.get("win11-acledit.dll"),
        ]
        if any(row and _gap(row, "missing_entries") <= 2 for row in controls):
            return "passed", "shared_epilogue_control_fixture_covered", []
        return "failed", "shared_epilogue_control_absent", []
    body_rows = [
        row
        for row in rows
        if "webservices" in str(row.get("file", "")).lower()
        or "rtkauduservice" in str(row.get("file", "")).lower()
    ]
    missing_total = sum(_gap(row, "missing_entries") for row in body_rows)
    if missing_total > 0:
        return (
            "passed",
            "body_split_recall_fixture_covered",
            [f"body_split_missing_entries={missing_total}"],
        )
    return "failed", "body_split_signal_absent", []


def _seed_count(row: dict[str, Any], seed_class: str) -> int:
    stats = (row.get("glaurung") or {}).get("stats") or {}
    counts = stats.get("seed_kind_counts") or {}
    return int(counts.get(seed_class) or 0)


def _gap(row: dict[str, Any], key: str) -> int:
    return int((row.get("address_gap") or {}).get(key) or 0)


def _row_summary(row: dict[str, Any]) -> str:
    return (
        f"{row.get('file')}: missing={_gap(row, 'missing_entries')} "
        f"extra={_gap(row, 'extra_entries')}"
    )


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def build_tool() -> WindowsFunctionizationRuleReplayTool:
    return WindowsFunctionizationRuleReplayTool()
