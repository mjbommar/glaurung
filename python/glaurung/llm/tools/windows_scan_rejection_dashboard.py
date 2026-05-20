"""Corpus dashboard for Windows scanner rejection gates."""

from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path
from typing import Any, Literal

import glaurung as g
from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Edge, Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .windows_agent_evidence_bundle import (
    WindowsEvidenceBundle,
    WindowsEvidenceCoverage,
    WindowsEvidenceSubject,
    evidence_ref,
    make_windows_evidence_bundle,
)


DEFAULT_DIAGNOSTICS = (
    "docs/windows-port/glaurung_vs_ghidra_vendor_windows_30_diagnostics.json"
)

RejectionSampleSource = Literal["cached", "native"]
RecallRiskLevel = Literal["low", "medium", "high", "unknown"]


class WindowsScanRejectionDashboardArgs(BaseModel):
    diagnostics_path: str = Field(
        DEFAULT_DIAGNOSTICS,
        description=(
            "Glaurung-vs-Ghidra diagnostics JSON. Rows may contain cached "
            "stats.scan_rejection_counts and stats.scan_rejections."
        ),
    )
    file: str | None = Field(
        None,
        description="Optional binary filename or path substring filter.",
    )
    include_native_scan: bool = Field(
        False,
        description=(
            "If true, rerun native function discovery for matching local PE "
            "paths and compute address-level rejected-start/Ghidra-missing hits."
        ),
    )
    max_native_files: int = Field(3, ge=0, le=64)
    max_rows: int = Field(24, ge=0, le=256)
    max_samples_per_reason: int = Field(4, ge=0, le=32)
    max_read_bytes: int = Field(104_857_600, ge=1)
    max_file_size: int = Field(104_857_600, ge=1)
    max_functions: int = Field(0, ge=0)
    max_blocks: int = Field(1_000_000, ge=1)
    max_instructions: int = Field(30_000_000, ge=1)
    timeout_ms: int = Field(600_000, ge=1)
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact scan-rejection dashboard node to the KB.",
    )


class WindowsScanRejectionSample(BaseModel):
    file: str
    path: str
    reason: str
    source: RejectionSampleSource
    va: int | None = None
    address: str | None = None
    source_va: int | None = None
    source_address: str | None = None
    detail: str | None = None
    ghidra_missing_match: bool = False


class WindowsScanRejectionReasonRow(BaseModel):
    reason: str
    count: int
    cached_count: int = 0
    native_count: int = 0
    file_count: int
    affected_files: list[str] = Field(default_factory=list)
    ghidra_missing_address_hits: int = 0
    precision_guard_count: int = 0
    estimated_precision_guard_ratio: float | None = None
    missing_entry_context: int = 0
    extra_entry_context: int = 0
    recall_risk_level: RecallRiskLevel = "unknown"
    next_action: str
    reason_codes: list[str] = Field(default_factory=list)
    samples: list[WindowsScanRejectionSample] = Field(default_factory=list)


class WindowsScanRejectionDashboardResult(BaseModel):
    claim_level: str = "scan_rejection_dashboard_not_finding"
    diagnostics_path: str
    file_filter: str | None = None
    file_count_total: int
    filtered_file_count: int
    native_file_count: int
    reason_count: int
    total_rejection_count: int
    total_ghidra_missing_address_hits: int
    rows: list[WindowsScanRejectionReasonRow]
    evidence_bundle: WindowsEvidenceBundle
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


@dataclass
class _ReasonAccumulator:
    cached_count: int = 0
    native_count: int = 0
    files: list[str] = field(default_factory=list)
    missing_entry_context: int = 0
    extra_entry_context: int = 0
    ghidra_missing_address_hits: int = 0
    samples: list[WindowsScanRejectionSample] = field(default_factory=list)


class WindowsScanRejectionDashboardTool(
    MemoryTool[
        WindowsScanRejectionDashboardArgs,
        WindowsScanRejectionDashboardResult,
    ]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_scan_rejection_dashboard",
                description=(
                    "Summarize Windows scanner rejection gates across a corpus, "
                    "including address-level recall-risk hits when rejected VAs "
                    "overlap Ghidra-only starts."
                ),
                tags=("windows", "pe", "functionization", "scanner", "dashboard"),
            ),
            WindowsScanRejectionDashboardArgs,
            WindowsScanRejectionDashboardResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsScanRejectionDashboardArgs,
    ) -> WindowsScanRejectionDashboardResult:
        diagnostics_path = Path(args.diagnostics_path).expanduser()
        raw_rows = _load_json_rows(diagnostics_path)
        rows = _filter_rows(raw_rows, args.file)
        accumulators: dict[str, _ReasonAccumulator] = {}
        native_file_count = 0

        for row in rows:
            _add_cached_row(accumulators, row, args.max_samples_per_reason)

        if args.include_native_scan and args.max_native_files:
            for row in rows:
                path = Path(str(row.get("path") or row.get("file") or ""))
                if not path.exists():
                    continue
                _add_native_row(accumulators, row, path, args)
                native_file_count += 1
                if native_file_count >= args.max_native_files:
                    break

        reason_rows = _reason_rows(accumulators, args.max_rows)
        notes = [
            "Scan-rejection dashboard is functionization quality telemetry, not a vulnerability finding.",
            "Address-level recall risk requires stats.scan_rejections or include_native_scan=true.",
        ]
        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_scan_rejection_dashboard",
                    props={
                        "diagnostics_path": str(diagnostics_path),
                        "file": args.file,
                        "reason_count": len(reason_rows),
                        "total_rejection_count": sum(row.count for row in reason_rows),
                        "native_file_count": native_file_count,
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))

        return WindowsScanRejectionDashboardResult(
            diagnostics_path=str(diagnostics_path),
            file_filter=args.file,
            file_count_total=len(raw_rows),
            filtered_file_count=len(rows),
            native_file_count=native_file_count,
            reason_count=len(reason_rows),
            total_rejection_count=sum(row.count for row in reason_rows),
            total_ghidra_missing_address_hits=sum(
                row.ghidra_missing_address_hits for row in reason_rows
            ),
            rows=reason_rows,
            evidence_bundle=_evidence_bundle(
                diagnostics_path=str(diagnostics_path),
                file_filter=args.file,
                rows=reason_rows,
                file_count=len(rows),
                native_file_count=native_file_count,
                notes=notes,
            ),
            evidence_node_id=evidence_node_id,
            notes=notes,
        )


def _load_json_rows(path: Path) -> list[dict[str, Any]]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ValueError(f"{path}: expected a JSON row list")
    return [row for row in raw if isinstance(row, dict)]


def _filter_rows(rows: list[dict[str, Any]], file_filter: str | None) -> list[dict[str, Any]]:
    if not file_filter:
        return rows
    needle = file_filter.lower()
    out: list[dict[str, Any]] = []
    for row in rows:
        file_name = str(row.get("file") or Path(str(row.get("path") or "")).name)
        path = str(row.get("path") or "")
        if needle in file_name.lower() or needle in path.lower():
            out.append(row)
    return out


def _add_cached_row(
    accumulators: dict[str, _ReasonAccumulator],
    row: dict[str, Any],
    max_samples_per_reason: int,
) -> None:
    stats = _stats(row)
    missing_vas = _missing_vas(row)
    counts = _rejection_counts(stats)
    records = _scan_rejection_records(stats)
    record_counts = _record_counts(records)
    for reason, count in record_counts.items():
        counts.setdefault(reason, count)
    file_name = _file_name(row)
    missing_count = _missing_count(row)
    extra_count = _extra_count(row)
    for reason, count in counts.items():
        acc = accumulators.setdefault(reason, _ReasonAccumulator())
        acc.cached_count += count
        _append_unique(acc.files, file_name)
        acc.missing_entry_context += missing_count
        acc.extra_entry_context += extra_count
    for record in records:
        reason = str(record.get("reason") or "")
        if not reason:
            continue
        acc = accumulators.setdefault(reason, _ReasonAccumulator())
        sample = _sample_from_record(
            row=row,
            record=record,
            source="cached",
            missing_vas=missing_vas,
        )
        if sample.ghidra_missing_match:
            acc.ghidra_missing_address_hits += 1
        if len(acc.samples) < max_samples_per_reason:
            acc.samples.append(sample)


def _add_native_row(
    accumulators: dict[str, _ReasonAccumulator],
    row: dict[str, Any],
    path: Path,
    args: WindowsScanRejectionDashboardArgs,
) -> None:
    _functions, _callgraph, native_stats = g.analysis.analyze_functions_path_with_stats(  # ty: ignore[unresolved-attribute]
        str(path),
        args.max_read_bytes,
        args.max_file_size,
        args.max_functions,
        args.max_blocks,
        args.max_instructions,
        args.timeout_ms,
    )
    stats = dict(native_stats)
    missing_vas = _missing_vas(row)
    counts = _rejection_counts(stats)
    records = _scan_rejection_records(stats)
    record_counts = _record_counts(records)
    for reason, count in record_counts.items():
        counts.setdefault(reason, count)
    file_name = _file_name(row)
    missing_count = _missing_count(row)
    extra_count = _extra_count(row)
    native_row = dict(row)
    native_row["path"] = str(path)
    for reason, count in counts.items():
        acc = accumulators.setdefault(reason, _ReasonAccumulator())
        acc.native_count += count
        _append_unique(acc.files, file_name)
        acc.missing_entry_context += missing_count
        acc.extra_entry_context += extra_count
    for record in records:
        reason = str(record.get("reason") or "")
        if not reason:
            continue
        acc = accumulators.setdefault(reason, _ReasonAccumulator())
        sample = _sample_from_record(
            row=native_row,
            record=record,
            source="native",
            missing_vas=missing_vas,
        )
        if sample.ghidra_missing_match:
            acc.ghidra_missing_address_hits += 1
        if len(acc.samples) < args.max_samples_per_reason:
            acc.samples.append(sample)


def _reason_rows(
    accumulators: dict[str, _ReasonAccumulator],
    max_rows: int,
) -> list[WindowsScanRejectionReasonRow]:
    rows: list[WindowsScanRejectionReasonRow] = []
    for reason, acc in accumulators.items():
        count = acc.cached_count + acc.native_count
        if count <= 0:
            continue
        precision_guard_count = max(0, count - acc.ghidra_missing_address_hits)
        ratio = precision_guard_count / count if count else None
        rows.append(
            WindowsScanRejectionReasonRow(
                reason=reason,
                count=count,
                cached_count=acc.cached_count,
                native_count=acc.native_count,
                file_count=len(acc.files),
                affected_files=acc.files[:16],
                ghidra_missing_address_hits=acc.ghidra_missing_address_hits,
                precision_guard_count=precision_guard_count,
                estimated_precision_guard_ratio=ratio,
                missing_entry_context=acc.missing_entry_context,
                extra_entry_context=acc.extra_entry_context,
                recall_risk_level=_recall_risk(acc),
                next_action=_next_action(reason, acc),
                reason_codes=_reason_codes(reason, acc),
                samples=acc.samples,
            )
        )
    rows.sort(
        key=lambda row: (
            -_risk_priority(row.recall_risk_level),
            -row.ghidra_missing_address_hits,
            -row.count,
            row.reason,
        )
    )
    return rows[:max_rows]


def _stats(row: dict[str, Any]) -> dict[str, Any]:
    direct = row.get("stats")
    if isinstance(direct, dict):
        return direct
    glaurung = row.get("glaurung")
    if isinstance(glaurung, dict) and isinstance(glaurung.get("stats"), dict):
        return glaurung["stats"]
    return {}


def _rejection_counts(stats: dict[str, Any]) -> dict[str, int]:
    counts: dict[str, int] = {}
    raw_counts = stats.get("scan_rejection_counts")
    if isinstance(raw_counts, dict):
        for reason, count in raw_counts.items():
            if isinstance(reason, str) and isinstance(count, int) and count > 0:
                counts[reason] = count
    for key, value in stats.items():
        if (
            isinstance(key, str)
            and key.endswith("_rejected")
            and isinstance(value, int)
            and value > 0
        ):
            counts.setdefault(key, value)
    return counts


def _scan_rejection_records(stats: dict[str, Any]) -> list[dict[str, Any]]:
    records = stats.get("scan_rejections")
    if not isinstance(records, list):
        return []
    return [record for record in records if isinstance(record, dict)]


def _record_counts(records: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for record in records:
        reason = record.get("reason")
        if isinstance(reason, str) and reason:
            counts[reason] = counts.get(reason, 0) + 1
    return counts


def _sample_from_record(
    *,
    row: dict[str, Any],
    record: dict[str, Any],
    source: RejectionSampleSource,
    missing_vas: set[int],
) -> WindowsScanRejectionSample:
    va = _parse_int(record.get("va"))
    source_va = _parse_int(record.get("source_va"))
    return WindowsScanRejectionSample(
        file=_file_name(row),
        path=str(row.get("path") or ""),
        reason=str(record.get("reason") or ""),
        source=source,
        va=va,
        address=_hex(va),
        source_va=source_va,
        source_address=_hex(source_va),
        detail=str(record.get("detail")) if record.get("detail") is not None else None,
        ghidra_missing_match=va in missing_vas if va is not None else False,
    )


def _missing_vas(row: dict[str, Any]) -> set[int]:
    out: set[int] = set()
    for item in row.get("missing") or []:
        if not isinstance(item, dict):
            continue
        value = (
            item.get("va")
            if item.get("va") is not None
            else item.get("address", item.get("entry"))
        )
        parsed = _parse_int(value)
        if parsed is not None:
            out.add(parsed)
    gap = row.get("address_gap")
    if isinstance(gap, dict):
        for item in gap.get("sample_missing") or []:
            if not isinstance(item, dict):
                continue
            parsed = _parse_int(item.get("va", item.get("entry")))
            if parsed is not None:
                out.add(parsed)
    return out


def _missing_count(row: dict[str, Any]) -> int:
    if isinstance(row.get("missing_count"), int):
        return int(row["missing_count"])
    gap = row.get("address_gap")
    if isinstance(gap, dict) and isinstance(gap.get("missing_entries"), int):
        return int(gap["missing_entries"])
    missing = row.get("missing")
    return len(missing) if isinstance(missing, list) else 0


def _extra_count(row: dict[str, Any]) -> int:
    if isinstance(row.get("extra_count"), int):
        return int(row["extra_count"])
    gap = row.get("address_gap")
    if isinstance(gap, dict) and isinstance(gap.get("extra_entries"), int):
        return int(gap["extra_entries"])
    extra = row.get("extra")
    return len(extra) if isinstance(extra, list) else 0


def _file_name(row: dict[str, Any]) -> str:
    if isinstance(row.get("file"), str):
        return str(row["file"])
    path = str(row.get("path") or "")
    return Path(path).name if path else "<unknown>"


def _recall_risk(acc: _ReasonAccumulator) -> RecallRiskLevel:
    if acc.ghidra_missing_address_hits > 0:
        return "high"
    if acc.samples:
        return "low"
    if acc.missing_entry_context > 0:
        return "medium"
    return "unknown"


def _reason_codes(reason: str, acc: _ReasonAccumulator) -> list[str]:
    codes = ["scan_rejection_reason", f"reason:{reason}"]
    if acc.ghidra_missing_address_hits:
        codes.append("address_rejection_overlaps_ghidra_missing")
    if acc.native_count:
        codes.append("native_scan_replay")
    if acc.cached_count:
        codes.append("cached_dashboard_stats")
    if acc.missing_entry_context and not acc.ghidra_missing_address_hits:
        codes.append("aggregate_missing_context_without_address_hit")
    return codes


def _next_action(reason: str, acc: _ReasonAccumulator) -> str:
    if acc.ghidra_missing_address_hits:
        return (
            "Inspect rejected Ghidra-missing addresses with "
            "windows_function_start_explain before tightening or loosening this gate."
        )
    if acc.samples:
        return (
            "Spot-check representative rejected addresses and keep this as a "
            "precision guard unless a Ghidra-missing hit appears."
        )
    if "pdata" in reason:
        return "Refresh the parity dashboard with per-address .pdata rejection records."
    return "Refresh diagnostics with per-address scan_rejections for this reason."


def _risk_priority(level: RecallRiskLevel) -> int:
    return {"high": 3, "medium": 2, "low": 1, "unknown": 0}[level]


def _evidence_bundle(
    *,
    diagnostics_path: str,
    file_filter: str | None,
    rows: list[WindowsScanRejectionReasonRow],
    file_count: int,
    native_file_count: int,
    notes: list[str],
) -> WindowsEvidenceBundle:
    total_hits = sum(row.ghidra_missing_address_hits for row in rows)
    return make_windows_evidence_bundle(
        claim_level="functionization_review_not_vulnerability",
        subject=WindowsEvidenceSubject(
            kind="functionization",
            file=file_filter,
            attributes={
                "diagnostics_path": diagnostics_path,
                "file_count": file_count,
                "native_file_count": native_file_count,
                "reason_count": len(rows),
                "total_rejection_count": sum(row.count for row in rows),
                "ghidra_missing_address_hits": total_hits,
            },
        ),
        source_tools=["windows_scan_rejection_dashboard"],
        tool_sequence=["windows_scan_rejection_dashboard"],
        evidence_refs=[
            evidence_ref(
                kind="tool_result",
                source="windows_scan_rejection_dashboard",
                summary=(
                    f"{row.reason}: count={row.count} "
                    f"missing_hits={row.ghidra_missing_address_hits}"
                ),
                confidence=row.estimated_precision_guard_ratio,
                reason_codes=row.reason_codes,
                provenance=[diagnostics_path, *row.affected_files[:4]],
            )
            for row in rows[:8]
        ],
        coverage=WindowsEvidenceCoverage(
            ghidra_missing_entries=total_hits,
            missing_capabilities=[
                row.reason
                for row in rows
                if row.recall_risk_level in {"medium", "unknown"}
            ],
            stale_or_blocking_facts=[
                row.reason for row in rows if row.recall_risk_level == "high"
            ],
            validation_ready=total_hits == 0,
        ),
        reason_codes=[
            "scan_rejection_dashboard_not_finding",
            *[code for row in rows[:8] for code in row.reason_codes],
        ],
        blockers=[
            row.reason for row in rows if row.ghidra_missing_address_hits > 0
        ],
        next_actions=_dedupe([row.next_action for row in rows[:8]]),
        notes=notes,
    )


def _parse_int(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        try:
            return int(text, 0)
        except ValueError:
            return None
    return None


def _hex(value: int | None) -> str | None:
    return None if value is None else f"0x{value:x}"


def _append_unique(values: list[str], value: str) -> None:
    if value and value not in values:
        values.append(value)


def _dedupe(values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value and value not in seen:
            seen.add(value)
            out.append(value)
    return out


def build_tool() -> WindowsScanRejectionDashboardTool:
    return WindowsScanRejectionDashboardTool()
