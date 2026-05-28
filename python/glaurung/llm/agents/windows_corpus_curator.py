"""Deterministic Windows regression-corpus curation workflow."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Literal

import glaurung as g
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


CorpusSuite = Literal["fast_baseline", "stress"]
CorpusBinaryKind = Literal["exe", "dll", "sys", "other"]

FAST_BASELINE_FILES = {
    "win10-vwififlt.sys",
    "win10-audmigplugin.dll",
    "win11-SyncInfrastructureps.dll",
    "win11-acledit.dll",
    "win8-pciidex.sys",
    "windows-update-keysink.exe",
    "windows-update-SurfacePenBleLcAddrAdaptationDriver.sys",
    "sqfs-amd-clinfo.exe",
    "sqfs-intel-DptfParticipantDisplayService.exe",
    "sqfs-intel-DptfDevGen.sys",
}


class WindowsCorpusFixtureRecord(BaseModel):
    file: str
    path: str
    suite: CorpusSuite
    source_label: str | None = None
    source_path: str | None = None
    file_description: str | None = None
    binary_kind: CorpusBinaryKind
    architecture: str
    size_bytes: int
    sha256: str
    pdb_status: str
    stress_purpose: list[str] = Field(default_factory=list)
    ghidra_internal_functions: int | None = None
    glaurung_functions: int | None = None
    missing_entries: int | None = None
    extra_entries: int | None = None


class WindowsCorpusDuplicateClass(BaseModel):
    key: str
    files: list[str]
    reason: str


CorpusManifestDriftReason = Literal[
    "missing_manifest",
    "missing_manifest_entry",
    "stale_manifest_entry",
    "stale_manifest_field",
    "missing_dashboard_entry",
    "missing_local_file",
]


class WindowsCorpusManifestDrift(BaseModel):
    file: str
    field: str
    reason: CorpusManifestDriftReason
    current: Any = None
    recorded: Any = None


class WindowsCorpusAcceptedDrift(BaseModel):
    file: str
    field: str
    acceptance_reason: str = Field(min_length=1)
    drift_reason: CorpusManifestDriftReason | None = None
    current: Any = None
    recorded: Any = None
    expires_utc_date: str | None = None


class WindowsCorpusAcceptedDriftMatch(BaseModel):
    drift: WindowsCorpusManifestDrift
    acceptance: WindowsCorpusAcceptedDrift


class WindowsCorpusCuratorConfig(BaseModel):
    corpus_root: str = "samples/binaries/platforms/windows/vendor/realworld"
    comparison_path: str = "docs/windows-port/glaurung_vs_ghidra_vendor_windows_30_after_tiny_stub_gate.json"
    manifest_path: str | None = None
    accepted_drift_path: str | None = Field(
        None,
        description=(
            "Optional JSON policy file listing intentionally accepted drift "
            "items. Matching entries keep drift visible but exclude it from "
            "fail_on_drift failures."
        ),
    )
    review_notes_path: str | None = Field(
        None,
        description=(
            "Optional markdown path for a corpus review/release note that "
            "summarizes dashboard state, drift policy, and follow-up commands."
        ),
    )
    write_manifest: bool = Field(
        False,
        description=(
            "If true, write an enriched corpus manifest. Defaults to a dry-run "
            "inventory so review agents do not mutate the tree implicitly."
        ),
    )
    fail_on_drift: bool = Field(
        False,
        description=(
            "If true, raise when manifest, local corpus files, and cached "
            "dashboard rows are not synchronized. Intended for CI drift guards."
        ),
    )
    max_selected: int = Field(12, ge=1, le=64)


class WindowsCorpusCuratorResult(BaseModel):
    claim_level: str = "corpus_curation_not_analysis"
    fixture_count: int
    selected_fixtures: list[WindowsCorpusFixtureRecord]
    all_fixtures: list[WindowsCorpusFixtureRecord]
    duplicate_classes: list[WindowsCorpusDuplicateClass]
    missing_dashboard_entries: list[str]
    missing_local_files: list[str]
    manifest_drift: list[WindowsCorpusManifestDrift]
    manifest_drift_count: int
    accepted_drift: list[WindowsCorpusAcceptedDriftMatch]
    accepted_drift_count: int
    unaccepted_manifest_drift: list[WindowsCorpusManifestDrift]
    unaccepted_manifest_drift_count: int
    accepted_drift_path: str | None = None
    drift_guard_passed: bool
    fast_baseline_count: int
    stress_count: int
    binary_kind_counts: dict[str, int]
    manifest_path: str
    manifest_written: bool
    manifest_fixture_count: int
    review_notes_markdown: str
    review_notes_path: str | None = None
    dashboard_refresh_commands: list[str]
    tool_sequence: list[str]
    evidence_bundle: WindowsEvidenceBundle
    notes: list[str] = Field(default_factory=list)


def run_windows_corpus_curator(
    config: WindowsCorpusCuratorConfig,
) -> WindowsCorpusCuratorResult:
    _ctx()
    corpus_root = Path(config.corpus_root)
    manifest_path = _manifest_path(corpus_root, config.manifest_path)
    manifest_records = _load_manifest_records(manifest_path)
    accepted_drift_policy = _load_accepted_drift(config.accepted_drift_path)
    comparison_rows = _load_comparison(Path(config.comparison_path))
    rows_by_file = {str(row.get("file") or ""): row for row in comparison_rows}
    local_files = _local_pe_files(corpus_root)
    local_by_name = {path.name: path for path in local_files}
    records = [
        _fixture_record(
            path,
            rows_by_file.get(path.name),
            corpus_root,
            manifest_records.get(path.name),
        )
        for path in local_files
    ]
    selected = _select_diverse(records, config.max_selected)
    missing_dashboard = sorted(
        name for name in local_by_name if name not in rows_by_file
    )
    missing_local = sorted(name for name in rows_by_file if name not in local_by_name)
    duplicates = _duplicate_classes(records)
    notes = [
        "Corpus curation records provenance and dashboard coverage; it does not run Ghidra itself.",
        "Use the dashboard refresh command after adding or replacing vendored fixtures.",
    ]
    if config.write_manifest:
        _write_manifest(
            manifest_path=manifest_path,
            records=records,
            source_manifest=manifest_path if manifest_path.exists() else None,
        )
        manifest_records = _load_manifest_records(manifest_path)
        notes.append(f"wrote enriched corpus manifest to {manifest_path}")
    manifest_drift = _manifest_drift(
        manifest_path=manifest_path,
        manifest_records=manifest_records,
        records=records,
        missing_dashboard=missing_dashboard,
        missing_local=missing_local,
    )
    accepted_drift, unaccepted_manifest_drift = _classify_manifest_drift(
        manifest_drift,
        accepted_drift_policy,
    )
    if manifest_drift:
        notes.append(f"detected {len(manifest_drift)} corpus manifest drift item(s)")
    if accepted_drift:
        notes.append(
            f"accepted {len(accepted_drift)} intentional corpus drift item(s)"
        )
    if unaccepted_manifest_drift:
        notes.append(
            f"{len(unaccepted_manifest_drift)} corpus drift item(s) remain unaccepted"
        )
    else:
        notes.append("manifest/local/dashboard drift guard passed")
    if config.fail_on_drift and unaccepted_manifest_drift:
        raise ValueError(
            "Windows corpus drift guard failed with "
            f"{len(unaccepted_manifest_drift)} unaccepted item(s) "
            f"({len(accepted_drift)} accepted)"
        )
    commands = [
        "python scripts/windows_ghidra_parity.py "
        "--windows-root samples/binaries/platforms/windows/vendor/realworld "
        "--out-json docs/windows-port/glaurung_vs_ghidra_vendor_windows_30_after_tiny_stub_gate.json"
    ]
    tool_sequence = [
        "windows_corpus_curator:local_inventory",
        "cached_ghidra_dashboard",
    ]
    if config.accepted_drift_path:
        tool_sequence.append("windows_corpus_curator:accepted_drift_policy")
    review_notes_markdown = _review_notes_markdown(
        config=config,
        fixture_count=len(records),
        fast_baseline_count=sum(
            1 for record in records if record.suite == "fast_baseline"
        ),
        stress_count=sum(1 for record in records if record.suite == "stress"),
        manifest_path=manifest_path,
        manifest_drift=manifest_drift,
        accepted_drift=accepted_drift,
        unaccepted_manifest_drift=unaccepted_manifest_drift,
        dashboard_refresh_commands=commands,
        selected=selected,
    )
    if config.review_notes_path:
        _write_review_notes(config.review_notes_path, review_notes_markdown)
        tool_sequence.append("windows_corpus_curator:write_review_notes")
    return WindowsCorpusCuratorResult(
        fixture_count=len(records),
        selected_fixtures=selected,
        all_fixtures=records,
        duplicate_classes=duplicates,
        missing_dashboard_entries=missing_dashboard,
        missing_local_files=missing_local,
        manifest_drift=manifest_drift,
        manifest_drift_count=len(manifest_drift),
        accepted_drift=accepted_drift,
        accepted_drift_count=len(accepted_drift),
        unaccepted_manifest_drift=unaccepted_manifest_drift,
        unaccepted_manifest_drift_count=len(unaccepted_manifest_drift),
        accepted_drift_path=config.accepted_drift_path,
        drift_guard_passed=not unaccepted_manifest_drift,
        fast_baseline_count=sum(
            1 for record in records if record.suite == "fast_baseline"
        ),
        stress_count=sum(1 for record in records if record.suite == "stress"),
        binary_kind_counts=_kind_counts(records),
        manifest_path=str(manifest_path),
        manifest_written=config.write_manifest,
        manifest_fixture_count=len(records),
        review_notes_markdown=review_notes_markdown,
        review_notes_path=config.review_notes_path,
        dashboard_refresh_commands=commands,
        tool_sequence=tool_sequence,
        evidence_bundle=_evidence_bundle(
            config=config,
            records=records,
            selected=selected,
            duplicates=duplicates,
            missing_dashboard=missing_dashboard,
            missing_local=missing_local,
            manifest_drift=manifest_drift,
            accepted_drift=accepted_drift,
            unaccepted_manifest_drift=unaccepted_manifest_drift,
            tool_sequence=tool_sequence,
            notes=notes,
        ),
        notes=notes,
    )


def _load_comparison(path: Path) -> list[dict[str, Any]]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ValueError(f"{path}: expected comparison list")
    return [row for row in raw if isinstance(row, dict)]


def _local_pe_files(root: Path) -> list[Path]:
    if not root.exists():
        raise FileNotFoundError(root)
    return sorted(
        path
        for path in root.iterdir()
        if path.is_file() and path.suffix.lower() in {".exe", ".dll", ".sys"}
    )


def _fixture_record(
    path: Path,
    row: dict[str, Any] | None,
    corpus_root: Path,
    manifest_entry: dict[str, Any] | None,
) -> WindowsCorpusFixtureRecord:
    gap = (row or {}).get("address_gap") or {}
    glaurung = (row or {}).get("glaurung") or {}
    ghidra = (row or {}).get("ghidra") or {}
    ghidra_metrics = ghidra.get("metrics") or {}
    return WindowsCorpusFixtureRecord(
        file=path.name,
        path=_display_path(path),
        suite="fast_baseline" if path.name in FAST_BASELINE_FILES else "stress",
        source_label=(row or {}).get("source_label")
        or (manifest_entry or {}).get("source_label"),
        source_path=(manifest_entry or {}).get("source_path"),
        file_description=(manifest_entry or {}).get("file_description"),
        binary_kind=_binary_kind(path),
        architecture="x64-pe",
        size_bytes=path.stat().st_size,
        sha256=_sha256(path),
        pdb_status="unknown",
        stress_purpose=_stress_purpose(path.name, row),
        ghidra_internal_functions=ghidra_metrics.get("internal_functions"),
        glaurung_functions=glaurung.get("functions"),
        missing_entries=gap.get("missing_entries"),
        extra_entries=gap.get("extra_entries"),
    )


def _display_path(path: Path) -> str:
    try:
        return str(path.relative_to(Path.cwd()))
    except ValueError:
        return str(path)


def _manifest_path(corpus_root: Path, configured: str | None) -> Path:
    if configured:
        return Path(configured)
    return corpus_root / "MANIFEST.json"


def _load_manifest_records(path: Path) -> dict[str, dict[str, Any]]:
    if not path.exists():
        return {}
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        return {}
    fixtures = raw.get("fixtures")
    if not isinstance(fixtures, list):
        return {}
    records: dict[str, dict[str, Any]] = {}
    for fixture in fixtures:
        if not isinstance(fixture, dict):
            continue
        file_name = fixture.get("file")
        if isinstance(file_name, str) and file_name:
            records[file_name] = fixture
    return records


def _load_accepted_drift(path_text: str | None) -> list[WindowsCorpusAcceptedDrift]:
    if not path_text:
        return []
    path = Path(path_text)
    raw = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(raw, dict):
        entries = (
            raw.get("accepted_drift")
            or raw.get("acceptances")
            or raw.get("drift_acceptances")
            or []
        )
    else:
        entries = raw
    if not isinstance(entries, list):
        raise ValueError(f"{path}: expected accepted_drift list")
    accepted: list[WindowsCorpusAcceptedDrift] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        normalized = dict(entry)
        if "acceptance_reason" not in normalized and "reason" in normalized:
            normalized["acceptance_reason"] = normalized.pop("reason")
        accepted.append(WindowsCorpusAcceptedDrift.model_validate(normalized))
    return accepted


def _classify_manifest_drift(
    drift: list[WindowsCorpusManifestDrift],
    accepted_policy: list[WindowsCorpusAcceptedDrift],
) -> tuple[list[WindowsCorpusAcceptedDriftMatch], list[WindowsCorpusManifestDrift]]:
    accepted: list[WindowsCorpusAcceptedDriftMatch] = []
    unaccepted: list[WindowsCorpusManifestDrift] = []
    for item in drift:
        policy = next(
            (
                candidate
                for candidate in accepted_policy
                if _accepted_drift_matches(item, candidate)
            ),
            None,
        )
        if policy is None:
            unaccepted.append(item)
        else:
            accepted.append(
                WindowsCorpusAcceptedDriftMatch(drift=item, acceptance=policy)
            )
    return accepted, unaccepted


def _accepted_drift_matches(
    drift: WindowsCorpusManifestDrift,
    accepted: WindowsCorpusAcceptedDrift,
) -> bool:
    if accepted.file != drift.file or accepted.field != drift.field:
        return False
    if accepted.drift_reason is not None and accepted.drift_reason != drift.reason:
        return False
    if accepted.current is not None and accepted.current != drift.current:
        return False
    if accepted.recorded is not None and accepted.recorded != drift.recorded:
        return False
    return True


def _manifest_drift(
    *,
    manifest_path: Path,
    manifest_records: dict[str, dict[str, Any]],
    records: list[WindowsCorpusFixtureRecord],
    missing_dashboard: list[str],
    missing_local: list[str],
) -> list[WindowsCorpusManifestDrift]:
    drift: list[WindowsCorpusManifestDrift] = []
    records_by_file = {record.file: record for record in records}
    if not manifest_path.exists():
        drift.append(
            WindowsCorpusManifestDrift(
                file=str(manifest_path),
                field="manifest",
                reason="missing_manifest",
                current="present",
                recorded="missing",
            )
        )
    for name in missing_dashboard:
        drift.append(
            WindowsCorpusManifestDrift(
                file=name,
                field="dashboard",
                reason="missing_dashboard_entry",
                current="local_file",
                recorded="missing",
            )
        )
    for name in missing_local:
        drift.append(
            WindowsCorpusManifestDrift(
                file=name,
                field="local_file",
                reason="missing_local_file",
                current="missing",
                recorded="dashboard_row",
            )
        )
    if not manifest_records:
        return drift

    for name in sorted(set(records_by_file) - set(manifest_records)):
        drift.append(
            WindowsCorpusManifestDrift(
                file=name,
                field="fixtures",
                reason="missing_manifest_entry",
                current="local_file",
                recorded="missing",
            )
        )
    for name in sorted(set(manifest_records) - set(records_by_file)):
        drift.append(
            WindowsCorpusManifestDrift(
                file=name,
                field="fixtures",
                reason="stale_manifest_entry",
                current="missing",
                recorded="manifest_entry",
            )
        )
    for name in sorted(set(records_by_file) & set(manifest_records)):
        record = records_by_file[name]
        manifest_entry = manifest_records[name]
        for field in _MANIFEST_DRIFT_FIELDS:
            current = getattr(record, field)
            recorded = manifest_entry.get(field)
            if recorded != current:
                drift.append(
                    WindowsCorpusManifestDrift(
                        file=name,
                        field=field,
                        reason="stale_manifest_field",
                        current=current,
                        recorded=recorded,
                    )
                )
    return drift


_MANIFEST_DRIFT_FIELDS = (
    "path",
    "suite",
    "binary_kind",
    "architecture",
    "size_bytes",
    "sha256",
    "pdb_status",
    "stress_purpose",
    "ghidra_internal_functions",
    "glaurung_functions",
    "missing_entries",
    "extra_entries",
)


def _write_manifest(
    *,
    manifest_path: Path,
    records: list[WindowsCorpusFixtureRecord],
    source_manifest: Path | None,
) -> None:
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest = _manifest_document(records, source_manifest)
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=False) + "\n",
        encoding="utf-8",
    )


def _manifest_document(
    records: list[WindowsCorpusFixtureRecord],
    source_manifest: Path | None,
) -> dict[str, Any]:
    base: dict[str, Any] = {}
    if source_manifest is not None and source_manifest.exists():
        loaded = json.loads(source_manifest.read_text(encoding="utf-8"))
        if isinstance(loaded, dict):
            base = loaded
    return {
        "schema_version": 2,
        "purpose": base.get(
            "purpose",
            "Vendored real-world Windows PE smoke and stress corpus for Glaurung analysis development.",
        ),
        "selection_method": base.get("selection_method"),
        "created_utc_date": base.get("created_utc_date"),
        "source_roots": base.get("source_roots", []),
        "license_note": base.get("license_note"),
        "curation": {
            "tool": "windows_corpus_curator",
            "fixture_count": len(records),
            "fast_baseline_count": sum(
                1 for record in records if record.suite == "fast_baseline"
            ),
            "stress_count": sum(1 for record in records if record.suite == "stress"),
            "fields_added": [
                "suite",
                "binary_kind",
                "architecture",
                "pdb_status",
                "stress_purpose",
                "ghidra_internal_functions",
                "glaurung_functions",
                "missing_entries",
                "extra_entries",
            ],
        },
        "fixtures": [
            {
                "file": record.file,
                "path": record.path,
                "suite": record.suite,
                "source_label": record.source_label,
                "source_path": record.source_path,
                "file_description": record.file_description,
                "binary_kind": record.binary_kind,
                "architecture": record.architecture,
                "size_bytes": record.size_bytes,
                "sha256": record.sha256,
                "pdb_status": record.pdb_status,
                "stress_purpose": record.stress_purpose,
                "ghidra_internal_functions": record.ghidra_internal_functions,
                "glaurung_functions": record.glaurung_functions,
                "missing_entries": record.missing_entries,
                "extra_entries": record.extra_entries,
            }
            for record in records
        ],
    }


def _binary_kind(path: Path) -> CorpusBinaryKind:
    suffix = path.suffix.lower()
    if suffix == ".exe":
        return "exe"
    if suffix == ".dll":
        return "dll"
    if suffix == ".sys":
        return "sys"
    return "other"


def _stress_purpose(path_name: str, row: dict[str, Any] | None) -> list[str]:
    purposes: list[str] = []
    lowered = path_name.lower()
    if path_name in FAST_BASELINE_FILES:
        purposes.append("fast_baseline_parity")
    if "webservices" in lowered or "rtkauduservice" in lowered:
        purposes.append("body_split_overmerge")
    if "npu" in lowered or "xrt" in lowered:
        purposes.append("vendor_tiny_stub_precision")
    if "netwtw" in lowered:
        purposes.append("large_driver_data_ref_padding")
    if "dism" in lowered or "wdscore" in lowered or "netsetupapi" in lowered:
        purposes.append("deployment_dll_tiny_thunk_recall")
    if "surfacepen" in lowered:
        purposes.append("callback_table_data_ref_recall")
    if row is not None:
        reason = str(row.get("suspected_reason") or "")
        if reason and reason != "parity_or_over":
            purposes.append(reason)
    if not purposes:
        purposes.append("general_windows_pe_coverage")
    return _dedupe(purposes)


def _select_diverse(
    records: list[WindowsCorpusFixtureRecord],
    max_selected: int,
) -> list[WindowsCorpusFixtureRecord]:
    selected: list[WindowsCorpusFixtureRecord] = []
    seen_keys: set[tuple[str, str, str]] = set()
    for record in sorted(records, key=_selection_key):
        purpose = record.stress_purpose[0] if record.stress_purpose else "general"
        key = (record.suite, record.binary_kind, purpose)
        if key in seen_keys and len(selected) < max_selected // 2:
            continue
        selected.append(record)
        seen_keys.add(key)
        if len(selected) >= max_selected:
            break
    return selected


def _selection_key(record: WindowsCorpusFixtureRecord) -> tuple[int, int, str]:
    suite_rank = 0 if record.suite == "fast_baseline" else 1
    gap = (record.missing_entries or 0) + (record.extra_entries or 0)
    return (suite_rank, -gap, record.file)


def _duplicate_classes(
    records: list[WindowsCorpusFixtureRecord],
) -> list[WindowsCorpusDuplicateClass]:
    by_sha: dict[str, list[str]] = {}
    by_purpose: dict[str, list[str]] = {}
    for record in records:
        by_sha.setdefault(record.sha256, []).append(record.file)
        purpose_key = "|".join(
            [record.suite, record.binary_kind, ",".join(record.stress_purpose)]
        )
        by_purpose.setdefault(purpose_key, []).append(record.file)
    duplicates: list[WindowsCorpusDuplicateClass] = []
    for sha, files in sorted(by_sha.items()):
        if len(files) > 1:
            duplicates.append(
                WindowsCorpusDuplicateClass(
                    key=sha,
                    files=sorted(files),
                    reason="identical sha256",
                )
            )
    for purpose, files in sorted(by_purpose.items()):
        if len(files) > 2:
            duplicates.append(
                WindowsCorpusDuplicateClass(
                    key=purpose,
                    files=sorted(files),
                    reason="same suite, binary kind, and stress purpose",
                )
            )
    return duplicates


def _kind_counts(records: list[WindowsCorpusFixtureRecord]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for record in records:
        counts[record.binary_kind] = counts.get(record.binary_kind, 0) + 1
    return counts


def _review_notes_markdown(
    *,
    config: WindowsCorpusCuratorConfig,
    fixture_count: int,
    fast_baseline_count: int,
    stress_count: int,
    manifest_path: Path,
    manifest_drift: list[WindowsCorpusManifestDrift],
    accepted_drift: list[WindowsCorpusAcceptedDriftMatch],
    unaccepted_manifest_drift: list[WindowsCorpusManifestDrift],
    dashboard_refresh_commands: list[str],
    selected: list[WindowsCorpusFixtureRecord],
) -> str:
    lines = [
        "# Windows Corpus Review",
        "",
        "Claim level: corpus_curation_not_analysis",
        "",
        "## Scope",
        "",
        f"- Corpus root: `{config.corpus_root}`",
        f"- Manifest: `{manifest_path}`",
        f"- Dashboard: `{config.comparison_path}`",
        f"- Fixtures: {fixture_count}",
        f"- Fast baseline: {fast_baseline_count}",
        f"- Stress suite: {stress_count}",
        "",
        "## Drift",
        "",
        f"- Total drift items: {len(manifest_drift)}",
        f"- Accepted drift items: {len(accepted_drift)}",
        f"- Unaccepted drift items: {len(unaccepted_manifest_drift)}",
        "",
    ]
    if accepted_drift:
        lines.extend(["### Accepted Drift", ""])
        lines.extend(
            (
                f"- `{item.drift.file}` `{item.drift.field}`: "
                f"{item.acceptance.acceptance_reason}"
            )
            for item in accepted_drift
        )
        lines.append("")
    if unaccepted_manifest_drift:
        lines.extend(["### Unaccepted Drift", ""])
        lines.extend(
            (
                f"- `{item.file}` `{item.field}` reason={item.reason} "
                f"current={item.current!r} recorded={item.recorded!r}"
            )
            for item in unaccepted_manifest_drift[:50]
        )
        if len(unaccepted_manifest_drift) > 50:
            lines.append(f"- ... {len(unaccepted_manifest_drift) - 50} more")
        lines.append("")
    lines.extend(["## Dashboard Refresh", ""])
    lines.extend(f"- `{command}`" for command in dashboard_refresh_commands)
    lines.extend(["", "## Review Sample", ""])
    lines.extend(
        (
            f"- `{record.file}` suite={record.suite} kind={record.binary_kind} "
            f"purpose={','.join(record.stress_purpose)}"
        )
        for record in selected[:16]
    )
    lines.append("")
    return "\n".join(lines)


def _write_review_notes(path_text: str, markdown: str) -> None:
    path = Path(path_text)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(markdown, encoding="utf-8")


def _evidence_bundle(
    *,
    config: WindowsCorpusCuratorConfig,
    records: list[WindowsCorpusFixtureRecord],
    selected: list[WindowsCorpusFixtureRecord],
    duplicates: list[WindowsCorpusDuplicateClass],
    missing_dashboard: list[str],
    missing_local: list[str],
    manifest_drift: list[WindowsCorpusManifestDrift],
    accepted_drift: list[WindowsCorpusAcceptedDriftMatch],
    unaccepted_manifest_drift: list[WindowsCorpusManifestDrift],
    tool_sequence: list[str],
    notes: list[str],
) -> WindowsEvidenceBundle:
    blockers = [
        f"unaccepted corpus drift: {item.file} field={item.field} "
        f"reason={item.reason}"
        for item in unaccepted_manifest_drift
    ]
    return make_windows_evidence_bundle(
        claim_level="triage_evidence_bundle_not_finding",
        subject=WindowsEvidenceSubject(
            kind="generic",
            attributes={
                "corpus_root": config.corpus_root,
                "comparison_path": config.comparison_path,
                "fixture_count": len(records),
                "selected_count": len(selected),
                "duplicate_class_count": len(duplicates),
                "missing_dashboard_count": len(missing_dashboard),
                "missing_local_count": len(missing_local),
                "manifest_drift_count": len(manifest_drift),
                "accepted_drift_count": len(accepted_drift),
                "unaccepted_manifest_drift_count": len(unaccepted_manifest_drift),
                "accepted_drift_path": config.accepted_drift_path,
                "review_notes_path": config.review_notes_path,
            },
        ),
        source_tools=tool_sequence,
        tool_sequence=tool_sequence,
        evidence_refs=[
            evidence_ref(
                kind="tool_result",
                source="windows_corpus_curator",
                summary=f"{record.file}: {record.binary_kind} {record.suite} {record.sha256[:12]}",
                reason_codes=record.stress_purpose,
                provenance=[record.path],
            )
            for record in selected[:16]
        ],
        coverage=WindowsEvidenceCoverage(
            fact_coverage=["sha256", "binary_kind", "architecture", "stress_purpose"],
            missing_facts=blockers,
        ),
        blockers=blockers,
        next_actions=["run dashboard refresh after fixture changes"],
        notes=notes,
    )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _dedupe(values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value and value not in seen:
            seen.add(value)
            out.append(value)
    return out


def _ctx() -> MemoryContext:
    artifact = g.triage.analyze_bytes(b"MZ")
    ctx = MemoryContext(file_path="<windows-corpus-curator>", artifact=artifact)
    import_triage(ctx.kb, artifact, "<windows-corpus-curator>")
    return ctx
