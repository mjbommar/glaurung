"""Persist execution identities and proved runtime-to-static relations.

These rows are immutable measurements joining one captured process address to
one exact static image.  They are deliberately separate from static xrefs and
annotations: an observation cannot rename, retype, or otherwise overwrite a
decompiler fact, and repeated executions remain independently attributable.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sqlite3
import time
from dataclasses import dataclass
from collections.abc import Sequence
from typing import Any

from .persistent import PersistentKnowledgeBase


_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS runtime_runs (
    run_pk INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id INTEGER NOT NULL,
    run_id TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    UNIQUE (binary_id, run_id)
);
CREATE TABLE IF NOT EXISTS runtime_captures (
    capture_pk INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id INTEGER NOT NULL,
    run_id TEXT NOT NULL,
    capture_id TEXT NOT NULL,
    acquisition TEXT NOT NULL CHECK (acquisition IN ('live', 'core', 'trace')),
    capsule_sha256 TEXT NOT NULL,
    executable_sha256 TEXT NOT NULL,
    captured_at TEXT NOT NULL,
    host_os TEXT NOT NULL,
    kernel TEXT NOT NULL,
    capsule_json TEXT NOT NULL,
    imported_at INTEGER NOT NULL,
    UNIQUE (binary_id, capture_id),
    FOREIGN KEY (binary_id, run_id) REFERENCES runtime_runs(binary_id, run_id)
);
CREATE INDEX IF NOT EXISTS idx_runtime_captures_run
    ON runtime_captures(binary_id, run_id, capture_id);
CREATE TABLE IF NOT EXISTS runtime_payloads (
    payload_pk INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id INTEGER NOT NULL,
    capture_id TEXT NOT NULL,
    payload_id TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    byte_len INTEGER NOT NULL,
    sensitivity TEXT NOT NULL,
    data BLOB NOT NULL,
    UNIQUE (binary_id, capture_id, payload_id),
    FOREIGN KEY (binary_id, capture_id)
        REFERENCES runtime_captures(binary_id, capture_id)
);
CREATE INDEX IF NOT EXISTS idx_runtime_payloads_capture
    ON runtime_payloads(binary_id, capture_id, payload_id);
CREATE TABLE IF NOT EXISTS runtime_processes (
    process_pk INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id INTEGER NOT NULL,
    capture_id TEXT NOT NULL,
    process_id TEXT NOT NULL,
    os_pid INTEGER NOT NULL,
    parent_process_id TEXT,
    terminal_json TEXT,
    UNIQUE (binary_id, capture_id, process_id),
    FOREIGN KEY (binary_id, capture_id)
        REFERENCES runtime_captures(binary_id, capture_id)
);
CREATE TABLE IF NOT EXISTS runtime_modules (
    module_pk INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id INTEGER NOT NULL,
    capture_id TEXT NOT NULL,
    module_id TEXT NOT NULL,
    process_id TEXT NOT NULL,
    artifact_sha256 TEXT NOT NULL,
    artifact_json TEXT NOT NULL,
    load_bias INTEGER,
    mapping_ids_json TEXT NOT NULL,
    UNIQUE (binary_id, capture_id, module_id),
    FOREIGN KEY (binary_id, capture_id, process_id)
        REFERENCES runtime_processes(binary_id, capture_id, process_id)
);
CREATE TABLE IF NOT EXISTS runtime_mappings (
    mapping_pk INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id INTEGER NOT NULL,
    capture_id TEXT NOT NULL,
    mapping_id TEXT NOT NULL,
    process_id TEXT NOT NULL,
    start_va INTEGER NOT NULL,
    end_va INTEGER NOT NULL,
    permissions_json TEXT NOT NULL,
    backing_json TEXT NOT NULL,
    module_id TEXT,
    file_offset INTEGER,
    UNIQUE (binary_id, capture_id, mapping_id),
    FOREIGN KEY (binary_id, capture_id, process_id)
        REFERENCES runtime_processes(binary_id, capture_id, process_id)
);
CREATE INDEX IF NOT EXISTS idx_runtime_processes_capture
    ON runtime_processes(binary_id, capture_id, process_id);
CREATE INDEX IF NOT EXISTS idx_runtime_modules_capture
    ON runtime_modules(binary_id, capture_id, process_id, module_id);
CREATE INDEX IF NOT EXISTS idx_runtime_mappings_capture
    ON runtime_mappings(binary_id, capture_id, process_id, start_va);
CREATE TABLE IF NOT EXISTS runtime_threads (
    thread_pk INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id INTEGER NOT NULL,
    capture_id TEXT NOT NULL,
    thread_id TEXT NOT NULL,
    process_id TEXT NOT NULL,
    os_tid INTEGER NOT NULL,
    registers_json TEXT NOT NULL,
    fault_json TEXT,
    UNIQUE (binary_id, capture_id, thread_id),
    FOREIGN KEY (binary_id, capture_id, process_id)
        REFERENCES runtime_processes(binary_id, capture_id, process_id)
);
CREATE TABLE IF NOT EXISTS runtime_events (
    event_pk INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id INTEGER NOT NULL,
    capture_id TEXT NOT NULL,
    process_id TEXT NOT NULL,
    thread_id TEXT,
    thread_scope TEXT NOT NULL,
    sequence INTEGER NOT NULL,
    kind TEXT NOT NULL,
    address INTEGER,
    fields_json TEXT NOT NULL,
    UNIQUE (binary_id, capture_id, process_id, thread_scope, sequence),
    FOREIGN KEY (binary_id, capture_id, process_id)
        REFERENCES runtime_processes(binary_id, capture_id, process_id)
);
CREATE INDEX IF NOT EXISTS idx_runtime_threads_capture
    ON runtime_threads(binary_id, capture_id, process_id, thread_id);
CREATE INDEX IF NOT EXISTS idx_runtime_events_stream
    ON runtime_events(binary_id, capture_id, process_id, thread_scope, sequence);
CREATE TABLE IF NOT EXISTS runtime_pages (
    page_pk INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id INTEGER NOT NULL,
    capture_id TEXT NOT NULL,
    process_id TEXT NOT NULL,
    mapping_id TEXT NOT NULL,
    start_va INTEGER NOT NULL,
    byte_len INTEGER NOT NULL,
    record_json TEXT NOT NULL,
    UNIQUE (binary_id, capture_id, process_id, mapping_id, start_va),
    FOREIGN KEY (binary_id, capture_id, process_id)
        REFERENCES runtime_processes(binary_id, capture_id, process_id)
);
CREATE TABLE IF NOT EXISTS runtime_objects (
    object_pk INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id INTEGER NOT NULL,
    capture_id TEXT NOT NULL,
    object_id TEXT NOT NULL,
    process_id TEXT NOT NULL,
    mapping_id TEXT,
    kind TEXT NOT NULL,
    start_va INTEGER NOT NULL,
    byte_len INTEGER NOT NULL,
    record_json TEXT NOT NULL,
    UNIQUE (binary_id, capture_id, object_id),
    FOREIGN KEY (binary_id, capture_id, process_id)
        REFERENCES runtime_processes(binary_id, capture_id, process_id)
);
CREATE TABLE IF NOT EXISTS runtime_object_snapshots (
    snapshot_pk INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id INTEGER NOT NULL,
    capture_id TEXT NOT NULL,
    snapshot_id TEXT NOT NULL,
    process_id TEXT NOT NULL,
    object_id TEXT NOT NULL,
    sequence INTEGER NOT NULL,
    record_json TEXT NOT NULL,
    UNIQUE (binary_id, capture_id, snapshot_id),
    FOREIGN KEY (binary_id, capture_id, object_id)
        REFERENCES runtime_objects(binary_id, capture_id, object_id)
);
CREATE TABLE IF NOT EXISTS runtime_outputs (
    output_pk INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id INTEGER NOT NULL,
    capture_id TEXT NOT NULL,
    process_id TEXT NOT NULL,
    stream TEXT NOT NULL,
    payload_id TEXT NOT NULL,
    record_json TEXT NOT NULL,
    UNIQUE (binary_id, capture_id, process_id, stream),
    FOREIGN KEY (binary_id, capture_id, process_id)
        REFERENCES runtime_processes(binary_id, capture_id, process_id)
);
CREATE TABLE IF NOT EXISTS runtime_descriptors (
    descriptor_pk INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id INTEGER NOT NULL,
    capture_id TEXT NOT NULL,
    process_id TEXT NOT NULL,
    descriptor_number INTEGER NOT NULL,
    kind TEXT NOT NULL,
    redacted INTEGER NOT NULL CHECK (redacted IN (0, 1)),
    record_json TEXT NOT NULL,
    UNIQUE (binary_id, capture_id, process_id, descriptor_number),
    FOREIGN KEY (binary_id, capture_id, process_id)
        REFERENCES runtime_processes(binary_id, capture_id, process_id)
);
CREATE INDEX IF NOT EXISTS idx_runtime_pages_capture
    ON runtime_pages(binary_id, capture_id, process_id, start_va);
CREATE INDEX IF NOT EXISTS idx_runtime_objects_capture
    ON runtime_objects(binary_id, capture_id, process_id, start_va);
CREATE INDEX IF NOT EXISTS idx_runtime_snapshots_object
    ON runtime_object_snapshots(binary_id, capture_id, object_id, sequence);
CREATE INDEX IF NOT EXISTS idx_runtime_outputs_capture
    ON runtime_outputs(binary_id, capture_id, process_id, stream);
CREATE INDEX IF NOT EXISTS idx_runtime_descriptors_capture
    ON runtime_descriptors(binary_id, capture_id, process_id, descriptor_number);
CREATE TABLE IF NOT EXISTS runtime_operation_occurrences (
    occurrence_pk INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id INTEGER NOT NULL,
    capture_id TEXT NOT NULL,
    occurrence_id TEXT NOT NULL,
    process_id TEXT NOT NULL,
    thread_id TEXT,
    thread_scope TEXT NOT NULL,
    event_sequence INTEGER NOT NULL,
    image_sha256 TEXT NOT NULL,
    function_entry INTEGER NOT NULL,
    machine_va INTEGER NOT NULL,
    machine_operation_ordinal INTEGER NOT NULL,
    lift_profile TEXT NOT NULL,
    block_start INTEGER NOT NULL,
    operation_index INTEGER NOT NULL,
    operation_kind TEXT NOT NULL,
    identity_json TEXT NOT NULL,
    UNIQUE (binary_id, capture_id, occurrence_id),
    FOREIGN KEY (binary_id, capture_id, process_id)
        REFERENCES runtime_processes(binary_id, capture_id, process_id)
);
CREATE INDEX IF NOT EXISTS idx_runtime_occurrences_stream
    ON runtime_operation_occurrences(
        binary_id, capture_id, process_id, thread_scope, event_sequence
    );
CREATE INDEX IF NOT EXISTS idx_runtime_occurrences_static
    ON runtime_operation_occurrences(
        binary_id, image_sha256, function_entry, block_start, operation_index
    );
CREATE TABLE IF NOT EXISTS runtime_operation_occurrence_evidence (
    evidence_pk INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id INTEGER NOT NULL,
    capture_id TEXT NOT NULL,
    occurrence_id TEXT NOT NULL,
    evidence_sha256 TEXT NOT NULL,
    record_json TEXT NOT NULL,
    UNIQUE (binary_id, capture_id, occurrence_id, evidence_sha256),
    FOREIGN KEY (binary_id, capture_id, occurrence_id)
        REFERENCES runtime_operation_occurrences(
            binary_id, capture_id, occurrence_id
        )
);
CREATE INDEX IF NOT EXISTS idx_runtime_occurrence_evidence
    ON runtime_operation_occurrence_evidence(
        binary_id, capture_id, occurrence_id, evidence_sha256
    );
CREATE TABLE IF NOT EXISTS runtime_analysis_reports (
    report_pk INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id INTEGER NOT NULL,
    capture_id TEXT NOT NULL,
    analyzer TEXT NOT NULL,
    report_schema TEXT NOT NULL,
    report_sha256 TEXT NOT NULL,
    report_json TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    UNIQUE (binary_id, capture_id, analyzer, report_schema),
    FOREIGN KEY (binary_id, capture_id)
        REFERENCES runtime_captures(binary_id, capture_id)
);
CREATE INDEX IF NOT EXISTS idx_runtime_analysis_reports_capture
    ON runtime_analysis_reports(binary_id, capture_id, analyzer);
CREATE TABLE IF NOT EXISTS runtime_address_relations (
    relation_id INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id INTEGER NOT NULL,
    capture_id TEXT NOT NULL,
    acquisition TEXT NOT NULL,
    capsule_sha256 TEXT NOT NULL,
    process_id TEXT NOT NULL,
    mapping_id TEXT NOT NULL,
    module_id TEXT NOT NULL,
    raw_va INTEGER NOT NULL,
    image_sha256 TEXT NOT NULL,
    runtime_file_offset INTEGER NOT NULL,
    static_va INTEGER NOT NULL,
    module_relative INTEGER NOT NULL,
    byte_status_json TEXT NOT NULL,
    function_json TEXT NOT NULL,
    code_json TEXT NOT NULL,
    claim_kind TEXT NOT NULL CHECK (claim_kind = 'inferred'),
    created_at INTEGER NOT NULL,
    UNIQUE (
        binary_id, capture_id, process_id, mapping_id, raw_va,
        image_sha256, static_va
    )
);
CREATE INDEX IF NOT EXISTS idx_runtime_address_capture
    ON runtime_address_relations(binary_id, capture_id, process_id);
CREATE INDEX IF NOT EXISTS idx_runtime_address_static
    ON runtime_address_relations(binary_id, static_va);
CREATE INDEX IF NOT EXISTS idx_runtime_address_raw
    ON runtime_address_relations(capture_id, process_id, raw_va);
"""


def _ensure_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(_SCHEMA_SQL)
    conn.commit()


def _u64_to_db(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{field} must be an unsigned 64-bit integer")
    if value < 0 or value >= 1 << 64:
        raise ValueError(f"{field} must be an unsigned 64-bit integer")
    return value if value < 1 << 63 else value - (1 << 64)


def _u64_from_db(value: int) -> int:
    return value if value >= 0 else value + (1 << 64)


def _required_str(container: dict[str, Any], field: str, scope: str) -> str:
    value = container.get(field)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{scope}.{field} must be a non-empty string")
    return value


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


@dataclass(frozen=True)
class RuntimeAddressRelation:
    """One persisted, exact runtime-to-static address relation."""

    relation_id: int
    binary_id: int
    capture_id: str
    acquisition: str
    capsule_sha256: str
    process_id: str
    mapping_id: str
    module_id: str
    raw_va: int
    image_sha256: str
    runtime_file_offset: int
    static_va: int
    module_relative: int
    byte_status: dict[str, Any]
    function: dict[str, Any]
    code: dict[str, Any]
    claim_kind: str
    created_at: int


@dataclass(frozen=True)
class RuntimeRun:
    """One project-scoped execution identity."""

    run_pk: int
    binary_id: int
    run_id: str
    created_at: int


@dataclass(frozen=True)
class RuntimeCapture:
    """One immutable, validated process-capsule artifact within a run."""

    capture_pk: int
    binary_id: int
    run_id: str
    capture_id: str
    acquisition: str
    capsule_sha256: str
    executable_sha256: str
    captured_at: str
    host_os: str
    kernel: str
    capsule_json: str
    imported_at: int


@dataclass(frozen=True)
class RuntimeProcess:
    process_pk: int
    binary_id: int
    capture_id: str
    process_id: str
    os_pid: int
    parent_process_id: str | None
    terminal: dict[str, Any] | None


@dataclass(frozen=True)
class RuntimeModule:
    module_pk: int
    binary_id: int
    capture_id: str
    module_id: str
    process_id: str
    artifact_sha256: str
    artifact: dict[str, Any]
    load_bias: int | None
    mapping_ids: list[str]


@dataclass(frozen=True)
class RuntimeMapping:
    mapping_pk: int
    binary_id: int
    capture_id: str
    mapping_id: str
    process_id: str
    start_va: int
    end_va: int
    permissions: dict[str, Any]
    backing: dict[str, Any]
    module_id: str | None
    file_offset: int | None


@dataclass(frozen=True)
class RuntimeThread:
    thread_pk: int
    binary_id: int
    capture_id: str
    thread_id: str
    process_id: str
    os_tid: int
    registers: list[dict[str, Any]]
    fault: dict[str, Any] | None


@dataclass(frozen=True)
class RuntimeEvent:
    event_pk: int
    binary_id: int
    capture_id: str
    process_id: str
    thread_id: str | None
    sequence: int
    kind: str
    address: int | None
    fields: dict[str, str]


@dataclass(frozen=True)
class RuntimeAnalysisReport:
    """One deterministic analyzer result over one exact persisted capture."""

    report_pk: int
    binary_id: int
    capture_id: str
    analyzer: str
    report_schema: str
    report_sha256: str
    report_json: str
    created_at: int


@dataclass(frozen=True)
class RuntimeOperationOccurrence:
    """One occurrence-scoped observation joined to an immutable LLIR operation."""

    occurrence_pk: int
    binary_id: int
    capture_id: str
    occurrence_id: str
    process_id: str
    thread_id: str | None
    event_sequence: int
    static_operation: dict[str, Any]
    evidence_records: list[dict[str, Any]]


def persist_process_capsule(
    kb: PersistentKnowledgeBase,
    capsule_json: str,
    payloads: Sequence[tuple[str, bytes]] = (),
    *,
    run_id: str | None = None,
) -> RuntimeCapture:
    """Validate and persist one immutable capture under an explicit run.

    A missing ``run_id`` creates a one-capture run named by the capsule's own
    capture identity. Supplying a run ID allows later acquisition artifacts to
    be grouped deliberately; it never infers grouping from PID or timestamps.
    """
    from glaurung import runtime_analysis

    runtime_analysis.validate_process_capsule_json(capsule_json)
    try:
        capsule = json.loads(capsule_json)
    except (json.JSONDecodeError, TypeError) as error:
        raise ValueError(f"process capsule is not valid JSON: {error}") from error
    if not isinstance(capsule, dict):
        raise ValueError("process capsule must be a JSON object")
    identity = capsule.get("identity")
    executable = capsule.get("executable")
    if not isinstance(identity, dict) or not isinstance(executable, dict):
        raise ValueError("capsule identity and executable must be objects")
    capture_id = _required_str(identity, "capture_id", "capsule.identity")
    acquisition = _required_str(identity, "acquisition", "capsule.identity")
    captured_at = _required_str(identity, "captured_at", "capsule.identity")
    host_os = _required_str(identity, "host_os", "capsule.identity")
    kernel = _required_str(identity, "kernel", "capsule.identity")
    executable_sha256 = _required_str(executable, "sha256", "capsule.executable")
    selected_run_id = capture_id if run_id is None else run_id
    if not isinstance(selected_run_id, str) or not selected_run_id.strip():
        raise ValueError("run_id must be a non-empty string")

    binary_sha_row = kb._conn.execute(
        "SELECT sha256 FROM binaries WHERE binary_id = ?", (kb.binary_id,)
    ).fetchone()
    if binary_sha_row is None or binary_sha_row[0] != executable_sha256:
        raise ValueError("capsule executable identity disagrees with project binary")

    capsule_sha256 = hashlib.sha256(capsule_json.encode()).hexdigest()
    verified_payloads = _verify_capsule_payloads(capsule, payloads)
    imported_at = int(time.time())
    _ensure_schema(kb._conn)
    existing = kb._conn.execute(
        "SELECT run_id, capsule_sha256 FROM runtime_captures "
        "WHERE binary_id = ? AND capture_id = ?",
        (kb.binary_id, capture_id),
    ).fetchone()
    if existing is not None and existing != (selected_run_id, capsule_sha256):
        raise ValueError("capture identity already names different persisted evidence")

    with kb._conn:
        kb._conn.execute(
            "INSERT OR IGNORE INTO runtime_runs (binary_id, run_id, created_at) "
            "VALUES (?, ?, ?)",
            (kb.binary_id, selected_run_id, imported_at),
        )
        kb._conn.execute(
            "INSERT OR IGNORE INTO runtime_captures "
            "(binary_id, run_id, capture_id, acquisition, capsule_sha256, "
            "executable_sha256, captured_at, host_os, kernel, capsule_json, imported_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                kb.binary_id,
                selected_run_id,
                capture_id,
                acquisition,
                capsule_sha256,
                executable_sha256,
                captured_at,
                host_os,
                kernel,
                capsule_json,
                imported_at,
            ),
        )
        for payload_id, data, digest, sensitivity in verified_payloads:
            kb._conn.execute(
                "INSERT OR IGNORE INTO runtime_payloads "
                "(binary_id, capture_id, payload_id, sha256, byte_len, "
                "sensitivity, data) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    kb.binary_id,
                    capture_id,
                    payload_id,
                    digest,
                    len(data),
                    sensitivity,
                    data,
                ),
            )
        _persist_runtime_identity_graph(kb, capture_id, capsule)
    row = kb._conn.execute(
        "SELECT capture_pk, binary_id, run_id, capture_id, acquisition, "
        "capsule_sha256, executable_sha256, captured_at, host_os, kernel, "
        "capsule_json, imported_at FROM runtime_captures "
        "WHERE binary_id = ? AND capture_id = ?",
        (kb.binary_id, capture_id),
    ).fetchone()
    if row is None:
        raise RuntimeError("failed to persist runtime capture")
    return _row_to_capture(row)


def list_runtime_runs(kb: PersistentKnowledgeBase) -> list[RuntimeRun]:
    """List this binary's runs in deterministic creation order."""
    _ensure_schema(kb._conn)
    rows = kb._conn.execute(
        "SELECT run_pk, binary_id, run_id, created_at FROM runtime_runs "
        "WHERE binary_id = ? ORDER BY created_at, run_pk",
        (kb.binary_id,),
    ).fetchall()
    return [RuntimeRun(*row) for row in rows]


def list_runtime_captures(
    kb: PersistentKnowledgeBase, *, run_id: str | None = None
) -> list[RuntimeCapture]:
    """List this binary's immutable capture artifacts."""
    _ensure_schema(kb._conn)
    where = ["binary_id = ?"]
    params: list[Any] = [kb.binary_id]
    if run_id is not None:
        where.append("run_id = ?")
        params.append(run_id)
    rows = kb._conn.execute(
        "SELECT capture_pk, binary_id, run_id, capture_id, acquisition, "
        "capsule_sha256, executable_sha256, captured_at, host_os, kernel, "
        "capsule_json, imported_at FROM runtime_captures WHERE "
        + " AND ".join(where)
        + " ORDER BY run_id, captured_at, capture_pk",
        params,
    ).fetchall()
    return [_row_to_capture(row) for row in rows]


def _row_to_capture(row: tuple[Any, ...]) -> RuntimeCapture:
    return RuntimeCapture(*row)


def _verify_capsule_payloads(
    capsule: dict[str, Any], payloads: Sequence[tuple[str, bytes]]
) -> list[tuple[str, bytes, str, str]]:
    supplied: dict[str, bytes] = {}
    for payload_id, data in payloads:
        if not isinstance(payload_id, str) or not payload_id:
            raise ValueError("payload ID must be a non-empty string")
        if not isinstance(data, bytes):
            raise ValueError(f"payload {payload_id} data must be bytes")
        if payload_id in supplied:
            raise ValueError(f"duplicate payload ID {payload_id}")
        supplied[payload_id] = data

    references: dict[str, dict[str, Any]] = {}
    contents = [item.get("content") for item in capsule.get("pages", [])]
    contents.extend(item.get("content") for item in capsule.get("object_snapshots", []))
    for output in capsule.get("outputs", []):
        references[
            _required_str(output["payload"], "id", "capsule.outputs[].payload")
        ] = output["payload"]
    for content in contents:
        if not isinstance(content, dict) or content.get("status") != "captured":
            continue
        reference = content.get("payload")
        if not isinstance(reference, dict):
            raise ValueError("captured content payload must be an object")
        payload_id = _required_str(reference, "id", "captured content payload")
        prior = references.setdefault(payload_id, reference)
        if prior != reference:
            raise ValueError(f"payload {payload_id} has inconsistent references")

    missing = sorted(set(references) - set(supplied))
    if missing:
        raise ValueError(f"capture payloads are missing referenced IDs: {missing}")
    verified = []
    for payload_id, data in sorted(supplied.items()):
        digest = hashlib.sha256(data).hexdigest()
        reference = references.get(payload_id)
        sensitivity = "unknown"
        if reference is not None:
            if reference.get("sha256") != digest or reference.get("byte_len") != len(
                data
            ):
                raise ValueError(f"payload {payload_id} disagrees with its reference")
            sensitivity = _required_str(
                reference, "sensitivity", "captured content payload"
            )
        verified.append((payload_id, data, digest, sensitivity))
    return verified


def load_process_capsule(
    kb: PersistentKnowledgeBase, capture_id: str
) -> tuple[str, list[tuple[str, bytes]]]:
    """Reload one exact capsule artifact and its persisted payload bytes."""
    _ensure_schema(kb._conn)
    row = kb._conn.execute(
        "SELECT capsule_json FROM runtime_captures "
        "WHERE binary_id = ? AND capture_id = ?",
        (kb.binary_id, capture_id),
    ).fetchone()
    if row is None:
        raise KeyError(f"unknown runtime capture {capture_id}")
    payload_rows = kb._conn.execute(
        "SELECT payload_id, data FROM runtime_payloads "
        "WHERE binary_id = ? AND capture_id = ? ORDER BY payload_id",
        (kb.binary_id, capture_id),
    ).fetchall()
    return row[0], [(item[0], bytes(item[1])) for item in payload_rows]


def _persist_runtime_identity_graph(
    kb: PersistentKnowledgeBase, capture_id: str, capsule: dict[str, Any]
) -> None:
    for process in capsule.get("processes", []):
        process_id = _required_str(process, "id", "capsule.processes[]")
        terminal = process.get("terminal")
        kb._conn.execute(
            "INSERT OR IGNORE INTO runtime_processes "
            "(binary_id, capture_id, process_id, os_pid, parent_process_id, terminal_json) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                kb.binary_id,
                capture_id,
                process_id,
                _u64_to_db(process.get("os_pid"), "process.os_pid"),
                process.get("parent_id"),
                None if terminal is None else _canonical_json(terminal),
            ),
        )
    for module in capsule.get("modules", []):
        module_id = _required_str(module, "id", "capsule.modules[]")
        process_id = _required_str(module, "process_id", "capsule.modules[]")
        artifact = module.get("artifact")
        if not isinstance(artifact, dict):
            raise ValueError("capsule.modules[].artifact must be an object")
        load_bias = module.get("load_bias")
        kb._conn.execute(
            "INSERT OR IGNORE INTO runtime_modules "
            "(binary_id, capture_id, module_id, process_id, artifact_sha256, "
            "artifact_json, load_bias, mapping_ids_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                kb.binary_id,
                capture_id,
                module_id,
                process_id,
                _required_str(artifact, "sha256", "capsule.modules[].artifact"),
                _canonical_json(artifact),
                None
                if load_bias is None
                else _u64_to_db(load_bias, "module.load_bias"),
                _canonical_json(module.get("mapping_ids", [])),
            ),
        )
    for mapping in capsule.get("mappings", []):
        mapping_id = _required_str(mapping, "id", "capsule.mappings[]")
        process_id = _required_str(mapping, "process_id", "capsule.mappings[]")
        permissions = mapping.get("permissions")
        backing = mapping.get("backing")
        if not isinstance(permissions, dict) or not isinstance(backing, dict):
            raise ValueError(
                "capsule.mappings[] permissions and backing must be objects"
            )
        file_offset = mapping.get("file_offset")
        kb._conn.execute(
            "INSERT OR IGNORE INTO runtime_mappings "
            "(binary_id, capture_id, mapping_id, process_id, start_va, end_va, "
            "permissions_json, backing_json, module_id, file_offset) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                kb.binary_id,
                capture_id,
                mapping_id,
                process_id,
                _u64_to_db(mapping.get("start"), "mapping.start"),
                _u64_to_db(mapping.get("end"), "mapping.end"),
                _canonical_json(permissions),
                _canonical_json(backing),
                mapping.get("module_id"),
                None
                if file_offset is None
                else _u64_to_db(file_offset, "mapping.file_offset"),
            ),
        )
    for thread in capsule.get("threads", []):
        thread_id = _required_str(thread, "id", "capsule.threads[]")
        process_id = _required_str(thread, "process_id", "capsule.threads[]")
        fault = thread.get("fault")
        kb._conn.execute(
            "INSERT OR IGNORE INTO runtime_threads "
            "(binary_id, capture_id, thread_id, process_id, os_tid, "
            "registers_json, fault_json) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                kb.binary_id,
                capture_id,
                thread_id,
                process_id,
                _u64_to_db(thread.get("os_tid"), "thread.os_tid"),
                _canonical_json(thread.get("registers", [])),
                None if fault is None else _canonical_json(fault),
            ),
        )
    for event in capsule.get("events", []):
        process_id = _required_str(event, "process_id", "capsule.events[]")
        kind = _required_str(event, "kind", "capsule.events[]")
        thread_id = event.get("thread_id")
        address = event.get("address")
        kb._conn.execute(
            "INSERT OR IGNORE INTO runtime_events "
            "(binary_id, capture_id, process_id, thread_id, thread_scope, "
            "sequence, kind, address, fields_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                kb.binary_id,
                capture_id,
                process_id,
                thread_id,
                "" if thread_id is None else thread_id,
                _u64_to_db(event.get("sequence"), "event.sequence"),
                kind,
                None if address is None else _u64_to_db(address, "event.address"),
                _canonical_json(event.get("fields", {})),
            ),
        )
    for page in capsule.get("pages", []):
        kb._conn.execute(
            "INSERT OR IGNORE INTO runtime_pages "
            "(binary_id, capture_id, process_id, mapping_id, start_va, byte_len, "
            "record_json) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                kb.binary_id,
                capture_id,
                _required_str(page, "process_id", "capsule.pages[]"),
                _required_str(page, "mapping_id", "capsule.pages[]"),
                _u64_to_db(page.get("start"), "page.start"),
                _u64_to_db(page.get("byte_len"), "page.byte_len"),
                _canonical_json(page),
            ),
        )
    for runtime_object in capsule.get("runtime_objects", []):
        kb._conn.execute(
            "INSERT OR IGNORE INTO runtime_objects "
            "(binary_id, capture_id, object_id, process_id, mapping_id, kind, "
            "start_va, byte_len, record_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                kb.binary_id,
                capture_id,
                _required_str(runtime_object, "id", "capsule.runtime_objects[]"),
                _required_str(
                    runtime_object, "process_id", "capsule.runtime_objects[]"
                ),
                runtime_object.get("mapping_id"),
                _required_str(runtime_object, "kind", "capsule.runtime_objects[]"),
                _u64_to_db(runtime_object.get("start"), "runtime_object.start"),
                _u64_to_db(runtime_object.get("byte_len"), "runtime_object.byte_len"),
                _canonical_json(runtime_object),
            ),
        )
    for snapshot in capsule.get("object_snapshots", []):
        point = snapshot.get("point")
        if not isinstance(point, dict):
            raise ValueError("capsule.object_snapshots[].point must be an object")
        kb._conn.execute(
            "INSERT OR IGNORE INTO runtime_object_snapshots "
            "(binary_id, capture_id, snapshot_id, process_id, object_id, "
            "sequence, record_json) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                kb.binary_id,
                capture_id,
                _required_str(snapshot, "id", "capsule.object_snapshots[]"),
                _required_str(snapshot, "process_id", "capsule.object_snapshots[]"),
                _required_str(snapshot, "object_id", "capsule.object_snapshots[]"),
                _u64_to_db(point.get("sequence"), "object_snapshot.point.sequence"),
                _canonical_json(snapshot),
            ),
        )
    for output in capsule.get("outputs", []):
        payload = output.get("payload")
        if not isinstance(payload, dict):
            raise ValueError("capsule.outputs[].payload must be an object")
        kb._conn.execute(
            "INSERT OR IGNORE INTO runtime_outputs "
            "(binary_id, capture_id, process_id, stream, payload_id, record_json) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                kb.binary_id,
                capture_id,
                _required_str(output, "process_id", "capsule.outputs[]"),
                _required_str(output, "stream", "capsule.outputs[]"),
                _required_str(payload, "id", "capsule.outputs[].payload"),
                _canonical_json(output),
            ),
        )
    for descriptor in capsule.get("descriptors", []):
        kb._conn.execute(
            "INSERT OR IGNORE INTO runtime_descriptors "
            "(binary_id, capture_id, process_id, descriptor_number, kind, "
            "redacted, record_json) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                kb.binary_id,
                capture_id,
                _required_str(descriptor, "process_id", "capsule.descriptors[]"),
                _u64_to_db(descriptor.get("number"), "descriptor.number"),
                _required_str(descriptor, "kind", "capsule.descriptors[]"),
                int(bool(descriptor.get("redacted", False))),
                _canonical_json(descriptor),
            ),
        )


def list_runtime_processes(
    kb: PersistentKnowledgeBase, capture_id: str
) -> list[RuntimeProcess]:
    _ensure_schema(kb._conn)
    rows = kb._conn.execute(
        "SELECT process_pk, binary_id, capture_id, process_id, os_pid, "
        "parent_process_id, terminal_json FROM runtime_processes "
        "WHERE binary_id = ? AND capture_id = ? ORDER BY process_id",
        (kb.binary_id, capture_id),
    ).fetchall()
    return [
        RuntimeProcess(
            row[0],
            row[1],
            row[2],
            row[3],
            _u64_from_db(row[4]),
            row[5],
            None if row[6] is None else json.loads(row[6]),
        )
        for row in rows
    ]


def list_runtime_modules(
    kb: PersistentKnowledgeBase, capture_id: str
) -> list[RuntimeModule]:
    _ensure_schema(kb._conn)
    rows = kb._conn.execute(
        "SELECT module_pk, binary_id, capture_id, module_id, process_id, "
        "artifact_sha256, artifact_json, load_bias, mapping_ids_json "
        "FROM runtime_modules WHERE binary_id = ? AND capture_id = ? "
        "ORDER BY process_id, module_id",
        (kb.binary_id, capture_id),
    ).fetchall()
    return [
        RuntimeModule(
            row[0],
            row[1],
            row[2],
            row[3],
            row[4],
            row[5],
            json.loads(row[6]),
            None if row[7] is None else _u64_from_db(row[7]),
            json.loads(row[8]),
        )
        for row in rows
    ]


def list_runtime_mappings(
    kb: PersistentKnowledgeBase, capture_id: str
) -> list[RuntimeMapping]:
    _ensure_schema(kb._conn)
    rows = kb._conn.execute(
        "SELECT mapping_pk, binary_id, capture_id, mapping_id, process_id, "
        "start_va, end_va, permissions_json, backing_json, module_id, file_offset "
        "FROM runtime_mappings WHERE binary_id = ? AND capture_id = ? "
        "ORDER BY process_id, start_va, mapping_id",
        (kb.binary_id, capture_id),
    ).fetchall()
    return [
        RuntimeMapping(
            row[0],
            row[1],
            row[2],
            row[3],
            row[4],
            _u64_from_db(row[5]),
            _u64_from_db(row[6]),
            json.loads(row[7]),
            json.loads(row[8]),
            row[9],
            None if row[10] is None else _u64_from_db(row[10]),
        )
        for row in rows
    ]


def list_runtime_threads(
    kb: PersistentKnowledgeBase, capture_id: str
) -> list[RuntimeThread]:
    _ensure_schema(kb._conn)
    rows = kb._conn.execute(
        "SELECT thread_pk, binary_id, capture_id, thread_id, process_id, os_tid, "
        "registers_json, fault_json FROM runtime_threads "
        "WHERE binary_id = ? AND capture_id = ? ORDER BY process_id, thread_id",
        (kb.binary_id, capture_id),
    ).fetchall()
    return [
        RuntimeThread(
            row[0],
            row[1],
            row[2],
            row[3],
            row[4],
            _u64_from_db(row[5]),
            json.loads(row[6]),
            None if row[7] is None else json.loads(row[7]),
        )
        for row in rows
    ]


def list_runtime_events(
    kb: PersistentKnowledgeBase, capture_id: str
) -> list[RuntimeEvent]:
    """List events ordered within each provider-owned process/thread stream."""
    _ensure_schema(kb._conn)
    rows = kb._conn.execute(
        "SELECT event_pk, binary_id, capture_id, process_id, thread_id, sequence, "
        "kind, address, fields_json FROM runtime_events "
        "WHERE binary_id = ? AND capture_id = ? "
        "ORDER BY process_id, thread_scope, sequence, event_pk",
        (kb.binary_id, capture_id),
    ).fetchall()
    return [
        RuntimeEvent(
            row[0],
            row[1],
            row[2],
            row[3],
            row[4],
            _u64_from_db(row[5]),
            row[6],
            None if row[7] is None else _u64_from_db(row[7]),
            json.loads(row[8]),
        )
        for row in rows
    ]


def _list_runtime_record_json(
    kb: PersistentKnowledgeBase,
    table: str,
    capture_id: str,
    order_by: str,
) -> list[dict[str, Any]]:
    allowed = {
        "runtime_pages",
        "runtime_objects",
        "runtime_object_snapshots",
        "runtime_outputs",
        "runtime_descriptors",
    }
    if table not in allowed:
        raise ValueError("unsupported runtime record table")
    rows = kb._conn.execute(
        f"SELECT record_json FROM {table} "
        "WHERE binary_id = ? AND capture_id = ? ORDER BY " + order_by,
        (kb.binary_id, capture_id),
    ).fetchall()
    return [json.loads(row[0]) for row in rows]


def list_runtime_pages(
    kb: PersistentKnowledgeBase, capture_id: str
) -> list[dict[str, Any]]:
    _ensure_schema(kb._conn)
    return _list_runtime_record_json(
        kb, "runtime_pages", capture_id, "process_id, start_va, page_pk"
    )


def list_runtime_objects(
    kb: PersistentKnowledgeBase, capture_id: str
) -> list[dict[str, Any]]:
    _ensure_schema(kb._conn)
    return _list_runtime_record_json(
        kb, "runtime_objects", capture_id, "process_id, start_va, object_pk"
    )


def list_runtime_object_snapshots(
    kb: PersistentKnowledgeBase, capture_id: str
) -> list[dict[str, Any]]:
    _ensure_schema(kb._conn)
    return _list_runtime_record_json(
        kb,
        "runtime_object_snapshots",
        capture_id,
        "process_id, object_id, sequence, snapshot_pk",
    )


def list_runtime_outputs(
    kb: PersistentKnowledgeBase, capture_id: str
) -> list[dict[str, Any]]:
    _ensure_schema(kb._conn)
    return _list_runtime_record_json(
        kb, "runtime_outputs", capture_id, "process_id, stream, output_pk"
    )


def list_runtime_descriptors(
    kb: PersistentKnowledgeBase, capture_id: str
) -> list[dict[str, Any]]:
    _ensure_schema(kb._conn)
    return _list_runtime_record_json(
        kb,
        "runtime_descriptors",
        capture_id,
        "process_id, descriptor_number, descriptor_pk",
    )


_OCCURRENCE_FIELDS = {
    "id",
    "capture_id",
    "process_id",
    "event_sequence",
    "static_operation",
    "code_origin",
    "inputs",
    "output",
    "effects",
}


def _operation_occurrences(value: Any) -> list[dict[str, Any]]:
    """Collect native typed occurrences without interpreting their evidence."""
    found: dict[str, dict[str, Any]] = {}

    def visit(item: Any) -> None:
        if isinstance(item, dict):
            if _OCCURRENCE_FIELDS <= item.keys():
                occurrence_id = _required_str(item, "id", "operation occurrence")
                record_json = _canonical_json(item)
                found[f"{occurrence_id}:{record_json}"] = item
                return
            for child in item.values():
                visit(child)
        elif isinstance(item, list):
            for child in item:
                visit(child)

    visit(value)
    return [found[key] for key in sorted(found)]


def _persist_operation_occurrences(
    kb: PersistentKnowledgeBase,
    capture_id: str,
    report: Any,
) -> None:
    for occurrence in _operation_occurrences(report):
        if occurrence.get("capture_id") != capture_id:
            raise ValueError("operation occurrence does not name its report capture")
        operation = occurrence.get("static_operation")
        if not isinstance(operation, dict):
            raise ValueError("operation occurrence has no static operation record")
        occurrence_id = _required_str(occurrence, "id", "operation occurrence")
        process_id = _required_str(occurrence, "process_id", "operation occurrence")
        thread_id = occurrence.get("thread_id")
        if thread_id is not None and not isinstance(thread_id, str):
            raise ValueError("operation occurrence thread_id must be a string or null")
        event_sequence = _u64_to_db(
            occurrence.get("event_sequence"), "operation occurrence event_sequence"
        )
        identity = {
            key: occurrence.get(key)
            for key in (
                "id",
                "capture_id",
                "process_id",
                "thread_id",
                "event_sequence",
                "static_operation",
                "code_origin",
            )
        }
        identity_json = _canonical_json(identity)
        record_json = _canonical_json(occurrence)
        values = (
            kb.binary_id,
            capture_id,
            occurrence_id,
            process_id,
            thread_id,
            thread_id or "",
            event_sequence,
            _required_str(operation, "image_sha256", "static operation"),
            _u64_to_db(operation.get("function_entry"), "function_entry"),
            _u64_to_db(operation.get("machine_va"), "machine_va"),
            _u64_to_db(
                operation.get("machine_operation_ordinal"),
                "machine_operation_ordinal",
            ),
            _required_str(operation, "lift_profile", "static operation"),
            _u64_to_db(operation.get("block_start"), "block_start"),
            _u64_to_db(operation.get("operation_index"), "operation_index"),
            _required_str(operation, "kind", "static operation"),
            identity_json,
        )
        kb._conn.execute(
            "INSERT OR IGNORE INTO runtime_operation_occurrences "
            "(binary_id, capture_id, occurrence_id, process_id, thread_id, "
            "thread_scope, event_sequence, image_sha256, function_entry, "
            "machine_va, machine_operation_ordinal, lift_profile, block_start, "
            "operation_index, operation_kind, identity_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            values,
        )
        existing = kb._conn.execute(
            "SELECT identity_json FROM runtime_operation_occurrences "
            "WHERE binary_id = ? AND capture_id = ? AND occurrence_id = ?",
            (kb.binary_id, capture_id, occurrence_id),
        ).fetchone()
        if existing is None or existing[0] != identity_json:
            raise ValueError(
                f"operation occurrence {occurrence_id} conflicts with persisted identity"
            )
        evidence_sha256 = hashlib.sha256(record_json.encode()).hexdigest()
        kb._conn.execute(
            "INSERT OR IGNORE INTO runtime_operation_occurrence_evidence "
            "(binary_id, capture_id, occurrence_id, evidence_sha256, record_json) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                kb.binary_id,
                capture_id,
                occurrence_id,
                evidence_sha256,
                record_json,
            ),
        )


def list_runtime_operation_occurrences(
    kb: PersistentKnowledgeBase,
    *,
    capture_id: str | None = None,
) -> list[RuntimeOperationOccurrence]:
    """List occurrence relations while retaining static and runtime identities."""
    _ensure_schema(kb._conn)
    sql = (
        "SELECT occurrence_pk, binary_id, capture_id, occurrence_id, process_id, "
        "thread_id, event_sequence, identity_json FROM runtime_operation_occurrences "
        "WHERE binary_id = ?"
    )
    parameters: list[Any] = [kb.binary_id]
    if capture_id is not None:
        sql += " AND capture_id = ?"
        parameters.append(capture_id)
    sql += (
        " ORDER BY capture_id, process_id, thread_scope, event_sequence, occurrence_id"
    )
    occurrences = []
    for row in kb._conn.execute(sql, parameters).fetchall():
        identity = json.loads(row[7])
        evidence = kb._conn.execute(
            "SELECT record_json FROM runtime_operation_occurrence_evidence "
            "WHERE binary_id = ? AND capture_id = ? AND occurrence_id = ? "
            "ORDER BY evidence_sha256",
            (row[1], row[2], row[3]),
        ).fetchall()
        occurrences.append(
            RuntimeOperationOccurrence(
                row[0],
                row[1],
                row[2],
                row[3],
                row[4],
                row[5],
                _u64_from_db(row[6]),
                identity["static_operation"],
                [json.loads(item[0]) for item in evidence],
            )
        )
    return occurrences


def _persist_analysis_report(
    kb: PersistentKnowledgeBase,
    capture_id: str,
    analyzer: str,
    report_schema: str,
    parsed: dict[str, Any],
) -> RuntimeAnalysisReport:
    report_json = _canonical_json(parsed)
    report_sha256 = hashlib.sha256(report_json.encode()).hexdigest()
    with kb._conn:
        _persist_operation_occurrences(kb, capture_id, parsed)
        existing = kb._conn.execute(
            "SELECT report_pk, report_sha256, report_json, created_at "
            "FROM runtime_analysis_reports WHERE binary_id = ? "
            "AND capture_id = ? AND analyzer = ? AND report_schema = ?",
            (kb.binary_id, capture_id, analyzer, report_schema),
        ).fetchone()
        if existing is not None:
            if existing[1] != report_sha256 or existing[2] != report_json:
                raise ValueError(
                    "analyzer produced different evidence for an existing capture/schema"
                )
            return RuntimeAnalysisReport(
                existing[0],
                kb.binary_id,
                capture_id,
                analyzer,
                report_schema,
                existing[1],
                existing[2],
                existing[3],
            )
        created_at = int(time.time())
        cursor = kb._conn.execute(
            "INSERT INTO runtime_analysis_reports "
            "(binary_id, capture_id, analyzer, report_schema, report_sha256, "
            "report_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                kb.binary_id,
                capture_id,
                analyzer,
                report_schema,
                report_sha256,
                report_json,
                created_at,
            ),
        )
        report_pk = cursor.lastrowid
        if report_pk is None:
            raise RuntimeError("SQLite did not return the inserted report identity")
        return RuntimeAnalysisReport(
            report_pk,
            kb.binary_id,
            capture_id,
            analyzer,
            report_schema,
            report_sha256,
            report_json,
            created_at,
        )


def _persisted_analysis_inputs(
    kb: PersistentKnowledgeBase,
    capture_id: str,
    executable_bytes: bytes,
) -> tuple[str, list[tuple[str, bytes]]]:
    capsule_json, payloads = load_process_capsule(kb, capture_id)
    capture = next(
        (item for item in list_runtime_captures(kb) if item.capture_id == capture_id),
        None,
    )
    if capture is None:
        raise KeyError(f"unknown runtime capture: {capture_id}")
    executable_sha256 = hashlib.sha256(executable_bytes).hexdigest()
    if executable_sha256 != capture.executable_sha256:
        raise ValueError("executable bytes disagree with persisted capture identity")
    return capsule_json, payloads


def analyze_and_persist_crash(
    kb: PersistentKnowledgeBase,
    capture_id: str,
    executable_bytes: bytes,
) -> RuntimeAnalysisReport:
    """Run the deterministic crash analyzer over persisted evidence and store it."""
    from glaurung import runtime_analysis

    capsule_json, payloads = _persisted_analysis_inputs(
        kb, capture_id, executable_bytes
    )
    parsed = json.loads(
        runtime_analysis.analyze_process_capsule_crash(
            capsule_json, payloads, executable_bytes
        )
    )
    report_schema = "glaurung-runtime-crash-analysis-v1"
    if parsed.get("outcome") == "crash":
        report = parsed.get("report")
        if not isinstance(report, dict) or report.get("capture_id") != capture_id:
            raise ValueError("crash report does not name its persisted capture")
        report_schema = _required_str(report, "schema", "crash report")
    return _persist_analysis_report(
        kb, capture_id, "runtime-crash", report_schema, parsed
    )


def analyze_and_persist_instruction_trace(
    kb: PersistentKnowledgeBase,
    capture_id: str,
    executable_bytes: bytes,
) -> RuntimeAnalysisReport:
    """Persist a typed trace report and its occurrence-scoped LLIR joins."""
    from glaurung import runtime_analysis

    capsule_json, payloads = _persisted_analysis_inputs(
        kb, capture_id, executable_bytes
    )
    parsed = json.loads(
        runtime_analysis.analyze_process_capsule_instruction_trace(
            capsule_json, payloads, executable_bytes
        )
    )
    if parsed.get("capture_id") != capture_id:
        raise ValueError("instruction trace report does not name its persisted capture")
    report_schema = _required_str(parsed, "schema", "instruction trace report")
    return _persist_analysis_report(
        kb, capture_id, "runtime-instruction-trace", report_schema, parsed
    )


def analyze_and_persist_mapping_behavior(
    kb: PersistentKnowledgeBase,
    capture_id: str,
) -> RuntimeAnalysisReport:
    """Normalize persisted mapping events and store their typed history."""
    from glaurung import runtime_analysis

    capsule_json, _payloads = load_process_capsule(kb, capture_id)
    parsed = json.loads(
        runtime_analysis.analyze_process_capsule_mapping_behavior(capsule_json)
    )
    if parsed.get("capture_id") != capture_id:
        raise ValueError("mapping behavior report does not name its persisted capture")
    report_schema = _required_str(parsed, "schema", "mapping behavior report")
    return _persist_analysis_report(
        kb, capture_id, "runtime-mapping-behavior", report_schema, parsed
    )


def list_runtime_analysis_reports(
    kb: PersistentKnowledgeBase,
    *,
    capture_id: str | None = None,
) -> list[RuntimeAnalysisReport]:
    """List deterministic analyzer outputs without joining annotation state."""
    _ensure_schema(kb._conn)
    sql = (
        "SELECT report_pk, binary_id, capture_id, analyzer, report_schema, "
        "report_sha256, report_json, created_at FROM runtime_analysis_reports "
        "WHERE binary_id = ?"
    )
    parameters: list[Any] = [kb.binary_id]
    if capture_id is not None:
        sql += " AND capture_id = ?"
        parameters.append(capture_id)
    sql += " ORDER BY capture_id, analyzer, report_schema, report_pk"
    return [
        RuntimeAnalysisReport(*row)
        for row in kb._conn.execute(sql, parameters).fetchall()
    ]


def runtime_crash_explanation_json(
    kb: PersistentKnowledgeBase,
    capture_id: str,
) -> str:
    """Return the one persisted crash analysis for an exact capture.

    This surface never reacquires the process or reruns analysis. It verifies
    the content address and capture/schema bindings before returning the exact
    canonical report bytes stored by :func:`analyze_and_persist_crash`.
    """
    reports = [
        report
        for report in list_runtime_analysis_reports(kb, capture_id=capture_id)
        if report.analyzer == "runtime-crash"
    ]
    if not reports:
        raise KeyError(f"no persisted runtime crash analysis for capture: {capture_id}")
    if len(reports) != 1:
        raise ValueError(
            f"multiple persisted runtime crash analyses for capture: {capture_id}"
        )
    persisted = reports[0]
    if hashlib.sha256(persisted.report_json.encode()).hexdigest() != (
        persisted.report_sha256
    ):
        raise ValueError("persisted runtime crash analysis hash mismatch")
    try:
        analysis = json.loads(persisted.report_json)
    except json.JSONDecodeError as error:
        raise ValueError("persisted runtime crash analysis is invalid JSON") from error
    if not isinstance(analysis, dict):
        raise ValueError("persisted runtime crash analysis must be an object")
    outcome = _required_str(analysis, "outcome", "runtime crash analysis")
    if outcome == "crash":
        report = analysis.get("report")
        if not isinstance(report, dict):
            raise ValueError("persisted crash outcome has no report object")
        if report.get("capture_id") != capture_id:
            raise ValueError("persisted crash report names a different capture")
        if report.get("schema") != persisted.report_schema:
            raise ValueError("persisted crash report schema disagrees with its index")
    elif persisted.report_schema != "glaurung-runtime-crash-analysis-v1":
        raise ValueError("persisted non-crash analysis schema disagrees with its index")
    return persisted.report_json


def runtime_mapping_history_json(
    kb: PersistentKnowledgeBase,
    capture_id: str,
) -> str:
    """Return one content-addressed, persisted mapping-history report."""
    reports = [
        report
        for report in list_runtime_analysis_reports(kb, capture_id=capture_id)
        if report.analyzer == "runtime-mapping-behavior"
    ]
    if not reports:
        raise KeyError(
            f"no persisted runtime mapping history for capture: {capture_id}"
        )
    if len(reports) != 1:
        raise ValueError(
            f"multiple persisted runtime mapping histories for capture: {capture_id}"
        )
    persisted = reports[0]
    if hashlib.sha256(persisted.report_json.encode()).hexdigest() != (
        persisted.report_sha256
    ):
        raise ValueError("persisted runtime mapping history hash mismatch")
    try:
        report = json.loads(persisted.report_json)
    except json.JSONDecodeError as error:
        raise ValueError("persisted runtime mapping history is invalid JSON") from error
    if not isinstance(report, dict):
        raise ValueError("persisted runtime mapping history must be an object")
    if report.get("capture_id") != capture_id:
        raise ValueError("persisted mapping history names a different capture")
    if report.get("schema") != persisted.report_schema:
        raise ValueError("persisted mapping history schema disagrees with its index")
    return persisted.report_json


def _claim_kinds(value: Any) -> list[str]:
    kinds: set[str] = set()

    def visit(item: Any) -> None:
        if isinstance(item, dict):
            status = item.get("status")
            if status in {
                "observed",
                "inferred",
                "static",
                "replayed",
                "symbolic",
                "unknown",
            }:
                kinds.add(status)
            for child in item.values():
                visit(child)
        elif isinstance(item, list):
            for child in item:
                visit(child)

    visit(value)
    return sorted(kinds)


def runtime_evidence_packet_json(
    kb: PersistentKnowledgeBase,
    capture_id: str,
    *,
    include_sensitive: bool = False,
) -> str:
    """Export a deterministic evidence packet under an explicit privacy policy.

    The default packet contains only redacted projections and content
    identities. ``include_sensitive=True`` is the explicit analyst boundary
    that additionally includes the exact capsule, report documents, and
    payload bytes. The executable remains identified by hash in both modes.
    """
    if not isinstance(include_sensitive, bool):
        raise TypeError("include_sensitive must be a boolean")
    capsule_json, _ = load_process_capsule(kb, capture_id)
    try:
        capsule = json.loads(capsule_json)
    except json.JSONDecodeError as error:
        raise ValueError("persisted process capsule is invalid JSON") from error
    capture = next(
        (item for item in list_runtime_captures(kb) if item.capture_id == capture_id),
        None,
    )
    if capture is None:
        raise KeyError(f"unknown runtime capture {capture_id}")
    if hashlib.sha256(capsule_json.encode()).hexdigest() != capture.capsule_sha256:
        raise ValueError("persisted process capsule hash mismatch")

    completeness = []
    for record in capsule.get("completeness", []):
        if not isinstance(record, dict):
            raise ValueError("persisted capsule completeness record is not an object")
        completeness.append(
            {
                "evidence": _required_str(record, "evidence", "completeness record"),
                "status": _required_str(record, "status", "completeness record"),
                "requested": record.get("requested"),
                "obtained": record.get("obtained"),
                "expected": record.get("expected"),
                "reason_redacted": bool(record.get("reason")),
            }
        )
    completeness.sort(key=lambda item: item["evidence"])

    payloads = []
    rows = kb._conn.execute(
        "SELECT payload_id, sha256, byte_len, sensitivity, data "
        "FROM runtime_payloads WHERE binary_id = ? AND capture_id = ? "
        "ORDER BY payload_id",
        (kb.binary_id, capture_id),
    ).fetchall()
    for payload_id, sha256, byte_len, sensitivity, stored_data in rows:
        data = bytes(stored_data)
        if len(data) != byte_len or hashlib.sha256(data).hexdigest() != sha256:
            raise ValueError(f"persisted runtime payload {payload_id} hash mismatch")
        payload = {
            "id": payload_id,
            "sha256": sha256,
            "byte_len": byte_len,
            "sensitivity": sensitivity,
            "included": include_sensitive,
        }
        if include_sensitive:
            payload["data_base64"] = base64.b64encode(data).decode("ascii")
        payloads.append(payload)

    reports = []
    for persisted in list_runtime_analysis_reports(kb, capture_id=capture_id):
        if hashlib.sha256(persisted.report_json.encode()).hexdigest() != (
            persisted.report_sha256
        ):
            raise ValueError(
                f"persisted runtime analysis report {persisted.analyzer} hash mismatch"
            )
        try:
            document = json.loads(persisted.report_json)
        except json.JSONDecodeError as error:
            raise ValueError(
                f"persisted runtime analysis report {persisted.analyzer} is invalid JSON"
            ) from error
        if not isinstance(document, dict):
            raise ValueError(
                f"persisted runtime analysis report {persisted.analyzer} must be an object"
            )
        document_schema = document.get("schema")
        document_capture = document.get("capture_id")
        if persisted.analyzer == "runtime-crash":
            if document.get("outcome") == "crash":
                crash_report = document.get("report")
                if not isinstance(crash_report, dict):
                    raise ValueError("persisted crash analysis has no report object")
                document_schema = crash_report.get("schema")
                document_capture = crash_report.get("capture_id")
            else:
                document_schema = "glaurung-runtime-crash-analysis-v1"
        if document_schema != persisted.report_schema:
            raise ValueError(
                f"persisted runtime analysis report {persisted.analyzer} "
                "schema disagrees with its index"
            )
        if document_capture is not None and document_capture != capture_id:
            raise ValueError(
                f"persisted runtime analysis report {persisted.analyzer} "
                "names a different capture"
            )
        report = {
            "analyzer": persisted.analyzer,
            "schema": persisted.report_schema,
            "sha256": persisted.report_sha256,
            "claim_kinds": _claim_kinds(document),
            "document_included": include_sensitive,
        }
        if include_sensitive:
            report["document"] = document
        reports.append(report)

    capsule_entry: dict[str, Any] = {
        "sha256": capture.capsule_sha256,
        "included": include_sensitive,
    }
    if include_sensitive:
        capsule_entry["document"] = capsule
    packet: dict[str, Any] = {
        "schema": "glaurung-runtime-evidence-packet-v1",
        "export_policy": "include_sensitive" if include_sensitive else "redacted",
        "capture_summary": json.loads(runtime_capture_summary_json(kb, capture_id)),
        "completeness": completeness,
        "capsule": capsule_entry,
        "payloads": payloads,
        "analysis_reports": reports,
        "executable": {
            "sha256": capture.executable_sha256,
            "included": False,
        },
        "omissions": (
            ["executable_bytes"]
            if include_sensitive
            else [
                "capsule_document",
                "payload_bytes",
                "analysis_report_documents",
                "executable_bytes",
                "completeness_reasons",
            ]
        ),
    }
    return _canonical_json(packet) + "\n"


def runtime_capture_summary_json(
    kb: PersistentKnowledgeBase,
    capture_id: str,
) -> str:
    """Return deterministic, payload-free JSON over persisted runtime facts.

    This is the default automation/LLM surface. It exposes capture identity,
    OS context, normalized counts, report identities, and observed static
    operation links, but never payload bytes, registers, page/object snapshots,
    descriptor targets, event fields, or occurrence evidence values.
    """
    _ensure_schema(kb._conn)
    capture = next(
        (item for item in list_runtime_captures(kb) if item.capture_id == capture_id),
        None,
    )
    if capture is None:
        raise KeyError(f"unknown runtime capture: {capture_id}")

    tables = {
        "processes": "runtime_processes",
        "modules": "runtime_modules",
        "mappings": "runtime_mappings",
        "threads": "runtime_threads",
        "events": "runtime_events",
        "pages": "runtime_pages",
        "objects": "runtime_objects",
        "object_snapshots": "runtime_object_snapshots",
        "outputs": "runtime_outputs",
        "descriptors": "runtime_descriptors",
        "operation_occurrences": "runtime_operation_occurrences",
        "operation_evidence_views": "runtime_operation_occurrence_evidence",
        "analysis_reports": "runtime_analysis_reports",
    }
    counts = {
        name: kb._conn.execute(
            f"SELECT COUNT(*) FROM {table} WHERE binary_id = ? AND capture_id = ?",
            (kb.binary_id, capture_id),
        ).fetchone()[0]
        for name, table in tables.items()
    }
    processes = [
        {
            "process_id": row[0],
            "terminal": None if row[1] is None else json.loads(row[1]),
        }
        for row in kb._conn.execute(
            "SELECT process_id, terminal_json FROM runtime_processes "
            "WHERE binary_id = ? AND capture_id = ? ORDER BY process_id",
            (kb.binary_id, capture_id),
        ).fetchall()
    ]
    modules = [
        {"module_id": row[0], "process_id": row[1], "artifact_sha256": row[2]}
        for row in kb._conn.execute(
            "SELECT module_id, process_id, artifact_sha256 FROM runtime_modules "
            "WHERE binary_id = ? AND capture_id = ? ORDER BY process_id, module_id",
            (kb.binary_id, capture_id),
        ).fetchall()
    ]
    mappings = [
        {
            "mapping_id": row[0],
            "process_id": row[1],
            "byte_len": _u64_from_db(row[3]) - _u64_from_db(row[2]),
            "permissions": json.loads(row[4]),
            "backing_kind": json.loads(row[5]).get("kind", "unknown"),
            "module_id": row[6],
            "file_offset": None if row[7] is None else _u64_from_db(row[7]),
        }
        for row in kb._conn.execute(
            "SELECT mapping_id, process_id, start_va, end_va, permissions_json, "
            "backing_json, module_id, file_offset FROM runtime_mappings "
            "WHERE binary_id = ? AND capture_id = ? ORDER BY process_id, mapping_id",
            (kb.binary_id, capture_id),
        ).fetchall()
    ]
    event_kinds = {
        row[0]: row[1]
        for row in kb._conn.execute(
            "SELECT kind, COUNT(*) FROM runtime_events WHERE binary_id = ? "
            "AND capture_id = ? GROUP BY kind ORDER BY kind",
            (kb.binary_id, capture_id),
        ).fetchall()
    }
    descriptors = [
        {
            "process_id": row[0],
            "number": row[1],
            "kind": row[2],
            "redacted": bool(row[3]),
        }
        for row in kb._conn.execute(
            "SELECT process_id, descriptor_number, kind, redacted "
            "FROM runtime_descriptors WHERE binary_id = ? AND capture_id = ? "
            "ORDER BY process_id, descriptor_number",
            (kb.binary_id, capture_id),
        ).fetchall()
    ]
    reports = []
    for report in list_runtime_analysis_reports(kb, capture_id=capture_id):
        parsed = json.loads(report.report_json)
        reports.append(
            {
                "analyzer": report.analyzer,
                "schema": report.report_schema,
                "sha256": report.report_sha256,
                "outcome": parsed.get("outcome"),
            }
        )
    observed_operations = [
        {
            "occurrence_id": row[0],
            "process_id": row[1],
            "thread_id": row[2],
            "event_sequence": _u64_from_db(row[3]),
            "image_sha256": row[4],
            "function_entry": _u64_from_db(row[5]),
            "machine_va": _u64_from_db(row[6]),
            "machine_operation_ordinal": _u64_from_db(row[7]),
            "lift_profile": row[8],
            "block_start": _u64_from_db(row[9]),
            "operation_index": _u64_from_db(row[10]),
            "operation_kind": row[11],
        }
        for row in kb._conn.execute(
            "SELECT occurrence_id, process_id, thread_id, event_sequence, "
            "image_sha256, function_entry, machine_va, machine_operation_ordinal, "
            "lift_profile, block_start, operation_index, operation_kind "
            "FROM runtime_operation_occurrences WHERE binary_id = ? "
            "AND capture_id = ? ORDER BY process_id, thread_scope, event_sequence, "
            "occurrence_id",
            (kb.binary_id, capture_id),
        ).fetchall()
    ]
    summary = {
        "schema": "glaurung-runtime-project-summary-v1",
        "capture": {
            "run_id": capture.run_id,
            "capture_id": capture.capture_id,
            "acquisition": capture.acquisition,
            "capsule_sha256": capture.capsule_sha256,
            "executable_sha256": capture.executable_sha256,
            "host_os": capture.host_os,
            "kernel": capture.kernel,
        },
        "counts": counts,
        "processes": processes,
        "modules": modules,
        "mappings": mappings,
        "event_kinds": event_kinds,
        "descriptors": descriptors,
        "analysis_reports": reports,
        "observed_operations": observed_operations,
        "redaction": {
            "payload_bytes": "omitted",
            "registers": "omitted",
            "memory_snapshots": "omitted",
            "paths_and_descriptor_targets": "omitted",
            "event_and_occurrence_values": "omitted",
        },
    }
    return _canonical_json(summary) + "\n"


def compare_runtime_captures_json(
    kb: PersistentKnowledgeBase,
    left_capture_id: str,
    right_capture_id: str,
) -> str:
    """Compare two redacted persisted summaries without aligning raw addresses."""
    left = json.loads(runtime_capture_summary_json(kb, left_capture_id))
    right = json.loads(runtime_capture_summary_json(kb, right_capture_id))
    return _compare_runtime_summaries(left, right)


def compare_runtime_summaries_json(
    left_summary_json: str,
    right_summary_json: str,
) -> str:
    """Compare redacted summaries from separate projects or binary builds."""
    left = json.loads(left_summary_json)
    right = json.loads(right_summary_json)
    expected_schema = "glaurung-runtime-project-summary-v1"
    if left.get("schema") != expected_schema or right.get("schema") != expected_schema:
        raise ValueError("runtime comparison requires two project-summary-v1 inputs")
    return _compare_runtime_summaries(left, right)


def _compare_runtime_summaries(
    left: dict[str, Any],
    right: dict[str, Any],
) -> str:

    count_names = sorted(left["counts"].keys() | right["counts"].keys())
    count_delta = {
        name: right["counts"].get(name, 0) - left["counts"].get(name, 0)
        for name in count_names
    }
    event_kinds = sorted(left["event_kinds"].keys() | right["event_kinds"].keys())
    event_kind_delta = {
        kind: right["event_kinds"].get(kind, 0) - left["event_kinds"].get(kind, 0)
        for kind in event_kinds
    }

    def report_outcomes(summary: dict[str, Any]) -> dict[str, Any]:
        return {
            f"{item['analyzer']}:{item['schema']}": item["outcome"]
            for item in summary["analysis_reports"]
        }

    def static_operations(summary: dict[str, Any]) -> dict[str, dict[str, Any]]:
        operations = {}
        for item in summary["observed_operations"]:
            identity = {
                key: item[key]
                for key in (
                    "image_sha256",
                    "function_entry",
                    "machine_va",
                    "machine_operation_ordinal",
                    "lift_profile",
                    "block_start",
                    "operation_index",
                    "operation_kind",
                )
            }
            operations[_canonical_json(identity)] = identity
        return operations

    left_operations = static_operations(left)
    right_operations = static_operations(right)
    left_keys = set(left_operations)
    right_keys = set(right_operations)
    comparison = {
        "schema": "glaurung-runtime-project-comparison-v1",
        "left": left["capture"],
        "right": right["capture"],
        "same_executable": (
            left["capture"]["executable_sha256"]
            == right["capture"]["executable_sha256"]
        ),
        "count_delta_right_minus_left": count_delta,
        "event_kind_delta_right_minus_left": event_kind_delta,
        "terminal_states": {
            "left": [item["terminal"] for item in left["processes"]],
            "right": [item["terminal"] for item in right["processes"]],
        },
        "analysis_outcomes": {
            "left": report_outcomes(left),
            "right": report_outcomes(right),
        },
        "observed_static_operations": {
            "common": [left_operations[key] for key in sorted(left_keys & right_keys)],
            "left_only": [
                left_operations[key] for key in sorted(left_keys - right_keys)
            ],
            "right_only": [
                right_operations[key] for key in sorted(right_keys - left_keys)
            ],
        },
        "limits": [
            "comparison uses persisted redacted summaries only",
            "raw runtime addresses and evidence values are not aligned",
            "cross-build operation alignment requires a stable cross-build identity",
        ],
    }
    return _canonical_json(comparison) + "\n"


def resolve_and_persist_address(
    kb: PersistentKnowledgeBase,
    capsule_json: str,
    payloads: list[tuple[str, bytes]],
    executable_bytes: bytes,
    process_id: str,
    raw_va: int,
) -> RuntimeAddressRelation:
    """Resolve through the native analyzer and persist its exact relation.

    Keeping resolution and persistence in one product API means callers cannot
    edit a serialized ``static_va`` between those steps.  The project binary's
    content identity is checked again before the row is written.
    """
    from glaurung import runtime_analysis

    resolution_json = runtime_analysis.resolve_process_capsule_address(
        capsule_json,
        payloads,
        executable_bytes,
        process_id,
        raw_va,
    )
    return _persist_address_resolution(kb, capsule_json, resolution_json)


def _persist_address_resolution(
    kb: PersistentKnowledgeBase,
    capsule_json: str,
    resolution_json: str,
) -> RuntimeAddressRelation:
    """Persist one exact native address resolution with capture provenance.

    This private seam accepts only the product result generated immediately by
    :func:`resolve_and_persist_address`. Cross-checking identities here prevents
    a result from being attached to a different capture or project.
    Repeating the same import is idempotent; a different capture gets its own
    row even when it resolves to the same static instruction.
    """
    try:
        capsule = json.loads(capsule_json)
        resolution = json.loads(resolution_json)
    except (json.JSONDecodeError, TypeError) as error:
        raise ValueError(
            f"runtime relation input is not valid JSON: {error}"
        ) from error
    if not isinstance(capsule, dict) or not isinstance(resolution, dict):
        raise ValueError("runtime relation inputs must be JSON objects")
    if capsule.get("schema") != "glaurung-process-capsule-v1":
        raise ValueError("unsupported process capsule schema")
    identity = capsule.get("identity")
    if not isinstance(identity, dict):
        raise ValueError("capsule.identity must be an object")
    capture_id = _required_str(identity, "capture_id", "capsule.identity")
    acquisition = _required_str(identity, "acquisition", "capsule.identity")
    if resolution.get("verdict") != "exact":
        raise ValueError("only exact runtime address resolutions can be persisted")
    address = resolution.get("address")
    if not isinstance(address, dict):
        raise ValueError("exact resolution.address must be an object")
    runtime = address.get("runtime")
    if not isinstance(runtime, dict):
        raise ValueError("exact resolution.address.runtime must be an object")
    if _required_str(runtime, "capture_id", "resolution.address.runtime") != capture_id:
        raise ValueError("capsule and resolution capture identities disagree")

    process_id = _required_str(runtime, "process_id", "resolution.address.runtime")
    process_ids = {
        item.get("id")
        for item in capsule.get("processes", [])
        if isinstance(item, dict)
    }
    if process_id not in process_ids:
        raise ValueError("resolution process is absent from capsule")
    mapping_id = _required_str(runtime, "mapping_id", "resolution.address.runtime")
    module_id = _required_str(runtime, "module_id", "resolution.address.runtime")
    mappings = {
        item.get("id"): item
        for item in capsule.get("mappings", [])
        if isinstance(item, dict)
    }
    mapping = mappings.get(mapping_id)
    if mapping is None:
        raise ValueError("resolution mapping is absent from capsule")
    if mapping.get("process_id") != process_id or mapping.get("module_id") != module_id:
        raise ValueError("resolution scope disagrees with capsule mapping")

    image_sha256 = _required_str(address, "image_sha256", "resolution.address")
    binary_sha_row = kb._conn.execute(
        "SELECT sha256 FROM binaries WHERE binary_id = ?", (kb.binary_id,)
    ).fetchone()
    if binary_sha_row is None or binary_sha_row[0] != image_sha256:
        raise ValueError("resolution image identity disagrees with project binary")

    byte_status = address.get("byte_status")
    function = address.get("function")
    code = address.get("code")
    if not all(isinstance(value, dict) for value in (byte_status, function, code)):
        raise ValueError("resolution byte_status, function, and code must be objects")

    raw_va = _u64_to_db(runtime.get("raw_va"), "raw_va")
    runtime_file_offset = _u64_to_db(
        address.get("runtime_file_offset"), "runtime_file_offset"
    )
    static_va = _u64_to_db(address.get("static_va"), "static_va")
    module_relative = _u64_to_db(address.get("module_relative"), "module_relative")
    capsule_sha256 = hashlib.sha256(capsule_json.encode()).hexdigest()
    created_at = int(time.time())
    _ensure_schema(kb._conn)
    kb._conn.execute(
        "INSERT OR IGNORE INTO runtime_address_relations "
        "(binary_id, capture_id, acquisition, capsule_sha256, process_id, "
        "mapping_id, module_id, raw_va, image_sha256, runtime_file_offset, "
        "static_va, module_relative, byte_status_json, function_json, code_json, "
        "claim_kind, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            kb.binary_id,
            capture_id,
            acquisition,
            capsule_sha256,
            process_id,
            mapping_id,
            module_id,
            raw_va,
            image_sha256,
            runtime_file_offset,
            static_va,
            module_relative,
            _canonical_json(byte_status),
            _canonical_json(function),
            _canonical_json(code),
            "inferred",
            created_at,
        ),
    )
    kb._conn.commit()
    row = kb._conn.execute(
        "SELECT relation_id, binary_id, capture_id, acquisition, capsule_sha256, "
        "process_id, mapping_id, module_id, raw_va, image_sha256, "
        "runtime_file_offset, static_va, module_relative, byte_status_json, "
        "function_json, code_json, claim_kind, created_at "
        "FROM runtime_address_relations WHERE binary_id = ? AND capture_id = ? "
        "AND process_id = ? AND mapping_id = ? AND raw_va = ? "
        "AND image_sha256 = ? AND static_va = ?",
        (
            kb.binary_id,
            capture_id,
            process_id,
            mapping_id,
            raw_va,
            image_sha256,
            static_va,
        ),
    ).fetchone()
    if row is None:
        raise RuntimeError("failed to persist runtime address relation")
    return _row_to_relation(row)


def list_address_relations(
    kb: PersistentKnowledgeBase,
    *,
    capture_id: str | None = None,
    static_va: int | None = None,
) -> list[RuntimeAddressRelation]:
    """List persisted relations for this binary in deterministic order."""
    _ensure_schema(kb._conn)
    where = ["binary_id = ?"]
    params: list[Any] = [kb.binary_id]
    if capture_id is not None:
        where.append("capture_id = ?")
        params.append(capture_id)
    if static_va is not None:
        where.append("static_va = ?")
        params.append(_u64_to_db(static_va, "static_va"))
    rows = kb._conn.execute(
        "SELECT relation_id, binary_id, capture_id, acquisition, capsule_sha256, "
        "process_id, mapping_id, module_id, raw_va, image_sha256, "
        "runtime_file_offset, static_va, module_relative, byte_status_json, "
        "function_json, code_json, claim_kind, created_at "
        "FROM runtime_address_relations WHERE "
        + " AND ".join(where)
        + " ORDER BY capture_id, process_id, raw_va, relation_id",
        params,
    ).fetchall()
    return [_row_to_relation(row) for row in rows]


def _row_to_relation(row: tuple[Any, ...]) -> RuntimeAddressRelation:
    return RuntimeAddressRelation(
        relation_id=row[0],
        binary_id=row[1],
        capture_id=row[2],
        acquisition=row[3],
        capsule_sha256=row[4],
        process_id=row[5],
        mapping_id=row[6],
        module_id=row[7],
        raw_va=_u64_from_db(row[8]),
        image_sha256=row[9],
        runtime_file_offset=_u64_from_db(row[10]),
        static_va=_u64_from_db(row[11]),
        module_relative=_u64_from_db(row[12]),
        byte_status=json.loads(row[13]),
        function=json.loads(row[14]),
        code=json.loads(row[15]),
        claim_kind=row[16],
        created_at=row[17],
    )
