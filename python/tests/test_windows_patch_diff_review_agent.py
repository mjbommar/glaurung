from __future__ import annotations

import json
import sqlite3
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


def _seed_project_boundaries(before: Path, after: Path) -> None:
    for path in (before, after):
        conn = sqlite3.connect(path)
        try:
            conn.executescript(
                """
CREATE TABLE IF NOT EXISTS function_boundaries (
    boundary_id INTEGER PRIMARY KEY,
    binary_id INTEGER,
    entry_va INTEGER,
    end_va INTEGER,
    size INTEGER,
    source TEXT,
    confidence REAL,
    name TEXT,
    detail_json TEXT
);
CREATE TABLE IF NOT EXISTS function_chunk_facts (
    chunk_id INTEGER PRIMARY KEY,
    binary_id INTEGER,
    identity_key TEXT,
    owner_entry_va INTEGER,
    chunk_start_va INTEGER,
    chunk_end_va INTEGER,
    chunk_size INTEGER,
    chunk_kind TEXT,
    relation_kind TEXT,
    target_va INTEGER,
    target_name TEXT,
    source TEXT,
    confidence REAL,
    name TEXT,
    detail_json TEXT,
    indexed_at INTEGER
);
"""
            )
            conn.execute("DELETE FROM function_boundaries")
            conn.execute("DELETE FROM function_chunk_facts")
            conn.commit()
        finally:
            conn.close()

    before_conn = sqlite3.connect(before)
    try:
        before_conn.execute(
            "INSERT INTO function_boundaries VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                1,
                1,
                0x140001000,
                0x140001100,
                0x100,
                "pdata",
                0.90,
                "dispatch",
                "{}",
            ),
        )
        before_conn.execute(
            "INSERT INTO function_chunk_facts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                1,
                1,
                "dispatch-thunk",
                0x140001000,
                0x140001080,
                0x140001086,
                6,
                "import_thunk",
                "import_thunk",
                0x180001000,
                "ZwClose",
                "function_name",
                0.74,
                "dispatch$thunk",
                "{}",
                0,
            ),
        )
        before_conn.commit()
    finally:
        before_conn.close()

    after_conn = sqlite3.connect(after)
    try:
        after_conn.execute(
            "INSERT INTO function_boundaries VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                1,
                1,
                0x140001000,
                0x140001140,
                0x140,
                "pdata",
                0.88,
                "dispatch",
                "{}",
            ),
        )
        after_conn.execute(
            "INSERT INTO function_chunk_facts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                1,
                1,
                "dispatch-thunk",
                0x140001000,
                0x140001080,
                0x140001086,
                6,
                "import_thunk",
                "import_thunk",
                0x180002000,
                "ZwQueryInformationProcess",
                "function_name",
                0.76,
                "dispatch$thunk",
                "{}",
                0,
            ),
        )
        after_conn.commit()
    finally:
        after_conn.close()


def _seed_project_tables(before: Path, after: Path) -> None:
    for path in (before, after):
        conn = sqlite3.connect(path)
        try:
            conn.executescript(
                """
CREATE TABLE IF NOT EXISTS function_names (
    binary_id INTEGER NOT NULL,
    entry_va INTEGER NOT NULL,
    canonical TEXT NOT NULL,
    aliases_json TEXT NOT NULL DEFAULT '[]',
    set_by TEXT,
    set_at INTEGER,
    demangled TEXT,
    flavor TEXT,
    PRIMARY KEY (binary_id, entry_va)
);
CREATE TABLE IF NOT EXISTS data_labels (
    binary_id INTEGER NOT NULL,
    va INTEGER NOT NULL,
    name TEXT NOT NULL,
    c_type TEXT,
    size INTEGER,
    set_by TEXT,
    set_at INTEGER,
    PRIMARY KEY (binary_id, va)
);
CREATE TABLE IF NOT EXISTS xrefs (
    xref_id INTEGER PRIMARY KEY,
    binary_id INTEGER NOT NULL,
    src_va INTEGER NOT NULL,
    dst_va INTEGER NOT NULL,
    kind TEXT NOT NULL,
    src_function_va INTEGER,
    indexed_at INTEGER
);
CREATE TABLE IF NOT EXISTS function_chunk_facts (
    chunk_id INTEGER PRIMARY KEY,
    binary_id INTEGER NOT NULL,
    identity_key TEXT NOT NULL,
    owner_entry_va INTEGER,
    chunk_start_va INTEGER NOT NULL,
    chunk_end_va INTEGER,
    chunk_size INTEGER,
    chunk_kind TEXT NOT NULL,
    relation_kind TEXT NOT NULL,
    target_va INTEGER,
    target_name TEXT,
    source TEXT NOT NULL,
    confidence REAL NOT NULL,
    name TEXT,
    detail_json TEXT NOT NULL DEFAULT '{}',
    indexed_at INTEGER NOT NULL
);
DELETE FROM function_names;
DELETE FROM data_labels;
DELETE FROM xrefs;
DELETE FROM function_chunk_facts;
"""
            )
            conn.executemany(
                "INSERT INTO function_names VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                [
                    (1, 0x140001000, "DriverEntry", "[]", "pdb", 0, None, None),
                    (1, 0x140002000, "Dispatch", "[]", "pdb", 0, None, None),
                    (1, 0x140003000, "TableUser", "[]", "pdb", 0, None, None),
                ],
            )
            conn.commit()
        finally:
            conn.close()

    before_conn = sqlite3.connect(before)
    try:
        before_conn.executemany(
            "INSERT INTO data_labels VALUES (?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    1,
                    0x140020000,
                    "DriverObject.MajorFunction",
                    "PDRIVER_DISPATCH[28]",
                    28 * 8,
                    "pdb",
                    0,
                ),
                (
                    1,
                    0x140021000,
                    "SelectorTable",
                    "ULONG[8]",
                    8 * 4,
                    "manual",
                    0,
                ),
            ],
        )
        before_conn.executemany(
            "INSERT INTO xrefs VALUES (?, ?, ?, ?, ?, ?, ?)",
            [
                (1, 1, 0x140001020, 0x140020000, "data_write", 0x140001000, 0),
                (2, 1, 0x140002030, 0x140020030, "data_read", 0x140002000, 0),
            ],
        )
        before_conn.executemany(
            "INSERT INTO function_chunk_facts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    1,
                    1,
                    "iat-close",
                    0x140010000,
                    0x140010000,
                    0x140010006,
                    6,
                    "import_thunk",
                    "import_thunk",
                    0x180001000,
                    "nt!ZwClose",
                    "function_name",
                    0.76,
                    "driver!IatRun",
                    "{}",
                    0,
                ),
                (
                    2,
                    1,
                    "iat-create",
                    0x140010006,
                    0x140010006,
                    0x14001000C,
                    6,
                    "import_thunk",
                    "import_thunk",
                    0x180003000,
                    "nt!ZwCreateFile",
                    "function_name",
                    0.76,
                    "driver!IatRun",
                    "{}",
                    0,
                ),
            ],
        )
        before_conn.commit()
    finally:
        before_conn.close()

    after_conn = sqlite3.connect(after)
    try:
        after_conn.executemany(
            "INSERT INTO data_labels VALUES (?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    1,
                    0x140020000,
                    "DriverObject.MajorFunction",
                    "PDRIVER_DISPATCH[32]",
                    32 * 8,
                    "pdb",
                    0,
                ),
                (
                    1,
                    0x140022000,
                    "DeviceVtable",
                    "void *[3]",
                    3 * 8,
                    "pdb",
                    0,
                ),
            ],
        )
        after_conn.executemany(
            "INSERT INTO xrefs VALUES (?, ?, ?, ?, ?, ?, ?)",
            [
                (1, 1, 0x140001020, 0x140020000, "data_write", 0x140001000, 0),
                (2, 1, 0x140002030, 0x140020038, "data_read", 0x140002000, 0),
                (3, 1, 0x140003010, 0x140020040, "data_read", 0x140003000, 0),
            ],
        )
        after_conn.executemany(
            "INSERT INTO function_chunk_facts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    1,
                    1,
                    "iat-close",
                    0x140010000,
                    0x140010000,
                    0x140010006,
                    6,
                    "import_thunk",
                    "import_thunk",
                    0x180002000,
                    "nt!ZwOpenProcess",
                    "function_name",
                    0.76,
                    "driver!IatRun",
                    "{}",
                    0,
                ),
                (
                    2,
                    1,
                    "iat-create",
                    0x140010006,
                    0x140010006,
                    0x14001000C,
                    6,
                    "import_thunk",
                    "import_thunk",
                    0x180003000,
                    "nt!ZwCreateFile",
                    "function_name",
                    0.76,
                    "driver!IatRun",
                    "{}",
                    0,
                ),
            ],
        )
        after_conn.commit()
    finally:
        after_conn.close()


def _seed_project_callgraphs(before: Path, after: Path) -> None:
    for path in (before, after):
        conn = sqlite3.connect(path)
        try:
            conn.executescript(
                """
CREATE TABLE IF NOT EXISTS function_names (
    binary_id INTEGER NOT NULL,
    entry_va INTEGER NOT NULL,
    canonical TEXT NOT NULL,
    aliases_json TEXT NOT NULL DEFAULT '[]',
    set_by TEXT,
    set_at INTEGER,
    demangled TEXT,
    flavor TEXT,
    PRIMARY KEY (binary_id, entry_va)
);
CREATE TABLE IF NOT EXISTS xrefs (
    xref_id INTEGER PRIMARY KEY,
    binary_id INTEGER NOT NULL,
    src_va INTEGER NOT NULL,
    dst_va INTEGER NOT NULL,
    kind TEXT NOT NULL,
    src_function_va INTEGER,
    indexed_at INTEGER
);
DELETE FROM function_names;
DELETE FROM xrefs;
"""
            )
            conn.executemany(
                "INSERT INTO function_names VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                [
                    (1, 0x140001000, "Dispatch", "[]", "pdb", 0, None, None),
                    (1, 0x140002000, "Helper", "[]", "pdb", 0, None, None),
                    (1, 0x140002800, "NewCaller", "[]", "pdb", 0, None, None),
                    (1, 0x140003000, "nt!ProbeForRead", "[]", "pdb", 0, None, None),
                    (1, 0x140003100, "nt!ProbeForWrite", "[]", "pdb", 0, None, None),
                    (1, 0x140003200, "nt!RtlCopyMemory", "[]", "pdb", 0, None, None),
                    (1, 0x140003300, "nt!ZwOpenProcess", "[]", "pdb", 0, None, None),
                    (1, 0x140004000, "OldHelper", "[]", "pdb", 0, None, None),
                ],
            )
            conn.commit()
        finally:
            conn.close()

    before_conn = sqlite3.connect(before)
    try:
        before_conn.executemany(
            "INSERT INTO xrefs VALUES (?, ?, ?, ?, ?, ?, ?)",
            [
                (1, 1, 0x140001010, 0x140003000, "call", 0x140001000, 0),
                (2, 1, 0x140001020, 0x140003200, "call", 0x140001000, 0),
                (3, 1, 0x140002010, 0x140004000, "call", 0x140002000, 0),
            ],
        )
        before_conn.commit()
    finally:
        before_conn.close()

    after_conn = sqlite3.connect(after)
    try:
        after_conn.executemany(
            "INSERT INTO xrefs VALUES (?, ?, ?, ?, ?, ?, ?)",
            [
                (1, 1, 0x140001018, 0x140003100, "call", 0x140001000, 0),
                (2, 1, 0x140001028, 0x140003200, "call", 0x140001000, 0),
                (3, 1, 0x140002820, 0x140003300, "call", 0x140002800, 0),
            ],
        )
        after_conn.commit()
    finally:
        after_conn.close()


def _seed_project_guards(before: Path, after: Path) -> None:
    for path in (before, after):
        conn = sqlite3.connect(path)
        try:
            conn.executescript(
                """
CREATE TABLE IF NOT EXISTS function_names (
    binary_id INTEGER NOT NULL,
    entry_va INTEGER NOT NULL,
    canonical TEXT NOT NULL,
    aliases_json TEXT NOT NULL DEFAULT '[]',
    set_by TEXT,
    set_at INTEGER,
    demangled TEXT,
    flavor TEXT,
    PRIMARY KEY (binary_id, entry_va)
);
CREATE TABLE IF NOT EXISTS cfg_branch_facts (
    binary_id INTEGER NOT NULL,
    function_va INTEGER NOT NULL,
    block_id TEXT NOT NULL,
    branch_va INTEGER NOT NULL,
    branch_mnemonic TEXT NOT NULL,
    branch_operands_json TEXT NOT NULL DEFAULT '[]',
    compare_va INTEGER,
    compare_mnemonic TEXT,
    compare_operands_json TEXT NOT NULL DEFAULT '[]',
    condition_kind TEXT NOT NULL,
    target_block_id TEXT,
    fallthrough_block_id TEXT,
    indexed_at INTEGER NOT NULL,
    PRIMARY KEY (binary_id, function_va, block_id, branch_va)
);
CREATE TABLE IF NOT EXISTS callsite_path_conditions (
    binary_id INTEGER NOT NULL,
    callsite_va INTEGER NOT NULL,
    caller_va INTEGER,
    block_id TEXT NOT NULL,
    branch_va INTEGER NOT NULL,
    branch_mnemonic TEXT NOT NULL,
    branch_operands_json TEXT NOT NULL DEFAULT '[]',
    compare_va INTEGER,
    compare_mnemonic TEXT,
    compare_operands_json TEXT NOT NULL DEFAULT '[]',
    condition_kind TEXT NOT NULL,
    condition_role TEXT NOT NULL,
    target_block_id TEXT,
    fallthrough_block_id TEXT,
    distance_bytes INTEGER,
    confidence REAL NOT NULL,
    provenance_json TEXT NOT NULL DEFAULT '[]',
    indexed_at INTEGER NOT NULL,
    PRIMARY KEY (binary_id, callsite_va, branch_va)
);
DELETE FROM function_names;
DELETE FROM cfg_branch_facts;
DELETE FROM callsite_path_conditions;
"""
            )
            conn.execute(
                "INSERT INTO function_names VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (1, 0x140001000, "Dispatch", "[]", "pdb", 0, None, None),
            )
            conn.commit()
        finally:
            conn.close()

    before_conn = sqlite3.connect(before)
    try:
        before_conn.executemany(
            "INSERT INTO cfg_branch_facts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    1,
                    0x140001000,
                    "bb0",
                    0x140001010,
                    "jb",
                    json.dumps(["0x140001080"]),
                    0x14000100C,
                    "cmp",
                    json.dumps(["Length", "OutputBufferLength"]),
                    "unsigned_less",
                    "bb_ok",
                    "bb_fail",
                    0,
                ),
                (
                    1,
                    0x140001000,
                    "bb1",
                    0x140001020,
                    "je",
                    json.dumps(["0x140001090"]),
                    0x14000101A,
                    "cmp",
                    json.dumps(["RequestorMode", "KernelMode"]),
                    "equal",
                    "bb_kernel",
                    "bb_user",
                    0,
                ),
            ],
        )
        before_conn.execute(
            "INSERT INTO callsite_path_conditions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                1,
                0x140001060,
                0x140001000,
                "bb0",
                0x140001010,
                "jb",
                json.dumps(["0x140001080"]),
                0x14000100C,
                "cmp",
                json.dumps(["Length", "OutputBufferLength"]),
                "unsigned_less",
                "length_bound",
                "bb_ok",
                "bb_fail",
                80,
                0.82,
                json.dumps(["cfg_branch_facts"]),
                0,
            ),
        )
        before_conn.commit()
    finally:
        before_conn.close()

    after_conn = sqlite3.connect(after)
    try:
        after_conn.executemany(
            "INSERT INTO cfg_branch_facts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    1,
                    0x140001000,
                    "bb0",
                    0x140001012,
                    "jbe",
                    json.dumps(["0x140001080"]),
                    0x14000100C,
                    "cmp",
                    json.dumps(["Length", "OutputBufferLength"]),
                    "unsigned_less_equal",
                    "bb_ok",
                    "bb_fail",
                    0,
                ),
                (
                    1,
                    0x140001000,
                    "bb1",
                    0x140001030,
                    "je",
                    json.dumps(["0x140001090"]),
                    0x14000102A,
                    "cmp",
                    json.dumps(["RequestorMode", "KernelMode"]),
                    "equal",
                    "bb_kernel",
                    "bb_user",
                    0,
                ),
            ],
        )
        after_conn.execute(
            "INSERT INTO callsite_path_conditions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                1,
                0x140001068,
                0x140001000,
                "bb0",
                0x140001012,
                "jbe",
                json.dumps(["0x140001080"]),
                0x14000100C,
                "cmp",
                json.dumps(["Length", "OutputBufferLength"]),
                "unsigned_less_equal",
                "length_bound",
                "bb_ok",
                "bb_fail",
                86,
                0.82,
                json.dumps(["cfg_branch_facts"]),
                0,
            ),
        )
        after_conn.commit()
    finally:
        after_conn.close()


def _seed_project_memory_accesses(before: Path, after: Path) -> None:
    for path in (before, after):
        conn = sqlite3.connect(path)
        try:
            conn.executescript(
                """
CREATE TABLE IF NOT EXISTS function_names (
    binary_id INTEGER NOT NULL,
    entry_va INTEGER NOT NULL,
    canonical TEXT NOT NULL,
    aliases_json TEXT NOT NULL DEFAULT '[]',
    set_by TEXT,
    set_at INTEGER,
    demangled TEXT,
    flavor TEXT,
    PRIMARY KEY (binary_id, entry_va)
);
CREATE TABLE IF NOT EXISTS memory_operand_facts (
    binary_id INTEGER NOT NULL,
    function_va INTEGER NOT NULL,
    function_name TEXT,
    instruction_va INTEGER NOT NULL,
    instruction_text TEXT NOT NULL,
    mnemonic TEXT NOT NULL,
    operand_index INTEGER NOT NULL,
    operand_text TEXT NOT NULL,
    access_kind TEXT NOT NULL,
    width_bytes INTEGER,
    address_expression TEXT NOT NULL,
    base_register TEXT,
    index_register TEXT,
    scale INTEGER,
    displacement INTEGER NOT NULL DEFAULT 0,
    role_hint TEXT NOT NULL,
    base_object TEXT,
    base_object_kind TEXT,
    base_object_type TEXT,
    base_object_role TEXT,
    field_offset INTEGER NOT NULL DEFAULT 0,
    likely_field_name TEXT,
    likely_type_name TEXT,
    data_target_va INTEGER,
    data_target_kind TEXT,
    data_target_name TEXT,
    data_target_type TEXT,
    data_target_size INTEGER,
    confidence REAL NOT NULL,
    set_by TEXT NOT NULL,
    set_at INTEGER NOT NULL,
    PRIMARY KEY (binary_id, function_va, instruction_va, operand_index)
);
DELETE FROM function_names;
DELETE FROM memory_operand_facts;
"""
            )
            conn.execute(
                "INSERT INTO function_names VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (1, 0x140001000, "Dispatch", "[]", "pdb", 0, None, None),
            )
            conn.commit()
        finally:
            conn.close()

    before_conn = sqlite3.connect(before)
    try:
        before_conn.executemany(
            "INSERT INTO memory_operand_facts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                _memory_row(
                    0x140001020,
                    "mov [rcx+18h], rdx",
                    "write",
                    8,
                    "Irp",
                    "user_pointer",
                    "UserBuffer",
                    "IRP",
                    None,
                    None,
                    None,
                ),
                _memory_row(
                    0x140001030,
                    "mov eax, [rcx+30h]",
                    "read",
                    4,
                    "IoStack",
                    "stack_local",
                    "InputBufferLength",
                    "IO_STACK_LOCATION",
                    None,
                    None,
                    None,
                ),
            ],
        )
        before_conn.commit()
    finally:
        before_conn.close()

    after_conn = sqlite3.connect(after)
    try:
        after_conn.executemany(
            "INSERT INTO memory_operand_facts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                _memory_row(
                    0x140001028,
                    "mov [rcx+18h], r8",
                    "write",
                    8,
                    "Irp",
                    "user_pointer",
                    "UserBuffer",
                    "IRP",
                    None,
                    None,
                    None,
                ),
                _memory_row(
                    0x140001038,
                    "mov rax, [rcx+30h]",
                    "read",
                    8,
                    "IoStack",
                    "stack_local",
                    "InputBufferLength",
                    "IO_STACK_LOCATION",
                    None,
                    None,
                    None,
                ),
                _memory_row(
                    0x140001050,
                    "mov [rip+3000h], rax",
                    "write",
                    8,
                    "driver!CallbackTable",
                    "global",
                    "CallbackTable",
                    "PDRIVER_DISPATCH",
                    0x140030000,
                    "driver!CallbackTable",
                    "PDRIVER_DISPATCH[4]",
                ),
            ],
        )
        after_conn.commit()
    finally:
        after_conn.close()


def _memory_row(
    instruction_va: int,
    instruction_text: str,
    access_kind: str,
    width_bytes: int,
    base_object: str,
    base_object_kind: str,
    likely_field_name: str,
    likely_type_name: str,
    data_target_va: int | None,
    data_target_name: str | None,
    data_target_type: str | None,
) -> tuple[object, ...]:
    return (
        1,
        0x140001000,
        "Dispatch",
        instruction_va,
        instruction_text,
        "mov",
        0,
        instruction_text.split(" ", 2)[1].rstrip(","),
        access_kind,
        width_bytes,
        "rcx+0x18" if likely_field_name == "UserBuffer" else "rcx+0x30",
        None,
        None,
        None,
        0x18 if likely_field_name == "UserBuffer" else 0x30,
        "memory",
        base_object,
        base_object_kind,
        likely_type_name,
        "irp" if likely_field_name == "UserBuffer" else "field",
        0x18 if likely_field_name == "UserBuffer" else 0x30,
        likely_field_name,
        likely_type_name,
        data_target_va,
        "global" if data_target_va is not None else None,
        data_target_name,
        data_target_type,
        None,
        0.86,
        "test",
        0,
    )


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


def test_windows_patch_diff_review_ranks_project_boundary_deltas(
    tmp_path: Path,
) -> None:
    a = _need(_SWITCHY_V1)
    b = _need(_SWITCHY_V2)
    before_project = _project(tmp_path, "before")
    after_project = _project(tmp_path, "after")
    _seed_project_boundaries(before_project, after_project)

    result = run_windows_patch_diff_review(
        WindowsPatchDiffReviewConfig(
            binary_a=str(a),
            binary_b=str(b),
            before_project_path=str(before_project),
            after_project_path=str(after_project),
            max_items=20,
        )
    )

    assert result.boundary_diff is not None
    assert result.boundary_diff.changed_count == 2
    assert "windows_project_function_boundary_diff" in result.tool_sequence
    assert "project_boundary_deltas" in result.evidence_bundle.coverage.fact_coverage
    assert result.evidence_bundle.subject.attributes["boundary_delta_count"] == 2
    boundary_items = [
        item for item in result.review_items if item.kind == "boundary_delta"
    ]
    assert boundary_items
    assert any(
        "project_function_boundary_diff" in item.match_basis for item in boundary_items
    )
    assert any("function_range_delta" in item.reason_codes for item in boundary_items)
    assert any("thunk_delta" in item.reason_codes for item in boundary_items)


def test_windows_patch_diff_review_ranks_project_data_table_deltas(
    tmp_path: Path,
) -> None:
    a = _need(_SWITCHY_V1)
    b = _need(_SWITCHY_V2)
    before_project = _project(tmp_path, "before")
    after_project = _project(tmp_path, "after")
    _seed_project_tables(before_project, after_project)

    result = run_windows_patch_diff_review(
        WindowsPatchDiffReviewConfig(
            binary_a=str(a),
            binary_b=str(b),
            before_project_path=str(before_project),
            after_project_path=str(after_project),
            max_items=20,
        )
    )

    assert result.data_table_diff is not None
    assert result.data_table_diff.changed_count == 2
    assert result.data_table_diff.added_count == 1
    assert result.data_table_diff.removed_count == 1
    assert "windows_project_data_table_diff" in result.tool_sequence
    assert "project_data_table_deltas" in result.evidence_bundle.coverage.fact_coverage
    assert result.evidence_bundle.subject.attributes["table_delta_count"] == 4
    table_items = [item for item in result.review_items if item.kind == "table_delta"]
    assert table_items
    assert any("project_data_table_diff" in item.match_basis for item in table_items)
    assert any("table_target_delta" in item.reason_codes for item in table_items)
    assert any("dispatch_table" in item.reason_codes for item in table_items)


def test_windows_patch_diff_review_ranks_project_callgraph_deltas(
    tmp_path: Path,
) -> None:
    a = _need(_SWITCHY_V1)
    b = _need(_SWITCHY_V2)
    before_project = _project(tmp_path, "before")
    after_project = _project(tmp_path, "after")
    _seed_project_callgraphs(before_project, after_project)

    result = run_windows_patch_diff_review(
        WindowsPatchDiffReviewConfig(
            binary_a=str(a),
            binary_b=str(b),
            before_project_path=str(before_project),
            after_project_path=str(after_project),
            max_items=20,
        )
    )

    assert result.callgraph_diff is not None
    assert result.callgraph_diff.changed_count == 1
    assert result.callgraph_diff.added_count == 2
    assert result.callgraph_diff.removed_count == 2
    assert "windows_project_callgraph_diff" in result.tool_sequence
    assert "project_callgraph_deltas" in result.evidence_bundle.coverage.fact_coverage
    assert result.evidence_bundle.subject.attributes["callgraph_delta_count"] == 5
    callgraph_items = [
        item for item in result.review_items if item.kind == "callgraph_delta"
    ]
    assert callgraph_items
    assert any("project_callgraph_diff" in item.match_basis for item in callgraph_items)
    assert any(
        "sink_or_api_call_delta" in item.reason_codes for item in callgraph_items
    )


def test_windows_patch_diff_review_ranks_project_guard_deltas(
    tmp_path: Path,
) -> None:
    a = _need(_SWITCHY_V1)
    b = _need(_SWITCHY_V2)
    before_project = _project(tmp_path, "before")
    after_project = _project(tmp_path, "after")
    _seed_project_guards(before_project, after_project)

    result = run_windows_patch_diff_review(
        WindowsPatchDiffReviewConfig(
            binary_a=str(a),
            binary_b=str(b),
            before_project_path=str(before_project),
            after_project_path=str(after_project),
            max_items=20,
        )
    )

    assert result.guard_condition_diff is not None
    assert result.guard_condition_diff.changed_count == 1
    assert result.guard_condition_diff.added_count == 2
    assert result.guard_condition_diff.removed_count == 2
    assert "windows_project_guard_condition_diff" in result.tool_sequence
    assert (
        "project_guard_condition_deltas"
        in result.evidence_bundle.coverage.fact_coverage
    )
    assert result.evidence_bundle.subject.attributes["guard_delta_count"] == 5
    guard_items = [item for item in result.review_items if item.kind == "guard_delta"]
    assert guard_items
    assert any(
        "project_guard_condition_diff" in item.match_basis for item in guard_items
    )
    assert any("bounds_guard_delta" in item.reason_codes for item in guard_items)
    assert any("guard_removed" in item.reason_codes for item in guard_items)


def test_windows_patch_diff_review_ranks_project_memory_access_deltas(
    tmp_path: Path,
) -> None:
    a = _need(_SWITCHY_V1)
    b = _need(_SWITCHY_V2)
    before_project = _project(tmp_path, "before")
    after_project = _project(tmp_path, "after")
    _seed_project_memory_accesses(before_project, after_project)

    result = run_windows_patch_diff_review(
        WindowsPatchDiffReviewConfig(
            binary_a=str(a),
            binary_b=str(b),
            before_project_path=str(before_project),
            after_project_path=str(after_project),
            max_items=20,
        )
    )

    assert result.memory_access_diff is not None
    assert result.memory_access_diff.changed_count == 2
    assert result.memory_access_diff.added_count == 1
    assert "windows_project_memory_access_diff" in result.tool_sequence
    assert (
        "project_memory_access_deltas" in result.evidence_bundle.coverage.fact_coverage
    )
    assert result.evidence_bundle.subject.attributes["memory_access_delta_count"] == 3
    memory_items = [
        item for item in result.review_items if item.kind == "memory_access_delta"
    ]
    assert memory_items
    assert any(
        "project_memory_access_diff" in item.match_basis for item in memory_items
    )
    assert any("memory_write_delta" in item.reason_codes for item in memory_items)
    assert any(
        "user_or_request_memory_delta" in item.reason_codes for item in memory_items
    )


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
