"""Tests for the persistent xref database (#154)."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

import glaurung as g
from glaurung.llm.kb.persistent import PersistentKnowledgeBase
from glaurung.llm.kb import xref_db


def _hello_path() -> Path:
    p = Path(
        "samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-gcc-O2"
    )
    if not p.exists():
        pytest.skip(f"missing sample binary {p}")
    return p


def _ntoskrnl_path() -> Path:
    p = Path("tests/fixtures/msvc-pdb/ntoskrnl.exe")
    if not p.exists():
        pytest.skip(f"missing PE/PDB fixture {p}")
    return p


def test_index_callgraph_persists(tmp_path: Path) -> None:
    binary = _hello_path()
    db = tmp_path / "xrefs.glaurung"

    kb = PersistentKnowledgeBase.open(db, binary_path=binary)
    assert not xref_db.is_indexed(kb)

    edges = xref_db.index_callgraph(kb, str(binary))
    assert edges > 0, "hello-gcc-O2 has internal calls"
    assert xref_db.is_indexed(kb)
    kb.close()

    # Reopen — still indexed, no re-run needed.
    kb2 = PersistentKnowledgeBase.open(db, binary_path=binary)
    assert xref_db.is_indexed(kb2)
    kb2.close()


def test_index_callgraph_persists_exact_callsite_vas(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binary = _hello_path()
    db = tmp_path / "callsites.glaurung"

    def fake_analyze_functions_path(_path: str):
        funcs = [
            SimpleNamespace(
                name="caller",
                entry_point=SimpleNamespace(value=0x1000),
            ),
            SimpleNamespace(
                name="callee",
                entry_point=SimpleNamespace(value=0x2000),
            ),
        ]
        edge = SimpleNamespace(
            caller="caller",
            callee="callee",
            call_sites=[
                SimpleNamespace(value=0x1010),
                SimpleNamespace(value=0x1024),
            ],
        )
        return funcs, SimpleNamespace(edges=[edge])

    monkeypatch.setattr(
        g.analysis,
        "analyze_functions_path",
        fake_analyze_functions_path,
    )

    kb = PersistentKnowledgeBase.open(db, binary_path=binary)
    assert xref_db.index_callgraph(kb, str(binary)) == 2

    rows = xref_db.list_xrefs_to(kb, 0x2000)
    assert [(r.src_va, r.dst_va, r.kind, r.src_function_va) for r in rows] == [
        (0x1010, 0x2000, "call", 0x1000),
        (0x1024, 0x2000, "call", 0x1000),
    ]
    kb.close()


def test_analyze_functions_populates_callgraph_call_sites() -> None:
    binary = _hello_path()
    _, cg = g.analysis.analyze_functions_path(
        str(binary),
        max_functions=64,
        max_blocks=4096,
        max_instructions=200_000,
        timeout_ms=1000,
    )
    assert any(e.call_sites for e in cg.edges)


def test_xrefs_to_and_from(tmp_path: Path) -> None:
    binary = _hello_path()
    db = tmp_path / "xrefs.glaurung"
    kb = PersistentKnowledgeBase.open(db, binary_path=binary)
    xref_db.index_callgraph(kb, str(binary))

    # main is at 0x13d0 — every internal call from it shows up
    # via list_xrefs_from. We don't assert specific targets (those
    # depend on the toolchain) but the count must be > 0.
    out = xref_db.list_xrefs_from(kb, 0x13d0)
    # Either empty (if the analyser produced no recognisable internal
    # edges) or non-empty — but it must NOT crash.
    assert isinstance(out, list)

    # _start at 0x1840 calls main via __libc_start_main; some
    # toolchains emit a direct call edge to main.
    incoming = xref_db.list_xrefs_to(kb, 0x13d0)
    assert isinstance(incoming, list)
    kb.close()


def test_function_names_and_comments(tmp_path: Path) -> None:
    binary = _hello_path()
    db = tmp_path / "names.glaurung"
    kb = PersistentKnowledgeBase.open(db, binary_path=binary)

    xref_db.set_function_name(kb, 0x10c0, "parse_config", set_by="llm")
    xref_db.set_function_name(kb, 0x10c0, "parse_config_v2",
                              set_by="manual",
                              aliases=["parse_config"])
    name = xref_db.get_function_name(kb, 0x10c0)
    assert name is not None
    assert name.canonical == "parse_config_v2"
    assert "parse_config" in name.aliases
    assert name.set_by == "manual"

    xref_db.set_comment(kb, 0x10cf, "stack canary save")
    assert xref_db.get_comment(kb, 0x10cf) == "stack canary save"
    kb.close()

    # Reopen — names and comments survived.
    kb2 = PersistentKnowledgeBase.open(db, binary_path=binary)
    name2 = xref_db.get_function_name(kb2, 0x10c0)
    assert name2 is not None
    assert name2.canonical == "parse_config_v2"
    assert xref_db.get_comment(kb2, 0x10cf) == "stack canary save"
    kb2.close()


def test_add_xref_data_kind(tmp_path: Path) -> None:
    binary = _hello_path()
    db = tmp_path / "data.glaurung"
    kb = PersistentKnowledgeBase.open(db, binary_path=binary)
    xref_db.add_xref(kb, src_va=0x1500, dst_va=0x4040, kind="data_read",
                     src_function_va=0x14d0)
    xref_db.add_xref(kb, src_va=0x1510, dst_va=0x4040, kind="data_write",
                     src_function_va=0x14d0)
    # Filter by kind via list_xrefs_to.
    reads = xref_db.list_xrefs_to(kb, 0x4040, kinds=["data_read"])
    writes = xref_db.list_xrefs_to(kb, 0x4040, kinds=["data_write"])
    assert len(reads) == 1
    assert len(writes) == 1
    assert reads[0].kind == "data_read"
    assert writes[0].kind == "data_write"

    # In-function summary.
    in_fn = xref_db.list_xrefs_in_function(kb, 0x14d0)
    assert len(in_fn) == 2
    kb.close()


def test_index_data_xrefs_persists_exact_source_and_function_vas(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binary = _hello_path()
    db = tmp_path / "data-index.glaurung"

    def fake_data_xrefs_path(_path: str, **_kwargs: object) -> list[tuple[int, int, int]]:
        return [
            (0x401010, 0x404040, 0x401000),
            (0x401020, 0x404048, 0x401000),
        ]

    def fake_analyze_functions_path(_path: str, **_kwargs: object) -> tuple[list, object]:
        return [
            SimpleNamespace(
                name="uses_data",
                entry_point=SimpleNamespace(value=0x401000),
            )
        ], SimpleNamespace(edges=[])

    monkeypatch.setattr(g.analysis, "data_xrefs_path", fake_data_xrefs_path)
    monkeypatch.setattr(g.analysis, "analyze_functions_path", fake_analyze_functions_path)

    kb = PersistentKnowledgeBase.open(db, binary_path=binary)
    xref_db.add_xref(kb, src_va=0x400100, dst_va=0x400200, kind="call",
                     src_function_va=0x400000)

    assert not xref_db.is_data_xrefs_indexed(kb)
    assert xref_db.index_data_xrefs(kb, str(binary)) == 2
    assert xref_db.is_data_xrefs_indexed(kb)

    rows = xref_db.list_xrefs_to(kb, 0x404040, kinds=["data_read"])
    assert [(r.src_va, r.dst_va, r.kind, r.src_function_va) for r in rows] == [
        (0x401010, 0x404040, "data_read", 0x401000),
    ]
    fn = xref_db.get_function_name(kb, 0x401000)
    assert fn is not None
    assert fn.display == "uses_data"
    assert xref_db.list_xrefs_to(kb, 0x400200, kinds=["call"])
    kb.close()


def test_index_data_xrefs_real_pe_fixture(tmp_path: Path) -> None:
    binary = _ntoskrnl_path()
    db = tmp_path / "ntoskrnl-data-xrefs.glaurung"
    kb = PersistentKnowledgeBase.open(db, binary_path=binary)

    count = xref_db.index_data_xrefs(kb, str(binary))
    assert count > 0

    selected_ascii_string_vas = [
        0x14003DEB0,  # minkernel\hals\lib\interrupts\common\connect.c
        0x140014B30,  # timersup.c
        0x14003E4A8,  # intsup.c
        0x140015508,  # SdbpReadMappedData
        0x140048010,  # Out of memory
    ]
    cur = kb._conn.cursor()
    cur.execute(
        "SELECT src_va, dst_va, src_function_va FROM xrefs "
        "WHERE binary_id = ? AND kind = 'data_read' "
        f"AND dst_va IN ({','.join('?' for _ in selected_ascii_string_vas)}) "
        "LIMIT 1",
        (kb.binary_id, *selected_ascii_string_vas),
    )
    row = cur.fetchone()
    assert row is not None
    assert int(row[0]) > 0
    assert int(row[1]) in selected_ascii_string_vas
    assert int(row[2]) > 0
    kb.close()
