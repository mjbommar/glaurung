"""Tests for the evidence-log persistence layer (#200 v0)."""

from __future__ import annotations

from pathlib import Path

import pytest

from glaurung.llm.kb import xref_db
from glaurung.llm.kb.persistent import PersistentKnowledgeBase


_HELLO = Path(
    "samples/binaries/platforms/linux/amd64/export/native/clang/debug/hello-clang-debug"
)


def _need(p: Path) -> Path:
    if not p.exists():
        pytest.skip(f"missing path {p}")
    return p


def test_record_get_round_trip(tmp_path: Path) -> None:
    binary = _need(_HELLO)
    db = tmp_path / "ev.glaurung"
    kb = PersistentKnowledgeBase.open(db, binary_path=binary)

    cid = xref_db.record_evidence(
        kb,
        tool="view_hex",
        args={"va": 0x12d0, "length": 32},
        summary="hex dump @main entry",
        va_start=0x12d0, va_end=0x12d0 + 32,
        output={"bytes_hex": "55488..."},
    )
    assert cid >= 1

    rec = xref_db.get_evidence(kb, cid)
    assert rec is not None
    assert rec.tool == "view_hex"
    assert rec.args["va"] == 0x12d0
    assert rec.summary == "hex dump @main entry"
    assert rec.va_start == 0x12d0
    assert rec.va_end == 0x12d0 + 32
    assert rec.output and rec.output["bytes_hex"].startswith("55")
    kb.close()


def test_cite_ids_are_monotonic(tmp_path: Path) -> None:
    """Successive record_evidence calls must return strictly
    increasing cite_ids — agent-quoted citations need stable
    ordering for chat-UI rendering."""
    binary = _need(_HELLO)
    db = tmp_path / "ev.glaurung"
    kb = PersistentKnowledgeBase.open(db, binary_path=binary)
    ids = [
        xref_db.record_evidence(
            kb, tool="t", args={}, summary=f"row {i}",
        )
        for i in range(5)
    ]
    assert ids == sorted(ids)
    assert len(set(ids)) == len(ids)  # unique
    kb.close()


def test_list_evidence_filters_by_tool(tmp_path: Path) -> None:
    binary = _need(_HELLO)
    db = tmp_path / "ev.glaurung"
    kb = PersistentKnowledgeBase.open(db, binary_path=binary)

    xref_db.record_evidence(kb, tool="view_hex", args={}, summary="a")
    xref_db.record_evidence(kb, tool="decompile", args={}, summary="b")
    xref_db.record_evidence(kb, tool="view_hex", args={}, summary="c")

    only_hex = xref_db.list_evidence(kb, tool="view_hex")
    assert len(only_hex) == 2
    assert all(e.tool == "view_hex" for e in only_hex)
    only_decomp = xref_db.list_evidence(kb, tool="decompile")
    assert [e.summary for e in only_decomp] == ["b"]
    kb.close()


def test_list_evidence_filters_by_va(tmp_path: Path) -> None:
    binary = _need(_HELLO)
    db = tmp_path / "ev.glaurung"
    kb = PersistentKnowledgeBase.open(db, binary_path=binary)

    xref_db.record_evidence(
        kb, tool="t", args={}, summary="covers main",
        va_start=0x1000, va_end=0x2000,
    )
    xref_db.record_evidence(
        kb, tool="t", args={}, summary="covers init",
        va_start=0x3000, va_end=0x3100,
    )
    xref_db.record_evidence(
        kb, tool="t", args={}, summary="whole-file",
        # no va_start → matches every va query
    )

    main = xref_db.list_evidence(kb, va=0x1234)
    summaries = {e.summary for e in main}
    assert "covers main" in summaries
    assert "whole-file" in summaries  # NULL va matches all VAs
    assert "covers init" not in summaries
    kb.close()


def test_render_markdown_compact(tmp_path: Path) -> None:
    binary = _need(_HELLO)
    db = tmp_path / "ev.glaurung"
    kb = PersistentKnowledgeBase.open(db, binary_path=binary)
    cid = xref_db.record_evidence(
        kb, tool="scan_until_byte", args={"file_offset": 0x100},
        summary="found null at offset 0x150",
        file_offset=0x150,
    )
    md = xref_db.render_evidence_markdown(xref_db.list_evidence(kb))
    assert f"#{cid}" in md
    assert "scan_until_byte" in md
    assert "found null" in md


def test_rename_function_audited_records_evidence(tmp_path: Path) -> None:
    """`set_function_name_audited` should rename the function AND
    leave a cite-able audit row showing the before/after names."""
    binary = _need(_HELLO)
    db = tmp_path / "ev.glaurung"
    kb = PersistentKnowledgeBase.open(db, binary_path=binary)

    # Pre-populate function_names so we have a "before" name to rename.
    xref_db.set_function_name(kb, 0x12d0, "sub_12d0", set_by="analyzer")

    cite_id, new = xref_db.set_function_name_audited(
        kb, 0x12d0, "parse_request",
        set_by="manual",
        rationale="calls recv() then strchr('\\n')",
    )
    assert cite_id >= 1
    assert new is not None
    assert new.canonical == "parse_request"
    assert new.set_by == "manual"

    # Evidence row recorded with before/after names visible.
    rec = xref_db.get_evidence(kb, cite_id)
    assert rec is not None
    assert rec.tool == "rename_function"
    assert rec.args["old_name"] == "sub_12d0"
    assert rec.args["new_name"] == "parse_request"
    assert rec.args["rationale"]
    assert rec.va_start == 0x12d0
    kb.close()


def test_set_comment_audited_records_evidence(tmp_path: Path) -> None:
    binary = _need(_HELLO)
    db = tmp_path / "ev.glaurung"
    kb = PersistentKnowledgeBase.open(db, binary_path=binary)

    cite_id = xref_db.set_comment_audited(
        kb, va=0x12cf, body="stack canary save",
    )
    rec = xref_db.get_evidence(kb, cite_id)
    assert rec is not None
    assert rec.tool == "set_comment"
    assert rec.args["body"] == "stack canary save"
    # Underlying comment table also got the row.
    assert xref_db.get_comment(kb, 0x12cf) == "stack canary save"
    kb.close()


def test_args_complex_types_round_trip(tmp_path: Path) -> None:
    """Args / output containing nested dicts and lists must round-trip
    through the JSON serialization."""
    binary = _need(_HELLO)
    db = tmp_path / "ev.glaurung"
    kb = PersistentKnowledgeBase.open(db, binary_path=binary)
    args = {"pattern": "48 8b ?? f8", "matches": [{"va": 0x1234, "off": 0x100}]}
    output = {"hits": 3, "samples": ["abc", "def"]}
    cid = xref_db.record_evidence(
        kb, tool="search_byte_pattern",
        args=args, summary="found 3 hits", output=output,
    )
    rec = xref_db.get_evidence(kb, cid)
    assert rec is not None
    assert rec.args == args
    assert rec.output == output
    kb.close()
