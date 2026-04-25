"""Tests for rename consistency verification (#201 v0)."""

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


def test_family_keyword_dispatch() -> None:
    """Hand-coded sanity: name-keyword dispatch picks the obvious
    family for canonical analyst-rename styles."""
    cases = [
        ("free_session_state", "memory_free"),
        ("alloc_request_buf", "memory_alloc"),
        ("parse_packet", "parse"),
        ("format_response", "format"),
        ("encrypt_payload", "crypto"),
        ("send_beacon", "network"),
        ("open_config_file", "file_io"),
        ("strcopy_safe", "string"),
        ("spawn_worker", "process"),
        ("totally_unknown_function", None),
    ]
    for name, expected_family in cases:
        got = xref_db._family_for_name(name)
        actual = got[0] if got else None
        assert actual == expected_family, (
            f"name {name!r} → {actual!r}, expected {expected_family!r}"
        )


def test_no_callees_flag(tmp_path: Path) -> None:
    """Functions with zero outgoing call edges produce a `no-callees`
    flag — the verifier can't make a meaningful claim either way."""
    binary = _need(_HELLO)
    db = tmp_path / "v.glaurung"
    kb = PersistentKnowledgeBase.open(db, binary_path=binary)
    xref_db.set_function_name(kb, 0x1000, "leaf_function", set_by="manual")
    res = xref_db.verify_function_name(kb, 0x1000)
    assert res is not None
    assert res.callee_count == 0
    assert "no-callees" in res.flags
    kb.close()


def test_family_mismatch_flag(tmp_path: Path) -> None:
    """Function named `free_session` but its callees are all
    parser-shaped should flag `family-mismatch`."""
    binary = _need(_HELLO)
    db = tmp_path / "v.glaurung"
    kb = PersistentKnowledgeBase.open(db, binary_path=binary)
    # Set up the function and its callees.
    xref_db.set_function_name(kb, 0x2000, "free_session", set_by="manual")
    # Register PLT-style callees that DON'T match memory_free family.
    for va, callee in [
        (0x100, "strchr@plt"),
        (0x110, "strtol@plt"),
        (0x120, "atoi@plt"),
    ]:
        xref_db.set_function_name(kb, va, callee, set_by="analyzer")
        xref_db.add_xref(
            kb, src_va=0x2000 + 0x10, dst_va=va, kind="call",
            src_function_va=0x2000,
        )
    res = xref_db.verify_function_name(kb, 0x2000)
    assert res is not None
    assert res.matched_family == "memory_free"
    assert "family-mismatch" in res.flags
    assert res.score == 0.0  # no matching callees
    assert res.foreign_callees  # the parser-shaped callees show up here
    kb.close()


def test_consistent_rename_scores_high(tmp_path: Path) -> None:
    """A function named `parse_request` whose callees are
    parser-shaped (strchr / strtol / atoi) should score 1.0."""
    binary = _need(_HELLO)
    db = tmp_path / "v.glaurung"
    kb = PersistentKnowledgeBase.open(db, binary_path=binary)
    xref_db.set_function_name(kb, 0x3000, "parse_request", set_by="manual")
    for va, callee in [
        (0x300, "strchr@plt"),
        (0x310, "strtol@plt"),
        (0x320, "atoi@plt"),
    ]:
        xref_db.set_function_name(kb, va, callee, set_by="analyzer")
        xref_db.add_xref(
            kb, src_va=0x3000 + 0x10, dst_va=va, kind="call",
            src_function_va=0x3000,
        )
    res = xref_db.verify_function_name(kb, 0x3000)
    assert res is not None
    assert res.matched_family == "parse"
    assert res.score == 1.0
    assert "family-mismatch" not in res.flags
    assert len(res.matching_callees) == 3
    kb.close()


def test_audited_rename_inlines_warning_in_summary(tmp_path: Path) -> None:
    """When set_function_name_audited runs the verifier and finds a
    family mismatch, the evidence row's summary should include an
    inline ⚠ marker so the chat UI surfaces it without expanding the
    cite pane."""
    binary = _need(_HELLO)
    db = tmp_path / "v.glaurung"
    kb = PersistentKnowledgeBase.open(db, binary_path=binary)

    # Set up callees that look parser-shaped.
    for va, callee in [
        (0x500, "strchr@plt"),
        (0x510, "atoi@plt"),
        (0x520, "strtok@plt"),
    ]:
        xref_db.set_function_name(kb, va, callee, set_by="analyzer")
        xref_db.add_xref(
            kb, src_va=0x4000 + 0x10, dst_va=va, kind="call",
            src_function_va=0x4000,
        )
    # Now rename to something memory-shaped (mismatch).
    cite_id, _new = xref_db.set_function_name_audited(
        kb, 0x4000, "free_resources", set_by="manual",
        rationale="suspected cleanup function",
    )
    rec = xref_db.get_evidence(kb, cite_id)
    assert rec is not None
    # Summary contains the inline warning.
    assert "⚠" in rec.summary or "inconsistency" in rec.summary
    # Output structure exposes the verification fields.
    v = rec.output["verification"]
    assert v["matched_family"] == "memory_free"
    assert "family-mismatch" in v["flags"]
    kb.close()
