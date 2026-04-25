"""Tests for undo/redo on KB writes (#228)."""

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
        pytest.skip(f"missing {p}")
    return p


def _open(tmp_path: Path) -> PersistentKnowledgeBase:
    binary = _need(_HELLO)
    return PersistentKnowledgeBase.open(
        tmp_path / "undo.glaurung", binary_path=binary,
    )


def test_undo_reverts_function_rename(tmp_path: Path) -> None:
    kb = _open(tmp_path)
    xref_db.set_function_name(kb, 0x1000, "my_func", set_by="manual")
    assert xref_db.get_function_name(kb, 0x1000).canonical == "my_func"

    xref_db.set_function_name(kb, 0x1000, "renamed_func", set_by="manual")
    assert xref_db.get_function_name(kb, 0x1000).canonical == "renamed_func"

    applied = xref_db.undo(kb)
    assert len(applied) == 1
    assert applied[0].table_name == "function_names"
    assert xref_db.get_function_name(kb, 0x1000).canonical == "my_func"

    # One more undo deletes the row entirely (was a fresh insert).
    applied = xref_db.undo(kb)
    assert len(applied) == 1
    assert xref_db.get_function_name(kb, 0x1000) is None
    kb.close()


def test_redo_reapplies_undone_rename(tmp_path: Path) -> None:
    kb = _open(tmp_path)
    xref_db.set_function_name(kb, 0x1000, "first", set_by="manual")
    xref_db.set_function_name(kb, 0x1000, "second", set_by="manual")
    xref_db.undo(kb)
    assert xref_db.get_function_name(kb, 0x1000).canonical == "first"

    redone = xref_db.redo(kb)
    assert len(redone) == 1
    assert xref_db.get_function_name(kb, 0x1000).canonical == "second"
    kb.close()


def test_undo_does_not_record_non_manual_writes(tmp_path: Path) -> None:
    """Auto / dwarf / flirt / propagated writes must NOT clutter undo_log
    — they re-derive on the next pass and undoing them is meaningless."""
    kb = _open(tmp_path)
    xref_db.set_function_name(kb, 0x1000, "auto_name", set_by="auto")
    xref_db.set_function_name(kb, 0x1000, "dwarf_name", set_by="dwarf")
    xref_db.set_function_name(kb, 0x1000, "flirt_name", set_by="flirt")

    log = xref_db.list_undo_log(kb)
    assert log == []  # nothing recorded

    # A subsequent manual write IS recorded.
    xref_db.set_function_name(kb, 0x1000, "manual_name", set_by="manual")
    log = xref_db.list_undo_log(kb)
    assert len(log) == 1
    assert log[0].set_by == "manual"
    kb.close()


def test_undo_reverts_comment(tmp_path: Path) -> None:
    kb = _open(tmp_path)
    xref_db.set_comment(kb, 0x1010, "first note")
    xref_db.set_comment(kb, 0x1010, "second note")
    assert xref_db.get_comment(kb, 0x1010) == "second note"

    xref_db.undo(kb)
    assert xref_db.get_comment(kb, 0x1010) == "first note"

    xref_db.undo(kb)
    assert xref_db.get_comment(kb, 0x1010) is None
    kb.close()


def test_undo_reverts_data_label(tmp_path: Path) -> None:
    kb = _open(tmp_path)
    xref_db.set_data_label(
        kb, 0x4000, "g_buffer", c_type="char[256]", set_by="manual",
    )
    xref_db.set_data_label(
        kb, 0x4000, "g_renamed", c_type="char[256]", set_by="manual",
    )
    assert xref_db.get_data_label(kb, 0x4000).name == "g_renamed"

    xref_db.undo(kb)
    assert xref_db.get_data_label(kb, 0x4000).name == "g_buffer"
    kb.close()


def test_undo_reverts_stack_var(tmp_path: Path) -> None:
    kb = _open(tmp_path)
    xref_db.set_stack_var(
        kb, function_va=0x1000, offset=-0x10, name="local_a",
        c_type="int", set_by="manual",
    )
    xref_db.set_stack_var(
        kb, function_va=0x1000, offset=-0x10, name="local_renamed",
        c_type="long", set_by="manual",
    )
    cur = xref_db.get_stack_var(kb, 0x1000, -0x10)
    assert cur.name == "local_renamed"
    assert cur.c_type == "long"

    xref_db.undo(kb)
    cur = xref_db.get_stack_var(kb, 0x1000, -0x10)
    assert cur.name == "local_a"
    assert cur.c_type == "int"
    kb.close()


def test_undo_n_walks_history_in_order(tmp_path: Path) -> None:
    kb = _open(tmp_path)
    for i, name in enumerate(["a", "b", "c", "d"]):
        xref_db.set_function_name(kb, 0x1000, name, set_by="manual")
    assert xref_db.get_function_name(kb, 0x1000).canonical == "d"

    applied = xref_db.undo(kb, n=3)
    assert len(applied) == 3
    assert xref_db.get_function_name(kb, 0x1000).canonical == "a"

    redone = xref_db.redo(kb, n=2)
    assert len(redone) == 2
    assert xref_db.get_function_name(kb, 0x1000).canonical == "c"
    kb.close()


def test_undo_skips_no_op_writes(tmp_path: Path) -> None:
    """Writing the same value twice should NOT create a second undo
    entry — there is nothing to undo."""
    kb = _open(tmp_path)
    xref_db.set_function_name(kb, 0x1000, "stable", set_by="manual")
    xref_db.set_function_name(kb, 0x1000, "stable", set_by="manual")
    log = xref_db.list_undo_log(kb)
    # Only the initial creation. Repeat with same value records nothing.
    assert len(log) == 1
    kb.close()


def test_list_undo_log_filters_undone(tmp_path: Path) -> None:
    kb = _open(tmp_path)
    xref_db.set_function_name(kb, 0x1000, "a", set_by="manual")
    xref_db.set_function_name(kb, 0x1000, "b", set_by="manual")
    xref_db.undo(kb)

    all_log = xref_db.list_undo_log(kb)
    active = xref_db.list_undo_log(kb, include_undone=False)
    assert len(all_log) == 2
    assert len(active) == 1
    kb.close()


def test_undo_redo_cli_smoke(tmp_path: Path) -> None:
    """Smoke-test `glaurung undo` / `glaurung redo` / `glaurung undo --list`."""
    import io
    from contextlib import redirect_stdout
    from glaurung.cli.main import GlaurungCLI

    kb = _open(tmp_path)
    db = kb._conn_path if hasattr(kb, "_conn_path") else None
    db_path = tmp_path / "undo.glaurung"
    xref_db.set_function_name(kb, 0x1000, "first", set_by="manual")
    xref_db.set_function_name(kb, 0x1000, "second", set_by="manual")
    kb.close()

    cli = GlaurungCLI()

    # `undo --list` prints both entries without mutating.
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = cli.run(["undo", str(db_path), "--list"])
    assert rc == 0
    out = buf.getvalue()
    assert "function_names" in out
    assert "first" in out and "second" in out

    # `undo` reverts second→first.
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = cli.run(["undo", str(db_path)])
    assert rc == 0
    assert "undo" in buf.getvalue()

    from glaurung.llm.kb.persistent import PersistentKnowledgeBase
    kb2 = PersistentKnowledgeBase.open(db_path)
    assert xref_db.get_function_name(kb2, 0x1000).canonical == "first"
    kb2.close()

    # `redo` re-applies first→second.
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = cli.run(["redo", str(db_path)])
    assert rc == 0
    assert "redo" in buf.getvalue()

    kb3 = PersistentKnowledgeBase.open(db_path)
    assert xref_db.get_function_name(kb3, 0x1000).canonical == "second"
    kb3.close()
