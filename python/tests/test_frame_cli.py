"""Tests for `glaurung frame` stack-frame editor (#221)."""

from __future__ import annotations

import io
import json
from contextlib import redirect_stdout
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


def _seed(tmp_path: Path) -> tuple[Path, Path]:
    binary = _need(_HELLO)
    db = tmp_path / "frame.glaurung"
    kb = PersistentKnowledgeBase.open(db, binary_path=binary)
    # Seed three slots: a local, a saved-reg slot, and an arg slot.
    xref_db.set_stack_var(
        kb, function_va=0x1000, offset=-0x20, name="counter",
        c_type="int", use_count=4, set_by="auto",
    )
    xref_db.set_stack_var(
        kb, function_va=0x1000, offset=-0x10, name="buf",
        c_type="char[16]", use_count=2, set_by="manual",
    )
    xref_db.set_stack_var(
        kb, function_va=0x1000, offset=0x10, name="argv0",
        c_type="char *", use_count=1, set_by="auto",
    )
    kb.close()
    return db, binary


def test_frame_list_renders_slot_table(tmp_path: Path) -> None:
    from glaurung.cli.main import GlaurungCLI

    db, binary = _seed(tmp_path)
    cli = GlaurungCLI()
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = cli.run([
            "frame", str(db), "0x1000", "list", "--binary", str(binary),
        ])
    assert rc == 0
    out = buf.getvalue()
    # Header columns present.
    assert "offset" in out
    assert "name" in out
    assert "type" in out
    assert "set_by" in out
    # Rows.
    assert "counter" in out
    assert "buf" in out
    assert "argv0" in out
    assert "char[16]" in out


def test_frame_rename_persists(tmp_path: Path) -> None:
    from glaurung.cli.main import GlaurungCLI

    db, binary = _seed(tmp_path)
    cli = GlaurungCLI()
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = cli.run([
            "frame", str(db), "0x1000", "rename",
            "-0x20", "loop_index",
            "--binary", str(binary),
        ])
    assert rc == 0
    assert "loop_index" in buf.getvalue()

    kb = PersistentKnowledgeBase.open(db, binary_path=binary)
    sv = xref_db.get_stack_var(kb, 0x1000, -0x20)
    assert sv.name == "loop_index"
    assert sv.c_type == "int"  # preserved
    assert sv.set_by == "manual"
    kb.close()


def test_frame_retype_preserves_name(tmp_path: Path) -> None:
    from glaurung.cli.main import GlaurungCLI

    db, binary = _seed(tmp_path)
    cli = GlaurungCLI()
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = cli.run([
            "frame", str(db), "0x1000", "retype",
            "-0x10", "uint8_t[16]",
            "--binary", str(binary),
        ])
    assert rc == 0

    kb = PersistentKnowledgeBase.open(db, binary_path=binary)
    sv = xref_db.get_stack_var(kb, 0x1000, -0x10)
    assert sv.name == "buf"  # preserved
    assert sv.c_type == "uint8_t[16]"
    assert sv.set_by == "manual"
    kb.close()


def test_frame_retype_missing_slot_errors(tmp_path: Path) -> None:
    from glaurung.cli.main import GlaurungCLI

    db, binary = _seed(tmp_path)
    cli = GlaurungCLI()
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = cli.run([
            "frame", str(db), "0x1000", "retype",
            "-0x99", "int",
            "--binary", str(binary),
        ])
    assert rc == 5
    assert "no slot" in buf.getvalue()


def test_frame_list_json_format(tmp_path: Path) -> None:
    from glaurung.cli.main import GlaurungCLI

    db, binary = _seed(tmp_path)
    cli = GlaurungCLI()
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = cli.run([
            "frame", str(db), "0x1000", "list",
            "--binary", str(binary), "--format", "json",
        ])
    assert rc == 0
    rows = json.loads(buf.getvalue())
    assert len(rows) == 3
    by_offset = {r["offset"]: r for r in rows}
    assert by_offset[-0x20]["name"] == "counter"
    assert by_offset[-0x10]["c_type"] == "char[16]"


def test_frame_rename_is_undoable(tmp_path: Path) -> None:
    """Stack-var renames go through the same set_stack_var setter that
    #228 wires undo into — verify the round-trip end-to-end."""
    from glaurung.cli.main import GlaurungCLI

    db, binary = _seed(tmp_path)
    cli = GlaurungCLI()
    buf = io.StringIO()
    with redirect_stdout(buf):
        cli.run([
            "frame", str(db), "0x1000", "rename",
            "-0x10", "renamed_buf",
            "--binary", str(binary),
        ])

    kb = PersistentKnowledgeBase.open(db, binary_path=binary)
    assert xref_db.get_stack_var(kb, 0x1000, -0x10).name == "renamed_buf"
    xref_db.undo(kb)
    assert xref_db.get_stack_var(kb, 0x1000, -0x10).name == "buf"
    kb.close()


def test_frame_list_empty_function(tmp_path: Path) -> None:
    from glaurung.cli.main import GlaurungCLI

    db, binary = _seed(tmp_path)
    cli = GlaurungCLI()
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = cli.run([
            "frame", str(db), "0x9999", "list",
            "--binary", str(binary),
        ])
    assert rc == 0
    assert "no stack vars" in buf.getvalue()
