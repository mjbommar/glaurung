"""Tests for bookmarks + journal (#226)."""

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


def _open(tmp_path: Path) -> tuple[Path, Path]:
    binary = _need(_HELLO)
    db = tmp_path / "bm.glaurung"
    PersistentKnowledgeBase.open(db, binary_path=binary).close()
    return db, binary


# --- direct API tests ---------------------------------------------------

def test_add_and_list_bookmarks_round_trip(tmp_path: Path) -> None:
    db, binary = _open(tmp_path)
    kb = PersistentKnowledgeBase.open(db, binary_path=binary)
    a = xref_db.add_bookmark(kb, 0x1000, "check this branch")
    b = xref_db.add_bookmark(kb, 0x1080, "suspicious memcpy")
    rows = xref_db.list_bookmarks(kb)
    assert {r.bookmark_id for r in rows} == {a, b}
    assert any(r.va == 0x1000 and r.note == "check this branch" for r in rows)
    kb.close()


def test_multiple_bookmarks_per_va(tmp_path: Path) -> None:
    """Distinct from comments — multiple bookmarks per VA must coexist."""
    db, binary = _open(tmp_path)
    kb = PersistentKnowledgeBase.open(db, binary_path=binary)
    xref_db.add_bookmark(kb, 0x1000, "first reading: looks like parser")
    xref_db.add_bookmark(kb, 0x1000, "actually it's an init routine")
    rows = xref_db.list_bookmarks(kb, va=0x1000)
    assert len(rows) == 2
    kb.close()


def test_delete_bookmark(tmp_path: Path) -> None:
    db, binary = _open(tmp_path)
    kb = PersistentKnowledgeBase.open(db, binary_path=binary)
    bid = xref_db.add_bookmark(kb, 0x1000, "junk")
    assert xref_db.delete_bookmark(kb, bid) is True
    assert xref_db.delete_bookmark(kb, bid) is False
    assert xref_db.list_bookmarks(kb) == []
    kb.close()


def test_journal_round_trip(tmp_path: Path) -> None:
    db, binary = _open(tmp_path)
    kb = PersistentKnowledgeBase.open(db, binary_path=binary)
    a = xref_db.add_journal_entry(kb, "this binary embeds two C2 URLs")
    b = xref_db.add_journal_entry(kb, "encryption is XOR with hardcoded key")
    entries = xref_db.list_journal(kb)
    assert {e.entry_id for e in entries} == {a, b}
    # Newest first.
    assert entries[0].entry_id == b
    kb.close()


def test_delete_journal(tmp_path: Path) -> None:
    db, binary = _open(tmp_path)
    kb = PersistentKnowledgeBase.open(db, binary_path=binary)
    eid = xref_db.add_journal_entry(kb, "draft note")
    assert xref_db.delete_journal_entry(kb, eid) is True
    assert xref_db.delete_journal_entry(kb, 99999) is False
    kb.close()


# --- CLI smoke tests ----------------------------------------------------

def test_bookmark_cli_add_list_delete(tmp_path: Path) -> None:
    from glaurung.cli.main import GlaurungCLI

    db, binary = _open(tmp_path)
    cli = GlaurungCLI()

    buf = io.StringIO()
    with redirect_stdout(buf):
        cli.run([
            "bookmark", str(db), "add", "0x1234",
            "look at this branch later",
            "--binary", str(binary),
        ])
    assert "0x1234" in buf.getvalue()

    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = cli.run([
            "bookmark", str(db), "list", "--binary", str(binary),
        ])
    assert rc == 0
    out = buf.getvalue()
    assert "0x1234" in out
    assert "look at this branch later" in out

    # Delete the first bookmark id.
    kb = PersistentKnowledgeBase.open(db, binary_path=binary)
    bid = xref_db.list_bookmarks(kb)[0].bookmark_id
    kb.close()
    buf = io.StringIO()
    with redirect_stdout(buf):
        cli.run([
            "bookmark", str(db), "delete", str(bid),
            "--binary", str(binary),
        ])
    assert "deleted" in buf.getvalue()


def test_bookmark_cli_va_filter(tmp_path: Path) -> None:
    from glaurung.cli.main import GlaurungCLI

    db, binary = _open(tmp_path)
    kb = PersistentKnowledgeBase.open(db, binary_path=binary)
    xref_db.add_bookmark(kb, 0x1000, "alpha")
    xref_db.add_bookmark(kb, 0x2000, "beta")
    kb.close()

    cli = GlaurungCLI()
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = cli.run([
            "bookmark", str(db), "list", "--va", "0x1000",
            "--binary", str(binary),
        ])
    assert rc == 0
    out = buf.getvalue()
    assert "alpha" in out
    assert "beta" not in out


def test_bookmark_cli_json(tmp_path: Path) -> None:
    from glaurung.cli.main import GlaurungCLI

    db, binary = _open(tmp_path)
    cli = GlaurungCLI()
    cli.run([
        "bookmark", str(db), "add", "0x1234", "n", "--binary", str(binary),
    ])
    buf = io.StringIO()
    with redirect_stdout(buf):
        cli.run([
            "bookmark", str(db), "list",
            "--binary", str(binary), "--format", "json",
        ])
    rows = json.loads(buf.getvalue())
    assert rows
    assert rows[0]["va"] == 0x1234


def test_journal_cli_add_list_delete(tmp_path: Path) -> None:
    from glaurung.cli.main import GlaurungCLI

    db, binary = _open(tmp_path)
    cli = GlaurungCLI()
    buf = io.StringIO()
    with redirect_stdout(buf):
        cli.run([
            "journal", str(db), "add",
            "today: figured out the C2 protocol",
            "--binary", str(binary),
        ])
    assert "today" in buf.getvalue()

    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = cli.run([
            "journal", str(db), "list", "--binary", str(binary),
        ])
    assert rc == 0
    assert "today" in buf.getvalue()


def test_journal_empty_list(tmp_path: Path) -> None:
    from glaurung.cli.main import GlaurungCLI

    db, binary = _open(tmp_path)
    cli = GlaurungCLI()
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = cli.run([
            "journal", str(db), "list", "--binary", str(binary),
        ])
    assert rc == 0
    assert "no journal" in buf.getvalue().lower()
