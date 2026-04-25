"""Tests for `glaurung find` cross-table search (#225)."""

from __future__ import annotations

import io
import json
from contextlib import redirect_stdout
from pathlib import Path

import pytest

from glaurung.llm.kb import xref_db, type_db
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
    db = tmp_path / "find.glaurung"
    kb = PersistentKnowledgeBase.open(db, binary_path=binary)
    xref_db.set_function_name(kb, 0x1000, "parse_packet", set_by="manual")
    xref_db.set_function_name(kb, 0x1100, "validate_input", set_by="manual")
    xref_db.set_comment(kb, 0x1004, "TODO: bounds check parse here")
    xref_db.set_data_label(
        kb, 0x4000, "g_secret_key", c_type="char[32]", set_by="manual",
    )
    xref_db.set_stack_var(
        kb, function_va=0x1000, offset=-0x10, name="parse_buffer",
        c_type="char[256]", set_by="manual",
    )
    type_db.add_struct(
        kb, "Packet", [type_db.StructField(0, "magic", "uint32_t", 4)],
        set_by="manual",
    )
    kb.close()
    return db, binary


def test_find_function_names(tmp_path: Path) -> None:
    from glaurung.cli.main import GlaurungCLI

    db, binary = _seed(tmp_path)
    cli = GlaurungCLI()
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = cli.run([
            "find", str(db), "parse",
            "--kind", "function", "--binary", str(binary),
        ])
    assert rc == 0
    out = buf.getvalue()
    assert "parse_packet" in out
    assert "validate_input" not in out


def test_find_across_all_kinds(tmp_path: Path) -> None:
    """Default `--kind all` should pick up matches in functions,
    comments, AND stack vars for the same query."""
    from glaurung.cli.main import GlaurungCLI

    db, binary = _seed(tmp_path)
    cli = GlaurungCLI()
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = cli.run([
            "find", str(db), "parse",
            "--binary", str(binary),
        ])
    assert rc == 0
    out = buf.getvalue()
    assert "parse_packet" in out      # function
    assert "parse" in out and "TODO" in out   # comment
    assert "parse_buffer" in out      # stack var


def test_find_data_label_by_type(tmp_path: Path) -> None:
    """Searching for a c_type fragment should also surface labels
    typed that way (e.g. searching `char[32]` finds `g_secret_key`)."""
    from glaurung.cli.main import GlaurungCLI

    db, binary = _seed(tmp_path)
    cli = GlaurungCLI()
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = cli.run([
            "find", str(db), "char[32]",
            "--kind", "data", "--binary", str(binary),
        ])
    assert rc == 0
    assert "g_secret_key" in buf.getvalue()


def test_find_type(tmp_path: Path) -> None:
    from glaurung.cli.main import GlaurungCLI

    db, binary = _seed(tmp_path)
    cli = GlaurungCLI()
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = cli.run([
            "find", str(db), "Packet",
            "--kind", "type", "--binary", str(binary),
        ])
    assert rc == 0
    assert "Packet" in buf.getvalue()


def test_find_regex(tmp_path: Path) -> None:
    from glaurung.cli.main import GlaurungCLI

    db, binary = _seed(tmp_path)
    cli = GlaurungCLI()
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = cli.run([
            "find", str(db), r"^parse_",
            "--regex", "--kind", "function",
            "--binary", str(binary),
        ])
    assert rc == 0
    assert "parse_packet" in buf.getvalue()


def test_find_case_sensitive(tmp_path: Path) -> None:
    from glaurung.cli.main import GlaurungCLI

    db, binary = _seed(tmp_path)
    cli = GlaurungCLI()

    buf = io.StringIO()
    with redirect_stdout(buf):
        cli.run([
            "find", str(db), "PARSE",
            "--kind", "function", "--binary", str(binary),
        ])
    assert "parse_packet" in buf.getvalue()  # default case-insensitive

    buf = io.StringIO()
    with redirect_stdout(buf):
        cli.run([
            "find", str(db), "PARSE",
            "--kind", "function", "--case-sensitive",
            "--binary", str(binary),
        ])
    assert "parse_packet" not in buf.getvalue()


def test_find_no_matches(tmp_path: Path) -> None:
    from glaurung.cli.main import GlaurungCLI

    db, binary = _seed(tmp_path)
    cli = GlaurungCLI()
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = cli.run([
            "find", str(db), "definitely_not_in_db",
            "--kind", "function", "--binary", str(binary),
        ])
    assert rc == 0
    assert "no matches" in buf.getvalue().lower()


def test_find_json_format(tmp_path: Path) -> None:
    from glaurung.cli.main import GlaurungCLI

    db, binary = _seed(tmp_path)
    cli = GlaurungCLI()
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = cli.run([
            "find", str(db), "parse",
            "--kind", "function", "--binary", str(binary),
            "--format", "json",
        ])
    assert rc == 0
    rows = json.loads(buf.getvalue())
    assert any(r["snippet"].startswith("parse_packet") for r in rows)
