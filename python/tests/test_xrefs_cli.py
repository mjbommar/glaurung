"""Tests for `glaurung xrefs` CLI subcommand (#219)."""

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
    db = tmp_path / "xrefs.glaurung"
    kb = PersistentKnowledgeBase.open(db, binary_path=binary)
    # Seed a few xrefs by hand so the test isn't sensitive to which
    # pass discovers them. main calls foo and bar; bar reads g_buf.
    xref_db.set_function_name(kb, 0x1000, "main", set_by="manual")
    xref_db.set_function_name(kb, 0x1080, "foo", set_by="manual")
    xref_db.set_function_name(kb, 0x10c0, "bar", set_by="manual")
    xref_db.add_xref(
        kb, src_va=0x1010, dst_va=0x1080, kind="call",
        src_function_va=0x1000,
    )
    xref_db.add_xref(
        kb, src_va=0x1024, dst_va=0x10c0, kind="call",
        src_function_va=0x1000,
    )
    xref_db.add_xref(
        kb, src_va=0x10d4, dst_va=0x4000, kind="data_read",
        src_function_va=0x10c0,
    )
    kb.close()
    return db, binary


def test_xrefs_to_lists_callers(tmp_path: Path) -> None:
    """`xrefs <db> 0x1080 --direction to` should list main as a caller."""
    from glaurung.cli.main import GlaurungCLI

    db, binary = _seed(tmp_path)
    cli = GlaurungCLI()
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = cli.run([
            "xrefs", str(db), "0x1080",
            "--direction", "to", "--binary", str(binary),
        ])
    assert rc == 0
    out = buf.getvalue()
    # Header + one row.
    assert "src_va" in out
    assert "kind" in out
    assert "0x1010" in out
    assert "main" in out
    assert "call" in out


def test_xrefs_from_lists_callees(tmp_path: Path) -> None:
    """`xrefs --direction from` from inside main shows what main calls."""
    from glaurung.cli.main import GlaurungCLI

    db, binary = _seed(tmp_path)
    cli = GlaurungCLI()
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = cli.run([
            "xrefs", str(db), "0x1010",
            "--direction", "from", "--binary", str(binary),
        ])
    assert rc == 0
    out = buf.getvalue()
    assert "0x1010" in out
    # Output contains the call from 0x1010 → 0x1080, kind=call.
    assert "call" in out


def test_xrefs_kind_filter(tmp_path: Path) -> None:
    """`--kind data_read` should hide call/jump xrefs."""
    from glaurung.cli.main import GlaurungCLI

    db, binary = _seed(tmp_path)
    cli = GlaurungCLI()
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = cli.run([
            "xrefs", str(db), "0x4000",
            "--direction", "to", "--kind", "data_read",
            "--binary", str(binary),
        ])
    assert rc == 0
    out = buf.getvalue()
    assert "data_read" in out
    assert "bar" in out  # function that did the read


def test_xrefs_empty_result(tmp_path: Path) -> None:
    from glaurung.cli.main import GlaurungCLI

    db, binary = _seed(tmp_path)
    cli = GlaurungCLI()
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = cli.run([
            "xrefs", str(db), "0xdeadbeef",
            "--direction", "to", "--binary", str(binary),
        ])
    assert rc == 0
    assert "no" in buf.getvalue().lower()


def test_xrefs_json_format(tmp_path: Path) -> None:
    """`--format json` should emit a JSON array of dicts."""
    from glaurung.cli.main import GlaurungCLI

    db, binary = _seed(tmp_path)
    cli = GlaurungCLI()
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = cli.run([
            "xrefs", str(db), "0x1080",
            "--direction", "to", "--binary", str(binary),
            "--format", "json",
        ])
    assert rc == 0
    data = json.loads(buf.getvalue())
    assert isinstance(data, list)
    assert len(data) >= 1
    row = data[0]
    assert row["dst_va"] == 0x1080
    assert row["kind"] == "call"
    assert row["src_function"] == "main"
