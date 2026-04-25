"""Tests for `glaurung view` tri-pane (#223)."""

from __future__ import annotations

import io
import json
from contextlib import redirect_stdout
from pathlib import Path

import pytest

from glaurung.llm.kb.persistent import PersistentKnowledgeBase


_HELLO = Path(
    "samples/binaries/platforms/linux/amd64/export/native/clang/debug/hello-clang-debug"
)


def _need(p: Path) -> Path:
    if not p.exists():
        pytest.skip(f"missing {p}")
    return p


def _seed(tmp_path: Path) -> tuple[Path, Path, int]:
    """Return (db, binary, function_va)."""
    binary = _need(_HELLO)
    db = tmp_path / "view.glaurung"
    kb = PersistentKnowledgeBase.open(db, binary_path=binary)
    kb.close()
    # Discover functions and pick the first one with a non-trivial body.
    import glaurung as g
    funcs, _ = g.analysis.analyze_functions_path(str(binary))
    if not funcs:
        pytest.skip("no functions discovered")
    return db, binary, int(funcs[0].entry_point.value)


def test_view_renders_all_three_panes(tmp_path: Path) -> None:
    from glaurung.cli.main import GlaurungCLI

    db, binary, fn_va = _seed(tmp_path)
    cli = GlaurungCLI()
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = cli.run([
            "view", str(db), hex(fn_va), "--binary", str(binary),
        ])
    assert rc == 0
    out = buf.getvalue()
    assert "hex @" in out
    assert "disasm @" in out
    assert "pseudocode" in out


def test_view_pane_filter(tmp_path: Path) -> None:
    from glaurung.cli.main import GlaurungCLI

    db, binary, fn_va = _seed(tmp_path)
    cli = GlaurungCLI()
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = cli.run([
            "view", str(db), hex(fn_va),
            "--binary", str(binary), "--pane", "hex",
        ])
    assert rc == 0
    out = buf.getvalue()
    assert "hex @" in out
    assert "disasm @" not in out
    assert "pseudocode" not in out


def test_view_disasm_pane_marks_target(tmp_path: Path) -> None:
    """The first disasm row should carry the ← marker."""
    from glaurung.cli.main import GlaurungCLI

    db, binary, fn_va = _seed(tmp_path)
    cli = GlaurungCLI()
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = cli.run([
            "view", str(db), hex(fn_va),
            "--binary", str(binary), "--pane", "disasm",
        ])
    assert rc == 0
    out = buf.getvalue()
    # ← marker on the first disasm row.
    assert "←" in out


def test_view_json(tmp_path: Path) -> None:
    from glaurung.cli.main import GlaurungCLI

    db, binary, fn_va = _seed(tmp_path)
    cli = GlaurungCLI()
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = cli.run([
            "view", str(db), hex(fn_va),
            "--binary", str(binary), "--format", "json",
        ])
    assert rc == 0
    data = json.loads(buf.getvalue())
    assert data["va"] == fn_va
    assert {"hex", "disasm", "pseudo"} <= set(data.keys())
    assert isinstance(data["hex"], list)
    assert isinstance(data["disasm"], list)
    assert len(data["disasm"]) >= 1


def test_view_unmapped_va(tmp_path: Path) -> None:
    """Asking for a VA outside any segment must not crash; the hex pane
    reports the failure inline."""
    from glaurung.cli.main import GlaurungCLI

    db, binary, _fn_va = _seed(tmp_path)
    cli = GlaurungCLI()
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = cli.run([
            "view", str(db), "0xdeadbeefdeadbeef",
            "--binary", str(binary), "--pane", "hex",
        ])
    # Either resolve-failed or unmapped — both produce a non-crashing
    # explanatory line.
    assert rc == 0
    out = buf.getvalue().lower()
    assert "could not resolve" in out or "not in any mapped" in out
