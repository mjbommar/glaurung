"""Tests for the `glaurung graph` CLI subcommand (#167)."""

from __future__ import annotations

import io
import re
from contextlib import redirect_stdout
from pathlib import Path

import pytest

from glaurung.cli.main import GlaurungCLI


def _need(p: Path) -> Path:
    if not p.exists():
        pytest.skip(f"missing sample binary {p}")
    return p


_HELLO_DEBUG = Path(
    "samples/binaries/platforms/linux/amd64/export/native/clang/debug/hello-clang-debug"
)


def _run_cli(argv: list[str]) -> tuple[int, str]:
    cli = GlaurungCLI()
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = cli.run(argv)
    return rc, buf.getvalue()


def _is_balanced(dot: str) -> bool:
    """Cheap structural check: every `{` has a matching `}` and the
    overall block opens with `digraph <ident> {` and closes with `}`."""
    if not dot.strip().endswith("}"):
        return False
    if not re.search(r"^\s*digraph\s+[A-Za-z_][\w]*\s*\{", dot, re.MULTILINE):
        return False
    return dot.count("{") == dot.count("}")


def test_callgraph_emits_valid_dot() -> None:
    binary = _need(_HELLO_DEBUG)
    rc, out = _run_cli(["graph", str(binary), "callgraph"])
    assert rc == 0
    assert _is_balanced(out), f"unbalanced DOT braces:\n{out[:400]}"
    # Basic content checks: real function names from DWARF must appear.
    assert "main" in out
    assert "_start" in out
    # Highlighted entry-point styling.
    assert "lightyellow" in out


def test_cfg_emits_valid_dot_for_main() -> None:
    binary = _need(_HELLO_DEBUG)
    rc, out = _run_cli(["graph", str(binary), "cfg", "main"])
    assert rc == 0
    assert _is_balanced(out)
    # CFG-specific: at least one bb_<hex> identifier is present.
    assert re.search(r"\bbb_[0-9a-f]+\b", out), out[:200]
    # The label contains the function name.
    assert "main" in out


def test_cfg_resolves_by_va() -> None:
    """`graph cfg` should accept either a name or a VA."""
    binary = _need(_HELLO_DEBUG)
    rc1, out_name = _run_cli(["graph", str(binary), "cfg", "main"])
    assert rc1 == 0
    # Pick main's entry VA from the DOT label.
    m = re.search(r'label="CFG of main"', out_name)
    assert m
    # Now request the same function by hex VA.
    rc2, out_va = _run_cli(["graph", str(binary), "cfg", "0x12d0"])
    assert rc2 == 0
    assert "main" in out_va


def test_cfg_unknown_function_returns_error() -> None:
    binary = _need(_HELLO_DEBUG)
    rc, out = _run_cli(["graph", str(binary), "cfg", "definitely_not_a_real_symbol"])
    assert rc == 4
    assert "not found" in out.lower()
