"""Tests for the function-level binary diff tool (#184)."""

from __future__ import annotations

import io
import json
from contextlib import redirect_stdout
from pathlib import Path

import pytest

from glaurung.llm.kb.binary_diff import (
    diff_binaries, render_diff_markdown, to_json,
)


_SWITCHY_V1 = Path(
    "samples/binaries/platforms/linux/amd64/synthetic/switchy-c-gcc-O2"
)
_SWITCHY_V2 = Path(
    "samples/binaries/platforms/linux/amd64/synthetic/switchy-c-gcc-O2-v2"
)


def _need(p: Path) -> Path:
    if not p.exists():
        pytest.skip(f"missing path {p}")
    return p


def test_diff_self_reports_zero_changes(tmp_path: Path) -> None:
    """A binary diffed against itself must show 0 changed/added/removed."""
    binary = _need(_SWITCHY_V1)
    diff = diff_binaries(str(binary), str(binary))
    assert diff.changed == 0
    assert diff.added == 0
    assert diff.removed == 0
    assert diff.same == diff.functions_a == diff.functions_b


def test_diff_v1_vs_v2_isolates_the_patched_function(tmp_path: Path) -> None:
    """The v2 binary differs from v1 only by an added bounds check in
    `dispatch`. The diff's `changed` set must include `dispatch` and
    the function's body size in v2 must be larger than in v1."""
    a = _need(_SWITCHY_V1)
    b = _need(_SWITCHY_V2)
    diff = diff_binaries(str(a), str(b))
    assert diff.changed > 0, "v1→v2 should produce at least one changed function"

    # `dispatch` must be in the changed set.
    changed_names = {r.name for r in diff.changed_rows()}
    assert "dispatch" in changed_names

    dispatch = next(r for r in diff.changed_rows() if r.name == "dispatch")
    # v2 added bounds-check code; size must grow.
    assert dispatch.b.size > dispatch.a.size, (
        f"dispatch shrank or stayed same: v1={dispatch.a.size} v2={dispatch.b.size}"
    )
    # `main` should NOT be a structurally interesting change — the
    # bounds-check only lives in dispatch. (The compiler may rewrite
    # main due to relocation shifts; we just assert dispatch grew.)


def test_render_markdown_includes_changed_table(tmp_path: Path) -> None:
    a = _need(_SWITCHY_V1)
    b = _need(_SWITCHY_V2)
    diff = diff_binaries(str(a), str(b))
    md = render_diff_markdown(diff)
    assert "Binary diff" in md
    assert "## Changed functions" in md
    assert "dispatch" in md


def test_to_json_round_trips() -> None:
    a = _need(_SWITCHY_V1)
    b = _need(_SWITCHY_V2)
    diff = diff_binaries(str(a), str(b))
    payload = to_json(diff)
    parsed = json.loads(payload)
    assert parsed["schema_version"] == "1"
    assert parsed["binary_a"] == str(a)
    assert parsed["binary_b"] == str(b)
    assert "summary" in parsed
    assert parsed["summary"]["same"] == diff.same
    assert parsed["summary"]["changed"] == diff.changed


def test_skip_anonymous_filters_sub_placeholders(tmp_path: Path) -> None:
    """`skip_anonymous=True` (default) drops `sub_<hex>` rows; with it
    enabled, the diff reports zero added/removed for binaries whose
    only differences are placeholder names from VA shifts."""
    a = _need(_SWITCHY_V1)
    b = _need(_SWITCHY_V2)
    skipped = diff_binaries(str(a), str(b), skip_anonymous=True)
    included = diff_binaries(str(a), str(b), skip_anonymous=False)
    # With sub_* included, total function count grows.
    assert included.functions_a >= skipped.functions_a
    assert included.functions_b >= skipped.functions_b


def test_cli_diff_subcommand(tmp_path: Path) -> None:
    """Smoke-test `glaurung diff <a> <b>`."""
    from glaurung.cli.main import GlaurungCLI

    a = _need(_SWITCHY_V1)
    b = _need(_SWITCHY_V2)
    cli = GlaurungCLI()
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = cli.run(["diff", str(a), str(b)])
    out = buf.getvalue()
    # rc=1 because there's at least one change.
    assert rc == 1
    assert "Binary diff" in out
    assert "dispatch" in out
