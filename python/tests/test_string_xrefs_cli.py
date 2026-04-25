"""Tests for `glaurung strings-xrefs` (#222)."""

from __future__ import annotations

import io
import json
from contextlib import redirect_stdout
from pathlib import Path

import pytest

from glaurung.llm.kb import xref_db
from glaurung.llm.kb.persistent import PersistentKnowledgeBase


_C2 = Path(
    "samples/binaries/platforms/linux/amd64/export/native/clang/O0/c2_demo-clang-O0"
)


def _need(p: Path) -> Path:
    if not p.exists():
        pytest.skip(f"missing {p}")
    return p


def _seed(tmp_path: Path) -> tuple[Path, Path]:
    binary = _need(_C2)
    db = tmp_path / "strxr.glaurung"
    kb = PersistentKnowledgeBase.open(db, binary_path=binary)
    kb.close()
    return db, binary


def test_strings_xrefs_lists_strings(tmp_path: Path) -> None:
    """No xrefs seeded; just confirm we can extract strings + render
    the panel without crashing."""
    from glaurung.cli.main import GlaurungCLI

    db, binary = _seed(tmp_path)
    cli = GlaurungCLI()
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = cli.run([
            "strings-xrefs", str(db), "--binary", str(binary),
            "--limit", "10",
        ])
    assert rc == 0
    out = buf.getvalue()
    # Header columns visible.
    assert "offset" in out
    assert "len" in out
    assert "uses" in out
    # At least one IOC-like string from c2_demo should be in the output.
    # c2_demo carries hardcoded URLs / paths.
    assert "http" in out.lower() or "/etc" in out or len(out.splitlines()) > 3


def test_strings_xrefs_used_only_filter(tmp_path: Path) -> None:
    """When --used-only is set and no data_read xrefs exist in the KB,
    the panel should be empty."""
    from glaurung.cli.main import GlaurungCLI

    db, binary = _seed(tmp_path)
    cli = GlaurungCLI()
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = cli.run([
            "strings-xrefs", str(db), "--binary", str(binary),
            "--used-only",
        ])
    assert rc == 0
    assert "no strings matched" in buf.getvalue()


def test_strings_xrefs_resolves_seeded_xref(tmp_path: Path) -> None:
    """Seed a data_read xref pointing at a known string's file offset
    and confirm the panel surfaces the function."""
    import glaurung as g
    from glaurung.cli.main import GlaurungCLI

    db, binary = _seed(tmp_path)
    art = g.triage.analyze_path(str(binary), str_min_len=4, str_max_samples=200)
    if not list(art.strings.strings):
        pytest.skip("no strings extracted")

    # Pick a string and back-translate offset → VA.
    target = next(iter(art.strings.strings))
    file_off = int(target.offset)

    # Find a VA whose file offset matches by trying common .rodata-ish
    # mappings. We'll iterate a few candidate VAs.
    target_va = None
    for guess in (file_off, file_off + 0x1000, file_off + 0x2000, file_off + 0x3000):
        try:
            back = g.analysis.va_to_file_offset_path(str(binary), guess)
        except Exception:
            continue
        if back == file_off:
            target_va = guess
            break
    if target_va is None:
        pytest.skip("could not back-translate string offset to VA")

    kb = PersistentKnowledgeBase.open(db, binary_path=binary)
    xref_db.set_function_name(kb, 0x1110, "use_string_fn", set_by="manual")
    xref_db.add_xref(
        kb, src_va=0x1234, dst_va=target_va, kind="data_read",
        src_function_va=0x1110,
    )
    kb.close()

    cli = GlaurungCLI()
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = cli.run([
            "strings-xrefs", str(db), "--binary", str(binary),
            "--used-only", "--limit", "20",
        ])
    assert rc == 0
    out = buf.getvalue()
    assert "use_string_fn" in out
    assert "0x1234" in out


def test_strings_xrefs_json_output(tmp_path: Path) -> None:
    from glaurung.cli.main import GlaurungCLI

    db, binary = _seed(tmp_path)
    cli = GlaurungCLI()
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = cli.run([
            "strings-xrefs", str(db), "--binary", str(binary),
            "--limit", "5", "--format", "json",
        ])
    assert rc == 0
    rows = json.loads(buf.getvalue())
    assert isinstance(rows, list)
    assert all(
        {"offset", "encoding", "length", "text", "uses", "used_at"} <= set(r.keys())
        for r in rows
    )
