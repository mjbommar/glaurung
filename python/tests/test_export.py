"""Tests for KB export (#165 v0)."""

from __future__ import annotations

import io
import json
from contextlib import redirect_stdout
from pathlib import Path

import pytest

from glaurung.llm.kb import xref_db, type_db
from glaurung.llm.kb.export import (
    export_kb,
    export_to_c_header,
    export_to_json,
    export_to_markdown,
)
from glaurung.llm.kb.persistent import PersistentKnowledgeBase


_HELLO = Path(
    "samples/binaries/platforms/linux/amd64/export/native/clang/debug/hello-clang-debug"
)


def _need(p: Path) -> Path:
    if not p.exists():
        pytest.skip(f"missing path {p}")
    return p


def test_export_kb_collects_all_tables(tmp_path: Path) -> None:
    """Populate every persistent table; export; check every table
    surfaces in the dump."""
    binary = _need(_HELLO)
    db = tmp_path / "exp.glaurung"
    kb = PersistentKnowledgeBase.open(
        db, binary_path=binary, auto_load_stdlib=True,
    )

    # Seed a row per table.
    xref_db.set_function_name(kb, 0x1000, "my_func", set_by="manual")
    xref_db.set_comment(kb, 0x1010, "loop start")
    xref_db.set_data_label(kb, 0x4000, "g_table", c_type="int[]", set_by="manual")
    xref_db.set_stack_var(
        kb, function_va=0x1000, offset=-0x10, name="my_local",
        c_type="int", set_by="manual",
    )
    xref_db.add_xref(
        kb, src_va=0x1004, dst_va=0x2000, kind="call",
        src_function_va=0x1000,
    )
    type_db.add_struct(
        kb, "my_struct", [type_db.StructField(0, "fld", "int", 4)],
        set_by="manual",
    )
    xref_db.record_evidence(
        kb, tool="t", args={"x": 1}, summary="seed evidence",
    )

    data = export_kb(kb)
    assert data["schema_version"] == "1"
    summary = data["summary"]
    assert summary["function_names"] >= 1
    assert summary["comments"] >= 1
    assert summary["data_labels"] >= 1
    assert summary["stack_vars"] >= 1
    assert summary["types"] >= 1
    assert summary["evidence"] >= 1
    # Stdlib bundles autoload protos + types.
    assert summary["prototypes"] >= 50

    # Spot-check shape of one row per table.
    fn = next(f for f in data["function_names"] if f["entry_va"] == 0x1000)
    assert fn["canonical"] == "my_func"
    sl = next(s for s in data["stack_frame_vars"] if s["offset"] == -0x10)
    assert sl["name"] == "my_local"
    kb.close()


def test_export_to_json_is_valid_json(tmp_path: Path) -> None:
    binary = _need(_HELLO)
    db = tmp_path / "exp.glaurung"
    kb = PersistentKnowledgeBase.open(db, binary_path=binary)
    xref_db.set_function_name(kb, 0x1000, "test_fn", set_by="manual")

    out = export_to_json(kb)
    parsed = json.loads(out)
    assert parsed["schema_version"] == "1"
    assert any(
        fn["canonical"] == "test_fn" for fn in parsed["function_names"]
    )
    kb.close()


def test_export_to_markdown_includes_function_table(tmp_path: Path) -> None:
    binary = _need(_HELLO)
    db = tmp_path / "exp.glaurung"
    kb = PersistentKnowledgeBase.open(
        db, binary_path=binary, auto_load_stdlib=True,
    )
    xref_db.set_function_name(kb, 0x1234, "sample_fn", set_by="manual")

    md = export_to_markdown(kb)
    assert "Glaurung KB export" in md
    assert "function_names" in md
    assert "sample_fn" in md
    assert "Prototypes" in md  # stdlib protos auto-loaded
    kb.close()


def test_export_to_c_header_renders_struct(tmp_path: Path) -> None:
    binary = _need(_HELLO)
    db = tmp_path / "exp.glaurung"
    kb = PersistentKnowledgeBase.open(db, binary_path=binary)
    type_db.add_struct(
        kb, "exported_struct",
        [
            type_db.StructField(0, "a", "int", 4),
            type_db.StructField(8, "b", "void *", 8),
        ],
        set_by="manual",
    )
    h = export_to_c_header(kb)
    assert "struct exported_struct" in h
    assert "int a" in h
    assert "void *b" in h or "void * b" in h
    kb.close()


def test_export_to_ida_script_renders_python(tmp_path: Path) -> None:
    """The IDA script is real Python; the test only checks shape and
    that key API calls appear. We don't try to run it inside IDA."""
    binary = _need(_HELLO)
    db = tmp_path / "exp.glaurung"
    kb = PersistentKnowledgeBase.open(db, binary_path=binary)

    xref_db.set_function_name(kb, 0x1234, "my_named_fn", set_by="manual")
    xref_db.set_comment(kb, 0x1238, "stack canary save")
    xref_db.set_data_label(
        kb, va=0x4000, name="g_table", c_type="int[]", set_by="manual",
    )
    type_db.add_struct(
        kb, "exported_struct",
        [type_db.StructField(0, "a", "int", 4)],
        set_by="manual",
    )

    from glaurung.llm.kb.export import export_to_ida_script

    script = export_to_ida_script(kb)
    # Header + IDA imports.
    assert "import idaapi" in script
    assert "import ida_name" in script
    # Function rename uses ida_name.set_name with the canonical name.
    assert "my_named_fn" in script
    # Comment lands via idc.set_cmt.
    assert "stack canary save" in script
    # Data label uses ida_name.set_name.
    assert "g_table" in script
    # Struct definition arrives via parse_decls.
    assert "parse_decls" in script
    # Script is syntactically valid Python.
    compile(script, "<ida-export>", "exec")
    kb.close()


def test_export_to_binja_script_renders_python(tmp_path: Path) -> None:
    binary = _need(_HELLO)
    db = tmp_path / "exp.glaurung"
    kb = PersistentKnowledgeBase.open(db, binary_path=binary)
    xref_db.set_function_name(kb, 0x12d0, "binja_renamed", set_by="manual")
    xref_db.set_comment(kb, 0x12d4, "binja comment")
    xref_db.set_data_label(kb, va=0x4040, name="g_binja", set_by="manual")

    from glaurung.llm.kb.export import export_to_binja_script

    s = export_to_binja_script(kb)
    assert "Binary Ninja" in s
    assert "binja_renamed" in s
    assert "set_comment_at" in s
    assert "g_binja" in s
    assert "DataSymbol" in s
    # Valid Python syntactically.
    compile(s, "<binja-export>", "exec")
    kb.close()


def test_export_to_ghidra_script_renders_python(tmp_path: Path) -> None:
    binary = _need(_HELLO)
    db = tmp_path / "exp.glaurung"
    kb = PersistentKnowledgeBase.open(db, binary_path=binary)
    xref_db.set_function_name(kb, 0x12d0, "ghidra_renamed", set_by="manual")
    xref_db.set_comment(kb, 0x12d4, "ghidra comment")
    xref_db.set_data_label(kb, va=0x4040, name="g_ghidra", set_by="manual")

    from glaurung.llm.kb.export import export_to_ghidra_script

    s = export_to_ghidra_script(kb)
    assert "Ghidra" in s
    assert "ghidra_renamed" in s
    assert "setEOLComment" in s
    assert "g_ghidra" in s
    assert "createLabel" in s
    # Ghidra script is also valid as standalone Python (Jython 2.7
    # syntax is a subset of Python 3 syntax for this trivial shape).
    compile(s, "<ghidra-export>", "exec")
    kb.close()


def test_export_cli_smoke(tmp_path: Path) -> None:
    """Smoke-test `glaurung export <db>` with all three formats."""
    from glaurung.cli.main import GlaurungCLI

    binary = _need(_HELLO)
    db = tmp_path / "exp-cli.glaurung"
    kb = PersistentKnowledgeBase.open(db, binary_path=binary)
    xref_db.set_function_name(kb, 0x1000, "cli_fn", set_by="manual")
    kb.close()

    cli = GlaurungCLI()
    for fmt in ("markdown", "json", "header", "ida", "binja", "ghidra"):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli.run(["export", str(db), "--output-format", fmt])
        assert rc == 0, f"export {fmt} failed"
        out = buf.getvalue()
        if fmt == "markdown":
            assert "Glaurung KB export" in out
        elif fmt == "json":
            parsed = json.loads(out)
            assert parsed["schema_version"] == "1"
        elif fmt == "header":
            # Header format is allowed to be empty when the KB has
            # no types — just ensure no error.
            assert isinstance(out, str)
        elif fmt == "ida":
            assert "import idaapi" in out
            assert "cli_fn" in out
        elif fmt == "binja":
            assert "Binary Ninja" in out or "binaryninja" in out
            assert "cli_fn" in out
        elif fmt == "ghidra":
            assert "Ghidra" in out
            assert "cli_fn" in out
