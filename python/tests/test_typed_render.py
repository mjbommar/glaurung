"""Tests for type-aware re-render of decompiled output (#194)."""

from __future__ import annotations

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


def _open(tmp_path: Path):
    binary = _need(_C2)
    db = tmp_path / "typed.glaurung"
    return PersistentKnowledgeBase.open(
        db, binary_path=binary, auto_load_stdlib=True,
    ), binary


def test_typed_locals_emit_real_c_declarations(tmp_path: Path) -> None:
    """A stack var with c_type='char *' should produce a real C
    declaration in the prelude — `char *buf;` — not just a comment."""
    kb, binary = _open(tmp_path)
    import glaurung as g
    funcs, _ = g.analysis.analyze_functions_path(str(binary))
    fn_va = int(funcs[0].entry_point.value)

    xref_db.set_stack_var(
        kb, function_va=fn_va, offset=-0x10, name="msg_buf",
        c_type="char *", set_by="manual",
    )
    xref_db.set_stack_var(
        kb, function_va=fn_va, offset=-0x20, name="counter",
        c_type="int", set_by="manual",
    )
    text = xref_db.render_decompile_with_names(
        kb, str(binary), fn_va, timeout_ms=500, style="c",
    )
    # Real declarations, not commented-out form.
    assert "char *msg_buf;" in text
    assert "int counter;" in text
    # The header / footer separator comments should still be present
    # so the prelude block is visually distinct.
    assert "── locals" in text
    kb.close()


def test_untyped_slots_remain_comments(tmp_path: Path) -> None:
    """Slots without c_type but with a set_by tag (manual / dwarf /
    propagated) should still show as comments — they convey provenance
    but can't compile."""
    kb, binary = _open(tmp_path)
    import glaurung as g
    funcs, _ = g.analysis.analyze_functions_path(str(binary))
    fn_va = int(funcs[0].entry_point.value)

    xref_db.set_stack_var(
        kb, function_va=fn_va, offset=-0x30, name="local_unknown",
        c_type=None, set_by="manual",
    )
    text = xref_db.render_decompile_with_names(
        kb, str(binary), fn_va, timeout_ms=500, style="c",
    )
    # A bare `local_unknown;` C declaration would be invalid — it
    # should appear as a comment instead.
    assert "// " in text and "local_unknown" in text
    # And specifically not as `; local_unknown;` (a syntax error).
    assert "\nlocal_unknown;\n" not in text
    kb.close()


def test_signature_comment_appears_when_proto_known(tmp_path: Path) -> None:
    """When the function has a prototype in the KB, the renderer
    should prepend a `// signature: ...` comment so the analyst sees
    the typed contract before the body."""
    from glaurung.llm.kb.xref_db import (
        FunctionParam, set_function_prototype,
    )
    kb, binary = _open(tmp_path)
    import glaurung as g
    funcs, _ = g.analysis.analyze_functions_path(str(binary))
    fn_va = int(funcs[0].entry_point.value)
    # Give the function a name and a prototype.
    xref_db.set_function_name(kb, fn_va, "do_work", set_by="manual")
    set_function_prototype(
        kb, "do_work", "int",
        [FunctionParam(name="argc", c_type="int"),
         FunctionParam(name="argv", c_type="char **")],
        set_by="manual",
    )
    text = xref_db.render_decompile_with_names(
        kb, str(binary), fn_va, timeout_ms=500, style="c",
    )
    assert "// signature: int do_work(int argc, char ** argv);" in text
    kb.close()


def test_no_prelude_when_no_typed_locals(tmp_path: Path) -> None:
    """A function with zero typed slots and no prototype should not
    produce a stray prelude block (the original render shape)."""
    kb, binary = _open(tmp_path)
    import glaurung as g
    funcs, _ = g.analysis.analyze_functions_path(str(binary))
    fn_va = int(funcs[0].entry_point.value)
    text = xref_db.render_decompile_with_names(
        kb, str(binary), fn_va, timeout_ms=500, style="c",
    )
    # No prelude header when nothing to surface.
    assert "── locals" not in text
    assert "// signature:" not in text
    kb.close()
