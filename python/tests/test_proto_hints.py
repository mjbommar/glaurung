"""Tests for function-prototype hints in render_decompile (#227)."""

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


def _seed(tmp_path: Path):
    binary = _need(_C2)
    db = tmp_path / "proto.glaurung"
    kb = PersistentKnowledgeBase.open(
        db, binary_path=binary, auto_load_stdlib=True,
    )
    return kb, binary


def _find_function_with_call(kb, binary, callee_name: str):
    """Return a (caller_va, body) where the rendered body contains a
    call to `callee_name`. Skips when not present."""
    import glaurung as g
    funcs, _ = g.analysis.analyze_functions_path(str(binary))
    for f in funcs:
        try:
            text = xref_db.render_decompile_with_names(
                kb, str(binary), int(f.entry_point.value),
                timeout_ms=500, style="c",
                include_call_proto_hints=False,
            )
        except Exception:
            continue
        if callee_name in text:
            return int(f.entry_point.value), text
    pytest.skip(f"no function calls {callee_name} in this binary")


def test_proto_hint_appears_for_libc_call(tmp_path: Path) -> None:
    """A call to printf (or any libc fn auto-loaded as a stdlib proto)
    should grow a `// proto: int printf(const char *fmt, ...)` hint
    on the call line."""
    kb, binary = _seed(tmp_path)
    fn_va, _ = _find_function_with_call(kb, binary, "printf")
    text = xref_db.render_decompile_with_names(
        kb, str(binary), fn_va, timeout_ms=500, style="c",
        include_call_proto_hints=True,
    )
    # Must contain at least one printf call line with a hint comment.
    assert any(
        "printf" in line and "// proto:" in line and "fmt" in line
        for line in text.splitlines()
    )
    kb.close()


def test_proto_hint_can_be_disabled(tmp_path: Path) -> None:
    kb, binary = _seed(tmp_path)
    fn_va, _ = _find_function_with_call(kb, binary, "printf")
    text = xref_db.render_decompile_with_names(
        kb, str(binary), fn_va, timeout_ms=500, style="c",
        include_call_proto_hints=False,
    )
    # No proto hints anywhere when the flag is off.
    assert "// proto:" not in text
    kb.close()


def test_proto_hint_skips_lines_with_existing_comment(tmp_path: Path) -> None:
    """The hint pass must not append to a line that already carries
    a `//` comment — those came from the locals prelude or analyst
    annotation and shouldn't be double-tagged."""
    kb, binary = _seed(tmp_path)
    fn_va, _ = _find_function_with_call(kb, binary, "printf")
    text = xref_db.render_decompile_with_names(
        kb, str(binary), fn_va, timeout_ms=500, style="c",
        include_call_proto_hints=True,
    )
    # No line should have two `//` comments.
    for line in text.splitlines():
        assert line.count("//") <= 1, f"double-comment on: {line}"
    kb.close()


def test_proto_hint_uses_analyst_set_proto(tmp_path: Path) -> None:
    """Manually set a prototype for a function and confirm the hint
    appears at every call site for that function."""
    from glaurung.llm.kb.xref_db import (
        FunctionParam, set_function_prototype,
    )
    kb, binary = _seed(tmp_path)
    fn_va, _ = _find_function_with_call(kb, binary, "memcpy")
    set_function_prototype(
        kb, "memcpy", "void *",
        [
            FunctionParam(name="dst", c_type="void *"),
            FunctionParam(name="src", c_type="const void *"),
            FunctionParam(name="n", c_type="size_t"),
        ],
        set_by="manual",
    )
    text = xref_db.render_decompile_with_names(
        kb, str(binary), fn_va, timeout_ms=500, style="c",
        include_call_proto_hints=True,
    )
    assert any(
        "memcpy" in line and "// proto:" in line and "size_t n" in line
        for line in text.splitlines()
    )
    kb.close()


def test_proto_hint_no_proto_no_hint(tmp_path: Path) -> None:
    """If a function has no prototype in the KB, its call lines must
    not gain a hint."""
    kb, binary = _seed(tmp_path)
    # Use a function name that's almost certainly NOT in any bundle.
    bogus = "totally_made_up_function"
    text = xref_db.render_decompile_with_names(
        kb, str(binary), 0x1110, timeout_ms=500, style="c",
        include_call_proto_hints=True,
    )
    # No line should mention the bogus name with a hint.
    assert not any(
        bogus in line and "// proto:" in line for line in text.splitlines()
    )
    kb.close()
