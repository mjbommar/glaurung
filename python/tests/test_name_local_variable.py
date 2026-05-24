"""Unit tests for Tool #5: name_local_variable.

These tests exercise the heuristic fallback path -- the LLM path is
covered indirectly via the F4 integration tests in
test_cli_explain_with_layer0.py. The heuristic path must always
produce a well-formed snake_case name and a confidence in [0, 1].
"""

from __future__ import annotations

import pytest

from glaurung.llm.context import Budgets, MemoryContext
from glaurung.llm.tools.name_local_variable import (
    NameLocalVariableArgs,
    NameLocalVariableTool,
    _heuristic,
    _slugify,
)


def _bare_ctx() -> MemoryContext:
    return MemoryContext(
        file_path="/dev/null",
        artifact=None,
        budgets=Budgets(timeout_ms=1000),
    )


def test_slugify_strips_special_chars():
    assert _slugify("var3") == "var3"
    assert _slugify("%var3") == "var3"
    assert _slugify("path-len") == "path_len"
    assert _slugify("") == "var"
    assert _slugify("    ") == "var"


def test_heuristic_recognises_char_pointer_with_strlen():
    out = _heuristic(
        "var3",
        "char*",
        ["len = strlen(var3)", "if var3[0] == 0"],
        "local",
    )
    assert out.name == "str"
    assert 0.0 <= out.confidence <= 1.0


def test_heuristic_recognises_generic_char_pointer():
    out = _heuristic("var3", "char*", [], "local")
    assert out.name == "buf"


def test_heuristic_recognises_size_type():
    out = _heuristic("var3", "size_t", [], "local")
    assert out.name == "len"


def test_heuristic_recognises_loop_counter():
    # Heuristic looks for ``+\s*1\b`` AND ``<\s*\w+`` in the slice body
    # -- the increment-by-one + comparison shape of a canonical for-loop.
    out = _heuristic(
        "var3",
        "int",
        ["i = 0", "while var3 < n", "var3 = var3 + 1"],
        "local",
    )
    assert out.name == "i"


def test_heuristic_recognises_return_role():
    out = _heuristic("var3", "int", [], "return")
    assert out.name == "ret"


def test_heuristic_falls_back_to_sanitised_id():
    out = _heuristic("var3", "int", [], "local")
    # No distinguishing features -- output is the sanitised original.
    assert out.name == "var3"
    assert out.confidence <= 0.3


def test_tool_use_llm_false_is_pure_heuristic():
    """``use_llm=False`` must never reach the LLM; output is the
    heuristic only."""
    ctx = _bare_ctx()
    tool = NameLocalVariableTool()
    result = tool.run(
        ctx,
        ctx.kb,
        NameLocalVariableArgs(
            current_id="var3",
            recovered_type="char*",
            def_use_slice=["len = strlen(var3)"],
            role_hint="local",
            use_llm=False,
        ),
    )
    assert result.source == "heuristic"
    assert result.current_id == "var3"
    assert result.named.name == "str"
    assert 0.0 <= result.named.confidence <= 1.0


def test_tool_returns_snake_case_identifier():
    """Whatever path fires, the returned name must be snake_case."""
    ctx = _bare_ctx()
    tool = NameLocalVariableTool()
    result = tool.run(
        ctx,
        ctx.kb,
        NameLocalVariableArgs(
            current_id="%arg0",
            recovered_type="int",
            def_use_slice=[],
            role_hint="parameter",
            use_llm=False,
        ),
    )
    name = result.named.name
    # snake_case = lowercase alphanumeric + underscore only.
    assert all(c.islower() or c.isdigit() or c == "_" for c in name), (
        f"non-snake-case name: {name!r}"
    )
