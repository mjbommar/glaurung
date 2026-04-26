"""Tests for KB-aware decompile rendering (#196)."""

from __future__ import annotations

from pathlib import Path

import pytest

import glaurung as g
from glaurung.llm.kb import xref_db
from glaurung.llm.kb.persistent import PersistentKnowledgeBase


_C2_DEMO = Path(
    "samples/binaries/platforms/linux/amd64/export/native/clang/O0/c2_demo-clang-O0"
)
_HELLO_DEBUG = Path(
    "samples/binaries/platforms/linux/amd64/export/native/clang/debug/hello-clang-debug"
)


def _need(p: Path) -> Path:
    if not p.exists():
        pytest.skip(f"missing path {p}")
    return p


def test_decompile_with_names_substitutes_known_slots(tmp_path: Path) -> None:
    """When stack-frame slots are populated for a function, the
    rendered output should substitute named locals for the raw
    `(rbp - N)` references."""
    binary = _need(_C2_DEMO)
    db = tmp_path / "decomp.glaurung"
    kb = PersistentKnowledgeBase.open(db, binary_path=binary)

    funcs, _ = g.analysis.analyze_functions_path(str(binary))
    main = next((f for f in funcs if f.name == "main"), None)
    if main is None:
        pytest.skip("main not discovered")

    # Pre-populate slots from the disasm pass.
    xref_db.discover_stack_vars(kb, str(binary), int(main.entry_point.value))
    slots = xref_db.list_stack_vars(kb, function_va=int(main.entry_point.value))
    assert slots, "auto-discovery should produce slots in main"

    rendered = xref_db.render_decompile_with_names(
        kb, str(binary), int(main.entry_point.value),
    )
    # The original output contains `(rbp - N)` references; after
    # substitution, at least one should be replaced with a `var_*` name.
    assert "var_" in rendered, (
        f"no var_* substitutions made:\n{rendered[:400]}"
    )


def test_decompile_with_names_preserves_address_of_semantics(tmp_path: Path) -> None:
    """`(rbp - N)` is the *address* of a local — it must render as
    `&var_N` after substitution, not just `var_N`."""
    binary = _need(_C2_DEMO)
    db = tmp_path / "decomp.glaurung"
    kb = PersistentKnowledgeBase.open(db, binary_path=binary)
    funcs, _ = g.analysis.analyze_functions_path(str(binary))
    main = next((f for f in funcs if f.name == "main"), None)
    if main is None:
        pytest.skip("main not discovered")
    xref_db.discover_stack_vars(kb, str(binary), int(main.entry_point.value))

    rendered = xref_db.render_decompile_with_names(
        kb, str(binary), int(main.entry_point.value),
    )
    # c2_demo's main calls memcpy/snprintf with a `(rbp - 272)`
    # destination → after rendering, `&var_110` should appear at least
    # once (272 = 0x110).
    assert "&var_" in rendered, (
        f"expected at least one &var_* (address-of local); got:\n{rendered[:400]}"
    )


def test_decompile_with_names_falls_back_when_no_slots(tmp_path: Path) -> None:
    """No slots in KB → output is unchanged from raw decompile."""
    binary = _need(_HELLO_DEBUG)
    db = tmp_path / "decomp.glaurung"
    kb = PersistentKnowledgeBase.open(db, binary_path=binary)

    funcs, _ = g.analysis.analyze_functions_path(str(binary))
    main = next((f for f in funcs if f.name == "main"), None)
    if main is None:
        pytest.skip("main not discovered")
    # Don't run discover_stack_vars; KB has no slots for this function.
    raw = g.ir.decompile_at(
        str(binary), int(main.entry_point.value),
        timeout_ms=500, style="c",
    )
    rendered = xref_db.render_decompile_with_names(
        kb, str(binary), int(main.entry_point.value),
    )
    assert rendered == raw, "no-slots case should pass through unchanged"


def test_locals_prelude_lists_typed_slots(tmp_path: Path) -> None:
    """When propagation has typed slots, the rendered output should
    include a `// ── locals (from KB)` block at the top of the function
    body listing each typed slot with its c_type and provenance."""
    binary = _need(_C2_DEMO)
    db = tmp_path / "decomp.glaurung"
    kb = PersistentKnowledgeBase.open(
        db, binary_path=binary, auto_load_stdlib=True,
    )
    xref_db.index_callgraph(kb, str(binary))
    funcs, _ = g.analysis.analyze_functions_path(str(binary))
    main = next((f for f in funcs if f.name == "main"), None)
    if main is None:
        pytest.skip("main not discovered")
    xref_db.discover_stack_vars(kb, str(binary), int(main.entry_point.value))
    xref_db.propagate_types_at_callsites(kb, str(binary), int(main.entry_point.value))

    rendered = xref_db.render_decompile_with_names(
        kb, str(binary), int(main.entry_point.value),
    )
    assert "── locals (from KB)" in rendered
    # Propagated slots show their set_by tag (#194 changed format
    # from `// propagated` comment line to `set_by=propagated` tag
    # alongside a real C declaration).
    assert "set_by=propagated" in rendered
    kb.close()


def test_locals_prelude_can_be_disabled(tmp_path: Path) -> None:
    binary = _need(_C2_DEMO)
    db = tmp_path / "decomp.glaurung"
    kb = PersistentKnowledgeBase.open(db, binary_path=binary)
    funcs, _ = g.analysis.analyze_functions_path(str(binary))
    main = next((f for f in funcs if f.name == "main"), None)
    if main is None:
        pytest.skip("main not discovered")
    xref_db.discover_stack_vars(kb, str(binary), int(main.entry_point.value))
    xref_db.set_stack_var(
        kb, function_va=int(main.entry_point.value), offset=-0x110,
        name="my_buf", c_type="char[256]", set_by="manual",
    )
    rendered = xref_db.render_decompile_with_names(
        kb, str(binary), int(main.entry_point.value),
        include_locals_prelude=False,
    )
    assert "── locals (from KB)" not in rendered
    # But name substitution still happens.
    assert "my_buf" in rendered
    kb.close()


def test_manual_rename_propagates_to_decompile_output(tmp_path: Path) -> None:
    """When an analyst renames a slot, the rename should appear in the
    next `decomp` invocation — closing the loop on the analyst UX."""
    binary = _need(_C2_DEMO)
    db = tmp_path / "decomp.glaurung"
    kb = PersistentKnowledgeBase.open(db, binary_path=binary)
    funcs, _ = g.analysis.analyze_functions_path(str(binary))
    main = next((f for f in funcs if f.name == "main"), None)
    if main is None:
        pytest.skip("main not discovered")
    xref_db.discover_stack_vars(kb, str(binary), int(main.entry_point.value))

    # Find a slot the disassembler discovered and rename it.
    slots = xref_db.list_stack_vars(kb, function_va=int(main.entry_point.value))
    target = next((s for s in slots if s.offset == -0x110), None)
    if target is None:
        pytest.skip("expected slot at offset -0x110 not present")
    xref_db.set_stack_var(
        kb, function_va=int(main.entry_point.value), offset=-0x110,
        name="c2_url_buffer", c_type="char[256]", set_by="manual",
    )
    rendered = xref_db.render_decompile_with_names(
        kb, str(binary), int(main.entry_point.value),
    )
    assert "c2_url_buffer" in rendered, (
        "manual rename did not appear in re-rendered decompile output"
    )
    # The default `var_110` name should NOT also appear (it was renamed).
    assert "var_110" not in rendered
