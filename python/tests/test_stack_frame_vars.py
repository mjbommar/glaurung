"""Tests for stack-frame variable recovery (#191)."""

from __future__ import annotations

from pathlib import Path

import pytest

import glaurung as g
from glaurung.llm.kb import xref_db
from glaurung.llm.kb.persistent import PersistentKnowledgeBase


def _need(p: Path) -> Path:
    if not p.exists():
        pytest.skip(f"missing sample binary {p}")
    return p


_HELLO_DEBUG = Path(
    "samples/binaries/platforms/linux/amd64/export/native/clang/debug/hello-clang-debug"
)
_HELLO_O2 = Path(
    "samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-gcc-O2"
)


def test_parse_frame_offset_recognises_canonical_forms() -> None:
    """The disassembler emits operands shaped `rbp:[rbp - 0x10]` /
    `[rbp+0x18]`. Parser must extract the signed offset reliably."""
    cases = [
        ("rbp:[rbp - 0x10]", -16),
        ("rbp:[rbp - 0x4]", -4),
        ("[rbp+0x18]", 0x18),
        ("rsp:[rsp - 0x40]", -64),
        ("[rsp + 8]", 8),
        ("[ebp - 0x20]", -0x20),
    ]
    for op, expected in cases:
        assert xref_db._parse_frame_offset(op) == expected, (
            f"parser failed on {op!r}: got {xref_db._parse_frame_offset(op)}, want {expected}"
        )


def test_parse_frame_offset_rejects_non_frame_operands() -> None:
    """Register-only operands and non-rbp/rsp memory refs return None."""
    for op in ("rax", "rdi", "[rax+0x10]", "[rdx*8]", "0x1234", ""):
        assert xref_db._parse_frame_offset(op) is None, (
            f"parser falsely accepted non-frame operand {op!r}"
        )


def test_default_var_name_uses_ida_convention() -> None:
    assert xref_db._default_var_name(-16) == "var_10"
    assert xref_db._default_var_name(-4) == "var_4"
    assert xref_db._default_var_name(0x18) == "arg_18"
    assert xref_db._default_var_name(8) == "arg_8"


def test_set_get_list_round_trip(tmp_path: Path) -> None:
    binary = _need(_HELLO_DEBUG)
    db = tmp_path / "stack.glaurung"
    kb = PersistentKnowledgeBase.open(db, binary_path=binary)

    xref_db.set_stack_var(
        kb, function_va=0x12d0, offset=-0x10, name="argc_storage",
        c_type="int", set_by="manual",
    )
    xref_db.set_stack_var(
        kb, function_va=0x12d0, offset=-0x18, name="argv_storage",
        c_type="char **", set_by="manual",
    )
    xref_db.set_stack_var(
        kb, function_va=0x12d0, offset=0x10, name="ret_addr",
        set_by="auto", use_count=3,
    )

    rec = xref_db.get_stack_var(kb, 0x12d0, -0x10)
    assert rec is not None
    assert rec.name == "argc_storage"
    assert rec.c_type == "int"
    assert rec.set_by == "manual"

    listing = xref_db.list_stack_vars(kb, function_va=0x12d0)
    assert len(listing) == 3
    # Sorted by offset: -0x18, -0x10, +0x10
    assert [s.offset for s in listing] == [-0x18, -0x10, 0x10]
    kb.close()


def test_manual_entries_survive_auto_overwrite_attempt(tmp_path: Path) -> None:
    binary = _need(_HELLO_DEBUG)
    db = tmp_path / "stack.glaurung"
    kb = PersistentKnowledgeBase.open(db, binary_path=binary)

    # Analyst names a slot.
    xref_db.set_stack_var(
        kb, function_va=0x12d0, offset=-0x8, name="my_size",
        c_type="size_t", set_by="manual",
    )
    # Auto-discovery later finds the same slot.
    xref_db.set_stack_var(
        kb, function_va=0x12d0, offset=-0x8, name="var_8",
        set_by="auto", use_count=5,
    )

    rec = xref_db.get_stack_var(kb, 0x12d0, -0x8)
    assert rec is not None
    assert rec.name == "my_size"            # manual preserved
    assert rec.c_type == "size_t"
    # use_count from the auto pass DOES land — it's evidence, not a name.
    assert rec.use_count == 5
    kb.close()


def test_discover_stack_vars_finds_real_locals(tmp_path: Path) -> None:
    """End-to-end against a real -O0 -g binary's main, which always has
    a populated stack frame."""
    binary = _need(_HELLO_DEBUG)
    db = tmp_path / "stack.glaurung"
    kb = PersistentKnowledgeBase.open(db, binary_path=binary)

    funcs, _cg = g.analysis.analyze_functions_path(str(binary))
    main = next((f for f in funcs if f.name == "main"), None)
    if main is None:
        pytest.skip("main not discovered in sample")

    n = xref_db.discover_stack_vars(kb, str(binary), int(main.entry_point.value))
    assert n >= 2, (
        f"expected to find at least 2 stack-frame slots in main; got {n}"
    )
    listing = xref_db.list_stack_vars(kb, function_va=int(main.entry_point.value))
    assert len(listing) == n
    # Locals: at least one negative-offset slot, named var_*.
    locals_only = [s for s in listing if s.offset < 0]
    assert locals_only, "no negative-offset slots discovered"
    assert all(s.name.startswith("var_") for s in locals_only)
    # Auto-discovery records use_count.
    assert all(s.use_count > 0 for s in locals_only)
    kb.close()


def test_discover_handles_optimized_binary_without_crashing(tmp_path: Path) -> None:
    """-O2 builds often elide rbp ('frame pointer omission') and use rsp
    instead. The discover pass must still complete and may surface fewer
    slots; either way it must not raise."""
    binary = _need(_HELLO_O2)
    db = tmp_path / "stack.glaurung"
    kb = PersistentKnowledgeBase.open(db, binary_path=binary)
    funcs, _cg = g.analysis.analyze_functions_path(str(binary))
    main = next((f for f in funcs if f.name == "main"), None)
    if main is None:
        pytest.skip("main not discovered in -O2 sample")
    n = xref_db.discover_stack_vars(kb, str(binary), int(main.entry_point.value))
    assert n >= 0  # zero is acceptable on heavily-optimized code
    kb.close()
