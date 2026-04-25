"""Tests for cross-function type propagation v2 (#195)."""

from __future__ import annotations

from pathlib import Path

import pytest

import glaurung as g
from glaurung.llm.kb import xref_db
from glaurung.llm.kb.persistent import PersistentKnowledgeBase


_HELLO_C_O0 = Path(
    "samples/binaries/platforms/linux/amd64/export/native/clang/O0/hello-c-clang-O0"
)
_HELLO_DEBUG = Path(
    "samples/binaries/platforms/linux/amd64/export/native/clang/debug/hello-clang-debug"
)
_C2_DEMO_O0 = Path(
    "samples/binaries/platforms/linux/amd64/export/native/clang/O0/c2_demo-clang-O0"
)


def _need(p: Path) -> Path:
    if not p.exists():
        pytest.skip(f"missing path {p}")
    return p


def test_operand_destination_register_recognises_sysv_args() -> None:
    """Helper used by the propagation pass: any operand naming an
    SysV arg register (in any width) maps to its 64-bit canonical."""
    cases = [
        ("rdi", "rdi"),
        ("edi", "rdi"),
        ("rsi:rsi", "rsi"),  # disassembler colon prefix
        ("EDX", "rdx"),
        ("rax", None),       # not an arg register
        ("[rdi]", None),     # memory operand
        ("0x10", None),
    ]
    for op, expected in cases:
        got = xref_db._operand_destination_register(op)
        assert got == expected, f"{op!r} → {got!r}, want {expected!r}"


def test_resolve_call_target_uses_va_map() -> None:
    """Quick smoke against the call-target resolver."""

    class _Op:
        def __init__(self, s):
            self.s = s

        def __str__(self):
            return self.s

    class _Inst:
        def __init__(self, ops):
            self.operands = [_Op(o) for o in ops]
            self.mnemonic = "call"

    name_by_va = {0x1180: "puts", 0x1190: "strlen"}
    assert xref_db._resolve_call_target_name(_Inst(["0x1180"]), name_by_va) == "puts"
    assert xref_db._resolve_call_target_name(_Inst(["0x9999"]), name_by_va) is None
    # Symbolic operand passes through.
    assert xref_db._resolve_call_target_name(_Inst(["printf"]), name_by_va) == "printf"
    # Indirect call.
    assert xref_db._resolve_call_target_name(_Inst(["[rax]"]), name_by_va) is None


def test_propagation_does_not_overwrite_manual_slots(tmp_path: Path) -> None:
    """Even when a propagation candidate exists, a slot whose c_type
    was set manually must survive."""
    binary = _need(_HELLO_DEBUG)
    db = tmp_path / "tp.glaurung"
    kb = PersistentKnowledgeBase.open(db, binary_path=binary, auto_load_stdlib=True)

    funcs, _ = g.analysis.analyze_functions_path(str(binary))
    main = next((f for f in funcs if f.name == "main"), None)
    if main is None:
        pytest.skip("main not discovered")

    # Pre-populate a slot with a manual type.
    xref_db.set_stack_var(
        kb, function_va=int(main.entry_point.value), offset=-0x10,
        name="my_argv", c_type="my_custom_type", set_by="manual",
    )
    xref_db.index_callgraph(kb, str(binary))
    xref_db.propagate_types_at_callsites(kb, str(binary), int(main.entry_point.value))
    rec = xref_db.get_stack_var(kb, int(main.entry_point.value), -0x10)
    assert rec is not None
    assert rec.c_type == "my_custom_type"
    assert rec.set_by == "manual"
    kb.close()


def test_propagation_returns_zero_without_prototypes(tmp_path: Path) -> None:
    """If the prototype table is empty, the pass is a no-op."""
    binary = _need(_HELLO_DEBUG)
    db = tmp_path / "tp.glaurung"
    # auto_load_stdlib=False → no prototypes loaded.
    kb = PersistentKnowledgeBase.open(db, binary_path=binary)
    funcs, _ = g.analysis.analyze_functions_path(str(binary))
    main = next((f for f in funcs if f.name == "main"), None)
    assert main is not None
    n = xref_db.propagate_types_at_callsites(
        kb, str(binary), int(main.entry_point.value),
    )
    assert n == 0
    kb.close()


def test_propagation_lifts_c2_demo_via_libc_calls(tmp_path: Path) -> None:
    """End-to-end against c2_demo-clang-O0: this binary makes many
    direct calls to libc (open/read/write/close/strcpy/...) with
    stack-slot arguments, so the propagation pass should reliably
    refine a meaningful number of slots to libc parameter types
    (`void *`, `char *`, `size_t`, `int`)."""
    binary = _need(_C2_DEMO_O0)
    db = tmp_path / "tp.glaurung"
    kb = PersistentKnowledgeBase.open(
        db, binary_path=binary, auto_load_stdlib=True,
    )
    xref_db.index_callgraph(kb, str(binary))

    funcs, _ = g.analysis.analyze_functions_path(str(binary))
    total = 0
    for f in funcs:
        if not f.basic_blocks:
            continue
        xref_db.discover_stack_vars(kb, str(binary), int(f.entry_point.value))
        total += xref_db.propagate_types_at_callsites(
            kb, str(binary), int(f.entry_point.value),
        )
    assert total >= 5, (
        f"expected ≥5 stack-slot type refinements via libc-call propagation; got {total}"
    )
    typed = [s for s in xref_db.list_stack_vars(kb)
             if s.c_type and s.set_by == "propagated"]
    assert typed
    # Sanity: types come from the libc proto bundle vocabulary.
    seen_types = {s.c_type for s in typed}
    libc_shaped = {t for t in seen_types if any(
        kw in t for kw in ("char", "void *", "size_t", "int", "FILE", "*const")
    )}
    assert libc_shaped, f"propagated types don't look libc-shaped: {seen_types}"
    kb.close()
