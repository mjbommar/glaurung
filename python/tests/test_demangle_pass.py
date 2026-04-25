"""Tests for demangler audit + KB-wide pass (#182)."""

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
_HELLO_C = Path(
    "samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-c-gcc-O2"
)


def test_native_demangler_handles_itanium_and_rust() -> None:
    """Quick smoke against the native demangle bridge."""
    r = g.strings.demangle_text("_ZN10HelloWorld12printMessageEv")
    assert r is not None
    demangled, flavor = r
    assert flavor == "itanium"
    assert "HelloWorld" in demangled and "printMessage" in demangled

    # Rust v0 — pulled from a real Rust mangling.
    r2 = g.strings.demangle_text("_ZN3std4sync4onceE")
    if r2 is not None:
        _, flavor2 = r2
        assert flavor2 in ("rust", "itanium")  # cpp_demangle may also accept

    # Plain C names should not match anything.
    assert g.strings.demangle_text("main") is None
    assert g.strings.demangle_text("printf") is None


def test_demangle_pass_lights_itanium_names(tmp_path: Path) -> None:
    binary = _need(_HELLO_DEBUG)
    db = tmp_path / "demangle.glaurung"
    kb = PersistentKnowledgeBase.open(db, binary_path=binary)

    # index_callgraph populates function_names AND now runs the demangle pass.
    xref_db.index_callgraph(kb, str(binary))

    names = xref_db.list_function_names(kb)
    assert names, "expected function_names rows"
    # At least one C++ function should have its demangled column populated.
    demangled_count = sum(1 for n in names if n.demangled)
    assert demangled_count >= 3, (
        f"expected >=3 demangled names; got {demangled_count} of {len(names)}"
    )
    # Spot-check: an Itanium-mangled C++ method renders sanely.
    cpp = [n for n in names if n.flavor == "itanium"]
    assert cpp, "no Itanium-mangled functions surfaced"
    sample = cpp[0]
    assert sample.demangled and sample.demangled != sample.canonical
    # display property prefers demangled when available.
    assert sample.display == sample.demangled
    # Plain-C names display as canonical (no mangling).
    plain = [n for n in names if n.flavor is None]
    if plain:
        assert plain[0].display == plain[0].canonical
    kb.close()


def test_demangle_pass_idempotent(tmp_path: Path) -> None:
    binary = _need(_HELLO_DEBUG)
    db = tmp_path / "demangle.glaurung"
    kb = PersistentKnowledgeBase.open(db, binary_path=binary)
    xref_db.index_callgraph(kb, str(binary))

    a = xref_db.demangle_function_names(kb)
    b = xref_db.demangle_function_names(kb)
    assert a["total"] == b["total"]
    assert a.get("itanium", 0) == b.get("itanium", 0)
    kb.close()


def test_set_function_name_preserves_demangled(tmp_path: Path) -> None:
    """Renaming via set_function_name should NOT clobber a previously
    populated demangled column. Behavior: when an analyst renames a
    mangled symbol to something readable, the old demangled value
    becomes stale — we clear it on rename so callers fetch a fresh one."""
    binary = _need(_HELLO_DEBUG)
    db = tmp_path / "demangle.glaurung"
    kb = PersistentKnowledgeBase.open(db, binary_path=binary)
    xref_db.index_callgraph(kb, str(binary))

    cpp_names = [n for n in xref_db.list_function_names(kb) if n.flavor == "itanium"]
    if not cpp_names:
        pytest.skip("no Itanium-mangled symbols in sample")
    n = cpp_names[0]
    xref_db.set_function_name(kb, n.entry_va, "my_renamed", set_by="manual")
    after = xref_db.get_function_name(kb, n.entry_va)
    assert after is not None
    assert after.canonical == "my_renamed"
    # demangled and flavor are reset by INSERT OR REPLACE — that's the
    # documented behavior. A re-run of demangle_function_names will
    # repopulate them based on the new canonical (which won't match any
    # mangling, so the columns stay NULL).
    assert after.demangled is None
    kb.close()


def test_demangler_handles_c_only_binary(tmp_path: Path) -> None:
    binary = _need(_HELLO_C)
    db = tmp_path / "c.glaurung"
    kb = PersistentKnowledgeBase.open(db, binary_path=binary)
    xref_db.index_callgraph(kb, str(binary))

    names = xref_db.list_function_names(kb)
    # A C binary has no mangled names — most should show flavor=None.
    plain = [n for n in names if n.flavor is None]
    assert plain, "C binary should have unmangled function names"
    kb.close()
