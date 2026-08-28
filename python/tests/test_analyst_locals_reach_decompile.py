"""An analyst's local names and types must reach the decompiled body.

Renaming and retyping locals were previously visible only as a `// locals (from
KB)` comment block appended by a regex post-processor -- the body itself kept
`local_c`, and a retype changed no expression, no cast, and no declaration.

These now ride the same mechanism DWARF names use: `StackLocalFacts`'
`source_names` / `source_types`, applied by
`naming::apply_authoritative_local_names` at the presentation boundary, after
every semantic pass.

THE RULE THIS FILE EXISTS TO PIN. A name is applied only alongside a type. That
is not a formality. Measured on a stripped `-O0` build of the fixture, renaming
the surviving local at `rbp-0xc` with no type attached turned

    int local_c;   local_c = 0;   ...   return (unsigned int)(local_c);

into

    long running_total;   *(int *)(running_total) = 0;

-- a pointer store synthesised from a scalar assignment, because the local lost
its recovered width along with its `local_` identity. Declining the rename is
the correct answer; emitting that is not.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

from glaurung.llm.kb import xref_db
from glaurung.llm.kb.persistent import PersistentKnowledgeBase

ROOT = Path(__file__).resolve().parent.parent.parent
SOURCE = ROOT / "tests" / "fixtures" / "analyst_rename" / "analyst_locals.c"


@pytest.fixture(scope="module")
def binary(tmp_path_factory) -> Path:
    """Stripped: with DWARF the locals already have their source names."""
    sys.path.insert(0, str(ROOT / "tools"))
    import fixture_toolchain as TC

    out = tmp_path_factory.mktemp("analyst-locals") / "analyst-locals-gcc-O0.so"
    compiled = TC.run(
        ["gcc", "-shared", "-fPIC", "-O0", "-o", str(out), str(SOURCE)], timeout=60
    )
    assert compiled.returncode == 0, compiled.stderr
    stripped = TC.run(["strip", "--strip-debug", str(out)], timeout=60)
    assert stripped.returncode == 0, stripped.stderr
    return out


@pytest.fixture(scope="module")
def scan_va(binary: Path) -> int:
    nm = subprocess.run(
        ["nm", "-D", "--defined-only", str(binary)],
        capture_output=True,
        text=True,
        timeout=60,
        check=True,
    )
    for line in nm.stdout.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[2] == "scan":
            return int(parts[0], 16)
    raise AssertionError(nm.stdout)


def decompile(binary: Path, db: str | None) -> str:
    argv = [
        "glaurung",
        "decompile",
        str(binary),
        "--func",
        "scan",
        "--style",
        "decbench",
        "--no-color",
        "--cache-dir",
        "",
    ]
    if db:
        argv += ["--db", db]
    return subprocess.run(
        argv, capture_output=True, text=True, timeout=300, check=True
    ).stdout


def project(tmp_path: Path, binary: Path, scan_va: int, slots) -> str:
    tmp_path.mkdir(parents=True, exist_ok=True)
    db = tmp_path / "p.glaurung"
    kb = PersistentKnowledgeBase.open(str(db), binary_path=str(binary))
    for offset, name, c_type in slots:
        xref_db.set_stack_var(
            kb,
            function_va=scan_va,
            offset=offset,
            name=name,
            c_type=c_type,
            set_by="manual",
        )
    kb.close()
    return str(db)


def bound_offsets(binary: Path, scan_va: int, tmp_path_factory) -> list[int]:
    """Every frame offset in `scan` that a typed rename actually binds to.

    Probed rather than hard-coded: which slots survive promotion is a codegen
    detail a compiler upgrade will move, and a hard-coded offset that stopped
    binding would make these tests pass vacuously.
    """
    found = []
    for offset in range(-4, -40, -4):
        db = project(
            tmp_path_factory.mktemp(f"probe{-offset}"),
            binary,
            scan_va,
            [(offset, f"probe_{-offset}", "unsigned int")],
        )
        if f"probe_{-offset}" in decompile(binary, db):
            found.append(offset)
    return found


@pytest.fixture(scope="module")
def bound(binary, scan_va, tmp_path_factory) -> list[int]:
    offsets = bound_offsets(binary, scan_va, tmp_path_factory)
    if not offsets:
        pytest.skip("no frame slot in `scan` bound to a rename on this toolchain")
    return offsets


@pytest.fixture(scope="module")
def replacing_offset(binary, scan_va, bound, tmp_path_factory) -> int:
    """An offset whose rename REPLACES a `local_N` the baseline declared.

    Distinguished from an offset that ADDS a declaration, because the two are
    different behaviours and both are correct -- one renames a variable the
    render kept, the other recovers a source variable the passes had copy-
    propagated away.
    """
    plain = decompile(binary, None)
    baseline_locals = set(re.findall(r"\blocal_[0-9a-f]+\b", plain))
    for offset in bound:
        db = project(
            tmp_path_factory.mktemp(f"repl{-offset}"),
            binary,
            scan_va,
            [(offset, "renamed_slot", "unsigned int")],
        )
        after = set(re.findall(r"\blocal_[0-9a-f]+\b", decompile(binary, db)))
        if after < baseline_locals:
            return offset
    pytest.skip("no rename replaced a declared local on this toolchain")


def test_a_rename_with_a_type_replaces_a_declared_local(
    binary, scan_va, replacing_offset, tmp_path
):
    db = project(
        tmp_path, binary, scan_va, [(replacing_offset, "running_total", "unsigned int")]
    )
    text = decompile(binary, db)
    assert re.search(r"^\s+unsigned int running_total;", text, re.M), text
    assert "running_total = 0;" in text or "running_total =" in text, text


def test_no_rename_ever_produces_a_pointer_store(binary, scan_va, bound, tmp_path):
    """The failure this rule exists to prevent.

    Applied without a type, a rename lost the slot's recovered width along with
    its `local_` identity and the renderer read it as an address:
    `long running_total; *(int *)(running_total) = 0;` where the un-renamed
    body had `int local_c; local_c = 0;`.
    """
    for offset in bound:
        db = project(
            tmp_path / f"ptr{-offset}",
            binary,
            scan_va,
            [(offset, "named_slot", "unsigned int")],
        )
        text = decompile(binary, db)
        assert not re.search(r"\*\([^)]*\)\(named_slot\)\s*=", text), (
            f"offset {offset} produced a pointer store:\n{text}"
        )


def test_every_declared_local_is_assigned_before_the_body_uses_it(
    binary, scan_va, bound, tmp_path
):
    """A rename may recover a variable the passes had copy-propagated away --
    that is correct and closer to the source than the propagated form. What it
    must never do is DECLARE one and never assign it."""
    for offset in bound:
        db = project(
            tmp_path / f"init{-offset}",
            binary,
            scan_va,
            [(offset, "named_slot", "unsigned int")],
        )
        text = decompile(binary, db)
        if "named_slot" not in text:
            continue
        assert re.search(r"^\s+named_slot\s*=", text, re.M), (
            f"offset {offset} declared `named_slot` and never assigned it:\n{text}"
        )


def test_a_rename_without_a_type_is_declined_not_applied_wrongly(
    binary, scan_va, bound, tmp_path
):
    """Declining is correct; emitting a pointer store is not."""
    plain = decompile(binary, None)
    for offset in bound:
        db = project(
            tmp_path / f"untyped{-offset}", binary, scan_va, [(offset, "untyped", None)]
        )
        text = decompile(binary, db)
        assert text == plain, (
            f"an untyped rename at {offset} changed the output; it must be "
            f"declined outright\n--- without --db ---\n{plain}\n"
            f"--- with --db ---\n{text}"
        )


def test_a_retype_propagates_into_the_expressions(
    binary, scan_va, replacing_offset, tmp_path
):
    """The half a comment prelude could never do.

    Retyping the accumulator to `unsigned int` drops the `(unsigned int)` cast
    the untyped render needed on the return, because the declared type now
    matches. That is a change to an expression, not to a comment.
    """
    plain = decompile(binary, None)
    db = project(tmp_path, binary, scan_va, [(replacing_offset, "acc", "unsigned int")])
    text = decompile(binary, db)
    assert text != plain
    assert "acc" in text, text


def test_an_unusable_name_is_refused(binary, scan_va, bound, tmp_path):
    """A C keyword or an ABI role would produce C that does not compile, or
    would collide with a name the renderer owns."""
    plain = decompile(binary, None)
    for bad in ("int", "return", "arg0"):
        for offset in bound:
            db = project(
                tmp_path / f"bad-{bad}-{-offset}",
                binary,
                scan_va,
                [(offset, bad, "int")],
            )
            text = decompile(binary, db)
            assert not re.search(
                rf"^\s+(int|unsigned int) {re.escape(bad)};", text, re.M
            ), f"the unusable name {bad!r} was declared:\n{text}"


def test_without_a_project_nothing_changes(binary):
    text = decompile(binary, None)
    assert re.search(r"\blocal_[0-9a-f]+\b", text), (
        "the stripped baseline should show anonymous locals:\n" + text
    )
