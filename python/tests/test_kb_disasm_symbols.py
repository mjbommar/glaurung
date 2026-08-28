"""`disasm --db --function` layers the project over the binary, not instead of it.

The KB-aware disassembler read names, entry points and function bounds from the
project ALONE. A project is an overlay on what the binary says; treating it as a
replacement meant a project holding one analyst rename knew exactly one
function, and three things broke at once:

* `--function main` failed with `function not found in DB` on any binary whose
  names had not been imported into the project;
* the function's end was "the next entry in the KB", and for the last function
  in a section there is none -- a 44-byte function disassembled **2,011
  instructions across 24 KB** of padding and whatever followed;
* `call 0x1020` stayed a bare address, because a PLT stub is not a KB row --
  in a module whose documented purpose is symbol-annotated output.

The exact function size was in the discovered function all along and was simply
not being asked for.
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
SOURCE = ROOT / "tests" / "fixtures" / "analyst_rename" / "analyst_rename.c"


@pytest.fixture(scope="module")
def toolchain():
    sys.path.insert(0, str(ROOT / "tools"))
    import fixture_toolchain as TC

    return TC


@pytest.fixture(scope="module")
def shared_object(toolchain, tmp_path_factory) -> Path:
    out = tmp_path_factory.mktemp("disasm-so") / "disasm-names-gcc-O1.so"
    compiled = toolchain.run(
        ["gcc", "-shared", "-fPIC", "-g", "-O1", "-o", str(out), str(SOURCE)],
        timeout=60,
    )
    assert compiled.returncode == 0, compiled.stderr
    return out


@pytest.fixture(scope="module")
def executable(toolchain, tmp_path_factory) -> Path:
    src = tmp_path_factory.mktemp("disasm-exe") / "e.c"
    src.write_text(
        "#include <stdio.h>\n#include <string.h>\n"
        "static int helper(const char *s) { return (int)strlen(s) * 3; }\n"
        "int main(int argc, char **argv) "
        '{ printf("%d\\n", helper(argv[0]) + argc); return 0; }\n'
    )
    out = src.parent / "e.bin"
    compiled = toolchain.run(["gcc", "-O0", "-g", "-o", str(out), str(src)], timeout=60)
    assert compiled.returncode == 0, compiled.stderr
    return out


def sizes(binary: Path) -> dict[str, tuple[int, int]]:
    """`{name: (va, size)}` straight from the dynamic symbol table."""
    nm = subprocess.run(
        ["nm", "-S", "-D", "--defined-only", str(binary)],
        capture_output=True,
        text=True,
        timeout=60,
        check=True,
    )
    out = {}
    for line in nm.stdout.splitlines():
        parts = line.split()
        if len(parts) == 4:
            out[parts[3]] = (int(parts[0], 16), int(parts[1], 16))
    return out


def empty_project(tmp_path: Path, binary: Path) -> str:
    db = tmp_path / "p.glaurung"
    PersistentKnowledgeBase.open(str(db), binary_path=str(binary)).close()
    return str(db)


def disasm(binary: Path, db: str, function: str) -> str:
    result = subprocess.run(
        ["glaurung", "disasm", str(binary), "--db", db, "--function", function],
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout


def test_a_function_absent_from_the_project_resolves_by_name(shared_object, tmp_path):
    """`function not found in DB` for a function the binary plainly exports."""
    db = empty_project(tmp_path, shared_object)
    assert "; driver" in disasm(shared_object, db, "driver")


def test_the_extent_is_the_functions_real_size(shared_object, tmp_path):
    """The last function in a section had no next entry, so it ran to the
    window cap -- 44 bytes became 24 KB."""
    db = empty_project(tmp_path, shared_object)
    va, size = sizes(shared_object)["driver"]
    header = disasm(shared_object, db, "driver").splitlines()[0]
    match = re.search(r"0x([0-9a-f]+)-0x([0-9a-f]+)", header)
    assert match, header
    start, end = int(match.group(1), 16), int(match.group(2), 16)
    assert start == va, header
    assert end - start <= size, (
        f"disassembled {end - start} bytes of a {size}-byte function: {header}"
    )


def test_a_library_call_is_symbolized(executable, tmp_path):
    db = empty_project(tmp_path, executable)
    text = disasm(executable, db, "main")
    assert "printf@plt" in text, text


def test_a_local_call_is_symbolized(executable, tmp_path):
    db = empty_project(tmp_path, executable)
    assert "-> helper" in disasm(executable, db, "main")


def test_a_plt_name_beats_a_synthesised_sub_name(shared_object, tmp_path):
    """Discovery finds the stub as an anonymous function; the call site is
    reaching `validate@plt`, and `sub_1020` says nothing."""
    db = empty_project(tmp_path, shared_object)
    text = disasm(shared_object, db, "driver")
    assert "validate@plt" in text, text
    assert re.search(r"->\s*sub_[0-9a-f]+", text) is None, text


def test_an_analyst_rename_reaches_the_call_site(shared_object, tmp_path):
    """A rename that stops at the function leaves the call site reading the old
    name, which is worse than showing no name at all."""
    va = sizes(shared_object)["validate"][0]
    db = tmp_path / "p.glaurung"
    kb = PersistentKnowledgeBase.open(str(db), binary_path=str(shared_object))
    xref_db.set_function_name(kb, va, "parse_packet_hdr", set_by="manual")
    kb.close()
    text = disasm(shared_object, str(db), "driver")
    assert "parse_packet_hdr@plt" in text, text
    assert "validate" not in text, text


def test_the_analyst_name_wins_over_the_binarys(shared_object, tmp_path):
    """The overlay is an overlay: it wins where it covers, and nowhere else."""
    va = sizes(shared_object)["validate"][0]
    db = tmp_path / "p.glaurung"
    kb = PersistentKnowledgeBase.open(str(db), binary_path=str(shared_object))
    xref_db.set_function_name(kb, va, "renamed_fn", set_by="manual")
    kb.close()
    text = disasm(shared_object, str(db), "renamed_fn")
    assert "; renamed_fn" in text, text
    # `driver` was never renamed and must still resolve from the binary.
    assert "; driver" in disasm(shared_object, str(db), "driver")
