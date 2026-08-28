"""A callgraph has to be readable, which means its nodes need names.

Two defects, both making the callgraph disagree with every other surface:

1. **Library and intra-module edges were anonymous.** A callgraph node is named
   after a discovered *function*, and a PLT stub is not one, so `main` called
   `sub_1030` rather than `printf@plt`. On a shared object every intra-module
   call goes through a stub, so essentially every edge was hex. The decompiler
   has always resolved these (`ir::name_resolve` folds `elf_plt_map` into its
   address map); only this surface did not.

2. **`graph` was blind to the project.** A function renamed by the analyst
   still appeared under its old name here while appearing under the new one in
   `decompile --db` -- and its stub kept the old name too, so the rename was
   visible on the node and invisible on the edge pointing at it.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from glaurung.llm.kb import xref_db
from glaurung.llm.kb.persistent import PersistentKnowledgeBase

ROOT = Path(__file__).resolve().parent.parent.parent
SOURCE = ROOT / "tests" / "fixtures" / "analyst_rename" / "analyst_rename.c"


def graph(binary: Path, *extra: str) -> str:
    result = subprocess.run(
        ["glaurung", "graph", str(binary), "callgraph", *extra],
        capture_output=True,
        text=True,
        timeout=300,
        check=True,
    )
    return result.stdout


@pytest.fixture(scope="module")
def toolchain():
    sys.path.insert(0, str(ROOT / "tools"))
    import fixture_toolchain as TC

    return TC


@pytest.fixture(scope="module")
def shared_object(toolchain, tmp_path_factory) -> Path:
    out = tmp_path_factory.mktemp("graph-so") / "graph-names-gcc-O1.so"
    compiled = toolchain.run(
        ["gcc", "-shared", "-fPIC", "-g", "-O1", "-o", str(out), str(SOURCE)],
        timeout=60,
    )
    assert compiled.returncode == 0, compiled.stderr
    return out


@pytest.fixture(scope="module")
def executable(toolchain, tmp_path_factory) -> Path:
    """A normal executable, so the PLT case is not only a shared-object quirk."""
    src = tmp_path_factory.mktemp("graph-exe") / "e.c"
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


def entry_vas(binary: Path) -> dict[str, int]:
    nm = subprocess.run(
        ["nm", "-D", "--defined-only", str(binary)],
        capture_output=True,
        text=True,
        timeout=60,
        check=True,
    )
    return {
        p[2]: int(p[0], 16)
        for p in (line.split() for line in nm.stdout.splitlines())
        if len(p) == 3
    }


# --------------------------------------------------------------------------
# PLT labelling (no project involved)
# --------------------------------------------------------------------------


def test_library_calls_are_named_not_hex(executable):
    dot = graph(executable)
    assert '"main" -> "printf@plt"' in dot, dot
    assert '"helper" -> "strlen@plt"' in dot, dot


def test_the_qualifier_is_kept(executable):
    """`@plt` says the edge goes through a stub. That is information, not
    decoration, and dropping it would make a stub indistinguishable from the
    real function."""
    dot = graph(executable)
    assert "printf@plt" in dot
    assert '"printf";' not in dot


def test_two_stubs_for_one_symbol_emit_one_node(executable):
    """`.plt` and `.plt.sec` hold separate stubs for the same symbol, so two
    nodes now resolve to one label. The collapse is correct; emitting the node
    line twice is not."""
    dot = graph(executable)
    for label in ("printf@plt", "strlen@plt"):
        declarations = [
            line
            for line in dot.splitlines()
            if line.strip().startswith(f'"{label}"') and "->" not in line
        ]
        assert len(declarations) == 1, (label, declarations)


def test_edges_are_deduplicated(executable):
    edges = [line.strip() for line in graph(executable).splitlines() if "->" in line]
    assert len(edges) == len(set(edges)), "duplicate edges after the label collapse"


def test_a_non_elf_still_renders(tmp_path):
    """No PLT map is an absence of labels, not a failure."""
    fake = tmp_path / "not-an-elf.bin"
    fake.write_bytes(b"MZ" + b"\x00" * 512)
    result = subprocess.run(
        ["glaurung", "graph", str(fake), "callgraph"],
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert result.returncode in (0, 3), result.stderr


# --------------------------------------------------------------------------
# The project overlay
# --------------------------------------------------------------------------


@pytest.fixture
def project(shared_object: Path, tmp_path: Path) -> str:
    vas = entry_vas(shared_object)
    assert "validate" in vas
    db = tmp_path / "p.glaurung"
    kb = PersistentKnowledgeBase.open(str(db), binary_path=str(shared_object))
    xref_db.set_function_name(kb, vas["validate"], "parse_packet_hdr", set_by="manual")
    kb.close()
    return str(db)


def test_without_a_project_the_binarys_own_names_are_used(shared_object):
    dot = graph(shared_object)
    assert '"validate"' in dot
    assert "parse_packet_hdr" not in dot


def test_a_rename_reaches_the_node(shared_object, project):
    dot = graph(shared_object, "--db", project)
    assert '"parse_packet_hdr"' in dot, dot


def test_a_rename_reaches_the_stub_the_edges_point_at(shared_object, project):
    """The half that makes the graph self-consistent.

    A rename that stops at the node leaves `driver -> validate@plt` sitting
    next to a node called `parse_packet_hdr`, which is harder to read than no
    names at all.
    """
    dot = graph(shared_object, "--db", project)
    assert '"driver" -> "parse_packet_hdr@plt"' in dot, dot
    assert "validate" not in dot, "a pre-rename name survived somewhere:\n" + dot


def test_an_unreadable_project_does_not_kill_the_graph(shared_object, tmp_path):
    junk = tmp_path / "junk.glaurung"
    junk.write_bytes(b"this is not a sqlite database")
    dot = graph(shared_object, "--db", str(junk))
    assert '"validate"' in dot, "a bad project should degrade to no overlay"


def test_a_kickoff_placeholder_does_not_erase_a_plt_name(shared_object, tmp_path):
    """`kickoff` imports the whole discovered function set into `function_names`,
    unnamed addresses included, so an ordinary project holds a `sub_<hex>` row
    for every PLT stub.

    Treating those as analyst decisions made the overlay ERASE information: an
    edge that read `validate@plt` without `--db` printed `sub_1050` with it.
    A placeholder is not a name and must not outrank a real one.
    """
    from glaurung.llm.kb import xref_db

    db = tmp_path / "p.glaurung"
    kb = PersistentKnowledgeBase.open(str(db), binary_path=str(shared_object))
    # Exactly what kickoff records for an address discovery found no name for.
    for stub_va in range(0x1020, 0x1060, 0x10):
        xref_db.set_function_name(kb, stub_va, f"sub_{stub_va:x}", set_by="auto")
    kb.close()

    with_db = graph(shared_object, "--db", str(db))
    assert "validate@plt" in with_db, with_db
    assert '"sub_1050"' not in with_db, with_db
    # And it must not have made things worse than no project at all.
    assert "validate@plt" in graph(shared_object)
