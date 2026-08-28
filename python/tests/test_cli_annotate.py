"""The non-interactive analyst write surface.

Before these commands existed, `rename`, `comment`, `label` and `proto` lived
only inside the interactive REPL. Nothing outside it could annotate a project,
so an analyst workflow could not be scripted, replayed, or driven by an agent —
the writable non-REPL surfaces were `frame`, `bookmark`, `journal`, `undo` and
`redo`, which is the wrong half to expose.

These tests drive the shipped commands as a user would, through `subprocess`,
because the value of the change is precisely that they work from a shell.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from glaurung.llm.kb import xref_db
from glaurung.llm.kb.persistent import PersistentKnowledgeBase

VA = 0x1030


def run(*argv: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["glaurung", *argv], capture_output=True, text=True, timeout=120
    )


@pytest.fixture
def project(tmp_path: Path) -> str:
    binary = tmp_path / "bin"
    binary.write_bytes(b"\x7fELF" + b"\x00" * 128)
    db = tmp_path / "p.glaurung"
    PersistentKnowledgeBase.open(str(db), binary_path=str(binary)).close()
    return str(db)


def reopen(project: str) -> PersistentKnowledgeBase:
    return PersistentKnowledgeBase.open(project)


# --------------------------------------------------------------------------
# rename
# --------------------------------------------------------------------------


def test_rename_by_address(project):
    result = run("rename", project, hex(VA), "parse_packet_hdr")
    assert result.returncode == 0, result.stderr + result.stdout
    kb = reopen(project)
    try:
        row = next(r for r in xref_db.list_function_names(kb) if r.entry_va == VA)
    finally:
        kb.close()
    assert row.canonical == "parse_packet_hdr"
    assert row.set_by == "manual"


def test_rename_by_current_name(project):
    """Without this the analyst must look an address up first, which is exactly
    the friction that keeps people in a GUI."""
    assert run("rename", project, hex(VA), "first").returncode == 0
    result = run("rename", project, "first", "second")
    assert result.returncode == 0, result.stdout
    kb = reopen(project)
    try:
        row = next(r for r in xref_db.list_function_names(kb) if r.entry_va == VA)
    finally:
        kb.close()
    assert row.canonical == "second"


def test_a_number_is_an_address_not_a_name(project):
    """A function perversely named `0x1030` must not shadow the address."""
    assert run("rename", project, hex(VA), "0x1030").returncode == 0
    assert run("rename", project, hex(VA), "real_name").returncode == 0
    kb = reopen(project)
    try:
        assert len(xref_db.list_function_names(kb)) == 1
    finally:
        kb.close()


def test_an_automatic_source_cannot_overwrite_an_analyst_rename(project):
    """Reported, with a distinct exit code — not silently dropped."""
    assert run("rename", project, hex(VA), "analyst_chose").returncode == 0
    result = run("rename", project, hex(VA), "robot_chose", "--by", "auto")
    assert result.returncode == 5, result.stdout
    assert "refused" in result.stdout
    kb = reopen(project)
    try:
        row = next(r for r in xref_db.list_function_names(kb) if r.entry_va == VA)
    finally:
        kb.close()
    assert row.canonical == "analyst_chose"


def test_renaming_an_unknown_name_is_an_error_not_a_new_function(project):
    result = run("rename", project, "no_such_function", "x")
    assert result.returncode == 4, result.stdout
    kb = reopen(project)
    try:
        assert xref_db.list_function_names(kb) == []
    finally:
        kb.close()


def test_a_blank_name_is_refused(project):
    """A blank canonical name would erase a good automatic one."""
    assert run("rename", project, hex(VA), "   ").returncode == 2


def test_a_missing_project_is_reported_not_created(project, tmp_path):
    missing = tmp_path / "nope.glaurung"
    result = run("rename", str(missing), hex(VA), "x")
    assert result.returncode == 2
    assert not missing.exists(), "a typo'd path must not silently create a project"


# --------------------------------------------------------------------------
# comment
# --------------------------------------------------------------------------


def test_comment_set_show_and_clear(project):
    assert (
        run(
            "comment", project, hex(VA), "bounds-checks", "before", "indexing"
        ).returncode
        == 0
    )
    shown = run("comment", project, hex(VA))
    assert "bounds-checks before indexing" in shown.stdout
    assert run("comment", project, hex(VA), "--delete").returncode == 0
    kb = reopen(project)
    try:
        assert not xref_db.get_comment(kb, VA)
    finally:
        kb.close()


def test_comment_accepts_a_function_name(project):
    assert run("rename", project, hex(VA), "validate").returncode == 0
    assert run("comment", project, "validate", "hello").returncode == 0
    kb = reopen(project)
    try:
        assert xref_db.get_comment(kb, VA) == "hello"
    finally:
        kb.close()


def test_showing_an_absent_comment_is_not_an_error(project):
    result = run("comment", project, hex(VA))
    assert result.returncode == 0
    assert "no comment" in result.stdout


# --------------------------------------------------------------------------
# label
# --------------------------------------------------------------------------


def test_label_set_show_and_delete(project):
    assert (
        run(
            "label", project, "0x4000", "g_table", "--type", "int[16]", "--size", "64"
        ).returncode
        == 0
    )
    shown = run("label", project, "0x4000")
    assert "g_table" in shown.stdout and "int[16]" in shown.stdout
    assert run("label", project, "0x4000", "--delete").returncode == 0
    kb = reopen(project)
    try:
        assert xref_db.get_data_label(kb, 0x4000) is None
    finally:
        kb.close()


def test_deleting_a_label_is_undoable(project):
    """Deletion used to be the one analyst write with no undo entry, so
    `label remove` destroyed a manual name with `undo` unable to see it."""
    assert (
        run("label", project, "0x4000", "g_table", "--type", "int[16]").returncode == 0
    )
    assert run("label", project, "0x4000", "--delete").returncode == 0
    assert run("undo", project).returncode == 0
    kb = reopen(project)
    try:
        restored = xref_db.get_data_label(kb, 0x4000)
    finally:
        kb.close()
    assert restored is not None, "undo did not restore the deleted label"
    assert restored.name == "g_table"
    assert restored.c_type == "int[16]", "undo restored the row without its type"


def test_an_automatic_source_cannot_delete_an_analyst_label(project):
    assert run("label", project, "0x4000", "g_table").returncode == 0
    result = run("label", project, "0x4000", "--delete", "--by", "auto")
    assert result.returncode == 5, result.stdout
    kb = reopen(project)
    try:
        assert xref_db.get_data_label(kb, 0x4000) is not None
    finally:
        kb.close()


def test_deleting_an_absent_label_is_reported(project):
    assert run("label", project, "0x4000", "--delete").returncode == 4


# --------------------------------------------------------------------------
# proto
# --------------------------------------------------------------------------


def test_proto_set_and_show(project):
    result = run("proto", project, "validate", "int", "p:const uint8_t *", "n:int")
    assert result.returncode == 0, result.stdout
    shown = run("proto", project, "validate")
    assert "int validate(const uint8_t * p, int n)" in shown.stdout


def test_proto_rejects_a_malformed_parameter(project):
    """`name:type` is the whole grammar; a silent mis-parse would record a
    prototype the analyst did not write."""
    for bad in ("justaname", ":int", "n:"):
        result = run("proto", project, "validate", "int", bad)
        assert result.returncode == 2, (bad, result.stdout)
    kb = reopen(project)
    try:
        assert xref_db.get_function_prototype(kb, "validate") is None
    finally:
        kb.close()


def test_proto_variadic(project):
    assert (
        run(
            "proto", project, "logf", "int", "fmt:const char *", "--variadic"
        ).returncode
        == 0
    )
    shown = run("proto", project, "logf")
    assert "..." in shown.stdout


def test_showing_an_absent_prototype_is_not_an_error(project):
    result = run("proto", project, "nothing")
    assert result.returncode == 0
    assert "no prototype" in result.stdout


# --------------------------------------------------------------------------
# The loop closed
# --------------------------------------------------------------------------


def test_a_cli_rename_reaches_the_decompiler(tmp_path):
    """The whole point, end to end, with nothing interactive involved.

    Two halves had to land for this to work at all. The project was previously
    unwritable from anywhere but the REPL, and `decompile` was previously blind
    to the project. Either one missing and this test fails, which is why it is
    written as one story rather than two assertions.
    """
    import sys

    root = Path(__file__).resolve().parent.parent.parent
    sys.path.insert(0, str(root / "tools"))
    import fixture_toolchain as TC

    source = root / "tests" / "fixtures" / "analyst_rename" / "analyst_rename.c"
    binary = tmp_path / "annotate-e2e-gcc-O1.so"
    compiled = TC.run(
        ["gcc", "-shared", "-fPIC", "-g", "-O1", "-o", str(binary), str(source)],
        timeout=60,
    )
    assert compiled.returncode == 0, compiled.stderr

    nm = subprocess.run(
        ["nm", "-D", "--defined-only", str(binary)],
        capture_output=True,
        text=True,
        timeout=60,
        check=True,
    )
    vas = {
        parts[2]: int(parts[0], 16)
        for parts in (line.split() for line in nm.stdout.splitlines())
        if len(parts) == 3
    }
    assert "validate" in vas and "driver" in vas, nm.stdout

    db = tmp_path / "p.glaurung"
    PersistentKnowledgeBase.open(str(db), binary_path=str(binary)).close()

    assert (
        run("rename", str(db), hex(vas["validate"]), "parse_packet_hdr").returncode == 0
    )

    result = subprocess.run(
        [
            "glaurung",
            "decompile",
            str(binary),
            "--func",
            hex(vas["driver"]),
            "--style",
            "decbench",
            "--no-color",
            "--cache-dir",
            "",
            "--db",
            str(db),
        ],
        capture_output=True,
        text=True,
        timeout=300,
        check=True,
    )
    assert "parse_packet_hdr(" in result.stdout, result.stdout
    assert "validate" not in result.stdout, (
        "the caller still shows the pre-rename name:\n" + result.stdout
    )


def test_a_renamed_function_is_reachable_by_its_new_name(tmp_path):
    """`--func` resolved names against the binary alone.

    So renaming a function made it unreachable by the name the analyst had
    just chosen: `decompile --func parse_packet_hdr --db p.glaurung` answered
    "no function named 'parse_packet_hdr' in this binary", which is true and
    useless. Found by walking the documented workflow end to end rather than
    by testing a unit.
    """
    import sys

    root = Path(__file__).resolve().parent.parent.parent
    sys.path.insert(0, str(root / "tools"))
    import fixture_toolchain as TC

    source = root / "tests" / "fixtures" / "analyst_rename" / "analyst_rename.c"
    binary = tmp_path / "byname-gcc-O1.so"
    compiled = TC.run(
        ["gcc", "-shared", "-fPIC", "-g", "-O1", "-o", str(binary), str(source)],
        timeout=60,
    )
    assert compiled.returncode == 0, compiled.stderr

    nm = subprocess.run(
        ["nm", "-D", "--defined-only", str(binary)],
        capture_output=True,
        text=True,
        timeout=60,
        check=True,
    )
    va = next(
        int(p[0], 16)
        for p in (line.split() for line in nm.stdout.splitlines())
        if len(p) == 3 and p[2] == "validate"
    )

    db = tmp_path / "p.glaurung"
    PersistentKnowledgeBase.open(str(db), binary_path=str(binary)).close()
    assert run("rename", str(db), hex(va), "parse_packet_hdr").returncode == 0

    result = subprocess.run(
        [
            "glaurung",
            "decompile",
            str(binary),
            "--func",
            "parse_packet_hdr",
            "--style",
            "decbench",
            "--cache-dir",
            "",
            "--db",
            str(db),
        ],
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "parse_packet_hdr" in result.stdout

    # Without the project the new name must still be unknown -- the project is
    # consulted second, so this cannot change no-`--db` behaviour.
    missing = subprocess.run(
        ["glaurung", "decompile", str(binary), "--func", "parse_packet_hdr"],
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert missing.returncode != 0
