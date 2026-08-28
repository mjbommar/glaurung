"""The project file's function names must reach `glaurung decompile`.

Before this, the knowledge base was write-only with respect to the primary
decompile command: an analyst could rename a function in the `.glaurung`
project and the decompiler would keep printing the old name, because
`decompile` never opened the project at all. `view` and `repl` papered over it
with a regex substitution on the rendered text, which cannot follow a call
through a PLT stub and will happily rewrite a matching substring inside a
string literal.

These tests pin the three properties the real fix has to have, each of which
was broken at some point while building it:

1. the rename reaches the function's own header;
2. it reaches every CALL SITE, including calls through a PLT stub, whose
   address is not the address the analyst renamed;
3. it changes NOTHING ELSE -- in particular the callee's recovered prototype
   and arity survive, which they did not in the first working version.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
SOURCE = ROOT / "tests" / "fixtures" / "analyst_rename" / "analyst_rename.c"


def _decompile(binary: Path, func: str, db: str | None) -> str:
    argv = [
        "glaurung",
        "decompile",
        str(binary),
        "--func",
        func,
        "--style",
        "decbench",
        "--no-color",
        # An empty cache directory disables the on-disk decompile cache, so a
        # stale entry cannot make either arm of the comparison pass.
        "--cache-dir",
        "",
    ]
    if db is not None:
        argv += ["--db", db]
    result = subprocess.run(
        argv, capture_output=True, text=True, timeout=300, check=True
    )
    return result.stdout


@pytest.fixture(scope="module")
def binary(tmp_path_factory: pytest.TempPathFactory) -> Path:
    sys.path.insert(0, str(ROOT / "tools"))
    import fixture_toolchain as TC

    out = tmp_path_factory.mktemp("analyst-rename") / "analyst-rename-gcc-O1.so"
    compiled = TC.run(
        ["gcc", "-shared", "-fPIC", "-g", "-O1", "-o", str(out), str(SOURCE)],
        timeout=60,
    )
    assert compiled.returncode == 0, compiled.stderr
    return out


@pytest.fixture(scope="module")
def entry_vas(binary: Path) -> dict[str, int]:
    """Entry addresses straight from the dynamic symbol table."""
    result = subprocess.run(
        ["nm", "-D", "--defined-only", str(binary)],
        capture_output=True,
        text=True,
        timeout=60,
        check=True,
    )
    out: dict[str, int] = {}
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[2] in {"validate", "driver"}:
            out[parts[2]] = int(parts[0], 16)
    assert {"validate", "driver"} <= out.keys(), result.stdout
    return out


@pytest.fixture(scope="module")
def project(binary: Path, entry_vas: dict[str, int], tmp_path_factory) -> str:
    """A project file in which `validate` has been renamed by hand."""
    from glaurung.llm.kb import xref_db
    from glaurung.llm.kb.persistent import PersistentKnowledgeBase

    path = tmp_path_factory.mktemp("analyst-rename-db") / "p.glaurung"
    kb = PersistentKnowledgeBase.open(str(path), binary_path=str(binary))
    xref_db.set_function_name(
        kb, entry_vas["validate"], "parse_packet_hdr", set_by="manual"
    )
    kb.close()
    return str(path)


def test_without_a_project_the_binarys_own_name_is_used(binary: Path) -> None:
    """The no-`--db` path must be untouched by any of this."""
    text = _decompile(binary, "validate", None)
    assert re.search(r"\bvalidate\b", text), text
    assert "parse_packet_hdr" not in text


def test_a_rename_reaches_the_functions_own_header(binary: Path, project: str) -> None:
    text = _decompile(binary, "validate", project)
    assert re.search(r"^int parse_packet_hdr\(", text, re.M), text


def test_a_rename_reaches_a_call_site_through_a_plt_stub(
    binary: Path, project: str
) -> None:
    """The call targets the stub, not the renamed address.

    This is the half that a rename keyed only on the analyst's own address
    silently misses, leaving `driver` calling `validate` while `validate`
    displays as `parse_packet_hdr`.
    """
    text = _decompile(binary, "driver", project)
    assert "parse_packet_hdr(" in text, text
    assert not re.search(r"\bvalidate\b", text), (
        "a call site still shows the pre-rename name:\n" + text
    )


@pytest.mark.parametrize("func", ["validate", "driver"])
def test_a_rename_changes_nothing_but_the_name(
    binary: Path, project: str, func: str
) -> None:
    """The regression that shipped in the first working version.

    Applying the overlay before callee analysis made that analysis resolve a
    name no symbol source knows, so it found nothing and downgraded
    `int validate(char *, int)` to `long f(void)` -- the call site kept the new
    name and LOST ITS ARGUMENTS. Substituting the old name back into the
    renamed output must reproduce the un-renamed output exactly.
    """
    plain = _decompile(binary, func, None)
    renamed = _decompile(binary, func, project)
    assert renamed != plain, "the rename must actually do something"
    assert renamed.replace("parse_packet_hdr", "validate") == plain, (
        "the rename changed something other than the name\n"
        f"--- without --db ---\n{plain}\n--- with --db ---\n{renamed}"
    )


def test_the_callees_recovered_prototype_survives_the_rename(
    binary: Path, project: str
) -> None:
    """Stated directly, so a failure names the defect rather than a diff."""
    text = _decompile(binary, "driver", project)
    assert re.search(r"extern int parse_packet_hdr\(char \*, int\);", text), (
        "the callee's recovered prototype did not follow the rename:\n" + text
    )
    assert "(void))parse_packet_hdr)()" not in text, (
        "the call site lost its arguments:\n" + text
    )


def test_the_decompile_cache_is_invalidated_by_a_rename(
    binary: Path, project: str, tmp_path: Path
) -> None:
    """A cache blind to the project would serve the pre-rename text forever."""
    cache = tmp_path / "cache"
    base = [
        "glaurung",
        "decompile",
        str(binary),
        "--func",
        "validate",
        "--style",
        "decbench",
        "--no-color",
        "--cache-dir",
        str(cache),
    ]
    first = subprocess.run(
        base, capture_output=True, text=True, timeout=300, check=True
    )
    assert re.search(r"\bvalidate\b", first.stdout), first.stdout
    second = subprocess.run(
        base + ["--db", project],
        capture_output=True,
        text=True,
        timeout=300,
        check=True,
    )
    assert "parse_packet_hdr" in second.stdout, (
        "the cached pre-rename entry was served for a run with --db:\n" + second.stdout
    )


def test_an_absent_or_unreadable_project_is_not_fatal(
    binary: Path, tmp_path: Path
) -> None:
    """`--db` pointing at nothing must decompile, not crash.

    A project file is analyst state; a decompile is not allowed to depend on it
    being present and well-formed.
    """
    missing = tmp_path / "does-not-exist.glaurung"
    assert re.search(r"\bvalidate\b", _decompile(binary, "validate", str(missing)))

    junk = tmp_path / "junk.glaurung"
    junk.write_bytes(b"this is not a sqlite database")
    assert re.search(r"\bvalidate\b", _decompile(binary, "validate", str(junk)))


def test_json_output_carries_the_renamed_function(binary: Path, project: str) -> None:
    """The scriptable surface must agree with the human one."""
    result = subprocess.run(
        [
            "glaurung",
            "decompile",
            str(binary),
            "--format",
            "json",
            "--func",
            "validate",
            "--style",
            "decbench",
            "--cache-dir",
            "",
            "--db",
            project,
        ],
        capture_output=True,
        text=True,
        timeout=300,
        check=True,
    )
    payload = json.loads(result.stdout)
    assert "parse_packet_hdr" in payload["pseudocode"], payload
