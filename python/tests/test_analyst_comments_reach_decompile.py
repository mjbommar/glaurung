"""An analyst's comments must appear on the function they are about.

Annotating is one of the two things nearly every professional reverse engineer
does (14 of 16 in Votipka et al., USENIX Security 2020, alongside renaming).
Comments lived in the project and reached no output at all: `decompile` did not
open the project, and the `view`/`repl` post-processor did not render them
either.

TWO KINDS, DELIBERATELY. A comment attached to the FUNCTION renders above the
signature, where nothing can orphan it. Comments at other addresses are LISTED
with their addresses rather than guessed onto lines, because placing them needs
an instruction-to-line map the AST cannot supply yet (`lower_block` drops
`ins.va`), and a plausible wrong placement reads as fact -- it silently
mis-attributes the analyst's note to unrelated code.

That split is not an invention. Hex-Rays says of its position-anchored
pseudocode comments that they "can move around or even end up as orphan
comments when the pseudocode changes", and ships a `Delete orphan comments`
action for the consequences; its function comments have no such problem.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from glaurung.llm.kb.persistent import PersistentKnowledgeBase

ROOT = Path(__file__).resolve().parent.parent.parent
SOURCE = ROOT / "tests" / "fixtures" / "analyst_rename" / "analyst_locals.c"


@pytest.fixture(scope="module")
def binary(tmp_path_factory) -> Path:
    sys.path.insert(0, str(ROOT / "tools"))
    import fixture_toolchain as TC

    out = tmp_path_factory.mktemp("analyst-comments") / "comments-gcc-O0.so"
    compiled = TC.run(
        ["gcc", "-shared", "-fPIC", "-O0", "-o", str(out), str(SOURCE)], timeout=60
    )
    assert compiled.returncode == 0, compiled.stderr
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


def decompile(binary: Path, db: str | None, cache: str = "") -> str:
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
        cache,
    ]
    if db:
        argv += ["--db", db]
    return subprocess.run(
        argv, capture_output=True, text=True, timeout=300, check=True
    ).stdout


def project(tmp_path: Path, binary: Path, comments) -> str:
    from glaurung.llm.kb import xref_db

    tmp_path.mkdir(parents=True, exist_ok=True)
    db = tmp_path / "p.glaurung"
    kb = PersistentKnowledgeBase.open(str(db), binary_path=str(binary))
    for va, body in comments:
        xref_db.set_comment(kb, va, body, set_by="manual")
    kb.close()
    return str(db)


def test_a_function_comment_renders_above_the_signature(binary, scan_va, tmp_path):
    db = project(tmp_path, binary, [(scan_va, "Sums the first n bytes.")])
    text = decompile(binary, db)
    lines = text.splitlines()
    comment_at = next(i for i, l in enumerate(lines) if "Sums the first n bytes." in l)
    signature_at = next(i for i, l in enumerate(lines) if l.startswith("int scan("))
    assert comment_at < signature_at, text


def test_the_tool_banner_stays_the_first_line(binary, scan_va, tmp_path):
    """`tools/roundtrip3.py` anchors on `^// glaurung: <name> @ <va>`."""
    db = project(tmp_path, binary, [(scan_va, "a note")])
    assert decompile(binary, db).splitlines()[0].startswith("// glaurung:"), decompile(
        binary, db
    )


def test_the_comment_is_emitted_as_c_comments(binary, scan_va, tmp_path):
    """The decbench style exists to be parsed as C; a bare note would break it."""
    db = project(tmp_path, binary, [(scan_va, "line one\nline two")])
    text = decompile(binary, db)
    body_start = text.index("int scan(")
    for line in text[:body_start].splitlines():
        assert line == "" or line.startswith("//"), (line, text)
    assert "// line one" in text and "// line two" in text, text


def test_an_interior_comment_is_listed_with_its_address(binary, scan_va, tmp_path):
    """Listed, not placed. A guessed line would read as fact."""
    db = project(tmp_path, binary, [(scan_va + 0x20, "the bounds check happens here")])
    text = decompile(binary, db)
    assert "analyst notes at addresses inside this function" in text, text
    assert f"0x{scan_va + 0x20:x}: the bounds check happens here" in text, text


def test_a_comment_outside_the_function_is_not_shown(binary, scan_va, tmp_path):
    """A neighbour's notes must not be attributed to this function."""
    db = project(tmp_path, binary, [(scan_va + 0x9000, "belongs to something else")])
    assert "belongs to something else" not in decompile(binary, db)


def test_without_a_project_no_comment_block_appears(binary, scan_va, tmp_path):
    plain = decompile(binary, None)
    assert "analyst notes" not in plain
    db = project(tmp_path, binary, [(scan_va, "a note")])
    assert decompile(binary, db) != plain


def test_an_edited_comment_shows_through_a_warm_cache(binary, scan_va, tmp_path):
    """The block is applied after the cached artifact, so a comment edit must
    show even when the decompile itself is served from cache."""
    cache = str(tmp_path / "cache")
    db = project(tmp_path, binary, [(scan_va, "first version")])
    assert "first version" in decompile(binary, db, cache=cache)
    db2 = project(tmp_path / "second", binary, [(scan_va, "second version")])
    text = decompile(binary, db2, cache=cache)
    assert "second version" in text, text
    assert "first version" not in text, text


def test_an_unreadable_project_does_not_kill_the_decompile(binary, tmp_path):
    junk = tmp_path / "junk.glaurung"
    junk.write_bytes(b"this is not a sqlite database")
    assert "int scan(" in decompile(binary, str(junk))
