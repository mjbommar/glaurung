"""An analyst's prototype must change the recovered signature, not just be filed.

`glaurung proto` recorded a signature into `function_prototypes` and nothing
read it: the decompiler kept printing whatever it had recovered, and the only
visible effect was a `// proto:` comment appended by the `view`/`repl` regex
post-processor. Hex-Rays calls the prototype "the highest-leverage single edit,
because it propagates to every call site"; ours propagated nowhere.

It now rides the slot DWARF already uses. `declared_prototype` overrides the
recovered prototype for rendering and drives both the return type and the
parameter c_types (`ast::declaration_plan`), so there is no second mechanism and
the two cannot disagree. The analyst outranks DWARF, for the same reason their
rename outranks the symbol table.

THE ARITY RULE. The renderer applies a declared prototype only when its
parameter COUNT matches the recovered arity, and drops the WHOLE declaration --
return type included -- otherwise. That gate is pre-existing and protects DWARF
identically; it is why a wrong prototype cannot corrupt output. These tests pin
both halves, because "safe" and "silently does nothing" are different promises
and the analyst needs to know which one they got.
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
def binary(tmp_path_factory) -> Path:
    """Stripped, so the recovered signature is the decompiler's own work."""
    sys.path.insert(0, str(ROOT / "tools"))
    import fixture_toolchain as TC

    out = tmp_path_factory.mktemp("analyst-proto") / "proto-gcc-O1.so"
    compiled = TC.run(
        ["gcc", "-shared", "-fPIC", "-O1", "-o", str(out), str(SOURCE)], timeout=60
    )
    assert compiled.returncode == 0, compiled.stderr
    stripped = TC.run(["strip", "--strip-debug", str(out)], timeout=60)
    assert stripped.returncode == 0, stripped.stderr
    return out


def decompile(binary: Path, db: str | None) -> str:
    argv = [
        "glaurung",
        "decompile",
        str(binary),
        "--func",
        "validate",
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


def signature(text: str) -> str:
    match = re.search(r"^\w[\w \*]*\bvalidate\([^)]*\)", text, re.M)
    assert match, text
    return match.group(0)


def project(
    tmp_path: Path, binary: Path, ret: str, params: list[tuple[str, str]]
) -> str:
    tmp_path.mkdir(parents=True, exist_ok=True)
    db = tmp_path / "p.glaurung"
    kb = PersistentKnowledgeBase.open(str(db), binary_path=str(binary))
    xref_db.set_function_prototype(
        kb,
        "validate",
        ret,
        [xref_db.FunctionParam(name=n, c_type=t) for n, t in params],
        set_by="manual",
    )
    kb.close()
    return str(db)


@pytest.fixture(scope="module")
def recovered_arity(binary: Path) -> int:
    inner = signature(decompile(binary, None)).split("(", 1)[1].rstrip(")").strip()
    return 0 if inner in ("", "void") else inner.count(",") + 1


def test_the_prototype_changes_the_rendered_signature(
    binary, recovered_arity, tmp_path
):
    plain = signature(decompile(binary, None))
    db = project(
        tmp_path,
        binary,
        "unsigned int",
        [(f"p{i}", "short") for i in range(recovered_arity)],
    )
    changed = signature(decompile(binary, db))
    assert changed != plain, "the prototype did nothing"
    assert changed.startswith("unsigned int validate("), changed
    assert changed.count("short") == recovered_arity, changed


def test_the_return_type_alone_can_be_declared(binary, recovered_arity, tmp_path):
    db = project(
        tmp_path,
        binary,
        "unsigned long",
        [(f"p{i}", "int") for i in range(recovered_arity)],
    )
    assert signature(decompile(binary, db)).startswith("unsigned long validate(")


@pytest.mark.parametrize("delta", [-1, 1])
def test_a_wrong_arity_is_ignored_entirely(binary, recovered_arity, tmp_path, delta):
    """Both halves of the rule: nothing is applied, INCLUDING the return type.

    A partially-applied prototype would be the dangerous outcome -- a signature
    the analyst did not write, over a body that does not match it.
    """
    count = recovered_arity + delta
    if count < 0:
        pytest.skip("no such arity")
    plain = decompile(binary, None)
    db = project(
        tmp_path / f"d{delta}",
        binary,
        "unsigned long",
        [(f"p{i}", "short") for i in range(count)],
    )
    text = decompile(binary, db)
    assert signature(text) == signature(plain), (
        f"a {count}-parameter prototype was partially applied to a "
        f"{recovered_arity}-parameter function:\n{text}"
    )
    assert "unsigned long validate" not in text, (
        "the return type was applied without the parameters:\n" + text
    )


def test_an_unspecified_parameter_type_becomes_void_star(
    binary, recovered_arity, tmp_path
):
    """A SHARP EDGE, pinned rather than fixed.

    `set_function_prototype` normalises an empty `c_type` to `void *` on write,
    so "I did not say what this parameter is" is stored as "it is a void
    pointer". By the time any reader sees the row the distinction is gone, and
    the overlay then replaces a recovered `char *` with `void *` -- strictly
    less information than the decompiler had on its own.

    This is pre-existing KB behaviour shared with the stdlib prototype bundle
    and every other prototype consumer, so it is not changed here. The loader
    still refuses a genuinely empty type defensively; that guard simply cannot
    fire through this path. Recorded so the next person meets it as a
    documented decision rather than a surprise.
    """
    db = project(
        tmp_path,
        binary,
        "int",
        [("p0", "")] + [(f"p{i}", "int") for i in range(1, recovered_arity)],
    )
    assert "void * arg0" in signature(decompile(binary, db))


def test_without_a_project_nothing_changes(binary):
    assert "validate(" in decompile(binary, None)


def test_the_cache_is_invalidated_by_a_prototype_edit(
    binary, recovered_arity, tmp_path
):
    cache = str(tmp_path / "cache")
    argv = [
        "glaurung",
        "decompile",
        str(binary),
        "--func",
        "validate",
        "--style",
        "decbench",
        "--no-color",
        "--cache-dir",
        cache,
    ]
    first = subprocess.run(
        argv, capture_output=True, text=True, timeout=300, check=True
    )
    assert "unsigned int validate" not in first.stdout
    db = project(
        tmp_path / "p2",
        binary,
        "unsigned int",
        [(f"p{i}", "short") for i in range(recovered_arity)],
    )
    second = subprocess.run(
        argv + ["--db", db], capture_output=True, text=True, timeout=300, check=True
    )
    assert "unsigned int validate" in second.stdout, (
        "a cached entry was served for a run with a prototype overlay:\n"
        + second.stdout
    )


def test_proto_check_arity_reports_a_mismatch(binary, recovered_arity, tmp_path):
    """The rule is conservative; it must not also be silent."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    db = tmp_path / "p.glaurung"
    PersistentKnowledgeBase.open(str(db), binary_path=str(binary)).close()
    result = subprocess.run(
        [
            "glaurung",
            "proto",
            str(db),
            "validate",
            "int",
            *[f"p{i}:int" for i in range(recovered_arity + 1)],
            "--binary",
            str(binary),
            "--check-arity",
        ],
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "will be ignored" in result.stdout, result.stdout


def test_proto_check_arity_is_quiet_when_it_matches(binary, recovered_arity, tmp_path):
    tmp_path.mkdir(parents=True, exist_ok=True)
    db = tmp_path / "p.glaurung"
    PersistentKnowledgeBase.open(str(db), binary_path=str(binary)).close()
    result = subprocess.run(
        [
            "glaurung",
            "proto",
            str(db),
            "validate",
            "int",
            *[f"p{i}:int" for i in range(recovered_arity)],
            "--binary",
            str(binary),
            "--check-arity",
        ],
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert result.returncode == 0
    assert "will be ignored" not in result.stdout, result.stdout


def test_check_arity_works_on_a_renamed_function(binary, recovered_arity, tmp_path):
    """The case that silently failed, found by running the documented workflow.

    Prototypes are keyed by NAME, and the name an analyst types is the one they
    just chose -- which the binary does not know. Resolving the function against
    the binary alone made `--check-arity` raise, get swallowed, and print
    nothing: no warning on a mismatch, i.e. exactly when it was wanted. It now
    resolves through the project first.
    """
    tmp_path.mkdir(parents=True, exist_ok=True)
    db = tmp_path / "p.glaurung"
    kb = PersistentKnowledgeBase.open(str(db), binary_path=str(binary))
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
    xref_db.set_function_name(kb, va, "parse_packet_hdr", set_by="manual")
    kb.close()

    def run_proto(count: int):
        return subprocess.run(
            [
                "glaurung",
                "proto",
                str(db),
                "parse_packet_hdr",
                "int",
                *[f"p{i}:int" for i in range(count)],
                "--binary",
                str(binary),
                "--check-arity",
            ],
            capture_output=True,
            text=True,
            timeout=300,
        )

    wrong = run_proto(recovered_arity + 1)
    assert wrong.returncode == 0, wrong.stdout + wrong.stderr
    assert "will be ignored" in wrong.stdout, (
        "no warning for a renamed function -- the check resolved against the "
        "binary, which does not know the new name:\n" + wrong.stdout
    )

    right = run_proto(recovered_arity)
    assert right.returncode == 0
    assert "will be ignored" not in right.stdout, right.stdout


def test_check_arity_reports_an_unknown_function(binary, tmp_path):
    """Silence would read as "your prototype is fine"."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    db = tmp_path / "p.glaurung"
    PersistentKnowledgeBase.open(str(db), binary_path=str(binary)).close()
    result = subprocess.run(
        [
            "glaurung",
            "proto",
            str(db),
            "no_such_function",
            "int",
            "--binary",
            str(binary),
            "--check-arity",
        ],
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "arity unchecked" in result.stdout, result.stdout
