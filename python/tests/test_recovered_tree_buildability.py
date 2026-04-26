"""Project-wide build-gate for every recovered-source tree under
``out/`` (Bug Z).

Bug Y wired up an end-to-end build gate for the gfortran-recovered
tree. The same regression class — extern prototypes, struct
bodies, mangled-name preservation, LOCAL statics — can affect any
language the rewriter targets. This test parametrises across
every recovered tree found under ``out/`` and records the build
status so:

  * Trees that currently build pass and stay green.
  * Trees that currently fail are marked ``xfail`` with the
    surfaced error class. Any future rewriter change that fixes
    them flips ``xfail`` → ``XPASS`` and the test fails loudly,
    forcing the developer to remove the ``xfail`` marker.
  * Any tree that goes from green → red (a regression) fails the
    suite immediately.

This is the test version of "the audit gates the orchestrator's
verify step" — it's deterministic, doesn't need an LLM, and runs
in seconds.
"""

from __future__ import annotations

from pathlib import Path
import os
import shutil
import subprocess
import tempfile

import pytest

_REPO = Path(__file__).resolve().parents[2]
_OUT = _REPO / "out"


def _find_gcc_with_libgfortran() -> str | None:
    """Same probe as test_recover_source_fortran_build.py."""
    for cc in ("gcc", "gcc-13", "gcc-12", "gcc-14"):
        if shutil.which(cc) is None:
            continue
        try:
            res = subprocess.run(
                [cc, "-print-file-name=libgfortran.so"],
                capture_output=True, text=True, check=True,
            )
        except (subprocess.CalledProcessError, FileNotFoundError):
            continue
        if res.stdout.strip() != "libgfortran.so" and Path(res.stdout.strip()).exists():
            return cc
    return None


def _list_recovered_trees() -> list[Path]:
    """Every immediate subdir of ``out/`` that has a CMakeLists.txt
    and at least one .c / .cpp source file."""
    if not _OUT.exists():
        return []
    out: list[Path] = []
    for child in sorted(_OUT.iterdir()):
        if not child.is_dir():
            continue
        if not (child / "CMakeLists.txt").exists():
            continue
        has_source = any(child.rglob("*.c")) or any(child.rglob("*.cpp"))
        if has_source:
            out.append(child)
    return out


# Trees that currently fail to build, with a one-line reason.
# Removing an entry here = asserting the tree now builds — and the
# corresponding test will fail loudly if it actually still doesn't.
# Adding an entry = a new regression we're acknowledging while
# someone else gets paged.
_KNOWN_BROKEN: dict[str, str] = {
    "hello-recovered":
        "iostream_support.c emits raw C++ syntax (std::ostream, "
        "std::ctype<char>, etc.) without including <iostream> — "
        "the rewriter wrote a 'recovered std::endl' as plain C++ "
        "tokens, which won't parse without the standard headers. "
        "(Bug AA closed std__vector_string cross-TU; the iostream "
        "implementation gap is a separate v2 problem.)",
    # hello-recovered-v2: closed by Bugs BB + DD (extern "C"
    # bridging + main/strings/vector-dtor stubs). Tree builds,
    # links, and runs.
    # hello-recovered-v3: closed by Bugs CC + DD (extern "C"
    # bridging for libstdc++ exception-handling symbols). Tree
    # builds, links, and runs to completion — entry removed so
    # any future rewriter regression that breaks the build fails
    # the suite immediately.
}


@pytest.mark.parametrize(
    "tree",
    _list_recovered_trees(),
    ids=lambda p: p.name,
)
def test_recovered_tree_builds(tree: Path):
    """For each recovered tree under out/, run cmake + cmake build
    and assert success.  Trees in _KNOWN_BROKEN are ``xfail``."""
    cc = _find_gcc_with_libgfortran() or shutil.which("gcc") or shutil.which("g++")
    if cc is None:
        pytest.skip("no C / C++ compiler available")

    if tree.name in _KNOWN_BROKEN:
        pytest.xfail(_KNOWN_BROKEN[tree.name])

    with tempfile.TemporaryDirectory(prefix=f"glaurung-build-{tree.name}-") as tmp:
        tmp_path = Path(tmp)
        env = {**os.environ, "CC": cc}

        configure = subprocess.run(
            ["cmake", str(tree)],
            cwd=tmp_path, capture_output=True, text=True, env=env,
        )
        assert configure.returncode == 0, (
            f"cmake configure failed for {tree.name}:\n"
            f"stdout={configure.stdout}\nstderr={configure.stderr}"
        )

        build = subprocess.run(
            ["cmake", "--build", "."],
            cwd=tmp_path, capture_output=True, text=True,
        )
        assert build.returncode == 0, (
            f"cmake build failed for {tree.name} — recovered-tree "
            f"regression. Most recent rewriter / orchestrator "
            f"change is the suspect.\n"
            f"stderr={build.stderr}"
        )


def test_known_broken_set_does_not_drift():
    """Ensure _KNOWN_BROKEN doesn't list trees that don't exist —
    a stale entry would silently mask a missing build-gate."""
    existing = {t.name for t in _list_recovered_trees()}
    stale = set(_KNOWN_BROKEN) - existing
    assert not stale, (
        f"_KNOWN_BROKEN lists trees that no longer exist under out/: "
        f"{stale}. Either restore the trees or remove the entries."
    )


def test_recovered_trees_under_out_are_discoverable():
    """Sanity: at least one recovered tree exists. Catches the
    accidental ``rm -rf out/`` regression."""
    trees = _list_recovered_trees()
    assert trees, (
        "no recovered-source trees found under out/; the parametrised "
        "build-gate above will degrade to zero coverage."
    )
