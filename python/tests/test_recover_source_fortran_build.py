"""End-to-end build gate for the gfortran-recovered tree (Bug Y).

After Bugs P-W closed, the Fortran-recovered tree at
``out/hello-fortran-recovered`` compiles + links cleanly under
``gcc -O2 -Wall -Werror`` plus ``-lgfortran``. The build-clean
state is the regression watchdog: if a future rewriter change
re-introduces an undeclared extern, a missing struct body, an
unrecovered LOCAL static, or a name-mangling drop, this test fails
loudly.

The test is skipped automatically when the toolchain isn't
available (no gcc, no libgfortran). On CI we expect the harness
to install both via apt.
"""

from pathlib import Path
import shutil
import subprocess
import tempfile

import pytest

_REPO = Path(__file__).resolve().parents[2]
_RECOVERED = _REPO / "out/hello-fortran-recovered"


def _find_gcc_with_libgfortran() -> str | None:
    """Return the name of a gcc whose matching libgfortran is
    installed, or None if no toolchain is reachable.

    Tries `gcc` first, then versioned fallbacks. `gcc -print-file-
    name=libgfortran.so` returns the literal string when the
    library is missing, so we resolve and existence-check."""
    candidates = ["gcc", "gcc-13", "gcc-12", "gcc-14"]
    for cc in candidates:
        if shutil.which(cc) is None:
            continue
        try:
            result = subprocess.run(
                [cc, "-print-file-name=libgfortran.so"],
                capture_output=True, text=True, check=True,
            )
        except (subprocess.CalledProcessError, FileNotFoundError):
            continue
        path = result.stdout.strip()
        if path != "libgfortran.so" and Path(path).exists():
            return cc
    return None


@pytest.mark.skipif(not _RECOVERED.exists(), reason="recovered tree missing")
def test_recovered_fortran_tree_builds_and_links():
    """Run the canonical CMake build of the recovered tree. The
    test passes iff cmake succeeds in producing the executable —
    we don't run it (Bug X documents the runtime fidelity gap)."""
    cc = _find_gcc_with_libgfortran()
    if cc is None:
        pytest.skip("no gcc has libgfortran installed (apt install libgfortran-13-dev)")
    with tempfile.TemporaryDirectory(prefix="glaurung-recov-build-") as tmp:
        tmp_path = Path(tmp)

        # Pass the discovered gcc explicitly so cmake doesn't
        # fall back to a version whose libgfortran is missing.
        configure = subprocess.run(
            ["cmake", str(_RECOVERED)],
            cwd=tmp_path,
            capture_output=True, text=True,
            env={**__import__("os").environ, "CC": cc},
        )
        assert configure.returncode == 0, (
            f"cmake configure failed:\n"
            f"stdout={configure.stdout}\n"
            f"stderr={configure.stderr}"
        )

        build = subprocess.run(
            ["cmake", "--build", "."],
            cwd=tmp_path,
            capture_output=True, text=True,
        )
        assert build.returncode == 0, (
            f"cmake build failed — Bug L regression. The "
            f"recovered Fortran tree no longer compiles + links. "
            f"Check the most recent rewriter change.\n"
            f"stdout={build.stdout}\nstderr={build.stderr}"
        )

        # Sanity: the executable exists and is non-empty.
        exe = tmp_path / "hello_gfortran_O2"
        assert exe.exists() and exe.stat().st_size > 0, (
            f"build claimed success but produced no executable at "
            f"{exe}"
        )


@pytest.mark.skipif(not _RECOVERED.exists(), reason="recovered tree missing")
def test_recovered_fortran_tree_makefile_compiles_main():
    """Sanity check on the fallback Makefile: at minimum, the
    standalone main.c must compile clean (no link). Catches the
    extern-prototype regression class without needing libgfortran."""
    if shutil.which("gcc") is None:
        pytest.skip("gcc not available")
    with tempfile.TemporaryDirectory(prefix="glaurung-recov-make-") as tmp:
        result = subprocess.run(
            ["gcc", "-O2", "-Wall", "-Werror", "-c",
             str(_RECOVERED / "main.c"), "-o", f"{tmp}/main.o"],
            capture_output=True, text=True,
        )
        assert result.returncode == 0, (
            f"main.c failed to compile under -Wall -Werror:\n"
            f"stderr={result.stderr}"
        )
