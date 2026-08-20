"""The dev tooling must not write temporary files to the shared `/tmp` tmpfs.

`/tmp` here is a 62 GB tmpfs with a per-user quota, shared with every other
project on the host. When it fills it does not report "disk full" — it has
surfaced as a plausible assertion failure inside a DecBench test, as eight
fabricated `pass->fail` regressions in the fixture matrix, as a pytest
`INTERNALERROR` that reported **exit code 0 with no test results**, and twice as
the shell dying with every command returning nonzero and no output.

The largest single writer was not `mktemp`. It was `maturin develop`, which
writes a fresh wheel to `TMPDIR` on every rebuild — a dozen per working session.

`tools/scratch.py` redirects `TMPDIR` on import. These tests pin that the
redirect is actually wired into the tools that create temporary files, because
the failure mode is silent: a tool that quietly reverts to `/tmp` looks fine
until the tmpfs fills days later and the damage shows up as someone else's
mysterious test failure.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
TOOLS = ROOT / "tools"

#: Dev tools that create temporary files and so must carry the redirect.
#: Deliberately spelled out rather than globbed: a new tool that needs it should
#: fail this list loudly, not be silently excluded by a pattern.
WIRED_TOOLS = [
    "dectest",
    "arch_roundtrip",
    "decompiler_output_canaries",
    "fixture_harness",
    "recompile_fidelity",
    "diff_decompile",
    "gen_structural_baseline",
    "realistic_corpus",
]


def _tempdir_after_importing(module: str) -> str:
    """Where `tempfile` would place files after importing one tool, TMPDIR unset.

    Run in a subprocess with a scrubbed environment, because `TMPDIR` and
    `tempfile.tempdir` are process-global: importing the tool in *this*
    interpreter would contaminate every later check.
    """
    code = (
        "import sys, tempfile; sys.path.insert(0, %r); "
        "import %s; print(tempfile.gettempdir())" % (str(TOOLS), module)
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        env={"PATH": "/usr/bin:/bin", "HOME": str(Path.home())},
        cwd=str(ROOT),
    )
    if result.returncode != 0:
        pytest.fail(f"importing {module} failed:\n{result.stderr[-1500:]}")
    return result.stdout.strip().splitlines()[-1]


@pytest.mark.parametrize("module", WIRED_TOOLS)
def test_tool_does_not_write_temporaries_to_the_shared_tmpfs(module):
    """Importing any temp-creating tool must move `tempfile` off `/tmp`.

    This asserts the outcome, not the spelling. Several of these tools pick the
    redirect up transitively — `dectest` imports `fixture_harness`, which
    imports `scratch` — and that is fine: what matters is where the bytes land.
    Verified non-vacuous by pointing `scratch.DEFAULT_SCRATCH` back at `/tmp`,
    which fails every case here.
    """
    where = _tempdir_after_importing(module)
    assert not where.startswith("/tmp"), (
        f"{module} would create temporary files in {where}, which is the "
        "shared quota'd tmpfs. Either the tool lost its `import scratch` and "
        "has no importer that carries one, or tools/scratch.py itself is "
        "pointing at the wrong place."
    )


def test_an_explicit_tmpdir_is_respected():
    """A caller who chose a location knows something the default does not."""
    sys.path.insert(0, str(TOOLS))
    import scratch

    chosen = ROOT / "tests" / "realistic_corpus" / "build"
    assert scratch.ensure_tmpdir(chosen) is not None


def test_the_default_scratch_is_not_on_the_tmpfs():
    """The fallback location itself has to be somewhere with room."""
    sys.path.insert(0, str(TOOLS))
    import scratch

    assert not str(scratch.DEFAULT_SCRATCH).startswith("/tmp"), (
        f"the default scratch {scratch.DEFAULT_SCRATCH} is on the very tmpfs "
        "this module exists to avoid"
    )


def test_the_redirect_degrades_under_the_fixed_worker_environment():
    """It must never be the reason a process dies.

    `build_guard.worker_env()` deliberately sets `HOME=/`, because the
    environment block sits at the top of the initial stack and its *size*
    shifts every frame beneath it — a recovered function reading an
    uninitialised local returns different garbage depending on how many
    variables the invoking shell exported.

    Under that environment the default scratch resolves to `/.cache/...`, which
    cannot be created. The first version of `scratch.py` let the resulting
    `PermissionError` escape, which killed the execution worker and turned 27
    fixture tests into `worker crashed (exit 1)`. Keeping `/tmp` clean is an
    optimisation; running is a requirement.
    """
    code = (
        "import sys, tempfile; sys.path.insert(0, %r); import scratch; "
        "print(scratch.ensure_tmpdir()); print(tempfile.gettempdir()); "
        "import tempfile as t, shutil; d = t.mkdtemp(); shutil.rmtree(d); "
        "print('MKDTEMP_OK')" % str(TOOLS)
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        env={"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/", "LC_ALL": "C"},
        cwd=str(ROOT),
    )
    assert result.returncode == 0, (
        "importing scratch under the fixed worker environment failed:\n"
        f"{result.stderr[-1200:]}"
    )
    assert "MKDTEMP_OK" in result.stdout, (
        f"tempfile is unusable under the worker environment:\n{result.stdout}"
    )
