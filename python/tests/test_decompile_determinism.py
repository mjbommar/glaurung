"""Roadmap design rule 12: "Serial and parallel analysis must produce
identical facts and output."

The Rust decompile pipeline itself (`decompile_all`/`decompile_many` in
`src/python_bindings/ir.rs`) is a single, GIL-held, purely sequential loop
over discovered functions -- it does not use `rayon` or spawn worker
threads to decompile several functions concurrently. The only place this
codebase actually runs decompilation of a binary "in parallel" today is at
the OS-process level: `tools/fixture_harness.py`'s `--jobs` wraps
`subprocess.run` calls in a `ThreadPoolExecutor` (threads that block on a
subprocess release the GIL, so this is real concurrent OS-process
execution, not GIL-serialized Python threads). That is also exactly the
shape `tools/dectest.py` and `tools/decbench_matrix.py` use.

These tests hold the decompiler to design rule 12 at the level parallelism
is actually exercised in this codebase: decompiling the same binary from
several concurrently running OS processes must produce output byte-identical
to a serial run, and repeated runs (same process, and separate sequential
processes) must reproduce the same bytes every time.

Scope is deliberately small (2 architectures, <= 30 functions per binary) so
the whole file runs in well under a second of wall time even though it
launches a couple dozen subprocesses.
"""

from __future__ import annotations

import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import glaurung as g
import pytest

X86_SAMPLE = Path(
    "samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-gcc-O2"
)
ARM64_SAMPLE = Path(
    "samples/binaries/platforms/linux/arm64/export/cross/arm64/hello-arm64-gcc"
)
# A real, moderately sized (232 KiB) x86-64 PE with dozens of functions --
# enough surface area that a scheduling-order bug has room to show up, while
# still decompiling in well under a second.
MATHLIB_SAMPLE = Path(
    "samples/binaries/platforms/linux/amd64/libraries/shared/mathlib.dll"
)

BINARIES = [
    pytest.param(X86_SAMPLE, 8, id="x86_64-hello-gcc-O2"),
    pytest.param(ARM64_SAMPLE, 8, id="arm64-hello-gcc"),
    pytest.param(MATHLIB_SAMPLE, 25, id="x86_64-mathlib-dll"),
]


def _decompile_cli_json(path: Path, limit: int) -> subprocess.CompletedProcess:
    """Invoke `glaurung decompile --all --format json` as a fresh OS process.

    Mirrors `tools/fixture_harness.py::_run_lane`'s `subprocess.run(...,
    env=...)` shape (see `python/tests/test_cli_decompile.py::_run`), which is
    the real mechanism `--jobs` uses to run lanes "in parallel": independent
    processes, not threads inside one interpreter.
    """
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "glaurung.cli",
            "decompile",
            str(path),
            "--all",
            "--limit",
            str(limit),
            "--format",
            "json",
        ],
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.mark.parametrize("path,limit", BINARIES)
def test_decompile_all_repeats_identically_in_one_process(path: Path, limit: int):
    """Same process, same binary, called twice: must be byte-identical.

    This is the property `src/ir/stack_locals.rs` documents having lost once
    already (a bare `HashMap` `collect()` let iteration order pick `char` vs
    `long`). Nothing pins it at the whole-decompile level; this does.
    """
    if not path.exists():
        pytest.skip(f"sample missing: {path}")
    first = g.ir.decompile_all(str(path), limit=limit)
    second = g.ir.decompile_all(str(path), limit=limit)
    assert first == second
    # `decompile_all` returns [(name, va, text), ...]; a plain `==` on lists
    # of tuples already demands identical order, not just identical content
    # as a set -- exactly what "identical facts and output" requires.
    assert len(first) >= 1


@pytest.mark.parametrize("path,limit", BINARIES)
def test_decompile_all_repeats_identically_across_sequential_processes(
    path: Path, limit: int
):
    """Two freshly started processes decompiling the same binary, one after
    the other, must produce byte-identical stdout."""
    if not path.exists():
        pytest.skip(f"sample missing: {path}")
    run_a = _decompile_cli_json(path, limit)
    run_b = _decompile_cli_json(path, limit)
    assert run_a.returncode == 0, run_a.stderr
    assert run_b.returncode == 0, run_b.stderr
    assert run_a.stdout == run_b.stdout


@pytest.mark.parametrize("path,limit", BINARIES)
def test_decompile_all_concurrent_processes_match_serial_baseline(
    path: Path, limit: int
):
    """The actual serial/parallel differential: a serial baseline run versus
    several OS processes decompiling the SAME binary at the same time.

    `ThreadPoolExecutor` here mirrors `tools/fixture_harness.py::run_matrix`
    exactly: each worker thread blocks inside `subprocess.run`, which
    releases the GIL, so the subprocesses genuinely execute concurrently.
    """
    if not path.exists():
        pytest.skip(f"sample missing: {path}")

    baseline = _decompile_cli_json(path, limit)
    assert baseline.returncode == 0, baseline.stderr

    n_workers = 6
    with ThreadPoolExecutor(max_workers=n_workers) as pool:
        futures = [
            pool.submit(_decompile_cli_json, path, limit) for _ in range(n_workers)
        ]
        results = [f.result() for f in futures]

    for i, r in enumerate(results):
        assert r.returncode == 0, f"worker {i}: {r.stderr}"
        assert r.stdout == baseline.stdout, (
            f"worker {i}: parallel decompile of {path} diverged from the "
            f"serial baseline -- serial and parallel analysis produced "
            f"different output (roadmap design rule 12)"
        )
