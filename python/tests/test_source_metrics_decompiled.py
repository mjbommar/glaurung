"""`glaurung.source` over our own decompiler's output, end to end.

Split out of `test_source_metrics.py` on purpose. `tools/gen_test_facets.py`
classifies a test file by the paths it names, and `core` is the absence of every
other facet -- so a single reference to a Git LFS sample or to the gitignored
fixture build directory would drop all thirty-odd metric tests out of the tier
that runs on every push. One file needs a binary; the rest need nothing but the
built extension, and they should be tiered accordingly.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

import glaurung

ROOT = Path(__file__).resolve().parent.parent.parent

#: Fixture objects when the fixture harness has run, else a committed sample.
_DECOMPILE_CANDIDATES = (
    ROOT / "tests" / "decompiler_fixtures" / "build" / "03_loop_shapes-gcc-O0.so",
    ROOT / "samples/binaries/platforms/linux/amd64/export/native/gcc/O0/hello-gcc-O0",
)

#: Fixture objects when the fixture harness has run, else a committed sample.
_DECOMPILE_CANDIDATES = (
    ROOT / "tests" / "decompiler_fixtures" / "build" / "03_loop_shapes-gcc-O0.so",
    ROOT / "samples/binaries/platforms/linux/amd64/export/native/gcc/O0/hello-gcc-O0",
)


@pytest.mark.core
def test_our_own_decompiler_output_measures_cleanly():
    """The loop this module exists to close: decompile a real binary, measure
    the C that comes out, and read the structural cost.

    `tests/decompiler_fixtures/build/` is gitignored, so the fixture object is
    used when the harness has run and a committed sample ELF otherwise. Both
    are real binaries; neither is constructed for this test.

    The assertions are on the *pipeline*, not on today's numbers: which
    functions the decompiler recovers and how branchy they are moves with every
    structurer change, and pinning that here would make this a duplicate of the
    fixture matrix that fails for the wrong reasons.
    """
    binary = next((p for p in _DECOMPILE_CANDIDATES if p.exists()), None)
    if binary is None:
        pytest.skip(
            "needs tests/decompiler_fixtures/build (run the fixture harness) "
            "or the committed sample ELFs (git lfs pull)"
        )

    decompiled = subprocess.run(
        [
            sys.executable,
            "-m",
            "glaurung.cli",
            "decompile",
            str(binary),
            "--all",
            "--limit",
            "40",
            "--style",
            "decbench",
        ],
        capture_output=True,
        text=True,
        check=False,
        cwd=ROOT,
    )
    assert decompiled.returncode == 0, decompiled.stderr[-2000:]
    assert decompiled.stdout.strip(), "the decompiler emitted nothing"

    report = glaurung.source.analyze(decompiled.stdout, dialect="decompiled")

    # Our own C must parse. A diagnostic here is either a decompiler emitting
    # something that is not C, or a front end that cannot read it -- and both
    # are defects worth failing on, because every metric downstream of a
    # recovered parse is measured over less text than it claims.
    assert not [d for d in report.diagnostics if d.severity == "error"], [
        d.message for d in report.diagnostics if d.severity == "error"
    ][:5]
    assert len(report) > 0, "no function measured in the decompiler's output"

    summary = report.summary()
    assert summary["functions"] == len(report)
    assert summary["structured_functions"] + sum(
        1 for f in report.functions if not f.is_structured
    ) == len(report)
    for f in report.functions:
        assert f.cyclomatic >= 1
        assert f.has_body
