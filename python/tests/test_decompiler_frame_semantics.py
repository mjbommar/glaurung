"""Real-binary coverage for source-level frame semantics.

GCC and Clang materialise an x86-64 frame with ``push rbp; mov rbp, rsp`` at
``-O0``.  Once frame-relative loads and stores have been promoted to C locals,
that machine setup is no longer part of the source program and must not survive
as reads or writes of uninitialised C variables.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import diff_decompile as D  # ty: ignore[unresolved-import]  # added above

pytestmark = pytest.mark.slow


@pytest.mark.parametrize("compiler", ["gcc", "clang"])
def test_promoted_x86_frame_has_no_raw_machine_state(
    compiler: str, tmp_path: Path
) -> None:
    """A promoted frame must render as locals, not ``rsp``/``rbp`` plumbing."""
    source = ROOT / "tests" / "decbench_corpus" / "src" / "arrays.c"
    binary = tmp_path / f"arrays-{compiler}-O0.so"
    compiled = subprocess.run(
        [
            compiler,
            "-shared",
            "-fPIC",
            "-g",
            "-O0",
            "-o",
            str(binary),
            str(source),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert compiled.returncode == 0, compiled.stderr

    functions = D.exported_functions(str(binary))
    code = D.decompiled_c(str(binary), functions["sum_array"])
    assert code is not None
    for machine_name in ("rsp", "rbp", "stack_0"):
        assert machine_name not in code, code
    # GCC and Clang choose different frame offsets for the same two source
    # locals.  DWARF names are authoritative, so the semantic invariant is that
    # both survive as typed source locals; physical offsets are not observable.
    assert re.search(r"^    int i;$", code, re.MULTILINE), code
    assert re.search(r"^    int s;$", code, re.MULTILINE), code
