"""A Cortex-M critical section decodes, lifts, and keeps its body.

The defect (DecBench failure class F2a, 31 rows)
------------------------------------------------

Capstone in glaurung's ARM configuration **rejected** every Cortex-M
system-register instruction. `mrs r1, BASEPRI` (`f3ef 8111`) returned
`InvalidInstruction`, and a function whose first instruction cannot be decoded
is abandoned whole. A BASEPRI critical section is the ordinary way an RTOS
masks interrupts, so this was not an exotic corner: it appears in essentially
every RTOS and bare-metal image in the corpus.

Why the fix is a fallback and not a mode change
-----------------------------------------------

Decoding these needs `CS_MODE_MCLASS`, and M-profile and A-profile assign
different meanings to the same Thumb encodings, so no single configuration
decodes both. Enabling MClass globally is strictly worse than the bug:
`f381 8100` is `msr cpsr_c, r1` on A-profile and decodes as
`msr apsr_nzcvq, r1` under MClass -- a silently WRONG answer rather than a
failed one. So MClass is consulted **only after** the primary decoder rejects
an instruction. A-profile system instructions decode on the primary and never
reach it; Cortex-M ones are rejected there, and rejection is what costs the
function.

The object is committed (952 bytes) because the defect is in decoding, which
needs no link.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
FIXTURE_DIR = ROOT / "tests" / "cortex_m"
FIXTURE = FIXTURE_DIR / "rtos.o"


def decompile_all() -> str:
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "glaurung.cli",
            "decompile",
            str(FIXTURE),
            "--style",
            "decbench",
            "--no-color",
        ],
        capture_output=True,
        text=True,
        cwd=ROOT,
        timeout=600,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr[-800:]
    return proc.stdout


@pytest.fixture(scope="module")
def rendered() -> str:
    assert FIXTURE.is_file(), f"{FIXTURE} is committed; the checkout is broken"
    return decompile_all()


def test_the_fixture_matches_its_manifest():
    m = json.loads((FIXTURE_DIR / "MANIFEST.json").read_text())
    assert hashlib.sha256(FIXTURE.read_bytes()).hexdigest() == m["sha256"], (
        "rtos.o does not match MANIFEST.json; rebuild with build.sh and "
        "refresh the manifest, or the assertions below measure other bytes."
    )


def test_the_critical_section_function_is_recovered(rendered):
    """The whole point: a function starting with `mrs` must not vanish.

    `guarded_increment` begins `mrs r1, BASEPRI` at offset 0. While that
    instruction was undecodable the function had no first basic block and was
    dropped from the output entirely.
    """
    assert "// glaurung:" in rendered, (
        "no function was recovered from the object at all:\n" + rendered[:600]
    )
    body = rendered[rendered.index("// glaurung:") :]
    assert body.count("\n") >= 4, f"recovered a stub, not a body:\n{body}"


def test_both_msr_writes_survive_into_the_body(rendered):
    """A critical section has two BASEPRI writes: enter and exit.

    Keeping only one would mean the interrupt mask is modelled as never
    restored, which reads as a permanently-masked path.
    """
    writes = re.findall(r"arm32\.msr\.basepri", rendered)
    assert len(writes) == 2, (
        f"expected two `msr basepri` intrinsics (enter + exit), found "
        f"{len(writes)}:\n{rendered}"
    )


def test_the_intrinsic_names_its_system_register(rendered):
    """`arm32.msr.basepri`, not a bare `msr` or an unnamed unknown.

    BASEPRI and BASEPRI_MAX have different update semantics -- the latter only
    raises the priority ceiling -- so an intrinsic that drops the register name
    models one as the other.
    """
    assert "arm32.msr.basepri" in rendered, (
        "the system register is missing from the intrinsic name:\n" + rendered
    )
    assert not re.search(r"arm32\.(mrs|msr)\.\s*\(", rendered), (
        "an intrinsic was emitted with an empty system register:\n" + rendered
    )


def test_the_guarded_store_is_still_between_the_two_writes(rendered):
    """The body inside the critical section must survive, in order.

    The source is `shared_counter += by`. If the increment were dropped or
    hoisted outside the two BASEPRI writes the recovery would be wrong in a way
    that still looks plausible.
    """
    first = rendered.index("arm32.msr.basepri")
    last = rendered.rindex("arm32.msr.basepri")
    between = rendered[first:last]
    assert "+" in between, f"no arithmetic between the two BASEPRI writes:\n{rendered}"
