"""The same binary decompiles to the same C, twice in a process and across two.

Why this matters more than it looks
-----------------------------------

Everything downstream assumes this and nothing asserted it. All six recorded
baselines, every byte-identity sweep used to validate a refactor, and every A/B
measurement this project has ever made are only meaningful if a second run of
the same input produces the same output. That assumption has never been
checked at the decompiler level.

It is not a hypothetical worry. Triage JSON *was* nondeterministic until
2026-08-31 -- wall-clock guards inside the string and IOC scans cut them at a
load-dependent point, so one sample reported 9 IOC samples on one run and 49 on
the next -- and separately, architecture ranking read out of a `HashMap` whose
iteration order is randomised per process, with two architectures that always
tie. Both were found only because a test that had never compiled was finally
wired up.

Why a subprocess leg
--------------------

Two calls in one process share a hash seed, so they cannot see the failure mode
that matters most here: Python and Rust both randomise `HashMap`/`dict`
iteration per process, and `SipHash` is 7.8% of this project's decompile
profile. An ordering that leaks from a hash map into rendered output is
identical within a process and differs between them. The subprocess leg is the
only one that can catch it.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
CANARY = ROOT / "tests" / "decompiler_fixtures" / "canary"
sys.path.insert(0, str(ROOT / "tools"))

import diff_decompile as D  # ty: ignore[unresolved-import]  # added above

#: A subset of the canary set. Determinism is a property of the pipeline rather
#: than of any one shape, so this trades breadth for staying inside the
#: default suite's time budget -- each subprocess leg pays a fresh interpreter
#: start.
SUBJECTS = [
    "04_switch_shapes-gcc-O0.so",
    "09_memory_effects-gcc-O2.so",
    "212_loop_with_returning_arm-gcc-O2.so",
]

#: Decompiles every exported function and prints a stable digest of the whole
#: render. Run in a FRESH interpreter so the hash seed differs from the
#: parent's.
CHILD = """
import hashlib, json, sys
sys.path.insert(0, {tools!r})
import diff_decompile as D

binary = sys.argv[1]
rendered = {{}}
for name, va in sorted(D.exported_functions(binary).items()):
    rendered[name] = D.decompiled_c(binary, va) or ""
blob = json.dumps(rendered, sort_keys=True).encode()
print(hashlib.sha256(blob).hexdigest())
"""


def render_digest_in_process(binary: Path) -> str:
    import hashlib

    rendered = {
        name: D.decompiled_c(str(binary), va) or ""
        for name, va in sorted(D.exported_functions(str(binary)).items())
    }
    blob = json.dumps(rendered, sort_keys=True).encode()
    return hashlib.sha256(blob).hexdigest()


def render_digest_in_subprocess(binary: Path) -> str:
    proc = subprocess.run(
        [sys.executable, "-c", CHILD.format(tools=str(ROOT / "tools")), str(binary)],
        capture_output=True,
        text=True,
        cwd=ROOT,
        timeout=600,
        check=False,
    )
    assert proc.returncode == 0, (
        f"child failed for {binary.name}: {proc.stderr.strip()[-600:]}"
    )
    return proc.stdout.strip()


@pytest.mark.parametrize("name", SUBJECTS)
def test_two_renders_in_one_process_are_identical(name):
    binary = CANARY / name
    assert binary.is_file(), f"{name} missing from the committed canary set"
    first = render_digest_in_process(binary)
    second = render_digest_in_process(binary)
    assert first == second, (
        f"{name}: two decompiles in ONE process disagree ({first[:12]} != "
        f"{second[:12]}). Something in the pipeline carries state between runs "
        "-- a thread-local that outlives its render, or a cache keyed on "
        "something that is not the input."
    )


@pytest.mark.parametrize("name", SUBJECTS)
def test_a_fresh_process_renders_the_same_bytes(name):
    """The leg that catches hash-order leaks; see the module docstring."""
    binary = CANARY / name
    assert binary.is_file(), f"{name} missing from the committed canary set"
    parent = render_digest_in_process(binary)
    child = render_digest_in_subprocess(binary)
    assert parent == child, (
        f"{name}: a fresh interpreter renders different C ({parent[:12]} != "
        f"{child[:12]}). This is the signature of an iteration order leaking "
        "from a HashMap/dict into output -- identical within a process, "
        "different across them. Every recorded baseline assumes this cannot "
        "happen."
    )


def test_the_subject_list_is_not_empty():
    """A vacuity guard: parametrising over [] passes silently."""
    assert SUBJECTS, "no determinism subjects configured"
    for name in SUBJECTS:
        assert (CANARY / name).is_file(), f"{name} is not in the canary set"
