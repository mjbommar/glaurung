"""Definition-before-use census across EVERY fixture lane.

WHY THIS EXISTS SEPARATELY FROM `structural.py`
-----------------------------------------------
`structural.py` already records a per-function `verify` map and the structural
lane already ratchets it. But it builds each fixture exactly once, with
``gcc -O0 -g``, so its ratchet covers one lane of the four-to-six each fixture
has. Measured at ``2ed9b07`` over 740 lanes, that one lane holds **7** of the
**304** definition-before-use violations present in REQUIRED functions:

    clang:O2 128   gcc:O2 107   rustc:O0 32   rustc:O2 22   clang:O0 8   gcc:O0 7

97.7% of the corpus's undefined reads were therefore ungated. That is not a
rounding error in coverage — the optimising lanes are where value-model
corruption actually happens, because that is where copy chains, register views,
phi coalescing and landing-pad live-ins get hard, and the unoptimised lane the
ratchet watched is the one least able to produce a violation.

WHAT IS MEASURED
----------------
Every fixture is compiled in every lane its language supports
(``fixture_harness.matrix_for``) and decompiled at the ``decbench`` style with
``GLAURUNG_VERIFY_DEFS=1``, which splices each violation the pre-render verifier
found into the output as a ``// glaurung-verify:`` comment. Two levels are
recorded, deliberately at different precision:

* ``required`` — the exact violation list for every REQUIRED function of every
  lane. Per-function and per-message, so a new violation names itself.
* ``lane_totals`` — counts over EVERY emitted function, including the library
  and compiler-runtime bodies the manifest makes no claim about. Those are real
  decompilations with real undefined reads (12,702 of them at ``2ed9b07``), but
  they are not functions the corpus asserts a contract for, so they are held to
  an aggregate ceiling rather than a per-name list.

The lane is slow (it compiles and decompiles the whole corpus several times
over), which is why it lives behind the ``slow`` marker exactly as the
structural lane does.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

HERE = Path(__file__).resolve().parent
SRC = HERE / "src"
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent.parent / "tools"))

import build_guard as BG  # ty: ignore[unresolved-import]
import fixture_harness as H  # ty: ignore[unresolved-import]
import fixture_toolchain as TC  # ty: ignore[unresolved-import]
import manifest as M

#: The decbench provenance header every rendered function begins with.
_HDR = re.compile(r"(?m)^// glaurung: (\S+) @ 0x[0-9a-fA-F]+\s*$")
#: One reported definition-before-use violation.
_VERIFY = re.compile(r"(?m)^// glaurung-verify: (.+)$")

#: Reserved key holding the compile toolchain identity, as in the other maps.
TOOLCHAIN_KEY = H.TOOLCHAIN_KEY


def _source(stem: str) -> Path | None:
    """The fixture's source in whatever language it is written in."""
    for candidate in sorted(SRC.glob(f"{stem}.*")):
        if candidate.stem == stem:
            return candidate
    return None


def _blocks(text: str) -> dict[str, str]:
    """Split a multi-function ``--all`` render into {function: text block}."""
    parts = list(_HDR.finditer(text))
    return {
        match.group(1): text[
            match.start() : (
                parts[index + 1].start() if index + 1 < len(parts) else len(text)
            )
        ]
        for index, match in enumerate(parts)
    }


def violations_in(block: str) -> list[str]:
    """The violations the decompiler reported for one rendered function."""
    return sorted(match.group(1).strip() for match in _VERIFY.finditer(block))


def _lane(job: tuple[str, str, str]) -> tuple[str, dict[str, list[str]] | None, str]:
    fixture, cc, opt = job
    key = f"{fixture}:{cc}:{opt}"
    src = _source(fixture)
    if src is None:
        return key, None, "no-source"
    so, error = H.compile_fixture(src, cc, opt)
    if so is None:
        return key, None, f"compile-failed: {error}"
    try:
        run = subprocess.run(
            [
                BG.glaurung_bin(),
                "decompile",
                str(so),
                "--all",
                "--limit",
                "1000",
                "--style",
                "decbench",
                "--no-color",
            ],
            capture_output=True,
            text=True,
            timeout=600,
            check=False,
            # Opt in to the per-violation diagnostics. They are OFF by default
            # because the decbench render is an artifact other tools score; this
            # lane is the consumer they exist for.
            env={**os.environ, "GLAURUNG_VERIFY_DEFS": "1"},
        )
    except subprocess.TimeoutExpired:
        return key, None, "decompile-timeout"
    if run.returncode != 0:
        return key, None, f"decompile-failed: {run.stderr.strip()[-160:]}"
    return key, {n: violations_in(b) for n, b in _blocks(run.stdout).items()}, ""


def jobs() -> list[tuple[str, str, str]]:
    """Every (fixture, compiler, optimisation) lane the corpus declares."""
    out: list[tuple[str, str, str]] = []
    for fixture in sorted(M.REQUIRED_FUNCTIONS):
        src = _source(fixture)
        if src is None:
            continue
        out.extend((fixture, cc, opt) for cc, opt in H.matrix_for(src))
    return out


def defuse_report(max_workers: int | None = None) -> dict:
    """Census every lane and return the committed-baseline shape.

    ``problems`` is part of the report rather than an exception: a lane that
    fails to build is a fact the gate must see, and dropping it silently would
    shrink the census into an easier one that still reads as green.
    """
    if max_workers is None:
        max_workers = H.default_jobs()
    required: dict[str, list[str]] = {}
    lane_totals: dict[str, dict[str, int]] = {}
    problems: list[str] = []
    with ProcessPoolExecutor(max_workers=max_workers) as pool:
        for key, per_function, error in pool.map(_lane, jobs()):
            if per_function is None:
                problems.append(f"{key}: {error}")
                continue
            fixture, cc, opt = key.split(":")
            declared = set(M.REQUIRED_FUNCTIONS.get(fixture, ()))
            for name in sorted(declared):
                block = per_function.get(name)
                required[f"{key}:{name}"] = ["not_emitted"] if block is None else block
            totals = lane_totals.setdefault(
                f"{cc}:{opt}",
                {
                    "functions_emitted": 0,
                    "functions_with_violations": 0,
                    "violations": 0,
                },
            )
            for found in per_function.values():
                totals["functions_emitted"] += 1
                totals["violations"] += len(found)
                totals["functions_with_violations"] += 1 if found else 0
    return {
        TOOLCHAIN_KEY: TC.fingerprint(),
        "required": required,
        "lane_totals": lane_totals,
        "problems": sorted(problems),
    }


def summarize(report: dict) -> dict[str, int]:
    """Headline counts over REQUIRED functions."""
    found = {k: v for k, v in report["required"].items() if v and v != ["not_emitted"]}
    return {
        "required_functions": len(report["required"]),
        "required_functions_with_violations": len(found),
        "required_violations": sum(len(v) for v in found.values()),
        "not_emitted": sum(
            1 for v in report["required"].values() if v == ["not_emitted"]
        ),
    }
