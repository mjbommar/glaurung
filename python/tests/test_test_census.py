"""How many tests each module declares, and which are never run.

R8.3. The counts are healthy and the distribution is not, and neither fact was
recorded anywhere before this. Measured 2026-09-01:

* `ir` declares **1,875** of 3,187 tests — 59% of every `#[test]` in the tree —
  against `disasm` 19, `symbols` 22 and `entropy` 20;
* **271 tests are never executed by any gate.** `src/symbolic/` (195) and
  `src/exec/` (76) are behind features that neither `cargo test` nor
  `--features python-ext` enables, and `scripts/feature-build-gate.sh` runs
  `cargo check --all-targets`, which compiles test code without running it. So
  they are type-checked forever and executed never.

Why a declaration count
-----------------------

This counts `#[test]` attributes in source rather than parsing a test-runner
listing, which needs a full build and would make the ratchet unusable in the
default suite. The gap between declared and executed is not noise — it is the
measurement: `cargo test` executes 2,835 of 3,187 declared.

That makes it approximate in one direction worth stating: macro-generated and
parameterised tests are undercounted (one `#[test]` attribute can produce many
executions), which is why `--features python-ext` adds 122 executions from 32
declared `python_bindings` attributes. The ratchet is therefore about
*direction*, not exactness: a module must not lose declared tests, and the
never-executed pool must not grow.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
BASELINE = ROOT / "tests" / "test_census_baseline.json"
GENERATOR = ROOT / "tools" / "gen_test_census.py"

sys.path.insert(0, str(ROOT / "tools"))


def measured() -> dict:
    """Recompute the census in-process, the way the generator does."""
    import importlib.util

    spec = importlib.util.spec_from_file_location("gen_test_census", GENERATOR)
    assert spec is not None and spec.loader is not None, (
        f"cannot load {GENERATOR}; the census tool and this ratchet must stay "
        "together or neither measures anything"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    counts = mod.census()
    never = {k: v for k, v in counts.items() if k in mod.NEVER_EXECUTED}
    return {
        "total_declared": sum(counts.values()),
        "never_executed_total": sum(never.values()),
        "never_executed": never,
        "by_module": counts,
    }


@pytest.fixture(scope="module")
def now() -> dict:
    return measured()


@pytest.fixture(scope="module")
def recorded() -> dict:
    assert BASELINE.is_file(), (
        f"{BASELINE.name} missing; regenerate with `uv run python "
        f"{GENERATOR.relative_to(ROOT)}`"
    )
    return json.loads(BASELINE.read_text())


def test_no_module_loses_declared_tests(now, recorded):
    """The ratchet. A module that sheds tests must do so deliberately."""
    lost = {
        m: (recorded["by_module"][m], now["by_module"].get(m, 0))
        for m in recorded["by_module"]
        if now["by_module"].get(m, 0) < recorded["by_module"][m]
    }
    assert not lost, (
        "these modules declare fewer tests than the baseline records:\n  "
        + "\n  ".join(f"{m}: {was} -> {isnow}" for m, (was, isnow) in lost.items())
        + "\n\nIf tests moved, they must be shown running in their new home. "
        "If they were deleted deliberately, regenerate the baseline."
    )


def test_the_never_executed_pool_does_not_grow(now, recorded):
    """271 tests are compiled and never run. That number may only fall.

    Adding a test to `src/symbolic/` or `src/exec/` writes a test nothing will
    ever execute — it is type-checked by `feature-build-gate.sh` and run by
    nothing. Growing that pool is a decision, not an accident.
    """
    assert now["never_executed_total"] <= recorded["never_executed_total"], (
        f"tests that no gate executes grew "
        f"{recorded['never_executed_total']} -> {now['never_executed_total']}: "
        f"{now['never_executed']}. Either wire a lane that runs them, or "
        "regenerate the baseline deliberately."
    )


def test_the_baseline_is_current(now, recorded):
    """A stale baseline silently stops ratcheting.

    If the census has IMPROVED — tests added, or the never-executed pool
    shrunk — the baseline must be tightened, or the next regression is
    compared against a number nobody meant.
    """
    assert now["total_declared"] >= recorded["total_declared"], "covered above"
    assert now["total_declared"] <= recorded["total_declared"] + 25, (
        f"declared tests grew {recorded['total_declared']} -> "
        f"{now['total_declared']}. Good — regenerate the baseline so the gain "
        f"is locked in: `uv run python {GENERATOR.relative_to(ROOT)}`"
    )


def test_the_generator_reproduces_the_committed_baseline():
    """The tool and the record must agree, or neither can be trusted."""
    proc = subprocess.run(
        [sys.executable, str(GENERATOR)],
        capture_output=True,
        text=True,
        cwd=ROOT,
        timeout=300,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr[-500:]
    # The generator rewrites the file; it must be identical to what was
    # committed, or the baseline drifted from its own tool.
    assert (
        subprocess.run(
            ["git", "diff", "--quiet", "--", str(BASELINE.relative_to(ROOT))],
            cwd=ROOT,
            check=False,
        ).returncode
        == 0
    ), (
        f"{BASELINE.name} differs from what the generator produces. Commit the "
        "regenerated file, or the ratchet is measuring against a hand-edited "
        "number."
    )


def test_the_imbalance_is_recorded_not_merely_felt(now):
    """A named landmark: `ir` dominates and `disasm` is thin.

    Pinned so the shape of the estate stays legible. If these stop being true
    the docstring above and the R8 section of the roadmap package need updating
    together with the baseline.
    """
    by = now["by_module"]
    assert by.get("ir", 0) > 1500, f"ir is {by.get('ir')}, expected the bulk"
    assert by.get("disasm", 0) < 60, (
        f"disasm is {by.get('disasm')} — if it really grew, update the R8 "
        "narrative, which cites 19 against ir's 1,875"
    )
