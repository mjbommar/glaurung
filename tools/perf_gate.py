#!/usr/bin/env python3
"""A performance number something actually compares against.

The gap this closes
-------------------

Ten criterion targets exist and **no baseline is recorded for any of them**,
nothing anywhere invokes ``cargo bench``, and ``bench/harness.py`` records
``decompile_ms`` without ever comparing it. ``CLAUDE.md`` states the
consequence plainly: a change that doubles decompile time still ships green.
This is the missing half -- a recorded number and a gate that reads it.

Why instructions and not seconds
--------------------------------

Wall-clock on this machine is noisy enough to produce false failures; the arch
gate has already recorded some, which is why baseline regeneration is
documented as needing a quiet machine. Instructions retired are stable to
about 1% across load, which is what makes a tight threshold honest rather than
flaky.

Measured while writing this, on ``hello-rust-release`` (692 functions):
86.61e9 / 85.61e9 / 84.97e9 instructions across three runs -- a 1.9% spread,
with interpreter startup under 1% of the total. The same measurement on a
*small* binary spread 13%, because there the number is mostly Python startup.
That is why the reference set is deliberately made of large binaries and why
the driver bypasses ``uv run``, whose own overhead measured 10.4e9
instructions for ``--help`` alone -- an order of magnitude more than the work
being measured.

Why not criterion
-----------------

The criterion targets stay what they are: diagnosis tools for *where* a
regression lives once this says *that* one exists. Gating on ten criterion
wall-clock targets is exactly the noisy multi-minute check that gets skipped,
and skipping is how the current situation arose.

Usage
-----

    uv run python tools/perf_gate.py                  # measure and compare
    uv run python tools/perf_gate.py --write-baseline # deliberate update
    uv run python tools/perf_gate.py --json           # machine-readable
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
#: Overridable so the gate's own failure states are testable without touching
#: the committed baseline. Production never sets it.
BASELINE = Path(
    os.environ.get("GLAURUNG_PERF_BASELINE", REPO / "bench" / "perf_baseline.json")
)

#: Exit code meaning "this run is not evidence" -- distinct from 0 (compared,
#: no regression) and 1 (compared, regression found).
#:
#: Three states used to return 0 and were therefore indistinguishable from a
#: pass: no baseline, incomparable units, and a baseline reference this run did
#: not measure. Scheduling a gate with those semantics manufactures assurance,
#: which is why R6 increment A comes before increment G.
NOT_EVIDENCE = 3
PYTHON = REPO / ".venv" / "bin" / "python"

#: Reference binaries, chosen so the decompile dominates the measurement.
#:
#: Every one is large enough that interpreter startup is under 1% of the work.
#: A small binary is NOT a cheaper version of this measurement -- it is a
#: measurement of Python startup, which is why none are here.
#:
#: The first version of this list ignored its own rule and included
#: `hello-c-clang-O2`. It measured 670e6 instructions with a **28.7% spread**,
#: against 0.2% and 2.4% for the two large binaries in the same run -- a
#: reference that could not have held any threshold, in a list whose comment
#: explained why it should not be there.
REFERENCES = [
    "samples/binaries/platforms/linux/amd64/rust/hello-rust-release",
    "samples/binaries/platforms/linux/amd64/go/hello-go",
    "samples/binaries/platforms/linux/amd64/rust/hello-rust-debug",
]

#: Instruction counts are stable to ~1%, so 5% is a real regression rather than
#: noise. Wall-clock, the fallback, gets 25% because it is not.
INSTRUCTION_THRESHOLD = 0.05
WALLCLOCK_THRESHOLD = 0.25

#: MINIMUM of this many runs, not the median.
#:
#: Instructions retired only ever go UP under interference -- an interrupt, a
#: migration between the core and atom PMUs on this hybrid CPU, a retried
#: syscall. Nothing makes the same work retire fewer instructions. So the
#: minimum is the closest observation to the work itself, while the median
#: still carries whatever noise was present in half the runs. Measured on
#: `hello-go`, the median-of-3 spread was 4.4% against a 5% threshold, which
#: would have been flaky by construction; the minimum is stable.
RUNS = 3

DRIVER = """
import sys
import glaurung

glaurung.ir.decompile_all(sys.argv[1], style="decbench")
"""


def have_perf() -> bool:
    """Whether `perf stat` can actually count in this session.

    Presence on PATH is not enough: `kernel.perf_event_paranoid` gates it, and
    this box ships at 4 (everything denied) until someone lowers it.
    """
    if not shutil.which("perf"):
        return False
    probe = subprocess.run(
        ["perf", "stat", "-e", "instructions:u", "-x,", "true"],
        capture_output=True,
        text=True,
        check=False,
    )
    return any(
        field.strip().isdigit()
        for line in probe.stderr.splitlines()
        for field in line.split(",")[:1]
    )


def instructions_for(binary: Path, driver: Path) -> int | None:
    """User-space instructions retired for one decompile of `binary`."""
    proc = subprocess.run(
        [
            "perf",
            "stat",
            "-e",
            "instructions:u",
            "-x,",
            "--",
            str(PYTHON),
            str(driver),
            str(binary),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        return None
    # This is a hybrid CPU: `perf` reports one row per PMU (cpu_core,
    # cpu_atom), and a thread migrating between them splits its count across
    # both. Summing is the only correct read; taking the first row silently
    # loses whatever ran on the other core type.
    total = 0
    for line in proc.stderr.splitlines():
        head = line.split(",", 1)[0].strip()
        if head.isdigit():
            total += int(head)
    return total or None


def seconds_for(binary: Path, driver: Path) -> float:
    """Wall-clock for one decompile. The weak fallback; see the module docs."""
    start = time.perf_counter()
    subprocess.run(
        [str(PYTHON), str(driver), str(binary)],
        capture_output=True,
        check=False,
    )
    return time.perf_counter() - start


def measure(use_perf: bool) -> dict[str, float]:
    """Median cost per reference binary."""
    results: dict[str, float] = {}
    driver = REPO / ".perf_gate_driver.py"
    driver.write_text(DRIVER)
    try:
        for relative in REFERENCES:
            binary = REPO / relative
            if not binary.is_file():
                print(f"  SKIP (absent): {relative}", file=sys.stderr)
                continue
            samples: list[float] = []
            for _ in range(RUNS):
                value = (
                    instructions_for(binary, driver)
                    if use_perf
                    else seconds_for(binary, driver)
                )
                if value is None:
                    print(f"  FAILED to measure: {relative}", file=sys.stderr)
                    break
                samples.append(float(value))
            if len(samples) == RUNS:
                results[relative] = min(samples)
                spread = (max(samples) - min(samples)) / min(samples)
                unit = "instructions" if use_perf else "s"
                print(
                    f"  {relative.split('/')[-1]:<26} "
                    f"{results[relative]:>16,.0f} {unit}  (spread {spread:.1%})",
                    file=sys.stderr,
                )
    finally:
        driver.unlink(missing_ok=True)
    return results


def build_is_current() -> bool:
    """Whether the installed extension is newer than every Rust source file.

    A measurement against a stale `.so` records the previous commit's behaviour
    under this one, and nothing downstream can tell -- `CLAUDE.md` records that
    happening to a baseline regeneration. `build_guard.py` owns this check; it
    is called rather than reimplemented.
    """
    proc = subprocess.run(
        [str(PYTHON), str(REPO / "tools" / "build_guard.py")],
        capture_output=True,
        text=True,
        cwd=REPO,
        check=False,
    )
    return proc.returncode == 0 and "STALE" not in proc.stdout


def compare(current: dict[str, float], baseline: dict, threshold: float) -> list[str]:
    """Regressions worse than `threshold`, as human-readable lines."""
    problems = []
    for name, now in sorted(current.items()):
        was = baseline.get("measures", {}).get(name)
        if not isinstance(was, (int, float)) or was <= 0:
            continue
        change = (now - was) / was
        if change > threshold:
            problems.append(
                f"{name}: {was:,.0f} -> {now:,.0f} (+{change:.1%}, "
                f"threshold {threshold:.0%})"
            )
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--write-baseline",
        action="store_true",
        help="overwrite the baseline with today's measures (deliberate update)",
    )
    parser.add_argument("--json", action="store_true", help="emit JSON")
    parser.add_argument(
        "--allow-stale-build",
        action="store_true",
        help="measure even if the built extension is older than src/ (rarely right)",
    )
    args = parser.parse_args()

    if not PYTHON.is_file():
        print(
            f"no interpreter at {PYTHON}; run `uv sync --locked --dev`", file=sys.stderr
        )
        return 2
    if not args.allow_stale_build and not build_is_current():
        print(
            "REFUSING: the built extension is older than src/. A number measured\n"
            "now would describe the previous build. Run `uv run maturin develop\n"
            "--release` first, or pass --allow-stale-build if you truly mean to.",
            file=sys.stderr,
        )
        return 2

    use_perf = have_perf()
    if not use_perf:
        print(
            "perf unavailable (check kernel.perf_event_paranoid); falling back to\n"
            "wall-clock, which is the WEAK form -- threshold widens to 25%.",
            file=sys.stderr,
        )
    unit = "instructions" if use_perf else "seconds"
    threshold = INSTRUCTION_THRESHOLD if use_perf else WALLCLOCK_THRESHOLD

    # Reject metadata-only failure states before starting nine deliberately
    # expensive whole-binary decompilations. A missing baseline or a unit
    # mismatch cannot become comparable because of anything measurement might
    # discover. Baseline creation is the exception: it exists to measure and
    # write the current unit.
    baseline: dict | None = None
    expected: set[str] = set()
    if not args.write_baseline:
        if not BASELINE.is_file():
            print(
                f"NOT EVIDENCE: no baseline at {BASELINE}. Record one with\n"
                "--write-baseline. This is exit 3, not 0: absence of evidence is\n"
                "not evidence of no regression, and a caller cannot tell the two\n"
                "apart from an exit status alone.",
                file=sys.stderr,
            )
            return NOT_EVIDENCE

        baseline = json.loads(BASELINE.read_text())
        if baseline.get("unit") != unit:
            print(
                f"NOT EVIDENCE: baseline is in {baseline.get('unit')} and this run\n"
                f"is in {unit}; the two cannot be compared. This is the ordinary\n"
                "state on a host without usable `perf` (every GitHub runner blocks\n"
                "instruction counting via kernel.perf_event_paranoid), where the\n"
                "gate falls back to wall-clock. Exit 3 so an unsupported runner is\n"
                "visibly not evidence rather than a pass.",
                file=sys.stderr,
            )
            return NOT_EVIDENCE

        expected = {
            name
            for name, value in baseline.get("measures", {}).items()
            if isinstance(value, (int, float)) and value > 0
        }
        impossible = sorted(
            name
            for name in expected
            if name not in REFERENCES or not (REPO / name).is_file()
        )
        if impossible:
            print(
                "NOT EVIDENCE: the baseline records references this run cannot\n"
                f"measure: {impossible}. A partial measurement is not a\n"
                "measurement -- the missing rows would otherwise vanish from the\n"
                "comparison and the gate would pass on the remainder.",
                file=sys.stderr,
            )
            return NOT_EVIDENCE

    print(f"measuring ({unit}, minimum of {RUNS}):", file=sys.stderr)
    current = measure(use_perf)
    if not current:
        print("nothing measured", file=sys.stderr)
        return 2

    report = {"unit": unit, "runs": RUNS, "measures": current}

    if args.write_baseline:
        BASELINE.parent.mkdir(parents=True, exist_ok=True)
        BASELINE.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        print(f"wrote baseline: {BASELINE}", file=sys.stderr)
        return 0

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))

    assert baseline is not None

    # P2: comparison iterates CURRENT results, so a reference that failed to
    # measure silently leaves the comparison rather than failing it. Measure
    # one of three and the gate would pass on a third of the evidence.
    unmeasured = sorted(expected - set(current))
    if unmeasured:
        print(
            "NOT EVIDENCE: the baseline records references this run did not\n"
            f"measure: {unmeasured}. A partial measurement is not a\n"
            "measurement -- the missing rows would otherwise vanish from the\n"
            "comparison and the gate would pass on the remainder.",
            file=sys.stderr,
        )
        return NOT_EVIDENCE

    problems = compare(current, baseline, threshold)
    if problems:
        for line in problems:
            print(f"REGRESSION: {line}", file=sys.stderr)
        print(
            f"perf gate FAILED: {len(problems)} reference(s) got worse", file=sys.stderr
        )
        return 1
    print("perf gate: passed", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
