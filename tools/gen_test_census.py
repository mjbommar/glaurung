#!/usr/bin/env python3
"""Record how many tests each module declares, and which are never executed.

R8.3. See `python/tests/test_test_census.py` for the contract. This counts
`#[test]` attributes in source, which is deliberately a DECLARATION count, not
an execution count -- the gap between the two is the thing worth measuring.
"""

from __future__ import annotations

import json
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BASELINE = ROOT / "tests" / "test_census_baseline.json"

TEST_ATTR = re.compile(r"^\s*#\[test\]", re.M)

#: Trees whose tests NO gate executes.
#:
#: **Empty, as of the `symbolic` CI lane.** Every tree is now reached by some
#: job, which is the outcome R8.3 existed to force rather than merely record.
#: The tuple stays so the ratchet keeps a shape to fail on: adding a tree here
#: means admitting its tests cannot fail.
#:
#: The history matters, because both earlier values were wrong in instructive
#: ways:
#:
#: * `("symbolic", "exec")` — 271. Wrong by 76. `Cargo.toml` defines
#:   `python-ext = [..., "exec"]`, so the extension build enables the emulator
#:   and `--features python-ext` runs 65 of exec's 76 tests; the other 11 are
#:   `src/exec/oracle.rs` behind `dev-oracle`, which links libunicorn and is
#:   never shipped. Reading a `cfg` gate tells you what a module needs; only
#:   running the suite tells you what executed.
#: * `("symbolic",)` — 195. Correct as a measurement, obsolete as a claim:
#:   nothing was preventing those tests from running. `symbolic = ["exec"]` is
#:   pure Rust, and the first `cargo test --features symbolic` passed 3,025 / 0
#:   with 103 symbolic tests executing. They needed a CI job, not a fix.
#:
#: 92 tests remain behind `solver-axeyum`/`solver-bitwuzla`/`solver-z3`, which
#: link external SMT libraries. `feature-build-gate.sh` type-checks them and no
#: lane runs them; that is a provisioning decision, recorded in
#: `solver_gated_estimate` below rather than hidden in this tuple.
NEVER_EXECUTED: tuple[str, ...] = ()

#: Tests behind a `solver-*` feature, which need an external SMT library.
#: Measured as (declared in symbolic) - (executed by `--features symbolic`).
SOLVER_GATED_ESTIMATE = 92


def module_of(path: Path) -> str:
    if path.parts[0] == "src":
        return path.parts[1].replace(".rs", "")
    return "tests/" + path.stem


def census() -> dict[str, int]:
    counts: Counter[str] = Counter()
    for base in ("src", "tests"):
        for p in (ROOT / base).rglob("*.rs"):
            n = len(TEST_ATTR.findall(p.read_text(errors="ignore")))
            if n:
                counts[module_of(p.relative_to(ROOT))] += n
    return dict(sorted(counts.items()))


def main() -> int:
    counts = census()
    never = {k: v for k, v in counts.items() if k in NEVER_EXECUTED}
    payload = {
        "note": (
            "Declared #[test] attributes per module. A declaration count, not "
            "an execution count -- see never_executed."
        ),
        "total_declared": sum(counts.values()),
        "never_executed_total": sum(never.values()),
        "never_executed": never,
        "solver_gated_estimate": SOLVER_GATED_ESTIMATE,
        "by_module": counts,
    }
    BASELINE.write_text(json.dumps(payload, indent=1) + "\n")
    print(
        f"{BASELINE.relative_to(ROOT)}: {payload['total_declared']} declared, "
        f"{payload['never_executed_total']} never executed by any gate"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
