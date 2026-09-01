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
#: `cargo test` does not build them, and `scripts/feature-build-gate.sh` runs
#: `cargo check --all-targets`, which compiles test code without running it.
#: So these are type-checked forever and executed never.
#:
#: **`exec` is deliberately NOT here, and the first version of this file was
#: wrong to include it.** `Cargo.toml` defines
#: `python-ext = ["pyo3", "pyo3/extension-module", "exec"]`, so the Python
#: extension build enables the emulator and `cargo test --features python-ext`
#: runs **65** of its 76 declared tests. The 11 that remain are in
#: `src/exec/oracle.rs`, behind `dev-oracle`, which links system libunicorn and
#: is explicitly never shipped. Counting all 76 as unreachable overstated the
#: problem by 76 tests and was corrected by measuring the run rather than
#: reading the feature list.
NEVER_EXECUTED = ("symbolic",)


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
