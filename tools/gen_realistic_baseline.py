#!/usr/bin/env python3
"""Regenerate the realistic-corpus discovery baseline.

    uv run python tools/gen_realistic_baseline.py
    uv run python tools/gen_realistic_baseline.py --check   # exit 1 if stale

`tests/realistic_corpus/discovery_baseline.json` is a ratchet:
`python/tests/test_realistic_corpus.py` compares against it and fails when
discovery falls on a stripped lane. A ratchet that can be reset by hand is not a
ratchet, so this is the only supported way to move it — the same rule
`tools/gen_defuse_baseline.py` and `tools/gen_structural_baseline.py` already
follow, and for the same reason: a baseline refreshed by an ad-hoc snippet
leaves no record of how it was produced, and the next person cannot tell a
deliberate ratchet from an accident.

**It refuses to run against a stale extension.** A baseline written from a
`.so` older than the Rust sources records the *previous* build's behaviour under
the current commit, and nothing downstream can detect it afterwards. That has
happened here before, which is why `tools/build_guard.py` exists and why this
script will not proceed past it without `--allow-stale`.

Note the packed lanes are deliberately *not* count-ratcheted by the test — their
discovered count is not stable across links — so their numbers are recorded here
for reference only. See `test_realistic_corpus.py` for what is actually asserted.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

import scratch  # noqa: F401  -- points TMPDIR off the shared /tmp tmpfs on import

ROOT = Path(__file__).resolve().parent.parent
BASELINE = ROOT / "tests" / "realistic_corpus" / "discovery_baseline.json"

sys.path.insert(0, str(ROOT / "tests" / "realistic_corpus"))
sys.path.insert(0, str(ROOT / "tools"))


def _build_is_fresh() -> tuple[bool, str]:
    """Whether the built extension is newer than the Rust sources."""
    result = subprocess.run(
        [sys.executable, str(ROOT / "tools" / "build_guard.py")],
        capture_output=True,
        text=True,
        cwd=str(ROOT),
    )
    return result.returncode == 0, (result.stdout + result.stderr).strip()


def measure() -> dict:
    """Build the corpus if needed and measure every variant."""
    import discovery
    import realistic_corpus

    manifest = realistic_corpus.build()
    return {
        "schema": 2,
        "toolchain": manifest["toolchain"],
        "ground_truth_count": len(manifest["ground_truth"]),
        "variants": discovery.report(),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--check",
        action="store_true",
        help="do not write; exit 1 if the committed baseline is stale",
    )
    parser.add_argument(
        "--allow-stale",
        action="store_true",
        help="measure even if the built extension is older than the sources",
    )
    args = parser.parse_args(argv)

    fresh, detail = _build_is_fresh()
    if not fresh and not args.allow_stale:
        print(detail, file=sys.stderr)
        print(
            "\nRefusing to measure against a stale extension: the baseline would "
            "record the previous build's behaviour under this commit, and nothing "
            "downstream could tell. Rebuild with `uv run maturin develop`, or pass "
            "--allow-stale if you know why that is wrong here.",
            file=sys.stderr,
        )
        return 1

    measured = measure()

    if args.check:
        if not BASELINE.exists():
            print(f"{BASELINE} does not exist", file=sys.stderr)
            return 1
        committed = json.loads(BASELINE.read_text())
        if committed == measured:
            print("baseline is current")
            return 0
        print("baseline is STALE:", file=sys.stderr)
        for variant, now in measured["variants"].items():
            was = committed.get("variants", {}).get(variant)
            if was != now:
                print(f"  {variant}: {was} -> {now}", file=sys.stderr)
        return 1

    BASELINE.write_text(json.dumps(measured, indent=2) + "\n")
    print(f"wrote {BASELINE.relative_to(ROOT)}")
    print(f"  ground truth: {measured['ground_truth_count']} functions")
    for variant, counts in measured["variants"].items():
        print(
            f"  {variant:<8} discovered={counts['discovered']:<4} "
            f"named={counts['named']:<4} truth_hit={counts['truth_hit']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
