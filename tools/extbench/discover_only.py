#!/usr/bin/env python3
"""Function-discovery counts only, for binaries with no sound reference.

    discover_only.py <binary>

`busybox` is the largest musl sample here and the one where Glaurung's discovery
looked worst, but it ships with a 4-byte `.eh_frame` and no symbols, so there is
nothing to score recall against. What can still be compared is how many
functions each tool believes exist — and, more usefully, how much the four
agree. Three independent tools converging on a count that a fourth misses by an
order of magnitude is evidence even without ground truth; it is reported as
agreement, never as accuracy.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
from config import DECBENCH_PY, GHIDRA_DIR, GLAURUNG_BIN, RETDEC_BIN


def run(cmd: list[str], timeout: int = 1800) -> None:
    subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def main() -> int:
    binary = sys.argv[1]
    with tempfile.TemporaryDirectory() as td:
        out = Path(td)
        jobs = [
            (
                "glaurung",
                [
                    sys.executable,
                    str(HERE / "run_glaurung.py"),
                    GLAURUNG_BIN,
                    binary,
                    str(out / "g.json"),
                    "--vas",
                    "0x0",
                ],
            ),
            (
                "ghidra",
                [
                    DECBENCH_PY,
                    str(HERE / "run_ghidra.py"),
                    GHIDRA_DIR,
                    binary,
                    str(out / "gh.json"),
                    "--vas",
                    "0x0",
                ],
            ),
            (
                "angr",
                [
                    DECBENCH_PY,
                    str(HERE / "run_angr.py"),
                    binary,
                    str(out / "a.json"),
                    "--vas",
                    "0x0",
                ],
            ),
            (
                "retdec",
                [
                    sys.executable,
                    str(HERE / "run_retdec.py"),
                    RETDEC_BIN,
                    binary,
                    str(out / "r.json"),
                ],
            ),
        ]
        files = {
            "glaurung": "g.json",
            "ghidra": "gh.json",
            "angr": "a.json",
            "retdec": "r.json",
        }
        sets = {}
        for name, cmd in jobs:
            try:
                run(cmd)
                d = json.loads((out / files[name]).read_text())
                sets[name] = {x["va"] for x in d.get("discovered", [])}
                print(f"{name:9s} discovered {len(sets[name]):6d}")
            except Exception as exc:
                print(f"{name:9s} FAILED: {type(exc).__name__}: {exc}")

        if len(sets) >= 2:
            print("\npairwise overlap (|A∩B| / |A∪B|):")
            names = list(sets)
            for i, a in enumerate(names):
                for b in names[i + 1 :]:
                    u = sets[a] | sets[b]
                    print(
                        f"  {a:9s} vs {b:9s} "
                        f"{len(sets[a] & sets[b]) / len(u):.2f}"
                        f"   shared={len(sets[a] & sets[b])}"
                    )
            # Where three of four agree, the fourth is the outlier.
            from collections import Counter

            votes = Counter(va for s in sets.values() for va in s)
            consensus = {va for va, n in votes.items() if n >= 3}
            print(f"\nfunctions ≥3 tools agree on: {len(consensus)}")
            for name, s in sets.items():
                print(
                    f"  {name:9s} covers {len(s & consensus):6d} "
                    f"({100 * len(s & consensus) / max(1, len(consensus)):.0f}%)"
                )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
