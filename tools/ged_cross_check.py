#!/usr/bin/env python3
"""Differential: Glaurung's graph edit distance against the reference, on real CFGs.

`src/syntax/ged.rs` is checked in-tree against 124 vectors recorded from
`cfgutils.similarity.vj_ged` and against exhaustive permutation search on small
matrices. Both are exact, and both are inputs we chose. This checks the same
code against the **live reference** over thousands of degree sequences we did
not choose -- every function of a materialized DecBench tree.

It is a two-step differential because the two implementations live in different
runtimes and neither should gain a dependency on the other:

1. `cargo test --test source_cfg_ged` writes our value for each real pair to a
   JSON file, driven by `GLAURUNG_GED_DUMP`.
2. This tool rebuilds the same pairs from the same published CFGs, computes the
   reference value with `vj_ged`, and diffs.

    DECBENCH_DIR=/nas4/data/workspace-infosec/decbench \\
    PYTHONPATH=$DECBENCH_DIR $DECBENCH_DIR/.venv/bin/python \\
        tools/ged_cross_check.py ~/.cache/glaurung/decbench-full/tree --run

`--run` performs step 1 for you; without it, pass `--dump` naming a file step 1
already wrote.

Exit codes: 0 every compared pair agreed; 1 at least one disagreed; 2 the tree,
the dump or a dependency is missing, so an unrunnable check is never confused
with a failing one.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

#: How many `source_cfgs/*.json` files the Rust dump walks. Must match the
#: `corpus(80)` call in `tests/source_cfg_ged.rs::dump_real_pair_distances_for_the_cross_check`,
#: or the two sides pair up different functions and every row mismatches.
CFG_FILE_LIMIT = 80


def cfg_files(root: Path, limit: int) -> list[Path]:
    """The same files, in the same order, as the Rust side walks.

    The Rust side pushes directories onto a stack and sorts each directory's
    entries, so it yields a deterministic order; this reproduces it rather than
    assuming `rglob` agrees.
    """
    found: list[Path] = []
    stack = [root]
    while stack:
        directory = stack.pop()
        try:
            entries = sorted(directory.iterdir())
        except OSError:
            continue
        for path in entries:
            if path.is_dir():
                stack.append(path)
            elif path.suffix == ".json" and path.parent.name == "source_cfgs":
                found.append(path)
                if len(found) >= limit:
                    return found
    return found


def graphs(root: Path, limit: int) -> list[tuple[str, Any]]:
    """`(key, rebuilt CFG)` for every published function, in the Rust side's order."""
    from decbench.publish.cfg_export import rebuild_cfg

    out: list[tuple[str, Any]] = []
    for path in cfg_files(root, limit):
        try:
            data = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        binary = data.get("binary", "?")
        for name, func in sorted(data.get("functions", {}).items()):
            out.append((f"{binary}:{name}", rebuild_cfg(func)))
    return out


def run_rust_dump(root: Path, dump: Path) -> bool:
    """Run the Rust dump test. Returns whether it produced a file."""
    env = dict(
        os.environ, GLAURUNG_DECBENCH_TREE=str(root), GLAURUNG_GED_DUMP=str(dump)
    )
    proc = subprocess.run(
        [
            "cargo",
            "test",
            "--features",
            "python-ext",
            "--test",
            "source_cfg_ged",
            "dump_real_pair_distances",
            "--",
            "--nocapture",
        ],
        env=env,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        print(proc.stderr[-3000:], file=sys.stderr)
    return dump.is_file()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("tree", type=Path, help="materialized DecBench tree root")
    parser.add_argument(
        "--dump", type=Path, default=None, help="JSON from the Rust side"
    )
    parser.add_argument("--run", action="store_true", help="produce the dump first")
    parser.add_argument("--limit", type=int, default=CFG_FILE_LIMIT)
    parser.add_argument("--show", type=int, default=10, help="mismatches to print")
    args = parser.parse_args()

    root = args.tree.expanduser()
    if not root.is_dir():
        print(f"no tree at {root}", file=sys.stderr)
        return 2

    dump = args.dump
    if args.run:
        scratch = Path(os.environ.get("TMPDIR", "/tmp"))
        dump = dump or scratch / "ged_dump.json"
        if not run_rust_dump(root, dump):
            print("the Rust dump produced no file", file=sys.stderr)
            return 2
    if dump is None or not dump.is_file():
        print(
            "pass --run, or --dump naming a file the Rust side wrote", file=sys.stderr
        )
        return 2

    try:
        from cfgutils.similarity import vj_ged
    except ImportError as exc:
        print(f"needs the DecBench venv for cfgutils ({exc})", file=sys.stderr)
        return 2

    ours = json.loads(dump.read_text())
    theirs = graphs(root, args.limit)
    by_key = {key: graph for key, graph in theirs}

    agreed = disagreed = unmatched = approximated = 0
    worst: list[tuple[float, str, float, float]] = []
    for row in ours:
        # The reference cannot express the node-cap fallback: above the cap our
        # value is |dnodes| + |dedges| by design, not an assignment result, so
        # comparing it against vj_ged would be comparing two different formulas.
        if row.get("approximated"):
            approximated += 1
            continue
        left, right = by_key.get(row["a"]), by_key.get(row["b"])
        if left is None or right is None:
            unmatched += 1
            continue
        want = float(vj_ged(left, right))
        got = float(row["value"])
        if want == got:
            agreed += 1
        else:
            disagreed += 1
            worst.append((abs(want - got), f"{row['a']} vs {row['b']}", want, got))

    worst.sort(key=lambda r: -r[0])
    total = agreed + disagreed
    print(f"pairs in dump   {len(ours)}")
    print(f"  compared      {total}")
    print(f"  agreed        {agreed}" + (f"  ({agreed / total:.4%})" if total else ""))
    print(f"  disagreed     {disagreed}")
    print(
        f"  skipped       {approximated} above the node cap, {unmatched} unmatched keys"
    )
    for delta, pair, want, got in worst[: args.show]:
        print(f"  {pair}: reference {want}, ours {got} (delta {delta})")
    return 1 if disagreed else 0


if __name__ == "__main__":
    raise SystemExit(main())
