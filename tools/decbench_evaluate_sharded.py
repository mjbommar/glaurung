#!/usr/bin/env python3
"""Evaluate a DecBench tree by sharding across (opt, project) pairs.

WHY. `decbench evaluate-tree` walks (opt, project) groups SERIALLY and
parallelizes only over the binaries inside one group (`pipeline/evaluate.py`,
the `ProcessPoolExecutor` over `decompilations.items()`). With a single
decompiler column, a project holding one binary -- `betaflight`, `tar`,
`u-boot`, most of the corpus -- runs strictly serial no matter what `-j` says.
Wall-clock becomes the SUM of 117 groups' slowest binaries. Measured on this
corpus: three projects in two hours, extrapolating past sixty.

The corpus has 39 projects x 3 optimization levels, and every group writes only
to `<opt>/<project>/evaluated/`. Those paths are disjoint, so the groups are
embarrassingly parallel -- the serialization is in the driver, not the work.

This shards at that boundary WITHOUT touching the pinned decbench: each shard is
a directory of symlinks holding exactly one (opt, project), and `evaluate-tree`
runs against it unmodified. Symlinks resolve to the real tree, so results land
where they would have anyway, and the scoring code, its version, and its
`perfect_values` are identical. What changes is only which process runs which
group.

Concurrent shards never contend: two processes writing the same directory is
what produced the empty-result failures documented in
`tools/decbench_evaluate_verified.py`, and disjoint paths are exactly what
avoids it. Run `decbench_evaluate_verified.py` afterwards to certify coverage.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

#: Every group writes only under its own `<opt>/<project>/`, so a shard needs
#: exactly that subtree plus the sibling inputs `evaluate-tree` reads.
LINKED = ("compiled", "decompiled", "source_cfgs", "evaluated")


def groups(tree: Path) -> list[tuple[str, str]]:
    """Every (opt, project) pair the tree holds decompiled artifacts for."""
    seen = set()
    for art in tree.glob("*/*/decompiled/*"):
        project_dir = art.parent.parent
        seen.add((project_dir.parent.name, project_dir.name))
    return sorted(seen)


def run_shard(args: tuple[str, str, str, str, str]) -> tuple[str, str, int, float]:
    opt, project, tree_s, decbench_s, shard_root_s = args
    tree, decbench = Path(tree_s), Path(decbench_s)
    shard = Path(shard_root_s) / f"{opt}__{project}"
    (shard / opt / project).mkdir(parents=True, exist_ok=True)
    for name in LINKED:
        src = tree / opt / project / name
        if name == "evaluated":
            src.mkdir(parents=True, exist_ok=True)
        if src.exists():
            link = shard / opt / project / name
            if not link.exists():
                link.symlink_to(src.resolve(), target_is_directory=True)
    started = time.time()
    # No `-m`: the default is ALL metrics, and the published Union is over
    # ged AND type_match AND byte_match. `--no-parallel` because the outer
    # level is already saturating the machine.
    done = subprocess.run(
        [
            str(decbench),
            "evaluate-tree",
            str(shard),
            "-d",
            os.environ["DECBENCH_COLUMN"],
            "--no-parallel",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    return opt, project, done.returncode, time.time() - started


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("tree", type=Path)
    ap.add_argument("--decompiler", required=True)
    ap.add_argument("--decbench", type=Path, required=True)
    ap.add_argument("--jobs", type=int, default=12)
    ap.add_argument("--shard-root", type=Path, default=None)
    args = ap.parse_args()

    os.environ["DECBENCH_COLUMN"] = args.decompiler
    shard_root = args.shard_root or (args.tree.parent / "shards")
    if shard_root.exists():
        shutil.rmtree(shard_root)
    shard_root.mkdir(parents=True)

    todo = groups(args.tree)
    print(f"{len(todo)} (opt, project) groups, {args.jobs} concurrent", flush=True)

    started, done_n = time.time(), 0
    payload = [
        (o, p, str(args.tree), str(args.decbench), str(shard_root)) for o, p in todo
    ]
    with ProcessPoolExecutor(max_workers=args.jobs) as ex:
        futures = [ex.submit(run_shard, item) for item in payload]
        for fut in as_completed(futures):
            opt, project, rc, secs = fut.result()
            done_n += 1
            flag = "" if rc == 0 else f"  <- EXIT {rc}"
            print(
                f"  [{done_n}/{len(todo)}] {opt}/{project} {secs:.0f}s"
                f"  (elapsed {time.time() - started:.0f}s){flag}",
                flush=True,
            )

    print(f"\nall groups finished in {time.time() - started:.0f}s")
    print("Now run tools/decbench_evaluate_verified.py to certify coverage.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
