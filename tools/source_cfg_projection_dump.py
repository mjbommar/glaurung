#!/usr/bin/env python3
"""Dump the parity projection of every function in the in-repo C corpora.

One JSON object, keyed `<path>::<function>`, holding exactly what
`glaurung._native.csource.parity_cfgs` returns (nodes, edges, entry, exit,
degenerate). Two dumps from two builds of the extension diff by function, which
is how the cindergraph migration measured the projection with no DecBench tree
on the host (docs/development/cindergraph-migration-2026-09-17.md): 930
functions, 42 different -- 41 the crate's short-circuit loop-header elision,
one its computed-goto dispatch modelling.

    uv run python tools/source_cfg_projection_dump.py before.json   # old build
    uv run maturin develop --release --features python-ext,symbolic
    uv run python tools/source_cfg_projection_dump.py after.json
    uv run python tools/source_cfg_projection_dump.py --diff before.json after.json

The corpora are fixed so the two sides always have the same denominator; a
function present on one side only is reported, never dropped.
"""

from __future__ import annotations

import argparse
import glob
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
CORPORA = (
    "tests/decbench_corpus/src/*.c",
    "tests/decompiler_fixtures/src/*.c",
    "tests/decompiler_output_canaries/**/*.c",
)


def dump() -> dict[str, Any]:
    from glaurung import _native

    out: dict[str, Any] = {}
    for pattern in CORPORA:
        for path in sorted(glob.glob(str(ROOT / pattern), recursive=True)):
            text = Path(path).read_text(errors="replace")
            relative = str(Path(path).relative_to(ROOT))
            for name, cfg in _native.csource.parity_cfgs(text).items():
                out[f"{relative}::{name}"] = cfg
    return out


def diff(before: dict[str, Any], after: dict[str, Any]) -> int:
    only_before = sorted(set(before) - set(after))
    only_after = sorted(set(after) - set(before))
    changed = sorted(k for k in before if k in after and before[k] != after[k])
    print(
        f"before {len(before)}  after {len(after)}  only-before {len(only_before)}  "
        f"only-after {len(only_after)}  changed {len(changed)}"
    )
    for key in only_before:
        print(f"  only-before  {key}")
    for key in only_after:
        print(f"  only-after   {key}")
    for key in changed:
        b, a = before[key], after[key]
        print(
            f"  changed      {key}  nodes {len(b['nodes'])} -> {len(a['nodes'])}  "
            f"edges {len(b['edges'])} -> {len(a['edges'])}"
        )
    return 1 if (only_before or only_after or changed) else 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "paths", nargs="+", help="output path, or with --diff two dumps"
    )
    parser.add_argument("--diff", action="store_true", help="compare two dumps instead")
    args = parser.parse_args(argv)
    if args.diff:
        if len(args.paths) != 2:
            parser.error("--diff takes exactly two dump paths")
        before = json.loads(Path(args.paths[0]).read_text())
        after = json.loads(Path(args.paths[1]).read_text())
        return diff(before, after)
    if len(args.paths) != 1:
        parser.error("one output path")
    out = dump()
    Path(args.paths[0]).write_text(json.dumps(out, sort_keys=True))
    print(f"{len(out)} functions -> {args.paths[0]}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
