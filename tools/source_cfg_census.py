#!/usr/bin/env python3
"""Census of the Joern-derived source CFGs in a materialized DecBench tree.

The published dataset ships, per binary, a `source_cfgs/<stem>.json` holding the
`function -> CFG` map that DecBench's GED metric scores that binary against.
Those files are the only committed record of what Joern produces, and they are
the ground truth a Glaurung source-CFG front end has to reproduce
(`docs/design/static-c-analysis/`).

This tool reads that record and nothing else. It runs no decompiler, spawns no
JVM, and writes nothing into the tree.

    uv run python tools/source_cfg_census.py ~/.cache/glaurung/decbench-full/tree
    uv run python tools/source_cfg_census.py <tree> --json

Serialization contract (DecBench `decbench/publish/cfg_export.py`), per function:

    {"nodes": [int], "edges": [[int, int]], "labels": {"<i>": "<str(Block)>"},
     "entry": [int], "exit": [int], "degenerate": bool}

`labels` is provenance only -- `cfgutils.similarity.vj_ged` never reads it --
but it carries the pyjoern JIL statement dump per block, which is what makes a
statement-level comparison possible at all.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any

#: `decbench.metrics.ged.GED_MAX_NODES` default: above this the metric stops
#: solving the assignment problem and returns |dnodes| + |dedges| instead.
GED_MAX_NODES = 60

#: A per-function GED cell in an `evaluated/*.toml`: `"<column>.ged.functions.<name>" = <float>`.
GED_CELL_RE = re.compile(
    r'^"([^"]+)\.ged\.functions\.([^"]+)" = ([0-9.einf+-]+)', re.MULTILINE
)


def _statement_lines(label: str) -> list[str]:
    """The JIL statement lines of one serialized block.

    `pyjoern.cfg.jil.block.Block.__str__` writes `"<addr><.idx>:\\n"` and then one
    line per statement, so the head line is the block address, not a statement.
    """
    return [line for line in label.split("\n")[1:] if line]


def _classify(line: str) -> str:
    """Bucket one JIL statement line by the pyjoern class that printed it."""
    if line.startswith("<UnsupportedStmt"):
        return "UnsupportedStmt"
    if line.startswith("<UnknownStmt"):
        return "UnknownStmt"
    if line.startswith("<MergedRegionStart"):
        return "MergedRegionStart"
    if line == "FUNCTION_START":
        return "Nop.FUNC_START"
    if line == "FUNCTION_END":
        return "Nop.FUNC_END"
    if line == "NOP":
        return "Nop.NOP"
    if line.startswith("return "):
        return "Return"
    if " = " in line:
        return "Assignment"
    return "other"


def census(tree: Path) -> dict[str, Any]:
    """Walk `<tree>/<opt>/<project>/source_cfgs/*.json` and summarize."""
    files = sorted(tree.glob("*/*/source_cfgs/*.json"))
    functions = 0
    nodes = edges = 0
    degenerate = 0
    no_entry = no_exit = 0
    multi_entry = multi_exit = 0
    over_max_nodes = 0
    by_opt: Counter[str] = Counter()
    node_buckets: Counter[str] = Counter()
    statements: Counter[str] = Counter()
    statement_lines = 0

    for path in files:
        data = json.loads(path.read_text())
        opt = data.get("opt") or path.parts[-4]
        for func in data["functions"].values():
            functions += 1
            by_opt[opt] += 1
            count = len(func["nodes"])
            nodes += count
            edges += len(func["edges"])
            if func.get("degenerate"):
                degenerate += 1
            if not func["entry"]:
                no_entry += 1
            elif len(func["entry"]) > 1:
                multi_entry += 1
            if not func["exit"]:
                no_exit += 1
            elif len(func["exit"]) > 1:
                multi_exit += 1
            if count > GED_MAX_NODES:
                over_max_nodes += 1
            node_buckets[_bucket(count)] += 1
            for label in func["labels"].values():
                for line in _statement_lines(label):
                    statement_lines += 1
                    statements[_classify(line)] += 1

    return {
        "tree": str(tree),
        "binaries": len(files),
        "functions": functions,
        "nodes": nodes,
        "edges": edges,
        "mean_nodes": round(nodes / functions, 4) if functions else 0.0,
        "mean_edges": round(edges / functions, 4) if functions else 0.0,
        "degenerate": degenerate,
        "no_entry": no_entry,
        "no_exit": no_exit,
        "multi_entry": multi_entry,
        "multi_exit": multi_exit,
        "over_ged_max_nodes": over_max_nodes,
        "ged_max_nodes": GED_MAX_NODES,
        "functions_by_opt": dict(sorted(by_opt.items())),
        "node_count_buckets": dict(sorted(node_buckets.items(), key=_bucket_key)),
        "statement_lines": statement_lines,
        "statement_kinds": dict(statements.most_common()),
    }


def _bucket(count: int) -> str:
    for lo, hi in ((1, 1), (2, 3), (4, 7), (8, 15), (16, 31), (32, 60)):
        if lo <= count <= hi:
            return f"{lo}-{hi}" if lo != hi else "1"
    return ">60"


def _bucket_key(item: tuple[str, int]) -> int:
    head = item[0].lstrip(">").split("-")[0]
    return int(head) + (1000 if item[0].startswith(">") else 0)


def ged_cells(tree: Path) -> dict[str, int]:
    """Per-column count of stored per-function GED values in `evaluated/*.toml`.

    These are the expected values a reimplementation has to reproduce: each one
    is `vj_ged(published source CFG, Joern's CFG of the stored decompiled C)`.
    """
    columns: Counter[str] = Counter()
    for path in sorted(tree.glob("*/*/evaluated/*.toml")):
        for match in GED_CELL_RE.finditer(path.read_text()):
            columns[match.group(1)] += 1
    return dict(columns.most_common())


def pairing(tree: Path, column: str) -> dict[str, Any]:
    """How many binaries carry a complete (source CFG, decompiled C, GED) triple."""
    complete = missing_source = missing_decompiled = 0
    for path in sorted(tree.glob("*/*/evaluated/*.toml")):
        opt, project, _, stem = (
            path.parts[-4],
            path.parts[-3],
            path.parts[-2],
            path.stem,
        )
        source = tree / opt / project / "source_cfgs" / f"{stem}.json"
        decompiled = tree / opt / project / "decompiled" / f"{column}_{stem}.c"
        if not source.exists():
            missing_source += 1
        elif not decompiled.exists():
            missing_decompiled += 1
        else:
            complete += 1
    return {
        "column": column,
        "complete": complete,
        "missing_source_cfgs": missing_source,
        "missing_decompiled": missing_decompiled,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("tree", type=Path, help="materialized DecBench tree root")
    parser.add_argument("--json", action="store_true", help="emit the report as JSON")
    parser.add_argument(
        "--column",
        default=None,
        help="decompiler column to check pairing for (default: the one with the most GED cells)",
    )
    args = parser.parse_args()

    if not args.tree.is_dir():
        print(f"no tree at {args.tree}", file=sys.stderr)
        return 2

    report = census(args.tree)
    report["ged_cells_by_column"] = ged_cells(args.tree)
    column = args.column or next(iter(report["ged_cells_by_column"]), None)
    if column is not None:
        report["pairing"] = pairing(args.tree, column)

    if args.json:
        print(json.dumps(report, indent=2))
        return 0

    print(f"tree           {report['tree']}")
    print(f"binaries       {report['binaries']}")
    print(f"functions      {report['functions']}")
    print(f"nodes / edges  {report['nodes']} / {report['edges']}")
    print(f"mean nodes     {report['mean_nodes']} (edges {report['mean_edges']})")
    print(f"degenerate     {report['degenerate']}")
    print(f"no entry flag  {report['no_entry']}   multi-entry {report['multi_entry']}")
    print(f"no exit flag   {report['no_exit']}   multi-exit {report['multi_exit']}")
    print(f"> {report['ged_max_nodes']} nodes      {report['over_ged_max_nodes']}")
    print(
        "functions by opt "
        + ", ".join(f"{k}={v}" for k, v in report["functions_by_opt"].items())
    )
    print(
        "node buckets     "
        + ", ".join(f"{k}={v}" for k, v in report["node_count_buckets"].items())
    )
    print(f"statement lines  {report['statement_lines']}")
    for kind, count in report["statement_kinds"].items():
        share = (
            100 * count / report["statement_lines"] if report["statement_lines"] else 0
        )
        print(f"  {kind:<20} {count:>9}  {share:5.1f}%")
    print("GED cells by column")
    for name, count in report["ged_cells_by_column"].items():
        print(f"  {name:<28} {count}")
    if "pairing" in report:
        pair = report["pairing"]
        print(
            f"pairing ({pair['column']}): complete={pair['complete']} "
            f"missing_source_cfgs={pair['missing_source_cfgs']} "
            f"missing_decompiled={pair['missing_decompiled']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
