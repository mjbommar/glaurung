#!/usr/bin/env python3
"""Audit source-CFG definition coverage where DecBench published no source CFG.

The scored parity runner deliberately requires a complete source/decoded/GED
triple. This companion closes the corpus denominator without inventing a score:
it runs the same provider on every stored decompiled C file whose matching
``source_cfgs/<binary>.json`` is absent and compares returned function names to
DecBench's ``// Function:`` definition markers.

Exit 0 means every marked definition was returned and no provider call failed.
Exit 1 means coverage was lost or a provider failed. No-source files are not a
passing GED result; they are an explicitly unscored coverage population.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path
from typing import Any

from source_cfg_parity import PROVIDERS


FUNCTION_MARKER_RE = re.compile(r"^// Function: (.+?) @", re.MULTILINE)


def graph_shape(graph: Any) -> dict[str, int]:
    """Return only stable, provider-independent graph cardinalities."""
    return {"nodes": graph.number_of_nodes(), "edges": graph.number_of_edges()}


def missing_source_inputs(tree: Path, column: str) -> list[tuple[str, str, str, Path]]:
    """Return every stored C file without its binary's published source CFG."""
    prefix = f"{column}_"
    rows: list[tuple[str, str, str, Path]] = []
    for path in sorted(tree.glob(f"*/*/decompiled/{prefix}*.c")):
        opt, project = path.parts[-4], path.parts[-3]
        binary = path.stem.removeprefix(prefix)
        source = tree / opt / project / "source_cfgs" / f"{binary}.json"
        if not source.exists():
            rows.append((opt, project, binary, path))
    return rows


def run(tree: Path, column: str, provider_name: str, details_path: Path) -> dict[str, Any]:
    provider = PROVIDERS[provider_name]()
    inputs = missing_source_inputs(tree, column)
    rows: list[dict[str, Any]] = []
    failures: list[dict[str, str]] = []
    started = time.monotonic()

    for index, (opt, project, binary, path) in enumerate(inputs, 1):
        text = path.read_text()
        marked = set(FUNCTION_MARKER_RE.findall(text))
        call_started = time.monotonic()
        try:
            cfgs = provider.cfgs(text)
        except Exception as exc:  # provider boundary: one file must not void siblings
            cfgs = {}
            failures.append(
                {
                    "opt": opt,
                    "project": project,
                    "binary": binary,
                    "error": f"{type(exc).__name__}: {exc}",
                }
            )
        names = set(cfgs)
        extras = sorted(names - marked)
        row = {
            "opt": opt,
            "project": project,
            "binary": binary,
            "path": str(path),
            "marked": len(marked),
            "covered": len(marked & names),
            "missing": sorted(marked - names),
            "provider_functions": len(names),
            "extras": extras,
            "extra_shapes": {name: graph_shape(cfgs[name]) for name in extras},
            "elapsed_seconds": round(time.monotonic() - call_started, 3),
        }
        rows.append(row)
        print(
            f"progress provider={provider_name} files={index}/{len(inputs)} "
            f"marked={row['marked']} covered={row['covered']} "
            f"missing={len(row['missing'])} extras={len(extras)} binary={binary}",
            file=sys.stderr,
            flush=True,
        )

    details_path.parent.mkdir(parents=True, exist_ok=True)
    details_path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows))
    marked_total = sum(row["marked"] for row in rows)
    covered_total = sum(row["covered"] for row in rows)
    report = {
        "tree": str(tree),
        "column": column,
        "provider": provider_name,
        "files": len(rows),
        "marked_definitions": marked_total,
        "covered_definitions": covered_total,
        "missing_definitions": marked_total - covered_total,
        "provider_functions": sum(row["provider_functions"] for row in rows),
        "extras": sum(len(row["extras"]) for row in rows),
        "provider_failures": failures,
        "elapsed_seconds": round(time.monotonic() - started, 3),
    }
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tree", type=Path)
    parser.add_argument("--provider", choices=sorted(PROVIDERS), required=True)
    parser.add_argument("--column", default="glaurung-229fbb1-clean")
    parser.add_argument("--details-jsonl", type=Path, required=True)
    parser.add_argument("--output-json", type=Path, required=True)
    args = parser.parse_args()

    report = run(args.tree.resolve(), args.column, args.provider, args.details_jsonl)
    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, indent=2, sort_keys=True))
    return int(bool(report["missing_definitions"] or report["provider_failures"]))


if __name__ == "__main__":
    raise SystemExit(main())
