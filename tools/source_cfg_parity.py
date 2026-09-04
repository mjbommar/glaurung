#!/usr/bin/env python3
"""Score a source-CFG provider against DecBench's stored GED values.

This is the primary gate of `docs/design/static-c-analysis/parity-plan.md`
(level L3): for every function with a stored GED value, compute

    vj_ged(published source CFG, provider's CFG of the stored decompiled C)

and compare it with the value DecBench recorded. A provider that reproduces
every cell exactly has a CFG front end indistinguishable from Joern's *as far
as the metric can see* -- which is the parity bar, because the metric reads only
degree sequences and entry/exit flags (`joern-behavior.md` section 2).

The oracle is entirely offline. The published dataset ships Joern's own source
CFGs and the exact decompiled C that produced each stored value, so **no Joern
run is needed** to check a provider. Only the `joern` provider itself spawns a
JVM, and it exists solely to validate that the oracle reproduces its own
recorded numbers.

    # inventory and plumbing only -- no provider, no JVM, no build
    uv run python tools/source_cfg_parity.py <tree> --provider null

    # the real gate, once a front end exists
    uv run python tools/source_cfg_parity.py <tree> --provider glaurung

    # self-check of the oracle: needs the DecBench venv AND spawns a JVM per
    # file, so it is opt-in and slow. Ask before running it.
    DECBENCH_DIR=... uv run python tools/source_cfg_parity.py <tree> \\
        --provider joern --limit 3

Exit codes: 0 only when every stored cell was both covered and reproduced
exactly; 1 on any mismatch **or any coverage loss** -- a front end that silently
produces nothing must never read as a pass, which is the whole point of
separating `uncovered` from `mismatched`; 2 when the tree or a dependency is
missing, so an unrunnable gate is never confused with a failing one.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Callable, Iterator, Protocol

#: A per-function GED cell in an `evaluated/*.toml`.
GED_CELL_RE = re.compile(
    r'^"([^"]+)\.ged\.functions\.([^"]+)" = ([0-9.]+|inf|-inf|nan)', re.MULTILINE
)

#: Mismatch buckets, by absolute difference from the stored value.
DELTA_BUCKETS = (0.5, 1.5, 5.5, 20.5)


class Provider(Protocol):
    """Turns decompiled C text into ``{function name: GED-ready CFG}``."""

    name: str

    def cfgs(self, text: str) -> dict[str, Any]:  # pragma: no cover - interface
        ...


class NullProvider:
    """Produces nothing, so every cell is reported as a coverage miss.

    Its job is to exercise the harness -- the walk, the pairing, the reporting
    -- without any front end existing, which is exactly what Phase 0 of the
    parity plan asks for before any code is written.
    """

    name = "null"

    def cfgs(self, text: str) -> dict[str, Any]:
        return {}


class JoernProvider:
    """pyjoern itself, for validating that the oracle reproduces its own values.

    **Spawns a JVM per file.** `CLAUDE.md` forbids running Joern without being
    asked, so this provider is never the default and should be used with
    ``--limit`` on a small slice.
    """

    name = "joern"

    def cfgs(self, text: str) -> dict[str, Any]:
        import tempfile

        from decbench.utils.cfg import extract_cfgs_from_source

        with tempfile.NamedTemporaryFile(
            "w", suffix=".c", delete=False, dir=os.environ.get("TMPDIR")
        ) as handle:
            handle.write(text)
            path = Path(handle.name)
        try:
            return extract_cfgs_from_source(path, sanitize_decompiled=True)
        finally:
            path.unlink(missing_ok=True)


class GlaurungProvider:
    """Glaurung's own C front end, once it exists.

    Deliberately fails loudly rather than silently scoring zero: a provider that
    quietly returns nothing looks exactly like a front end that lost every
    function, and that ambiguity is what this harness exists to remove.
    """

    name = "glaurung"

    def __init__(self) -> None:
        try:
            import glaurung  # noqa: F401
        except ImportError as exc:  # pragma: no cover - environment dependent
            raise SystemExit(f"glaurung extension not importable: {exc}") from exc
        self._entry = self._resolve()

    @staticmethod
    def _resolve() -> Callable[[str], dict[str, Any]]:
        import glaurung

        for path in ("source_cfg", "csource"):
            module = getattr(glaurung, path, None)
            entry = getattr(module, "cfgs_from_decompiled", None) if module else None
            if entry is not None:
                return entry
        raise SystemExit(
            "no source-CFG entry point on the glaurung extension yet "
            "(expected glaurung.source_cfg.cfgs_from_decompiled). "
            "This is stage S3 of docs/design/static-c-analysis/roadmap.md."
        )

    def cfgs(self, text: str) -> dict[str, Any]:
        return self._entry(text)


PROVIDERS: dict[str, Callable[[], Provider]] = {
    "null": NullProvider,
    "joern": JoernProvider,
    "glaurung": GlaurungProvider,
}


def stored_cells(path: Path, column: str) -> dict[str, float]:
    """The recorded per-function GED values for one binary and one column."""
    cells: dict[str, float] = {}
    for match in GED_CELL_RE.finditer(path.read_text()):
        if match.group(1) != column:
            continue
        try:
            cells[match.group(2)] = float(match.group(3))
        except ValueError:
            continue
    return cells


def triples(tree: Path, column: str) -> Iterator[tuple[Path, Path, Path]]:
    """Yield `(evaluated.toml, source_cfgs.json, decompiled.c)` for each binary.

    Only complete triples are yielded; an incomplete one is a gap in the
    dataset, not a provider failure, and is counted separately by the caller.
    """
    for evaluated in sorted(tree.glob("*/*/evaluated/*.toml")):
        opt, project, stem = evaluated.parts[-4], evaluated.parts[-3], evaluated.stem
        source = tree / opt / project / "source_cfgs" / f"{stem}.json"
        decompiled = tree / opt / project / "decompiled" / f"{column}_{stem}.c"
        if source.exists() and decompiled.exists():
            yield evaluated, source, decompiled


def _bucket(delta: float) -> str:
    for edge in DELTA_BUCKETS:
        if delta <= edge:
            return f"<={int(edge)}"
    return f">{int(DELTA_BUCKETS[-1])}"


def run(
    tree: Path, column: str, provider: Provider, limit: int | None, verbose: bool
) -> dict[str, Any]:
    """Walk the oracle and score `provider` against every stored cell."""
    # `decbench.metrics.vj_ged` is the same cost model on scipy's
    # `linear_sum_assignment`; `cfgutils.similarity.vj_ged` is a pure-Python
    # Munkres. Both are O((n+m)^3), but the constant is the difference between
    # a run that finishes and one that does not: `bash` alone carries 582-,
    # 570- and 490-node published CFGs, and the cfgutils path did not produce
    # a `--limit 3` result in over 20 minutes where scipy takes 5.6 seconds.
    # The scipy one is also what the pipeline used to compute the stored
    # values. They were checked to agree on every one of `update-passwd`'s 48
    # cells before this was changed. The fallback keeps a non-fork checkout,
    # which has no `decbench.metrics.vj_ged`, working.
    try:
        from decbench.metrics.vj_ged import vj_ged
    except ImportError:  # pragma: no cover - depends on which checkout is on the path
        from cfgutils.similarity import vj_ged
    from decbench.metrics.ged import GED_MAX_NODES
    from decbench.publish.cfg_export import rebuild_cfg

    exact = mismatched = uncovered = no_source_cfg = 0
    cells = binaries = 0
    gained = 0
    delta_hist: Counter[str] = Counter()
    worst: list[tuple[float, str, float, float]] = []

    for evaluated, source_path, decompiled_path in triples(tree, column):
        if limit is not None and binaries >= limit:
            break
        binaries += 1
        expected = stored_cells(evaluated, column)
        if not expected:
            continue
        published = json.loads(source_path.read_text())["functions"]
        try:
            produced = provider.cfgs(decompiled_path.read_text(errors="replace"))
        except Exception as exc:  # noqa: BLE001 - a provider crash is a result
            if verbose:
                print(f"  provider failed on {decompiled_path.name}: {exc}")
            produced = {}

        gained += len(set(produced) - set(expected))

        for name, want in expected.items():
            cells += 1
            serialized = published.get(name)
            if serialized is None:
                no_source_cfg += 1
                continue
            ours = produced.get(name)
            if ours is None:
                uncovered += 1
                continue
            got = float(vj_ged(rebuild_cfg(serialized), ours))
            if got == want:
                exact += 1
            else:
                mismatched += 1
                delta = abs(got - want)
                delta_hist[_bucket(delta)] += 1
                worst.append((delta, f"{evaluated.stem}:{name}", want, got))

    worst.sort(key=lambda row: -row[0])
    attempted = exact + mismatched
    return {
        "tree": str(tree),
        "column": column,
        "provider": provider.name,
        "ged_max_nodes": GED_MAX_NODES,
        "binaries": binaries,
        "cells": cells,
        "attempted": attempted,
        "exact": exact,
        "mismatched": mismatched,
        "uncovered": uncovered,
        "no_source_cfg": no_source_cfg,
        "gained": gained,
        "exact_rate": round(exact / attempted, 6) if attempted else 0.0,
        "delta_histogram": dict(sorted(delta_hist.items())),
        "worst": [
            {"function": name, "expected": want, "got": got, "delta": delta}
            for delta, name, want, got in worst[:20]
        ],
    }


def default_column(tree: Path) -> str | None:
    """The decompiler column with the most stored GED cells."""
    counts: Counter[str] = Counter()
    for path in sorted(tree.glob("*/*/evaluated/*.toml")):
        for match in GED_CELL_RE.finditer(path.read_text()):
            counts[match.group(1)] += 1
    return counts.most_common(1)[0][0] if counts else None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("tree", type=Path, help="materialized DecBench tree root")
    parser.add_argument(
        "--provider", choices=sorted(PROVIDERS), default="null", help="CFG source"
    )
    parser.add_argument("--column", default=None, help="decompiler column to score")
    parser.add_argument("--limit", type=int, default=None, help="stop after N binaries")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    parser.add_argument("--verbose", action="store_true", help="report provider errors")
    args = parser.parse_args()

    if not args.tree.is_dir():
        print(f"no tree at {args.tree}", file=sys.stderr)
        return 2
    column = args.column or default_column(args.tree)
    if column is None:
        print(f"no stored GED cells under {args.tree}", file=sys.stderr)
        return 2

    try:
        report = run(
            args.tree, column, PROVIDERS[args.provider](), args.limit, args.verbose
        )
    except ImportError as exc:
        print(
            f"needs the DecBench venv for cfgutils/decbench ({exc}). "
            "Run under $DECBENCH_DIR/.venv/bin/python.",
            file=sys.stderr,
        )
        return 2

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"tree        {report['tree']}")
        print(f"column      {report['column']}   provider {report['provider']}")
        print(f"binaries    {report['binaries']}")
        print(f"cells       {report['cells']} stored")
        print(f"  attempted {report['attempted']}")
        print(f"  exact     {report['exact']}  ({report['exact_rate']:.4%})")
        print(f"  mismatch  {report['mismatched']}")
        print(f"  uncovered {report['uncovered']}  (provider produced no CFG)")
        print(f"  no source {report['no_source_cfg']}  (dataset gap, not a failure)")
        print(f"  gained    {report['gained']}  (functions Joern did not produce)")
        if report["delta_histogram"]:
            print("mismatch by |delta|")
            for bucket, count in report["delta_histogram"].items():
                print(f"  {bucket:<8} {count}")
        for row in report["worst"][:10]:
            print(
                f"  worst {row['function']}: expected {row['expected']}, "
                f"got {row['got']} (delta {row['delta']})"
            )
    # Coverage loss fails the gate as hard as a wrong value: a provider that
    # produced nothing would otherwise exit 0 having proved nothing at all.
    return 1 if report["mismatched"] or report["uncovered"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
