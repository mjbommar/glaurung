"""Measure C source files: `glaurung source-metrics`.

Three shapes of output, because the use cases want different things:

* a **table**, sorted by one metric, for looking at a file or a tree and
  deciding what to read first;
* **JSON**, the full report, for a dashboard or a diff between two builds;
* **CSV**, the fixed-width feature matrix, for a corpus-scale consumer.

Plus a threshold mode that exits non-zero, so the command can be a CI gate
rather than only a report.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Iterable

import glaurung as g

from .base import BaseCommand
from ..formatters.base import BaseFormatter, OutputFormat

#: Metrics the table can be sorted by and thresholded on.
SORT_KEYS = (
    "cognitive",
    "cyclomatic",
    "max_nesting",
    "max_loop_depth",
    "lines",
    "code_lines",
    "tokens",
    "statements",
    "calls",
    "parameters",
    "decision_points",
    "loops",
    "unreachable_statements",
    "halstead_volume",
    "halstead_difficulty",
    "halstead_effort",
)


class SourceMetricsCommand(BaseCommand):
    """Report complexity and size metrics for C source files."""

    def get_name(self) -> str:
        """Return the command name."""
        return "source-metrics"

    def get_help(self) -> str:
        """Return the command help text."""
        return "Measure C source: complexity, nesting, size, Halstead"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        """Add command-specific arguments."""
        parser.add_argument(
            "paths",
            nargs="+",
            help="C files, or directories to search for *.c and *.h",
        )
        parser.add_argument(
            "--dialect",
            choices=["preprocessed", "decompiled"],
            default=None,
            help=(
                "Normalize before parsing: 'preprocessed' for a gcc .i unit, "
                "'decompiled' for a decompiler's output. Note that "
                "'preprocessed' strips everything not under a user-file line "
                "marker, so it empties an ordinary .c file"
            ),
        )
        parser.add_argument(
            "--sort",
            choices=SORT_KEYS,
            default="cognitive",
            help="Metric to rank functions by (default: cognitive)",
        )
        parser.add_argument(
            "--limit",
            type=int,
            default=20,
            help="How many functions to show; 0 means all (default: 20)",
        )
        parser.add_argument(
            "--summary",
            action="store_true",
            help="Print one aggregate line per file instead of a function table",
        )
        parser.add_argument(
            "--csv",
            action="store_true",
            help="Emit the fixed-width feature matrix as CSV instead of a table",
        )
        parser.add_argument(
            "--fail-over",
            metavar="METRIC=N",
            action="append",
            default=[],
            help=(
                "Exit 1 if any function exceeds N for METRIC, and list the "
                "offenders. Repeatable, e.g. --fail-over cyclomatic=25 "
                "--fail-over max_nesting=5"
            ),
        )

    def execute(self, args: argparse.Namespace, formatter: BaseFormatter) -> int:
        """Measure every named file and report."""
        try:
            thresholds = _parse_thresholds(args.fail_over)
        except ValueError as error:
            formatter.output_plain(f"Error: {error}")
            return 2

        paths = list(_expand(args.paths))
        if not paths:
            formatter.output_plain("Error: no C source files found")
            return 2

        reports = []
        for path in paths:
            try:
                reports.append(g.source.analyze_path(path, dialect=args.dialect))
            except OSError as error:
                # Unreadable file: report it and keep going. One bad path must
                # not void a tree-wide run.
                formatter.output_plain(f"Error: {path}: {error}", stream=sys.stderr)
        if not reports:
            return 2

        if args.csv:
            _emit_csv(reports)
        elif args.summary and formatter.format_type == OutputFormat.JSON:
            print(json.dumps([report.summary() for report in reports], indent=2))
        elif args.summary:
            _emit_summary(formatter, reports)
        elif formatter.format_type == OutputFormat.JSON:
            payload = [{"path": report.name, **report.to_dict()} for report in reports]
            print(json.dumps(payload, indent=2))
        else:
            _emit_table(formatter, reports, args.sort, args.limit)

        return _check_thresholds(formatter, reports, thresholds)


def _expand(paths: Iterable[str]) -> list[Path]:
    """Every C file named, with directories searched recursively.

    Returns paths sorted, so a run over a tree is reproducible and two runs can
    be diffed.
    """
    found: list[Path] = []
    for raw in paths:
        path = Path(raw)
        if path.is_dir():
            found.extend(p for p in path.rglob("*.c") if p.is_file())
            found.extend(p for p in path.rglob("*.h") if p.is_file())
        elif path.is_file():
            found.append(path)
    return sorted(set(found))


def _parse_thresholds(raw: list[str]) -> list[tuple[str, float]]:
    """Parse `--fail-over METRIC=N` pairs.

    Raises:
        ValueError: On a malformed pair or an unknown metric. Silently ignoring
            either would turn a CI gate into a no-op that still exits 0, which
            is the worst possible failure for a gate.
    """
    parsed: list[tuple[str, float]] = []
    for item in raw:
        metric, separator, value = item.partition("=")
        if not separator:
            raise ValueError(f"--fail-over wants METRIC=N, got {item!r}")
        if metric not in SORT_KEYS:
            raise ValueError(
                f"unknown metric {metric!r}; expected one of {', '.join(SORT_KEYS)}"
            )
        try:
            parsed.append((metric, float(value)))
        except ValueError:
            raise ValueError(f"--fail-over {metric} wants a number, got {value!r}")
    return parsed


def _emit_table(formatter: BaseFormatter, reports: list, sort: str, limit: int) -> None:
    """Print one ranked table across every file measured."""
    functions = [(report, f) for report in reports for f in report.functions]
    functions.sort(key=lambda pair: (-getattr(pair[1], sort), pair[1].name))
    shown = functions if limit <= 0 else functions[:limit]

    total_lines = sum(report.lines for report in reports)
    formatter.output_plain(
        f"{len(reports)} file(s), {total_lines} lines, {len(functions)} function(s); "
        f"top {len(shown)} by {sort}"
    )
    formatter.output_plain(
        f"{'function':<34} {'cyc':>4} {'cog':>4} {'nest':>4} {'loops':>5} "
        f"{'lines':>5} {'calls':>5}  location"
    )
    for report, f in shown:
        where = f"{report.name}:{f.first_line}"
        formatter.output_plain(
            f"{f.name[:34]:<34} {f.cyclomatic:>4} {f.cognitive:>4} "
            f"{f.max_nesting:>4} {f.loops:>5} {f.lines:>5} {f.calls:>5}  {where}"
        )


def _emit_summary(formatter: BaseFormatter, reports: list) -> None:
    """Print one aggregate line per file, plus a total.

    The whole-tree view: which files carry the complexity, how much of it is
    unstructured, and where the dead code is.
    """
    formatter.output_plain(
        f"{'file':<52} {'fns':>4} {'lines':>6} {'maxcyc':>6} {'maxcog':>6} "
        f"{'goto':>5} {'dead':>5}"
    )
    totals = {"functions": 0, "lines": 0, "gotos": 0, "unreachable_statements": 0}
    for report in reports:
        summary = report.summary()
        distributions = summary["distributions"]
        max_cyclomatic = distributions["cyclomatic"]["max"] if distributions else 0
        max_cognitive = distributions["cognitive"]["max"] if distributions else 0
        name = str(summary["name"] or "<unnamed>")
        formatter.output_plain(
            f"{name[-52:]:<52} {summary['functions']:>4} {summary['lines']:>6} "
            f"{max_cyclomatic:>6.0f} {max_cognitive:>6.0f} {summary['gotos']:>5} "
            f"{summary['unreachable_statements']:>5}"
        )
        for key in totals:
            totals[key] += summary[key]
    formatter.output_plain(
        f"{'TOTAL':<52} {totals['functions']:>4} {totals['lines']:>6} "
        f"{'':>6} {'':>6} {totals['gotos']:>5} "
        f"{totals['unreachable_statements']:>5}"
    )


def _emit_csv(reports: list) -> None:
    """Write the feature matrix, one row per function, to stdout.

    Rows come from `report.source`, which is the *normalized* text when
    `--dialect` was given -- the same string the report's offsets address, so a
    CSV row and a JSON report of the same run describe the same bytes.
    """
    names = list(g.source.feature_names())
    writer = csv.writer(sys.stdout)
    writer.writerow(["path", "function", *names])
    for report in reports:
        for name, row in g.source.features(report.source):
            writer.writerow([report.name, name, *row])


def _check_thresholds(
    formatter: BaseFormatter, reports: list, thresholds: list[tuple[str, float]]
) -> int:
    """Report every function over a threshold and return the exit code."""
    if not thresholds:
        return 0
    offenders = []
    for report in reports:
        for f in report.functions:
            for metric, limit in thresholds:
                value = getattr(f, metric)
                if value > limit:
                    offenders.append((report.name, f, metric, value, limit))
    if not offenders:
        return 0
    formatter.output_plain("", stream=sys.stderr)
    formatter.output_plain(
        f"{len(offenders)} threshold violation(s):", stream=sys.stderr
    )
    for path, f, metric, value, limit in offenders:
        formatter.output_plain(
            f"  {path}:{f.first_line}: {f.name}: {metric} {value:g} > {limit:g}",
            stream=sys.stderr,
        )
    return 1
