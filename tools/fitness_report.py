#!/usr/bin/env python3
"""Measure the "Code quality, composition, and file-size program" fitness
metrics from `docs/design/decompiler-roadmap.md` and report them against the
roadmap's end-state targets::

    tools/fitness_report.py                  # human-readable table, exit 0
    tools/fitness_report.py --json            # machine-readable report
    tools/fitness_report.py --check-ratchet   # fail if any measure got worse

The measures are physical-LOC statistics over `src/*.rs`, excluding:

* test files/modules -- any path component (directory or file stem) that is
  exactly `test`/`tests`, or ends in `_test`/`_tests` (matches this crate's
  own naming: `session_tests.rs`, `ast_tests/`, `tests.rs`), and
* generated tables -- a file whose first 20 lines contain `@generated` or
  `DO NOT EDIT` (case-insensitive). Mixed-responsibility logic is never
  exempt, only files that are wholly generated data/tables.

Inline `#[cfg(test)] mod ... { ... }` (and other `#[cfg(test)]`-attributed
items) inside an otherwise-product file are stripped before counting, so a
1,200-line file with a 900-line test module counts as 300 product lines.

This is measurement only. It does not move any code toward the targets --
see the roadmap's "a file split counts only if it creates a narrower API and
one reason to change; arbitrary fragmentation is not architecture."
"""

from __future__ import annotations

import argparse
import json
import re
import statistics
import sys
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any

JsonObject = dict[str, Any]

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SRC = ROOT / "src"
DEFAULT_BASELINE = Path(__file__).resolve().parent / "fitness_baseline.json"
DEFAULT_IR_SUBDIR = "ir"

SCHEMA = "glaurung-fitness-report-v1"

_TEST_COMPONENT_RE = re.compile(r"^(?:.*_)?tests?$")
_CFG_TEST_ATTR_RE = re.compile(r"^\s*#\[cfg\(test\)\]\s*$")
_GENERATED_RE = re.compile(r"@generated|DO NOT EDIT", re.IGNORECASE)

# End-state fitness targets from the roadmap's "Code quality, composition,
# and file-size program" section. `higher_is_worse=True` means the ratchet
# regresses when the current value goes up; every target here is a ceiling.
TARGETS: tuple[tuple[str, str, float], ...] = (
    ("product_mean_loc", "Product-code mean", 450.0),
    ("product_median_loc", "Product-code median", 250.0),
    ("product_files_above_1000", "Product files above 1,000 LOC", 35.0),
    ("product_files_above_2000", "Product files above 2,000 LOC", 5.0),
    ("product_pct_loc_above_1000", "Product LOC in files above 1,000", 25.0),
    ("ir_median_loc", "src/ir median", 500.0),
    ("ir_files_above_1000", "src/ir files above 1,000 LOC", 5.0),
)

# Measures the ratchet compares against the committed baseline. All of them
# are "lower is better" ceilings, same direction as TARGETS.
RATCHET_KEYS: tuple[str, ...] = tuple(key for key, _label, _target in TARGETS)

# Float measures get a tiny tolerance so re-running on the same tree can't
# flap on floating-point noise; integer counts are compared exactly.
_FLOAT_KEYS = {
    "product_mean_loc",
    "product_median_loc",
    "product_pct_loc_above_1000",
    "ir_median_loc",
}
_TOLERANCE = 1e-6


class FitnessError(ValueError):
    """Raised when the source tree or baseline cannot be measured/compared."""


def is_test_path(relative: Path) -> bool:
    """Return whether `relative` (a path under the scanned root) is test-only.

    A file counts as test-only if any directory component or its own file
    stem is exactly `test`/`tests`, or ends with `_test`/`_tests` -- the
    pattern this crate already uses (`session_tests.rs`, `ast_tests/`,
    `linux_ioctl/tests.rs`).
    """
    parts = [*relative.parts[:-1], relative.stem]
    return any(_TEST_COMPONENT_RE.match(part) for part in parts)


def is_generated(text: str) -> bool:
    """Return whether `text` opens with a generated-file marker.

    Only a marker in the first 20 lines counts, so a file that merely
    contains a generated-looking table deep inside is not exempted --
    mixed-responsibility logic is never an exemption.
    """
    head = text.splitlines()[:20]
    return any(_GENERATED_RE.search(line) for line in head)


def strip_test_items(text: str) -> str:
    """Remove every `#[cfg(test)]`-attributed item from `text`.

    Handles both `#[cfg(test)] mod tests { ... }` blocks and single-item
    forms like `#[cfg(test)] fn helper_for_test() { ... }`, by counting
    braces from the attribute to the end of the following item. An item with
    no braces at all (e.g. a `#[cfg(test)] use ...;`) is removed up to its
    terminating `;`.
    """
    lines = text.splitlines()
    kept: list[str] = []
    index = 0
    count = len(lines)
    while index < count:
        if not _CFG_TEST_ATTR_RE.match(lines[index]):
            kept.append(lines[index])
            index += 1
            continue
        index += 1  # consume the attribute line itself
        depth = 0
        seen_brace = False
        while index < count:
            line = lines[index]
            depth += line.count("{") - line.count("}")
            if "{" in line:
                seen_brace = True
            index += 1
            if seen_brace and depth <= 0:
                break
            if not seen_brace and line.rstrip().endswith(";"):
                break
    return "\n".join(kept)


def product_loc(text: str) -> int:
    """Physical line count of `text` after stripping `#[cfg(test)]` items."""
    stripped = strip_test_items(text)
    if stripped == "":
        return 0
    return len(stripped.splitlines())


def iter_source_files(root: Path) -> Iterable[Path]:
    """Yield every `*.rs` file under `root`, in a stable sorted order."""
    yield from sorted(root.rglob("*.rs"))


def measured_files(root: Path) -> list[tuple[Path, int]]:
    """Return `(relative_path, product_loc)` for every counted file.

    Whole test files and whole generated files are excluded entirely (they
    do not appear even as a zero-LOC row); test *modules* inside an
    otherwise-product file are stripped but the file itself is kept.
    """
    rows: list[tuple[Path, int]] = []
    for path in iter_source_files(root):
        relative = path.relative_to(root)
        if is_test_path(relative):
            continue
        text = path.read_text(encoding="utf-8")
        if is_generated(text):
            continue
        rows.append((relative, product_loc(text)))
    return rows


def _stats(sizes: Sequence[int]) -> JsonObject:
    if not sizes:
        raise FitnessError("no product files found to measure")
    above_1000 = sum(1 for size in sizes if size > 1000)
    above_2000 = sum(1 for size in sizes if size > 2000)
    total = sum(sizes)
    loc_above_1000 = sum(size for size in sizes if size > 1000)
    return {
        "file_count": len(sizes),
        "total_loc": total,
        "mean_loc": statistics.fmean(sizes),
        "median_loc": statistics.median(sizes),
        "files_above_1000": above_1000,
        "files_above_2000": above_2000,
        "loc_in_files_above_1000": loc_above_1000,
        "pct_loc_above_1000": (100.0 * loc_above_1000 / total) if total else 0.0,
    }


def build_report(
    root: Path = DEFAULT_SRC, ir_subdir: str = DEFAULT_IR_SUBDIR
) -> JsonObject:
    """Measure the fitness metrics over `root`.

    Args:
        root: Source root to scan (default: the crate's `src/`).
        ir_subdir: Name of the `src/ir`-equivalent subdirectory to break out.

    Returns:
        A JSON-compatible report with the whole-product and `src/ir`
        statistics, and a `targets` section comparing each roadmap measure
        against its end-state target.

    Raises:
        FitnessError: If no product files are found.
    """
    rows = measured_files(root)
    product = _stats([size for _path, size in rows])
    ir_root = root / ir_subdir
    ir_rows = [(path, size) for path, size in rows if path.parts[0] == ir_subdir]
    if not ir_rows:
        raise FitnessError(f"no product files found under {ir_root}")
    ir = _stats([size for _path, size in ir_rows])

    measures = {
        "product_mean_loc": product["mean_loc"],
        "product_median_loc": product["median_loc"],
        "product_files_above_1000": product["files_above_1000"],
        "product_files_above_2000": product["files_above_2000"],
        "product_pct_loc_above_1000": product["pct_loc_above_1000"],
        "ir_median_loc": ir["median_loc"],
        "ir_files_above_1000": ir["files_above_1000"],
    }
    targets = [
        {
            "measure": key,
            "label": label,
            "value": measures[key],
            "target": target,
            "meets_target": measures[key] <= target,
        }
        for key, label, target in TARGETS
    ]
    try:
        root_label = str(root.resolve().relative_to(ROOT))
    except ValueError:
        root_label = str(root)
    return {
        "schema": SCHEMA,
        "root": root_label,
        "product": product,
        "ir": ir,
        "measures": measures,
        "targets": targets,
        "largest_files": [
            {"path": str(path), "loc": size}
            for path, size in sorted(rows, key=lambda row: -row[1])[:15]
        ],
    }


def render_table(report: JsonObject) -> str:
    """Render the target comparison as a human-readable table."""
    summary = (
        f"Product code: {report['product']['file_count']} files, "
        f"{report['product']['total_loc']} LOC "
        f"(src/ir: {report['ir']['file_count']} files, {report['ir']['total_loc']} LOC)"
    )
    lines = [
        summary,
        "",
        f"{'measure':<32} {'current':>12} {'target':>12}  status",
        "-" * 66,
    ]
    for entry in report["targets"]:
        value = entry["value"]
        rendered = f"{value:.1f}" if isinstance(value, float) else str(value)
        status = "OK" if entry["meets_target"] else "over target"
        lines.append(
            f"{entry['label']:<32} {rendered:>12} {entry['target']:>12.0f}  {status}"
        )
    lines.append("")
    lines.append("Largest product files:")
    for row in report["largest_files"]:
        lines.append(f"  {row['loc']:>6}  {row['path']}")
    return "\n".join(lines) + "\n"


def render_json(report: JsonObject) -> str:
    """Render canonical, byte-stable JSON."""
    return json.dumps(report, sort_keys=True, allow_nan=False, indent=2) + "\n"


def load_baseline(path: Path) -> JsonObject:
    """Load a committed baseline measures file.

    Raises:
        FitnessError: If the file is missing or is not a JSON object with a
            numeric value for every ratchet key.
    """
    if not path.is_file():
        raise FitnessError(f"baseline does not exist: {path}")
    with path.open(encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict) or "measures" not in value:
        raise FitnessError(
            f"baseline must be a JSON object with a measures field: {path}"
        )
    measures = value["measures"]
    for key in RATCHET_KEYS:
        if not isinstance(measures.get(key), (int, float)):
            raise FitnessError(f"baseline is missing a numeric {key!r}")
    return value


def check_ratchet(current: JsonObject, baseline: JsonObject) -> list[str]:
    """Compare `current["measures"]` against a baseline and report regressions.

    Every measure in `RATCHET_KEYS` is a ceiling (lower is better), so a
    regression is any increase beyond its measure's tolerance. Improvements
    and unchanged values are never reported.

    Returns:
        Human-readable regression descriptions; empty if none.
    """
    problems: list[str] = []
    current_measures = current["measures"]
    baseline_measures = baseline["measures"]
    for key in RATCHET_KEYS:
        before = baseline_measures[key]
        after = current_measures[key]
        tolerance = _TOLERANCE if key in _FLOAT_KEYS else 0
        if after > before + tolerance:
            problems.append(f"{key}: {before} -> {after} (worse)")
    return problems


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root", type=Path, default=DEFAULT_SRC, help="source root to scan"
    )
    parser.add_argument(
        "--ir-subdir",
        default=DEFAULT_IR_SUBDIR,
        help="name of the src/ir-equivalent subdirectory",
    )
    parser.add_argument(
        "--json", action="store_true", help="print JSON instead of a table"
    )
    parser.add_argument("--output", type=Path, help="write the report to a file")
    parser.add_argument(
        "--baseline",
        type=Path,
        default=DEFAULT_BASELINE,
        help="committed baseline measures",
    )
    parser.add_argument(
        "--check-ratchet",
        action="store_true",
        help="compare against --baseline and exit non-zero on any regression",
    )
    parser.add_argument(
        "--write-baseline",
        action="store_true",
        help="overwrite --baseline with the current measures (deliberate ratchet update)",
    )
    return parser


def _accepted_regressions(report: JsonObject, baseline_path: Path) -> list[JsonObject]:
    """Append this regeneration's regressions to the baseline's own history.

    A ratchet that is regenerated by the change which would have failed it is a
    logbook, not a ratchet — and on 2026-08-15 this one was regenerated ten times
    in a day while `product_mean_loc` went 515.9 to 530.1, monotonically worse,
    with each step individually defensible and the trend visible to nobody.

    Carrying the accepted regressions INSIDE the baseline makes the trend
    impossible to regenerate away: the next person to run `--write-baseline`
    inherits the list and has to look at it. This deliberately does not block the
    write. Blocking would only teach people to delete the file, and the failure
    here was not that the movement was refused too rarely — it was that nobody
    could see the movements accumulating.
    """
    history: list[JsonObject] = []
    if baseline_path.is_file():
        try:
            previous = json.loads(baseline_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return history
        history = list(previous.get("accepted_regressions") or [])
        problems = check_ratchet(report, previous)
        if problems:
            history.append(
                {"measures": previous.get("measures", {}), "worsened": problems}
            )
    return history[-50:]


def _print_drift(report: JsonObject) -> None:
    """Say out loud how far the accepted baseline has drifted, and how often."""
    history = report.get("accepted_regressions") or []
    if not history:
        return
    first = history[0].get("measures", {})
    now = report.get("measures", {})
    print(f"accepted regressions recorded: {len(history)}")
    for key in sorted(set(first) & set(now)):
        was, is_now = first[key], now[key]
        if (
            isinstance(was, (int, float))
            and isinstance(is_now, (int, float))
            and was != is_now
        ):
            print(f"  drift since first recorded: {key}: {was} -> {is_now}")


def main(argv: list[str] | None = None) -> int:
    """Run the fitness-report command-line interface."""
    args = _parser().parse_args(argv)
    try:
        report = build_report(args.root, args.ir_subdir)
        if args.write_baseline:
            report["accepted_regressions"] = _accepted_regressions(
                report, args.baseline
            )
            args.baseline.write_text(render_json(report), encoding="utf-8")
            print(f"wrote baseline: {args.baseline}")
            _print_drift(report)
            return 0
        if args.check_ratchet:
            baseline = load_baseline(args.baseline)
            problems = check_ratchet(report, baseline)
            if problems:
                for problem in problems:
                    print(f"REGRESSION: {problem}", file=sys.stderr)
                print(
                    f"fitness ratchet FAILED: {len(problems)} measure(s) got worse",
                    file=sys.stderr,
                )
                return 1
            print("fitness ratchet: no regressions")
    except FitnessError as error:
        raise SystemExit(f"fitness report failed: {error}") from error

    output = render_json(report) if args.json else render_table(report)
    if args.output is None:
        sys.stdout.write(output)
    else:
        args.output.write_text(output, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
