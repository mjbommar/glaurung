#!/usr/bin/env python3
"""Convert Glaurung JSONL pass traces into attributed health reports.

Capture a trace with::

    GLAURUNG_PASS_HEALTH=1 glaurung decompile BINARY --func NAME \
      --style decbench 2> pass-health.log
    tools/pass_health_report.py pass-health.log

Ordinary stderr is ignored. Pass-health lines are schema-validated and a trace
with no events fails, preventing a missing environment variable from looking
like an empty, healthy result.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

PREFIX = "[glaurung-pass-health] "
EVENT_SCHEMA = "glaurung-pass-health-v1"
REPORT_SCHEMA = "glaurung-pass-health-report-v1"
COUNTERS = (
    "parameters",
    "declarations",
    "temporaries",
    "physical_registers",
    "undefined_uses",
    "gotos",
    "uncovered_cfg_edges",
    "invented_cfg_edges",
    "structure_fallbacks",
    "unresolved_transfers",
    "statements",
)
# Counters the emitter may add without invalidating an older trace.
#
# The validator used to demand an EXACT key set, which makes every new counter a
# breaking change to recorded evidence: adding the edge-completeness counters
# would have rejected every trace captured before them, including the one this
# tool is tested against. Required counters must be present; anything else the
# emitter knows about is summarized when it is there and ignored when it is not.
OPTIONAL_COUNTERS = (
    "unknown_cfg_edges",
    "terminal_edges",
    "unknown_terminal_edges",
    "unresolved_indirect_edges",
    "indirect_symbol_edges",
    "indirect_slot_edges",
)
JsonObject = dict[str, Any]


class HealthReportError(ValueError):
    """Raised when pass-health evidence is absent or malformed."""


def _validated_event(value: Any, line_number: int) -> JsonObject:
    if not isinstance(value, dict):
        raise HealthReportError(f"line {line_number}: event must be an object")
    if value.get("schema") != EVENT_SCHEMA:
        raise HealthReportError(
            f"line {line_number}: unsupported schema {value.get('schema')!r}"
        )
    for field in ("pass", "function", "entry_va"):
        if not isinstance(value.get(field), str) or not value[field]:
            raise HealthReportError(f"line {line_number}: invalid {field}")
    health = value.get("health")
    if not isinstance(health, dict) or not set(COUNTERS) <= set(health):
        raise HealthReportError(
            f"line {line_number}: health counters must include {COUNTERS!r}"
        )
    unknown = set(health) - set(COUNTERS) - set(OPTIONAL_COUNTERS)
    if unknown:
        raise HealthReportError(
            f"line {line_number}: unrecognised health counters {sorted(unknown)!r}"
        )
    for counter in health:
        measured = health[counter]
        if not isinstance(measured, int) or isinstance(measured, bool) or measured < 0:
            raise HealthReportError(
                f"line {line_number}: {counter} must be a non-negative integer"
            )
    violations = value.get("violations")
    if not isinstance(violations, list):
        raise HealthReportError(f"line {line_number}: violations must be an array")
    for violation in violations:
        if (
            not isinstance(violation, dict)
            or set(violation) != {"name", "kind"}
            or not isinstance(violation["name"], str)
            or not violation["name"]
            or not isinstance(violation["kind"], str)
            or not violation["kind"]
        ):
            raise HealthReportError(f"line {line_number}: invalid violation")
    return value


def parse_trace(lines: Iterable[str]) -> list[JsonObject]:
    """Parse schema-tagged health events from mixed stderr lines.

    Args:
        lines: Trace/stderr lines.

    Returns:
        Validated events in encounter order.

    Raises:
        HealthReportError: If an event is malformed or no events are present.
    """
    events: list[JsonObject] = []
    for line_number, line in enumerate(lines, 1):
        if not line.startswith(PREFIX):
            continue
        try:
            value = json.loads(line[len(PREFIX) :])
        except json.JSONDecodeError as error:
            raise HealthReportError(
                f"line {line_number}: invalid JSON: {error.msg}"
            ) from error
        events.append(_validated_event(value, line_number))
    if not events:
        raise HealthReportError("no pass-health events found")
    return events


def _function_report(
    events: list[JsonObject], source_cfg_nodes: int | None
) -> JsonObject:
    baseline = events[0]["health"]
    final = events[-1]["health"]
    first_changes: JsonObject = {}
    for counter in (*COUNTERS, *OPTIONAL_COUNTERS):
        if counter not in baseline:
            continue
        before = baseline[counter]
        for event in events[1:]:
            after = event["health"].get(counter, before)
            if after != before:
                first_changes[counter] = {
                    "pass": event["pass"],
                    "before": before,
                    "after": after,
                    "delta": after - before,
                }
                break
    final_violations = sorted(
        events[-1]["violations"],
        key=lambda violation: (violation["kind"], violation["name"]),
    )
    first_violation_passes: dict[str, str] = {}
    for violation in final_violations:
        identity = f"{violation['kind']}:{violation['name']}"
        for event in events:
            if violation in event["violations"]:
                first_violation_passes[identity] = event["pass"]
                break
    ratio = None
    if source_cfg_nodes is not None:
        if source_cfg_nodes <= 0:
            raise HealthReportError("source CFG node counts must be positive")
        ratio = final["statements"] / source_cfg_nodes
    return {
        "entry_va": events[0]["entry_va"],
        "function": events[0]["function"],
        "event_count": len(events),
        "source_cfg_nodes": source_cfg_nodes,
        "output_to_source_cfg_ratio": ratio,
        "initial": baseline,
        "final": final,
        "final_violations": final_violations,
        "first_violation_passes": first_violation_passes,
        "first_changes": first_changes,
        "stages": [
            {
                "pass": event["pass"],
                "health": event["health"],
                "violations": event["violations"],
            }
            for event in events
        ],
    }


def build_report(
    events: Iterable[Mapping[str, Any]],
    source_cfg_nodes: Mapping[str, int] | None = None,
) -> JsonObject:
    """Group events per function and attribute the first counter changes.

    Args:
        events: Validated pass-health events.
        source_cfg_nodes: Optional entry-VA to source CFG node counts.

    Returns:
        Deterministic report with per-function stages and final totals.
    """
    groups: dict[tuple[str, str], list[JsonObject]] = {}
    for raw_event in events:
        event = dict(raw_event)
        key = (str(event["entry_va"]), str(event["function"]))
        groups.setdefault(key, []).append(event)
    if not groups:
        raise HealthReportError("no pass-health events found")
    functions = [
        _function_report(
            groups[key],
            None if source_cfg_nodes is None else source_cfg_nodes.get(key[0]),
        )
        for key in sorted(groups)
    ]
    totals = {
        counter: sum(function["final"][counter] for function in functions)
        for counter in COUNTERS
    }
    return {
        "schema": REPORT_SCHEMA,
        "function_count": len(functions),
        "totals": totals,
        "functions": functions,
    }


def render_json(report: Mapping[str, Any]) -> str:
    """Render canonical, byte-stable JSON."""
    return (
        json.dumps(report, sort_keys=True, allow_nan=False, separators=(",", ":"))
        + "\n"
    )


def _load_sizes(path: Path | None) -> dict[str, int] | None:
    if path is None:
        return None
    with path.open(encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict) or not all(
        isinstance(key, str)
        and isinstance(count, int)
        and not isinstance(count, bool)
        and count > 0
        for key, count in value.items()
    ):
        raise HealthReportError(
            "source CFG sizes must map entry-VA strings to positive integers"
        )
    return value


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trace", type=Path, help="mixed stderr/pass-health trace")
    parser.add_argument(
        "--source-cfg-sizes",
        type=Path,
        help="optional JSON object mapping entry VA to source CFG node count",
    )
    parser.add_argument("--output", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the pass-health report command-line interface."""
    args = _parser().parse_args(argv)
    try:
        events = parse_trace(args.trace.read_text(encoding="utf-8").splitlines())
        report = build_report(events, _load_sizes(args.source_cfg_sizes))
    except (OSError, json.JSONDecodeError, HealthReportError) as error:
        raise SystemExit(f"pass-health report failed: {error}") from error
    output = render_json(report)
    if args.output is None:
        sys.stdout.write(output)
    else:
        args.output.write_text(output, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
