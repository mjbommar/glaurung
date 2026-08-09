#!/usr/bin/env python3
"""Summarize opt-in Glaurung pipeline timing and object-parse traces.

Capture a trace with::

    GLAURUNG_PIPELINE_PROFILE=1 glaurung decompile BINARY --func NAME \
      --style decbench 2> pipeline-profile.log
    tools/pipeline_profile_report.py pipeline-profile.log

Non-profile stderr is ignored. Missing, malformed, or unknown-schema evidence
fails closed so an instrumentation mistake cannot masquerade as a fast run.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

PREFIX = "[glaurung-pipeline-profile] "
EVENT_SCHEMA = "glaurung-pipeline-profile-v1"
REPORT_SCHEMA = "glaurung-pipeline-profile-report-v1"
JsonObject = dict[str, Any]


class ProfileReportError(ValueError):
    """Raised when pipeline-profile evidence is absent or malformed."""


def _non_negative_integer(value: Any, field: str, line_number: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ProfileReportError(
            f"line {line_number}: {field} must be a non-negative integer"
        )
    return value


def _non_empty_string(value: Any, field: str, line_number: int) -> str:
    if not isinstance(value, str) or not value:
        raise ProfileReportError(f"line {line_number}: invalid {field}")
    return value


def _validated_event(value: Any, line_number: int) -> JsonObject:
    if not isinstance(value, dict):
        raise ProfileReportError(f"line {line_number}: event must be an object")
    if value.get("schema") != EVENT_SCHEMA:
        raise ProfileReportError(
            f"line {line_number}: unsupported schema {value.get('schema')!r}"
        )
    event = value.get("event")
    _non_negative_integer(value.get("duration_ns"), "duration_ns", line_number)
    if event == "stage":
        expected = {
            "schema",
            "event",
            "function",
            "entry_va",
            "stage",
            "duration_ns",
        }
        if set(value) != expected:
            raise ProfileReportError(f"line {line_number}: invalid stage fields")
        _non_empty_string(value.get("function"), "function", line_number)
        _non_empty_string(value.get("entry_va"), "entry_va", line_number)
        _non_empty_string(value.get("stage"), "stage", line_number)
    elif event == "run":
        expected = {
            "schema",
            "event",
            "entry_point",
            "duration_ns",
            "object_parse_count",
        }
        if set(value) != expected:
            raise ProfileReportError(f"line {line_number}: invalid run fields")
        _non_empty_string(value.get("entry_point"), "entry_point", line_number)
        _non_negative_integer(
            value.get("object_parse_count"), "object_parse_count", line_number
        )
    else:
        raise ProfileReportError(f"line {line_number}: unsupported event {event!r}")
    return value


def parse_trace(lines: Iterable[str]) -> list[JsonObject]:
    """Parse and validate profile events from mixed stderr lines."""
    events: list[JsonObject] = []
    for line_number, line in enumerate(lines, 1):
        if not line.startswith(PREFIX):
            continue
        try:
            value = json.loads(line[len(PREFIX) :])
        except json.JSONDecodeError as error:
            raise ProfileReportError(
                f"line {line_number}: invalid JSON: {error.msg}"
            ) from error
        events.append(_validated_event(value, line_number))
    if not events:
        raise ProfileReportError("no pipeline-profile events found")
    return events


def build_report(events: Iterable[Mapping[str, Any]]) -> JsonObject:
    """Aggregate stage timings by function while retaining each run boundary."""
    functions: dict[tuple[str, str], JsonObject] = {}
    runs: list[JsonObject] = []
    event_count = 0
    for raw_event in events:
        event_count += 1
        event = dict(raw_event)
        if event["event"] == "run":
            runs.append(
                {
                    "entry_point": event["entry_point"],
                    "duration_ns": event["duration_ns"],
                    "object_parse_count": event["object_parse_count"],
                }
            )
            continue
        key = (str(event["entry_va"]), str(event["function"]))
        function = functions.setdefault(
            key,
            {
                "entry_va": key[0],
                "function": key[1],
                "stage_event_count": 0,
                "stage_duration_ns": {},
            },
        )
        function["stage_event_count"] += 1
        stages = function["stage_duration_ns"]
        stage = str(event["stage"])
        stages[stage] = stages.get(stage, 0) + int(event["duration_ns"])
    if event_count == 0:
        raise ProfileReportError("no pipeline-profile events found")
    if not runs:
        raise ProfileReportError("profile trace has no completed run event")
    return {
        "schema": REPORT_SCHEMA,
        "runs": runs,
        "functions": [functions[key] for key in sorted(functions)],
    }


def render_json(report: Mapping[str, Any]) -> str:
    """Render canonical, byte-stable JSON."""
    return (
        json.dumps(report, sort_keys=True, allow_nan=False, separators=(",", ":"))
        + "\n"
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trace", type=Path, help="mixed stderr/pipeline-profile trace")
    parser.add_argument("--output", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the profile report command-line interface."""
    args = _parser().parse_args(argv)
    try:
        report = build_report(
            parse_trace(args.trace.read_text(encoding="utf-8").splitlines())
        )
    except (OSError, ProfileReportError) as error:
        raise SystemExit(f"pipeline-profile report failed: {error}") from error
    output = render_json(report)
    if args.output is None:
        sys.stdout.write(output)
    else:
        args.output.write_text(output, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
