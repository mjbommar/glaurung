#!/usr/bin/env python3
"""Append one bounded host-condition observation for a runtime profile lane."""

from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone
from pathlib import Path


def _cpu_pressure() -> dict[str, float] | None:
    path = Path("/proc/pressure/cpu")
    if not path.is_file():
        return None
    for line in path.read_text().splitlines():
        fields = line.split()
        if fields and fields[0] == "some":
            values = dict(field.split("=", 1) for field in fields[1:])
            return {name: float(values[name]) for name in ("avg10", "avg60", "avg300")}
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--iteration", type=int, required=True)
    parser.add_argument("--lane", choices=("cold", "optimized"), required=True)
    parser.add_argument("--stage", choices=("before", "after"), required=True)
    args = parser.parse_args()

    load1, load5, load15 = os.getloadavg()
    observation = {
        "schema": "glaurung-runtime-profile-host-observation-v1",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "iteration": args.iteration,
        "lane": args.lane,
        "stage": args.stage,
        "load_average": {"one": load1, "five": load5, "fifteen": load15},
        "logical_cpus": os.cpu_count(),
        "cpu_affinity": sorted(os.sched_getaffinity(0)),
        "cpu_pressure_some": _cpu_pressure(),
    }
    with args.output.open("a") as output:
        output.write(json.dumps(observation, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
