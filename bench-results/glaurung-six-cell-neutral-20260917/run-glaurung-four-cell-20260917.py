#!/usr/bin/env python3
"""Execute ADR-0272's fixed Glaurung campaign at the 2026-09-16 pin (four cells).

Copied from axeyum/scripts/run-glaurung-six-cell-neutral.py
(SHA-256 daeec160c41862e3a70cc216831971a402d8b7392e3e6b60504b2503e89fbc7c) with
exactly three edits: GLAURUNG_REVISION, EXECUTABLE_SHA256, and the producer
validator path (the file moved to tools/axeyum/ after July). Nothing else.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import pathlib
import subprocess
import sys
from typing import Any, Sequence


GLAURUNG_REVISION = "b1f420ab1e406ec2479509f65143211191428be0"
EXECUTABLE_SHA256 = "4f3e5c376ef2da45ec0fc904b94874931ba3d5ff717da1e4482ca46c3a055f3f"
CPU = 2
REPETITIONS = 5
DRIVERS = (
    (
        "dptf",
        "samples/binaries/platforms/windows/vendor/realworld/sqfs-intel-DptfDevGen.sys",
        "074be1b90deb21897538a6b093af9826e62610ffd878c92289af31c5ca3f724b",
    ),
    (
        "vwififlt",
        "samples/binaries/platforms/windows/vendor/realworld/win10-vwififlt.sys",
        "13c3b69a5d0179ed3cc2c999ff97edbaedd63da55ddb74427251c360706a3820",
    ),
    (
        "intcsst",
        "samples/binaries/platforms/windows/vendor/realworld/windows-update-intel-audio-IntcSST.sys",
        "f7c8e4f106baa5b2a1a18e60731ad42a6f734aee1d049576eaf6d123d5629750",
    ),
    (
        "surfacepen",
        "samples/binaries/platforms/windows/vendor/realworld/windows-update-SurfacePenBleLcAddrAdaptationDriver.sys",
        "3c062dc57832caab776bec99656798474af7ffb59ef751c9a004a95c0ae74405",
    ),
)
FIXED_ENVIRONMENT = {
    "GLAURUNG_FAIR_SHADOW": "1",
    "GLAURUNG_CHECK_TIMEOUT_MS": "250",
    "GLAURUNG_AXEYUM_REPLAY_SAT_CACHE": "1",
    "GLAURUNG_AXEYUM_WARM_MAX_LIVE_PATHS": "9",
    "GLAURUNG_AXEYUM_WARM_MAX_ASSERTIONS_PER_PATH": "512",
    "IOCTLANCE_DEADLINE_SECS": "600",
    "IOCTLANCE_MAX_ANALYZED_FUNCTIONS": "100000",
    "IOCTLANCE_SOLVE_BUDGET": "20000",
    "IOCTLANCE_SOLVE_SECS": "60",
}
MEMORY_GUARD = pathlib.Path(
    "/home/mjbommar/projects/personal/axeyum/scripts/mem-run.sh"
)


class CampaignError(RuntimeError):
    """The registered campaign cannot proceed."""


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def command_output(command: Sequence[str], cwd: pathlib.Path) -> str:
    completed = subprocess.run(
        command,
        cwd=cwd,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return completed.stdout.strip()


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def write_json(path: pathlib.Path, value: Any) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    temporary.replace(path)


def sanitize_environment(trace_root: pathlib.Path) -> dict[str, str]:
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("GLAURUNG_", "IOCTLANCE_", "BITWUZLA_"))
        and key != "LD_LIBRARY_PATH"
    }
    environment.update(FIXED_ENVIRONMENT)
    environment["GLAURUNG_ORDERED_TRACE_DIR"] = str(trace_root)
    environment["MEM_LIMIT_GB"] = "64"
    return environment


def preflight(
    glaurung_root: pathlib.Path,
    executable: pathlib.Path,
    output_root: pathlib.Path,
) -> dict[str, Any]:
    if command_output(["git", "rev-parse", "HEAD"], glaurung_root) != GLAURUNG_REVISION:
        raise CampaignError("Glaurung revision differs from ADR-0272")
    if command_output(["git", "status", "--short"], glaurung_root):
        raise CampaignError("Glaurung worktree is dirty")
    if not executable.is_file() or sha256_file(executable) != EXECUTABLE_SHA256:
        raise CampaignError("release executable identity differs from registration")
    if not MEMORY_GUARD.is_file():
        raise CampaignError("registered memory guard is absent")
    if CPU not in os.sched_getaffinity(0):
        raise CampaignError(f"registered logical CPU {CPU} is unavailable")
    if not output_root.is_dir() or any(output_root.iterdir()):
        raise CampaignError("output root must exist and be empty")
    driver_rows = []
    for label, relative_path, expected_hash in DRIVERS:
        path = glaurung_root / relative_path
        actual_hash = sha256_file(path) if path.is_file() else None
        if actual_hash != expected_hash:
            raise CampaignError(f"driver identity differs for {label}")
        driver_rows.append(
            {"label": label, "path": relative_path, "sha256": actual_hash}
        )
    return {
        "schema": "axeyum-glaurung-six-cell-campaign-v1",
        "registration": "ADR-0272",
        "started_utc": utc_now(),
        "glaurung_revision": GLAURUNG_REVISION,
        "executable": str(executable),
        "executable_sha256": EXECUTABLE_SHA256,
        "logical_cpu": CPU,
        "repetitions_per_driver": REPETITIONS,
        "fixed_environment": FIXED_ENVIRONMENT,
        "drivers": driver_rows,
        "runs": [],
        "terminal_status": "preflight",
    }


def run_campaign(
    glaurung_root: pathlib.Path,
    executable: pathlib.Path,
    output_root: pathlib.Path,
    campaign: dict[str, Any],
) -> None:
    campaign_path = output_root / "campaign.json"
    campaign["terminal_status"] = "running"
    write_json(campaign_path, campaign)
    validator = (
        glaurung_root
        / "tools/axeyum/validate_ordered_trace.py"
    )
    for driver_index, (label, relative_path, _) in enumerate(DRIVERS, 1):
        for repetition in range(1, REPETITIONS + 1):
            run_name = f"{driver_index:02d}-{label}-r{repetition}"
            run_root = output_root / run_name
            trace_parent = run_root / "traces"
            trace_parent.mkdir(parents=True)
            command = [
                str(MEMORY_GUARD),
                "taskset",
                "-c",
                str(CPU),
                str(executable),
                relative_path,
            ]
            record: dict[str, Any] = {
                "run": run_name,
                "driver": label,
                "repetition": repetition,
                "command": command,
                "started_utc": utc_now(),
                "trace_parent": str(trace_parent),
            }
            campaign["runs"].append(record)
            write_json(campaign_path, campaign)
            with (run_root / "stdout.log").open("wb") as stdout, (
                run_root / "stderr.log"
            ).open("wb") as stderr:
                completed = subprocess.run(
                    command,
                    cwd=glaurung_root,
                    env=sanitize_environment(trace_parent),
                    stdout=stdout,
                    stderr=stderr,
                    check=False,
                )
            record["ended_utc"] = utc_now()
            record["return_code"] = completed.returncode
            traces = sorted(
                path.parent
                for path in trace_parent.rglob("trace-manifest-v1.json")
            )
            record["traces"] = [str(path) for path in traces]
            if completed.returncode != 0 or len(traces) != 1:
                record["validation"] = "not-run"
                campaign["terminal_status"] = "failed"
                write_json(campaign_path, campaign)
                raise CampaignError(
                    f"{run_name} returned {completed.returncode} with {len(traces)} traces"
                )
            validation = subprocess.run(
                [sys.executable, str(validator), str(traces[0])],
                cwd=glaurung_root,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            (run_root / "validator.stdout.log").write_text(
                validation.stdout, encoding="utf-8"
            )
            (run_root / "validator.stderr.log").write_text(
                validation.stderr, encoding="utf-8"
            )
            record["validator_return_code"] = validation.returncode
            record["validation"] = "accepted" if validation.returncode == 0 else "failed"
            write_json(run_root / "run-record.json", record)
            write_json(campaign_path, campaign)
            if validation.returncode != 0:
                campaign["terminal_status"] = "failed"
                write_json(campaign_path, campaign)
                raise CampaignError(f"producer validator rejected {run_name}")
    campaign["terminal_status"] = "complete"
    campaign["ended_utc"] = utc_now()
    write_json(campaign_path, campaign)


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--glaurung-root", required=True, type=pathlib.Path)
    parser.add_argument("--executable", required=True, type=pathlib.Path)
    parser.add_argument("--output-root", required=True, type=pathlib.Path)
    parser.add_argument("--preflight-only", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        campaign = preflight(
            args.glaurung_root.resolve(),
            args.executable.resolve(),
            args.output_root.resolve(),
        )
        if args.preflight_only:
            print(json.dumps(campaign, indent=2, sort_keys=True))
            return 0
        run_campaign(
            args.glaurung_root.resolve(),
            args.executable.resolve(),
            args.output_root.resolve(),
            campaign,
        )
    except (CampaignError, OSError, subprocess.SubprocessError) as error:
        print(f"six-cell campaign failed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
