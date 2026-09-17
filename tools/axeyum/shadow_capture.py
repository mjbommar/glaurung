#!/usr/bin/env python3
"""Run a combined-shadow capture over named drivers and publish the splits.

This is the producer half of the shadow-split capture tier (solver-034); the
gate half is ``split_verdicts.py`` and ``tests/axeyum_shadow_split_verdicts.rs``,
and ``scripts/shadow-capture.sh`` runs the three in order.  Until 2026-09-17
a capture was a command in a README that nobody re-ran, which is how a
two-month-old corpus with 735 exporter-defect scripts was still being quoted
as a solver gap.

For each ``--driver`` this tool runs the ``ioctlance`` example (a
``solver-z3,solver-axeyum`` build) in fair-shadow mode with
``GLAURUNG_DUMP_SHADOW_SPLITS`` pointed at ``<root>/<capture>/``, so the
in-process publisher writes every exactly-one-backend-decided query there
through its atomic, content-addressed, z3-parse-checked path.  Afterwards it:

* refuses to treat a silent run as a clean one -- the process must exit 0 and
  print a ``[shadow-diff] queries=N`` summary with ``N > 0`` (a capture that
  issued no checks proves nothing);
* fails on any **disagreement** (both backends decided, differently: the
  bytes are under ``<capture>/disagreements/``), on any **malformed** export
  (``<capture>/malformed.tsv``, solver-016's class -- the exporter's bug, not
  the solver's), and reports the split count and the histogram of the
  nondecided backend's reason class (``<capture>/nondecisions.tsv``);
* for a capture that produced splits, validates it with
  ``validate_shadow_splits.py`` and writes the sidecars the pinned captures
  carry: ``summary-v1.json``, ``capture-index-v1.json`` and ``capture-v1.json``
  (producer revisions, driver identity, policy, run statistics).  A capture
  that produced no split creates no directory and is reported as such.

The capture name is ``<token>-<ceiling>s-<glaurung short rev>``, matching the
committed ``tcpip-60s-d60ed0f``; ``--driver TOKEN=PATH`` names the token,
otherwise it is the last ``-``-separated part of the file stem, lower-cased.
An existing capture directory is refused: the publisher appends, and a second
run at the same revision would duplicate index rows.

Exit status: 0 when every driver ran, measured something, and produced no
disagreement and no malformed export (new splits are findings, not failures);
1 on any of those; 2 on a usage or environment error.
"""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import validate_shadow_splits  # noqa: E402

SHADOW_DIFF_RE = re.compile(r"^\[shadow-diff\] queries=(\d+) agree=(\d+) disagree=(\d+)")
MODEL_CHOICE_RE = re.compile(
    r"^\[model-choice\] both-sat=(\d+) different-model=(\d+) \| "
    r"z3-unknown=(\d+) axeyum-unknown=(\d+) unknown-split=(\d+)"
)
SYMBOLIC_RE = re.compile(r"^\[symbolic\] .* analyzed=(\d+)/(\d+)")
WARM_RE = re.compile(
    r"^\[axeyum-warm\] checks=(\d+) .* resets=(\d+) .* "
    r"path-cap-fallbacks=(\d+) assertion-cap-fallbacks=(\d+)"
)
PIN_RE = re.compile(r'source = "git\+[^"]*axeyum\.git\?rev=([0-9a-f]+)#')

# The fixed environment of a capture, per driver. The per-function ceiling is
# the argument; the rest mirrors the six-cell protocol (solver-033) so a split
# captured here is a split the measured configuration produces.
FIXED_ENV = {
    "GLAURUNG_FAIR_SHADOW": "1",
    "IOCTLANCE_SOLVE_BUDGET": "20000",
    "IOCTLANCE_MAX_ANALYZED_FUNCTIONS": "100000",
}
STRIPPED_PREFIXES = ("GLAURUNG_", "IOCTLANCE_", "BITWUZLA_")


class CaptureError(Exception):
    """A finding that fails the tier (exit 1)."""


def parse_driver(spec: str) -> tuple[str, Path]:
    if "=" in spec:
        token, _, raw = spec.partition("=")
    else:
        raw = spec
        token = Path(raw).stem.rsplit("-", 1)[-1].lower()
    if not re.fullmatch(r"[a-z0-9]+", token):
        raise ValueError(f"driver token {token!r} must be [a-z0-9]+ (use TOKEN=PATH)")
    path = Path(raw)
    if not path.is_file():
        raise ValueError(f"driver not found: {path}")
    return token, path


def axeyum_pin(lock: Path) -> str:
    if not lock.is_file():
        return "unknown"
    found = PIN_RE.search(lock.read_text(encoding="utf-8"))
    return found.group(1) if found else "unknown"


def git_revision(repo: Path) -> str:
    try:
        out = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return "unknown"
    return out.stdout.strip() or "unknown"


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def capture_env(capture: Path, ceiling: int, deadline: int, extra: list[str]) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith(STRIPPED_PREFIXES)}
    env.update(FIXED_ENV)
    env["GLAURUNG_DUMP_SHADOW_SPLITS"] = str(capture)
    env["IOCTLANCE_SOLVE_SECS"] = str(ceiling)
    env["IOCTLANCE_DEADLINE_SECS"] = str(deadline)
    for item in extra:
        key, sep, value = item.partition("=")
        if not sep or not key:
            raise ValueError(f"--env expects KEY=VALUE, got {item!r}")
        env[key] = value
    return env


def parse_summary(stderr: str) -> dict[str, int]:
    """The run statistics ``ioctlance`` prints; raises when the evidence line is missing."""
    stats: dict[str, int] = {}
    for line in stderr.splitlines():
        if found := SHADOW_DIFF_RE.match(line):
            stats["queries"], stats["agree_or_nondecided"], stats["sat_unsat_disagreements"] = (
                int(found.group(1)),
                int(found.group(2)),
                int(found.group(3)),
            )
        elif found := MODEL_CHOICE_RE.match(line):
            stats["both_sat"] = int(found.group(1))
            stats["different_model"] = int(found.group(2))
            stats["z3_nondecided_occurrences"] = int(found.group(3))
            stats["axeyum_nondecided_occurrences"] = int(found.group(4))
            stats["split_occurrences"] = int(found.group(5))
        elif found := SYMBOLIC_RE.match(line):
            stats["functions_analyzed"] = int(found.group(1))
            stats["functions_reachable"] = int(found.group(2))
        elif found := WARM_RE.match(line):
            stats["warm_checks"] = int(found.group(1))
            stats["warm_resets"] = int(found.group(2))
            stats["path_cap_fallbacks"] = int(found.group(3))
            stats["assertion_cap_fallbacks"] = int(found.group(4))
    if "queries" not in stats:
        raise CaptureError("no `[shadow-diff] queries=` line: the run is not evidence")
    if stats["queries"] == 0:
        raise CaptureError("`[shadow-diff] queries=0`: the run issued no checks and proves nothing")
    return stats


def read_rows(path: Path, width: int) -> list[list[str]]:
    if not path.is_file():
        return []
    rows = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line:
            continue
        fields = line.split("\t")
        if len(fields) < width:
            raise CaptureError(f"{path}:{number}: expected {width} tab-separated fields")
        rows.append(fields)
    return rows


def run_driver(
    binary: Path,
    token: str,
    driver: Path,
    capture: Path,
    ceiling: int,
    deadline: int,
    extra_env: list[str],
    driver_timeout: int,
    log_dir: Path,
) -> tuple[dict[str, object], str]:
    """Run one capture; return (record, stderr text). Raises CaptureError on a failed run."""
    env = capture_env(capture, ceiling, deadline, extra_env)
    log_dir.mkdir(parents=True, exist_ok=True)
    stderr_path = log_dir / f"{capture.name}.stderr"
    started = time.monotonic()
    started_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    try:
        proc = subprocess.run(
            [str(binary), str(driver)],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",
            timeout=driver_timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        partial = error.stderr if isinstance(error.stderr, str) else (error.stderr or b"").decode("utf-8", "replace")
        stderr_path.write_text(partial, encoding="utf-8")
        raise CaptureError(
            f"{token}: {driver.name} did not finish within --driver-timeout {driver_timeout} s"
        ) from error
    wall = time.monotonic() - started
    stderr_path.write_text(proc.stderr, encoding="utf-8")
    if proc.returncode != 0:
        tail = "\n".join(proc.stderr.splitlines()[-5:])
        raise CaptureError(f"{token}: {driver.name} exited {proc.returncode}; stderr tail:\n{tail}")
    stats = parse_summary(proc.stderr)
    stats["wall_seconds"] = round(wall, 3)
    # ru_maxrss over every child so far: exact for the first driver, an upper
    # bound afterwards. Recorded as such.
    stats["max_rss_kib_children_so_far"] = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    record: dict[str, object] = {
        "token": token,
        "capture_name": capture.name,
        "driver": {"path": str(driver), "sha256": sha256_of(driver), "bytes": driver.stat().st_size},
        "started_at": started_at,
        "run": stats,
        "stderr_log": str(stderr_path),
    }
    return record, proc.stderr


def inspect_capture(capture: Path) -> tuple[dict[str, object], list[str]]:
    """Counts, the reason histogram, and the findings (disagreements/malformed) of one capture."""
    findings: list[str] = []
    result: dict[str, object] = {"splits": 0, "nondecision_reasons": {}, "disagreements": 0, "malformed": 0}
    if not capture.is_dir():
        return result, findings
    splits = read_rows(capture / "shadow-splits.tsv", 3)
    result["splits"] = len(splits)
    result["split_classes"] = dict(sorted(Counter(f"{z}/{a}" for _, z, a in (r[:3] for r in splits)).items()))
    reasons = read_rows(capture / "nondecisions.tsv", 3)
    histogram = Counter(f"{backend}:{reason}" for _, backend, reason in (r[:3] for r in reasons))
    result["nondecision_reasons"] = dict(sorted(histogram.items()))
    disagreements = read_rows(capture / "disagreements.tsv", 3)
    result["disagreements"] = len(disagreements)
    for content_hash, z3_class, axeyum_class in (r[:3] for r in disagreements):
        findings.append(
            f"{capture.name}: DISAGREEMENT {content_hash}: z3 {z3_class}, axeyum {axeyum_class} "
            f"(bytes: {capture / 'disagreements' / (content_hash + '.smt2')})"
        )
    malformed = read_rows(capture / "malformed.tsv", 4)
    result["malformed"] = len(malformed)
    for content_hash, z3_class, axeyum_class, error in (r[:4] for r in malformed):
        findings.append(
            f"{capture.name}: MALFORMED export {content_hash} ({z3_class}/{axeyum_class}): {error} "
            "-- an exporter defect (solver-016), fix the exporter"
        )
    return result, findings


def write_sidecars(
    capture: Path,
    record: dict[str, object],
    inspected: dict[str, object],
    glaurung_revision: str,
    axeyum_revision: str,
    ceiling: int,
    deadline: int,
    env: dict[str, str],
    jobs: int,
) -> None:
    summary, rows, sizes = validate_shadow_splits.validate_capture(capture, jobs)
    (capture / "summary-v1.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    token = str(record["token"])
    source = (
        f"Glaurung {glaurung_revision[:7]}; Axeyum {axeyum_revision[:7]}; fair shadow "
        f"(cold z3 vs warm Axeyum), {ceiling} seconds per function; "
        "scripts/shadow-capture.sh (solver-034); expected is the only backend-decided class"
    )
    index = validate_shadow_splits.build_capture_index(rows, sizes, f"glaurung-{token}-shadow-splits-v1", source)
    (capture / "capture-index-v1.json").write_text(json.dumps(index, indent=2) + "\n", encoding="utf-8")
    policy_env = {k: v for k, v in sorted(env.items()) if k.startswith(STRIPPED_PREFIXES)}
    meta = {
        "schema": "glaurung-shadow-split-capture-v1",
        "producer": {
            "glaurung_revision": glaurung_revision,
            "axeyum_revision": axeyum_revision,
            "tier": "scripts/shadow-capture.sh",
            "tool": "tools/axeyum/shadow_capture.py",
        },
        "driver": record["driver"],
        "policy": {
            "fair_shadow": True,
            "solver_seconds_per_function": ceiling,
            "analysis_deadline_seconds": deadline,
            "solve_budget": int(env["IOCTLANCE_SOLVE_BUDGET"]),
            "max_analyzed_functions": int(env["IOCTLANCE_MAX_ANALYZED_FUNCTIONS"]),
            "check_timeout_ms": int(env.get("GLAURUNG_CHECK_TIMEOUT_MS", "250")),
            "environment": policy_env,
        },
        "run": record["run"],
        "started_at": record["started_at"],
        "nondecision_reasons": inspected["nondecision_reasons"],
        "validated_summary": "summary-v1.json",
        "split_index": "shadow-splits.tsv",
        "capture_index": "capture-index-v1.json",
        "nondecision_index": "nondecisions.tsv",
    }
    (capture / "capture-v1.json").write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--binary", type=Path, required=True, help="ioctlance built with solver-z3,solver-axeyum")
    parser.add_argument("--root", type=Path, required=True, help="tests/corpora/axeyum-qfbv/shadow-splits")
    parser.add_argument("--driver", action="append", default=[], help="PATH or TOKEN=PATH; repeatable")
    parser.add_argument("--ceiling", type=int, default=60, help="IOCTLANCE_SOLVE_SECS per function")
    parser.add_argument("--deadline", type=int, default=600, help="IOCTLANCE_DEADLINE_SECS per driver")
    parser.add_argument("--driver-timeout", type=int, default=None, help="kill a driver after this many seconds (default deadline + 300)")
    parser.add_argument("--env", action="append", default=[], help="extra KEY=VALUE for the capture process; repeatable")
    parser.add_argument("--revision", default=None, help="Glaurung revision to name the capture (default: git HEAD of the repo holding --root)")
    parser.add_argument("--lock", type=Path, default=None, help="Cargo.lock to read the Axeyum pin from")
    parser.add_argument("--log-dir", type=Path, default=None, help="where each driver's stderr goes (default <root>/../shadow-capture-logs)")
    parser.add_argument("--report", type=Path, default=None, help="write the per-driver JSON report here")
    parser.add_argument("--jobs", type=int, default=8)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.driver:
        print("shadow_capture.py: ERROR: at least one --driver is required", file=sys.stderr)
        return 2
    if args.ceiling <= 0 or args.deadline <= 0 or args.jobs <= 0:
        print("shadow_capture.py: ERROR: --ceiling, --deadline and --jobs must be positive", file=sys.stderr)
        return 2
    if not (args.binary.is_file() and os.access(args.binary, os.X_OK)):
        print(f"shadow_capture.py: ERROR: --binary {args.binary} is not an executable file", file=sys.stderr)
        return 2
    if not args.root.is_dir():
        print(f"shadow_capture.py: ERROR: --root {args.root} is not a directory", file=sys.stderr)
        return 2
    try:
        drivers = [parse_driver(spec) for spec in args.driver]
        _ = capture_env(args.root, args.ceiling, args.deadline, args.env)
    except ValueError as error:
        print(f"shadow_capture.py: ERROR: {error}", file=sys.stderr)
        return 2
    repo = args.root.resolve()
    while repo != repo.parent and not (repo / ".git").exists():
        repo = repo.parent
    glaurung_revision = args.revision or git_revision(repo)
    axeyum_revision = axeyum_pin(args.lock or (repo / "Cargo.lock"))
    driver_timeout = args.driver_timeout or (args.deadline + 300)
    log_dir = args.log_dir or (args.root.resolve().parent / "shadow-capture-logs")

    planned = []
    for token, driver in drivers:
        capture = args.root / f"{token}-{args.ceiling}s-{glaurung_revision[:7]}"
        if capture.exists():
            print(
                f"shadow_capture.py: ERROR: {capture} exists; a rerun at the same revision would "
                "duplicate index rows -- remove it or capture at a new revision",
                file=sys.stderr,
            )
            return 2
        planned.append((token, driver, capture))
    print(
        f"shadow-capture: glaurung {glaurung_revision[:12]} axeyum {axeyum_revision[:12]} "
        f"ceiling {args.ceiling} s deadline {args.deadline} s, {len(planned)} driver(s)"
    )

    report: dict[str, object] = {
        "schema": "glaurung-shadow-capture-report-v1",
        "glaurung_revision": glaurung_revision,
        "axeyum_revision": axeyum_revision,
        "ceiling_seconds": args.ceiling,
        "deadline_seconds": args.deadline,
        "drivers": [],
        "created_captures": [],
    }
    findings: list[str] = []
    status = 0
    for token, driver, capture in planned:
        print(f"--- {token}: {driver} -> {capture.name}")
        try:
            record, _stderr = run_driver(
                args.binary, token, driver, capture, args.ceiling, args.deadline, args.env,
                driver_timeout, log_dir,
            )
        except CaptureError as error:
            findings.append(str(error))
            report["drivers"].append({"token": token, "capture_name": capture.name, "failed": str(error)})
            status = 1
            continue
        inspected, capture_findings = inspect_capture(capture)
        record["capture"] = inspected
        findings.extend(capture_findings)
        run = record["run"]
        assert isinstance(run, dict)
        if run["sat_unsat_disagreements"] and not inspected["disagreements"]:
            findings.append(
                f"{capture.name}: the process counted {run['sat_unsat_disagreements']} "
                "sat/unsat disagreement(s) but published none -- the dump path failed; see the stderr log"
            )
        print(
            f"    wall {run['wall_seconds']} s, checks {run['queries']}, disagree {run['sat_unsat_disagreements']}, "
            f"split occurrences {run.get('split_occurrences', '?')}, distinct splits {inspected['splits']}, "
            f"malformed {inspected['malformed']}, reasons {inspected['nondecision_reasons']}"
        )
        if capture.is_dir():
            report["created_captures"].append(str(capture))
        if capture.is_dir() and inspected["splits"]:
            try:
                write_sidecars(
                    capture, record, inspected, glaurung_revision, axeyum_revision, args.ceiling, args.deadline,
                    capture_env(capture, args.ceiling, args.deadline, args.env), args.jobs,
                )
            except ValueError as error:
                findings.append(f"{capture.name}: validate_shadow_splits rejected the capture: {error}")
        elif capture.is_dir():
            # Only disagreements/ or malformed/ were written: no split index.
            findings.append(f"{capture.name}: directory holds no indexed split; do not commit it")
        else:
            print("    no split; no capture directory created")
        report["drivers"].append(record)

    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if findings:
        for finding in findings:
            print(f"shadow_capture.py: FAIL: {finding}", file=sys.stderr)
        return 1
    return status


if __name__ == "__main__":
    raise SystemExit(main())
