#!/usr/bin/env python3
"""Run and compare the fail-closed Glaurung/Axeyum lineage variance gate."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import platform
import re
import resource
import statistics
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from typing import Any

SCHEMA = "glaurung-axeyum-lineage-gate-v1"
DEFAULT_LIVE_PATHS = 9
DEFAULT_ASSERTIONS = 512
DEFAULT_REPLAY_SAT_CACHE_ENTRIES = 64
DEFAULT_REPLAY_SAT_CACHE_MODEL_VALUES = 4_096
DEFAULT_REPLAY_SAT_CACHE_MODEL_BITS = 262_144


@dataclass(frozen=True)
class DriverSpec:
    name: str
    filename: str
    solve_budget: int
    expected_queries: int
    expected_warm: dict[str, int]
    expected_auto_warm: dict[str, int]
    expected_auto: dict[str, int]
    expected_adaptive_warm: dict[str, int]
    expected_adaptive: dict[str, int]
    expected_adaptive_transfer_warm: dict[str, int]
    expected_adaptive_transfer: dict[str, int]
    expected_direct_delta_warm: dict[str, int]
    expected_adaptive_serial_warm: dict[str, int]
    expected_adaptive_serial: dict[str, int]


DRIVERS = {
    "surface": DriverSpec(
        name="surface",
        filename="windows-update-SurfacePenBleLcAddrAdaptationDriver.sys",
        solve_budget=1_000_000,
        expected_queries=2_551,
        expected_warm={
            "checks": 2_551,
            "exact": 121,
            "prefix-roots": 290_670,
            "added": 19_467,
            "popped": 147,
            "resets": 0,
            "paths-created": 358,
            "paths-closed": 358,
            "paths-live": 0,
            "paths-peak": 4,
            "path-cap-fallbacks": 0,
            "assertion-cap-fallbacks": 0,
            "max-live-paths": 9,
            "max-assertions-per-path": 512,
        },
        expected_auto_warm={
            "checks": 2_193,
            "exact": 8,
            "prefix-roots": 281_122,
            "added": 11_562,
            "popped": 146,
            "resets": 0,
            "paths-created": 191,
            "paths-closed": 191,
            "paths-live": 0,
            "paths-peak": 1,
            "path-cap-fallbacks": 0,
            "assertion-cap-fallbacks": 0,
            "max-live-paths": 9,
            "max-assertions-per-path": 512,
        },
        expected_auto={"probes": 358, "activations": 191},
        expected_adaptive_warm={
            "checks": 2_464,
            "exact": 92,
            "prefix-roots": 286_545,
            "added": 14_814,
            "popped": 147,
            "resets": 0,
            "paths-created": 300,
            "paths-closed": 300,
            "paths-live": 0,
            "paths-peak": 2,
            "path-cap-fallbacks": 87,
            "assertion-cap-fallbacks": 0,
            "max-live-paths": 9,
            "max-assertions-per-path": 512,
        },
        expected_adaptive={
            "pressure-events": 87,
            "expansions": 0,
            "initial-live-paths": 2,
            "pressure-threshold": 128,
        },
        expected_adaptive_transfer_warm={
            "checks": 2_535,
            "exact": 105,
            "prefix-roots": 296_225,
            "added": 11_152,
            "popped": 147,
            "resets": 0,
            "paths-created": 207,
            "paths-closed": 207,
            "paths-live": 0,
            "paths-peak": 2,
            "path-cap-fallbacks": 16,
            "assertion-cap-fallbacks": 0,
            "max-live-paths": 9,
            "max-assertions-per-path": 512,
        },
        expected_adaptive_transfer={
            "pressure-events": 16,
            "expansions": 0,
            "initial-live-paths": 2,
            "pressure-threshold": 128,
        },
        expected_direct_delta_warm={
            "checks": 2_535,
            "exact": 169,
            "prefix-roots": 296_225,
            "added": 11_005,
            "popped": 0,
            "resets": 0,
            "paths-created": 207,
            "paths-closed": 207,
            "paths-live": 0,
            "paths-peak": 2,
            "path-cap-fallbacks": 16,
            "assertion-cap-fallbacks": 0,
            "max-live-paths": 9,
            "max-assertions-per-path": 512,
        },
        expected_adaptive_serial_warm={
            "checks": 2_551,
            "exact": 61,
            "prefix-roots": 307_592,
            "added": 2_545,
            "popped": 1_087,
            "resets": 0,
            "paths-created": 43,
            "paths-closed": 43,
            "paths-live": 0,
            "paths-peak": 1,
            "path-cap-fallbacks": 0,
            "assertion-cap-fallbacks": 0,
            "max-live-paths": 9,
            "max-assertions-per-path": 512,
        },
        expected_adaptive_serial={
            "share-events": 165,
            "tracked-owners": 0,
            "references": 0,
            "peak-references": 11,
        },
    ),
    "netwtw10": DriverSpec(
        name="netwtw10",
        filename="windows-update-intel-wifi-NETwtw10.sys",
        solve_budget=20_000,
        expected_queries=28_356,
        expected_warm={
            "checks": 20_031,
            "exact": 1_285,
            "prefix-roots": 529_071,
            "added": 247_311,
            "popped": 2_228,
            "resets": 0,
            "paths-created": 5_961,
            "paths-closed": 5_961,
            "paths-live": 0,
            "paths-peak": 9,
            "path-cap-fallbacks": 8_325,
            "assertion-cap-fallbacks": 0,
            "max-live-paths": 9,
            "max-assertions-per-path": 512,
        },
        expected_auto_warm={
            "checks": 17_669,
            "exact": 173,
            "prefix-roots": 546_887,
            "added": 184_570,
            "popped": 2_974,
            "resets": 0,
            "paths-created": 4_099,
            "paths-closed": 4_099,
            "paths-live": 0,
            "paths-peak": 1,
            "path-cap-fallbacks": 0,
            "assertion-cap-fallbacks": 0,
            "max-live-paths": 9,
            "max-assertions-per-path": 512,
        },
        expected_auto={"probes": 10_687, "activations": 4_099},
        expected_adaptive_warm={
            "checks": 20_380,
            "exact": 1_316,
            "prefix-roots": 537_404,
            "added": 250_687,
            "popped": 2_319,
            "resets": 0,
            "paths-created": 6_056,
            "paths-closed": 6_056,
            "paths-live": 0,
            "paths-peak": 9,
            "path-cap-fallbacks": 7_976,
            "assertion-cap-fallbacks": 0,
            "max-live-paths": 9,
            "max-assertions-per-path": 512,
        },
        expected_adaptive={
            "pressure-events": 128,
            "expansions": 1,
            "initial-live-paths": 2,
            "pressure-threshold": 128,
        },
        expected_adaptive_transfer_warm={
            "checks": 25_820,
            "exact": 1_424,
            "prefix-roots": 940_157,
            "added": 165_023,
            "popped": 4_338,
            "resets": 0,
            "paths-created": 3_739,
            "paths-closed": 3_739,
            "paths-live": 0,
            "paths-peak": 9,
            "path-cap-fallbacks": 2_536,
            "assertion-cap-fallbacks": 0,
            "max-live-paths": 9,
            "max-assertions-per-path": 512,
        },
        expected_adaptive_transfer={
            "pressure-events": 128,
            "expansions": 1,
            "initial-live-paths": 2,
            "pressure-threshold": 128,
        },
        expected_direct_delta_warm={
            "checks": 25_820,
            "exact": 2_947,
            "prefix-roots": 940_152,
            "added": 160_588,
            "popped": 0,
            "resets": 0,
            "paths-created": 3_739,
            "paths-closed": 3_739,
            "paths-live": 0,
            "paths-peak": 9,
            "path-cap-fallbacks": 2_536,
            "assertion-cap-fallbacks": 0,
            "max-live-paths": 9,
            "max-assertions-per-path": 512,
        },
        expected_adaptive_serial_warm={
            "checks": 28_356,
            "exact": 1_056,
            "prefix-roots": 1_220_943,
            "added": 28_409,
            "popped": 24_915,
            "resets": 0,
            "paths-created": 164,
            "paths-closed": 164,
            "paths-live": 0,
            "paths-peak": 1,
            "path-cap-fallbacks": 0,
            "assertion-cap-fallbacks": 0,
            "max-live-paths": 9,
            "max-assertions-per-path": 512,
        },
        expected_adaptive_serial={
            "share-events": 5_551,
            "tracked-owners": 0,
            "references": 0,
            "peak-references": 31,
        },
    ),
}


def fail(message: str) -> None:
    raise ValueError(message)


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def command_output(*command: str) -> str:
    return subprocess.run(
        command, check=True, text=True, capture_output=True
    ).stdout.strip()


def git_identity(path: pathlib.Path, allow_dirty: bool) -> dict[str, Any]:
    git = ("git", "-c", "safe.directory=*")
    revision = command_output(*git, "-C", str(path), "rev-parse", "HEAD")
    dirty_lines = command_output(
        *git, "-C", str(path), "status", "--porcelain"
    ).splitlines()
    if dirty_lines and not allow_dirty:
        fail(f"repository is dirty: {path}: {dirty_lines[:5]}")
    return {"path": str(path.resolve()), "revision": revision, "dirty": dirty_lines}


def parse_key_values(line: str, prefix: str) -> dict[str, int]:
    if not line.startswith(prefix):
        fail(f"missing {prefix} prefix")
    values: dict[str, int] = {}
    for token in line[len(prefix) :].strip().split():
        if "=" not in token:
            continue
        key, raw = token.split("=", 1)
        if not re.fullmatch(r"[0-9]+", raw):
            fail(f"non-integer {prefix} field {key}={raw!r}")
        values[key] = int(raw)
    return values


def parse_elapsed(raw: str) -> float:
    parts = raw.split(":")
    if len(parts) == 2:
        minutes, seconds = parts
        return int(minutes) * 60 + float(seconds)
    if len(parts) == 3:
        hours, minutes, seconds = parts
        return int(hours) * 3600 + int(minutes) * 60 + float(seconds)
    fail(f"invalid elapsed time: {raw!r}")


def parse_run(stderr_path: pathlib.Path, time_path: pathlib.Path) -> dict[str, Any]:
    stderr = stderr_path.read_text(errors="replace")
    shadow_matches = re.findall(
        r"^\[shadow-diff\] queries=(\d+) agree=(\d+) disagree=(\d+) \| "
        r"SAME-STREAM z3=([0-9.]+)ms axeyum=([0-9.]+)ms speedup=([0-9.]+)x$",
        stderr,
        re.MULTILINE,
    )
    warm_lines = re.findall(r"^\[axeyum-warm\].*$", stderr, re.MULTILINE)
    auto_lines = re.findall(r"^\[axeyum-auto\].*$", stderr, re.MULTILINE)
    adaptive_lines = re.findall(r"^\[axeyum-adaptive\].*$", stderr, re.MULTILINE)
    serial_lines = re.findall(r"^\[axeyum-serial-owner\].*$", stderr, re.MULTILINE)
    sat_cache_lines = re.findall(r"^\[axeyum-sat-cache\].*$", stderr, re.MULTILINE)
    model_matches = re.findall(r"unknown-split=(\d+)$", stderr, re.MULTILINE)
    if (
        len(shadow_matches) != 1
        or len(warm_lines) != 1
        or len(auto_lines) > 1
        or len(adaptive_lines) > 1
        or len(serial_lines) > 1
        or len(sat_cache_lines) > 1
        or len(model_matches) != 1
    ):
        fail(
            "expected exactly one shadow/warm/model and at most one auto/adaptive/serial footer: "
            f"shadow={len(shadow_matches)} warm={len(warm_lines)} "
            f"auto={len(auto_lines)} adaptive={len(adaptive_lines)} "
            f"serial={len(serial_lines)} "
            f"sat-cache={len(sat_cache_lines)} "
            f"model={len(model_matches)}"
        )
    queries, agree, disagree, z3_ms, axeyum_ms, _speedup = shadow_matches[0]
    timing = time_path.read_text(errors="replace")
    rss_matches = re.findall(r"Maximum resident set size \(kbytes\): (\d+)", timing)
    elapsed_matches = re.findall(
        r"Elapsed \(wall clock\) time \(h:mm:ss or m:ss\): ([0-9:.]+)", timing
    )
    if len(rss_matches) != 1 or len(elapsed_matches) != 1:
        fail(f"expected exactly one RSS/elapsed record in {time_path}")
    return {
        "queries": int(queries),
        "agree": int(agree),
        "disagree": int(disagree),
        "unknown_split": int(model_matches[0]),
        "z3_ms": float(z3_ms),
        "axeyum_ms": float(axeyum_ms),
        "warm": parse_key_values(warm_lines[0], "[axeyum-warm]"),
        "auto": (
            parse_key_values(auto_lines[0], "[axeyum-auto]") if auto_lines else {}
        ),
        "adaptive": (
            parse_key_values(adaptive_lines[0], "[axeyum-adaptive]")
            if adaptive_lines
            else {}
        ),
        "serial": (
            parse_key_values(serial_lines[0], "[axeyum-serial-owner]")
            if serial_lines
            else {}
        ),
        "sat_cache": (
            parse_key_values(sat_cache_lines[0], "[axeyum-sat-cache]")
            if sat_cache_lines
            else {}
        ),
        "max_rss_kib": int(rss_matches[0]),
        "wall_seconds": parse_elapsed(elapsed_matches[0]),
    }


def summarize(runs: list[dict[str, Any]]) -> dict[str, Any]:
    axeyum = [float(run["axeyum_ms"]) for run in runs]
    z3 = [float(run["z3_ms"]) for run in runs]
    rss = [int(run["max_rss_kib"]) for run in runs]
    axeyum_mean = statistics.fmean(axeyum)
    z3_mean = statistics.fmean(z3)
    return {
        "runs": len(runs),
        "axeyum_mean_ms": axeyum_mean,
        "z3_mean_ms": z3_mean,
        "axeyum_z3_ratio": axeyum_mean / z3_mean,
        "axeyum_population_cv": statistics.pstdev(axeyum) / axeyum_mean,
        "z3_population_cv": statistics.pstdev(z3) / z3_mean,
        "median_rss_kib": int(statistics.median(rss)),
        "min_rss_kib": min(rss),
        "max_rss_kib": max(rss),
    }


def validate_artifact(artifact: dict[str, Any]) -> dict[str, dict[str, Any]]:
    if artifact.get("schema") != SCHEMA:
        fail(f"unexpected schema: {artifact.get('schema')!r}")
    repetitions = artifact.get("repetitions")
    if not isinstance(repetitions, int) or repetitions <= 0:
        fail("repetitions must be a positive integer")
    runs = artifact.get("runs")
    if not isinstance(runs, list) or not runs:
        fail("runs must be a non-empty array")
    policy = artifact.get("policy", {})
    warm_reuse = policy.get("warm_reuse", "lineage")
    if warm_reuse not in {"adaptive", "auto", "lineage"}:
        fail(f"unsupported warm-reuse policy: {warm_reuse!r}")
    replay_sat_cache = policy.get("replay_sat_cache", "off")
    if replay_sat_cache not in {"off", "on"}:
        fail(f"unsupported replay-SAT-cache policy: {replay_sat_cache!r}")
    warm_owner_transfer = policy.get("warm_owner_transfer", "off")
    if warm_owner_transfer not in {"off", "on"}:
        fail(f"unsupported warm-owner-transfer policy: {warm_owner_transfer!r}")
    if warm_owner_transfer == "on" and warm_reuse != "adaptive":
        fail("warm-owner transfer is admitted only with adaptive warm reuse")
    serial_sibling_reuse = policy.get("serial_sibling_reuse", "off")
    if serial_sibling_reuse not in {"off", "on"}:
        fail(f"unsupported serial-sibling-reuse policy: {serial_sibling_reuse!r}")
    if serial_sibling_reuse == "on" and (
        warm_reuse != "adaptive" or warm_owner_transfer != "on"
    ):
        fail("serial sibling reuse requires adaptive warm reuse and owner transfer")
    direct_delta = policy.get("direct_delta", "off")
    if direct_delta not in {"off", "on"}:
        fail(f"unsupported direct-delta policy: {direct_delta!r}")
    if direct_delta == "on" and (
        warm_reuse != "adaptive"
        or warm_owner_transfer != "on"
        or serial_sibling_reuse != "off"
    ):
        fail(
            "direct delta gate requires adaptive reuse, exclusive owner transfer, "
            "and serial sibling reuse off"
        )
    by_driver: dict[str, list[dict[str, Any]]] = {}
    for run in runs:
        if not isinstance(run, dict):
            fail("run is not an object")
        name = run.get("driver")
        if name not in DRIVERS:
            fail(f"unknown driver in artifact: {name!r}")
        by_driver.setdefault(name, []).append(run)
    summaries: dict[str, dict[str, Any]] = {}
    for name, driver_runs in sorted(by_driver.items()):
        spec = DRIVERS[name]
        if direct_delta == "on":
            expected_warm = spec.expected_direct_delta_warm
        elif serial_sibling_reuse == "on":
            expected_warm = spec.expected_adaptive_serial_warm
        elif warm_reuse == "adaptive" and warm_owner_transfer == "on":
            expected_warm = spec.expected_adaptive_transfer_warm
        elif warm_reuse == "adaptive":
            expected_warm = spec.expected_adaptive_warm
        elif warm_reuse == "auto":
            expected_warm = spec.expected_auto_warm
        else:
            expected_warm = spec.expected_warm
        expected_auto = spec.expected_auto if warm_reuse == "auto" else {}
        if serial_sibling_reuse == "on":
            expected_adaptive = {}
        elif warm_reuse == "adaptive" and warm_owner_transfer == "on":
            expected_adaptive = spec.expected_adaptive_transfer
        else:
            expected_adaptive = (
                spec.expected_adaptive if warm_reuse == "adaptive" else {}
            )
        if len(driver_runs) != repetitions:
            fail(f"{name}: expected {repetitions} runs, got {len(driver_runs)}")
        driver_runs.sort(key=lambda run: run.get("repetition", -1))
        stdout_hash = driver_runs[0].get("stdout_sha256")
        expected_cache = driver_runs[0].get("sat_cache", {})
        for index, run in enumerate(driver_runs, 1):
            if run.get("repetition") != index:
                fail(f"{name}: non-contiguous repetition sequence")
            if run.get("queries") != spec.expected_queries:
                fail(f"{name} run {index}: query count drift: {run.get('queries')}")
            if run.get("agree") != spec.expected_queries or run.get("disagree") != 0:
                fail(f"{name} run {index}: agreement gate failed")
            if run.get("unknown_split") != 0:
                fail(f"{name} run {index}: unknown split is nonzero")
            if run.get("warm") != expected_warm:
                fail(f"{name} run {index}: warm traffic drift: {run.get('warm')!r}")
            if run.get("auto", {}) != expected_auto:
                fail(f"{name} run {index}: auto traffic drift: {run.get('auto')!r}")
            if run.get("adaptive", {}) != expected_adaptive:
                fail(
                    f"{name} run {index}: adaptive traffic drift: "
                    f"{run.get('adaptive')!r}"
                )
            expected_serial = (
                spec.expected_adaptive_serial if serial_sibling_reuse == "on" else {}
            )
            if run.get("serial", {}) != expected_serial:
                fail(
                    f"{name} run {index}: serial-owner traffic drift: "
                    f"{run.get('serial')!r}"
                )
            cache = run.get("sat_cache", {})
            if cache != expected_cache:
                fail(f"{name} run {index}: replay-SAT-cache traffic drift")
            validate_replay_sat_cache(
                cache,
                enabled=replay_sat_cache == "on",
                warm_checks=run["warm"]["checks"],
                context=f"{name} run {index}",
            )
            if run.get("stdout_sha256") != stdout_hash:
                fail(f"{name} run {index}: finding output drift")
            warm = run["warm"]
            probes = run.get("auto", {}).get("probes", 0)
            if (
                warm["checks"]
                + probes
                + warm["path-cap-fallbacks"]
                + warm["assertion-cap-fallbacks"]
                != run["queries"]
            ):
                fail(f"{name} run {index}: warm/fallback partition mismatch")
        summaries[name] = summarize(driver_runs)
    return summaries


def validate_replay_sat_cache(
    cache: dict[str, int], *, enabled: bool, warm_checks: int, context: str
) -> None:
    if not cache:
        if enabled:
            fail(f"{context}: missing enabled replay-SAT-cache footer")
        return
    expected_fields = {
        "enabled",
        "max-entries",
        "max-model-values",
        "max-model-bits",
        "hits",
        "misses",
        "insertions",
        "evictions",
        "replay-failures",
        "declined-unsat",
        "declined-unknown",
        "declined-oversized-models",
        "declined-non-scalar-models",
        "entries",
        "model-values",
        "model-bits",
    }
    if set(cache) != expected_fields:
        fail(f"{context}: replay-SAT-cache footer fields drift")
    if cache["enabled"] != int(enabled):
        fail(f"{context}: replay-SAT-cache enablement mismatch")
    expected_bounds = (
        (
            DEFAULT_REPLAY_SAT_CACHE_ENTRIES,
            DEFAULT_REPLAY_SAT_CACHE_MODEL_VALUES,
            DEFAULT_REPLAY_SAT_CACHE_MODEL_BITS,
        )
        if enabled
        else (0, 0, 0)
    )
    observed_bounds = (
        cache["max-entries"],
        cache["max-model-values"],
        cache["max-model-bits"],
    )
    if observed_bounds != expected_bounds:
        fail(f"{context}: replay-SAT-cache bounds drift")
    if not enabled:
        if any(cache[field] for field in expected_fields - {"enabled"}):
            fail(f"{context}: disabled replay-SAT-cache has nonzero traffic")
        return
    if cache["hits"] + cache["misses"] != warm_checks:
        fail(f"{context}: replay-SAT-cache check partition mismatch")
    if cache["replay-failures"] != 0:
        fail(f"{context}: replay-SAT-cache replay failure")
    declined = (
        cache["declined-unsat"]
        + cache["declined-unknown"]
        + cache["declined-oversized-models"]
        + cache["declined-non-scalar-models"]
    )
    if cache["insertions"] + declined != cache["misses"]:
        fail(f"{context}: replay-SAT-cache fresh-result partition mismatch")
    if cache["entries"] or cache["model-values"] or cache["model-bits"]:
        fail(f"{context}: replay-SAT-cache state survived terminal paths")


def memory_limiter(bytes_limit: int):
    def limit() -> None:
        resource.setrlimit(resource.RLIMIT_AS, (bytes_limit, bytes_limit))

    return limit


def run_gate(args: argparse.Namespace) -> None:
    if args.warm_owner_transfer == "on" and args.warm_reuse != "adaptive":
        fail("warm-owner transfer is admitted only with adaptive warm reuse")
    if args.serial_sibling_reuse == "on" and (
        args.warm_reuse != "adaptive" or args.warm_owner_transfer != "on"
    ):
        fail("serial sibling reuse requires adaptive warm reuse and owner transfer")
    if args.direct_delta == "on" and (
        args.warm_reuse != "adaptive"
        or args.warm_owner_transfer != "on"
        or args.serial_sibling_reuse != "off"
    ):
        fail(
            "direct delta gate requires adaptive reuse, exclusive owner transfer, "
            "and serial sibling reuse off"
        )
    binary = pathlib.Path(args.binary).resolve()
    sample_root = pathlib.Path(args.sample_root).resolve()
    output = pathlib.Path(args.output).resolve()
    axeyum_repo = pathlib.Path(args.axeyum_repo).resolve()
    if not binary.is_file() or not os.access(binary, os.X_OK):
        fail(f"binary is not executable: {binary}")
    output.mkdir(parents=True, exist_ok=False)
    selected = [DRIVERS[name] for name in args.driver]
    sources = {
        "glaurung": git_identity(pathlib.Path.cwd(), args.allow_dirty),
        "axeyum": git_identity(axeyum_repo, args.allow_dirty),
        "binary": {"path": str(binary), "sha256": sha256_file(binary)},
    }
    drivers = {}
    for spec in selected:
        path = sample_root / spec.filename
        if not path.is_file():
            fail(f"missing driver: {path}")
        drivers[spec.name] = {
            "path": str(path),
            "sha256": sha256_file(path),
            "bytes": path.stat().st_size,
            "solve_budget": spec.solve_budget,
        }
    artifact: dict[str, Any] = {
        "schema": SCHEMA,
        "sources": sources,
        "system": {
            "platform": platform.platform(),
            "machine": platform.machine(),
            "processor": platform.processor(),
            "rustc": command_output("rustc", "-Vv"),
        },
        "policy": {
            "warm_reuse": args.warm_reuse,
            "warm_owner_transfer": args.warm_owner_transfer,
            "serial_sibling_reuse": args.serial_sibling_reuse,
            "direct_delta": args.direct_delta,
            "replay_sat_cache": args.replay_sat_cache,
            "replay_sat_cache_max_entries_per_path": DEFAULT_REPLAY_SAT_CACHE_ENTRIES,
            "replay_sat_cache_max_model_values_per_path": DEFAULT_REPLAY_SAT_CACHE_MODEL_VALUES,
            "replay_sat_cache_max_model_bits_per_path": DEFAULT_REPLAY_SAT_CACHE_MODEL_BITS,
            "max_live_paths": DEFAULT_LIVE_PATHS,
            "max_assertions_per_path": DEFAULT_ASSERTIONS,
            "analysis_deadline_seconds": 400,
            "solver_seconds": 600,
            "memory_limit_gib": args.memory_gib,
        },
        "repetitions": args.repetitions,
        "drivers": drivers,
        "runs": [],
    }
    bytes_limit = args.memory_gib * 1024**3
    for spec in selected:
        for repetition in range(1, args.repetitions + 1):
            prefix = f"{spec.name}-r{repetition}"
            stdout_path = output / f"{prefix}.stdout"
            stderr_path = output / f"{prefix}.stderr"
            time_path = output / f"{prefix}.time"
            environment = os.environ.copy()
            environment.update(
                {
                    "GLAURUNG_SHADOW_DIFF": "1",
                    "GLAURUNG_AXEYUM_WARM_REUSE": args.warm_reuse,
                    "GLAURUNG_AXEYUM_WARM_OWNER_TRANSFER": args.warm_owner_transfer,
                    "GLAURUNG_AXEYUM_WARM_SERIAL_SIBLING_REUSE": args.serial_sibling_reuse,
                    "GLAURUNG_AXEYUM_DIRECT_DELTA": args.direct_delta,
                    "GLAURUNG_AXEYUM_REPLAY_SAT_CACHE": args.replay_sat_cache,
                    "GLAURUNG_AXEYUM_WARM_MAX_LIVE_PATHS": str(DEFAULT_LIVE_PATHS),
                    "GLAURUNG_AXEYUM_WARM_MAX_ASSERTIONS_PER_PATH": str(
                        DEFAULT_ASSERTIONS
                    ),
                    "IOCTLANCE_DEADLINE_SECS": "400",
                    "IOCTLANCE_SOLVE_BUDGET": str(spec.solve_budget),
                    "IOCTLANCE_SOLVE_SECS": "600",
                }
            )
            command = [
                "/usr/bin/time",
                "-v",
                "-o",
                str(time_path),
                str(binary),
                str(sample_root / spec.filename),
            ]
            with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
                result = subprocess.run(
                    command,
                    env=environment,
                    stdout=stdout,
                    stderr=stderr,
                    preexec_fn=memory_limiter(bytes_limit),
                    check=False,
                )
            if result.returncode != 0:
                fail(f"{spec.name} repetition {repetition} exited {result.returncode}")
            run = parse_run(stderr_path, time_path)
            run.update(
                {
                    "driver": spec.name,
                    "repetition": repetition,
                    "stdout_sha256": sha256_file(stdout_path),
                    "stdout_path": stdout_path.name,
                    "stderr_path": stderr_path.name,
                    "time_path": time_path.name,
                }
            )
            artifact["runs"].append(run)
    artifact["summaries"] = validate_artifact(artifact)
    destination = output / "lineage-gate-v1.json"
    with tempfile.NamedTemporaryFile("w", dir=output, delete=False) as temporary:
        json.dump(artifact, temporary, indent=2, sort_keys=True)
        temporary.write("\n")
        temporary_path = pathlib.Path(temporary.name)
    temporary_path.replace(destination)
    print(json.dumps(artifact["summaries"], indent=2, sort_keys=True))
    print(f"artifact={destination}")


def load_artifact(path: pathlib.Path) -> dict[str, Any]:
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        fail(f"artifact is not an object: {path}")
    return value


def validate_comparison_identity(
    baseline: dict[str, Any],
    candidate: dict[str, Any],
    *,
    allow_lineage_to_adaptive: bool,
    allow_replay_sat_cache_enablement: bool = False,
    allow_warm_owner_transfer_enablement: bool = False,
    allow_serial_sibling_reuse_enablement: bool = False,
    allow_direct_delta_enablement: bool = False,
    allow_serial_snapshot_to_direct_delta: bool = False,
) -> None:
    for field in ("system", "repetitions", "drivers"):
        if baseline.get(field) != candidate.get(field):
            fail(f"comparison identity drift in {field}")
    before_policy = baseline.get("policy")
    after_policy = candidate.get("policy")
    if not isinstance(before_policy, dict) or not isinstance(after_policy, dict):
        fail("comparison policy identity is not an object")
    before_common = dict(before_policy)
    after_common = dict(after_policy)
    before_common.setdefault("direct_delta", "off")
    after_common.setdefault("direct_delta", "off")
    if (
        not allow_lineage_to_adaptive
        and not allow_replay_sat_cache_enablement
        and not allow_warm_owner_transfer_enablement
        and not allow_serial_sibling_reuse_enablement
        and not allow_direct_delta_enablement
        and not allow_serial_snapshot_to_direct_delta
    ):
        if before_common != after_common:
            fail("comparison identity drift in policy")
        return
    if allow_lineage_to_adaptive:
        before_warm = before_common.pop("warm_reuse", None)
        after_warm = after_common.pop("warm_reuse", None)
        if (before_warm, after_warm) != ("lineage", "adaptive"):
            fail(
                "cross-policy comparison requires lineage baseline and adaptive candidate"
            )
        if before_common != after_common:
            fail("comparison identity drift outside warm-reuse policy")
        return
    if allow_serial_snapshot_to_direct_delta:
        before_serial = before_common.pop("serial_sibling_reuse", "off")
        after_serial = after_common.pop("serial_sibling_reuse", "off")
        before_direct = before_common.pop("direct_delta", "off")
        after_direct = after_common.pop("direct_delta", "off")
        if (before_serial, after_serial, before_direct, after_direct) != (
            "on",
            "off",
            "off",
            "on",
        ):
            fail(
                "production direct comparison requires serial-snapshot baseline "
                "and exclusive-transfer direct candidate"
            )
        if before_common != after_common:
            fail("comparison identity drift outside production direct transition")
        return
    if allow_replay_sat_cache_enablement:
        before_cache = before_common.pop("replay_sat_cache", "off")
        after_cache = after_common.pop("replay_sat_cache", "off")
        if (before_cache, after_cache) != ("off", "on"):
            fail(
                "cache comparison requires replay-SAT-cache off baseline and on candidate"
            )
    if allow_warm_owner_transfer_enablement:
        before_transfer = before_common.pop("warm_owner_transfer", "off")
        after_transfer = after_common.pop("warm_owner_transfer", "off")
        if (before_transfer, after_transfer) != ("off", "on"):
            fail("owner-transfer comparison requires off baseline and on candidate")
    if allow_serial_sibling_reuse_enablement:
        before_serial = before_common.pop("serial_sibling_reuse", "off")
        after_serial = after_common.pop("serial_sibling_reuse", "off")
        if (before_serial, after_serial) != ("off", "on"):
            fail("serial-sibling comparison requires off baseline and on candidate")
    if allow_direct_delta_enablement:
        before_direct = before_common.pop("direct_delta", "off")
        after_direct = after_common.pop("direct_delta", "off")
        if (before_direct, after_direct) != ("off", "on"):
            fail("direct-delta comparison requires off baseline and on candidate")
    if before_common != after_common:
        fail("comparison identity drift outside named policy change")


def compare_artifacts(args: argparse.Namespace) -> None:
    baseline = load_artifact(pathlib.Path(args.baseline))
    candidate = load_artifact(pathlib.Path(args.candidate))
    baseline_summary = validate_artifact(baseline)
    candidate_summary = validate_artifact(candidate)
    validate_comparison_identity(
        baseline,
        candidate,
        allow_lineage_to_adaptive=args.allow_lineage_to_adaptive,
        allow_replay_sat_cache_enablement=args.allow_replay_sat_cache_enablement,
        allow_warm_owner_transfer_enablement=args.allow_warm_owner_transfer_enablement,
        allow_serial_sibling_reuse_enablement=args.allow_serial_sibling_reuse_enablement,
        allow_direct_delta_enablement=args.allow_direct_delta_enablement,
        allow_serial_snapshot_to_direct_delta=(
            args.allow_serial_snapshot_to_direct_delta
        ),
    )
    if set(baseline_summary) != set(candidate_summary):
        fail("driver membership drift")
    comparison = {}
    for name in sorted(baseline_summary):
        before_hashes = {
            run["stdout_sha256"] for run in baseline["runs"] if run["driver"] == name
        }
        after_hashes = {
            run["stdout_sha256"] for run in candidate["runs"] if run["driver"] == name
        }
        if before_hashes != after_hashes:
            fail(f"{name}: finding output drift across artifacts")
        before = baseline_summary[name]
        after = candidate_summary[name]
        comparison[name] = {
            "axeyum_change": after["axeyum_mean_ms"] / before["axeyum_mean_ms"] - 1,
            "z3_change": after["z3_mean_ms"] / before["z3_mean_ms"] - 1,
            "ratio_change": after["axeyum_z3_ratio"] / before["axeyum_z3_ratio"] - 1,
            "median_rss_change": after["median_rss_kib"] / before["median_rss_kib"] - 1,
        }
    print(json.dumps(comparison, indent=2, sort_keys=True))
    violations = threshold_violations(
        comparison,
        max_axeyum=args.max_axeyum_regression / 100,
        max_ratio=args.max_ratio_regression / 100,
        max_rss=args.max_rss_regression / 100,
        max_z3_drift=args.max_z3_drift / 100,
    )
    if violations:
        fail("regression alarms: " + "; ".join(violations))


def threshold_violations(
    comparison: dict[str, dict[str, float]],
    *,
    max_axeyum: float,
    max_ratio: float,
    max_rss: float,
    max_z3_drift: float,
) -> list[str]:
    violations = []
    for name, row in sorted(comparison.items()):
        checks = (
            ("axeyum", row["axeyum_change"], max_axeyum, False),
            ("ratio", row["ratio_change"], max_ratio, False),
            ("median-rss", row["median_rss_change"], max_rss, False),
            ("z3-drift", row["z3_change"], max_z3_drift, True),
        )
        for label, value, limit, absolute in checks:
            observed = abs(value) if absolute else value
            if observed > limit:
                violations.append(
                    f"{name} {label} {value * 100:+.2f}% exceeds {limit * 100:.2f}%"
                )
    return violations


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    run = subparsers.add_parser("run", help="run the fixed-work held-out gate")
    run.add_argument("--binary", required=True)
    run.add_argument("--axeyum-repo", required=True)
    run.add_argument(
        "--sample-root", default="samples/binaries/platforms/windows/vendor/realworld"
    )
    run.add_argument("--output", required=True)
    run.add_argument("--driver", choices=sorted(DRIVERS), action="append", default=[])
    run.add_argument("--repetitions", type=int, default=3)
    run.add_argument("--memory-gib", type=int, default=4)
    run.add_argument(
        "--warm-reuse", choices=("adaptive", "auto", "lineage"), default="lineage"
    )
    run.add_argument("--warm-owner-transfer", choices=("off", "on"), default="off")
    run.add_argument("--serial-sibling-reuse", choices=("off", "on"), default="off")
    run.add_argument("--direct-delta", choices=("off", "on"), default="off")
    run.add_argument("--replay-sat-cache", choices=("off", "on"), default="on")
    run.add_argument("--allow-dirty", action="store_true")
    validate = subparsers.add_parser("validate", help="validate one artifact")
    validate.add_argument("artifact")
    compare = subparsers.add_parser("compare", help="compare two homogeneous artifacts")
    compare.add_argument("baseline")
    compare.add_argument("candidate")
    compare.add_argument("--max-axeyum-regression", type=float, default=3.0)
    compare.add_argument("--max-ratio-regression", type=float, default=3.0)
    compare.add_argument("--max-rss-regression", type=float, default=5.0)
    compare.add_argument("--max-z3-drift", type=float, default=2.0)
    compare.add_argument("--allow-lineage-to-adaptive", action="store_true")
    compare.add_argument("--allow-replay-sat-cache-enablement", action="store_true")
    compare.add_argument("--allow-warm-owner-transfer-enablement", action="store_true")
    compare.add_argument("--allow-serial-sibling-reuse-enablement", action="store_true")
    compare.add_argument("--allow-direct-delta-enablement", action="store_true")
    compare.add_argument("--allow-serial-snapshot-to-direct-delta", action="store_true")
    args = parser.parse_args()
    try:
        if args.command == "run":
            if not args.driver:
                args.driver = sorted(DRIVERS)
            if args.repetitions <= 0 or args.memory_gib <= 0:
                fail("repetitions and memory-gib must be positive")
            run_gate(args)
        elif args.command == "validate":
            summary = validate_artifact(load_artifact(pathlib.Path(args.artifact)))
            print(json.dumps(summary, indent=2, sort_keys=True))
        else:
            if (
                min(
                    args.max_axeyum_regression,
                    args.max_ratio_regression,
                    args.max_rss_regression,
                    args.max_z3_drift,
                )
                < 0
            ):
                fail("comparison thresholds must be nonnegative percentages")
            compare_artifacts(args)
    except (
        OSError,
        subprocess.CalledProcessError,
        json.JSONDecodeError,
        ValueError,
    ) as error:
        print(f"lineage gate failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
