#!/usr/bin/env python3
"""Run Glaurung's real LLM pipeline over a blinded DecBench eval kit.

The runner reads only ``functions.json.public`` and performs static analysis.
It never executes target binaries. Successful records must prove that all three
agentic stages used an LLM; heuristic or malformed output is rejected.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, NamedTuple, cast

DEFAULT_MODEL = "openai:gpt-5.4-mini"
DEFAULT_SERVICE_TIER = "flex"
REQUIRED_LLM_STAGES = (
    "infer_function_signature",
    "classify_function_role",
    "rewrite_function_idiomatic",
)
DIAGNOSTICS_NAME = "glaurung-agentic-diagnostics.json"
C_PREAMBLE = """#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
"""


class PayloadError(ValueError):
    """The CLI returned output that is unsafe to treat as an agentic result."""


class AcceptedPayload(NamedTuple):
    """Validated C and its auditable LLM-stage provenance."""

    identifier: str
    source: str
    stage_sources: dict[str, str]
    confidence: float | None


class FunctionRun(NamedTuple):
    """One requested DecBench target and its retained outcome."""

    binary: str
    requested_va: int
    status: str
    elapsed_seconds: float
    identifier: str | None
    source: str | None
    stage_sources: dict[str, str]
    confidence: float | None
    error: str | None
    stderr_tail: str

    @classmethod
    def success(
        cls,
        *,
        binary: str,
        requested_va: int,
        accepted: AcceptedPayload,
        elapsed_seconds: float,
        stderr_tail: str = "",
    ) -> FunctionRun:
        """Build one accepted function record."""
        return cls(
            binary=binary,
            requested_va=requested_va,
            status="accepted",
            elapsed_seconds=elapsed_seconds,
            identifier=accepted.identifier,
            source=accepted.source,
            stage_sources=accepted.stage_sources,
            confidence=accepted.confidence,
            error=None,
            stderr_tail=stderr_tail,
        )

    @classmethod
    def failure(
        cls,
        *,
        binary: str,
        requested_va: int,
        elapsed_seconds: float,
        error: str,
        stderr_tail: str = "",
    ) -> FunctionRun:
        """Build one failed function record."""
        return cls(
            binary=binary,
            requested_va=requested_va,
            status="failed",
            elapsed_seconds=elapsed_seconds,
            identifier=None,
            source=None,
            stage_sources={},
            confidence=None,
            error=error,
            stderr_tail=stderr_tail,
        )


def _definition_present(source: str, identifier: str) -> bool:
    pattern = rf"\b{re.escape(identifier)}\s*\([^;{{}}]*\)\s*\{{"
    return re.search(pattern, source, flags=re.MULTILINE) is not None


def accept_payload(payload: object, *, requested_va: int) -> AcceptedPayload:
    """Validate one ``glaurung explain --format json`` payload.

    The authoritative address remains the kit's requested VA. An odd ARM Thumb
    bit is tolerated, but no other address translation is accepted.
    """
    if not isinstance(payload, dict):
        raise PayloadError("payload is not a JSON object")
    entry_va = payload.get("entry_va")
    if not isinstance(entry_va, int) or (entry_va & ~1) != (requested_va & ~1):
        raise PayloadError(
            f"entry address mismatch: requested 0x{requested_va:x}, got {entry_va!r}"
        )
    if payload.get("language") != "c":
        raise PayloadError(f"language is not C: {payload.get('language')!r}")

    stages = payload.get("stages")
    if not isinstance(stages, dict):
        raise PayloadError("stages is not a JSON object")
    stage_sources: dict[str, str] = {}
    for name in REQUIRED_LLM_STAGES:
        record = stages.get(name)
        source = record.get("source") if isinstance(record, dict) else None
        if source != "llm":
            raise PayloadError(f"{name} did not use the LLM: {source!r}")
        stage_sources[name] = cast(str, source)

    source = payload.get("source")
    if not isinstance(source, str) or not source.strip():
        raise PayloadError("source is empty")
    if "```" in source:
        raise PayloadError("source contains a markdown fence")

    identifier = f"sub_{requested_va & ~1:x}"
    if not _definition_present(source, identifier):
        raise PayloadError(f"source has no top-level {identifier} function definition")
    confidence = payload.get("confidence")
    confidence_value = (
        float(confidence) if isinstance(confidence, (int, float)) else None
    )
    return AcceptedPayload(
        identifier=identifier,
        source=source.rstrip() + "\n",
        stage_sources=stage_sources,
        confidence=confidence_value,
    )


def explain_command(
    binary: Path,
    requested_va: int,
    glaurung: Path,
    *,
    stage_timeout_ms: int,
) -> list[str]:
    """Return the address-scoped, fail-closed static-analysis command."""
    return [
        str(glaurung),
        "explain",
        str(binary),
        "--func",
        hex(requested_va),
        "--style",
        "c",
        "--fidelity",
        "tldr",
        "--no-layer0",
        "--timeout-ms",
        str(stage_timeout_ms),
        "--require-llm",
        "--format",
        "json",
    ]


def _kill_process_group(process: subprocess.Popen[str]) -> None:
    try:
        os.killpg(os.getpgid(process.pid), signal.SIGKILL)
    except (OSError, ProcessLookupError, PermissionError):
        try:
            process.kill()
        except OSError:
            pass
    try:
        process.wait(timeout=15)
    except subprocess.TimeoutExpired:
        pass


def run_one(
    *,
    kit_root: Path,
    glaurung: Path,
    binary_name: str,
    requested_va: int,
    stage_timeout_ms: int,
    process_timeout: int,
    model: str,
    service_tier: str,
) -> FunctionRun:
    """Run and validate one target. The target file is only read statically."""
    binary = kit_root / "binaries" / binary_name
    command = explain_command(
        binary, requested_va, glaurung, stage_timeout_ms=stage_timeout_ms
    )
    environment = dict(os.environ)
    environment["GLAURUNG_LLM_MODEL"] = model
    environment["GLAURUNG_OPENAI_SERVICE_TIER"] = service_tier
    environment["GLAURUNG_REQUIRE_LLM"] = "1"
    started = time.monotonic()
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=environment,
        start_new_session=True,
    )
    try:
        stdout, stderr = process.communicate(timeout=process_timeout)
    except subprocess.TimeoutExpired:
        _kill_process_group(process)
        return FunctionRun.failure(
            binary=binary_name,
            requested_va=requested_va,
            elapsed_seconds=time.monotonic() - started,
            error=f"process timeout after {process_timeout}s",
        )
    elapsed = time.monotonic() - started
    stderr_tail = stderr[-4000:]
    if process.returncode != 0:
        return FunctionRun.failure(
            binary=binary_name,
            requested_va=requested_va,
            elapsed_seconds=elapsed,
            error=f"glaurung exited {process.returncode}",
            stderr_tail=stderr_tail,
        )
    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError as error:
        return FunctionRun.failure(
            binary=binary_name,
            requested_va=requested_va,
            elapsed_seconds=elapsed,
            error=f"invalid JSON: {error}",
            stderr_tail=stderr_tail,
        )
    try:
        accepted = accept_payload(payload, requested_va=requested_va)
    except PayloadError as error:
        return FunctionRun.failure(
            binary=binary_name,
            requested_va=requested_va,
            elapsed_seconds=elapsed,
            error=str(error),
            stderr_tail=stderr_tail,
        )
    return FunctionRun.success(
        binary=binary_name,
        requested_va=requested_va,
        accepted=accepted,
        elapsed_seconds=elapsed,
        stderr_tail=stderr_tail,
    )


def build_submission(
    runs: list[FunctionRun], *, version: str
) -> tuple[dict[str, Any], dict[str, str]]:
    """Build DecBench's one-C-file-per-binary submission representation."""
    grouped: dict[str, list[FunctionRun]] = {}
    for run in runs:
        if run.status == "accepted" and run.source and run.identifier:
            grouped.setdefault(run.binary, []).append(run)

    results: dict[str, Any] = {}
    sources: dict[str, str] = {}
    for binary_name in sorted(grouped):
        accepted = sorted(grouped[binary_name], key=lambda item: item.requested_va)
        c_name = f"{Path(binary_name).stem}.c"
        source_parts = [cast(str, run.source).rstrip() for run in accepted]
        sources[c_name] = C_PREAMBLE + "\n" + "\n\n".join(source_parts) + "\n"
        results[c_name] = {
            "binary": binary_name,
            "functions": {
                str(run.identifier): f"0x{run.requested_va:x}" for run in accepted
            },
        }
    return (
        {
            "decompiler": {"name": "glaurung-agentic", "version": version},
            "results": results,
        },
        sources,
    )


def _atomic_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=path.parent, delete=False
    ) as stream:
        stream.write(text)
        temporary = Path(stream.name)
    os.replace(temporary, path)


def _run_to_dict(run: FunctionRun) -> dict[str, Any]:
    return {
        "binary": run.binary,
        "requested_va": f"0x{run.requested_va:x}",
        "status": run.status,
        "elapsed_seconds": round(run.elapsed_seconds, 3),
        "identifier": run.identifier,
        "source": run.source,
        "stage_sources": run.stage_sources,
        "confidence": run.confidence,
        "error": run.error,
        "stderr_tail": run.stderr_tail,
    }


def _run_from_dict(record: object) -> FunctionRun | None:
    if not isinstance(record, dict):
        return None
    typed_record = cast(dict[str, object], record)
    try:
        raw_va = typed_record["requested_va"]
        if isinstance(raw_va, str):
            requested_va = int(raw_va, 16)
        elif isinstance(raw_va, int):
            requested_va = raw_va
        else:
            return None
        raw_elapsed = typed_record.get("elapsed_seconds", 0.0)
        elapsed = (
            float(raw_elapsed) if isinstance(raw_elapsed, (int, float, str)) else 0.0
        )
        raw_stages = typed_record.get("stage_sources", {})
        stages = (
            cast(dict[object, object], raw_stages)
            if isinstance(raw_stages, dict)
            else {}
        )
        raw_confidence = typed_record.get("confidence")
        return FunctionRun(
            binary=str(typed_record["binary"]),
            requested_va=requested_va,
            status=str(typed_record["status"]),
            elapsed_seconds=elapsed,
            identifier=(
                str(typed_record["identifier"])
                if typed_record.get("identifier")
                else None
            ),
            source=(
                str(typed_record["source"]) if typed_record.get("source") else None
            ),
            stage_sources={str(key): str(value) for key, value in stages.items()},
            confidence=(
                float(raw_confidence)
                if isinstance(raw_confidence, (int, float))
                else None
            ),
            error=(str(typed_record["error"]) if typed_record.get("error") else None),
            stderr_tail=str(typed_record.get("stderr_tail", "")),
        )
    except (KeyError, TypeError, ValueError):
        return None


def _diagnostics(
    runs: list[FunctionRun],
    *,
    targets_total: int,
    binaries_total: int,
    model: str,
    service_tier: str,
    version: str,
    stage_timeout_ms: int,
    process_timeout: int,
) -> dict[str, Any]:
    accepted = [run for run in runs if run.status == "accepted"]
    return {
        "schema_version": 1,
        "static_analysis_only": True,
        "uses_functions_json_public_only": True,
        "configuration": {
            "model": model,
            "service_tier": service_tier,
            "version": version,
            "stage_timeout_ms": stage_timeout_ms,
            "process_timeout_seconds": process_timeout,
        },
        "summary": {
            "functions_total": targets_total,
            "functions_attempted": len(runs),
            "functions_accepted": len(accepted),
            "functions_failed": len(runs) - len(accepted),
            "binaries_total": binaries_total,
            "binaries_accepted": len({run.binary for run in accepted}),
            "elapsed_seconds": round(sum(run.elapsed_seconds for run in runs), 3),
        },
        "runs": [
            _run_to_dict(run)
            for run in sorted(runs, key=lambda item: (item.binary, item.requested_va))
        ],
    }


def _write_state(
    output_root: Path,
    runs: list[FunctionRun],
    *,
    targets_total: int,
    binaries_total: int,
    model: str,
    service_tier: str,
    version: str,
    stage_timeout_ms: int,
    process_timeout: int,
) -> dict[str, Any]:
    diagnostics = _diagnostics(
        runs,
        targets_total=targets_total,
        binaries_total=binaries_total,
        model=model,
        service_tier=service_tier,
        version=version,
        stage_timeout_ms=stage_timeout_ms,
        process_timeout=process_timeout,
    )
    _atomic_text(
        output_root / DIAGNOSTICS_NAME,
        json.dumps(diagnostics, indent=2, sort_keys=True) + "\n",
    )
    submission, sources = build_submission(runs, version=version)
    results_dir = output_root / "results"
    for name, source in sources.items():
        _atomic_text(results_dir / name, source)
    _atomic_text(
        results_dir / "results.json",
        json.dumps(submission, indent=2, sort_keys=True) + "\n",
    )
    return diagnostics


def _load_public_targets(kit_root: Path) -> dict[str, list[int]]:
    payload = json.loads((kit_root / "functions.json").read_text())
    public = payload.get("public") if isinstance(payload, dict) else None
    if not isinstance(public, dict) or not public:
        raise ValueError("functions.json.public is missing or empty")
    targets: dict[str, list[int]] = {}
    for binary_name, raw_addresses in public.items():
        if not isinstance(binary_name, str) or not isinstance(raw_addresses, list):
            raise TypeError("functions.json.public has an invalid entry")
        binary = kit_root / "binaries" / binary_name
        if not binary.is_file():
            raise ValueError(f"target binary is missing: {binary}")
        targets[binary_name] = [
            int(address, 16) if isinstance(address, str) else int(address)
            for address in raw_addresses
        ]
    return targets


def _default_version(model: str) -> str:
    revision = "unknown"
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "--short=12", "HEAD"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        if completed.returncode == 0 and completed.stdout.strip():
            revision = completed.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        pass
    return f"git-{revision}+{model}"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main(argv: list[str] | None = None) -> int:
    """Run or resume the official blinded external evaluation."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kit", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--glaurung", type=Path, default=None)
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--service-tier", default=DEFAULT_SERVICE_TIER)
    parser.add_argument("--version", default=None)
    parser.add_argument("--stage-timeout-ms", type=int, default=120_000)
    parser.add_argument("--process-timeout", type=int, default=900)
    parser.add_argument("--jobs", type=int, default=1)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument(
        "--only", action="append", default=[], help="attempt only this binary name"
    )
    args = parser.parse_args(argv)

    if args.jobs < 1 or args.jobs > 4:
        parser.error("--jobs must be between 1 and 4")
    if args.stage_timeout_ms < 2_000:
        parser.error("--stage-timeout-ms must be at least 2000")
    if args.process_timeout < 1:
        parser.error("--process-timeout must be positive")
    kit_root = args.kit.resolve()
    output_root = args.output_root.resolve()
    glaurung_raw = args.glaurung or shutil.which("glaurung")
    if not glaurung_raw:
        parser.error("glaurung executable not found; pass --glaurung")
    glaurung = Path(glaurung_raw).resolve()
    if not glaurung.is_file():
        parser.error(f"glaurung executable does not exist: {glaurung}")
    if args.model.startswith("openai:") and not os.environ.get("OPENAI_API_KEY"):
        parser.error("OPENAI_API_KEY is not set")

    try:
        targets = _load_public_targets(kit_root)
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as error:
        parser.error(str(error))
    if args.only:
        unknown = sorted(set(args.only) - set(targets))
        if unknown:
            parser.error(f"unknown --only binary: {', '.join(unknown)}")
        selected = {name: targets[name] for name in args.only}
    else:
        selected = targets

    diagnostics_path = output_root / DIAGNOSTICS_NAME
    if diagnostics_path.exists() and not args.resume:
        parser.error(
            f"{diagnostics_path} already exists; pass --resume or choose a fresh output root"
        )
    runs_by_key: dict[tuple[str, int], FunctionRun] = {}
    if args.resume and diagnostics_path.is_file():
        existing = json.loads(diagnostics_path.read_text())
        for record in existing.get("runs", []):
            run = _run_from_dict(record)
            if run is not None and run.status == "accepted":
                runs_by_key[(run.binary, run.requested_va)] = run

    work = [
        (binary_name, address)
        for binary_name, addresses in sorted(selected.items())
        for address in addresses
        if (binary_name, address) not in runs_by_key
    ]
    version = args.version or _default_version(args.model)
    output_root.mkdir(parents=True, exist_ok=True)
    total_targets = sum(len(addresses) for addresses in targets.values())

    def execute(item: tuple[str, int]) -> FunctionRun:
        binary_name, requested_va = item
        return run_one(
            kit_root=kit_root,
            glaurung=glaurung,
            binary_name=binary_name,
            requested_va=requested_va,
            stage_timeout_ms=args.stage_timeout_ms,
            process_timeout=args.process_timeout,
            model=args.model,
            service_tier=args.service_tier,
        )

    completed_count = 0
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as executor:
            futures = {executor.submit(execute, item): item for item in work}
            for future in concurrent.futures.as_completed(futures):
                run = future.result()
                runs_by_key[(run.binary, run.requested_va)] = run
                completed_count += 1
                runs = list(runs_by_key.values())
                diagnostics = _write_state(
                    output_root,
                    runs,
                    targets_total=total_targets,
                    binaries_total=len(targets),
                    model=args.model,
                    service_tier=args.service_tier,
                    version=version,
                    stage_timeout_ms=args.stage_timeout_ms,
                    process_timeout=args.process_timeout,
                )
                label = "ok" if run.status == "accepted" else f"FAILED: {run.error}"
                print(
                    f"[{completed_count:03d}/{len(work):03d}] {run.binary} "
                    f"@ 0x{run.requested_va:x}: {label} ({run.elapsed_seconds:.1f}s); "
                    f"accepted {diagnostics['summary']['functions_accepted']}/{total_targets}",
                    flush=True,
                )
    except KeyboardInterrupt:
        print(
            "interrupted; accepted results were retained for --resume", file=sys.stderr
        )
        return 130

    diagnostics = _write_state(
        output_root,
        list(runs_by_key.values()),
        targets_total=total_targets,
        binaries_total=len(targets),
        model=args.model,
        service_tier=args.service_tier,
        version=version,
        stage_timeout_ms=args.stage_timeout_ms,
        process_timeout=args.process_timeout,
    )
    summary = diagnostics["summary"]
    print(
        f"accepted {summary['functions_accepted']}/{total_targets} functions across "
        f"{summary['binaries_accepted']}/{len(targets)} binaries"
    )
    print(f"diagnostics sha256: {_sha256(output_root / DIAGNOSTICS_NAME)}")
    return 0 if summary["functions_failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
