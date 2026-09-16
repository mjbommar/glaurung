#!/usr/bin/env python3
"""Build, run, and capture Glaurung's runtime-analysis C corpus."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import resource
import shutil
import signal
import subprocess
import sys
import time
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "tests" / "runtime_samples"
MANIFEST = CORPUS / "manifest.toml"
DEFAULT_OUT = ROOT / "target" / "runtime-samples"


@dataclass(frozen=True)
class Sample:
    id: str
    category: str
    source: Path
    good: str
    bad: str
    expected_good: str
    expected_bad: str
    cflags: tuple[str, ...] = ()
    ldflags: tuple[str, ...] = ()


def load_samples(path: Path = MANIFEST) -> list[Sample]:
    raw = tomllib.loads(path.read_text())
    samples = [
        Sample(
            id=item["id"],
            category=item["category"],
            source=path.parent / item["source"],
            good=item["good"],
            bad=item["bad"],
            expected_good=item["expected_good"],
            expected_bad=item["expected_bad"],
            cflags=tuple(item.get("cflags", [])),
            ldflags=tuple(item.get("ldflags", [])),
        )
        for item in raw["sample"]
    ]
    ids = [sample.id for sample in samples]
    if len(ids) != len(set(ids)):
        raise ValueError("runtime sample ids must be unique")
    missing = [str(sample.source) for sample in samples if not sample.source.is_file()]
    if missing:
        raise ValueError(f"runtime sample sources missing: {missing}")
    return samples


def select(samples: list[Sample], names: list[str], categories: list[str]) -> list[Sample]:
    wanted = set(names)
    selected = [
        sample
        for sample in samples
        if (not wanted or sample.id in wanted)
        and (not categories or sample.category in categories)
    ]
    unknown = wanted - {sample.id for sample in samples}
    if unknown:
        raise ValueError(f"unknown samples: {', '.join(sorted(unknown))}")
    return selected


def lane_dir(out: Path, compiler: str, opt: str, link: str) -> Path:
    return out / "build" / f"{Path(compiler).name}-{opt}-{link}"


def compile_sample(sample: Sample, compiler: str, opt: str, link: str, out: Path) -> Path:
    destination = lane_dir(out, compiler, opt, link) / sample.id
    destination.parent.mkdir(parents=True, exist_ok=True)
    flags = ["-std=c11", "-g", f"-{opt}", "-fno-omit-frame-pointer", "-I", str(CORPUS / "include")]
    if link == "pie":
        flags += ["-fPIE", "-pie"]
    elif link == "no-pie":
        flags += ["-fno-pie", "-no-pie"]
    elif link == "static":
        flags += ["-static"]
    else:
        raise ValueError(f"unsupported link mode: {link}")
    command = [compiler, *flags, *sample.cflags, str(sample.source), "-o", str(destination), *sample.ldflags]
    subprocess.run(command, check=True)
    return destination


def compiler_identity(compiler: str) -> str:
    done = subprocess.run([compiler, "--version"], check=True, capture_output=True, text=True)
    return done.stdout.splitlines()[0]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def scenario_arg(sample: Sample, scenario: str) -> str:
    return sample.good if scenario == "good" else sample.bad


def run_one(binary: Path, sample: Sample, scenario: str, timeout: float) -> dict[str, Any]:
    started = time.monotonic()
    try:
        done = subprocess.run(
            [str(binary), scenario_arg(sample, scenario)],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            cwd=binary.parent,
        )
        returncode = done.returncode
        stdout = done.stdout
        stderr = done.stderr
        timed_out = False
    except subprocess.TimeoutExpired as error:
        returncode = None
        stdout = error.stdout.decode(errors="replace") if isinstance(error.stdout, bytes) else (error.stdout or "")
        stderr = error.stderr.decode(errors="replace") if isinstance(error.stderr, bytes) else (error.stderr or "")
        timed_out = True
    return {
        "sample": sample.id,
        "category": sample.category,
        "scenario": scenario,
        "returncode": returncode,
        "signal": -returncode if returncode is not None and returncode < 0 else None,
        "timed_out": timed_out,
        "stdout": stdout,
        "stderr": stderr,
        "elapsed_ms": round((time.monotonic() - started) * 1000, 3),
        "binary_sha256": sha256(binary),
    }


def observed_outcome(record: dict[str, Any]) -> str:
    if record["timed_out"]:
        return "timeout"
    if record["signal"] is not None:
        try:
            name = signal.Signals(record["signal"]).name
        except ValueError:
            name = str(record["signal"])
        return f"signal:{name}"
    return f"exit:{record['returncode']}"


def wait_stopped(pid: int, timeout: float) -> int:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        waited, status = os.waitpid(pid, os.WUNTRACED | os.WNOHANG)
        if waited == pid:
            if os.WIFSTOPPED(status):
                return os.WSTOPSIG(status)
            raise RuntimeError(f"process {pid} exited before checkpoint: status={status}")
        time.sleep(0.01)
    raise TimeoutError(f"process {pid} did not reach checkpoint")


def proc_text(pid: int, name: str) -> str:
    return Path(f"/proc/{pid}/{name}").read_text(errors="replace")


def environment_inventory(data: bytes) -> list[dict[str, Any]]:
    inventory = []
    for entry in data.split(b"\0"):
        if not entry:
            continue
        key, separator, value = entry.partition(b"=")
        inventory.append(
            {
                "name": key.decode(errors="replace"),
                "has_value": bool(separator),
                "value_size": len(value),
                "value_sha256": hashlib.sha256(value).hexdigest(),
            }
        )
    return sorted(inventory, key=lambda item: item["name"])


def capture_live(
    binary: Path,
    sample: Sample,
    scenario: str,
    out: Path,
    timeout: float,
    checkpoint: str = "exit",
) -> Path:
    capture = out / "captures" / binary.parent.name / sample.id / scenario / f"live-{checkpoint}"
    capture.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    checkpoint_variable = (
        "GLAURUNG_RUNTIME_CHECKPOINT_ENTRY"
        if checkpoint == "entry"
        else "GLAURUNG_RUNTIME_CHECKPOINT"
    )
    env[checkpoint_variable] = "1"
    proc = subprocess.Popen(
        [str(binary), scenario_arg(sample, scenario)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=binary.parent,
        env=env,
    )
    try:
        stop_signal = wait_stopped(proc.pid, timeout)
        files = {}
        for name in ("maps", "status", "stat", "cmdline", "auxv"):
            source = Path(f"/proc/{proc.pid}/{name}")
            if not source.exists():
                continue
            data = source.read_bytes()
            target = capture / name
            target.write_bytes(data)
            files[name] = {"size": len(data), "sha256": sha256(target)}
        environment = environment_inventory(Path(f"/proc/{proc.pid}/environ").read_bytes())
        environment_path = capture / "environment.json"
        environment_path.write_text(json.dumps(environment, indent=2, sort_keys=True) + "\n")
        files["environment"] = {
            "size": environment_path.stat().st_size,
            "sha256": sha256(environment_path),
            "values": "sha256-only",
        }
        fd_entries = {}
        for entry in sorted(Path(f"/proc/{proc.pid}/fd").iterdir(), key=lambda item: int(item.name)):
            try:
                fd_entries[entry.name] = os.readlink(entry)
            except OSError as error:
                fd_entries[entry.name] = f"<unreadable: {error}>"
        manifest = {
            "schema": "glaurung-runtime-live-v1",
            "sample": sample.id,
            "category": sample.category,
            "scenario": scenario,
            "pid": proc.pid,
            "checkpoint_signal": stop_signal,
            "checkpoint": checkpoint,
            "binary": str(binary),
            "binary_sha256": sha256(binary),
            "platform": platform.platform(),
            "files": files,
            "fds": fd_entries,
        }
        (capture / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    finally:
        try:
            os.kill(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait(timeout=timeout)
    return capture


def enable_core() -> None:
    resource.setrlimit(resource.RLIMIT_CORE, (resource.RLIM_INFINITY, resource.RLIM_INFINITY))


def capture_core(binary: Path, sample: Sample, scenario: str, out: Path, timeout: float) -> Path:
    capture = out / "captures" / binary.parent.name / sample.id / scenario / "core"
    capture.mkdir(parents=True, exist_ok=True)
    done = subprocess.run(
        [str(binary), scenario_arg(sample, scenario)],
        cwd=capture,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
        preexec_fn=enable_core,
    )
    candidates = sorted(capture.glob("core*"))
    cores = [path for path in candidates if path.is_file()]
    policy = Path("/proc/sys/kernel/core_pattern").read_text().strip()
    record = {
        "schema": "glaurung-runtime-core-v1",
        "sample": sample.id,
        "category": sample.category,
        "scenario": scenario,
        "returncode": done.returncode,
        "signal": -done.returncode if done.returncode < 0 else None,
        "stdout": done.stdout,
        "stderr": done.stderr,
        "core_pattern": policy,
        "core_files": [
            {"path": path.name, "size": path.stat().st_size, "sha256": sha256(path)} for path in cores
        ],
        "core_captured": bool(cores),
        "core_absence_reason": None if cores else "host core_pattern redirected or suppressed the dump",
    }
    (capture / "manifest.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    return capture


def ensure_binary(sample: Sample, args: argparse.Namespace) -> Path:
    binary = lane_dir(args.out, args.compiler, args.opt, args.link) / sample.id
    if not binary.exists() or args.rebuild:
        binary = compile_sample(sample, args.compiler, args.opt, args.link, args.out)
    return binary


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--manifest", type=Path, default=MANIFEST)
    result.add_argument("--out", type=Path, default=DEFAULT_OUT)
    sub = result.add_subparsers(dest="command", required=True)
    list_cmd = sub.add_parser("list")
    list_cmd.add_argument("--category", action="append", default=[])
    for name in ("build", "run", "verify", "live", "core"):
        cmd = sub.add_parser(name)
        cmd.add_argument("--sample", action="append", default=[])
        cmd.add_argument("--category", action="append", default=[])
        cmd.add_argument("--compiler", default="gcc")
        cmd.add_argument("--opt", choices=("O0", "O1", "O2", "O3", "Og", "Os"), default="O2")
        cmd.add_argument("--link", choices=("pie", "no-pie", "static"), default="pie")
        cmd.add_argument("--rebuild", action="store_true")
        cmd.add_argument("--timeout", type=float, default=5.0)
    for name in ("run", "live", "core"):
        sub.choices[name].add_argument("--scenario", choices=("good", "bad"), default="bad")
    sub.choices["live"].add_argument("--checkpoint", choices=("entry", "exit"), default="exit")
    matrix = sub.add_parser("matrix")
    matrix.add_argument("--sample", action="append", default=[])
    matrix.add_argument("--category", action="append", default=[])
    matrix.add_argument("--compiler", action="append", default=[])
    matrix.add_argument("--opt", action="append", choices=("O0", "O1", "O2", "O3", "Og", "Os"), default=[])
    matrix.add_argument("--link", action="append", choices=("pie", "no-pie", "static"), default=[])
    matrix.add_argument("--timeout", type=float, default=5.0)
    matrix.add_argument("--rebuild", action="store_true")
    return result


def main() -> int:
    args = parser().parse_args()
    samples = select(load_samples(args.manifest), getattr(args, "sample", []), args.category)
    if args.command == "list":
        for sample in samples:
            print(f"{sample.id}\t{sample.category}\t{sample.source.relative_to(CORPUS)}")
        return 0
    if args.command == "matrix":
        compilers = args.compiler or [name for name in ("gcc", "clang") if shutil.which(name)]
        opts = args.opt or ["O0", "O2"]
        links = args.link or ["pie", "no-pie"]
        if not compilers:
            raise SystemExit("no C compiler found")
        failures = []
        checked = 0
        for compiler in compilers:
            if shutil.which(compiler) is None:
                failures.append({"lane": compiler, "error": "compiler not found"})
                continue
            for opt in opts:
                for link in links:
                    for sample in samples:
                        binary = compile_sample(sample, compiler, opt, link, args.out)
                        for scenario in ("good", "bad"):
                            record = run_one(binary, sample, scenario, args.timeout)
                            expected = sample.expected_good if scenario == "good" else sample.expected_bad
                            observed = observed_outcome(record)
                            checked += 1
                            if observed != expected:
                                failures.append(
                                    {
                                        "lane": f"{compiler}-{opt}-{link}",
                                        "sample": sample.id,
                                        "scenario": scenario,
                                        "expected": expected,
                                        "observed": observed,
                                    }
                                )
        print(json.dumps({"checked": checked, "failures": failures}, indent=2, sort_keys=True))
        return 1 if failures else 0
    if shutil.which(args.compiler) is None:
        raise SystemExit(f"compiler not found: {args.compiler}")
    if args.command == "build":
        print(f"compiler: {compiler_identity(args.compiler)}")
        for sample in samples:
            print(compile_sample(sample, args.compiler, args.opt, args.link, args.out))
        return 0
    records = []
    for sample in samples:
        binary = ensure_binary(sample, args)
        if args.command == "run":
            records.append(run_one(binary, sample, args.scenario, args.timeout))
        elif args.command == "verify":
            for scenario in ("good", "bad"):
                record = run_one(binary, sample, scenario, args.timeout)
                expected = sample.expected_good if scenario == "good" else sample.expected_bad
                record["expected_outcome"] = expected
                record["observed_outcome"] = observed_outcome(record)
                record["matches"] = record["observed_outcome"] == expected
                records.append(record)
        elif args.command == "live":
            print(
                capture_live(
                    binary,
                    sample,
                    args.scenario,
                    args.out,
                    args.timeout,
                    args.checkpoint,
                )
            )
        else:
            print(capture_core(binary, sample, args.scenario, args.out, args.timeout))
    if records:
        if args.command == "verify":
            failures = [record for record in records if not record["matches"]]
            print(
                json.dumps(
                    {"checked": len(records), "failures": failures},
                    indent=2,
                    sort_keys=True,
                )
            )
            if failures:
                return 1
        else:
            print(json.dumps(records, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
