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
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "tests" / "runtime_samples"
MANIFEST = CORPUS / "manifest.toml"
SEMANTIC_ORACLES = CORPUS / "semantic-oracles.toml"
DEFAULT_OUT = ROOT / "target" / "runtime-samples"
SEMANTIC_FACT_VALUE_STATUSES = {
    "observed",
    "inferred",
    "static",
    "replayed",
    "symbolic",
}
SEMANTIC_FACT_INCOMPLETE_STATUSES = {"unknown", "unsupported", "unavailable"}


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


@dataclass(frozen=True)
class SemanticAssertion:
    kind: str
    subject: str
    predicate: str
    expected: str
    independent_oracle: str
    applies_to: tuple[str, ...]


@dataclass(frozen=True)
class SemanticOracle:
    id: str
    sample: str
    scenario: str
    process_outcome: str
    assertions: tuple[SemanticAssertion, ...]


def assertion_applies(
    assertion: SemanticAssertion,
    *,
    compiler: str,
    opt: str,
    link: str,
) -> bool:
    """Return whether any selector clause matches this exact build lane."""
    lane = {"compiler": Path(compiler).name, "opt": opt, "link": link}
    for clause in assertion.applies_to:
        if clause == "*":
            return True
        terms = clause.split(",")
        parsed: dict[str, str] = {}
        for term in terms:
            key, separator, value = term.partition(":")
            if not separator or key not in lane or not value or key in parsed:
                raise ValueError(f"invalid semantic oracle lane selector: {clause!r}")
            parsed[key] = value
        if all(lane[key] == value for key, value in parsed.items()):
            return True
    return False


def assertions_for_lane(
    oracle: SemanticOracle,
    *,
    compiler: str,
    opt: str,
    link: str,
) -> tuple[SemanticAssertion, ...]:
    return tuple(
        assertion
        for assertion in oracle.assertions
        if assertion_applies(
            assertion,
            compiler=compiler,
            opt=opt,
            link=link,
        )
    )


def evaluate_semantic_result(
    result: dict[str, Any],
    oracle: SemanticOracle,
) -> dict[str, Any]:
    """Compare analyzer facts to an oracle only at the evaluator boundary."""
    if result.get("schema") != "glaurung-runtime-semantic-result-v1":
        raise ValueError(
            "semantic result schema must be glaurung-runtime-semantic-result-v1"
        )
    if (result.get("sample"), result.get("scenario")) != (
        oracle.sample,
        oracle.scenario,
    ):
        raise ValueError("semantic result identity disagrees with oracle")
    lane = result.get("lane")
    if not isinstance(lane, dict):
        raise ValueError("semantic result lane must be an object")
    compiler = lane.get("compiler")
    opt = lane.get("optimization")
    link = lane.get("link")
    if not all(isinstance(value, str) and value for value in (compiler, opt, link)):
        raise ValueError("semantic result lane is incomplete")

    facts = result.get("facts")
    if not isinstance(facts, list):
        raise ValueError("semantic result facts must be a list")
    by_key: dict[tuple[str, str, str], dict[str, Any]] = {}
    for fact in facts:
        if not isinstance(fact, dict):
            raise ValueError("semantic result fact must be an object")
        key_values = tuple(fact.get(name) for name in ("kind", "subject", "predicate"))
        if not all(isinstance(value, str) and value for value in key_values):
            raise ValueError("semantic result fact identity is incomplete")
        key = (key_values[0], key_values[1], key_values[2])
        if key in by_key:
            raise ValueError(f"duplicate semantic result fact: {key!r}")
        status = fact.get("status")
        if (
            status
            not in SEMANTIC_FACT_VALUE_STATUSES | SEMANTIC_FACT_INCOMPLETE_STATUSES
        ):
            raise ValueError(f"semantic result fact has invalid status: {status!r}")
        if status in SEMANTIC_FACT_VALUE_STATUSES and not isinstance(
            fact.get("value"), str
        ):
            raise ValueError("resolved semantic result fact requires a string value")
        if status in SEMANTIC_FACT_INCOMPLETE_STATUSES and not isinstance(
            fact.get("reason"), str
        ):
            raise ValueError("incomplete semantic result fact requires a reason")
        by_key[key] = fact

    failures = []
    incomplete = []
    active = assertions_for_lane(oracle, compiler=compiler, opt=opt, link=link)
    expected_keys: set[tuple[str, str, str]] = set()
    for assertion in active:
        key = (assertion.kind, assertion.subject, assertion.predicate)
        if key in expected_keys:
            raise ValueError(f"oracle has duplicate active assertion: {key!r}")
        expected_keys.add(key)
        fact = by_key.get(key)
        if fact is None:
            failures.append({"fact": key, "error": "missing"})
        elif fact["status"] in SEMANTIC_FACT_INCOMPLETE_STATUSES:
            incomplete.append(
                {"fact": key, "status": fact["status"], "reason": fact["reason"]}
            )
        elif fact["value"] != assertion.expected:
            failures.append(
                {
                    "fact": key,
                    "error": "value_mismatch",
                    "expected": assertion.expected,
                    "observed": fact["value"],
                }
            )
    return {
        "schema": "glaurung-runtime-semantic-evaluation-v1",
        "case": oracle.id,
        "lane": lane,
        "passed": not failures and not incomplete,
        "matched": len(active) - len(failures) - len(incomplete),
        "failures": failures,
        "incomplete": incomplete,
        "unscored_facts": [list(key) for key in sorted(set(by_key) - expected_keys)],
    }


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


def load_semantic_oracles(
    path: Path = SEMANTIC_ORACLES,
    samples: list[Sample] | None = None,
    *,
    require_complete: bool = False,
) -> dict[tuple[str, str], SemanticOracle]:
    """Load evaluator-only semantic expectations for selected real samples.

    The execution and capture functions never receive this mapping. Keeping the
    join here, after acquisition, prevents expected facts from becoming analyzer
    inputs merely because they share a corpus manifest.
    """
    all_samples = load_samples()
    all_sample_ids = {sample.id for sample in all_samples}
    selected = samples if samples is not None else all_samples
    sample_by_id = {sample.id: sample for sample in selected}
    raw = tomllib.loads(path.read_text())
    if raw.get("version") != 1:
        raise ValueError("semantic oracle version must be 1")
    result: dict[tuple[str, str], SemanticOracle] = {}
    valid_kinds = {
        "terminal",
        "memory",
        "control",
        "dataflow",
        "os_event",
        "mapping",
        "negative",
    }
    for item in raw.get("case", []):
        sample_id = item.get("sample")
        if sample_id not in all_sample_ids:
            raise ValueError(
                f"semantic oracle references unknown sample: {sample_id!r}"
            )
        if sample_id not in sample_by_id:
            continue
        scenario = item.get("scenario")
        if scenario not in {"good", "bad"}:
            raise ValueError(f"semantic oracle has invalid scenario: {scenario!r}")
        key = (sample_id, scenario)
        if key in result:
            raise ValueError(f"duplicate semantic oracle: {sample_id}.{scenario}")
        expected_id = f"{sample_id}.{scenario}"
        if item.get("id") != expected_id:
            raise ValueError(f"semantic oracle id must be {expected_id}")
        process_outcome = item.get("process_outcome")
        sample = sample_by_id[sample_id]
        manifest_outcome = (
            sample.expected_good if scenario == "good" else sample.expected_bad
        )
        if process_outcome != manifest_outcome:
            raise ValueError(
                f"semantic oracle {expected_id} process outcome disagrees with manifest: "
                f"{process_outcome!r} != {manifest_outcome!r}"
            )
        assertions = []
        for assertion in item.get("assertion", []):
            missing = {
                name
                for name in (
                    "kind",
                    "subject",
                    "predicate",
                    "expected",
                    "independent_oracle",
                )
                if not isinstance(assertion.get(name), str) or not assertion[name]
            }
            if missing:
                raise ValueError(
                    f"semantic oracle {expected_id} assertion missing: {', '.join(sorted(missing))}"
                )
            if assertion["kind"] not in valid_kinds:
                raise ValueError(
                    f"semantic oracle {expected_id} has invalid assertion kind: "
                    f"{assertion['kind']}"
                )
            applies_to = assertion.get("applies_to", ["*"])
            if (
                not isinstance(applies_to, list)
                or not applies_to
                or any(
                    not isinstance(selector, str) or not selector
                    for selector in applies_to
                )
            ):
                raise ValueError(
                    f"semantic oracle {expected_id} has invalid applies_to selectors"
                )
            assertions.append(
                SemanticAssertion(
                    kind=assertion["kind"],
                    subject=assertion["subject"],
                    predicate=assertion["predicate"],
                    expected=assertion["expected"],
                    independent_oracle=assertion["independent_oracle"],
                    applies_to=tuple(applies_to),
                )
            )
            # Validate selector grammar even before a concrete lane is chosen.
            assertion_applies(
                assertions[-1],
                compiler="validation",
                opt="validation",
                link="validation",
            )
        if not assertions:
            raise ValueError(f"semantic oracle {expected_id} has no assertions")
        result[key] = SemanticOracle(
            id=expected_id,
            sample=sample_id,
            scenario=scenario,
            process_outcome=process_outcome,
            assertions=tuple(assertions),
        )
    if require_complete:
        missing_cases = [
            f"{sample.id}.{scenario}"
            for sample in selected
            for scenario in ("good", "bad")
            if (sample.id, scenario) not in result
        ]
        if missing_cases:
            raise ValueError(
                f"semantic oracles missing selected cases: {', '.join(missing_cases)}"
            )
    return result


def select(
    samples: list[Sample], names: list[str], categories: list[str]
) -> list[Sample]:
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


def compile_sample(
    sample: Sample, compiler: str, opt: str, link: str, out: Path
) -> Path:
    destination = lane_dir(out, compiler, opt, link) / sample.id
    destination.parent.mkdir(parents=True, exist_ok=True)
    flags = [
        "-std=c11",
        "-g",
        f"-{opt}",
        "-fno-omit-frame-pointer",
        "-I",
        str(CORPUS / "include"),
    ]
    if link == "pie":
        flags += ["-fPIE", "-pie"]
    elif link == "no-pie":
        flags += ["-fno-pie", "-no-pie"]
    elif link == "static":
        flags += ["-static"]
    else:
        raise ValueError(f"unsupported link mode: {link}")
    command = [
        compiler,
        *flags,
        *sample.cflags,
        str(sample.source),
        "-o",
        str(destination),
        *sample.ldflags,
    ]
    subprocess.run(command, check=True)
    return destination


def compiler_identity(compiler: str) -> str:
    done = subprocess.run(
        [compiler, "--version"], check=True, capture_output=True, text=True
    )
    return done.stdout.splitlines()[0]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_json(value: Any) -> str:
    """Serialize a ledger value deterministically, with no volatile whitespace."""
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    )


def analyzer_input_record(
    sample: Sample,
    scenario: str,
    binary: Path,
    binary_sha256: str,
) -> dict[str, Any]:
    """Describe analyzer inputs without copying expectations into the record."""
    return {
        "sample": sample.id,
        "category": sample.category,
        "scenario": scenario,
        "scenario_argument": scenario_arg(sample, scenario),
        "binary": binary.name,
        "binary_sha256": binary_sha256,
    }


def ledger_entry(
    *,
    sample: Sample,
    scenario: str,
    compiler: str,
    compiler_id: str,
    opt: str,
    link: str,
    binary: Path,
    record: dict[str, Any],
    semantic_oracle: SemanticOracle | None,
) -> dict[str, Any]:
    """Build one stable matrix result, excluding timings and output payloads."""
    expected = sample.expected_good if scenario == "good" else sample.expected_bad
    observed = observed_outcome(record)
    return {
        "sample": sample.id,
        "category": sample.category,
        "scenario": scenario,
        "lane": {
            "compiler": Path(compiler).name,
            "compiler_identity": compiler_id,
            "optimization": opt,
            "link": link,
        },
        "source_sha256": sha256(sample.source),
        "binary_sha256": record["binary_sha256"],
        "scenario_argument_sha256": hashlib.sha256(
            scenario_arg(sample, scenario).encode()
        ).hexdigest(),
        "expected_process_outcome": expected,
        "observed_process_outcome": observed,
        "process_outcome_matches": observed == expected,
        "semantic_oracle_id": semantic_oracle.id
        if semantic_oracle is not None
        else None,
    }


def make_matrix_ledger(
    *,
    entries: list[dict[str, Any]],
    requested: dict[str, list[str]],
    process_manifest_sha256: str,
    oracle_sha256: str | None,
) -> dict[str, Any]:
    ordered = sorted(
        entries,
        key=lambda item: (
            item["lane"]["compiler"],
            item["lane"]["optimization"],
            item["lane"]["link"],
            item["sample"],
            item["scenario"],
        ),
    )
    return {
        "schema": "glaurung-runtime-matrix-ledger-v1",
        "producer_sha256": sha256(Path(__file__)),
        "process_manifest_sha256": process_manifest_sha256,
        "requested": requested,
        "semantic_oracle_sha256": oracle_sha256,
        "entries": ordered,
        "summary": {
            "checked": len(ordered),
            "process_oracle_mismatches": sum(
                not entry["process_outcome_matches"] for entry in ordered
            ),
        },
    }


def scenario_arg(sample: Sample, scenario: str) -> str:
    return sample.good if scenario == "good" else sample.bad


def prepare_fixture_cwd(sample: Sample, cwd: Path) -> None:
    """Create deterministic non-secret inputs required by a real corpus case."""
    if sample.id == "normal_open_file":
        (cwd / "input.txt").write_bytes(b"glaurung runtime sample\n")
    if sample.id == "danger_symlink_follow":
        regular = cwd / "regular-input"
        target = cwd / "symlink-target"
        link = cwd / "link-input"
        regular.write_bytes(b"regular\n")
        target.write_bytes(b"symlink target\n")
        if link.is_symlink() or link.exists():
            link.unlink()
        link.symlink_to(target.name)


def fixture_environment(sample: Sample) -> dict[str, str]:
    """Return a deterministic environment for inputs a fixture deliberately reads."""
    env = os.environ.copy()
    if sample.id == "danger_dlopen_input":
        env["RUNTIME_SAMPLE_LIBRARY"] = "./untrusted-runtime-sample.so"
    return env


def run_one(
    binary: Path, sample: Sample, scenario: str, timeout: float
) -> dict[str, Any]:
    prepare_fixture_cwd(sample, binary.parent)
    started = time.monotonic()
    captured_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    proc = subprocess.Popen(
        [str(binary), scenario_arg(sample, scenario)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.DEVNULL,
        text=True,
        cwd=binary.parent,
        env=fixture_environment(sample),
    )
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
        returncode = proc.returncode
        timed_out = False
    except subprocess.TimeoutExpired as error:
        proc.kill()
        stdout, stderr = proc.communicate()
        returncode = None
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
        "os_pid": proc.pid,
        "captured_at": captured_at,
    }


def terminal_process_capsule(
    binary: Path, record: dict[str, Any], invocation_input: bytes
) -> tuple[str, list[tuple[str, bytes]]]:
    """Build a bounded terminal-result capsule without consulting an oracle."""
    if record["timed_out"] or record["returncode"] is None:
        raise ValueError("terminal-result capsule requires completed wait status")
    process_id = "process-main"
    artifact = {
        "sha256": sha256(binary),
        "byte_len": binary.stat().st_size,
        "display_path": str(binary),
    }
    if record["signal"] is None:
        terminal = {"kind": "exited", "code": record["returncode"]}
    else:
        terminal = {
            "kind": "signaled",
            "signal": record["signal"],
            "core_dumped": False,
        }
    payloads: list[tuple[str, bytes]] = []
    outputs = []
    for stream in ("stdout", "stderr"):
        data = record[stream].encode()
        payload_id = f"process-output-{stream}"
        payloads.append((payload_id, data))
        outputs.append(
            {
                "process_id": process_id,
                "stream": stream,
                "payload": {
                    "id": payload_id,
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "byte_len": len(data),
                    "sensitivity": "sensitive",
                },
                "truncated": False,
            }
        )
    capsule = {
        "schema": "glaurung-process-capsule-v1",
        "version": 1,
        "identity": {
            "capture_id": "terminal-"
            + hashlib.sha256(canonical_json(record).encode()).hexdigest(),
            "acquisition": "trace",
            "host_os": platform.system().lower(),
            "kernel": platform.release(),
            "captured_at": record["captured_at"],
        },
        "required_features": [],
        "target": {
            "architecture": {"x86_64": "X86_64", "amd64": "X86_64"}.get(
                platform.machine().lower(), "Unknown"
            ),
            "endianness": "Little" if sys.byteorder == "little" else "Big",
            "address_bits": 64 if sys.maxsize > 2**32 else 32,
            "os_abi": "linux",
        },
        "executable": artifact,
        "processes": [
            {
                "id": process_id,
                "os_pid": record["os_pid"],
                "terminal": terminal,
            }
        ],
        "modules": [],
        "mappings": [],
        "threads": [],
        "pages": [],
        "outputs": outputs,
        "descriptors": [],
        "events": [],
        "provenance": {
            "producer": "tools/runtime_sample_harness.py:terminal-result",
            "producer_version": "1",
            "command": [],
            "input_artifacts": [artifact],
            "input_bytes": [
                {
                    "name": "argv[1]",
                    "sha256": hashlib.sha256(invocation_input).hexdigest(),
                    "byte_len": len(invocation_input),
                    "sensitivity": "public",
                }
            ],
            "warnings": [],
        },
        "completeness": [
            {
                "evidence": "terminal_status",
                "status": "complete",
                "requested": True,
                "obtained": 1,
                "expected": 1,
            },
            {
                "evidence": "process_outputs",
                "status": "complete",
                "requested": True,
                "obtained": 2,
                "expected": 2,
            },
            {
                "evidence": "runtime_state",
                "status": "omitted",
                "reason": "terminal-result provider captures no mappings, threads, or pages",
                "requested": False,
                "obtained": 0,
                "expected": 0,
            },
        ],
    }
    return canonicalize_process_capsule(capsule), payloads


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


def process_semantic_result(
    record: dict[str, Any], *, compiler: str, opt: str, link: str
) -> dict[str, Any]:
    """Produce generic wait-status/stdout facts without loading semantic oracles."""
    facts: list[dict[str, Any]] = []
    if record["timed_out"]:
        facts.append(
            {
                "kind": "negative",
                "subject": "terminal_fault",
                "predicate": "present",
                "status": "unavailable",
                "reason": "process timed out before terminal wait status",
                "source": "wait_status",
            }
        )
    elif record["signal"] is not None:
        try:
            signal_name = signal.Signals(record["signal"]).name
        except ValueError:
            signal_name = str(record["signal"])
        facts.append(
            {
                "kind": "terminal",
                "subject": "terminal_fault",
                "predicate": "signal",
                "status": "observed",
                "value": signal_name,
                "source": "wait_status",
            }
        )
        reason = "wait status does not establish crash semantics or access direction"
        for kind, subject, predicate in (
            ("terminal", "terminal_fault", "class"),
            ("memory", "faulting_access", "access"),
            ("control", "faulting_transfer", "access"),
            ("control", "faulting_transfer", "target"),
        ):
            facts.append(
                {
                    "kind": kind,
                    "subject": subject,
                    "predicate": predicate,
                    "status": "unsupported",
                    "reason": reason,
                    "source": "wait_status",
                }
            )
    else:
        facts.append(
            {
                "kind": "negative",
                "subject": "terminal_fault",
                "predicate": "present",
                "status": "observed",
                "value": "false",
                "source": "wait_status",
            }
        )

    for line in record["stdout"].splitlines():
        fields = line.split()
        if len(fields) == 3 and fields[0] == "RESULT":
            label, value = fields[1:]
            facts.append(
                {
                    "kind": "process",
                    "subject": f"result:{label}",
                    "predicate": "value",
                    "status": "observed",
                    "value": value,
                    "source": "fixture_stdout",
                }
            )

    return {
        "schema": "glaurung-runtime-semantic-result-v1",
        "sample": record["sample"],
        "scenario": record["scenario"],
        "lane": {
            "compiler": Path(compiler).name,
            "optimization": opt,
            "link": link,
        },
        "evidence": {
            "kind": "process_record",
            "sha256": hashlib.sha256(canonical_json(record).encode()).hexdigest(),
        },
        "facts": facts,
    }


def crash_semantic_result(
    analysis: dict[str, Any],
    *,
    sample: str,
    scenario: str,
    compiler: str,
    opt: str,
    link: str,
) -> dict[str, Any]:
    """Project a typed crash analysis without consulting semantic oracles."""
    facts: list[dict[str, Any]] = []
    outcome = analysis.get("outcome")
    if outcome == "crash":
        report = analysis.get("report")
        if not isinstance(report, dict):
            raise ValueError("crash analysis is missing its report")
        signal_number = report.get("signal")
        if not isinstance(signal_number, int):
            raise ValueError("crash report is missing its numeric signal")
        try:
            signal_name = signal.Signals(signal_number).name
        except ValueError:
            signal_name = str(signal_number)
        facts.append(
            {
                "kind": "terminal",
                "subject": "terminal_fault",
                "predicate": "signal",
                "status": "observed",
                "value": signal_name,
                "source": "glaurung-runtime-crash-report-v1",
            }
        )
        crash_class = report.get("class")
        if isinstance(crash_class, dict):
            class_status = crash_class.get("status")
            if class_status in {"observed", "inferred"} and isinstance(
                crash_class.get("value"), str
            ):
                facts.append(
                    {
                        "kind": "terminal",
                        "subject": "terminal_fault",
                        "predicate": "class",
                        "status": class_status,
                        "value": crash_class["value"],
                        "source": crash_class.get(
                            "source", "glaurung-runtime-crash-report-v1"
                        ),
                    }
                )
            elif class_status == "unknown" and isinstance(
                crash_class.get("reason"), str
            ):
                facts.append(
                    {
                        "kind": "terminal",
                        "subject": "terminal_fault",
                        "predicate": "class",
                        "status": "unknown",
                        "reason": crash_class["reason"],
                        "source": "glaurung-runtime-crash-report-v1",
                    }
                )
        access = report.get("access")
        if isinstance(access, dict):
            access_status = access.get("status")
            if access_status in {"observed", "inferred"} and isinstance(
                access.get("value"), str
            ):
                subject = (
                    "faulting_transfer"
                    if access["value"] == "execute"
                    else "faulting_access"
                )
                facts.append(
                    {
                        "kind": "control"
                        if subject == "faulting_transfer"
                        else "memory",
                        "subject": subject,
                        "predicate": "direction",
                        "status": access_status,
                        "value": access["value"],
                        "source": access.get(
                            "source", "glaurung-runtime-crash-report-v1"
                        ),
                    }
                )
                precise_access = _crash_null_memory_access(report, access["value"])
                if precise_access is not None:
                    facts.append(
                        {
                            "kind": "memory",
                            "subject": "faulting_access",
                            "predicate": "access",
                            "status": "inferred",
                            "value": precise_access,
                            "source": (
                                "observed crash address/direction joined to exact "
                                "LLIR memory-operation width"
                            ),
                        }
                    )
                else:
                    facts.append(
                        {
                            "kind": "control"
                            if subject == "faulting_transfer"
                            else "memory",
                            "subject": subject,
                            "predicate": "access",
                            "status": "unsupported",
                            "reason": (
                                "crash report establishes direction but not the complete "
                                "object, permission, width, value, or byte description"
                            ),
                            "source": "glaurung-runtime-crash-report-v1",
                        }
                    )
        fault_address = report.get("fault_address")
        if (
            isinstance(fault_address, dict)
            and fault_address.get("status") == "observed"
            and isinstance(fault_address.get("value"), int)
        ):
            facts.append(
                {
                    "kind": "control",
                    "subject": "faulting_transfer",
                    "predicate": "target",
                    "status": "observed",
                    "value": f"address={fault_address['value']}",
                    "source": fault_address.get(
                        "source", "glaurung-runtime-crash-report-v1"
                    ),
                }
            )
    elif outcome == "no_crash":
        facts.append(
            {
                "kind": "negative",
                "subject": "terminal_fault",
                "predicate": "present",
                "status": "observed",
                "value": "false",
                "source": "glaurung-runtime-crash-report-v1",
            }
        )
    elif outcome in {"incomplete", "invalid_capsule"}:
        reason = analysis.get("reason")
        facts.append(
            {
                "kind": "negative",
                "subject": "terminal_fault",
                "predicate": "present",
                "status": "unavailable",
                "reason": reason
                if isinstance(reason, str)
                else "crash analysis incomplete",
                "source": "glaurung-runtime-crash-report-v1",
            }
        )
    else:
        raise ValueError(f"unsupported crash analysis outcome: {outcome!r}")

    return {
        "schema": "glaurung-runtime-semantic-result-v1",
        "sample": sample,
        "scenario": scenario,
        "lane": {
            "compiler": Path(compiler).name,
            "optimization": opt,
            "link": link,
        },
        "evidence": {
            "kind": "glaurung-runtime-crash-report-v1",
            "sha256": hashlib.sha256(canonical_json(analysis).encode()).hexdigest(),
        },
        "facts": facts,
    }


def _crash_null_memory_access(report: dict[str, Any], direction: str) -> str | None:
    """Return an exact null-access fact only when runtime and LLIR evidence agree."""
    expected_kind = {"read": "load", "write": "store"}.get(direction)
    if expected_kind is None:
        return None
    crash_class = report.get("class")
    fault_address = report.get("fault_address")
    static_location = report.get("static_location")
    if (
        not isinstance(crash_class, dict)
        or crash_class.get("status") not in {"observed", "inferred"}
        or crash_class.get("value") != f"null_{direction}"
        or not isinstance(fault_address, dict)
        or fault_address.get("status") != "observed"
        or fault_address.get("value") != 0
        or not isinstance(static_location, dict)
        or static_location.get("status") != "inferred"
    ):
        return None
    resolution = static_location.get("value")
    if not isinstance(resolution, dict) or resolution.get("verdict") != "exact":
        return None
    address = resolution.get("address")
    code = address.get("code") if isinstance(address, dict) else None
    operation_resolution = code.get("operations") if isinstance(code, dict) else None
    operations = (
        operation_resolution.get("operations")
        if isinstance(operation_resolution, dict)
        and operation_resolution.get("verdict") == "resolved"
        else None
    )
    if not isinstance(operations, list):
        return None
    candidates = [
        operation
        for operation in operations
        if isinstance(operation, dict)
        and operation.get("kind") == expected_kind
        and isinstance(operation.get("memory_access"), dict)
        and isinstance(operation["memory_access"].get("byte_len"), int)
    ]
    if len(candidates) != 1:
        return None
    byte_len = candidates[0]["memory_access"]["byte_len"]
    if byte_len <= 0:
        return None
    return f"{direction}:null:width={byte_len}"


def mapping_semantic_result(
    capsule_json: str,
    *,
    sample: str,
    scenario: str,
    compiler: str,
    opt: str,
    link: str,
) -> dict[str, Any]:
    """Derive bounded anonymous-mapping history without consulting oracles."""
    from glaurung import runtime_analysis

    canonical = runtime_analysis.canonicalize_process_capsule_json(capsule_json)
    behavior = json.loads(
        runtime_analysis.analyze_process_capsule_mapping_behavior(canonical)
    )
    complete = behavior.get("event_scope", {}).get("status") == "observed"
    candidates: list[str] = []
    if complete:
        transitions = behavior["transitions"]
        for lifetime in behavior["lifetimes"]:
            if lifetime.get("anonymous") is not True or not isinstance(
                lifetime.get("removed_sequence"), int
            ):
                continue
            labels = {
                "none": "none",
                "read": "R",
                "read|write": "RW",
                "read|execute": "RX",
                "read|write|execute": "RWX",
            }
            created_permissions = lifetime.get("created_permissions")
            if created_permissions not in labels:
                continue
            history = [labels[created_permissions]]
            for index in lifetime["transition_indices"]:
                permissions = transitions[index]["to_permissions"]
                history.append(labels.get(permissions, str(permissions)))
            history.append("unmapped")
            candidates.append("->".join(history))

    facts: list[dict[str, Any]] = []
    if len(candidates) == 1:
        facts.append(
            {
                "kind": "mapping",
                "subject": "anonymous_mapping",
                "predicate": "permission_history",
                "status": "observed",
                "value": candidates[0],
                "source": "complete normalized mmap/mprotect/munmap event stream",
            }
        )
    else:
        facts.append(
            {
                "kind": "mapping",
                "subject": "anonymous_mapping",
                "predicate": "permission_history",
                "status": "unknown" if complete else "unavailable",
                "reason": (
                    f"expected one complete anonymous RW mapping lifetime, found {len(candidates)}"
                    if complete
                    else "mapping event stream is incomplete"
                ),
                "source": "normalized mapping events",
            }
        )
    blind_spot = (
        "mapping event scope does not observe whether bytes in the mapping executed"
    )
    facts.extend(
        [
            {
                "kind": "negative",
                "subject": "anonymous_mapping",
                "predicate": "executed",
                "status": "unsupported",
                "reason": blind_spot,
                "source": "normalized mapping events",
            },
            {
                "kind": "mapping",
                "subject": "anonymous_mapping",
                "predicate": "executed_bytes",
                "status": "unsupported",
                "reason": blind_spot,
                "source": "normalized mapping events",
            },
        ]
    )
    if len(candidates) == 1:
        lifetime = next(
            item
            for item in behavior["lifetimes"]
            if item.get("anonymous") is True
            and isinstance(item.get("removed_sequence"), int)
            and item.get("created_permissions")
            in {"none", "read", "read|write", "read|execute", "read|write|execute"}
        )
        simultaneous = lifetime["created_permissions"] == "read|write|execute"
        facts.append(
            {
                "kind": "mapping" if simultaneous else "negative",
                "subject": "anonymous_mapping",
                "predicate": "simultaneous_wx",
                "status": "observed",
                "value": (
                    f"true:length={lifetime['byte_len']}" if simultaneous else "false"
                ),
                "source": "complete normalized mapping_create event",
            }
        )
    return {
        "schema": "glaurung-runtime-semantic-result-v1",
        "sample": sample,
        "scenario": scenario,
        "lane": {
            "compiler": Path(compiler).name,
            "optimization": opt,
            "link": link,
        },
        "evidence": {
            "kind": "glaurung-process-capsule-v1:mapping_events",
            "sha256": hashlib.sha256(canonical.encode()).hexdigest(),
        },
        "facts": facts,
    }


def process_tree_semantic_result(
    capsule_json: str,
    *,
    sample: str,
    scenario: str,
    compiler: str,
    opt: str,
    link: str,
) -> dict[str, Any]:
    """Project a bounded parent/child lifecycle without consulting oracles."""
    from glaurung import runtime_analysis

    canonical = runtime_analysis.canonicalize_process_capsule_json(capsule_json)
    behavior = json.loads(
        runtime_analysis.analyze_process_capsule_process_behavior(canonical)
    )
    complete = behavior.get("event_scope", {}).get("status") == "observed"
    created = []
    reaped = []
    malformed = False
    for creation in behavior.get("creations", []):
        outcome = creation.get("outcome") if isinstance(creation, dict) else None
        value = outcome.get("value") if isinstance(outcome, dict) else None
        if (
            isinstance(value, dict)
            and value.get("kind") == "success"
            and isinstance(value.get("child_os_pid"), int)
        ):
            created.append(value["child_os_pid"])
    for wait in behavior.get("waits", []):
        outcome = wait.get("outcome") if isinstance(wait, dict) else None
        value = outcome.get("value") if isinstance(outcome, dict) else None
        if (
            isinstance(value, dict)
            and value.get("kind") == "success"
            and isinstance(value.get("reaped_os_pid"), int)
        ):
            reaped.append(value["reaped_os_pid"])
    malformed = behavior.get("ignored_events") != 0
    coherent = (
        complete
        and not malformed
        and len(set(created)) == len(created)
        and len(set(reaped)) == len(reaped)
        and set(reaped).issubset(created)
    )
    facts: list[dict[str, Any]] = []
    if coherent:
        facts.extend(
            [
                {
                    "kind": "os_event",
                    "subject": "process_tree",
                    "predicate": "children_created",
                    "status": "observed",
                    "value": str(len(created)),
                    "source": "complete normalized process_create event scope",
                },
                {
                    "kind": "os_event",
                    "subject": "process_tree",
                    "predicate": "children_reaped",
                    "status": "observed",
                    "value": str(len(reaped)),
                    "source": "created-child identities joined to normalized process_wait results",
                },
            ]
        )
        if len(created) <= 1:
            facts.append(
                {
                    "kind": "negative",
                    "subject": "finding:excessive_fork",
                    "predicate": "present",
                    "status": "observed",
                    "value": "false",
                    "source": "complete bounded process-event scope",
                }
            )
    else:
        reason = "process-event scope is incomplete, malformed, or incoherent"
        for predicate in ("children_created", "children_reaped"):
            facts.append(
                {
                    "kind": "os_event",
                    "subject": "process_tree",
                    "predicate": predicate,
                    "status": "unknown",
                    "reason": reason,
                    "source": "normalized process events",
                }
            )
    return {
        "schema": "glaurung-runtime-semantic-result-v1",
        "sample": sample,
        "scenario": scenario,
        "lane": {
            "compiler": Path(compiler).name,
            "optimization": opt,
            "link": link,
        },
        "evidence": {
            "kind": "glaurung-runtime-process-behavior-report-v1",
            "sha256": hashlib.sha256(canonical_json(behavior).encode()).hexdigest(),
        },
        "facts": facts,
    }


def file_semantic_result(
    capsule_json: str,
    *,
    sample: str,
    scenario: str,
    compiler: str,
    opt: str,
    link: str,
) -> dict[str, Any]:
    """Project authorized file lifecycle facts without consulting semantic oracles."""
    from glaurung import runtime_analysis

    canonical = runtime_analysis.canonicalize_process_capsule_json(capsule_json)
    behavior = json.loads(
        runtime_analysis.analyze_process_capsule_file_behavior(canonical)
    )
    facts: list[dict[str, Any]] = []
    for opened in behavior["opens"]:
        path = opened["path"]
        outcome = opened["outcome"]
        if path.get("status") != "observed" or outcome.get("status") != "observed":
            continue
        value = outcome["value"]
        if value["kind"] == "success":
            result = "success"
        elif value["kind"] == "failure":
            result = f"failure:{value['errno']}"
        else:
            continue
        facts.append(
            {
                "kind": "os_event",
                "subject": f"path:{path['value']}",
                "predicate": "open_result",
                "status": "observed",
                "value": result,
                "source": outcome["source"],
            }
        )
        flags = set(opened["flags"].split("|"))
        if value["kind"] != "success" or "O_CREAT" not in flags:
            continue
        resource_id = opened["resource_id"]
        writes = sorted(
            (
                write
                for write in behavior["writes"]
                if write["resource_id"] == resource_id
                and write["sequence"] > opened["sequence"]
            ),
            key=lambda write: write["sequence"],
        )
        closes = sorted(
            (
                close
                for close in behavior["closes"]
                if close["resource_id"] == resource_id
                and close["sequence"] > opened["sequence"]
            ),
            key=lambda close: close["sequence"],
        )
        if not writes or not closes:
            continue
        if (
            any(
                write["content"].get("status") != "observed"
                or write["outcome"].get("status") != "observed"
                for write in writes
            )
            or closes[-1]["outcome"].get("status") != "observed"
        ):
            continue
        if "O_APPEND" in flags:
            for write in writes:
                facts.append(
                    {
                        "kind": "os_event",
                        "subject": f"file:{path['value']}",
                        "predicate": "write",
                        "status": "observed",
                        "value": (
                            f"O_APPEND:length={write['outcome']['value']}:"
                            f"bytes={write['content']['value']}"
                        ),
                        "source": "linked O_APPEND file_open and normalized file_write events",
                    }
                )
        open_parts = ["create"]
        if "O_TRUNC" in flags:
            open_parts.append("truncate")
        mode = opened.get("mode")
        if not isinstance(mode, str):
            continue
        lifecycle = f"open:{'|'.join(open_parts)}:{mode}"
        for write in writes:
            lifecycle += (
                f"->write:{write['outcome']['value']}:bytes={write['content']['value']}"
            )
        lifecycle += "->close"
        facts.append(
            {
                "kind": "os_event",
                "subject": f"file:{path['value']}",
                "predicate": "lifecycle",
                "status": "observed",
                "value": lifecycle,
                "source": "linked normalized file_open, file_write, and file_close events",
            }
        )
    for stated in behavior["stats"]:
        path = stated["path"]
        outcome = stated["outcome"]
        if path.get("status") != "observed" or outcome.get("status") != "observed":
            continue
        value = outcome["value"]
        if value["kind"] == "success":
            result = f"success:file_type={value['file_type']}"
        elif value["kind"] == "failure":
            result = f"failure:{value['errno']}"
        else:
            continue
        facts.append(
            {
                "kind": "os_event",
                "subject": f"path:{path['value']}",
                "predicate": "stat_result",
                "status": "observed",
                "value": result,
                "source": outcome["source"],
            }
        )
    for chmod in behavior["chmods"]:
        path = chmod["path"]
        outcome = chmod["outcome"]
        if (
            path.get("status") != "observed"
            or outcome.get("status") != "observed"
            or outcome.get("value") != "success"
        ):
            continue
        try:
            mode = int(chmod["mode"], 8)
        except (KeyError, TypeError, ValueError):
            continue
        subject = f"file:{path['value']}"
        facts.append(
            {
                "kind": "os_event",
                "subject": subject,
                "predicate": "mode_after_chmod",
                "status": "observed",
                "value": f"{mode & 0o7777:04o}",
                "source": outcome["source"],
            }
        )
        if mode & 0o002:
            facts.append(
                {
                    "kind": "os_event",
                    "subject": subject,
                    "predicate": "world_writable",
                    "status": "inferred",
                    "value": "true",
                    "source": "successful chmod mode permits world write",
                }
            )
    opens_by_resource = {
        opened["resource_id"]: opened
        for opened in behavior["opens"]
        if opened["path"].get("status") == "observed"
    }
    for read in behavior["reads"]:
        opened = opens_by_resource.get(read["resource_id"])
        if opened is None:
            continue
        content = read["content"]
        outcome = read["outcome"]
        if content.get("status") != "observed" or outcome.get("status") != "observed":
            continue
        content_bytes = bytes.fromhex(content["value"])
        content_summary = (
            "all_zero"
            if content_bytes and not any(content_bytes)
            else f"bytes={content['value']}"
        )
        facts.append(
            {
                "kind": "os_event",
                "subject": f"descriptor:{opened['path']['value']}",
                "predicate": "read",
                "status": "observed",
                "value": (
                    f"offset={read['offset']}:length={read['requested_byte_len']}:"
                    f"result={outcome['value']}:{content_summary}"
                ),
                "source": "linked normalized file_open and selected-content file_read events",
            }
        )
    for ioctl in behavior["ioctls"]:
        opened = opens_by_resource.get(ioctl["resource_id"])
        result = ioctl["result"]
        if opened is None or result.get("status") != "observed":
            continue
        facts.append(
            {
                "kind": "os_event",
                "subject": f"descriptor:{opened['path']['value']}",
                "predicate": "ioctl_request",
                "status": "observed",
                "value": f"0x{ioctl['request']:08x}:result={result['value']}",
                "source": "linked file_open resource and normalized ioctl result",
            }
        )
    authorized_handles_closed = True
    authorized_success_count = 0
    for opened in opens_by_resource.values():
        outcome = opened["outcome"]
        if outcome.get("status") != "observed":
            authorized_handles_closed = False
            continue
        open_value = outcome["value"]
        if open_value["kind"] != "success":
            continue
        authorized_success_count += 1
        resource_id = opened["resource_id"]
        source_descriptor = open_value["descriptor"]
        duplications = [
            duplication
            for duplication in behavior["duplications"]
            if duplication["resource_id"] == resource_id
            and duplication["outcome"].get("status") == "observed"
        ]
        handles = {source_descriptor} | {
            duplication["outcome"]["value"] for duplication in duplications
        }
        closed_handles = {
            close["descriptor"]
            for close in behavior["closes"]
            if close["resource_id"] == resource_id
            and close["outcome"].get("status") == "observed"
        }
        if not handles.issubset(closed_handles):
            authorized_handles_closed = False
        for duplication in duplications:
            duplicate_descriptor = duplication["outcome"]["value"]
            writes = [
                write
                for write in behavior["writes"]
                if write["resource_id"] == resource_id
                and write["descriptor"] == duplicate_descriptor
                and write["sequence"] > duplication["sequence"]
                and write["outcome"].get("status") == "observed"
            ]
            if len(writes) != 1 or not handles.issubset(closed_handles):
                continue
            facts.append(
                {
                    "kind": "os_event",
                    "subject": f"descriptor:{opened['path']['value']}",
                    "predicate": "duplication",
                    "status": "observed",
                    "value": (
                        f"open->dup->write:length={writes[0]['outcome']['value']}"
                        "->close_both"
                    ),
                    "source": "linked file_open, file_dup, file_write, and two file_close events",
                }
            )
    scope_complete = behavior.get("event_scope", {}).get("status") == "observed"
    well_formed_scope = scope_complete and behavior.get("ignored_events") == 0
    descriptor_leak_absent = (
        well_formed_scope and authorized_success_count > 0 and authorized_handles_closed
    )
    facts.append(
        {
            "kind": "negative",
            "subject": "finding:descriptor_leak",
            "predicate": "present",
            "status": "observed" if descriptor_leak_absent else "unknown",
            **(
                {"value": "false"}
                if descriptor_leak_absent
                else {"reason": "authorized descriptor closure is incomplete"}
            ),
            "source": "linked normalized descriptor handles and close events",
        }
    )
    for finding_kind in (
        "dangerous_file_open",
        "unsafe_file_create",
        "unsafe_file_write",
        "unsafe_append",
        "unsafe_metadata_access",
        "out_of_bounds_read",
        "untrusted_ioctl_request",
        "world_writable",
    ):
        finding_present = any(
            finding.get("kind") == finding_kind
            for finding in behavior["dangerous_findings"]
        )
        fact: dict[str, Any] = {
            "kind": "negative",
            "subject": f"finding:{finding_kind}",
            "predicate": "present",
            "source": "glaurung-runtime-file-behavior-report-v1",
        }
        if well_formed_scope and not finding_present:
            fact.update(status="observed", value="false")
        else:
            fact.update(
                status="unknown",
                reason="file-event scope is incomplete, malformed, or has matching finding evidence",
            )
        facts.append(fact)
    return {
        "schema": "glaurung-runtime-semantic-result-v1",
        "sample": sample,
        "scenario": scenario,
        "lane": {
            "compiler": Path(compiler).name,
            "optimization": opt,
            "link": link,
        },
        "evidence": {
            "kind": "glaurung-runtime-file-behavior-report-v1",
            "sha256": hashlib.sha256(canonical_json(behavior).encode()).hexdigest(),
        },
        "facts": facts,
    }


def instruction_trace_semantic_result(
    capsule_json: str,
    payloads: list[tuple[str, bytes]],
    executable_bytes: bytes,
    *,
    sample: str,
    scenario: str,
    compiler: str,
    opt: str,
    link: str,
) -> dict[str, Any]:
    """Project file facts plus typed instruction-trace source-to-sink evidence."""
    from glaurung import runtime_analysis

    result = file_semantic_result(
        capsule_json,
        sample=sample,
        scenario=scenario,
        compiler=compiler,
        opt=opt,
        link=link,
    )
    canonical = runtime_analysis.canonicalize_process_capsule_json(capsule_json)
    trace = json.loads(
        runtime_analysis.analyze_process_capsule_instruction_trace(
            canonical, payloads, executable_bytes
        )
    )
    behavior = json.loads(
        runtime_analysis.analyze_process_capsule_file_behavior(canonical)
    )
    capsule = json.loads(canonical)
    existing_ioctl = any(fact["predicate"] == "ioctl_request" for fact in result["facts"])
    ioctl_calls = [
        call
        for call in trace["call_relations"]
        if call["callee"].get("status") == "inferred"
        and call["callee"].get("value") == "ioctl"
        and call["operation_occurrence"].get("status") == "inferred"
        and call["return_occurrence"].get("status") == "inferred"
    ]
    if not existing_ioctl and len(ioctl_calls) == 1:
        ioctl_call = ioctl_calls[0]
        occurrence = ioctl_call["operation_occurrence"]["value"]
        descriptor = occurrence["inputs"].get("descriptor", {})
        request = occurrence["inputs"].get("request", {})
        matching_paths = {
            opened["path"]["value"]
            for opened in behavior["opens"]
            if opened["path"].get("status") == "observed"
            and opened["outcome"].get("status") == "observed"
            and opened["outcome"].get("value", {}).get("kind") == "success"
            and str(opened["outcome"]["value"].get("descriptor"))
            == descriptor.get("value")
        }
        matching_paths.update(
            item["target"]
            for item in capsule["descriptors"]
            if not item["redacted"]
            and str(item["number"]) == descriptor.get("value")
            and isinstance(item.get("target"), str)
        )
        if (
            descriptor.get("status") == "observed"
            and request.get("status") == "observed"
            and len(matching_paths) == 1
        ):
            return_value = ioctl_call["return_occurrence"]["value"]["return_value"]
            result32 = return_value & 0xFFFF_FFFF
            if result32 & 0x8000_0000:
                result32 -= 1 << 32
            result["facts"].append(
                {
                    "kind": "os_event",
                    "subject": f"descriptor:{next(iter(matching_paths))}",
                    "predicate": "ioctl_request",
                    "status": "inferred",
                    "value": f"0x{int(request['value']):08x}:result={result32}",
                    "source": (
                        "exact imported ioctl occurrence and observed return joined to "
                        "one authorized descriptor identity"
                    ),
                }
            )
    inferred = [
        relation["relation"]["value"]
        for relation in trace["input_to_call_arguments"]
        if relation["relation"].get("status") == "inferred"
    ]
    if len(inferred) == 1:
        relation = inferred[0]
        call_target = relation["sink_occurrence"]["static_operation"].get(
            "call_target", {}
        )
        if (
            relation["source_name"].startswith("argv[")
            and relation["argument_name"] == "request"
            and call_target.get("kind") == "direct"
            and call_target.get("symbol") == "ioctl"
        ):
            result["facts"].append(
                {
                    "kind": "dataflow",
                    "subject": "ioctl_request",
                    "predicate": "source_to_sink",
                    "status": "inferred",
                    "value": "scenario_selected->ioctl",
                    "source": (
                        "one inferred glaurung-runtime-instruction-trace-report-v1 "
                        "input-to-call-argument relation"
                    ),
                }
            )
            if relation["argument_value"] == "0" and len(ioctl_calls) == 1:
                negative = next(
                    fact
                    for fact in result["facts"]
                    if fact["kind"] == "negative"
                    and fact["subject"] == "finding:untrusted_ioctl_request"
                    and fact["predicate"] == "present"
                )
                negative.update(
                    status="inferred",
                    value="false",
                    source=(
                        "one typed input-to-ioctl relation carries the observed zero "
                        "request across the complete bounded trace"
                    ),
                )
                negative.pop("reason", None)
    result["evidence"] = {
        "kind": "glaurung-runtime-instruction-trace-report-v1",
        "sha256": hashlib.sha256(canonical_json(trace).encode()).hexdigest(),
    }
    return result


def descriptor_semantic_result(
    capsule_json: str,
    *,
    sample: str,
    scenario: str,
    compiler: str,
    opt: str,
    link: str,
) -> dict[str, Any]:
    """Project descriptor-resource facts without consulting semantic oracles."""
    from glaurung import runtime_analysis

    canonical = runtime_analysis.canonicalize_process_capsule_json(capsule_json)
    behavior = json.loads(
        runtime_analysis.analyze_process_capsule_descriptor_behavior(canonical)
    )
    facts: list[dict[str, Any]] = []
    all_endpoints_closed = True
    observed_resource_kinds: set[str] = set()
    for descriptor_resource in behavior["resources"]:
        resource_kind = descriptor_resource["kind"]
        if (
            resource_kind not in {"pipe", "socket", "socketpair"}
            or descriptor_resource["outcome"].get("status") != "observed"
        ):
            continue
        observed_resource_kinds.add(resource_kind)
        resource_id = descriptor_resource["resource_id"]
        transfers = sorted(
            (
                transfer
                for transfer in behavior["transfers"]
                if transfer["resource_id"] == resource_id
            ),
            key=lambda transfer: transfer["sequence"],
        )
        closed = {
            close["descriptor"]
            for close in behavior["closes"]
            if close["resource_id"] == resource_id
            and close["outcome"].get("status") == "observed"
        }
        endpoints = {
            endpoint["descriptor"] for endpoint in descriptor_resource["endpoints"]
        }
        if not endpoints.issubset(closed):
            all_endpoints_closed = False
        if resource_kind == "socket":
            domain = descriptor_resource.get("domain")
            socket_type = descriptor_resource.get("socket_type")
            if not isinstance(domain, str) or not isinstance(socket_type, str):
                continue
            for bound in behavior["binds"]:
                if (
                    bound["resource_id"] != resource_id
                    or bound["outcome"].get("status") != "observed"
                ):
                    continue
                port = "ephemeral" if bound["port"] == 0 else str(bound["port"])
                facts.append(
                    {
                        "kind": "os_event",
                        "subject": f"socket:{domain}/{socket_type}",
                        "predicate": "bind_endpoint",
                        "status": "observed",
                        "value": f"{bound['address']}:{port}",
                        "source": bound["outcome"]["source"],
                    }
                )
            continue
        if len(transfers) != 2:
            continue
        sent, received = transfers
        expected_operations = (
            ("write", "read") if resource_kind == "pipe" else ("send", "recv")
        )
        if (sent["operation"], received["operation"]) != expected_operations:
            continue
        if any(
            transfer["content"].get("status") != "observed"
            or transfer["outcome"].get("status") != "observed"
            for transfer in transfers
        ):
            continue
        if resource_kind == "pipe":
            subject = "pipe"
            source = "ordered linked pipe write/read observations"
        else:
            domain = descriptor_resource.get("domain")
            socket_type = descriptor_resource.get("socket_type")
            if not isinstance(domain, str) or not isinstance(socket_type, str):
                continue
            subject = f"socketpair:{domain}/{socket_type}"
            source = "ordered linked socketpair send/recv observations"
        facts.append(
            {
                "kind": "os_event",
                "subject": subject,
                "predicate": "roundtrip",
                "status": "observed",
                "value": (
                    f"{sent['operation']}:{sent['content']['value']}:"
                    f"length={sent['outcome']['value']}"
                    f"->{received['operation']}:{received['content']['value']}:"
                    f"length={received['outcome']['value']}"
                ),
                "source": source,
            }
        )
    scope_complete = behavior.get("event_scope", {}).get("status") == "observed"
    safe = (
        scope_complete
        and behavior.get("ignored_events") == 0
        and bool(observed_resource_kinds)
        and all_endpoints_closed
    )
    if "pipe" in observed_resource_kinds:
        negative_subject = "finding:unsafe_ipc"
        negative_predicate = "present"
    elif "socket" in observed_resource_kinds:
        socket_resource = next(
            item for item in behavior["resources"] if item["kind"] == "socket"
        )
        negative_subject = (
            f"socket:{socket_resource['domain']}/{socket_resource['socket_type']}"
        )
        negative_predicate = "listen_called"
        if behavior["listens"]:
            safe = False
    else:
        negative_subject = "finding:network_listener"
        negative_predicate = "present"
    facts.append(
        {
            "kind": "negative",
            "subject": negative_subject,
            "predicate": negative_predicate,
            "status": "observed" if safe else "unknown",
            **(
                {"value": "false"}
                if safe
                else {
                    "reason": "descriptor event scope or endpoint closure is incomplete"
                }
            ),
            "source": "glaurung-runtime-descriptor-behavior-report-v1",
        }
    )
    return {
        "schema": "glaurung-runtime-semantic-result-v1",
        "sample": sample,
        "scenario": scenario,
        "lane": {
            "compiler": Path(compiler).name,
            "optimization": opt,
            "link": link,
        },
        "evidence": {
            "kind": "glaurung-runtime-descriptor-behavior-report-v1",
            "sha256": hashlib.sha256(canonical_json(behavior).encode()).hexdigest(),
        },
        "facts": facts,
    }


def heap_object_semantic_result(
    capsule_json: str,
    report: dict[str, Any],
    *,
    sample: str,
    scenario: str,
    compiler: str,
    opt: str,
    link: str,
) -> dict[str, Any]:
    """Project source-related heap lifetime facts without loading an oracle."""
    if report.get("schema") != "glaurung-runtime-object-change-report-v1":
        raise ValueError("object-change report has an unsupported schema")
    capsule = json.loads(capsule_json)
    write_completeness = next(
        (
            item
            for item in capsule.get("completeness", [])
            if item.get("evidence") == "heap_object_writes"
        ),
        None,
    )
    write_scope = capsule.get("provider.heap_snapshot", {}).get("write_scope")
    facts: list[dict[str, Any]] = []
    for changed in report.get("objects", []):
        if not isinstance(changed, dict):
            continue
        prefix_evidence = changed.get("allocation_prefix_write")
        prefix = (
            prefix_evidence.get("value")
            if isinstance(prefix_evidence, dict)
            and prefix_evidence.get("status") == "inferred"
            and isinstance(prefix_evidence.get("value"), dict)
            else None
        )
        if (
            isinstance(prefix, dict)
            and prefix.get("classification")
            == "crosses_allocation_prefix_within_object"
            and isinstance(prefix.get("logical_prefix_byte_len"), int)
            and isinstance(prefix.get("write_byte_len"), int)
            and isinstance(prefix.get("source_pointer"), dict)
            and isinstance(prefix["source_pointer"].get("source_name"), str)
        ):
            facts.append(
                {
                    "kind": "memory",
                    "subject": (
                        f"heap_object:{prefix['source_pointer']['source_name']}"
                    ),
                    "predicate": "bounds_violation",
                    "status": "inferred",
                    "value": (
                        f"logical_allocation={prefix['logical_prefix_byte_len']}:"
                        f"write_length={prefix['write_byte_len']}"
                    ),
                    "source": (
                        "glaurung-runtime-object-change-report-v1 "
                        "allocation-prefix relation"
                    ),
                }
            )
        writes = [
            write
            for write in changed.get("write_observations", [])
            if isinstance(write, dict)
            and write.get("source_pointer", {}).get("status") == "inferred"
        ]
        source_names = {
            write["source_pointer"]["value"].get("source_name") for write in writes
        }
        source_names.discard(None)
        if len(source_names) != 1:
            continue
        source_name = next(iter(source_names))
        if not isinstance(source_name, str):
            continue
        subject = f"heap_object:{source_name}"
        ended = [write for write in writes if write.get("lifetime") == "ended"]
        live = [write for write in writes if write.get("lifetime") == "live"]
        selected = ended[-1] if ended else (live[-1] if live else None)
        transition_evidence = changed.get("allocation_prefix_transition")
        transition = (
            transition_evidence.get("value")
            if isinstance(transition_evidence, dict)
            and transition_evidence.get("status") == "inferred"
            and isinstance(transition_evidence.get("value"), dict)
            else None
        )
        prefix_intervals = (
            transition.get("prefix_changed_intervals")
            if isinstance(transition, dict)
            else None
        )
        transition_emitted = False
        if isinstance(prefix_intervals, list) and len(prefix_intervals) == 1:
            interval = prefix_intervals[0]
            if isinstance(interval, dict):
                start = interval.get("object_offset_start")
                end = interval.get("object_offset_end")
                before_hex = interval.get("before_hex")
                after_hex = interval.get("after_hex")
                if (
                    isinstance(start, int)
                    and isinstance(end, int)
                    and isinstance(before_hex, str)
                    and isinstance(after_hex, str)
                ):

                    def compact_uniform(encoded: str) -> str:
                        raw = bytes.fromhex(encoded)
                        return raw[:1].hex() if raw and len(set(raw)) == 1 else encoded

                    facts.append(
                        {
                            "kind": "memory",
                            "subject": subject,
                            "predicate": "changed_interval",
                            "status": "inferred",
                            "value": (
                                f"offset={start}..{end}:"
                                f"old={compact_uniform(before_hex)}:"
                                f"new={compact_uniform(after_hex)}"
                            ),
                            "source": (
                                "hash-verified snapshots bracketing one exact "
                                "allocation-prefix write occurrence"
                            ),
                        }
                    )
                    transition_emitted = True
        if selected is not None and not transition_emitted:
            offset = selected.get("object_offset", {}).get("value")
            byte_len = selected.get("byte_len")
            after_hex = selected.get("after_hex", {}).get("value")
            if (
                isinstance(offset, int)
                and isinstance(byte_len, int)
                and isinstance(after_hex, str)
            ):
                old_hex = "unknown"
                if selected.get("lifetime") == "live":
                    intervals = changed.get("changed_intervals", {}).get("value")
                    if isinstance(intervals, list):
                        matches = [
                            interval
                            for interval in intervals
                            if isinstance(interval, dict)
                            and interval.get("object_offset_start") == offset
                            and interval.get("object_offset_end") == offset + byte_len
                            and interval.get("after_hex") == after_hex
                        ]
                        if len(matches) == 1 and isinstance(
                            matches[0].get("before_hex"), str
                        ):
                            old_hex = matches[0]["before_hex"]
                facts.append(
                    {
                        "kind": "memory",
                        "subject": subject,
                        "predicate": "changed_interval",
                        "status": "inferred",
                        "value": (
                            f"offset={offset}..{offset + byte_len}:old={old_hex}:"
                            f"new={after_hex}:lifetime={selected['lifetime']}"
                        ),
                        "source": "glaurung-runtime-object-change-report-v1",
                    }
                )
        if ended:
            violation = ended[-1]
            offset = violation.get("object_offset", {}).get("value")
            if isinstance(offset, int):
                facts.append(
                    {
                        "kind": "memory",
                        "subject": subject,
                        "predicate": "lifetime_violation",
                        "status": "inferred",
                        "value": f"write_after_free:offset={offset}",
                        "source": "event-ordered allocation lifetime and operation occurrence",
                    }
                )
        else:
            complete = (
                isinstance(write_completeness, dict)
                and write_completeness.get("status") == "complete"
            )
            facts.append(
                {
                    "kind": "negative",
                    "subject": subject,
                    "predicate": "changed",
                    "status": "unknown",
                    "reason": (
                        "write stream is complete only for provider scope "
                        f"{write_scope!r}"
                        if complete
                        else "heap write-stream completeness is unavailable"
                    ),
                    "source": "capsule heap_object_writes completeness",
                }
            )
    return {
        "schema": "glaurung-runtime-semantic-result-v1",
        "sample": sample,
        "scenario": scenario,
        "lane": {
            "compiler": Path(compiler).name,
            "optimization": opt,
            "link": link,
        },
        "evidence": {
            "kind": "glaurung-runtime-object-change-report-v1",
            "sha256": hashlib.sha256(canonical_json(report).encode()).hexdigest(),
        },
        "facts": facts,
    }


def memory_interval_semantic_result(
    report: dict[str, Any],
    *,
    sample: str,
    scenario: str,
    compiler: str,
    opt: str,
    link: str,
) -> dict[str, Any]:
    """Project logical memory intervals from executed-store relations."""
    if report.get("schema") != "glaurung-runtime-instruction-trace-report-v1":
        raise ValueError("instruction-trace report has an unsupported schema")
    facts: list[dict[str, Any]] = []
    for relation in report.get("executed_stores", []):
        if not isinstance(relation, dict):
            continue
        prefix_evidence = relation.get("allocation_prefix")
        prefix = (
            prefix_evidence.get("value")
            if isinstance(prefix_evidence, dict)
            and prefix_evidence.get("status") == "inferred"
            and isinstance(prefix_evidence.get("value"), dict)
            else None
        )
        if (
            isinstance(prefix, dict)
            and prefix.get("classification")
            == "crosses_allocation_prefix_within_object"
            and isinstance(prefix.get("store_object_offset"), int)
            and isinstance(prefix.get("logical_prefix_byte_len"), int)
            and isinstance(prefix.get("source_pointer"), dict)
            and isinstance(prefix["source_pointer"].get("source_name"), str)
        ):
            facts.append(
                {
                    "kind": "memory",
                    "subject": (
                        f"heap_object:{prefix['source_pointer']['source_name']}"
                    ),
                    "predicate": "bounds_violation",
                    "status": "inferred",
                    "value": (
                        f"write:index={prefix['store_object_offset']}:"
                        f"declared_data_length={prefix['logical_prefix_byte_len']}"
                    ),
                    "source": (
                        "executed LLIR store, allocation occurrence, DWARF extent, "
                        "and runtime object"
                    ),
                }
            )
        if (
            isinstance(prefix, dict)
            and prefix.get("classification") == "within_allocation_prefix"
            and isinstance(prefix.get("store_object_offset"), int)
            and isinstance(prefix.get("store_byte_len"), int)
            and isinstance(prefix.get("source_pointer"), dict)
            and isinstance(prefix["source_pointer"].get("source_name"), str)
        ):
            prefix_transition_evidence = relation.get("object_transition")
            prefix_transition = (
                prefix_transition_evidence.get("value")
                if isinstance(prefix_transition_evidence, dict)
                and prefix_transition_evidence.get("status") == "inferred"
                and isinstance(prefix_transition_evidence.get("value"), dict)
                else None
            )
            if (
                isinstance(prefix_transition, dict)
                and isinstance(prefix_transition.get("before_hex"), str)
                and isinstance(prefix_transition.get("stored_hex"), str)
            ):
                start = prefix["store_object_offset"]
                end = start + prefix["store_byte_len"]
                facts.append(
                    {
                        "kind": "memory",
                        "subject": (
                            f"heap_object:"
                            f"{prefix['source_pointer']['source_name']}"
                        ),
                        "predicate": "changed_interval",
                        "status": "inferred",
                        "value": (
                            f"offset={start}..{end}:"
                            f"old={prefix_transition['before_hex']}:"
                            f"new={prefix_transition['stored_hex']}"
                        ),
                        "source": (
                            "executed LLIR store within allocation prefix and "
                            "ordered runtime-object snapshots"
                        ),
                    }
                )
        tail_evidence = relation.get("allocation_tail")
        tail = (
            tail_evidence.get("value")
            if isinstance(tail_evidence, dict)
            and tail_evidence.get("status") == "inferred"
            and isinstance(tail_evidence.get("value"), dict)
            else None
        )
        if isinstance(tail, dict):
            tail_source_name = tail.get("source_name")
            pointee_byte_len = tail.get("pointee_byte_len")
            overlap_byte_len = tail.get("store_overlap_byte_len")
            before_hex = tail.get("before_hex")
            stored_hex = tail.get("stored_hex")
            final_hex = tail.get("final_hex")
            if (
                isinstance(tail_source_name, str)
                and isinstance(pointee_byte_len, int)
                and isinstance(overlap_byte_len, int)
                and isinstance(before_hex, str)
                and isinstance(stored_hex, str)
                and isinstance(final_hex, str)
            ):
                before = bytes.fromhex(before_hex)
                stored = bytes.fromhex(stored_hex)
                final = bytes.fromhex(final_hex)
                if len(before) == len(stored) == len(final) == pointee_byte_len:
                    final_value = int.from_bytes(final, "little")
                    subject = f"heap_object:{tail_source_name}"
                    if overlap_byte_len == 0 and before == stored == final:
                        facts.append(
                            {
                                "kind": "negative",
                                "subject": subject,
                                "predicate": "changed",
                                "status": "inferred",
                                "value": (
                                    f"false:value=0x"
                                    f"{final_value:0{pointee_byte_len * 2}x}"
                                ),
                                "source": (
                                    "occurrence-time allocation-tail pointer and "
                                    "three ordered runtime-object snapshots"
                                ),
                            }
                        )
                    changed_offsets = [
                        offset
                        for offset, (old, new) in enumerate(zip(before, stored))
                        if old != new
                    ]
                    if (
                        overlap_byte_len > 0
                        and len(changed_offsets) == overlap_byte_len
                        and changed_offsets
                        == list(range(changed_offsets[0], changed_offsets[-1] + 1))
                        and stored == final
                    ):
                        start = changed_offsets[0]
                        end = changed_offsets[-1] + 1
                        facts.append(
                            {
                                "kind": "memory",
                                "subject": subject,
                                "predicate": "changed_interval",
                                "status": "inferred",
                                "value": (
                                    f"offset={start}..{end}:"
                                    f"old={before[start:end].hex()}:"
                                    f"new={stored[start:end].hex()}:"
                                    f"final=0x"
                                    f"{final_value:0{pointee_byte_len * 2}x}"
                                ),
                                "source": (
                                    "executed LLIR store overlapping an "
                                    "occurrence-time allocation-tail pointer and "
                                    "three ordered runtime-object snapshots"
                                ),
                            }
                        )
        source_evidence = relation.get("source_pointer")
        transition_evidence = relation.get("object_transition")
        source = (
            source_evidence.get("value")
            if isinstance(source_evidence, dict)
            and source_evidence.get("status") == "inferred"
            and isinstance(source_evidence.get("value"), dict)
            else None
        )
        transition = (
            transition_evidence.get("value")
            if isinstance(transition_evidence, dict)
            and transition_evidence.get("status") == "inferred"
            and isinstance(transition_evidence.get("value"), dict)
            else None
        )
        if not isinstance(source, dict) or not isinstance(transition, dict):
            continue
        source_name = source.get("source_name")
        store_offset_from_pointer = source.get("store_offset_from_pointer")
        byte_len = transition.get("byte_len")
        stored_hex = transition.get("stored_hex")
        final_hex = transition.get("final_hex")
        changed = transition.get("changed_after_store")
        if (
            not isinstance(source_name, str)
            or store_offset_from_pointer != 0
            or not isinstance(byte_len, int)
            or not isinstance(stored_hex, str)
            or not isinstance(final_hex, str)
            or not isinstance(changed, bool)
            or len(bytes.fromhex(stored_hex)) != byte_len
            or len(bytes.fromhex(final_hex)) != byte_len
        ):
            continue
        subject = f"heap_object:{source_name}"
        final_value = int.from_bytes(bytes.fromhex(final_hex), "little")
        if changed:
            facts.append(
                {
                    "kind": "memory",
                    "subject": subject,
                    "predicate": "changed_interval",
                    "status": "inferred",
                    "value": (
                        f"offset=0..{byte_len}:old={stored_hex}:new={final_hex}:"
                        f"final=0x{final_value:0{byte_len * 2}x}"
                    ),
                    "source": (
                        "executed LLIR store, DWARF source pointer, and ordered "
                        "runtime-object snapshots"
                    ),
                }
            )
        else:
            facts.append(
                {
                    "kind": "negative",
                    "subject": subject,
                    "predicate": "changed",
                    "status": "inferred",
                    "value": f"false:value=0x{final_value:0{byte_len * 2}x}",
                    "source": (
                        "executed LLIR store, DWARF source pointer, and ordered "
                        "runtime-object snapshots"
                    ),
                }
            )
    return {
        "schema": "glaurung-runtime-semantic-result-v1",
        "sample": sample,
        "scenario": scenario,
        "lane": {
            "compiler": Path(compiler).name,
            "optimization": opt,
            "link": link,
        },
        "evidence": {
            "kind": "glaurung-runtime-instruction-trace-report-v1",
            "sha256": hashlib.sha256(canonical_json(report).encode()).hexdigest(),
        },
        "facts": facts,
    }


def instruction_store_semantic_result(
    report: dict[str, Any],
    *,
    sample: str,
    scenario: str,
    compiler: str,
    opt: str,
    link: str,
) -> dict[str, Any]:
    """Compatibility name for :func:`memory_interval_semantic_result`."""
    return memory_interval_semantic_result(
        report,
        sample=sample,
        scenario=scenario,
        compiler=compiler,
        opt=opt,
        link=link,
    )


def stack_write_semantic_result(
    report: dict[str, Any],
    *,
    sample: str,
    scenario: str,
    compiler: str,
    opt: str,
    link: str,
) -> dict[str, Any]:
    """Project DWARF-backed stack-field bounds without loading an oracle."""
    if report.get("schema") != "glaurung-runtime-stack-write-report-v1":
        raise ValueError("stack-write report has an unsupported schema")
    facts: list[dict[str, Any]] = []
    for relation in report.get("relations", []):
        if not isinstance(relation, dict):
            continue
        stack_object = relation.get("object")
        field = relation.get("field")
        bounds = relation.get("bounds")
        occurrence = relation.get("operation_occurrence")
        if not (
            isinstance(stack_object, dict) and stack_object.get("status") == "inferred"
        ):
            continue
        object_value = stack_object.get("value")
        field_value = (
            field.get("value")
            if isinstance(field, dict)
            and field.get("status") == "inferred"
            and isinstance(field.get("value"), dict)
            else None
        )
        bounds_value = (
            bounds.get("value")
            if isinstance(bounds, dict)
            and bounds.get("status") == "inferred"
            and isinstance(bounds.get("value"), dict)
            else None
        )
        if not isinstance(object_value, dict):
            continue
        c_type = object_value.get("c_type")
        field_name = field_value.get("name") if isinstance(field_value, dict) else None
        write_len = (
            bounds_value.get("write_byte_len")
            if isinstance(bounds_value, dict)
            else None
        )
        field_len = (
            field_value.get("byte_len") if isinstance(field_value, dict) else None
        )
        if not isinstance(c_type, str):
            continue
        type_name = c_type.removeprefix("struct ").removeprefix("union ")
        address_derivation = relation.get("address_derivation")
        address_value = (
            address_derivation.get("value")
            if isinstance(address_derivation, dict)
            and address_derivation.get("status") == "inferred"
            and isinstance(address_derivation.get("value"), dict)
            else None
        )
        occurrence_value = (
            occurrence.get("value")
            if isinstance(occurrence, dict)
            and occurrence.get("status") == "inferred"
            and isinstance(occurrence.get("value"), dict)
            else None
        )
        static_operation = (
            occurrence_value.get("static_operation")
            if isinstance(occurrence_value, dict)
            and isinstance(occurrence_value.get("static_operation"), dict)
            else None
        )
        call_target = (
            static_operation.get("call_target")
            if isinstance(static_operation, dict)
            and isinstance(static_operation.get("call_target"), dict)
            else None
        )
        callee = (
            call_target.get("symbol")
            if isinstance(call_target, dict)
            and isinstance(call_target.get("symbol"), str)
            else None
        )
        call_inputs = (
            occurrence_value.get("inputs")
            if isinstance(occurrence_value, dict)
            and isinstance(occurrence_value.get("inputs"), dict)
            else {}
        )

        def observed_input(name: str) -> int | None:
            evidence = call_inputs.get(name)
            value = evidence.get("value") if isinstance(evidence, dict) else None
            return int(value) if isinstance(value, str) and value.isdecimal() else None

        destination_address = observed_input("destination_address")
        source_address = observed_input("source_address")
        call_byte_len = observed_input("byte_len")
        copy_ranges_overlap = (
            callee in {"memcpy", "memmove"}
            and isinstance(destination_address, int)
            and isinstance(source_address, int)
            and isinstance(call_byte_len, int)
            and destination_address < source_address + call_byte_len
            and source_address < destination_address + call_byte_len
        )
        object_change = relation.get("object_change")
        if (
            relation.get("event_kind") == "semantic_call"
            and copy_ranges_overlap
            and field_value is None
            and isinstance(object_change, dict)
            and object_change.get("status") == "inferred"
            and isinstance(object_change.get("value"), dict)
        ):
            change = object_change["value"]
            intervals = change.get("changed_intervals")
            before_hex = change.get("before_hex")
            after_hex = change.get("after_hex")
            source_name = object_value.get("source_name")
            if (
                isinstance(intervals, list)
                and len(intervals) == 1
                and isinstance(intervals[0], dict)
                and isinstance(before_hex, str)
                and isinstance(after_hex, str)
                and isinstance(source_name, str)
            ):
                interval = intervals[0]
                old_bytes = bytes.fromhex(str(interval.get("before_hex", "")))
                new_bytes = bytes.fromhex(str(interval.get("after_hex", "")))
                value = (
                    f"offset={interval.get('object_offset_start')}.."
                    f"{interval.get('object_offset_end')}:"
                    f"old={old_bytes.hex()}:new={new_bytes.hex()}"
                )
                if copy_ranges_overlap and callee == "memmove":
                    value = (
                        f"offset={interval.get('object_offset_start')}.."
                        f"{interval.get('object_offset_end')}:"
                        f"original={old_bytes.hex()}:final={new_bytes.hex()}"
                    )
                elif copy_ranges_overlap and callee == "memcpy":
                    after_object = bytes.fromhex(after_hex)
                    if len(after_object) > 2:
                        value = (
                            f"offset={interval.get('object_offset_start')}.."
                            f"{interval.get('object_offset_end')}:"
                            f"original={old_bytes.hex()}:"
                            "final=implementation_defined:"
                            f"observed_b2={after_object[2]}"
                        )
                facts.append(
                    {
                        "kind": "memory",
                        "subject": f"stack_object:{source_name}",
                        "predicate": "changed_interval",
                        "status": "inferred",
                        "value": value,
                        "source": "glaurung-runtime-stack-write-report-v1",
                    }
                )
        field_changes = relation.get("field_changes")
        if (
            isinstance(field_changes, dict)
            and field_changes.get("status") == "inferred"
            and isinstance(field_changes.get("value"), list)
        ):
            for change in field_changes["value"]:
                if not isinstance(change, dict) or not isinstance(
                    change.get("field"), dict
                ):
                    continue
                changed_field = change["field"]
                changed_name = changed_field.get("name")
                changed_type = changed_field.get("c_type")
                before_hex = change.get("before_hex")
                after_hex = change.get("after_hex")
                intervals = change.get("changed_intervals")
                if (
                    not isinstance(changed_name, str)
                    or not isinstance(changed_type, str)
                    or not isinstance(before_hex, str)
                    or not isinstance(after_hex, str)
                    or not isinstance(intervals, list)
                ):
                    continue
                subject = f"stack_object:{type_name}.{changed_name}"
                scalar = "[" not in changed_type and len(bytes.fromhex(after_hex)) <= 8
                if not intervals and scalar and before_hex == after_hex:
                    facts.append(
                        {
                            "kind": "negative",
                            "subject": subject,
                            "predicate": "changed",
                            "status": "inferred",
                            "value": (
                                "false:value="
                                f"0x{int.from_bytes(bytes.fromhex(after_hex), 'little'):0{len(after_hex)}x}"
                            ),
                            "source": "glaurung-runtime-stack-write-report-v1",
                        }
                    )
                elif len(intervals) == 1 and isinstance(intervals[0], dict):
                    interval = intervals[0]
                    old_bytes = bytes.fromhex(str(interval.get("before_hex", "")))
                    new_bytes = bytes.fromhex(str(interval.get("after_hex", "")))
                    preserve_element_width = scalar or (
                        relation.get("event_kind") == "instruction_step"
                        and isinstance(address_value, dict)
                        and isinstance(address_value.get("element_byte_len"), int)
                        and address_value["element_byte_len"] > 1
                    )
                    old_value = (
                        old_bytes[:1].hex()
                        if old_bytes
                        and len(set(old_bytes)) == 1
                        and not preserve_element_width
                        else old_bytes.hex()
                    )
                    new_value = (
                        new_bytes[:1].hex()
                        if new_bytes
                        and len(set(new_bytes)) == 1
                        and not preserve_element_width
                        else new_bytes.hex()
                    )
                    value = (
                        f"offset={interval.get('field_offset_start')}.."
                        f"{interval.get('field_offset_end')}:"
                        f"old={old_value}:"
                        f"new={new_value}"
                    )
                    occurrence_value = (
                        occurrence.get("value")
                        if isinstance(occurrence, dict)
                        and occurrence.get("status") == "inferred"
                        and isinstance(occurrence.get("value"), dict)
                        else None
                    )
                    interval_start = interval.get("field_offset_start")
                    interval_end = interval.get("field_offset_end")
                    field_runtime_start = changed_field.get("runtime_start")
                    occurrence_exactly_matches_interval = (
                        isinstance(occurrence_value, dict)
                        and isinstance(occurrence_value.get("effects"), list)
                        and isinstance(interval_start, int)
                        and isinstance(interval_end, int)
                        and isinstance(field_runtime_start, int)
                        and any(
                            isinstance(effect, dict)
                            and effect.get("kind") == "memory_write"
                            and effect.get("address")
                            == field_runtime_start + interval_start
                            and effect.get("byte_len") == interval_end - interval_start
                            for effect in occurrence_value["effects"]
                        )
                    )
                    if (
                        relation.get("event_kind") == "instruction_step"
                        and isinstance(address_value, dict)
                        and address_value.get("element_byte_len") == 1
                        and isinstance(address_value.get("base_field"), dict)
                        and address_value["base_field"].get("name") == changed_name
                        and occurrence_exactly_matches_interval
                    ):
                        value = (
                            f"offset={interval.get('field_offset_start')}.."
                            f"{interval.get('field_offset_end')}:value={new_value}"
                        )
                    if scalar:
                        value += (
                            ":final="
                            f"0x{int.from_bytes(bytes.fromhex(after_hex), 'little'):0{len(after_hex)}x}"
                        )
                    if copy_ranges_overlap and callee == "memmove":
                        value = (
                            f"offset={interval.get('field_offset_start')}.."
                            f"{interval.get('field_offset_end')}:"
                            f"original={old_bytes.hex()}:final={new_bytes.hex()}"
                        )
                    elif copy_ranges_overlap and callee == "memcpy":
                        after_field = bytes.fromhex(after_hex)
                        if len(after_field) > 2:
                            value = (
                                f"offset={interval.get('field_offset_start')}.."
                                f"{interval.get('field_offset_end')}:"
                                "original="
                                f"{old_bytes.hex()}:final=implementation_defined:"
                                f"observed_b2={after_field[2]}"
                            )
                    facts.append(
                        {
                            "kind": "memory",
                            "subject": subject,
                            "predicate": "changed_interval",
                            "status": "inferred",
                            "value": value,
                            "source": "glaurung-runtime-stack-write-report-v1",
                        }
                    )
        if copy_ranges_overlap:
            field_runtime_start = (
                field_value.get("runtime_start")
                if isinstance(field_value, dict)
                else object_value.get("runtime_start")
            )
            if (
                isinstance(field_runtime_start, int)
                and isinstance(destination_address, int)
                and isinstance(source_address, int)
                and isinstance(call_byte_len, int)
                and field_runtime_start <= destination_address
                and field_runtime_start <= source_address
            ):
                source_start = source_address - field_runtime_start
                destination_start = destination_address - field_runtime_start
                if callee == "memcpy":
                    facts.append(
                        {
                            "kind": "memory",
                            "subject": "copy_operation",
                            "predicate": "overlap_violation",
                            "status": "inferred",
                            "value": (
                                f"memcpy:source={source_start}.."
                                f"{source_start + call_byte_len}:destination="
                                f"{destination_start}.."
                                f"{destination_start + call_byte_len}"
                            ),
                            "source": "glaurung-runtime-stack-write-report-v1",
                        }
                    )
                elif callee == "memmove":
                    facts.append(
                        {
                            "kind": "negative",
                            "subject": "copy_operation",
                            "predicate": "changed",
                            "status": "inferred",
                            "value": "false:invalid_overlap",
                            "source": "glaurung-runtime-stack-write-report-v1",
                        }
                    )
        # A traced machine write can independently expose a field crossing even
        # when it cannot be related to a static operation.  Keep that evidence
        # in the stack-write report, but do not manufacture a semantic
        # operation name for the oracle projection.  A surrounding semantic
        # call (for example strcat) may legitimately cover the same bytes and
        # supplies the authoritative operation occurrence.
        if (
            isinstance(bounds_value, dict)
            and isinstance(field_name, str)
            and isinstance(write_len, int)
            and isinstance(field_len, int)
            and bounds_value.get("classification") == "crosses_field_boundary"
            and (
                relation.get("event_kind") != "instruction_step"
                or (
                    isinstance(occurrence, dict)
                    and occurrence.get("status") == "inferred"
                )
            )
        ):
            operation_name = "read"
            length_name = "length"
            reported_length = write_len
            occurrence_value = (
                occurrence.get("value")
                if isinstance(occurrence, dict)
                and occurrence.get("status") == "inferred"
                and isinstance(occurrence.get("value"), dict)
                else None
            )
            static_operation = (
                occurrence_value.get("static_operation")
                if isinstance(occurrence_value, dict)
                and isinstance(occurrence_value.get("static_operation"), dict)
                else None
            )
            call_target = (
                static_operation.get("call_target")
                if isinstance(static_operation, dict)
                and isinstance(static_operation.get("call_target"), dict)
                else None
            )
            if isinstance(call_target, dict) and isinstance(
                call_target.get("symbol"), str
            ):
                operation_name = call_target["symbol"]
                if operation_name == "strcpy":
                    length_name = "source_bytes"
                elif operation_name == "sprintf":
                    length_name = "output_bytes"
                elif operation_name == "strcat":
                    length_name = "final_bytes"
                    final_extent = (
                        occurrence_value.get("inputs", {}).get("final_bytes", {})
                        if isinstance(occurrence_value, dict)
                        and isinstance(occurrence_value.get("inputs"), dict)
                        else {}
                    )
                    final_value = (
                        final_extent.get("value")
                        if isinstance(final_extent, dict)
                        and final_extent.get("status") == "observed"
                        else None
                    )
                    if isinstance(final_value, str) and final_value.isdecimal():
                        reported_length = int(final_value)
            facts.append(
                {
                    "kind": "memory",
                    "subject": f"stack_object:{type_name}.{field_name}",
                    "predicate": "bounds_violation",
                    "status": "inferred",
                    "value": (
                        f"{operation_name}:{length_name}={reported_length}:"
                        f"declared_length={field_len}"
                    ),
                    "source": "glaurung-runtime-stack-write-report-v1",
                }
            )
        if (
            isinstance(address_value, dict)
            and address_value.get("classification") == "crosses_field_boundary"
            and isinstance(address_value.get("base_field"), dict)
            and isinstance(address_value.get("element_index"), int)
            and isinstance(address_value["base_field"].get("name"), str)
            and isinstance(address_value["base_field"].get("byte_len"), int)
        ):
            base_field = address_value["base_field"]
            element_byte_len = address_value.get("element_byte_len")
            declared = base_field["byte_len"]
            if isinstance(element_byte_len, int) and element_byte_len > 1:
                bound_name = "declared_elements"
                declared //= element_byte_len
            else:
                bound_name = "declared_length"
            operation_name = "write"
            if (
                isinstance(occurrence, dict)
                and occurrence.get("status") == "inferred"
                and isinstance(occurrence.get("value"), dict)
                and isinstance(occurrence["value"].get("static_operation"), dict)
            ):
                stored_value = occurrence["value"]["static_operation"].get(
                    "stored_value"
                )
                if (
                    isinstance(stored_value, dict)
                    and stored_value.get("kind") == "constant"
                    and stored_value.get("value") == 0
                    and isinstance(base_field.get("c_type"), str)
                    and base_field["c_type"].startswith("char")
                    and element_byte_len == 1
                ):
                    operation_name = "terminator"
            facts.append(
                {
                    "kind": "memory",
                    "subject": f"stack_object:{type_name}.{base_field['name']}",
                    "predicate": "bounds_violation",
                    "status": "inferred",
                    "value": (
                        f"{operation_name}:index={address_value['element_index']}:"
                        f"{bound_name}={declared}"
                    ),
                    "source": "glaurung-runtime-stack-write-report-v1",
                }
            )
    for relation in report.get("integer_conversion_writes", []):
        if not isinstance(relation, dict) or relation.get("classification") != (
            "narrowing_precedes_field_overflow"
        ):
            continue
        source_value = relation.get("source_value")
        converted_value = relation.get("converted_value")
        converted_bits = relation.get("converted_bits")
        write_bounds = relation.get("write_bounds")
        write_field = relation.get("write_field")
        source_object = relation.get("source_object")
        converted_object = relation.get("converted_object")
        if not (
            isinstance(source_value, int)
            and isinstance(converted_value, int)
            and isinstance(converted_bits, int)
            and isinstance(write_bounds, dict)
            and isinstance(write_bounds.get("write_byte_len"), int)
            and isinstance(write_field, dict)
            and isinstance(write_field.get("byte_len"), int)
            and isinstance(source_object, dict)
            and isinstance(source_object.get("source_name"), str)
            and isinstance(converted_object, dict)
            and isinstance(converted_object.get("source_name"), str)
        ):
            continue
        facts.append(
            {
                "kind": "memory",
                "subject": "integer_conversion",
                "predicate": "bounds_violation",
                "status": "inferred",
                "value": (
                    f"{source_object['source_name']}={source_value}:"
                    f"{converted_object['source_name']}_u{converted_bits}="
                    f"{converted_value}:"
                    f"write_length={write_bounds['write_byte_len']}:"
                    f"declared_length={write_field['byte_len']}"
                ),
                "source": (
                    "bounded LLIR integer reduction joined through observed frame "
                    "identity to DWARF locals and a subsequent semantic write occurrence"
                ),
            }
        )
    deduplicated_facts: list[dict[str, Any]] = []
    seen_facts: set[str] = set()
    for fact in facts:
        identity = canonical_json(fact)
        if identity not in seen_facts:
            seen_facts.add(identity)
            deduplicated_facts.append(fact)
    return {
        "schema": "glaurung-runtime-semantic-result-v1",
        "sample": sample,
        "scenario": scenario,
        "lane": {
            "compiler": Path(compiler).name,
            "optimization": opt,
            "link": link,
        },
        "evidence": {
            "kind": "glaurung-runtime-stack-write-report-v1",
            "sha256": hashlib.sha256(canonical_json(report).encode()).hexdigest(),
        },
        "facts": deduplicated_facts,
    }


def wait_stopped(pid: int, timeout: float) -> int:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        waited, status = os.waitpid(pid, os.WUNTRACED | os.WNOHANG)
        if waited == pid:
            if os.WIFSTOPPED(status):
                return os.WSTOPSIG(status)
            raise RuntimeError(
                f"process {pid} exited before checkpoint: status={status}"
            )
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


def parse_proc_maps(
    data: str, *, process_id: str, executable: Path, executable_sha256: str
) -> tuple[list[dict[str, Any]], list[str]]:
    """Translate a procfs maps snapshot without treating paths as identity."""
    mappings: list[dict[str, Any]] = []
    executable_mapping_ids: list[str] = []
    executable_realpath = executable.resolve()
    for index, line in enumerate(data.splitlines()):
        columns = line.split(maxsplit=5)
        if len(columns) < 5:
            raise ValueError(f"malformed /proc maps line: {line!r}")
        address, permissions, offset, _device, _inode = columns[:5]
        path = columns[5] if len(columns) == 6 else ""
        start_text, separator, end_text = address.partition("-")
        if not separator:
            raise ValueError(f"malformed /proc maps range: {address!r}")
        start = int(start_text, 16)
        end = int(end_text, 16)
        mapping_id = f"mapping-{index:06d}"
        deleted = path.endswith(" (deleted)")
        identity_path = path.removesuffix(" (deleted)")
        is_executable = False
        if identity_path and not identity_path.startswith("["):
            try:
                is_executable = Path(identity_path).resolve() == executable_realpath
            except OSError:
                is_executable = False
        if is_executable:
            backing: dict[str, Any] = {
                "kind": "file",
                "artifact_sha256": executable_sha256,
                "deleted": deleted,
            }
            executable_mapping_ids.append(mapping_id)
            module_id = "module-main"
            file_offset: int | None = int(offset, 16)
        elif path.startswith("[") and path.endswith("]"):
            backing = {"kind": "special", "name": path}
            module_id = None
            file_offset = None
        elif path:
            backing = {
                "kind": "unknown",
                "reason": "path observed but backing artifact identity was not captured",
            }
            module_id = None
            file_offset = None
        else:
            backing = {"kind": "anonymous"}
            module_id = None
            file_offset = None
        mappings.append(
            {
                "id": mapping_id,
                "process_id": process_id,
                "start": start,
                "end": end,
                "permissions": {
                    "read": permissions[0] == "r",
                    "write": permissions[1] == "w",
                    "execute": permissions[2] == "x",
                    "private": permissions[3] == "p",
                },
                "backing": backing,
                **({"module_id": module_id} if module_id else {}),
                **({"file_offset": file_offset} if file_offset is not None else {}),
            }
        )
    return mappings, executable_mapping_ids


def live_process_capsule(
    *,
    binary: Path,
    pid: int,
    checkpoint: str,
    captured_at: str,
    proc_files: dict[str, dict[str, Any]],
    maps_text: str,
    descriptors: dict[str, str],
    invocation_input: bytes,
) -> dict[str, Any]:
    """Build provider metadata; Rust remains the capsule format authority."""
    from glaurung import runtime_analysis

    process_id = "process-main"
    executable_sha256 = sha256(binary)
    executable_build_id = runtime_analysis.elf_executable_build_id(binary.read_bytes())
    mappings, executable_mapping_ids = parse_proc_maps(
        maps_text,
        process_id=process_id,
        executable=binary,
        executable_sha256=executable_sha256,
    )
    if not executable_mapping_ids:
        raise ValueError("live capture did not identify an exact executable mapping")
    artifact = {
        "sha256": executable_sha256,
        "byte_len": binary.stat().st_size,
        "display_path": str(binary),
        **({"build_id": executable_build_id} if executable_build_id else {}),
    }
    captured_artifacts = [artifact]
    captured_artifacts.extend(
        {
            "sha256": record["sha256"],
            "byte_len": record["size"],
            "display_path": f"procfs:{name}",
        }
        for name, record in sorted(proc_files.items())
    )
    tids = sorted(int(item.name) for item in Path(f"/proc/{pid}/task").iterdir())
    capture_seed = "\0".join(
        (executable_sha256, str(pid), proc_files["stat"]["sha256"], checkpoint)
    )
    capture_id = "live-" + hashlib.sha256(capture_seed.encode()).hexdigest()
    return {
        "schema": "glaurung-process-capsule-v1",
        "version": 1,
        "identity": {
            "capture_id": capture_id,
            "acquisition": "live",
            "host_os": platform.system().lower(),
            "kernel": platform.release(),
            "captured_at": captured_at,
        },
        "required_features": [],
        "target": {
            "architecture": {"x86_64": "X86_64", "amd64": "X86_64"}.get(
                platform.machine().lower(), "Unknown"
            ),
            "endianness": "Little" if sys.byteorder == "little" else "Big",
            "address_bits": 64 if sys.maxsize > 2**32 else 32,
            "os_abi": "linux",
        },
        "executable": artifact,
        "processes": [
            {"id": process_id, "os_pid": pid, "terminal": {"kind": "running"}}
        ],
        "modules": [
            {
                "id": "module-main",
                "process_id": process_id,
                "artifact": artifact,
                "mapping_ids": executable_mapping_ids,
            }
        ],
        "mappings": mappings,
        "threads": [
            {
                "id": f"thread-{tid}",
                "process_id": process_id,
                "os_tid": tid,
                "registers": [],
            }
            for tid in tids
        ],
        "pages": [],
        "descriptors": [
            {
                "process_id": process_id,
                "number": int(number),
                "kind": "unknown",
                "target": target,
                "redacted": False,
            }
            for number, target in sorted(
                descriptors.items(), key=lambda item: int(item[0])
            )
        ],
        "events": [],
        "provenance": {
            "producer": "tools/runtime_sample_harness.py",
            "producer_version": "1",
            "command": sys.argv,
            "input_artifacts": captured_artifacts,
            "input_bytes": [
                {
                    "name": "argv[1]",
                    "sha256": hashlib.sha256(invocation_input).hexdigest(),
                    "byte_len": len(invocation_input),
                    "sensitivity": "public",
                }
            ],
            "warnings": [
                "procfs is a non-atomic snapshot; mapping, thread, and descriptor reads may race"
            ],
        },
        "completeness": [
            {
                "evidence": "descriptors",
                "status": "raced",
                "reason": "procfs descriptor enumeration is not atomic",
                "requested": True,
                "obtained": len(descriptors),
            },
            {
                "evidence": "mappings",
                "status": "raced",
                "reason": "procfs mapping capture is not atomic",
                "requested": True,
                "obtained": len(mappings),
            },
            {
                "evidence": "pages",
                "status": "omitted",
                "reason": "page capture was not requested by the metadata provider",
                "requested": False,
                "obtained": 0,
                "expected": 0,
            },
            {
                "evidence": "registers",
                "status": "unsupported",
                "reason": "the procfs metadata provider does not acquire registers",
                "requested": True,
                "obtained": 0,
            },
            {
                "evidence": "threads",
                "status": "raced",
                "reason": "procfs task enumeration is not atomic",
                "requested": True,
                "obtained": len(tids),
            },
        ],
        "provider.procfs": {
            "checkpoint": checkpoint,
            "files": proc_files,
        },
    }


def canonicalize_process_capsule(capsule: dict[str, Any]) -> str:
    """Validate and serialize through the Rust capsule implementation."""
    from glaurung import runtime_analysis

    return runtime_analysis.canonicalize_process_capsule_json(
        json.dumps(capsule, separators=(",", ":"), ensure_ascii=False)
    )


def publish_process_capsule(capture: Path, capsule: dict[str, Any]) -> Path:
    """Publish validated capsule metadata atomically in its capture directory."""
    target = capture / "process-capsule.json"
    partial = capture / ".process-capsule.json.part"
    canonical = canonicalize_process_capsule(capsule)
    descriptor = os.open(
        partial,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        with os.fdopen(descriptor, "w") as stream:
            stream.write(canonical)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        partial.unlink(missing_ok=True)
        raise
    try:
        os.replace(partial, target)
    except BaseException:
        partial.unlink(missing_ok=True)
        raise
    return target


def clear_process_capsule_outputs(capture: Path) -> None:
    """Prevent a failed rerun from exposing an older capsule as current."""
    for name in ("process-capsule.json", ".process-capsule.json.part"):
        path = capture / name
        if path.is_dir() and not path.is_symlink():
            raise IsADirectoryError(path)
        path.unlink(missing_ok=True)


def publish_capsule_payloads(
    capture: Path, capsule_text: str, payloads: list[tuple[str, bytes]]
) -> Path:
    """Store sensitive payloads by capsule hash without following links."""
    capsule_hash = hashlib.sha256(capsule_text.encode()).hexdigest()
    directory = capture / f"payloads-{capsule_hash}"
    directory.mkdir(mode=0o700, exist_ok=True)
    if directory.is_symlink():
        raise FileExistsError(f"payload directory must not be a symlink: {directory}")
    os.chmod(directory, 0o700)
    expected = {
        page["content"]["payload"]["id"]: page["content"]["payload"]
        for page in json.loads(capsule_text)["pages"]
        if page["content"]["status"] == "captured"
    }
    expected.update(
        {
            output["payload"]["id"]: output["payload"]
            for output in json.loads(capsule_text).get("outputs", [])
        }
    )
    if set(expected) != {payload_id for payload_id, _data in payloads}:
        raise ValueError("core importer payload set disagrees with capsule references")
    for payload_id, data in payloads:
        if not payload_id or any(
            character not in "abcdefghijklmnopqrstuvwxyz0123456789-"
            for character in payload_id
        ):
            raise ValueError(f"unsafe capsule payload id: {payload_id!r}")
        reference = expected[payload_id]
        if len(data) != reference["byte_len"]:
            raise ValueError(f"payload {payload_id} length disagrees with capsule")
        if hashlib.sha256(data).hexdigest() != reference["sha256"]:
            raise ValueError(f"payload {payload_id} hash disagrees with capsule")
        target = directory / f"{payload_id}.bin"
        if target.exists():
            if target.is_symlink() or target.read_bytes() != data:
                raise FileExistsError(
                    f"payload target is not the expected bytes: {target}"
                )
            continue
        descriptor = os.open(
            target,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    return directory


def import_core_capsule(
    core: Path,
    binary: Path,
    capture: Path,
    invocation_input: bytes,
    stdout: bytes,
    stderr: bytes,
) -> tuple[Path, Path]:
    """Import a real core through Rust and publish metadata plus page payloads."""
    from glaurung import runtime_analysis

    captured_at = (
        datetime.fromtimestamp(core.stat().st_mtime, timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )
    capsule_text, payloads = runtime_analysis.import_elf_core(
        core.read_bytes(),
        binary.read_bytes(),
        str(core.resolve()),
        str(binary.resolve()),
        captured_at,
        invocation_input,
        stdout,
        stderr,
    )
    capsule = json.loads(capsule_text)
    payload_directory = publish_capsule_payloads(capture, capsule_text, payloads)
    capsule_path = publish_process_capsule(capture, capsule)
    return capsule_path, payload_directory


def capture_live(
    binary: Path,
    sample: Sample,
    scenario: str,
    out: Path,
    timeout: float,
    checkpoint: str = "exit",
) -> Path:
    capture = (
        out
        / "captures"
        / binary.parent.name
        / sample.id
        / scenario
        / f"live-{checkpoint}"
    )
    capture.mkdir(parents=True, exist_ok=True)
    clear_process_capsule_outputs(capture)
    prepare_fixture_cwd(sample, binary.parent)
    env = fixture_environment(sample)
    checkpoint_variable = (
        "GLAURUNG_RUNTIME_CHECKPOINT_ENTRY"
        if checkpoint == "entry"
        else "GLAURUNG_RUNTIME_CHECKPOINT"
    )
    env[checkpoint_variable] = "1"
    proc = subprocess.Popen(
        [str(binary), scenario_arg(sample, scenario)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=binary.parent,
        env=env,
    )
    try:
        stop_signal = wait_stopped(proc.pid, timeout)
        captured_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        files = {}
        for name in ("maps", "status", "stat", "cmdline", "auxv"):
            source = Path(f"/proc/{proc.pid}/{name}")
            if not source.exists():
                continue
            data = source.read_bytes()
            target = capture / name
            target.write_bytes(data)
            files[name] = {"size": len(data), "sha256": sha256(target)}
        environment = environment_inventory(
            Path(f"/proc/{proc.pid}/environ").read_bytes()
        )
        environment_path = capture / "environment.json"
        environment_path.write_text(
            json.dumps(environment, indent=2, sort_keys=True) + "\n"
        )
        files["environment"] = {
            "size": environment_path.stat().st_size,
            "sha256": sha256(environment_path),
            "values": "sha256-only",
        }
        fd_entries = {}
        for entry in sorted(
            Path(f"/proc/{proc.pid}/fd").iterdir(), key=lambda item: int(item.name)
        ):
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
        (capture / "manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n"
        )
        capsule = live_process_capsule(
            binary=binary,
            pid=proc.pid,
            checkpoint=checkpoint,
            captured_at=captured_at,
            proc_files=files,
            maps_text=(capture / "maps").read_text(errors="replace"),
            descriptors=fd_entries,
            invocation_input=scenario_arg(sample, scenario).encode(),
        )
        capsule_path = publish_process_capsule(capture, capsule)
        manifest["process_capsule"] = {
            "path": capsule_path.name,
            "size": capsule_path.stat().st_size,
            "sha256": sha256(capsule_path),
        }
        (capture / "manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n"
        )
    finally:
        try:
            os.kill(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait(timeout=timeout)
    return capture


def enable_core() -> None:
    resource.setrlimit(
        resource.RLIMIT_CORE, (resource.RLIM_INFINITY, resource.RLIM_INFINITY)
    )


def capture_core(
    binary: Path, sample: Sample, scenario: str, out: Path, timeout: float
) -> Path:
    capture = out / "captures" / binary.parent.name / sample.id / scenario / "core"
    capture.mkdir(parents=True, exist_ok=True)
    clear_process_capsule_outputs(capture)
    for stale_core in capture.glob("core*"):
        if stale_core.is_dir() and not stale_core.is_symlink():
            raise IsADirectoryError(stale_core)
        stale_core.unlink()
    prepare_fixture_cwd(sample, capture)
    done = subprocess.run(
        [str(binary), scenario_arg(sample, scenario)],
        cwd=capture,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
        preexec_fn=enable_core,
        env=fixture_environment(sample),
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
        "binary": str(binary),
        "binary_sha256": sha256(binary),
        "stdout": done.stdout,
        "stderr": done.stderr,
        "core_pattern": policy,
        "core_files": [
            {"path": path.name, "size": path.stat().st_size, "sha256": sha256(path)}
            for path in cores
        ],
        "core_captured": bool(cores),
        "core_absence_reason": None
        if cores
        else "host core_pattern redirected or suppressed the dump",
    }
    if len(cores) == 1:
        capsule_path, payload_directory = import_core_capsule(
            cores[0],
            binary,
            capture,
            scenario_arg(sample, scenario).encode(),
            done.stdout.encode(),
            done.stderr.encode(),
        )
        record["process_capsule"] = {
            "path": capsule_path.name,
            "size": capsule_path.stat().st_size,
            "sha256": sha256(capsule_path),
            "payload_directory": payload_directory.name,
            "payload_count": len(list(payload_directory.glob("*.bin"))),
        }
    elif len(cores) > 1:
        record["process_capsule_absence_reason"] = (
            "multiple core files require explicit process-to-core selection"
        )
    (capture / "manifest.json").write_text(
        json.dumps(record, indent=2, sort_keys=True) + "\n"
    )
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
        cmd.add_argument(
            "--opt", choices=("O0", "O1", "O2", "O3", "Og", "Os"), default="O2"
        )
        cmd.add_argument("--link", choices=("pie", "no-pie", "static"), default="pie")
        cmd.add_argument("--rebuild", action="store_true")
        cmd.add_argument("--timeout", type=float, default=5.0)
    for name in ("run", "live", "core"):
        sub.choices[name].add_argument(
            "--scenario", choices=("good", "bad"), default="bad"
        )
    sub.choices["run"].add_argument(
        "--semantic-result-dir",
        type=Path,
        help="write oracle-independent glaurung-runtime-semantic-result-v1 records",
    )
    sub.choices["live"].add_argument(
        "--checkpoint", choices=("entry", "exit"), default="exit"
    )
    matrix = sub.add_parser("matrix")
    matrix.add_argument("--sample", action="append", default=[])
    matrix.add_argument("--category", action="append", default=[])
    matrix.add_argument("--compiler", action="append", default=[])
    matrix.add_argument(
        "--opt",
        action="append",
        choices=("O0", "O1", "O2", "O3", "Og", "Os"),
        default=[],
    )
    matrix.add_argument(
        "--link", action="append", choices=("pie", "no-pie", "static"), default=[]
    )
    matrix.add_argument("--timeout", type=float, default=5.0)
    matrix.add_argument("--rebuild", action="store_true")
    matrix.add_argument(
        "--ledger",
        type=Path,
        help="write canonical glaurung-runtime-matrix-ledger-v1 JSON",
    )
    matrix.add_argument("--semantic-oracles", type=Path, default=SEMANTIC_ORACLES)
    evaluate = sub.add_parser("evaluate")
    evaluate.add_argument("result", type=Path)
    evaluate.add_argument("--semantic-oracles", type=Path, default=SEMANTIC_ORACLES)
    return result


def main() -> int:
    args = parser().parse_args()
    if args.command == "evaluate":
        result = json.loads(args.result.read_text())
        sample_id = result.get("sample")
        scenario = result.get("scenario")
        samples = [
            sample for sample in load_samples(args.manifest) if sample.id == sample_id
        ]
        if len(samples) != 1 or scenario not in {"good", "bad"}:
            raise ValueError("semantic result names an unknown sample or scenario")
        oracles = load_semantic_oracles(
            args.semantic_oracles, samples, require_complete=True
        )
        evaluation = evaluate_semantic_result(result, oracles[(sample_id, scenario)])
        print(json.dumps(evaluation, indent=2, sort_keys=True))
        return 0 if evaluation["passed"] else 1
    samples = select(
        load_samples(args.manifest),
        getattr(args, "sample", []),
        getattr(args, "category", []),
    )
    if args.command == "list":
        for sample in samples:
            print(
                f"{sample.id}\t{sample.category}\t{sample.source.relative_to(CORPUS)}"
            )
        return 0
    if args.command == "matrix":
        compilers = args.compiler or ["gcc", "clang"]
        opts = args.opt or ["O0", "O2"]
        links = args.link or ["pie", "no-pie"]
        semantic_oracles = load_semantic_oracles(
            args.semantic_oracles, samples, require_complete=True
        )
        semantic_oracle_sha256 = sha256(args.semantic_oracles)
        failures = []
        ledger_entries = []
        checked = 0
        for compiler in compilers:
            if shutil.which(compiler) is None:
                failures.append({"lane": compiler, "error": "compiler not found"})
                continue
            compiler_id = compiler_identity(compiler)
            for opt in opts:
                for link in links:
                    for sample in samples:
                        try:
                            binary = compile_sample(
                                sample, compiler, opt, link, args.out
                            )
                        except subprocess.CalledProcessError as error:
                            failures.append(
                                {
                                    "lane": f"{compiler}-{opt}-{link}",
                                    "sample": sample.id,
                                    "error": f"compiler exited {error.returncode}",
                                }
                            )
                            continue
                        for scenario in ("good", "bad"):
                            record = run_one(binary, sample, scenario, args.timeout)
                            expected = (
                                sample.expected_good
                                if scenario == "good"
                                else sample.expected_bad
                            )
                            observed = observed_outcome(record)
                            checked += 1
                            ledger_entries.append(
                                ledger_entry(
                                    sample=sample,
                                    scenario=scenario,
                                    compiler=compiler,
                                    compiler_id=compiler_id,
                                    opt=opt,
                                    link=link,
                                    binary=binary,
                                    record=record,
                                    semantic_oracle=semantic_oracles.get(
                                        (sample.id, scenario)
                                    ),
                                )
                            )
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
        ledger = make_matrix_ledger(
            entries=ledger_entries,
            requested={"compilers": compilers, "opts": opts, "links": links},
            process_manifest_sha256=sha256(args.manifest),
            oracle_sha256=semantic_oracle_sha256,
        )
        if args.ledger is not None:
            args.ledger.parent.mkdir(parents=True, exist_ok=True)
            args.ledger.write_text(canonical_json(ledger))
        print(
            json.dumps(
                {
                    "checked": checked,
                    "failures": failures,
                    "ledger": str(args.ledger) if args.ledger is not None else None,
                    "ledger_sha256": (
                        hashlib.sha256(canonical_json(ledger).encode()).hexdigest()
                        if args.ledger is not None
                        else None
                    ),
                },
                indent=2,
                sort_keys=True,
            )
        )
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
            record = run_one(binary, sample, args.scenario, args.timeout)
            records.append(record)
            if args.semantic_result_dir is not None:
                args.semantic_result_dir.mkdir(parents=True, exist_ok=True)
                semantic_result = process_semantic_result(
                    record, compiler=args.compiler, opt=args.opt, link=args.link
                )
                path = args.semantic_result_dir / f"{sample.id}.{args.scenario}.json"
                path.write_text(canonical_json(semantic_result))
        elif args.command == "verify":
            for scenario in ("good", "bad"):
                record = run_one(binary, sample, scenario, args.timeout)
                expected = (
                    sample.expected_good if scenario == "good" else sample.expected_bad
                )
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
