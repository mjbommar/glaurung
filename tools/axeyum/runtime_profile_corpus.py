#!/usr/bin/env python3
"""Capture and replay the real runtime fixtures used by the Axeyum gate."""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
HARNESS_PATH = ROOT / "tools" / "runtime_sample_harness.py"
SPEC = importlib.util.spec_from_file_location("runtime_sample_harness", HARNESS_PATH)
assert SPEC is not None and SPEC.loader is not None
HARNESS = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = HARNESS
SPEC.loader.exec_module(HARNESS)

CORPUS_SCHEMA = "glaurung-runtime-axeyum-profile-corpus-v2"
CASES = (
    (
        "memory_index_write",
        "-DGLAURUNG_RUNTIME_COUNTERFACTUAL_SINK_FIXTURE",
        ["satisfiable"],
    ),
    (
        "danger_command_argument",
        "-DGLAURUNG_RUNTIME_COUNTERFACTUAL_PROFILE_FIXTURE",
        ["satisfiable", "satisfiable", "unsatisfiable", "unsatisfiable"],
    ),
    (
        "crash_null_write",
        "-DGLAURUNG_RUNTIME_COUNTERFACTUAL_CRASH_FIXTURE",
        ["satisfiable"],
    ),
)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def capture_corpus(output: Path, timeout: float) -> dict[str, Any]:
    """Capture each real fixture once without running the analyzer."""
    from glaurung.runtime_capture import capture_instruction_trace_child

    output.mkdir(parents=True, exist_ok=False)
    samples = {sample.id: sample for sample in HARNESS.load_samples()}
    cases: list[dict[str, Any]] = []
    for sample_id, fixture_flag, expected_statuses in CASES:
        sample = samples[sample_id]
        instrumented = replace(sample, cflags=sample.cflags + (fixture_flag,))
        case_dir = output / sample_id
        case_dir.mkdir()
        binary = HARNESS.compile_sample(instrumented, "gcc", "O0", "pie", case_dir)
        supplied = b"cad"
        capture = capture_instruction_trace_child(
            binary,
            [supplied.decode()],
            environment=HARNESS.fixture_environment(sample),
            cwd=case_dir,
            timeout=timeout,
            public_input=supplied,
        )
        binary_bytes = binary.read_bytes()
        cases.append(
            {
                "sample": sample_id,
                "binary": str(binary.relative_to(output)),
                "binary_sha256": _sha256(binary_bytes),
                "capsule_json": capture.capsule_json,
                "payloads": [
                    {
                        "id": payload_id,
                        "sha256": _sha256(payload),
                        "base64": base64.b64encode(payload).decode("ascii"),
                    }
                    for payload_id, payload in capture.payloads
                ],
                "expected_counterfactual_statuses": expected_statuses,
            }
        )
    corpus = {"schema": CORPUS_SCHEMA, "cases": cases}
    (output / "corpus.json").write_text(
        json.dumps(corpus, indent=2, sort_keys=True) + "\n"
    )
    return corpus


def analyze_corpus(corpus_path: Path) -> dict[str, Any]:
    """Analyze a captured corpus and fail on semantic or integrity drift."""
    from glaurung import runtime_analysis

    corpus = json.loads(corpus_path.read_text())
    if corpus.get("schema") != CORPUS_SCHEMA:
        raise ValueError(f"unsupported corpus schema: {corpus.get('schema')!r}")
    results: list[dict[str, Any]] = []
    for case in corpus.get("cases", []):
        binary_path = corpus_path.parent / case["binary"]
        binary = binary_path.read_bytes()
        if _sha256(binary) != case["binary_sha256"]:
            raise ValueError(f"binary hash mismatch for {case['sample']}")
        payloads: list[tuple[str, bytes]] = []
        for encoded in case["payloads"]:
            payload = base64.b64decode(encoded["base64"], validate=True)
            if _sha256(payload) != encoded["sha256"]:
                raise ValueError(
                    f"payload hash mismatch for {case['sample']}:{encoded['id']}"
                )
            payloads.append((encoded["id"], payload))
        report = json.loads(
            runtime_analysis.analyze_process_capsule_instruction_trace(
                case["capsule_json"], payloads, binary
            )
        )
        statuses = sorted(
            candidate["counterfactual"]["status"]
            for candidate in report["solver_query_candidates"]
        )
        expected = sorted(case["expected_counterfactual_statuses"])
        if statuses != expected:
            raise ValueError(
                f"counterfactual statuses differ for {case['sample']}: "
                f"expected {expected!r}, got {statuses!r}"
            )
        results.append(
            {
                "sample": case["sample"],
                "capture_id": report["capture_id"],
                "counterfactual_statuses": statuses,
            }
        )
    if len(results) != len(CASES):
        raise ValueError(f"corpus contains {len(results)} cases, expected {len(CASES)}")
    return {
        "schema": "glaurung-runtime-axeyum-profile-analysis-v1",
        "corpus_sha256": _sha256(corpus_path.read_bytes()),
        "results": results,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    capture = subparsers.add_parser("capture")
    capture.add_argument("--output", type=Path, required=True)
    capture.add_argument("--timeout", type=float, default=30.0)
    analyze = subparsers.add_parser("analyze")
    analyze.add_argument("--corpus", type=Path, required=True)
    analyze.add_argument("--output", type=Path)
    args = parser.parse_args()

    if args.command == "capture":
        if not 1 <= args.timeout <= 120:
            parser.error("--timeout must be in [1, 120] seconds")
        result = capture_corpus(args.output, args.timeout)
    else:
        result = analyze_corpus(args.corpus)
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if getattr(args, "output", None) is None or args.command == "capture":
        print(rendered, end="")
    else:
        args.output.write_text(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
