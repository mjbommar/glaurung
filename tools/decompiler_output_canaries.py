#!/usr/bin/env python3
"""Capture and verify deterministic function-level decompiler output canaries."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

TOOLS = Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

from pass_health_report import build_report as build_health_report
from pass_health_report import parse_trace as parse_health_trace

MANIFEST_SCHEMA = "glaurung-output-canaries-v1"
REPORT_SCHEMA = "glaurung-output-canary-report-v1"
JsonObject = dict[str, Any]


class CanaryError(ValueError):
    """Raised when canary inputs or observations are incomplete."""


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _require_fields(value: Mapping[str, Any], expected: set[str], context: str) -> None:
    if set(value) != expected:
        raise CanaryError(
            f"{context} fields must be exactly {sorted(expected)!r}; "
            f"found {sorted(value)!r}"
        )


def _valid_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def load_manifest(path: Path) -> JsonObject:
    """Load a strict, fully pinned canary manifest."""
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise CanaryError(f"cannot read manifest: {error}") from error
    if not isinstance(value, dict):
        raise CanaryError("manifest must be an object")
    _require_fields(value, {"schema", "cases"}, "manifest")
    if value["schema"] != MANIFEST_SCHEMA:
        raise CanaryError(f"unsupported manifest schema {value['schema']!r}")
    cases = value["cases"]
    if not isinstance(cases, list) or not cases:
        raise CanaryError("manifest cases must be a non-empty array")
    names: set[str] = set()
    for index, case in enumerate(cases):
        context = f"case {index}"
        if not isinstance(case, dict):
            raise CanaryError(f"{context} must be an object")
        kind = case.get("kind")
        if kind == "external":
            _require_fields(
                case,
                {"name", "kind", "path", "binary_sha256", "functions"},
                context,
            )
        elif kind == "build":
            _require_fields(
                case,
                {
                    "name",
                    "kind",
                    "source",
                    "source_sha256",
                    "compiler",
                    "compiler_version",
                    "flags",
                    "functions",
                },
                context,
            )
        else:
            raise CanaryError(f"{context}: unsupported kind {kind!r}")
        name = case.get("name")
        if not isinstance(name, str) or not name or name in names:
            raise CanaryError(f"{context}: invalid or duplicate name")
        names.add(name)
        if kind == "external" and not _valid_sha256(case.get("binary_sha256")):
            raise CanaryError(f"{context}: invalid binary_sha256")
        if kind == "build":
            if not _valid_sha256(case.get("source_sha256")):
                raise CanaryError(f"{context}: invalid source_sha256")
            if (
                not all(
                    isinstance(case.get(field), str) and case[field]
                    for field in ("source", "compiler", "compiler_version")
                )
                or not isinstance(case.get("flags"), list)
                or not all(isinstance(flag, str) and flag for flag in case["flags"])
            ):
                raise CanaryError(f"{context}: invalid build recipe")
        functions = case.get("functions")
        if not isinstance(functions, list) or not functions:
            raise CanaryError(f"{context}: functions must be non-empty")
        labels: set[str] = set()
        for function_index, function in enumerate(functions):
            function_context = f"{context} function {function_index}"
            if not isinstance(function, dict):
                raise CanaryError(f"{function_context} must be an object")
            expected = {"label", "entry_va"} if kind == "external" else {"label"}
            _require_fields(function, expected, function_context)
            label = function.get("label")
            if not isinstance(label, str) or not label or label in labels:
                raise CanaryError(f"{function_context}: invalid or duplicate label")
            labels.add(label)
            if kind == "external":
                try:
                    entry_va = int(function["entry_va"], 0)
                except (TypeError, ValueError) as error:
                    raise CanaryError(
                        f"{function_context}: invalid entry_va"
                    ) from error
                if entry_va < 0:
                    raise CanaryError(f"{function_context}: invalid entry_va")
    return value


def capture_function(binary: Path, label: str, entry_va: int) -> JsonObject:
    """Capture deterministic output and final pass-health for one real function."""
    if not binary.is_file():
        raise CanaryError(f"missing binary: {binary}")
    environment = os.environ.copy()
    environment["GLAURUNG_PASS_HEALTH"] = "1"
    script = (
        "import glaurung as g,sys; "
        "sys.stdout.write(g.ir.decompile_at(sys.argv[1], int(sys.argv[2], 0), "
        "style='decbench'))"
    )
    result = subprocess.run(
        [sys.executable, "-c", script, str(binary), hex(entry_va)],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    if result.returncode != 0:
        raise CanaryError(
            f"{label}@0x{entry_va:x}: decompiler failed ({result.returncode}): "
            f"{result.stderr.strip()}"
        )
    output = result.stdout
    if not output:
        raise CanaryError(f"{label}@0x{entry_va:x}: empty decompiler output")
    health_report = build_health_report(parse_health_trace(result.stderr.splitlines()))
    matching = [
        function
        for function in health_report["functions"]
        if function["entry_va"] == hex(entry_va)
    ]
    if len(matching) != 1:
        raise CanaryError(
            f"{label}@0x{entry_va:x}: expected one health function, found {len(matching)}"
        )
    health = matching[0]
    signature = next(
        (
            line.strip()
            for line in output.splitlines()
            if "(" in line and line.rstrip().endswith("{")
        ),
        None,
    )
    if signature is None:
        raise CanaryError(f"{label}@0x{entry_va:x}: output has no function signature")
    return {
        "label": label,
        "entry_va": hex(entry_va),
        "rendered_function": health["function"],
        "signature": signature,
        "output_sha256": _sha256_bytes(output.encode()),
        "output_bytes": len(output.encode()),
        "output_lines": len(output.splitlines()),
        "health_event_count": health["event_count"],
        "health": health["final"],
        "final_violations": health["final_violations"],
        "first_violation_passes": health["first_violation_passes"],
    }


def _compiler_version(compiler: str) -> str:
    result = subprocess.run(
        [compiler, "--version"],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    if result.returncode != 0 or not result.stdout.splitlines():
        raise CanaryError(f"cannot query compiler {compiler!r}")
    return result.stdout.splitlines()[0].strip()


def _dynamic_symbols(binary: Path) -> dict[str, int]:
    result = subprocess.run(
        ["nm", "-D", "--defined-only", str(binary)],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    if result.returncode != 0:
        raise CanaryError(f"nm failed for {binary}: {result.stderr.strip()}")
    symbols: dict[str, int] = {}
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) >= 3:
            try:
                symbols[fields[-1]] = int(fields[0], 16)
            except ValueError:
                continue
    return symbols


def _capture_case(
    case: Mapping[str, Any], root: Path, external_root: Path | None, build_dir: Path
) -> JsonObject:
    kind = case["kind"]
    if kind == "external":
        if external_root is None:
            raise CanaryError("external cases require --external-root")
        binary = (external_root / case["path"]).resolve()
        actual_hash = _sha256_file(binary)
        if actual_hash != case["binary_sha256"]:
            raise CanaryError(
                f"{case['name']}: binary hash mismatch: "
                f"{case['binary_sha256']} != {actual_hash}"
            )
        functions = [
            capture_function(binary, function["label"], int(function["entry_va"], 0))
            for function in case["functions"]
        ]
        provenance = {"kind": kind, "path": case["path"], "binary_sha256": actual_hash}
    else:
        source = (root / case["source"]).resolve()
        actual_source_hash = _sha256_file(source)
        if actual_source_hash != case["source_sha256"]:
            raise CanaryError(f"{case['name']}: source hash mismatch")
        actual_version = _compiler_version(case["compiler"])
        if actual_version != case["compiler_version"]:
            raise CanaryError(
                f"{case['name']}: compiler mismatch: "
                f"{case['compiler_version']!r} != {actual_version!r}"
            )
        binary = build_dir / f"{case['name']}.so"
        command = [case["compiler"], *case["flags"], "-o", str(binary), str(source)]
        result = subprocess.run(
            command, capture_output=True, text=True, check=False, timeout=60
        )
        if result.returncode != 0:
            raise CanaryError(
                f"{case['name']}: compile failed: {result.stderr.strip()}"
            )
        symbols = _dynamic_symbols(binary)
        functions = []
        for function in case["functions"]:
            label = function["label"]
            if label not in symbols:
                raise CanaryError(f"{case['name']}: missing dynamic symbol {label}")
            functions.append(capture_function(binary, label, symbols[label]))
        provenance = {
            "kind": kind,
            "source": case["source"],
            "source_sha256": actual_source_hash,
            "compiler": case["compiler"],
            "compiler_version": actual_version,
            "flags": case["flags"],
            "binary_sha256": _sha256_file(binary),
        }
    return {"name": case["name"], "provenance": provenance, "functions": functions}


def capture_manifest(
    manifest: Mapping[str, Any], root: Path, external_root: Path | None
) -> JsonObject:
    """Build/capture every manifest case in declared order."""
    with tempfile.TemporaryDirectory(prefix="glaurung-output-canaries-") as directory:
        build_dir = Path(directory)
        cases = [
            _capture_case(case, root, external_root, build_dir)
            for case in manifest["cases"]
        ]
    revision = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    status = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    return {
        "schema": REPORT_SCHEMA,
        "git": {
            "revision": revision.stdout.strip()
            if revision.returncode == 0
            else "unknown",
            "dirty": status.returncode != 0 or bool(status.stdout.strip()),
        },
        "cases": cases,
    }


def _scalar_differences(
    current: Any, expected: Any, prefix: str, differences: list[str]
) -> None:
    if isinstance(expected, dict) and isinstance(current, dict):
        for key in sorted(set(expected) | set(current)):
            child = f"{prefix} {key}" if prefix else key
            if key not in expected:
                differences.append(f"{child}: unexpected")
            elif key not in current:
                differences.append(f"{child}: missing")
            else:
                _scalar_differences(current[key], expected[key], child, differences)
    elif current != expected:
        differences.append(f"{prefix}: {expected!r} -> {current!r}")


def compare_reports(
    current: Mapping[str, Any], expected: Mapping[str, Any]
) -> list[str]:
    """Return deterministic function-attributed differences."""
    if (
        current.get("schema") != REPORT_SCHEMA
        or expected.get("schema") != REPORT_SCHEMA
    ):
        return ["report schema mismatch"]
    current_cases = {case["name"]: case for case in current.get("cases", [])}
    expected_cases = {case["name"]: case for case in expected.get("cases", [])}
    differences: list[str] = []
    for case_name in sorted(set(current_cases) | set(expected_cases)):
        if case_name not in expected_cases:
            differences.append(f"{case_name}: unexpected case")
            continue
        if case_name not in current_cases:
            differences.append(f"{case_name}: missing case")
            continue
        current_case = current_cases[case_name]
        expected_case = expected_cases[case_name]
        current_functions = {
            function["label"]: function
            for function in current_case.get("functions", [])
        }
        expected_functions = {
            function["label"]: function
            for function in expected_case.get("functions", [])
        }
        if current_case.get("provenance") != expected_case.get("provenance"):
            _scalar_differences(
                current_case.get("provenance"),
                expected_case.get("provenance"),
                f"{case_name} provenance",
                differences,
            )
        for label in sorted(set(current_functions) | set(expected_functions)):
            if label not in expected_functions:
                differences.append(f"{case_name}:{label}: unexpected function")
            elif label not in current_functions:
                differences.append(f"{case_name}:{label}: missing function")
            else:
                expected_function = expected_functions[label]
                current_function = current_functions[label]
                for key in sorted(set(expected_function) | set(current_function)):
                    if key == "label":
                        continue
                    prefix = f"{case_name}:{label} {key}"
                    if key not in expected_function:
                        differences.append(f"{prefix}: unexpected")
                    elif key not in current_function:
                        differences.append(f"{prefix}: missing")
                    else:
                        _scalar_differences(
                            current_function[key],
                            expected_function[key],
                            prefix,
                            differences,
                        )
    return differences


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--external-root", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--check", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Capture the manifest and optionally compare it with a baseline."""
    args = _parser().parse_args(argv)
    try:
        manifest = load_manifest(args.manifest)
        report = capture_manifest(manifest, Path.cwd(), args.external_root)
        if args.check is not None:
            expected = json.loads(args.check.read_text(encoding="utf-8"))
            differences = compare_reports(report, expected)
            if differences:
                raise CanaryError("\n".join(differences))
    except (OSError, json.JSONDecodeError, CanaryError) as error:
        raise SystemExit(f"output canary failed: {error}") from error
    rendered = json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n"
    if args.output is None:
        sys.stdout.write(rendered)
    else:
        args.output.write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
