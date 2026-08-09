"""Tests for pass-attributed decompiler output-health reports."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
TOOL = ROOT / "tools" / "pass_health_report.py"
TRACE = (
    ROOT / "tests" / "decbench_scoreboard" / "fixtures" / "hello-main-pass-health.jsonl"
)


def _load_tool():
    spec = importlib.util.spec_from_file_location("pass_health_report", TOOL)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def report_module():
    return _load_tool()


def test_real_trace_names_the_first_pass_that_changed_each_health_counter(
    report_module,
):
    events = report_module.parse_trace(TRACE.read_text(encoding="utf-8").splitlines())
    # The checked-in binary's real CFG has 22 blocks (analyze_functions_path).
    report = report_module.build_report(events, source_cfg_nodes={"0x2549": 22})
    function = report["functions"][0]

    assert function["function"] == "main"
    assert function["event_count"] == 22
    assert function["first_changes"]["declarations"] == {
        "pass": "reconstruct",
        "before": 261,
        "after": 187,
        "delta": -74,
    }
    assert function["first_changes"]["parameters"]["pass"] == "apply_role_names"
    assert function["first_changes"]["undefined_uses"]["pass"] == (
        "promote_stack_locals"
    )
    assert function["final"]["physical_registers"] == 0
    assert function["final"]["uncovered_cfg_edges"] == 0
    assert function["final"]["invented_cfg_edges"] == 0
    assert function["final_violations"] == [
        {"kind": "never_defined", "name": "var105"},
        {"kind": "never_defined", "name": "var93"},
    ]
    assert function["first_violation_passes"] == {
        "never_defined:var105": "apply_role_names",
        "never_defined:var93": "apply_role_names",
    }
    assert function["output_to_source_cfg_ratio"] == pytest.approx(69 / 22)


def test_report_retains_every_stage_and_is_byte_deterministic(report_module):
    events = report_module.parse_trace(TRACE.read_text(encoding="utf-8").splitlines())
    first = report_module.render_json(report_module.build_report(events))
    second = report_module.render_json(report_module.build_report(events))

    assert first == second
    decoded = json.loads(first)
    assert decoded["schema"] == "glaurung-pass-health-report-v1"
    assert decoded["functions"][0]["stages"][0]["pass"] == "lower"
    assert decoded["functions"][0]["stages"][-1]["pass"] == "ready_to_render"


def test_trace_parser_rejects_stale_schema_and_malformed_events(report_module):
    stale = (
        '[glaurung-pass-health] {"schema":"old","pass":"x",'
        '"function":"f","entry_va":"0x1","health":{}}'
    )
    with pytest.raises(report_module.HealthReportError, match="unsupported schema"):
        report_module.parse_trace([stale])

    with pytest.raises(report_module.HealthReportError, match="invalid JSON"):
        report_module.parse_trace(["[glaurung-pass-health] {"])


def test_missing_trace_events_fail_instead_of_producing_an_empty_report(report_module):
    with pytest.raises(report_module.HealthReportError, match="no pass-health events"):
        report_module.parse_trace(["ordinary stderr"])


def test_real_decompiler_pipeline_emits_parseable_health_for_every_pass(report_module):
    binary = (
        ROOT
        / "samples"
        / "binaries"
        / "platforms"
        / "linux"
        / "amd64"
        / "export"
        / "native"
        / "gcc"
        / "O0"
        / "hello-gcc-O0"
    )
    executable = ROOT / ".venv" / "bin" / "glaurung"
    assert binary.is_file() and executable.is_file()
    environment = os.environ.copy()
    environment["GLAURUNG_PASS_HEALTH"] = "1"

    command = [
        str(executable),
        "decompile",
        str(binary),
        "--func",
        "main",
        "--style",
        "decbench",
        "--no-color",
    ]
    result = subprocess.run(
        command,
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )

    assert result.returncode == 0, result.stderr
    events = report_module.parse_trace(result.stderr.splitlines())
    assert events[0]["pass"] == "lower"
    assert events[-1]["pass"] == "ready_to_render"
    assert events[-1]["health"]["undefined_uses"] == len(events[-1]["violations"])
    assert events[-1]["health"]["uncovered_cfg_edges"] == 0
    assert events[-1]["health"]["invented_cfg_edges"] == 0

    plain = subprocess.run(
        command,
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert plain.returncode == 0, plain.stderr
    assert plain.stdout == result.stdout
    assert report_module.PREFIX not in plain.stderr
