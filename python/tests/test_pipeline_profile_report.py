"""Tests for decompiler pipeline timing and object-parse reports."""

from __future__ import annotations

import importlib.util
import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
TOOL = ROOT / "tools" / "pipeline_profile_report.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("pipeline_profile_report", TOOL)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def report_module():
    return _load_tool()


def test_profile_parser_aggregates_repeated_function_stages(report_module):
    lines = [
        "noise",
        (
            '[glaurung-pipeline-profile] {"schema":"glaurung-pipeline-profile-v1",'
            '"event":"stage","function":"main","entry_va":"0x1000",'
            '"stage":"lower","duration_ns":10}'
        ),
        (
            '[glaurung-pipeline-profile] {"schema":"glaurung-pipeline-profile-v1",'
            '"event":"stage","function":"main","entry_va":"0x1000",'
            '"stage":"lower","duration_ns":7}'
        ),
        (
            '[glaurung-pipeline-profile] {"schema":"glaurung-pipeline-profile-v1",'
            '"event":"run","entry_point":"decompile_many","duration_ns":30,'
            '"object_parse_count":12}'
        ),
    ]

    report = report_module.build_report(report_module.parse_trace(lines))

    assert report == {
        "schema": "glaurung-pipeline-profile-report-v1",
        "runs": [
            {
                "duration_ns": 30,
                "entry_point": "decompile_many",
                "object_parse_count": 12,
            }
        ],
        "functions": [
            {
                "entry_va": "0x1000",
                "function": "main",
                "stage_event_count": 2,
                "stage_duration_ns": {"lower": 17},
            }
        ],
    }


@pytest.mark.parametrize(
    "line, message",
    [
        ("ordinary stderr", "no pipeline-profile events"),
        (
            '[glaurung-pipeline-profile] {"schema":"old"}',
            "unsupported schema",
        ),
        (
            (
                "[glaurung-pipeline-profile] "
                '{"schema":"glaurung-pipeline-profile-v1",'
                '"event":"run","entry_point":"x","duration_ns":-1,'
                '"object_parse_count":0}'
            ),
            "duration_ns",
        ),
    ],
)
def test_profile_parser_fails_closed(report_module, line, message):
    with pytest.raises(report_module.ProfileReportError, match=message):
        report_module.parse_trace([line])


def test_real_profile_is_output_transparent_and_counts_all_object_parses(report_module):
    binary = (
        ROOT
        / "samples/binaries/platforms/linux/amd64/export/native/gcc/O0/hello-gcc-O0"
    )
    python = ROOT / ".venv/bin/python"
    script = (
        "import glaurung as g; "
        f"print(g.ir.decompile_at({str(binary)!r}, 0x2549, style='decbench'), end='')"
    )
    plain = subprocess.run(
        [str(python), "-c", script],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    environment = os.environ.copy()
    environment["GLAURUNG_PIPELINE_PROFILE"] = "1"
    profiled = subprocess.run(
        [str(python), "-c", script],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )

    assert plain.returncode == 0, plain.stderr
    assert profiled.returncode == 0, profiled.stderr
    assert profiled.stdout == plain.stdout
    report = report_module.build_report(
        report_module.parse_trace(profiled.stderr.splitlines())
    )
    assert report["runs"][0]["entry_point"] == "decompile_at"
    assert report["runs"][0]["duration_ns"] > 0
    assert report["runs"][0]["object_parse_count"] > 0
    assert report["functions"][0]["stage_event_count"] >= 20
    assert report["functions"][0]["stage_duration_ns"]["render_decbench"] > 0
