"""Tests for the reproducible decompiler performance harness."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
TOOL = ROOT / "tools/decompiler_profile.py"


def test_profile_harness_captures_cold_warm_rss_parse_and_stage_evidence(tmp_path):
    binary = (
        ROOT
        / "samples/binaries/platforms/linux/amd64/export/native/gcc/O0/hello-gcc-O0"
    )
    output = tmp_path / "profile.json"
    result = subprocess.run(
        [
            str(ROOT / ".venv/bin/python"),
            str(TOOL),
            "--case",
            f"hello={binary}@0x2549",
            "--warm-runs",
            "2",
            "--output",
            str(output),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )

    assert result.returncode == 0, result.stderr
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["schema"] == "glaurung-decompiler-profile-v1"
    assert report["warm_runs"] == 2
    case = report["cases"][0]
    assert case["name"] == "hello"
    assert case["path"] == (
        "samples/binaries/platforms/linux/amd64/export/native/gcc/O0/hello-gcc-O0"
    )
    assert case["binary_sha256"]
    assert case["cold"]["process_wall_ns"] > case["cold"]["decompile_ns"][0]
    assert case["cold"]["max_rss_kib"] > 0
    assert case["cold"]["object_parse_count"][0] > 0
    assert case["warm"]["object_parse_count"] == [
        case["cold"]["object_parse_count"][0],
        case["cold"]["object_parse_count"][0],
    ]
    assert len(case["warm"]["decompile_ns"]) == 2
    assert len(set(case["warm"]["output_sha256"])) == 1
    assert case["cold"]["stage_duration_ns"]["render_decbench"] > 0


def test_profile_harness_rejects_ambiguous_or_missing_cases():
    for arguments, expected in [
        ([], "at least one --case"),
        (["--case", "broken"], "NAME=PATH@VA"),
    ]:
        result = subprocess.run(
            [str(ROOT / ".venv/bin/python"), str(TOOL), *arguments],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        assert result.returncode != 0
        assert expected in result.stderr
