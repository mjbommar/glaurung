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


def test_decompile_at_reuses_one_program_image_for_address_translation(report_module):
    binary = (
        ROOT
        / "samples/binaries/platforms/linux/amd64/export/native/gcc/O0/hello-gcc-O0"
    )
    script = (
        "import glaurung as g; "
        f"g.ir.decompile_at({str(binary)!r}, 0x2549, style='decbench')"
    )
    environment = os.environ.copy()
    environment["GLAURUNG_PIPELINE_PROFILE"] = "1"
    profiled = subprocess.run(
        [str(ROOT / ".venv/bin/python"), "-c", script],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )

    assert profiled.returncode == 0, profiled.stderr
    report = report_module.build_report(
        report_module.parse_trace(profiled.stderr.splitlines())
    )
    # Object-backed analyses still parse independently while ProgramImage is
    # introduced incrementally, but address translation must never reopen the
    # object once per decoded instruction (3,679 parses on this fixture before
    # the program-scoped index existed, versus 47 after that migration, versus
    # 19 measured at dcc62aa once ProgramImage took ownership of PLT ranges,
    # no-return imports, exception sites and DWARF functions). The bound is a
    # ratchet on that residue; the binary-independence of the number is pinned
    # separately below.
    assert report["runs"] == [
        {
            "duration_ns": report["runs"][0]["duration_ns"],
            "entry_point": "decompile_at",
            "object_parse_count": report["runs"][0]["object_parse_count"],
        }
    ]
    assert report["runs"][0]["object_parse_count"] <= 20


# Four checked-in ELFs that share no toolchain, no libc, and no size class:
# a small unoptimized gcc C binary, an optimized clang one, a static Go binary
# with a `.gopclntab`, and a 1146-function static Rust/musl binary.
_PARSE_BUDGET_BINARIES = (
    "samples/binaries/platforms/linux/amd64/export/native/gcc/O0/hello-gcc-O0",
    "samples/binaries/platforms/linux/amd64/export/native/clang/O2/hello-clang-O2",
    "samples/binaries/platforms/linux/amd64/export/go/hello-go-static",
    "samples/binaries/platforms/linux/amd64/export/rust/hello-rust-musl",
)


def _whole_program_parse_count(report_module, relative_path: str, limit: int) -> int:
    """Return the object parses one whole-program decompile run performs."""
    binary = ROOT / relative_path
    script = (
        "import glaurung as g; "
        f"g.ir.decompile_all({str(binary)!r}, style='decbench', limit={limit})"
    )
    environment = os.environ.copy()
    environment["GLAURUNG_PIPELINE_PROFILE"] = "1"
    profiled = subprocess.run(
        [str(ROOT / ".venv/bin/python"), "-c", script],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=300,
    )

    assert profiled.returncode == 0, profiled.stderr
    report = report_module.build_report(
        report_module.parse_trace(profiled.stderr.splitlines())
    )
    assert report["runs"][0]["entry_point"] == "decompile_all"
    return int(report["runs"][0]["object_parse_count"])


def test_object_parse_count_is_a_session_constant_not_a_function_of_the_binary(
    report_module,
):
    """A session's object parses must not depend on what it is analysing.

    The Phase 1 target is exactly one base object parse per reusable session.
    The count is not one — it is a fixed set of one-shot program analyses that
    each parse once — but it *is* a constant, and that is the property a
    regression would break. Before `ProgramImage` took ownership the count was
    `O(functions + branches + callees)`: 58 parses on `hello-gcc-O2` and 40,865
    on `hello-rust-musl` at the default limit, varying between runs of the same
    binary. Any reintroduced per-function, per-branch or per-callee parse makes
    these four binaries — and the two limits — disagree.
    """
    counts = {
        path: _whole_program_parse_count(report_module, path, 50)
        for path in _PARSE_BUDGET_BINARIES
    }
    # Raising the discovery limit finds far more functions on the small binary
    # and must still cost the same parses.
    counts["hello-gcc-O0 @ limit=30000"] = _whole_program_parse_count(
        report_module, _PARSE_BUDGET_BINARIES[0], 30_000
    )

    assert len(set(counts.values())) == 1, (
        f"object parses vary with the binary or the discovery limit: {counts}"
    )
    only = next(iter(counts.values()))
    assert 0 < only <= 20, (
        f"whole-program object parses moved off the measured constant: {counts}"
    )
