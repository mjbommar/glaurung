"""Integration tests for the `glaurung explain` CLI subcommand.

The explain pipeline is a thin orchestrator around three Layer-1/2 tools
(infer_function_signature, classify_function_role,
rewrite_function_idiomatic). Each of those tools has its own heuristic
fallback path that fires when no LLM credentials are configured, so
these tests exercise the full pipeline offline -- no key required.

The smoke test against the fastfat.sys CVE-2025-24985 fixture is gated
on the binary's presence in /tmp; CI doesn't have it, but local
operator runs do. We don't pin a specific VA there because
``decompile_at``'s entry-discovery pass varies across builds.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest


SAMPLE = Path(
    "samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-gcc-O2"
)
FASTFAT_POST = Path(
    "/tmp/patch-tuesday/2025-Mar/CVE-2025-24985/fastfat.sys/post/fastfat.sys"
)


def _run(args: list[str]) -> subprocess.CompletedProcess:
    """Invoke the CLI in-process via `python -m glaurung.cli`."""
    return subprocess.run(
        [sys.executable, "-m", "glaurung.cli", "explain", *args],
        capture_output=True,
        text=True,
        check=False,
    )


def test_explain_help_exposes_new_flags():
    """--help must advertise every Layer-0/1/2 flag the spec promises."""
    result = _run(["--help"])
    assert result.returncode == 0, result.stderr
    text = result.stdout
    for flag in (
        "--func",
        "--style",
        "--no-types",
        "--no-roles",
        "--no-layer0",
        "--pdb-cache",
        "--cache-dir",
        "--json",
    ):
        assert flag in text, f"--help missing {flag}"


@pytest.mark.skipif(not SAMPLE.exists(), reason="linux sample missing")
def test_explain_runs_offline_pipeline_on_hello_world():
    """End-to-end smoke test: no LLM key -> every tool falls back to its
    heuristic path -> output is still well-formed C wrapping the
    pseudocode."""
    result = _run([str(SAMPLE), "--func", "0x1840", "--no-types", "--no-roles"])
    assert result.returncode == 0, result.stderr
    out = result.stdout
    # The plain-text formatter prepends a banner comment.
    assert "// entry_va: 0x1840" in out
    assert "// rewrite-source: heuristic" in out
    # The placeholder prototype is the giveaway that --no-types fired.
    assert "sub_1840" in out
    # The heuristic rewrite wraps the pseudocode in a function shell.
    assert "{" in out and "}" in out


@pytest.mark.skipif(not SAMPLE.exists(), reason="linux sample missing")
def test_explain_json_output_shape_matches_spec():
    """--json must emit the entry_va / c_prototype / source / assumptions /
    confidence / rationale fields the F3 spec calls out."""
    result = _run(
        [str(SAMPLE), "--func", "0x1840", "--no-types", "--no-roles", "--json"]
    )
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    # Top-level keys promised by the spec.
    for key in (
        "entry_va",
        "c_prototype",
        "source",
        "assumptions",
        "confidence",
        "rationale",
    ):
        assert key in payload, f"missing key: {key}"
    # And per-stage bookkeeping so callers can tell which path fired.
    assert "stages" in payload
    stages = payload["stages"]
    assert stages["infer_function_signature"]["source"] == "skipped"
    assert stages["classify_function_role"]["source"] == "skipped"
    # Rewrite stage always runs.
    assert stages["rewrite_function_idiomatic"]["source"] in ("llm", "heuristic")
    # Schema sanity: entry_va is the integer we asked for.
    assert payload["entry_va"] == 0x1840


@pytest.mark.skipif(not SAMPLE.exists(), reason="linux sample missing")
def test_explain_no_layer0_flag_accepted():
    """--no-layer0 is currently a no-op (Layer-0 wiring is F4) but must
    parse cleanly so downstream callers can opt in unconditionally."""
    result = _run(
        [str(SAMPLE), "--func", "0x1840", "--no-types", "--no-roles", "--no-layer0"]
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.skipif(not SAMPLE.exists(), reason="linux sample missing")
def test_explain_invalid_va_reports_error():
    """An unrecognised VA must surface as a clear CLI error, not a stack
    trace, so diff_explain can fall back to raw decompile."""
    result = _run([str(SAMPLE), "--func", "0xdeadbeef", "--no-types", "--no-roles"])
    assert result.returncode != 0
    assert "Error" in result.stdout or "Error" in result.stderr


@pytest.mark.skipif(not SAMPLE.exists(), reason="linux sample missing")
def test_explain_quiet_suppresses_banner():
    """-q hides the // entry_va / // prototype-source banner so the
    output is pipeline-friendly (just the rewritten body)."""
    result = _run(
        [str(SAMPLE), "--func", "0x1840", "--no-types", "--no-roles", "-q"]
    )
    assert result.returncode == 0, result.stderr
    assert "// entry_va:" not in result.stdout
    # But the rewritten body still lands.
    assert "sub_1840" in result.stdout


@pytest.mark.skipif(
    not FASTFAT_POST.exists(),
    reason="fastfat.sys CVE-2025-24985 fixture not available",
)
def test_explain_fastfat_smoke():
    """Calibration smoke test against the CVE-2025-24985 fix-site binary.

    We deliberately do not pin sub_1c005baf8 here: decompile_at's
    entry-discovery pass does not surface that VA on the post-patch
    binary (range-based decompile is not exposed at the CLI yet). We
    instead drive the entry point that detect_entry_path returns and
    assert that the pipeline produces a plausible idiomatic body.
    """
    result = _run([str(FASTFAT_POST), "--no-types", "--no-roles"])
    assert result.returncode == 0, result.stderr
    # Banner + a real rewrite (heuristic or LLM, both acceptable
    # offline).
    assert "// rewrite-source:" in result.stdout
    # The placeholder prototype carries the entry-point VA, so the body
    # must at least mention 'sub_'.
    assert "sub_" in result.stdout
