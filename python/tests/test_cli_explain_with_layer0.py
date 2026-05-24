"""F4 integration tests for `glaurung explain --with-layer0`.

The Layer-0 pre-pass runs Tools #5 / #3 / #2 across a function's
pseudocode and feeds the resulting tables into Tool #14. These tests
exercise the offline (heuristic-fallback) path so they pass without
an LLM key -- the F4 contract is that the pre-pass produces a
non-empty audit log even when every individual tool falls back to
its heuristic.

The fastfat.sys post-patch fixture lives at the canonical corpus
location; tests that need it skip cleanly when it's missing.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest


SAMPLE = Path(
    "samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-gcc-O2"
)
FASTFAT_POST = Path(
    "/nas4/data/workspace-infosec/agentic-security-bot/projects/"
    "windows-hunting/corpora/cve-2025-24985/post/fastfat.sys"
)
FASTFAT_VA = 0x1C0067010


def _run(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "glaurung.cli", "explain", *args],
        capture_output=True,
        text=True,
        check=False,
    )


# ---------------------------------------------------------------------------
# Flag-parsing smoke tests (no binary required)
# ---------------------------------------------------------------------------


def test_with_layer0_flag_in_help():
    """--with-layer0 must be discoverable via --help."""
    result = _run(["--help"])
    assert result.returncode == 0, result.stderr
    assert "--with-layer0" in result.stdout
    # The help blurb must call out the cost so operators understand
    # what they're opting into.
    assert "Layer-0" in result.stdout


# ---------------------------------------------------------------------------
# End-to-end against the linux hello-world sample (no API key required)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not SAMPLE.exists(), reason="linux sample missing")
def test_with_layer0_emits_layer0_block_in_json():
    """--with-layer0 --json must add a top-level 'layer0' block with
    audit lists for variables / strings / constants and a stats
    sub-object."""
    result = _run(
        [
            str(SAMPLE),
            "--func", "0x1840",
            "--no-types", "--no-roles",
            "--with-layer0",
            "--json",
        ]
    )
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert "layer0" in payload
    block = payload["layer0"]
    for key in ("variables", "strings", "constants", "stats"):
        assert key in block, f"layer0 block missing key: {key}"
    assert isinstance(block["variables"], list)
    assert isinstance(block["strings"], list)
    assert isinstance(block["constants"], list)
    stats = block["stats"]
    for key in (
        "variables_resolved",
        "strings_resolved",
        "constants_resolved",
        "llm_calls",
        "cache_hits",
    ):
        assert key in stats, f"layer0 stats missing key: {key}"
    # Stage bookkeeping must mark layer0 as enabled (not skipped).
    assert payload["stages"]["layer0_prepass"]["source"] == "enabled"


@pytest.mark.skipif(not SAMPLE.exists(), reason="linux sample missing")
def test_with_layer0_plain_text_banner_shows_counts():
    """Plain text mode shows a `// layer0:` banner with the resolved
    counts so an operator running interactively sees what fired."""
    result = _run(
        [
            str(SAMPLE),
            "--func", "0x1840",
            "--no-types", "--no-roles",
            "--with-layer0",
        ]
    )
    assert result.returncode == 0, result.stderr
    assert "// layer0:" in result.stdout
    # The banner mentions all three resolved categories.
    for cat in ("vars=", "strs=", "consts="):
        assert cat in result.stdout, (
            f"layer0 banner missing {cat}: {result.stdout!r}"
        )


@pytest.mark.skipif(not SAMPLE.exists(), reason="linux sample missing")
def test_no_layer0_omits_layer0_block():
    """Without --with-layer0 the JSON payload must NOT carry a
    top-level layer0 block (F3 default behaviour preserved)."""
    result = _run(
        [
            str(SAMPLE),
            "--func", "0x1840",
            "--no-types", "--no-roles",
            "--no-layer0",  # explicit
            "--json",
        ]
    )
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert "layer0" not in payload
    assert payload["stages"]["layer0_prepass"]["source"] == "skipped"


# ---------------------------------------------------------------------------
# A7 cache wiring: a second run with the same cache dir must hit cache.
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not SAMPLE.exists(), reason="linux sample missing")
def test_with_layer0_cache_dir_hits_on_second_run(tmp_path: Path):
    """The Layer-0 prepass writes per-call entries under <cache>/layer0/
    so the second invocation reports cache_hits > 0."""
    cache_dir = tmp_path / "glaurung-cache"
    args = [
        str(SAMPLE),
        "--func", "0x1840",
        "--no-types", "--no-roles",
        "--with-layer0",
        "--cache-dir", str(cache_dir),
        "--json",
    ]
    # First run -- populate the cache.
    first = _run(args)
    assert first.returncode == 0, first.stderr
    first_payload = json.loads(first.stdout)
    # The disk tree under cache_dir/layer0/ must exist after run 1.
    layer0_root = cache_dir / "layer0"
    assert layer0_root.exists(), (
        f"layer0 cache tree not created: {list(cache_dir.iterdir())}"
    )
    # Second run -- expect cache hits.
    second = _run(args)
    assert second.returncode == 0, second.stderr
    second_payload = json.loads(second.stdout)
    second_stats = second_payload["layer0"]["stats"]
    assert second_stats["cache_hits"] > 0, (
        f"expected cache hits on rerun, got {second_stats}"
    )


# ---------------------------------------------------------------------------
# Fastfat.sys post-patch calibration smoke test
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    not FASTFAT_POST.exists(),
    reason="fastfat.sys CVE-2025-24985 fixture not available",
)
def test_with_layer0_fastfat_smoke():
    """Calibration smoke test: --with-layer0 against the CVE-2025-24985
    post-patch binary must produce a non-empty layer0 audit block and
    Tool #14 must still complete."""
    result = _run(
        [
            str(FASTFAT_POST),
            "--func", hex(FASTFAT_VA),
            "--no-types", "--no-roles",
            "--with-layer0",
            "--json",
        ]
    )
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert "layer0" in payload
    block = payload["layer0"]
    # The pre-pass must have seen at least *some* locals -- this
    # function's pseudocode references var0 / arg0 / stack_0.
    assert len(block["variables"]) > 0, (
        f"layer0.variables must be non-empty for fastfat: {block}"
    )
    # Tool #14 must still produce a rewritten body.
    assert payload["source"], "rewrite produced empty source"
    # Rewrite stage source must be one of the documented values.
    assert payload["stages"]["rewrite_function_idiomatic"]["source"] in (
        "llm",
        "heuristic",
    )
