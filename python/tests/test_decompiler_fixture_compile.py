"""Compile-only gate: every fixture source must build cleanly in every required
host lane (gcc/clang x O0/O2) with -Wall -Wextra -Werror.

This is deliberately fast (no decompilation/execution) so it runs on every PR and
catches a malformed fixture immediately — e.g. the `int*/int` comment that once
silently terminated fixture 09's block comment. Intentional switch fallthroughs
are annotated with __attribute__((fallthrough)), not warning suppression. A clang
C++ lane on a host lacking the C++ runtime is a probed, declared env gap.
"""
from __future__ import annotations

import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "tests" / "decompiler_fixtures"))
import fixture_harness as H


@pytest.mark.skipif(not (shutil.which("gcc") and shutil.which("clang")),
                    reason="requires gcc and clang")
def test_all_fixtures_compile_strict_in_every_lane():
    problems = H.strict_compile_problems()
    assert not problems, "STRICT COMPILE FAILURES:\n  " + "\n  ".join(problems)


def test_probed_env_missing_is_a_real_gap():
    # Whatever the probe declares missing must genuinely fail to build — the
    # declaration can never mask a lane that actually works.
    for cc, opt, stem in H.detect_allowed_missing():
        src = H.SRC / f"{stem}.cpp"
        assert src.exists()
        so, _ = H.compile_fixture(src, cc, opt, strict=True)
        assert so is None, f"{stem}:{cc}:{opt} declared env-missing but compiled"
