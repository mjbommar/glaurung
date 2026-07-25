"""Compile-only gate: every fixture source must build cleanly in every required
lane (gcc/clang x O0/O2) with -Wall -Wextra -Werror.

This is deliberately fast (no decompilation/execution) so it runs on every PR and
catches a malformed fixture immediately — e.g. the `int*/int` comment that once
silently terminated fixture 09's block comment. Intentional switch fallthroughs
are annotated with __attribute__((fallthrough)), not warning suppression.

The lanes compile under the pinned toolchain (`tools/fixture_toolchain.py`), which
provisions gcc, g++, clang and clang++ with a working C++ runtime — so there is no
"this host lacks a compiler" skip to take, and no env gap for the C++ lanes.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "tests" / "decompiler_fixtures"))
import fixture_harness as H


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
