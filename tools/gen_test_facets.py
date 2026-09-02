#!/usr/bin/env python3
"""Classify every Python test file by what it NEEDS, and record it.

Writes `tests/test_facets.json`. `python/tests/conftest.py` reads that file at
collection time and applies one pytest marker per facet, so a run can select a
tier without anyone hand-editing 459 files -- and so the classification is a
reviewable artifact rather than a set of scattered decorators.

Why facets are requirements rather than subjects
------------------------------------------------

`ir` versus `core` is a subject axis. What actually decides where a test can
RUN is what it needs: the built fixture matrix (gitignored, ~40 minutes to
build), a compiler at test time, Git LFS sample binaries, Docker, a live LLM
key, or the out-of-tree DecBench checkout. Tiering along those lines makes a
marker *predict* whether a test can run on a given machine, which is what a
CI job needs to know, and it makes every skip reason precise.

The rules are deliberately dumb text patterns. They are explainable, they run
in under a second, and a wrong classification is visible in the JSON diff. A
test that needs something the rules cannot see should say so with an explicit
`pytestmark` in the file; the hook merges both.

`core` is the absence of every other facet.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TESTS = ROOT / "python" / "tests"
OUT = ROOT / "tests" / "test_facets.json"

#: facet -> what in the file's text proves the test needs it.
RULES: dict[str, re.Pattern[str]] = {
    # The built decompiler fixture matrix. Gitignored; absent on every fresh
    # clone and on the test-suite CI runner.
    "fixtures": re.compile(
        r"decompiler_fixtures/build|FIXTURE_BUILD\b|fixture_harness|"
        r"decompiler_fixtures\"\s*/\s*\"build|known_failures\.json"
    ),
    # Invokes a compiler at test time (as opposed to reading a committed .so).
    "toolchain": re.compile(
        r"shutil\.which\(\s*[\"'](gcc|clang|cc|rustc|go|zig|arm-none-eabi-gcc|"
        r"clang-cl|lld-link|i686-w64-mingw32-gcc)|"
        r"subprocess\.run\(\s*\[\s*[\"'](gcc|clang|cc|rustc|zig|arm-none-eabi-gcc|"
        r"clang-cl|lld-link)\b"
    ),
    # Reads sample binaries, which are Git LFS objects: a checkout without
    # `lfs: true` sees 130-byte pointer files.
    "lfs": re.compile(r"samples/(binaries|packed|adversarial|source)\b"),
    # Needs the pinned fixture-toolchain Docker image. The rule wants an
    # INVOCATION, not the word: a test that merely says "docker" in a docstring
    # about CI would otherwise be tiered as needing it.
    "docker": re.compile(
        r"shutil\.which\(\s*[\"']docker|subprocess\.run\(\s*\[\s*[\"']docker|"
        r"fixture_toolchain\b|\bTC\.run\("
    ),
    # Needs a live model endpoint and a key. Opt-in by construction.
    "llm": re.compile(
        r"OPENAI_API_KEY|ANTHROPIC_API_KEY|GLAURUNG_LLM_LIVE|live_llm|"
        r"requires_live_llm"
    ),
    # Needs the out-of-tree DecBench checkout or a Joern JVM.
    "decbench": re.compile(r"mark\.decbench|DECBENCH_DIR|decbench_full|decbench-full"),
}


def classify(text: str) -> list[str]:
    found = [name for name, rule in RULES.items() if rule.search(text)]
    return found or ["core"]


def census() -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for path in sorted(TESTS.glob("test_*.py")):
        out[path.name] = classify(path.read_text(errors="ignore"))
    return out


def main() -> int:
    facets = census()
    counts: dict[str, int] = {}
    for names in facets.values():
        for n in names:
            counts[n] = counts.get(n, 0) + 1
    payload = {
        "note": (
            "Test files classified by what they NEED. Applied as pytest markers "
            "by python/tests/conftest.py. Regenerate with "
            "tools/gen_test_facets.py; do not hand-edit."
        ),
        "counts": dict(sorted(counts.items(), key=lambda kv: -kv[1])),
        "files": facets,
    }
    OUT.write_text(json.dumps(payload, indent=1) + "\n")
    print(
        f"{OUT.relative_to(ROOT)}: {len(facets)} files, "
        + ", ".join(f"{k}={v}" for k, v in payload["counts"].items())
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
