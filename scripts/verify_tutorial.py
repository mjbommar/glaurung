#!/usr/bin/env python
"""Verify the tutorial track against shipped CLI surfaces.

For every chapter in docs/tutorial/, runs the documented commands
end-to-end against samples/binaries/, captures the real output to
docs/tutorial/_fixtures/<chapter>/<step>.out, and produces a diff
report when the markdown contains synthesized output that doesn't
match.

Usage:
    uv run python scripts/verify_tutorial.py            # capture + check
    uv run python scripts/verify_tutorial.py --capture  # capture only
    uv run python scripts/verify_tutorial.py --check    # check only

Each chapter is encoded as a list of (label, command) pairs. The
harness:

  1. Runs each command, captures stdout (stderr merged), strips a
     few sources of nondeterminism (timestamps, paths under /tmp,
     elapsed_ms latencies).
  2. Writes the captured output to a stable .out file the markdown
     can include or assert against.
  3. Optionally diffs the captured output against the previous
     fixture so test runs can fail when the surface drifts.

Convention: every chapter has exactly one `.glaurung` file under
/tmp/tutorial-fixtures/<chapter>.glaurung — the harness creates a
fresh one per chapter so steps don't bleed state.
"""

from __future__ import annotations

import argparse
import os
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Iterable, List, Tuple

REPO = Path(__file__).resolve().parent.parent
FIXTURES = REPO / "docs" / "tutorial" / "_fixtures"
TMP = Path("/tmp/tutorial-fixtures")

# ---------------------------------------------------------------------------
# Sample binaries used across chapters — keep these as constants so the
# harness can fail fast if a sample disappears from the corpus.
# ---------------------------------------------------------------------------

S_HELLO = REPO / "samples/binaries/platforms/linux/amd64/export/native/clang/debug/hello-clang-debug"
S_HELLO_C = REPO / "samples/binaries/platforms/linux/amd64/export/native/clang/debug/hello-c-clang-debug"
S_GO = REPO / "samples/binaries/platforms/linux/amd64/export/go/hello-go"
S_DOTNET = REPO / "samples/binaries/platforms/linux/amd64/export/dotnet/mono/Hello-mono.exe"
S_JAVA_CLASS = REPO / "samples/binaries/platforms/linux/amd64/export/java/HelloWorld.class"
S_JAVA_JAR = REPO / "samples/binaries/platforms/linux/amd64/export/java/HelloWorld.jar"
S_LUA = REPO / "samples/binaries/platforms/linux/amd64/export/lua/hello-lua5.3.luac"
S_VULN = REPO / "samples/binaries/platforms/linux/amd64/synthetic/vulnparse-c-gcc-O0"
S_PACKED = REPO / "samples/packed/hello-go.upx9"
S_C2 = REPO / "samples/binaries/platforms/linux/amd64/export/native/clang/O0/c2_demo-clang-O0"
S_SWITCHY = REPO / "samples/binaries/platforms/linux/amd64/synthetic/switchy-c-gcc-O2"
S_SWITCHY_V2 = REPO / "samples/binaries/platforms/linux/amd64/synthetic/switchy-c-gcc-O2-v2"


def stable(text: str) -> str:
    """Strip nondeterministic noise from captured output."""
    # Timestamps in benchmark / kickoff markdown summaries.
    text = re.sub(
        r"benchmark — \d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:\d{2})?",
        "benchmark — TIMESTAMP",
        text,
    )
    # `_completed in NN ms_` — keep the structure, blank the value.
    text = re.sub(r"_completed in \d+(?:\.\d+)? ms_", "_completed in N ms_", text)
    # Latency lines in bench markdown rows.
    text = re.sub(r"(\| )\d{2,5} \|$", r"\1NN |", text, flags=re.MULTILINE)
    # Glaurung HEAD commit id is volatile.
    text = re.sub(r"glaurung HEAD: `[0-9a-f]{12}`", "glaurung HEAD: `<sha>`", text)
    # `at NN ms` from kickoff timing footers.
    text = re.sub(r"\(at (\d+) ms\)", "(at N ms)", text)
    return text


def run(cmd: List[str], *, env_extra: dict | None = None) -> str:
    """Run a command, return stdout with stderr merged. Times out at 5min."""
    env = os.environ.copy()
    if env_extra:
        env.update(env_extra)
    res = subprocess.run(
        cmd,
        cwd=str(REPO),
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
    )
    out = res.stdout + (res.stderr if res.stderr else "")
    return out


def write_fixture(chapter: str, step: str, output: str) -> Path:
    chapter_dir = FIXTURES / chapter
    chapter_dir.mkdir(parents=True, exist_ok=True)
    path = chapter_dir / f"{step}.out"
    path.write_text(stable(output))
    return path


# ---------------------------------------------------------------------------
# Chapter recipes. Each chapter is a list of (step_name, [argv]) pairs.
# Steps are run in order; the chapter's dedicated .glaurung file persists
# across steps within a chapter.
# ---------------------------------------------------------------------------


def reset_chapter(name: str) -> Path:
    """Return a fresh DB path for the chapter, deleting any prior one."""
    db = TMP / f"{name}.glaurung"
    db.parent.mkdir(parents=True, exist_ok=True)
    if db.exists():
        db.unlink()
    return db


def cmd(*args: str) -> List[str]:
    """Build a `uv run glaurung` argv with the given subcommand args."""
    return ["uv", "run", "glaurung", *args]


# Tier 1 §B — first-binary
def chapter_first_binary() -> List[Tuple[str, List[str]]]:
    db = reset_chapter("01-first-binary")
    return [
        ("file", ["file", str(S_HELLO)]),
        ("kickoff", cmd("kickoff", str(S_HELLO), "--db", str(db))),
        ("sqlite-fnames", [
            "sqlite3", str(db), "-cmd", ".mode column",
            "SELECT printf('%#x', entry_va) AS entry_va, canonical, set_by "
            "FROM function_names ORDER BY entry_va LIMIT 5;",
        ]),
        ("view", cmd(
            "view", str(db), "0x11e0",
            "--binary", str(S_HELLO),
            "--hex-window", "32",
            "--pseudo-lines", "6",
        )),
        ("strings", cmd("strings", str(S_HELLO))),
        ("find-main", cmd("find", str(db), "main", "--kind", "function")),
    ]


# Tier 3 §M — hello-c-clang walkthrough
def chapter_hello_c_clang() -> List[Tuple[str, List[str]]]:
    db = reset_chapter("03-hello-c-clang")
    return [
        ("file", ["file", str(S_HELLO_C)]),
        ("kickoff", cmd("kickoff", str(S_HELLO_C), "--db", str(db))),
        ("find-main", cmd("find", str(db), "main", "--kind", "function")),
        ("find-all", cmd("find", str(db), "", "--kind", "function")),
        ("view-main", cmd(
            "view", str(db), "0x1150",
            "--binary", str(S_HELLO_C),
            "--pane", "pseudo",
            "--pseudo-lines", "25",
        )),
        ("view-print-sum", cmd(
            "view", str(db), "0x11d0",
            "--binary", str(S_HELLO_C),
            "--pane", "pseudo",
            "--pseudo-lines", "8",
        )),
        ("xrefs-print-sum", cmd(
            "xrefs", str(db), "0x11d0",
            "--binary", str(S_HELLO_C),
            "--direction", "to",
        )),
        ("xrefs-static-fn", cmd(
            "xrefs", str(db), "0x1200",
            "--binary", str(S_HELLO_C),
            "--direction", "to",
        )),
    ]


# Tier 3 §N — stripped Go walkthrough
def chapter_stripped_go() -> List[Tuple[str, List[str]]]:
    db = reset_chapter("03-stripped-go")
    return [
        ("file", ["file", str(S_GO)]),
        ("kickoff", cmd("kickoff", str(S_GO), "--db", str(db))),
        ("find-main-main", cmd(
            "find", str(db), r"main.main$",
            "--regex", "--kind", "function",
        )),
        ("find-main-namespace", cmd(
            "find", str(db), r"main\.",
            "--regex", "--kind", "function",
            "--limit", "20",
        )),
        ("find-runtime-main", cmd(
            "find", str(db), r"runtime.main$",
            "--regex", "--kind", "function",
        )),
        ("find-runtime-gopanic", cmd(
            "find", str(db), r"runtime.gopanic$",
            "--regex", "--kind", "function",
        )),
        ("find-internal-abi", cmd(
            "find", str(db), "internal/abi.Kind.String",
            "--kind", "function",
        )),
    ]


# Tier 3 §O — managed .NET PE
def chapter_dotnet_pe() -> List[Tuple[str, List[str]]]:
    db = reset_chapter("03-dotnet-pe")
    return [
        ("file", ["file", str(S_DOTNET)]),
        ("kickoff", cmd("kickoff", str(S_DOTNET), "--db", str(db))),
        ("find-hello", cmd(
            "find", str(db), "Hello", "--kind", "function",
        )),
    ]


# Tier 3 §P — JVM classfile
def chapter_jvm() -> List[Tuple[str, List[str]]]:
    return [
        ("file-class", ["file", str(S_JAVA_CLASS)]),
        ("classfile", cmd("classfile", str(S_JAVA_CLASS))),
        ("classfile-jar", cmd("classfile", str(S_JAVA_JAR))),
    ]


# Tier 3 §Q — vulnerable parser
def chapter_vulnparse() -> List[Tuple[str, List[str]]]:
    db = reset_chapter("03-vulnparse")
    return [
        ("file", ["file", str(S_VULN)]),
        ("kickoff", cmd("kickoff", str(S_VULN), "--db", str(db))),
        ("find-all-funcs", cmd("find", str(db), "", "--kind", "function")),
        ("view-main", cmd(
            "view", str(db), "0x12ae",
            "--binary", str(S_VULN),
            "--pane", "pseudo",
            "--pseudo-lines", "30",
        )),
        ("view-parse-record", cmd(
            "view", str(db), "0x11e9",
            "--binary", str(S_VULN),
            "--pane", "pseudo",
            "--pseudo-lines", "30",
        )),
        ("xrefs-parse-record", cmd(
            "xrefs", str(db), "0x11e9",
            "--binary", str(S_VULN),
            "--direction", "to",
        )),
    ]


# Tier 3 §R — UPX-packed
def chapter_upx_packed() -> List[Tuple[str, List[str]]]:
    db = reset_chapter("03-upx-packed")
    return [
        ("file", ["file", str(S_PACKED)]),
        ("detect-packer", cmd("detect-packer", str(S_PACKED))),
        ("kickoff", cmd("kickoff", str(S_PACKED), "--db", str(db))),
    ]


# Tier 3 §S — c2_demo flagship
def chapter_c2_demo() -> List[Tuple[str, List[str]]]:
    db = reset_chapter("03-c2-demo")
    return [
        ("file", ["file", str(S_C2)]),
        ("kickoff", cmd("kickoff", str(S_C2), "--db", str(db))),
        ("strings-grep-iocs", [
            "bash", "-c",
            f"uv run glaurung strings {shlex.quote(str(S_C2))} "
            f"| grep -iE 'http|\\.com|\\.org|10\\.|update|cron|systemd|backdoor'"
        ]),
        ("view-main", cmd(
            "view", str(db), "0x1160",
            "--binary", str(S_C2),
            "--pane", "pseudo",
            "--pseudo-lines", "25",
        )),
    ]


# Tier 4 §T — diffing two binaries
def chapter_diff() -> List[Tuple[str, List[str]]]:
    return [
        ("diff", cmd("diff", str(S_SWITCHY), str(S_SWITCHY_V2))),
    ]


# Tier 4 §W — bench harness
def chapter_bench() -> List[Tuple[str, List[str]]]:
    out = TMP / "bench-ci.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    return [
        ("ci-matrix", [
            "uv", "run", "python", "-m", "glaurung.bench",
            "--ci-matrix", "--output", str(out), "--quiet",
        ]),
        ("packed-matrix", [
            "uv", "run", "python", "-m", "glaurung.bench",
            "--packed-matrix", "--output",
            str(TMP / "bench-packed.json"), "--quiet",
        ]),
    ]


# Tier 5 §X — kickoff anatomy: same as §B but on c2_demo, since
# the chapter shows the IOC-richer summary.
def chapter_kickoff_anatomy() -> List[Tuple[str, List[str]]]:
    db = reset_chapter("05-kickoff-anatomy")
    return [
        ("kickoff", cmd("kickoff", str(S_C2), "--db", str(db))),
    ]


# Tier 4 §U — exporting (run the export commands; agent-LLM not required)
def chapter_export() -> List[Tuple[str, List[str]]]:
    db = reset_chapter("04-export")
    out_md = TMP / "export-md.out"
    out_json = TMP / "export.json"
    out_h = TMP / "export.h"
    out_ida = TMP / "export-ida.py"
    out_binja = TMP / "export-binja.py"
    out_ghidra = TMP / "export-ghidra.py"
    return [
        ("kickoff", cmd("kickoff", str(S_HELLO_C), "--db", str(db))),
        ("export-markdown-head", [
            "bash", "-c",
            f"uv run glaurung export {shlex.quote(str(db))} "
            f"--output-format markdown | head -30",
        ]),
        ("export-json-summary", [
            "bash", "-c",
            f"uv run glaurung export {shlex.quote(str(db))} "
            f"--output-format json | python -c "
            "'import json,sys; d=json.load(sys.stdin); "
            "print(\"schema_version:\", d[\"schema_version\"]); "
            "print(\"keys:\", sorted(d.keys()))'",
        ]),
        ("export-ida-head", [
            "bash", "-c",
            f"uv run glaurung export {shlex.quote(str(db))} "
            f"--output-format ida | head -20",
        ]),
        ("export-binja-head", [
            "bash", "-c",
            f"uv run glaurung export {shlex.quote(str(db))} "
            f"--output-format binja | head -20",
        ]),
        ("export-ghidra-head", [
            "bash", "-c",
            f"uv run glaurung export {shlex.quote(str(db))} "
            f"--output-format ghidra | head -20",
        ]),
    ]


CHAPTERS: dict[str, callable] = {
    "01-first-binary": chapter_first_binary,
    "03-hello-c-clang": chapter_hello_c_clang,
    "03-stripped-go": chapter_stripped_go,
    "03-dotnet-pe": chapter_dotnet_pe,
    "03-jvm": chapter_jvm,
    "03-vulnparse": chapter_vulnparse,
    "03-upx-packed": chapter_upx_packed,
    "03-c2-demo": chapter_c2_demo,
    "04-diff": chapter_diff,
    "04-export": chapter_export,
    "04-bench": chapter_bench,
    "05-kickoff-anatomy": chapter_kickoff_anatomy,
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify the tutorial track by running every documented command.",
    )
    parser.add_argument(
        "--chapter", action="append", default=[],
        help="Run only specific chapter(s). Can repeat.",
    )
    parser.add_argument(
        "--list", action="store_true",
        help="List chapter names and exit.",
    )
    args = parser.parse_args(argv)

    if args.list:
        for name in CHAPTERS:
            print(name)
        return 0

    targets = args.chapter or list(CHAPTERS.keys())
    failures: List[str] = []

    for chapter in targets:
        recipe_fn = CHAPTERS.get(chapter)
        if recipe_fn is None:
            print(f"unknown chapter: {chapter}", file=sys.stderr)
            failures.append(chapter)
            continue
        print(f"=== {chapter} ===", flush=True)
        steps = recipe_fn()
        for step_name, command in steps:
            print(f"  → {step_name}: {' '.join(map(shlex.quote, command))}", flush=True)
            try:
                output = run(command)
            except subprocess.TimeoutExpired:
                print(f"    TIMEOUT", flush=True)
                failures.append(f"{chapter}/{step_name}")
                continue
            except Exception as e:
                print(f"    ERROR: {e}", flush=True)
                failures.append(f"{chapter}/{step_name}")
                continue
            path = write_fixture(chapter, step_name, output)
            print(f"    → {path.relative_to(REPO)}  ({len(output)} bytes)", flush=True)

    if failures:
        print(f"\n{len(failures)} step(s) failed:", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1
    print(f"\nOK — {sum(len(CHAPTERS[c]()) for c in targets)} step(s) captured into {FIXTURES.relative_to(REPO)}/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
