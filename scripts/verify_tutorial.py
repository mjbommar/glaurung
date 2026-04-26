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
    # (Removed an over-eager bench-latency regex that also stripped
    # the b-size column in `glaurung diff` markdown.)
    # Glaurung HEAD commit id is volatile.
    text = re.sub(r"glaurung HEAD: `[0-9a-f]{12}`", "glaurung HEAD: `<sha>`", text)
    # `at NN ms` from kickoff timing footers.
    text = re.sub(r"\(at (\d+) ms\)", "(at N ms)", text)
    # Bookmark / journal "when" column: 2026-04-26 09:11:37 → TIMESTAMP
    text = re.sub(
        r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}",
        "YYYY-MM-DD HH:MM:SS",
        text,
    )
    return text


def run(cmd: List[str], *, env_extra: dict | None = None,
        stdin_lines: list[str] | None = None) -> str:
    """Run a command, return stdout with stderr merged. Times out at 5min.

    If `stdin_lines` is provided, each entry is piped to the process's
    stdin in order (with a trailing newline appended per entry). Used
    to drive the REPL non-interactively for transcript capture.
    """
    env = os.environ.copy()
    if env_extra:
        env.update(env_extra)
    stdin_text = None
    if stdin_lines is not None:
        stdin_text = "\n".join(stdin_lines) + "\n"
    res = subprocess.run(
        cmd,
        cwd=str(REPO),
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
        input=stdin_text,
    )
    out = res.stdout + (res.stderr if res.stderr else "")
    return out


def run_repl_session(
    binary: Path, db: Path, lines: list[str],
    *, decorate: bool = True,
) -> str:
    """Drive `glaurung repl <binary> --db <db>` with the supplied
    keystroke list. Captures stdout (including prompts) and synthesises
    a fake `>>>` prefix for each input line so the transcript is
    readable. The REPL itself emits `<addr>>` prompts that are
    interleaved with output; we keep the raw stdout but prepend a
    rendered "input echo" block so the captured fixture shows what
    the user typed AND what the REPL printed.
    """
    argv = ["uv", "run", "glaurung", "repl", str(binary), "--db", str(db)]
    out = run(argv, stdin_lines=lines)
    if not decorate:
        return out
    # Prepend the input transcript so readers know what was typed.
    header_lines = ["─── input keystrokes (piped to stdin) ───"]
    for line in lines:
        header_lines.append(f">>> {line}" if line else "")
    header_lines.append("─── REPL stdout ───")
    return "\n".join(header_lines) + "\n" + out


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


# Tier 1 §A — install (the verifiable parts: --version, --help, kickoff)
def chapter_install() -> List[Tuple[str, List[str]]]:
    return [
        ("version", cmd("--version")),
        ("help-head", [
            "bash", "-c",
            "uv run glaurung --help 2>&1 | head -3",
        ]),
        ("kickoff-smoketest", cmd("kickoff", str(S_HELLO_C))),
    ]


# Tier 1 §C — cli-tour: every CLI subcommand at least once
def chapter_cli_tour() -> List[Tuple[str, List[str]]]:
    db = reset_chapter("01-cli-tour")
    bin_path = S_HELLO_C
    return [
        ("triage", cmd("triage", str(bin_path))),
        ("strings-head", [
            "bash", "-c",
            f"uv run glaurung strings {shlex.quote(str(bin_path))} | head -10",
        ]),
        ("disasm-head", cmd(
            "disasm", str(bin_path),
            "--addr", "0x1150", "--max-instructions", "5",
        )),
        ("cfg-head", [
            "bash", "-c",
            f"uv run glaurung cfg {shlex.quote(str(bin_path))} 2>&1 | head -10",
        ]),
        ("kickoff", cmd("kickoff", str(bin_path), "--db", str(db))),
        ("find-main", cmd("find", str(db), "main", "--kind", "function")),
        ("view-main", cmd(
            "view", str(db), "0x1150",
            "--binary", str(bin_path),
            "--hex-window", "16",
            "--pseudo-lines", "5",
        )),
        ("xrefs-print-sum", cmd(
            "xrefs", str(db), "0x11d0",
            "--binary", str(bin_path),
            "--direction", "to",
        )),
        ("strings-xrefs-head", cmd(
            "strings-xrefs", str(db), "--binary", str(bin_path),
            "--limit", "5",
        )),
        ("frame-list", cmd(
            "frame", str(db), "0x1150", "list",
            "--binary", str(bin_path),
        )),
        ("undo-list", cmd("undo", str(db), "--list")),
    ]


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
    out_ci = TMP / "bench-ci.json"
    out_packed = TMP / "bench-packed.json"
    out_ci.parent.mkdir(parents=True, exist_ok=True)
    return [
        ("ci-matrix", [
            "uv", "run", "python", "-m", "glaurung.bench",
            "--ci-matrix", "--output", str(out_ci), "--quiet",
        ]),
        ("ci-matrix-md-head", [
            "bash", "-c",
            f"head -22 {shlex.quote(str(out_ci.with_suffix('.md')))}",
        ]),
        ("packed-matrix", [
            "uv", "run", "python", "-m", "glaurung.bench",
            "--packed-matrix", "--output", str(out_packed), "--quiet",
        ]),
        ("packed-matrix-md-head", [
            "bash", "-c",
            f"head -22 {shlex.quote(str(out_packed.with_suffix('.md')))}",
        ]),
    ]


# Tier 5 §X — kickoff anatomy: same as §B but on c2_demo, since
# the chapter shows the IOC-richer summary.
def chapter_kickoff_anatomy() -> List[Tuple[str, List[str]]]:
    db = reset_chapter("05-kickoff-anatomy")
    return [
        ("kickoff", cmd("kickoff", str(S_C2), "--db", str(db))),
        ("evidence-log-head", [
            "sqlite3", str(db),
            "SELECT cite_id, tool, summary FROM evidence_log "
            "ORDER BY cite_id LIMIT 10;",
        ]),
        ("evidence-log-schema", [
            "sqlite3", str(db), ".schema evidence_log",
        ]),
        ("evidence-log-args-output", [
            "sqlite3", str(db),
            "SELECT cite_id, tool, summary, va_start, va_end, "
            "substr(args_json, 1, 80) AS args_head, "
            "substr(output_json, 1, 80) AS output_head "
            "FROM evidence_log ORDER BY cite_id LIMIT 3;",
        ]),
    ]


# REPL-driven recipes. Each step is encoded as a special bash command
# that pipes the keystrokes via printf into `glaurung repl`. The fixture
# captures the resulting stdout (including REPL prompts/output) — the
# script header records exactly which keystrokes were sent.
#
# The harness handles these uniformly with run() since they're plain
# subprocess calls. The bash wrapper makes the invocation visible in
# the captured `step.out` so the docs can show what was piped.
def _repl_recipe(db: Path, lines: list[str]) -> List[str]:
    """Build a bash invocation that pipes `lines` into glaurung repl.
    The captured fixture starts with a visible `# stdin:` block so
    the reader sees what was typed."""
    keystrokes = "\n".join(lines)
    # Emit a header showing the keystrokes, then run the REPL with the
    # keystrokes piped in. Use printf so newlines are interpreted.
    return [
        "bash", "-c",
        f"printf '%s\\n' '─── stdin (keystrokes piped to glaurung repl) ───';\n"
        f"printf '%s\\n' {shlex.quote(keystrokes)};\n"
        f"printf '%s\\n' '─── glaurung repl stdout ───';\n"
        f"printf '%s\\n' {shlex.quote(keystrokes)} | "
        f"uv run glaurung repl <BINARY> --db <DB>"
    ]


# Tier 1 §D — REPL tour
def chapter_repl_tour() -> List[Tuple[str, List[str]]]:
    db = reset_chapter("01-repl-tour")
    # Pre-populate the DB with kickoff so the REPL has something to work
    # with (functions discovered, callgraph indexed).
    bin_path = S_HELLO_C
    keystrokes_help = ["help", "q"]
    keystrokes_navigate = [
        "g 0x1150", "b", "f", "q",
    ]
    keystrokes_inspect = [
        "g 0x1150",
        "x",
        "q",
    ]
    keystrokes_decomp = [
        "g 0x11d0",
        "d",
        "q",
    ]
    keystrokes_locals = [
        "g 0x1150",
        "l",
        "q",
    ]
    keystrokes_functions = [
        "functions 6",
        "q",
    ]
    keystrokes_annotate = [
        "g 0x1200",
        "n demo_static",
        "c 0x1200 called once from main; flags-only side effect",
        "save",
        "q",
    ]
    keystrokes_locals_rename = [
        "g 0x1150",
        "locals rename -0x18 argc_copy",
        "save",
        "q",
    ]
    keystrokes_proto = [
        "proto printf",
        "q",
    ]
    return [
        ("kickoff", cmd("kickoff", str(bin_path), "--db", str(db))),
        ("repl-help", _build_repl_invocation(bin_path, db, keystrokes_help)),
        ("repl-navigate", _build_repl_invocation(bin_path, db, keystrokes_navigate)),
        ("repl-inspect", _build_repl_invocation(bin_path, db, keystrokes_inspect)),
        ("repl-decomp", _build_repl_invocation(bin_path, db, keystrokes_decomp)),
        ("repl-locals", _build_repl_invocation(bin_path, db, keystrokes_locals)),
        ("repl-functions", _build_repl_invocation(bin_path, db, keystrokes_functions)),
        ("repl-annotate", _build_repl_invocation(bin_path, db, keystrokes_annotate)),
        ("repl-locals-rename", _build_repl_invocation(bin_path, db, keystrokes_locals_rename)),
        ("repl-proto", _build_repl_invocation(bin_path, db, keystrokes_proto)),
        ("undo-list-after", cmd("undo", str(db), "--list")),
    ]


def _build_repl_invocation(binary: Path, db: Path, lines: list[str]) -> List[str]:
    """Return a bash invocation that pipes keystrokes into the REPL,
    prepending a visible header so the captured fixture shows what
    was typed. The output is ordered:
      ─── stdin ───
      <keystrokes verbatim>
      ─── glaurung repl stdout ───
      <REPL output>
    """
    keystrokes = "\n".join(lines)
    return [
        "bash", "-c",
        f"echo '─── stdin (keystrokes piped to glaurung repl) ───';\n"
        f"printf '%s\\n' {shlex.quote(keystrokes)};\n"
        f"echo '─── glaurung repl stdout ───';\n"
        f"printf '%s\\n' {shlex.quote(keystrokes)} | "
        f"uv run glaurung repl {shlex.quote(str(binary))} "
        f"--db {shlex.quote(str(db))} 2>&1"
    ]


# Tier 2 §E — naming-and-types: REPL n / y / c on c2_demo
def chapter_naming_and_types() -> List[Tuple[str, List[str]]]:
    db = reset_chapter("02-naming-and-types")
    bin_path = S_C2
    return [
        ("kickoff", cmd("kickoff", str(bin_path), "--db", str(db))),
        ("repl-functions", _build_repl_invocation(bin_path, db, [
            "functions",
            "q",
        ])),
        ("repl-rename", _build_repl_invocation(bin_path, db, [
            "g 0x1160",
            "n c2_main",
            "save",
            "q",
        ])),
        ("repl-comment", _build_repl_invocation(bin_path, db, [
            "c 0x1160 entry: stash argc/argv into locals",
            "save",
            "q",
        ])),
        ("repl-label-set", _build_repl_invocation(bin_path, db, [
            "label set 0x4040 g_c2_endpoints char *",
            "save",
            "q",
        ])),
        ("repl-retype", _build_repl_invocation(bin_path, db, [
            "y 0x4040 char[64]",
            "save",
            "q",
        ])),
        ("repl-locals-rename", _build_repl_invocation(bin_path, db, [
            "g 0x1160",
            "l",
            "locals rename -0x1b0 url_buffer",
            "save",
            "q",
        ])),
        ("repl-decomp-after", _build_repl_invocation(bin_path, db, [
            "g 0x1160",
            "d",
            "q",
        ])),
        ("find-renamed", cmd(
            "find", str(db), "c2_main", "--kind", "function",
        )),
        ("find-label", cmd(
            "find", str(db), "g_c2_endpoints", "--kind", "data",
        )),
        ("find-comment", cmd(
            "find", str(db), "stash argc", "--kind", "comment",
        )),
        ("undo-list", cmd("undo", str(db), "--list")),
    ]


# Tier 2 §F — cross-references: every form of xrefs.
# Uses hello-c-clang because its kickoff populates the xref index;
# c2_demo's kickoff does not register PLT-call xrefs.
def chapter_xrefs_demo() -> List[Tuple[str, List[str]]]:
    db = reset_chapter("02-cross-references")
    bin_path = S_HELLO_C
    return [
        ("kickoff", cmd("kickoff", str(bin_path), "--db", str(db))),
        ("find-print-sum", cmd(
            "find", str(db), "print_sum", "--kind", "function",
        )),
        ("xrefs-to-print-sum", cmd(
            "xrefs", str(db), "0x11d0",
            "--binary", str(bin_path),
            "--direction", "to",
        )),
        ("xrefs-from-main", cmd(
            "xrefs", str(db), "0x1150",
            "--binary", str(bin_path),
            "--direction", "from",
        )),
        ("xrefs-from-main-call", cmd(
            "xrefs", str(db), "0x1150",
            "--binary", str(bin_path),
            "--direction", "from",
            "--kind", "call",
        )),
        ("xrefs-both", cmd(
            "xrefs", str(db), "0x11d0",
            "--binary", str(bin_path),
            "--direction", "both",
        )),
        ("xrefs-json", cmd(
            "xrefs", str(db), "0x11d0",
            "--binary", str(bin_path),
            "--direction", "to",
            "--format", "json",
        )),
        ("repl-x", _build_repl_invocation(bin_path, db, [
            "g 0x11d0",
            "x",
            "q",
        ])),
    ]


# Tier 2 §G — stack-frames: list / discover / rename / retype
def chapter_stack_frames() -> List[Tuple[str, List[str]]]:
    db = reset_chapter("02-stack-frames")
    bin_path = S_C2
    return [
        ("kickoff", cmd("kickoff", str(bin_path), "--db", str(db))),
        ("frame-list-before", cmd(
            "frame", str(db), "0x1160", "list",
            "--binary", str(bin_path),
        )),
        ("frame-discover", cmd(
            "frame", str(db), "0x1160", "discover",
            "--binary", str(bin_path),
        )),
        ("frame-list-after", cmd(
            "frame", str(db), "0x1160", "list",
            "--binary", str(bin_path),
        )),
        ("frame-rename", cmd(
            "frame", str(db), "0x1160", "rename",
            "-0x1b0", "url_buffer",
            "--binary", str(bin_path),
        )),
        ("frame-retype", cmd(
            "frame", str(db), "0x1160", "retype",
            "-0x1b0", "char[256]",
            "--binary", str(bin_path),
        )),
        ("frame-list-final", cmd(
            "frame", str(db), "0x1160", "list",
            "--binary", str(bin_path),
        )),
        ("frame-list-json", cmd(
            "frame", str(db), "0x1160", "list",
            "--binary", str(bin_path),
            "--format", "json",
        )),
    ]


# Tier 2 §H — strings-and-data: strings-xrefs + label
def chapter_strings_and_data() -> List[Tuple[str, List[str]]]:
    db = reset_chapter("02-strings-and-data")
    bin_path = S_C2
    return [
        ("kickoff", cmd("kickoff", str(bin_path), "--db", str(db))),
        ("strings-xrefs-default", cmd(
            "strings-xrefs", str(db),
            "--binary", str(bin_path),
            "--limit", "10",
        )),
        ("strings-xrefs-min-len", cmd(
            "strings-xrefs", str(db),
            "--binary", str(bin_path),
            "--min-len", "12",
            "--limit", "10",
        )),
        ("strings-xrefs-used-only", cmd(
            "strings-xrefs", str(db),
            "--binary", str(bin_path),
            "--used-only",
            "--limit", "10",
        )),
        ("strings-xrefs-json", cmd(
            "strings-xrefs", str(db),
            "--binary", str(bin_path),
            "--min-len", "12",
            "--limit", "5",
            "--format", "json",
        )),
        ("repl-label", _build_repl_invocation(bin_path, db, [
            "label set 0x4040 g_c2_endpoints char *",
            "save",
            "q",
        ])),
        ("repl-retype", _build_repl_invocation(bin_path, db, [
            "y 0x4040 char[64]",
            "save",
            "q",
        ])),
        ("repl-label-list", _build_repl_invocation(bin_path, db, [
            "label",
            "q",
        ])),
        ("find-label", cmd(
            "find", str(db), "g_c2_endpoints", "--kind", "data",
        )),
        ("find-data-prefix", cmd(
            "find", str(db), "g_", "--kind", "data",
        )),
    ]


# Tier 2 §I — searching: every find query shape.
# Uses hello-c-clang because its kickoff registers PLT entries
# (printf, strlen) — c2_demo's kickoff doesn't.
def chapter_searching() -> List[Tuple[str, List[str]]]:
    db = reset_chapter("02-searching")
    bin_path = S_HELLO_C
    return [
        ("kickoff", cmd("kickoff", str(bin_path), "--db", str(db))),
        ("find-substring", cmd("find", str(db), "main")),
        ("find-kind-function", cmd(
            "find", str(db), "main", "--kind", "function",
        )),
        ("find-all-functions", cmd(
            "find", str(db), "", "--kind", "function",
        )),
        ("find-regex-funcs", cmd(
            "find", str(db), r"^_",
            "--regex", "--kind", "function",
        )),
        ("find-case-sensitive", cmd(
            "find", str(db), "MAIN", "--kind", "function",
        )),
        ("find-case-sensitive-flag", cmd(
            "find", str(db), "MAIN",
            "--kind", "function",
            "--case-sensitive",
        )),
        ("find-strings", cmd(
            "find", str(db), "Hello", "--kind", "string",
        )),
        ("find-disasm", cmd(
            "find", str(db), r"^push",
            "--regex", "--kind", "disasm",
        )),
        ("find-json", cmd(
            "find", str(db), "main",
            "--kind", "function",
            "--format", "json",
        )),
    ]


# Tier 2 §J — bookmarks-and-journal
def chapter_bookmarks() -> List[Tuple[str, List[str]]]:
    db = reset_chapter("02-bookmarks")
    bin_path = S_C2
    return [
        ("kickoff", cmd("kickoff", str(bin_path), "--db", str(db))),
        ("bookmark-add-1", cmd(
            "bookmark", str(db), "add", "0x1140",
            "weird branch — investigate",
            "--binary", str(bin_path),
        )),
        ("bookmark-add-2", cmd(
            "bookmark", str(db), "add", "0x1160",
            "main entry",
            "--binary", str(bin_path),
        )),
        ("bookmark-add-second-at-1140", cmd(
            "bookmark", str(db), "add", "0x1140",
            "actually it's a parser",
            "--binary", str(bin_path),
        )),
        ("bookmark-list", cmd(
            "bookmark", str(db), "list",
            "--binary", str(bin_path),
        )),
        ("bookmark-list-filter", cmd(
            "bookmark", str(db), "list", "--va", "0x1140",
            "--binary", str(bin_path),
        )),
        ("journal-add", cmd(
            "journal", str(db), "add",
            "today: traced the C2 protocol",
            "--binary", str(bin_path),
        )),
        ("journal-list", cmd(
            "journal", str(db), "list",
            "--binary", str(bin_path),
        )),
        ("bookmark-delete", cmd(
            "bookmark", str(db), "delete", "1",
            "--binary", str(bin_path),
        )),
        ("bookmark-list-after-delete", cmd(
            "bookmark", str(db), "list",
            "--binary", str(bin_path),
        )),
        ("bookmark-list-json", cmd(
            "bookmark", str(db), "list",
            "--binary", str(bin_path),
            "--format", "json",
        )),
    ]


# Tier 2 §K — undo-redo
def chapter_undo_redo() -> List[Tuple[str, List[str]]]:
    db = reset_chapter("02-undo-redo")
    bin_path = S_C2
    return [
        ("kickoff", cmd("kickoff", str(bin_path), "--db", str(db))),
        ("repl-make-changes", _build_repl_invocation(bin_path, db, [
            "g 0x1160",
            "n c2_main",
            "c 0x1160 entry: stash argc/argv into locals",
            "label set 0x4040 g_c2_endpoints char *",
            "save",
            "q",
        ])),
        ("undo-list-before", cmd("undo", str(db), "--list")),
        ("undo-once", cmd("undo", str(db))),
        ("undo-list-after", cmd("undo", str(db), "--list")),
        ("redo-once", cmd("redo", str(db))),
        ("undo-list-after-redo", cmd("undo", str(db), "--list")),
        ("undo-multi", cmd("undo", str(db), "-n", "3")),
        ("undo-list-final", cmd("undo", str(db), "--list")),
    ]


# Tier 2 §L — patch-and-verify
def chapter_patch() -> List[Tuple[str, List[str]]]:
    bin_in = S_HELLO_C
    return [
        ("disasm-target", cmd(
            "disasm", str(bin_in), "--addr", "0x11e0",
            "--max-instructions", "4",
        )),
        ("patch-nop", cmd(
            "patch", str(bin_in), str(TMP / "patched-nop.bin"),
            "--va", "0x11e0", "--nop", "--verify", "--force",
        )),
        ("patch-bytes", cmd(
            "patch", str(bin_in), str(TMP / "patched-bytes.bin"),
            "--va", "0x11e5", "--bytes", "90 90", "--verify", "--force",
        )),
        ("patch-json", cmd(
            "patch", str(bin_in), str(TMP / "patched-json.bin"),
            "--va", "0x11e0", "--nop", "--verify", "--force",
            "--format", "json",
        )),
    ]


# Tier 4 §V — typed-locals: show how propagation lights up libc-call slots
def chapter_typed_locals() -> List[Tuple[str, List[str]]]:
    db = reset_chapter("04-typed-locals")
    bin_path = S_C2
    return [
        ("kickoff", cmd("kickoff", str(bin_path), "--db", str(db))),
        ("view-typed-locals", cmd(
            "view", str(db), "0x1160",
            "--binary", str(bin_path),
            "--pane", "pseudo",
            "--pseudo-lines", "8",
        )),
        ("find-stack-vars-propagated", [
            "bash", "-c",
            f"uv run glaurung find {shlex.quote(str(db))} '' --kind stack_var "
            f"| grep 'set_by=propagated' | head",
        ]),
        ("repl-propagate", _build_repl_invocation(bin_path, db, [
            "g 0x1160",
            "propagate",
            "save",
            "q",
        ])),
        ("find-types-head", [
            "bash", "-c",
            f"uv run glaurung find {shlex.quote(str(db))} '' --kind type | head -10",
        ]),
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
    "01-install": chapter_install,
    "01-cli-tour": chapter_cli_tour,
    "01-first-binary": chapter_first_binary,
    "01-repl-tour": chapter_repl_tour,
    "02-naming-and-types": chapter_naming_and_types,
    "02-cross-references": chapter_xrefs_demo,
    "02-stack-frames": chapter_stack_frames,
    "02-strings-and-data": chapter_strings_and_data,
    "02-searching": chapter_searching,
    "02-bookmarks": chapter_bookmarks,
    "02-undo-redo": chapter_undo_redo,
    "02-patch": chapter_patch,
    "03-hello-c-clang": chapter_hello_c_clang,
    "03-stripped-go": chapter_stripped_go,
    "03-dotnet-pe": chapter_dotnet_pe,
    "03-jvm": chapter_jvm,
    "03-vulnparse": chapter_vulnparse,
    "03-upx-packed": chapter_upx_packed,
    "03-c2-demo": chapter_c2_demo,
    "04-diff": chapter_diff,
    "04-export": chapter_export,
    "04-typed-locals": chapter_typed_locals,
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
    captured = 0

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
            captured += 1

    if failures:
        print(f"\n{len(failures)} step(s) failed:", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1
    print(f"\nOK — {captured} step(s) captured into {FIXTURES.relative_to(REPO)}/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
