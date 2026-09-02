"""Verify the tutorial track against shipped CLI surfaces.

For every encoded chapter in docs/tutorial/, runs the documented commands
end-to-end against samples/binaries/ and compares or captures the real output
in docs/tutorial/_fixtures/<chapter>/<step>.out.

Usage:
    uv run python scripts/verify_tutorial.py            # check only
    uv run python scripts/verify_tutorial.py --check    # check only
    uv run python scripts/verify_tutorial.py --capture  # refresh fixtures

Each chapter is encoded as a list of (label, command) pairs. The
harness:

  1. Runs each command, captures stdout (stderr merged), strips a
     few sources of nondeterminism (timestamps, paths under /tmp,
     elapsed_ms latencies).
  2. In check mode, compares stable output with the checked-in fixture
     without modifying it and fails when the command or output drifts.
  3. In explicit capture mode, refreshes the stable .out file that the
     Markdown can link to or quote.

Convention: every chapter has exactly one `.glaurung` file under
`$TMPDIR/tutorial-fixtures/<chapter>.glaurung` — the harness creates a
fresh one per chapter so steps don't bleed state.
"""

from __future__ import annotations

import argparse
import difflib
import os
import re
import shlex
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
FIXTURES = REPO / "docs" / "tutorial" / "_fixtures"


def _scratch_root() -> Path:
    """Where the harness may create per-chapter databases and patched binaries.

    Nothing in this project may write to `/tmp`: it is a shared, per-user
    quota'd tmpfs here, and exhausting it has produced fake fixture drift and
    pytest internal errors rather than a disk-full message. `TMPDIR` is the
    documented escape hatch; the fallback matches the cache directory the
    project's own instructions tell contributors to export.
    """
    env = os.environ.get("TMPDIR")
    root = Path(env) if env else Path.home() / ".cache" / "glaurung" / "tmp"
    return root / "tutorial-fixtures"


TMP = _scratch_root()
TMP.mkdir(parents=True, exist_ok=True)

#: The path the checked-in fixtures were captured under. Scratch paths appear
#: verbatim in captured output (`db=…/03-c2-demo.glaurung`), so the real
#: scratch directory is normalized back to this token and the evidence files
#: stay comparable across machines and across the `TMPDIR` fix above. It is a
#: display token, not a location the harness writes to.
TMP_TOKEN = "/tmp/tutorial-fixtures"


@dataclass(frozen=True)
class CommandResult:
    """Captured output and exit status from one documented command."""

    returncode: int
    output: str


# ---------------------------------------------------------------------------
# Sample binaries used across chapters — keep these as constants so the
# harness can fail fast if a sample disappears from the corpus.
# ---------------------------------------------------------------------------

S_HELLO = (
    REPO
    / "samples/binaries/platforms/linux/amd64/export/native/clang/debug/hello-clang-debug"
)
S_HELLO_C = (
    REPO
    / "samples/binaries/platforms/linux/amd64/export/native/clang/debug/hello-c-clang-debug"
)
S_GO = REPO / "samples/binaries/platforms/linux/amd64/export/go/hello-go"
S_DOTNET = (
    REPO / "samples/binaries/platforms/linux/amd64/export/dotnet/mono/Hello-mono.exe"
)
S_JAVA_CLASS = (
    REPO / "samples/binaries/platforms/linux/amd64/export/java/HelloWorld.class"
)
S_JAVA_JAR = REPO / "samples/binaries/platforms/linux/amd64/export/java/HelloWorld.jar"
S_LUA = REPO / "samples/binaries/platforms/linux/amd64/export/lua/hello-lua5.3.luac"
S_VULN = REPO / "samples/binaries/platforms/linux/amd64/synthetic/vulnparse-c-gcc-O0"
S_PACKED = REPO / "samples/packed/hello-go.upx9"
S_C2 = (
    REPO
    / "samples/binaries/platforms/linux/amd64/export/native/clang/O0/c2_demo-clang-O0"
)
S_SWITCHY = REPO / "samples/binaries/platforms/linux/amd64/synthetic/switchy-c-gcc-O2"
S_SWITCHY_V2 = (
    REPO / "samples/binaries/platforms/linux/amd64/synthetic/switchy-c-gcc-O2-v2"
)

EXPECTED_RETURN_CODES: dict[tuple[str, str], set[int]] = {
    # Plain-text detect-packer uses exit 1 as a positive packed verdict. JSON
    # modes return zero, but this tutorial intentionally verifies the human
    # output and its documented shell signal.
    ("03-upx-packed", "detect-packer"): {1},
    # Plain-text diff uses exit 1 when differences are present. This recipe
    # specifically proves the two checked-in variants remain different.
    ("04-diff", "diff"): {1},
}


def expected_return_codes(chapter: str, step: str) -> set[int]:
    """Return the exact successful process statuses for one tutorial step."""
    return EXPECTED_RETURN_CODES.get((chapter, step), {0})


def stable(text: str) -> str:
    """Strip nondeterministic noise from captured output."""
    # Keep fixture diffs clean when column-oriented tools pad their output.
    text = re.sub(r"[ \t]+(?=\r?$)", "", text, flags=re.MULTILINE)
    # Fixtures must compare across clones and worktrees. Keep the repository
    # relative suffix while removing the machine-specific checkout prefix.
    text = text.replace(str(REPO), "<repo>")
    # The scratch directory is `TMPDIR`-derived and therefore machine-specific;
    # fixtures record it under the token the corpus was captured with.
    text = text.replace(str(TMP), TMP_TOKEN)
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
    # Bookmark JSON stores Unix seconds rather than a rendered timestamp.
    text = re.sub(
        r'("created_at"\s*:\s*)\d+',
        r'\1"TIMESTAMP"',
        text,
    )
    # IOC counts originate from map-backed aggregation and can render in a
    # different order between otherwise identical runs. Canonicalize only the
    # direct bullet block beneath this heading; example rows below it retain
    # their analyzer-defined order.
    lines = text.splitlines(keepends=True)
    for index, line in enumerate(lines):
        if line.rstrip("\r\n") != "## IOCs (from string scan)":
            continue
        start = index + 1
        while start < len(lines) and not lines[start].strip():
            start += 1
        end = start
        while end < len(lines) and lines[end].startswith("- **"):
            end += 1
        lines[start:end] = sorted(lines[start:end])

    # The benchmark Markdown table ends in a wall-clock `ms` column. Normalize
    # only rows beneath that exact header so structural sizes in other tables
    # remain meaningful evidence.
    in_benchmark_table = False
    for index, line in enumerate(lines):
        if line.rstrip("\r\n") == (
            "| binary | funcs | named | chunks>1 | cold orphans | decompiled | ms |"
        ):
            in_benchmark_table = True
            continue
        if not in_benchmark_table:
            continue
        if line.startswith("|---"):
            continue
        if not line.startswith("| `"):
            in_benchmark_table = False
            continue
        lines[index] = re.sub(r"\| \d+ \|(\r?\n)?$", r"| N |\1", line)
    return "".join(lines)


def run(
    cmd: list[str],
    *,
    env_extra: dict | None = None,
    stdin_lines: list[str] | None = None,
) -> CommandResult:
    """Run a command and retain merged output plus its exit status.

    If `stdin_lines` is provided, each entry is piped to the process's
    stdin in order (with a trailing newline appended per entry). Used
    to drive the REPL non-interactively for transcript capture.
    """
    env = os.environ.copy()
    # Fixture capture is a byte comparison, so the child must not colourise.
    # Python 3.14's argparse emits ANSI escapes when FORCE_COLOR is set, and
    # it is set by several terminals and CI runners — which made every
    # `--help` transcript in the tutorial drift for reasons that have nothing
    # to do with the tutorial. Neutralise it here rather than in each caller,
    # but do it before `env_extra` so a step can still opt back in.
    env.pop("FORCE_COLOR", None)
    env.pop("CLICOLOR_FORCE", None)
    env["NO_COLOR"] = "1"
    env["PYTHON_COLORS"] = "0"
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
        check=False,
    )
    output = res.stdout + (res.stderr if res.stderr else "")
    return CommandResult(returncode=res.returncode, output=output)


def run_repl_session(
    binary: Path,
    db: Path,
    lines: list[str],
    *,
    decorate: bool = True,
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
    result = run(argv, stdin_lines=lines)
    if not decorate:
        return result.output
    # Prepend the input transcript so readers know what was typed.
    header_lines = ["─── input keystrokes (piped to stdin) ───"]
    for line in lines:
        header_lines.append(f">>> {line}" if line else "")
    header_lines.append("─── REPL stdout ───")
    return "\n".join(header_lines) + "\n" + result.output


def write_fixture(chapter: str, step: str, output: str) -> Path:
    chapter_dir = FIXTURES / chapter
    chapter_dir.mkdir(parents=True, exist_ok=True)
    path = chapter_dir / f"{step}.out"
    path.write_text(stable(output))
    return path


def fixture_path(chapter: str, step: str) -> Path:
    """Return the checked-in evidence path without creating or writing it."""
    return FIXTURES / chapter / f"{step}.out"


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


def cmd(*args: str) -> list[str]:
    """Build a `uv run glaurung` argv with the given subcommand args."""
    return ["uv", "run", "glaurung", *args]


# Tier 1 §A — install (the verifiable parts: --version, --help, kickoff)
def chapter_install() -> list[tuple[str, list[str]]]:
    return [
        ("version", cmd("--version")),
        (
            "help-head",
            [
                "bash",
                "-c",
                "uv run glaurung --help 2>&1 | head -3",
            ],
        ),
        ("kickoff-smoketest", cmd("kickoff", str(S_HELLO_C))),
    ]


# Tier 1 §C — cli-tour: every CLI subcommand at least once
def chapter_cli_tour() -> list[tuple[str, list[str]]]:
    db = reset_chapter("01-cli-tour")
    bin_path = S_HELLO_C
    return [
        ("triage", cmd("triage", str(bin_path))),
        (
            "strings-head",
            [
                "bash",
                "-c",
                f"uv run glaurung strings {shlex.quote(str(bin_path))} | head -10",
            ],
        ),
        (
            "disasm-head",
            cmd(
                "disasm",
                str(bin_path),
                "--addr",
                "0x1150",
                "--max-instructions",
                "5",
            ),
        ),
        (
            "cfg-head",
            [
                "bash",
                "-c",
                f"uv run glaurung cfg {shlex.quote(str(bin_path))} 2>&1 | head -10",
            ],
        ),
        ("kickoff", cmd("kickoff", str(bin_path), "--db", str(db))),
        ("find-main", cmd("find", str(db), "main", "--kind", "function")),
        (
            "view-main",
            cmd(
                "view",
                str(db),
                "0x1150",
                "--binary",
                str(bin_path),
                "--hex-window",
                "16",
                "--pseudo-lines",
                "5",
            ),
        ),
        (
            "xrefs-print-sum",
            cmd(
                "xrefs",
                str(db),
                "0x11d0",
                "--binary",
                str(bin_path),
                "--direction",
                "to",
            ),
        ),
        (
            "strings-xrefs-head",
            cmd(
                "strings-xrefs",
                str(db),
                "--binary",
                str(bin_path),
                "--limit",
                "5",
            ),
        ),
        (
            "frame-list",
            cmd(
                "frame",
                str(db),
                "0x1150",
                "list",
                "--binary",
                str(bin_path),
            ),
        ),
        ("undo-list", cmd("undo", str(db), "--list")),
    ]


# Tier 1 §B — first-binary
def chapter_first_binary() -> list[tuple[str, list[str]]]:
    db = reset_chapter("01-first-binary")
    return [
        ("file", ["file", str(S_HELLO)]),
        ("kickoff", cmd("kickoff", str(S_HELLO), "--db", str(db))),
        (
            "sqlite-fnames",
            [
                "sqlite3",
                str(db),
                "-cmd",
                ".mode column",
                (
                    "SELECT printf('%#x', entry_va) AS entry_va, canonical, set_by "
                    "FROM function_names WHERE canonical IN ('_start', 'main') "
                    "ORDER BY entry_va;"
                ),
            ],
        ),
        (
            "view",
            cmd(
                "view",
                str(db),
                "0x11e0",
                "--binary",
                str(S_HELLO),
                "--hex-window",
                "32",
                "--pseudo-lines",
                "6",
            ),
        ),
        ("strings", cmd("strings", str(S_HELLO))),
        ("find-main", cmd("find", str(db), "main", "--kind", "function")),
    ]


# Tier 3 §M — hello-c-clang walkthrough
def chapter_hello_c_clang() -> list[tuple[str, list[str]]]:
    db = reset_chapter("03-hello-c-clang")
    return [
        ("file", ["file", str(S_HELLO_C)]),
        ("kickoff", cmd("kickoff", str(S_HELLO_C), "--db", str(db))),
        ("find-main", cmd("find", str(db), "main", "--kind", "function")),
        ("find-all", cmd("find", str(db), "", "--kind", "function")),
        (
            "view-main",
            cmd(
                "view",
                str(db),
                "0x1150",
                "--binary",
                str(S_HELLO_C),
                "--pane",
                "pseudo",
                "--pseudo-lines",
                "25",
            ),
        ),
        (
            "view-print-sum",
            cmd(
                "view",
                str(db),
                "0x11d0",
                "--binary",
                str(S_HELLO_C),
                "--pane",
                "pseudo",
                "--pseudo-lines",
                "8",
            ),
        ),
        (
            "xrefs-print-sum",
            cmd(
                "xrefs",
                str(db),
                "0x11d0",
                "--binary",
                str(S_HELLO_C),
                "--direction",
                "to",
            ),
        ),
        (
            "xrefs-static-fn",
            cmd(
                "xrefs",
                str(db),
                "0x1200",
                "--binary",
                str(S_HELLO_C),
                "--direction",
                "to",
            ),
        ),
    ]


# Tier 3 §N — stripped Go walkthrough
def chapter_stripped_go() -> list[tuple[str, list[str]]]:
    db = reset_chapter("03-stripped-go")
    return [
        ("file", ["file", str(S_GO)]),
        ("kickoff", cmd("kickoff", str(S_GO), "--db", str(db))),
        (
            "find-main-main",
            cmd(
                "find",
                str(db),
                r"main.main$",
                "--regex",
                "--kind",
                "function",
            ),
        ),
        (
            "find-main-namespace",
            cmd(
                "find",
                str(db),
                r"main\.",
                "--regex",
                "--kind",
                "function",
                "--limit",
                "20",
            ),
        ),
        (
            "find-runtime-main",
            cmd(
                "find",
                str(db),
                r"runtime.main$",
                "--regex",
                "--kind",
                "function",
            ),
        ),
        (
            "find-runtime-gopanic",
            cmd(
                "find",
                str(db),
                r"runtime.gopanic$",
                "--regex",
                "--kind",
                "function",
            ),
        ),
        (
            "find-internal-abi",
            cmd(
                "find",
                str(db),
                "internal/abi.Kind.String",
                "--kind",
                "function",
            ),
        ),
    ]


# Tier 3 §O — managed .NET PE
def chapter_dotnet_pe() -> list[tuple[str, list[str]]]:
    db = reset_chapter("03-dotnet-pe")
    return [
        ("file", ["file", str(S_DOTNET)]),
        ("kickoff", cmd("kickoff", str(S_DOTNET), "--db", str(db))),
        (
            "find-hello",
            cmd(
                "find",
                str(db),
                "Hello",
                "--kind",
                "function",
            ),
        ),
    ]


# Tier 3 §P — JVM classfile
def chapter_jvm() -> list[tuple[str, list[str]]]:
    return [
        ("file-class", ["file", str(S_JAVA_CLASS)]),
        ("classfile", cmd("classfile", str(S_JAVA_CLASS))),
        ("classfile-jar", cmd("classfile", str(S_JAVA_JAR))),
    ]


# Tier 3 §Q — vulnerable parser
def chapter_vulnparse() -> list[tuple[str, list[str]]]:
    db = reset_chapter("03-vulnparse")
    return [
        ("file", ["file", str(S_VULN)]),
        ("kickoff", cmd("kickoff", str(S_VULN), "--db", str(db))),
        ("find-all-funcs", cmd("find", str(db), "", "--kind", "function")),
        (
            "view-main",
            cmd(
                "view",
                str(db),
                "0x12ae",
                "--binary",
                str(S_VULN),
                "--pane",
                "pseudo",
                "--pseudo-lines",
                "30",
            ),
        ),
        (
            "view-parse-record",
            cmd(
                "view",
                str(db),
                "0x11e9",
                "--binary",
                str(S_VULN),
                "--pane",
                "pseudo",
                "--pseudo-lines",
                "30",
            ),
        ),
        (
            "xrefs-parse-record",
            cmd(
                "xrefs",
                str(db),
                "0x11e9",
                "--binary",
                str(S_VULN),
                "--direction",
                "to",
            ),
        ),
    ]


# Tier 3 §R — UPX-packed
def chapter_upx_packed() -> list[tuple[str, list[str]]]:
    db = reset_chapter("03-upx-packed")
    return [
        ("file", ["file", str(S_PACKED)]),
        ("detect-packer", cmd("detect-packer", str(S_PACKED))),
        ("kickoff", cmd("kickoff", str(S_PACKED), "--db", str(db))),
    ]


# Tier 3 §S — c2_demo flagship
def chapter_c2_demo() -> list[tuple[str, list[str]]]:
    db = reset_chapter("03-c2-demo")
    return [
        ("file", ["file", str(S_C2)]),
        ("kickoff", cmd("kickoff", str(S_C2), "--db", str(db))),
        (
            "strings-grep-iocs",
            [
                "bash",
                "-c",
                (
                    f"uv run glaurung strings {shlex.quote(str(S_C2))} "
                    f"| grep -iE 'http|\\.com|\\.org|10\\.|update|cron|systemd|backdoor'"
                ),
            ],
        ),
        (
            "view-main",
            cmd(
                "view",
                str(db),
                "0x1160",
                "--binary",
                str(S_C2),
                "--pane",
                "pseudo",
                "--pseudo-lines",
                "25",
            ),
        ),
    ]


# Tier 4 §T — diffing two binaries
def chapter_diff() -> list[tuple[str, list[str]]]:
    return [
        ("diff", cmd("diff", str(S_SWITCHY), str(S_SWITCHY_V2))),
    ]


# Tier 4 §W — bench harness
def chapter_bench() -> list[tuple[str, list[str]]]:
    out_ci = TMP / "bench-ci.json"
    out_packed = TMP / "bench-packed.json"
    out_ci.parent.mkdir(parents=True, exist_ok=True)
    return [
        (
            "ci-matrix",
            [
                "uv",
                "run",
                "python",
                "-m",
                "glaurung.bench",
                "--ci-matrix",
                "--output",
                str(out_ci),
                "--quiet",
            ],
        ),
        (
            "ci-matrix-md-head",
            [
                "bash",
                "-c",
                f"head -22 {shlex.quote(str(out_ci.with_suffix('.md')))}",
            ],
        ),
        (
            "packed-matrix",
            [
                "uv",
                "run",
                "python",
                "-m",
                "glaurung.bench",
                "--packed-matrix",
                "--output",
                str(out_packed),
                "--quiet",
            ],
        ),
        (
            "packed-matrix-md-head",
            [
                "bash",
                "-c",
                f"head -22 {shlex.quote(str(out_packed.with_suffix('.md')))}",
            ],
        ),
    ]


# Tier 5 §X — kickoff anatomy: same as §B but on c2_demo, since
# the chapter shows the IOC-richer summary.
def chapter_kickoff_anatomy() -> list[tuple[str, list[str]]]:
    db = reset_chapter("05-kickoff-anatomy")
    return [
        ("kickoff", cmd("kickoff", str(S_C2), "--db", str(db))),
        (
            "evidence-log-head",
            [
                "sqlite3",
                str(db),
                (
                    "SELECT cite_id, tool, summary FROM evidence_log "
                    "ORDER BY cite_id LIMIT 10;"
                ),
            ],
        ),
        (
            "evidence-log-schema",
            [
                "sqlite3",
                str(db),
                ".schema evidence_log",
            ],
        ),
        (
            "evidence-log-args-output",
            [
                "sqlite3",
                str(db),
                (
                    "SELECT cite_id, tool, summary, va_start, va_end, "
                    "substr(args_json, 1, 80) AS args_head, "
                    "substr(output_json, 1, 80) AS output_head "
                    "FROM evidence_log ORDER BY cite_id LIMIT 3;"
                ),
            ],
        ),
    ]


# REPL-driven recipes. Each step is encoded as a special bash command
# that pipes the keystrokes via printf into `glaurung repl`. The fixture
# captures the resulting stdout (including REPL prompts/output) — the
# script header records exactly which keystrokes were sent.
#
# The harness handles these uniformly with run() since they're plain
# subprocess calls. The bash wrapper makes the invocation visible in
# the captured `step.out` so the docs can show what was piped.
def _repl_recipe(db: Path, lines: list[str]) -> list[str]:
    """Build a bash invocation that pipes `lines` into glaurung repl.
    The captured fixture starts with a visible `# stdin:` block so
    the reader sees what was typed."""
    keystrokes = "\n".join(lines)
    # Emit a header showing the keystrokes, then run the REPL with the
    # keystrokes piped in. Use printf so newlines are interpreted.
    return [
        "bash",
        "-c",
        (
            f"printf '%s\\n' '─── stdin (keystrokes piped to glaurung repl) ───';\n"
            f"printf '%s\\n' {shlex.quote(keystrokes)};\n"
            f"printf '%s\\n' '─── glaurung repl stdout ───';\n"
            f"printf '%s\\n' {shlex.quote(keystrokes)} | "
            f"uv run glaurung repl <BINARY> --db <DB>"
        ),
    ]


# Tier 1 §D — REPL tour
def chapter_repl_tour() -> list[tuple[str, list[str]]]:
    db = reset_chapter("01-repl-tour")
    # Pre-populate the DB with kickoff so the REPL has something to work
    # with (functions discovered, callgraph indexed).
    bin_path = S_HELLO_C
    keystrokes_help = ["help", "q"]
    keystrokes_navigate = [
        "g 0x1150",
        "b",
        "f",
        "q",
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
        (
            "repl-locals-rename",
            _build_repl_invocation(bin_path, db, keystrokes_locals_rename),
        ),
        ("repl-proto", _build_repl_invocation(bin_path, db, keystrokes_proto)),
        ("undo-list-after", cmd("undo", str(db), "--list")),
    ]


def _build_repl_invocation(binary: Path, db: Path, lines: list[str]) -> list[str]:
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
        "bash",
        "-c",
        (
            f"echo '─── stdin (keystrokes piped to glaurung repl) ───';\n"
            f"printf '%s\\n' {shlex.quote(keystrokes)};\n"
            f"echo '─── glaurung repl stdout ───';\n"
            f"printf '%s\\n' {shlex.quote(keystrokes)} | "
            f"uv run glaurung repl {shlex.quote(str(binary))} "
            f"--db {shlex.quote(str(db))} 2>&1"
        ),
    ]


# Tier 2 §E — naming-and-types: REPL n / y / c on c2_demo
def chapter_naming_and_types() -> list[tuple[str, list[str]]]:
    db = reset_chapter("02-naming-and-types")
    bin_path = S_C2
    return [
        ("kickoff", cmd("kickoff", str(bin_path), "--db", str(db))),
        (
            "repl-functions",
            _build_repl_invocation(
                bin_path,
                db,
                [
                    "functions",
                    "q",
                ],
            ),
        ),
        (
            "repl-rename",
            _build_repl_invocation(
                bin_path,
                db,
                [
                    "g 0x1160",
                    "n c2_main",
                    "save",
                    "q",
                ],
            ),
        ),
        (
            "repl-comment",
            _build_repl_invocation(
                bin_path,
                db,
                [
                    "c 0x1160 entry: stash argc/argv into locals",
                    "save",
                    "q",
                ],
            ),
        ),
        (
            "repl-label-set",
            _build_repl_invocation(
                bin_path,
                db,
                [
                    "label set 0x4040 primary_c2_server void *",
                    "save",
                    "q",
                ],
            ),
        ),
        (
            "repl-retype",
            _build_repl_invocation(
                bin_path,
                db,
                [
                    "y 0x4040 const char *",
                    "save",
                    "q",
                ],
            ),
        ),
        (
            "repl-locals-rename",
            _build_repl_invocation(
                bin_path,
                db,
                [
                    "g 0x1160",
                    "l",
                    "locals rename -0x1b0 service_path",
                    "save",
                    "q",
                ],
            ),
        ),
        (
            "repl-decomp-after",
            _build_repl_invocation(
                bin_path,
                db,
                [
                    "g 0x1160",
                    "d",
                    "q",
                ],
            ),
        ),
        (
            "find-renamed",
            cmd(
                "find",
                str(db),
                "c2_main",
                "--kind",
                "function",
            ),
        ),
        (
            "find-label",
            cmd(
                "find",
                str(db),
                "primary_c2_server",
                "--kind",
                "data",
            ),
        ),
        (
            "find-comment",
            cmd(
                "find",
                str(db),
                "stash argc",
                "--kind",
                "comment",
            ),
        ),
        ("undo-list", cmd("undo", str(db), "--list")),
    ]


# Tier 2 §F — cross-references: every form of xrefs.
# Uses hello-c-clang because its kickoff populates the xref index;
# c2_demo's kickoff does not register PLT-call xrefs.
def chapter_xrefs_demo() -> list[tuple[str, list[str]]]:
    db = reset_chapter("02-cross-references")
    bin_path = S_HELLO_C
    return [
        ("kickoff", cmd("kickoff", str(bin_path), "--db", str(db))),
        (
            "find-print-sum",
            cmd(
                "find",
                str(db),
                "print_sum",
                "--kind",
                "function",
            ),
        ),
        (
            "xrefs-to-print-sum",
            cmd(
                "xrefs",
                str(db),
                "0x11d0",
                "--binary",
                str(bin_path),
                "--direction",
                "to",
            ),
        ),
        (
            "xrefs-from-main",
            cmd(
                "xrefs",
                str(db),
                "0x11bd",
                "--binary",
                str(bin_path),
                "--direction",
                "from",
            ),
        ),
        (
            "xrefs-from-main-call",
            cmd(
                "xrefs",
                str(db),
                "0x11bd",
                "--binary",
                str(bin_path),
                "--direction",
                "from",
                "--kind",
                "call",
            ),
        ),
        (
            "xrefs-both",
            cmd(
                "xrefs",
                str(db),
                "0x11d0",
                "--binary",
                str(bin_path),
                "--direction",
                "both",
            ),
        ),
        (
            "xrefs-json",
            cmd(
                "xrefs",
                str(db),
                "0x11d0",
                "--binary",
                str(bin_path),
                "--direction",
                "to",
                "--format",
                "json",
            ),
        ),
        (
            "repl-x",
            _build_repl_invocation(
                bin_path,
                db,
                [
                    "g 0x11d0",
                    "x",
                    "q",
                ],
            ),
        ),
    ]


# Tier 2 §G — stack-frames: list / discover / rename / retype
def chapter_stack_frames() -> list[tuple[str, list[str]]]:
    db = reset_chapter("02-stack-frames")
    bin_path = S_C2
    return [
        ("kickoff", cmd("kickoff", str(bin_path), "--db", str(db))),
        (
            "frame-list-before",
            cmd(
                "frame",
                str(db),
                "0x1160",
                "list",
                "--binary",
                str(bin_path),
            ),
        ),
        (
            "frame-discover",
            cmd(
                "frame",
                str(db),
                "0x1160",
                "discover",
                "--binary",
                str(bin_path),
            ),
        ),
        (
            "frame-list-after",
            cmd(
                "frame",
                str(db),
                "0x1160",
                "list",
                "--binary",
                str(bin_path),
            ),
        ),
        (
            "frame-rename",
            cmd(
                "frame",
                str(db),
                "0x1160",
                "rename",
                "-0x1b0",
                "service_path",
                "--binary",
                str(bin_path),
            ),
        ),
        (
            "frame-retype",
            cmd(
                "frame",
                str(db),
                "0x1160",
                "retype",
                "-0x1b0",
                "char[48]",
                "--binary",
                str(bin_path),
            ),
        ),
        (
            "frame-list-final",
            cmd(
                "frame",
                str(db),
                "0x1160",
                "list",
                "--binary",
                str(bin_path),
            ),
        ),
        (
            "frame-list-json",
            cmd(
                "frame",
                str(db),
                "0x1160",
                "list",
                "--binary",
                str(bin_path),
                "--format",
                "json",
            ),
        ),
    ]


# Tier 2 §H — strings-and-data: strings-xrefs + label
def chapter_strings_and_data() -> list[tuple[str, list[str]]]:
    db = reset_chapter("02-strings-and-data")
    bin_path = S_C2
    return [
        ("kickoff", cmd("kickoff", str(bin_path), "--db", str(db))),
        (
            "strings-xrefs-default",
            cmd(
                "strings-xrefs",
                str(db),
                "--binary",
                str(bin_path),
                "--limit",
                "10",
            ),
        ),
        (
            "strings-xrefs-min-len",
            cmd(
                "strings-xrefs",
                str(db),
                "--binary",
                str(bin_path),
                "--min-len",
                "12",
                "--limit",
                "10",
            ),
        ),
        (
            "strings-xrefs-used-only",
            cmd(
                "strings-xrefs",
                str(db),
                "--binary",
                str(bin_path),
                "--used-only",
                "--limit",
                "10",
            ),
        ),
        (
            "strings-xrefs-json",
            cmd(
                "strings-xrefs",
                str(db),
                "--binary",
                str(bin_path),
                "--min-len",
                "12",
                "--limit",
                "5",
                "--format",
                "json",
            ),
        ),
        (
            "repl-label",
            _build_repl_invocation(
                bin_path,
                db,
                [
                    "label set 0x4040 primary_c2_server void *",
                    "save",
                    "q",
                ],
            ),
        ),
        (
            "repl-retype",
            _build_repl_invocation(
                bin_path,
                db,
                [
                    "y 0x4040 const char *",
                    "save",
                    "q",
                ],
            ),
        ),
        (
            "repl-label-list",
            _build_repl_invocation(
                bin_path,
                db,
                [
                    "label",
                    "q",
                ],
            ),
        ),
        (
            "find-label",
            cmd(
                "find",
                str(db),
                "primary_c2_server",
                "--kind",
                "data",
            ),
        ),
        (
            "find-data-prefix",
            cmd(
                "find",
                str(db),
                "server",
                "--kind",
                "data",
            ),
        ),
    ]


# Tier 2 §I — searching: every find query shape.
# Uses hello-c-clang because its kickoff registers PLT entries
# (printf, strlen) — c2_demo's kickoff doesn't.
def chapter_searching() -> list[tuple[str, list[str]]]:
    db = reset_chapter("02-searching")
    bin_path = S_HELLO_C
    return [
        ("kickoff", cmd("kickoff", str(bin_path), "--db", str(db))),
        ("find-substring", cmd("find", str(db), "main")),
        (
            "find-kind-function",
            cmd(
                "find",
                str(db),
                "main",
                "--kind",
                "function",
            ),
        ),
        (
            "find-all-functions",
            cmd(
                "find",
                str(db),
                "",
                "--kind",
                "function",
            ),
        ),
        (
            "find-regex-funcs",
            cmd(
                "find",
                str(db),
                r"^_",
                "--regex",
                "--kind",
                "function",
            ),
        ),
        (
            "find-case-sensitive",
            cmd(
                "find",
                str(db),
                "MAIN",
                "--kind",
                "function",
            ),
        ),
        (
            "find-case-sensitive-flag",
            cmd(
                "find",
                str(db),
                "MAIN",
                "--kind",
                "function",
                "--case-sensitive",
            ),
        ),
        (
            "find-strings",
            cmd(
                "find",
                str(db),
                "Hello",
                "--kind",
                "string",
            ),
        ),
        (
            "find-disasm",
            cmd(
                "find",
                str(db),
                r"^push",
                "--regex",
                "--kind",
                "disasm",
                "--limit",
                "10",
            ),
        ),
        (
            "find-json",
            cmd(
                "find",
                str(db),
                "main",
                "--kind",
                "function",
                "--format",
                "json",
            ),
        ),
    ]


# Tier 2 §J — bookmarks-and-journal
def chapter_bookmarks() -> list[tuple[str, list[str]]]:
    db = reset_chapter("02-bookmarks")
    bin_path = S_C2
    return [
        ("kickoff", cmd("kickoff", str(bin_path), "--db", str(db))),
        (
            "bookmark-add-1",
            cmd(
                "bookmark",
                str(db),
                "add",
                "0x1140",
                "weird branch — investigate",
                "--binary",
                str(bin_path),
            ),
        ),
        (
            "bookmark-add-2",
            cmd(
                "bookmark",
                str(db),
                "add",
                "0x1160",
                "main entry",
                "--binary",
                str(bin_path),
            ),
        ),
        (
            "bookmark-add-second-at-1140",
            cmd(
                "bookmark",
                str(db),
                "add",
                "0x1140",
                "actually it's a parser",
                "--binary",
                str(bin_path),
            ),
        ),
        (
            "bookmark-list",
            cmd(
                "bookmark",
                str(db),
                "list",
                "--binary",
                str(bin_path),
            ),
        ),
        (
            "bookmark-list-filter",
            cmd(
                "bookmark",
                str(db),
                "list",
                "--va",
                "0x1140",
                "--binary",
                str(bin_path),
            ),
        ),
        (
            "journal-add",
            cmd(
                "journal",
                str(db),
                "add",
                "today: traced the C2 protocol",
                "--binary",
                str(bin_path),
            ),
        ),
        (
            "journal-list",
            cmd(
                "journal",
                str(db),
                "list",
                "--binary",
                str(bin_path),
            ),
        ),
        (
            "bookmark-delete",
            cmd(
                "bookmark",
                str(db),
                "delete",
                "1",
                "--binary",
                str(bin_path),
            ),
        ),
        (
            "bookmark-list-after-delete",
            cmd(
                "bookmark",
                str(db),
                "list",
                "--binary",
                str(bin_path),
            ),
        ),
        (
            "bookmark-list-json",
            cmd(
                "bookmark",
                str(db),
                "list",
                "--binary",
                str(bin_path),
                "--format",
                "json",
            ),
        ),
    ]


# Tier 2 §K — undo-redo
def chapter_undo_redo() -> list[tuple[str, list[str]]]:
    db = reset_chapter("02-undo-redo")
    bin_path = S_C2
    return [
        ("kickoff", cmd("kickoff", str(bin_path), "--db", str(db))),
        (
            "repl-make-changes",
            _build_repl_invocation(
                bin_path,
                db,
                [
                    "g 0x1160",
                    "n c2_main",
                    "c 0x1160 entry: stash argc/argv into locals",
                    "label set 0x4040 primary_c2_server void *",
                    "save",
                    "q",
                ],
            ),
        ),
        ("undo-list-before", cmd("undo", str(db), "--list")),
        ("undo-once", cmd("undo", str(db))),
        ("undo-list-after", cmd("undo", str(db), "--list")),
        ("redo-once", cmd("redo", str(db))),
        ("undo-list-after-redo", cmd("undo", str(db), "--list")),
        ("undo-multi", cmd("undo", str(db), "-n", "3")),
        ("undo-list-final", cmd("undo", str(db), "--list")),
    ]


# Tier 2 §L — patch-and-verify
def chapter_patch() -> list[tuple[str, list[str]]]:
    bin_in = S_HELLO_C
    return [
        (
            "disasm-target",
            cmd(
                "disasm",
                str(bin_in),
                "--addr",
                "0x11e0",
                "--max-instructions",
                "4",
            ),
        ),
        (
            "patch-nop",
            cmd(
                "patch",
                str(bin_in),
                str(TMP / "patched-nop.bin"),
                "--va",
                "0x11e0",
                "--nop",
                "--verify",
                "--force",
            ),
        ),
        (
            "patch-bytes",
            cmd(
                "patch",
                str(bin_in),
                str(TMP / "patched-bytes.bin"),
                "--va",
                "0x11e5",
                "--bytes",
                "90 90",
                "--verify",
                "--force",
            ),
        ),
        (
            "patch-json",
            cmd(
                "patch",
                str(bin_in),
                str(TMP / "patched-json.bin"),
                "--va",
                "0x11e0",
                "--nop",
                "--verify",
                "--force",
                "--format",
                "json",
            ),
        ),
    ]


# Tier 4 §V — typed-locals: show how propagation lights up libc-call slots
def chapter_typed_locals() -> list[tuple[str, list[str]]]:
    db = reset_chapter("04-typed-locals")
    bin_path = S_C2
    return [
        ("kickoff", cmd("kickoff", str(bin_path), "--db", str(db))),
        (
            "view-typed-locals",
            cmd(
                "view",
                str(db),
                "0x1160",
                "--binary",
                str(bin_path),
                "--pane",
                "pseudo",
                "--pseudo-lines",
                "8",
            ),
        ),
        (
            "find-stack-vars-propagated",
            [
                "sqlite3",
                str(db),
                "-cmd",
                ".mode column",
                (
                    "SELECT printf('%#x', function_va) AS function_va, "
                    "printf('-%#x', -offset) AS offset, name, c_type, set_by "
                    "FROM stack_frame_vars "
                    "WHERE function_va = 0x1160 AND set_by = 'propagated' "
                    "ORDER BY stack_frame_vars.offset;"
                ),
            ],
        ),
        (
            "repl-propagate",
            _build_repl_invocation(
                bin_path,
                db,
                [
                    "g 0x1160",
                    "propagate",
                    "save",
                    "q",
                ],
            ),
        ),
        (
            "find-types-head",
            [
                "bash",
                "-c",
                f"uv run glaurung find {shlex.quote(str(db))} '' --kind type | head -10",
            ],
        ),
    ]


# Tier 4 §U — exporting (run the export commands; agent-LLM not required)
def chapter_export() -> list[tuple[str, list[str]]]:
    db = reset_chapter("04-export")
    TMP / "export-md.out"
    TMP / "export.json"
    TMP / "export.h"
    TMP / "export-ida.py"
    TMP / "export-binja.py"
    TMP / "export-ghidra.py"
    return [
        ("kickoff", cmd("kickoff", str(S_HELLO_C), "--db", str(db))),
        (
            "export-markdown-head",
            [
                "bash",
                "-c",
                (
                    f"uv run glaurung export {shlex.quote(str(db))} "
                    f"--output-format markdown | head -30"
                ),
            ],
        ),
        (
            "export-json-summary",
            [
                "bash",
                "-c",
                (
                    f"uv run glaurung export {shlex.quote(str(db))} "
                    f"--output-format json | python -c "
                    "'import json,sys; d=json.load(sys.stdin); "
                    'print("schema_version:", d["schema_version"]); '
                    'print("keys:", sorted(d.keys()))\''
                ),
            ],
        ),
        (
            "export-ida-head",
            [
                "bash",
                "-c",
                (
                    f"uv run glaurung export {shlex.quote(str(db))} "
                    f"--output-format ida | head -20"
                ),
            ],
        ),
        (
            "export-binja-head",
            [
                "bash",
                "-c",
                (
                    f"uv run glaurung export {shlex.quote(str(db))} "
                    f"--output-format binja | head -20"
                ),
            ],
        ),
        (
            "export-ghidra-head",
            [
                "bash",
                "-c",
                (
                    f"uv run glaurung export {shlex.quote(str(db))} "
                    f"--output-format ghidra | head -20"
                ),
            ],
        ),
    ]


ChapterRecipe = Callable[[], list[tuple[str, list[str]]]]


CHAPTERS: dict[str, ChapterRecipe] = {
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
        "--chapter",
        action="append",
        default=[],
        help="Run only specific chapter(s). Can repeat.",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List chapter names and exit.",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--check",
        action="store_true",
        help="Compare live output with fixtures without rewriting them (default).",
    )
    mode.add_argument(
        "--capture",
        action="store_true",
        help="Refresh fixtures from successful live commands.",
    )
    args = parser.parse_args(argv)

    if args.list:
        for name in CHAPTERS:
            print(name)
        return 0

    targets = args.chapter or list(CHAPTERS.keys())
    failures: list[str] = []
    processed = 0
    capture = bool(args.capture)

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
                result = run(command)
            except subprocess.TimeoutExpired:
                print("    TIMEOUT", flush=True)
                failures.append(f"{chapter}/{step_name}")
                continue
            except (OSError, UnicodeError) as e:
                print(f"    ERROR: {e}", flush=True)
                failures.append(f"{chapter}/{step_name}")
                continue
            allowed_returncodes = expected_return_codes(chapter, step_name)
            if result.returncode not in allowed_returncodes:
                print(f"    EXIT {result.returncode}", flush=True)
                if result.output:
                    print(result.output.rstrip(), flush=True)
                failures.append(f"{chapter}/{step_name}")
                continue

            normalized = stable(result.output)
            path = fixture_path(chapter, step_name)
            if capture:
                write_fixture(chapter, step_name, result.output)
                print(
                    f"    captured {path.relative_to(REPO)}  "
                    f"({len(result.output)} bytes)",
                    flush=True,
                )
                processed += 1
                continue

            if not path.is_file():
                print(f"    MISSING {path.relative_to(REPO)}", flush=True)
                failures.append(f"{chapter}/{step_name}")
                continue
            expected = path.read_text(encoding="utf-8")
            if expected != normalized:
                print(f"    DRIFT {path.relative_to(REPO)}", flush=True)
                diff = difflib.unified_diff(
                    expected.splitlines(),
                    normalized.splitlines(),
                    fromfile=f"expected/{path.name}",
                    tofile=f"current/{path.name}",
                    lineterm="",
                )
                for line in diff:
                    print(f"      {line}", flush=True)
                failures.append(f"{chapter}/{step_name}")
                continue
            print(f"    checked {path.relative_to(REPO)}", flush=True)
            processed += 1

    if failures:
        print(f"\n{len(failures)} step(s) failed:", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1
    verb = "captured" if capture else "checked"
    print(f"\nOK — {processed} step(s) {verb} in {FIXTURES.relative_to(REPO)}/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
