#!/usr/bin/env python3
"""Run glaurung, angr and Ghidra over the same function and show the results together.

Why this exists
---------------

The three-way comparison in ``docs/development/decompiler-parity-backlog.md``
was originally done by hand, and every claim in it — that we recover ``argv[i]``
where both others emit pointer arithmetic, that both others erase a
``main & ~0xFFF`` page-align by snapping to ``_init`` — is only as durable as
someone's willingness to redo the shell by hand. Reference tools also move:
the numbers in that document are angr 9.3.3 and Ghidra 12.1.3 and will drift.

So the comparison is a command, not a memory.

What it does NOT do
-------------------

It does not score. There is no metric here and no baseline, deliberately:
"which output is better" over a handful of functions is a judgement a human
makes by reading, and a number would only lend it false authority. Corpus-scale
scoring is DecBench's job, and DecBench stays held out.

Availability
------------

Both reference tools are optional. Absent, the corresponding column is
reported as unavailable and the run still succeeds — this must stay usable on
a machine with neither installed.

* **angr** — ``uv pip install angr``.
* **Ghidra** — needs a JDK; ``GHIDRA_INSTALL_DIR`` or ``/opt/ghidra``.

Ghidra gotchas, both of which cost real time to find:

1. ``analyzeHeadless`` refuses any project or script path containing a
   **dot-prefixed element** ("Path element starting with '.' is not
   permitted"), so the project directory cannot live under ``~/.cache``. This
   script therefore keeps Ghidra state in a dotless directory.
2. Ghidra 12.x needs **JDK 21**. A newer JDK (25) is rejected as unsupported
   and an older one (17) is too old. If ``java`` on PATH is the wrong version
   the run fails with a message that does not obviously say so, so this script
   looks for a 21 explicitly and reports clearly when it cannot find one.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

#: Ghidra state lives here rather than under TMPDIR. The project path may not
#: contain a dot-prefixed element and the repository's TMPDIR is
#: ``~/.cache/glaurung/tmp``, which does.
GHIDRA_WORK_DIR = Path.home() / "glaurung-ghidra"

#: The postscript handed to ``analyzeHeadless``. Prints one marker line per
#: function so the caller can split a single Ghidra run into per-function
#: results -- Ghidra's startup and analysis cost is paid once per binary, not
#: once per function, and that is the difference between seconds and minutes.
GHIDRA_SCRIPT = """\
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;

public class GlaurungCompare extends GhidraScript {
    public void run() throws Exception {
        String[] want = getScriptArgs();
        DecompInterface di = new DecompInterface();
        di.openProgram(currentProgram);
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            boolean match = false;
            for (String w : want) {
                if (f.getName().equals(w)) {
                    match = true;
                }
            }
            if (!match) {
                continue;
            }
            DecompileResults r = di.decompileFunction(f, 60, monitor);
            println("=====GLAURUNG_CMP_FN " + f.getName() + "=====");
            if (r != null && r.decompileCompleted()) {
                println(r.getDecompiledFunction().getC());
            } else {
                println("<decompile failed>");
            }
        }
    }
}
"""

ANGR_DRIVER = '''\
"""Decompile named functions with angr and print them with marker lines."""
import json
import logging
import sys
import warnings

warnings.filterwarnings("ignore")
for _name in list(logging.root.manager.loggerDict):
    logging.getLogger(_name).setLevel(logging.CRITICAL)
logging.getLogger("angr").setLevel(logging.CRITICAL)

import angr  # noqa: E402

binary, names = sys.argv[1], json.loads(sys.argv[2])
proj = angr.Project(binary, auto_load_libs=False)
cfg = proj.analyses.CFGFast(normalize=True, data_references=True)
proj.analyses.CompleteCallingConventions(recover_variables=True, cfg=cfg.model)
for name in names:
    func = next((f for f in cfg.kb.functions.values() if f.name == name), None)
    print(f"=====GLAURUNG_CMP_FN {name}=====")
    if func is None:
        print("<function not found>")
        continue
    try:
        dec = proj.analyses.Decompiler(func, cfg=cfg.model)
        print(dec.codegen.text if dec.codegen else "<no codegen>")
    except Exception as exc:  # noqa: BLE001 - report, never abort the comparison
        print(f"<decompile raised {type(exc).__name__}: {exc}>")
'''

MARKER = re.compile(r"^=====GLAURUNG_CMP_FN (.+)=====$", re.MULTILINE)


@dataclass
class ToolResult:
    """One decompiler's output for one binary, keyed by function name."""

    name: str
    available: bool
    version: str = ""
    functions: dict[str, str] = field(default_factory=dict)
    error: str = ""


def split_on_markers(text: str) -> dict[str, str]:
    """Split marker-delimited output into ``{function: body}``."""
    parts = MARKER.split(text)
    # ``parts`` is [preamble, name, body, name, body, ...].
    return {parts[i].strip(): parts[i + 1].strip() for i in range(1, len(parts) - 1, 2)}


def find_jdk21() -> str | None:
    """A JDK 21 home, which is what Ghidra 12.x requires."""
    for candidate in sorted(Path("/usr/lib/jvm").glob("*21*")):
        if (candidate / "bin" / "java").exists():
            return str(candidate)
    return None


def find_ghidra() -> Path | None:
    """The Ghidra install directory, if one is present."""
    env = os.environ.get("GHIDRA_INSTALL_DIR")
    candidates = [Path(env)] if env else []
    candidates += [Path("/opt/ghidra"), *sorted(Path("/opt").glob("ghidra_*"))]
    for candidate in candidates:
        if (candidate / "support" / "analyzeHeadless").exists():
            return candidate
    return None


def run_glaurung(binary: Path, names: list[str], style: str) -> ToolResult:
    """Decompile with the in-repo glaurung CLI, one invocation per function.

    ``--style decbench`` is the default and the only fair comparison: the
    ``c`` style is a low-level IR view that exposes flag arithmetic, and
    comparing it against two finished decompilers would flatter them.
    """
    result = ToolResult(name="glaurung", available=True, version=_glaurung_version())
    for func in names:
        proc = subprocess.run(
            [
                "uv",
                "run",
                "glaurung",
                "decompile",
                str(binary),
                "--func",
                func,
                "--style",
                style,
                "--no-color",
            ],
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
            timeout=300,
            check=False,
        )
        output = proc.stdout.strip()
        result.functions[func] = (
            output or f"<exit {proc.returncode}: {proc.stderr.strip()[:200]}>"
        )
    return result


def _glaurung_version() -> str:
    proc = subprocess.run(
        ["git", "rev-parse", "--short", "HEAD"],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        check=False,
    )
    return f"git {proc.stdout.strip()}" if proc.returncode == 0 else "unknown"


def run_angr(binary: Path, names: list[str]) -> ToolResult:
    """Decompile with angr in one subprocess (CFG recovery is the expensive part)."""
    probe = subprocess.run(
        ["uv", "run", "python", "-c", "import angr; print(angr.__version__)"],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        check=False,
    )
    if probe.returncode != 0:
        return ToolResult(
            name="angr",
            available=False,
            error="not importable; install with `uv pip install angr`",
        )
    version = probe.stdout.strip().splitlines()[-1] if probe.stdout.strip() else "?"

    with tempfile.TemporaryDirectory() as tmp:
        driver = Path(tmp) / "angr_driver.py"
        driver.write_text(ANGR_DRIVER)
        proc = subprocess.run(
            ["uv", "run", "python", str(driver), str(binary), json.dumps(names)],
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
            timeout=1800,
            check=False,
        )
    if proc.returncode != 0 and not MARKER.search(proc.stdout):
        return ToolResult(
            name="angr",
            available=True,
            version=version,
            error=f"exit {proc.returncode}: {proc.stderr.strip()[-400:]}",
        )
    return ToolResult(
        name="angr",
        available=True,
        version=version,
        functions=split_on_markers(proc.stdout),
    )


def run_ghidra(binary: Path, names: list[str]) -> ToolResult:
    """Decompile with Ghidra headless: one import+analysis, all functions."""
    install = find_ghidra()
    if install is None:
        return ToolResult(
            name="ghidra",
            available=False,
            error="not found; set GHIDRA_INSTALL_DIR or install to /opt/ghidra",
        )
    jdk = find_jdk21()
    if jdk is None:
        return ToolResult(
            name="ghidra",
            available=False,
            error="no JDK 21 under /usr/lib/jvm (Ghidra 12.x rejects 17 and 25)",
        )

    # Dotless working directory: analyzeHeadless refuses a path containing a
    # dot-prefixed element, which rules out the repo's TMPDIR (~/.cache/...).
    GHIDRA_WORK_DIR.mkdir(parents=True, exist_ok=True)
    scripts = GHIDRA_WORK_DIR / "scripts"
    scripts.mkdir(exist_ok=True)
    (scripts / "GlaurungCompare.java").write_text(GHIDRA_SCRIPT)
    project = GHIDRA_WORK_DIR / "proj"
    project.mkdir(exist_ok=True)

    env = dict(os.environ, JAVA_HOME=jdk, GHIDRA_JAVA_HOME=jdk)
    proc = subprocess.run(
        [
            str(install / "support" / "analyzeHeadless"),
            str(project),
            f"cmp_{binary.name.replace('.', '_')}",
            "-import",
            str(binary),
            "-overwrite",
            "-scriptPath",
            str(scripts),
            "-postScript",
            "GlaurungCompare.java",
            *names,
        ],
        capture_output=True,
        text=True,
        env=env,
        timeout=1800,
        check=False,
    )
    # Ghidra prefixes every script println with log furniture, and keeps
    # logging its own progress after the script ends -- so stripping the prefix
    # is not enough. Without also dropping the trailing HeadlessAnalyzer lines
    # they are captured as part of the LAST function's body, which is how the
    # first version of this reported five lines of "REPORT: Import succeeded"
    # as decompiler output.
    cleaned_lines: list[str] = []
    for line in proc.stdout.splitlines():
        stripped = re.sub(r"^INFO\s+GlaurungCompare\.java> ", "", line, count=1)
        if stripped == line and re.match(r"^(INFO|WARN|ERROR|DEBUG)\s", line):
            continue  # Ghidra's own progress log, not script output.
        body = stripped.replace("(GhidraScript)", "").rstrip()
        # A multi-line println carries the "(GhidraScript)" suffix only on its
        # final line, so that suffix can arrive as a line of its own -- which
        # is why it is removed unconditionally rather than as a line filter.
        cleaned_lines.append(body)
    cleaned = "\n".join(cleaned_lines)
    functions = split_on_markers(cleaned)
    if not functions:
        return ToolResult(
            name="ghidra",
            available=True,
            version=install.name,
            error=f"no output; exit {proc.returncode}: {proc.stdout.strip()[-400:]}",
        )
    return ToolResult(
        name="ghidra", available=True, version=install.name, functions=functions
    )


def render_text(binary: Path, names: list[str], results: list[ToolResult]) -> str:
    """A readable side-by-side report."""
    out: list[str] = [f"# {binary}", ""]
    for tool in results:
        status = f"{tool.version}" if tool.available else f"UNAVAILABLE - {tool.error}"
        out.append(f"  {tool.name:<10} {status}")
        if tool.available and tool.error:
            out.append(f"  {'':<10} ERROR: {tool.error}")
    out.append("")
    for func in names:
        out.append("=" * 78)
        out.append(f"  {func}")
        out.append("=" * 78)
        for tool in results:
            body = tool.functions.get(func)
            out.append(f"\n----- {tool.name} -----")
            if not tool.available:
                out.append(f"  (unavailable: {tool.error})")
            elif body is None:
                out.append("  (no output for this function)")
            else:
                out.append(textwrap.indent(body, "  "))
        out.append("")
    return "\n".join(out)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("binary", type=Path, help="binary to decompile")
    parser.add_argument(
        "functions", nargs="+", help="function names to compare, e.g. main print_sum"
    )
    parser.add_argument(
        "--style",
        default="decbench",
        choices=["decbench", "c", "plain"],
        help="glaurung render style (default: decbench, the scored one)",
    )
    parser.add_argument(
        "--skip",
        action="append",
        default=[],
        choices=["angr", "ghidra"],
        help="skip a reference tool (repeatable)",
    )
    parser.add_argument("--json", action="store_true", help="emit JSON instead of text")
    parser.add_argument("--out", type=Path, help="write to this file instead of stdout")
    args = parser.parse_args()

    if not args.binary.exists():
        print(f"no such binary: {args.binary}", file=sys.stderr)
        return 2

    results = [run_glaurung(args.binary, args.functions, args.style)]
    if "angr" not in args.skip:
        results.append(run_angr(args.binary, args.functions))
    if "ghidra" not in args.skip:
        results.append(run_ghidra(args.binary, args.functions))

    if args.json:
        payload = {
            "binary": str(args.binary),
            "functions": args.functions,
            "tools": [
                {
                    "name": t.name,
                    "available": t.available,
                    "version": t.version,
                    "error": t.error,
                    "functions": t.functions,
                }
                for t in results
            ],
        }
        text = json.dumps(payload, indent=2)
    else:
        text = render_text(args.binary, args.functions, results)

    if args.out:
        args.out.write_text(text)
        print(f"wrote {args.out}")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
