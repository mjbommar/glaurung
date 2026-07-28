#!/usr/bin/env python3
"""Three-way round trip: C -> binary -> C, for glaurung, Ghidra and angr.

    tools/roundtrip3.py --out DIR [--programs a b c] [--lanes gcc:O0 clang:O0]

For every (program, compiler, opt) it compiles the source, decompiles the result
with all three decompilers, and writes one markdown file per program with the
original source and all three recoveries side by side, function by function.

**Why side-by-side text and not metrics.** GED, `type_match` and `byte_match`
each compress a whole function to one number, and none of them knows whether the
code is right — `structs:dist2` scores a perfect 0.0 graph edit distance while
its body reads two locals nothing assigns. The differences that matter (a `for`
recovered as `while(1){if(..)break;}`, a switch guard reading a stale flag, a
parameter typed `long` instead of `char *`) are visible in seconds by reading and
invisible in the aggregate. This makes reading cheap.

Environment: `GHIDRA_INSTALL_DIR`, plus a python that can import angr (the
DecBench venv) given by `ANGR_PYTHON`, and a `pyghidra`-capable python given by
`GHIDRA_PYTHON`. Each decompiler is optional; a missing one is reported in the
output rather than silently skipped.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "tests" / "decbench_corpus" / "src"
FIXTURES = ROOT / "tests" / "decompiler_fixtures" / "src"

HDR_GLAURUNG = re.compile(r"^// glaurung: (\S+) @ 0x[0-9a-fA-F]+")
HDR_OTHER = re.compile(r"^===== (\S+) =====$")


def compile_one(src: Path, cc: str, opt: str, out: Path) -> Path | None:
    so = out / f"{src.stem}-{cc}-{opt}.so"
    r = subprocess.run(
        [cc, "-shared", "-fPIC", "-g", f"-{opt}", "-w", "-o", str(so), str(src)],
        capture_output=True,
        text=True,
        check=False,
    )
    return so if r.returncode == 0 else None


def _split(text: str, header: re.Pattern) -> dict[str, str]:
    """Split a decompiler's whole-binary output into {function: body}."""
    out: dict[str, str] = {}
    cur, buf = None, []
    for line in text.splitlines():
        m = header.match(line)
        if m:
            if cur:
                out[cur] = "\n".join(buf).strip()
            cur, buf = m.group(1), []
            if header is HDR_GLAURUNG:
                buf.append(line)
        else:
            buf.append(line)
    if cur:
        out[cur] = "\n".join(buf).strip()
    return out


def run_glaurung(so: Path) -> dict[str, str]:
    exe = os.environ.get("GLAURUNG_BIN") or str(ROOT / ".venv" / "bin" / "glaurung")
    r = subprocess.run(
        [
            exe,
            "decompile",
            str(so),
            "--all",
            "--limit",
            "200",
            "--style",
            "decbench",
            "--no-color",
        ],
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )
    return _split(r.stdout, HDR_GLAURUNG)


def run_ghidra(so: Path) -> dict[str, str]:
    py = os.environ.get("GHIDRA_PYTHON")
    install = os.environ.get("GHIDRA_INSTALL_DIR")
    if not py or not install:
        return {}
    r = subprocess.run(
        [py, str(ROOT / "tools" / "ghidra_decompile.py"), install, str(so)],
        capture_output=True,
        text=True,
        timeout=1800,
        check=False,
    )
    return _split(r.stdout, HDR_OTHER)


def run_angr(so: Path) -> dict[str, str]:
    py = os.environ.get("ANGR_PYTHON")
    if not py:
        return {}
    r = subprocess.run(
        [py, str(ROOT / "tools" / "angr_decompile.py"), str(so)],
        capture_output=True,
        text=True,
        timeout=1800,
        check=False,
    )
    return _split(r.stdout, HDR_OTHER)


def source_of(src: Path, name: str) -> str | None:
    """The function's source text, by brace matching from its signature."""
    text = src.read_text()
    m = re.search(rf"(?m)^[A-Za-z_][\w \*]*\b{re.escape(name)}\s*\(", text)
    if not m:
        return None
    i = text.index("{", m.start())
    depth, j = 0, i
    while j < len(text):
        if text[j] == "{":
            depth += 1
        elif text[j] == "}":
            depth -= 1
            if depth == 0:
                return text[m.start() : j + 1]
        j += 1
    return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--programs", nargs="*", default=None)
    ap.add_argument("--lanes", nargs="*", default=["gcc:O0"])
    ap.add_argument(
        "--fixtures",
        action="store_true",
        help="use tests/decompiler_fixtures/src instead of the DecBench corpus",
    )
    args = ap.parse_args()

    srcdir = FIXTURES if args.fixtures else CORPUS
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    build = out / "build"
    build.mkdir(exist_ok=True)

    srcs = sorted(srcdir.glob("*.c"))
    if args.programs:
        srcs = [s for s in srcs if s.stem in set(args.programs)]

    for src in srcs:
        for lane in args.lanes:
            cc, opt = lane.split(":")
            so = compile_one(src, cc, opt, build)
            if so is None:
                print(f"  {src.stem}:{lane} BUILD FAILED", file=sys.stderr)
                continue
            g, h, a = run_glaurung(so), run_ghidra(so), run_angr(so)
            names = sorted(set(g) | set(h) | set(a))
            dest = out / f"{src.stem}-{cc}-{opt}.md"
            with dest.open("w") as fh:
                fh.write(f"# {src.stem} ({cc} -{opt})\n\n")
                fh.write(
                    f"glaurung: {len(g)} fns | ghidra: {len(h)} fns | angr: {len(a)} fns\n\n"
                )
                for n in names:
                    s = source_of(src, n)
                    if s is None:
                        continue  # CRT/PLT noise with no source counterpart
                    fh.write(f"## `{n}`\n\n### source\n```c\n{s}\n```\n")
                    for label, body in (
                        ("glaurung", g.get(n)),
                        ("ghidra", h.get(n)),
                        ("angr", a.get(n)),
                    ):
                        fh.write(f"\n### {label}\n```c\n{body or '(absent)'}\n```\n")
                    fh.write("\n---\n")
            print(
                f"  wrote {dest.name}  ({len([n for n in names if source_of(src, n)])} scored fns)",
                file=sys.stderr,
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
