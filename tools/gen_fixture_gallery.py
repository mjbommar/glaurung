#!/usr/bin/env python3
"""Emit the JSON the glaurung.dev fixture gallery renders.

WHY IT IS GENERATED AND NOT WRITTEN. glaurung.dev's house rule is that a code
block holds real captured output -- run the command, paste what came back. A
gallery of 213 fixtures across six toolchain/optimisation lanes is 1,278
decompilations; the only honest way to publish it is to run every one and record
what the tool actually emitted, together with the verdict the execution
differential already reached for it.

WHAT MAKES THIS WORTH PUBLISHING. `baseline.json` is not a similarity score. It
records, per fixture per lane per function, whether the recovered C was
recompiled, dlopened beside the original, called with the same seeded inputs,
and returned the same values and buffers. So a page can say `pass` and mean
"this recompiles and behaves identically", and say `fail` and mean it too. The
failures are the reason to believe the passes, which is the site's rule 6.

Output: one JSON per fixture plus an index, under `--out`.

    uv run python tools/gen_fixture_gallery.py --out ../glaurung.dev/src/data/fixtures
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import tomllib
import sys
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "tests/decompiler_fixtures/src"
BUILD = ROOT / "tests/decompiler_fixtures/build"
BASELINE = ROOT / "tests/decompiler_fixtures/baseline.json"
STRUCTURAL = ROOT / "tests/decompiler_fixtures/structural_baseline.json"

#: Source suffix -> the toolchains that build it. `rustc` is its own front and
#: back end, so the {gcc, clang} axis has no meaning for a `.rs` fixture.
TOOLCHAINS = {
    ".c": ("gcc", "clang"),
    ".cpp": ("gcc", "clang"),
    ".rs": ("rustc",),
    ".go": ("go",),
    ".S": ("gcc", "clang"),
}
OPTS = ("O0", "O2")

#: Display names. `.S` is hand-written assembly, which has a source view but no
#: "recovered from a higher-level language" story -- it is here because the
#: corpus has one and dropping it silently is how Go went missing.
LANGUAGES = {".c": "C", ".cpp": "C++", ".rs": "Rust", ".go": "Go", ".S": "Assembly"}

#: `arch_baseline.json` is a SEPARATE matrix from `baseline.json`: the same
#: per-function execution-differential verdicts, but across six cross-compiled
#: targets at two optimisation levels rather than the two host compilers. It
#: covers 206 fixtures x 12 lanes. A gallery that reads only `baseline.json`
#: shows the host lanes and silently omits every architecture, which is what the
#: first version of this script did.
ARCH_BASELINE = ROOT / "tests/decompiler_fixtures/arch_baseline.json"

#: Named slices from `tests/decompiler_fixtures/sets.toml` -- the corpus's own
#: taxonomy, with descriptions written by whoever added each set. Far better
#: than any grouping inferred from the fixture numbers, which are
#: chronological-by-addition.
SETS = ROOT / "tests/decompiler_fixtures/sets.toml"

#: A fixture's header comment states which recovery problem it isolates and why
#: existing fixtures do not cover it. That is the page's prose, already written
#: by whoever built the fixture -- far better than anything generated.
#: The block comment is usually first, but often sits just after the `#include`
#: lines -- `102_duffs_device.c` and `212_loop_with_returning_arm.c` both do.
#: Anchoring at position 0 silently dropped the prose for those, so search the
#: head of the file instead and take the first substantial comment.
C_HEADER = re.compile(r"/\*(.*?)\*/", re.S)
RUST_HEADER = re.compile(r"\A((?:\s*//!.*\n)+)")


#: Thematic bands. The fixture numbers are chronological-by-addition rather than
#: a difficulty curve, but they were added in runs, so the ranges do carry
#: meaning -- 15-40 is the data-structures run, 132-139 the C++ object model,
#: 182-219 the ABI and codegen edges found while chasing DecBench cells. Every
#: band below was read against its actual contents, not assumed from the range.
#: Language wins over number: 218 is a C++ fixture inside the ABI run, 219 a
#: Rust one.
BANDS = [
    (1, 14, "Control flow and calls"),
    (15, 40, "Data structures and algorithms"),
    (41, 53, "Strings, encoding, hashing"),
    (54, 80, "Numeric and domain code"),
    (81, 131, "C language semantics"),
    (140, 150, "Runtime and obfuscation"),
    (151, 165, "Scale, linkage, wire formats"),
    (172, 181, "Floating point"),
    (182, 220, "ABI and codegen edges"),
]


def band_of(number: str | None, language: str) -> str:
    """The group a fixture belongs to, language first."""
    if language == "Rust":
        return "Rust"
    if language == "C++":
        return "C++ object model"
    if not number or not number.isdigit():
        return "Other"
    n = int(number)
    for lo, hi, name in BANDS:
        if lo <= n <= hi:
            return name
    return "Other"


def header_prose(text: str, suffix: str) -> str:
    """The fixture's own explanation of what it isolates, as plain paragraphs."""
    if suffix == ".rs":
        m = RUST_HEADER.match(text)
        if not m:
            return ""
        body = "\n".join(
            l.strip().removeprefix("//!").strip() for l in m.group(1).splitlines()
        )
    else:
        head = "\n".join(text.splitlines()[:60])
        m = next(
            (c for c in C_HEADER.finditer(head) if len(c.group(1)) > 80),
            None,
        )
        if not m:
            return ""
        body = "\n".join(
            re.sub(r"^\s*\*ractical?", "", l).strip().lstrip("*").strip()
            for l in m.group(1).splitlines()
        )
    # The first line is usually just the filename; drop it when so.
    lines = [l for l in body.splitlines()]
    while lines and (not lines[0] or lines[0].endswith((".c", ".cpp", ".rs"))):
        lines.pop(0)
    return "\n".join(lines).strip()


def decompile(binary: Path, func: str) -> str | None:
    """One function's recovered C, or None when the tool produced nothing."""
    done = subprocess.run(
        [
            "glaurung",
            "decompile",
            str(binary),
            "--func",
            func,
            "--style",
            "decbench",
            "--no-color",
        ],
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
        cwd=ROOT,
    )
    if done.returncode != 0 or not done.stdout.strip():
        return None
    return done.stdout.rstrip("\n")


def load_sets() -> tuple[list[dict], dict[str, list[str]]]:
    """`sets.toml` as (set metadata, fixture -> set names).

    These are the corpus's own named slices, each with a description written by
    whoever added it. Wildcard selectors (`*:gcc:O0`, `187_*`) are skipped for
    membership: a set that names every fixture describes a lane, not a subject.
    """
    if not SETS.exists():
        return [], {}
    raw = tomllib.loads(SETS.read_text())
    meta, by_fixture = [], {}
    for name, body in sorted(raw.items()):
        selectors = body.get("selectors", []) or []
        stems = sorted(
            {
                s.split(":")[0]
                for s in selectors
                if not s.startswith("@") and "*" not in s.split(":")[0]
            }
        )
        meta.append(
            {
                "name": name,
                "description": body.get("description", ""),
                "fixtures": stems,
                "kind": "curriculum" if name.startswith("curriculum") else "capability",
            }
        )
        for stem in stems:
            by_fixture.setdefault(stem, []).append(name)
    return meta, by_fixture


def build_fixture(args: tuple[str, dict, dict, dict, dict]) -> dict | None:
    stem, baseline, structural, arch, sets_by_fixture = args
    source_path = next(
        (SRC / f"{stem}{s}" for s in TOOLCHAINS if (SRC / f"{stem}{s}").exists()), None
    )
    if source_path is None:
        return None
    text = source_path.read_text(errors="replace")
    lanes = []
    for tc in TOOLCHAINS[source_path.suffix]:
        for opt in OPTS:
            key = f"{stem}:{tc}:{opt}"
            verdicts = baseline.get(key)
            if not isinstance(verdicts, dict):
                continue
            binary = BUILD / f"{stem}-{tc}-{opt}.so"
            if not binary.exists():
                continue
            functions = []
            for fn, verdict in sorted(verdicts.items()):
                if not isinstance(verdict, str):
                    continue
                code = decompile(binary, fn)
                functions.append(
                    {
                        "name": fn,
                        "verdict": verdict,
                        "code": code,
                        "lines": len(code.splitlines()) if code else 0,
                    }
                )
            passed = sum(1 for f in functions if f["verdict"] == "pass")
            lanes.append(
                {
                    "toolchain": tc,
                    "opt": opt,
                    "id": f"{tc}-{opt}",
                    "binary": binary.name,
                    "functions": functions,
                    "passed": passed,
                    "total": len(functions),
                }
            )
    # The cross-compiled matrix. `tools/arch_roundtrip.py` builds these into a
    # temporary directory and leaves nothing behind, so there is no binary here
    # to decompile -- the verdicts are the artifact. Recording them without the
    # code is honest and still answers "does this shape survive on AArch64".
    arch_lanes = []
    for key, verdicts in sorted(arch.items()):
        if not key.startswith(f"{stem}:") or not isinstance(verdicts, dict):
            continue
        _, target, opt = key.split(":", 2)
        fns = {k: v for k, v in verdicts.items() if isinstance(v, str)}
        if not fns:
            continue
        arch_lanes.append(
            {
                "target": target,
                "opt": opt,
                "id": f"{target}-{opt}",
                "passed": sum(1 for v in fns.values() if v == "pass"),
                "total": len(fns),
                "functions": [
                    {"name": k, "verdict": v} for k, v in sorted(fns.items())
                ],
            }
        )

    if not lanes and not arch_lanes:
        return None
    all_fns = sorted({f["name"] for l in lanes for f in l["functions"]})
    total = sum(l["total"] for l in lanes)
    passed = sum(l["passed"] for l in lanes)
    number = stem.split("_", 1)[0] if stem[0].isdigit() else None
    language = LANGUAGES[source_path.suffix]
    # How much C the fixture makes the decompiler produce, summed over lanes.
    # A size proxy, not a difficulty one -- difficulty is the pass rate.
    recovered_lines = sum(f["lines"] for l in lanes for f in l["functions"])
    return {
        "stem": stem,
        "group": band_of(number, language),
        "recovered_lines": recovered_lines,
        "source_lines": len(text.splitlines()),
        "title": stem.split("_", 1)[1].replace("_", " ") if "_" in stem else stem,
        "number": number,
        "language": language,
        "source_file": source_path.name,
        "source": text,
        "prose": header_prose(text, source_path.suffix),
        "functions": all_fns,
        "lanes": lanes,
        "passed": passed,
        "total": total,
        "arch_lanes": arch_lanes,
        "arch_passed": sum(l["passed"] for l in arch_lanes),
        "arch_total": sum(l["total"] for l in arch_lanes),
        "sets": sets_by_fixture.get(stem, []),
        "structural": {
            k.split(":", 1)[1]: v
            for k, v in structural.get("closure", {}).items()
            if k.startswith(f"{stem}:")
        },
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--only", nargs="*", help="fixture stems to build (default: all)")
    ap.add_argument("--jobs", type=int, default=8)
    args = ap.parse_args()

    baseline = json.loads(BASELINE.read_text())
    structural = json.loads(STRUCTURAL.read_text()) if STRUCTURAL.exists() else {}
    arch = json.loads(ARCH_BASELINE.read_text()) if ARCH_BASELINE.exists() else {}
    set_meta, sets_by_fixture = load_sets()
    # Union of both matrices: a fixture present only in the arch baseline still
    # gets a page.
    stems = sorted(
        {k.split(":")[0] for k in baseline if ":" in k}
        | {k.split(":")[0] for k in arch if ":" in k}
    )
    if args.only:
        stems = [s for s in stems if s in set(args.only)]

    args.out.mkdir(parents=True, exist_ok=True)
    print(f"{len(stems)} fixtures, {args.jobs} workers", flush=True)

    index, done_n = [], 0
    payload = [(s, baseline, structural, arch, sets_by_fixture) for s in stems]
    with ProcessPoolExecutor(max_workers=args.jobs) as ex:
        for fixture in ex.map(build_fixture, payload):
            done_n += 1
            if fixture is None:
                continue
            (args.out / f"{fixture['stem']}.json").write_text(
                json.dumps(fixture, indent=1)
            )
            index.append(
                {
                    k: fixture[k]
                    for k in (
                        "stem",
                        "title",
                        "number",
                        "language",
                        "passed",
                        "total",
                        "group",
                        "recovered_lines",
                        "source_lines",
                    )
                }
                | {
                    "functions": len(fixture["functions"]),
                    "lanes": len(fixture["lanes"]),
                }
            )
            if done_n % 25 == 0:
                print(f"  {done_n}/{len(stems)}", flush=True)

    index.sort(key=lambda f: f["stem"])
    grand_total = sum(f["total"] for f in index)
    grand_pass = sum(f["passed"] for f in index)
    (args.out / "index.json").write_text(
        json.dumps(
            {
                "fixtures": index,
                "counts": {
                    "fixtures": len(index),
                    "function_lanes": grand_total,
                    "passing": grand_pass,
                    "rate": round(100.0 * grand_pass / grand_total, 1)
                    if grand_total
                    else 0.0,
                },
                "sets": set_meta,
                "source": {
                    "baseline": "tests/decompiler_fixtures/baseline.json",
                    "arch_baseline": "tests/decompiler_fixtures/arch_baseline.json",
                    "sets": "tests/decompiler_fixtures/sets.toml",
                    "commit": subprocess.run(
                        ["git", "rev-parse", "--short=8", "HEAD"],
                        capture_output=True,
                        text=True,
                        cwd=ROOT,
                    ).stdout.strip(),
                },
            },
            indent=1,
        )
    )
    print(f"\n{len(index)} fixtures -> {args.out}")
    print(
        f"{grand_pass:,} of {grand_total:,} function-lanes pass ({100.0 * grand_pass / grand_total:.1f}%)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
