#!/usr/bin/env python3
"""Build realistic binaries — stripped, section-header-less, packed — from our own sources.

Every fixture in `tests/decompiler_fixtures/src/` is compiled as a translation
unit with no `main`, which is the right shape for the execution differential but
the wrong shape for whole-binary analysis: there is no entry point, no PLT, no
dynamic segment, and nothing for a packer to pack. This module links a chosen
spread of those fixtures against a *generated* driver to produce a real, running
executable, and then applies the post-processing a real-world binary has already
been through by the time an analyst sees it.

**Nothing here copies a system binary.** The corpus is our own C, compiled here,
and the ground-truth function list is the driver's own address table — so recall
is measured against a set we constructed rather than one we inferred.

The variants, in increasing order of hostility:

``dwarf``
    ``-O2 -g``. Full ``.symtab`` and DWARF. The control.
``strip``
    ``strip --strip-all``. ``.symtab`` and DWARF gone, ``.dynsym`` and the
    section header table remain. This is what `O2strip` in the fixture harness
    already covers.
``sstrip``
    ``strip --strip-all`` then ``sstrip``: the section header table itself is
    removed (``e_shnum`` 30 -> 0). **The executable bytes are unchanged** — only
    metadata that a loader never reads is gone, so anything that regresses here
    regressed because it was reading section headers rather than program
    headers. Routine in real stripped malware.
``upx``
    ``upx -9`` over the stripped build: one compressed blob plus a decompressor
    stub, and ``e_shnum`` is 0 here too.
``upxg``
    ``upx -9`` over the *unstripped* build, which keeps more of the original
    intact and separates "packed" from "stripped" as independent axes.

Build products land in a gitignored cache; the committed artifacts are this
file, the spec below, and the baseline the tests compare against. Toolchain
versions are recorded in the manifest because `upx` and `gcc` output move
between releases, and a recall number measured under a different packer is not
comparable to one measured under this packer.
"""

from __future__ import annotations

import scratch  # noqa: F401  -- points TMPDIR off the shared /tmp tmpfs on import
import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "tests" / "decompiler_fixtures" / "src"
BUILD = ROOT / "tests" / "realistic_corpus" / "build"
MANIFEST = BUILD / "manifest.json"

#: The fixtures linked into the corpus. Chosen for spread rather than size: the
#: obfuscation family (145-150) is the part most likely to interact badly with
#: stripping, and the rest supply ordinary control flow, aggregates and string
#: handling so that a regression in the hostile lanes can be told apart from a
#: regression in everything.
SPEC: tuple[str, ...] = (
    "145_control_flow_flattening",
    "146_opaque_predicates",
    "148_dispatch_obfuscation",
    "150_obfuscation_composite",
    "03_loop_shapes",
    "04_switch_shapes",
    "02_integer_widths",
    "24_merge_sort",
    "20_graph_bfs",
    "07_packet_parser",
)

#: Variant name -> the post-processing applied after `-O2 -g` compilation.
VARIANTS: tuple[str, ...] = ("dwarf", "strip", "sstrip", "upx", "upxg")

#: Tools whose version changes the bytes we produce, so a recall number taken
#: under one version is not comparable to one taken under another.
VERSIONED_TOOLS: tuple[str, ...] = ("gcc", "strip", "sstrip", "upx")


class CorpusError(RuntimeError):
    """A corpus build step failed in a way the caller cannot work around."""


def _run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def missing_tools() -> list[str]:
    """Which of the tools this module needs are not on PATH."""
    return [t for t in VERSIONED_TOOLS if shutil.which(t) is None]


def tool_versions() -> dict[str, str]:
    """First version line of each tool, for the manifest."""
    out: dict[str, str] = {}
    for tool in VERSIONED_TOOLS:
        if shutil.which(tool) is None:
            out[tool] = "MISSING"
            continue
        r = _run([tool, "--version"])
        out[tool] = (
            (r.stdout or r.stderr).splitlines()[0].strip()
            if (r.stdout or r.stderr)
            else "?"
        )
    return out


def _compile_objects(build: Path) -> list[Path]:
    """Compile each spec fixture to an object file, failing loudly on the first error."""
    objs: list[Path] = []
    for stem in SPEC:
        src = SRC / f"{stem}.c"
        if not src.exists():
            raise CorpusError(f"spec names {stem} but {src} does not exist")
        obj = build / f"{stem}.o"
        r = _run(["gcc", "-O2", "-g", "-c", "-o", str(obj), str(src)])
        if r.returncode != 0:
            raise CorpusError(f"compiling {stem}: {r.stderr.strip()[-400:]}")
        objs.append(obj)
    return objs


def _global_text_symbols(objs: list[Path]) -> list[str]:
    """The `T` symbols across the objects — our ground truth, sorted for determinism."""
    r = _run(["nm", "--defined-only", *[str(o) for o in objs]])
    if r.returncode != 0:
        raise CorpusError(f"nm failed: {r.stderr.strip()[-400:]}")
    names = {
        parts[2]
        for line in r.stdout.splitlines()
        if len(parts := line.split()) == 3 and parts[1] == "T"
    }
    return sorted(names)


def _driver_source(symbols: list[str]) -> str:
    """A `main` that takes the address of every corpus function.

    Addresses only — never a call — so the declarations do not have to match the
    real prototypes, while the reference still stops the linker from garbage
    collecting the function and keeps the entry point genuinely reachable.
    """
    externs = "\n".join(f"extern void {s}(void);" for s in symbols)
    entries = "\n".join(f"    (void *)&{s}," for s in symbols)
    return f"""/* GENERATED by tools/realistic_corpus.py — do not edit. */
#include <stdio.h>

{externs}

static void *const table[] = {{
{entries}
}};

int main(int argc, char **argv) {{
    unsigned long acc = 0;
    for (unsigned i = 0; i < sizeof(table) / sizeof(table[0]); i++)
        acc += (unsigned long)table[i];
    printf("glaurung-corpus %u entries acc=%lx argc=%d\\n",
           (unsigned)(sizeof(table) / sizeof(table[0])), acc, argc);
    return 0;
}}
"""


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _runs(path: Path) -> bool:
    """A variant that does not execute is not evidence about anything."""
    try:
        r = _run([str(path)], timeout=30)
    except (OSError, subprocess.SubprocessError):
        return False
    return r.returncode == 0 and "glaurung-corpus" in r.stdout


def build(force: bool = False) -> dict:
    """Build every variant and return the manifest.

    Args:
        force: Rebuild even if a manifest already exists.

    Returns:
        The manifest: ground-truth symbols, per-variant sha256/size/runs, and
        the toolchain versions the bytes depend on.
    """
    if missing := missing_tools():
        raise CorpusError(
            f"missing required tools: {', '.join(missing)}. "
            "Install with: sudo apt-get install -y upx-ucl elfkickers"
        )
    if MANIFEST.exists() and not force:
        return json.loads(MANIFEST.read_text())

    BUILD.mkdir(parents=True, exist_ok=True)
    objs = _compile_objects(BUILD)
    symbols = _global_text_symbols(objs)
    if not symbols:
        raise CorpusError("no global text symbols across the spec objects")

    driver = BUILD / "driver.c"
    driver.write_text(_driver_source(symbols))

    dwarf = BUILD / "corpus.dwarf"
    r = _run(
        ["gcc", "-O2", "-g", "-o", str(dwarf), str(driver), *[str(o) for o in objs]]
    )
    if r.returncode != 0:
        raise CorpusError(f"linking corpus: {r.stderr.strip()[-600:]}")

    stripped = BUILD / "corpus.strip"
    shutil.copy2(dwarf, stripped)
    _run(["strip", "--strip-all", str(stripped)])

    sstripped = BUILD / "corpus.sstrip"
    shutil.copy2(stripped, sstripped)
    _run(["sstrip", str(sstripped)])

    for name, base in (("upx", stripped), ("upxg", dwarf)):
        packed = BUILD / f"corpus.{name}"
        shutil.copy2(base, packed)
        r = _run(["upx", "-9", "-q", "-f", str(packed)])
        if r.returncode != 0:
            raise CorpusError(
                f"packing {name}: {(r.stderr or r.stdout).strip()[-400:]}"
            )

    manifest = {
        "schema": 1,
        "spec": list(SPEC),
        "ground_truth": symbols,
        "toolchain": tool_versions(),
        "variants": {},
    }
    for v in VARIANTS:
        p = BUILD / f"corpus.{v}"
        manifest["variants"][v] = {
            "sha256": _sha256(p),
            "size": p.stat().st_size,
            "runs": _runs(p),
        }
    MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


def variant_path(name: str) -> Path:
    """Path to one built variant, building the corpus first if needed."""
    if name not in VARIANTS:
        raise CorpusError(f"unknown variant {name!r}; known: {', '.join(VARIANTS)}")
    build()
    return BUILD / f"corpus.{name}"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--force", action="store_true", help="rebuild even if cached")
    ap.add_argument("--json", action="store_true", help="print the manifest as JSON")
    args = ap.parse_args(argv)

    if missing := missing_tools():
        print(f"missing tools: {', '.join(missing)}", file=sys.stderr)
        print("install: sudo apt-get install -y upx-ucl elfkickers", file=sys.stderr)
        return 1

    m = build(force=args.force)
    if args.json:
        print(json.dumps(m, indent=2))
        return 0

    print(
        f"corpus: {len(m['spec'])} fixtures, {len(m['ground_truth'])} ground-truth functions"
    )
    for tool, ver in m["toolchain"].items():
        print(f"  {tool:8s} {ver}")
    print(f"  {'variant':<8} {'size':>9}  {'runs':<5} sha256")
    for v, info in m["variants"].items():
        ok = "YES" if info["runs"] else "NO"
        print(f"  {v:<8} {info['size']:>9}  {ok:<5} {info['sha256'][:16]}")
    if not all(i["runs"] for i in m["variants"].values()):
        print(
            "\nA variant does not execute — it is not evidence about anything.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
