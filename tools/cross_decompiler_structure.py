#!/usr/bin/env python3
"""Score Ghidra, angr and our own decompiler against the same fixture source.

WHAT THIS ANSWERS
-----------------
`tools/fixture_structure_census.py` measures how far our recovered C is from the
source it came from. It cannot say whether that distance is *normal*, because
the only other reference in the estate is the null decompiler. This tool adds
external columns: it runs the same control-skeleton projection
(`src/metrics/tree_distance.rs`, via PyO3) over Ghidra's and angr's output on the
same binaries, so every backend is scored by one rule on one denominator.

The findings are written up in
`docs/design/metrics-research/cross-decompiler-structure.md`. Read the warning
there about cross-corpus comparison before quoting any number from a different
corpus: on DecBench's samples Ghidra emits 8.53 goto/function and on our fixtures
it emits 0.065, and the difference is the corpus, not the tool.

USAGE
-----
    export TMPDIR="$HOME/.cache/glaurung/tmp"

    # 1. our column (fast: ~30s for 206 binaries)
    uv run python tools/cross_decompiler_structure.py collect --backend glaurung

    # 2. ghidra, in two steps -- the sweep is external, this assembles it
    #    analyzeHeadless <proj> P -import <so> -scriptPath <dir> \
    #      -postScript DumpCStruct.java <dumpdir>/<stem>.txt -deleteProject -readOnly
    uv run python tools/cross_decompiler_structure.py collect --backend ghidra \
        --ghidra-dumps ~/glaurung-ghidra/dump

    # 3. compare whatever columns exist
    uv run python tools/cross_decompiler_structure.py compare

Columns are JSON, one per backend, under `--out` (default
`$TMPDIR/../structcmp`). The angr column is produced by an external sweep in an
isolated environment (angr is deliberately not a project dependency) and only
needs to match the column schema below.

COLUMN SCHEMA
-------------
    {"backend": str, "lane": "gcc-O0",
     "functions": {fixture_stem: {function_name: "<C text>"}},
     "missing":   {fixture_stem: [function_name, ...]},
     "failed":    {fixture_stem: <error>}}

Only `manifest.REQUIRED_FUNCTIONS` are kept, and foreign C is stored verbatim --
no reformatting, no comment stripping. The point is to measure what the tool
actually produced.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path
from statistics import mean, median

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "tools"))
sys.path.insert(0, str(REPO / "tests/decompiler_fixtures"))

LANE = "gcc-O0"
BUILD = REPO / "tests/decompiler_fixtures/build/build.aside"
SRC = REPO / "tests/decompiler_fixtures/src"
NULL_C = "int glaurung_null_decompiler(void) { return 0; }"

#: `DumpCStruct.java`'s delimiters. A per-function marker rather than one blob,
#: so a function Ghidra failed on is recorded as a failure and never silently
#: merged into its neighbour's body.
GHIDRA_START = "@@@GLAURUNG_FUNC_START@@@"
GHIDRA_END = "@@@GLAURUNG_FUNC_END@@@"
GHIDRA_FAILED = "@@@GLAURUNG_FUNC_FAILED@@@"

KEYWORDS = ("goto", "continue", "break", "switch", "do", "while")


def default_out() -> Path:
    """Where columns live: beside the cache, never inside the repo."""
    return Path.home() / ".cache/glaurung/structcmp"


def required_functions() -> dict[str, list[str]]:
    """`{fixture stem: [required function names]}` from the fixture manifest."""
    import manifest as M  # ty: ignore[unresolved-import]

    return {k: sorted(v) for k, v in M.REQUIRED_FUNCTIONS.items()}


def strip_c(text: str) -> str:
    """Drop comments and string/char literals before counting keywords.

    A `goto` inside a string literal or a comment is not control flow, and
    decompiler output carries a lot of both.
    """
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    text = re.sub(r"//[^\n]*", "", text)
    text = re.sub(r'"(\\.|[^"\\])*"', '""', text)
    return re.sub(r"'(\\.|[^'\\])*'", "''", text)


def constructs(text: str) -> dict[str, int]:
    """Control-construct occurrences in one function's C text."""
    text = strip_c(text)
    counts = {k: len(re.findall(rf"\b{k}\b", text)) for k in KEYWORDS}
    counts["?:"] = len(re.findall(r"\?[^;:]{0,80}:", text))
    return counts


def collect_glaurung(out: Path) -> Path:
    """Our own decompiler's C for the lane, via the census tool's CLI wrapper."""
    from fixture_structure_census import decompile_functions  # ty: ignore[unresolved-import]

    wanted = required_functions()
    column: dict[str, object] = {
        "backend": "glaurung",
        "lane": LANE,
        "command": "glaurung decompile <so> --all",
        "functions": {},
        "missing": {},
        "failed": {},
    }
    objects = sorted(BUILD.glob(f"*-{LANE}.so"))
    started = time.time()
    for index, so in enumerate(objects, 1):
        stem = so.name[: -len(f"-{LANE}.so")]
        want = wanted.get(stem, [])
        if not want:
            continue
        try:
            blocks = decompile_functions(so)
        except Exception as error:  # noqa: BLE001 - a refusal is data, not a crash
            column["failed"][stem] = f"{type(error).__name__}: {error}"[:300]
            continue
        got = {name: blocks[name] for name in want if name in blocks}
        if got:
            column["functions"][stem] = got
        missing = [name for name in want if name not in blocks]
        if missing:
            column["missing"][stem] = missing
        if index % 50 == 0:
            print(f"  {index}/{len(objects)}  {time.time() - started:.0f}s", flush=True)
    return write_column(out, column, started)


def parse_ghidra_dump(text: str) -> tuple[dict[str, str], dict[str, str]]:
    """Split one `DumpCStruct.java` dump into functions and per-function failures."""
    functions: dict[str, str] = {}
    failures: dict[str, str] = {}
    current: str | None = None
    body: list[str] = []
    for line in text.splitlines():
        if line.startswith(GHIDRA_START):
            current, body = line[len(GHIDRA_START) :].strip(), []
        elif line.startswith(GHIDRA_END):
            if current is not None:
                functions[current] = "\n".join(body)
            current, body = None, []
        elif line.startswith(GHIDRA_FAILED):
            name, _, reason = line[len(GHIDRA_FAILED) :].partition("@@@")
            failures[name.strip()] = reason.strip()
        elif current is not None:
            body.append(line)
    return functions, failures


def collect_ghidra(out: Path, dumps: Path) -> Path:
    """Assemble an external headless Ghidra sweep into a column."""
    wanted = required_functions()
    version = "unknown"
    props = Path("/opt/ghidra/Ghidra/application.properties")
    if props.exists():
        found = re.search(r"application\.version=(.+)", props.read_text())
        if found:
            version = found.group(1).strip()
    column: dict[str, object] = {
        "backend": "ghidra",
        "lane": LANE,
        "ghidra_version": version,
        "command": (
            "analyzeHeadless <proj> P -import <so> -scriptPath <dir> "
            "-postScript DumpCStruct.java <out> -deleteProject -readOnly"
        ),
        "functions": {},
        "missing": {},
        "failed": {},
    }
    started = time.time()
    for dump in sorted(dumps.glob("*.txt")):
        want = wanted.get(dump.stem, [])
        if not want:
            continue
        functions, failures = parse_ghidra_dump(dump.read_text(errors="replace"))
        got = {name: functions[name] for name in want if name in functions}
        if got:
            column["functions"][dump.stem] = got
        missing = [name for name in want if name not in functions]
        if missing:
            column["missing"][dump.stem] = missing
        for name in want:
            if name in failures:
                column["failed"].setdefault(dump.stem, {})[name] = failures[name]
    return write_column(out, column, started)


def write_column(out: Path, column: dict[str, object], started: float) -> Path:
    out.mkdir(parents=True, exist_ok=True)
    path = out / f"{column['backend']}-{LANE}.json"
    path.write_text(json.dumps(column))
    functions = sum(len(v) for v in column["functions"].values())  # ty: ignore[possibly-unbound-attribute]
    missing = sum(len(v) for v in column["missing"].values())  # ty: ignore[possibly-unbound-attribute]
    print(
        f"{column['backend']}: fixtures={len(column['functions'])} "  # ty: ignore[possibly-unbound-attribute]
        f"functions={functions} missing={missing} failed={len(column['failed'])} "  # ty: ignore[possibly-unbound-attribute]
        f"wall={time.time() - started:.0f}s -> {path}"
    )
    return path


def compare(out: Path) -> int:
    """Score every column present against source, on their shared functions."""
    from glaurung._native import metrics  # ty: ignore[unresolved-import]

    source = {}
    for path in sorted(SRC.glob("*.c")):
        try:
            source[path.stem] = metrics.skeletons(path.read_text(errors="replace"))
        except Exception:  # noqa: BLE001 - a fixture we cannot parse is simply absent
            continue

    columns = {}
    for path in sorted(out.glob(f"*-{LANE}.json")):
        column = json.loads(path.read_text())
        columns[column["backend"]] = column
    if not columns:
        print(f"no columns under {out}", file=sys.stderr)
        return 1

    keysets = [
        {
            (stem, name)
            for stem, names in column["functions"].items()
            for name in names
            if stem in source and name in source[stem]
        }
        for column in columns.values()
    ]
    shared = sorted(set.intersection(*keysets))
    print(f"backends: {', '.join(sorted(columns))}")
    print(f"shared functions (in every column and in source): {len(shared)}\n")

    rows = []
    for backend, column in sorted(columns.items()):
        distances, exact, unparsed = [], 0, 0
        counts = {k: 0 for k in (*KEYWORDS, "?:")}
        for stem, name in shared:
            text = column["functions"][stem][name]
            for key, value in constructs(text).items():
                counts[key] += value
            skeleton = metrics.skeletons(text)
            if name not in skeleton:
                unparsed += 1
                continue
            distance = metrics.tree_edit_distance(source[stem][name], skeleton[name])
            if distance is None:
                unparsed += 1
                continue
            distances.append(distance)
            exact += distance == 0
        rows.append((backend, exact, distances, unparsed, counts))

    null = metrics.skeletons(NULL_C)["glaurung_null_decompiler"]
    null_distances = [
        d
        for stem, name in shared
        if (d := metrics.tree_edit_distance(source[stem][name], null)) is not None
    ]
    rows.append(
        (
            "NULL(return 0)",
            sum(1 for d in null_distances if d == 0),
            null_distances,
            0,
            {k: 0 for k in (*KEYWORDS, "?:")},
        )
    )

    n = len(shared)
    print(
        f"{'backend':16s} {'exact':>6s} {'exact%':>7s} {'median':>7s} {'mean':>7s} {'unparsed':>9s}"
    )
    print("-" * 60)
    # Median first: this population has a few functions with distances in the
    # thousands, and they move the mean by several points on their own.
    for backend, exact, distances, unparsed, _ in sorted(rows, key=lambda r: -r[1]):
        print(
            f"{backend:16s} {exact:6d} {100 * exact / max(n, 1):6.1f}% "
            f"{median(distances) if distances else 0:7.1f} "
            f"{mean(distances) if distances else 0:7.2f} {unparsed:9d}"
        )

    header = (*KEYWORDS, "?:")
    print(f"\nconstructs per function, same {n} functions")
    print(f"{'backend':16s} " + " ".join(f"{h:>9s}" for h in header))
    print("-" * 84)
    for backend, _, _, _, counts in rows:
        if backend.startswith("NULL"):
            continue
        print(
            f"{backend:16s} "
            + " ".join(f"{counts[h] / max(n, 1):9.3f}" for h in header)
        )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("mode", choices=("collect", "compare"))
    parser.add_argument("--backend", choices=("glaurung", "ghidra"))
    parser.add_argument(
        "--ghidra-dumps", type=Path, help="directory of DumpCStruct.java output"
    )
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args(argv)
    out = args.out or default_out()

    if args.mode == "compare":
        return compare(out)
    if args.backend == "glaurung":
        collect_glaurung(out)
        return 0
    if args.backend == "ghidra":
        if not args.ghidra_dumps or not args.ghidra_dumps.is_dir():
            parser.error("--backend ghidra needs --ghidra-dumps <dir>")
        collect_ghidra(out, args.ghidra_dumps)
        return 0
    parser.error("collect needs --backend")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
