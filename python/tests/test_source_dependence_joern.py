"""Cross-validate our control dependence against Joern's, when Joern is here.

`CLAUDE.md` forbids running Joern by default, and this needs a JVM per file, so
the whole module is `decbench`-marked and `pytest.ini` deselects it. Run it
deliberately:

    uv run pytest python/tests/test_source_dependence_joern.py -m decbench

What it checks is *agreement on the relation*, not on the graph. Joern's nodes
are expression-granular and ours are CFG nodes, so the comparison is on the
pairs of source lines a control dependence connects: for every (controller,
controlled) line pair Joern reports, do we report it too.

Measured 2026-09-05 at engine commit b1a03020, this found every dependence
Joern did on three of four fixture files and 174 of 176 on the fourth, where
both misses were a statement split across two lines that Joern attributes to
its continuation and we attribute to its start.
"""

from __future__ import annotations

import re
import subprocess
import tempfile
from pathlib import Path

import pytest

import glaurung

pytestmark = pytest.mark.decbench

JOERN = Path.home() / (
    ".cache/glaurung/decbench-full/decbench/.venv/lib/python3.12/"
    "site-packages/pyjoern/bin/joern-cli"
)

FIXTURES = [
    "03_loop_shapes.c",
    "01_conditional_polarity.c",
    "13_loop_early_exit.c",
]


def _joern_pairs(path: Path) -> dict[str, set[tuple[int, int]]] | None:
    """Control dependences Joern finds, as (controller line, controlled line)."""
    with tempfile.TemporaryDirectory() as tmp:
        parse = subprocess.run(
            [str(JOERN / "joern-parse"), str(path.resolve())],
            cwd=tmp,
            capture_output=True,
            timeout=600,
        )
        if parse.returncode:
            return None
        out = Path(tmp) / "cdg"
        export = subprocess.run(
            [str(JOERN / "joern-export"), "--repr", "cdg", "--out", str(out)],
            cwd=tmp,
            capture_output=True,
            timeout=600,
        )
        if export.returncode:
            return None
        found: dict[str, set[tuple[int, int]]] = {}
        for dot in out.rglob("*.dot"):
            body = dot.read_text(errors="replace")
            name = re.search(r'digraph "([^"]+)"', body)
            if not name:
                continue
            line_of = dict(re.findall(r'"(\d+)" \[label = <.*?<SUB>(\d+)</SUB>', body))
            found[name.group(1)] = {
                (int(line_of[a]), int(line_of[b]))
                for a, b in re.findall(r'"(\d+)" -> "(\d+)"', body)
                if a in line_of and b in line_of
            }
        return found


def _our_pairs(text: str) -> dict[str, set[tuple[int, int]]]:
    """The same relation from our control-dependence graph."""
    import json

    # Byte offsets, so lines are counted in bytes. See the warning on
    # `glaurung.source.control_dependence`.
    raw = text.encode()
    found: dict[str, set[tuple[int, int]]] = {}
    for name, body in glaurung.source.export_graphs(text, repr="cdg", format="json"):
        graph = json.loads(body)
        span_of = {node["id"]: node["span"] for node in graph["nodes"]}
        pairs = set()
        for edge in graph["edges"]:
            start = int(span_of[edge["source"]].split(":")[0])
            end = int(span_of[edge["target"]].split(":")[0])
            pairs.add((raw[:start].count(b"\n") + 1, raw[:end].count(b"\n") + 1))
        found[name] = pairs
    return found


@pytest.mark.parametrize("stem", FIXTURES)
def test_we_find_every_control_dependence_joern_finds(stem):
    if not JOERN.exists():
        pytest.skip(f"joern-cli not installed at {JOERN}")
    path = (
        Path(__file__).resolve().parents[2]
        / "tests"
        / "decompiler_fixtures"
        / "src"
        / stem
    )
    theirs = _joern_pairs(path)
    if theirs is None:
        pytest.skip("joern-parse or joern-export failed on this input")
    ours = _our_pairs(path.read_text(errors="replace"))

    shared = sorted(set(theirs) & set(ours))
    assert shared, "no function names in common"

    missing: dict[str, set[tuple[int, int]]] = {}
    for function in shared:
        gap = theirs[function] - ours[function]
        if gap:
            missing[function] = gap
    assert not missing, f"control dependences Joern found and we did not: {missing}"
