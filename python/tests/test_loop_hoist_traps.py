"""The four loops whose verbose lowering is load-bearing.

Hoisting a loop header above its loop can let constant propagation substitute the
initial value that dominates at the hoist position. When the emitted condition then
reads only that frozen temporary, the loop stops making progress. The conservative
`while (1) { pre; if (!cond) break; }` form is always safe; a source-level `while
(cond)` is safe too when the printed condition directly reads a variable that the
body updates, so C reevaluates the loop-carried dependency on every iteration.

The cost is real and measured, which is why this file exists. On branch
`recover-ged-cells` (docs/design/ged-recovery-measured-trade.md), always-hoisting recovers
**50.32 GED points — 46% of a regression** — and breaks exactly these four functions
across six lanes. Somebody will eventually notice the verbose form, "fix" it, and see the
metric improve. This test is the thing that tells them what it cost.

Four predicates have been tried and all four failed, each in a different direction: a
copy-chain rule, a loop-invariance rule, a use-count rule, and a post-fold check that
required only a nonempty read/write intersection. The last one passes `find_first_set`,
whose body reassigns its flag further down while the frozen value sits inside the hoisted
expression — so a post-fold check must preserve EVERY loop-carried dependency, not one
overlapping register.

Why here and not in the fixture differential: the differential already covers these
functions, but it takes ~8 minutes and reports a wrong ANSWER without saying why. This
runs four decompilations in seconds and names the trap.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
BUILD = ROOT / "tests" / "decompiler_fixtures" / "build"

#: (fixture, compiler, opt, function) — the exact cells that regress under always-hoist.
TRAPS = [
    ("03_loop_shapes", "gcc", "O2", "while_prefix"),
    ("12_loop_rotation", "gcc", "O2", "find_first_set"),
    ("13_loop_early_exit", "gcc", "O2", "classify_run"),
    ("13_loop_early_exit", "clang", "O2", "classify_run"),
    ("14_flag_effects", "gcc", "O0", "countdown"),
    ("14_flag_effects", "clang", "O0", "countdown"),
]


def _symbol_va(so: Path, name: str) -> int | None:
    r = subprocess.run(
        ["nm", "-D", "--defined-only", str(so)],
        capture_output=True,
        text=True,
        check=False,
    )
    for line in r.stdout.splitlines():
        p = line.split()
        if len(p) == 3 and p[1] == "T" and p[2] == name:
            return int(p[0], 16)
    return None


def _decompile(so: Path, va: int) -> str:
    r = subprocess.run(
        ["glaurung", "decompile", str(so), "--vas", hex(va), "--style", "decbench"],
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    return r.stdout


def _condition_reads_a_body_updated_value(text: str) -> bool:
    """Whether a source-level while condition retains a loop-carried value."""
    for match in re.finditer(r"while\s*\(([^\n]*)\)\s*\{", text):
        condition = match.group(1)
        body_start = match.end()
        # The first closing brace is enough for this proof: the relevant update
        # precedes any nested early-exit close in every declared trap.
        body_end = text.find("}", body_start)
        if body_end < 0:
            continue
        body = text[body_start:body_end]
        condition_names = set(re.findall(r"\b[A-Za-z_]\w*\b", condition))
        assigned_names = set(
            re.findall(r"(?m)^\s*([A-Za-z_]\w*)\s*(?:=|\+\+|--)", body)
        )
        if condition_names & assigned_names:
            return True
    return False


@pytest.mark.parametrize(
    ("fixture", "cc", "opt", "func"),
    TRAPS,
    ids=[f"{f}:{c}:{o}:{fn}" for f, c, o, fn in TRAPS],
)
def test_loop_keeps_its_loop_carried_condition(fixture, cc, opt, func):
    """The loop must retain every iteration-dependent condition input.

    Either the protective form keeps the header inside the body, or a recovered
    source-level condition must directly name a value assigned by that body.
    """
    so = BUILD / f"{fixture}-{cc}-{opt}.so"
    if not so.is_file():
        pytest.skip(f"fixture not built: {so.name} (run the fixture gate first)")
    va = _symbol_va(so, func)
    assert va is not None, f"{func} not exported from {so.name}"

    text = _decompile(so, va)
    assert text.strip(), f"{func}: decompiler produced nothing"

    # The protective form keeps the complete machine header inside. A recovered
    # while is equally safe only when it directly rereads a body-updated value;
    # a condition over a pre-loop scratch temporary still fails this test.
    has_guard = "while (1)" in text and "break;" in text
    has_live_condition = _condition_reads_a_body_updated_value(text)
    assert has_guard or has_live_condition, (
        f"{fixture}:{cc}:{opt}:{func} neither retained its protective `while (1)` "
        f"form nor emitted a condition that directly reads a body-updated value.\n\n"
        f"That can freeze a loop-carried value: constant propagation substitutes the "
        f"initial value dominating the hoist position. Always-hoisting is worth 50.32 "
        f"GED points (46% of a regression) and breaks exactly this function plus three "
        f"others — see docs/design/ged-recovery-measured-trade.md. If you are making "
        f"this trade deliberately, update that document and this test together.\n\n"
        f"--- emitted ---\n{text}"
    )


def test_the_trap_is_documented_where_someone_would_look():
    """Each fixture source must carry the explanation next to the function.

    A test failure sends you to the source; the source has to explain why the verbose
    form is deliberate, or the next person re-derives it from scratch. Four people have
    now tried four different predicates on this exact question.
    """
    src = ROOT / "tests" / "decompiler_fixtures" / "src"
    for fixture in sorted({f for f, _, _, _ in TRAPS}):
        path = src / f"{fixture}.c"
        assert path.is_file(), f"missing fixture source: {path}"
        assert "HOIST TRAP" in path.read_text(), (
            f"{fixture}.c has no HOIST TRAP note. The verbose loop form in this file is "
            f"load-bearing and must say so next to the function it protects."
        )
