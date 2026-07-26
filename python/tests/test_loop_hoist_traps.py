"""The four loops whose verbose lowering is load-bearing.

Hoisting a loop header above its loop lets constant propagation substitute the initial
value that dominates at the hoist position. When the hoisted expression carries a
loop-carried register, that freezes it and the loop stops making progress. The
`while (1) { pre; if (!cond) break; }` form these four decompile to is therefore not
untidiness to be cleaned up — it is what keeps them correct.

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

import subprocess
import sys
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
        ["nm", "-D", "--defined-only", str(so)], capture_output=True, text=True
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
    )
    return r.stdout


@pytest.mark.parametrize(
    ("fixture", "cc", "opt", "func"),
    TRAPS,
    ids=[f"{f}:{c}:{o}:{fn}" for f, c, o, fn in TRAPS],
)
def test_loop_keeps_its_protective_form(fixture, cc, opt, func):
    """The loop must not be lowered to a bare `while (cond)`.

    A bare `while (cond)` here means the header was hoisted, which freezes a
    loop-carried value. The correct form is `while (1)` with an explicit `break`.
    """
    so = BUILD / f"{fixture}-{cc}-{opt}.so"
    if not so.is_file():
        pytest.skip(f"fixture not built: {so.name} (run the fixture gate first)")
    va = _symbol_va(so, func)
    assert va is not None, f"{func} not exported from {so.name}"

    text = _decompile(so, va)
    assert text.strip(), f"{func}: decompiler produced nothing"

    # The protective form. `while (1)` plus a `break` is what keeps the header inside.
    has_guard = "while (1)" in text and "break;" in text
    assert has_guard, (
        f"{fixture}:{cc}:{opt}:{func} lost its `while (1) {{ ...; if (!cond) break; }}` "
        f"form, so its loop header was hoisted.\n\n"
        f"That freezes a loop-carried value: constant propagation substitutes the "
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
