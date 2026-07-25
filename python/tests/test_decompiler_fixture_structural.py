"""Structural lane: correctness properties the execution gate cannot see.

Some faithfulness properties are not observable by recompiling and calling the
decompilation — control-flow closure across every render style, that an indirect
callback stays an indirect call, that a memory store survives, that no fabricated
`sub_1234()` / `dispatch_<va>` target names are invented, and the C++ vtable/EH
shapes. This lane inspects the decompiled TEXT and compares it to a committed
`structural_baseline.json`, so known-broken output stays visible while any
regression fails closed — and any *improvement* fails too, forcing a baseline
refresh so the gate ratchets upward (it can never silently slide back).

Hard, non-baselined invariants (must always hold):
  * every execution-untestable REQUIRED function carries a structural assertion
    (`gaps` empty) — a `structural` status with nothing executed behind it fails;
  * the DecBench render style is control-flow closed for every function;
  * apply() remains an indirect callback call.

Marked `slow` (builds 10 fixtures + decompiles each in 3 styles); run with -m slow.
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "tests" / "decompiler_fixtures"))
import manifest as M
import structural as S

BASELINE = ROOT / "tests" / "decompiler_fixtures" / "structural_baseline.json"
pytestmark = pytest.mark.slow


def _baseline() -> dict:
    assert BASELINE.is_file(), (
        "structural_baseline.json missing — regenerate with "
        "tools/gen_structural_baseline.py"
    )
    return json.loads(BASELINE.read_text())


@pytest.fixture(scope="session")
def report() -> dict:
    _td = M.tmpdir()
    with tempfile.TemporaryDirectory(**({"dir": _td} if _td else {})) as td:
        return S.structural_report(Path(td))


@pytest.fixture(scope="session")
def baseline() -> dict:
    return _baseline()


# --- hard invariants --------------------------------------------------------

def test_every_structural_only_function_has_an_assertion(report):
    # A function the exec gate can only mark `structural` MUST have a structural
    # assertion — otherwise it is completely untested.
    assert report["gaps"] == [], f"structural-only functions with no assertion: {report['gaps']}"


def test_decbench_output_is_control_flow_closed(report):
    broken = {k: v for k, v in report["closure"].items()
              if k.endswith(":decbench") and v != "closed"}
    assert not broken, f"DecBench render not control-flow closed: {broken}"


def test_apply_remains_an_indirect_callback_call(report):
    got = report["effects"].get("08_indirect_dispatch:apply", {})
    assert got.get("indirect_call") is True, "apply() lost its indirect callback call"


def test_declared_structural_predicates_are_all_present(report):
    # A declared predicate must actually be evaluated (True/False), never absent —
    # a structural assertion that silently does not run is a fail-open gap.
    for key, spec in M.STRUCTURAL.items():
        fkey = f"{key[0]}:{key[1]}"
        got = report["effects"].get(fkey, {})
        for pred in spec:
            assert pred in got, f"predicate {pred} not evaluated for {fkey}"


# --- baseline comparison (fail closed on regression) ------------------------

def _closure_regressed(base: str, cur: str) -> bool:
    if base == cur:
        return False
    if base == "closed" and cur != "closed":
        return True
    return base != "not_emitted" and cur == "not_emitted"


def test_no_structural_regression(report, baseline):
    problems = []
    for k, base in baseline["closure"].items():
        cur = report["closure"].get(k)
        if cur is None:
            problems.append(f"closure {k}: MISSING")
        elif _closure_regressed(base, cur):
            problems.append(f"closure {k}: {base} -> {cur}")
    for k, base in baseline["effects"].items():
        cur = report["effects"].get(k, {})
        for pred, bval in base.items():
            if bval and not cur.get(pred):
                problems.append(f"effect {k}.{pred}: True -> {cur.get(pred)}")
    for k, bval in baseline["placeholder"].items():
        cur = report["placeholder"].get(k)
        if cur is None:
            problems.append(f"placeholder {k}: MISSING")
        elif not bval and cur:
            problems.append(f"placeholder {k}: fabricated name newly introduced")
    # Definition-before-use: known violations stay visible, a NEW one fails. The
    # emitted C reading a value it never produced is real corruption, so this is
    # baselined per function rather than merely logged.
    for k, base in baseline.get("verify", {}).items():
        cur = report["verify"].get(k)
        if cur is None:
            problems.append(f"verify {k}: MISSING")
            continue
        new = sorted(set(cur) - set(base))
        if new:
            problems.append(f"verify {k}: NEW def-before-use violation(s): {new}")
    for k, cur in report["verify"].items():
        if k not in baseline.get("verify", {}) and cur:
            problems.append(f"verify {k}: unrecorded function with violation(s): {cur}")
    assert not problems, "STRUCTURAL REGRESSIONS:\n  " + "\n  ".join(problems)


def test_structural_improvements_require_a_baseline_refresh(report, baseline):
    # Ratchet: an improvement that is not yet recorded must fail, so the baseline
    # is refreshed to lock it in and the function can never regress unnoticed.
    improved = []
    for k, base in baseline["closure"].items():
        cur = report["closure"].get(k)
        if base != "closed" and cur == "closed":
            improved.append(f"closure {k}: now closed")
    for k, base in baseline["effects"].items():
        cur = report["effects"].get(k, {})
        for pred, bval in base.items():
            if not bval and cur.get(pred):
                improved.append(f"effect {k}.{pred}: now True")
    for k, bval in baseline["placeholder"].items():
        if bval and not report["placeholder"].get(k):
            improved.append(f"placeholder {k}: fabricated name now gone")
    for k, base in baseline.get("verify", {}).items():
        fixed = sorted(set(base) - set(report["verify"].get(k, [])))
        if fixed:
            improved.append(f"verify {k}: violation(s) resolved: {fixed}")
    assert not improved, (
        "STRUCTURAL IMPROVEMENTS — refresh structural_baseline.json to ratchet:\n  "
        + "\n  ".join(improved)
    )
