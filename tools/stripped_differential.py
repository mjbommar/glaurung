#!/usr/bin/env python3
"""The stripped lane: decompile the SAME compile with the debug info removed, and
diff the verdicts against the `-g` build's.

Every lane in `tests/decompiler_fixtures/` compiles with `-g`, unconditionally
(`fixture_harness.compile_fixture`). The whole corpus is therefore blind to any
defect that only appears without debug info — which is the configuration real
targets ship in, and the configuration where the decompiler has to work hardest,
because function extents, prototypes and types come from analysis instead of
being handed over. A landing-pad ownership defect fixed in `965f8585` rejected
74% of the LSDA sites in libstdc++ and emitted C containing dangling `goto`s, and
not one of the corpus's lanes could see it: `-O0` masks it, and `-O2 -g` masks it
because `apply_dwarf_overrides` hands the function a wide DWARF range.

WHY A DIFFERENTIAL AND NOT A PASS/FAIL LANE
-------------------------------------------
For a correct decompiler, debug info should improve NAMING and never STRUCTURE.
So the interesting quantity is not "does the stripped cell pass" — most of the
corpus's known failures fail with `-g` too, and a standalone stripped baseline
would record them a second time and call it coverage. The interesting quantity is
the DIFFERENCE:

  * `pass` with `-g`, not `pass` stripped  -> a REGRESSION, and one that arrives
    with its own control already attached. The same source, the same compiler,
    the same flags, the same addresses; the only variable removed is the debug
    info, so the defect is in what analysis had to infer.
  * not `pass` in both                     -> pre-existing. This lane did not
    find it and does not claim it.
  * `pass` stripped, not `pass` with `-g`  -> an IMPROVEMENT, reported because a
    verdict that moves in this direction usually means a DWARF override is
    injecting something wrong, not that blindness helps.

The `-g` control is read from the committed `baseline.json` rather than re-run.
That halves the cost and is not a shortcut: `fixture:cc:O2` is the identical
compile of the identical source, and it is already gated by
`python/tests/test_decompiler_fixture_matrix.py`, so re-running it here would
measure the same thing twice.

  tools/stripped_differential.py                    # whole corpus, report
  tools/stripped_differential.py --fixture 10_cpp_runtime_shapes
  tools/stripped_differential.py --explain          # + why each divergence
  tools/stripped_differential.py --write-divergences

Exit status: 0 when every divergence is already recorded in
`stripped_divergences.json`, 1 when a NEW one appeared or a recorded one vanished,
2 on an infrastructure problem (a lane error, or a cell with no `-g` control).
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "decompiler_fixtures"
BASELINE = FIXTURES / "baseline.json"
#: Divergences already known and accepted. Deliberately NOT named `*baseline*`:
#: it is not a record of what the stripped lane produced, it is the (much
#: smaller) list of cells where stripped and `-g` disagree. A cell drops out of
#: this file when the defect is fixed, and the gate fails if one drops out
#: silently.
DIVERGENCES = FIXTURES / "stripped_divergences.json"

sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(FIXTURES))
import build_guard as BG  # ty: ignore[unresolved-import]

if __name__ == "__main__":
    BG.reexec_with_repo_python()

import fixture_harness as H  # noqa: E402
import manifest as M  # ty: ignore[unresolved-import]  # noqa: E402

#: How a (fixture, cc, opt, func) cell's two verdicts relate.
REGRESSION = "regression"
IMPROVEMENT = "improvement"
CHANGED = "changed"


def classify(debug_status: str, stripped_status: str) -> str | None:
    """`None` when the two verdicts agree, else which kind of divergence."""
    if debug_status == stripped_status:
        return None
    if debug_status == "pass":
        return REGRESSION
    if stripped_status == "pass":
        return IMPROVEMENT
    return CHANGED


def fixture_sources() -> dict[str, Path]:
    return {src.stem: src for src in H.fixture_sources()}


def planned_lanes(fixtures: list[str] | None) -> list[tuple[str, str, str]]:
    """`(fixture, cc, opt)` for every stripped lane in scope."""
    sources = fixture_sources()
    names = sorted(sources) if fixtures is None else sorted(fixtures)
    plan = []
    for name in names:
        src = sources.get(name)
        if src is None:
            raise FileNotFoundError(f"no fixture source for {name!r}")
        for cc, opt in H.stripped_lanes_for(src):
            plan.append((name, cc, opt))
    return plan


def compare(stripped: dict, baseline: dict) -> tuple[dict, list[str]]:
    """Divergences keyed `fixture:cc:opt:func`, plus infrastructure problems.

    A stripped cell with no `-g` control is an infrastructure problem and never a
    finding: without the control the lane cannot say whether the debug info was
    load-bearing, which is the only question it is here to answer.
    """
    found: dict[str, dict] = {}
    problems: list[str] = []
    for lane, funcs in sorted(stripped.items()):
        if lane == H.TOOLCHAIN_KEY:
            continue
        if "__lane__" in funcs:
            if funcs["__lane__"] != "env-missing":
                problems.append(f"{lane}: lane error ({funcs['__lane__']})")
            continue
        fixture, cc, opt = lane.split(":")
        base_opt, _ = H.split_opt(opt)
        control_lane = f"{fixture}:{cc}:{base_opt}"
        control = baseline.get(control_lane)
        if control is None:
            problems.append(f"{lane}: no `-g` control lane {control_lane} in baseline")
            continue
        if "__lane__" in control:
            if control["__lane__"] != "env-missing":
                problems.append(f"{lane}: control {control_lane} is a lane error")
            continue
        for func, status in sorted(funcs.items()):
            control_status = control.get(func)
            if control_status is None:
                problems.append(f"{lane}:{func}: no `-g` control verdict")
                continue
            kind = classify(control_status, status)
            if kind is not None:
                found[f"{lane}:{func}"] = {
                    "kind": kind,
                    "debug": control_status,
                    "stripped": status,
                }
    return found, problems


def ratchet(found: dict, recorded: dict) -> tuple[list[str], list[str]]:
    """`(new, healed)` — divergences this run found that are not recorded, and
    recorded ones that no longer diverge (or now diverge differently)."""
    new = [
        cell
        for cell, d in sorted(found.items())
        if recorded.get(cell, {}).get("stripped") != d["stripped"]
        or recorded.get(cell, {}).get("debug") != d["debug"]
    ]
    healed = [cell for cell in sorted(recorded) if cell not in found]
    return new, healed


def explain(cell: str) -> str:
    """Re-run one diverging function on both sides and return the two details.

    A second pass over the divergences only. `_run_lane` returns statuses because
    that is what a baseline records; a REPORT wants the reason, and running
    `diff_decompile` again for the handful of cells that actually diverged is far
    cheaper than widening the shared path every lane goes through.
    """
    fixture, cc, opt, func = cell.split(":")
    base_opt, _ = H.split_opt(opt)
    src = fixture_sources()[fixture]
    out = []
    for lane_opt in (base_opt, opt):
        so, err = H.compile_fixture(src, cc, lane_opt)
        if so is None:
            out.append(f"{lane_opt}: compile failed: {err}")
            continue
        cmd = [
            BG.python_bin(),
            str(ROOT / "tools" / "diff_decompile.py"),
            str(so),
            str(src),
            "--fixture",
            fixture,
            "--function",
            func,
            "--json",
        ]
        if H.split_opt(lane_opt)[1]:
            cmd += ["--dwarf-so", str(H.dwarf_sibling(so))]
        r = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=3600,
            check=False,
            env=BG.export_bin_to_path(),
        )
        try:
            payload = json.loads(r.stdout)
        except json.JSONDecodeError:
            out.append(f"{lane_opt}: gate crashed: {r.stderr.strip()[-200:]}")
            continue
        entry = payload.get(func) or payload
        out.append(
            f"{lane_opt}: {entry.get('status', '?')}: {entry.get('detail', '?')}"
        )
    return "\n      ".join(out)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--fixture", action="append", default=None)
    ap.add_argument("--fuzz", type=int, default=M.FIXTURE_FUZZ)
    ap.add_argument("--jobs", type=int, default=None)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--explain", action="store_true")
    ap.add_argument("--write-divergences", action="store_true")
    args = ap.parse_args()

    if not BASELINE.is_file():
        print(f"no {BASELINE} — the `-g` control is required", file=sys.stderr)
        return 2
    baseline = json.loads(BASELINE.read_text())
    plan = planned_lanes(args.fixture)
    stripped = H.run_lanes(
        [(fixture, cc, opt, ()) for fixture, cc, opt in plan],
        args.fuzz,
        jobs=args.jobs,
    )
    found, problems = compare(stripped, baseline)
    recorded = json.loads(DIVERGENCES.read_text()) if DIVERGENCES.is_file() else {}

    if args.write_divergences:
        if problems:
            print("REFUSING to write — infrastructure problems:", file=sys.stderr)
            for problem in problems:
                print(f"  {problem}", file=sys.stderr)
            return 2
        DIVERGENCES.write_text(json.dumps(found, indent=2, sort_keys=True) + "\n")
        print(f"wrote {DIVERGENCES} ({len(found)} divergence(s))")
        return 0

    if args.json:
        print(json.dumps({"divergences": found, "problems": problems}, indent=2))
        return 2 if problems else (1 if ratchet(found, recorded)[0] else 0)

    cells = sum(
        len([f for f in funcs if f != "__lane__"]) for funcs in stripped.values()
    )
    print(f"stripped lanes: {len(plan)}   comparable cells: {cells}")
    counts = {REGRESSION: 0, IMPROVEMENT: 0, CHANGED: 0}
    for _cell, divergence in sorted(found.items()):
        counts[divergence["kind"]] += 1
    for kind in (REGRESSION, CHANGED, IMPROVEMENT):
        rows = [(c, d) for c, d in sorted(found.items()) if d["kind"] == kind]
        if not rows:
            continue
        print(f"\n=== {kind.upper()} ({len(rows)}) ===")
        for cell, divergence in rows:
            mark = " " if cell in recorded else "*"
            print(
                f" {mark}{cell:62s}  -g={divergence['debug']:10s} "
                f"stripped={divergence['stripped']}"
            )
            if args.explain:
                print(f"      {explain(cell)}")
    new, healed = ratchet(found, recorded)
    print(
        f"\n=== {counts[REGRESSION]} regression, {counts[CHANGED]} changed, "
        f"{counts[IMPROVEMENT]} improvement; {len(new)} unrecorded (*), "
        f"{len(healed)} recorded-but-gone ==="
    )
    for problem in problems:
        print(f"INFRA {problem}", file=sys.stderr)
    if problems:
        return 2
    return 1 if (new or healed) else 0


if __name__ == "__main__":
    raise SystemExit(main())
