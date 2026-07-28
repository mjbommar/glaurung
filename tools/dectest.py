#!/usr/bin/env python3
"""Run the smallest slice of the decompiler fixture corpus that answers your question.

The gate (`pytest -m slow python/tests/test_decompiler_fixture_matrix.py`) compiles
and executes 56 lanes to tell you whether ANYTHING regressed ANYWHERE. That is the
right cost for a gate and the wrong cost for iterating on one defect: you change
`detect_if_shape`, and finding out what it did to `sum_until_zero` costs minutes.

`dectest` runs the same harness, the same compilers, the same seeded vectors, and
the same baseline comparison — over a selection.

    tools/dectest.py 13_loop_early_exit                  # one fixture, 4 lanes
    tools/dectest.py 13_loop_early_exit:gcc:O0           # one lane
    tools/dectest.py 13_loop_early_exit:gcc:O0:bisect    # one function
    tools/dectest.py '*:clang:O0:ternary*'               # globs, any position
    tools/dectest.py @loops                              # a named set
    tools/dectest.py @smoke --show                       # + source vs our C

Two properties are load-bearing, and both are tested in
`python/tests/test_dectest_selection.py`:

  * **Selection is fail-closed.** A selector matching nothing is an error. A typo
    that silently matched zero lanes would print "no regressions" and read as
    success — the exact failure mode that let a metric lane skip for a whole
    session elsewhere in this repository.
  * **A scoped run cannot be mistaken for the gate.** Every summary line says
    SCOPED and how much of the matrix it covered, and there is no
    `--write-baseline`: refreshing from a partial run would record new verdicts
    for the lanes that ran and leave the rest describing an older build.

Exit status: 0 when nothing in scope regressed against `baseline.json`, 1 when
something did, 2 on an infrastructure problem (compile failure, harness crash).
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "decompiler_fixtures"
SETS = FIXTURES / "sets.toml"
BASELINE = FIXTURES / "baseline.json"

sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(FIXTURES))
import build_guard as BG

if __name__ == "__main__":
    # The executable's env-python shebang may select system Python.  Restart
    # before importing/running dependency-bearing helpers so verdicts and
    # ``--show`` diagnostics both see the repository's synced environment.
    BG.reexec_with_repo_python()

import fixture_harness as H
import manifest as M  # ty: ignore[unresolved-import]

COMPILERS = ("gcc", "clang")
OPTS = ("O0", "O2")
FULL_MATRIX_LANES = len(M.REQUIRED_FUNCTIONS) * len(COMPILERS) * len(OPTS)


class NoMatch(Exception):
    """A selector matched nothing. Always an error — see the module docstring."""


def function_universe() -> dict[str, list[str]]:
    """Every selectable function per fixture.

    NOT just `manifest.REQUIRED_FUNCTIONS`. That declares which functions must
    *exist* (a dropped export fails the gate) and covers roughly a third of the
    corpus: the harness executes every DWARF-typed export, so the baseline holds
    72 functions the manifest never names — `mul_widen`, `deposit_byte1`,
    `two_latches`, `tailcall_to_sum4`, the whole C++ mangled set. Selecting from
    the manifest alone would leave exactly the interesting failures unaddressable,
    including the three the implementation directive asks to be classified first.

    So the universe is the baseline (what actually ran) unioned with the manifest
    (what must exist). The union matters in both directions: a newly added
    fixture is selectable before its first baseline refresh.
    """
    universe = {k: list(v) for k, v in M.REQUIRED_FUNCTIONS.items()}
    if BASELINE.is_file():
        observed = json.loads(BASELINE.read_text())
        for cell, fns in observed.items():
            if cell.startswith("__") or not isinstance(fns, dict):
                continue
            fixture = cell.split(":")[0]
            if fixture not in universe:
                continue
            known = set(universe[fixture])
            for name in fns:
                if not name.startswith("__") and name not in known:
                    universe[fixture].append(name)
                    known.add(name)
    return {k: sorted(v) for k, v in universe.items()}


def lane_function_universe() -> dict[tuple[str, str, str], list[str]]:
    """Selectable functions for each exact compiler/optimisation lane.

    C++ ABI aliases are not stable across compilers or optimisation levels. The
    baseline records what actually existed in each pinned lane; required
    functions are added to every lane because their absence is infrastructure.
    """
    universe = {
        (fixture, cc, opt): set(required)
        for fixture, required in M.REQUIRED_FUNCTIONS.items()
        for cc in COMPILERS
        for opt in OPTS
    }
    if BASELINE.is_file():
        observed = json.loads(BASELINE.read_text())
        for cell, fns in observed.items():
            if cell.startswith("__") or not isinstance(fns, dict):
                continue
            parts = cell.split(":")
            if len(parts) != 3:
                continue
            key = tuple(parts)
            if key not in universe:
                continue
            universe[key].update(name for name in fns if not name.startswith("__"))
    return {key: sorted(funcs) for key, funcs in universe.items()}


@dataclass(frozen=True)
class Selector:
    fixture: str
    cc: str
    opt: str
    func: str


@dataclass(frozen=True)
class Lane:
    fixture: str
    cc: str
    opt: str
    funcs: tuple[str, ...]

    @property
    def key(self) -> str:
        return f"{self.fixture}:{self.cc}:{self.opt}"


def parse_selector(raw: str) -> Selector:
    """`fixture[:cc[:opt[:func]]]`, each component defaulting to `*`."""
    parts = raw.split(":")
    if len(parts) > 4:
        raise ValueError(
            f"too many components in selector {raw!r} "
            f"(expected fixture[:cc[:opt[:func]]])"
        )
    parts = parts + ["*"] * (4 - len(parts))
    return Selector(*parts)


def load_sets() -> dict:
    if not SETS.is_file():
        return {}
    return tomllib.loads(SETS.read_text())


def _expand(raw: str) -> list[str]:
    if not raw.startswith("@"):
        return [raw]
    name = raw[1:]
    sets = load_sets()
    if name not in sets:
        raise NoMatch(
            f"no set named @{name}. Available: "
            + ", ".join(f"@{k}" for k in sorted(sets))
        )
    return list(sets[name]["selectors"])


def resolve(raws: list[str]) -> list[Lane]:
    """Selectors -> the lanes to run, each with the functions to report on.

    Every stage is fail-closed independently, so the error names the component
    that matched nothing rather than reporting an empty run.
    """
    universe = function_universe()
    lane_universe = lane_function_universe()
    selectors = [parse_selector(r) for raw in raws for r in _expand(raw)]
    by_lane: dict[tuple[str, str, str], set[str]] = {}
    for sel in selectors:
        fixtures = fnmatch.filter(sorted(universe), sel.fixture)
        if not fixtures:
            raise NoMatch(
                f"no fixture matches {sel.fixture!r}. Available: "
                + ", ".join(sorted(universe))
            )
        ccs = fnmatch.filter(list(COMPILERS), sel.cc)
        opts = fnmatch.filter(list(OPTS), sel.opt)
        if not ccs or not opts:
            raise NoMatch(
                f"no lane matches {sel.cc}:{sel.opt} "
                f"(compilers: {', '.join(COMPILERS)}; opts: {', '.join(OPTS)})"
            )
        # A function pattern is matched per fixture, but only has to match
        # SOMEWHERE in the selector. `*:gcc:O0:ternary*` means "the ternary
        # functions, wherever they live" — erroring because 02_integer_widths
        # has none would make cross-fixture selection useless. An exactly-named
        # fixture is different: there the miss is a typo, and is reported as one.
        matched_any = False
        for fixture in fixtures:
            for cc in ccs:
                for opt in opts:
                    funcs = fnmatch.filter(lane_universe[(fixture, cc, opt)], sel.func)
                    if not funcs:
                        continue
                    matched_any = True
                    by_lane.setdefault((fixture, cc, opt), set()).update(funcs)
        if not matched_any:
            where = (
                fixtures[0]
                if len(fixtures) == 1
                else f"any of {len(fixtures)} fixtures"
            )
            declared = (
                ", ".join(universe[fixtures[0]])
                if len(fixtures) == 1
                else "(run --list to see them)"
            )
            raise NoMatch(
                f"no function matches {sel.func!r} in {where}. Declared: {declared}"
            )
    return [
        Lane(f, cc, opt, tuple(sorted(funcs)))
        for (f, cc, opt), funcs in sorted(by_lane.items())
    ]


def summary_line(
    lanes, regressions, improvements, full_matrix: bool, infra=None
) -> str:
    """The last line of every run. It states the scope on purpose: a green result
    over 1 lane and a green result over 56 are different claims."""
    scope = "FULL MATRIX" if full_matrix else "SCOPED"
    n = len(lanes)
    pct = f"{100 * n / FULL_MATRIX_LANES:.0f}%"
    head = f"{scope}: {n} lane{'' if n == 1 else 's'} of {FULL_MATRIX_LANES} ({pct})"
    if infra:
        return f"{head} — {len(infra)} INFRASTRUCTURE ERROR(S)"
    if regressions:
        return f"{head} — {len(regressions)} REGRESSION(S)"
    tail = (
        f", {len(improvements)} improvement(s) — refresh the baseline"
        if improvements
        else ""
    )
    return f"{head} — no regressions in scope{tail}"


def compare(observed: dict, baseline: dict, lanes) -> tuple[list, list, list]:
    """(regressions, improvements, infra) within the selected scope only."""
    regressions, improvements, infra = [], [], []
    for lane in lanes:
        cur = observed.get(lane.key, {})
        base = baseline.get(lane.key, {})
        if "__lane__" in cur:
            if cur["__lane__"] != "env-missing":
                infra.append(f"{lane.key}: {cur['__lane__']}")
            continue
        for func in lane.funcs:
            now = cur.get(func)
            was = base.get(func)
            if now is None:
                infra.append(f"{lane.key}:{func}: absent from this run")
            elif now in ("missing", "nocases", "timeout"):
                infra.append(f"{lane.key}:{func}: {now}")
            elif was == "pass" and now != "pass":
                regressions.append(f"{lane.key}:{func}: pass -> {now}")
            elif was is not None and was != "pass" and now == "pass":
                improvements.append(f"{lane.key}:{func}: {was} -> pass")
            elif was is not None and was != now:
                # structural <-> fail is not a regression against a passing
                # baseline, but it IS a change and hiding it trains people to
                # trust a diff that omits things.
                improvements.append(f"{lane.key}:{func}: {was} -> {now}")
    return regressions, improvements, infra


def show_function(lane: Lane, func: str) -> None:
    """Source and our C, side by side, for one function. Reading the output is
    the check the metrics cannot do — see `tools/roundtrip_review.py`, which does
    this for the DecBench corpus. Reuses its helpers so there is one renderer."""
    sys.path.insert(0, str(ROOT / "tools"))
    import roundtrip_review as RR

    src = FIXTURES / "src"
    candidates = list(src.glob(f"{lane.fixture}.c")) + list(
        src.glob(f"{lane.fixture}.cpp")
    )
    if not candidates:
        return
    text = RR.source_of(candidates[0], func)
    print(f"\n----- {lane.key}:{func} — source -----")
    print(text or "(not found)")
    so = H.BUILD / f"{lane.fixture}-{lane.cc}-{lane.opt}.so"
    if not so.exists():
        return
    import diff_decompile as DD

    vas = DD.exported_functions(str(so))
    if func in vas:
        print(f"----- {lane.key}:{func} — our C -----")
        print(DD.decompiled_c(str(so), vas[func]) or "(no output)")


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="dectest",
        description="Run a scoped slice of the decompiler fixture corpus.",
        epilog="Selectors: fixture[:cc[:opt[:func]]], globs allowed; @name for a set.",
    )
    ap.add_argument("selectors", nargs="*", default=["@smoke"], help="default: @smoke")
    ap.add_argument(
        "--list",
        action="store_true",
        help="resolve the selection and print it; run nothing",
    )
    ap.add_argument(
        "--list-sets",
        action="store_true",
        help="print the named sets and what they cover",
    )
    ap.add_argument(
        "--full",
        action="store_true",
        help="print every verdict, not just changes against the baseline",
    )
    ap.add_argument(
        "--show",
        action="store_true",
        help="for each failing function, print its source and our C",
    )
    ap.add_argument("--jobs", type=int, default=None)
    ap.add_argument(
        "--fuzz",
        type=int,
        default=M.FIXTURE_FUZZ,
        help=f"seeded trials per function (default {M.FIXTURE_FUZZ}, "
        "the value the baseline was recorded with)",
    )
    ap.add_argument(
        "--allow-stale",
        action="store_true",
        help="run against an extension older than the Rust source",
    )
    return ap


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    if args.list_sets:
        sets = load_sets()
        width = max(len(k) for k in sets) + 1
        for name, spec in sorted(sets.items()):
            lanes = resolve([f"@{name}"])
            print(f"@{name:<{width}} {len(lanes):>2} lanes  {spec['description']}")
        return 0

    try:
        lanes = resolve(args.selectors)
    except (NoMatch, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    if args.list:
        for lane in lanes:
            print(f"{lane.key}  ({len(lane.funcs)} fn): {' '.join(lane.funcs)}")
        print(f"\n{len(lanes)} lane(s), {sum(len(l.funcs) for l in lanes)} function(s)")
        return 0

    warning = BG.check_fresh(allow_stale=args.allow_stale)
    if warning:
        print(warning, file=sys.stderr)

    if args.fuzz != M.FIXTURE_FUZZ:
        print(
            f"note: --fuzz {args.fuzz} differs from the baseline's "
            f"{M.FIXTURE_FUZZ}; verdicts are not comparable to baseline.json",
            file=sys.stderr,
        )

    observed = H.run_lanes(
        [(l.fixture, l.cc, l.opt, l.funcs) for l in lanes],
        fuzz=args.fuzz,
        jobs=args.jobs,
    )
    baseline = json.loads(BASELINE.read_text()) if BASELINE.is_file() else {}
    regressions, improvements, infra = compare(observed, baseline, lanes)

    if args.full:
        width = max((len(f"{l.key}:{fn}") for l in lanes for fn in l.funcs), default=40)
        for lane in lanes:
            cur = observed.get(lane.key, {})
            if "__lane__" in cur:
                print(f"{lane.key:<{width}}  LANE: {cur['__lane__']}")
                continue
            for func in lane.funcs:
                print(
                    f"{lane.key}:{func:<{width - len(lane.key) - 1}}  {cur.get(func, '?')}"
                )

    for group, items in (
        ("INFRASTRUCTURE", infra),
        ("REGRESSIONS", regressions),
        ("IMPROVEMENTS", improvements),
    ):
        if items:
            print(f"\n{group} ({len(items)}):")
            for it in items:
                print(f"  {it}")

    if args.show:
        for lane in lanes:
            cur = observed.get(lane.key, {})
            for func in lane.funcs:
                if cur.get(func) == "fail":
                    show_function(lane, func)

    print(
        "\n"
        + summary_line(
            lanes,
            regressions,
            improvements,
            full_matrix=len(lanes) == FULL_MATRIX_LANES,
            infra=infra,
        )
    )
    if infra:
        return 2
    return 1 if regressions else 0


if __name__ == "__main__":
    raise SystemExit(main())
