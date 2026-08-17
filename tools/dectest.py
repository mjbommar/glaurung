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

ARCHITECTURES
-------------
The compiler slot also accepts an architecture from `tools/arch_roundtrip.py`
(`x86_64`, `x86_64_gcc15`, `i386`, `aarch64`, `armv7`, `armv7_a32`), which is
the same shape those lanes are keyed with in `arch_baseline.json`:

    tools/dectest.py 173_float_int_conversions:i386:O2:widen_int_to_float
    tools/dectest.py @vector-float --arch i386           # a set, retargeted

This matters more than ergonomics. The two architectures with the worst recorded
failure rates — `armv7_a32` at 26.5% and `i386` at 21.8%, against x86-64's 13.7%
— were the two with no fast loop at all: `arch_roundtrip.py` has no function
selection, so asking about one function on one architecture meant executing every
export in the fixture. On `03_loop_shapes:i386:O2` that is 11.4s of work to
answer a question worth 0.9s.

An architecture is only ever selected DELIBERATELY. A glob in the compiler slot
expands over `gcc`/`clang`/`rustc` and nothing else, so `@o0` (`*:gcc:O0`,
`*:clang:O0`) still means exactly the 368 host lanes it always did; an
architecture must be named outright or requested with `--arch`. Anything else
would silently quadruple every existing set.

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
#: The cross-architecture gate's committed verdicts. Kept separate because they
#: are a separate population: the same function is judged against a different
#: object, by a different compiler, under an emulator.
ARCH_BASELINE = FIXTURES / "arch_baseline.json"

sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(FIXTURES))
import build_guard as BG

if __name__ == "__main__":
    # The executable's env-python shebang may select system Python.  Restart
    # before importing/running dependency-bearing helpers so verdicts and
    # ``--show`` diagnostics both see the repository's synced environment.
    BG.reexec_with_repo_python()

import arch_roundtrip as AR
import fixture_harness as H
import manifest as M  # ty: ignore[unresolved-import]

COMPILERS = ("gcc", "clang", "rustc")
OPTS = ("O0", "O2")

#: The architectures selectable in the compiler slot. Read from
#: `arch_roundtrip.TARGETS` rather than restated, so a target added there is
#: selectable here without a second list to fall out of step with it.
ARCHES = tuple(AR.TARGETS)


def fixture_lanes(fixture: str) -> list[tuple[str, str]]:
    """The `(compiler, opt)` lanes that EXIST for one fixture.

    Not the cross product. A Rust fixture is built by `rustc` and by nothing
    else, so `170_rust_panic_unwind:clang:O2` names an object no toolchain
    produces. `dectest` used to manufacture it anyway; the harness then read a
    file that was not there and the lane died inside pyelftools with
    `ELFError: Magic number does not match` — reported as an INFRASTRUCTURE
    error, which blocks `--write-baseline` outright.
    ``fixture_harness.matrix_for`` is the gate's own answer to this question, so
    it is the one consulted here rather than a second list to fall out of step
    with it.
    """
    source = next(
        (path for path in FIXTURES.glob(f"src/{fixture}.*") if path.stem == fixture),
        None,
    )
    return list(H.matrix_for(source)) if source is not None else list(H.REQUIRED_MATRIX)


FULL_MATRIX_LANES = sum(len(fixture_lanes(name)) for name in M.REQUIRED_FUNCTIONS)


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
        for cc, opt in fixture_lanes(fixture)
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


def _arch_baseline() -> dict:
    if not ARCH_BASELINE.is_file():
        return {}
    return json.loads(ARCH_BASELINE.read_text())


def arch_lane_function_universe() -> dict[tuple[str, str, str], list[str]]:
    """Selectable functions for each exact `(fixture, arch, opt)` lane.

    Sourced from `arch_baseline.json` alone, and NOT unioned with the manifest
    the way `lane_function_universe` is. That union exists on the host side so a
    newly added fixture is selectable before its first baseline refresh; here the
    same move would invent `(fixture, arch, opt)` lanes the cross gate has never
    recorded, and every verdict they produced would compare against nothing.
    Adding a fixture already requires refreshing `arch_baseline.json`
    (CLAUDE.md), so the coupling is the one that already holds.

    Two exclusions follow from reading the baseline: lanes recorded as
    declared-unsupported (see `arch_unsupported_lanes`), and Rust fixtures, which
    have no cross-`rustc` target configured and therefore no arch lane at all.

    Functions the target ABI cannot express ARE included, and are recorded
    `incomparable` rather than dropped — `long count_up(int)` is 4 bytes on i386
    and 8 on the host, and the harness declining to judge it is itself a verdict
    worth being able to select and look at.
    """
    universe: dict[tuple[str, str, str], list[str]] = {}
    for cell, fns in _arch_baseline().items():
        if cell.startswith("__") or not isinstance(fns, dict) or "__lane__" in fns:
            continue
        parts = cell.split(":")
        if len(parts) != 3 or parts[1] not in ARCHES:
            continue
        universe[(parts[0], parts[1], parts[2])] = sorted(
            name for name in fns if not name.startswith("__")
        )
    return universe


def arch_unsupported_lanes() -> dict[tuple[str, str, str], str]:
    """`(fixture, arch, opt) -> reason` for lanes the baseline records as gaps.

    `02_integer_widths` has no i386 form at all — `__int128` is not a type on a
    32-bit target — and Debian ships no `aarch64-linux-gnu-g++`, so every C++
    fixture is absent there. These are declared, probed gaps rather than
    failures, and naming one is a reasonable thing for a person to do; saying
    "no function matches" would read as a typo. See `arch_roundtrip.detect_unsupported`.
    """
    out: dict[tuple[str, str, str], str] = {}
    for cell, fns in _arch_baseline().items():
        if cell.startswith("__") or not isinstance(fns, dict):
            continue
        parts = cell.split(":")
        if len(parts) != 3 or parts[1] not in ARCHES:
            continue
        lane = fns.get("__lane__")
        if isinstance(lane, str) and lane.startswith(AR.UNSUPPORTED_PREFIX):
            out[(parts[0], parts[1], parts[2])] = lane[len(AR.UNSUPPORTED_PREFIX) :]
    return out


@dataclass(frozen=True)
class Selector:
    fixture: str
    cc: str
    opt: str
    func: str

    @property
    def is_arch(self) -> bool:
        return self.cc in ARCHES


@dataclass(frozen=True)
class Lane:
    fixture: str
    cc: str
    opt: str
    funcs: tuple[str, ...]

    @property
    def key(self) -> str:
        return f"{self.fixture}:{self.cc}:{self.opt}"

    @property
    def is_arch(self) -> bool:
        """Whether this lane is judged against `arch_baseline.json`.

        The compiler slot decides, and the two vocabularies are disjoint
        (`gcc`/`clang`/`rustc` against six architecture names), so one lane key
        shape serves both gates without ambiguity.
        """
        return self.cc in ARCHES


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


def retarget(sel: Selector, arches: list[str]) -> list[Selector]:
    """`--arch` applied to one selector: the compiler slot becomes each arch.

    Retargeting is what lets an existing set be reused unchanged —
    `@vector-float --arch i386` is the whole point, and it works because every
    set names fixtures rather than lanes. A selector that already names a
    DIFFERENT architecture is a contradiction and raises rather than being
    silently overwritten; naming the same one is simply redundant and allowed.
    """
    if sel.is_arch:
        if sel.cc not in arches:
            raise NoMatch(
                f"selector {sel.fixture}:{sel.cc}:{sel.opt} names architecture "
                f"{sel.cc!r} but --arch asked for {', '.join(arches)}"
            )
        return [sel]
    return [Selector(sel.fixture, arch, sel.opt, sel.func) for arch in arches]


def resolve(raws: list[str], arches: list[str] | None = None) -> list[Lane]:
    """Selectors -> the lanes to run, each with the functions to report on.

    Every stage is fail-closed independently, so the error names the component
    that matched nothing rather than reporting an empty run.
    """
    universe = function_universe()
    lane_universe = lane_function_universe()
    arch_universe = arch_lane_function_universe()
    unsupported = arch_unsupported_lanes()
    selectors = [parse_selector(r) for raw in raws for r in _expand(raw)]
    if arches:
        selectors = [out for sel in selectors for out in retarget(sel, arches)]
    by_lane: dict[tuple[str, str, str], set[str]] = {}
    for sel in selectors:
        fixtures = fnmatch.filter(sorted(universe), sel.fixture)
        if not fixtures:
            raise NoMatch(
                f"no fixture matches {sel.fixture!r}. Available: "
                + ", ".join(sorted(universe))
            )
        # An architecture is never glob-matched. `*` in the compiler slot means
        # the host compilers, so `@o0` stays the 368 host lanes it has always
        # been; a cross lane costs a cross build, a pinned reference build and an
        # emulator, and is opted into by name or by `--arch`.
        lanes_of = arch_universe if sel.is_arch else lane_universe
        ccs = [sel.cc] if sel.is_arch else fnmatch.filter(list(COMPILERS), sel.cc)
        opts = fnmatch.filter(list(OPTS), sel.opt)
        if not ccs or not opts:
            raise NoMatch(
                f"no lane matches {sel.cc}:{sel.opt} "
                f"(compilers: {', '.join(COMPILERS)}; "
                f"architectures: {', '.join(ARCHES)}; opts: {', '.join(OPTS)})"
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
                    # A lane that does not exist for this fixture is skipped,
                    # not matched: `*:clang:O2` must cover every C fixture
                    # without claiming a clang build of a Rust one.
                    if (fixture, cc, opt) not in lanes_of:
                        continue
                    funcs = fnmatch.filter(lanes_of[(fixture, cc, opt)], sel.func)
                    if not funcs:
                        continue
                    matched_any = True
                    by_lane.setdefault((fixture, cc, opt), set()).update(funcs)
        if not matched_any:
            gaps = sorted(
                {
                    reason
                    for fixture in fixtures
                    for cc in ccs
                    for opt in opts
                    if (reason := unsupported.get((fixture, cc, opt))) is not None
                }
            )
            if gaps:
                raise NoMatch(
                    f"{sel.fixture}:{sel.cc}:{sel.opt} is a declared, probed gap "
                    f"rather than a lane: {'; '.join(gaps)}"
                )
            where = (
                fixtures[0]
                if len(fixtures) == 1
                else f"any of {len(fixtures)} fixtures"
            )
            # What is declared IN THE SELECTED LANES, which for an architecture
            # is a smaller set than the fixture's: a signature the target ABI
            # cannot express never gets a verdict there. Falls back to the
            # fixture-level universe when the selector named no lane at all
            # (`166_rust_generics:gcc:O0`), where the lane-level answer is empty
            # and unhelpful.
            in_lanes = sorted(
                {
                    f
                    for cc in ccs
                    for opt in opts
                    for f in lanes_of.get((fixtures[0], cc, opt), ())
                }
            ) or universe.get(fixtures[0], [])
            declared = (
                ", ".join(in_lanes)
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


def denominator(lanes) -> int:
    """The matrix a scope is a fraction OF.

    Host-only selections keep counting against the 748 host lanes, unchanged. As
    soon as an architecture lane is in scope the denominator grows to include the
    2208 cross lanes, because "1 of 748" would overstate what a run covering an
    i386 lane has to say about the corpus.
    """
    if any(lane.is_arch for lane in lanes):
        return FULL_MATRIX_LANES + len(arch_lane_function_universe())
    return FULL_MATRIX_LANES


def summary_line(
    lanes, regressions, improvements, full_matrix: bool, infra=None
) -> str:
    """The last line of every run. It states the scope on purpose: a green result
    over 1 lane and a green result over 56 are different claims."""
    scope = "FULL MATRIX" if full_matrix else "SCOPED"
    n = len(lanes)
    total = denominator(lanes)
    pct = f"{100 * n / total:.0f}%"
    head = f"{scope}: {n} lane{'' if n == 1 else 's'} of {total} ({pct})"
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


def compare(
    observed: dict, baseline: dict, lanes, arch_baseline: dict | None = None
) -> tuple[list, list, list]:
    """(regressions, improvements, infra) within the selected scope only.

    Each lane is judged against ITS OWN gate's committed verdicts: host lanes
    against `baseline.json`, architecture lanes against `arch_baseline.json`.
    Comparing an i386 verdict to the x86-64 record would report a regression for
    every function the lifters already differ on.
    """
    regressions, improvements, infra = [], [], []
    for lane in lanes:
        cur = observed.get(lane.key, {})
        base = (arch_baseline or {} if lane.is_arch else baseline).get(lane.key, {})
        if "__lane__" in cur:
            if cur["__lane__"] != "env-missing" and not str(cur["__lane__"]).startswith(
                AR.UNSUPPORTED_PREFIX
            ):
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


def toolchain_notes(arch_lanes, arch_baseline: dict) -> list[str]:
    """Warnings that this host's cross toolchain is not the baseline's.

    A cross verdict is a joint property of the lifter, the compiler that built
    the target object, and the emulator that ran it — and five of the six
    architectures are built by HOST compilers, because the pinned image ships no
    cross toolchains and no multilib. So an `armv7` regression on a machine whose
    `arm-linux-gnueabihf-gcc` is a different release than the baseline's may be
    the compiler, not the change under test. Saying so once, up front, is the
    difference between a confusing hour and a shrug.

    A WARNING rather than a refusal, deliberately, and the split is the same one
    `--allow-stale` draws. `arch_roundtrip.py --check` is the gate: it must fail
    closed, because it decides whether the ratchet moves. This is the iteration
    loop, where the useful comparison is against your own previous run — and
    where refusing to start on any host whose gcc differs from the recorded one
    would mean refusing to start on most hosts.

    Only the host-side facts are checked, which is what keeps this to a
    `--version` call. The PINNED rebuild image is a fixed tag built from this
    repository's own Dockerfile and is fingerprinted by `--check`; probing it
    here would add six `docker exec`s to a run that should cost a second.
    """
    arches = sorted({lane.cc for lane in arch_lanes})
    recorded = arch_baseline.get(H.TOOLCHAIN_KEY) or {}
    if not recorded:
        return []
    current = AR.host_fingerprint(arches)
    notes = []
    for kind in ("fixture", "runner"):
        want, got = recorded.get(kind) or {}, current.get(kind) or {}
        for arch in arches:
            if arch in want and want[arch] != got.get(arch):
                notes.append(
                    f"note: {kind}[{arch}] is {got.get(arch)!r} here but the "
                    f"baseline recorded {want[arch]!r}; a difference on this "
                    f"lane may be the toolchain rather than the change"
                )
    if recorded.get("aslr") != current.get("aslr"):
        notes.append(
            f"note: aslr is {current.get('aslr')!r} here and {recorded.get('aslr')!r} "
            f"in the baseline — a recovery that reads an uninitialised local gives "
            f"a different answer under each. Install `setarch` (util-linux)."
        )
    return notes


def unbaselined_fixture_notes(lanes: list[Lane]) -> list[str]:
    """Warn when a selected fixture has no baseline entry, so the run judges
    only its REQUIRED functions.

    `lane_function_universe` is the union of `M.REQUIRED_FUNCTIONS` and whatever
    `baseline.json` already observed. For a fixture with no baseline entry that
    union is just the required list -- so a brand-new fixture's helpers are
    invisible here, in exactly the window where someone is iterating on it and
    most wants the feedback.

    That is not hypothetical. `197_homogeneous_float_aggregates` declares five
    required functions and contains eleven. Before its first refresh this tool
    printed five verdicts per lane and after it printed eleven; the six it could
    not show held two real defects, one of them on a path nothing else in the
    corpus exercises (diary Entry 58).

    The gap closes on the first `tools/fixture_harness.py --write-baseline`, so
    the fix is a note rather than a change to the universe: widening it would
    invent selectable functions the gate has never recorded, which is the exact
    reasoning `arch_lane_function_universe` gives for staying narrow.

    The count of unjudged functions comes from the built object when one exists,
    because that is ground truth rather than a guess at the source.
    """
    if not BASELINE.is_file():
        return []
    baselined = {
        cell.split(":")[0]
        for cell in json.loads(BASELINE.read_text())
        if not cell.startswith("__")
    }
    notes: list[str] = []
    for fixture in sorted({lane.fixture for lane in lanes}):
        if fixture in baselined:
            continue
        judged = sorted(
            {fn for lane in lanes if lane.fixture == fixture for fn in lane.funcs}
        )
        extra = _unjudged_function_names(fixture, judged)
        detail = (
            f"; {len(extra)} more in the built object are NOT judged: "
            + ", ".join(extra)
            if extra
            else ""
        )
        notes.append(
            f"note: {fixture} has no baseline entry, so only its "
            f"{len(judged)} REQUIRED function(s) are judged{detail}. "
            f"Run `tools/fixture_harness.py --write-baseline` to see the rest."
        )
    return notes


def _unjudged_function_names(fixture: str, judged: list[str]) -> list[str]:
    """Functions present in a built fixture object that this run will not judge.

    Returns `[]` when no object has been built yet -- a guess from the source
    text would be worse than saying nothing, since the note's whole value is
    that its count is trustworthy.
    """
    try:
        sys.path.insert(0, str(ROOT / "tools"))
        import diff_decompile as DD
    except Exception:
        return []
    for so in sorted(H.BUILD.glob(f"{fixture}-*.so")):
        try:
            present = set(DD.exported_functions(str(so)))
        except Exception:
            continue
        return sorted(present - set(judged))
    return []


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
    import diff_decompile as DD

    if lane.is_arch:
        # Architecture lanes leave no artifact behind: `arch_roundtrip._run_lane`
        # cross-builds into a temporary directory. Rebuild here rather than skip
        # — reading the recovered C is the check the metrics cannot do, and it is
        # needed MOST on the architectures with the worst numbers.
        import tempfile

        with tempfile.TemporaryDirectory(dir=M.tmpdir()) as td:
            so = Path(td) / f"{lane.fixture}-{lane.cc}-{lane.opt}.so"
            ok, err = AR._cross_build(lane.cc, candidates[0], lane.opt, so)
            if not ok:
                print(f"(cross build failed: {err[-160:]})")
                return
            vas = DD.exported_functions(str(so))
            if func in vas:
                print(f"----- {lane.key}:{func} — our C -----")
                print(DD.decompiled_c(str(so), vas[func]) or "(no output)")
        return
    so = H.BUILD / f"{lane.fixture}-{lane.cc}-{lane.opt}.so"
    if not so.exists():
        return
    vas = DD.exported_functions(str(so))
    if func in vas:
        print(f"----- {lane.key}:{func} — our C -----")
        print(DD.decompiled_c(str(so), vas[func]) or "(no output)")


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="dectest",
        description="Run a scoped slice of the decompiler fixture corpus.",
        epilog="Selectors: fixture[:cc[:opt[:func]]], globs allowed; @name for a set. "
        "The cc slot also takes an architecture (" + ", ".join(ARCHES) + ").",
    )
    ap.add_argument("selectors", nargs="*", default=["@smoke"], help="default: @smoke")
    ap.add_argument(
        "--arch",
        action="append",
        choices=list(ARCHES),
        help="retarget every selector to this architecture (repeatable). "
        "`@vector-float --arch i386` is the intended shape; judged against "
        "arch_baseline.json.",
    )
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
        lanes = resolve(args.selectors, arches=args.arch)
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

    for note in unbaselined_fixture_notes(lanes):
        print(note, file=sys.stderr)

    arch_lanes = [l for l in lanes if l.is_arch]
    host_lanes = [l for l in lanes if not l.is_arch]
    arch_baseline = _arch_baseline()
    observed: dict = {}
    if host_lanes:
        observed.update(
            H.run_lanes(
                [(l.fixture, l.cc, l.opt, l.funcs) for l in host_lanes],
                fuzz=args.fuzz,
                jobs=args.jobs,
            )
        )
    if arch_lanes:
        for note in toolchain_notes(arch_lanes, arch_baseline):
            print(note, file=sys.stderr)
        observed.update(
            AR.run_lanes(
                [(l.fixture, l.cc, l.opt, l.funcs) for l in arch_lanes],
                fuzz=args.fuzz,
                jobs=args.jobs,
            )
        )
    baseline = json.loads(BASELINE.read_text()) if BASELINE.is_file() else {}
    regressions, improvements, infra = compare(
        observed, baseline, lanes, arch_baseline=arch_baseline
    )

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
