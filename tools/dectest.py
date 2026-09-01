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

STRIPPED
--------
The optimisation slot also accepts a STRIPPED build, where the object handed to
the decompiler has had `strip` run over it — no `.symtab`, no DWARF:

    tools/dectest.py 10_cpp_runtime_shapes:gcc:O2strip:cpp_exception --show
    tools/dectest.py @exceptions --stripped

That is the configuration real targets ship in, and the one the corpus was blind
to: `tools/fixture_harness.py` compiled every lane `-g`, unconditionally. A
stripped lane is judged against the `-g` build of the SAME compile — same source,
same compiler, same flags, same addresses — so a `pass -> fail` here means the
debug info was doing structural work, which for a correct decompiler it never
should. `tools/stripped_differential.py` is the gated form of this lane and holds
the ratchet of divergences already known; `dectest` reports all of them, known or
not, because it is the loop rather than the gate.

Like an architecture, a stripped lane is only ever selected deliberately: `*` in
the optimisation slot still means `O0`/`O2`, so `@o0` and `@o2` are unchanged.

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

Three properties are load-bearing, and all are tested in
`python/tests/test_dectest_selection.py`:

  * **Selection is fail-closed.** A selector matching nothing is an error. A typo
    that silently matched zero lanes would print "no regressions" and read as
    success — the exact failure mode that let a metric lane skip for a whole
    session elsewhere in this repository.
  * **A scoped run cannot be mistaken for the gate.** Every summary line says
    SCOPED and how much of the matrix it covered, and there is no
    `--write-baseline`: refreshing from a partial run would record new verdicts
    for the lanes that ran and leave the rest describing an older build.
  * **"Matches the baseline" and "the baseline has nothing to say" are different
    answers.** A cell with no baseline entry is reported as UNBASELINED and
    counted in the summary line, never folded into "no regressions". On a
    fixture added since the last refresh this tool used to print `4 lanes — no
    regressions in scope` while thirteen of the twenty cells under it were
    failing; the sentence was true (a first failure regresses against nothing)
    and it read as a pass. Only `--full` showed the verdicts, and even `--full`
    ended with the same line.

Exit status: 0 when nothing in scope regressed against `baseline.json`, 1 when
something did, 2 on an infrastructure problem (compile failure, harness crash).
Unbaselined cells do NOT set a non-zero status — they are not a failure, they
are the absence of a judgement — so the summary line is where they are said out
loud.
"""

from __future__ import annotations

import scratch  # noqa: F401  -- points TMPDIR off the shared /tmp tmpfs on import
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

#: The optimisation slot also accepts a STRIPPED build (`O2strip` — see
#: `fixture_harness.STRIP_SUFFIX`), where the object handed to the decompiler has
#: had `strip` run over it and carries no `.symtab` and no DWARF at all.
#:
#: Like an architecture, it is only ever selected DELIBERATELY: `*` in the
#: optimisation slot expands over `OPTS` and nothing else, so `@o0` and `@o2` are
#: exactly the debug-info lanes they have always been, and a stripped lane must be
#: named outright or asked for with `--stripped`. Anything else would silently
#: double every existing set.
#:
#: A stripped lane is judged against the `-g` build of the SAME compile
#: (`Lane.control_key`), not against a stripped record of its own. That is the
#: whole design — see `tools/stripped_differential.py`, which is this lane's gate
#: and carries the ratchet of divergences already known. `dectest` is the
#: iteration loop, so it reports every divergence including the known ones.
STRIPPED_OPTS = tuple(H.stripped_opt(opt) for opt in H.STRIPPED_BASE_OPTS)

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
    for (fixture, cc, opt), funcs in list(universe.items()):
        # A stripped lane selects exactly the functions its `-g` control has.
        # They are the same exports at the same addresses — `strip` removes only
        # non-SHF_ALLOC sections — so anything else would be a second, drifting
        # answer to a question the control already answers.
        if opt in H.STRIPPED_BASE_OPTS:
            universe[(fixture, cc, H.stripped_opt(opt))] = set(funcs)
    return {key: sorted(funcs) for key, funcs in universe.items()}


def _arch_baseline() -> dict:
    if not ARCH_BASELINE.is_file():
        return {}
    return json.loads(ARCH_BASELINE.read_text())


def arch_lane_function_universe() -> dict[tuple[str, str, str], list[str]]:
    """Selectable functions for each exact `(fixture, arch, opt)` lane.

    `arch_baseline.json` unioned with the manifest's REQUIRED_FUNCTIONS, exactly
    as `lane_function_universe` does on the host side.

    This used to be the baseline ALONE, on the reasoning that a manifest union
    would invent `(fixture, arch, opt)` lanes the cross gate has never recorded
    and "every verdict they produced would compare against nothing." The premise
    was right and the conclusion was the wrong half of it: comparing against
    nothing is a fine thing to DO and an unacceptable thing to HIDE, and `compare`
    now reports such cells as `unbaselined` instead of dropping them. What the
    old rule actually bought was that `dectest --arch` could not reach a new
    fixture AT ALL — the selector failed as "no function matches", which reads as
    a typo — in precisely the window where the cross lifters are least exercised
    and the feedback is worth most.

    Measured before the change, 2026-08-18: over the whole committed corpus the
    union adds ZERO lanes and ZERO functions, because every declared fixture is
    already recorded. It differs only for a fixture added since the last
    `arch_baseline.json` refresh, which is the case it exists for.

    Two exclusions follow from reading the baseline: lanes recorded as
    declared-unsupported (see `arch_unsupported_lanes`), and Rust fixtures, which
    have no cross-`rustc` target configured and therefore no arch lane at all.
    The union preserves both — a `.rs` source contributes no arch lane, and a
    lane the target genuinely cannot build comes back `__lane__: unsupported`,
    which `compare` already skips.

    Functions the target ABI cannot express ARE included, and are recorded
    `incomparable` rather than dropped — `long count_up(int)` is 4 bytes on i386
    and 8 on the host, and the harness declining to judge it is itself a verdict
    worth being able to select and look at.
    """
    declared_gaps = arch_unsupported_lanes()
    universe: dict[tuple[str, str, str], set[str]] = {}
    for fixture, required in M.REQUIRED_FUNCTIONS.items():
        source = next(
            (p for p in FIXTURES.glob(f"src/{fixture}.*") if p.stem == fixture), None
        )
        if source is None or source.suffix == ".rs":
            continue
        for arch in ARCHES:
            for opt in OPTS:
                if (fixture, arch, opt) in declared_gaps:
                    continue
                universe[(fixture, arch, opt)] = set(required)
    for cell, fns in _arch_baseline().items():
        if cell.startswith("__") or not isinstance(fns, dict) or "__lane__" in fns:
            continue
        parts = cell.split(":")
        if len(parts) != 3 or parts[1] not in ARCHES:
            continue
        universe.setdefault((parts[0], parts[1], parts[2]), set()).update(
            name for name in fns if not name.startswith("__")
        )
    return {key: sorted(funcs) for key, funcs in universe.items()}


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

    @property
    def is_stripped(self) -> bool:
        return self.opt in STRIPPED_OPTS


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

    @property
    def is_stripped(self) -> bool:
        return self.opt in STRIPPED_OPTS

    @property
    def control_key(self) -> str:
        """The baseline row this lane's verdicts are compared against.

        Itself for every ordinary lane. For a stripped lane, the `-g` build of
        the same compile: same source, same compiler, same flags, same addresses,
        and the only variable removed is the debug info — which is what makes a
        divergence attributable rather than merely observed.
        """
        base_opt, stripped = H.split_opt(self.opt)
        return f"{self.fixture}:{self.cc}:{base_opt}" if stripped else self.key


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


def strip_retarget(sel: Selector) -> Selector:
    """`--stripped` applied to one selector: the optimisation slot gains `strip`.

    Retargeting rather than a separate set list, for the same reason `--arch`
    retargets: every set names fixtures, so `@exceptions --stripped` reuses a set
    unchanged. A selector whose optimisation slot is a glob keeps that glob and
    resolves through `STRIPPED_BASE_OPTS`, which is `-O2` only, so `@o0
    --stripped` selects nothing and says so rather than inventing an `O0strip`
    lane that `stripped_lanes_for` does not build.
    """
    if sel.is_stripped:
        return sel
    if sel.opt == "*":
        bases = list(H.STRIPPED_BASE_OPTS)
    else:
        bases = fnmatch.filter(list(H.STRIPPED_BASE_OPTS), sel.opt)
    if not bases:
        raise NoMatch(
            f"--stripped has no lane for optimisation {sel.opt!r}; "
            f"stripped lanes exist at {', '.join(H.STRIPPED_BASE_OPTS)} only"
        )
    return Selector(sel.fixture, sel.cc, H.stripped_opt(bases[0]), sel.func)


def resolve(
    raws: list[str], arches: list[str] | None = None, stripped: bool = False
) -> list[Lane]:
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
    if stripped:
        selectors = [strip_retarget(sel) for sel in selectors]
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
        # A stripped optimisation level is never glob-reached (see STRIPPED_OPTS).
        opts = (
            [sel.opt]
            if sel.opt in STRIPPED_OPTS
            else fnmatch.filter(list(OPTS), sel.opt)
        )
        if not ccs or not opts:
            raise NoMatch(
                f"no lane matches {sel.cc}:{sel.opt} "
                f"(compilers: {', '.join(COMPILERS)}; "
                f"architectures: {', '.join(ARCHES)}; "
                f"opts: {', '.join(OPTS + STRIPPED_OPTS)})"
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
    lanes, regressions, improvements, full_matrix: bool, infra=None, unbaselined=None
) -> str:
    """The last line of every run. It states the scope on purpose: a green result
    over 1 lane and a green result over 56 are different claims.

    It also states how many cells the baseline had NOTHING TO SAY about, which is
    a third claim again. "No regressions" is a comparison, and a cell with no
    baseline entry was never compared: on a fixture added since the last refresh
    every cell is in that state, so the old line reported `4 lanes — no
    regressions in scope` while five of the forty cells underneath it were
    failing. Technically true, practically a lie, and only `--full` showed it.

    A cell that was never judged is therefore never folded into the green half of
    the sentence. When nothing at all in scope was judged the line does not say
    "no regressions" at all, because there was no comparison to report the result
    of.
    """
    scope = "FULL MATRIX" if full_matrix else "SCOPED"
    n = len(lanes)
    total = denominator(lanes)
    pct = f"{100 * n / total:.0f}%"
    head = f"{scope}: {n} lane{'' if n == 1 else 's'} of {total} ({pct})"
    if infra:
        return f"{head} — {len(infra)} INFRASTRUCTURE ERROR(S)"
    unjudged = len(unbaselined or ())
    cells = sum(len(lane.funcs) for lane in lanes)
    if regressions:
        return f"{head} — {len(regressions)} REGRESSION(S)"
    if unjudged and unjudged >= cells:
        return (
            f"{head} — NO VERDICT: all {unjudged} cell(s) are unbaselined, "
            f"nothing was compared (use --full to see what they did)"
        )
    tail = (
        f", {len(improvements)} improvement(s) — refresh the baseline"
        if improvements
        else ""
    )
    if unjudged:
        tail += (
            f", {unjudged} of {cells} cell(s) UNBASELINED and not judged (use --full)"
        )
    return f"{head} — no regressions in scope{tail}"


def compare(
    observed: dict, baseline: dict, lanes, arch_baseline: dict | None = None
) -> tuple[list, list, list, list]:
    """(regressions, improvements, infra, unbaselined) within the selected scope.

    Each lane is judged against ITS OWN gate's committed verdicts: host lanes
    against `baseline.json`, architecture lanes against `arch_baseline.json`.
    Comparing an i386 verdict to the x86-64 record would report a regression for
    every function the lifters already differ on.

    `unbaselined` is the fourth outcome and the reason this returns four lists. A
    cell whose baseline entry does not exist cannot be a regression, an
    improvement, or unchanged -- every one of those words names a COMPARISON, and
    there is nothing here to compare against. Such a cell used to fall through
    all four branches below and vanish, so the caller counted zero regressions
    and said so out loud. Absence of a verdict is now itself a reported outcome;
    what it must never do is silently join the passing majority.
    """
    regressions, improvements, infra, unbaselined = [], [], [], []
    for lane in lanes:
        cur = observed.get(lane.key, {})
        base = (arch_baseline or {} if lane.is_arch else baseline).get(
            lane.control_key, {}
        )
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
            elif was is None:
                unbaselined.append(f"{lane.key}:{func}: {now} (no baseline entry)")
            elif was == "pass" and now != "pass":
                regressions.append(f"{lane.key}:{func}: pass -> {now}")
            elif was != "pass" and now == "pass":
                improvements.append(f"{lane.key}:{func}: {was} -> pass")
            elif was != now:
                # structural <-> fail is not a regression against a passing
                # baseline, but it IS a change and hiding it trains people to
                # trust a diff that omits things.
                improvements.append(f"{lane.key}:{func}: {was} -> {now}")
    return regressions, improvements, infra, unbaselined


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
    invent selectable functions the gate has never recorded.

    The count of unjudged functions comes from the built object when one exists,
    because that is ground truth rather than a guess at the source.

    A BASELINED fixture gets the same treatment for the harder version of the
    same hole: add a function to an existing fixture's source and it appears in
    no baseline cell, so it is not in the universe, so no selector reaches it and
    nothing says so -- and unlike a brand-new fixture there is no other signal at
    all. The comparison is against everything the baseline has EVER recorded for
    that fixture (unioned with its required list), not against what this run
    happened to select, or a scoped selector would make the note fire constantly
    and stop being read. Measured over the committed corpus, 2026-08-18: 194
    fixtures, every built lane, ZERO exports outside that set -- so the note is
    silent until a source genuinely outgrows its baseline.
    """
    if not BASELINE.is_file():
        return []
    baseline = json.loads(BASELINE.read_text())
    recorded: dict[str, set[str]] = {}
    for cell, fns in baseline.items():
        if cell.startswith("__") or not isinstance(fns, dict):
            continue
        recorded.setdefault(cell.split(":")[0], set()).update(
            name for name in fns if not name.startswith("__")
        )
    notes: list[str] = []
    for fixture in sorted({lane.fixture for lane in lanes}):
        if fixture in recorded:
            known = sorted(
                recorded[fixture] | set(M.REQUIRED_FUNCTIONS.get(fixture, ()))
            )
            unseen = _unjudged_function_names(fixture, known)
            if unseen:
                notes.append(
                    f"note: {len(unseen)} function(s) in {fixture}'s built object "
                    f"appear in NO baseline cell, so no selector reaches them and "
                    f"the gate has never judged them: {', '.join(unseen)}. "
                    f"Run `tools/fixture_harness.py --write-baseline`."
                )
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

    ORPHAN objects are skipped. `build/` accumulates names no current lane
    produces (`fixture_harness.cache_problems`), and taking the first one
    alphabetically would let a `132_cpp_vtable_layout-rustc-O0.so` — left behind
    when `lanes_for` stopped cross-producting C++ sources with Rust lanes — decide
    which functions this run claims not to have judged.
    """
    try:
        sys.path.insert(0, str(ROOT / "tools"))
        import diff_decompile as DD
    except Exception:
        return []
    # A stripped lane leaves TWO objects behind (`fixture_harness.dwarf_sibling`),
    # and the `.dwarf.so` oracle is not a lane of its own — `expected_objects`
    # does not name it. Its exports are identical to its stripped sibling's, so
    # reading it would give the same answer today, but it is not a lane and this
    # glob is the kind that quietly starts describing the wrong file.
    declared = {n for n in H.expected_objects() if n.startswith(f"{fixture}-")}
    for so in sorted(H.BUILD.glob(f"{fixture}-*.so")):
        if so.name not in declared:
            continue
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
    candidates = (
        list(src.glob(f"{lane.fixture}.c"))
        + list(src.glob(f"{lane.fixture}.cpp"))
        + list(src.glob(f"{lane.fixture}.rs"))
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
    # `ensure_fixture`, not a bare path read: the object at that path may have
    # been built by an older flag list, an older compiler, or the host toolchain
    # instead of the pinned one, and NOTHING in `build/` used to say so. Reading
    # the recovered C is the check the metrics cannot do, and it is worthless if
    # the C came out of a binary the current gate would never produce.
    so, err = H.ensure_fixture(candidates[0], lane.cc, lane.opt)
    if so is None:
        print(f"(build failed: {err.strip()[-160:]})")
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
    ap.add_argument(
        "selectors",
        nargs="*",
        default=None,
        help="default: @smoke (but see --arch: it retargets these, it does not replace them)",
    )
    ap.add_argument(
        "--arch",
        action="append",
        choices=list(ARCHES),
        help="retarget every selector to this architecture (repeatable). "
        "`@vector-float --arch i386` is the intended shape; judged against "
        "arch_baseline.json.",
    )
    ap.add_argument(
        "--stripped",
        action="store_true",
        help="retarget every selector to the STRIPPED lane (`-O2 -g` then "
        "`strip`), judged against the `-g` build of the same compile. "
        "`tools/stripped_differential.py` is the gated form.",
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

    # `--arch` RETARGETS the selectors; it is not itself a selector. Defaulting
    # silently to `@smoke` under `--arch` is how the cross-arch gate in CLAUDE.md
    # ran as `SCOPED: 16 lanes of 3078 (1%) - no regressions in scope` on
    # 2026-08-20: a green line, in the exact shape of the real gate, over one
    # half of one percent of the matrix. Refuse rather than guess.
    if not args.selectors and (args.arch or args.stripped):
        retarget = " ".join(f"--arch {a}" for a in args.arch or []) or "--stripped"
        print(
            f"error: {retarget} retargets the selectors you give it, and you gave "
            "none, so this would silently have run @smoke. Name what to retarget, "
            f"e.g. `dectest.py @o0 @o2 {retarget}`.",
            file=sys.stderr,
        )
        return 2
    try:
        lanes = resolve(
            args.selectors or ["@smoke"], arches=args.arch, stripped=args.stripped
        )
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
    regressions, improvements, infra, unbaselined = compare(
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
        # Listed, not merely counted: the summary line says how many cells were
        # never judged, and the only useful next question is "which ones, and
        # what did they do". Printing them without `--full` is the whole point --
        # `--full` was already the only way to see this and nobody reaches for it
        # when the last line says the run was clean.
        ("UNBASELINED (not judged; nothing to compare against)", unbaselined),
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
            unbaselined=unbaselined,
        )
    )
    if infra:
        return 2
    return 1 if regressions else 0


if __name__ == "__main__":
    raise SystemExit(main())
