"""Selection, named sets, and the staleness guard for `tools/dectest.py`.

The gate (`test_decompiler_fixture_matrix.py`) answers "did anything regress
anywhere". It is the wrong tool for iterating on one defect: it compiles and
executes 56 lanes to tell you about the one function you just changed.

`dectest` is the small-scope counterpart. These tests pin the two properties
that make it safe to use during iteration:

  * **selection is fail-closed.** A selector that matches nothing is an ERROR.
    A typo'd fixture name silently matching zero lanes would report "no
    regressions" and read exactly like success.
  * **a scoped run can never be mistaken for the gate.** `dectest` cannot write
    a baseline, and it labels its own scope in the summary line.

These are pure — no compiling, no executing — so they run in the normal suite.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "tests" / "decompiler_fixtures"))

import build_guard as BG  # ty: ignore[unresolved-import]
import dectest as D  # ty: ignore[unresolved-import]
import manifest as M  # ty: ignore[unresolved-import]

# --- selector grammar ------------------------------------------------------


def test_a_bare_fixture_selects_every_lane_and_function():
    sel = D.parse_selector("03_loop_shapes")
    assert sel == D.Selector("03_loop_shapes", "*", "*", "*")


def test_each_component_is_optional_left_to_right():
    assert D.parse_selector("03_loop_shapes:gcc").opt == "*"
    assert D.parse_selector("03_loop_shapes:gcc:O0").func == "*"
    assert D.parse_selector("03_loop_shapes:gcc:O0:sum_to").func == "sum_to"


def test_more_than_four_components_is_an_error():
    with pytest.raises(ValueError, match="too many"):
        D.parse_selector("a:b:c:d:e")


def test_globs_are_allowed_in_every_position():
    lanes = D.resolve(["*:gcc:O0:ternary*"])
    names = {(lane.fixture, lane.cc, lane.opt) for lane in lanes}
    assert ("01_conditional_polarity", "gcc", "O0") in names
    assert all(cc == "gcc" and opt == "O0" for _, cc, opt in names)
    got = {f for lane in lanes for f in lane.funcs}
    # Every selected function matches the pattern, and the fixture named above
    # contributes its two. Asserted as a property rather than an exact set:
    # `83_ternary_chains` was added to the corpus after this test was written
    # and legitimately answers to `ternary*` too, so pinning the set made a
    # correct selection look like a bug.
    assert {"ternary", "ternary_nested"} <= got
    assert all(f.startswith("ternary") for f in got)


def test_a_globbed_fixture_drops_fixtures_without_a_matching_function():
    """`*:...:ternary*` means "the ternary functions, wherever they are". Erroring
    because `02_integer_widths` has none would make cross-fixture selection
    useless — but the selector as a whole must still match something, which
    `test_a_selector_matching_a_fixture_but_no_function_is_an_error` pins."""
    lanes = D.resolve(["*:gcc:O0:ternary*"])
    fixtures = {lane.fixture for lane in lanes}
    # The property under test is the DROPPING, not the exact survivor list: any
    # fixture the corpus later adds with a `ternary*` function belongs here too.
    assert "01_conditional_polarity" in fixtures
    assert "02_integer_widths" not in fixtures
    assert all(any(f.startswith("ternary") for f in lane.funcs) for lane in lanes)


def test_functions_the_manifest_never_declares_are_still_selectable():
    """`REQUIRED_FUNCTIONS` is a presence contract covering about a third of the
    corpus; the harness executes every DWARF-typed export. Selecting only from
    the manifest would leave 72 functions unaddressable — including `mul_widen`,
    which the implementation directive names as the first failure to classify."""
    universe = D.function_universe()
    assert "mul_widen" in universe["02_integer_widths"]
    assert "mul_widen" not in M.REQUIRED_FUNCTIONS["02_integer_widths"]
    lanes = D.resolve(["02_integer_widths:gcc:O0:mul_widen"])
    assert lanes[0].funcs == ("mul_widen",)


def test_the_universe_still_contains_every_required_function():
    """The union must not lose the manifest's side: a fixture added since the
    last baseline refresh has no observed functions at all."""
    universe = D.function_universe()
    for fixture, required in M.REQUIRED_FUNCTIONS.items():
        assert set(required) <= set(universe[fixture])


def test_bare_fixture_uses_each_lanes_observed_function_set():
    """C++ constructor/destructor aliases differ by compiler and optimisation.
    A full-fixture selector must not demand GCC-only aliases from Clang lanes."""
    lanes = {lane.key: lane for lane in D.resolve(["10_cpp_runtime_shapes"])}
    assert "_ZN5GuardC1EPii" in lanes["10_cpp_runtime_shapes:gcc:O0"].funcs
    assert "_ZN5GuardC1EPii" not in lanes["10_cpp_runtime_shapes:clang:O0"].funcs


# --- fail-closed -----------------------------------------------------------


def test_a_selector_matching_no_fixture_is_an_error():
    """The property that matters most. A typo that silently matches nothing
    would print "no regressions in 0 lanes" and be read as green."""
    with pytest.raises(D.NoMatch, match="03_loop_shape\\b"):
        D.resolve(["03_loop_shape"])  # missing the trailing 's'


def test_a_selector_matching_a_fixture_but_no_function_is_an_error():
    with pytest.raises(D.NoMatch, match="no function"):
        D.resolve(["03_loop_shapes:gcc:O0:no_such_function"])


def test_an_unknown_compiler_is_an_error():
    with pytest.raises(D.NoMatch, match="no lane"):
        D.resolve(["03_loop_shapes:tcc:O0"])


def test_an_unknown_set_name_is_an_error_that_lists_the_real_ones():
    with pytest.raises(D.NoMatch) as e:
        D.resolve(["@nonexistent"])
    assert "smoke" in str(e.value)


# --- named sets ------------------------------------------------------------


def test_named_sets_expand_to_selectors():
    lanes = D.resolve(["@early-exit"])
    assert {lane.fixture for lane in lanes} == {"13_loop_early_exit"}


def test_every_committed_set_resolves_to_at_least_one_lane():
    """A set is a reproducible test corpus. One that has rotted — naming a
    fixture that was renamed, or a function that no longer exists — must fail
    here rather than silently shrink someone's iteration loop."""
    sets = D.load_sets()
    assert sets, "sets.toml is empty"
    for name in sets:
        lanes = D.resolve([f"@{name}"])
        assert lanes, f"set @{name} resolves to nothing"


def test_every_set_has_a_description():
    """`dectest --list-sets` is the discovery surface; an undescribed set is
    one nobody else will use."""
    for name, spec in D.load_sets().items():
        assert spec.get("description"), f"set @{name} has no description"


def test_the_smoke_set_is_actually_small():
    """`@smoke` exists to be run constantly. If it grows to gate size it stops
    being run, and the fast feedback loop is gone."""
    lanes = D.resolve(["@smoke"])
    assert len(lanes) <= 6, f"@smoke has grown to {len(lanes)} lanes"


# --- scope is never mistakable for the gate --------------------------------


def test_a_scoped_result_reports_its_scope():
    lanes = D.resolve(["03_loop_shapes:gcc:O0"])
    summary = D.summary_line(lanes, regressions=[], improvements=[], full_matrix=False)
    assert "SCOPED" in summary
    assert "1 lane" in summary


def test_infrastructure_errors_can_never_render_as_green():
    lanes = D.resolve(["03_loop_shapes:gcc:O0"])
    summary = D.summary_line(
        lanes,
        regressions=[],
        improvements=[],
        full_matrix=False,
        infra=["worker crashed"],
    )
    assert "INFRASTRUCTURE" in summary
    assert "no regressions" not in summary


def test_dectest_has_no_baseline_writing_flag():
    """Refreshing a baseline from a scoped run would record verdicts for the
    lanes that ran and leave the rest of the file describing an older build.
    The only writer stays `fixture_harness.py --write-baseline`, which always
    runs the full matrix."""
    flags = D.build_parser()._option_string_actions
    assert not any("baseline" in f for f in flags)


# --- the staleness guard ---------------------------------------------------


def test_a_native_extension_older_than_the_rust_source_is_stale(tmp_path):
    """The recorded failure mode this exists for: measuring a change against a
    `.so` built before it. It cost a whole gate cycle once already."""
    so = tmp_path / "_native.so"
    so.write_bytes(b"")
    src = tmp_path / "src"
    src.mkdir()
    rs = src / "lib.rs"
    rs.write_text("// newer\n")
    import os

    os.utime(so, (1_000_000, 1_000_000))
    os.utime(rs, (2_000_000, 2_000_000))
    assert BG.stale_reason(so, [src]) is not None


def test_a_native_extension_newer_than_the_rust_source_is_fresh(tmp_path):
    so = tmp_path / "_native.so"
    so.write_bytes(b"")
    src = tmp_path / "src"
    src.mkdir()
    (src / "lib.rs").write_text("// older\n")
    import os

    os.utime(src / "lib.rs", (1_000_000, 1_000_000))
    os.utime(so, (2_000_000, 2_000_000))
    assert BG.stale_reason(so, [src]) is None


def test_a_missing_native_extension_is_stale(tmp_path):
    assert BG.stale_reason(tmp_path / "absent.so", [tmp_path]) is not None


def test_the_repo_declares_where_its_native_extension_lives():
    assert BG.NATIVE_GLOB.parent.is_dir()


# --- the glaurung binary is found without an activated venv ----------------


def test_the_venv_binary_is_preferred_over_bare_path(monkeypatch):
    """The whole harness shells out to `glaurung`. Running the gate from a
    fresh shell used to die with `FileNotFoundError: 'glaurung'` because the
    venv was not on PATH — a confusing failure for an environment problem."""
    monkeypatch.delenv("GLAURUNG_BIN", raising=False)
    found = BG.glaurung_bin()
    assert found.endswith("glaurung")


def test_an_explicit_binary_overrides_everything(monkeypatch, tmp_path):
    fake = tmp_path / "glaurung"
    fake.write_text("#!/bin/sh\n")
    fake.chmod(0o755)
    monkeypatch.setenv("GLAURUNG_BIN", str(fake))
    assert BG.glaurung_bin() == str(fake)


def test_a_declared_binary_that_does_not_exist_is_an_error(monkeypatch):
    monkeypatch.setenv("GLAURUNG_BIN", "/nonexistent/glaurung")
    with pytest.raises(FileNotFoundError):
        BG.glaurung_bin()


# --- subprocesses use the synced interpreter without venv activation -------


def test_the_repo_venv_python_is_preferred_for_harness_workers(monkeypatch):
    """The executable ``tools/dectest.py`` may itself start under system Python.

    Its worker imports development dependencies such as ``pyelftools``.  The
    worker must therefore use the repository's synced interpreter, just as the
    CLI resolver prefers the repository's ``glaurung`` binary.
    """
    monkeypatch.delenv("GLAURUNG_PYTHON", raising=False)
    found = BG.python_bin()
    assert found == str(BG.ROOT / ".venv" / "bin" / "python")


def test_an_explicit_worker_python_overrides_the_repo_venv(monkeypatch, tmp_path):
    fake = tmp_path / "python"
    fake.write_text("#!/bin/sh\n")
    fake.chmod(0o755)
    monkeypatch.setenv("GLAURUNG_PYTHON", str(fake))
    assert BG.python_bin() == str(fake)


def test_no_reexec_when_already_using_the_synced_python(monkeypatch):
    monkeypatch.setattr(BG, "python_bin", lambda: BG.sys.executable)
    monkeypatch.setattr(
        BG.os,
        "execv",
        lambda *_: pytest.fail("must not replace an already-correct interpreter"),
    )
    BG.reexec_with_repo_python()


def test_executable_tool_reexecs_under_the_synced_python(monkeypatch, tmp_path):
    target = tmp_path / "venv-python"
    target.touch()
    monkeypatch.setattr(BG, "python_bin", lambda: str(target))
    monkeypatch.setattr(BG.sys, "executable", str(tmp_path / "system-python"))
    seen = {}

    def capture(executable, argv):
        seen["call"] = (executable, argv)
        raise RuntimeError("execv does not return")

    monkeypatch.setattr(BG.os, "execv", capture)
    with pytest.raises(RuntimeError, match="does not return"):
        BG.reexec_with_repo_python()
    assert seen["call"][0] == str(target.resolve())
    assert seen["call"][1][0] == str(target.resolve())


# --- the sets file is consistent with the corpus ---------------------------


# --- the architecture dimension --------------------------------------------
#
# `arch_roundtrip.py` has no function selection and no named sets, so the two
# architectures with the worst recorded failure rates (`armv7_a32`, `i386`) were
# the two with no fast loop. These pin the grammar that closes that, and — more
# importantly — pin that opening it did not quietly widen every existing set.


def test_an_architecture_is_selectable_in_the_compiler_slot():
    """The same slot, because the lane key is the same shape: `arch_baseline.json`
    keys `fixture:arch:opt` exactly as `baseline.json` keys `fixture:cc:opt`."""
    lanes = D.resolve(["173_float_int_conversions:i386:O2"])
    assert [lane.key for lane in lanes] == ["173_float_int_conversions:i386:O2"]
    assert lanes[0].is_arch


def test_an_architecture_lane_selects_one_function():
    lanes = D.resolve(["173_float_int_conversions:i386:O2:widen_int_to_float"])
    assert lanes[0].funcs == ("widen_int_to_float",)


def test_host_lanes_are_not_architecture_lanes():
    assert not D.resolve(["03_loop_shapes:gcc:O0"])[0].is_arch


def test_a_glob_in_the_compiler_slot_never_reaches_an_architecture():
    """The load-bearing containment property. A cross lane costs a cross build, a
    pinned reference build and an emulator; if `*` matched architectures, every
    committed set would silently grow by a factor of six and `@o0` would stop
    being an iteration loop."""
    lanes = D.resolve(["03_loop_shapes:*:O0"])
    assert {lane.cc for lane in lanes} == {"gcc", "clang"}
    assert not any(lane.is_arch for lane in lanes)


def test_the_committed_opt_sets_are_unchanged_by_the_arch_dimension():
    """`@o0` and `@o2` are the two broadest sets anyone runs. Their size is the
    concrete form of the containment property above.

    The count is pinned, so adding a fixture lands here deliberately rather than
    silently. 368 -> 370 on 2026-08-16: `197_homogeneous_float_aggregates` adds
    one `gcc` and one `clang` lane to each opt. 370 -> 376 on 2026-08-17: the
    return-type census fixtures `194_narrow_return_widths`,
    `198_aggregate_return_edges` and `199_pointer_return_kinds` add one `gcc` and
    one `clang` lane each. 376 -> 380 on 2026-08-19:
    `201_float_bit_stores` and `202_bit_scan_and_count` add one `gcc` and one
    `clang` lane each to each opt -- two fixtures, four lanes per opt.
    Update this WITH the fixture, and say which fixture moved it.
    """
    for name in ("o0", "o2"):
        lanes = D.resolve([f"@{name}"])
        assert len(lanes) == 380, f"@{name} is now {len(lanes)} lanes"
        assert not any(lane.is_arch for lane in lanes)


def test_arch_retargets_an_existing_set():
    """`@vector-float --arch i386` is the shape this exists for: every set names
    fixtures rather than lanes, so they all retarget without being rewritten."""
    lanes = D.resolve(["@vector-float"], arches=["i386"])
    assert lanes and all(lane.cc == "i386" for lane in lanes)
    assert {lane.fixture for lane in lanes} >= {"173_float_int_conversions"}


def test_arch_retargets_a_selector_that_named_a_host_compiler():
    lanes = D.resolve(["03_loop_shapes:gcc:O2:for_sum"], arches=["aarch64"])
    assert [lane.key for lane in lanes] == ["03_loop_shapes:aarch64:O2"]


def test_two_arches_expand_to_both():
    lanes = D.resolve(["03_loop_shapes:*:O2:for_sum"], arches=["i386", "aarch64"])
    assert {lane.cc for lane in lanes} == {"i386", "aarch64"}


def test_arch_contradicting_an_explicit_architecture_is_an_error():
    """Silently overwriting it would run something other than what was typed."""
    with pytest.raises(D.NoMatch, match="--arch"):
        D.resolve(["03_loop_shapes:i386:O2"], arches=["aarch64"])


def test_naming_the_same_architecture_twice_is_merely_redundant():
    lanes = D.resolve(["03_loop_shapes:i386:O2"], arches=["i386"])
    assert [lane.key for lane in lanes] == ["03_loop_shapes:i386:O2"]


def test_a_declared_unsupported_lane_says_so_instead_of_looking_like_a_typo():
    """`__int128` is not a type on a 32-bit target, so `02_integer_widths` has no
    i386 form at all. That is a probed, declared gap; reporting "no function
    matches" would read as a misspelling and send someone hunting."""
    with pytest.raises(D.NoMatch, match="declared, probed gap"):
        D.resolve(["02_integer_widths:i386:O0"])


def test_rust_fixtures_have_no_architecture_lanes():
    """`arch_roundtrip.TARGETS` configures no cross-`rustc`, so an arch lane for
    a Rust fixture names an object nothing builds."""
    rust = [f for f in D.function_universe() if (D.FIXTURES / f"src/{f}.rs").is_file()]
    assert rust, "no Rust fixture in the corpus to check"
    universe = D.arch_lane_function_universe()
    assert not [key for key in universe if key[0] in set(rust)]


def test_an_unknown_architecture_error_lists_the_real_ones():
    with pytest.raises(D.NoMatch, match="architectures:"):
        D.resolve(["03_loop_shapes:mips64:O0"])


def test_architecture_verdicts_are_compared_against_the_arch_baseline():
    """The comparison this rests on. i386 and x86-64 disagree on plenty of
    functions by construction; judging an i386 run against `baseline.json` would
    manufacture a regression for every one of them."""
    lane = D.Lane("03_loop_shapes", "i386", "O2", ("for_sum",))
    observed = {"03_loop_shapes:i386:O2": {"for_sum": "fail"}}
    host = {"03_loop_shapes:i386:O2": {"for_sum": "pass"}}
    arch = {"03_loop_shapes:i386:O2": {"for_sum": "fail"}}
    regressions, _improvements, infra, _unbaselined = D.compare(
        observed, host, [lane], arch_baseline=arch
    )
    assert not regressions and not infra
    regressions, _improvements, _infra, _unbaselined = D.compare(
        observed,
        host,
        [lane],
        arch_baseline={"03_loop_shapes:i386:O2": {"for_sum": "pass"}},
    )
    assert regressions


def test_the_scope_denominator_grows_only_when_an_arch_lane_is_in_scope():
    """A host-only run still reports its fraction of the 748 host lanes. Saying
    "1 of 748" about a run that touched an i386 lane would overstate it."""
    host = D.resolve(["03_loop_shapes:gcc:O0"])
    assert D.denominator(host) == D.FULL_MATRIX_LANES
    arch = D.resolve(["03_loop_shapes:i386:O0"])
    assert D.denominator(arch) > D.FULL_MATRIX_LANES


def test_an_arch_run_is_still_labelled_scoped():
    lanes = D.resolve(["03_loop_shapes:i386:O0"])
    summary = D.summary_line(lanes, regressions=[], improvements=[], full_matrix=False)
    assert "SCOPED" in summary


def test_the_arch_dimension_is_read_from_arch_roundtrip_not_restated():
    """One list. A target added to `arch_roundtrip.TARGETS` must become
    selectable without a second edit here."""
    import arch_roundtrip as AR  # ty: ignore[unresolved-import]

    assert set(D.ARCHES) == set(AR.TARGETS)


def test_the_two_slot_vocabularies_stay_disjoint():
    """`Lane.is_arch` decides which baseline judges a lane purely from the
    compiler slot. A name in both sets would make that ambiguous."""
    assert not set(D.COMPILERS) & set(D.ARCHES)


def test_sets_only_name_fixtures_that_exist():
    stems = set(M.REQUIRED_FUNCTIONS)
    for name, spec in D.load_sets().items():
        for raw in spec["selectors"]:
            fixture = D.parse_selector(raw).fixture
            if any(ch in fixture for ch in "*?["):
                continue
            assert fixture in stems, f"set @{name} names unknown fixture {fixture!r}"


# --- the unbaselined-fixture note -------------------------------------------
#
# `lane_function_universe` is the union of REQUIRED_FUNCTIONS and whatever
# `baseline.json` already observed, so a fixture with no baseline entry
# contributes only its required list. That is a real hole and it has already
# cost accuracy: `197_homogeneous_float_aggregates` declares five required
# functions and contains eleven, and the six that could not be shown held two
# genuine defects. See diary Entry 58.


def test_a_baselined_fixture_gets_no_note():
    """The note must be rare enough to be worth reading."""
    lanes = D.resolve(["195_by_value_aggregates:gcc:O0"])
    assert D.unbaselined_fixture_notes(lanes) == []


def test_an_unbaselined_fixture_is_named_with_its_judged_count(monkeypatch):
    """A fixture absent from the baseline must say so, and say how little it is
    judging, rather than silently reporting a partial verdict set as the whole
    result."""
    lanes = D.resolve(["195_by_value_aggregates:gcc:O0"])
    monkeypatch.setattr(
        D.json, "loads", lambda _text: {"other_fixture:gcc:O0": {"f": "pass"}}
    )
    notes = D.unbaselined_fixture_notes(lanes)
    assert len(notes) == 1, notes
    assert "195_by_value_aggregates has no baseline entry" in notes[0]
    assert "REQUIRED function(s) are judged" in notes[0]
    assert "--write-baseline" in notes[0]


def test_the_note_names_the_functions_it_cannot_judge(monkeypatch):
    """The count is only useful if it comes from the built object rather than a
    guess at the source text, so the names are the evidence."""
    monkeypatch.setattr(
        D,
        "_unjudged_function_names",
        lambda _fixture, _judged: ["helper_a", "helper_b"],
    )
    lanes = D.resolve(["195_by_value_aggregates:gcc:O0"])
    monkeypatch.setattr(D.json, "loads", lambda _text: {})
    note = D.unbaselined_fixture_notes(lanes)[0]
    assert "2 more in the built object are NOT judged: helper_a, helper_b" in note


def test_unjudged_names_are_empty_when_nothing_is_built(tmp_path, monkeypatch):
    """Saying nothing beats guessing: the note's value is that its count can be
    trusted."""
    monkeypatch.setattr(D.H, "BUILD", tmp_path)
    assert D._unjudged_function_names("195_by_value_aggregates", []) == []


# --- a gate must never render "nothing to compare against" as a pass ---------
#
# The family: three places where `dectest` compared a run to a baseline that had
# no entry for it, and reported the absence as agreement.
#
#   1. a new fixture's non-required functions are outside the selectable
#      universe until the first refresh -- reported by `unbaselined_fixture_notes`;
#   2. `--arch` could not reach an unbaselined fixture at all, because
#      `arch_lane_function_universe` read `arch_baseline.json` alone;
#   3. and the summary line, below, which said "no regressions in scope" over a
#      fixture whose forty cells included five failures.
#
# The rule they share: a cell the baseline says nothing about is a fourth
# outcome, not a silent fourth kind of pass.


def test_a_cell_with_no_baseline_entry_is_reported_not_swallowed():
    """The core of instance 3. `fail` against no baseline is not a regression --
    but it is emphatically not "no regressions" either."""
    lane = D.Lane("03_loop_shapes", "gcc", "O0", ("for_sum", "while_sum"))
    observed = {"03_loop_shapes:gcc:O0": {"for_sum": "fail", "while_sum": "pass"}}
    regressions, improvements, infra, unbaselined = D.compare(observed, {}, [lane])
    assert not regressions and not improvements and not infra
    assert len(unbaselined) == 2
    assert any("for_sum: fail (no baseline entry)" in u for u in unbaselined)


def test_a_run_that_judged_nothing_does_not_claim_no_regressions():
    """The exact shape that cost two agents a session: four lanes, forty cells,
    five of them failing, and a last line reading `no regressions in scope`."""
    lanes = D.resolve(["03_loop_shapes:gcc:O0"])
    cells = sum(len(lane.funcs) for lane in lanes)
    summary = D.summary_line(
        lanes,
        regressions=[],
        improvements=[],
        full_matrix=False,
        unbaselined=[f"c{i}" for i in range(cells)],
    )
    assert "no regressions" not in summary
    assert "NO VERDICT" in summary
    assert str(cells) in summary


def test_a_partly_unbaselined_run_still_says_how_much_it_did_not_judge():
    lanes = D.resolve(["03_loop_shapes:gcc:O0"])
    summary = D.summary_line(
        lanes,
        regressions=[],
        improvements=[],
        full_matrix=False,
        unbaselined=["03_loop_shapes:gcc:O0:new_helper: fail (no baseline entry)"],
    )
    assert "no regressions in scope" in summary
    assert "1 of" in summary and "UNBASELINED" in summary


def test_a_fully_baselined_run_says_nothing_about_unbaselined_cells():
    """The report has to be rare, or it becomes noise and stops being read."""
    lanes = D.resolve(["03_loop_shapes:gcc:O0"])
    summary = D.summary_line(lanes, regressions=[], improvements=[], full_matrix=False)
    assert "UNBASELINED" not in summary and "NO VERDICT" not in summary
    assert "no regressions in scope" in summary


def test_a_regression_still_outranks_an_unbaselined_cell():
    lanes = D.resolve(["03_loop_shapes:gcc:O0"])
    summary = D.summary_line(
        lanes,
        regressions=["03_loop_shapes:gcc:O0:for_sum: pass -> fail"],
        improvements=[],
        full_matrix=False,
        unbaselined=["03_loop_shapes:gcc:O0:new_helper: fail (no baseline entry)"],
    )
    assert "1 REGRESSION(S)" in summary


def test_an_unbaselined_fixture_is_selectable_on_an_architecture(monkeypatch):
    """Instance 2 of the family. `arch_lane_function_universe` used to be read
    from `arch_baseline.json` alone, so a fixture added since the last refresh
    could not be named on ANY architecture -- the selector failed as if it were a
    typo. It is reachable now because an unjudged verdict is reported rather than
    hidden."""
    monkeypatch.setattr(D, "_arch_baseline", dict)
    universe = D.arch_lane_function_universe()
    fixture = next(
        name
        for name in sorted(M.REQUIRED_FUNCTIONS)
        if next(p for p in D.FIXTURES.glob(f"src/{name}.*") if p.stem == name).suffix
        != ".rs"
    )
    assert (fixture, "i386", "O0") in universe
    assert set(universe[(fixture, "i386", "O0")]) == set(M.REQUIRED_FUNCTIONS[fixture])


def test_the_arch_universe_union_changes_nothing_for_a_baselined_corpus():
    """The union must be inert over what is already recorded, or it would quietly
    widen every existing `--arch` run."""
    universe = D.arch_lane_function_universe()
    for cell, fns in D._arch_baseline().items():
        if cell.startswith("__") or not isinstance(fns, dict) or "__lane__" in fns:
            continue
        parts = tuple(cell.split(":"))
        if len(parts) != 3 or parts[1] not in D.ARCHES:
            continue
        recorded = {n for n in fns if not n.startswith("__")}
        assert set(universe[parts]) == recorded, cell


def test_a_declared_arch_gap_is_still_a_gap_not_a_manufactured_lane():
    """`02_integer_widths` has no i386 form (`__int128` is not a 32-bit type).
    The manifest union must not resurrect it as a runnable lane -- the probed,
    declared gap is the more useful answer."""
    gaps = D.arch_unsupported_lanes()
    assert gaps, "expected at least one declared gap in arch_baseline.json"
    universe = D.arch_lane_function_universe()
    for key in gaps:
        assert key not in universe, key


def test_a_function_the_baseline_has_never_seen_is_named_even_on_a_baselined_fixture(
    monkeypatch,
):
    """Instance 1's harder form: add a function to an EXISTING fixture and it
    lands in no baseline cell, so no selector reaches it and -- before this --
    nothing said so. A brand-new fixture at least got its own note."""
    monkeypatch.setattr(
        D, "_unjudged_function_names", lambda _fixture, _known: ["brand_new_helper"]
    )
    lanes = D.resolve(["03_loop_shapes:gcc:O0"])
    (note,) = D.unbaselined_fixture_notes(lanes)
    assert "appear in NO baseline cell" in note
    assert "brand_new_helper" in note


def test_the_new_function_note_compares_against_the_whole_baseline_not_the_selection(
    monkeypatch,
):
    """A scoped selector must not make the note fire. `13_loop_early_exit:gcc:O0:bisect`
    judges one function of many, and calling the other five "never seen" would
    make the note noise within a day."""
    seen = {}

    def spy(fixture, known):
        seen[fixture] = list(known)
        return []

    monkeypatch.setattr(D, "_unjudged_function_names", spy)
    lanes = D.resolve(["03_loop_shapes:gcc:O0:for_sum"])
    assert D.unbaselined_fixture_notes(lanes) == []
    assert len(seen["03_loop_shapes"]) > 1, seen


def test_the_new_function_note_is_silent_on_the_committed_corpus():
    """Measured: 194 fixtures, every built lane, zero exports outside the
    baseline. If this goes red, either a source outgrew its baseline (refresh it)
    or the note has become noise (fix the note)."""
    lanes = D.resolve(["@smoke"])
    assert D.unbaselined_fixture_notes(lanes) == []
