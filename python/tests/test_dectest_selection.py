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
    assert got == {"ternary", "ternary_nested"}


def test_a_globbed_fixture_drops_fixtures_without_a_matching_function():
    """`*:...:ternary*` means "the ternary functions, wherever they are". Erroring
    because `02_integer_widths` has none would make cross-fixture selection
    useless — but the selector as a whole must still match something, which
    `test_a_selector_matching_a_fixture_but_no_function_is_an_error` pins."""
    lanes = D.resolve(["*:gcc:O0:ternary*"])
    assert {lane.fixture for lane in lanes} == {"01_conditional_polarity"}


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


def test_sets_only_name_fixtures_that_exist():
    stems = set(M.REQUIRED_FUNCTIONS)
    for name, spec in D.load_sets().items():
        for raw in spec["selectors"]:
            fixture = D.parse_selector(raw).fixture
            if any(ch in fixture for ch in "*?["):
                continue
            assert fixture in stems, f"set @{name} names unknown fixture {fixture!r}"
