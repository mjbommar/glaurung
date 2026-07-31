"""The per-cell DecBench ratchet's comparator.

The matrix RUN is local-only (it needs the DecBench fork's `decbench evaluate`),
but its comparison logic is pure and must be tested here, because the failure
modes it exists to catch are precisely the ones that fooled us:

  * a cell that stops being scored at all silently IMPROVES the mean by leaving
    itself out. `recursion-gcc-O2` did exactly that — the O2 GED mean read 10.40
    over 27 binaries and looked like a win against angr's 14.46; including the
    binary put us at 14.42, a tie.
  * an aggregate hides one program getting much worse while another improves.

So `MISSING` and `GONE` are regressions, not absences.
"""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
TOOL = ROOT / "tools" / "decbench_matrix.py"


def _load():
    spec = importlib.util.spec_from_file_location("decbench_matrix", TOOL)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def dm():
    if not TOOL.exists():
        pytest.skip(f"{TOOL} missing")
    return _load()


def _report(dm, **cells):
    return {dm.TOOLCHAIN_KEY: {"gcc": "gcc 11", "clang": "clang 14"}, **cells}


def _cell(ged=5.0, type_match=0.9, byte_match=0.3):
    return {"ged": ged, "type_match": type_match, "byte_match": byte_match}


def test_an_identical_run_has_no_regressions(dm):
    base = _report(dm, **{"arith:gcc:O0": _cell()})
    assert dm.check(dict(base), base) == []


def test_a_worse_ged_is_a_regression(dm):
    base = _report(dm, **{"arith:gcc:O0": _cell(ged=5.0)})
    cur = _report(dm, **{"arith:gcc:O0": _cell(ged=6.0)})
    assert dm.check(cur, base) == ["arith:gcc:O0.ged: 5.0 -> 6.0"]


def test_a_lower_similarity_is_a_regression(dm):
    """GED is a distance and the other two are similarities, so `worse` points in
    opposite directions. Getting that backwards would make the ratchet celebrate
    every decline."""
    base = _report(dm, **{"arith:gcc:O0": _cell(type_match=0.9, byte_match=0.3)})
    cur = _report(dm, **{"arith:gcc:O0": _cell(type_match=0.5, byte_match=0.1)})
    problems = dm.check(cur, base)
    assert any("type_match: 0.9 -> 0.5" in p for p in problems), problems
    assert any("byte_match: 0.3 -> 0.1" in p for p in problems), problems


def test_an_improvement_is_not_a_regression(dm):
    base = _report(dm, **{"arith:gcc:O0": _cell(ged=5.0, type_match=0.9)})
    cur = _report(dm, **{"arith:gcc:O0": _cell(ged=4.0, type_match=0.95)})
    assert dm.check(cur, base) == []


def test_a_metric_that_stopped_being_scored_is_a_regression(dm):
    """The `recursion-gcc-O2` case: no GED at all, which an aggregate would treat
    as a smaller sample rather than a loss."""
    base = _report(dm, **{"recursion:gcc:O2": _cell(ged=123.0)})
    cur = _report(dm, **{"recursion:gcc:O2": _cell(ged=None)})
    assert dm.check(cur, base) == [
        "recursion:gcc:O2.ged: 123.0 -> GONE (no longer scored)"
    ]


def test_a_cell_absent_from_the_run_is_a_regression(dm):
    base = _report(dm, **{"arith:gcc:O0": _cell()})
    assert dm.check(_report(dm), base) == ["arith:gcc:O0: MISSING from the current run"]


def test_a_cell_absent_from_the_baseline_is_reported(dm):
    """A new cell must be recorded deliberately, the same discipline the fixture
    baseline uses — otherwise a corpus addition lands unmeasured."""
    base = _report(dm, **{"arith:gcc:O0": _cell()})
    cur = _report(dm, **{"arith:gcc:O0": _cell(), "newprog:gcc:O0": _cell()})
    assert dm.check(cur, base) == [
        "newprog:gcc:O0: present in the run but absent from the baseline"
    ]


def test_a_metric_never_scored_in_the_baseline_cannot_regress(dm):
    """Three binaries have no `type_match` on either side (DecBench finds no DWARF
    ground truth). That is a ground-truth gap, not ours, and must not be reported
    every run."""
    base = _report(dm, **{"recursion:gcc:O2": _cell(type_match=None)})
    cur = _report(dm, **{"recursion:gcc:O2": _cell(type_match=None)})
    assert dm.check(cur, base) == []


def test_metrics_are_not_comparable_across_a_toolchain_change(dm):
    """Comparing metrics measured under different compilers reports phantom
    regressions. Refuse the comparison instead."""
    base = _report(dm, **{"arith:gcc:O0": _cell()})
    cur = {
        dm.TOOLCHAIN_KEY: {"gcc": "gcc 14", "clang": "clang 14"},
        "arith:gcc:O0": _cell(),
    }
    problems = dm.check(cur, base)
    assert len(problems) == 1
    assert "not comparable" in problems[0]


def test_ged_is_compared_exactly_and_similarities_have_a_tolerance(dm):
    """GED is an integer edit count, so any movement is real. The similarities are
    ratios that can wobble in the last decimal."""
    assert dm.TOLERANCE["ged"] == 0.0
    assert dm.TOLERANCE["type_match"] > 0
    base = _report(dm, **{"a:gcc:O0": _cell(type_match=0.900)})
    tiny = _report(dm, **{"a:gcc:O0": _cell(type_match=0.899)})
    assert dm.check(tiny, base) == []


def test_the_corpus_is_committed_and_matches_the_matrix_size(dm):
    """The metrics in the design docs were measured against this corpus. It lived
    only in /tmp until 2026-07-26, which made them unrepeatable."""
    srcs = sorted(p.stem for p in dm.SRC.glob("*.c"))
    assert len(srcs) == 14, srcs
    assert "switch_jt" in srcs and "recursion" in srcs
    expected_cells = len(srcs) * len(dm.COMPILERS) * len(dm.OPTS)
    assert expected_cells == 56, expected_cells


def test_curriculum_corpus_selects_only_the_sixteen_textbook_projects(dm):
    src = dm.corpus_source("curriculum")
    projects = dm.corpus_programs("curriculum")

    assert projects == [
        "15_binary_search_tree",
        "16_red_black_tree",
        "17_hash_table",
        "18_binary_heap",
        "19_disjoint_set",
        "20_graph_bfs",
        "21_graph_dfs",
        "22_dijkstra",
        "23_topological_sort",
        "24_merge_sort",
        "25_kmp_search",
        "26_sparse_matrix",
        "27_newton_raphson",
        "28_euler_ode",
        "29_polynomial",
        "30_finite_difference",
    ]
    assert len(dm.all_cell_keys(src, projects)) == 64


def test_unknown_corpus_is_rejected_instead_of_falling_back(dm):
    with pytest.raises(ValueError, match="unknown corpus"):
        dm.corpus_source("typo")


# --- scoped runs (--only) --------------------------------------------------
#
# The full matrix is 56 cells, each spawning a Joern JVM. It historically took
# ~37 minutes serially; bounded isolated workers now reduce that wall clock. A
# change aimed at one program can still be measured against that program. The
# rules below stop a scoped run from being mistaken for the gate.


def test_a_bare_program_name_selects_all_four_of_its_cells(dm):
    assert dm.select_cells(["statemachine"]) == [
        "statemachine:gcc:O0",
        "statemachine:gcc:O2",
        "statemachine:clang:O0",
        "statemachine:clang:O2",
    ]


def test_curriculum_selection_never_leaks_non_curriculum_fixtures(dm):
    src = dm.corpus_source("curriculum")
    projects = dm.corpus_programs("curriculum")
    keys = dm.select_cells(["20_graph_bfs"], src, projects)
    assert keys == [
        "20_graph_bfs:gcc:O0",
        "20_graph_bfs:gcc:O2",
        "20_graph_bfs:clang:O0",
        "20_graph_bfs:clang:O2",
    ]
    assert all(
        not key.startswith("01_") for key in dm.select_cells(None, src, projects)
    )


def test_a_lane_glob_selects_that_lane_across_programs(dm):
    keys = dm.select_cells(["*:clang:O0"])
    assert len(keys) == 14
    assert all(k.endswith(":clang:O0") for k in keys)


def test_selecting_nothing_is_an_error_not_an_empty_run(dm):
    """The same fail-closed rule as `tools/dectest.py`: a typo that matched zero
    cells would print "no per-cell regressions across 0 cells"."""
    with pytest.raises(SystemExit, match="matches no cell"):
        dm.select_cells(["nosuchprogram"])


def test_no_selection_means_the_whole_matrix(dm):
    assert len(dm.select_cells(None)) == 56


def test_overlapping_selections_do_not_duplicate_cells(dm):
    keys = dm.select_cells(["statemachine", "statemachine:gcc:O0"])
    assert len(keys) == len(set(keys)) == 4


def test_a_scoped_check_does_not_report_unrun_cells_as_missing(dm):
    """Within the cells that ran, a regression is still a regression; the cells
    that were never selected are absent by construction, not lost."""
    base = _report(dm, **{"arith:gcc:O0": _cell(), "sort:gcc:O0": _cell()})
    cur = _report(dm, **{"arith:gcc:O0": _cell()})
    assert dm.check(cur, base, scoped=True) == []
    assert dm.check(cur, base, scoped=False) == [
        "sort:gcc:O0: MISSING from the current run"
    ]


def test_a_scoped_check_still_catches_a_regression_in_what_did_run(dm):
    base = _report(dm, **{"arith:gcc:O0": _cell(ged=5.0), "sort:gcc:O0": _cell()})
    cur = _report(dm, **{"arith:gcc:O0": _cell(ged=9.0)})
    assert dm.check(cur, base, scoped=True) == ["arith:gcc:O0.ged: 5.0 -> 9.0"]


# --- wall-clock parallelism ------------------------------------------------


def test_matrix_parallelism_is_bounded(dm):
    """Joern is memory-heavy, so use available CPUs without launching 56 JVMs."""
    assert dm.default_jobs(1) == 1
    assert dm.default_jobs(2) == 2
    assert dm.default_jobs(64) == 4


def test_parallel_cells_have_isolated_work_directories(dm, tmp_path):
    """Concurrent DecBench subprocesses must never share mutable result state."""
    first = dm.cell_workdir(tmp_path, "arith:gcc:O0")
    second = dm.cell_workdir(tmp_path, "arith:clang:O0")
    assert first != second
    assert first.parent == second.parent == tmp_path / "cells"
    assert first.name == "arith-gcc-O0"
    assert second.name == "arith-clang-O0"


def test_glaurung_cells_use_the_in_tree_decbench_adapter(dm, tmp_path, monkeypatch):
    """The external DecBench checkout deliberately has no Glaurung plugin.

    The metric lane must therefore launch DecBench through our owned adapter,
    while reference backends continue to use DecBench's normal console script.
    """
    python = tmp_path / "python"
    python.touch()
    monkeypatch.setenv("DECBENCH_PYTHON", str(python))

    assert dm.decbench_command(tmp_path, "glaurung") == [
        str(python),
        str(ROOT / "tools" / "decbench_glaurung.py"),
    ]
    assert dm.decbench_command(tmp_path, "angr") == ["decbench"]


def test_glaurung_evaluator_uses_the_repo_cli_without_an_activated_venv(
    dm, tmp_path, monkeypatch
):
    local = tmp_path / "glaurung"
    local.touch()
    monkeypatch.setattr(dm, "glaurung_bin", lambda: str(local))
    monkeypatch.delenv("GLAURUNG_BIN", raising=False)

    env = dm.evaluator_environment("glaurung")

    assert env["GLAURUNG_BIN"] == str(local)
    assert env["NO_COLOR"] == "1"


def _install_decbench_process(tmp_path: Path, body: str) -> Path:
    """Install a real subprocess fixture for evaluator failure-path coverage."""
    executable = tmp_path / "decbench"
    executable.write_text(f"#!/bin/sh\n{body}\n")
    executable.chmod(0o755)
    return executable


def test_real_evaluator_failure_is_not_silently_reported_as_blank_metrics(
    dm, tmp_path, monkeypatch
):
    _install_decbench_process(
        tmp_path, "echo \"Decompiler 'angr' not found\" >&2; exit 2"
    )
    monkeypatch.setenv("PATH", f"{tmp_path}{os.pathsep}{os.environ['PATH']}")

    result = dm.evaluate(
        tmp_path / "input.so",
        tmp_path / "input.c",
        "angr",
        tmp_path / "results",
        tmp_path,
    )

    assert result["ged"] is None
    assert "exit 2" in result["error"]
    assert "Decompiler 'angr' not found" in result["error"]


def test_real_evaluator_with_no_metrics_is_an_error(dm, tmp_path, monkeypatch):
    _install_decbench_process(tmp_path, 'echo "evaluation produced no report"; exit 0')
    monkeypatch.setenv("PATH", f"{tmp_path}{os.pathsep}{os.environ['PATH']}")

    result = dm.evaluate(
        tmp_path / "input.so",
        tmp_path / "input.c",
        "angr",
        tmp_path / "results",
        tmp_path,
    )

    assert result["ged"] is None
    assert "no metrics" in result["error"]
    assert "evaluation produced no report" in result["error"]
