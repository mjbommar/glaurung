"""Fail-closed catalog checks for the undergraduate algorithms corpus.

These are not text snapshots.  Each catalog entry names a real C translation
unit whose exported functions are compiled, decompiled, rebuilt, and executed by
the fixture differential in all four compiler/optimization lanes.
"""

from __future__ import annotations

import importlib
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
FIXTURES = ROOT / "tests" / "decompiler_fixtures"
sys.path.insert(0, str(FIXTURES))
sys.path.insert(0, str(ROOT / "tools"))

M = importlib.import_module("manifest")
H = importlib.import_module("fixture_harness")
D = importlib.import_module("diff_decompile")


EXPECTED_CURRICULUM = {
    "15_binary_search_tree": ["bst_search", "bst_inorder_checksum"],
    "16_red_black_tree": ["rb_validate"],
    "17_hash_table": ["hash_lookup", "hash_insert"],
    "18_binary_heap": ["heap_push", "heap_pop"],
    "19_disjoint_set": ["dsu_find", "dsu_union"],
    "20_graph_bfs": ["graph_bfs"],
    "21_graph_dfs": ["graph_dfs"],
    "22_dijkstra": ["dijkstra_dense"],
    "23_topological_sort": ["topological_sort"],
    "24_merge_sort": ["merge_sort_i32"],
    "25_kmp_search": ["kmp_search"],
    "26_sparse_matrix": ["csr_matvec"],
    "27_newton_raphson": ["newton_isqrt"],
    "28_euler_ode": ["euler_decay_q16"],
    "29_polynomial": ["polynomial_eval_mod32", "polynomial_derivative_mod32"],
    "30_finite_difference": ["heat_step_1d"],
}


def test_curriculum_catalog_is_complete_and_exact() -> None:
    assert M.CURRICULUM_PROJECTS == EXPECTED_CURRICULUM

    sources = {
        path.stem
        for path in (FIXTURES / "src").glob("*.c")
        if path.stem[:2].isdigit() and 15 <= int(path.stem[:2]) <= 30
    }
    assert sources == set(EXPECTED_CURRICULUM)

    for fixture, functions in EXPECTED_CURRICULUM.items():
        assert M.REQUIRED_FUNCTIONS[fixture] == functions


def test_curriculum_pointer_contracts_are_declared() -> None:
    """Every buffer-indexing function must declare its safe execution domain."""
    expected_contract_keys = {
        ("15_binary_search_tree", "bst_search"),
        ("15_binary_search_tree", "bst_inorder_checksum"),
        ("16_red_black_tree", "rb_validate"),
        ("17_hash_table", "hash_lookup"),
        ("17_hash_table", "hash_insert"),
        ("18_binary_heap", "heap_push"),
        ("18_binary_heap", "heap_pop"),
        ("19_disjoint_set", "dsu_find"),
        ("19_disjoint_set", "dsu_union"),
        ("20_graph_bfs", "graph_bfs"),
        ("21_graph_dfs", "graph_dfs"),
        ("22_dijkstra", "dijkstra_dense"),
        ("23_topological_sort", "topological_sort"),
        ("24_merge_sort", "merge_sort_i32"),
        ("25_kmp_search", "kmp_search"),
        ("26_sparse_matrix", "csr_matvec"),
        ("29_polynomial", "polynomial_eval_mod32"),
        ("29_polynomial", "polynomial_derivative_mod32"),
        ("30_finite_difference", "heat_step_1d"),
    }
    for key in expected_contract_keys:
        contract = M.OVERRIDES.get(key)
        assert contract is not None, f"missing safe execution contract for {key}"
        assert contract.get("len_args") or contract.get("arg_values"), key


@pytest.mark.slow
def test_dijkstra_recovers_all_three_natural_loops(tmp_path: Path) -> None:
    """Validation, body-local breaks, and dead copies retain source structure."""
    source = FIXTURES / "src" / "22_dijkstra.c"
    binary = tmp_path / "22_dijkstra-gcc-O0.so"
    compiled = subprocess.run(
        [
            "gcc",
            "-shared",
            "-fPIC",
            "-g",
            "-O0",
            "-o",
            str(binary),
            str(source),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert compiled.returncode == 0, compiled.stderr

    functions = D.exported_functions(str(binary))
    code = D.decompiled_c(str(binary), functions["dijkstra_dense"])
    assert code is not None
    # Loop promotion may render a recovered natural loop as either form. Count
    # structure, not one spelling: Dijkstra contains the distance initializer,
    # iteration loop, best-node scan, and edge-relaxation scan.
    assert code.count("while (") + code.count("for (") >= 4, code
    assert code.count("for (") >= 2, code
    assert code.count("break;") == 1, code
    # GCC -O0 lowers the six input checks to a shared labelled exit. Recover
    # their source-level short-circuit predicate before the first natural loop;
    # the two remaining gotos belong to the best-node scan, not validation.
    validation_prefix = code.split("for (", maxsplit=1)[0]
    assert validation_prefix.count("if (") == 1, code
    assert validation_prefix.count(" || ") >= 5, code
    assert "goto " not in validation_prefix, code
    assert "ret = 0;" in validation_prefix, code
    # The best-node scan is the second shared-label shape in this fixture. It
    # must recover as `unused && (best < 0 || distance[i] < distance[best])`,
    # leaving no unstructured control flow anywhere in the function.
    assert " && " in code, code
    assert "goto " not in code, code
    for dead_copy in ("var15", "var18", "var22", "var23", "var45", "var59"):
        assert dead_copy not in code, code


@pytest.mark.slow
def test_sparse_validation_guards_recover_as_ordered_early_returns(
    tmp_path: Path,
) -> None:
    """A long compound guard must not be mistaken for a switch tree."""
    source = FIXTURES / "src" / "26_sparse_matrix.c"
    binary = tmp_path / "26_sparse_matrix-gcc-O0.so"
    compiled = subprocess.run(
        [
            "gcc",
            "-shared",
            "-fPIC",
            "-g",
            "-O0",
            "-o",
            str(binary),
            str(source),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert compiled.returncode == 0, compiled.stderr

    functions = D.exported_functions(str(binary))
    code = D.decompiled_c(str(binary), functions["csr_matvec"])
    assert code is not None
    validation_prefix = code.split("while (", maxsplit=1)[0]
    assert "goto " not in validation_prefix, code
    assert validation_prefix.count("return 0;") >= 10, code


@pytest.mark.slow
def test_signed_q16_bounds_round_trip_in_every_lane() -> None:
    """Wide negative saturation bounds must retain signed C semantics."""
    lanes = [
        ("28_euler_ode", compiler, optimization, ("euler_decay_q16",))
        for compiler, optimization in H.REQUIRED_MATRIX
    ]

    observed = H.run_lanes(lanes, fuzz=M.FIXTURE_FUZZ, jobs=4)

    for compiler, optimization in H.REQUIRED_MATRIX:
        lane = observed[f"28_euler_ode:{compiler}:{optimization}"]
        assert lane == {"euler_decay_q16": "pass"}, lane


@pytest.mark.slow
def test_every_curriculum_function_round_trips_in_every_lane() -> None:
    """The curriculum is a fail-closed behavioral ratchet, not a score snapshot."""
    lanes = [
        (fixture, compiler, optimization, tuple(functions))
        for fixture, functions in M.CURRICULUM_PROJECTS.items()
        for compiler, optimization in H.REQUIRED_MATRIX
    ]

    observed = H.run_lanes(lanes, fuzz=M.FIXTURE_FUZZ, jobs=8)

    for fixture, functions in M.CURRICULUM_PROJECTS.items():
        expected = dict.fromkeys(functions, "pass")
        for compiler, optimization in H.REQUIRED_MATRIX:
            lane = observed[f"{fixture}:{compiler}:{optimization}"]
            assert lane == expected, {
                function: status
                for function, status in lane.items()
                if status != "pass"
            }
