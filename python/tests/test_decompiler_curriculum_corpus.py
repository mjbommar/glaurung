"""Fail-closed catalog checks for the undergraduate algorithms corpus.

These are not text snapshots.  Each catalog entry names a real C translation
unit whose exported functions are compiled, decompiled, rebuilt, and executed by
the fixture differential in all four compiler/optimization lanes.
"""

from __future__ import annotations

import importlib
import json
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
    "31_edit_distance": ["edit_distance", "hamming_distance"],
    "32_longest_common_subsequence": ["lcs_length", "lcs_recover"],
    "33_knapsack": ["knapsack_best_value", "unbounded_knapsack"],
    "34_coin_change": ["min_coins", "count_change"],
    "35_matrix_chain": ["matrix_chain_cost"],
    "36_quicksort": ["quicksort_i32"],
    "37_heapsort": ["heapsort_i32"],
    "38_insertion_shell_sort": ["insertion_sort_i32", "shell_sort_i32"],
    "39_counting_radix_sort": ["counting_sort_u8", "radix_sort_u32"],
    "40_quickselect": ["quickselect_kth", "median_of_three"],
    "41_tokenizer": ["tokenize"],
    "42_rpn_evaluator": ["rpn_evaluate"],
    "43_base64": ["base64_encode", "base64_decode"],
    "44_run_length": ["rle_encode", "rle_decode"],
    "45_string_algorithms": ["parse_decimal", "format_decimal", "is_palindrome"],
    "46_bitset": ["bitset_population", "bitset_rank", "bitset_select"],
    "47_huffman": ["huffman_code_lengths", "kraft_sum_q16"],
    "48_gray_code": [
        "binary_to_gray",
        "gray_to_binary",
        "reverse_bits32",
        "gray_sequence",
    ],
    "49_crc32": ["crc32_bitwise", "crc32_table_driven", "internet_checksum"],
    "50_varint": ["zigzag_encode", "zigzag_decode", "varint_encode", "varint_decode"],
    "51_rc4": ["rc4_keystream_checksum"],
    "52_hash_functions": ["fnv1a_32", "djb2_xor", "murmur3_finalize"],
    "53_pseudorandom": ["xorshift32", "lcg64_next_high", "bounded_sample"],
    "54_sha256_block": ["sha256_compress_block"],
    "55_modular_arithmetic": ["gcd_i32", "extended_gcd", "mod_pow"],
    "56_sieve": ["sieve_primes", "factorize"],
    "57_bignum": ["bignum_add", "bignum_mul_small"],
    "58_rational": ["rational_add", "rational_compare"],
    "59_combinatorics": ["pascal_row", "binomial", "catalan"],
    "60_integer_matrix": ["matrix_multiply", "matrix_transpose", "determinant3"],
    "61_fixed_point": ["fixed_multiply", "fixed_divide", "fixed_sqrt", "fixed_lerp"],
    "62_gaussian_elimination": ["gaussian_solve"],
    "63_numerical_integration": ["trapezoid_integrate", "simpson_integrate"],
    "64_root_finding": ["bisection_sqrt", "newton_sqrt"],
    "65_projectile_motion": ["projectile_step", "kinetic_energy"],
    "66_orbital_step": ["orbital_step"],
    "67_elastic_collision": [
        "elastic_velocity_a",
        "inelastic_velocity",
        "momentum_residual",
    ],
    "68_thermodynamics": ["ideal_gas_pressure", "newton_cooling", "mixing_temperature"],
    "69_molar_mass": ["molar_mass_centi"],
    "70_reaction_balance": ["balance_reaction"],
    "71_compound_interest": ["compound_balance", "annuity_future_value"],
    "72_loan_amortization": ["amortization_schedule", "remaining_balance"],
    "73_present_value": ["net_present_value", "internal_rate_of_return"],
    "74_moving_statistics": [
        "simple_moving_average",
        "exponential_moving_average",
        "population_variance",
    ],
    "75_order_book": ["match_order"],
    "76_portfolio_rebalance": ["maximum_drift", "rebalance_trades"],
    "77_lru_cache": ["lru_access"],
    "78_ring_buffer": ["ring_push", "ring_pop", "ring_occupancy"],
    "79_segment_tree": ["segment_build", "segment_update", "segment_range_sum"],
    "80_trie": ["trie_insert", "trie_lookup"],
}


def test_curriculum_catalog_is_complete_and_exact() -> None:
    assert M.CURRICULUM_PROJECTS == EXPECTED_CURRICULUM

    sources = {
        path.stem
        for path in (FIXTURES / "src").glob("*.c")
        if path.stem[:2].isdigit() and 15 <= int(path.stem[:2]) <= 80
    }
    assert sources == set(EXPECTED_CURRICULUM)

    for fixture, functions in EXPECTED_CURRICULUM.items():
        assert M.REQUIRED_FUNCTIONS[fixture] == functions


def test_curriculum_pointer_contracts_are_declared() -> None:
    """Every buffer-indexing function must declare its safe execution domain."""
    expected_contract_keys = {
        ("15_binary_search_tree", "bst_inorder_checksum"),
        ("15_binary_search_tree", "bst_search"),
        ("16_red_black_tree", "rb_validate"),
        ("17_hash_table", "hash_insert"),
        ("17_hash_table", "hash_lookup"),
        ("18_binary_heap", "heap_pop"),
        ("18_binary_heap", "heap_push"),
        ("19_disjoint_set", "dsu_find"),
        ("19_disjoint_set", "dsu_union"),
        ("20_graph_bfs", "graph_bfs"),
        ("21_graph_dfs", "graph_dfs"),
        ("22_dijkstra", "dijkstra_dense"),
        ("23_topological_sort", "topological_sort"),
        ("24_merge_sort", "merge_sort_i32"),
        ("25_kmp_search", "kmp_search"),
        ("26_sparse_matrix", "csr_matvec"),
        ("28_euler_ode", "euler_decay_q16"),
        ("29_polynomial", "polynomial_derivative_mod32"),
        ("29_polynomial", "polynomial_eval_mod32"),
        ("30_finite_difference", "heat_step_1d"),
        ("31_edit_distance", "edit_distance"),
        ("31_edit_distance", "hamming_distance"),
        ("32_longest_common_subsequence", "lcs_length"),
        ("32_longest_common_subsequence", "lcs_recover"),
        ("33_knapsack", "knapsack_best_value"),
        ("33_knapsack", "unbounded_knapsack"),
        ("34_coin_change", "count_change"),
        ("34_coin_change", "min_coins"),
        ("35_matrix_chain", "matrix_chain_cost"),
        ("36_quicksort", "quicksort_i32"),
        ("37_heapsort", "heapsort_i32"),
        ("38_insertion_shell_sort", "insertion_sort_i32"),
        ("38_insertion_shell_sort", "shell_sort_i32"),
        ("39_counting_radix_sort", "counting_sort_u8"),
        ("39_counting_radix_sort", "radix_sort_u32"),
        ("40_quickselect", "quickselect_kth"),
        ("41_tokenizer", "tokenize"),
        ("42_rpn_evaluator", "rpn_evaluate"),
        ("43_base64", "base64_decode"),
        ("43_base64", "base64_encode"),
        ("44_run_length", "rle_decode"),
        ("44_run_length", "rle_encode"),
        ("45_string_algorithms", "format_decimal"),
        ("45_string_algorithms", "is_palindrome"),
        ("45_string_algorithms", "parse_decimal"),
        ("46_bitset", "bitset_population"),
        ("46_bitset", "bitset_rank"),
        ("46_bitset", "bitset_select"),
        ("47_huffman", "huffman_code_lengths"),
        ("47_huffman", "kraft_sum_q16"),
        ("48_gray_code", "gray_sequence"),
        ("49_crc32", "crc32_bitwise"),
        ("49_crc32", "crc32_table_driven"),
        ("49_crc32", "internet_checksum"),
        ("50_varint", "varint_decode"),
        ("50_varint", "varint_encode"),
        ("51_rc4", "rc4_keystream_checksum"),
        ("52_hash_functions", "djb2_xor"),
        ("52_hash_functions", "fnv1a_32"),
        ("53_pseudorandom", "bounded_sample"),
        ("54_sha256_block", "sha256_compress_block"),
        ("55_modular_arithmetic", "extended_gcd"),
        ("56_sieve", "factorize"),
        ("56_sieve", "sieve_primes"),
        ("57_bignum", "bignum_add"),
        ("57_bignum", "bignum_mul_small"),
        ("58_rational", "rational_add"),
        ("58_rational", "rational_compare"),
        ("59_combinatorics", "pascal_row"),
        ("60_integer_matrix", "determinant3"),
        ("60_integer_matrix", "matrix_multiply"),
        ("60_integer_matrix", "matrix_transpose"),
        ("62_gaussian_elimination", "gaussian_solve"),
        ("63_numerical_integration", "simpson_integrate"),
        ("63_numerical_integration", "trapezoid_integrate"),
        ("64_root_finding", "bisection_sqrt"),
        ("64_root_finding", "newton_sqrt"),
        ("65_projectile_motion", "projectile_step"),
        ("66_orbital_step", "orbital_step"),
        ("68_thermodynamics", "newton_cooling"),
        ("69_molar_mass", "molar_mass_centi"),
        ("70_reaction_balance", "balance_reaction"),
        ("71_compound_interest", "annuity_future_value"),
        ("71_compound_interest", "compound_balance"),
        ("72_loan_amortization", "amortization_schedule"),
        ("72_loan_amortization", "remaining_balance"),
        ("73_present_value", "internal_rate_of_return"),
        ("73_present_value", "net_present_value"),
        ("74_moving_statistics", "exponential_moving_average"),
        ("74_moving_statistics", "population_variance"),
        ("74_moving_statistics", "simple_moving_average"),
        ("75_order_book", "match_order"),
        ("76_portfolio_rebalance", "maximum_drift"),
        ("76_portfolio_rebalance", "rebalance_trades"),
        ("77_lru_cache", "lru_access"),
        ("78_ring_buffer", "ring_pop"),
        ("78_ring_buffer", "ring_push"),
        ("79_segment_tree", "segment_build"),
        ("79_segment_tree", "segment_range_sum"),
        ("79_segment_tree", "segment_update"),
        ("80_trie", "trie_insert"),
        ("80_trie", "trie_lookup"),
    }
    for key in expected_contract_keys:
        contract = M.OVERRIDES.get(key)
        assert contract is not None, f"missing safe execution contract for {key}"
        # A function with no scalar parameter (sha256_compress_block,
        # determinant3, the ring-buffer pair) cannot pin one; for those the
        # safe domain IS the declared buffer length.
        assert (
            contract.get("len_args")
            or contract.get("arg_values")
            or contract.get("ptr_len")
        ), key


@pytest.mark.slow  # ty: ignore[unresolved-attribute]
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


@pytest.mark.slow  # ty: ignore[unresolved-attribute]
def test_optimized_bst_search_recovers_latch_and_terminal_returns(
    tmp_path: Path,
) -> None:
    """Clang's latch and shared epilogue must recover without duplicate exits."""
    source = FIXTURES / "src" / "15_binary_search_tree.c"
    binary = tmp_path / "15_binary_search_tree-clang-O2.so"
    compiled = subprocess.run(
        [
            "clang",
            "-shared",
            "-fPIC",
            "-g",
            "-O2",
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
    code = D.decompiled_c(str(binary), functions["bst_search"])
    assert code is not None
    assert code.count("do {") == 1, code
    assert code.count("return ") == 3, code
    validation_prefix = code.split("do {", maxsplit=1)[0]
    assert validation_prefix.count(" && ") == 2, code
    assert "goto " not in code, code

    inorder = D.decompiled_c(str(binary), functions["bst_inorder_checksum"])
    assert inorder is not None
    assert inorder.count("do {") == 2, inorder
    assert inorder.count("break;") == 1, inorder
    assert "goto " not in inorder, inorder


@pytest.mark.slow  # ty: ignore[unresolved-attribute]
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


@pytest.mark.slow  # ty: ignore[unresolved-attribute]
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


@pytest.mark.slow  # ty: ignore[unresolved-attribute]
def test_founding_curriculum_round_trips_in_every_lane() -> None:
    """Fixtures 15-30 are green and must stay green: a fail-closed ratchet."""
    founding = {
        fixture: functions
        for fixture, functions in M.CURRICULUM_PROJECTS.items()
        if 15 <= int(fixture[:2]) <= 30
    }
    lanes = [
        (fixture, compiler, optimization, tuple(functions))
        for fixture, functions in founding.items()
        for compiler, optimization in H.REQUIRED_MATRIX
    ]

    observed = H.run_lanes(lanes, fuzz=M.FIXTURE_FUZZ, jobs=8)

    for fixture, functions in founding.items():
        expected = dict.fromkeys(functions, "pass")
        for compiler, optimization in H.REQUIRED_MATRIX:
            lane = observed[f"{fixture}:{compiler}:{optimization}"]
            assert lane == expected, {
                function: status
                for function, status in lane.items()
                if status != "pass"
            }


@pytest.mark.slow  # ty: ignore[unresolved-attribute]
def test_expanded_curriculum_matches_recorded_baseline() -> None:
    """Fixtures 31-80 carry real, recorded decompiler debt.

    Asserting all-pass here would be false, and asserting nothing would let the
    debt drift. So this compares against `baseline.json` exactly: a recorded
    `fail` that now passes fails the test just as loudly as a regression, which
    forces the capability map to stay honest.
    """
    baseline = json.loads((FIXTURES / "baseline.json").read_text())
    expansion = {
        fixture: functions
        for fixture, functions in M.CURRICULUM_PROJECTS.items()
        if 31 <= int(fixture[:2]) <= 80
    }
    lanes = [
        (fixture, compiler, optimization, tuple(functions))
        for fixture, functions in expansion.items()
        for compiler, optimization in H.REQUIRED_MATRIX
    ]

    observed = H.run_lanes(lanes, fuzz=M.FIXTURE_FUZZ, jobs=8)

    drift: dict[str, dict[str, tuple[str, str]]] = {}
    for key, functions in observed.items():
        recorded = baseline[key]
        deltas = {
            function: (recorded.get(function), status)
            for function, status in functions.items()
            if recorded.get(function) != status
        }
        # An infrastructure status is never a semantic verdict; surface it as a
        # hard failure rather than letting it read as decompiler debt.
        infrastructure = {
            function: status
            for function, status in functions.items()
            if status in ("missing", "nocases", "timeout")
        }
        assert not infrastructure, f"{key}: infrastructure failure {infrastructure}"
        if deltas:
            drift[key] = deltas
    assert not drift, f"baseline drift (recorded -> observed): {drift}"
