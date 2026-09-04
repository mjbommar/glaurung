"""The PyO3 surface of the native decompiler-quality metrics.

`src/metrics/` holds three metrics validated case-for-case against DecBench's
Python reference: `type_match` (T-3/T-6/T-7), `byte_match` (B-5..B-8) and the
control-skeleton tree distance. `src/python_bindings/metrics.rs` is what makes
them callable; this file is what says the binding did not change any of their
answers on the way out.

Every expectation here is taken from real data, not invented:

* the skeleton cases are checked-in C fixtures under
  `tests/decompiler_fixtures/src/`, and the three branchless ones are the same
  three `src/metrics/tree_distance.rs` uses to show that the class every
  CFG-derived metric collapses into a single value is separated;
* the assembly listings are the byte strings of real functions from the
  LFS sample tree that `src/metrics/byte_match.rs` cites by binary and
  symbol, with the reference's own expected output -- the bytes are inline
  here, so nothing on disk is read for them;
* the type-match triples are lines of that module's `DIFFERENTIAL_CORPUS`,
  whose ground-truth halves are real DWARF read out of the built fixture
  matrix by DecBench's own extractor, and whose expectations are the
  reference's output on them.

The two facts most worth protecting are the ones a convenience change would
quietly break: an **abstention is `None`**, never `0.0`, and repeated calls on
one input give byte-identical output.

This lane needs nothing but the built extension and the checked-in `.c`
fixtures, so it is `core`.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from glaurung._native import metrics

#: Checked-in C sources of the decompiler fixture corpus. NOT the gitignored
#: `build/` tree: these are the inputs the compiler is run over, and they are
#: present in a fresh clone.
FIXTURE_SRC = (
    Path(__file__).resolve().parents[2] / "tests" / "decompiler_fixtures" / "src"
)

#: The ten fields of the reference's `MetricValue.metadata`, in the order
#: `src/metrics/type_match.rs`'s `EXPECT` lines record them.
EXPECT_FIELDS = (
    "true_positives",
    "false_positives",
    "false_negatives",
    "shift",
    "matched_by_arg",
    "matched_by_offset",
    "matched_by_name",
    "decomp_stack_vars",
    "gt_stack_vars",
    "gt_arg_vars",
)


def _skeleton(relative: str, function: str) -> metrics.Skeleton:
    """Project one function of one checked-in fixture source.

    Args:
        relative: Path under `tests/decompiler_fixtures/src/`.
        function: The function to project.

    Returns:
        That function's control skeleton.
    """
    text = (FIXTURE_SRC / relative).read_text()
    return metrics.skeletons(text)[function]


def _expect_ten(result: dict[str, object]) -> tuple[object, ...]:
    """Reduce a `match_structured` result to the reference's ten-field tuple.

    Args:
        result: What `metrics.match_structured` returned.

    Returns:
        The ten fields in `EXPECT` order, comparable against a corpus line.
    """
    return tuple(result[field] for field in EXPECT_FIELDS)


# --- tree distance ----------------------------------------------------------


def test_skeletons_projects_every_function_of_a_real_fixture_file() -> None:
    """The whole-file entry point returns one skeleton per definition."""
    projected = metrics.skeletons((FIXTURE_SRC / "118_bit_tricks.c").read_text())

    assert "isolate_lowest_set" in projected
    assert "round_up_to_power_of_two" in projected
    one = projected["isolate_lowest_set"]
    assert one.render() == "(seq return)"
    assert len(one) == 2
    assert one.census() == {"seq": 1, "return": 1}
    assert one.kinds() == ["return", "seq"]  # post-order: children before root
    assert one.truncated is False


def test_the_branchless_class_that_ged_collapses_is_separated() -> None:
    """The point of the metric, on the three functions the Rust test uses.

    All three are one-node, no-edge, entry-and-exit CFGs, so DecBench's `ged`
    scores every pair of them a perfect 0.0. Their control skeletons differ,
    and the distances below are what `src/metrics/tree_distance.rs` computes
    for the same inputs -- a binding that lost the shape would have to invent
    these numbers to keep passing.
    """
    cases = {
        "isolate_lowest_set": _skeleton("118_bit_tricks.c", "isolate_lowest_set"),
        "absolute_without_branch": _skeleton(
            "117_modular_arithmetic.c", "absolute_without_branch"
        ),
        "struct_assignment_copies": _skeleton(
            "100_struct_layout.c", "struct_assignment_copies"
        ),
    }
    for name, skeleton in cases.items():
        assert skeleton.is_branchless, f"{name} must have no control flow"

    assert (
        metrics.tree_edit_distance(
            cases["isolate_lowest_set"], cases["absolute_without_branch"]
        )
        == 2
    )
    assert (
        metrics.tree_edit_distance(
            cases["isolate_lowest_set"], cases["struct_assignment_copies"]
        )
        == 5
    )
    assert (
        metrics.tree_edit_distance(
            cases["absolute_without_branch"], cases["struct_assignment_copies"]
        )
        == 3
    )
    # ...and the class is genuinely more than one skeleton, which is the claim
    # `docs/design/metrics-research/README.md` makes about it.
    assert len({skeleton.render() for skeleton in cases.values()}) == 3


def test_distance_is_zero_only_on_an_identical_skeleton_and_is_symmetric() -> None:
    """Metric axioms, at the boundary: identity, symmetry, and a real score."""
    left = _skeleton("118_bit_tricks.c", "isolate_lowest_set")
    right = _skeleton("100_struct_layout.c", "struct_assignment_copies")

    assert metrics.tree_edit_distance(left, left) == 0
    assert metrics.skeleton_score(left, left) == 1.0
    assert metrics.tree_edit_distance(left, right) == metrics.tree_edit_distance(
        right, left
    )
    # `1 - 3/4`: three edits against a four-node source.
    middle = _skeleton("117_modular_arithmetic.c", "absolute_without_branch")
    assert metrics.skeleton_score(middle, right) == pytest.approx(0.25)


def test_an_oversized_skeleton_abstains_rather_than_scoring_zero() -> None:
    """Above `MAX_SKELETON_NODES` the answer is `None`, not a number.

    An abstention leaves the denominator uniformly for every decompiler; a
    `0.0` here would be a made-up score for a function nobody measured, which
    is precisely how a shared denominator rots.
    """
    body = "x = 1;" * (metrics.MAX_SKELETON_NODES + 10)
    oversized = metrics.skeletons(f"void f(void){{{body}}}")["f"]
    small = _skeleton("118_bit_tricks.c", "isolate_lowest_set")

    assert len(oversized) > metrics.MAX_SKELETON_NODES
    assert metrics.tree_edit_distance(oversized, oversized) is None
    assert metrics.tree_edit_distance(oversized, small) is None
    assert metrics.skeleton_score(oversized, small) is None
    assert metrics.skeleton_score(small, oversized) is None


def test_projection_is_deterministic_across_repeated_calls() -> None:
    """Same text in, byte-identical skeleton out -- every gate here is a diff."""
    text = (FIXTURE_SRC / "100_struct_layout.c").read_text()
    first = metrics.skeletons(text)
    second = metrics.skeletons(text)

    assert list(first) == list(second)
    for name, skeleton in first.items():
        assert skeleton.render() == second[name].render()
        assert skeleton == second[name]
        assert list(skeleton.census().items()) == list(second[name].census().items())


# --- byte match -------------------------------------------------------------


def test_disassembles_a_real_x86_64_function_like_the_reference() -> None:
    """`rust-hello-static` in the LFS sample tree, `StripPrefixError::fmt`.

    The expectation is DecBench's `_disassemble_bytes(bytes, 0x2c890,
    (CS_ARCH_X86, CS_MODE_64))`, copied from the Rust test that asserts it.
    """
    data = bytes.fromhex(
        "504889f048893c24488d3541ae01004c8d05da9a02004889e1ba10000000"
        "4889c7ff1529b7020059c3"
    )

    assert metrics.disassemble_lines(data, 0x2C890, "x86_64") == [
        "push rax",
        "mov rax, rsi",
        "mov qword ptr [rsp], rdi",
        "lea rsi, [rip+X]",
        "lea r8, [rip+X]",
        "mov rcx, rsp",
        "mov edx, 0x10",
        "mov rdi, rax",
        "call qword ptr [rip+X]",
        "pop rcx",
        "ret",
    ]


def test_disassembles_a_real_aarch64_function_like_the_reference() -> None:
    """`c2_demo-arm64-gcc` in the LFS sample tree, `call_weak_fn` at 0xa34."""
    data = bytes.fromhex("800000b000f047f9400000b488ffff17c0035fd6")

    assert metrics.disassemble_lines(data, 0xA34, "arm64") == [
        "adrp xX, X",
        "ldr x0, [x0, #0xfe0]",
        "cbz xX, X",
        "b X",
        "ret",
    ]


def test_disassembles_a_real_arm_thumb_function_like_the_reference() -> None:
    """`hello-armhf-gcc` in the LFS sample tree, `print_sum` at 0x5c4 (Thumb).

    `b.w #0x450` keeps its absolute target: `b.w` is not in the reference's
    50-mnemonic branch set, and reproducing that defect is the parity.
    """
    data = bytes.fromhex("0249024601207944fff740bfba000000")

    assert metrics.disassemble_lines(data, 0x5C4, "arm_thumb") == [
        "ldr r1, [pc+X]",
        "mov r2, r0",
        "movs r0, #1",
        "add r1, pc",
        "b.w #0x450",
        "lsls r2, r7, #2",
        "movs r0, r0",
    ]


def test_normalization_makes_one_function_at_two_addresses_identical() -> None:
    """What B-6 is for, end to end: the same bytes, relocated, score 1.0.

    A recompiled function almost never lands where the original did. If the
    address survived normalization, every PC-relative line would count as
    changed and `byte_match` would measure the linker rather than the
    decompiler.
    """
    data = bytes.fromhex(
        "504889f048893c24488d3541ae01004c8d05da9a02004889e1ba10000000"
        "4889c7ff1529b7020059c3"
    )
    here = metrics.disassemble_lines(data, 0x2C890, "x86_64")
    elsewhere = metrics.disassemble_lines(data, 0x401000, "x86_64")

    assert here == elsewhere
    assert metrics.score_lines(here, elsewhere) == {
        "similarity": 1.0,
        "changed_lines": 0,
        "a_only": 0,
        "shared": 11,
        "b_only": 0,
    }
    assert metrics.normalize_operands("call", "0x10f9") == "X"
    assert metrics.normalize_operands("lea", "rsi, [rip + 0x1ae41]") == "rsi, [rip+X]"
    # A non-branch immediate is NOT blanked; only branch and PC-relative ones.
    assert metrics.normalize_operands("mov", "edx, 0x10") == "edx, 0x10"


def test_score_and_diff_agree_on_two_real_listings() -> None:
    """B-7 and B-8 on two real functions of different architectures.

    The chunk lengths must reconstruct both inputs exactly -- a diff whose runs
    do not add up to the listings it was given has silently dropped lines, and
    the ratio computed from it would still look plausible.
    """
    x86 = metrics.disassemble_lines(
        bytes.fromhex(
            "504889f048893c24488d3541ae01004c8d05da9a02004889e1ba10000000"
            "4889c7ff1529b7020059c3"
        ),
        0x2C890,
        "x86_64",
    )
    arm = metrics.disassemble_lines(
        bytes.fromhex("800000b000f047f9400000b488ffff17c0035fd6"), 0xA34, "arm64"
    )

    scored = metrics.score_lines(x86, arm)
    assert scored is not None
    assert (scored["a_only"], scored["shared"], scored["b_only"]) == (10, 1, 4)
    assert scored["changed_lines"] == 14
    assert scored["similarity"] == pytest.approx(1 / 15)

    chunks = metrics.diff_lines(x86, arm)
    assert chunks is not None
    assert {op for op, _ in chunks} <= {"delete", "equal", "insert"}
    assert sum(length for op, length in chunks if op in ("delete", "equal")) == len(x86)
    assert sum(length for op, length in chunks if op in ("insert", "equal")) == len(arm)
    assert sum(length for op, length in chunks if op == "equal") == scored["shared"]


def test_empty_listings_follow_the_reference_and_are_not_abstentions() -> None:
    """Two empty listings agree completely (1.0); one empty agrees not at all."""
    assert metrics.score_lines([], []) == {
        "similarity": 1.0,
        "changed_lines": 0,
        "a_only": 0,
        "shared": 0,
        "b_only": 0,
    }
    one_sided = metrics.score_lines(["ret"], [])
    assert one_sided is not None
    assert one_sided["similarity"] == 0.0
    assert one_sided["changed_lines"] == 1


def test_an_oversized_pair_abstains_rather_than_scoring_zero() -> None:
    """Above `MAX_DIFF_LINES` both entry points return `None`.

    The cap exists because an unbounded diff once asked the kernel for 5 GiB.
    What matters at this boundary is that the refusal stays distinguishable
    from a score of zero.
    """
    half = metrics.MAX_DIFF_LINES // 2 + 1
    listing = ["ret"] * half

    assert metrics.score_lines(listing, listing) is None
    assert metrics.diff_lines(listing, listing) is None
    # One line under the cap is scored, so the abstention is the cap and not
    # some unrelated failure on long input.
    ok = metrics.score_lines(["ret"] * (half - 1), ["ret"] * (half - 1))
    assert ok is not None
    assert ok["similarity"] == 1.0


def test_target_names_round_trip_through_capstone_constants() -> None:
    """A recorded DecBench cell stores `(arch, mode)`; both directions agree."""
    for name in ("x86_32", "x86_64", "arm", "arm_thumb", "arm64"):
        arch, mode = metrics.capstone_ids(name)
        assert metrics.asm_target(arch, mode) == name

    assert metrics.capstone_ids("x86_64") == (3, 8)
    # A pair `binfmt.capstone_arch_mode` never returns is an ordinary "not
    # scored here", not an exception.
    assert metrics.asm_target(9, 9) is None
    with pytest.raises(ValueError, match="unknown asm target"):
        metrics.disassemble_lines(b"\xc3", 0, "mips")


# --- type match -------------------------------------------------------------


def test_match_structured_reproduces_the_reference_on_real_dwarf() -> None:
    """Three cases of `type_match.rs`'s differential corpus, verbatim.

    Ground truth is real DWARF from the built fixture matrix, extracted by
    DecBench's own `extract_ground_truth_types`; the decompiled
    half is that ground truth perturbed the way a named backend perturbs it;
    and each `EXPECT` is what `TypeMatchMetric._match_structured` returned.
    """
    # 01_conditional_polarity-gcc-O0.so:classify|shadow|0 -- a spurious
    # variable inserted first collides with a real one and turns a true
    # positive into a false positive.
    shadowed = metrics.match_structured(
        [
            metrics.GroundTruthVar("a", ["int"], [-4], 4, 0),
            metrics.GroundTruthVar("b", ["int"], [-8], 4, 1),
        ],
        [
            metrics.DecompiledVar("b", "char *", -8, 4, 1),
            metrics.DecompiledVar("a", "int", -4, 4, 0),
            metrics.DecompiledVar("b", "int", -8, 4, 1),
        ],
        0,
    )
    assert _expect_ten(shadowed) == (1, 1, 0, 0, 2, 0, 0, 3, 2, 2)
    assert shadowed["score"] == pytest.approx(0.5)
    # Recall over ground truth: the extra decompiled variable is in
    # `decomp_vars` and in no bucket of the denominator.
    assert (shadowed["gt_vars"], shadowed["decomp_vars"]) == (2, 3)

    # 01_conditional_polarity-gcc-O0.so:early_return|ida|96 -- IDA numbers the
    # slot from the frame bottom, and the per-function shift override rescues
    # it from the binary-wide +96 it was given.
    ida = metrics.match_structured(
        [metrics.GroundTruthVar("x", ["int"], [-4], 4, 0)],
        [metrics.DecompiledVar("var_4", "__int32", 92, 4, 0)],
        96,
    )
    assert _expect_ten(ida) == (1, 0, 0, -96, 1, 0, 0, 1, 1, 1)
    assert ida["score"] == 1.0

    # 02_integer_widths-gcc-O0.so:rotl32_7|ghidra|0 -- Ghidra drops the
    # structured offset and widens the type; both variables are still matched,
    # one by argument position and one by the offset mined from `local_4`.
    ghidra = metrics.match_structured(
        [
            metrics.GroundTruthVar(
                "x", ["__uint32_t", "int", "unsigned int"], [-20], 4, 0
            ),
            metrics.GroundTruthVar(
                "r", ["__uint32_t", "int", "unsigned int"], [-4], 4, None
            ),
        ],
        [
            metrics.DecompiledVar("local_14", "undefined4", None, 4, 0),
            metrics.DecompiledVar("local_4", "undefined4", None, 4, None),
        ],
        0,
    )
    assert _expect_ten(ghidra) == (2, 0, 0, 0, 1, 1, 0, 2, 2, 1)
    assert ghidra["score"] == 1.0


def test_an_empty_ground_truth_scores_zero_and_is_the_callers_to_exclude() -> None:
    """The reference's `tp / total if total > 0 else 0.0`, reproduced.

    A function with no ground-truth variables is not a function whose types
    were recovered badly; the reference never scores one, and a caller has to
    filter it. The `0.0` is a placeholder, and this test is where that is
    written down.
    """
    result = metrics.match_structured(
        [], [metrics.DecompiledVar("var_4", "__int32", 92, 4, 0)], None
    )

    assert result["score"] == 0.0
    assert result["gt_vars"] == 0
    assert result["decomp_vars"] == 1


def test_binary_calibration_is_bounded_to_plus_or_minus_32() -> None:
    """T-5's window, which is why `match_structured` also has an override.

    Ghidra's mined offsets agree with DWARF, so the binary-wide shift is the
    attested `0`. IDA's are +96 away -- outside the fixed candidate window a
    binary-wide claim is allowed to range over -- so the binary-wide answer is
    `None` and the per-function override in `match_structured` is what recovers
    those slots (see the `ida` case above).
    """
    ground_truth = [
        metrics.GroundTruthVar("x", ["__uint32_t", "int", "unsigned int"], [-20], 4, 0),
        metrics.GroundTruthVar(
            "r", ["__uint32_t", "int", "unsigned int"], [-4], 4, None
        ),
    ]
    ghidra = [
        metrics.DecompiledVar("local_14", "undefined4", None, 4, 0),
        metrics.DecompiledVar("local_4", "undefined4", None, 4, None),
    ]
    ida = [
        metrics.DecompiledVar("var_14", "_QWORD", 76, 4, 0),
        metrics.DecompiledVar("var_4", "__uint32_t", 92, 4, None),
    ]

    assert metrics.binary_calibration_shift([(ground_truth, ghidra)]) == 0
    assert metrics.binary_calibration_shift([(ground_truth, ida)]) is None
    assert metrics.binary_calibration_shift([]) is None


def test_effective_offset_mines_the_offset_a_backend_left_in_the_name() -> None:
    """Two of the three major backends only report the offset in the name.

    A caller that fed raw `stack_offset`s to the calibration would drop every
    one of those slots, so this rule has to be reachable from Python too.
    """
    assert (
        metrics.effective_offset(metrics.DecompiledVar("local_1c", "undefined4")) == -28
    )
    assert metrics.effective_offset(metrics.DecompiledVar("var_20", "int")) == -32
    # A structured offset wins outright over the name.
    assert (
        metrics.effective_offset(metrics.DecompiledVar("local_1c", "undefined4", -8))
        == -8
    )
    # Ghidra's register-SSA variables are correctly not stack variables.
    assert metrics.effective_offset(metrics.DecompiledVar("uVar1", "uint")) is None


def test_ground_truth_forms_unions_sorts_and_deduplicates() -> None:
    """The producer-side normalization, sorted because it feeds a cache key.

    A typedef chain reports several spellings of one type; the union of their
    normalized forms is what a `GroundTruthVar` must carry, and an unstable
    order there once cost the reference 77% of its disk cache.
    """
    forms = metrics.ground_truth_forms(["__int32_t", "int", "int"])

    assert forms == sorted(forms)
    assert len(forms) == len(set(forms))
    assert "int" in forms
    assert metrics.ground_truth_forms([]) == []
