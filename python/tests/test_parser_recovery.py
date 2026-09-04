"""Tests for `tools/parser_recovery_bench.py`.

Two tiers. The operator and metric tests are `core`: they need nothing but the
built extension, and they use small explicit C written *for this test file* --
it is unit-test input, never presented as decompiler output. The corpus tests
read the real Ghidra captures and the angr cache, so they skip when those are
absent.

A silently-skipped test is indistinguishable from a passing one, so
``GLAURUNG_PARSER_RECOVERY_DEMAND=1`` turns every skip in this file into a
failure. Run it that way on a machine that has the corpus.

This file was, briefly, deselected in its entirety. `tools/gen_test_facets.py`
classifies a *whole file* by text match, so the single test that read the
out-of-tree DecBench checkout tagged all fifty-nine and `pytest.ini` deselected
the lot -- the precise failure the demand switch above exists to prevent, one
level up. That test now lives in `test_parser_recovery_decbench.py`; everything
here needs nothing but the built extension. Run it with:



    uv run --with clang --with tree_sitter --with tree_sitter_c \
        pytest python/tests/test_parser_recovery.py -m ""
"""

from __future__ import annotations

import importlib.util
import os
import random
import sys
import threading
import time
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "parser_recovery_bench.py"


def _load_tool() -> ModuleType:
    """Import the benchmark as a module.

    `tools/` is not a package, so the module is loaded by path rather than by
    name -- importing it must not depend on the caller's ``sys.path``.

    Returns:
        The imported module.

    Raises:
        ImportError: When the tool cannot be loaded.
    """
    spec = importlib.util.spec_from_file_location("parser_recovery_bench", TOOL_PATH)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {TOOL_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


prb = _load_tool()


def _demanded() -> bool:
    """Whether skips in this file must be failures.

    Returns:
        ``True`` when ``GLAURUNG_PARSER_RECOVERY_DEMAND`` is set to ``1``.
    """
    return os.environ.get("GLAURUNG_PARSER_RECOVERY_DEMAND") == "1"


def _need(condition: bool, reason: str) -> None:
    """Skip -- or fail, under the demand switch -- when ``condition`` is false.

    Args:
        condition: What the test requires.
        reason: Why it cannot run.
    """
    if condition:
        return
    if _demanded():
        pytest.fail(f"demanded but unavailable: {reason}")
    pytest.skip(reason)


def _bounded(action: Callable[[], None], *, seconds: float) -> float:
    """Run ``action`` on a thread and fail if it outlives ``seconds``.

    Every test that drives `IsolatedRunner` must bound itself. A runner whose
    timeout stops firing would otherwise hang the whole suite -- which reads as
    "still running", not as a failure, and is precisely the defect these tests
    exist to catch. Measured: a mutation removing the runner's deadline hung a
    600-second pytest invocation before this helper existed.

    Args:
        action: What to run.
        seconds: Deadline.

    Returns:
        Elapsed wall-clock seconds.
    """
    thread = threading.Thread(target=action, daemon=True)
    started = time.monotonic()
    thread.start()
    thread.join(timeout=seconds)
    elapsed = time.monotonic() - started
    if thread.is_alive():
        pytest.fail(f"call did not bound itself ({elapsed:.1f}s and still going)")
    return elapsed


# Unit-test input, hand-written for these tests. Deliberately NOT decompiler
# output: the operators are exercised on a shape whose every offset is obvious,
# so an assertion failure points at the operator and not at a capture.
UNIT_A = prb.FunctionUnit(
    source="unit-test",
    binary="synthetic",
    name="alpha",
    text="int alpha(int a)\n{\n  int r = a + 1;\n  if (a) { r = r * 2; }\n  return r;\n}\n",
)
UNIT_B = prb.FunctionUnit(
    source="unit-test",
    binary="synthetic",
    name="beta",
    text="int beta(int b)\n{\n  int s = b - 1;\n  while (s) { s = s - 1; }\n  return s;\n}\n",
)
UNIT_C = prb.FunctionUnit(
    source="unit-test",
    binary="synthetic",
    name="gamma",
    text="int gamma(void)\n{\n  int t = 0;\n  return t;\n}\n",
)


@pytest.fixture(name="assembled")
def _assembled() -> prb.Assembled:
    """A three-function translation unit with recorded spans.

    Returns:
        The assembled unit.
    """
    return prb.assemble([UNIT_A, UNIT_B, UNIT_C])


# --- masking and slicing ----------------------------------------------------


@pytest.mark.core
def test_strip_c_noncode_preserves_offsets_and_hides_braces() -> None:
    """Masking must be offset-preserving, or every span in the tool is wrong."""
    text = 'int f(void) { char *s = "}{"; /* } */ return 0; } // }\n'
    masked = prb._strip_c_noncode(text)
    assert len(masked) == len(text)
    # Exactly two real braces survive: the body's opener and its closer.
    assert masked.count("{") == 1
    assert masked.count("}") == 1
    assert masked.index("{") == text.index("{")
    assert masked.rindex("}") == text.rindex("}", 0, text.index("//"))


@pytest.mark.core
@pytest.mark.parametrize(
    ("header", "expected"),
    [
        ("void FUN_00101020(void)\n", "FUN_00101020"),
        ("undefined8 * thunk(int a)\n", "thunk"),
        ("undefined1 [8] agg(void)\n", "agg"),
        ("/* WARNING: x */\n\nint __fastcall conv(int a)\n", "conv"),
        ("static void\nsplit_line(char *p)\n", "split_line"),
        ("int not_a_definition;\n", None),
        # A comment mentioning a call must not be mistaken for the declarator.
        (
            "/* WARNING: could not recover memcpy(dst, src, n) */\nvoid real(void)\n",
            "real",
        ),
        # Neither must a string in the preceding text.
        ('const char *s = "helper(";\nint after(int a)\n', "after"),
        # Nested parens in the parameter list.
        ("void cb(void (*fn)(int), int n)\n", "cb"),
    ],
)
def test_declarator_name(header: str, expected: str | None) -> None:
    """The name must come from the declarator, never from the return type."""
    assert prb._declarator_name(header) == expected


@pytest.mark.core
def test_slice_ghidra_functions_on_the_exporter_shape() -> None:
    """Two definitions, split at the right byte, names read from the header."""
    text = (
        "/* WARNING: bad data */\n\n"
        "void first(void)\n\n{\n  halt_baddata();\n}\n\n\n\n"
        "int second(int a)\n\n{\n  if (a) { return 1; }\n  return 0;\n}\n"
    )
    units = prb.slice_ghidra_functions(text, source="ghidra", binary="b")
    assert [unit.name for unit in units] == ["first", "second"]
    assert units[0].text.startswith("/* WARNING: bad data */")
    assert units[0].text.rstrip().endswith("}")
    assert "second" not in units[0].text
    assert "halt_baddata" not in units[1].text


# --- assembly ---------------------------------------------------------------


@pytest.mark.core
def test_assemble_spans_bracket_each_definition(assembled: prb.Assembled) -> None:
    """A span must contain its own function's body and no neighbour's."""
    assert assembled.names == ("alpha", "beta", "gamma")
    for unit in (UNIT_A, UNIT_B, UNIT_C):
        start, end = assembled.spans[unit.name]
        segment = assembled.text[start:end]
        assert segment == unit.text
        assert "// Function:" not in segment
    assert assembled.text.count("// Function: ") == 3


# --- damage operators -------------------------------------------------------
#
# Each operator gets an assertion on the SHAPE it is supposed to produce, not
# merely on "the text changed". An operator that no-ops, or that damages the
# wrong function, fails here.


@pytest.mark.core
@pytest.mark.parametrize("where", ["open_brace", "statement", "expression"])
def test_truncation_cuts_and_unbalances(assembled: prb.Assembled, where: str) -> None:
    """A truncation must shorten the file and leave an unclosed brace."""
    text, touched = prb.damage_truncate(
        assembled, "beta", random.Random(1), where=where
    )
    assert len(text) < len(assembled.text)
    masked = prb._strip_c_noncode(text)
    assert masked.count("{") > masked.count("}")
    assert touched == ("beta", "gamma")
    assert "int alpha(int a)" in text
    assert "int gamma(void)" not in text


@pytest.mark.core
def test_truncate_expression_cuts_deeper_than_statement(
    assembled: prb.Assembled,
) -> None:
    """The mid-expression cut must land past the statement cut, not on it."""
    at_statement, _ = prb.damage_truncate(
        assembled, "beta", random.Random(7), where="statement"
    )
    at_expression, _ = prb.damage_truncate(
        assembled, "beta", random.Random(7), where="expression"
    )
    assert len(at_expression) > len(at_statement)
    assert not at_expression.rstrip().endswith(";")


@pytest.mark.core
def test_drop_close_brace_removes_exactly_one(assembled: prb.Assembled) -> None:
    """One brace gone, from beta's body, and nothing else changed."""
    text, touched = prb.damage_drop_close_brace(assembled, "beta", random.Random(1))
    assert touched == ("beta",)
    assert len(text) == len(assembled.text) - 1
    masked_before = prb._strip_c_noncode(assembled.text)
    masked_after = prb._strip_c_noncode(text)
    assert masked_after.count("}") == masked_before.count("}") - 1
    assert masked_after.count("{") == masked_before.count("{")


@pytest.mark.core
def test_stray_close_brace_lands_inside_the_target(assembled: prb.Assembled) -> None:
    """The extra brace must be inside beta's span, not alpha's or gamma's."""
    text, touched = prb.damage_stray_close_brace(assembled, "beta", random.Random(3))
    assert touched == ("beta",)
    masked = prb._strip_c_noncode(text)
    assert masked.count("}") == prb._strip_c_noncode(assembled.text).count("}") + 1
    beta_start = text.index("int beta(int b)")
    gamma_start = text.index("int gamma(void)")
    inserted = text[beta_start:gamma_start]
    assert inserted.count("}") == 3  # the `while` closer, the stray, the real one


@pytest.mark.core
def test_drop_close_paren_unbalances_the_target(assembled: prb.Assembled) -> None:
    """One `)` gone from beta's body."""
    text, touched = prb.damage_drop_close_paren(assembled, "beta", random.Random(5))
    assert touched == ("beta",)
    masked = prb._strip_c_noncode(text)
    original = prb._strip_c_noncode(assembled.text)
    assert masked.count(")") == original.count(")") - 1
    assert masked.count("(") == original.count("(")


@pytest.mark.core
def test_overlapping_definition_injects_the_successor_header(
    assembled: prb.Assembled,
) -> None:
    """Gamma's header must appear inside beta's body, before beta closes."""
    text, touched = prb.damage_overlapping_definition(
        assembled, "beta", random.Random(9)
    )
    assert touched == ("beta", "gamma")
    assert text.count("int gamma(void)") == 2
    first_gamma = text.index("int gamma(void)")
    beta_start = text.index("int beta(int b)")
    assert beta_start < first_gamma < text.rindex("int gamma(void)")


@pytest.mark.core
def test_overlapping_definition_refuses_the_last_function(
    assembled: prb.Assembled,
) -> None:
    """There is no successor to splice, so the operator must decline."""
    with pytest.raises(ValueError, match="successor"):
        prb.damage_overlapping_definition(assembled, "gamma", random.Random(1))


@pytest.mark.core
def test_rodata_garbage_inserts_real_control_bytes(assembled: prb.Assembled) -> None:
    """The bytes must land as code, outside any literal."""
    text, touched = prb.damage_rodata_garbage(assembled, "beta", random.Random(2))
    assert touched == ("beta",)
    assert "\x1b" in text and "\x00" in text
    masked = prb._strip_c_noncode(text)
    assert "\x1b" in masked, "the escape must be outside a literal to be real damage"


@pytest.mark.core
def test_control_bytes_in_literal_stay_inside_the_literal(
    assembled: prb.Assembled,
) -> None:
    """DecBench's fifth rule: valid C, control bytes, but inside a string."""
    text, _ = prb.damage_control_bytes_in_literal(assembled, "beta", random.Random(2))
    assert "\x1b" in text
    masked = prb._strip_c_noncode(text)
    assert "\x1b" not in masked, "the bytes must be inside the literal"


@pytest.mark.core
def test_non_c_lines_are_not_c(assembled: prb.Assembled) -> None:
    """Two of the four canned lines, spliced into beta."""
    text, touched = prb.damage_non_c_lines(assembled, "beta", random.Random(4))
    assert touched == ("beta",)
    present = [line for line in prb._NON_C_LINES if line in text]
    assert len(present) == 2


@pytest.mark.core
@pytest.mark.parametrize(
    ("operator", "needle"),
    [
        (prb.damage_calling_convention, "__"),
        (prb.damage_usercall, "@<"),
        (prb.damage_register_annotation, " @ "),
        (prb.damage_aggregate_return, "undefined1 [8] beta(void)"),
        (prb.damage_int128_and_qword, "__int128"),
        (prb.damage_computed_goto, "goto *"),
        (prb.damage_gnu_extensions, "__typeof__"),
    ],
)
def test_dialect_and_gnu_operators_change_the_target_only(
    assembled: prb.Assembled,
    operator: Callable[
        [prb.Assembled, str, random.Random], tuple[str, tuple[str, ...]]
    ],
    needle: str,
) -> None:
    """Each operator must introduce its construct and touch only beta."""
    text, touched = operator(assembled, "beta", random.Random(11))
    assert touched == ("beta",)
    assert needle in text
    assert text != assembled.text
    # alpha is byte-identical up to the point where beta begins.
    alpha_end = text.index("// Function: beta")
    assert (
        text[:alpha_end] == assembled.text[: assembled.text.index("// Function: beta")]
    )


@pytest.mark.core
def test_usercall_produces_the_ida_spelling(assembled: prb.Assembled) -> None:
    """`__usercall beta@<eax>(...)`, not a stray `@` somewhere in the body."""
    text, _ = prb.damage_usercall(assembled, "beta", random.Random(0))
    header_start = text.index("// Function: beta")
    header = text[header_start : text.index("{", header_start)]
    assert "__usercall beta@<" in header


# --- case construction ------------------------------------------------------


@pytest.mark.core
def test_build_cases_is_deterministic_and_targets_a_non_first_function() -> None:
    """Same seed, same bytes; and the first function is never the target."""
    units = [
        UNIT_A,
        UNIT_B,
        UNIT_C,
        UNIT_C.__class__(**{**vars(UNIT_C), "name": "delta"}),
    ]
    first = prb.build_cases(units, seed=5, cases_per_source=1, functions_per_case=4)
    second = prb.build_cases(units, seed=5, cases_per_source=1, functions_per_case=4)
    assert [(case.case_id, case.text) for case in first] == [
        (case.case_id, case.text) for case in second
    ]
    other = prb.build_cases(units, seed=6, cases_per_source=1, functions_per_case=4)
    assert len(other) == len(first)

    pristine = [case for case in first if case.damage_class == "1-pristine"]
    assert len(pristine) == 1 and pristine[0].touched == ()
    for case in first:
        if case.damage_class == "1-pristine":
            continue
        assert case.touched, f"{case.case_id} claims to have damaged nothing"
        assert case.functions[0] not in case.touched
        assert case.intact, f"{case.case_id} left nothing intact to score"
        assert case.pristine_id == pristine[0].case_id


@pytest.mark.core
def test_every_damage_class_is_represented() -> None:
    """A class that produced no case would be silently absent from the report."""
    units = [
        UNIT_A,
        UNIT_B,
        UNIT_C,
        UNIT_C.__class__(**{**vars(UNIT_C), "name": "delta"}),
    ]
    cases = prb.build_cases(units, seed=5, cases_per_source=1, functions_per_case=4)
    produced = {case.damage_class for case in cases}
    assert produced == set(prb.DAMAGE_CLASSES)
    variants = {case.variant for case in cases if case.damage_class != "1-pristine"}
    expected = {
        variant
        for operators in prb.DAMAGE_OPERATORS.values()
        for variant, _ in operators
    }
    assert variants == expected


@pytest.mark.core
def test_normalize_pool_dedupes_and_caps() -> None:
    """Duplicate names inside one binary make ground truth ambiguous."""
    duplicate = prb.FunctionUnit(
        source="unit-test", binary="synthetic", name="alpha", text=UNIT_A.text
    )
    blacklisted = prb.FunctionUnit(
        source="unit-test", binary="synthetic", name="JUMPOUT", text=UNIT_A.text
    )
    pool = [UNIT_A, duplicate, blacklisted, UNIT_B, UNIT_C]
    kept = prb.normalize_pool(pool, max_per_binary=10)
    assert [unit.name for unit in kept] == ["alpha", "beta", "gamma"]
    assert [unit.name for unit in prb.normalize_pool(pool, max_per_binary=2)] == [
        "alpha",
        "beta",
    ]


# --- parsers ----------------------------------------------------------------


@pytest.mark.core
def test_parse_ours_finds_definitions_and_ignores_empty_bodies() -> None:
    """Our front end, on the shape the benchmark feeds it."""
    text = prb.assemble([UNIT_A, UNIT_B]).text
    got = prb.parse_ours(text)
    assert set(got) == {"alpha", "beta"}
    assert all(rec.body_size > 0 for rec in got.values())
    assert got["alpha"].signature != got["beta"].signature


@pytest.mark.core
def test_signatures_discriminate_a_changed_body() -> None:
    """A structure signature that never changes would make fidelity vacuous.

    This is the mutation check for the fidelity metric: swap one branch for a
    loop and every parser's signature must move.
    """
    branchy = "int f(int a)\n{\n  int r = 0;\n  if (a) { r = 1; }\n  return r;\n}\n"
    loopy = "int f(int a)\n{\n  int r = 0;\n  while (a) { r = 1; }\n  return r;\n}\n"
    ours_a, ours_b = prb.parse_ours(branchy)["f"], prb.parse_ours(loopy)["f"]
    assert ours_a.signature != ours_b.signature
    assert prb.parse_ours(branchy)["f"].signature == ours_a.signature

    pytest.importorskip("tree_sitter_c") if not _demanded() else __import__(
        "tree_sitter_c"
    )
    ts_a, ts_b = prb.parse_tree_sitter(branchy)["f"], prb.parse_tree_sitter(loopy)["f"]
    assert ts_a.signature != ts_b.signature


@pytest.mark.core
def test_tree_sitter_flags_a_broken_body_but_still_reports_it() -> None:
    """tree-sitter always returns a tree, so `error_free` is its only signal."""
    _need(
        importlib.util.find_spec("tree_sitter_c") is not None,
        "tree_sitter_c not installed",
    )
    good = prb.parse_tree_sitter(UNIT_A.text)["alpha"]
    broken = prb.parse_tree_sitter(
        "int alpha(int a)\n{\n  int r = a + ;\n  return r;\n}\n"
    )
    assert good.error_free is True
    assert broken["alpha"].error_free is False


#: The three shapes that separate semantic from syntactic tolerance. Every one
#: is syntactically well-formed C; only the *types* are missing, which is what
#: real Ghidra output looks like.
UNDEFINED_TYPE_SHAPES = {
    "unknown_return": (
        "undefined8 f(undefined8 a)\n{\n  undefined8 r;\n  r = g(a);\n  return r;\n}\n"
    ),
    "unknown_local": "void f(void)\n{\n  undefined8 r;\n  r = g();\n  return;\n}\n",
    "known_return": "int f(int a)\n{\n  undefined8 r;\n  r = g(a);\n  return 0;\n}\n",
}


@pytest.mark.core
def test_clang_discards_the_body_of_an_untypeable_function() -> None:
    """clang's recovery is semantic, and it loses code -- silently.

    Measured, not assumed: with an unknown *return* type clang still reports a
    ``FUNCTION_DECL`` that ``is_definition()``, but its ``COMPOUND_STMT`` is
    empty -- the whole body is gone. With a known return type and an unknown
    local type it keeps the body but drops the statements it cannot type. A CFG
    built from either is wrong, and nothing in the AST says so.

    This is the load-bearing counterexample to "semantic tolerance is easy", so
    it is asserted rather than described.
    """
    _need(importlib.util.find_spec("clang") is not None, "clang.cindex not installed")
    _need(
        any(Path(candidate).exists() for candidate in prb.LIBCLANG_CANDIDATES),
        "no libclang",
    )
    unknown_return = prb.parse_clang(UNDEFINED_TYPE_SHAPES["unknown_return"])
    assert unknown_return == {}, "clang is expected to lose the function entirely"

    unknown_local = prb.parse_clang(UNDEFINED_TYPE_SHAPES["unknown_local"])
    assert unknown_local["f"].body_size == 1, "only the `return` survives"
    assert unknown_local["f"].error_free is False

    known_return = prb.parse_clang(UNDEFINED_TYPE_SHAPES["known_return"])
    assert known_return["f"].body_size == 2, (
        "`undefined8 r;` and `r = g(a);` are dropped"
    )


@pytest.mark.core
def test_ours_and_tree_sitter_keep_untypeable_bodies() -> None:
    """The syntactic front ends keep every statement clang discards."""
    _need(
        importlib.util.find_spec("tree_sitter_c") is not None,
        "tree_sitter_c not installed",
    )
    for shape, text in UNDEFINED_TYPE_SHAPES.items():
        ours = prb.parse_ours(text)
        assert "f" in ours and ours["f"].body_size > 0, f"ours lost {shape}"
        theirs = prb.parse_tree_sitter(text)
        assert theirs["f"].body_size >= 10, f"tree-sitter thinned {shape}"
        assert theirs["f"].error_free is True, f"tree-sitter saw an error in {shape}"


# --- runner and scoring -----------------------------------------------------


@pytest.mark.core
def test_isolated_runner_records_a_crash_rather_than_raising() -> None:
    """A parser that explodes is a result, not an aborted run.

    Exercises the real worker subprocess, not a stand-in: the fault is injected
    through `DIAGNOSTIC_PARSERS`, which the worker resolves exactly the way it
    resolves a real parser.
    """
    runner = prb.IsolatedRunner(60.0)
    box: dict[str, Any] = {}
    _bounded(
        lambda: box.__setitem__(
            "o", runner.run("__diagnostic_crash", "int f(void){return 0;}")
        ),
        seconds=90.0,
    )
    runner.close()
    outcome = box["o"]
    assert outcome.status == "crash"
    assert "diagnostic crash" in outcome.detail


@pytest.mark.core
def test_isolated_runner_records_a_hang_rather_than_hanging() -> None:
    """A hang must be bounded by the timeout, killed, and reported.

    Regression test for a real defect in this harness: the first version forked
    its worker from a multi-threaded pytest process and deadlocked at 0% CPU,
    which is indistinguishable from a slow parser. A fresh interpreter plus a
    hard kill is what fixed it, so the kill is asserted here too.
    """
    runner = prb.IsolatedRunner(3.0)
    box: dict[str, Any] = {}

    def call() -> None:
        box["outcome"] = runner.run("__diagnostic_hang", "int f(void){return 0;}")
        # Read the worker table BEFORE close() empties it, or the assertion
        # below passes for the wrong reason.
        box["workers"] = dict(runner._workers)

    elapsed = _bounded(call, seconds=30.0)
    runner.close()
    assert box["outcome"].status == "timeout"
    assert elapsed < 30.0, f"the timeout did not bound the call ({elapsed:.1f}s)"
    assert box["workers"] == {}, (
        "the wedged worker must be killed, not left in the table"
    )


@pytest.mark.core
def test_isolated_runner_survives_a_killed_worker() -> None:
    """After a timeout the next call must still work, on a fresh worker."""
    runner = prb.IsolatedRunner(3.0)
    box: dict[str, Any] = {}

    def call() -> None:
        box["first"] = runner.run("__diagnostic_hang", "int f(void){return 0;}")
        box["kept"] = "__diagnostic_hang" in runner._workers
        # The same parser key must come back on a *new* worker, not the dead one.
        box["second"] = runner.run("__diagnostic_hang", "int f(void){return 0;}")
        box["recovered"] = runner.run("ours", UNIT_A.text)

    _bounded(call, seconds=60.0)
    runner.close()
    assert box["first"].status == "timeout"
    assert box["kept"] is False, "the wedged worker was kept"
    assert box["second"].status == "timeout"
    assert box["recovered"].status == "ok"
    assert "alpha" in box["recovered"].functions


@pytest.mark.core
def test_isolated_runner_moves_real_text_through_the_pipe() -> None:
    """Control bytes and NULs must survive the JSON round trip to the worker."""
    assembled = prb.assemble([UNIT_A, UNIT_B, UNIT_C])
    text, _ = prb.damage_rodata_garbage(assembled, "beta", random.Random(2))
    assert "\x00" in text
    runner = prb.IsolatedRunner(60.0)
    box: dict[str, Any] = {}
    _bounded(lambda: box.__setitem__("o", runner.run("ours", text)), seconds=90.0)
    runner.close()
    outcome = box["o"]
    assert outcome.status == "ok"
    assert "alpha" in outcome.functions


@pytest.mark.core
def test_score_counts_recall_localization_and_fidelity() -> None:
    """The three metrics must move independently, on hand-built outcomes."""
    pristine = prb.Case(
        case_id="c0",
        pristine_id="c0",
        source="unit-test",
        damage_class="1-pristine",
        variant="none",
        text="",
        functions=("a", "b", "c"),
        touched=(),
    )
    damaged = prb.Case(
        case_id="c0:x",
        pristine_id="c0",
        source="unit-test",
        damage_class="6-structural",
        variant="x",
        text="",
        functions=("a", "b", "c"),
        touched=("c",),
    )
    base = prb.ParseOutcome(
        functions={
            name: prb.Recovered(body_size=1, signature=f"sig-{name}", error_free=True)
            for name in ("a", "b", "c")
        }
    )
    # `a` survives identically, `b` survives but its structure changed, `c` is
    # the damaged one and is lost.
    after = prb.ParseOutcome(
        functions={
            "a": prb.Recovered(body_size=1, signature="sig-a", error_free=True),
            "b": prb.Recovered(body_size=1, signature="MOVED", error_free=False),
        }
    )
    outcomes = {("ours", "c0"): base, ("ours", "c0:x"): after}
    tallies = prb.score([pristine, damaged], outcomes)

    control = tallies[("ours", "unit-test", "1-pristine")]
    assert (control.recall_hit, control.recall_total) == (3, 3)
    assert (control.fidelity_hit, control.fidelity_total) == (3, 3)

    cell = tallies[("ours", "unit-test", "6-structural")]
    assert (cell.recall_hit, cell.recall_total) == (2, 3)
    assert (cell.local_hit, cell.local_total) == (2, 2)
    assert (cell.fidelity_hit, cell.fidelity_total) == (1, 2)
    assert (cell.error_free_hit, cell.error_free_total) == (1, 2)


@pytest.mark.core
def test_pristine_misses_names_the_lost_function() -> None:
    """A class-1 loss must be reported by name, not folded into a rate."""
    pristine = prb.Case(
        case_id="c0",
        pristine_id="c0",
        source="unit-test",
        damage_class="1-pristine",
        variant="none",
        text="",
        functions=("a", "b"),
        touched=(),
    )
    outcome = prb.ParseOutcome(
        functions={"a": prb.Recovered(body_size=1, signature="s", error_free=True)}
    )
    misses = prb.pristine_misses([pristine], {("ours", "c0"): outcome})
    assert misses["ours"] == ["c0/b"]


# --- the real corpus --------------------------------------------------------


@pytest.mark.core
def test_corpus_names_are_scoreable_by_our_own_policy() -> None:
    """`parity_cfgs` drops blacklisted names; the corpus must not contain any."""
    assert prb.is_corpus_name("FUN_00101020")
    assert not prb.is_corpus_name("JUMPOUT")
    assert not prb.is_corpus_name("<global>")
    assert not prb.is_corpus_name("")


def test_ghidra_captures_slice_into_real_functions() -> None:
    """The real captures must yield definitions whose bodies our parser reads."""
    out = Path(os.environ.get("GLAURUNG_GHIDRA_OUT", prb.DEFAULT_GHIDRA_OUT))
    _need(out.is_dir(), f"no Ghidra captures at {out}")
    units = prb.load_ghidra_units(out)
    assert len(units) > 100, f"only {len(units)} units sliced"
    assert all(unit.text.rstrip().endswith("}") for unit in units)
    # Ground truth is the slicer's; check it against a parser on a sample.
    sample = prb.normalize_pool(units, max_per_binary=4)[:20]
    recovered = 0
    for unit in sample:
        if unit.name in prb.parse_ours(unit.text):
            recovered += 1
    assert recovered >= len(sample) - 2, f"{recovered}/{len(sample)} names agree"


def test_angr_cache_holds_real_decompiler_output() -> None:
    """The angr corpus must exist, name its functions, and be parseable C-ish."""
    cache = prb.DEFAULT_CACHE_DIR / "angr-units.json"
    _need(cache.is_file(), f"no angr cache at {cache}; run `capture-angr` first")
    units = prb.load_angr_units(cache)
    assert len(units) > 50, f"only {len(units)} angr units"
    assert all(unit.source == "angr" for unit in units)
    assert all("{" in unit.text and "}" in unit.text for unit in units)
    # angr names the function itself, so ground truth is the producer's.
    assert any(unit.name.startswith("sub_") for unit in units)


@pytest.mark.core
def test_sanitizer_hazard_abstains_without_a_checkout(tmp_path: Path) -> None:
    """No checkout means no column, not a crash and not a zero.

    A zero would read as "nothing needed rewriting", which is the opposite of
    "we could not look".
    """
    units = [
        UNIT_A,
        UNIT_B,
        UNIT_C,
        UNIT_C.__class__(**{**vars(UNIT_C), "name": "delta"}),
    ]
    cases = prb.build_cases(units, seed=5, cases_per_source=1, functions_per_case=4)
    assert prb.sanitizer_hazard(cases, tmp_path / "not-a-checkout") is None


@pytest.mark.core
def test_definition_name_reads_the_declarator_not_the_preamble() -> None:
    """angr prefixes each function with typedefs and externs of its own."""
    angr_shaped = (
        "typedef struct struct_0 {\n    unsigned long long field_0;\n} struct_0;\n\n"
        "extern struct_0 *g_403ff8;\n\n"
        "unsigned long long * sub_401000(void)\n{\n    return 0;\n}\n"
    )
    assert prb.definition_name(angr_shaped) == "sub_401000"
    assert prb.definition_name("extern int x;\n") is None


@pytest.mark.core
@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("main", "main"),
        ("_166_rust_generics::max_generic", "max_generic"),
        ("std::sys::unix::args::imp::ARGV_INIT_ARRAY::init_wrapper", "init_wrapper"),
        ("_ZN3std3sysE", "_ZN3std3sysE"),
    ],
)
def test_normalized_name_strips_only_qualification(raw: str, expected: str) -> None:
    """Name normalization must be qualification-only, never a demangler."""
    assert prb.normalized_name(raw) == expected


@pytest.mark.core
def test_normalized_keeps_the_larger_body_on_a_collision() -> None:
    """Two qualified names collapsing onto one must not lose the real body."""
    functions = {
        "a::f": prb.Recovered(body_size=1, signature="small", error_free=True),
        "b::f": prb.Recovered(body_size=9, signature="large", error_free=True),
    }
    assert prb._normalized(functions)["f"].signature == "large"


def test_angr_ground_truth_matches_what_the_text_declares() -> None:
    """angr's `Function.name` is the mangled symbol; its codegen is demangled.

    Regression test for a real corpus defect: taking ground truth from angr's
    symbol table scored every parser 52.5% on undamaged output, because the
    mangled name never appears in the text any parser is given.
    """
    cache = prb.DEFAULT_CACHE_DIR / "angr-units.json"
    _need(cache.is_file(), f"no angr cache at {cache}; run `capture-angr` first")
    units = prb.load_angr_units(cache)
    assert units, "the cache produced no units"
    for unit in units:
        assert prb.definition_name(unit.text) == unit.name
        assert not unit.name.startswith("_ZN"), f"{unit.name} is a mangled symbol"


@pytest.mark.core
def test_calling_convention_precedes_the_whole_qualified_declarator() -> None:
    """`__fastcall` must land before `A::b`, never inside it.

    Regression test for a harness defect that cost real accuracy: splicing in
    front of the last component produced `_166_rust_generics::__fastcall
    max_generic`, which no decompiler emits, and it showed up in the matrix as
    a 7.5-point loss for our parser that was actually the harness's fault.
    """
    qualified = prb.FunctionUnit(
        source="unit-test",
        binary="synthetic",
        name="max_generic",
        text="u32 _166_rust_generics::max_generic(int a)\n{\n  return a;\n}\n",
    )
    assembled = prb.assemble([UNIT_A, qualified])
    text, _ = prb.damage_calling_convention(assembled, "max_generic", random.Random(1))
    assert (
        "::__fastcall" not in text
        and "::__cdecl" not in text
        and "::__stdcall" not in text
    )
    assert any(
        f"{convention} _166_rust_generics::max_generic(" in text
        for convention in ("__fastcall", "__cdecl", "__stdcall")
    ), text[text.index("// Function: max_generic") :][:120]

    usercall, _ = prb.damage_usercall(assembled, "max_generic", random.Random(1))
    assert "__usercall _166_rust_generics::max_generic@<" in usercall
