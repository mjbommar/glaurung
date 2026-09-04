"""Every emission style must render, not just the one the fixture gate uses.

Coverage analysis of the 688-lane corpus found that `src/ir/ast.rs`'s renderers
for `--style plain` (the CLI default) and `--style c` account for 2,210
uncovered regions — 64% of every miss in that file — because the execution
differential renders exclusively through `style="decbench"`.

That is not a missing C construct, it is a missing lane: the output an analyst
actually sees when they run `glaurung decompile` is produced by code no fixture
has ever exercised. This closes it without authoring a single new fixture, by
re-rendering fixtures the corpus already has.

The assertions are deliberately structural rather than golden-text. A golden
snapshot of three renderers over many fixtures would be enormous and would fail
on every legitimate rendering improvement, which trains people to regenerate it
unread. What must hold is weaker and unarguable: each style produces a
non-empty body that names the function and is brace-balanced. A renderer that
crashes, returns nothing, or emits truncated output fails; one that improves its
spelling does not.
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
FIXTURES = ROOT / "tests" / "decompiler_fixtures"
sys.path.insert(0, str(FIXTURES))
sys.path.insert(0, str(ROOT / "tools"))

H = importlib.import_module("fixture_harness")
D = importlib.import_module("diff_decompile")
M = importlib.import_module("manifest")

import glaurung as g

#: The three emission styles the renderer supports. "" is the CLI default
#: (`plain`); "decbench" is the only one the differential ever drives.
STYLES = ("", "c", "decbench")

#: A spread of shape families rather than a random sample: predicates, loops,
#: switches, aggregates, a graph algorithm, a language edge case, a C++ runtime
#: shape, and a floating-point kernel.
RENDER_CASES = [
    "01_conditional_polarity",
    "03_loop_shapes",
    "04_switch_shapes",
    "09_memory_effects",
    "20_graph_bfs",
    "26_sparse_matrix",
    "102_duffs_device",
    "118_bit_tricks",
    "130_bitpacked_codec",
    "175_float_matrix_kernel",
]

WIDE_CLANG_O2 = FIXTURES / "build" / "154_wide_switch-clang-O2.so"
LOOPS_GCC_O0 = FIXTURES / "build" / "03_loop_shapes-gcc-O0.so"


def test_shadow_batch_locally_declines_an_unavailable_function() -> None:
    """One typed refusal must not discard a verified sibling's v2 output."""
    exports = D.exported_functions(str(LOOPS_GCC_O0))
    rows = g.ir.decompile_many(
        str(LOOPS_GCC_O0),
        [exports["for_sum"], exports["dowhile_recompute"]],
        style="decbench",
        shadow_v2=True,
        max_functions=2,
    )

    assert [(name, va) for name, va, *_rest in rows] == [
        ("for_sum", exports["for_sum"])
    ]


def test_shadow_batch_rejects_a_non_decbench_style() -> None:
    """Local decline must not hide a caller error in the shadow contract."""
    exports = D.exported_functions(str(LOOPS_GCC_O0))

    with pytest.raises(ValueError, match="shadow_v2 requires style='decbench'"):
        g.ir.decompile_many(
            str(LOOPS_GCC_O0),
            [exports["for_sum"]],
            style="c",
            shadow_v2=True,
        )


def test_verified_shadow_region_uses_the_normal_typed_render_pipeline() -> None:
    # Isolate this render's verdict from any earlier test in the same process.
    g.ir.take_render_verification()
    exports = D.exported_functions(str(WIDE_CLANG_O2))
    [(_name, _va, body, *_extra)] = g.ir.decompile_many(
        str(WIDE_CLANG_O2),
        [exports["wide154_dense_effects"]],
        style="decbench",
        shadow_v2=True,
    )

    signature = next(
        line for line in body.splitlines() if "wide154_dense_effects(" in line
    )
    assert "int32_t" in signature, signature
    assert "int32_t *" in signature, signature
    assert "switch (" in body
    assert "case 0:" in body
    assert "case 255:" in body
    assert "unrecovered indirect jump" not in body

    verification = g.ir.take_render_verification()
    assert verification["verified_functions"] == 1, verification
    assert verification["undefined_uses"] == 0, verification
    assert verification["unverified"] == [], verification


def _source_for(fixture: str) -> Path:
    for suffix in (".c", ".cpp"):
        candidate = FIXTURES / "src" / f"{fixture}{suffix}"
        if candidate.is_file():
            return candidate
    raise AssertionError(f"no source for {fixture}")


@pytest.mark.slow
@pytest.mark.parametrize("fixture", RENDER_CASES)
def test_every_style_renders_every_function(fixture: str) -> None:
    source = _source_for(fixture)
    binary, error = H.compile_fixture(source, "gcc", "O0", strict=False)
    assert binary is not None, error

    exports = D.exported_functions(str(binary))
    required = [f for f in M.REQUIRED_FUNCTIONS[fixture] if f in exports]
    assert required, f"{fixture} exported none of its declared functions"

    for style in STYLES:
        rendered = g.ir.decompile_many(
            str(binary), [exports[f] for f in required], style=style
        )
        assert rendered, f"{fixture} style={style!r} rendered nothing at all"
        # decompile_many yields (name, va, code, size, variables) rows.
        for name, _va, body, *_extra in rendered:
            function = name
            assert body and body.strip(), (
                f"{fixture}:{function} style={style!r} rendered an empty body"
            )
            assert body.count("{") == body.count("}"), (
                f"{fixture}:{function} style={style!r} is brace-unbalanced, "
                f"i.e. truncated:\n{body}"
            )


@pytest.mark.slow
def test_styles_are_not_all_the_same_renderer() -> None:
    """The three styles must actually differ.

    If a style silently fell back to another, the lane above would still pass
    while covering nothing new — which is exactly the failure it exists to
    prevent.
    """
    source = _source_for("26_sparse_matrix")
    binary, error = H.compile_fixture(source, "gcc", "O0", strict=False)
    assert binary is not None, error
    exports = D.exported_functions(str(binary))
    va = exports["csr_matvec"]

    outputs = {}
    for style in STYLES:
        rendered = g.ir.decompile_many(str(binary), [va], style=style)
        assert rendered
        outputs[style] = rendered[0][2]

    assert len(set(outputs.values())) > 1, (
        "all emission styles produced byte-identical output, so at least one is "
        f"not really being selected: {sorted(outputs)}"
    )
