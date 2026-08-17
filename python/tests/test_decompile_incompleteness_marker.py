"""A function the CFG walk could not finish must SAY it could not be finished.

Discovery walks each function under `analysis::cfg::Budgets`. When `max_blocks`
or `max_instructions` fires, the walk stops and the `Function` that comes back
holds only the blocks it reached. Until this marker existed, the rendered
pseudocode said nothing about it: `0x1401fd8a0` in the checked-in Intel wifi
driver renders 153 068 characters at `max_blocks=4096` and 61 942 characters at
`max_blocks=256`, and neither output claimed to be less than the whole function.

That is stop condition 1 verbatim -- incomplete input becoming apparently
complete downstream -- and it lands hardest where it matters most. The shipping
caller with the tightest budget is `llm/finding_verifier.py`, at 256 blocks and
2 000 instructions: a verifier reasoning about 40% of a function while believing
it holds all of it will clear a finding whose evidence sat in the dropped part.

The rate is low. Measured across four real binaries, 0.04%-0.10% of functions
exceed those budgets. The reason to fix it is not the rate: it is that the
affected set is systematically the largest and most complex functions -- the
ones an analyst or a vuln-hunting agent actually opens -- and that the failure
mode is silent wrongness rather than an error.

The property that makes the marker trustworthy is the SECOND test here, not the
first. A marker that fires on functions that were walked to completion is worse
than no marker, because it teaches the reader to ignore it.
"""

from __future__ import annotations

from pathlib import Path

import glaurung as g
import pytest

ROOT = Path(__file__).resolve().parent.parent.parent

# The marker token `analysis::completeness` emits. Tests match on the token, not
# on the prose, so the wording can be improved without breaking them.
MARKER = "GLAURUNG-INCOMPLETE"

# A checked-in gcc -O2 hello world: a handful of functions, all tiny, and no
# compiler needed. Two blocks is below several of them and above the rest, which
# is all the no-contamination property needs.
HELLO_GCC_O2 = (
    ROOT / "samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-gcc-O2"
)

# The reproduction from the diary: 643 blocks, the largest function in a 4.9 MB
# shipped Intel wifi driver.
NETWTW10 = (
    ROOT
    / "samples/binaries/platforms/windows/vendor/realworld"
    / "windows-update-intel-wifi-NETwtw10.sys"
)
NETWTW10_BIG_FUNC = 0x1401FD8A0


def _decompile_many(path: Path, vas: list[int], **kwargs) -> dict[int, str]:
    """Decompile several functions in ONE discovery run, keyed by entry VA."""
    return {
        va: text for _name, va, text in g.ir.decompile_many(str(path), vas, **kwargs)
    }


@pytest.mark.slow
def test_a_truncated_function_says_so_and_the_same_function_untruncated_does_not():
    """The diary's reproduction, now with the marker it was missing.

    Same binary, same function, same renderer -- only the block budget differs.
    At 256 blocks 387 of 643 blocks are dropped and the output must say so; at
    4096 the whole function is recovered and the output must be silent.
    """
    assert NETWTW10.exists(), NETWTW10

    truncated = g.ir.decompile_at(
        str(NETWTW10), NETWTW10_BIG_FUNC, max_blocks=256, types=True, style=""
    )
    complete = g.ir.decompile_at(
        str(NETWTW10), NETWTW10_BIG_FUNC, max_blocks=4096, types=True, style=""
    )

    assert MARKER in truncated, "a function stopped at max_blocks=256 must say so"
    assert "max_blocks=256" in truncated, (
        "the note must name the budget AND its value, or it is not actionable"
    )
    assert MARKER not in complete, (
        "the same function walked to completion must carry no marker"
    )
    # The marker is the only difference the reader is being asked to act on, and
    # the body it precedes really is the short one.
    assert len(complete) > len(truncated)


def test_one_run_marks_only_the_function_the_budget_stopped():
    """No contamination: the marker partitions a single run correctly.

    `decompile_many` performs ONE discovery for the whole requested set, so a
    design that read a whole-run truncation flag would mark every function here.
    `max_blocks=2` stops the larger functions in this binary and not the smaller
    ones, and each rendered body must reflect its own walk.
    """
    assert HELLO_GCC_O2.exists(), HELLO_GCC_O2

    # Every discovered entry, so the run genuinely contains both kinds.
    functions, _cg = g.analysis.analyze_functions_path(
        str(HELLO_GCC_O2), max_blocks=4096
    )
    whole_blocks = {f.entry_point.value: len(f.basic_blocks) for f in functions}
    vas = sorted(whole_blocks)
    assert len(vas) > 3, "need several functions for a partition to mean anything"

    complete = _decompile_many(HELLO_GCC_O2, vas, max_blocks=4096, types=False)
    assert all(MARKER not in text for text in complete.values()), (
        "nothing may be marked when no budget fired"
    )

    tight = _decompile_many(HELLO_GCC_O2, vas, max_blocks=2, types=False)
    marked = {va for va, text in tight.items() if MARKER in text}
    clean = {va for va, text in tight.items() if MARKER not in text}

    assert marked, "a 2-block budget must stop something in this binary"
    assert clean, (
        "at least one function must come through the SAME run unmarked -- "
        "that is the property the marker is worthless without"
    )

    # Each marked body really was cut short, and each unmarked one really was
    # not: at a wider budget the marked functions grow and the clean ones do not.
    for va in marked:
        assert whole_blocks[va] > 2, (
            f"0x{va:x} was marked incomplete but has only {whole_blocks[va]} blocks in all"
        )
        assert "max_blocks=2" in tight[va]
    for va in clean:
        assert whole_blocks[va] <= 2, (
            f"0x{va:x} has {whole_blocks[va]} blocks, above a 2-block budget, "
            "and was NOT marked"
        )


def test_the_note_does_not_invent_a_number_it_cannot_prove():
    """Honesty about what is and is not known.

    A bounded walk stops without enumerating what it would have reached, so the
    number of missing blocks is not recoverable afterwards. The note therefore
    names the budget that fired and refuses to quantify the loss.
    """
    functions, _cg = g.analysis.analyze_functions_path(
        str(HELLO_GCC_O2), max_blocks=4096
    )
    vas = sorted(f.entry_point.value for f in functions)
    tight = _decompile_many(HELLO_GCC_O2, vas, max_blocks=2, types=False)
    note = next(text for text in tight.values() if MARKER in text)
    header = "\n".join(line for line in note.splitlines() if line.startswith("//"))

    assert "not known" in header
    assert "max_blocks=2" in header
    # Every line of the note is a comment: prepending it can never break a
    # consumer that compiles the output.
    marker_line = next(line for line in note.splitlines() if MARKER in line)
    assert marker_line.startswith("//")


def test_the_flag_is_readable_from_python_not_only_from_the_rendered_text():
    """The signal is a fact on the function, not a string in one renderer.

    A consumer that never calls the decompiler -- a triage pass, the KB, an LLM
    tool listing functions -- can ask the same question of the same object.
    """
    tight, _tight_cg = g.analysis.analyze_functions_path(
        str(HELLO_GCC_O2), max_blocks=2
    )
    wide, _wide_cg = g.analysis.analyze_functions_path(
        str(HELLO_GCC_O2), max_blocks=4096
    )

    assert any(f.cfg_is_incomplete() for f in tight)
    assert not any(f.cfg_is_incomplete() for f in wide)
    for f in tight:
        if f.cfg_is_incomplete():
            assert f.cfg_incomplete_budgets() == ["max_blocks"]
            assert f.has_flag(g.FunctionFlags.CFG_BLOCK_LIMIT)
        else:
            assert f.cfg_incomplete_budgets() == []
