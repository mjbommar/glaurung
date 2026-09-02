"""Known decompiler defects, encoded as tests that will announce their own fix.

Why this file exists
--------------------

A suite that is 100% green over a decompiler with known trade-offs is not
measuring the trade-offs. Every defect located during investigation and then
left only in a commit message or a plan document is a defect that will be
rediscovered, re-diagnosed, and re-argued.

The contract here is the one `test_decompiler_curriculum_corpus.py` already
uses: each test asserts the **correct** behaviour and carries
`@pytest.mark.xfail(strict=True)` with an `OPEN DEFECT` reason. Today it xfails
and the report says so out loud. The day someone fixes it, the test XPASSes,
`strict=True` turns that red, and the fix cannot land unnoticed.

That is deliberately the opposite of pinning today's output. Two lanes added
earlier in this workstream did pin it (`assert got == today`), which makes a
fix indistinguishable from a regression — they have been converted.

What is NOT here
----------------

Defects that already have a home stay there: `-flto` return-type collapse and
`bst_search` loop rotation are in the curriculum corpus, the clang-14 `fsm`
switch loss is in the CI-gap phase, and the AArch64 FMA and PDB-prototype gaps
sit in the format lanes that found them. This file is for defects with no
natural lane.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
SRC_DIR = ROOT / "tests" / "open_defects"
sys.path.insert(0, str(ROOT / "tools"))

import diff_decompile as D  # ty: ignore[unresolved-import]  # added above


@pytest.fixture(scope="module", params=["gcc", "clang"])
def inlined_printf_object(request, tmp_path_factory) -> Path:
    """`inlined_printf_arg.c` at -O2, which both compilers lower the same way."""
    cc = request.param
    if not shutil.which(cc):
        pytest.skip(f"{cc} is not installed")
    out = tmp_path_factory.mktemp("od") / f"inlined_{cc}.so"
    subprocess.run(
        [
            cc,
            "-O2",
            "-shared",
            "-fPIC",
            "-o",
            str(out),
            str(SRC_DIR / "inlined_printf_arg.c"),
        ],
        check=True,
        capture_output=True,
    )
    return out


#: An actual call, not a mention. The recovered static is NAMED
#: `inlined_printf_arg_static_var`, so a substring test for "printf" matches
#: three lines that are not calls -- which is how the first version of this
#: filter found five call sites in a function with two.
CALL = re.compile(r"\b_*printf(_chk)?\s*\(")


def printf_calls(object_path: Path) -> list[str]:
    exported = D.exported_functions(str(object_path))
    code = D.decompiled_c(str(object_path), exported["driver"]) or ""
    return [
        ln.strip() for ln in code.splitlines() if CALL.search(ln) and "extern" not in ln
    ]


def is_argless(call: str) -> bool:
    """Whether the format string is the LAST argument.

    Comma-counting does not work across compilers: gcc emits
    `__printf_chk(2, fmt)` and clang `printf(fmt)`, so the argless forms have
    one comma and none. What both share is ending immediately after the format
    literal's closing paren.
    """
    return call.rstrip().endswith('"));')


def test_the_fixture_still_reproduces_the_shape(inlined_printf_object):
    """A vacuity guard: the defect test below is meaningless if the compiler
    stopped inlining, or stopped using a `lea`-defined argument register."""
    calls = printf_calls(inlined_printf_object)
    assert len(calls) == 2, f"expected two inlined printf call sites: {calls}"


@pytest.mark.xfail(
    strict=True,
    reason=(
        'OPEN DEFECT (call_args intervening read): `printf("called %d '
        'times\\n", static_var)` loses its argument at -O2 on BOTH gcc and '
        "clang. Ghidra makes the identical error; angr keeps the argument "
        "(with the wrong name).\n\n"
        "It is NOT an inlining defect, which is what the parity backlog "
        "originally recorded. Two minimal candidates with the same inlining "
        "did not reproduce; what reproduces is the argument register being "
        "defined by `lea` and then READ by the store to the static before the "
        "call. `call_args.rs` requires that the register 'is not read between "
        "the assignment and the call', so the fold is refused and the slot is "
        "dropped entirely.\n\n"
        "The conflation is the bug: `read_between` answers *may this "
        "definition be MOVED into the call?* and is used to answer *is this "
        "slot an argument at all?* A read does not disturb the register.\n\n"
        "Relaxing the gate was built and measured: it fixes this and costs "
        "~1,600 undefined reads (clang:O0 140 -> 552) because it then claims "
        "slots that were never arguments. The execution differential ENDORSED "
        "that change -- 824 lanes, 2 improvements, 0 regressions -- and the "
        "def-use census rejected it. A landing fix needs independent evidence "
        "that the slot is an argument; format-string arity is the candidate, "
        "which makes this a dependent of parity #3."
    ),
)
def test_an_inlined_printf_keeps_its_argument(inlined_printf_object):
    """Both call sites must pass the counter they format."""
    calls = printf_calls(inlined_printf_object)
    argless = [c for c in calls if is_argless(c)]
    assert not argless, (
        "these printf calls format %d but pass no value:\n  " + "\n  ".join(argless)
    )


DUFF_OBJECT = (
    ROOT / "tests" / "decompiler_fixtures" / "build" / "102_duffs_device-gcc-O2.so"
)


def _duff_copy_code() -> str:
    """Render the real gcc-O2 Duff's-device fixture by exported address."""
    if not DUFF_OBJECT.is_file():
        pytest.skip(
            f"{DUFF_OBJECT.relative_to(ROOT)} is gitignored and absent; "
            "build the fixture matrix to run this defect"
        )
    exported = D.exported_functions(str(DUFF_OBJECT))
    assert "duff_copy" in exported, "fixture no longer exports duff_copy"
    code = D.decompiled_c(str(DUFF_OBJECT), exported["duff_copy"])
    assert code, "duff_copy produced no decompiled body"
    return code


@pytest.mark.xfail(
    strict=True,
    reason=(
        "OPEN DEFECT (constant-false live latch): gcc -O2 Duff's device emits "
        "`if (0) { goto L_1180; }`, deleting the live loop backedge. This is "
        "a semantic wrong answer distinct from the existing unrecovered "
        "indirect-jump inventory row."
    ),
)
def test_duff_copy_does_not_delete_its_live_loop_latch():
    """A live Duff's-device latch must not fold to a constant-false branch."""
    code = _duff_copy_code()
    false_latch = re.search(r"if\s*\(0\)\s*\{\s*goto\s+L_1180\s*;", code)
    assert false_latch is None, code
