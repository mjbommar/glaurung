"""Every DecBench-corpus function that can be handed an out-of-bounds length must
declare its input contract.

This exists because of a specific, expensive mistake. The DecBench validation corpus
(`tests/decbench_corpus/`) had no manifest at all, so the harness invented the scalar
arguments: `sum_array(const int *a, int n)` got a 16-element buffer and `n = 100`.
BOTH binaries then read 84 elements past the end, disagreed about the garbage, and the
differential reported WRONG — with a *different* wrong value on every run, which is the
signature of reading uninitialised memory rather than of a logic error. `reverse` and
`matmul` wrote past the end and segfaulted. `str_len` walked off a buffer with no NUL
and agreed only because both libraries happened to read the same heap in the same
process.

None of that was a decompiler bug, and reading it as one overstated how broken the
output was. The decompiled `sum_array` was, in fact, correct.

So: if a function takes a pointer and a scalar that could be its length, the manifest
must say so. The test cannot know which scalar is the length, and deliberately does not
guess — an unbounded pointer/scalar pair is a question for a human, and the answer
belongs in `DECBENCH_OVERRIDES`. Failing closed here is the whole point: the previous
behaviour was to fail *open*, and a differential that silently tests undefined
behaviour reports noise as signal.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
CORPUS = ROOT / "tests" / "decbench_corpus" / "src"
sys.path.insert(0, str(ROOT / "tests" / "decompiler_fixtures"))
import manifest as M

#: A function definition at top level: `<ret> name(<params>) {`. The corpus is
#: deliberately plain C, one construct per function, so a regex is honest here in a
#: way it would not be for arbitrary source.
_DEF = re.compile(
    r"^(?P<ret>[A-Za-z_][\w \t*]*?)\b(?P<name>\w+)\s*\((?P<params>[^)]*)\)\s*\{",
    re.MULTILINE,
)


def _functions(src: Path) -> list[tuple[str, list[str]]]:
    out = []
    for m in _DEF.finditer(src.read_text()):
        params = [p.strip() for p in m.group("params").split(",") if p.strip()]
        if params == ["void"]:
            params = []
        out.append((m.group("name"), params))
    return out


def _corpus_functions() -> list[tuple[str, str, list[str]]]:
    assert CORPUS.is_dir(), f"corpus source dir missing: {CORPUS}"
    out = []
    for src in sorted(CORPUS.glob("*.c")):
        for name, params in _functions(src):
            out.append((src.stem, name, params))
    assert out, "parsed zero functions from the corpus — the regex or corpus moved"
    return out


CORPUS_FUNCTIONS = _corpus_functions()


def _is_pointer(param: str) -> bool:
    return "*" in param or param.endswith("[]")


def _is_integral_scalar(param: str) -> bool:
    if _is_pointer(param):
        return False
    return any(
        t in param for t in ("int", "long", "short", "char", "unsigned", "size_t")
    )


@pytest.mark.parametrize(
    ("program", "func", "params"),
    [(p, f, ps) for p, f, ps in CORPUS_FUNCTIONS],
    ids=[f"{p}:{f}" for p, f, _ in CORPUS_FUNCTIONS],
)
def test_pointer_plus_scalar_declares_a_bound(program, func, params):
    """A pointer parameter alongside an integral scalar needs a declared bound.

    `len_args` (clamp the scalar to the buffer length) or `arg_values` (pin the
    scalar's domain) both satisfy this. Which one is right depends on the function —
    `matmul` indexes `A[i*n+k]` across three buffers, so its bound is sqrt(len), not
    len — and that judgement is what the manifest records.
    """
    if not any(_is_pointer(p) for p in params):
        return
    if not any(_is_integral_scalar(p) for p in params):
        return
    ov = M.override(program, func)
    if ov.get("skip_exec"):
        return  # not executed at all, so there is no vector to bound
    assert ov.get("len_args") or ov.get("arg_values"), (
        f"{program}:{func}({', '.join(params)}) takes a pointer and a scalar but "
        f"declares neither len_args nor arg_values. The harness will invent the "
        f"scalar, and if it exceeds the buffer length BOTH binaries read out of "
        f"bounds — the differential then compares garbage against garbage and "
        f"reports a decompiler bug that is not there. Add an entry to "
        f"DECBENCH_OVERRIDES in tests/decompiler_fixtures/manifest.py."
    )


@pytest.mark.parametrize(
    ("program", "func", "params"),
    [(p, f, ps) for p, f, ps in CORPUS_FUNCTIONS],
    ids=[f"{p}:{f}" for p, f, _ in CORPUS_FUNCTIONS],
)
def test_char_pointer_is_nul_terminated(program, func, params):
    """A `char *` with no length parameter is a C string, so it needs a NUL.

    `ptr_elem: "cstr"` guarantees one; `len_args` means the function is told how far
    to go and does not need one. Plain `u8` gives neither, and a string loop then runs
    off the end of the buffer into whatever follows it.
    """
    char_ptrs = [p for p in params if _is_pointer(p) and "char" in p]
    if not char_ptrs:
        return
    ov = M.override(program, func)
    if ov.get("len_args") or ov.get("skip_exec"):
        return
    assert ov.get("ptr_elem") == "cstr", (
        f"{program}:{func}({', '.join(params)}) takes a char pointer with no length "
        f"parameter, so it must stop at a NUL — but the buffer is not guaranteed to "
        f'contain one (ptr_elem={ov.get("ptr_elem")!r}). Set ptr_elem to "cstr". '
        f"Without it the two binaries agree only when they happen to read the same "
        f"heap, which is luck, not a passing test."
    )


def test_every_override_names_a_real_function():
    """The other direction: a contract for a function that does not exist is dead
    weight that reads as coverage. A renamed function must not silently lose its
    bound — that is how the out-of-bounds vectors would come back."""
    known = {(p, f) for p, f, _ in CORPUS_FUNCTIONS}
    stale = sorted(k for k in M.DECBENCH_OVERRIDES if k not in known)
    assert not stale, (
        f"DECBENCH_OVERRIDES entries name functions absent from "
        f"tests/decbench_corpus/src: {stale}. Either the function was renamed (move "
        f"its contract with it) or removed (delete the entry)."
    )


def test_switch_dispatch_vectors_execute_every_arm_with_signed_inputs():
    """A random 32-bit opcode almost always takes the default arm.

    The previous differential ran 110 cases yet exercised case 7 only as
    ``dispatch(7, 7, 7)``, missing the wrong logical shift for negative ``b``.
    Keep explicit in-range vectors so every recovered table edge is executed.
    """
    vectors = M.override("switch_jt", "dispatch").get("extra_vectors", [])
    covered = {int(vector[0]) for vector in vectors if len(vector) == 3}
    assert set(range(8)) <= covered, f"missing switch arms: {set(range(8)) - covered}"
    assert any(
        int(vector[0]) == 7 and int(vector[2]) < 0 for vector in vectors
    ), "case 7 needs a negative signed-shift operand"
    assert any(int(vector[0]) < 0 or int(vector[0]) > 7 for vector in vectors), (
        "the out-of-range default arm needs an explicit vector"
    )
