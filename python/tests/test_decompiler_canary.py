"""The default test suite exercises the decompiler, and says so in 60 seconds.

Why this exists
---------------

Of the six behavioural ratchets this project maintains, **every one is
`slow`-marked**. The only ratchet in the default suite measures code size. So
`uv run pytest python/tests/` -- the command anyone actually types -- could
pass on a build whose decompiler produced garbage, and on a fresh checkout it
could not exercise the decompiler at all, because
`tests/decompiler_fixtures/build/` is gitignored and absent.

`tests/decompiler_fixtures/canary/` closes that: nine fixture objects, 170 KB,
built hermetically in the pinned toolchain image and committed. They are
deliberately redundant with the slow execution differential. That is the
point. The differential proves correctness in ~50 minutes when someone runs
the gate; this proves non-brokenness in seconds every time anyone runs pytest.

What it asserts, and what it does not
-------------------------------------

**Structural predicates, never golden text.** A golden-output test over a
renderer under active development fails on every improvement, so it gets
regenerated reflexively and stops meaning anything. What is pinned here is
what must stay true regardless of how the output is spelled: the function is
found, it has a body, its recovered arity matches the source, a `switch`
survives where the source has one, and no raw process address leaks into the
C.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
CANARY = ROOT / "tests" / "decompiler_fixtures" / "canary"
sys.path.insert(0, str(ROOT / "tools"))

import diff_decompile as D  # ty: ignore[unresolved-import]  # added above

#: Per-object expectations. Each names ONE exported function and the property
#: that function exists to demonstrate, so a failure says which recovery
#: behaviour broke rather than only that something changed.
EXPECTATIONS: dict[str, dict[str, object]] = {
    "13_loop_early_exit-gcc-O0.so": {
        "function": "sum_positive",
        "must_contain": ["for", "if"],
        "why": "a loop with an early exit must keep both the loop and the exit test",
    },
    "04_switch_shapes-gcc-O0.so": {
        "function": "dense_jumptable",
        "must_contain": ["switch"],
        "why": "a dense jump table must recover as a switch, not as goto soup",
    },
    "212_loop_with_returning_arm-gcc-O2.so": {
        "function": "fsm_returns_from_arm",
        "must_contain": ["return"],
        "why": "a dispatch arm returning from inside a loop must not strand the loop body",
    },
    "216_packed_union_wire_record-gcc-O0.so": {
        "function": "bitfield_roundtrip",
        "must_contain": [],
        "why": "bitfields in a packed union must recover as storage, not as one wide field",
    },
    "172_float_double_widths-gcc-O0.so": {
        "function": "single_precision_horner",
        "must_contain": ["float"],
        "why": "a float parameter must not be recovered as an integer carrier",
    },
    "09_memory_effects-gcc-O2.so": {
        "function": "read_counter",
        "must_contain": [],
        "why": "static storage must render as a portable C object",
    },
    "03_loop_shapes-clang-O2.so": {
        "function": "dowhile_atleastonce",
        "must_contain": [],
        "why": "an optimised do-while must keep its body reachable",
    },
    "05_cleanup_and_state_machine-gcc-O0.so": {
        "function": "fsm",
        "must_contain": [],
        "why": "a protocol state machine must recover its dispatch",
    },
    "07_packet_parser-gcc-O2.so": {
        "function": "parse_packet",
        "must_contain": [],
        "why": "a wire-format parser must recover its field reads",
    },
}

#: A raw process virtual address in the output means the renderer fell back to
#: printing a pointer it could not model. Portable C never contains one.
RAW_ADDRESS = re.compile(r"\*\(\w+ \*\)\(0x[0-9a-f]{4,}\)")


def manifest() -> dict:
    return json.loads((CANARY / "MANIFEST.json").read_text())


def canary_objects() -> list[Path]:
    return sorted(CANARY.glob("*.so"))


def decompile(binary: Path, function: str) -> str | None:
    """The decbench render of one exported function, or None if absent."""
    exported = D.exported_functions(str(binary))
    if function not in exported:
        return None
    return D.decompiled_c(str(binary), exported[function])


def test_the_canary_set_is_present_and_intact():
    """A vacuity guard: every test below would pass over an empty directory."""
    objects = canary_objects()
    assert objects, (
        f"{CANARY} holds no objects. It is COMMITTED, not built -- if it is "
        "empty the checkout is broken, not the toolchain."
    )
    recorded = {e["object"]: e for e in manifest()["objects"]}
    assert set(recorded) == {p.name for p in objects}, (
        "MANIFEST.json and the directory disagree about which objects exist"
    )
    import hashlib

    for path in objects:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        assert digest == recorded[path.name]["sha256"], (
            f"{path.name} does not match its recorded sha256. These bytes are "
            "committed and hermetic; a mismatch means the file was rebuilt or "
            "corrupted, and every expectation below is measuring something else."
        )


def test_the_canary_set_stays_small():
    """It is a smoke test carried in git, not a corpus.

    The Rust fixture was excluded for exactly this reason -- a cdylib links
    std statically and one object would have been 78x the rest combined.
    """
    total = sum(p.stat().st_size for p in canary_objects())
    assert total < 1_000_000, (
        f"canary set is {total:,} bytes. Keep it under 1 MB: it is committed, "
        "and it is redundant with the slow matrix by design."
    )


@pytest.mark.parametrize("name", sorted(EXPECTATIONS))
def test_each_canary_decompiles_to_something_structural(name):
    """The decompiler produces a real body for a known function."""
    spec = EXPECTATIONS[name]
    binary = CANARY / name
    assert binary.is_file(), f"{name} missing from the committed canary set"

    code = decompile(binary, str(spec["function"]))
    assert code, (
        f"{name}: no output for {spec['function']!r} -- {spec['why']}. "
        f"Exported: {sorted(D.exported_functions(str(binary)))[:8]}"
    )
    # A body, not just a signature line.
    assert code.count("\n") >= 3, (
        f"{name}: body is {code.count(chr(10))} lines:\n{code}"
    )
    for token in spec["must_contain"]:  # ty: ignore[not-iterable]
        assert token in code, (
            f"{name}: {spec['function']} lost {token!r} -- {spec['why']}\n{code}"
        )


@pytest.mark.parametrize("name", sorted(EXPECTATIONS))
def test_no_canary_leaks_a_raw_process_address(name):
    """Portable C never dereferences a literal image address.

    This is the property `test_decompiler_global_data` pins for one fixture,
    checked across the whole canary set: a raw `*(int *)(0x4040)` means the
    renderer gave up on modelling storage and printed the pointer instead.
    """
    binary = CANARY / name
    code = decompile(binary, str(EXPECTATIONS[name]["function"]))
    assert code is not None
    found = RAW_ADDRESS.findall(code)
    assert not found, f"{name}: raw process address(es) {found} in output:\n{code}"
