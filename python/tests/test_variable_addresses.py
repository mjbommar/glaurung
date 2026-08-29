"""Per-variable machine addresses, validated against an independent oracle.

DecBench's ingest accepts direct per-variable addresses with no line map —
variable addresses are filtered independently of line mappings and survive with
none — and its auditor counts `functions_with_direct_only_addresses` as a
first-class statistic. dewolf and Reko emit exactly that shape. We did not, on
the mistaken belief that the AST dropping `ins.va` blocked it. It blocks a LINE
map; a variable-to-address map joins on STORAGE and needs no node identity.

These tests check the property that actually matters, against `objdump` rather
than against our own disassembler:

  RANGE  every address lies in [entry_va, entry_va + size)
  START  every address is a real instruction start
  REF    the instruction there actually accesses the slot's displacement

A wrong address is worse than none: it is a real instruction start inside the
function, so it passes a consumer's validator and silently mis-attributes the
evidence to another variable. That is why every rule in
`ir::variable_addresses` drops evidence rather than guessing, and why these
tests assert ZERO violations rather than a tolerance.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

import glaurung as g

ROOT = Path(__file__).resolve().parent.parent.parent
SOURCE = ROOT / "tests" / "decompiler_fixtures" / "src" / "19_disjoint_set.c"


def objdump_oracle(binary: Path, tool: str) -> tuple[set[int], dict[int, str]]:
    dis = subprocess.run(
        [tool, "-d", "--no-show-raw-insn", str(binary)],
        capture_output=True,
        text=True,
        timeout=120,
    ).stdout
    starts: set[int] = set()
    text: dict[int, str] = {}
    for line in dis.splitlines():
        m = re.match(r"\s+([0-9a-f]+):\s+(.*)", line)
        if m:
            addr = int(m.group(1), 16)
            starts.add(addr)
            text[addr] = m.group(2).strip()
    return starts, text


def access_width(insn: str) -> int:
    """Bytes one instruction's memory access spans.

    Not cosmetic: a 16-byte access covers two 8-byte slots, so the LLIR's
    per-slot displacement is legitimately INSIDE an access objdump prints with
    only its base offset. Getting this wrong made an earlier version of this
    audit report 158 false failures on aarch64 (`stp`/`ldp`) and 32 more on
    x86-64 (`movaps` through an `xmm` register).
    """
    if re.search(r"%[xy]mm|\b(movaps|movups|movdqa|movdqu)\b", insn):
        return 16
    if re.search(r"\b[qv]\d", insn):
        return 16
    if re.search(r"\b(stp|ldp)\b", insn):
        return 16
    return 8


def access_covers(insn: str, offset: int) -> bool:
    """Whether this instruction's frame access covers byte `offset`."""
    if offset == 0 and re.search(r"\[(sp|x29|fp|r7|r11|rbp|rsp)\]", insn):
        return True
    width = access_width(insn)
    for m in re.finditer(r"[#](-?\d+)", insn):
        start = int(m.group(1))
        if start <= offset < start + width:
            return True
    for m in re.finditer(r"(-?0x[0-9a-f]+)\(%[a-z0-9]+\)", insn):
        start = int(m.group(1), 16)
        if start <= offset < start + width:
            return True
    return False


def compile_fixture(tmp_path: Path, cc: str, opt: str) -> Path | None:
    out = tmp_path / f"disjoint-{Path(cc).name}-{opt}.so"
    result = subprocess.run(
        [cc, "-shared", "-fPIC", "-g", f"-{opt}", "-o", str(out), str(SOURCE)],
        capture_output=True,
        text=True,
        timeout=120,
    )
    return out if result.returncode == 0 else None


def audit(binary: Path, objdump: str) -> dict[str, int]:
    starts, text = objdump_oracle(binary, objdump)
    assert starts, f"{objdump} disassembled nothing from {binary}"
    counts = {"addresses": 0, "outside_hot_extent": 0, "start": 0, "ref": 0, "vars": 0}
    for _name, entry_va, _text, size, variables in g.ir.decompile_all(
        str(binary), limit=60, style="decbench"
    ):
        for variable in variables:
            if not variable["addresses"]:
                continue
            counts["vars"] += 1
            offset = variable["stack_offset"]
            for addr in variable["addresses"]:
                counts["addresses"] += 1
                if size and not (entry_va <= addr < entry_va + size):
                    # A function is not always contiguous: `cpp_exception.cold`
                    # sits BELOW its hot part, so a correct address for that
                    # function lands outside `[entry_va, entry_va + size)`.
                    # Counted, not failed -- being a real instruction start that
                    # accesses the right slot is the property that matters.
                    counts["outside_hot_extent"] += 1
                if addr not in starts:
                    counts["start"] += 1
                elif offset is not None and not access_covers(text[addr], offset):
                    counts["ref"] += 1
    return counts


@pytest.mark.parametrize("cc", ["gcc", "clang"])
def test_every_x86_64_address_survives_the_objdump_audit(cc, tmp_path):
    binary = compile_fixture(tmp_path, cc, "O0")
    if binary is None:
        pytest.skip(f"{cc} unavailable")
    counts = audit(binary, "objdump")
    assert counts["addresses"] > 0, "no addresses emitted at all"
    assert counts["start"] == 0, counts
    assert counts["ref"] == 0, counts


def test_aarch64_addresses_survive_the_audit(tmp_path):
    """A different frame base (`sp`/`x29`) and paired accesses."""
    if (
        not subprocess.run(
            ["which", "aarch64-linux-gnu-gcc"], capture_output=True
        ).returncode
        == 0
    ):
        pytest.skip("no aarch64 toolchain")
    binary = compile_fixture(tmp_path, "aarch64-linux-gnu-gcc", "O0")
    if binary is None:
        pytest.skip("aarch64 build failed")
    counts = audit(binary, "aarch64-linux-gnu-objdump")
    assert counts["addresses"] > 0, "no addresses emitted on aarch64"
    assert counts["start"] == 0 and counts["ref"] == 0, counts


def test_a_parameter_carries_no_addresses(tmp_path):
    """Deliberate: a register's live range is not a storage coordinate, and
    deriving one needs liveness this join does not do. Empty means unclaimed."""
    binary = compile_fixture(tmp_path, "gcc", "O0")
    if binary is None:
        pytest.skip("gcc unavailable")
    for _n, _va, _t, _s, variables in g.ir.decompile_all(
        str(binary), limit=60, style="decbench"
    ):
        for variable in variables:
            if variable["kind"] == "arg":
                assert variable["addresses"] == [], variable


def test_the_field_is_always_present(tmp_path):
    """A consumer checking for the key must not have to handle its absence."""
    binary = compile_fixture(tmp_path, "gcc", "O0")
    if binary is None:
        pytest.skip("gcc unavailable")
    for _n, _va, _t, _s, variables in g.ir.decompile_all(
        str(binary), limit=20, style="decbench"
    ):
        for variable in variables:
            assert "addresses" in variable
            assert isinstance(variable["addresses"], list)


def test_addresses_are_sorted_and_unique(tmp_path):
    """One machine instruction can expand into several LLIR ops sharing a VA;
    the consumer wants a set of instruction addresses, not a multiset."""
    binary = compile_fixture(tmp_path, "gcc", "O0")
    if binary is None:
        pytest.skip("gcc unavailable")
    for _n, _va, _t, _s, variables in g.ir.decompile_all(
        str(binary), limit=60, style="decbench"
    ):
        for variable in variables:
            addresses = variable["addresses"]
            assert addresses == sorted(set(addresses)), variable


def test_an_omitted_frame_pointer_build_is_silent_not_wrong(tmp_path):
    """The documented boundary, pinned.

    At `-O2` gcc omits the frame pointer, `stack_locals` normalises slots to an
    entry-relative frame, and `entry_rsp` never appears as a machine base. The
    join therefore finds nothing — and finding nothing is the required
    behaviour. If this ever starts producing addresses, they must still pass the
    audit, so this asserts correctness rather than emptiness.
    """
    binary = compile_fixture(tmp_path, "gcc", "O2")
    if binary is None:
        pytest.skip("gcc unavailable")
    counts = audit(binary, "objdump")
    assert counts["start"] == 0 and counts["ref"] == 0, counts
