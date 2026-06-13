"""Operand-fidelity tests for the disassembler binding (Python surface).

Regression guards for the extractor bugs fixed 2026-06-13:
- sign-extended immediates were dropped (`cmp r32, imm8s` lost its immediate),
- operand size/access were placeholders (0 / always Read),
- the Operand.immediate/register getters were SHADOWED by the same-named
  static constructors, so values were unreadable from Python.

Gated on GLAURUNG_IOCTL_FIXTURES (a dir with the reference .sys files); the
self-contained Rust tests in src/disasm/iced.rs cover the same logic without
fixtures.
"""

import os

import pytest

import glaurung.disasm as dis

FIX = os.environ.get("GLAURUNG_IOCTL_FIXTURES")
pytestmark = pytest.mark.skipif(
    not FIX, reason="set GLAURUNG_IOCTL_FIXTURES to a dir with the reference .sys files"
)

# e22w8x64 @ 0x1400034e6 is `cmp ecx, 0x15` (encoding 83 f9 15): a sign-extended
# imm8-to-32 compare whose immediate and register width are both checked.
_DRV = "e22w8x64.sys"
_VA = 0x1400034E6


def _cmp_insn():
    path = os.path.join(FIX, _DRV)
    if not os.path.exists(path):
        pytest.skip(f"{_DRV} not in fixtures dir")
    out = dis.disassemble_window_at(path, _VA, window_bytes=8, max_instructions=1)
    assert out, "no instruction decoded"
    return out[0]


def test_immediate_getter_returns_int_value():
    """`operand.immediate` must return the value, not the shadowing constructor."""
    ins = _cmp_insn()
    imms = [o.immediate for o in ins.operands if o.immediate is not None]
    assert imms, "sign-extended immediate must be extracted, not dropped"
    assert all(isinstance(v, int) for v in imms), "getter must return int, not a method"
    assert 0x15 in imms


def test_register_size_and_access_are_populated():
    ins = _cmp_insn()
    regs = [o for o in ins.operands if str(o.kind).endswith("Register")]
    assert regs, "ecx operand present"
    ecx = regs[0]
    assert ecx.size == 32, "ecx is 32-bit (was placeholder 0)"
    assert str(ecx.access).endswith("Read"), "cmp reads its register operand"
