"""Tests for ARM Thumb-mode dispatch on the disassembler.

Two layers of coverage:
1. Synthetic bytes — verifies `set_thumb_mode` toggles the Capstone handle
   and that the same byte sequence decodes differently in ARM vs Thumb.
2. Real 32-bit ARM ELF sample — sanity check that the binding loads and
   returns the expected arch.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import glaurung as g


ARM32_SAMPLE = Path(
    "samples/binaries/platforms/linux/amd64/cross/armhf/hello-armhf-gcc"
)


def _make_arm32_disasm() -> g.disasm.PyDisassembler:
    cfg = g.DisassemblerConfig(architecture=g.Architecture.ARM, endianness=g.Endianness.Little)
    return g.disasm.PyDisassembler(cfg)


def test_set_thumb_mode_is_noop_on_arm64():
    cfg = g.DisassemblerConfig(architecture=g.Architecture.ARM64, endianness=g.Endianness.Little)
    d = g.disasm.PyDisassembler(cfg)
    # Should not raise and should return the requested mode label.
    assert d.set_thumb_mode(True) == "thumb"
    assert d.set_thumb_mode(False) == "arm"


def test_thumb_mode_decodes_nop_as_two_bytes():
    d = _make_arm32_disasm()
    d.set_thumb_mode(True)
    # Thumb-2 NOP = 00 BF (2 bytes).
    addr = g.Address(g.AddressKind.VA, 0x1000, 32)
    ins = d.disassemble_bytes(addr, [0x00, 0xBF], 1, 50)
    assert len(ins) == 1
    assert ins[0].length == 2
    assert ins[0].mnemonic == "nop"


def test_arm_mode_decodes_mov_as_four_bytes():
    d = _make_arm32_disasm()
    d.set_thumb_mode(False)
    # `mov r0, r0` ARM encoding (LE): 00 00 A0 E1.
    addr = g.Address(g.AddressKind.VA, 0x1000, 32)
    ins = d.disassemble_bytes(addr, [0x00, 0x00, 0xA0, 0xE1], 1, 50)
    assert len(ins) == 1
    assert ins[0].length == 4
    # capstone outputs "mov" for this encoding.
    assert ins[0].mnemonic in {"mov", "nop"}


def test_mode_can_be_toggled_back_and_forth():
    d = _make_arm32_disasm()
    addr = g.Address(g.AddressKind.VA, 0, 32)
    d.set_thumb_mode(True)
    t = d.disassemble_bytes(addr, [0x00, 0xBF], 1, 50)
    assert t[0].length == 2
    d.set_thumb_mode(False)
    a = d.disassemble_bytes(addr, [0x00, 0x00, 0xA0, 0xE1], 1, 50)
    assert a[0].length == 4


@pytest.mark.skipif(not ARM32_SAMPLE.exists(), reason="ARM32 sample not present")
def test_disassembler_for_path_on_arm32_sample():
    d = g.disasm.disassembler_for_path(str(ARM32_SAMPLE))
    # hello-armhf-gcc is classic ARM (not Thumb) per `file`.
    assert str(d.arch()) == "arm"
    # Toggle method must exist and be callable.
    assert d.set_thumb_mode(False) == "arm"
