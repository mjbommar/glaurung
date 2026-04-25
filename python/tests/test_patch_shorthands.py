"""Tests for patch shorthands: nop / jmp / force-branch (#224)."""

from __future__ import annotations

import io
import json
from contextlib import redirect_stdout
from pathlib import Path

import pytest

import glaurung as g
from glaurung.llm.kb.patch import (
    encode_jmp, encode_nop, patch_force_branch, patch_jmp, patch_nop,
)


_HELLO = Path(
    "samples/binaries/platforms/linux/amd64/export/native/clang/debug/hello-clang-debug"
)


def _need(p: Path) -> Path:
    if not p.exists():
        pytest.skip(f"missing {p}")
    return p


def _first_instruction_va(binary: Path) -> int:
    """Pick the entry instruction VA so we have something deterministic
    to patch."""
    funcs, _ = g.analysis.analyze_functions_path(str(binary))
    if not funcs:
        pytest.skip("no functions discovered")
    return int(funcs[0].entry_point.value)


def test_encode_nop_emits_correct_bytes() -> None:
    assert encode_nop(1) == b"\x90"
    assert encode_nop(5) == b"\x90" * 5
    with pytest.raises(ValueError):
        encode_nop(0)


def test_encode_jmp_picks_short_form_when_close() -> None:
    # 5-byte function: target is 5 ahead of from_va, rel8 = 3 → fits.
    out = encode_jmp(0x1000, 0x1005)
    assert out == b"\xeb\x03"


def test_encode_jmp_uses_rel32_for_distant_target() -> None:
    out = encode_jmp(0x1000, 0x4000)
    assert out[0] == 0xE9
    assert len(out) == 5
    rel = int.from_bytes(out[1:5], "little", signed=True)
    assert 0x1000 + 5 + rel == 0x4000


def test_encode_jmp_forced_size_5() -> None:
    out = encode_jmp(0x1000, 0x1005, want_size=5)
    assert out[0] == 0xE9
    assert len(out) == 5


def test_patch_nop_size_preserves_instruction(tmp_path: Path) -> None:
    binary = _need(_HELLO)
    va = _first_instruction_va(binary)
    output = tmp_path / "patched-nop.bin"
    res = patch_nop(str(binary), str(output), va)
    # Original bytes ≠ all 0x90; patched bytes are all 0x90.
    assert all(b == 0x90 for b in bytes.fromhex(res.patched_hex))
    assert len(bytes.fromhex(res.patched_hex)) == len(bytes.fromhex(res.original_hex))


def test_patch_nop_actually_writes_nops_to_disk(tmp_path: Path) -> None:
    binary = _need(_HELLO)
    va = _first_instruction_va(binary)
    output = tmp_path / "patched-nop.bin"
    patch_nop(str(binary), str(output), va)
    # Re-disasm at the patched VA — should report `nop`.
    ins = g.disasm.disassemble_window_at(
        str(output), va, window_bytes=16, max_instructions=1,
    )
    assert ins
    assert ins[0].mnemonic.lower() == "nop"


def test_patch_jmp_preserves_length_with_padding(tmp_path: Path) -> None:
    """Patching a 5-byte instruction with a 2-byte JMP near target
    should NOP-pad to 5 bytes — caller specified preserve_length=True."""
    binary = _need(_HELLO)
    output = tmp_path / "patched-jmp.bin"
    # Find an instruction we know is at least 2 bytes. Use entry's
    # next instruction (entry might be a 1-byte op like 'push').
    funcs, _ = g.analysis.analyze_functions_path(str(binary))
    fn_va = int(funcs[0].entry_point.value)
    instrs = g.disasm.disassemble_window_at(
        str(binary), fn_va, window_bytes=64, max_instructions=8,
    )
    target_ins = None
    for ins in instrs:
        if len(ins.bytes or b"") >= 2:
            target_ins = ins
            break
    if target_ins is None:
        pytest.skip("no >=2-byte instruction near entry")
    from_va = int(target_ins.address.value)
    target_va = from_va + 0x10  # short forward jump

    res = patch_jmp(str(binary), str(output), from_va, target_va)
    patched = bytes.fromhex(res.patched_hex)
    assert len(patched) == len(bytes.fromhex(res.original_hex))
    # First two bytes encode `jmp +<rel>`.
    assert patched[0] == 0xEB
    # Rest must be NOP padding when the original was longer.
    if len(patched) > 2:
        assert all(b == 0x90 for b in patched[2:])


def test_patch_jmp_round_trip_decodes_as_jmp(tmp_path: Path) -> None:
    binary = _need(_HELLO)
    output = tmp_path / "jmp-rt.bin"
    funcs, _ = g.analysis.analyze_functions_path(str(binary))
    fn_va = int(funcs[0].entry_point.value)
    instrs = g.disasm.disassemble_window_at(
        str(binary), fn_va, window_bytes=64, max_instructions=8,
    )
    target_ins = next(
        (ins for ins in instrs if len(ins.bytes or b"") >= 2), None,
    )
    if target_ins is None:
        pytest.skip("no >=2-byte instruction")
    from_va = int(target_ins.address.value)
    target_va = from_va + 0x20
    patch_jmp(str(binary), str(output), from_va, target_va)

    ins = g.disasm.disassemble_window_at(
        str(output), from_va, window_bytes=16, max_instructions=1,
    )
    assert ins
    assert ins[0].mnemonic.lower() == "jmp"


def test_patch_cli_nop_mode(tmp_path: Path) -> None:
    """Smoke-test `glaurung patch in out --va N --nop --verify`."""
    from glaurung.cli.main import GlaurungCLI

    binary = _need(_HELLO)
    output = tmp_path / "cli-nop.bin"
    va = _first_instruction_va(binary)

    cli = GlaurungCLI()
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = cli.run([
            "patch", str(binary), str(output),
            "--va", hex(va), "--nop", "--verify", "--force",
        ])
    assert rc == 0
    out = buf.getvalue().lower()
    assert "patch applied" in out
    assert "nop" in out  # verify line should mention `nop`


def test_patch_cli_force_branch_false(tmp_path: Path) -> None:
    """force-branch false is just nop in disguise — exercise the CLI
    path end-to-end."""
    from glaurung.cli.main import GlaurungCLI

    binary = _need(_HELLO)
    output = tmp_path / "cli-fb.bin"
    va = _first_instruction_va(binary)

    cli = GlaurungCLI()
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = cli.run([
            "patch", str(binary), str(output),
            "--va", hex(va), "--force-branch", "false",
            "--verify", "--force",
        ])
    assert rc == 0


def test_patch_cli_requires_exactly_one_mode(tmp_path: Path) -> None:
    """--bytes and --nop together must be rejected."""
    from glaurung.cli.main import GlaurungCLI

    binary = _need(_HELLO)
    output = tmp_path / "cli-bad.bin"
    cli = GlaurungCLI()
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = cli.run([
            "patch", str(binary), str(output),
            "--va", "0x1000", "--bytes", "90", "--nop", "--force",
        ])
    assert rc == 2
    assert "exactly one" in buf.getvalue().lower()


def test_patch_cli_json_includes_verify(tmp_path: Path) -> None:
    from glaurung.cli.main import GlaurungCLI

    binary = _need(_HELLO)
    output = tmp_path / "cli-json.bin"
    va = _first_instruction_va(binary)
    cli = GlaurungCLI()
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = cli.run([
            "patch", str(binary), str(output),
            "--va", hex(va), "--nop", "--verify", "--force",
            "--format", "json",
        ])
    assert rc == 0
    data = json.loads(buf.getvalue())
    assert data["va"] == va
    assert "verify" in data
    assert "nop" in data["verify"].lower()
