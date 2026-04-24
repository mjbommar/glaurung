"""Tests for the LLIR Python bindings (`glaurung.ir`).

Each test asserts the shape of the dict representation: op dicts always
carry `va` and `kind` plus kind-specific fields, and `Value`s are encoded
as `{"kind": "reg"|"const"|"addr", ...}`.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import glaurung as g


def test_nop_lifts_to_nop_dict():
    ops = g.ir.lift_bytes(bytes([0x90]), 0x1000, 64)
    assert ops == [{"va": 0x1000, "kind": "nop"}]


def test_mov_reg_imm_lifts_to_assign_dict():
    # mov rax, 0x1234
    ops = g.ir.lift_bytes(
        bytes([0x48, 0xC7, 0xC0, 0x34, 0x12, 0x00, 0x00]), 0x1000, 64
    )
    assert len(ops) == 1
    assert ops[0] == {
        "va": 0x1000,
        "kind": "assign",
        "dst": "rax",
        "src": {"kind": "const", "value": 0x1234},
    }


def test_mov_reg_reg_lifts_to_assign_with_reg_value():
    # mov rax, rbx  (48 89 d8)
    ops = g.ir.lift_bytes(bytes([0x48, 0x89, 0xD8]), 0x1000, 64)
    assert len(ops) == 1
    assert ops[0]["kind"] == "assign"
    assert ops[0]["dst"] == "rax"
    assert ops[0]["src"] == {"kind": "reg", "name": "rbx"}


def test_add_reg_imm_lifts_to_bin_add():
    # add rax, 5  (48 83 c0 05)
    ops = g.ir.lift_bytes(bytes([0x48, 0x83, 0xC0, 0x05]), 0x1000, 64)
    assert len(ops) == 1
    o = ops[0]
    assert o["kind"] == "bin"
    assert o["op"] == "add"
    assert o["dst"] == "rax"
    assert o["lhs"] == {"kind": "reg", "name": "rax"}
    assert o["rhs"] == {"kind": "const", "value": 5}


def test_push_expands_into_two_ops():
    # push rax  (50)
    ops = g.ir.lift_bytes(bytes([0x50]), 0x1000, 64)
    assert len(ops) == 2
    # 1: sub rsp, 8
    assert ops[0]["kind"] == "bin"
    assert ops[0]["op"] == "sub"
    assert ops[0]["dst"] == "rsp"
    assert ops[0]["rhs"] == {"kind": "const", "value": 8}
    # 2: store
    assert ops[1]["kind"] == "store"
    assert ops[1]["addr"]["base"] == "rsp"
    assert ops[1]["addr"]["disp"] == 0


def test_ret_lifts_to_return():
    ops = g.ir.lift_bytes(bytes([0xC3]), 0x1000, 64)
    assert ops == [{"va": 0x1000, "kind": "return"}]


def test_call_direct_records_target_address():
    # call rel32 +0x4b from 0x1000 → target 0x1050
    ops = g.ir.lift_bytes(bytes([0xE8, 0x4B, 0x00, 0x00, 0x00]), 0x1000, 64)
    assert len(ops) == 1
    o = ops[0]
    assert o["kind"] == "call"
    assert o["target"] == {"kind": "direct", "addr": 0x1050}


def test_cmp_and_je_roundtrip():
    # cmp rax, rbx ; je +2 — cmp emits ZF/CF/Slt/Sle/S writes (plus a sub
    # temp to materialise the signed difference for %sf); je reads %zf.
    ops = g.ir.lift_bytes(bytes([0x48, 0x39, 0xD8, 0x74, 0x02]), 0x1000, 64)
    cmp_ops = [o for o in ops if o["kind"] == "cmp"]
    assert len(cmp_ops) == 5
    cmp_flags = {o["dst"] for o in cmp_ops}
    assert cmp_flags == {"%zf", "%cf", "%slt", "%sle", "%sf"}
    cj = [o for o in ops if o["kind"] == "cond_jump"]
    assert len(cj) == 1
    assert cj[0]["cond"] == "%zf"
    # From 0x1000: cmp is 3 bytes, je at 0x1003 (length 2), disp +2 → 0x1007.
    assert cj[0]["target"] == 0x1007


def test_js_after_test_reads_raw_sign_flag():
    # test rax, rax ; js +2 — js must read %sf, not %slt.
    ops = g.ir.lift_bytes(bytes([0x48, 0x85, 0xC0, 0x78, 0x02]), 0x1000, 64)
    cj = next(o for o in ops if o["kind"] == "cond_jump")
    assert cj["cond"] == "%sf"
    # And the test lifter itself must have written %sf.
    assert any(o["kind"] == "cmp" and o["dst"] == "%sf" for o in ops)


def test_jle_reads_sle_flag():
    # cmp rax, rbx ; jle +2  — jle should read %sle, not %slt or %zf.
    ops = g.ir.lift_bytes(bytes([0x48, 0x39, 0xD8, 0x7E, 0x02]), 0x1000, 64)
    cj = next(o for o in ops if o["kind"] == "cond_jump")
    assert cj["cond"] == "%sle"


def test_jl_reads_slt_flag():
    ops = g.ir.lift_bytes(bytes([0x48, 0x39, 0xD8, 0x7C, 0x02]), 0x1000, 64)
    cj = next(o for o in ops if o["kind"] == "cond_jump")
    assert cj["cond"] == "%slt"


def test_lift_bytes_rejects_invalid_bits():
    with pytest.raises(ValueError):
        g.ir.lift_bytes(bytes([0x90]), 0, 48)


SAMPLE = Path(
    "samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-gcc-O2"
)
ARM64_SAMPLE = Path(
    "samples/binaries/platforms/linux/arm64/export/cross/arm64/hello-arm64-gcc"
)


def test_arm64_nop_lifts_via_arch_parameter():
    # ARM64 NOP = 0xd503201f (LE: 1f 20 03 d5).
    ops = g.ir.lift_bytes(bytes([0x1F, 0x20, 0x03, 0xD5]), 0x1000, arch="arm64")
    assert ops == [{"va": 0x1000, "kind": "nop"}]


def test_arm64_ret_lifts_via_arch_parameter():
    # RET = 0xd65f03c0 (LE: c0 03 5f d6).
    ops = g.ir.lift_bytes(bytes([0xC0, 0x03, 0x5F, 0xD6]), 0x0, arch="arm64")
    assert ops == [{"va": 0, "kind": "return"}]


def test_lift_bytes_rejects_unknown_arch():
    with pytest.raises(ValueError):
        g.ir.lift_bytes(bytes([0x90]), 0, arch="riscv")


@pytest.mark.skipif(not SAMPLE.exists(), reason="x86-64 sample missing")
def test_decompile_all_returns_readable_functions():
    results = g.ir.decompile_all(str(SAMPLE), limit=3)
    assert len(results) >= 1
    for name, va, text in results:
        assert isinstance(name, str) and name
        assert isinstance(va, int) and va > 0
        assert text.startswith(f"function {name} @ 0x{va:x} {{")
        assert text.rstrip().endswith("}")


@pytest.mark.skipif(not SAMPLE.exists(), reason="x86-64 sample missing")
def test_decompile_at_rejects_unknown_va():
    with pytest.raises(ValueError):
        g.ir.decompile_at(str(SAMPLE), 0xDEADBEEF)


@pytest.mark.skipif(not SAMPLE.exists(), reason="x86-64 sample missing")
def test_decompile_at_for_first_function_produces_text():
    got = g.analysis.detect_entry_path(str(SAMPLE))
    entry_va = int(got[3])
    text = g.ir.decompile_at(str(SAMPLE), entry_va)
    assert text.startswith("function ")
    # End-to-end: we've plumbed cfg + lift + ssa + structure + lower +
    # reconstruct + print. A non-trivial function produces multiple lines.
    assert text.count("\n") > 5


@pytest.mark.skipif(not ARM64_SAMPLE.exists(), reason="arm64 sample missing")
def test_decompile_all_on_arm64_sample():
    results = g.ir.decompile_all(str(ARM64_SAMPLE), limit=2)
    assert len(results) >= 1
    assert any("function " in text for _, _, text in results)


@pytest.mark.skipif(not ARM64_SAMPLE.exists(), reason="arm64 sample missing")
def test_lift_window_at_on_arm64_entry():
    got = g.analysis.detect_entry_path(str(ARM64_SAMPLE))
    assert got is not None
    entry_va = int(got[3])
    ops = g.ir.lift_window_at(str(ARM64_SAMPLE), entry_va, 128, arch="arm64")
    assert len(ops) > 0
    kinds = {o["kind"] for o in ops}
    # A real ARM64 entry contains at least one control-flow op in 128 bytes.
    assert kinds & {"call", "jump", "cond_jump", "return"}


@pytest.mark.skipif(not SAMPLE.exists(), reason="sample missing")
def test_lift_window_at_returns_dicts_for_real_binary():
    # Probe the entry VA reported by the native entry detector.
    art = g.triage.analyze_path(str(SAMPLE))
    entry_va = None
    for v in art.verdicts:
        ep = getattr(v, "entry", None)
        if ep is not None:
            entry_va = int(getattr(ep, "value", ep))
            break
    if entry_va is None:
        # Fall back to the analysis helper that independently detects entry.
        got = g.analysis.detect_entry_path(str(SAMPLE))
        if got is None:
            pytest.skip("could not determine entry VA")
        entry_va = int(got[3])

    ops = g.ir.lift_window_at(str(SAMPLE), entry_va, 128, 64)
    assert len(ops) > 0
    # Every dict must be well-formed.
    for o in ops:
        assert isinstance(o["va"], int)
        assert o["kind"] in {
            "nop",
            "assign",
            "bin",
            "un",
            "cmp",
            "load",
            "store",
            "jump",
            "cond_jump",
            "call",
            "return",
            "unknown",
        }
    # A 128-byte entry window from a compiled C program must contain at least
    # one call or jump.
    kinds = [o["kind"] for o in ops]
    assert any(k in ("call", "jump") for k in kinds), f"no call/jump in {kinds}"
