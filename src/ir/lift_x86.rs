//! x86 / x86-64 → LLIR lifter.
//!
//! Decodes bytes with `iced_x86` and emits LLIR ops. One machine instruction
//! may produce multiple [`LlirInstr`]s sharing the same `va` (e.g. `push rax`
//! expands to `rsp = rsp - 8; store [rsp], rax`).
//!
//! Coverage is intentionally minimal for the first pass:
//!
//! * `nop` → [`Op::Nop`]
//! * `mov` between reg / imm / mem → [`Op::Assign`] / [`Op::Load`] / [`Op::Store`]
//! * `add`, `sub`, `sbb`, `and`, `or`, `xor`, `shl`, `shr`, `sar`, `imul`, `div` → [`Op::Bin`]
//! * `not`, `neg` → [`Op::Un`]
//! * `inc`, `dec`, `xadd`, `xchg`, `cmpxchg` on registers / memory → [`Op::Bin`] or load-modify-store
//! * `movsd` / `stos*` string ops → copy/store or exact repeated memory fill
//! * common SSE moves/zeroing (`movsd`, `movaps`, `xorps`) → assign/load/store/bin
//! * `cmp` → [`Op::Cmp`] writing `ZF`/`CF`/`SF`
//! * `test` → [`Op::Cmp`] writing `ZF`/`SF`
//! * `setcc` → [`Op::Assign`] / [`Op::Store`] from the corresponding flag
//! * `cmovcc` → [`Op::Ite`]
//! * `push` / `pop` → decomposed into rsp-adjust + load/store
//! * `call` near direct / indirect → [`Op::Call`]
//! * `ret` → [`Op::Return`]
//! * `jmp` near direct → [`Op::Jump`]
//! * `jcc` (je, jne, jl, jg, …) → [`Op::CondJump`] reading the appropriate flag
//! * `lea` with rip-relative memory → [`Op::Assign`] of absolute VA
//!
//! Anything outside this set becomes [`Op::Unknown`] with the source mnemonic.

use iced_x86::{Decoder, DecoderOptions, Mnemonic, OpKind, Register};

use crate::ir::regview;
use crate::ir::types::*;

mod bit_ops;
mod conditions;
mod flags;
mod mul_flags;
mod packed;
mod packed_halves;
mod packed_string;
mod scalar_float;
mod string_ops;
mod wide_arith;
mod xmm_views;
use bit_ops::{
    bit_test_ops, count_trailing_zeros_ops, population_count_ops, rotate_carry_right_ops, BitTest,
};
use conditions::{
    cmovcc_condition_for, condition_for_suffix, condition_suffix, materialize_condition,
    setcc_condition_for,
};
use flags::{
    adc_ops, append_rotate_flags, append_undef_flags, bin_for, cmp_flag_ops, emit_add_with_flags,
    emit_inc_dec_with_flags, emit_machine_bin_with_flags, sbb_ops, signed_cmp_value, undef_flag,
    zero_sign_flags,
};
use mul_flags::{append_imul_overflow_flags, imul_wide_product};
use packed::{
    movd_ops, packed_dword_and_not_ops, packed_dword_binary_ops, packed_dword_compare_equal_ops,
    packed_dword_immediate_arithmetic_shift_right_ops,
    packed_dword_immediate_logical_shift_right_ops, packed_dword_immediate_shift_left_ops,
    packed_dword_move_ops, packed_dword_shuffle_ops, packed_dword_unpack_low_ops,
    packed_float_shuffle_ops, packed_float_sign_mask_ops, packed_qword_binary_ops,
    packed_qword_move_ops, packed_qword_unpack_low_ops, packed_word_extract_ops, xorps_ops,
};
use packed_halves::{packed_qword_half_move_ops, packed_qword_half_swap_ops, XmmHalf};
use packed_string::{
    declare_xmm_register_effect_ops, packed_byte_compare_ops, packed_byte_shuffle_ops,
    packed_byte_sign_mask_ops, packed_byte_unpack_low_ops, packed_double_shuffle_ops,
    packed_dword_compare_greater_ops, packed_dword_saturating_pack_ops, packed_insert_ops,
    packed_qword_immediate_logical_shift_right_ops, packed_qword_unpack_high_ops,
    packed_unsigned_dword_multiply_ops, packed_word_shuffle_ops, packed_word_unpack_low_ops,
};
use scalar_float::{
    scalar_convert_ops, scalar_convert_source_bytes, scalar_float_binary_ops,
    scalar_float_compare_ops, scalar_move_ops,
};
use string_ops::{movs_ops, movs_width, pop_ops, push_ops, stos_ops};
use wide_arith::{bit_scan_ops, cmpxchg_ops, double_shift_ops, wide_div_ops, wide_mul_ops};
use xmm_views::{split_xmm_scalar_view, synchronise_xmm_views};
// `x87`'s `fcomi`/`fucomi` share the SSE four-outcome flag model verbatim; the
// re-export keeps `crate::ir::lift_x86::float_compare_flag_ops` the single name
// for it, exactly as it was before the split.
pub(crate) use scalar_float::float_compare_flag_ops;

fn reg_name(r: Register) -> String {
    let name = format!("{:?}", r).to_ascii_lowercase();
    // iced spells the byte views of the extended registers `R8L`..`R15L`, while
    // the canonical register-view layout (and every other tool) calls them
    // `r8b`..`r15b`. Without this normalisation those names match no known
    // register at all: writes to them vanish and reads return zero.
    regview::canonical_name(&name)
}

fn reg_size(r: Register) -> u8 {
    let s = r.size();
    if s == 0 {
        8
    } else {
        s as u8
    }
}

/// The register a 32-bit PIC "PC thunk" body materialises the program counter
/// into, or `None` when `body` is not a PC thunk.
///
/// 32-bit x86 has no PC-relative addressing mode, so position-independent code
/// obtains its own address by CALLing a two-instruction helper that copies the
/// pushed return address into a GP register:
///
/// ```text
///     call __x86.get_pc_thunk.bx      ; ebx = address of the next instruction
///     add  $_GLOBAL_OFFSET_TABLE_, %ebx
/// ```
///
/// It is a `call` in encoding only. It takes no argument, returns no value in
/// the ABI sense, and its entire effect is `reg = <return address>` — so lifting
/// it as a call both invents a callee that has no C spelling and, worse, leaves
/// the GOT base an unknown value, which makes every global and string reference
/// derived from it unrecoverable.
///
/// Matched on the callee's BYTES rather than its symbol name: the idiom survives
/// stripping, and gcc has spelled the symbol `__i686.get_pc_thunk.*` as well as
/// `__x86.get_pc_thunk.*`. `8b /r` with mod=00 and rm=100 (SIB) plus SIB byte
/// 0x24 (base=esp, no index) is `mov reg,(%esp)`; `c3` is `ret`. `esp` as the
/// destination is rejected: `mov (%esp),%esp` is not this idiom, and treating it
/// as one would silently rewrite the stack pointer.
pub fn pc_thunk_register(body: &[u8]) -> Option<&'static str> {
    let [0x8b, modrm, 0x24, 0xc3, ..] = body else {
        return None;
    };
    if modrm & 0xC7 != 0x04 {
        return None;
    }
    match (modrm >> 3) & 7 {
        0 => Some("eax"),
        1 => Some("ecx"),
        2 => Some("edx"),
        3 => Some("ebx"),
        4 => None, // `mov (%esp),%esp`
        5 => Some("ebp"),
        6 => Some("esi"),
        _ => Some("edi"),
    }
}

/// The register-view descriptor for a partial (bit-preserving) GP write, or
/// `None` when the destination is a full-width or zero-extending view that needs
/// no read-modify-write. Covers the 8-/16-bit low views AND the legacy high bytes
/// (`ah`/`bh`/`ch`/`dh`, bit offset 8).
///
/// The bank filter is load-bearing: a packed dword lane (`xmm0_d0`) is also a
/// bit-preserving view of its parent, but of a 128-bit one that this lifter
/// scalarises rather than reconstructs. Lowering `paddd`'s lane destination as a
/// masked read-modify-write of `xmm0` would both be wrong (the masks here are
/// 64-bit) and destroy the lane representation every packed op depends on.
fn partial_gp_view(name: &str) -> Option<regview::RegView> {
    regview::view(regview::Arch::X86_64, name)
        .filter(|v| v.bank == regview::RegBank::Gp && v.preserves_parent())
}

/// A 32-bit GP view whose write clears the upper half of its 64-bit parent.
fn zero_extending_gp_view(name: &str, bits: u32) -> Option<regview::RegView> {
    (bits == 64)
        .then(|| regview::view(regview::Arch::X86_64, name))
        .flatten()
        .filter(|view| view.zero_extends())
}

/// The constant a write through `dst_name` actually leaves in its canonical parent.
///
/// A 32-bit GP write on x86-64 zero-extends: `mov $0x80808081,%eax` leaves `rax`
/// holding 0x0000000080808081, a *positive* number. iced reports the imm32 as a
/// 32-bit two's-complement value and we read it `as i32 as i64`, which sign-extends
/// to 0xffffffff80808081 instead. Both spellings agree in the low 32 bits, so the
/// difference is invisible until something reads the parent at full width — which
/// `imul %rdx,%rax` immediately does.
///
/// 0x80808081 is the magic reciprocal for division by 255, so this one bit made
/// every `x % 255` decompile into different arithmetic: `mod255` came out as
/// `(-0x7f7f7f7f * x) >> 32`, which compiles, runs, and returns the wrong answer.
///
/// Only constants are adjusted, and only in 64-bit mode. A register source is
/// already handled by the explicit-widening pass, and in 32-bit mode `eax` *is* the
/// whole register — there masking would merely re-spell -1 as 4294967295 and lose
/// the signed reading the 32-bit comparisons rely on.
fn const_written_through_view(dst_name: &str, src: Value, bits: u32) -> Value {
    if bits != 64 {
        return src;
    }
    let Value::Const(c) = src else {
        return src;
    };
    match regview::view(regview::Arch::X86_64, dst_name) {
        Some(v) if v.zero_extends() => {
            Value::Const((u128::from(c as u64) & v.value_mask()) as u64 as i64)
        }
        _ => src,
    }
}

/// Lift a partial-register write `view = src` as a bit-preserving read-modify-write
/// of its CANONICAL 64-BIT parent:
///
/// ```text
///   parent = (parent & keep_mask) | ((src & value_mask) << offset)
/// ```
///
/// The masks come from the shared register-view descriptor, so `mov $0xAA,%al`
/// keeps bits 8..63 of `rax` — not just bits 8..31. Modelling this against the
/// 32-bit view instead (`eax`) was wrong twice over: a 32-bit write zero-extends,
/// so it cleared bits 32..63 that the instruction must preserve, and the mask
/// itself stopped at bit 31. A constant source whose masked value is zero
/// collapses to the mask alone (gcc's `mov $0,%al` low-byte clear).
fn partial_write_ops(v: regview::RegView, src: Value) -> Vec<Op> {
    let p = VReg::phys(v.parent);
    let mut ops = vec![Op::Bin {
        dst: p.clone(),
        op: BinOp::And,
        lhs: Value::Reg(p.clone()),
        rhs: Value::Const(v.keep_mask() as u64 as i64),
    }];
    let value_mask = (v.value_mask() >> v.offset) as u64 as i64;
    let positioned = match src {
        Value::Const(c) => {
            let m = (c & value_mask) << v.offset;
            if m == 0 {
                return ops;
            }
            Value::Const(m)
        }
        other => {
            let t = VReg::Temp(0);
            ops.push(Op::Bin {
                dst: t.clone(),
                op: BinOp::And,
                lhs: other,
                rhs: Value::Const(value_mask),
            });
            if v.offset != 0 {
                ops.push(Op::Bin {
                    dst: t.clone(),
                    op: BinOp::Shl,
                    lhs: Value::Reg(t.clone()),
                    rhs: Value::Const(v.offset as i64),
                });
            }
            Value::Reg(t)
        }
    };
    ops.push(Op::Bin {
        dst: p.clone(),
        op: BinOp::Or,
        lhs: Value::Reg(p),
        rhs: positioned,
    });
    ops
}

/// Read a bit-preserving partial view out of its canonical parent into `dst`:
/// `dst = (parent >> offset) & value_mask`.
///
/// Without this, a read of `ah` is just an unrelated register NAME to every
/// consumer that does not implement view semantics itself — which is every
/// decompiler pass. The execution engine's register file does implement them, so
/// it was already correct; the decompiler was not.
fn read_view_ops(v: regview::RegView, dst: VReg) -> Vec<Op> {
    let p = Value::Reg(VReg::phys(v.parent));
    let mask = (v.value_mask() >> v.offset) as u64 as i64;
    let mut ops = Vec::new();
    if v.offset == 0 {
        ops.push(Op::Bin {
            dst,
            op: BinOp::And,
            lhs: p,
            rhs: Value::Const(mask),
        });
    } else {
        ops.push(Op::Bin {
            dst: dst.clone(),
            op: BinOp::Shr,
            lhs: p,
            rhs: Value::Const(v.offset as i64),
        });
        ops.push(Op::Bin {
            dst: dst.clone(),
            op: BinOp::And,
            lhs: Value::Reg(dst),
            rhs: Value::Const(mask),
        });
    }
    ops
}

/// Lift `op view, src` — an ALU operation whose destination is a bit-preserving
/// partial register view — as a read-modify-write of the canonical parent:
///
/// ```text
///   acc    = (parent >> offset) & value_mask     // read the view
///   acc    = op(acc, src)                        // the operation, at view width
///   parent = (parent & keep_mask) | ((acc & value_mask) << offset)
/// ```
///
/// `partial_write_ops` covers `mov`; this covers the rest, and the gap between
/// them was not academic: gcc clears a byte lane with `xor %ah,%ah`, which took
/// the plain ALU path, wrote a register name unrelated to `rax`, and left the
/// following read of `eax` seeing the UNCLEARED value — the whole point of the
/// instruction, silently dropped (fixture `deposit_byte1`).
///
/// When `src` names the destination view itself (`xor %ah,%ah`), the accumulator is
/// reused for both operands, so constant folding still recognises the idiom.
fn partial_alu_ops(v: regview::RegView, op: BinOp, src: Value, bits: u32) -> Vec<Op> {
    let parent = VReg::phys(v.parent);
    let acc = VReg::Temp(0);
    let mask = (v.value_mask() >> v.offset) as u64 as i64;
    let mut ops = read_view_ops(v, acc.clone());

    let rhs = match &src {
        Value::Reg(VReg::Phys(n)) if n == v.view => Value::Reg(acc.clone()),
        Value::Reg(VReg::Phys(n)) => match partial_gp_view(n) {
            // A partial-view SOURCE needs the same treatment, or it too is just a
            // name (e.g. `add %ah,%al`).
            Some(sv) => {
                let t = VReg::Temp(1);
                ops.extend(read_view_ops(sv, t.clone()));
                Value::Reg(t)
            }
            _ => src.clone(),
        },
        _ => src.clone(),
    };
    ops.extend(emit_machine_bin_with_flags(
        acc.clone(),
        op,
        rhs,
        Width(v.width),
        bits,
    ));
    ops.push(Op::Bin {
        dst: parent.clone(),
        op: BinOp::And,
        lhs: Value::Reg(parent.clone()),
        rhs: Value::Const(v.keep_mask() as u64 as i64),
    });
    ops.push(Op::Bin {
        dst: acc.clone(),
        op: BinOp::And,
        lhs: Value::Reg(acc.clone()),
        rhs: Value::Const(mask),
    });
    if v.offset != 0 {
        ops.push(Op::Bin {
            dst: acc.clone(),
            op: BinOp::Shl,
            lhs: Value::Reg(acc.clone()),
            rhs: Value::Const(v.offset as i64),
        });
    }
    ops.push(Op::Bin {
        dst: parent.clone(),
        op: BinOp::Or,
        lhs: Value::Reg(parent),
        rhs: Value::Reg(acc),
    });
    ops
}

/// Translate an iced register operand to a VReg. `Register::None` maps to None
/// so callers can distinguish "no base" from "base is some register".
fn maybe_reg(r: Register) -> Option<VReg> {
    if r == Register::None {
        None
    } else {
        Some(VReg::phys(reg_name(r)))
    }
}

fn segment_override(seg: Register) -> Option<String> {
    // Only non-default segments are interesting — `fs`/`gs` on x86-64 carry
    // TLS semantics; `ds`/`ss`/`cs`/`es` are effectively implicit on every
    // ordinary memory access and would only add noise.
    match seg {
        Register::FS => Some("fs".to_string()),
        Register::GS => Some("gs".to_string()),
        _ => None,
    }
}

/// Decode a base/index-relative displacement with the address width that iced
/// used. In 32-bit mode iced returns `-0x24` as `0x00000000ffffffdc`; a direct
/// `as i64` therefore turns a frame local into a four-gigabyte positive offset.
/// Absolute no-base addresses remain unsigned VAs.
fn memory_displacement_i64(instr: &iced_x86::Instruction) -> i64 {
    let raw = instr.memory_displacement64();
    let base = instr.memory_base();
    let index = instr.memory_index();
    let has_relative_register = base != Register::None || index != Register::None;
    let uses_32bit_addressing = [base, index].into_iter().any(|register| {
        maybe_reg(register).and_then(|reg| match reg {
            VReg::Phys(name) => phys_reg_width(&name),
            _ => None,
        }) == Some(Width::W32)
    });
    if has_relative_register && uses_32bit_addressing {
        raw as u32 as i32 as i64
    } else {
        raw as i64
    }
}

pub(crate) fn mem_op_of(instr: &iced_x86::Instruction) -> MemOp {
    let base = if instr.memory_base() == Register::RIP {
        None
    } else {
        maybe_reg(instr.memory_base())
    };
    MemOp {
        base,
        index: maybe_reg(instr.memory_index()),
        scale: instr.memory_index_scale() as u8,
        disp: memory_displacement_i64(instr),
        size: instr.memory_size().size() as u8,
        segment: segment_override(instr.memory_segment()),
        endian: Endian::Little,
    }
}

/// Resolve a rip-relative memory reference to its absolute VA. iced already
/// exposes this via `memory_displacement64()` when the base register is RIP,
/// so we just return that value.
fn rip_relative_addr(instr: &iced_x86::Instruction) -> Option<u64> {
    if instr.memory_base() == Register::RIP {
        Some(instr.memory_displacement64())
    } else {
        None
    }
}

fn value_of_operand(instr: &iced_x86::Instruction, idx: u32) -> Option<Value> {
    match instr.op_kind(idx) {
        OpKind::Register => Some(Value::Reg(VReg::phys(reg_name(instr.op_register(idx))))),
        OpKind::Immediate8 => Some(Value::Const(instr.immediate8() as i8 as i64)),
        OpKind::Immediate16 => Some(Value::Const(instr.immediate16() as i16 as i64)),
        OpKind::Immediate32 => Some(Value::Const(instr.immediate32() as i32 as i64)),
        // EVERY sign-extended form has its own accessor, not just the 64-bit ones.
        // iced populates `immediate32()` only for a true `Immediate32`; on an
        // `Immediate8to32` it hands back the raw byte, so `83 c0 ff`
        // (`add eax, -1`) lifted as `+255`. clang -O0 spells `n--` exactly that
        // way, which made a loop counter climb instead of fall.
        OpKind::Immediate8to16 => Some(Value::Const(instr.immediate8to16() as i64)),
        OpKind::Immediate8to32 => Some(Value::Const(instr.immediate8to32() as i64)),
        // Calling the plain `immediate64()` on an `Immediate32to64`/`Immediate8to64`
        // operand returns garbage for the same reason, so `movq $0,[mem]` was
        // lifting to a bogus constant.
        OpKind::Immediate64 => Some(Value::Const(instr.immediate64() as i64)),
        OpKind::Immediate8to64 => Some(Value::Const(instr.immediate8to64())),
        OpKind::Immediate32to64 => Some(Value::Const(instr.immediate32to64())),
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
            Some(Value::Addr(instr.near_branch_target()))
        }
        _ => None,
    }
}

/// Resolve an operand to a `Value` for use as a `Cmp` input. If the operand
/// is a memory reference, prepend a load-into-temp op to `preamble` and
/// return `Value::Reg(temp)`. Returns `None` for operand kinds that cannot
/// be turned into a Value (e.g. branches).
fn cmp_operand_as_value(
    instr: &iced_x86::Instruction,
    idx: u32,
    temp: VReg,
    preamble: &mut Vec<Op>,
) -> Option<Value> {
    if instr.op_kind(idx) == OpKind::Memory {
        preamble.push(Op::Load {
            dst: temp.clone(),
            addr: mem_op_of(instr),
        });
        return Some(Value::Reg(temp));
    }
    if instr.op_kind(idx) == OpKind::Register {
        let name = reg_name(instr.op_register(idx));
        if let Some(view) = partial_gp_view(&name) {
            preamble.extend(read_view_ops(view, temp.clone()));
            return Some(Value::Reg(temp));
        }
        return Some(Value::Reg(VReg::phys(name)));
    }
    value_of_operand(instr, idx)
}

/// Width at which an instruction operand participates in arithmetic.
fn operand_width(instr: &iced_x86::Instruction, idx: u32) -> Width {
    match instr.op_kind(idx) {
        OpKind::Register => phys_reg_width(&reg_name(instr.op_register(idx))).unwrap_or(Width::W64),
        OpKind::Memory => Width::from_bytes(instr.memory_size().size() as u16),
        _ => Width::W64,
    }
}

fn accumulator_name_for_width(width: u8, bits: u32) -> &'static str {
    match width {
        1 => "al",
        2 => "ax",
        4 => "eax",
        8 => "rax",
        _ if bits == 64 => "rax",
        _ => "eax",
    }
}

/// Lift a single iced instruction into zero or more LLIR ops.
fn lift_one(instr: &iced_x86::Instruction, bits: u32) -> Vec<Op> {
    let mut ops = lift_one_inner(instr, bits);
    // Scalar -> lanes first, lanes -> scalar second. The order is load-bearing;
    // see the `xmm_views` module documentation.
    split_xmm_scalar_view(instr, &mut ops);
    synchronise_xmm_views(&mut ops);
    ops
}

fn lift_one_inner(instr: &iced_x86::Instruction, bits: u32) -> Vec<Op> {
    let mnem = instr.mnemonic();
    // Binary ops: dst op= src (two-operand x86 form)
    if let Some(op) = bin_for(mnem) {
        if instr.op_count() == 2 {
            // Destination: first operand (reg or mem).
            match instr.op_kind(0) {
                OpKind::Register => {
                    let dst_name = reg_name(instr.op_register(0));
                    let dst = VReg::phys(&dst_name);
                    // A bit-preserving partial destination (`al`, `ax`, `ah`, …) is
                    // a read-modify-write of its 64-bit parent, not a write to a
                    // register of its own — see `partial_alu_ops`.
                    let partial = partial_gp_view(&dst_name);
                    let src = if matches!(op, BinOp::Shl | BinOp::Shr | BinOp::Sar)
                        && instr.op_kind(1) == OpKind::Register
                        && instr.op_register(1) == Register::CL
                    {
                        // Variable shifts encode CL, but the value is defined
                        // through ECX/RCX. Use the canonical 32-bit view so SSA
                        // connects the count to the preceding ECX write instead
                        // of inventing an unrelated live-in `cl` value.
                        Some(Value::Reg(VReg::phys("ecx")))
                    } else {
                        value_of_operand(instr, 1)
                    };
                    if let Some(src) = src {
                        return match partial {
                            Some(v) => partial_alu_ops(v, op, src, bits),
                            None => {
                                let width = operand_width(instr, 0);
                                emit_machine_bin_with_flags(dst, op, src, width, bits)
                            }
                        };
                    } else if instr.op_kind(1) == OpKind::Memory {
                        // dst_reg = op(dst_reg, load([mem]))
                        // We introduce a temp to keep three-address form.
                        let tmp = VReg::Temp(2);
                        let load = Op::Load {
                            dst: tmp.clone(),
                            addr: mem_op_of(instr),
                        };
                        return match partial {
                            Some(v) => {
                                let mut ops = vec![load];
                                ops.extend(partial_alu_ops(v, op, Value::Reg(tmp), bits));
                                ops
                            }
                            None => {
                                let mut ops = vec![load];
                                ops.extend(emit_machine_bin_with_flags(
                                    dst,
                                    op,
                                    Value::Reg(tmp),
                                    operand_width(instr, 0),
                                    bits,
                                ));
                                ops
                            }
                        };
                    }
                }
                OpKind::Memory => {
                    // mem op= src (reg or imm): load-modify-store.
                    let addr = mem_op_of(instr);
                    if let Some(src) = value_of_operand(instr, 1) {
                        let tmp = VReg::Temp(0);
                        let mut ops = vec![Op::Load {
                            dst: tmp.clone(),
                            addr: addr.clone(),
                        }];
                        ops.extend(emit_machine_bin_with_flags(
                            tmp.clone(),
                            op,
                            src,
                            operand_width(instr, 0),
                            bits,
                        ));
                        ops.push(Op::Store {
                            addr,
                            src: Value::Reg(tmp),
                        });
                        return ops;
                    }
                }
                _ => {}
            }
        }
    }

    match mnem {
        Mnemonic::Nop
        | Mnemonic::Endbr32
        | Mnemonic::Endbr64
        | Mnemonic::Int3
        | Mnemonic::Fninit => vec![Op::Nop],
        Mnemonic::Mov => {
            if instr.op_count() != 2 {
                return vec![Op::Unknown {
                    mnemonic: "mov".into(),
                }];
            }
            match (instr.op_kind(0), instr.op_kind(1)) {
                (OpKind::Register, OpKind::Memory) => {
                    let dst_name = reg_name(instr.op_register(0));
                    if let Some(view) = partial_gp_view(&dst_name) {
                        let value = VReg::Temp(0);
                        let mut ops = vec![Op::Load {
                            dst: value.clone(),
                            addr: mem_op_of(instr),
                        }];
                        ops.extend(partial_write_ops(view, Value::Reg(value)));
                        ops
                    } else if zero_extending_gp_view(&dst_name, bits).is_some() {
                        let value = VReg::Temp(0);
                        vec![
                            Op::Load {
                                dst: value.clone(),
                                addr: mem_op_of(instr),
                            },
                            Op::ZExt {
                                dst: VReg::phys(dst_name),
                                src: Value::Reg(value),
                                from: Width::W32,
                                to: Width::W64,
                            },
                        ]
                    } else {
                        vec![Op::Load {
                            dst: VReg::phys(dst_name),
                            addr: mem_op_of(instr),
                        }]
                    }
                }
                (OpKind::Memory, _) => {
                    // A partial register SOURCE is a view of its canonical
                    // parent.  Spell the extraction explicitly before the
                    // store so SSA versions the producer and consumer as one
                    // value.  Treating `al` as an independent register here
                    // made `movzx eax,[mem]; mov [stack],al` store a loop-entry
                    // live-in instead of the byte just loaded.
                    if instr.op_kind(1) == OpKind::Register {
                        let src_name = reg_name(instr.op_register(1));
                        if let Some(view) = partial_gp_view(&src_name) {
                            let value = VReg::Temp(0);
                            let mut ops = read_view_ops(view, value.clone());
                            ops.push(Op::Store {
                                addr: mem_op_of(instr),
                                src: Value::Reg(value),
                            });
                            return ops;
                        }
                    }
                    if let Some(src) = value_of_operand(instr, 1) {
                        vec![Op::Store {
                            addr: mem_op_of(instr),
                            src,
                        }]
                    } else {
                        vec![Op::Unknown {
                            mnemonic: "mov".into(),
                        }]
                    }
                }
                (OpKind::Register, _) => {
                    let Some(src) = value_of_operand(instr, 1) else {
                        return vec![Op::Unknown {
                            mnemonic: "mov".into(),
                        }];
                    };
                    let dst_name = reg_name(instr.op_register(0));
                    // A partial register SOURCE is a view of its canonical parent,
                    // exactly as it is for the memory-destination and `movzx`/`movsx`
                    // forms above. This arm was the one that still read it as an
                    // independent name, and `regview::ssa_parent` refuses to merge a
                    // bit-preserving view with its parent — so `cdq; idiv ecx; mov
                    // ax, dx` (clang's sub-word remainder) read a `dx` that nothing
                    // in the function defines, and
                    // `185_subword_signed_division:remainder_signed_shorts` rendered
                    // the remainder as an undeclared `var10`.
                    let mut preamble = Vec::new();
                    let src = match (&src, partial_gp_view(&reg_name(instr.op_register(1)))) {
                        (Value::Reg(_), Some(view)) if instr.op_kind(1) == OpKind::Register => {
                            let value = VReg::Temp(76);
                            preamble = read_view_ops(view, value.clone());
                            Value::Reg(value)
                        }
                        _ => src,
                    };
                    // A partial (8-/16-bit, low or high-byte) GP write preserves
                    // the parent's other bits; a plain Assign would drop them and
                    // later `eax`/`rax` reads would see a stale value (e.g. gcc's
                    // low-byte-clear `mov $0, %al`).
                    if let Some(v) = partial_gp_view(&dst_name) {
                        preamble.extend(partial_write_ops(v, src));
                        return preamble;
                    }
                    if zero_extending_gp_view(&dst_name, bits).is_some()
                        && !matches!(src, Value::Const(_))
                    {
                        preamble.push(Op::ZExt {
                            dst: VReg::phys(dst_name),
                            src,
                            from: Width::W32,
                            to: Width::W64,
                        });
                        return preamble;
                    }
                    let src = const_written_through_view(&dst_name, src, bits);
                    preamble.push(Op::Assign {
                        dst: VReg::phys(dst_name),
                        src,
                    });
                    preamble
                }
                _ => vec![Op::Unknown {
                    mnemonic: "mov".into(),
                }],
            }
        }
        Mnemonic::Movsx | Mnemonic::Movsxd | Mnemonic::Movzx => {
            if instr.op_count() != 2 || instr.op_kind(0) != OpKind::Register {
                return vec![Op::Unknown {
                    mnemonic: format!("{:?}", mnem).to_ascii_lowercase(),
                }];
            }
            let dst_name = reg_name(instr.op_register(0));
            let to = phys_reg_width(&dst_name).unwrap_or(Width::W64);
            let dst = VReg::phys(dst_name);
            // `movzx` zero-extends; `movsx`/`movsxd` sign-extend. (The previous
            // code emitted a plain Assign for all three, which silently
            // zero-extended `movsx` — caught by the Unicorn differential oracle.)
            let signed = !matches!(mnem, Mnemonic::Movzx);
            match instr.op_kind(1) {
                OpKind::Register => {
                    let src_name = reg_name(instr.op_register(1));
                    let from = phys_reg_width(&src_name).unwrap_or(Width::W8);
                    // An 8-/16-bit source is a view of its full-width parent,
                    // not an independent register.  Extract it explicitly so
                    // SSA connects this read to partial writes such as SETcc.
                    let (mut ops, src) = if let Some(view) = partial_gp_view(&src_name) {
                        let value = VReg::Temp(0);
                        (read_view_ops(view, value.clone()), Value::Reg(value))
                    } else {
                        (Vec::new(), Value::Reg(VReg::phys(src_name)))
                    };
                    if signed {
                        ops.push(Op::SExt { dst, src, from, to });
                    } else {
                        ops.push(Op::ZExt { dst, src, from, to });
                    }
                    ops
                }
                OpKind::Memory => {
                    let mo = mem_op_of(instr);
                    let from = Width::from_bytes(mo.size as u16);
                    let tmp = VReg::Temp(0);
                    let load = Op::Load {
                        dst: tmp.clone(),
                        addr: mo,
                    };
                    let ext = if signed {
                        Op::SExt {
                            dst,
                            src: Value::Reg(tmp),
                            from,
                            to,
                        }
                    } else {
                        Op::ZExt {
                            dst,
                            src: Value::Reg(tmp),
                            from,
                            to,
                        }
                    };
                    vec![load, ext]
                }
                _ => vec![Op::Unknown {
                    mnemonic: format!("{:?}", mnem).to_ascii_lowercase(),
                }],
            }
        }
        // Accumulator sign-extension: `cbw`/`cwde`/`cdqe` (AT&T `cbtw`/`cwtl`/`cltq`)
        // widen the accumulator IN PLACE, sign-filling. `cdqe` was lifted as the plain
        // assignment `rax = eax`, which zero-extends — so every negative `int` promoted
        // to `long` became a huge positive. gcc emits this constantly for `int`->`long`
        // promotion and for array indexing, so the error was everywhere it mattered.
        Mnemonic::Cbw => vec![Op::SExt {
            dst: VReg::phys("ax"),
            src: Value::Reg(VReg::phys("al")),
            from: Width::W8,
            to: Width::W16,
        }],
        Mnemonic::Cwde => vec![Op::SExt {
            dst: VReg::phys("eax"),
            src: Value::Reg(VReg::phys("ax")),
            from: Width::W16,
            to: Width::W32,
        }],
        Mnemonic::Cdqe => vec![Op::SExt {
            dst: VReg::phys("rax"),
            src: Value::Reg(VReg::phys("eax")),
            from: Width::W32,
            to: Width::W64,
        }],
        // Sign-broadcast into the high half before a signed divide: `cwd`/`cdq`/`cqo`
        // (AT&T `cwtd`/`cltd`/`cqto`) set dx/edx/rdx to all-ones or all-zeros according
        // to the accumulator's sign bit — exactly an arithmetic shift by width-1.
        //
        // These were unlifted (38 `cqo` in the cross-compiled corpus), which left the
        // high half undefined. That is not harmless even though our `idiv` lift only
        // models the quotient: `rdx` is also the third SysV argument register, so an
        // undefined value there can be picked up as a call argument.
        // Preserve CDQ's 32-bit signedness through SSA renaming by making the
        // doubled-width value explicit, then taking its high dword. A bare SAR
        // loses its source width once `eax` becomes an untyped SSA name.
        Mnemonic::Cdq => vec![
            Op::SExt {
                dst: VReg::Temp(5),
                src: Value::Reg(VReg::phys("eax")),
                from: Width::W32,
                to: Width::W64,
            },
            Op::Extract {
                dst: VReg::phys("edx"),
                src: Value::Reg(VReg::Temp(5)),
                hi: 64,
                lo: 32,
            },
        ],
        Mnemonic::Cwd | Mnemonic::Cqo => {
            let (hi, lo, shift) = match mnem {
                Mnemonic::Cwd => ("dx", "ax", 15),
                _ => ("rdx", "rax", 63),
            };
            let ops = vec![Op::Bin {
                dst: VReg::phys(hi),
                op: BinOp::Sar,
                lhs: Value::Reg(VReg::phys(lo)),
                rhs: Value::Const(shift),
            }];
            // A 16-bit destination is a bit-preserving partial write of `rdx`.
            match partial_gp_view(hi) {
                Some(v) => {
                    let t = VReg::Temp(5);
                    vec![Op::Bin {
                        dst: t.clone(),
                        op: BinOp::Sar,
                        lhs: Value::Reg(VReg::phys(lo)),
                        rhs: Value::Const(shift),
                    }]
                    .into_iter()
                    .chain(partial_write_ops(v, Value::Reg(t)))
                    .collect()
                }
                None => ops,
            }
        }
        // 3-operand imul: `imul dst, src, imm` → dst = src * imm. (The 2-operand
        // form is handled by the binary-op path above.)
        Mnemonic::Imul => {
            if instr.op_count() == 1 {
                return wide_mul_ops(instr, true).unwrap_or_else(|| {
                    vec![Op::Unknown {
                        mnemonic: "imul".into(),
                    }]
                });
            }
            if instr.op_count() == 3 && instr.op_kind(0) == OpKind::Register {
                let dst_name = reg_name(instr.op_register(0));
                let dst = VReg::phys(&dst_name);
                if let Some(rhs) = value_of_operand(instr, 2) {
                    // The multiplicand may be MEMORY: clang at -O0 spills each
                    // parameter and multiplies straight out of the slot
                    // (`imul $0x3,-0xc(%rbp),%ecx`). Requiring a register source
                    // dropped the whole multiply — `a2 * 3` vanished from
                    // `sum_arg3` and the surrounding expression silently reused
                    // another term.
                    let mut ops = Vec::new();
                    let lhs = match (value_of_operand(instr, 1), instr.op_kind(1)) {
                        (Some(v), _) => v,
                        (None, OpKind::Memory) => {
                            let t = VReg::Temp(3);
                            ops.push(Op::Load {
                                dst: t.clone(),
                                addr: mem_op_of(instr),
                            });
                            Value::Reg(t)
                        }
                        _ => {
                            return vec![Op::Unknown {
                                mnemonic: "imul".into(),
                            }];
                        }
                    };
                    // CF/OF are the truncation verdict on the FULL product, so the
                    // wide multiply is snapshotted before the narrow one is written.
                    let width = operand_width(instr, 0);
                    let product = imul_wide_product(&mut ops, lhs.clone(), rhs.clone(), width);
                    // A partial-view destination is a bit-preserving write of the
                    // product, not a write of a register of its own.
                    match partial_gp_view(&dst_name) {
                        Some(v) => {
                            let t = VReg::Temp(4);
                            ops.push(Op::Bin {
                                dst: t.clone(),
                                op: BinOp::Mul,
                                lhs,
                                rhs,
                            });
                            ops.extend(partial_write_ops(v, Value::Reg(t)));
                        }
                        None => ops.push(Op::Bin {
                            dst,
                            op: BinOp::Mul,
                            lhs,
                            rhs,
                        }),
                    }
                    append_imul_overflow_flags(&mut ops, product, width);
                    append_undef_flags(
                        &mut ops,
                        &[Flag::Z, Flag::S, Flag::P, Flag::A],
                        "x86 IMUL leaves ZF/SF/PF/AF architecturally undefined",
                    );
                    return ops;
                }
            }
            vec![Op::Unknown {
                mnemonic: "imul".into(),
            }]
        }
        // Rotate `rol`/`ror r, {imm | cl}` lifts to the shift/shift/or identity
        // `(x << n) | (x >> (w-n))` (the consuming `or`'s width comes from the
        // physical dst, so the temps need no explicit width). Immediate-count
        // memory forms use the same identity around an exact load/store pair.
        Mnemonic::Rol | Mnemonic::Ror => {
            if instr.op_count() == 2 && instr.op_kind(0) == OpKind::Register {
                let dst_name = reg_name(instr.op_register(0));
                let width = phys_reg_width(&dst_name).unwrap_or(Width::W64);
                let w = width.bits() as i64;
                let view = partial_gp_view(&dst_name);
                let dst = if view.is_some() {
                    VReg::Temp(40)
                } else {
                    VReg::phys(dst_name)
                };
                let preamble = view
                    .map(|partial| read_view_ops(partial, dst.clone()))
                    .unwrap_or_default();
                if let Some(Value::Const(cnt)) = value_of_operand(instr, 1) {
                    let n = ((cnt % w) + w) % w;
                    if n == 0 {
                        return vec![Op::Nop];
                    }
                    let (t1, t2) = (VReg::Temp(41), VReg::Temp(42));
                    let (a_op, a_sh, b_op, b_sh) = if matches!(mnem, Mnemonic::Rol) {
                        (BinOp::Shl, n, BinOp::Shr, w - n)
                    } else {
                        (BinOp::Shr, n, BinOp::Shl, w - n)
                    };
                    let mut ops = preamble;
                    ops.extend([
                        Op::Bin {
                            dst: t1.clone(),
                            op: a_op,
                            lhs: Value::Reg(dst.clone()),
                            rhs: Value::Const(a_sh),
                        },
                        Op::Bin {
                            dst: t2.clone(),
                            op: b_op,
                            lhs: Value::Reg(dst.clone()),
                            rhs: Value::Const(b_sh),
                        },
                        Op::Bin {
                            dst: dst.clone(),
                            op: BinOp::Or,
                            lhs: Value::Reg(t1),
                            rhs: Value::Reg(t2),
                        },
                    ]);
                    append_rotate_flags(
                        &mut ops,
                        dst.clone(),
                        matches!(mnem, Mnemonic::Rol),
                        width,
                        n,
                    );
                    if let Some(partial) = view {
                        ops.extend(partial_write_ops(partial, Value::Reg(dst)));
                    }
                    return ops;
                } else if instr.op_kind(1) == OpKind::Register {
                    // Rotate by `cl`. x86 variable shifts/rotates always take the
                    // count in CL; use its 32-bit view ECX (identical low bits,
                    // and it canonicalises to a versioned value that connects to
                    // the count's definition -- CL itself is not sub-register
                    // canonicalised and would dangle). Runtime count `n`, so the
                    // rotate is the mask-and-recombine form, masked so `n == 0`
                    // shifts by 0 rather than by `w` (which is C undefined):
                    //   n  = count & (w-1)
                    //   lo = x <first>  n
                    //   hi = x <second> ((w - n) & (w-1))
                    //   dst = lo | hi
                    let mask = w - 1;
                    let cnt = VReg::phys("ecx");
                    let (t0, t1, t2, t3, t4) = (
                        VReg::Temp(41),
                        VReg::Temp(42),
                        VReg::Temp(43),
                        VReg::Temp(44),
                        VReg::Temp(45),
                    );
                    let (first, second) = if matches!(mnem, Mnemonic::Ror) {
                        (BinOp::Shr, BinOp::Shl)
                    } else {
                        (BinOp::Shl, BinOp::Shr)
                    };
                    let mut ops = preamble;
                    ops.extend([
                        Op::Bin {
                            dst: t0.clone(),
                            op: BinOp::And,
                            lhs: Value::Reg(cnt),
                            rhs: Value::Const(mask),
                        },
                        Op::Bin {
                            dst: t1.clone(),
                            op: first,
                            lhs: Value::Reg(dst.clone()),
                            rhs: Value::Reg(t0.clone()),
                        },
                        Op::Bin {
                            dst: t2.clone(),
                            op: BinOp::Sub,
                            lhs: Value::Const(w),
                            rhs: Value::Reg(t0),
                        },
                        Op::Bin {
                            dst: t3.clone(),
                            op: BinOp::And,
                            lhs: Value::Reg(t2),
                            rhs: Value::Const(mask),
                        },
                        Op::Bin {
                            dst: t4.clone(),
                            op: second,
                            lhs: Value::Reg(dst.clone()),
                            rhs: Value::Reg(t3),
                        },
                        Op::Bin {
                            dst: dst.clone(),
                            op: BinOp::Or,
                            lhs: Value::Reg(t1),
                            rhs: Value::Reg(t4),
                        },
                    ]);
                    append_undef_flags(
                        &mut ops,
                        &[Flag::C, Flag::O],
                        "x86 variable-count rotate has count-sensitive CF/OF effects not yet modelled",
                    );
                    if let Some(partial) = view {
                        ops.extend(partial_write_ops(partial, Value::Reg(dst)));
                    }
                    return ops;
                }
            }
            if instr.op_count() == 2 && instr.op_kind(0) == OpKind::Memory {
                let addr = mem_op_of(instr);
                let width = Width::from_bytes(u16::from(addr.size));
                if matches!(width, Width::W8 | Width::W16 | Width::W32 | Width::W64) {
                    if let Some(Value::Const(cnt)) = value_of_operand(instr, 1) {
                        let w = i64::from(width.bits());
                        let n = ((cnt % w) + w) % w;
                        if n == 0 {
                            return vec![Op::Nop];
                        }
                        let (value, first, second, result) = (
                            VReg::Temp(40),
                            VReg::Temp(41),
                            VReg::Temp(42),
                            VReg::Temp(43),
                        );
                        let (first_op, first_shift, second_op, second_shift) =
                            if matches!(mnem, Mnemonic::Rol) {
                                (BinOp::Shl, n, BinOp::Shr, w - n)
                            } else {
                                (BinOp::Shr, n, BinOp::Shl, w - n)
                            };
                        let mut ops = vec![
                            Op::Load {
                                dst: value.clone(),
                                addr: addr.clone(),
                            },
                            Op::Bin {
                                dst: first.clone(),
                                op: first_op,
                                lhs: Value::Reg(value.clone()),
                                rhs: Value::Const(first_shift),
                            },
                            Op::Bin {
                                dst: second.clone(),
                                op: second_op,
                                lhs: Value::Reg(value),
                                rhs: Value::Const(second_shift),
                            },
                            Op::Bin {
                                dst: result.clone(),
                                op: BinOp::Or,
                                lhs: Value::Reg(first),
                                rhs: Value::Reg(second),
                            },
                            Op::Store {
                                addr,
                                src: Value::Reg(result.clone()),
                            },
                        ];
                        append_rotate_flags(
                            &mut ops,
                            result,
                            matches!(mnem, Mnemonic::Rol),
                            width,
                            n,
                        );
                        return ops;
                    }
                }
            }
            vec![Op::Unknown {
                mnemonic: format!("{:?}", mnem).to_ascii_lowercase(),
            }]
        }
        // mul source: unsigned hi:lo = accumulator * source.
        Mnemonic::Mul => wide_mul_ops(instr, false).unwrap_or_else(|| {
            vec![Op::Unknown {
                mnemonic: "mul".into(),
            }]
        }),
        // The single-bit family. `bt` reads the selected bit into CF and stops;
        // `bts`/`btr`/`btc` additionally set, clear, or invert it in the
        // destination. See `bit_ops` for why the flag write is an ordinary op
        // rather than a second intrinsic output.
        Mnemonic::Bt => bit_test_ops(instr, BitTest::Read, bits),
        Mnemonic::Bts => bit_test_ops(instr, BitTest::Set, bits),
        Mnemonic::Btr => bit_test_ops(instr, BitTest::Reset, bits),
        Mnemonic::Btc => bit_test_ops(instr, BitTest::Complement, bits),
        // Pure functions of one operand that C spells exactly, lowered through
        // single-output intrinsics the AST renders as `__builtin_ctz` /
        // `__builtin_popcount` at the encoded width.
        Mnemonic::Tzcnt => count_trailing_zeros_ops(instr),
        Mnemonic::Popcnt => population_count_ops(instr),
        // `rcr reg, 1` — the only rotate-through-carry width this IR can state
        // exactly; see `bit_ops::rotate_carry_right_ops`.
        Mnemonic::Rcr => rotate_carry_right_ops(instr, bits),
        // bswap reg: byte-reverse. Emitted as a typed intrinsic executed by a
        // helper (the byte shuffle needs explicit per-byte widths).
        Mnemonic::Bswap => {
            if instr.op_count() == 1 && instr.op_kind(0) == OpKind::Register {
                let name = reg_name(instr.op_register(0));
                let w = phys_reg_width(&name).unwrap_or(Width::W64);
                if w.bytes() >= 2 {
                    let dst = VReg::phys(name);
                    return vec![Op::Intrinsic {
                        name: "bswap".into(),
                        ins: vec![Value::Reg(dst.clone())],
                        outs: vec![(dst, w)],
                        reads_mem: false,
                        writes_mem: false,
                    }];
                }
            }
            vec![Op::Unknown {
                mnemonic: "bswap".into(),
            }]
        }
        Mnemonic::Lea => {
            if instr.op_count() == 2 && instr.op_kind(0) == OpKind::Register {
                // When the base is RIP we can resolve to an absolute VA.
                if let Some(abs) = rip_relative_addr(instr) {
                    return vec![Op::Assign {
                        dst: VReg::phys(reg_name(instr.op_register(0))),
                        src: Value::Addr(abs),
                    }];
                }
                // Otherwise emit a chain of arithmetic ops computing
                //   dst = base + index*scale + disp
                // using a temp. Only the dst reg and any non-None base/index
                // contribute; the disp and scale are folded in.
                let dst = VReg::phys(reg_name(instr.op_register(0)));
                let base = maybe_reg(instr.memory_base());
                let index = maybe_reg(instr.memory_index());
                let scale = instr.memory_index_scale().max(1);
                let disp = memory_displacement_i64(instr);

                let mut ops: Vec<Op> = Vec::new();
                let tmp = VReg::Temp(0);
                // Seed tmp with base, or zero if no base.
                match base {
                    Some(b) => ops.push(Op::Assign {
                        dst: tmp.clone(),
                        src: Value::Reg(b),
                    }),
                    None => ops.push(Op::Assign {
                        dst: tmp.clone(),
                        src: Value::Const(0),
                    }),
                }
                // Add index*scale.
                if let Some(idx) = index {
                    if scale > 1 {
                        let scaled = VReg::Temp(1);
                        ops.push(Op::Bin {
                            dst: scaled.clone(),
                            op: BinOp::Mul,
                            lhs: Value::Reg(idx),
                            rhs: Value::Const(scale as i64),
                        });
                        ops.push(Op::Bin {
                            dst: tmp.clone(),
                            op: BinOp::Add,
                            lhs: Value::Reg(tmp.clone()),
                            rhs: Value::Reg(scaled),
                        });
                    } else {
                        ops.push(Op::Bin {
                            dst: tmp.clone(),
                            op: BinOp::Add,
                            lhs: Value::Reg(tmp.clone()),
                            rhs: Value::Reg(idx),
                        });
                    }
                }
                // Add disp.
                if disp != 0 {
                    ops.push(Op::Bin {
                        dst: tmp.clone(),
                        op: BinOp::Add,
                        lhs: Value::Reg(tmp.clone()),
                        rhs: Value::Const(disp),
                    });
                }
                // LEA's arithmetic is computed at the ADDRESS size, but the
                // result is written through the DESTINATION register's view —
                // and every other x86 ALU form already models that write
                // (`emit_machine_bin_with_flags` appends the same `ZExt`).
                // Omitting it here made `lea eax,[rdi+1]` a 64-bit addition:
                // at `seed == -1` the sum is 0x1_0000_0000 rather than 0, and
                // a following `shl rdx,32; or rax,rdx` then carried the stray
                // bit straight into the second member of a returned aggregate
                // (`195:gcc:O2:bv195_make_pair`, and the low half of every
                // `bv195_make_quad`/`agr198_make_trio` lane that composes two
                // eightbytes this way).
                let dst_name = reg_name(instr.op_register(0));
                if let Some(view) = partial_gp_view(&dst_name) {
                    ops.extend(partial_write_ops(view, Value::Reg(tmp)));
                } else if zero_extending_gp_view(&dst_name, bits).is_some() {
                    ops.push(Op::ZExt {
                        dst,
                        src: Value::Reg(tmp),
                        from: Width::W32,
                        to: Width::W64,
                    });
                } else {
                    ops.push(Op::Assign {
                        dst,
                        src: Value::Reg(tmp),
                    });
                }
                return ops;
            }
            vec![Op::Unknown {
                mnemonic: "lea".into(),
            }]
        }
        // Packed integer moves are split into explicit dword lanes so later
        // packed comparisons/arithmetic retain their element semantics.
        Mnemonic::Movdqa | Mnemonic::Movdqu => packed_dword_move_ops(instr),
        // Bitwise packed-float moves have the same four 32-bit lane transport
        // as MOVDQA/MOVDQU; later SHUFPS/ANDPS/MOVMSKPS consume those lanes.
        Mnemonic::Movaps | Mnemonic::Movups => packed_dword_move_ops(instr),
        Mnemonic::Movsd => match movs_width(instr, mnem) {
            Some(width) => movs_ops(instr, width, bits),
            None => scalar_move_ops(instr, 8, "movsd"),
        },
        // The binary32 sibling of the MOVSD form above, and — at 307 of the
        // float corpus's instructions — the single most common instruction the
        // lifter did not model. Every `float` spill, reload and argument setup
        // GCC and Clang emit is a MOVSS, so its absence turned all of
        // `172_float_double_widths`, `173_float_int_conversions`,
        // `174_float_compare_classify` and `175_float_matrix_kernel` into
        // bodies of `/* asm: movss */` comments with the values never defined.
        Mnemonic::Movss => scalar_move_ops(instr, 4, "movss"),
        // MOVAPD/MOVUPD transport the same sixteen bytes as MOVAPS/MOVUPS; the
        // only architectural difference is the element type the *processor*
        // assumes, which does not change what moves.
        Mnemonic::Movapd | Mnemonic::Movupd => packed_dword_move_ops(instr),
        // HALF-register memory traffic. Every one of these had no arm anywhere
        // in `src/ir/`, so each fell through to `Op::Unknown` — which carries a
        // mnemonic and nothing else: no operands, no reads, no writes. An
        // unmodelled instruction is therefore not conservatively modelled, it
        // is INVISIBLE to register dataflow, and the value its destination was
        // supposed to receive simply never arrives. Clang `-O0` spills a
        // System V `xmm0:xmm1` aggregate return with a pair of MOVLPDs, so on
        // `197_homogeneous_float_aggregates` the whole returned struct was lost
        // this way. The `pd`/`ps` suffix also made every one of them an
        // unmodelled float producer to `ast::float_gate`, shutting the
        // whole-function float gate on top.
        Mnemonic::Movlpd | Mnemonic::Movlps => packed_qword_half_move_ops(instr, XmmHalf::Low),
        Mnemonic::Movhpd | Mnemonic::Movhps => packed_qword_half_move_ops(instr, XmmHalf::High),
        // The register/register siblings of the two above: `movlhps` writes the
        // destination's HIGH half from the source's low one, `movhlps` the
        // reverse.
        Mnemonic::Movlhps => packed_qword_half_swap_ops(instr, XmmHalf::High),
        Mnemonic::Movhlps => packed_qword_half_swap_ops(instr, XmmHalf::Low),
        // As XORPS: the packed-double spelling of the same bitwise lanes, which
        // is how Clang zeroes an `xmm` before a binary64 accumulation and how
        // both compilers flip a sign bit.
        Mnemonic::Xorpd => packed_dword_binary_ops(instr, BinOp::Xor),
        Mnemonic::Andpd => packed_dword_binary_ops(instr, BinOp::And),
        Mnemonic::Orps | Mnemonic::Orpd => packed_dword_binary_ops(instr, BinOp::Or),
        Mnemonic::Addss => scalar_float_binary_ops(instr, Width::W32, "addss"),
        Mnemonic::Subss => scalar_float_binary_ops(instr, Width::W32, "subss"),
        Mnemonic::Mulss => scalar_float_binary_ops(instr, Width::W32, "mulss"),
        Mnemonic::Divss => scalar_float_binary_ops(instr, Width::W32, "divss"),
        Mnemonic::Addsd => scalar_float_binary_ops(instr, Width::W64, "addsd"),
        Mnemonic::Subsd => scalar_float_binary_ops(instr, Width::W64, "subsd"),
        Mnemonic::Mulsd => scalar_float_binary_ops(instr, Width::W64, "mulsd"),
        Mnemonic::Divsd => scalar_float_binary_ops(instr, Width::W64, "divsd"),
        Mnemonic::Sqrtss => scalar_convert_ops(instr, "sqrtss", 4, Width::W32),
        Mnemonic::Sqrtsd => scalar_convert_ops(instr, "sqrtsd", 8, Width::W64),
        // Float <-> float.
        Mnemonic::Cvtss2sd => scalar_convert_ops(instr, "cvtss2sd", 4, Width::W64),
        Mnemonic::Cvtsd2ss => scalar_convert_ops(instr, "cvtsd2ss", 8, Width::W32),
        // Signed integer -> float. The source width is the encoded operand's,
        // which iced reports even for the register form.
        Mnemonic::Cvtsi2ss => {
            let source_bytes = scalar_convert_source_bytes(instr);
            scalar_convert_ops(
                instr,
                if source_bytes == 8 {
                    "cvtsi2ss.q"
                } else {
                    "cvtsi2ss.l"
                },
                source_bytes,
                Width::W32,
            )
        }
        Mnemonic::Cvtsi2sd => {
            let source_bytes = scalar_convert_source_bytes(instr);
            scalar_convert_ops(
                instr,
                if source_bytes == 8 {
                    "cvtsi2sd.q"
                } else {
                    "cvtsi2sd.l"
                },
                source_bytes,
                Width::W64,
            )
        }
        // Float -> signed integer, truncating toward zero (the `t` forms) and
        // under the current rounding mode (the plain forms; the compilers only
        // emit these for `lrint`-family calls). The DESTINATION width is a
        // general-purpose register's, so it is read from the operand.
        Mnemonic::Cvttss2si => scalar_convert_ops(instr, "cvttss2si", 4, operand_width(instr, 0)),
        Mnemonic::Cvttsd2si => scalar_convert_ops(instr, "cvttsd2si", 8, operand_width(instr, 0)),
        Mnemonic::Cvtss2si => scalar_convert_ops(instr, "cvtss2si", 4, operand_width(instr, 0)),
        Mnemonic::Cvtsd2si => scalar_convert_ops(instr, "cvtsd2si", 8, operand_width(instr, 0)),
        Mnemonic::Ucomiss | Mnemonic::Comiss => {
            scalar_float_compare_ops(instr, Width::W32, "comiss")
        }
        Mnemonic::Ucomisd | Mnemonic::Comisd => {
            scalar_float_compare_ops(instr, Width::W64, "comisd")
        }
        Mnemonic::Cmp => {
            if instr.op_count() == 2 {
                // Memory operands need to be loaded into a temp first so the
                // Cmp can carry a plain Value. We use a pair of dedicated
                // temps (10, 11) to avoid colliding with the final sub-to-%sf
                // temp this branch also emits (VReg::Temp(0)).
                let mut preamble: Vec<Op> = Vec::new();
                let lhs = cmp_operand_as_value(instr, 0, VReg::Temp(10), &mut preamble);
                let rhs = cmp_operand_as_value(instr, 1, VReg::Temp(11), &mut preamble);
                let (Some(lhs), Some(rhs)) = (lhs, rhs) else {
                    return vec![Op::Unknown {
                        mnemonic: "cmp".into(),
                    }];
                };
                let width = operand_width(instr, 0);
                let mut ops = preamble;
                ops.extend(cmp_flag_ops(lhs, rhs, width));
                return ops;
            }
            vec![Op::Unknown {
                mnemonic: "cmp".into(),
            }]
        }
        Mnemonic::Test => {
            if instr.op_count() == 2 {
                let mut preamble: Vec<Op> = Vec::new();
                let lhs = cmp_operand_as_value(instr, 0, VReg::Temp(10), &mut preamble);
                let rhs = cmp_operand_as_value(instr, 1, VReg::Temp(11), &mut preamble);
                let (Some(lhs), Some(rhs)) = (lhs, rhs) else {
                    return vec![Op::Unknown {
                        mnemonic: "test".into(),
                    }];
                };
                // TEST sets ZF/SF/PF from `lhs & rhs`, clears CF/OF, and leaves
                // AF undefined. Materialise the AND once; PF remains explicit
                // poison until its low-byte parity expression is implemented.
                let tmp = VReg::Temp(0);
                let width = operand_width(instr, 0);
                let mut ops = preamble;
                ops.push(Op::Bin {
                    dst: tmp.clone(),
                    op: BinOp::And,
                    lhs,
                    rhs,
                });
                // TEST observes the encoded byte/word/dword/qword, not the
                // canonical parent that may carry unrelated high bits. Use the
                // same width-normalization boundary as every arithmetic flag
                // producer so ZF and SF describe one machine result.
                zero_sign_flags(Value::Reg(tmp), width, 1, &mut ops);
                ops.extend([
                    // TEST clears CF and OF. Materialising those architectural
                    // effects prevents a later composite condition from reading
                    // stale values.
                    Op::Assign {
                        dst: VReg::Flag(Flag::C),
                        src: Value::Const(0),
                    },
                    Op::Assign {
                        dst: VReg::Flag(Flag::O),
                        src: Value::Const(0),
                    },
                    undef_flag(
                        Flag::P,
                        "x86 TEST defines PF, but its exact low-byte parity expression is not modelled",
                    ),
                    undef_flag(Flag::A, "x86 TEST leaves AF architecturally undefined"),
                ]);
                return ops;
            }
            vec![Op::Unknown {
                mnemonic: "test".into(),
            }]
        }
        _ if setcc_condition_for(mnem).is_some() => {
            let condition = setcc_condition_for(mnem).expect("checked above");
            if instr.op_count() == 1 {
                let (mut ops, predicate) = materialize_condition(&condition);
                match instr.op_kind(0) {
                    OpKind::Register => {
                        let dst_name = reg_name(instr.op_register(0));
                        let value = if condition.inverted {
                            let logical_not = VReg::Temp(22);
                            ops.push(Op::Cmp {
                                dst: logical_not.clone(),
                                op: CmpOp::Eq,
                                lhs: Value::Reg(predicate),
                                rhs: Value::Const(0),
                            });
                            Value::Reg(logical_not)
                        } else {
                            Value::Reg(predicate)
                        };
                        // SETcc always writes an 8-bit view.  Model its real
                        // read-modify-write effect on the canonical parent so a
                        // following MOVZX reads this definition, not stale RAX.
                        if let Some(view) = partial_gp_view(&dst_name) {
                            ops.extend(partial_write_ops(view, value));
                        } else {
                            ops.push(Op::Assign {
                                dst: VReg::phys(dst_name),
                                src: value,
                            });
                        }
                        return ops;
                    }
                    OpKind::Memory => {
                        if condition.inverted {
                            let tmp = VReg::Temp(0);
                            ops.extend([
                                Op::Cmp {
                                    dst: tmp.clone(),
                                    op: CmpOp::Eq,
                                    lhs: Value::Reg(predicate),
                                    rhs: Value::Const(0),
                                },
                                Op::Store {
                                    addr: mem_op_of(instr),
                                    src: Value::Reg(tmp),
                                },
                            ]);
                            return ops;
                        }
                        ops.push(Op::Store {
                            addr: mem_op_of(instr),
                            src: Value::Reg(predicate),
                        });
                        return ops;
                    }
                    _ => {}
                }
            }
            vec![Op::Unknown {
                mnemonic: format!("{:?}", mnem).to_ascii_lowercase(),
            }]
        }
        _ if cmovcc_condition_for(mnem).is_some() => {
            let condition = cmovcc_condition_for(mnem).expect("checked above");
            if instr.op_count() == 2 && instr.op_kind(0) == OpKind::Register {
                let dst = VReg::phys(reg_name(instr.op_register(0)));
                let (mut ops, predicate) = materialize_condition(&condition);
                let cond = if condition.inverted {
                    let tmp = VReg::Temp(1);
                    ops.push(Op::Cmp {
                        dst: tmp.clone(),
                        op: CmpOp::Eq,
                        lhs: Value::Reg(predicate),
                        rhs: Value::Const(0),
                    });
                    tmp
                } else {
                    predicate
                };
                // `dst = cond ? src : dst` — a three-input SELECT, not a
                // conditional def. Stating the false arm explicitly is what keeps the
                // instruction that produced the destination's prior value alive; with
                // `Op::CondAssign` (destination = pure def) dataflow could not see
                // that reader, dead-code elimination dropped the producer, and the
                // emitted C conditionally assigned a variable nothing else wrote.
                // gcc -O0 compiles `abs(a)` to exactly this pair (`neg`, `cmovs`).
                let width = phys_reg_width(&reg_name(instr.op_register(0))).unwrap_or(Width::W64);
                match instr.op_kind(1) {
                    OpKind::Register => {
                        ops.push(Op::Ite {
                            cond,
                            t: Value::Reg(VReg::phys(reg_name(instr.op_register(1)))),
                            e: Value::Reg(dst.clone()),
                            dst,
                            width,
                        });
                        return ops;
                    }
                    OpKind::Memory => {
                        let tmp = VReg::Temp(0);
                        ops.push(Op::Load {
                            dst: tmp.clone(),
                            addr: mem_op_of(instr),
                        });
                        ops.push(Op::Ite {
                            cond,
                            t: Value::Reg(tmp),
                            e: Value::Reg(dst.clone()),
                            dst,
                            width,
                        });
                        return ops;
                    }
                    _ => {}
                }
            }
            vec![Op::Unknown {
                mnemonic: format!("{:?}", mnem).to_ascii_lowercase(),
            }]
        }
        Mnemonic::Not => {
            if instr.op_count() == 1 && instr.op_kind(0) == OpKind::Register {
                let name = reg_name(instr.op_register(0));
                // A bit-preserving partial destination (`sil`, `ah`, `ax`, ...)
                // is a read-modify-write of its 64-bit PARENT, not a write to a
                // register of its own -- for exactly the reason
                // [`partial_alu_ops`] exists, and the unary forms never got it.
                //
                // [`regview::ssa_parent`] canonicalises the parent and the
                // ZERO-EXTENDING 32-bit views and nothing else, because a byte
                // write preserves the bits above it and so is not a definition
                // of the whole register. That makes `sil` an SSA name in its own
                // right: `not %sil` defined it, and every later reader of
                // `esi`/`rsi` -- which DO canonicalise together -- saw the value
                // from before the complement. The instruction was not
                // mis-modelled, it was disconnected.
                //
                // `165_bitstream_reader:clang:O2` is that, and it is silent
                // wrong code rather than a decline. clang spells
                // `shift = 7 - (at & 7)` as
                // `mov %r10d,%esi ; not %sil ; and $0x7,%sil`, and the `and` --
                // which does take the read-modify-write path -- read `rsi` and
                // picked up the un-complemented copy. We emitted the bit index
                // as `at & 7` where the source says `7 - (at & 7)`: a different
                // bit, at every position, in both poke loops, in C that
                // compiles and runs.
                //
                // NOT touches no flags at all, which is what makes this the
                // three-op form of `partial_alu_ops`: read the view, complement
                // it, write it back.
                //
                // `neg` HAS THE IDENTICAL DEFECT AND IS DELIBERATELY NOT FIXED
                // HERE. Its arm below writes `VReg::phys(reg_name(..))` the same
                // way, so `neg %al` disconnects the same way. Two reasons it is
                // not folded in: it defines SF/ZF/CF/OF from the result, so it
                // needs the flag machinery rather than this shape; and it is
                // unmeasurable from the corpus we have -- all 40 byte-form `neg`
                // in `tests/decompiler_fixtures/build` are inside unbaselined
                // Rust `std`/`gimli` symbols, so nothing would prove the fix
                // right or wrong. Whoever has a failing lane for it should take
                // it; the mechanism is entirely the one described above.
                if let Some(view) = partial_gp_view(&name) {
                    let acc = VReg::Temp(0);
                    let mut ops = read_view_ops(view, acc.clone());
                    ops.push(Op::Un {
                        dst: acc.clone(),
                        op: UnOp::Not,
                        src: Value::Reg(acc.clone()),
                    });
                    ops.extend(partial_write_ops(view, Value::Reg(acc)));
                    return ops;
                }
                let r = VReg::phys(name);
                return vec![Op::Un {
                    dst: r.clone(),
                    op: UnOp::Not,
                    src: Value::Reg(r),
                }];
            }
            vec![Op::Unknown {
                mnemonic: "not".into(),
            }]
        }
        Mnemonic::Neg => {
            if instr.op_count() == 1 && instr.op_kind(0) == OpKind::Register {
                let r = VReg::phys(reg_name(instr.op_register(0)));
                // `neg` sets SF from the sign of the result and ZF from whether it is
                // zero. Leaving them undefined made a following `cmovs`/`js` read
                // either nothing or a stale flag from an unrelated comparison — the
                // `arith:signs` case, where the emitted C tested `sf` several
                // statements before anything assigned it.
                //
                // The flags read a TEMP holding the negation, sign-extended from the
                // OPERAND's width. Both halves of that matter:
                //
                // * Not the destination register — a 32-bit write zero-extends into
                //   the 64-bit parent, so reading `%edx` back would make the result
                //   unconditionally non-negative and SF permanently false.
                // * Sign-extended from the operand width, because `neg %edx` is a
                //   32-BIT negation. Taking the temp at face value computes
                //   `-(u32)x` in 64 bits: for `x = -1` that is -4294967295 (negative,
                //   so SF set) where the machine produces 1 (positive, SF clear).
                //   `abs(-1)` then came out as 4294967295 and the function returned
                //   -1 instead of 1 — a wrong answer from a right-looking `if`.
                //
                // CF is source!=0 and OF is source==INT_MIN at the operand width;
                // both are materialised exactly so every Jcc family sees the same
                // producer state.
                let t = VReg::Temp(0);
                let w = phys_reg_width(&reg_name(instr.op_register(0))).unwrap_or(Width::W64);
                let mut ops = vec![Op::Un {
                    dst: t.clone(),
                    op: UnOp::Neg,
                    src: Value::Reg(r.clone()),
                }];
                // The value the flags describe: the result read at the operand's
                // width. At 64 bits the temp already is that value.
                let flagged = if w.bits() < 64 {
                    let sx = VReg::Temp(1);
                    ops.push(Op::SExt {
                        dst: sx.clone(),
                        src: Value::Reg(t.clone()),
                        from: w,
                        to: Width::W64,
                    });
                    sx
                } else {
                    t.clone()
                };
                let signed_original =
                    signed_cmp_value(Value::Reg(r.clone()), w, VReg::Temp(2), &mut ops);
                ops.extend([
                    Op::Cmp {
                        dst: VReg::Flag(Flag::Z),
                        op: CmpOp::Eq,
                        lhs: Value::Reg(flagged.clone()),
                        rhs: Value::Const(0),
                    },
                    Op::Cmp {
                        dst: VReg::Flag(Flag::S),
                        op: CmpOp::Slt,
                        lhs: Value::Reg(flagged),
                        rhs: Value::Const(0),
                    },
                    Op::Cmp {
                        dst: VReg::Flag(Flag::C),
                        op: CmpOp::Ne,
                        lhs: Value::Reg(r.clone()),
                        rhs: Value::Const(0),
                    },
                    Op::Cmp {
                        dst: VReg::Flag(Flag::O),
                        op: CmpOp::Eq,
                        lhs: signed_original,
                        rhs: Value::Const(if w.bits() == 64 {
                            i64::MIN
                        } else {
                            -(1_i64 << (w.bits() - 1))
                        }),
                    },
                    undef_flag(
                        Flag::P,
                        "x86 NEG defines PF, but its exact low-byte parity expression is not modelled",
                    ),
                    undef_flag(
                        Flag::A,
                        "x86 NEG defines AF, but its exact low-bit borrow expression is not modelled",
                    ),
                    Op::Assign {
                        dst: r,
                        src: Value::Reg(t),
                    },
                ]);
                return ops;
            }
            vec![Op::Unknown {
                mnemonic: "neg".into(),
            }]
        }
        Mnemonic::Div | Mnemonic::Idiv => wide_div_ops(instr, mnem == Mnemonic::Idiv)
            .unwrap_or_else(|| {
                vec![Op::Unknown {
                    mnemonic: format!("{:?}", mnem).to_ascii_lowercase(),
                }]
            }),
        Mnemonic::Adc => adc_ops(instr),
        Mnemonic::Sbb => sbb_ops(instr),
        Mnemonic::Shrd => double_shift_ops(instr, true),
        Mnemonic::Shld => double_shift_ops(instr, false),
        Mnemonic::Bsr => bit_scan_ops(instr, false),
        Mnemonic::Bsf => bit_scan_ops(instr, true),
        Mnemonic::Pxor => packed_dword_binary_ops(instr, BinOp::Xor),
        Mnemonic::Pand => packed_dword_binary_ops(instr, BinOp::And),
        Mnemonic::Pandn => packed_dword_and_not_ops(instr),
        Mnemonic::Por => packed_dword_binary_ops(instr, BinOp::Or),
        Mnemonic::Paddd => packed_dword_binary_ops(instr, BinOp::Add),
        Mnemonic::Psubd => packed_dword_binary_ops(instr, BinOp::Sub),
        Mnemonic::Pslld => packed_dword_immediate_shift_left_ops(instr),
        Mnemonic::Psrld => packed_dword_immediate_logical_shift_right_ops(instr),
        Mnemonic::Psrad => packed_dword_immediate_arithmetic_shift_right_ops(instr),
        Mnemonic::Punpckldq => packed_dword_unpack_low_ops(instr),
        Mnemonic::Punpcklqdq => packed_qword_unpack_low_ops(instr),
        Mnemonic::Paddq => packed_qword_binary_ops(instr, BinOp::Add, "paddq"),
        Mnemonic::Psubq => packed_qword_binary_ops(instr, BinOp::Sub, "psubq"),
        Mnemonic::Pcmpeqd => packed_dword_compare_equal_ops(instr),
        Mnemonic::Pcmpgtd => packed_dword_compare_greater_ops(instr),
        Mnemonic::Pshufd => packed_dword_shuffle_ops(instr),
        // The SSE string-primitive family; see `packed_string` for which of
        // these are lifted exactly and which declare their register effect
        // only, and why the line falls where it does.
        Mnemonic::Pcmpeqb | Mnemonic::Pcmpgtb => packed_byte_compare_ops(instr),
        Mnemonic::Punpcklbw => packed_byte_unpack_low_ops(instr),
        Mnemonic::Pmovmskb => packed_byte_sign_mask_ops(instr, bits),
        Mnemonic::Packssdw => packed_dword_saturating_pack_ops(instr),
        Mnemonic::Pshufb => packed_byte_shuffle_ops(instr),
        Mnemonic::Punpckhqdq => packed_qword_unpack_high_ops(instr),
        Mnemonic::Shufpd => packed_double_shuffle_ops(instr),
        Mnemonic::Pmuludq => packed_unsigned_dword_multiply_ops(instr),
        Mnemonic::Psrlq => packed_qword_immediate_logical_shift_right_ops(instr),
        Mnemonic::Pshuflw => packed_word_shuffle_ops(instr, false),
        Mnemonic::Pshufhw => packed_word_shuffle_ops(instr, true),
        Mnemonic::Punpcklwd => packed_word_unpack_low_ops(instr),
        Mnemonic::Pinsrw => packed_insert_ops(instr, 2),
        Mnemonic::Pinsrd => packed_insert_ops(instr, 4),
        Mnemonic::Pinsrq => packed_insert_ops(instr, 8),
        Mnemonic::Movd => movd_ops(instr, bits),
        Mnemonic::Movq => packed_qword_move_ops(instr),
        Mnemonic::Pextrw => packed_word_extract_ops(instr),
        Mnemonic::Xorps => xorps_ops(instr),
        Mnemonic::Andps => packed_dword_binary_ops(instr, BinOp::And),
        Mnemonic::Shufps => packed_float_shuffle_ops(instr),
        Mnemonic::Movmskps => packed_float_sign_mask_ops(instr),
        // The AES round instructions. Their value is NOT modelled — see
        // `declare_xmm_register_effect_ops` for why declaring the register
        // effect is the whole point and modelling the round function is not.
        // Only `aesenc` is present in the committed corpus (222 of the silent
        // register writes); the other three are the identical
        // `dst = f(dst, src)` shape and are covered so a corpus that does
        // contain them is not a fresh census entry.
        Mnemonic::Aesenc | Mnemonic::Aesenclast | Mnemonic::Aesdec | Mnemonic::Aesdeclast => {
            declare_xmm_register_effect_ops(instr)
        }
        Mnemonic::Push => push_ops(instr, bits),
        Mnemonic::Pop => pop_ops(instr, bits),
        Mnemonic::Stosb | Mnemonic::Stosw | Mnemonic::Stosd | Mnemonic::Stosq => {
            stos_ops(instr, mnem, bits)
        }
        // The byte/word/quadword string moves. `Movsd` is dispatched with the
        // SSE scalar move above because the two share a mnemonic; the other
        // three do not, so they arrive here.
        Mnemonic::Movsb | Mnemonic::Movsw | Mnemonic::Movsq => match movs_width(instr, mnem) {
            Some(width) => movs_ops(instr, width, bits),
            None => vec![Op::Unknown {
                mnemonic: format!("{mnem:?}").to_ascii_lowercase(),
            }],
        },
        Mnemonic::Cld => vec![Op::Assign {
            dst: VReg::Flag(Flag::D),
            src: Value::Const(0),
        }],
        Mnemonic::Std => vec![Op::Assign {
            dst: VReg::Flag(Flag::D),
            src: Value::Const(1),
        }],
        Mnemonic::Cmpxchg => cmpxchg_ops(instr, bits),
        Mnemonic::Inc => {
            if instr.op_count() == 1 {
                match instr.op_kind(0) {
                    OpKind::Register => {
                        let name = reg_name(instr.op_register(0));
                        if let Some(view) = partial_gp_view(&name) {
                            let value = VReg::Temp(0);
                            let mut ops = read_view_ops(view, value.clone());
                            ops.extend(emit_inc_dec_with_flags(
                                value.clone(),
                                true,
                                Width(view.width),
                            ));
                            ops.extend(partial_write_ops(view, Value::Reg(value)));
                            return ops;
                        }
                        return emit_inc_dec_with_flags(
                            VReg::phys(name),
                            true,
                            operand_width(instr, 0),
                        );
                    }
                    OpKind::Memory => {
                        let addr = mem_op_of(instr);
                        let tmp = VReg::Temp(0);
                        let mut ops = vec![Op::Load {
                            dst: tmp.clone(),
                            addr: addr.clone(),
                        }];
                        ops.extend(emit_inc_dec_with_flags(
                            tmp.clone(),
                            true,
                            operand_width(instr, 0),
                        ));
                        ops.push(Op::Store {
                            addr,
                            src: Value::Reg(tmp),
                        });
                        return ops;
                    }
                    _ => {}
                }
            }
            vec![Op::Unknown {
                mnemonic: "inc".into(),
            }]
        }
        Mnemonic::Dec => {
            if instr.op_count() == 1 {
                match instr.op_kind(0) {
                    OpKind::Register => {
                        let name = reg_name(instr.op_register(0));
                        if let Some(view) = partial_gp_view(&name) {
                            let value = VReg::Temp(0);
                            let mut ops = read_view_ops(view, value.clone());
                            ops.extend(emit_inc_dec_with_flags(
                                value.clone(),
                                false,
                                Width(view.width),
                            ));
                            ops.extend(partial_write_ops(view, Value::Reg(value)));
                            return ops;
                        }
                        return emit_inc_dec_with_flags(
                            VReg::phys(name),
                            false,
                            operand_width(instr, 0),
                        );
                    }
                    OpKind::Memory => {
                        let addr = mem_op_of(instr);
                        let tmp = VReg::Temp(0);
                        let mut ops = vec![Op::Load {
                            dst: tmp.clone(),
                            addr: addr.clone(),
                        }];
                        ops.extend(emit_inc_dec_with_flags(
                            tmp.clone(),
                            false,
                            operand_width(instr, 0),
                        ));
                        ops.push(Op::Store {
                            addr,
                            src: Value::Reg(tmp),
                        });
                        return ops;
                    }
                    _ => {}
                }
            }
            vec![Op::Unknown {
                mnemonic: "dec".into(),
            }]
        }
        Mnemonic::Xadd => {
            if instr.op_count() == 2 && instr.op_kind(1) == OpKind::Register {
                let src = VReg::phys(reg_name(instr.op_register(1)));
                match instr.op_kind(0) {
                    OpKind::Register => {
                        let dst = VReg::phys(reg_name(instr.op_register(0)));
                        let old = VReg::Temp(0);
                        let mut ops = vec![Op::Assign {
                            dst: old.clone(),
                            src: Value::Reg(dst.clone()),
                        }];
                        ops.extend(emit_add_with_flags(
                            dst,
                            Value::Reg(src.clone()),
                            operand_width(instr, 0),
                        ));
                        ops.push(Op::Assign {
                            dst: src,
                            src: Value::Reg(old),
                        });
                        return ops;
                    }
                    OpKind::Memory => {
                        let addr = mem_op_of(instr);
                        let old = VReg::Temp(0);
                        let sum = VReg::Temp(1);
                        let mut ops = vec![
                            Op::Load {
                                dst: old.clone(),
                                addr: addr.clone(),
                            },
                            Op::Assign {
                                dst: sum.clone(),
                                src: Value::Reg(old.clone()),
                            },
                        ];
                        ops.extend(emit_add_with_flags(
                            sum.clone(),
                            Value::Reg(src.clone()),
                            operand_width(instr, 0),
                        ));
                        ops.extend([
                            Op::Store {
                                addr,
                                src: Value::Reg(sum),
                            },
                            Op::Assign {
                                dst: src,
                                src: Value::Reg(old),
                            },
                        ]);
                        return ops;
                    }
                    _ => {}
                }
            }
            vec![Op::Unknown {
                mnemonic: "xadd".into(),
            }]
        }
        Mnemonic::Xchg => {
            if instr.op_count() == 2 {
                match (instr.op_kind(0), instr.op_kind(1)) {
                    (OpKind::Register, OpKind::Register) => {
                        let left = VReg::phys(reg_name(instr.op_register(0)));
                        let right = VReg::phys(reg_name(instr.op_register(1)));
                        let tmp = VReg::Temp(0);
                        return vec![
                            Op::Assign {
                                dst: tmp.clone(),
                                src: Value::Reg(left.clone()),
                            },
                            Op::Assign {
                                dst: left,
                                src: Value::Reg(right.clone()),
                            },
                            Op::Assign {
                                dst: right,
                                src: Value::Reg(tmp),
                            },
                        ];
                    }
                    (OpKind::Memory, OpKind::Register) => {
                        let addr = mem_op_of(instr);
                        let reg = VReg::phys(reg_name(instr.op_register(1)));
                        let tmp = VReg::Temp(0);
                        return vec![
                            Op::Load {
                                dst: tmp.clone(),
                                addr: addr.clone(),
                            },
                            Op::Store {
                                addr,
                                src: Value::Reg(reg.clone()),
                            },
                            Op::Assign {
                                dst: reg,
                                src: Value::Reg(tmp),
                            },
                        ];
                    }
                    (OpKind::Register, OpKind::Memory) => {
                        let reg = VReg::phys(reg_name(instr.op_register(0)));
                        let addr = mem_op_of(instr);
                        let tmp = VReg::Temp(0);
                        return vec![
                            Op::Load {
                                dst: tmp.clone(),
                                addr: addr.clone(),
                            },
                            Op::Store {
                                addr,
                                src: Value::Reg(reg.clone()),
                            },
                            Op::Assign {
                                dst: reg,
                                src: Value::Reg(tmp),
                            },
                        ];
                    }
                    _ => {}
                }
            }
            vec![Op::Unknown {
                mnemonic: "xchg".into(),
            }]
        }
        Mnemonic::Leave => {
            // `leave` ≡ `mov rsp, rbp ; pop rbp` on x86-64 (or esp/ebp on 32-bit).
            let (sp, bp) = if bits == 64 {
                (VReg::phys("rsp"), VReg::phys("rbp"))
            } else {
                (VReg::phys("esp"), VReg::phys("ebp"))
            };
            let width: u8 = if bits == 64 { 8 } else { 4 };
            vec![
                Op::Assign {
                    dst: sp.clone(),
                    src: Value::Reg(bp.clone()),
                },
                Op::Load {
                    dst: bp,
                    addr: MemOp {
                        base: Some(sp.clone()),
                        index: None,
                        scale: 0,
                        disp: 0,
                        size: width,
                        segment: None,
                        endian: Endian::Little,
                    },
                },
                Op::Bin {
                    dst: sp.clone(),
                    op: BinOp::Add,
                    lhs: Value::Reg(sp),
                    rhs: Value::Const(width as i64),
                },
            ]
        }
        Mnemonic::Ret | Mnemonic::Retf => vec![Op::Return],
        Mnemonic::Jmp => match instr.op_kind(0) {
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
                vec![Op::Jump {
                    target: instr.near_branch_target(),
                }]
            }
            OpKind::Register => vec![Op::IndirectJump {
                target: Value::Reg(VReg::phys(reg_name(instr.op_register(0)))),
                index: None,
            }],
            OpKind::Memory => {
                // The memory operand contains the destination pointer; its
                // address is not itself the jump target. Preserve that
                // dereference explicitly so execution and downstream analyses
                // follow the loaded code address rather than the import slot.
                let target = VReg::Temp(0);
                vec![
                    Op::Load {
                        dst: target.clone(),
                        addr: mem_op_of(instr),
                    },
                    Op::IndirectJump {
                        target: Value::Reg(target),
                        index: None,
                    },
                ]
            }
            _ => vec![Op::Unknown {
                mnemonic: "jmp".into(),
            }],
        },
        Mnemonic::Call => match instr.op_kind(0) {
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
                vec![Op::Call {
                    target: CallTarget::Direct(instr.near_branch_target()),
                    effects: None,
                }]
            }
            OpKind::Register => vec![Op::Call {
                target: CallTarget::Indirect(Value::Reg(VReg::phys(reg_name(
                    instr.op_register(0),
                )))),
                effects: None,
            }],
            OpKind::Memory => {
                // The memory operand holds the destination pointer; its
                // effective address is not the callee. This used to lift to
                // `Indirect(Addr(memory_displacement64()))`, which named the
                // DISPLACEMENT as a resolved target and dropped base, index and
                // scale entirely: `call *(%rcx,%rax,8)` became a confident call
                // to address zero, and `call *[rip+got]` named the import slot
                // rather than the imported function. Nothing downstream could
                // tell that fiction from a real direct call — the dispatch
                // table's identity was already gone — and because
                // `Indirect(Addr(..))` reads no register, DCE saw the index
                // arithmetic as dead and deleted the lookup too.
                //
                // Mirror the `jmp *[mem]` path exactly: materialize the
                // dereference, then transfer through the loaded value. That
                // keeps every operand component in a real `Load`, which is what
                // xrefs, memory SSA, and the relocation-proven function-table
                // recovery all read the dispatch out of.
                let target = VReg::Temp(0);
                vec![
                    Op::Load {
                        dst: target.clone(),
                        addr: mem_op_of(instr),
                    },
                    Op::Call {
                        target: CallTarget::Indirect(Value::Reg(target)),
                        effects: None,
                    },
                ]
            }
            _ => vec![Op::Unknown {
                mnemonic: "call".into(),
            }],
        },
        _ => {
            // Conditional jumps
            if let Some(condition) =
                condition_suffix(mnem, "j").and_then(|s| condition_for_suffix(&s))
            {
                match instr.op_kind(0) {
                    OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
                        let (mut ops, predicate) = materialize_condition(&condition);
                        let (predicate, inverted) = if condition.inverted {
                            let logical_not = VReg::Temp(22);
                            ops.push(Op::Cmp {
                                dst: logical_not.clone(),
                                op: CmpOp::Eq,
                                lhs: Value::Reg(predicate),
                                rhs: Value::Const(0),
                            });
                            (logical_not, false)
                        } else {
                            (predicate, false)
                        };
                        ops.push(Op::CondJump {
                            cond: predicate,
                            target: instr.near_branch_target(),
                            inverted,
                        });
                        return ops;
                    }
                    _ => {}
                }
            }
            vec![Op::Unknown {
                mnemonic: format!("{:?}", mnem).to_ascii_lowercase(),
            }]
        }
    }
}

/// Lift a byte window of x86 / x86-64 machine code into LLIR instructions.
/// Decoding stops on the first invalid instruction.
pub fn lift_bytes(bytes: &[u8], start_va: u64, bits: u32) -> Vec<LlirInstr> {
    // x87 is a register STACK, so which storage `%st(1)` names depends on the
    // depth at that program point — a fact no per-instruction lifter can know.
    // A caller holding only raw bytes has no CFG to consult, so the depths are
    // resolved from the branch targets inside the window itself; `lift_function`
    // has the recovered basic blocks and supplies a whole-function answer.
    let depths = crate::ir::x87::plan_window(bytes, start_va, bits);
    lift_bytes_with_x87(bytes, start_va, bits, depths.as_ref())
}

/// [`lift_bytes`], with the x87 stack depths resolved by the caller.
///
/// `None` means "no proven depths": every x87 instruction is then lowered as a
/// conservative opaque that declares its memory footprint, rather than as an
/// operand-free [`Op::Unknown`] that declares nothing. That distinction matters
/// — an `fstp` whose store is invisible lets a later reload of the same slot
/// resolve to a stale value.
pub(crate) fn lift_bytes_with_x87(
    bytes: &[u8],
    start_va: u64,
    bits: u32,
    depths: Option<&crate::ir::x87::Depths>,
) -> Vec<LlirInstr> {
    let mut out = Vec::new();
    let mut decoder = Decoder::new(bits, bytes, DecoderOptions::NONE);
    decoder.set_ip(start_va);
    while decoder.can_decode() {
        let instr = decoder.decode();
        if instr.is_invalid() {
            break;
        }
        let va = instr.ip();
        let ops = if crate::ir::x87::is_x87(instr.mnemonic()) {
            depths
                .and_then(|depths| depths.state_at(va))
                .and_then(|state| crate::ir::x87::lift_instruction(&instr, state))
                .unwrap_or_else(|| {
                    vec![Op::opaque(format!(
                        "x87.{}",
                        format!("{:?}", instr.mnemonic()).to_ascii_lowercase()
                    ))]
                })
        } else {
            lift_one(&instr, bits)
        };
        for op in ops {
            out.push(LlirInstr { va, op });
        }
    }
    out
}

// -- silence unused-warning on reg_size until a future pass consumes it -------
#[allow(dead_code)]
fn _keep_reg_size() {
    let _ = reg_size(Register::RAX);
}

#[cfg(test)]
mod tests {

    use super::*;

    fn lift64(bytes: &[u8]) -> Vec<LlirInstr> {
        lift_bytes(bytes, 0x1000, 64)
    }

    /// `lift64` without the whole-register views [`synchronise_xmm_views`]
    /// appends after a lane write.
    ///
    /// Those are a separate contract — that the scalar and lane spellings of an
    /// XMM register stay interchangeable — and they are asserted on their own in
    /// `a_lane_write_also_defines_the_whole_register_view`. A packed test is
    /// about what the LANES hold, so scoping the sync out keeps its op list
    /// about the instruction under test instead of restating a global rule at
    /// every call site.
    fn lift64_lanes(bytes: &[u8]) -> Vec<LlirInstr> {
        let lifted = lift64(bytes);
        // Which registers this instruction wrote lanes of; the whole-register
        // definition appended for those is the sync, whichever form it took.
        let lane_written: std::collections::BTreeSet<String> = lifted
            .iter()
            .filter_map(
                |instruction| match crate::ir::use_def::def_uses(&instruction.op).0 {
                    Some(VReg::Phys(name)) => name
                        .split_once("_d")
                        .map(|(register, _)| register.to_string()),
                    _ => None,
                },
            )
            .collect();
        lifted
            .into_iter()
            .filter(|instruction| {
                !matches!(
                    crate::ir::use_def::def_uses(&instruction.op).0,
                    Some(VReg::Phys(name)) if lane_written.contains(&name)
                )
            })
            .collect()
    }

    #[test]
    fn nop_lifts_to_nop() {
        let ops = lift64(&[0x90]);
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].op, Op::Nop);
        assert_eq!(ops[0].va, 0x1000);
    }

    /// Every register form gcc actually emits a `__x86.get_pc_thunk.*` for.
    /// Encodings assembled with `as --32` (`mov (%esp),%REG ; ret`), not
    /// hand-derived from the modrm tables.
    #[test]
    fn pc_thunk_bodies_name_their_destination_register() {
        for (bytes, reg) in [
            ([0x8bu8, 0x04, 0x24, 0xc3], "eax"),
            ([0x8b, 0x0c, 0x24, 0xc3], "ecx"),
            ([0x8b, 0x14, 0x24, 0xc3], "edx"),
            ([0x8b, 0x1c, 0x24, 0xc3], "ebx"),
            ([0x8b, 0x2c, 0x24, 0xc3], "ebp"),
            ([0x8b, 0x34, 0x24, 0xc3], "esi"),
            ([0x8b, 0x3c, 0x24, 0xc3], "edi"),
        ] {
            assert_eq!(
                pc_thunk_register(&bytes),
                Some(reg),
                "{bytes:02x?} is `mov (%esp),%{reg} ; ret`"
            );
        }
        // Trailing padding after the `ret` is normal (gcc aligns the next
        // symbol), so a longer window must still match.
        assert_eq!(
            pc_thunk_register(&[0x8b, 0x1c, 0x24, 0xc3, 0x66, 0x90]),
            Some("ebx")
        );
    }

    /// `shr %eax,$8` in 32-BIT mode must still state the 32-bit read explicitly.
    /// The IR value is 64 bits wide whatever the target register is, so without
    /// the narrowing a negative value's sign-extension bits shift down into the
    /// low word. Encoding from `as --32` (`shr $8,%eax` = `c1 e8 08`).
    #[test]
    fn a_thirty_two_bit_logical_shift_narrows_before_shifting() {
        let ops = lift_bytes(&[0xc1, 0xe8, 0x08], 0x1000, 32);
        let narrowing = ops.iter().position(|instruction| {
            matches!(
                &instruction.op,
                Op::ZExt {
                    dst: VReg::Phys(dst),
                    from: Width::W32,
                    to: Width::W64,
                    ..
                } if dst == "eax"
            )
        });
        let shift = ops.iter().position(|instruction| {
            matches!(
                &instruction.op,
                Op::Bin {
                    op: BinOp::Shr,
                    dst: VReg::Phys(dst),
                    ..
                } if dst == "eax"
            )
        });
        let (Some(narrowing), Some(shift)) = (narrowing, shift) else {
            panic!("expected a zero-extension before the shift, got {ops:#?}");
        };
        assert!(
            narrowing < shift,
            "the narrowing must precede the shift: {ops:#?}"
        );
    }

    /// `sar` replicates bit 31, so its narrowing is a SIGN extension.
    /// `sar $8,%eax` = `c1 f8 08`.
    #[test]
    fn a_thirty_two_bit_arithmetic_shift_sign_extends_before_shifting() {
        let ops = lift_bytes(&[0xc1, 0xf8, 0x08], 0x1000, 32);
        assert!(
            ops.iter().any(|instruction| matches!(
                &instruction.op,
                Op::SExt {
                    dst: VReg::Phys(dst),
                    from: Width::W32,
                    to: Width::W64,
                    ..
                } if dst == "eax"
            )),
            "expected a sign-extension before the arithmetic shift, got {ops:#?}"
        );
    }

    #[test]
    fn non_thunk_bodies_are_not_mistaken_for_one() {
        // `mov (%esp),%esp` — architecturally the same load, but not the idiom,
        // and rewriting it would silently redefine the stack pointer.
        assert_eq!(pc_thunk_register(&[0x8b, 0x24, 0x24, 0xc3]), None);
        // `mov (%eax),%eax ; ret` — a real one-instruction accessor.
        assert_eq!(pc_thunk_register(&[0x8b, 0x00, 0xc3]), None);
        // `mov 0x4(%esp),%eax ; ret` — reads an argument, not the return address.
        assert_eq!(pc_thunk_register(&[0x8b, 0x44, 0x24, 0x04]), None);
        // A load that does not return immediately is some other function.
        assert_eq!(pc_thunk_register(&[0x8b, 0x1c, 0x24, 0x90]), None);
        assert_eq!(pc_thunk_register(&[0x8b, 0x1c, 0x24]), None);
        assert_eq!(pc_thunk_register(&[]), None);
    }

    // ----------------------------------------------------------------------
    // The flags architecture (docs/architecture/x86-flags.md).
    //
    // These two encode the STOP CONDITION for that work and are expected to be RED
    // until it lands. They are deliberately about the SHAPE of the model rather than
    // about any one instruction: the defect is that `Ule`/`Slt`/`Sle` are conditions
    // stored where architectural flags belong, and no per-instruction test can catch
    // that — each individual lifter looks locally reasonable.
    // ----------------------------------------------------------------------

    /// Representative flag-producing instructions, as (asm, encoding).
    fn flag_producers() -> Vec<(&'static str, Vec<u8>)> {
        vec![
            ("cmp %eax,%ebx", vec![0x39, 0xc3]),
            ("test %eax,%eax", vec![0x85, 0xc0]),
            ("neg %edx", vec![0xf7, 0xda]),
            ("sub $1,%edi", vec![0x83, 0xef, 0x01]),
            ("add %eax,%ebx", vec![0x01, 0xc3]),
            ("dec %ecx", vec![0xff, 0xc9]),
            ("inc %ecx", vec![0xff, 0xc1]),
            ("and %eax,%ebx", vec![0x21, 0xc3]),
            ("xor %eax,%ebx", vec![0x31, 0xc3]),
            ("shl $1,%eax", vec![0xd1, 0xe0]),
            ("shr $3,%eax", vec![0xc1, 0xe8, 0x03]),
            ("imul %ebx,%eax", vec![0x0f, 0xaf, 0xc3]),
            ("bt $0,%eax", vec![0x0f, 0xba, 0xe0, 0x00]),
            ("bts %rdi,%rdx", vec![0x48, 0x0f, 0xab, 0xfa]),
            ("btr %rdx,%rcx", vec![0x48, 0x0f, 0xb3, 0xd1]),
            ("btc %rdx,%rcx", vec![0x48, 0x0f, 0xbb, 0xd1]),
            ("tzcnt %edx,%ecx", vec![0xf3, 0x0f, 0xbc, 0xca]),
            ("popcnt %rax,%rdx", vec![0xf3, 0x48, 0x0f, 0xb8, 0xd0]),
            ("rcr $1,%rdx", vec![0x48, 0xd1, 0xda]),
            ("xadd %ebx,%eax", vec![0x0f, 0xc1, 0xd8]),
            ("cmpxchg %rcx,%rbx", vec![0x48, 0x0f, 0xb1, 0xcb]),
            ("rol $1,%eax", vec![0xd1, 0xc0]),
            ("ror $3,%eax", vec![0xc1, 0xc8, 0x03]),
        ]
    }

    #[test]
    fn no_lifter_writes_a_derived_predicate_as_a_flag() {
        // STOP CONDITION, made executable: `Ule`, `Slt` and `Sle` are CONDITIONS
        // (CF|ZF, SF!=OF, ZF|(SF!=OF)) — not architectural flags. A producer that
        // writes them has frozen a consumer's interpretation into its own output, so
        // every consumer that wants a different composition of the same underlying
        // flags is stuck reading a predicate someone else chose.
        //
        // Concretely, that is why `test` breaks: it defines Z and S honestly, but a
        // following `jle` wants ZF|(SF!=OF) and finds only a pre-baked `Sle` left by
        // whatever ran before it. Making `test` also write `Sle` would paper over
        // this instruction and leave the shape intact.
        let mut offenders: Vec<String> = Vec::new();
        for (asm, bytes) in flag_producers() {
            for ins in lift64(&bytes) {
                if let (Some(VReg::Flag(f)), _) = crate::ir::use_def::def_uses(&ins.op) {
                    if matches!(f, Flag::Ule | Flag::Slt | Flag::Sle) {
                        offenders.push(format!("{asm} writes Flag::{f:?}"));
                    }
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "producers must write only architectural flags {{CF,PF,AF,ZF,SF,OF}}; \
             conditions belong to the shared consumer mapping:\n  {}",
            offenders.join("\n  ")
        );
    }

    #[test]
    fn arithmetic_that_sets_flags_defines_at_least_one() {
        // The other half of the same gap. `add`, `sub`, `and`, `xor`, `inc`, `dec`,
        // the shifts and `imul` all set flags on real hardware and define NONE here,
        // so at -O2 — where the compiler branches on an arithmetic result instead of
        // emitting a separate `cmp` — the branch reads whatever a previous comparison
        // left behind. 14_flag_effects:dec_loop decompiles to an infinite loop
        // because of exactly this.
        //
        // Deliberately weak: it asserts only that SOMETHING is defined, not what.
        // The per-instruction semantics (CF preserved by inc/dec, OF undefined for
        // shift counts > 1, bt leaving the rest UNDEFINED rather than preserved) are
        // separate tests, because getting a flag wrong and not setting it at all are
        // different bugs and should fail differently.
        let mut silent: Vec<&str> = Vec::new();
        for (asm, bytes) in flag_producers() {
            let defines_a_flag = lift64(&bytes).iter().any(|ins| {
                matches!(
                    crate::ir::use_def::def_uses(&ins.op),
                    (Some(VReg::Flag(_)), _)
                )
            });
            if !defines_a_flag {
                silent.push(asm);
            }
        }
        assert!(
            silent.is_empty(),
            "these set flags on hardware but define none when lifted, so a following \
             jcc reads a stale flag:\n  {}",
            silent.join("\n  ")
        );
    }

    fn defined_arch_flags(ops: &[LlirInstr]) -> std::collections::BTreeSet<Flag> {
        ops.iter()
            .filter_map(|ins| match crate::ir::use_def::def_uses(&ins.op).0 {
                Some(VReg::Flag(flag)) => Some(flag),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn every_flag_producer_defines_or_intentionally_preserves_each_flag() {
        let all: std::collections::BTreeSet<Flag> =
            [Flag::C, Flag::P, Flag::A, Flag::Z, Flag::S, Flag::O]
                .into_iter()
                .collect();
        let cf_preserved: std::collections::BTreeSet<Flag> =
            [Flag::P, Flag::A, Flag::Z, Flag::S, Flag::O]
                .into_iter()
                .collect();
        let rotate_changed: std::collections::BTreeSet<Flag> =
            [Flag::C, Flag::O].into_iter().collect();
        // Intel SDM Vol. 2A, BT/BTS/BTR/BTC: "The CF flag contains the value of
        // the selected bit. The ZF flag is UNAFFECTED. The OF, SF, AF, and PF
        // flags are undefined." ZF used to be poisoned here along with the other
        // four, which is not a conservative approximation: an `Op::Undef` is a
        // real definition, so it destroys a live comparison result that a
        // preceding `cmp` produced and a following `je` still reads.
        let zf_preserved: std::collections::BTreeSet<Flag> =
            [Flag::C, Flag::P, Flag::A, Flag::S, Flag::O]
                .into_iter()
                .collect();
        let cases: &[(&str, &[u8], &std::collections::BTreeSet<Flag>)] = &[
            ("cmp", &[0x39, 0xc3], &all),
            ("test", &[0x85, 0xc0], &all),
            ("neg", &[0xf7, 0xda], &all),
            ("sub", &[0x83, 0xef, 0x01], &all),
            ("add", &[0x01, 0xc3], &all),
            ("and", &[0x21, 0xc3], &all),
            ("or", &[0x09, 0xc3], &all),
            ("xor", &[0x31, 0xc3], &all),
            ("shl", &[0xd1, 0xe0], &all),
            ("shr", &[0xc1, 0xe8, 0x03], &all),
            ("sar", &[0xc1, 0xf8, 0x03], &all),
            ("imul", &[0x0f, 0xaf, 0xc3], &all),
            ("bt", &[0x0f, 0xba, 0xe0, 0x00], &zf_preserved),
            ("bts", &[0x48, 0x0f, 0xab, 0xfa], &zf_preserved),
            ("btr", &[0x48, 0x0f, 0xb3, 0xd1], &zf_preserved),
            ("btc", &[0x48, 0x0f, 0xbb, 0xd1], &zf_preserved),
            // TZCNT defines CF (source was zero) and ZF (result was zero) and
            // poisons the other four; POPCNT defines ZF and CLEARS the rest.
            ("tzcnt", &[0xf3, 0x0f, 0xbc, 0xca], &all),
            ("popcnt", &[0xf3, 0x48, 0x0f, 0xb8, 0xd0], &all),
            // A rotate through carry by one is a rotate: CF and OF, nothing else.
            ("rcr", &[0x48, 0xd1, 0xda], &rotate_changed),
            ("xadd", &[0x0f, 0xc1, 0xd8], &all),
            ("cmpxchg", &[0x48, 0x0f, 0xb1, 0xcb], &all),
            ("rol", &[0xd1, 0xc0], &rotate_changed),
            ("ror", &[0xc1, 0xc8, 0x03], &rotate_changed),
            ("inc", &[0xff, 0xc1], &cf_preserved),
            ("dec", &[0xff, 0xc9], &cf_preserved),
        ];
        for (name, bytes, expected) in cases {
            assert_eq!(
                defined_arch_flags(&lift64(bytes)),
                **expected,
                "{name} left a stale flag value reachable"
            );
        }
    }

    #[test]
    fn rotate_counts_have_explicit_architectural_flag_protocol() {
        // A masked zero count preserves every flag.
        let zero = lift64(&[0xc1, 0xc0, 0x00]); // rol eax, 0
        assert!(defined_arch_flags(&zero).is_empty(), "got: {zero:#?}");

        // A one-bit rotate defines CF and OF exactly.
        let one = lift64(&[0xd1, 0xc0]); // rol eax, 1
        assert!(one.iter().any(|ins| matches!(
            ins.op,
            Op::Bin {
                dst: VReg::Flag(Flag::C),
                ..
            }
        )));
        assert!(one.iter().any(|ins| matches!(
            ins.op,
            Op::Bin {
                dst: VReg::Flag(Flag::O),
                ..
            }
        )));

        // CF is still defined for a multi-bit rotate; OF is explicitly
        // architectural poison, never an older stale value.
        let many = lift64(&[0xc1, 0xc8, 0x03]); // ror eax, 3
        assert!(many.iter().any(|ins| matches!(
            ins.op,
            Op::Bin {
                dst: VReg::Flag(Flag::C),
                ..
            }
        )));
        assert!(many.iter().any(|ins| matches!(
            ins.op,
            Op::Undef {
                dst: VReg::Flag(Flag::O),
                ..
            }
        )));

        // A variable count may be zero, one, or many at runtime. Until the IR
        // carries guarded flag writes, fail closed for the two affected flags
        // and preserve the four architecturally unaffected ones.
        let variable = lift64(&[0xd3, 0xc0]); // rol eax, cl
        assert_eq!(
            defined_arch_flags(&variable),
            [Flag::C, Flag::O].into_iter().collect()
        );
        assert!(
            variable
                .iter()
                .filter(|ins| matches!(ins.op, Op::Undef { .. }))
                .count()
                >= 2
        );
    }

    #[test]
    fn partial_rotate_then_movzx_tracks_the_canonical_parent() {
        // `rol $3,%di; movzwl %di,%eax` is GCC's -O2 implementation of a
        // 16-bit rotate.  DI is a view of RDI: the rotate must read/write that
        // view through RDI, and MOVZX must consume the updated parent.  A
        // detached `di = ...` definition is dead after MOVZX learns proper
        // register-view semantics, silently reducing rotl16_3(x) to x.
        let ops = lift64(&[0x66, 0xc1, 0xc7, 0x03, 0x0f, 0xb7, 0xc7]);

        for ins in &ops {
            let (def, uses) = crate::ir::use_def::def_uses(&ins.op);
            assert_ne!(def, Some(VReg::phys("di")), "detached DI def: {ops:#?}");
            assert!(
                !uses.contains(&VReg::phys("di")),
                "detached DI use: {ops:#?}"
            );
        }
        let parent_write = ops
            .iter()
            .position(|ins| {
                matches!(
                    &ins.op,
                    Op::Bin {
                        dst: VReg::Phys(parent),
                        op: BinOp::Or,
                        ..
                    } if parent == "rdi"
                )
            })
            .expect("ROL DI must update RDI");
        let movzx_read = ops
            .iter()
            .rposition(|ins| {
                matches!(
                    &ins.op,
                    Op::Bin {
                        lhs: Value::Reg(VReg::Phys(parent)),
                        op: BinOp::And,
                        ..
                    } if parent == "rdi"
                )
            })
            .expect("MOVZX DI must read RDI");
        assert!(
            parent_write < movzx_read,
            "MOVZX must follow the partial rotate's canonical write: {ops:#?}"
        );
    }

    #[test]
    fn memory_rotate_lifts_as_an_exact_load_rotate_store() {
        // rol dword ptr [rbp-0x34], 1 -- GCC -O0 emits this for the packet
        // checksum's portable `(sum << 1) | (sum >> 31)` idiom.
        let ops = lift64(&[0xd1, 0x45, 0xcc]);
        assert!(
            matches!(
                &ops[0].op,
                Op::Load { dst: VReg::Temp(40), addr }
                    if addr.base == Some(VReg::phys("rbp")) && addr.disp == -0x34 && addr.size == 4
            ),
            "missing dword load: {ops:#?}"
        );
        assert!(
            ops.iter().any(|instruction| matches!(
                &instruction.op,
                Op::Bin {
                    dst: VReg::Temp(43),
                    op: BinOp::Or,
                    lhs: Value::Reg(VReg::Temp(41)),
                    rhs: Value::Reg(VReg::Temp(42)),
                }
            )),
            "missing rotate recombination: {ops:#?}"
        );
        assert!(
            ops.iter().any(|instruction| matches!(
                &instruction.op,
                Op::Store {
                    addr,
                    src: Value::Reg(VReg::Temp(43)),
                } if addr.base == Some(VReg::phys("rbp")) && addr.disp == -0x34 && addr.size == 4
            )),
            "missing dword writeback: {ops:#?}"
        );
        assert!(
            !ops.iter().any(|instruction| matches!(
                instruction.op,
                Op::Unknown { .. } | Op::Intrinsic { .. }
            )),
            "memory rotate remained opaque: {ops:#?}"
        );
    }

    #[test]
    fn arithmetic_flags_cover_8_16_32_and_64_bit_operands() {
        let all: std::collections::BTreeSet<Flag> =
            [Flag::C, Flag::P, Flag::A, Flag::Z, Flag::S, Flag::O]
                .into_iter()
                .collect();
        for (width, bytes) in [
            (8, &[0x00, 0xd8][..]),        // add al,bl
            (16, &[0x66, 0x01, 0xd8][..]), // add ax,bx
            (32, &[0x01, 0xd8][..]),       // add eax,ebx
            (64, &[0x48, 0x01, 0xd8][..]), // add rax,rbx
        ] {
            assert_eq!(
                defined_arch_flags(&lift64(bytes)),
                all,
                "{width}-bit ADD did not replace every flag value"
            );
        }
    }

    #[test]
    fn shift_counts_zero_one_many_and_variable_have_explicit_effects() {
        let all: std::collections::BTreeSet<Flag> =
            [Flag::C, Flag::P, Flag::A, Flag::Z, Flag::S, Flag::O]
                .into_iter()
                .collect();
        assert!(
            defined_arch_flags(&lift64(&[0xc1, 0xe0, 0x00])).is_empty(),
            "masked count zero must preserve every flag"
        );
        for (shape, bytes) in [
            ("one", &[0xd1, 0xe0][..]),
            ("many", &[0xc1, 0xe0, 0x03][..]),
            ("variable", &[0xd3, 0xe0][..]),
        ] {
            assert_eq!(
                defined_arch_flags(&lift64(bytes)),
                all,
                "{shape}-count shift left a stale flag"
            );
        }
        assert!(lift64(&[0xc1, 0xe0, 0x03]).iter().any(|ins| matches!(
            &ins.op,
            Op::Undef {
                dst: VReg::Flag(Flag::O),
                reason,
            } if reason.contains("multi-bit shift")
        )));
    }

    #[test]
    fn variable_shift_count_uses_the_canonical_ecx_view() {
        // shr edx, cl. The CL encoding reads the value previously written via
        // ECX; leaving it as a separate `cl` register creates an undefined
        // pseudo-argument after SSA and naming. The machine then masks that
        // value to five bits. Emitted C must state the mask explicitly because
        // an oversized C shift is undefined instead of using x86 semantics.
        let ops = lift64(&[0xd3, 0xea]);
        let masked = ops
            .iter()
            .find_map(|ins| match &ins.op {
                Op::Bin {
                    dst,
                    op: BinOp::And,
                    lhs: Value::Reg(VReg::Phys(count)),
                    rhs: Value::Const(31),
                } if count == "ecx" => Some(dst.clone()),
                _ => None,
            })
            .unwrap_or_else(|| panic!("variable shift did not mask ECX: {ops:#?}"));
        assert!(
            ops.iter().any(|ins| matches!(
                &ins.op,
                Op::Bin {
                    op: BinOp::Shr,
                    rhs: Value::Reg(count),
                    ..
                } if count == &masked
            )),
            "got: {ops:#?}"
        );
    }

    #[test]
    fn adc_and_sbb_consume_old_cf_then_replace_all_flags() {
        for (name, bytes) in [("adc", &[0x11, 0xd8][..]), ("sbb", &[0x19, 0xd8][..])] {
            let ops = lift64(bytes);
            let cf_read = ops.iter().any(|ins| {
                crate::ir::use_def::def_uses(&ins.op)
                    .1
                    .contains(&VReg::Flag(Flag::C))
            });
            assert!(cf_read, "{name} did not consume incoming CF: {ops:#?}");
            assert_eq!(defined_arch_flags(&ops).len(), 6, "{name}: {ops:#?}");
        }
    }

    #[test]
    fn neg_defines_the_sign_and_zero_flags() {
        // `neg %edx` (f7 da). x86 sets SF from the sign of the RESULT and ZF from
        // whether it is zero. We defined neither, so a following `cmovs`/`js` read a
        // sign flag that either did not exist or — worse — was left over from an
        // unrelated later comparison, which is what `arith:signs` showed: the emitted
        // C tested `sf` several statements before anything assigned it.
        //
        // The flags are computed from a temp holding the negation at its natural
        // width, not from the destination register: a write to `%edx` zero-extends
        // into `rdx`, so reading the destination back would make the result
        // unconditionally non-negative and the sign flag always false.
        //
        // CF and OF are deliberately left undefined rather than guessed. `neg` sets
        // CF = (operand != 0) and OF only at INT_MIN, and the conditions that read
        // them (`jb`, `jl` — which needs SF != OF) cannot be expressed without
        // modelling OF. Defining them approximately would turn a visibly missing
        // flag into a silently wrong branch.
        let ops = lift64(&[0xf7, 0xda]);
        let flags: Vec<(Flag, CmpOp)> = ops
            .iter()
            .filter_map(|i| match &i.op {
                Op::Cmp {
                    dst: VReg::Flag(f),
                    op,
                    ..
                } => Some((*f, *op)),
                _ => None,
            })
            .collect();
        assert!(
            flags.contains(&(Flag::S, CmpOp::Slt)),
            "neg must define the sign flag, got {ops:#?}"
        );
        assert!(
            flags.contains(&(Flag::Z, CmpOp::Eq)),
            "neg must define the zero flag, got {ops:#?}"
        );
        // And it must still actually negate the register.
        assert!(
            ops.iter()
                .any(|i| matches!(&i.op, Op::Un { op: UnOp::Neg, .. })),
            "neg must still negate, got {ops:#?}"
        );
        let defines_dst = ops.iter().any(|i| {
            matches!(&i.op, Op::Un { dst: VReg::Phys(n), op: UnOp::Neg, .. } if n == "edx")
                || matches!(&i.op, Op::Assign { dst: VReg::Phys(n), .. } if n == "edx")
        });
        assert!(defines_dst, "neg must write %edx, got {ops:#?}");
    }

    #[test]
    fn jle_after_test_materializes_a_fresh_composite_predicate() {
        // test edi,edi ; jle +2. TEST clears OF, so JLE is exactly
        // `(signed32)(edi & edi) <= 0`; the consumer must not inherit Sle from
        // an unrelated earlier comparison.
        let ops = lift_bytes(&[0x85, 0xff, 0x7e, 0x02], 0x1000, 64);
        let jle_at = ops
            .iter()
            .position(|i| matches!(i.op, Op::CondJump { .. }))
            .expect("jle must lift");
        assert!(
            ops[..jle_at].iter().any(|i| matches!(
                &i.op,
                Op::Bin {
                    dst: VReg::Temp(20),
                    op: BinOp::Xor,
                    lhs: Value::Reg(VReg::Flag(Flag::S)),
                    rhs: Value::Reg(VReg::Flag(Flag::O)),
                }
            )),
            "JLE must materialize SF^OF: {ops:#?}"
        );
        assert!(
            ops[..jle_at].iter().any(|i| matches!(
                &i.op,
                Op::Bin {
                    dst: VReg::Temp(21),
                    op: BinOp::Or,
                    lhs: Value::Reg(VReg::Flag(Flag::Z)),
                    rhs: Value::Reg(VReg::Temp(20)),
                }
            )),
            "JLE must materialize ZF|(SF^OF): {ops:#?}"
        );
        assert!(matches!(
            &ops[jle_at].op,
            Op::CondJump {
                cond: VReg::Temp(21),
                ..
            }
        ));
    }

    #[test]
    fn test_zero_and_sign_flags_observe_the_exact_encoded_width() {
        // A canonical parent can have high bits even when TEST observes only a
        // byte, word, or dword view.  ZF and SF must both derive from the same
        // encoded-width result.  In particular, `rdi = 1 << 32; test edi,edi`
        // sets ZF, while `test rdi,rdi` clears it.  Pin both register and memory
        // encodings so neither operand path can silently fall back to host word
        // width.
        let cases: &[(&str, &[u8], Width)] = &[
            ("register byte", &[0x84, 0xc0], Width::W8),
            ("register word", &[0x66, 0x85, 0xc0], Width::W16),
            ("register dword", &[0x85, 0xc0], Width::W32),
            ("register qword", &[0x48, 0x85, 0xc0], Width::W64),
            ("memory byte", &[0x84, 0x07], Width::W8),
            ("memory word", &[0x66, 0x85, 0x07], Width::W16),
            ("memory dword", &[0x85, 0x07], Width::W32),
            ("memory qword", &[0x48, 0x85, 0x07], Width::W64),
        ];

        for (label, bytes, width) in cases {
            let ops = lift64(bytes);
            let zf_lhs = ops
                .iter()
                .find_map(|instruction| match &instruction.op {
                    Op::Cmp {
                        dst: VReg::Flag(Flag::Z),
                        op: CmpOp::Eq,
                        lhs,
                        rhs: Value::Const(0),
                    } => Some(lhs.clone()),
                    _ => None,
                })
                .unwrap_or_else(|| panic!("{label} did not define ZF: {ops:#?}"));
            let sf_lhs = ops
                .iter()
                .find_map(|instruction| match &instruction.op {
                    Op::Cmp {
                        dst: VReg::Flag(Flag::S),
                        op: CmpOp::Slt,
                        lhs,
                        rhs: Value::Const(0),
                    } => Some(lhs.clone()),
                    _ => None,
                })
                .unwrap_or_else(|| panic!("{label} did not define SF: {ops:#?}"));

            if *width == Width::W64 {
                assert_eq!(zf_lhs, Value::Reg(VReg::Temp(0)), "{label}: {ops:#?}");
                assert_eq!(sf_lhs, Value::Reg(VReg::Temp(0)), "{label}: {ops:#?}");
                continue;
            }

            let unsigned_view = ops.iter().find_map(|instruction| match &instruction.op {
                Op::ZExt {
                    dst,
                    src: Value::Reg(VReg::Temp(0)),
                    from,
                    to: Width::W64,
                } if from == width => Some(dst.clone()),
                _ => None,
            });
            let signed_view = ops.iter().find_map(|instruction| match &instruction.op {
                Op::SExt {
                    dst,
                    src: Value::Reg(VReg::Temp(0)),
                    from,
                    to: Width::W64,
                } if from == width => Some(dst.clone()),
                _ => None,
            });
            assert_eq!(
                zf_lhs,
                Value::Reg(unsigned_view.unwrap_or_else(|| {
                    panic!("{label} did not normalize the ZF input from {width:?}: {ops:#?}")
                })),
                "{label} ZF did not consume its encoded-width view: {ops:#?}"
            );
            assert_eq!(
                sf_lhs,
                Value::Reg(signed_view.unwrap_or_else(|| {
                    panic!("{label} did not normalize the SF input from {width:?}: {ops:#?}")
                })),
                "{label} SF did not consume its encoded-width view: {ops:#?}"
            );
        }
    }

    #[test]
    fn shift_defines_zero_after_writing_its_result() {
        // shr $1,edi ; jne +2. The JNE consumes ZF for the shifted RESULT.
        let ops = lift_bytes(&[0xd1, 0xef, 0x75, 0x02], 0x1000, 64);
        let bin_at = ops
            .iter()
            .position(|i| matches!(&i.op, Op::Bin { op: BinOp::Shr, .. }))
            .expect("shr must lift");
        let zf_at = ops
            .iter()
            .position(|i| {
                matches!(
                    &i.op,
                    Op::Cmp {
                        dst: VReg::Flag(Flag::Z),
                        op: CmpOp::Eq,
                        rhs: Value::Const(0),
                        ..
                    }
                )
            })
            .expect("shr must define ZF");
        assert!(
            zf_at > bin_at,
            "ZF must describe the shifted result: {ops:#?}"
        );
    }

    #[test]
    fn sar_eax_signs_the_low_word_then_zero_extends_the_parent() {
        // `sar eax,1` reads eax as a signed 32-bit value, then (because it
        // writes eax) clears rax[63:32]. Treating the already-zero-extended
        // parent as a signed 64-bit value turns -3 >> 1 into 2147483646.
        let ops = lift64(&[0xd1, 0xf8]);
        let sext = ops
            .iter()
            .position(|instruction| {
                matches!(
                    &instruction.op,
                    Op::SExt {
                        dst,
                        src: Value::Reg(src),
                        from: Width::W32,
                        to: Width::W64,
                    } if *dst == VReg::phys("eax") && *src == VReg::phys("eax")
                )
            })
            .expect("32-bit SAR must sign-extend its low-word input");
        let shift = ops
            .iter()
            .position(|instruction| matches!(&instruction.op, Op::Bin { op: BinOp::Sar, .. }))
            .expect("SAR operation");
        let zext = ops
            .iter()
            .rposition(|instruction| {
                matches!(
                    &instruction.op,
                    Op::ZExt {
                        dst,
                        src: Value::Reg(src),
                        from: Width::W32,
                        to: Width::W64,
                    } if *dst == VReg::phys("eax") && *src == VReg::phys("eax")
                )
            })
            .expect("32-bit destination must zero-extend its parent after the shift");
        assert!(
            sext < shift && shift < zext,
            "wrong width-operation order: {ops:#?}"
        );
    }

    #[test]
    fn signed_cmp_uses_the_machine_operand_width() {
        // cmp $0,eax. A 32-bit negative value lives in a zero-extended 64-bit
        // parent after the write, so comparing that parent directly against zero
        // makes every value non-negative. The signed flag atom must consume a
        // sign-extension from 32 bits.
        let ops = lift64(&[0x83, 0xf8, 0x00]);
        assert!(
            ops.iter().any(|i| matches!(
                &i.op,
                Op::SExt {
                    dst: VReg::Temp(30),
                    from: Width::W32,
                    to: Width::W64,
                    ..
                }
            )),
            "32-bit CMP must sign-extend its signed operand: {ops:#?}"
        );
        assert!(
            ops.iter().any(|i| matches!(
                &i.op,
                Op::Cmp {
                    dst: VReg::Temp(32),
                    lhs: Value::Reg(VReg::Temp(30)),
                    ..
                }
            )),
            "signed relation must use the widened value: {ops:#?}"
        );
        assert!(
            ops.iter().any(|i| matches!(
                &i.op,
                Op::Cmp {
                    dst: VReg::Flag(Flag::S),
                    lhs: Value::Reg(VReg::Temp(34)),
                    ..
                }
            )),
            "architectural SF must use the width-normalized result: {ops:#?}"
        );
    }

    #[test]
    fn inverted_composite_jcc_materializes_logical_not() {
        // test edi,edi ; jg +2. JG is !(ZF | (SF^OF)); keeping `inverted=true`
        // on an arbitrary temporary lets AST lowering render bitwise `~temp`,
        // which is true for both zero and one.
        let ops = lift_bytes(&[0x85, 0xff, 0x7f, 0x02], 0x1000, 64);
        assert!(
            ops.iter().any(|i| matches!(
                &i.op,
                Op::Cmp {
                    dst: VReg::Temp(22),
                    op: CmpOp::Eq,
                    rhs: Value::Const(0),
                    ..
                }
            )),
            "inverted Jcc must materialize predicate == 0: {ops:#?}"
        );
        assert!(
            ops.iter().any(|i| matches!(
                &i.op,
                Op::CondJump {
                    cond: VReg::Temp(22),
                    inverted: false,
                    ..
                }
            )),
            "CondJump must consume the positive logical-not value: {ops:#?}"
        );
    }

    #[test]
    fn all_sixteen_jcc_setcc_and_cmovcc_conditions_share_one_mapping() {
        // Intel condition-code nibble order for 0x70/0x0f90/0x0f40 families.
        // Every odd entry is the logical inverse of the preceding even entry.
        let expected: [Vec<Flag>; 16] = [
            vec![Flag::O],
            vec![Flag::O],
            vec![Flag::C],
            vec![Flag::C],
            vec![Flag::Z],
            vec![Flag::Z],
            vec![Flag::C, Flag::Z],
            vec![Flag::C, Flag::Z],
            vec![Flag::S],
            vec![Flag::S],
            vec![Flag::P],
            vec![Flag::P],
            vec![Flag::S, Flag::O],
            vec![Flag::S, Flag::O],
            vec![Flag::Z, Flag::S, Flag::O],
            vec![Flag::Z, Flag::S, Flag::O],
        ];

        let read_flags = |ops: &[LlirInstr]| {
            let mut flags: Vec<Flag> = ops
                .iter()
                .flat_map(|ins| crate::ir::use_def::def_uses(&ins.op).1)
                .filter_map(|reg| match reg {
                    VReg::Flag(flag) => Some(flag),
                    _ => None,
                })
                .collect();
            flags.sort();
            flags.dedup();
            flags
        };

        for cc in 0u8..16 {
            let mut want = expected[cc as usize].clone();
            want.sort();

            let jcc = lift64(&[0x70 + cc, 0x00]);
            assert!(
                matches!(
                    jcc.last().map(|ins| &ins.op),
                    Some(Op::CondJump {
                        inverted: false,
                        ..
                    })
                ),
                "Jcc/{cc:x} did not end in a positive predicate jump: {jcc:#?}"
            );
            assert_eq!(read_flags(&jcc), want, "Jcc/{cc:x} flag inputs");

            let setcc = lift64(&[0x0f, 0x90 + cc, 0xc0]);
            assert!(!setcc.iter().any(|ins| matches!(ins.op, Op::Unknown { .. })));
            assert_eq!(read_flags(&setcc), want, "SETcc/{cc:x} flag inputs");
            assert!(matches!(
                crate::ir::use_def::def_uses(&setcc.last().expect("SETcc output").op).0,
                Some(VReg::Phys(_))
            ));

            let cmovcc = lift64(&[0x0f, 0x40 + cc, 0xc3]);
            assert!(!cmovcc
                .iter()
                .any(|ins| matches!(ins.op, Op::Unknown { .. })));
            assert_eq!(read_flags(&cmovcc), want, "CMOVcc/{cc:x} flag inputs");
            assert!(matches!(
                cmovcc.last().map(|ins| &ins.op),
                Some(Op::Ite { .. })
            ));
        }
    }

    #[test]
    fn setcc_then_movzx_tracks_the_low_byte_through_its_parent() {
        // `sete al; movzx eax, al` is Clang's -O0 spelling of a boolean
        // return.  AL is not an independent SSA register: SETE updates the low
        // byte of RAX, and MOVZX must read that newly-written byte.  Keeping a
        // direct `al = zf` definition lets later canonicalisation read a stale
        // RAX value instead (the DecBench statemachine returned its loop index
        // instead of `state == 3`).
        let ops = lift64(&[0x0f, 0x94, 0xc0, 0x0f, 0xb6, 0xc0]);

        for ins in &ops {
            let (def, uses) = crate::ir::use_def::def_uses(&ins.op);
            assert_ne!(def, Some(VReg::phys("al")), "detached AL def: {ops:#?}");
            assert!(
                !uses.contains(&VReg::phys("al")),
                "detached AL use: {ops:#?}"
            );
        }
        assert!(
            ops.iter().any(|ins| matches!(
                &ins.op,
                Op::Bin {
                    dst: VReg::Phys(parent),
                    op: BinOp::Or,
                    ..
                } if parent == "rax"
            )),
            "SETE must update the canonical parent: {ops:#?}"
        );
        assert!(
            matches!(
                ops.last().map(|ins| &ins.op),
                Some(Op::ZExt {
                    dst: VReg::Phys(dst),
                    src: Value::Reg(VReg::Temp(_)),
                    from: Width::W8,
                    to: Width::W32,
                }) if dst == "eax"
            ),
            "MOVZX must extract AL from the updated parent: {ops:#?}"
        );
    }

    #[test]
    fn test_of_setcc_bytes_reads_their_canonical_parents() {
        // GCC -O2 lowers `(a > 0 && b > 0)` as `setg cl; setg al;
        // test al,cl`.  SETcc already updates RCX/RAX through their low-byte
        // views; TEST must extract those same views.  Reading detached CL/AL
        // loses both definitions, invents an incoming RCX argument, and makes
        // the real sc_mixed round trip return 90 instead of 9.
        let ops = lift64(&[0x0f, 0x9f, 0xc1, 0x0f, 0x9f, 0xc0, 0x84, 0xc8]);

        for ins in &ops {
            let (_, uses) = crate::ir::use_def::def_uses(&ins.op);
            assert!(
                !uses.contains(&VReg::phys("cl")) && !uses.contains(&VReg::phys("al")),
                "TEST bypassed canonical parent definitions: {ops:#?}"
            );
        }
        assert!(
            ops.iter().any(|ins| matches!(
                &ins.op,
                Op::Bin {
                    dst: VReg::Temp(10),
                    lhs: Value::Reg(VReg::Phys(parent)),
                    op: BinOp::And,
                    rhs: Value::Const(255),
                } if parent == "rax"
            )),
            "TEST must extract AL from RAX: {ops:#?}"
        );
        assert!(
            ops.iter().any(|ins| matches!(
                &ins.op,
                Op::Bin {
                    dst: VReg::Temp(11),
                    lhs: Value::Reg(VReg::Phys(parent)),
                    op: BinOp::And,
                    rhs: Value::Const(255),
                } if parent == "rcx"
            )),
            "TEST must extract CL from RCX: {ops:#?}"
        );
    }

    #[test]
    fn mov_imm32_into_32bit_register_zero_extends() {
        // `mov $0x80808081,%eax` (b8 81 80 80 80).
        //
        // On x86-64 a write to a 32-bit register view zero-extends into the 64-bit
        // parent, so `rax` becomes 0x0000000080808081 — a POSITIVE value. Reading
        // the imm32 as `as i32 as i64` sign-extends it to -0x7f7f7f7f instead, and
        // the two differ in exactly the bits a following 64-bit `imul %rdx,%rax`
        // reads.
        //
        // 0x80808081 is the magic reciprocal for division by 255, so this single
        // sign bit made every `x % 255` decompile to the wrong arithmetic:
        // `mod255(x)` rendered as `(-0x7f7f7f7f * x) >> 32 ...`. `x % 255` is not an
        // exotic operation — it is the core of Fletcher's checksum — and the emitted
        // C compiled and ran, just with a different answer.
        let ops = lift64(&[0xb8, 0x81, 0x80, 0x80, 0x80]);
        assert_eq!(ops.len(), 1, "expected one op, got {ops:?}");
        match &ops[0].op {
            Op::Assign {
                src: Value::Const(c),
                ..
            } => assert_eq!(
                *c, 0x8080_8081,
                "a 32-bit register write zero-extends: expected 0x80808081, \
                 got {c:#x} ({c})"
            ),
            other => panic!("expected Assign of a Const, got {other:?}"),
        }
    }

    #[test]
    fn mov_reg32_into_reg32_keeps_the_zero_extension_explicit() {
        // `mov eax, edi` is the first half of GCC's `uint64_t` multiply
        // lowering. A later `imul rax, rsi` consumes all 64 bits, so reducing
        // this to a bare parent-register copy loses the fact that bits 32..63
        // were cleared and lets C perform the product at 32-bit width.
        let ops = lift64(&[0x89, 0xf8]);
        assert_eq!(ops.len(), 1, "expected one explicit extension: {ops:#?}");
        assert!(
            matches!(
                &ops[0].op,
                Op::ZExt {
                    dst: VReg::Phys(dst),
                    src: Value::Reg(VReg::Phys(src)),
                    from: Width::W32,
                    to: Width::W64,
                } if dst == "eax" && src == "edi"
            ),
            "32-bit MOV semantics must remain explicit: {ops:#?}"
        );
    }

    #[test]
    fn mov_store_from_low_byte_reads_the_canonical_parent_value() {
        // `mov byte ptr [rbp-9], al` (88 45 f7), as emitted immediately after
        // `movzx eax, byte ptr [rax]` in the real GCC -O0 DecBench `fsm`.
        // `al` is a view of the newly-written `rax`, not an independent SSA
        // register.  Keeping it as `Value::Reg("al")` creates a loop phi from
        // the entry live-in and stores an uninitialised old byte instead.
        let ops = lift64(&[0x88, 0x45, 0xf7]);
        assert_eq!(ops.len(), 2, "expected extract + store, got {ops:#?}");
        assert!(matches!(
            &ops[0].op,
            Op::Bin {
                dst: VReg::Temp(0),
                op: BinOp::And,
                lhs: Value::Reg(VReg::Phys(parent)),
                rhs: Value::Const(0xff),
            } if parent == "rax"
        ));
        assert!(matches!(
            &ops[1].op,
            Op::Store {
                src: Value::Reg(VReg::Temp(0)),
                ..
            }
        ));
    }

    #[test]
    fn mov_load_into_low_byte_updates_the_canonical_parent_value() {
        // `mov al, byte ptr [rax]` (8a 00).  A partial destination preserves
        // the other parent bits, so it must be load-to-temp plus the same
        // canonical read/modify/write used for register/immediate MOV.  Leaving
        // this as `al = load` while a following store reads `rax & 255` makes
        // the store see the old pointer byte rather than the loaded byte.
        let ops = lift64(&[0x8a, 0x00]);
        assert_eq!(ops.len(), 4, "expected load + parent RMW, got {ops:#?}");
        assert!(matches!(
            &ops[0].op,
            Op::Load {
                dst: VReg::Temp(0),
                ..
            }
        ));
        assert!(ops.iter().skip(1).any(|ins| matches!(
            &ins.op,
            Op::Bin {
                dst: VReg::Phys(parent),
                op: BinOp::Or,
                ..
            } if parent == "rax"
        )));
        assert!(!ops.iter().any(|ins| matches!(
            crate::ir::use_def::def_uses(&ins.op).0,
            Some(VReg::Phys(name)) if name == "al"
        )));
    }

    #[test]
    fn mov_imm32_into_64bit_dest_still_sign_extends() {
        // The counterpart, so the fix above cannot be over-applied: `movq
        // $-1,-0x8(%rbp)` and friends encode a *sign-extended* imm32, and a 64-bit
        // destination must keep that sign. Only the 32-bit-view destination
        // zero-extends. `mov $0xffffffff,%eax` (b8 ff ff ff ff) is the 32-bit case
        // and must become 0xffffffff, NOT -1: `rax` really does hold 4294967295.
        let ops = lift64(&[0xb8, 0xff, 0xff, 0xff, 0xff]);
        match &ops[0].op {
            Op::Assign {
                src: Value::Const(c),
                ..
            } => assert_eq!(
                *c, 0xffff_ffff,
                "mov $0xffffffff,%eax leaves rax = 4294967295, got {c:#x}"
            ),
            other => panic!("expected Assign of a Const, got {other:?}"),
        }

        // ...whereas the 64-bit form of the same immediate is genuinely -1.
        let ops = lift64(&[0x48, 0xc7, 0xc0, 0xff, 0xff, 0xff, 0xff]);
        match &ops[0].op {
            Op::Assign {
                src: Value::Const(c),
                ..
            } => assert_eq!(*c, -1, "movq $-1,%rax must sign-extend, got {c:#x}"),
            other => panic!("expected Assign of a Const, got {other:?}"),
        }
    }

    #[test]
    fn movq_imm32to64_store_decodes_immediate_correctly() {
        // movq $0x0,-0x8(%rbp) — the immediate is a sign-extended imm32, which
        // must be read via `immediate32to64()`. Using `immediate64()` returned
        // garbage (`-8 << 32`), turning `long x = 0;` into a bogus constant.
        let ops = lift64(&[0x48, 0xc7, 0x45, 0xf8, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(ops.len(), 1);
        match &ops[0].op {
            Op::Store {
                src: Value::Const(c),
                ..
            } => assert_eq!(*c, 0, "movq $0 must store 0, got {c:#x}"),
            other => panic!("expected Store of Const(0), got {other:?}"),
        }
    }

    #[test]
    fn movq_imm32to64_negative_store_sign_extends() {
        // movq $-1,-0x8(%rbp): 48 c7 45 f8 ff ff ff ff -> Const(-1).
        let ops = lift64(&[0x48, 0xc7, 0x45, 0xf8, 0xff, 0xff, 0xff, 0xff]);
        match &ops[0].op {
            Op::Store {
                src: Value::Const(c),
                ..
            } => assert_eq!(*c, -1, "movq $-1 must sign-extend to -1, got {c:#x}"),
            other => panic!("expected Store of Const(-1), got {other:?}"),
        }
    }

    #[test]
    fn mov_reg_imm_lifts_to_assign() {
        // mov rax, 0x1234
        let ops = lift64(&[0x48, 0xc7, 0xc0, 0x34, 0x12, 0x00, 0x00]);
        assert_eq!(ops.len(), 1);
        match &ops[0].op {
            Op::Assign { dst, src } => {
                assert_eq!(*dst, VReg::phys("rax"));
                assert_eq!(*src, Value::Const(0x1234));
            }
            other => panic!("expected Assign, got {:?}", other),
        }
    }

    #[test]
    fn mov_reg_reg_lifts_to_assign() {
        // mov rax, rbx  (48 89 d8)
        let ops = lift64(&[0x48, 0x89, 0xd8]);
        assert_eq!(ops.len(), 1);
        match &ops[0].op {
            Op::Assign { dst, src } => {
                assert_eq!(*dst, VReg::phys("rax"));
                assert_eq!(*src, Value::Reg(VReg::phys("rbx")));
            }
            other => panic!("expected Assign, got {:?}", other),
        }
    }

    #[test]
    fn add_reg_imm_sets_bin_add() {
        // add rax, 5  (48 83 c0 05)
        let ops = lift64(&[0x48, 0x83, 0xc0, 0x05]);
        let add = ops
            .iter()
            .find(|ins| matches!(ins.op, Op::Bin { op: BinOp::Add, .. }))
            .expect("ADD result op");
        match &add.op {
            Op::Bin { dst, op, lhs, rhs } => {
                assert_eq!(*dst, VReg::phys("rax"));
                assert_eq!(*op, BinOp::Add);
                assert_eq!(*lhs, Value::Reg(VReg::phys("rax")));
                assert_eq!(*rhs, Value::Const(5));
            }
            other => panic!("expected Bin, got {:?}", other),
        }
        assert!(ops.iter().any(|ins| matches!(
            &ins.op,
            Op::Cmp {
                dst: VReg::Flag(Flag::Z),
                op: CmpOp::Eq,
                lhs: Value::Reg(VReg::Phys(name)),
                rhs: Value::Const(0),
            } if name == "rax"
        )));
    }

    #[test]
    fn three_operand_imul_from_memory_is_lifted() {
        // imul $0x3,-0xc(%rbp),%ecx — clang at -O0 multiplies straight out of a
        // parameter's spill slot. Requiring a REGISTER multiplicand dropped the whole
        // instruction to `Unknown`, so `a2 * 3` silently vanished from `sum_arg3` and
        // the surrounding expression reused another term instead.
        let ops = lift64(&[0x6b, 0x4d, 0xf4, 0x03]);
        assert!(ops.len() >= 2, "expected a load then a multiply: {ops:?}");
        assert!(matches!(&ops[0].op, Op::Load { .. }), "{:?}", ops[0].op);
        // The architectural multiply is the one that writes the destination
        // register; the CF/OF overflow predicate contributes a second, wider one.
        let arch = ops
            .iter()
            .find(|ins| {
                matches!(&ins.op, Op::Bin { dst: VReg::Phys(n), op: BinOp::Mul, .. } if n == "ecx")
            })
            .unwrap_or_else(|| panic!("expected a multiply into ecx: {ops:?}"));
        match &arch.op {
            Op::Bin {
                rhs: Value::Const(3),
                ..
            } => {}
            other => panic!("expected a multiply by 3, got {other:?}"),
        }
    }

    /// x86 IMUL's two- and three-operand forms truncate a `2N`-bit product to `N`
    /// bits and report that truncation in CF/OF: SDM Vol. 2A says both are set
    /// "when the signed integer value of the intermediate product differs from the
    /// sign extended operand-size-truncated product". Marking them `Undef` made a
    /// later `seto`/`jo` read a value the IR had declared meaningless — which is
    /// exactly what Rust's `overflowing_mul` / `checked_mul` emit.
    #[test]
    fn truncating_imul_defines_cf_and_of_from_the_wide_product() {
        for (name, bytes) in [
            // imul %esi,%eax        (0f af c6)
            ("two-operand", &[0x0f, 0xaf, 0xc6][..]),
            // imul $0x5,%ecx,%eax   (6b c1 05)
            ("three-operand", &[0x6b, 0xc1, 0x05][..]),
        ] {
            let ops = lift64(bytes);
            for flag in [Flag::C, Flag::O] {
                assert!(
                    !ops.iter().any(
                        |ins| matches!(&ins.op, Op::Undef { dst, .. } if *dst == VReg::Flag(flag))
                    ),
                    "{name} imul still poisons {flag:?}: {ops:?}"
                );
                assert!(
                    ops.iter().any(|ins| matches!(
                        &ins.op,
                        Op::Cmp { dst, op: CmpOp::Ne, .. } if *dst == VReg::Flag(flag)
                    )),
                    "{name} imul does not define {flag:?} from an inequality: {ops:?}"
                );
            }
            // The predicate is `product != sext_32(trunc_32(product))`.
            assert!(
                ops.iter().any(|ins| matches!(
                    &ins.op,
                    Op::Trunc { from, to, .. } if *from == Width::W64 && *to == Width::W32
                )),
                "{name} imul never truncates the wide product: {ops:?}"
            );
            assert!(
                ops.iter().any(|ins| matches!(
                    &ins.op,
                    Op::SExt { from, to, .. } if *from == Width::W32 && *to == Width::W64
                )),
                "{name} imul never sign-extends the truncated product: {ops:?}"
            );
        }
    }

    /// A 64-bit IMUL's intermediate product is 128 bits wide, which no IR value
    /// can hold, so those two flags stay honest poison rather than a wrong answer.
    #[test]
    fn sixty_four_bit_imul_keeps_cf_and_of_poisoned() {
        // imul %rsi,%rax  (48 0f af c6)
        let ops = lift64(&[0x48, 0x0f, 0xaf, 0xc6]);
        for flag in [Flag::C, Flag::O] {
            assert!(
                ops.iter().any(
                    |ins| matches!(&ins.op, Op::Undef { dst, .. } if *dst == VReg::Flag(flag))
                ),
                "64-bit imul should still poison {flag:?}: {ops:?}"
            );
        }
    }

    #[test]
    fn three_operand_imul_from_a_register_still_lifts_to_one_op() {
        // imul $0x5,%ecx,%eax  (6b c1 05)
        let ops = lift64(&[0x6b, 0xc1, 0x05]);
        match &ops
            .iter()
            .find(|ins| matches!(ins.op, Op::Bin { op: BinOp::Mul, .. }))
            .expect("multiply")
            .op
        {
            Op::Bin {
                op: BinOp::Mul,
                rhs: Value::Const(5),
                ..
            } => {}
            other => panic!("expected a multiply by 5, got {other:?}"),
        }
    }

    #[test]
    fn xor_self_is_recognised_as_xor() {
        // xor eax, eax  (31 c0)
        let ops = lift64(&[0x31, 0xc0]);
        assert!(matches!(&ops[0].op, Op::Bin { op: BinOp::Xor, .. }));
    }

    #[test]
    fn push_expands_to_sub_rsp_plus_store() {
        // push rax  (50)
        let ops = lift64(&[0x50]);
        assert_eq!(ops.len(), 2);
        match &ops[0].op {
            Op::Bin {
                dst,
                op: BinOp::Sub,
                rhs: Value::Const(8),
                ..
            } => assert_eq!(*dst, VReg::phys("rsp")),
            other => panic!("expected sub rsp, 8; got {:?}", other),
        }
        assert!(matches!(&ops[1].op, Op::Store { .. }));
    }

    #[test]
    fn pop_expands_to_load_plus_add_rsp() {
        // pop rax  (58)
        let ops = lift64(&[0x58]);
        assert_eq!(ops.len(), 2);
        assert!(matches!(&ops[0].op, Op::Load { .. }));
        match &ops[1].op {
            Op::Bin {
                dst,
                op: BinOp::Add,
                rhs: Value::Const(8),
                ..
            } => assert_eq!(*dst, VReg::phys("rsp")),
            other => panic!("expected add rsp, 8; got {:?}", other),
        }
    }

    #[test]
    fn ret_lifts_to_return() {
        // ret  (c3)
        let ops = lift64(&[0xc3]);
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].op, Op::Return);
    }

    #[test]
    fn call_near_direct_records_target() {
        // call rel32 to 0x1050 (e8 4b 00 00 00) from 0x1000
        // instr length = 5, so target = 0x1000 + 5 + 0x4b = 0x1050
        let ops = lift64(&[0xe8, 0x4b, 0x00, 0x00, 0x00]);
        assert_eq!(ops.len(), 1);
        match &ops[0].op {
            Op::Call {
                target: CallTarget::Direct(addr),
                ..
            } => {
                assert_eq!(*addr, 0x1050);
            }
            other => panic!("expected direct Call, got {:?}", other),
        }
    }

    #[test]
    fn jmp_near_direct_records_target() {
        // jmp rel8 +2  (eb 02)  — from 0x1000, length 2, target = 0x1004
        let ops = lift64(&[0xeb, 0x02]);
        assert_eq!(ops.len(), 1);
        match &ops[0].op {
            Op::Jump { target } => assert_eq!(*target, 0x1004),
            other => panic!("expected Jump, got {:?}", other),
        }
    }

    #[test]
    fn sub_defines_the_flags_a_range_check_branch_reads() {
        // sub $0x7,%rax (48 83 e8 07) — the switch range check. Before this, the
        // arithmetic form emitted no flags at all, so the following `ja` read a
        // stale flag from an unrelated earlier compare.
        let ops = lift64(&[0x48, 0x83, 0xe8, 0x07]);
        let flags: Vec<_> = ops
            .iter()
            .filter_map(|i| match crate::ir::use_def::def_uses(&i.op).0 {
                Some(VReg::Flag(f)) => Some(f),
                _ => None,
            })
            .collect();
        for want in [Flag::Z, Flag::C, Flag::S, Flag::O] {
            assert!(flags.contains(&want), "sub must define {want:?}: {flags:?}");
        }
        // Relational atoms use the pre-subtract operands; ZF uses the written
        // result and therefore follows the Bin.
        let bin_at = ops
            .iter()
            .rposition(|i| matches!(&i.op, Op::Bin { op: BinOp::Sub, .. }))
            .expect("sub must still do the arithmetic");
        let zf_at = ops
            .iter()
            .position(|i| {
                matches!(
                    &i.op,
                    Op::Cmp {
                        dst: VReg::Flag(Flag::Z),
                        ..
                    }
                )
            })
            .expect("ZF present");
        assert!(zf_at > bin_at, "ZF must describe the post-subtract result");
    }

    #[test]
    fn jmp_rip_memory_records_indirect_tail_call_slot() {
        // jmp qword ptr [rip+0x1234] (ff 25 34 12 00 00) from 0x1000 — a PLT-style
        // tail call through an import slot.
        //
        // This is an `IndirectJump`, not a `Call`. It used to lift as a call so the
        // slot address stayed reachable for name resolution, but a jump that lifts
        // to a call tells every consumer control comes back, and it does not. The
        // slot is still recoverable — it is the jump's target — which is what this
        // test actually needs to hold.
        let ops = lift64(&[0xff, 0x25, 0x34, 0x12, 0x00, 0x00]);
        assert_eq!(ops.len(), 2);
        assert!(matches!(
            &ops[0].op,
            Op::Load {
                dst: VReg::Temp(0),
                addr: MemOp {
                    base: None,
                    disp: 0x223a,
                    size: 8,
                    ..
                }
            }
        ));
        assert!(matches!(
            &ops[1].op,
            Op::IndirectJump {
                target: Value::Reg(VReg::Temp(0)),
                index: None,
            }
        ));
    }

    #[test]
    fn call_through_indexed_memory_keeps_the_whole_operand() {
        // call qword ptr [rcx+rax*8] (ff 14 c1) — the ordinary shape of a
        // C++ vtable dispatch, a jump-table-driven callback, and most
        // obfuscated dispatch.
        //
        // This used to lift to `Indirect(Addr(memory_displacement64()))`,
        // i.e. `Addr(0)`, because base/index/scale live nowhere in a
        // `CallTarget`. Every consumer downstream then reasoned about a
        // resolved call to address zero and none of them could tell it was
        // fiction. The dereference must be explicit, exactly as it is for
        // `jmp *[mem]`, so the dispatch table survives to the passes that
        // recover it.
        let ops = lift64(&[0xff, 0x14, 0xc1]);
        assert_eq!(ops.len(), 2, "expected Load + Call, got {ops:?}");
        match &ops[0].op {
            Op::Load {
                dst: VReg::Temp(0),
                addr,
            } => {
                assert_eq!(addr.base, Some(VReg::phys("rcx")));
                assert_eq!(addr.index, Some(VReg::phys("rax")));
                assert_eq!(addr.scale, 8);
                assert_eq!(addr.disp, 0);
                assert_eq!(addr.size, 8);
            }
            other => panic!("expected a Load of the call slot, got {other:?}"),
        }
        assert!(matches!(
            &ops[1].op,
            Op::Call {
                target: CallTarget::Indirect(Value::Reg(VReg::Temp(0))),
                effects: None,
            }
        ));
        // The registers forming the effective address must be reported as
        // reads of this machine instruction; otherwise DCE deletes the index
        // arithmetic that selects the callee.
        let (_, uses) = crate::ir::use_def::def_uses(&ops[0].op);
        assert!(uses.contains(&VReg::phys("rcx")), "base must be a use");
        assert!(uses.contains(&VReg::phys("rax")), "index must be a use");
    }

    #[test]
    fn call_through_rip_memory_targets_the_loaded_pointer_not_the_slot() {
        // call qword ptr [rip+0x1234] (ff 15 34 12 00 00) from 0x1000 — a
        // PLT-less indirect call through a GOT slot. Instruction length is 6,
        // so the slot is 0x1006 + 0x1234 = 0x223a. The callee is the CONTENTS
        // of that slot, not the slot, which is what naming the displacement as
        // the target claimed.
        let ops = lift64(&[0xff, 0x15, 0x34, 0x12, 0x00, 0x00]);
        assert_eq!(ops.len(), 2, "expected Load + Call, got {ops:?}");
        assert!(matches!(
            &ops[0].op,
            Op::Load {
                dst: VReg::Temp(0),
                addr: MemOp {
                    base: None,
                    index: None,
                    disp: 0x223a,
                    size: 8,
                    ..
                }
            }
        ));
        assert!(matches!(
            &ops[1].op,
            Op::Call {
                target: CallTarget::Indirect(Value::Reg(VReg::Temp(0))),
                ..
            }
        ));
    }

    #[test]
    fn cmp_emits_architectural_condition_atoms() {
        // cmp rax, rbx (48 39 d8) — all architectural effects replace their
        // previous SSA values. Composite conditions still belong to consumers.
        let ops = lift64(&[0x48, 0x39, 0xd8]);
        assert!(!ops.is_empty(), "cmp must produce flag effects");
        let flags: Vec<_> = ops
            .iter()
            .filter_map(|i| match crate::ir::use_def::def_uses(&i.op).0 {
                Some(dst @ VReg::Flag(_)) => Some(dst),
                _ => None,
            })
            .collect();
        for want in [
            VReg::Flag(Flag::Z),
            VReg::Flag(Flag::C),
            VReg::Flag(Flag::S),
            VReg::Flag(Flag::O),
            VReg::Flag(Flag::P),
            VReg::Flag(Flag::A),
        ] {
            assert!(flags.contains(&want), "missing {:?} in {:?}", want, flags);
        }
    }

    #[test]
    fn js_after_test_reads_raw_sign_flag() {
        // test rax, rax (48 85 c0) ; js +2 (78 02)
        let ops = lift_bytes(&[0x48, 0x85, 0xc0, 0x78, 0x02], 0x1000, 64);
        let cj = ops
            .iter()
            .find_map(|i| match &i.op {
                Op::CondJump { cond, .. } => Some(cond.clone()),
                _ => None,
            })
            .expect("expected CondJump");
        assert_eq!(cj, VReg::Flag(Flag::S));
        // And `test` itself must have written %sf.
        assert!(ops.iter().any(|i| matches!(
            &i.op,
            Op::Cmp {
                dst: VReg::Flag(Flag::S),
                ..
            }
        )));
    }

    #[test]
    fn jle_reads_signed_less_or_equal_flag() {
        // cmp rax, rbx ; jle +2  (48 39 d8 7e 02)
        let ops = lift_bytes(&[0x48, 0x39, 0xd8, 0x7e, 0x02], 0x1000, 64);
        let cj = ops
            .iter()
            .find_map(|i| match &i.op {
                Op::CondJump { cond, target, .. } => Some((cond.clone(), *target)),
                _ => None,
            })
            .expect("expected CondJump");
        assert_eq!(cj.0, VReg::Temp(21));
    }

    #[test]
    fn jl_reads_signed_less_than_flag() {
        // cmp rax, rbx ; jl +2  (48 39 d8 7c 02)
        let ops = lift_bytes(&[0x48, 0x39, 0xd8, 0x7c, 0x02], 0x1000, 64);
        let cj = ops
            .iter()
            .find_map(|i| match &i.op {
                Op::CondJump { cond, .. } => Some(cond.clone()),
                _ => None,
            })
            .expect("expected CondJump");
        assert_eq!(cj, VReg::Temp(20));
    }

    #[test]
    fn je_lifts_to_conditional_jump_on_zf() {
        // cmp rax, rbx ; je +2
        // 48 39 d8 74 02
        let ops = lift_bytes(&[0x48, 0x39, 0xd8, 0x74, 0x02], 0x1000, 64);
        let cj = ops
            .iter()
            .find_map(|i| match &i.op {
                Op::CondJump { cond, target, .. } => Some((cond.clone(), *target)),
                _ => None,
            })
            .expect("expected a CondJump");
        assert_eq!(cj.0, VReg::Flag(Flag::Z));
        // cmp is 3 bytes, je short is 2 bytes, start 0x1000 → je at 0x1003 → target 0x1005 + 2? Let's compute:
        // je is at 0x1003, length 2, disp +2 → target = 0x1003 + 2 + 2 = 0x1007
        assert_eq!(cj.1, 0x1007);
    }

    #[test]
    fn jbe_reads_unsigned_less_or_equal_flag() {
        // cmp rax, rbx ; jbe +2  (48 39 d8 76 02)
        let ops = lift_bytes(&[0x48, 0x39, 0xd8, 0x76, 0x02], 0x1000, 64);
        let cj = ops
            .iter()
            .find_map(|i| match &i.op {
                Op::CondJump { cond, target, .. } => Some((cond.clone(), *target)),
                _ => None,
            })
            .expect("expected CondJump");
        assert_eq!(cj.0, VReg::Temp(20));
        assert_eq!(cj.1, 0x1007);
    }

    #[test]
    fn sete_updates_the_low_byte_of_the_canonical_parent() {
        // sete al  (0f 94 c0)
        let ops = lift64(&[0x0f, 0x94, 0xc0]);
        assert_eq!(ops.len(), 3, "expected parent read/modify/write: {ops:#?}");
        assert!(matches!(
            &ops[0].op,
            Op::Bin {
                dst: VReg::Phys(dst),
                op: BinOp::And,
                lhs: Value::Reg(VReg::Phys(src)),
                rhs: Value::Const(-256),
            } if dst == "rax" && src == "rax"
        ));
        assert!(matches!(
            &ops[1].op,
            Op::Bin {
                dst: VReg::Temp(0),
                op: BinOp::And,
                lhs: Value::Reg(VReg::Flag(Flag::Z)),
                rhs: Value::Const(255),
            }
        ));
        assert!(matches!(
            &ops[2].op,
            Op::Bin {
                dst: VReg::Phys(dst),
                op: BinOp::Or,
                lhs: Value::Reg(VReg::Phys(src)),
                rhs: Value::Reg(VReg::Temp(0)),
            } if dst == "rax" && src == "rax"
        ));
    }

    #[test]
    fn cmovne_lifts_to_a_select_that_reads_its_own_destination() {
        // cmovne rax, rbx  (48 0f 45 c3) — `rax = cond ? rbx : rax`.
        //
        // The old lowering used `Op::CondAssign`, whose destination is a pure DEF:
        // dataflow could not see that the false path keeps the destination's PRIOR
        // value. So the instruction that produced that prior value had no reader,
        // dead-code elimination removed it, and the emitted C conditionally assigned
        // a variable that was otherwise never written.
        //
        // `Op::Ite` is the same operation stated honestly — a three-input select —
        // which makes the old value an explicit use, keeps its producer live, and
        // lowers to a two-armed `if` instead of a one-armed one. `abs(a)`, compiled
        // by gcc -O0 to `neg %edx ; cmovs %eax,%edx`, needs exactly this.
        let ops = lift64(&[0x48, 0x0f, 0x45, 0xc3]);
        assert_eq!(ops.len(), 2, "got: {:#?}", ops);
        match &ops[0].op {
            Op::Cmp {
                dst: VReg::Temp(1),
                op: CmpOp::Eq,
                lhs: Value::Reg(cond),
                rhs: Value::Const(0),
            } => assert_eq!(*cond, VReg::Flag(Flag::Z)),
            other => panic!("expected inverted-condition Cmp, got {:?}", other),
        }
        match &ops[1].op {
            Op::Ite {
                dst,
                cond,
                t: Value::Reg(t),
                e: Value::Reg(e),
                ..
            } => {
                assert_eq!(*dst, VReg::phys("rax"));
                assert_eq!(*cond, VReg::Temp(1));
                assert_eq!(*t, VReg::phys("rbx"), "true arm is the moved source");
                assert_eq!(
                    *e,
                    VReg::phys("rax"),
                    "false arm must READ the destination — that is the whole point"
                );
            }
            other => panic!("expected Ite, got {:?}", other),
        }
    }

    #[test]
    fn xchg_reg_reg_lifts_to_swap_sequence() {
        // xchg rax, rbx  (48 87 d8)
        let ops = lift64(&[0x48, 0x87, 0xd8]);
        assert_eq!(ops.len(), 3, "got: {:#?}", ops);
        assert!(matches!(
            &ops[0].op,
            Op::Assign {
                dst: VReg::Temp(0),
                src: Value::Reg(src),
            } if *src == VReg::phys("rax")
        ));
        assert!(matches!(
            &ops[1].op,
            Op::Assign {
                dst,
                src: Value::Reg(src),
            } if *dst == VReg::phys("rax") && *src == VReg::phys("rbx")
        ));
        assert!(matches!(
            &ops[2].op,
            Op::Assign {
                dst,
                src: Value::Reg(VReg::Temp(0)),
            } if *dst == VReg::phys("rbx")
        ));
    }

    #[test]
    fn rep_stosq_lifts_to_directional_memory_fill_and_exact_output_updates() {
        // rep stosq  (f3 48 ab). The repeat count and direction flag are
        // architectural inputs; one representative store is not equivalent.
        let ops = lift64(&[0xf3, 0x48, 0xab]);
        assert_eq!(ops.len(), 8, "got: {:#?}", ops);
        assert!(matches!(
            &ops[2].op,
            Op::Intrinsic {
                name,
                ins,
                outs,
                reads_mem: false,
                writes_mem: true,
            } if name == "memory.fill.8.word8"
                && ins == &[
                    Value::Reg(VReg::Temp(0)),
                    Value::Reg(VReg::Temp(1)),
                    Value::Reg(VReg::phys("rax")),
                    Value::Reg(VReg::Flag(Flag::D)),
                ]
                && outs.is_empty()
        ));
        assert!(matches!(
            &ops[6].op,
            Op::Bin {
                dst,
                op: BinOp::Add,
                lhs: Value::Reg(lhs),
                rhs: Value::Reg(VReg::Temp(4)),
            } if *dst == VReg::phys("rdi") && *lhs == VReg::phys("rdi")
        ));
        assert!(matches!(
            &ops[7].op,
            Op::Assign {
                dst,
                src: Value::Const(0),
            } if *dst == VReg::phys("rcx")
        ));

        // F2 is architecturally the same count-controlled repeat for STOS;
        // only compare-based string instructions give REPNE distinct stopping
        // semantics.
        let repne = lift64(&[0xf2, 0x48, 0xab]);
        assert_eq!(repne.len(), 8, "got: {:#?}", repne);
        assert!(matches!(
            &repne[2].op,
            Op::Intrinsic { name, .. } if name == "memory.fill.8.word8"
        ));
    }

    /// `rep movsq` — the largest single shape behind `movsq`'s 134 census
    /// entries, and the whole reason the string moves needed an arm.
    ///
    /// The contract is deliberately the OPPOSITE of `rep stos`' on one point.
    /// `stos` writes memory and its `memory.fill` intrinsic carries empty
    /// `outs` because it has no register result of its own; `movs` writes
    /// memory AND steps two pointers, so the empty-`outs` intrinsic here is the
    /// memory effect only and the RDI/RSI/RCX updates beside it are what makes
    /// the lift honest. Inheriting `stos`' empty `outs` without them is exactly
    /// the bug this closes.
    #[test]
    fn rep_movsq_declares_both_pointers_and_drains_the_count() {
        // rep movsq  (f3 48 a5).
        let ops = lift64(&[0xf3, 0x48, 0xa5]);
        assert_eq!(ops.len(), 10, "got: {ops:#?}");

        // Private cursors, snapshotted before anything architectural moves.
        assert!(matches!(
            &ops[0].op,
            Op::Assign { dst: VReg::Temp(0), src: Value::Reg(src) } if *src == VReg::phys("rdi")
        ));
        assert!(matches!(
            &ops[1].op,
            Op::Assign { dst: VReg::Temp(1), src: Value::Reg(src) } if *src == VReg::phys("rsi")
        ));
        assert!(matches!(
            &ops[2].op,
            Op::Assign { dst: VReg::Temp(2), src: Value::Reg(src) } if *src == VReg::phys("rcx")
        ));
        assert!(
            matches!(
                &ops[3].op,
                Op::Intrinsic {
                    name,
                    ins,
                    outs,
                    reads_mem: true,
                    writes_mem: true,
                } if name == "memory.copy.8.word8"
                    && ins == &[
                        Value::Reg(VReg::Temp(0)),
                        Value::Reg(VReg::Temp(1)),
                        Value::Reg(VReg::Temp(2)),
                        Value::Reg(VReg::Flag(Flag::D)),
                    ]
                    && outs.is_empty()
            ),
            "got: {ops:#?}"
        );

        // Both pointers advance by the SAME signed byte count -- x86 has one
        // direction flag, not one per pointer -- and the count is drained.
        let defined: Vec<Option<VReg>> = ops
            .iter()
            .map(|instruction| crate::ir::use_def::def_uses(&instruction.op).0)
            .collect();
        for register in ["rdi", "rsi", "rcx"] {
            assert!(
                defined.contains(&Some(VReg::phys(register))),
                "rep movsq did not declare its write to {register}: {ops:#?}"
            );
        }
        assert!(matches!(
            &ops[9].op,
            Op::Assign { dst, src: Value::Const(0) } if *dst == VReg::phys("rcx")
        ));
        let step = match &ops[8].op {
            Op::Bin {
                dst,
                op: BinOp::Add,
                lhs: Value::Reg(lhs),
                rhs: Value::Reg(step),
            } if *dst == VReg::phys("rsi") && *lhs == VReg::phys("rsi") => step.clone(),
            other => panic!("rsi was not stepped: {other:#?} in {ops:#?}"),
        };
        assert!(
            matches!(
                &ops[7].op,
                Op::Bin {
                    dst,
                    op: BinOp::Add,
                    lhs: Value::Reg(lhs),
                    rhs: Value::Reg(other),
                } if *dst == VReg::phys("rdi") && *lhs == VReg::phys("rdi") && *other == step
            ),
            "rdi and rsi must share one directional step: {ops:#?}"
        );
        // That step is the direction flag's, not a hardcoded sign.
        assert!(matches!(
            &ops[6].op,
            Op::Ite { dst, cond: VReg::Flag(Flag::D), .. } if *dst == step
        ));

        // REPNE repeats identically: MOVS writes no flags, so there is no ZF
        // for F2 to terminate on.
        assert!(matches!(
            &lift64(&[0xf2, 0x48, 0xa5])[3].op,
            Op::Intrinsic { name, .. } if name == "memory.copy.8.word8"
        ));
    }

    /// The single-step string move is a different instruction in effect: RCX is
    /// neither read nor written, and exactly one element moves.
    #[test]
    fn a_single_step_movs_moves_one_element_and_touches_no_count() {
        for (bytes, width) in [
            (&[0xa4][..], 1u8),     // movsb
            (&[0x66, 0xa5][..], 2), // movsw
            (&[0xa5][..], 4),       // movsd (the STRING one)
            (&[0x48, 0xa5][..], 8), // movsq
        ] {
            let ops = lift64(bytes);
            assert_eq!(ops.len(), 5, "{bytes:02x?}: {ops:#?}");
            assert!(
                matches!(
                    &ops[0].op,
                    Op::Load { dst: VReg::Temp(0), addr }
                        if addr.base == Some(VReg::phys("rsi")) && addr.size == width
                ),
                "{bytes:02x?}: {ops:#?}"
            );
            assert!(
                matches!(
                    &ops[1].op,
                    Op::Store { addr, src: Value::Reg(VReg::Temp(0)) }
                        if addr.base == Some(VReg::phys("rdi")) && addr.size == width
                ),
                "{bytes:02x?}: {ops:#?}"
            );
            assert!(
                matches!(
                    &ops[2].op,
                    Op::Ite {
                        dst: VReg::Temp(1),
                        cond: VReg::Flag(Flag::D),
                        t: Value::Const(back),
                        e: Value::Const(forward),
                        ..
                    } if *back == -i64::from(width) && *forward == i64::from(width)
                ),
                "{bytes:02x?}: {ops:#?}"
            );
            let touches_count = ops.iter().any(|instruction| {
                let (defined, used) = crate::ir::use_def::def_uses(&instruction.op);
                defined == Some(VReg::phys("rcx")) || used.contains(&VReg::phys("rcx"))
            });
            assert!(
                !touches_count,
                "an unrepeated string move must not read or write RCX: {ops:#?}"
            );
        }
    }

    /// `movsd` names two unrelated instructions. Only the `Code` separates the
    /// dword string move from the SSE scalar double move, and dispatching on
    /// the mnemonic alone would give one of them the other's semantics.
    #[test]
    fn the_dword_string_move_and_the_sse_scalar_move_stay_apart() {
        // a5 -- MOVSD m32, m32: a string move, so RSI/RDI step.
        let string_form = lift64(&[0xa5]);
        assert!(
            string_form.iter().any(|instruction| matches!(
                &instruction.op,
                Op::Bin { dst, .. } if *dst == VReg::phys("rsi")
            )),
            "got: {string_form:#?}"
        );
        // f2 0f 10 c1 -- MOVSD xmm0, xmm1: a scalar float move, which must not
        // have acquired a pointer step.
        let scalar_form = lift64(&[0xf2, 0x0f, 0x10, 0xc1]);
        assert!(
            !scalar_form.iter().any(|instruction| {
                let (defined, _) = crate::ir::use_def::def_uses(&instruction.op);
                defined == Some(VReg::phys("rsi")) || defined == Some(VReg::phys("rdi"))
            }),
            "the SSE scalar move took the string arm: {scalar_form:#?}"
        );
    }

    /// `aesenc` — 222 occurrences, the largest single entry the census had.
    ///
    /// The judgement here is that the AES round function is not worth modelling
    /// and that saying nothing is not the alternative. Four single-output
    /// intrinsics declare which XMM lanes are written and which are read; the
    /// destination is snapshotted first because the round reads its own old
    /// value.
    #[test]
    fn aesenc_declares_the_lanes_it_writes_without_modelling_the_round() {
        // aesenc xmm0, xmm1  (66 0f 38 dc c1).
        let ops = lift64_lanes(&[0x66, 0x0f, 0x38, 0xdc, 0xc1]);
        let mut written: Vec<String> = Vec::new();
        for instruction in &ops {
            if let Op::Intrinsic {
                name, ins, outs, ..
            } = &instruction.op
            {
                assert_eq!(outs.len(), 1, "multi-output intrinsic: {ops:#?}");
                assert!(name.starts_with("x86.aesenc.lane"), "got: {name}");
                // Both operands' four lanes: the round is a function of all of
                // them, and claiming otherwise would be a narrower lie than the
                // one this replaces.
                assert_eq!(ins.len(), 8, "{ops:#?}");
                written.push(match &outs[0].0 {
                    VReg::Phys(name) => name.clone(),
                    other => panic!("non-physical destination {other:?}"),
                });
            }
        }
        assert_eq!(
            written,
            vec!["xmm0_d0", "xmm0_d1", "xmm0_d2", "xmm0_d3"],
            "got: {ops:#?}"
        );
        // Nothing left over claiming to know nothing.
        assert!(
            !ops.iter()
                .any(|instruction| matches!(&instruction.op, Op::Unknown { .. })),
            "got: {ops:#?}"
        );
    }

    #[test]
    fn cmpxchg_reg_reg_lifts_to_compare_and_conditional_updates() {
        // cmpxchg rbx, rcx  (48 0f b1 cb)
        let ops = lift64(&[0x48, 0x0f, 0xb1, 0xcb]);
        assert!(matches!(
            &ops[0].op,
            Op::Assign {
                dst: VReg::Temp(0),
                src: Value::Reg(src),
            } if *src == VReg::phys("rbx")
        ));
        assert!(ops.iter().any(|ins| matches!(
            &ins.op,
            Op::Cmp {
                dst: VReg::Flag(Flag::Z),
                op: CmpOp::Eq,
                lhs: Value::Reg(lhs),
                rhs: Value::Reg(VReg::Temp(0)),
            } if *lhs == VReg::phys("rax")
        )));
        assert!(ops.iter().any(|ins| matches!(
            &ins.op,
            Op::Ite {
                dst,
                cond: VReg::Flag(Flag::Z),
                t: Value::Reg(t),
                e: Value::Reg(e),
                width: Width::W64,
            } if *dst == VReg::phys("rbx")
                && *t == VReg::phys("rcx")
                && *e == VReg::phys("rbx")
        )));
        assert!(matches!(
            &ops.last().expect("accumulator update").op,
            Op::Ite {
                dst,
                cond: VReg::Temp(2),
                t: Value::Reg(VReg::Temp(0)),
                e: Value::Reg(e),
                width: Width::W64,
            } if *dst == VReg::phys("rax")
                && *e == VReg::phys("rax")
        ));
    }

    #[test]
    fn cmpxchg_mem_reg_lifts_to_conditional_store_shape() {
        // cmpxchg qword ptr [rip+0x10], rcx  (48 0f b1 0d 10 00 00 00)
        let ops = lift64(&[0x48, 0x0f, 0xb1, 0x0d, 0x10, 0x00, 0x00, 0x00]);
        assert!(matches!(
            &ops[0].op,
            Op::Load {
                dst: VReg::Temp(0),
                addr: MemOp { size: 8, .. },
            }
        ));
        assert!(ops.iter().any(|ins| matches!(
            &ins.op,
            Op::CondStore {
                cond: VReg::Flag(Flag::Z),
                inverted: false,
                addr: MemOp { size: 8, .. },
                src: Value::Reg(src),
            } if *src == VReg::phys("rcx")
        )));
        assert!(
            ops.iter().all(|ins| !matches!(&ins.op, Op::Store { .. })),
            "cmpxchg failure must not perform an unconditional store: {ops:#?}"
        );
        assert!(matches!(
            &ops.last().expect("accumulator update").op,
            Op::Ite {
                dst,
                cond: VReg::Temp(2),
                t: Value::Reg(VReg::Temp(0)),
                e: Value::Reg(e),
                width: Width::W64,
            } if *dst == VReg::phys("rax")
                && *e == VReg::phys("rax")
        ));
    }

    #[test]
    fn int3_lifts_to_nop() {
        let ops = lift64(&[0xcc]);
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].op, Op::Nop);
    }

    #[test]
    fn div_reg_snapshots_inputs_and_lifts_both_outputs_independently() {
        // div rcx  (48 f7 f1) → unsigned rdx:rax / rcx, quotient→rax,
        // remainder→rdx. Each semantic output has one SSA definition; both
        // consume snapshots taken before either architectural output changes.
        let ops = lift64(&[0x48, 0xf7, 0xf1]);
        let arithmetic: Vec<&Op> = ops
            .iter()
            .map(|instruction| &instruction.op)
            .filter(|op| !matches!(op, Op::Undef { .. }))
            .collect();
        assert_eq!(arithmetic.len(), 5, "got: {arithmetic:#?}");
        assert!(matches!(
            arithmetic[0],
            Op::Assign { dst: VReg::Temp(70), src: Value::Reg(src) }
                if *src == VReg::phys("rdx")
        ));
        assert!(matches!(
            arithmetic[1],
            Op::Assign { dst: VReg::Temp(71), src: Value::Reg(src) }
                if *src == VReg::phys("rax")
        ));
        assert!(matches!(
            arithmetic[2],
            Op::Assign { dst: VReg::Temp(72), src: Value::Reg(src) }
                if *src == VReg::phys("rcx")
        ));
        for (op, name, output) in [
            (arithmetic[3], "x86.udiv_quot.64", "rax"),
            (arithmetic[4], "x86.udiv_rem.64", "rdx"),
        ] {
            assert!(
                matches!(
                    op,
                    Op::Intrinsic { name: got, ins, outs, .. }
                        if got == name
                            && *ins == vec![
                                Value::Reg(VReg::Temp(70)),
                                Value::Reg(VReg::Temp(71)),
                                Value::Reg(VReg::Temp(72)),
                            ]
                            && *outs == vec![(VReg::phys(output), Width::W64)]
                ),
                "got: {op:#?}"
            );
        }
    }

    /// The 16-bit accumulator pair is `dx:ax`, and both are BIT-PRESERVING views.
    ///
    /// `regview::ssa_parent` deliberately refuses to merge such a view with its
    /// parent, so a bare `%dx` read is a read of a name no `mov edx, 0` ever
    /// defines. Lifting it that way is exactly how
    /// `185_subword_signed_division:divide_unsigned_shorts` came to render an
    /// undeclared `var3` as the high half of its dividend. Each half must be
    /// extracted from its parent instead.
    #[test]
    fn div_at_sixteen_bits_reads_its_accumulator_halves_out_of_their_parents() {
        // div cx  (66 f7 f1) → unsigned dx:ax / cx.
        let ops = lift64(&[0x66, 0xf7, 0xf1]);
        let reads_bare_view = ops.iter().any(|instruction| {
            matches!(&instruction.op, Op::Assign { src: Value::Reg(source), .. }
                if *source == VReg::phys("dx") || *source == VReg::phys("ax"))
        });
        assert!(
            !reads_bare_view,
            "a 16-bit divide must not read `dx`/`ax` as bare names: {ops:#?}"
        );
        for (temp, parent) in [(VReg::Temp(70), "rdx"), (VReg::Temp(71), "rax")] {
            assert!(
                ops.iter().any(|instruction| matches!(
                    &instruction.op,
                    Op::Bin {
                        dst,
                        op: BinOp::And,
                        lhs: Value::Reg(source),
                        rhs: Value::Const(0xffff),
                    } if *dst == temp && *source == VReg::phys(parent)
                )),
                "missing `{temp:?} = {parent} & 0xffff` snapshot: {ops:#?}"
            );
        }
    }

    /// `mov ax, dx` — a register-to-register move whose SOURCE is a bit-preserving
    /// view.
    ///
    /// The memory-destination and `movzx`/`movsx` forms already extracted such a
    /// source from its parent; this arm did not, so the read named a register the
    /// SSA layer never sees defined. It is how clang's sub-word remainder
    /// (`cdq; idiv ecx; mov ax, dx`) rendered `var10` in
    /// `185_subword_signed_division:remainder_signed_shorts`.
    #[test]
    fn a_sixteen_bit_register_move_extracts_its_source_from_the_parent() {
        // mov ax, dx  (66 89 d0)
        let ops = lift64(&[0x66, 0x89, 0xd0]);
        assert!(
            !ops.iter().any(|instruction| matches!(
                &instruction.op,
                Op::Assign { src: Value::Reg(source), .. } | Op::Bin { rhs: Value::Reg(source), .. }
                    if *source == VReg::phys("dx")
            )),
            "the source view must not survive as a bare `dx` read: {ops:#?}"
        );
        assert!(
            ops.iter().any(|instruction| matches!(
                &instruction.op,
                Op::Bin {
                    dst,
                    op: BinOp::And,
                    lhs: Value::Reg(source),
                    rhs: Value::Const(0xffff),
                } if *dst == VReg::Temp(76) && *source == VReg::phys("rdx")
            )),
            "missing `Temp(76) = rdx & 0xffff` extraction: {ops:#?}"
        );
        // The destination is still a read-modify-write of `rax`, not a clobber.
        assert!(
            ops.iter().any(|instruction| matches!(
                &instruction.op,
                Op::Bin { dst, op: BinOp::And, rhs: Value::Const(mask), .. }
                    if *dst == VReg::phys("rax") && *mask as u64 == 0xffff_ffff_ffff_0000
            )),
            "the 16-bit destination must preserve the parent's other bits: {ops:#?}"
        );
    }

    /// A full-width register move keeps its single `Assign`: the extraction above
    /// must not fire for names that already ARE their canonical parent.
    #[test]
    fn a_full_width_register_move_stays_one_assignment() {
        // mov rax, rdx  (48 89 d0)
        let ops = lift64(&[0x48, 0x89, 0xd0]);
        assert_eq!(ops.len(), 1, "got: {ops:#?}");
        assert!(matches!(
            &ops[0].op,
            Op::Assign { dst, src: Value::Reg(source) }
                if *dst == VReg::phys("rax") && *source == VReg::phys("rdx")
        ));
    }

    /// The same rule for the one-operand multiply, whose accumulator at 16 bits is
    /// `ax` — likewise bit-preserving, likewise invisible to the SSA layer.
    #[test]
    fn mul_at_sixteen_bits_reads_its_accumulator_out_of_its_parent() {
        // mul cx  (66 f7 e1) → dx:ax = ax * cx.
        let ops = lift64(&[0x66, 0xf7, 0xe1]);
        assert!(
            !ops.iter().any(|instruction| matches!(
                &instruction.op,
                Op::Assign { src: Value::Reg(source), .. } if *source == VReg::phys("ax")
            )),
            "a 16-bit multiply must not read `ax` as a bare name: {ops:#?}"
        );
        assert!(
            ops.iter().any(|instruction| matches!(
                &instruction.op,
                Op::Bin {
                    dst,
                    op: BinOp::And,
                    lhs: Value::Reg(source),
                    rhs: Value::Const(0xffff),
                } if *dst == VReg::Temp(60) && *source == VReg::phys("rax")
            )),
            "missing `Temp(60) = rax & 0xffff` snapshot: {ops:#?}"
        );
    }

    /// Every op an instruction lifted to, flags and poison stripped.
    fn arithmetic_ops(bytes: &[u8]) -> Vec<Op> {
        lift64(bytes)
            .into_iter()
            .map(|instruction| instruction.op)
            .filter(|op| !matches!(op, Op::Undef { .. }))
            .collect()
    }

    /// Does any op DEFINE `name` as a bare physical register?
    fn defines_bare(ops: &[Op], name: &str) -> bool {
        ops.iter().any(|op| {
            crate::ir::use_def::defs_uses(op)
                .0
                .contains(&VReg::phys(name))
        })
    }

    /// Is `parent = parent & mask` present — one half of a masked deposit?
    fn masks_parent(ops: &[Op], parent: &str, mask: i64) -> bool {
        ops.iter().any(|op| {
            matches!(op, Op::Bin { dst, op: BinOp::And, lhs: Value::Reg(source), rhs: Value::Const(m) }
                if *dst == VReg::phys(parent) && *source == VReg::phys(parent) && *m == mask)
        })
    }

    /// `mul r/m8` writes its WHOLE 16-bit product to `AX` — SDM Vol. 2A, MUL —
    /// so the "pair" is `ah:al`, two byte views of one parent, and there is no
    /// second register. Until this width had an arm at all the instruction fell
    /// to the unhandled path: gcc's `uint8_t / 3u` is
    /// `mov $0xffffffab,%edx ; mul %dl ; shr $0x8,%ax ; shr $1,%dl`, and the
    /// reciprocal 0xAB appeared nowhere in the recovered C
    /// (`194_narrow_return_widths:gcc:O0:nrw194_u8_mix`).
    #[test]
    fn eight_bit_mul_writes_both_product_bytes_through_rax() {
        // mul dl  (f6 e2) → AX = AL * DL.
        let ops = arithmetic_ops(&[0xf6, 0xe2]);
        assert!(
            ops.iter().any(|op| matches!(
                op,
                Op::Bin {
                    dst,
                    op: BinOp::Mul,
                    lhs: Value::Reg(VReg::Temp(60)),
                    rhs: Value::Reg(VReg::Temp(61)),
                } if *dst == VReg::Temp(62)
            )),
            "missing low product: {ops:#?}"
        );
        assert!(
            ops.iter().any(|op| matches!(
                op,
                Op::Intrinsic { name, ins, outs, .. }
                    if name == "x86.umul_hi.8"
                        && *ins == vec![
                            Value::Reg(VReg::Temp(60)),
                            Value::Reg(VReg::Temp(61)),
                        ]
                        && *outs == vec![(VReg::Temp(63), Width::W8)]
            )),
            "missing high product: {ops:#?}"
        );
        // Neither half may be DEFINED under its own name: `regview::ssa_parent`
        // keeps `al`/`ah` separate from `rax`, and every read of either is
        // lowered as an extract from `rax`, so such a definition is unreachable.
        for half in ["al", "ah"] {
            assert!(
                !defines_bare(&ops, half),
                "`{half}` was defined as a bare name: {ops:#?}"
            );
        }
        // Both bytes are deposited into `rax`: bits 0..7 keep 0xFF..FF00,
        // bits 8..15 keep 0xFF..00FF.
        assert!(
            masks_parent(&ops, "rax", -256) && masks_parent(&ops, "rax", -65281),
            "both product bytes must be deposited into rax: {ops:#?}"
        );
    }

    /// `div r/m8` divides `AX` — not a register pair — leaving the quotient in
    /// `AL` and the remainder in `AH` (SDM Vol. 2A, DIV). Both halves are read
    /// out of `rax` and both are deposited back into it.
    /// `185_subword_signed_division:gcc:O0:divide_unsigned_bytes` is the lane.
    #[test]
    fn eight_bit_div_reads_and_writes_both_accumulator_bytes_through_rax() {
        // div dl  (f6 f2) → AL = AX / DL, AH = AX % DL.
        let ops = arithmetic_ops(&[0xf6, 0xf2]);
        // The dividend halves: `ah` is (rax >> 8) & 0xff, `al` is rax & 0xff.
        assert!(
            ops.iter().any(|op| matches!(
                op,
                Op::Bin { dst, op: BinOp::Shr, lhs: Value::Reg(source), rhs: Value::Const(8) }
                    if *dst == VReg::Temp(70) && *source == VReg::phys("rax")
            )),
            "missing `ah` snapshot out of rax: {ops:#?}"
        );
        assert!(
            ops.iter().any(|op| matches!(
                op,
                Op::Bin { dst, op: BinOp::And, lhs: Value::Reg(source), rhs: Value::Const(0xff) }
                    if *dst == VReg::Temp(71) && *source == VReg::phys("rax")
            )),
            "missing `al` snapshot out of rax: {ops:#?}"
        );
        let inputs = vec![
            Value::Reg(VReg::Temp(70)),
            Value::Reg(VReg::Temp(71)),
            Value::Reg(VReg::Temp(72)),
        ];
        for (intrinsic, scratch) in [
            ("x86.udiv_quot.8", VReg::Temp(73)),
            ("x86.udiv_rem.8", VReg::Temp(74)),
        ] {
            assert!(
                ops.iter().any(|op| matches!(
                    op,
                    Op::Intrinsic { name, ins, outs, .. }
                        if name == intrinsic
                            && *ins == inputs
                            && *outs == vec![(scratch.clone(), Width::W8)]
                )),
                "missing {intrinsic}: {ops:#?}"
            );
        }
        for half in ["al", "ah"] {
            assert!(
                !defines_bare(&ops, half),
                "`{half}` was defined as a bare name: {ops:#?}"
            );
        }
        assert!(
            masks_parent(&ops, "rax", -256) && masks_parent(&ops, "rax", -65281),
            "quotient and remainder must both be deposited into rax: {ops:#?}"
        );
    }

    /// The write-side twin of
    /// [`div_at_sixteen_bits_reads_its_accumulator_halves_out_of_their_parents`].
    ///
    /// Reading `dx`/`ax` out of their parents was only half the fix: the
    /// quotient was still DEPOSITED under the bare name `ax`, which no reader
    /// can reach for exactly the same reason. `divide_unsigned_shorts` rendered
    /// `return dividend;` — the `divw` gone without a trace — for four months
    /// after the read side was corrected.
    #[test]
    fn div_at_sixteen_bits_deposits_its_results_into_their_parents() {
        // div cx  (66 f7 f1) → unsigned dx:ax / cx.
        let ops = arithmetic_ops(&[0x66, 0xf7, 0xf1]);
        for half in ["ax", "dx"] {
            assert!(
                !defines_bare(&ops, half),
                "`{half}` was defined as a bare name: {ops:#?}"
            );
        }
        // A 16-bit deposit keeps bits 16..63 of its own parent.
        assert!(
            masks_parent(&ops, "rax", -65536) && masks_parent(&ops, "rdx", -65536),
            "quotient and remainder must be deposited into rax/rdx: {ops:#?}"
        );
    }

    /// The 32- and 64-bit halves are canonical SSA names, so their lowerings
    /// must stay direct architectural writes with no deposit at all.
    #[test]
    fn wide_arithmetic_at_canonical_widths_still_writes_its_registers_directly() {
        for (bytes, lo, hi) in [
            (&[0x48, 0xf7, 0xf1][..], "rax", "rdx"), // div rcx
            (&[0xf7, 0xf1][..], "eax", "edx"),       // div ecx
            (&[0x48, 0xf7, 0xe2][..], "rax", "rdx"), // mul rdx
            (&[0xf7, 0xe2][..], "eax", "edx"),       // mul edx
        ] {
            let ops = arithmetic_ops(bytes);
            assert!(
                defines_bare(&ops, lo) && defines_bare(&ops, hi),
                "{lo}/{hi} must still be written directly: {ops:#?}"
            );
        }
    }

    #[test]
    fn idiv_reg_lifts_exact_signed_quotient_and_remainder_outputs() {
        // idiv rcx  (48 f7 f9)
        let ops = lift64(&[0x48, 0xf7, 0xf9]);
        let names: Vec<(&str, &[(VReg, Width)])> = ops
            .iter()
            .filter_map(|instruction| match &instruction.op {
                Op::Intrinsic { name, outs, .. } => Some((name.as_str(), outs.as_slice())),
                _ => None,
            })
            .collect();
        assert_eq!(
            names,
            vec![
                ("x86.sdiv_quot.64", &[(VReg::phys("rax"), Width::W64)][..]),
                ("x86.sdiv_rem.64", &[(VReg::phys("rdx"), Width::W64)][..]),
            ]
        );
    }

    #[test]
    fn one_operand_mul_and_imul_define_low_and_high_halves() {
        for (bytes, high_name) in [
            (&[0x48, 0xf7, 0xe2][..], "x86.umul_hi.64"), // mul rdx
            (&[0x48, 0xf7, 0xea][..], "x86.smul_hi.64"), // imul rdx
        ] {
            let ops = lift64(bytes);
            assert!(
                ops.iter().any(|instruction| matches!(
                    &instruction.op,
                    Op::Bin {
                        dst,
                        op: BinOp::Mul,
                        lhs: Value::Reg(VReg::Temp(60)),
                        rhs: Value::Reg(VReg::Temp(61)),
                    } if *dst == VReg::phys("rax")
                )),
                "missing low product for {high_name}: {ops:#?}"
            );
            assert!(
                ops.iter().any(|instruction| matches!(
                    &instruction.op,
                    Op::Intrinsic { name, ins, outs, .. }
                        if name == high_name
                            && *ins == vec![
                                Value::Reg(VReg::Temp(60)),
                                Value::Reg(VReg::Temp(61)),
                            ]
                            && *outs == vec![(VReg::phys("rdx"), Width::W64)]
                )),
                "missing high product for {high_name}: {ops:#?}"
            );
        }
    }

    /// The one-operand multiplies keep the whole product, so CF/OF answer "does it
    /// fit in `width` bits" — unsigned for MUL, signed for IMUL. At 32 bits that
    /// product fits an IR value, so the flags are real; at 64 bits it is 128 bits
    /// wide and they stay poisoned.
    #[test]
    fn one_operand_multiply_defines_cf_and_of_where_the_product_is_representable() {
        for (bytes, extend_is_signed) in [
            (&[0xf7, 0xe2][..], false), // mul edx
            (&[0xf7, 0xea][..], true),  // imul edx
        ] {
            let ops = lift64(bytes);
            for flag in [Flag::C, Flag::O] {
                assert!(
                    !ops.iter().any(
                        |ins| matches!(&ins.op, Op::Undef { dst, .. } if *dst == VReg::Flag(flag))
                    ),
                    "32-bit wide multiply still poisons {flag:?}: {ops:?}"
                );
                assert!(
                    ops.iter().any(|ins| matches!(
                        &ins.op,
                        Op::Cmp { dst, op: CmpOp::Ne, .. } if *dst == VReg::Flag(flag)
                    )),
                    "32-bit wide multiply does not define {flag:?}: {ops:?}"
                );
            }
            // The fit test re-extends the truncated product with the multiply's own
            // signedness — a zero extension for MUL, a sign extension for IMUL.
            let widens_back = ops.iter().any(|ins| match &ins.op {
                Op::SExt { from, to, .. } if extend_is_signed => {
                    *from == Width::W32 && *to == Width::W64
                }
                Op::ZExt { from, to, .. } if !extend_is_signed => {
                    *from == Width::W32 && *to == Width::W64
                }
                _ => false,
            });
            assert!(widens_back, "wrong signedness in the fit test: {ops:?}");
        }
        // `mul rdx; seto` is how Clang range-checks an allocation size; at 64 bits
        // there is no wide product to take, but the high half is already an output,
        // so CF/OF read `rdx != 0` rather than staying poisoned.
        let wide = lift64(&[0x48, 0xf7, 0xe2]);
        for flag in [Flag::C, Flag::O] {
            assert!(
                wide.iter().any(|ins| matches!(
                    &ins.op,
                    Op::Cmp { dst, op: CmpOp::Ne, lhs: Value::Reg(VReg::Phys(n)), rhs: Value::Const(0) }
                        if *dst == VReg::Flag(flag) && n == "rdx"
                )),
                "64-bit mul should define {flag:?} from the high half: {wide:?}"
            );
        }
        // imul rdx — same width, but the high half must equal the low half's sign.
        let signed_wide = lift64(&[0x48, 0xf7, 0xea]);
        assert!(
            signed_wide.iter().any(|ins| matches!(
                &ins.op,
                Op::Bin { op: BinOp::Sar, lhs: Value::Reg(VReg::Phys(n)), rhs: Value::Const(63), .. }
                    if n == "rax"
            )),
            "64-bit imul should compare the high half against rax's sign: {signed_wide:?}"
        );
    }

    #[test]
    fn cdqe_sign_extends_eax_into_rax() {
        // This test previously asserted `cdqe` lifts to the plain assignment
        // `rax = eax` — it PINNED THE BUG. `cdqe` (AT&T `cltq`) sign-extends; a plain
        // assignment zero-extends, so every negative `int` promoted to `long` became a
        // huge positive, wherever gcc emits it for `int`->`long` conversion and array
        // indexing. Executing the lift is what settles it: see
        // `tests/register_view_semantics.rs::cdqe_sign_extends_a_negative_int_into_the_full_register`.
        let ops = lift64(&[0x48, 0x98]);
        assert_eq!(ops.len(), 1, "got: {ops:#?}");
        assert!(
            matches!(
                &ops[0].op,
                Op::SExt {
                    dst,
                    src: Value::Reg(src),
                    from: Width::W32,
                    to: Width::W64,
                } if *dst == VReg::phys("rax") && *src == VReg::phys("eax")
            ),
            "got: {:?}",
            ops[0].op
        );
    }

    #[test]
    fn cdq_materializes_the_high_dword_from_an_explicit_signed_doubleword() {
        let ops = lift64(&[0x99]); // cdq
        assert_eq!(ops.len(), 2, "got: {ops:#?}");
        assert!(matches!(
            &ops[0].op,
            Op::SExt {
                dst: VReg::Temp(5),
                src: Value::Reg(VReg::Phys(src)),
                from: Width::W32,
                to: Width::W64,
            } if src == "eax"
        ));
        assert!(matches!(
            &ops[1].op,
            Op::Extract {
                dst: VReg::Phys(dst),
                src: Value::Reg(VReg::Temp(5)),
                hi: 64,
                lo: 32,
            } if dst == "edx"
        ));
    }

    /// `shrd eax, edx, 2` is the low word of a 64-bit `>> 2` held in `edx:eax`.
    /// It is exact only if both halves are read at their ENCODED width: `eax`
    /// canonicalises into a 64-bit `rax` whose high half nothing clears, so a
    /// raw `>>` would shift in bits that are not the machine's and a raw `<<`
    /// would produce a value no 32-bit register can hold.
    #[test]
    fn shrd_reads_both_halves_at_their_encoded_thirty_two_bit_width() {
        // 0f ac d0 02 -> shrd eax, edx, 0x2
        let ops: Vec<Op> = lift_bytes(&[0x0f, 0xac, 0xd0, 0x02], 0x1000, 32)
            .into_iter()
            .map(|i| i.op)
            .collect();
        let arithmetic: Vec<&Op> = ops
            .iter()
            .filter(|op| !matches!(op, Op::Undef { .. }))
            .collect();
        assert_eq!(
            arithmetic.len(),
            6,
            "zext, shift, zext, shift, or, mask: {ops:#?}"
        );
        assert!(
            matches!(
                arithmetic[0],
                Op::ZExt { src: Value::Reg(VReg::Phys(n)), from: Width::W32, to: Width::W64, .. }
                    if n == "eax"
            ),
            "the destination half must be read at 32 bits: {ops:#?}"
        );
        assert!(
            matches!(
                arithmetic[1],
                Op::Bin {
                    op: BinOp::Shr,
                    rhs: Value::Const(2),
                    ..
                }
            ),
            "the kept half shifts right by the count: {ops:#?}"
        );
        assert!(
            matches!(
                arithmetic[2],
                Op::ZExt { src: Value::Reg(VReg::Phys(n)), from: Width::W32, to: Width::W64, .. }
                    if n == "edx"
            ),
            "the incoming half must be read at 32 bits: {ops:#?}"
        );
        assert!(
            matches!(
                arithmetic[3],
                Op::Bin {
                    op: BinOp::Shl,
                    rhs: Value::Const(30),
                    ..
                }
            ),
            "the incoming half shifts left by width - count: {ops:#?}"
        );
        assert!(
            matches!(arithmetic[4], Op::Bin { op: BinOp::Or, dst, .. } if *dst == VReg::phys("eax")),
            "the halves join into the destination: {ops:#?}"
        );
        assert!(
            matches!(
                arithmetic[5],
                Op::Bin {
                    op: BinOp::And,
                    rhs: Value::Const(0xffff_ffff),
                    ..
                }
            ),
            "the joined word must stay 32 bits wide: {ops:#?}"
        );
        // A wrong CF would let a later `jb` render a branch the CPU never
        // evaluated; x86 defines it as the last bit shifted out, and this
        // lowering does not compute that.
        assert!(
            ops.iter()
                .any(|op| matches!(op, Op::Undef { dst, .. } if *dst == VReg::Flag(Flag::C))),
            "the unmodelled flags must be undefined, never stale: {ops:#?}"
        );
    }

    /// A count of zero is architecturally a complete no-op — the destination is
    /// unchanged AND the flags are untouched. Emitting the shift chain anyway
    /// would shift by the full width, which is undefined in the C we render.
    #[test]
    fn a_zero_count_double_shift_is_a_nop() {
        let ops: Vec<Op> = lift_bytes(&[0x0f, 0xac, 0xd0, 0x00], 0x1000, 32)
            .into_iter()
            .map(|i| i.op)
            .collect();
        assert_eq!(ops, vec![Op::Nop], "got: {ops:#?}");
    }

    /// Interpret the small, closed subset of LLIR the double shift emits.
    ///
    /// This exists so the `cl`-count lowering can be checked as ARITHMETIC
    /// rather than as a shape. The zero-count case is the one that matters and
    /// the one an op-list assertion cannot see: it is the difference between
    /// "the destination is unchanged" and undefined behaviour in the C this
    /// renders to. Flag definitions are skipped -- they are poison, and this is
    /// about the value.
    fn evaluate_integer_ops(
        ops: &[Op],
        seed: &[(&str, u64)],
    ) -> std::collections::HashMap<VReg, u64> {
        let mut state: std::collections::HashMap<VReg, u64> = seed
            .iter()
            .map(|(name, value)| (VReg::phys(*name), *value))
            .collect();
        fn read(state: &std::collections::HashMap<VReg, u64>, value: &Value) -> u64 {
            match value {
                Value::Const(constant) => *constant as u64,
                Value::Reg(register) => *state
                    .get(register)
                    .unwrap_or_else(|| panic!("read of undefined {register:?}")),
                other => panic!("unsupported operand {other:?}"),
            }
        }
        for op in ops {
            match op {
                Op::Bin { dst, op, lhs, rhs } => {
                    if matches!(dst, VReg::Flag(_)) {
                        continue;
                    }
                    let (lhs, rhs) = (read(&state, lhs), read(&state, rhs));
                    let value = match op {
                        BinOp::And => lhs & rhs,
                        BinOp::Or => lhs | rhs,
                        BinOp::Sub => lhs.wrapping_sub(rhs),
                        BinOp::Shl => lhs.checked_shl(rhs as u32).unwrap_or(0),
                        BinOp::Shr => lhs.checked_shr(rhs as u32).unwrap_or(0),
                        other => panic!("unsupported {other:?}"),
                    };
                    state.insert(dst.clone(), value);
                }
                Op::ZExt { dst, src, from, .. } => {
                    let value = read(&state, src);
                    let mask = match from.bits() {
                        64 => u64::MAX,
                        bits => (1u64 << bits) - 1,
                    };
                    state.insert(dst.clone(), value & mask);
                }
                Op::Assign { dst, src } if !matches!(dst, VReg::Flag(_)) => {
                    let value = read(&state, src);
                    state.insert(dst.clone(), value);
                }
                Op::Assign { .. } | Op::Nop => {}
                // The poisoned flags. This is about the value.
                Op::Undef { dst, .. } if matches!(dst, VReg::Flag(_)) => {}
                other => panic!("unsupported op in a double shift: {other:#?}"),
            }
        }
        state
    }

    /// The `cl`-count double shift, checked against the architecture for EVERY
    /// count rather than for a representative one.
    ///
    /// The zero count is the whole difficulty. `src << (bits - n)` is undefined
    /// C at `n == 0`, and `n == 0` is exactly the architectural no-op the
    /// immediate path answers with `Op::Nop`; a variable count can do neither.
    /// The lowering splits the join into `(src << 1) << (bits - 1 - n)`, which
    /// keeps both amounts inside the operand width and makes the join
    /// contribute zero at `n == 0`. This asserts that claim numerically.
    #[test]
    fn a_variable_count_double_shift_is_exact_at_every_count() {
        // 0f ad d0    -> shrd eax, edx, cl
        // 4c 0f ad da -> shrd rdx, r11, cl   (the form the corpus contains)
        // 0f a5 d0    -> shld eax, edx, cl
        for (bytes, bits, right, dst_name, src_name) in [
            (&[0x0f, 0xad, 0xd0][..], 32u32, true, "eax", "edx"),
            (&[0x4c, 0x0f, 0xad, 0xda][..], 64, true, "rdx", "r11"),
            (&[0x0f, 0xa5, 0xd0][..], 32, false, "eax", "edx"),
        ] {
            let mode = if bits == 64 { 64 } else { 32 };
            let ops: Vec<Op> = lift_bytes(bytes, 0x1000, mode)
                .into_iter()
                .map(|instruction| instruction.op)
                .collect();
            assert!(
                !ops.iter()
                    .any(|op| matches!(op, Op::Unknown { .. } | Op::Intrinsic { .. })),
                "{bytes:02x?} did not lift: {ops:#?}"
            );
            let mask = match bits {
                64 => u64::MAX,
                bits => (1u64 << bits) - 1,
            };
            let destination = 0xdead_beef_cafe_f00du64 & mask;
            let source = 0x0123_4567_89ab_cdefu64 & mask;
            for count in 0..bits {
                let state = evaluate_integer_ops(
                    &ops,
                    &[
                        (dst_name, destination),
                        (src_name, source),
                        // The count arrives through the canonical ECX view.
                        ("ecx", u64::from(count)),
                    ],
                );
                let got = state[&VReg::phys(dst_name)];
                let expected = if count == 0 {
                    destination
                } else if right {
                    ((destination >> count) | (source << (bits - count))) & mask
                } else {
                    ((destination << count) | (source >> (bits - count))) & mask
                };
                assert_eq!(
                    got, expected,
                    "{bytes:02x?} count={count}: got {got:#018x}, want {expected:#018x}"
                );
            }
        }
    }

    /// `bsr` is exactly `(BITS - 1) - clz(x)` for a nonzero operand, and gcc
    /// -O2 emits it for `14_flag_effects:shift_until_zero`. The count must be
    /// taken at the ENCODED width: `eax` canonicalises into a 64-bit `rax`
    /// whose high half nothing clears, so `x86.clz.64` on the raw value would
    /// answer 32 too high.
    #[test]
    fn bsr_is_the_encoded_width_minus_one_less_its_leading_zero_count() {
        // 0f bd c8 -> bsr ecx, eax
        let ops: Vec<Op> = lift_bytes(&[0x0f, 0xbd, 0xc8], 0x1000, 32)
            .into_iter()
            .map(|i| i.op)
            .collect();
        assert!(
            ops.iter().any(|op| matches!(
                op,
                Op::ZExt { src: Value::Reg(VReg::Phys(n)), from: Width::W32, to: Width::W64, .. }
                    if n == "eax"
            )),
            "the source must be read at its encoded 32 bits: {ops:#?}"
        );
        assert!(
            ops.iter().any(|op| matches!(
                op,
                Op::Intrinsic { name, outs, .. }
                    if name == "x86.clz.32" && outs[0].1 == Width::W32
            )),
            "a 32-bit scan counts a 32-bit quantity's leading zeros: {ops:#?}"
        );
        assert!(
            ops.iter().any(|op| matches!(
                op,
                Op::Bin {
                    op: BinOp::Sub,
                    lhs: Value::Const(31),
                    ..
                }
            )),
            "the highest set bit's index is 31 - clz: {ops:#?}"
        );
    }

    /// True when the op names `ecx` (or its 64-bit parent) in any input
    /// position. Used to prove the bit-scan lowering never reads its own
    /// destination before writing it.
    fn reads_ecx(op: &Op) -> bool {
        fn is_ecx(v: &Value) -> bool {
            matches!(v, Value::Reg(VReg::Phys(name)) if name == "ecx" || name == "rcx")
        }
        match op {
            Op::Assign { src, .. } => is_ecx(src),
            Op::Bin { lhs, rhs, .. } | Op::Cmp { lhs, rhs, .. } => is_ecx(lhs) || is_ecx(rhs),
            Op::Un { src, .. } => is_ecx(src),
            Op::Ite { cond, t, e, .. } => {
                matches!(cond, VReg::Phys(name) if name == "ecx" || name == "rcx")
                    || is_ecx(t)
                    || is_ecx(e)
            }
            Op::Intrinsic { ins, .. } => ins.iter().any(is_ecx),
            Op::Load { addr, .. } => addr
                .base
                .as_ref()
                .is_some_and(|b| matches!(b, VReg::Phys(name) if name == "ecx" || name == "rcx")),
            _ => false,
        }
    }

    /// x86's zero case is NOT ARM's, but it is also not AMD's. Intel documents
    /// the DESTINATION as UNDEFINED when the source is zero; only AMD promises
    /// it is preserved. So the count is written unconditionally and ZF — the one
    /// flag x86 defines here, and the one callers actually branch on — carries
    /// the distinction.
    ///
    /// The property this test exists to hold is the absence of a self-read. A
    /// `dst = src ? f(src) : dst` gate makes `dst` live-in on the zero path, and
    /// a live-in physical register sitting in an argument slot is promoted to a
    /// parameter — which gave `shift_until_zero(unsigned int)` four parameters
    /// and an unassigned local read in an arm the guard never selects. Modelling
    /// a value the architecture refuses to define is not worth that.
    #[test]
    fn a_zero_bit_scan_source_sets_zf_without_reading_the_destination() {
        let ops: Vec<Op> = lift_bytes(&[0x0f, 0xbd, 0xc8], 0x1000, 32)
            .into_iter()
            .map(|i| i.op)
            .collect();
        assert!(
            ops.iter().any(|op| matches!(
                op,
                Op::Cmp {
                    dst: VReg::Flag(Flag::Z),
                    op: CmpOp::Eq,
                    rhs: Value::Const(0),
                    ..
                }
            )),
            "ZF is the one flag x86 defines here: {ops:#?}"
        );
        // The destination is written, and nothing anywhere in the lowering reads
        // it first — that read is what parameter recovery mistakes for an
        // incoming argument.
        assert!(
            ops.iter()
                .any(|op| matches!(op, Op::Assign { dst: VReg::Phys(d), .. } if d == "ecx")),
            "the count is written unconditionally: {ops:#?}"
        );
        let defined_at = ops
            .iter()
            .position(|op| matches!(op, Op::Assign { dst: VReg::Phys(d), .. } if d == "ecx"))
            .expect("checked above");
        assert!(
            !ops[..defined_at].iter().any(reads_ecx),
            "no read of the destination may precede its definition: {ops:#?}"
        );
        for flag in [Flag::C, Flag::O, Flag::S, Flag::P, Flag::A] {
            assert!(
                ops.iter()
                    .any(|op| matches!(op, Op::Undef { dst, .. } if *dst == VReg::Flag(flag))),
                "{flag:?} is architecturally undefined and must not go stale: {ops:#?}"
            );
        }
    }

    /// The memory source form loads once and scans the loaded word. Reading the
    /// operand twice would be two loads of an address the ISA dereferences once.
    #[test]
    fn a_memory_source_bit_scan_loads_once() {
        // 0f bd 08 -> bsr ecx, dword ptr [eax]
        let ops: Vec<Op> = lift_bytes(&[0x0f, 0xbd, 0x08], 0x1000, 32)
            .into_iter()
            .map(|i| i.op)
            .collect();
        assert_eq!(
            ops.iter()
                .filter(|op| matches!(op, Op::Load { .. }))
                .count(),
            1,
            "exactly one dereference: {ops:#?}"
        );
        assert!(
            ops.iter().any(|op| matches!(
                op,
                Op::Intrinsic { name, .. } if name == "x86.clz.32"
            )),
            "the loaded word is what gets scanned: {ops:#?}"
        );
    }

    /// `bsf` is the same shape over `x ^ (x - 1)`, whose highest set bit is the
    /// LOWEST set bit of `x`. The identity avoids `x & -x` so that nothing in
    /// the rendered C negates a value.
    #[test]
    fn bsf_scans_the_trailing_zero_mask_rather_than_negating() {
        // 48 0f bc c8 -> bsf rcx, rax
        let ops: Vec<Op> = lift64(&[0x48, 0x0f, 0xbc, 0xc8])
            .into_iter()
            .map(|i| i.op)
            .collect();
        assert!(
            ops.iter().any(|op| matches!(
                op,
                Op::Bin {
                    op: BinOp::Sub,
                    rhs: Value::Const(1),
                    ..
                }
            )),
            "the mask starts from x - 1: {ops:#?}"
        );
        assert!(
            ops.iter()
                .any(|op| matches!(op, Op::Bin { op: BinOp::Xor, .. })),
            "x ^ (x - 1) isolates the trailing-zero run: {ops:#?}"
        );
        assert!(
            !ops.iter()
                .any(|op| matches!(op, Op::Un { op: UnOp::Neg, .. })),
            "nothing may negate: {ops:#?}"
        );
        assert!(
            ops.iter().any(|op| matches!(
                op,
                Op::Intrinsic { name, .. } if name == "x86.clz.64"
            )) && ops.iter().any(|op| matches!(
                op,
                Op::Bin {
                    op: BinOp::Sub,
                    lhs: Value::Const(63),
                    ..
                }
            )),
            "a 64-bit scan counts 64 bits and indexes from 63: {ops:#?}"
        );
    }

    /// The 16-bit form is real, but `ast::write_wide_arithmetic_dec` spells any
    /// sub-64-bit count as `__builtin_clz((unsigned int)(x))` — a count over 32
    /// bits — so `x86.clz.16` would answer 16 too high. Refuse it rather than
    /// emit a wrong index.
    #[test]
    fn a_sixteen_bit_bit_scan_is_not_guessed() {
        // 66 0f bd c8 -> bsr cx, ax
        let ops: Vec<Op> = lift64(&[0x66, 0x0f, 0xbd, 0xc8])
            .into_iter()
            .map(|i| i.op)
            .collect();
        assert_eq!(
            ops,
            vec![Op::Unknown {
                mnemonic: "bsr".into()
            }],
            "got: {ops:#?}"
        );
    }

    // --- the single-bit and bit-count family (`lift_x86::bit_ops`) ----------

    /// Byte encodings of the family, assembled with GNU `as --64` rather than
    /// derived from the modrm tables, and read back with `objdump -d -M intel`.
    mod bit_ops_encodings {
        pub const BTS_RDX_RDI: &[u8] = &[0x48, 0x0f, 0xab, 0xfa];
        pub const BTS_RCX_63: &[u8] = &[0x48, 0x0f, 0xba, 0xe9, 0x3f];
        pub const BTS_ECX_EBX: &[u8] = &[0x0f, 0xab, 0xd9];
        pub const BTR_RCX_RDX: &[u8] = &[0x48, 0x0f, 0xb3, 0xd1];
        pub const BTR_ECX_EBX: &[u8] = &[0x0f, 0xb3, 0xd9];
        pub const BTR_RCX_33: &[u8] = &[0x48, 0x0f, 0xba, 0xf1, 0x21];
        pub const BTC_RCX_RDX: &[u8] = &[0x48, 0x0f, 0xbb, 0xd1];
        pub const BT_RCX_5: &[u8] = &[0x48, 0x0f, 0xba, 0xe1, 0x05];
        pub const TZCNT_ECX_EDX: &[u8] = &[0xf3, 0x0f, 0xbc, 0xca];
        pub const TZCNT_RAX_RDI: &[u8] = &[0xf3, 0x48, 0x0f, 0xbc, 0xc7];
        pub const TZCNT_EAX_MEM: &[u8] = &[0xf3, 0x0f, 0xbc, 0x45, 0xfc];
        pub const POPCNT_RDX_RAX: &[u8] = &[0xf3, 0x48, 0x0f, 0xb8, 0xd0];
        pub const POPCNT_EAX_EDI: &[u8] = &[0xf3, 0x0f, 0xb8, 0xc7];
        pub const MOVLHPS_XMM15_XMM0: &[u8] = &[0x44, 0x0f, 0x16, 0xf8];
        pub const MOVHLPS_XMM1_XMM2: &[u8] = &[0x0f, 0x12, 0xca];
        pub const RCR_RDX_1: &[u8] = &[0x48, 0xd1, 0xda];

        /// Every encoding above, for the properties asserted of the whole set.
        pub const ALL: &[&[u8]] = &[
            BTS_RDX_RDI,
            BTS_RCX_63,
            BTS_ECX_EBX,
            BTR_RCX_RDX,
            BTR_ECX_EBX,
            BTR_RCX_33,
            BTC_RCX_RDX,
            BT_RCX_5,
            TZCNT_ECX_EDX,
            TZCNT_RAX_RDI,
            TZCNT_EAX_MEM,
            POPCNT_RDX_RAX,
            POPCNT_EAX_EDI,
            MOVLHPS_XMM15_XMM0,
            MOVHLPS_XMM1_XMM2,
            RCR_RDX_1,
        ];
    }

    /// The encodings really are the instructions the tests below name them.
    /// A wrong byte would otherwise make every assertion below vacuously true
    /// against some other lowering.
    #[test]
    fn the_bit_operation_encodings_decode_to_their_mnemonics() {
        use bit_ops_encodings as e;
        for (bytes, expected) in [
            (e::BTS_RDX_RDI, "bts rdx,rdi"),
            (e::BTS_RCX_63, "bts rcx,3Fh"),
            (e::BTS_ECX_EBX, "bts ecx,ebx"),
            (e::BTR_RCX_RDX, "btr rcx,rdx"),
            (e::BTR_ECX_EBX, "btr ecx,ebx"),
            (e::BTR_RCX_33, "btr rcx,21h"),
            (e::BTC_RCX_RDX, "btc rcx,rdx"),
            (e::BT_RCX_5, "bt rcx,5"),
            (e::TZCNT_ECX_EDX, "tzcnt ecx,edx"),
            (e::TZCNT_RAX_RDI, "tzcnt rax,rdi"),
            (e::TZCNT_EAX_MEM, "tzcnt eax,[rbp-4]"),
            (e::POPCNT_RDX_RAX, "popcnt rdx,rax"),
            (e::POPCNT_EAX_EDI, "popcnt eax,edi"),
            (e::MOVLHPS_XMM15_XMM0, "movlhps xmm15,xmm0"),
            (e::MOVHLPS_XMM1_XMM2, "movhlps xmm1,xmm2"),
            (e::RCR_RDX_1, "rcr rdx,1"),
        ] {
            let instruction = decode64(bytes);
            let mut text = String::new();
            iced_x86::Formatter::format(
                &mut iced_x86::NasmFormatter::new(),
                &instruction,
                &mut text,
            );
            assert_eq!(text, expected, "{bytes:02x?}");
        }
    }

    /// The point of the whole change: none of these leaves a residue that
    /// declares no register write. This is the census predicate applied to the
    /// single encodings, so it fails on a regression even when the sample
    /// corpus is absent.
    // --- `not` on a bit-preserving partial view --------------------------

    /// `not` on a byte view is a read-modify-write of its canonical PARENT, not
    /// a write to a register of its own.
    ///
    /// [`regview::ssa_parent`] canonicalises the parent and the zero-extending
    /// 32-bit views and nothing else, so `sil` is an SSA name nothing else
    /// mentions: writing it defined a register no reader ever names, and the
    /// next read of `esi`/`rsi` saw the value from before the complement.
    ///
    /// Unlike everything else on the silent-register-write census, this one
    /// never showed up there — `Op::Un` DECLARES its destination, so the census
    /// predicate is satisfied. The write was declared and simply pointed at the
    /// wrong name, which no "does this declare a write" check can see.
    #[test]
    fn not_on_a_byte_view_rewrites_its_parent() {
        // 40 f6 d6 -> not sil
        let ops: Vec<Op> = lift64(&[0x40, 0xf6, 0xd6])
            .into_iter()
            .map(|instruction| instruction.op)
            .collect();
        assert!(
            !ops.iter()
                .any(|op| matches!(op, Op::Un { dst: VReg::Phys(n), .. } if n == "sil")),
            "writing `sil` writes a name no reader of this function mentions: {ops:#?}"
        );
        assert!(
            ops.iter().any(
                |op| matches!(op, Op::Bin { dst: VReg::Phys(n), op: BinOp::Or, .. } if n == "rsi")
            ),
            "the complemented byte must be merged back into `rsi`: {ops:#?}"
        );
        // The upper 56 bits are PRESERVED. That is what makes this a partial
        // write rather than a 64-bit `not` of the parent, which would be just as
        // wrong in the other direction.
        assert!(
            ops.iter().any(|op| matches!(
                op,
                Op::Bin { dst: VReg::Phys(n), op: BinOp::And, rhs: Value::Const(mask), .. }
                    if n == "rsi" && *mask == 0xFFFF_FFFF_FFFF_FF00u64 as i64
            )),
            "bits 8..63 of the parent are kept: {ops:#?}"
        );
        assert!(
            ops.iter()
                .any(|op| matches!(op, Op::Un { op: UnOp::Not, .. })),
            "something must actually complement: {ops:#?}"
        );
    }

    /// The exact three-instruction sequence from
    /// `165_bitstream_reader:clang:O2`, which is where this was found: clang
    /// spells `shift = 7 - (at & 7)` as `mov %r10d,%esi ; not %sil ;
    /// and $0x7,%sil`. The `and` already took the read-modify-write path, so it
    /// read `rsi` — and before this fix picked up the un-complemented copy,
    /// leaving the recovered C computing `at & 7`.
    ///
    /// Asserted as a DATAFLOW property rather than an op list: the value the
    /// masking step reads must be one this sequence produced, not the one
    /// `mov %r10d,%esi` left behind.
    #[test]
    fn the_complement_reaches_the_mask_that_follows_it() {
        let ops: Vec<Op> = lift64(&[
            0x44, 0x89, 0xd6, // mov  %r10d,%esi
            0x40, 0xf6, 0xd6, // not  %sil
            0x40, 0x80, 0xe6, 0x07, // and  $0x7,%sil
        ])
        .into_iter()
        .map(|instruction| instruction.op)
        .collect();

        let complement = ops
            .iter()
            .position(|op| matches!(op, Op::Un { op: UnOp::Not, .. }))
            .expect("the complement must be lifted at all");
        let parent_write = ops
            .iter()
            .position(
                |op| matches!(op, Op::Bin { dst: VReg::Phys(n), op: BinOp::Or, .. } if n == "rsi"),
            )
            .expect("the complement must land in the parent");
        let mask_read = ops
            .iter()
            .skip(parent_write)
            .position(|op| {
                matches!(
                    op,
                    Op::Bin { op: BinOp::And, lhs: Value::Reg(VReg::Phys(n)), .. } if n == "rsi"
                )
            })
            .map(|offset| offset + parent_write)
            .expect("the `and $0x7,%sil` reads the parent");

        assert!(
            complement < parent_write && parent_write < mask_read,
            "the masking step must read a parent the complement has already \
             written; before this fix it read the one `mov %r10d,%esi` left: \
             {ops:#?}"
        );
    }

    /// A full-width `not` still writes its register directly. The partial-view
    /// route must not swallow the ordinary case, whose destination already
    /// canonicalises to the parent on its own.
    #[test]
    fn a_full_width_not_is_left_alone() {
        // 48 f7 d0 -> not rax
        let ops: Vec<Op> = lift64(&[0x48, 0xf7, 0xd0])
            .into_iter()
            .map(|instruction| instruction.op)
            .collect();
        assert_eq!(
            ops,
            vec![Op::Un {
                dst: VReg::phys("rax"),
                op: UnOp::Not,
                src: Value::Reg(VReg::phys("rax")),
            }],
            "got: {ops:#?}"
        );
    }

    #[test]
    fn no_bit_operation_hides_its_register_writes() {
        for bytes in bit_ops_encodings::ALL {
            let ops = lift_one(&decode64(bytes), 64);
            assert!(
                !hides_its_register_writes(&ops),
                "{bytes:02x?} still declares no register write: {ops:#?}"
            );
        }
    }

    /// `bts rdx, rdi` — CF from the ORIGINAL destination, then `dst |= 1 << n`,
    /// with the index taken modulo the operand width.
    #[test]
    fn bts_reads_carry_from_the_value_it_is_about_to_change() {
        let ops: Vec<Op> = lift64(bit_ops_encodings::BTS_RDX_RDI)
            .into_iter()
            .map(|instruction| instruction.op)
            .collect();

        assert!(
            matches!(
                &ops[0],
                Op::Bin { dst: VReg::Temp(200), op: BinOp::And, lhs: Value::Reg(lhs), rhs: Value::Const(63) }
                    if *lhs == VReg::phys("rdi")
            ),
            "got: {ops:#?}"
        );
        assert!(
            matches!(
                &ops[1],
                Op::Bin { dst: VReg::Temp(201), op: BinOp::Shr, lhs: Value::Reg(lhs), rhs: Value::Reg(VReg::Temp(200)) }
                    if *lhs == VReg::phys("rdx")
            ),
            "got: {ops:#?}"
        );
        assert!(
            matches!(
                &ops[2],
                Op::Bin {
                    dst: VReg::Flag(Flag::C),
                    op: BinOp::And,
                    lhs: Value::Reg(VReg::Temp(201)),
                    rhs: Value::Const(1)
                }
            ),
            "got: {ops:#?}"
        );
        assert!(
            matches!(
                &ops[3],
                Op::ZExt {
                    dst: VReg::Temp(202),
                    src: Value::Const(1),
                    from: Width::W8,
                    to: Width::W64
                }
            ),
            "the mask literal is widened to the operand width BEFORE the shift: \
             an unadorned `1` is an `int` in the recovered C, so `1 << 40` there \
             is undefined and the host answers `1 << 8`: {ops:#?}"
        );
        assert!(
            matches!(
                &ops[4],
                Op::Bin {
                    dst: VReg::Temp(202),
                    op: BinOp::Shl,
                    lhs: Value::Reg(VReg::Temp(202)),
                    rhs: Value::Reg(VReg::Temp(200))
                }
            ),
            "got: {ops:#?}"
        );
        assert!(
            matches!(
                &ops[5],
                Op::Bin { dst, op: BinOp::Or, lhs: Value::Reg(lhs), rhs: Value::Reg(VReg::Temp(202)) }
                    if *dst == VReg::phys("rdx") && *lhs == VReg::phys("rdx")
            ),
            "got: {ops:#?}"
        );

        // The CF read must come before the write that changes the bit.
        let carry = ops
            .iter()
            .position(|op| {
                matches!(
                    op,
                    Op::Bin {
                        dst: VReg::Flag(Flag::C),
                        ..
                    }
                )
            })
            .expect("no CF definition");
        let update = ops
            .iter()
            .position(
                |op| matches!(op, Op::Bin { dst, op: BinOp::Or, .. } if *dst == VReg::phys("rdx")),
            )
            .expect("no destination update");
        assert!(carry < update, "CF must be read before the bit is set");
    }

    /// An immediate index folds to a constant mask instead of a shift, and bit
    /// 63 is a legal one — `1 << 63` is `i64::MIN`, not an overflow.
    #[test]
    fn bts_with_an_immediate_index_folds_the_mask() {
        let ops: Vec<Op> = lift64(bit_ops_encodings::BTS_RCX_63)
            .into_iter()
            .map(|instruction| instruction.op)
            .collect();
        assert!(
            ops.iter().any(|op| matches!(
                op,
                Op::Bin { dst, op: BinOp::Or, rhs: Value::Const(mask), .. }
                    if *dst == VReg::phys("rcx") && *mask == i64::MIN
            )),
            "got: {ops:#?}"
        );
        assert!(
            !ops.iter()
                .any(|op| matches!(op, Op::Bin { op: BinOp::Shl, .. })),
            "a constant index needs no shift: {ops:#?}"
        );
    }

    /// `btr` clears the bit, so its mask is the complement — and at 32 bits the
    /// complement is masked to the operand width rather than left as a 64-bit
    /// constant whose high half only the parent zero-extension would clear.
    #[test]
    fn btr_uses_the_complement_of_the_bit_mask() {
        let constant: Vec<Op> = lift64(bit_ops_encodings::BTR_RCX_33)
            .into_iter()
            .map(|instruction| instruction.op)
            .collect();
        assert!(
            constant.iter().any(|op| matches!(
                op,
                Op::Bin { dst, op: BinOp::And, rhs: Value::Const(mask), .. }
                    if *dst == VReg::phys("rcx") && *mask == !(1i64 << 33)
            )),
            "got: {constant:#?}"
        );

        let variable: Vec<Op> = lift64(bit_ops_encodings::BTR_RCX_RDX)
            .into_iter()
            .map(|instruction| instruction.op)
            .collect();
        assert!(
            variable.iter().any(|op| matches!(
                op,
                Op::Un {
                    dst: VReg::Temp(202),
                    op: UnOp::Not,
                    src: Value::Reg(VReg::Temp(202))
                }
            )),
            "got: {variable:#?}"
        );
        assert!(
            variable.iter().any(|op| matches!(
                op,
                Op::ZExt {
                    dst: VReg::Temp(202),
                    src: Value::Const(1),
                    from: Width::W8,
                    to: Width::W64
                }
            )),
            "got: {variable:#?}"
        );
        assert!(
            variable.iter().any(|op| matches!(
                op,
                Op::Bin { dst, op: BinOp::And, rhs: Value::Reg(VReg::Temp(202)), .. }
                    if *dst == VReg::phys("rcx")
            )),
            "got: {variable:#?}"
        );
    }

    /// `btc` inverts the bit.
    #[test]
    fn btc_exclusive_ors_the_bit_mask() {
        let ops: Vec<Op> = lift64(bit_ops_encodings::BTC_RCX_RDX)
            .into_iter()
            .map(|instruction| instruction.op)
            .collect();
        assert!(
            ops.iter().any(|op| matches!(
                op,
                Op::Bin { dst, op: BinOp::Xor, rhs: Value::Reg(VReg::Temp(202)), .. }
                    if *dst == VReg::phys("rcx")
            )),
            "got: {ops:#?}"
        );
    }

    /// A 32-bit destination zero-extends into its 64-bit parent, exactly as
    /// every ordinary 32-bit ALU write does. Without the explicit record the IR
    /// would claim `rcx`'s high half survived an instruction that clears it.
    #[test]
    fn a_32_bit_bit_test_zero_extends_its_parent() {
        for bytes in [
            bit_ops_encodings::BTS_ECX_EBX,
            bit_ops_encodings::BTR_ECX_EBX,
        ] {
            let ops: Vec<Op> = lift64(bytes)
                .into_iter()
                .map(|instruction| instruction.op)
                .collect();
            assert!(
                ops.iter().any(|op| matches!(
                    op,
                    Op::ZExt { dst, src: Value::Reg(src), from: Width::W32, to: Width::W64 }
                        if *dst == VReg::phys("ecx") && *src == VReg::phys("ecx")
                )),
                "{bytes:02x?} got: {ops:#?}"
            );
            // A 32-bit destination widens its mask to 32 bits, so the shift
            // stays inside the width the machine operates at.
            assert!(
                ops.iter().any(|op| matches!(
                    op,
                    Op::ZExt {
                        dst: VReg::Temp(202),
                        src: Value::Const(1),
                        from: Width::W8,
                        to: Width::W32
                    }
                )),
                "{bytes:02x?} got: {ops:#?}"
            );
            // The index is masked to 31, not 63, at this width.
            assert!(
                ops.iter().any(|op| matches!(
                    op,
                    Op::Bin {
                        dst: VReg::Temp(200),
                        op: BinOp::And,
                        rhs: Value::Const(31),
                        ..
                    }
                )),
                "{bytes:02x?} got: {ops:#?}"
            );
        }
        // A 64-bit destination IS the whole register and needs no such record.
        let wide: Vec<Op> = lift64(bit_ops_encodings::BTS_RDX_RDI)
            .into_iter()
            .map(|instruction| instruction.op)
            .collect();
        assert!(
            !wide.iter().any(|op| matches!(
                op,
                Op::ZExt {
                    dst: VReg::Phys(_),
                    ..
                }
            )),
            "the only widening at this width is the bit mask's, which names a \
             temporary: {wide:#?}"
        );
    }

    /// Intel SDM Vol. 2A, BT/BTS/BTR/BTC: "The ZF flag is unaffected."
    ///
    /// The `bt` arm this family replaced poisoned ZF along with OF/SF/PF/AF,
    /// which is not merely imprecise — an `Op::Undef` is a real definition, so
    /// it would destroy a live comparison result that a preceding `cmp`
    /// produced and a following `je` still reads.
    #[test]
    fn the_bit_test_family_leaves_the_zero_flag_alone() {
        for bytes in [
            bit_ops_encodings::BT_RCX_5,
            bit_ops_encodings::BTS_RDX_RDI,
            bit_ops_encodings::BTR_RCX_RDX,
            bit_ops_encodings::BTC_RCX_RDX,
        ] {
            let ops: Vec<Op> = lift64(bytes)
                .into_iter()
                .map(|instruction| instruction.op)
                .collect();
            assert!(
                !ops.iter().any(|op| matches!(
                    crate::ir::use_def::def_uses(op).0,
                    Some(VReg::Flag(Flag::Z))
                )),
                "{bytes:02x?} must not touch ZF: {ops:#?}"
            );
            for flag in [Flag::O, Flag::S, Flag::P, Flag::A] {
                assert!(
                    ops.iter()
                        .any(|op| matches!(op, Op::Undef { dst: VReg::Flag(f), .. } if *f == flag)),
                    "{bytes:02x?} must poison {flag:?}: {ops:#?}"
                );
            }
        }
    }

    /// `bt` alone still reads the bit into CF and still leaves the destination
    /// untouched — absorbing it into the family must not have given it the
    /// write its three siblings have.
    #[test]
    fn plain_bt_defines_carry_and_nothing_else() {
        let ops: Vec<Op> = lift64(bit_ops_encodings::BT_RCX_5)
            .into_iter()
            .map(|instruction| instruction.op)
            .collect();
        assert!(
            ops.iter().any(|op| matches!(
                op,
                Op::Bin {
                    dst: VReg::Flag(Flag::C),
                    op: BinOp::And,
                    rhs: Value::Const(1),
                    ..
                }
            )),
            "got: {ops:#?}"
        );
        assert!(
            !ops.iter().any(|op| matches!(
                crate::ir::use_def::def_uses(op).0,
                Some(VReg::Phys(name)) if name == "rcx"
            )),
            "bt does not write its destination: {ops:#?}"
        );
    }

    /// `tzcnt` is a single-output intrinsic naming the encoded width, with CF
    /// reporting a zero SOURCE and ZF a zero RESULT.
    #[test]
    fn tzcnt_lowers_to_a_width_stated_single_output_intrinsic() {
        for (bytes, name, destination, source, width) in [
            (
                bit_ops_encodings::TZCNT_ECX_EDX,
                "x86.ctz.32",
                "ecx",
                "edx",
                Width::W32,
            ),
            (
                bit_ops_encodings::TZCNT_RAX_RDI,
                "x86.ctz.64",
                "rax",
                "rdi",
                Width::W64,
            ),
        ] {
            let ops: Vec<Op> = lift64(bytes)
                .into_iter()
                .map(|instruction| instruction.op)
                .collect();
            let intrinsic = ops
                .iter()
                .find_map(|op| match op {
                    Op::Intrinsic {
                        name: n,
                        ins,
                        outs,
                        reads_mem: false,
                        writes_mem: false,
                    } if n == name => Some((ins, outs)),
                    _ => None,
                })
                .unwrap_or_else(|| panic!("no {name}: {ops:#?}"));
            assert_eq!(intrinsic.1.len(), 1, "one output per destination");
            assert_eq!(intrinsic.1[0], (VReg::phys(destination), width));
            assert_eq!(intrinsic.0.len(), 1);

            // CF is (source == 0); ZF is (destination == 0).
            let carry = ops
                .iter()
                .find(|op| {
                    matches!(
                        op,
                        Op::Cmp {
                            dst: VReg::Flag(Flag::C),
                            ..
                        }
                    )
                })
                .unwrap_or_else(|| panic!("no CF: {ops:#?}"));
            assert!(matches!(
                carry,
                Op::Cmp {
                    op: CmpOp::Eq,
                    rhs: Value::Const(0),
                    ..
                }
            ));
            assert!(
                ops.iter().any(|op| matches!(
                    op,
                    Op::Cmp { dst: VReg::Flag(Flag::Z), op: CmpOp::Eq, lhs: Value::Reg(lhs), rhs: Value::Const(0) }
                        if *lhs == VReg::phys(destination)
                )),
                "got: {ops:#?}"
            );
            for flag in [Flag::O, Flag::S, Flag::P, Flag::A] {
                assert!(
                    ops.iter()
                        .any(|op| matches!(op, Op::Undef { dst: VReg::Flag(f), .. } if *f == flag)),
                    "{name} must poison {flag:?}: {ops:#?}"
                );
            }
            // The 32-bit source is narrowed to its encoded width before it is
            // counted; a 64-bit one already is the whole register.
            assert_eq!(
                ops.iter().any(|op| matches!(
                    op,
                    Op::ZExt { src: Value::Reg(src), from: Width::W32, to: Width::W64, .. }
                        if *src == VReg::phys(source)
                )),
                width == Width::W32,
                "got: {ops:#?}"
            );
        }
    }

    /// gcc at -O0 spells `__builtin_ctz` on a spilled local as
    /// `tzcnt -0x4(%rbp),%eax` — a MEMORY source, which the corpus sweep never
    /// showed because the samples are all optimised.
    #[test]
    fn tzcnt_accepts_a_memory_source_at_the_operand_width() {
        let ops: Vec<Op> = lift64(bit_ops_encodings::TZCNT_EAX_MEM)
            .into_iter()
            .map(|instruction| instruction.op)
            .collect();
        assert!(
            matches!(
                &ops[0],
                Op::Load {
                    dst: VReg::Temp(203),
                    ..
                }
            ),
            "got: {ops:#?}"
        );
        assert!(
            ops.iter().any(|op| matches!(
                op,
                Op::Intrinsic { name, outs, .. }
                    if name == "x86.ctz.32" && outs[0].0 == VReg::phys("eax")
            )),
            "got: {ops:#?}"
        );
    }

    /// `popcnt` defines every flag: ZF from a zero SOURCE, and the other five
    /// CLEARED rather than poisoned (Intel SDM Vol. 2B, POPCNT).
    #[test]
    fn popcnt_clears_the_flags_it_does_not_compute() {
        for (bytes, name, destination) in [
            (bit_ops_encodings::POPCNT_RDX_RAX, "x86.popcnt.64", "rdx"),
            (bit_ops_encodings::POPCNT_EAX_EDI, "x86.popcnt.32", "eax"),
        ] {
            let ops: Vec<Op> = lift64(bytes)
                .into_iter()
                .map(|instruction| instruction.op)
                .collect();
            assert!(
                ops.iter().any(|op| matches!(
                    op,
                    Op::Intrinsic { name: n, ins, outs, .. }
                        if n == name && ins.len() == 1 && outs.len() == 1
                            && outs[0].0 == VReg::phys(destination)
                )),
                "got: {ops:#?}"
            );
            assert!(
                ops.iter().any(|op| matches!(
                    op,
                    Op::Cmp {
                        dst: VReg::Flag(Flag::Z),
                        ..
                    }
                )),
                "got: {ops:#?}"
            );
            for flag in [Flag::C, Flag::O, Flag::S, Flag::P, Flag::A] {
                assert!(
                    ops.iter().any(|op| matches!(
                        op,
                        Op::Assign { dst: VReg::Flag(f), src: Value::Const(0) } if *f == flag
                    )),
                    "{name} clears {flag:?} rather than poisoning it: {ops:#?}"
                );
            }
            assert!(
                !ops.iter().any(|op| matches!(op, Op::Undef { .. })),
                "popcnt leaves no flag undefined: {ops:#?}"
            );
        }
    }

    /// `movlhps xmm15, xmm0` writes the destination's HIGH lanes from the
    /// source's low quadword and touches nothing else — in particular not the
    /// destination's scalar spelling, which IS the low quadword this
    /// instruction preserves.
    #[test]
    fn movlhps_writes_only_the_destinations_high_lanes() {
        let ops = lift64(bit_ops_encodings::MOVLHPS_XMM15_XMM0);
        assert_eq!(lanes_defined(&ops, "xmm15"), vec![2, 3], "got: {ops:#?}");
        assert!(
            !ops.iter().any(|instruction| matches!(
                crate::ir::use_def::def_uses(&instruction.op).0,
                Some(VReg::Phys(name)) if name == "xmm15"
            )),
            "the low quadword, and so the scalar name, is preserved: {ops:#?}"
        );
        assert!(
            ops.iter().any(|instruction| matches!(
                &instruction.op,
                Op::Assign { dst: VReg::Temp(150), src: Value::Reg(src) }
                    if *src == VReg::phys("xmm0")
            )),
            "the source's low quadword is read through its scalar name: {ops:#?}"
        );
    }

    /// `movhlps xmm1, xmm2` is the mirror: the destination's LOW lanes from the
    /// source's high quadword, which has no scalar spelling and so is assembled
    /// from its two lanes. Writing lanes 0 and 1 also redefines the
    /// destination's scalar name, through the ordinary view synchronisation.
    #[test]
    fn movhlps_writes_only_the_destinations_low_lanes() {
        let ops = lift64(bit_ops_encodings::MOVHLPS_XMM1_XMM2);
        assert_eq!(lanes_defined(&ops, "xmm1"), vec![0, 1], "got: {ops:#?}");
        assert!(
            ops.iter().any(|instruction| matches!(
                &instruction.op,
                Op::Concat { dst: VReg::Temp(150), hi: Value::Reg(hi), lo: Value::Reg(lo) }
                    if *hi == VReg::phys("xmm2_d3") && *lo == VReg::phys("xmm2_d2")
            )),
            "got: {ops:#?}"
        );
        assert!(
            ops.iter().any(|instruction| matches!(
                crate::ir::use_def::def_uses(&instruction.op).0,
                Some(VReg::Phys(name)) if name == "xmm1"
            )),
            "a low-lane write is mirrored into the scalar spelling: {ops:#?}"
        );
    }

    /// `rcr rdx, 1` rotates the carry into the top bit and the old bottom bit
    /// out into the carry, and both reads happen before either write.
    #[test]
    fn rcr_by_one_rotates_through_the_carry_flag() {
        let ops: Vec<Op> = lift64(bit_ops_encodings::RCR_RDX_1)
            .into_iter()
            .map(|instruction| instruction.op)
            .collect();
        assert!(
            matches!(
                &ops[0],
                Op::Assign {
                    dst: VReg::Temp(205),
                    src: Value::Reg(VReg::Flag(Flag::C))
                }
            ),
            "got: {ops:#?}"
        );
        assert!(
            matches!(
                &ops[1],
                Op::Bin { dst: VReg::Temp(206), op: BinOp::And, lhs: Value::Reg(lhs), rhs: Value::Const(1) }
                    if *lhs == VReg::phys("rdx")
            ),
            "got: {ops:#?}"
        );
        assert!(
            ops.iter().any(|op| matches!(
                op,
                Op::ZExt {
                    dst: VReg::Temp(208),
                    src: Value::Reg(VReg::Temp(205)),
                    from: Width::W1,
                    to: Width::W64
                }
            )),
            "the carry is widened before it is shifted 63 places: {ops:#?}"
        );
        assert!(
            ops.iter().any(|op| matches!(
                op,
                Op::Bin {
                    dst: VReg::Temp(208),
                    op: BinOp::Shl,
                    lhs: Value::Reg(VReg::Temp(208)),
                    rhs: Value::Const(63)
                }
            )),
            "got: {ops:#?}"
        );
        assert!(
            ops.iter().any(|op| matches!(
                op,
                Op::Bin { dst, op: BinOp::Shr, rhs: Value::Const(1), .. } if *dst == VReg::phys("rdx")
            )),
            "got: {ops:#?}"
        );
        assert!(
            ops.iter().any(|op| matches!(
                op,
                Op::Bin { dst, op: BinOp::Or, rhs: Value::Reg(VReg::Temp(208)), .. }
                    if *dst == VReg::phys("rdx")
            )),
            "got: {ops:#?}"
        );
        assert!(
            ops.iter().any(|op| matches!(
                op,
                Op::Assign {
                    dst: VReg::Flag(Flag::C),
                    src: Value::Reg(VReg::Temp(206))
                }
            )),
            "the outgoing carry is the destination's OLD bit 0: {ops:#?}"
        );
        assert!(
            ops.iter().any(|op| matches!(
                op,
                Op::Bin {
                    dst: VReg::Flag(Flag::O),
                    op: BinOp::Xor,
                    lhs: Value::Reg(VReg::Temp(205)),
                    rhs: Value::Reg(VReg::Temp(207))
                }
            )),
            "OF is the exclusive-or of the result's top two bits: {ops:#?}"
        );
    }

    /// A rotate through carry by anything other than one is NOT lifted. It is a
    /// rotation of a `width + 1` bit quantity, which this IR has no width for,
    /// and the ISA leaves OF undefined there as well — so it stays visible on
    /// the census rather than acquiring an invented lowering.
    #[test]
    fn a_multi_bit_rotate_through_carry_is_left_unmodelled() {
        // `rcr rdx, 3` — 48 c1 da 03.
        let ops = lift_one(&decode64(&[0x48, 0xc1, 0xda, 0x03]), 64);
        assert_eq!(
            ops,
            vec![Op::Unknown {
                mnemonic: "rcr".into()
            }],
            "got: {ops:#?}"
        );
        // `rcr rdx, cl` — 48 d3 da.
        let variable = lift_one(&decode64(&[0x48, 0xd3, 0xda]), 64);
        assert_eq!(
            variable,
            vec![Op::Unknown {
                mnemonic: "rcr".into()
            }],
            "got: {variable:#?}"
        );
    }

    /// A 16-bit `bt*` destination is a bit-preserving partial view of a 64-bit
    /// parent, so the write is a read-modify-write this lowering does not
    /// perform. Refusing it keeps the mnemonic honest on the census instead of
    /// silently clobbering the parent's high 48 bits.
    #[test]
    fn a_16_bit_bit_test_is_left_unmodelled() {
        // `bts cx, dx` — 66 0f ab d1.
        let ops = lift_one(&decode64(&[0x66, 0x0f, 0xab, 0xd1]), 64);
        assert_eq!(
            ops,
            vec![Op::Unknown {
                mnemonic: "bts".into()
            }],
            "got: {ops:#?}"
        );
    }

    #[test]
    fn sbb_reg_reg_lifts_to_sub_with_carry_dependency() {
        let ops = lift64(&[0x48, 0x19, 0xc8]);
        let arithmetic: Vec<_> = ops
            .iter()
            .filter(|instruction| {
                matches!(
                    &instruction.op,
                    Op::Bin {
                        dst,
                        op: BinOp::Sub,
                        ..
                    } if *dst == VReg::phys("rax")
                )
            })
            .collect();
        assert!(matches!(
            &arithmetic[0].op,
            Op::Bin {
                lhs: Value::Reg(lhs),
                rhs: Value::Reg(rhs),
                ..
            } if *lhs == VReg::phys("rax") && *rhs == VReg::phys("rcx")
        ));
        assert!(matches!(
            &arithmetic[1].op,
            Op::Bin {
                lhs: Value::Reg(lhs),
                rhs: Value::Reg(VReg::Temp(60)),
                ..
            } if *lhs == VReg::phys("rax")
        ));
        assert!(matches!(
            &ops[0].op,
            Op::Assign {
                dst: VReg::Temp(60),
                src: Value::Reg(VReg::Flag(Flag::C)),
            }
        ));
    }

    #[test]
    fn xorps_self_lifts_to_zero_assign() {
        let ops = lift64(&[0x0f, 0x57, 0xc0]);
        assert_eq!(ops.len(), 5, "got: {ops:#?}");
        assert!(matches!(
            &ops[0].op,
            Op::Assign {
                dst,
                src: Value::Const(0),
            } if *dst == VReg::phys("xmm0")
        ));
        for lane in 0..4 {
            assert!(ops.iter().any(|instruction| matches!(
                &instruction.op,
                Op::Assign {
                    dst: VReg::Phys(dst),
                    src: Value::Const(0),
                } if dst == &format!("xmm0_d{lane}")
            )));
        }
    }

    /// The register form of MOVSD moves the low quadword and PRESERVES bits
    /// 64..127, so it defines three names: the scalar spelling and the two
    /// lanes that spell the same 64 bits. Lanes 2 and 3 stay undefined, which
    /// is how this LLIR says "unchanged".
    #[test]
    fn movsd_scalar_reg_reg_lifts_to_assign() {
        let ops = lift64(&[0xf2, 0x0f, 0x10, 0xc1]);
        assert_eq!(ops.len(), 3, "got: {ops:#?}");
        assert!(matches!(
            &ops[0].op,
            Op::Assign {
                dst,
                src: Value::Reg(src),
            } if *dst == VReg::phys("xmm0") && *src == VReg::phys("xmm1")
        ));
        assert!(matches!(
            &ops[1].op,
            Op::Trunc { dst, src: Value::Reg(src), to: Width::W32, .. }
                if *dst == VReg::phys("xmm0_d0") && *src == VReg::phys("xmm0")
        ));
        assert!(matches!(
            &ops[2].op,
            Op::Extract { dst, src: Value::Reg(src), hi: 64, lo: 32 }
                if *dst == VReg::phys("xmm0_d1") && *src == VReg::phys("xmm0")
        ));
    }

    /// Every lane of `register` that a definition in `ops` covers.
    fn lanes_defined(ops: &[LlirInstr], register: &str) -> Vec<usize> {
        let mut lanes: Vec<usize> = ops
            .iter()
            .filter_map(
                |instruction| match crate::ir::use_def::def_uses(&instruction.op).0 {
                    Some(VReg::Phys(name)) => {
                        let (defined, lane) = name.split_once("_d")?;
                        (defined == register).then(|| lane.parse::<usize>().ok())?
                    }
                    _ => None,
                },
            )
            .collect();
        lanes.sort_unstable();
        lanes
    }

    /// `movss xmm, m32` ZEROES bits 32..127 (Intel SDM Vol. 2B, MOVSS
    /// "Operation"), so all four lanes are defined: lane 0 from the value, the
    /// other three as constant zero.
    #[test]
    fn a_scalar_load_from_memory_defines_every_lane_it_zeroes() {
        let ops = lift64(&[0xF3, 0x0F, 0x10, 0x00]); // movss (%rax),%xmm0
        assert_eq!(lanes_defined(&ops, "xmm0"), vec![0, 1, 2, 3], "{ops:#?}");
        assert!(
            matches!(
                &ops[1].op,
                Op::Trunc { dst, src: Value::Reg(src), to: Width::W32, .. }
                    if *dst == VReg::phys("xmm0_d0") && *src == VReg::phys("xmm0")
            ),
            "lane 0 comes from the SCALAR NAME, not from a second narrow load of \
             the same address: {ops:#?}"
        );
        for lane in 1..4 {
            assert!(
                ops.iter().any(|instruction| matches!(
                    &instruction.op,
                    Op::Assign { dst: VReg::Phys(dst), src: Value::Const(0) }
                        if dst == &format!("xmm0_d{lane}")
                )),
                "lane {lane} is zeroed by the instruction: {ops:#?}"
            );
        }
        // Exactly one memory access, at the architectural width. Splitting the
        // transfer into narrow lane loads is bit-identical and changes what the
        // stack-object recovery infers about the frame — see
        // `packed_halves::packed_qword_half_move_ops`.
        let loads: Vec<u8> = ops
            .iter()
            .filter_map(|instruction| match &instruction.op {
                Op::Load { addr, .. } => Some(addr.size),
                _ => None,
            })
            .collect();
        assert_eq!(loads, vec![4], "{ops:#?}");
    }

    /// `movss xmm, xmm` PRESERVES bits 32..127, and "unchanged" in this LLIR is
    /// spelled by NOT defining the lane — the previous definition still reaches.
    #[test]
    fn a_scalar_register_move_leaves_the_lanes_it_preserves_undefined() {
        let ops = lift64(&[0xF3, 0x0F, 0x10, 0xC1]); // movss %xmm1,%xmm0
        assert_eq!(lanes_defined(&ops, "xmm0"), vec![0], "{ops:#?}");
    }

    /// The 64-bit sibling of both rules at once: `movsd xmm, m64` defines lanes
    /// 0 and 1 from the value and zeroes 2 and 3.
    #[test]
    fn a_binary64_scalar_load_defines_two_lanes_and_zeroes_two() {
        let ops = lift64(&[0xF2, 0x0F, 0x10, 0x00]); // movsd (%rax),%xmm0
        assert_eq!(lanes_defined(&ops, "xmm0"), vec![0, 1, 2, 3], "{ops:#?}");
        assert!(
            ops.iter().any(|instruction| matches!(
                &instruction.op,
                Op::Extract { dst, src: Value::Reg(src), hi: 64, lo: 32 }
                    if *dst == VReg::phys("xmm0_d1") && *src == VReg::phys("xmm0")
            )),
            "lane 1 is the high half of the scalar value: {ops:#?}"
        );
        for lane in 2..4 {
            assert!(
                ops.iter().any(|instruction| matches!(
                    &instruction.op,
                    Op::Assign { dst: VReg::Phys(dst), src: Value::Const(0) }
                        if dst == &format!("xmm0_d{lane}")
                )),
                "lane {lane} is zeroed: {ops:#?}"
            );
        }
    }

    /// A scalar ARITHMETIC result preserves the bits above it whatever its
    /// source operand is — the rule that differs from MOVSS/MOVSD, and the
    /// reason this is a per-mnemonic table rather than one rule.
    #[test]
    fn scalar_arithmetic_preserves_the_lanes_above_its_result() {
        // `addss %xmm1,%xmm0` — 4-byte result, lanes 1..3 untouched.
        let addss = lift64(&[0xF3, 0x0F, 0x58, 0xC1]);
        assert_eq!(lanes_defined(&addss, "xmm0"), vec![0], "{addss:#?}");
        // `addsd %xmm1,%xmm0` — 8-byte result, lanes 2..3 untouched.
        let addsd = lift64(&[0xF2, 0x0F, 0x58, 0xC1]);
        assert_eq!(lanes_defined(&addsd, "xmm0"), vec![0, 1], "{addsd:#?}");
        // `cvtsi2sd %eax,%xmm0` — a conversion is the same shape.
        let cvtsi2sd = lift64(&[0xF2, 0x0F, 0x2A, 0xC0]);
        assert_eq!(
            lanes_defined(&cvtsi2sd, "xmm0"),
            vec![0, 1],
            "{cvtsi2sd:#?}"
        );
    }

    /// A lowering that defines both spellings for itself is not double-defined.
    /// `movlpd xmm, m64` writes lanes 0 and 1 AND the scalar name; the mirror
    /// must add nothing.
    #[test]
    fn a_lowering_that_already_writes_both_spellings_gains_no_second_definition() {
        let ops = lift64(&[0x66, 0x0F, 0x12, 0x00]); // movlpd (%rax),%xmm0
        assert_eq!(lanes_defined(&ops, "xmm0"), vec![0, 1], "{ops:#?}");
        assert_eq!(
            ops.iter()
                .filter(|instruction| matches!(
                    crate::ir::use_def::def_uses(&instruction.op).0,
                    Some(VReg::Phys(name)) if name == "xmm0"
                ))
                .count(),
            1,
            "one definition of the scalar name, not two: {ops:#?}"
        );
    }

    /// The two directions never both fire, so the lane-to-scalar bridge's
    /// `single_source_of_lane_copy` — whose `lanes_seen == 4` predicate a
    /// two-lane mirror would fail — is not consulted for a scalar producer at
    /// all. Its routing of the packed cases is unaffected, which is what the
    /// negative control below asserts.
    #[test]
    fn a_scalar_producer_is_never_re_bridged_back_from_its_own_lanes() {
        for (name, bytes) in [
            ("movss (%rax),%xmm0", &[0xF3u8, 0x0F, 0x10, 0x00][..]),
            ("movsd %xmm1,%xmm0", &[0xF2, 0x0F, 0x10, 0xC1][..]),
            ("addsd %xmm1,%xmm0", &[0xF2, 0x0F, 0x58, 0xC1][..]),
        ] {
            let ops = lift64(bytes);
            assert_eq!(
                ops.iter()
                    .filter(|instruction| matches!(
                        crate::ir::use_def::def_uses(&instruction.op).0,
                        Some(VReg::Phys(register)) if register == "xmm0"
                    ))
                    .count(),
                1,
                "{name} defines the scalar name once, with no appended bridge: {ops:#?}"
            );
        }
        // Negative control: a PACKED producer still gets the bridge it always
        // did, by whichever of the two forms applies.
        let movaps = lift64(&[0x0F, 0x28, 0xC1]); // movaps %xmm1,%xmm0
        assert!(
            movaps.iter().any(|instruction| matches!(
                &instruction.op,
                Op::Assign { dst, src: Value::Reg(src) }
                    if *dst == VReg::phys("xmm0") && *src == VReg::phys("xmm1")
            )),
            "a four-lane register copy still carries the source's scalar view: {movaps:#?}"
        );
        let movdqa = lift64(&[0x66, 0x0F, 0x6F, 0x00]); // movdqa (%rax),%xmm0
        assert!(
            movdqa.iter().any(|instruction| matches!(
                &instruction.op,
                Op::Concat { dst, .. } if *dst == VReg::phys("xmm0")
            )),
            "a four-lane load still rebuilds the scalar view by concat: {movdqa:#?}"
        );
    }

    /// The defect, end to end: GCC's whole `-O0` body for `-value` is a scalar
    /// load followed by a packed sign-bit mask, and the mask read four lanes the
    /// load had never defined.
    #[test]
    fn a_scalar_load_reaches_a_packed_mask_of_the_same_register() {
        // movss (%rax),%xmm0 ; xorps %xmm1,%xmm0
        let ops = lift64(&[0xF3, 0x0F, 0x10, 0x00, 0x0F, 0x57, 0xC1]);
        let mask_va = ops
            .iter()
            .find(|instruction| instruction.va != 0x1000)
            .map(|instruction| instruction.va)
            .expect("the mask is a second instruction");
        let defined_before_mask: std::collections::BTreeSet<VReg> = ops
            .iter()
            .filter(|instruction| instruction.va < mask_va)
            .filter_map(|instruction| crate::ir::use_def::def_uses(&instruction.op).0)
            .collect();
        let read_by_mask: Vec<VReg> = ops
            .iter()
            .filter(|instruction| instruction.va == mask_va)
            .flat_map(|instruction| crate::ir::use_def::def_uses(&instruction.op).1)
            .filter(|register| matches!(register, VReg::Phys(name) if name.starts_with("xmm0")))
            .collect();
        assert!(!read_by_mask.is_empty(), "the mask reads xmm0: {ops:#?}");
        for register in read_by_mask {
            assert!(
                defined_before_mask.contains(&register),
                "{register} is read by the sign-bit mask with no reaching \
                 definition — the whole function body folds to zero: {ops:#?}"
            );
        }
    }

    /// The string move's pointer step is the direction flag's sign, not `+width`.
    ///
    /// This test used to assert `rhs: Value::Const(4)` on both pointer updates,
    /// which is what the dword string move — the only string move that had an
    /// arm — actually emitted. It is right for every `movs` a compiler emits
    /// and wrong for `std; rep movsq`, which is how a correct overlapping
    /// backward `memmove` is written. `stos_ops` had honoured DF since it was
    /// written; the string move did not, and the asymmetry was not deliberate.
    ///
    /// Honouring it costs nothing where DF is clear: `lift_function` seeds
    /// `DF = 0` at the entry of any function that reads the flag, so the select
    /// const-folds back to `+width` in exactly the programs the old constant
    /// was right for.
    #[test]
    fn the_string_move_steps_by_the_direction_flag_not_a_fixed_sign() {
        let ops = lift64(&[0xa5]);
        let step = match &ops[2].op {
            Op::Ite {
                dst,
                cond: VReg::Flag(Flag::D),
                t: Value::Const(-4),
                e: Value::Const(4),
                width: Width::W64,
            } => dst.clone(),
            other => panic!("no directional step: {other:#?} in {ops:#?}"),
        };
        for (index, pointer) in [(3usize, "rsi"), (4, "rdi")] {
            assert!(
                matches!(
                    &ops[index].op,
                    Op::Bin {
                        dst,
                        op: BinOp::Add,
                        lhs: Value::Reg(lhs),
                        rhs: Value::Reg(rhs),
                    } if *dst == VReg::phys(pointer)
                        && *lhs == VReg::phys(pointer)
                        && *rhs == step
                ),
                "{pointer}: {ops:#?}"
            );
        }
        // And the flag really is READ, which is what makes `lift_function`
        // materialise the ABI's DF-clear guarantee for this function.
        assert!(ops
            .iter()
            .any(|instruction| crate::ir::use_def::def_uses(&instruction.op)
                .1
                .contains(&VReg::Flag(Flag::D))));
    }

    #[test]
    fn fninit_lifts_to_nop() {
        let ops = lift64(&[0xdb, 0xe3]);
        assert_eq!(ops.len(), 1, "got: {ops:#?}");
        assert_eq!(ops[0].op, Op::Nop);
    }

    #[test]
    fn lea_rip_relative_resolves_to_absolute() {
        // lea rax, [rip + 0x10]  (48 8d 05 10 00 00 00)  from 0x1000, length 7
        // target = 0x1000 + 7 + 0x10 = 0x1017
        let ops = lift64(&[0x48, 0x8d, 0x05, 0x10, 0x00, 0x00, 0x00]);
        assert_eq!(ops.len(), 1);
        match &ops[0].op {
            Op::Assign {
                dst,
                src: Value::Addr(a),
            } => {
                assert_eq!(*dst, VReg::phys("rax"));
                assert_eq!(*a, 0x1017);
            }
            other => panic!("expected Assign of Addr, got {:?}", other),
        }
    }

    #[test]
    fn real_binary_entry_lift_produces_return_and_no_panic() {
        // Smoke test against a real binary: lift 128 bytes starting at the
        // entry of the committed hello-gcc-O2 sample. We assert only structural
        // properties (no panics, at least one call or jump, non-empty output)
        // because the precise opcode sequence depends on the compiler.
        let sample = std::path::Path::new(
            "samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-gcc-O2",
        );
        if !sample.exists() {
            eprintln!("sample missing: {}", sample.display());
            return;
        }
        let data = std::fs::read(sample).expect("read sample");
        let info = crate::analysis::entry::detect_entry(&data).expect("detect entry");
        let foff = info.file_offset.expect("file offset");
        let window = &data[foff..(foff + 128).min(data.len())];
        let ops = lift_bytes(window, info.entry_va, 64);
        assert!(!ops.is_empty(), "no LLIR produced");
        // Entry code from a compiled C program invariably contains at least
        // one call or unconditional jump in the first 128 bytes.
        assert!(
            ops.iter()
                .any(|i| matches!(&i.op, Op::Call { .. } | Op::Jump { .. })),
            "expected Call or Jump in lifted entry; got {:#?}",
            ops
        );
    }

    #[test]
    fn endbr64_lifts_to_nop() {
        // ENDBR64 = F3 0F 1E FA
        let ops = lift64(&[0xf3, 0x0f, 0x1e, 0xfa]);
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].op, Op::Nop);
    }

    #[test]
    fn lea_with_base_and_disp_lifts_to_bin_chain() {
        // LEA rax, [rbp - 0x10]  (48 8d 45 f0)
        let ops = lift64(&[0x48, 0x8d, 0x45, 0xf0]);
        // Expected chain: tmp = rbp; tmp = tmp + (-0x10); rax = tmp.
        assert_eq!(ops.len(), 3, "got: {:#?}", ops);
        assert!(matches!(
            &ops[0].op,
            Op::Assign {
                dst: VReg::Temp(0),
                src: Value::Reg(r),
            } if *r == VReg::phys("rbp")
        ));
        assert!(matches!(
            &ops[1].op,
            Op::Bin {
                dst: VReg::Temp(0),
                op: BinOp::Add,
                rhs: Value::Const(-16),
                ..
            }
        ));
        assert!(matches!(
            &ops[2].op,
            Op::Assign {
                dst,
                src: Value::Reg(VReg::Temp(0)),
            } if *dst == VReg::phys("rax")
        ));
    }

    #[test]
    fn lea_32bit_negative_disp_is_sign_extended() {
        // lea eax, [ebp - 0x24]  (8d 45 dc). iced exposes the displacement as
        // 0x00000000ffffffdc in 32-bit mode; treating that as an i64 invents a
        // huge positive stack offset instead of the local at -0x24.
        let ops = lift_bytes(&[0x8d, 0x45, 0xdc], 0x1000, 32);
        assert!(
            matches!(
                &ops[1].op,
                Op::Bin {
                    dst: VReg::Temp(0),
                    op: BinOp::Add,
                    rhs: Value::Const(-36),
                    ..
                }
            ),
            "got: {ops:#?}"
        );
    }

    #[test]
    fn lea_with_index_and_scale_includes_mul() {
        // LEA rax, [rbx + rcx*8]  (48 8d 04 cb)
        let ops = lift64(&[0x48, 0x8d, 0x04, 0xcb]);
        // Expect: tmp = rbx; tmp1 = rcx * 8; tmp = tmp + tmp1; rax = tmp.
        assert!(ops.iter().any(|i| matches!(
            &i.op,
            Op::Bin {
                op: BinOp::Mul,
                rhs: Value::Const(8),
                ..
            }
        )));
    }

    #[test]
    fn movaps_reg_reg_lifts_to_assign() {
        // MOVAPS xmm0, xmm1  (0f 28 c1)
        let ops = lift64_lanes(&[0x0f, 0x28, 0xc1]);
        assert_eq!(ops.len(), 4, "got: {ops:#?}");
        for lane in 0..4 {
            assert!(ops.iter().any(|instruction| matches!(
                &instruction.op,
                Op::Assign {
                    dst: VReg::Phys(dst),
                    src: Value::Reg(VReg::Phys(src)),
                } if dst == &format!("xmm0_d{lane}") && src == &format!("xmm1_d{lane}")
            )));
        }
    }

    #[test]
    fn movdqu_reg_mem_lifts_to_16_byte_load() {
        // MOVDQU xmm0, [rdi]   (f3 0f 6f 07). Packed dword users need four
        // explicit scalar lanes, not one opaque 128-bit scalar.
        let ops = lift64_lanes(&[0xf3, 0x0f, 0x6f, 0x07]);
        assert_eq!(ops.len(), 4, "got: {ops:#?}");
        for (lane, instruction) in ops.iter().enumerate() {
            match &instruction.op {
                Op::Load {
                    dst: VReg::Phys(dst),
                    addr,
                } => {
                    assert_eq!(dst, &format!("xmm0_d{lane}"));
                    assert_eq!(addr.size, 4);
                    assert_eq!(addr.disp, (lane * 4) as i64);
                }
                other => panic!("expected lane load, got {other:?}"),
            }
        }
    }

    #[test]
    fn packed_dword_positive_sum_sequence_has_explicit_lane_semantics() {
        // The exact SSE2 core emitted by clang -O2 for fixture
        // `13_loop_early_exit:sum_positive`: load four signed dwords, build a
        // positive-lane mask, mask the values, and accumulate lane-wise.
        let ops = lift64(&[
            0x66, 0x0f, 0xef, 0xd2, // pxor xmm2,xmm2
            0xf3, 0x0f, 0x6f, 0x1f, // movdqu xmm3,[rdi]
            0x66, 0x0f, 0x6f, 0xfb, // movdqa xmm7,xmm3
            0x66, 0x0f, 0x66, 0xfa, // pcmpgtd xmm7,xmm2
            0x66, 0x0f, 0xdb, 0xfb, // pand xmm7,xmm3
            0x66, 0x0f, 0xfe, 0xf8, // paddd xmm7,xmm0
        ]);

        assert!(
            !ops.iter().any(|instruction| matches!(
                instruction.op,
                Op::Unknown { .. } | Op::Intrinsic { .. }
            )),
            "packed dword dataflow must be explicit: {ops:#?}"
        );
        for lane in 0..4 {
            let lane_name = format!("xmm7_d{lane}");
            assert!(
                ops.iter().any(|instruction| matches!(
                    &instruction.op,
                    Op::Bin { dst: VReg::Phys(dst), op: BinOp::Add, .. }
                        if dst == &lane_name
                )),
                "missing lane {lane} accumulator: {ops:#?}"
            );
        }
        assert_eq!(
            ops.iter()
                .filter(|instruction| matches!(
                    instruction.op,
                    Op::Ite {
                        t: Value::Const(-1),
                        e: Value::Const(0),
                        width: Width::W32,
                        ..
                    }
                ))
                .count(),
            4,
            "PCMPGTD must produce four all-ones/zero masks: {ops:#?}"
        );
    }

    #[test]
    fn packed_dword_scale_by_thirty_one_has_explicit_lane_semantics() {
        // The exact SSE2 pair emitted by clang -O2 for
        // `11_call_shapes:call_accumulate_bytes`: each dword lane computes
        // `(seed << 5) - seed`, i.e. seed * 31. Dropping either operation
        // changes the round-trip result for every non-zero seed.
        let ops = lift64(&[
            0x66, 0x0f, 0x72, 0xf2, 0x05, // pslld xmm2,5
            0x66, 0x0f, 0xfa, 0xd1, // psubd xmm2,xmm1
        ]);

        assert!(
            !ops.iter().any(|instruction| matches!(
                instruction.op,
                Op::Unknown { .. } | Op::Intrinsic { .. }
            )),
            "packed scale dataflow must be explicit: {ops:#?}"
        );
        for lane in 0..4 {
            let lane_name = format!("xmm2_d{lane}");
            assert!(ops.iter().any(|instruction| matches!(
                &instruction.op,
                Op::Bin {
                    dst: VReg::Phys(dst),
                    op: BinOp::Shl,
                    lhs: Value::Reg(VReg::Phys(lhs)),
                    rhs: Value::Const(5),
                } if dst == &lane_name && lhs == dst
            )));
            assert!(ops.iter().any(|instruction| matches!(
                &instruction.op,
                Op::Bin {
                    dst: VReg::Phys(dst),
                    op: BinOp::Sub,
                    lhs: Value::Reg(VReg::Phys(lhs)),
                    rhs: Value::Reg(VReg::Phys(rhs)),
                } if dst == &lane_name && lhs == dst && rhs == &format!("xmm1_d{lane}")
            )));
        }
    }

    #[test]
    fn packed_dword_immediate_shift_obeys_large_count_zeroing_and_rejects_mmx() {
        let xmm_ops = lift64_lanes(&[0x66, 0x0f, 0x72, 0xf2, 0x20]); // pslld xmm2,32
        assert_eq!(xmm_ops.len(), 4, "got: {xmm_ops:#?}");
        for (lane, instruction) in xmm_ops.iter().enumerate() {
            assert!(matches!(
                &instruction.op,
                Op::Assign {
                    dst: VReg::Phys(dst),
                    src: Value::Const(0),
                } if dst == &format!("xmm2_d{lane}")
            ));
        }

        let mmx_ops = lift64_lanes(&[0x0f, 0x72, 0xf2, 0x05]); // pslld mm2,5
        assert_eq!(mmx_ops.len(), 1, "got: {mmx_ops:#?}");
        assert!(matches!(
            &mmx_ops[0].op,
            Op::Unknown { mnemonic } if mnemonic == "pslld"
        ));
    }

    #[test]
    fn packed_dword_logical_right_shift_preserves_all_lanes_and_zeroes_large_counts() {
        let ops = lift64_lanes(&[0x66, 0x0f, 0x72, 0xd4, 0x1f]); // psrld xmm4,31
        assert_eq!(ops.len(), 8);
        for lane in 0..4 {
            assert!(matches!(
                &ops[lane * 2].op,
                Op::Trunc {
                    dst: VReg::Temp(temp),
                    src: Value::Reg(VReg::Phys(src)),
                    to: Width::W32,
                    ..
                } if *temp == 140 + lane as u32 && src == &format!("xmm4_d{lane}")
            ));
            assert!(matches!(
                &ops[lane * 2 + 1].op,
                Op::Bin {
                    dst: VReg::Phys(dst),
                    op: BinOp::Shr,
                    lhs: Value::Reg(VReg::Temp(temp)),
                    rhs: Value::Const(31),
                } if dst == &format!("xmm4_d{lane}") && *temp == 140 + lane as u32
            ));
        }

        let large = lift64_lanes(&[0x66, 0x0f, 0x72, 0xd4, 0x20]); // psrld xmm4,32
        assert!(large.iter().all(|instruction| matches!(
            &instruction.op,
            Op::Assign {
                src: Value::Const(0),
                ..
            }
        )));
    }

    #[test]
    fn packed_self_equality_materializes_ones_without_reading_old_lanes() {
        let ops = lift64_lanes(&[0x66, 0x0f, 0x76, 0xe4]); // pcmpeqd xmm4,xmm4
        assert_eq!(ops.len(), 4);
        for (lane, instruction) in ops.iter().enumerate() {
            assert!(matches!(
                &instruction.op,
                Op::Assign {
                    dst: VReg::Phys(dst),
                    src: Value::Const(-1),
                } if dst == &format!("xmm4_d{lane}")
            ));
        }
    }

    #[test]
    fn packed_dword_arithmetic_shift_builds_sign_masks_and_saturates_count() {
        let ops = lift64_lanes(&[
            0x66, 0x0f, 0x72, 0xe2, 0x1f, // psrad xmm2,31
            0x66, 0x0f, 0x72, 0xe1, 0xff, // psrad xmm1,255
        ]);
        assert_eq!(ops.len(), 8, "got: {ops:#?}");
        for (instruction, expected_register) in ops.iter().zip(
            (0..4)
                .map(|lane| format!("xmm2_d{lane}"))
                .chain((0..4).map(|lane| format!("xmm1_d{lane}"))),
        ) {
            assert!(matches!(
                &instruction.op,
                Op::Bin {
                    dst: VReg::Phys(dst),
                    op: BinOp::Sar,
                    lhs: Value::Reg(VReg::Phys(lhs)),
                    rhs: Value::Const(31),
                } if dst == &expected_register && lhs == dst
            ));
        }
    }

    #[test]
    fn pxor_self_defines_whole_register_and_every_dword_lane_as_zero() {
        let ops = lift64(&[0x66, 0x0f, 0xef, 0xc0]); // pxor xmm0,xmm0
        assert!(matches!(
            &ops[0].op,
            Op::Assign {
                dst,
                src: Value::Const(0)
            } if *dst == VReg::phys("xmm0")
        ));
        for lane in 0..4 {
            let name = format!("xmm0_d{lane}");
            assert!(
                ops.iter().any(|instruction| matches!(
                    &instruction.op,
                    Op::Assign { dst: VReg::Phys(dst), src: Value::Const(0) } if dst == &name
                )),
                "missing zero definition for {name}: {ops:#?}"
            );
        }
    }

    #[test]
    fn packed_dword_max_select_sequence_has_explicit_lane_semantics() {
        // clang -O2 lowers a signed packed maximum to
        //   mask = candidate > current
        //   selected = (candidate & mask) | (current & ~mask)
        // PANDN has the unusual destination semantics `dst = (~dst) & src`.
        let ops = lift64(&[
            0x66, 0x0f, 0x66, 0xe0, // pcmpgtd xmm4,xmm0
            0x66, 0x0f, 0xdb, 0xd4, // pand xmm2,xmm4
            0x66, 0x0f, 0xdf, 0xe0, // pandn xmm4,xmm0
            0x66, 0x0f, 0xeb, 0xc2, // por xmm0,xmm2
        ]);

        assert!(
            !ops.iter().any(|instruction| matches!(
                instruction.op,
                Op::Unknown { .. } | Op::Intrinsic { .. }
            )),
            "packed max selection must be explicit: {ops:#?}"
        );
        for lane in 0..4 {
            let mask = format!("xmm4_d{lane}");
            assert!(ops.iter().any(|instruction| matches!(
                &instruction.op,
                Op::Un {
                    dst: VReg::Temp(dst),
                    op: UnOp::Not,
                    src: Value::Reg(VReg::Phys(src)),
                } if *dst == 88 + lane as u32 && src == &mask
            )));
            assert!(ops.iter().any(|instruction| matches!(
                &instruction.op,
                Op::Bin {
                    dst: VReg::Phys(dst),
                    op: BinOp::And,
                    lhs: Value::Reg(VReg::Temp(lhs)),
                    rhs: Value::Reg(VReg::Phys(rhs)),
                } if dst == &mask && *lhs == 88 + lane as u32 && rhs == &format!("xmm0_d{lane}")
            )));
            assert!(ops.iter().any(|instruction| matches!(
                &instruction.op,
                Op::Bin {
                    dst: VReg::Phys(dst),
                    op: BinOp::Or,
                    lhs: Value::Reg(VReg::Phys(lhs)),
                    rhs: Value::Reg(VReg::Phys(rhs)),
                } if dst == &format!("xmm0_d{lane}")
                    && lhs == dst
                    && rhs == &format!("xmm2_d{lane}")
            )));
        }
    }

    #[test]
    fn packed_dword_equal_and_memory_mask_have_explicit_lane_semantics() {
        // The exact unsupported SSE2 core emitted by Clang -O2 for
        // `checksum:crc32_step`: compare four dwords for equality, then mask
        // each resulting all-ones/zero lane with a read-only memory operand.
        let ops = lift64(&[
            0x66, 0x0f, 0x76, 0xc1, // pcmpeqd xmm0,xmm1
            0x66, 0x0f, 0xdb, 0x05, 0xc7, 0x0e, 0x00, 0x00, // pand xmm0,[rip+0xec7]
        ]);

        assert!(
            !ops.iter().any(|instruction| matches!(
                instruction.op,
                Op::Unknown { .. } | Op::Intrinsic { .. }
            )),
            "packed equality and memory mask must be explicit: {ops:#?}"
        );
        for lane in 0..4 {
            let lane_name = format!("xmm0_d{lane}");
            assert!(ops.iter().any(|instruction| matches!(
                &instruction.op,
                Op::Ite {
                    dst: VReg::Phys(dst),
                    t: Value::Const(-1),
                    e: Value::Const(0),
                    width: Width::W32,
                    ..
                } if dst == &lane_name
            )));
            assert!(ops.iter().any(|instruction| matches!(
                &instruction.op,
                Op::Bin {
                    dst: VReg::Phys(dst),
                    op: BinOp::And,
                    lhs: Value::Reg(VReg::Phys(lhs)),
                    rhs: Value::Reg(VReg::Temp(_)),
                } if dst == &lane_name && lhs == dst
            )));
        }
    }

    #[test]
    fn mmx_paddd_is_not_misrepresented_as_four_xmm_dword_lanes() {
        // PADDD mm0,mm1 is a 64-bit MMX operation with two lanes. The XMM
        // scalariser must fail closed instead of inventing four `mm*_dN` lanes.
        let ops = lift64(&[0x0f, 0xfe, 0xc1]);
        assert_eq!(ops.len(), 1, "got: {ops:#?}");
        assert!(matches!(
            &ops[0].op,
            Op::Unknown { mnemonic } if mnemonic == "paddd"
        ));
    }

    #[test]
    fn pshufd_and_movd_expose_the_horizontal_sum_lane() {
        // pshufd xmm1,xmm0,0xee; paddd xmm1,xmm0;
        // pshufd xmm0,xmm1,0x55; paddd xmm0,xmm1; movd eax,xmm0
        let ops = lift64(&[
            0x66, 0x0f, 0x70, 0xc8, 0xee, 0x66, 0x0f, 0xfe, 0xc8, 0x66, 0x0f, 0x70, 0xc1, 0x55,
            0x66, 0x0f, 0xfe, 0xc1, 0x66, 0x0f, 0x7e, 0xc0,
        ]);

        assert!(
            !ops.iter().any(|instruction| matches!(
                instruction.op,
                Op::Unknown { .. } | Op::Intrinsic { .. }
            )),
            "horizontal reduction must be explicit: {ops:#?}"
        );
        assert!(ops.iter().any(|instruction| matches!(
            &instruction.op,
            Op::ZExt {
                dst: VReg::Phys(dst),
                src: Value::Reg(VReg::Phys(src)),
                from: Width::W32,
                to: Width::W64,
            } if dst == "eax" && src == "xmm0_d0"
        )));
        // 0xee selects [2, 3, 2, 3] from xmm0. The first four ops snapshot the
        // source and the next four write the shuffled xmm1 lanes.
        for (lane, selected) in [2_u32, 3, 2, 3].into_iter().enumerate() {
            assert!(ops.iter().any(|instruction| matches!(
                &instruction.op,
                Op::Assign {
                    dst: VReg::Phys(dst),
                    src: Value::Reg(VReg::Temp(src)),
                } if dst == &format!("xmm1_d{lane}") && *src == 84 + selected
            )));
        }
    }

    #[test]
    fn unpack_and_qword_reduction_preserve_full_width_lane_semantics() {
        // The exact reduction tail emitted by clang -O2 for
        // `12_loop_rotation:skip_odd_sum`. PUNPCKLDQ constructs two 64-bit
        // masks, PADDQ horizontally adds the two qwords, and MOVQ exposes the
        // complete low qword as the function result.
        let ops = lift64_lanes(&[
            0x66, 0x0f, 0x62, 0xd8, // punpckldq xmm3,xmm0
            0x66, 0x0f, 0xd4, 0xc3, // paddq xmm0,xmm3
            0x66, 0x48, 0x0f, 0x7e, 0xc0, // movq rax,xmm0
        ]);

        assert!(
            !ops.iter().any(|instruction| matches!(
                instruction.op,
                Op::Unknown { .. } | Op::Intrinsic { .. }
            )),
            "qword reduction dataflow must be explicit: {ops:#?}"
        );
        assert_eq!(
            ops.iter()
                .filter(|instruction| matches!(instruction.op, Op::Bin { op: BinOp::Add, .. }))
                .count(),
            2,
            "PADDQ must add both complete qword lanes: {ops:#?}"
        );
        assert_eq!(
            ops.iter()
                .filter(|instruction| matches!(
                    instruction.op,
                    Op::Trunc {
                        from: Width::W64,
                        to: Width::W32,
                        ..
                    }
                ))
                .count(),
            2,
            "both low dwords must come from the complete qword sums: {ops:#?}"
        );
        assert_eq!(
            ops.iter()
                .filter(|instruction| matches!(instruction.op, Op::Extract { hi: 64, lo: 32, .. }))
                .count(),
            2,
            "both high dwords must retain carry from the complete qword sums: {ops:#?}"
        );
        // MOVQ reads the WHOLE-REGISTER view now, not the two lanes directly.
        // The reduction still reaches `rax` through exactly those lanes — the
        // second assertion below is the link — but routing it through the
        // scalar spelling is what lets a scalar float producer (`movsd`) and a
        // packed producer (`paddq`) both be visible to the same MOVQ.
        assert!(ops.iter().any(|instruction| matches!(
            &instruction.op,
            Op::Assign {
                dst: VReg::Phys(dst),
                src: Value::Reg(VReg::Phys(src)),
            } if dst == "rax" && src == "xmm0"
        )));
        assert!(
            lift64(&[
                0x66, 0x0f, 0x62, 0xd8, 0x66, 0x0f, 0xd4, 0xc3, 0x66, 0x48, 0x0f, 0x7e, 0xc0,
            ])
            .iter()
            .any(|instruction| matches!(
                &instruction.op,
                Op::Concat {
                    dst: VReg::Phys(dst),
                    hi: Value::Reg(VReg::Phys(hi)),
                    lo: Value::Reg(VReg::Phys(lo)),
                } if dst == "xmm0" && hi == "xmm0_d1" && lo == "xmm0_d0"
            )),
            "the whole-register view must be defined from the summed lanes"
        );
    }

    /// Every register a lifted op reads and writes, as `use_def` sees it.
    ///
    /// The whole point of the MOVLPD/MOVHPD family below is that `Op::Unknown`
    /// answers "nothing" to both questions, so the assertions are about this
    /// view of the ops rather than about their shape.
    fn def_and_use_names(ops: &[LlirInstr]) -> (Vec<String>, Vec<String>) {
        let mut defs = Vec::new();
        let mut uses = Vec::new();
        for instruction in ops {
            let (definition, used) = crate::ir::use_def::def_uses(&instruction.op);
            if let Some(VReg::Phys(name)) = definition {
                defs.push(name);
            }
            uses.extend(used.into_iter().filter_map(|register| match register {
                VReg::Phys(name) => Some(name),
                _ => None,
            }));
        }
        (defs, uses)
    }

    /// `movlpd %xmm0,-0x38(%rbp)` — the exact instruction clang `-O0` uses to
    /// spill a System V `xmm0:xmm1` aggregate return.
    ///
    /// It had no arm anywhere in `src/ir/`, so it lifted to `Op::Unknown`, whose
    /// single `mnemonic` field declares no reads at all. The consequence is not
    /// "conservative": the returned struct's only consumer disappeared, the
    /// `SsePair` result split lost every user and was eliminated as dead, and
    /// `ast::float_gate` — which reads the trailing `pd` as an unmodelled float
    /// producer — shut the whole-function gate on top of that.
    ///
    /// The source is read through the WHOLE-REGISTER spelling. That is the one
    /// the views are synchronised INTO: a lane write is mirrored to the scalar
    /// name, a scalar write is not mirrored to the lanes, so reading the lanes
    /// here would find nothing after any `movsd`/`cvtsi2sd` producer.
    #[test]
    fn movlpd_stores_the_low_quadword_as_one_eight_byte_access() {
        let ops = lift64(&[0x66, 0x0F, 0x13, 0x45, 0xC8]); // movlpd %xmm0,-0x38(%rbp)
        let stores: Vec<(i64, u8, String)> = ops
            .iter()
            .filter_map(|instruction| match &instruction.op {
                Op::Store {
                    addr,
                    src: Value::Reg(VReg::Phys(src)),
                } => Some((addr.disp, addr.size, src.clone())),
                _ => None,
            })
            .collect();
        assert_eq!(
            stores,
            vec![(-0x38, 8, "xmm0".to_string())],
            "one 64-bit store, from the spelling both producers reach: {ops:#?}"
        );
        assert!(
            !ops.iter()
                .any(|instruction| matches!(&instruction.op, Op::Unknown { .. })),
            "no residual opaque marker may survive: {ops:#?}"
        );
        let (defs, uses) = def_and_use_names(&ops);
        assert!(defs.is_empty(), "a store defines no register: {defs:?}");
        assert!(
            uses.iter().any(|name| name == "xmm0"),
            "the source register must be VISIBLE to register dataflow: {uses:?}"
        );
    }

    /// `movlpd -0x38(%rbp),%xmm0` writes the low half and — unlike MOVQ — leaves
    /// the high half exactly as it was.
    ///
    /// Reusing [`packed_qword_move_ops`] here would invent the zero MOVQ writes
    /// into bits 64..127, which this instruction does not. All three names the
    /// transferred bits have get defined, so both XMM spellings agree.
    #[test]
    fn movlpd_loads_the_low_quadword_without_touching_the_high_one() {
        let ops = lift64(&[0x66, 0x0F, 0x12, 0x45, 0xC8]); // movlpd -0x38(%rbp),%xmm0
        let loads: Vec<(i64, u8)> = ops
            .iter()
            .filter_map(|instruction| match &instruction.op {
                Op::Load { addr, .. } => Some((addr.disp, addr.size)),
                _ => None,
            })
            .collect();
        assert_eq!(
            loads,
            vec![(-0x38, 8)],
            "the machine performs ONE 64-bit read: {ops:#?}"
        );
        let (defs, _) = def_and_use_names(&ops);
        assert_eq!(
            defs,
            vec![
                "xmm0_d0".to_string(),
                "xmm0_d1".to_string(),
                "xmm0".to_string()
            ],
            "both lanes and the scalar view are defined, and nothing else: {ops:#?}"
        );
        assert!(
            !defs
                .iter()
                .any(|name| name == "xmm0_d2" || name == "xmm0_d3"),
            "MOVLPD preserves bits 64..127; MOVQ's zeroing must not leak in: {defs:?}"
        );
    }

    /// `movhpd -0x38(%rbp),%xmm1` writes lanes 2 and 3 from the address the
    /// operand names — the displacement counts from the m64, not from the half
    /// of the register it lands in.
    ///
    /// And it must NOT redefine the whole-register spelling: that name is the
    /// low quadword, which MOVHPD does not touch. Rebuilding it here would
    /// overwrite a live scalar value with lanes nobody wrote.
    #[test]
    fn movhpd_loads_the_high_quadword_and_leaves_the_scalar_view_alone() {
        let ops = lift64(&[0x66, 0x0F, 0x16, 0x4D, 0xC8]); // movhpd -0x38(%rbp),%xmm1
        let loads: Vec<(i64, u8)> = ops
            .iter()
            .filter_map(|instruction| match &instruction.op {
                Op::Load { addr, .. } => Some((addr.disp, addr.size)),
                _ => None,
            })
            .collect();
        assert_eq!(
            loads,
            vec![(-0x38, 8)],
            "the high half is read from the operand address itself: {ops:#?}"
        );
        let (defs, _) = def_and_use_names(&ops);
        assert_eq!(
            defs,
            vec!["xmm1_d2".to_string(), "xmm1_d3".to_string()],
            "the scalar view is the LOW quadword and MOVHPD does not write it: {ops:#?}"
        );
    }

    /// `movhpd %xmm1,-0x30(%rbp)` reads lanes 2 and 3. Bits 64..127 have no
    /// scalar spelling, so unlike the LOW store this one has to assemble the
    /// transferred quadword from the lanes.
    #[test]
    fn movhpd_stores_the_high_quadword() {
        let ops = lift64(&[0x66, 0x0F, 0x17, 0x4D, 0xD0]); // movhpd %xmm1,-0x30(%rbp)
        let stores: Vec<(i64, u8)> = ops
            .iter()
            .filter_map(|instruction| match &instruction.op {
                Op::Store { addr, .. } => Some((addr.disp, addr.size)),
                _ => None,
            })
            .collect();
        assert_eq!(stores, vec![(-0x30, 8)], "one 64-bit store: {ops:#?}");
        assert!(
            ops.iter().any(|instruction| matches!(
                &instruction.op,
                Op::Concat {
                    hi: Value::Reg(VReg::Phys(hi)),
                    lo: Value::Reg(VReg::Phys(lo)),
                    ..
                } if hi == "xmm1_d3" && lo == "xmm1_d2"
            )),
            "the stored value is lane 3 over lane 2: {ops:#?}"
        );
        let (_, uses) = def_and_use_names(&ops);
        assert!(
            uses.iter().any(|name| name == "xmm1_d2") && uses.iter().any(|name| name == "xmm1_d3"),
            "both high lanes must be VISIBLE to register dataflow: {uses:?}"
        );
    }

    /// MOVLPS/MOVHPS move the same 64 bits as MOVLPD/MOVHPD — two packed floats
    /// instead of one double — so the identical lowering serves them. The
    /// encodings differ only by the absent `66` prefix.
    #[test]
    fn movlps_and_movhps_get_the_same_half_register_lowering() {
        for (packed_double, packed_single) in [
            (
                [0x66, 0x0F, 0x12, 0x45, 0xC8].as_slice(),
                [0x0F, 0x12, 0x45, 0xC8].as_slice(),
            ),
            (&[0x66, 0x0F, 0x13, 0x45, 0xC8], &[0x0F, 0x13, 0x45, 0xC8]),
            (&[0x66, 0x0F, 0x16, 0x45, 0xC8], &[0x0F, 0x16, 0x45, 0xC8]),
            (&[0x66, 0x0F, 0x17, 0x45, 0xC8], &[0x0F, 0x17, 0x45, 0xC8]),
        ] {
            let double: Vec<Op> = lift64(packed_double)
                .into_iter()
                .map(|instruction| instruction.op)
                .collect();
            let single: Vec<Op> = lift64(packed_single)
                .into_iter()
                .map(|instruction| instruction.op)
                .collect();
            assert!(
                !double.iter().any(|op| matches!(op, Op::Unknown { .. })),
                "{packed_double:02x?} still opaque: {double:#?}"
            );
            assert_eq!(
                double, single,
                "the `pd` and `ps` spellings move the same bits: {packed_double:02x?}"
            );
        }
    }

    /// PIN — `iced_x86` has no register/register encoding for ANY of the four.
    ///
    /// `MOVLHPS`/`MOVHLPS` are the reg-reg operations and carry their own
    /// mnemonics, so the eight `Code` variants below are the complete set the
    /// dispatch must serve. If a future `iced_x86` widens one of these
    /// mnemonics, this test fails and the lowering gets looked at before the
    /// new form silently takes the memory arm's semantics.
    #[test]
    fn the_half_register_moves_have_only_memory_forms() {
        use iced_x86::{Code, Mnemonic};

        let mut found = Vec::new();
        for raw in 0..u16::MAX {
            let Ok(code) = Code::try_from(raw as usize) else {
                continue;
            };
            if matches!(
                code.mnemonic(),
                Mnemonic::Movlpd | Mnemonic::Movhpd | Mnemonic::Movlps | Mnemonic::Movhps
            ) {
                found.push(format!("{code:?}"));
            }
        }
        found.sort();
        assert_eq!(
            found,
            vec![
                "Movhpd_m64_xmm",
                "Movhpd_xmm_m64",
                "Movhps_m64_xmm",
                "Movhps_xmm_m64",
                "Movlpd_m64_xmm",
                "Movlpd_xmm_m64",
                "Movlps_m64_xmm",
                "Movlps_xmm_m64",
            ],
            "every form is a memory form; there is no register/register encoding"
        );
    }

    /// The census predicate of
    /// [`unmodelled_instructions_that_silently_claim_no_register_write`],
    /// factored out so it can be demonstrated on single encodings as well as
    /// swept over the corpus.
    ///
    /// Two op shapes tell [`crate::ir::use_def`] that no register was written.
    /// [`Op::Unknown`] declares no footprint at all, in memory or in registers,
    /// so it is an undeclared residue whatever surrounds it. An
    /// [`Op::Intrinsic`] with empty `outs` — the shape [`Op::opaque`] builds —
    /// declares its MEMORY footprint honestly and says nothing about registers,
    /// so it is a lie only when nothing else in the same lift declares the
    /// write.
    ///
    /// That qualification is why this is not simply `outs.is_empty()`, and it
    /// is measured rather than supposed: `rep stos` emits a `memory.fill.*`
    /// intrinsic with empty `outs` beside ORDINARY LLIR that updates RDI and
    /// RCX, and over the committed corpus the unqualified predicate adds
    /// `stosd` (38) and `stosq` (16) for declaring their register writes in the
    /// place the IR is meant to declare them. In the same sweep no
    /// `Op::Unknown` shares a lift with a physical-register definition, so the
    /// asymmetry between the two clauses changes no entry today and only
    /// decides how a future arm is read.
    fn hides_its_register_writes(ops: &[Op]) -> bool {
        if ops.iter().any(|op| matches!(op, Op::Unknown { .. })) {
            return true;
        }
        ops.iter()
            .any(|op| matches!(op, Op::Intrinsic { outs, .. } if outs.is_empty()))
            && !ops.iter().any(|op| {
                crate::ir::use_def::defs_uses(op)
                    .0
                    .iter()
                    .any(|register| matches!(register, VReg::Phys(_)))
            })
    }

    /// The new half of the census predicate, demonstrated rather than asserted.
    ///
    /// The bypass the census exists to close is one edit wide: replace an arm's
    /// `Op::Unknown { mnemonic }` with `Op::opaque(mnemonic)` and the mnemonic
    /// leaves `SILENT_REGISTER_WRITERS` while its destination remains exactly as
    /// invisible to register dataflow as it was. Both spellings of `bsr` below
    /// are therefore caught; and `rep stosq`, which really does declare its
    /// register writes and merely keeps its memory effect in an operandless
    /// intrinsic, is not.
    #[test]
    fn the_census_predicate_reads_op_opaque_as_the_lie_it_is() {
        assert!(
            hides_its_register_writes(&[Op::Unknown {
                mnemonic: "bsr".into()
            }]),
            "an Op::Unknown declares no footprint at all"
        );
        assert!(
            hides_its_register_writes(&[Op::opaque("bsr")]),
            "Op::opaque is an Op::Intrinsic with empty outs, which declares no \
             register write either -- rewriting an arm to it must not be a way \
             off the list"
        );

        // `rep stosq` (f3 48 ab). Its lift pairs an operandless `memory.fill.*`
        // intrinsic with ordinary LLIR that updates RDI and RCX, so the empty
        // `outs` is a memory declaration, not a hidden register write.
        let ops = lift_one(&decode64(&[0xf3, 0x48, 0xab]), 64);
        assert!(
            ops.iter()
                .any(|op| matches!(op, Op::Intrinsic { outs, .. } if outs.is_empty())),
            "the qualification is only exercised if this lift really does \
             contain an empty-outs intrinsic: {ops:#?}"
        );
        assert!(
            !hides_its_register_writes(&ops),
            "rep stosq declares RDI and RCX in ordinary ops: {ops:#?}"
        );

        // A fully modelled instruction is not on the list for any reason.
        assert!(
            !hides_its_register_writes(&lift_one(&decode64(&[0x48, 0x0f, 0xc8]), 64)),
            "bswap rax lifts to a declared, single-output intrinsic"
        );
    }

    /// Decode exactly one 64-bit instruction, the way the corpus sweep does.
    fn decode64(bytes: &[u8]) -> iced_x86::Instruction {
        let mut decoder =
            iced_x86::Decoder::with_ip(64, bytes, 0x1000, iced_x86::DecoderOptions::NONE);
        let instruction = decoder.decode();
        assert!(!instruction.is_invalid(), "{bytes:02x?} did not decode");
        instruction
    }

    /// Every committed x86-64 sample, paired with the byte ranges that are
    /// PROVABLY code: sized `STT_FUNC` symbols and nothing else.
    ///
    /// A linear sweep of the whole `.text` also decodes alignment padding, jump
    /// tables and constant pools as if they were instructions, and the junk it
    /// invents (`aesenc`, `xlatb`, `iretd`, `in`) dominates any census taken
    /// over it — 79 mnemonics from padding against 52 real ones when this was
    /// first measured. A sized `STT_FUNC` symbol is code the producer said is
    /// code.
    ///
    /// Returns an empty vector when the corpus is absent, so a checkout without
    /// `samples/` degrades to a skip rather than a failure.
    ///
    /// Shared by the two sweeps below because they have to agree on the
    /// population: a false positive only means something if it was measured
    /// over the same bytes as the census it is qualifying.
    fn census_corpus() -> Vec<(Vec<u8>, Vec<(usize, usize)>)> {
        use object::{Object, ObjectSection, ObjectSymbol};

        let root = std::path::Path::new("samples/binaries/platforms/linux/amd64");
        if !root.exists() {
            return Vec::new();
        }
        let mut binaries: Vec<std::path::PathBuf> = Vec::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(directory) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&directory) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.extension().is_none() {
                    binaries.push(path);
                }
            }
        }
        binaries.sort();
        assert!(
            binaries.len() > 50,
            "the census needs the committed corpus; found {}",
            binaries.len()
        );

        let mut corpus = Vec::new();
        for path in &binaries {
            let Ok(data) = std::fs::read(path) else {
                continue;
            };
            let Ok(object) = crate::decompile::profile::parse_object(data.as_slice()) else {
                continue;
            };
            if object.architecture() != object::Architecture::X86_64 {
                continue;
            }
            let mut ranges: Vec<(usize, usize)> = Vec::new();
            for symbol in object.symbols() {
                if symbol.kind() != object::SymbolKind::Text || symbol.size() == 0 {
                    continue;
                }
                let Some(section) = symbol
                    .section_index()
                    .and_then(|index| object.section_by_index(index).ok())
                else {
                    continue;
                };
                let Some((section_offset, _)) = section.file_range() else {
                    continue;
                };
                let start = (section_offset + (symbol.address() - section.address())) as usize;
                let end = start + symbol.size() as usize;
                if end <= data.len() && start < end {
                    ranges.push((start, end));
                }
            }
            drop(object);
            if !ranges.is_empty() {
                corpus.push((data, ranges));
            }
        }
        corpus
    }

    /// The naive predicate's false positives, MEASURED rather than asserted.
    ///
    /// "Any empty `outs`" is the obvious way to write
    /// [`hides_its_register_writes`], and it is wrong — because an empty `outs`
    /// is also how a DELIBERATE memory-only effect is spelled. `rep stosd`
    /// lowers to an operandless `memory.fill.*` intrinsic paired with ordinary
    /// LLIR that updates RDI and RCX: the empty `outs` is a statement about
    /// memory, and the register writes are right there in the same lift.
    ///
    /// [`the_census_predicate_reads_op_opaque_as_the_lie_it_is`] pins that for
    /// one hand-written encoding. This pins the POPULATION: over the same bytes
    /// the census sweeps, the naive predicate fires on exactly the string
    /// MOVE and string STORE families, which the qualified one correctly
    /// ignores. Both lower to a `memory.*` effect whose intrinsic carries no
    /// `outs` because the write is to MEMORY; for the moves, `rdi`, `rsi` and
    /// `rcx` are declared by ordinary LLIR assignments emitted beside the
    /// intrinsic, not by the intrinsic itself. `movsd` appears here in its
    /// STRING form (`Movsd_m32_m32`), which is a different instruction from
    /// the SSE scalar-double `movsd` despite sharing a mnemonic.
    ///
    /// This list grew from {stosd, stosq} to include the moves when `rep movs`
    /// was lifted, and the growth is the test working: it forced the reason
    /// above to be written down rather than absorbed. If a mnemonic appears
    /// here that is NOT a `memory.*` effect, that is the sloppy-predicate case
    /// and the assertion names it — which is the
    /// only way to tell "the predicate found something new" apart from "the
    /// predicate got sloppier", and the census itself cannot tell them apart
    /// because a loosened predicate makes its list GROW, which reads exactly
    /// like a regression somewhere else.
    ///
    /// Kept as its own test so that a change to either sweep cannot silently
    /// absorb the other's failure.
    #[test]
    fn the_deliberately_empty_outs_are_exactly_the_string_stores() {
        use iced_x86::{Decoder, DecoderOptions};

        let corpus = census_corpus();
        if corpus.is_empty() {
            eprintln!("sample corpus missing; nothing to sweep");
            return;
        }
        let mut false_positives: std::collections::BTreeMap<String, usize> =
            std::collections::BTreeMap::new();
        for (data, ranges) in &corpus {
            for (start, end) in ranges {
                let mut decoder =
                    Decoder::with_ip(64, &data[*start..*end], 0x1000, DecoderOptions::NONE);
                for instruction in decoder.iter() {
                    if instruction.is_invalid() {
                        continue;
                    }
                    let ops = lift_one(&instruction, 64);
                    let naive = ops.iter().any(|op| {
                        matches!(op, Op::Unknown { .. })
                            || matches!(op, Op::Intrinsic { outs, .. } if outs.is_empty())
                    });
                    if naive && !hides_its_register_writes(&ops) {
                        *false_positives
                            .entry(format!("{:?}", instruction.mnemonic()).to_ascii_lowercase())
                            .or_default() += 1;
                    }
                }
            }
        }
        let observed: Vec<&str> = false_positives.keys().map(String::as_str).collect();
        assert_eq!(
            observed,
            vec!["movsb", "movsd", "movsq", "stosd", "stosq"],
            "these are the lifts a naive `empty outs` predicate would report as \
             hidden register writes and the qualified predicate correctly does \
             not: the string move and string store families, whose intrinsics \
             carry a MEMORY effect rather than a register write. Anything else \
             appearing here means the predicate got sloppier, not that the \
             corpus grew. Occurrences: {false_positives:?}"
        );
    }

    /// CENSUS — every x86-64 mnemonic this lifter leaves unmodelled while the
    /// ISA says it WRITES a register.
    ///
    /// `Op::Unknown` has one field, a mnemonic, so [`crate::ir::use_def`]
    /// answers "nothing" to both "what does this define" and "what does this
    /// read". The conservative form the function boundary migrates it to,
    /// [`Op::opaque`], is conservative about MEMORY only —
    /// `reads_mem: true, writes_mem: true` over `ins: []`, `outs: []`. An
    /// unmodelled instruction with a register destination is therefore not
    /// over-approximated but INVISIBLE: the def-use census believes the
    /// destination was never written, and whatever the register held before
    /// flows on to every later reader as if the instruction were not there.
    ///
    /// BOTH of those shapes are swept, because they tell register dataflow
    /// the same lie and only one of them looks like a gap. Flagging
    /// `Op::Unknown` alone would leave a documented bypass: rewrite the arm
    /// as `Op::opaque(mnemonic)` and the mnemonic leaves this list while its
    /// destination stays exactly as invisible as before. No arm of `lift_one`
    /// has taken that route — every entry that has left the list left it by
    /// being lifted or by declaring its destination — and the point of covering
    /// the shape is that taking it now fails the test instead of shrinking it.
    ///
    /// One place already has: [`lift_bytes_with_x87`] emits
    /// `Op::opaque("x87.<mnemonic>")` for every x87 instruction whose stack
    /// depth is unproven, and `lift_function` reaches the lifter through THAT,
    /// not through `lift_one`. This sweep therefore sees the x87 family as
    /// `Op::Unknown` (`fadd`, `fmul`, `fstp` and six more below) where the
    /// pipeline sees it as the opaque shape. Same lie about ST(i), counted
    /// once; a census over the pipeline entry point would be a different and
    /// larger test than this one.
    ///
    /// That is the mechanism, not a hypothesis. `movlpd` had no arm anywhere in
    /// `src/ir/`, and on `197_homogeneous_float_aggregates:clang:O0` it silently
    /// deleted an entire `xmm0:xmm1` aggregate return: the `SsePair` result
    /// split was computed correctly, found no users because its only consumers
    /// were operandless markers, and was eliminated as dead.
    ///
    /// This test changes nothing about the fallback — that is a larger change
    /// with its own risks. It makes the POPULATION visible and pins its size
    /// over the committed corpus, so the next instruction to join it arrives as
    /// a failing diff naming the mnemonic instead of as a wrong answer nobody
    /// can see. Raising `SILENT_REGISTER_WRITERS` is allowed; doing it without
    /// reading which mnemonic appeared is the thing this exists to stop.
    #[test]
    fn unmodelled_instructions_that_silently_claim_no_register_write() {
        use iced_x86::{Decoder, DecoderOptions, InstructionInfoFactory, OpAccess};

        /// Mnemonics observed to leave an `Op::Unknown` in their lift while
        /// `iced_x86` reports at least one written register, over the committed
        /// x86-64 sample corpus. Each one is a register definition the LLIR does
        /// not have and does not admit to not having.
        ///
        /// The shape of the list is itself the argument. It is not exotica: the
        /// 16-bit `bsr`, `syscall`, the x87 arithmetic this build has no depth
        /// solution for, and the VEX encodings of instructions whose SSE
        /// spellings ARE lifted.
        ///
        /// It was twenty-eight mnemonics and 1,130 occurrences after the
        /// bit-manipulation family left it. Three more arms took 602 of those
        /// off, and the three are worth distinguishing because they are three
        /// different answers to the same question:
        ///
        /// * `movsb` (242) and `movsq` (134) are LIFTED — see
        ///   [`string_ops::movs_ops`]. The string moves step RDI and RSI by the
        ///   element width and, under `rep`, drain RCX; none of that is
        ///   optional or unknowable, and leaving it undeclared meant every
        ///   `rep movsq` memcpy recovered with both pointers frozen at their
        ///   pre-loop values.
        /// * `aesenc` (222) is DECLARED, not modelled — see
        ///   [`packed_string::declare_xmm_register_effect_ops`]. Four
        ///   single-output intrinsics state which XMM lanes it writes and which
        ///   it reads; nothing pretends to know the round function.
        /// * `shrd` (4) was lifted for immediate counts only and fell through
        ///   for `shrd rdx,r11,cl`. [`wide_arith::double_shift_ops`] now covers
        ///   the CL form as well.
        ///
        /// The corpus this measures and the FIXTURE corpus agree on almost
        /// nothing, which is the more useful half of the finding. Every one of
        /// the ~200 fixture sources was compiled at `-O0` and `-O2` under both
        /// gcc and clang and the disassembly grepped: it contains no `movs`
        /// string move of any width, no `aesenc` and no `syscall` at all, and
        /// its 105 `shrd` and 104 `shld` sites are all immediate-count forms
        /// the existing arm already handled. These samples are glibc- and
        /// OpenSSL-shaped; the fixtures are compiled C. A mnemonic can be the
        /// largest entry here and have no `dectest` lane whatever, so a census
        /// count is not a priority and the two corpora have to be read
        /// together.
        ///
        /// The SSE string primitives glibc's `strlen`/`strcmp`/`memcmp` are
        /// built from used to be the largest cluster on this list -- `pcmpeqb`
        /// 204, `pcmpgtb` 220, `punpcklbw` 260, `pmovmskb` 222, `pshuflw` 232,
        /// `psrlq` 120, `pmuludq` 48, and nine more, 1,388 occurrences in
        /// total. `packed_string` took all seventeen off it, by two different
        /// routes: the word/dword/qword-granular members are lifted exactly,
        /// and the byte-parallel core emits a single-output `Op::Intrinsic` per
        /// destination lane that declares what it writes and what it reads
        /// without claiming to compute the value. Both routes satisfy this
        /// guard, and only the first claims to know the answer.
        ///
        /// The list covers the shape the second route could have taken and
        /// deliberately did not, as well as the one it did. `Op::opaque`
        /// builds an `Op::Intrinsic` with EMPTY `ins`/`outs`, so an arm
        /// rewritten from `Op::Unknown` to `Op::opaque` would be just as
        /// invisible to register dataflow; `lower_unknowns` performs exactly
        /// that rewrite on whatever survives lifting, so the pipeline this
        /// census is a proxy for is built out of the second shape. The
        /// census still measures the lifter rather than the pipeline, but it
        /// can no longer be satisfied by moving an entry between the two
        /// shapes.
        ///
        /// The guard is DEMONSTRATED, not asserted: deleting this commit's two
        /// dispatch arms and re-running puts `"movhps": 26` back on the list,
        /// which is every `movhps` in the corpus. It would not have caught
        /// `movlpd` on its own, because these samples contain no MOVLPD at all
        /// and its store form writes no register — that one needed the fixture
        /// corpus, which is compiled rather than committed and so cannot be
        /// swept from a unit test. This is the committed-corpus slice of the
        /// question, not the whole of it.
        ///
        /// The opaque half is demonstrated the same way, by taking the bypass
        /// and checking the list does not move. Rewriting `bit_scan_ops`'
        /// `unsupported()` fallback from `Op::Unknown` to `Op::opaque(mnemonic)`
        /// — one line, no change whatever to what the LLIR says about a
        /// register — drops `bsr` from the pre-2026-08-18 predicate, which reads
        /// as a mnemonic fixed and invites whoever is holding the constant to
        /// delete it. (`shrd` used to be dropped here too; its variable-count
        /// form is lifted now, so it has left the list for real.) The predicate
        /// here keeps every remaining entry and passes unchanged.
        /// Why a mnemonic on the list below is STILL on it.
        ///
        /// A bare list of names is a census nobody reads; the same list with a
        /// reason per entry is an ALLOWLIST, and the difference shows up when
        /// someone comes to shrink it. `bsr` and `syscall` sit next to each
        /// other alphabetically and are not remotely the same problem: one is
        /// an arm that handles the rest of its family and declines exactly one
        /// encoding, the other is a register write nothing has ever modelled.
        /// Ranking the list without that distinction ranks it by occurrence
        /// count, which is how `syscall` (310) and `aesenc` (222) -- the two
        /// largest entries, with zero occurrences between them in the fixture
        /// corpus -- end up looking like the place to start.
        ///
        /// Each assignment below is measured, not inferred: the sweep was rerun
        /// with `instruction.code()` and `InstructionInfoFactory`'s written
        /// registers printed, so the encoding and the destination behind every
        /// entry are known rather than assumed.
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        enum Silence {
            /// No dispatch arm exists at all. A register the ISA writes that
            /// this lifter has never had an opinion about. The prize category.
            NoArm,
            /// An arm exists and REFUSES this encoding, for a stated reason,
            /// rather than guessing. The answer is absent on purpose -- though
            /// absent invisibly, which is why these are still counted.
            FormRefused,
            /// x87. [`lift_bytes_with_x87`] is the pipeline's real entry point
            /// for these and emits `Op::opaque("x87.<mnemonic>")` whenever the
            /// stack depth is unproven, so the pipeline tells the same lie
            /// about `ST(i)` that this sweep sees as an `Op::Unknown`. ONE
            /// problem -- the x87 stack model -- counted nine times.
            X87Stack,
            /// The destination (or the source the destination is computed from)
            /// is a 256-bit `ymm`, and an XMM register in this IR is four
            /// 32-bit lanes: 128 bits, full stop. There is no name here to
            /// write bits 128..255 to. Lowering only the low half would be a
            /// different wrong answer, not a smaller one.
            WiderThanTheLaneModel,
            /// **Correct as it stands.** The instruction's whole architectural
            /// effect is on state this IR does not represent, so declaring no
            /// register write is the truth rather than a hole.
            ///
            /// `VEX_Vzeroupper` zeroes bits 128..255 of every vector register
            /// and touches nothing else; in a 128-bit lane model that is a
            /// no-op, and it appears here only because `iced_x86` reports the
            /// write at `ZMM0..ZMM15` granularity.
            ///
            /// This variant exists so that "correct" and "not done yet" stop
            /// looking identical in the census. Everything else on the list is
            /// work; this is a boundary.
            NoStateThisIrModels,
        }

        /// The allowlist: 28 mnemonics, 1,130 occurrences over the committed
        /// corpus. Every entry is a register definition the LLIR does not have;
        /// the reason says whether that is a gap or a boundary.
        ///
        /// Occurrence counts, for whoever ranks what to fix next: `syscall` 310,
        /// `movsb` 242, `aesenc` 222, `movsq` 134, `vmovdqu` 58, `fstp` 34,
        /// `vzeroupper` 26, `fxch` 14, `fmul` 12, `vpcmpeqb` 12, `fchs` 10,
        /// `vpmovmskb` 8, `cpuid` 6, `fadd` 6, `bsr` 4, `fsubp` 4, `shrd` 4,
        /// `vpxor` 4, and eight more at 2.
        ///
        /// **Those counts are the SAMPLE corpus, and it is not the population
        /// that decides what a fix is worth.** The samples are glibc- and
        /// OpenSSL-shaped; the decompiler fixture corpus is compiled C written
        /// to exercise the decompiler, and the two agree on almost nothing. Of
        /// these 28, **zero** occur in any fixture function that has a
        /// baselined verdict -- measured by disassembling all 782 objects in
        /// `tests/decompiler_fixtures/build` and joining the result to
        /// `baseline.json`. The seven mnemonics that came off this list on
        /// 2026-08-19 were chosen that way rather than by the counts above:
        /// `tzcnt` was 130 here and 139 there across 27 fixture functions,
        /// while `syscall` is 310 here and 0 there.
        const SILENT_REGISTER_WRITERS: &[(&str, Silence)] = &[
            // `Bsr_r16_rm16` only, all four of them: the 16-bit form is the one
            // `bit_scan_ops` declines. Its stated reason (that a 16-bit count
            // would need an `x86.clz.16` answering 16 too high) does not hold --
            // `bsr16(x) = 31 - clz32(zext16(x))` is exact with today's renderer;
            // the real blocker is that both operands are bit-preserving partial
            // views and the lowering writes neither through its parent.
            ("bsr", Silence::FormRefused),
            ("cpuid", Silence::NoArm),
            ("fadd", Silence::X87Stack),
            ("faddp", Silence::X87Stack),
            ("fchs", Silence::X87Stack),
            ("fisub", Silence::X87Stack),
            ("fmul", Silence::X87Stack),
            ("fstp", Silence::X87Stack),
            ("fsub", Silence::X87Stack),
            ("fsubp", Silence::X87Stack),
            ("fxch", Silence::X87Stack),
            ("popfq", Silence::NoArm),
            ("pushfq", Silence::NoArm),
            ("rdtsc", Silence::NoArm),
            ("rdtscp", Silence::NoArm),
            // Writes RCX and R11 (the return address and RFLAGS). RAX is the
            // kernel's doing, not the instruction's, and iced does not claim it.
            ("syscall", Silence::NoArm),
            ("vmovdqu", Silence::WiderThanTheLaneModel),
            ("vpand", Silence::WiderThanTheLaneModel),
            ("vpbroadcastb", Silence::WiderThanTheLaneModel),
            ("vpcmpeqb", Silence::WiderThanTheLaneModel),
            // `VEX_Vpmovmskb_r32_ymm`: the DESTINATION is an ordinary GP
            // register, but the source is a 256-bit `ymm` this IR cannot spell,
            // so the mask has no expression to be. The 128-bit `pmovmskb` is
            // lifted.
            ("vpmovmskb", Silence::WiderThanTheLaneModel),
            // Not a width problem: `VEX_Vpxor_xmm_xmm_xmmm128` is 128 bits and
            // the SSE `pxor` spelling IS lifted. The VEX encoding simply has no
            // arm.
            ("vpxor", Silence::NoArm),
            ("vzeroupper", Silence::NoStateThisIrModels),
            ("xgetbv", Silence::NoArm),
        ];

        // The comparison below is by name in sorted order, so a duplicate or a
        // misplaced entry would make it depend on how the table was edited.
        assert!(
            SILENT_REGISTER_WRITERS
                .windows(2)
                .all(|pair| pair[0].0 < pair[1].0),
            "SILENT_REGISTER_WRITERS must be sorted and free of duplicates"
        );

        let corpus = census_corpus();
        if corpus.is_empty() {
            eprintln!("sample corpus missing; nothing to sweep");
            return;
        }

        let mut factory = InstructionInfoFactory::new();
        let mut silent: std::collections::BTreeMap<String, usize> =
            std::collections::BTreeMap::new();
        for (data, ranges) in &corpus {
            for (start, end) in ranges {
                let bytes = &data[*start..*end];
                let mut decoder = Decoder::with_ip(64, bytes, 0x1000, DecoderOptions::NONE);
                for instruction in decoder.iter() {
                    if instruction.is_invalid() {
                        continue;
                    }
                    let ops = lift_one(&instruction, 64);
                    if !hides_its_register_writes(&ops) {
                        continue;
                    }
                    let writes_a_register =
                        factory
                            .info(&instruction)
                            .used_registers()
                            .iter()
                            .any(|used| {
                                matches!(
                                    used.access(),
                                    OpAccess::Write | OpAccess::ReadWrite | OpAccess::CondWrite
                                )
                            });
                    if writes_a_register {
                        *silent
                            .entry(format!("{:?}", instruction.mnemonic()).to_ascii_lowercase())
                            .or_default() += 1;
                    }
                }
            }
        }

        let observed: Vec<&str> = silent.keys().map(String::as_str).collect();
        let allowed: Vec<&str> = SILENT_REGISTER_WRITERS
            .iter()
            .map(|(mnemonic, _)| *mnemonic)
            .collect();
        assert_eq!(
            observed, allowed,
            "an unmodelled instruction with a register destination declares no \
             write at all, so its destination silently keeps its previous value. \
             An `Op::Unknown` and an `Op::opaque` that nothing else in the lift \
             covers count the same here, because register dataflow cannot tell \
             them apart. A mnemonic ADDED to this diff is a new hole and needs \
             a lift, not an allowlist entry; a mnemonic REMOVED is one that was \
             just fixed, and its entry goes with it. Occurrences: {silent:?}"
        );
    }

    // --- the SSE string-primitive family (`lift_x86::packed_string`) --------

    /// Byte encodings of the family, each verified by decoding it back rather
    /// than trusted from the modrm tables. Registers are `xmm0` (destination),
    /// `xmm1` (source) and `eax`/`rax` throughout.
    mod sse_string_encodings {
        pub const PUNPCKHQDQ: &[u8] = &[0x66, 0x0f, 0x6d, 0xc1];
        pub const PUNPCKHQDQ_IN_PLACE: &[u8] = &[0x66, 0x0f, 0x6d, 0xc0];
        pub const SHUFPD_1: &[u8] = &[0x66, 0x0f, 0xc6, 0xc1, 0x01];
        pub const PMULUDQ: &[u8] = &[0x66, 0x0f, 0xf4, 0xc1];
        pub const PSRLQ_6: &[u8] = &[0x66, 0x0f, 0x73, 0xd0, 0x06];
        pub const PSRLQ_65: &[u8] = &[0x66, 0x0f, 0x73, 0xd0, 0x41];
        pub const PSRLQ_BY_REGISTER: &[u8] = &[0x66, 0x0f, 0xd3, 0xc1];
        pub const PSHUFLW_D4: &[u8] = &[0xf2, 0x0f, 0x70, 0xc1, 0xd4];
        pub const PSHUFHW_0: &[u8] = &[0xf3, 0x0f, 0x70, 0xc1, 0x00];
        pub const PUNPCKLWD: &[u8] = &[0x66, 0x0f, 0x61, 0xc1];
        pub const PUNPCKLWD_IN_PLACE: &[u8] = &[0x66, 0x0f, 0x61, 0xc0];
        pub const PINSRW_WORD4: &[u8] = &[0x66, 0x0f, 0xc4, 0xc0, 0x04];
        pub const PINSRW_WORD5: &[u8] = &[0x66, 0x0f, 0xc4, 0xc0, 0x05];
        pub const PINSRD_LANE2: &[u8] = &[0x66, 0x0f, 0x3a, 0x22, 0xc0, 0x02];
        pub const PINSRQ_HIGH: &[u8] = &[0x66, 0x48, 0x0f, 0x3a, 0x22, 0xc0, 0x01];
        pub const PCMPEQB: &[u8] = &[0x66, 0x0f, 0x74, 0xc1];
        pub const PCMPGTB: &[u8] = &[0x66, 0x0f, 0x64, 0xc1];
        pub const PUNPCKLBW: &[u8] = &[0x66, 0x0f, 0x60, 0xc1];
        pub const PMOVMSKB: &[u8] = &[0x66, 0x0f, 0xd7, 0xc0];
        pub const PACKSSDW: &[u8] = &[0x66, 0x0f, 0x6b, 0xc1];
        pub const PSHUFB: &[u8] = &[0x66, 0x0f, 0x38, 0x00, 0xc1];
        pub const SHUFPD_1_IN_PLACE: &[u8] = &[0x66, 0x0f, 0xc6, 0xc0, 0x01];
        pub const PMULUDQ_IN_PLACE: &[u8] = &[0x66, 0x0f, 0xf4, 0xc0];
        pub const PSHUFLW_D4_IN_PLACE: &[u8] = &[0xf2, 0x0f, 0x70, 0xc0, 0xd4];
        pub const PUNPCKLBW_IN_PLACE: &[u8] = &[0x66, 0x0f, 0x60, 0xc0];
        pub const PACKSSDW_IN_PLACE: &[u8] = &[0x66, 0x0f, 0x6b, 0xc0];
        pub const PSHUFB_IN_PLACE: &[u8] = &[0x66, 0x0f, 0x38, 0x00, 0xc0];
        pub const PCMPGTD_RIP: &[u8] = &[0x66, 0x0f, 0x66, 0x05, 0x00, 0x00, 0x00, 0x00];

        /// Every encoding above, for the sweeps that assert a property of the
        /// whole family rather than of one member.
        pub const ALL: &[&[u8]] = &[
            PUNPCKHQDQ,
            PUNPCKHQDQ_IN_PLACE,
            SHUFPD_1,
            PMULUDQ,
            PSRLQ_6,
            PSRLQ_65,
            PSRLQ_BY_REGISTER,
            PSHUFLW_D4,
            PSHUFHW_0,
            PUNPCKLWD,
            PUNPCKLWD_IN_PLACE,
            PINSRW_WORD4,
            PINSRW_WORD5,
            PINSRD_LANE2,
            PINSRQ_HIGH,
            PCMPEQB,
            PCMPGTB,
            PUNPCKLBW,
            PMOVMSKB,
            PACKSSDW,
            PSHUFB,
            PCMPGTD_RIP,
            SHUFPD_1_IN_PLACE,
            PMULUDQ_IN_PLACE,
            PSHUFLW_D4_IN_PLACE,
            PUNPCKLBW_IN_PLACE,
            PACKSSDW_IN_PLACE,
            PSHUFB_IN_PLACE,
        ];
    }

    /// The lane values every value-level test below starts from. Chosen so no
    /// two bytes, words, dwords or quadwords of the two registers collide —
    /// a permutation that dropped a lane, swapped two, or read the wrong half
    /// of one cannot produce a coincidentally correct answer.
    const XMM0_LANES: [u64; 4] = [0x1122_3344, 0x5566_7788, 0x99aa_bbcc, 0xddee_ff00];
    const XMM1_LANES: [u64; 4] = [0xa1a2_a3a4, 0xb1b2_b3b4, 0xc1c2_c3c4, 0xd1d2_d3d4];

    /// A concrete evaluator for the op subset the packed lowerings emit.
    ///
    /// Asserting the op LIST of an exact lowering restates the implementation
    /// in a second notation and passes whether or not the lowering is right;
    /// asserting the VALUE it computes does not. `pshuflw`, `punpcklwd` and the
    /// `pinsr*` family are bit-field surgery inside a 32-bit lane, which is
    /// where an off-by-16 hides — so the tests below state the architectural
    /// result and let this run the lift to reach it.
    ///
    /// Deliberately not [`crate::exec::interp`]: that lives behind the `exec`
    /// feature, which `--features python-ext` does not build, so a test written
    /// against it would not run in the configuration this lifter ships in.
    ///
    /// `Op::Intrinsic` is NOT evaluated — an effect-only intrinsic has no value
    /// to evaluate, which is the entire point of it — so this is used only on
    /// the exactly-lifted members. `evaluated_every_op` returns whether the
    /// whole op list was understood, and the exact-lift tests assert it.
    fn evaluate_lanes(
        bytes: &[u8],
        seed: &[(&str, u64)],
    ) -> (std::collections::BTreeMap<String, u64>, bool) {
        use std::collections::BTreeMap;

        /// A `_dN` lane is 32 bits wide; every other name here is a temporary
        /// or a 64-bit general register.
        fn width_mask(name: &str) -> u64 {
            match name.split_once("_d") {
                Some((_, lane)) if matches!(lane, "0" | "1" | "2" | "3") => u64::from(u32::MAX),
                _ => u64::MAX,
            }
        }

        let mut physical: BTreeMap<String, u64> = seed
            .iter()
            .map(|(name, value)| ((*name).to_string(), *value))
            .collect();
        let mut temporaries: BTreeMap<u32, u64> = BTreeMap::new();
        let mut understood = true;

        let mut read = |register: &VReg,
                        physical: &BTreeMap<String, u64>,
                        temporaries: &BTreeMap<u32, u64>| match register {
            VReg::Phys(name) => *physical.get(name).unwrap_or(&0),
            VReg::Temp(id) => *temporaries.get(id).unwrap_or(&0),
            _ => 0,
        };

        for instruction in lift64(bytes) {
            let value_of = |value: &Value,
                            physical: &BTreeMap<String, u64>,
                            temporaries: &BTreeMap<u32, u64>| match value
            {
                Value::Const(constant) => *constant as u64,
                Value::Reg(register) => read(register, physical, temporaries),
                Value::Addr(address) => *address,
            };
            let computed = match &instruction.op {
                Op::Assign { dst, src } => {
                    Some((dst.clone(), value_of(src, &physical, &temporaries)))
                }
                Op::ZExt { dst, src, from, to } => {
                    let raw = value_of(src, &physical, &temporaries);
                    let narrowed = raw & bit_mask(u32::from(from.bits()));
                    Some((dst.clone(), narrowed & bit_mask(u32::from(to.bits()))))
                }
                Op::Trunc { dst, src, to, .. } => Some((
                    dst.clone(),
                    value_of(src, &physical, &temporaries) & bit_mask(u32::from(to.bits())),
                )),
                Op::Extract { dst, src, hi, lo } => Some((
                    dst.clone(),
                    (value_of(src, &physical, &temporaries) >> lo) & bit_mask(u32::from(hi - lo)),
                )),
                Op::Concat { dst, hi, lo } => {
                    // Every `Concat` in this family joins two 32-bit lanes.
                    let high = value_of(hi, &physical, &temporaries) & bit_mask(32);
                    let low = value_of(lo, &physical, &temporaries) & bit_mask(32);
                    Some((dst.clone(), (high << 32) | low))
                }
                Op::Bin { dst, op, lhs, rhs } => {
                    let left = value_of(lhs, &physical, &temporaries);
                    let right = value_of(rhs, &physical, &temporaries);
                    let result = match op {
                        BinOp::Add => left.wrapping_add(right),
                        BinOp::Sub => left.wrapping_sub(right),
                        BinOp::Mul => left.wrapping_mul(right),
                        BinOp::And => left & right,
                        BinOp::Or => left | right,
                        BinOp::Xor => left ^ right,
                        BinOp::Shl => left.wrapping_shl(right as u32),
                        BinOp::Shr => left.wrapping_shr(right as u32),
                        _ => {
                            understood = false;
                            0
                        }
                    };
                    Some((dst.clone(), result))
                }
                Op::Nop => None,
                _ => {
                    understood = false;
                    None
                }
            };
            match computed {
                Some((VReg::Phys(name), value)) => {
                    let masked = value & width_mask(&name);
                    physical.insert(name, masked);
                }
                Some((VReg::Temp(id), value)) => {
                    temporaries.insert(id, value);
                }
                Some(_) | None => {}
            }
        }
        (physical, understood)
    }

    /// Low `bits` bits set; `bits == 64` is the whole word.
    fn bit_mask(bits: u32) -> u64 {
        if bits >= 64 {
            u64::MAX
        } else {
            (1u64 << bits) - 1
        }
    }

    /// The four lanes of `register` after lifting `bytes` over the standard
    /// seed, plus the assertion that every op was evaluable.
    fn lanes_after(bytes: &[u8]) -> [u64; 4] {
        let seed: Vec<(String, u64)> = (0..4)
            .flat_map(|lane| {
                [
                    (format!("xmm0_d{lane}"), XMM0_LANES[lane]),
                    (format!("xmm1_d{lane}"), XMM1_LANES[lane]),
                ]
            })
            .collect();
        let borrowed: Vec<(&str, u64)> = seed
            .iter()
            .map(|(name, value)| (name.as_str(), *value))
            .collect();
        let (state, understood) = evaluate_lanes(bytes, &borrowed);
        assert!(
            understood,
            "an exactly-lifted member emitted an op the value test cannot evaluate: {:#?}",
            lift64(bytes)
        );
        std::array::from_fn(|lane| *state.get(&format!("xmm0_d{lane}")).unwrap_or(&0))
    }

    #[test]
    fn punpckhqdq_takes_the_high_quadword_of_each_operand() {
        assert_eq!(
            lanes_after(sse_string_encodings::PUNPCKHQDQ),
            [XMM0_LANES[2], XMM0_LANES[3], XMM1_LANES[2], XMM1_LANES[3]]
        );
        // The in-place form is the one a lowering that wrote before it read
        // would get wrong: `punpckhqdq %xmm0,%xmm0` broadcasts the high half.
        assert_eq!(
            lanes_after(sse_string_encodings::PUNPCKHQDQ_IN_PLACE),
            [XMM0_LANES[2], XMM0_LANES[3], XMM0_LANES[2], XMM0_LANES[3]]
        );
    }

    #[test]
    fn shufpd_selects_one_quadword_from_each_operand_by_immediate() {
        // imm 1: bit 0 picks the destination's HIGH quadword for the result's
        // low half; bit 1 is clear, so the source's LOW quadword becomes the
        // result's high half.
        assert_eq!(
            lanes_after(sse_string_encodings::SHUFPD_1),
            [XMM0_LANES[2], XMM0_LANES[3], XMM1_LANES[0], XMM1_LANES[1]]
        );
    }

    #[test]
    fn pmuludq_multiplies_the_even_dwords_into_full_quadwords() {
        let low = XMM0_LANES[0] * XMM1_LANES[0];
        let high = XMM0_LANES[2] * XMM1_LANES[2];
        assert_eq!(
            lanes_after(sse_string_encodings::PMULUDQ),
            [low & 0xffff_ffff, low >> 32, high & 0xffff_ffff, high >> 32]
        );
    }

    #[test]
    fn psrlq_shifts_each_quadword_and_zeroes_past_sixty_three() {
        let low = ((XMM0_LANES[1] << 32) | XMM0_LANES[0]) >> 6;
        let high = ((XMM0_LANES[3] << 32) | XMM0_LANES[2]) >> 6;
        assert_eq!(
            lanes_after(sse_string_encodings::PSRLQ_6),
            [low & 0xffff_ffff, low >> 32, high & 0xffff_ffff, high >> 32]
        );
        // Intel specifies a ZERO result for a count above 63, not a masked
        // count — 0x41 is 65, which a `& 63` would turn into a shift by one.
        assert_eq!(lanes_after(sse_string_encodings::PSRLQ_65), [0, 0, 0, 0]);
    }

    #[test]
    fn pshuflw_permutes_the_low_four_words_and_copies_the_high_quadword() {
        // Control 0xd4 selects source words 0, 1, 1, 3.
        let word = |index: usize| (XMM1_LANES[index / 2] >> ((index % 2) * 16)) & 0xffff;
        assert_eq!(
            lanes_after(sse_string_encodings::PSHUFLW_D4),
            [
                word(0) | (word(1) << 16),
                word(1) | (word(3) << 16),
                XMM1_LANES[2],
                XMM1_LANES[3],
            ]
        );
    }

    #[test]
    fn pshufhw_permutes_the_high_four_words_and_copies_the_low_quadword() {
        // Control 0 broadcasts source word 4 across the high quadword.
        let word4 = XMM1_LANES[2] & 0xffff;
        assert_eq!(
            lanes_after(sse_string_encodings::PSHUFHW_0),
            [
                XMM1_LANES[0],
                XMM1_LANES[1],
                word4 | (word4 << 16),
                word4 | (word4 << 16),
            ]
        );
    }

    #[test]
    fn punpcklwd_interleaves_the_low_four_words_of_each_operand() {
        let destination = |index: usize| (XMM0_LANES[index / 2] >> ((index % 2) * 16)) & 0xffff;
        let source = |index: usize| (XMM1_LANES[index / 2] >> ((index % 2) * 16)) & 0xffff;
        assert_eq!(
            lanes_after(sse_string_encodings::PUNPCKLWD),
            std::array::from_fn(|lane| destination(lane) | (source(lane) << 16))
        );
        // In place, every result word is doubled.
        assert_eq!(
            lanes_after(sse_string_encodings::PUNPCKLWD_IN_PLACE),
            std::array::from_fn(|lane| destination(lane) | (destination(lane) << 16))
        );
    }

    #[test]
    fn pinsr_writes_one_field_and_leaves_every_other_lane_intact() {
        let inserted = 0x1234_abcdu64;
        let with_eax = |bytes: &[u8]| {
            let seed: Vec<(String, u64)> = (0..4)
                .map(|lane| (format!("xmm0_d{lane}"), XMM0_LANES[lane]))
                .chain([("eax".to_string(), inserted), ("rax".to_string(), inserted)])
                .collect();
            let borrowed: Vec<(&str, u64)> = seed
                .iter()
                .map(|(name, value)| (name.as_str(), *value))
                .collect();
            let (state, understood) = evaluate_lanes(bytes, &borrowed);
            assert!(understood, "pinsr lowering emitted an unevaluable op");
            std::array::from_fn::<u64, 4, _>(|lane| {
                *state.get(&format!("xmm0_d{lane}")).unwrap_or(&0)
            })
        };
        // Word 4 is the LOW half of lane 2; word 5 is its high half. The three
        // other lanes must be untouched in both cases — an unlifted `pinsrw`
        // did not merely lose the inserted field, it lost the statement that
        // the rest of the register survives.
        assert_eq!(
            with_eax(sse_string_encodings::PINSRW_WORD4),
            [
                XMM0_LANES[0],
                XMM0_LANES[1],
                (XMM0_LANES[2] & 0xffff_0000) | (inserted & 0xffff),
                XMM0_LANES[3],
            ]
        );
        assert_eq!(
            with_eax(sse_string_encodings::PINSRW_WORD5),
            [
                XMM0_LANES[0],
                XMM0_LANES[1],
                (XMM0_LANES[2] & 0xffff) | ((inserted & 0xffff) << 16),
                XMM0_LANES[3],
            ]
        );
        assert_eq!(
            with_eax(sse_string_encodings::PINSRD_LANE2),
            [XMM0_LANES[0], XMM0_LANES[1], inserted, XMM0_LANES[3]]
        );
        // PINSRQ writes a whole quadword, which is two lanes.
        assert_eq!(
            with_eax(sse_string_encodings::PINSRQ_HIGH),
            [
                XMM0_LANES[0],
                XMM0_LANES[1],
                inserted & 0xffff_ffff,
                inserted >> 32,
            ]
        );
    }

    /// Every `(name, ins, outs)` triple of the intrinsics one lift emitted.
    fn intrinsics_of(bytes: &[u8]) -> Vec<(String, Vec<String>, Vec<String>)> {
        lift64(bytes)
            .into_iter()
            .filter_map(|instruction| match instruction.op {
                Op::Intrinsic {
                    name, ins, outs, ..
                } => Some((
                    name,
                    ins.iter()
                        .map(|value| format!("{value}").trim_start_matches('%').to_string())
                        .collect(),
                    outs.iter()
                        .map(|(register, _)| {
                            format!("{register}").trim_start_matches('%').to_string()
                        })
                        .collect(),
                )),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn byte_parallel_compares_declare_one_lane_local_effect_per_lane() {
        // PCMPEQB and PCMPGTB compare sixteen bytes independently, so result
        // lane N depends on lane N of both operands and on nothing else. Four
        // single-output intrinsics state exactly that. They are NOT given a
        // value: a scalar transliteration of sixteen byte compares is ~80 ops
        // whose only consumer in real code is `pmovmskb`.
        for (bytes, expected) in [
            (sse_string_encodings::PCMPEQB, "x86.pcmpeqb"),
            (sse_string_encodings::PCMPGTB, "x86.pcmpgtb"),
        ] {
            let intrinsics = intrinsics_of(bytes);
            assert_eq!(intrinsics.len(), 4, "{expected}: {intrinsics:?}");
            for (lane, (name, ins, outs)) in intrinsics.iter().enumerate() {
                assert_eq!(name, expected);
                assert_eq!(ins, &[format!("xmm0_d{lane}"), format!("xmm1_d{lane}")]);
                assert_eq!(outs, &[format!("xmm0_d{lane}")]);
            }
        }
    }

    #[test]
    fn punpcklbw_names_its_two_halves_apart() {
        // Result lanes 0 and 1 are two DIFFERENT functions of the same input
        // pair. One shared name would let value numbering collapse them, so the
        // low and high halves are named apart.
        let intrinsics = intrinsics_of(sse_string_encodings::PUNPCKLBW);
        let expected: Vec<(String, Vec<String>, Vec<String>)> = (0..4)
            .map(|lane| {
                let input = lane / 2;
                (
                    format!("x86.punpcklbw.{}", if lane % 2 == 0 { "lo" } else { "hi" }),
                    vec![format!("t{}", 138 + input), format!("xmm1_d{input}")],
                    vec![format!("xmm0_d{lane}")],
                )
            })
            .collect();
        assert_eq!(intrinsics, expected);
    }

    #[test]
    fn pmovmskb_declares_a_general_register_write_from_four_lanes() {
        // The escape point out of the vector domain: in a real `strlen` this
        // mask is what the following `bsf` branches on, and while it was
        // unlifted that `bsf` read a register nothing in the function defined.
        let intrinsics = intrinsics_of(sse_string_encodings::PMOVMSKB);
        assert_eq!(intrinsics.len(), 1);
        assert_eq!(intrinsics[0].0, "x86.pmovmskb");
        assert_eq!(
            intrinsics[0].1,
            (0..4)
                .map(|lane| format!("xmm0_d{lane}"))
                .collect::<Vec<_>>()
        );
        // A 32-bit destination on x86-64 zero-extends into its parent, which is
        // what `movd`'s GPR form already records; the mask must not be written
        // as a bare 32-bit assignment that leaves `rax`'s high half undefined.
        assert!(
            lift64(sse_string_encodings::PMOVMSKB)
                .iter()
                .any(|instruction| matches!(
                    &instruction.op,
                    Op::ZExt { dst: VReg::Phys(name), to: Width::W64, .. } if name == "eax"
                )),
            "{:#?}",
            lift64(sse_string_encodings::PMOVMSKB)
        );
    }

    #[test]
    fn packssdw_pairs_the_lanes_each_result_lane_saturates_from() {
        let intrinsics = intrinsics_of(sse_string_encodings::PACKSSDW);
        assert_eq!(intrinsics.len(), 4);
        assert!(intrinsics.iter().all(|(name, ..)| name == "x86.packssdw"));
        assert_eq!(
            intrinsics
                .iter()
                .map(|(_, ins, outs)| (ins.clone(), outs.clone()))
                .collect::<Vec<_>>(),
            vec![
                (vec!["t138".into(), "t139".into()], vec!["xmm0_d0".into()]),
                (vec!["t140".into(), "t141".into()], vec!["xmm0_d1".into()]),
                (
                    vec!["xmm1_d0".into(), "xmm1_d1".into()],
                    vec!["xmm0_d2".into()]
                ),
                (
                    vec!["xmm1_d2".into(), "xmm1_d3".into()],
                    vec!["xmm0_d3".into()]
                ),
            ]
        );
    }

    #[test]
    fn pshufb_declares_every_output_lane_dependent_on_every_input_lane() {
        // The one member with no static expression at all: its byte indices are
        // a runtime register value, so each output byte is a sixteen-way select
        // on something no analysis can read off the encoding.
        let intrinsics = intrinsics_of(sse_string_encodings::PSHUFB);
        assert_eq!(intrinsics.len(), 4);
        for (lane, (name, ins, outs)) in intrinsics.iter().enumerate() {
            assert_eq!(name, &format!("x86.pshufb.lane{lane}"));
            assert_eq!(ins.len(), 8, "table lanes and index lanes");
            assert_eq!(outs, &[format!("xmm0_d{lane}")]);
        }
    }

    #[test]
    fn a_shape_an_exact_lowering_declines_still_declares_its_effect() {
        // `psrlq %xmm1,%xmm0` takes its count from the low quadword of an XMM
        // register. That is not lifted — inventing a second quadword read is
        // not better than declining — but declining must not mean vanishing.
        let intrinsics = intrinsics_of(sse_string_encodings::PSRLQ_BY_REGISTER);
        assert_eq!(intrinsics.len(), 4);
        for (lane, (name, _, outs)) in intrinsics.iter().enumerate() {
            assert_eq!(name, &format!("x86.psrlq.lane{lane}"));
            assert_eq!(outs, &[format!("xmm0_d{lane}")]);
        }
    }

    #[test]
    fn pcmpgtd_compares_against_a_memory_operand_too() {
        // The register form was already lifted; the memory form fell through to
        // `Op::Unknown` and was every one of `pcmpgtd`'s twelve appearances in
        // the sample corpus.
        let ops = lift64(sse_string_encodings::PCMPGTD_RIP);
        assert!(
            !ops.iter()
                .any(|instruction| matches!(instruction.op, Op::Unknown { .. })),
            "{ops:#?}"
        );
        assert_eq!(
            ops.iter()
                .filter(|instruction| matches!(instruction.op, Op::Load { .. }))
                .count(),
            4,
            "one load per compared lane: {ops:#?}"
        );
        assert_eq!(
            ops.iter()
                .filter(|instruction| matches!(instruction.op, Op::Ite { .. }))
                .count(),
            4
        );
    }

    #[test]
    fn an_operand_named_twice_is_read_before_the_destination_is_overwritten() {
        // `packed_dword_sources` hands back LIVE lane names for a register
        // operand, which is right when the two registers differ and silently
        // wrong when they do not: every lowering here writes destination lane 0
        // before reading source lane 1 or 2, so `shufpd $1,%xmm0,%xmm0` would
        // have read a lane this same instruction had already overwritten. The
        // destination was snapshotted from the start; the source needed the
        // same treatment, and only when it aliases.
        //
        // Checked by VALUE for the exactly-lifted members, because that is the
        // only form of this bug that produces a wrong number rather than a
        // wrong-looking op list.
        assert_eq!(
            lanes_after(sse_string_encodings::SHUFPD_1_IN_PLACE),
            [XMM0_LANES[2], XMM0_LANES[3], XMM0_LANES[0], XMM0_LANES[1]]
        );
        let product = XMM0_LANES[2] * XMM0_LANES[2];
        assert_eq!(
            lanes_after(sse_string_encodings::PMULUDQ_IN_PLACE)[2..],
            [product & 0xffff_ffff, product >> 32]
        );
        let word = |index: usize| (XMM0_LANES[index / 2] >> ((index % 2) * 16)) & 0xffff;
        assert_eq!(
            lanes_after(sse_string_encodings::PSHUFLW_D4_IN_PLACE),
            [
                word(0) | (word(1) << 16),
                word(1) | (word(3) << 16),
                XMM0_LANES[2],
                XMM0_LANES[3],
            ]
        );
        // For the effect-only members the same bug shows as an intrinsic whose
        // declared input is a destination lane a previous intrinsic in the same
        // instruction already redefined. No input may name `xmm0_dN` at all
        // once the source aliases the destination — every one has to be a
        // snapshot temporary.
        for bytes in [
            sse_string_encodings::PUNPCKLBW_IN_PLACE,
            sse_string_encodings::PACKSSDW_IN_PLACE,
            sse_string_encodings::PSHUFB_IN_PLACE,
        ] {
            for (name, ins, _) in intrinsics_of(bytes) {
                assert!(
                    ins.iter().all(|input| input.starts_with('t')),
                    "{name} reads {ins:?}, which this instruction overwrites"
                );
            }
        }
    }

    #[test]
    fn no_member_of_the_sse_string_family_hides_its_register_write() {
        // The family-wide contract, and the one the census in this module
        // measures across the sample corpus: neither `Op::Unknown` (which
        // declares nothing at all) nor an `Op::Intrinsic` with empty `outs`
        // (which `Op::opaque` builds, and which declares nothing about
        // registers while looking modelled) may survive lifting.
        for bytes in sse_string_encodings::ALL {
            let ops = lift64(bytes);
            let mut wrote_a_register = false;
            for instruction in &ops {
                match &instruction.op {
                    Op::Unknown { mnemonic } => {
                        panic!("{mnemonic} still lifts to Op::Unknown: {ops:#?}")
                    }
                    Op::Intrinsic { name, outs, .. } => {
                        assert!(
                            !outs.is_empty(),
                            "{name} declares no output, which is the defect: {ops:#?}"
                        );
                        wrote_a_register = true;
                    }
                    _ => {}
                }
                if crate::ir::use_def::defs_uses(&instruction.op)
                    .0
                    .iter()
                    .any(|register| matches!(register, VReg::Phys(_)))
                {
                    wrote_a_register = true;
                }
            }
            assert!(wrote_a_register, "{bytes:02x?} defines nothing: {ops:#?}");
        }
    }

    #[test]
    fn every_sse_string_lowering_leaves_both_xmm_spellings_consistent() {
        // Each of these writes `_dN` lane names; the whole-register spelling a
        // scalar float operation or a GPR transfer would read has to be
        // redefined at the same instruction or it keeps a stale value. That is
        // `synchronise_xmm_views`' job, and it reads definitions through
        // `def_uses` — which reports a single-output intrinsic's `outs[0]`, so
        // the effect-only members participate exactly as the lifted ones do.
        for bytes in sse_string_encodings::ALL {
            let ops = lift64(bytes);
            let writes_low_lane = ops.iter().any(|instruction| {
                crate::ir::use_def::defs_uses(&instruction.op)
                    .0
                    .iter()
                    .any(|register| {
                        matches!(register, VReg::Phys(name)
                            if name == "xmm0_d0" || name == "xmm0_d1")
                    })
            });
            if !writes_low_lane {
                continue;
            }
            assert!(
                ops.iter().any(|instruction| matches!(
                    &instruction.op,
                    Op::Assign { dst: VReg::Phys(dst), .. }
                        | Op::Concat { dst: VReg::Phys(dst), .. } if dst == "xmm0"
                )),
                "{bytes:02x?} wrote a low lane without redefining the whole-register view: {ops:#?}"
            );
        }
    }

    #[test]
    fn a_lane_write_also_defines_the_whole_register_view() {
        // PXOR zeroes the lanes; the scalar spelling of the same register must
        // become readable at the same instruction, or a following scalar float
        // operation reads a value nothing defined.
        let ops = lift64(&[0x66, 0x0f, 0xef, 0xc9]); // pxor xmm1,xmm1
        assert!(
            ops.iter().any(|instruction| matches!(
                &instruction.op,
                Op::Assign { dst: VReg::Phys(dst), .. } | Op::Concat { dst: VReg::Phys(dst), .. }
                    if dst == "xmm1"
            )),
            "pxor must define the whole-register view: {ops:#?}"
        );
    }

    /// PIN — the remaining root cause, stated against the register-view model.
    ///
    /// This lifter has TWO spellings for the same 32 bits of an XMM register and
    /// they are not the same name: `movss` writes the whole-register spelling
    /// `xmm0` with a 4-byte operand, while `movd` writes and reads the dword lane
    /// `xmm0_d0`. [`crate::ir::regview`] now says outright that those name the
    /// same storage — the lane defines bits 0..32 of the parent — but the lifter
    /// still emits both, so nothing in SSA connects them.
    ///
    /// That single inconsistency is what both symptom patches exist to bridge:
    /// [`synchronise_xmm_views`] reconciles the two spellings per instruction,
    /// and `ir::abi::touches_result_candidate` has to accept either spelling of a
    /// call's float result. Neither can be deleted while the spellings differ.
    /// The fix is to give the scalar views their own names in the same
    /// namespace as the lanes, not to add another bridge.
    #[test]
    fn the_same_thirty_two_bits_still_have_two_spellings() {
        use crate::ir::regview::{self, Arch, ParentDefinition};

        // `movss (%rax),%xmm0` — a 32-BIT load that names the 128-bit register.
        // The lanes that follow it are `split_xmm_scalar_view`'s mirror, which
        // bridges the gap this test pins but does not close it: the two
        // spellings are still two names.
        let movss = lift64(&[0xF3, 0x0F, 0x10, 0x00]);
        let [LlirInstr {
            op: Op::Load { dst, addr },
            ..
        }, ..] = &movss[..]
        else {
            panic!("movss did not lift to a load first: {movss:#?}");
        };
        assert_eq!(dst, &VReg::phys("xmm0"));
        assert_eq!(addr.size, 4, "the transfer really is 32 bits wide");
        assert!(
            regview::view(Arch::X86_64, "xmm0").is_some_and(|v| v.is_parent() && v.width == 128),
            "yet the destination it names is the whole 128-bit parent"
        );

        // `movd %xmm0,%eax` — the SAME 32 bits, spelled as the lane.
        let movd = lift64(&[0x66, 0x0F, 0x7E, 0xC0]);
        let [LlirInstr {
            op: Op::ZExt {
                src: Value::Reg(src),
                ..
            },
            ..
        }] = &movd[..]
        else {
            panic!("movd did not lift to one zero-extend: {movd:#?}");
        };
        assert_eq!(src, &VReg::phys("xmm0_d0"));

        // The model relates them; the IR does not.
        assert_eq!(regview::parent_of(Arch::X86_64, "xmm0_d0"), Some("xmm0"));
        assert_eq!(
            regview::parent_definition(Arch::X86_64, "xmm0", ["xmm0_d0"]),
            Some(ParentDefinition::Partial {
                defined: 0xFFFF_FFFF,
                undefined: !0xFFFF_FFFFu128,
            })
        );
        assert_eq!(
            regview::ssa_parent(Arch::X86_64, "xmm0_d0"),
            None,
            "SSA gives the lane its own identity, so a definition of `xmm0` does \
             not reach a use of `xmm0_d0` — which is the whole reason both \
             symptom patches exist"
        );
    }

    /// PIN — the bridge over-claims, and the model now says by how much.
    ///
    /// `movd %eax,%xmm0` writes all four lanes (`eax` into lane 0, zeroes above),
    /// which is a COMPLETE definition of `xmm0`. [`synchronise_xmm_views`] then
    /// appends `xmm0 = concat(xmm0_d1, xmm0_d0)`, defining the 128-bit register
    /// from 64 bits — because LLIR has no way to spell a partial definition, and
    /// because the scalar spelling `xmm0` has to be given a value somehow.
    #[test]
    fn the_scalar_view_bridge_defines_a_128_bit_name_from_64_bits() {
        use crate::ir::regview::{self, Arch, ParentDefinition};

        let ops = lift64(&[0x66, 0x0F, 0x6E, 0xC0]); // movd %eax,%xmm0
        let lanes: Vec<String> = ops
            .iter()
            .filter_map(
                |instruction| match crate::ir::use_def::def_uses(&instruction.op).0 {
                    Some(VReg::Phys(name)) if name.contains("_d") => Some(name),
                    _ => None,
                },
            )
            .collect();
        assert_eq!(
            regview::parent_definition(Arch::X86_64, "xmm0", lanes.iter().map(String::as_str)),
            Some(ParentDefinition::Complete),
            "the instruction's own lane writes already cover the whole register"
        );

        let bridge = ops
            .iter()
            .filter_map(|instruction| match &instruction.op {
                Op::Concat {
                    dst: VReg::Phys(dst),
                    hi: Value::Reg(VReg::Phys(hi)),
                    lo: Value::Reg(VReg::Phys(lo)),
                } if dst == "xmm0" => Some((hi.clone(), lo.clone())),
                _ => None,
            })
            .next()
            .expect("the scalar-view bridge is appended: {ops:#?}");
        assert_eq!(bridge, ("xmm0_d1".to_string(), "xmm0_d0".to_string()));
        let low_qword = u128::from(u64::MAX);
        assert_eq!(
            regview::parent_definition(Arch::X86_64, "xmm0", ["xmm0_d0", "xmm0_d1"]),
            Some(ParentDefinition::Partial {
                defined: low_qword,
                undefined: !low_qword,
            }),
            "but the bridge redefines it from half of them"
        );
    }

    #[test]
    fn a_scalar_write_is_visible_through_the_gpr_transfer() {
        // The GCC -O0 float return: `movsd -8(%rbp),%xmm0 ; movq %xmm0,%rax`.
        // The MOVQ must read what the MOVSD wrote, which is the crossing that
        // used to return a zero reconstructed from untouched lanes.
        let ops = lift64(&[
            0xf2, 0x0f, 0x10, 0x45, 0xf8, // movsd -0x8(%rbp),%xmm0
            0x66, 0x48, 0x0f, 0x7e, 0xc0, // movq %xmm0,%rax
        ]);
        assert!(
            ops.iter().any(|instruction| matches!(
                &instruction.op,
                Op::Assign {
                    dst: VReg::Phys(dst),
                    src: Value::Reg(VReg::Phys(src)),
                } if dst == "rax" && src == "xmm0"
            )),
            "movq must read the scalar view the movsd defined: {ops:#?}"
        );
    }

    #[test]
    fn packed_qword_unpack_interleaves_complete_low_qwords() {
        let ops = lift64(&[0x66, 0x0f, 0x6c, 0xde]); // punpcklqdq xmm3,xmm6
        assert!(
            !ops.iter().any(|instruction| matches!(
                instruction.op,
                Op::Unknown { .. } | Op::Intrinsic { .. }
            )),
            "qword unpack must expose its lane permutation: {ops:#?}"
        );
        for (lane, temporary) in [104_u32, 105, 106, 107].into_iter().enumerate() {
            assert!(ops.iter().any(|instruction| matches!(
                &instruction.op,
                Op::Assign {
                    dst: VReg::Phys(dst),
                    src: Value::Reg(VReg::Temp(src)),
                } if dst == &format!("xmm3_d{lane}") && *src == temporary
            )));
        }
    }

    #[test]
    fn movq_xmm_memory_moves_exactly_two_dword_lanes() {
        // movq xmm0,qword ptr [rax]; movq qword ptr [rax],xmm0.  GCC uses
        // this pair to load and conditionally swap adjacent i32 elements.
        // The upper two XMM lanes are cleared on the load and are not stored.
        let ops = lift64(&[0xf3, 0x0f, 0x7e, 0x00, 0x66, 0x0f, 0xd6, 0x00]);
        assert!(
            !ops.iter().any(|instruction| matches!(
                instruction.op,
                Op::Unknown { .. } | Op::Intrinsic { .. }
            )),
            "packed qword moves must be explicit: {ops:#?}"
        );
        for lane in 0..2 {
            assert!(ops.iter().any(|instruction| matches!(
                &instruction.op,
                Op::Load {
                    dst: VReg::Phys(dst),
                    addr,
                } if dst == &format!("xmm0_d{lane}")
                    && addr.disp == (lane * 4) as i64
                    && addr.size == 4
            )));
            assert!(ops.iter().any(|instruction| matches!(
                &instruction.op,
                Op::Store {
                    addr,
                    src: Value::Reg(VReg::Phys(src)),
                } if src == &format!("xmm0_d{lane}")
                    && addr.disp == (lane * 4) as i64
                    && addr.size == 4
            )));
        }
        for lane in 2..4 {
            assert!(ops.iter().any(|instruction| matches!(
                &instruction.op,
                Op::Assign {
                    dst: VReg::Phys(dst),
                    src: Value::Const(0),
                } if dst == &format!("xmm0_d{lane}")
            )));
        }
    }

    #[test]
    fn movq_gpr_to_xmm_and_pextrw_preserve_the_selected_word() {
        // Exact Clang -O2 Dijkstra guard shape:
        // movq xmm0,r8; pextrw r8d,xmm0,4.
        let ops = lift64(&[
            0x66, 0x49, 0x0f, 0x6e, 0xc0, 0x66, 0x44, 0x0f, 0xc5, 0xc0, 0x04,
        ]);

        assert!(
            !ops.iter().any(|instruction| matches!(
                instruction.op,
                Op::Unknown { .. } | Op::Intrinsic { .. }
            )),
            "integer XMM transfer and word extraction must be explicit: {ops:#?}"
        );
        assert!(ops.iter().any(|instruction| matches!(
            &instruction.op,
            Op::Trunc {
                dst: VReg::Phys(dst),
                src: Value::Reg(VReg::Phys(src)),
                from: Width::W64,
                to: Width::W32,
            } if dst == "xmm0_d0" && src == "r8"
        )));
        assert!(ops.iter().any(|instruction| matches!(
            &instruction.op,
            Op::ZExt {
                dst: VReg::Phys(dst),
                from: Width::W16,
                to: Width::W32,
                ..
            } if dst == "r8d"
        )));
    }

    #[test]
    fn shufps_andps_movmskps_expose_clang_pointer_guard() {
        // The exact core of Clang -O2's four-pointer null guard in csr_matvec.
        let ops = lift64(&[
            0x0f, 0xc6, 0xc2, 0xdd, // shufps xmm0,xmm2,0xdd
            0x0f, 0xc6, 0xca, 0x88, // shufps xmm1,xmm2,0x88
            0x0f, 0x54, 0xc8, // andps xmm1,xmm0
            0x44, 0x0f, 0x50, 0xd1, // movmskps r10d,xmm1
        ]);

        assert!(
            !ops.iter().any(|instruction| matches!(
                instruction.op,
                Op::Unknown { .. } | Op::Intrinsic { .. }
            )),
            "packed pointer guard must be explicit: {ops:#?}"
        );
        assert!(ops.iter().any(|instruction| matches!(
            &instruction.op,
            Op::Assign {
                dst: VReg::Phys(dst),
                src: Value::Const(0),
            } if dst == "r10d"
        )));
        assert_eq!(
            ops.iter()
                .filter(|instruction| matches!(instruction.op, Op::Cmp { op: CmpOp::Slt, .. }))
                .count(),
            4,
            "MOVMSKPS must extract all four sign bits: {ops:#?}"
        );
    }

    #[test]
    fn psubq_subtracts_complete_qword_lanes() {
        let ops = lift64(&[0x66, 0x0f, 0xfb, 0xc2]); // psubq xmm0,xmm2

        assert!(
            !ops.iter().any(|instruction| matches!(
                instruction.op,
                Op::Unknown { .. } | Op::Intrinsic { .. }
            )),
            "packed qword subtraction must be explicit: {ops:#?}"
        );
        assert_eq!(
            ops.iter()
                .filter(|instruction| matches!(instruction.op, Op::Bin { op: BinOp::Sub, .. }))
                .count(),
            2,
            "PSUBQ must subtract both complete qword lanes: {ops:#?}"
        );
    }

    #[test]
    fn movzx_indexed_mem_lifts_to_load_then_zext() {
        // movzx eax, word ptr [r15 + rax*2]  (41 0f b7 04 47)
        // Now lifts to a Load into a temp followed by a zero-extend to the dst
        // width (so the widening is explicit and correct for both backends).
        let ops = lift64(&[0x41, 0x0f, 0xb7, 0x04, 0x47]);
        assert_eq!(ops.len(), 2);
        let tmp = match &ops[0].op {
            Op::Load { dst, addr } => {
                assert_eq!(addr.base, Some(VReg::phys("r15")));
                assert_eq!(addr.index, Some(VReg::phys("rax")));
                assert_eq!(addr.scale, 2);
                assert_eq!(addr.size, 2);
                dst.clone()
            }
            other => panic!("expected Load, got {:?}", other),
        };
        match &ops[1].op {
            Op::ZExt { dst, src, from, to } => {
                assert_eq!(*dst, VReg::phys("eax"));
                assert_eq!(*src, Value::Reg(tmp));
                assert_eq!(*from, Width::W16);
                assert_eq!(*to, Width::W32);
            }
            other => panic!("expected ZExt, got {:?}", other),
        }
    }

    #[test]
    fn cmp_reg_mem_emits_load_before_flags() {
        // cmp rax, qword [rbx]  (48 3b 03)
        let ops = lift64(&[0x48, 0x3b, 0x03]);
        // First op must be a Load of the memory operand.
        assert!(matches!(
            &ops[0].op,
            Op::Load {
                dst: VReg::Temp(11),
                ..
            }
        ));
        // Subsequent ops should be the architectural cmp flag writes, all of which
        // read the temp rather than a bare memory operand.
        let flag_count = ops
            .iter()
            .filter(|i| matches!(i.op, Op::Cmp { .. }))
            .count();
        assert!(
            flag_count >= 4,
            "expected signed relation plus ZF, CF, and SF"
        );
        assert!(
            ops.iter().any(|i| matches!(
                i.op,
                Op::Bin {
                    dst: VReg::Flag(Flag::O),
                    op: BinOp::Xor,
                    ..
                }
            )),
            "CMP must define architectural OF: {ops:#?}"
        );
    }

    #[test]
    fn cmp_reg32_normalizes_both_operands_for_equality_and_carry() {
        // `cmp eax, edx`. The canonical parents may have reached this point via
        // different signed/zero-extending paths, but ZF and CF observe the same
        // low 32-bit machine words. Both operands must therefore be normalized
        // before equality or unsigned ordering is computed.
        let ops = lift64(&[0x39, 0xd0]);
        assert!(
            ops.iter().any(|instruction| matches!(
                &instruction.op,
                Op::ZExt {
                    dst: VReg::Temp(35),
                    src: Value::Reg(VReg::Phys(src)),
                    from: Width::W32,
                    to: Width::W64,
                } if src == "eax"
            )),
            "left comparison operand was not normalized: {ops:#?}"
        );
        assert!(
            ops.iter().any(|instruction| matches!(
                &instruction.op,
                Op::ZExt {
                    dst: VReg::Temp(36),
                    src: Value::Reg(VReg::Phys(src)),
                    from: Width::W32,
                    to: Width::W64,
                } if src == "edx"
            )),
            "right comparison operand was not normalized: {ops:#?}"
        );
        for (flag, op) in [(Flag::Z, CmpOp::Eq), (Flag::C, CmpOp::Ult)] {
            assert!(
                ops.iter().any(|instruction| matches!(
                    &instruction.op,
                    Op::Cmp {
                        dst: VReg::Flag(got_flag),
                        op: got_op,
                        lhs: Value::Reg(VReg::Temp(35)),
                        rhs: Value::Reg(VReg::Temp(36)),
                    } if *got_flag == flag && *got_op == op
                )),
                "{flag:?} did not compare normalized words: {ops:#?}"
            );
        }
    }

    #[test]
    fn cmp_mem_imm_emits_load_and_flags() {
        // cmp dword [rbx], 0   (83 3b 00)
        let ops = lift64(&[0x83, 0x3b, 0x00]);
        // Must include a Load of the memory operand and at least one Cmp.
        assert!(ops.iter().any(|i| matches!(&i.op, Op::Load { .. })));
        assert!(ops.iter().any(|i| matches!(&i.op, Op::Cmp { .. })));
        // And NOT have any Unknown cmp stubs.
        assert!(!ops
            .iter()
            .any(|i| matches!(&i.op, Op::Unknown { mnemonic } if mnemonic == "cmp")));
    }

    #[test]
    fn cmp_gs_mem_imm8to16_emits_load_and_flags() {
        // cmp word ptr gs:[0x1a4], 0
        let ops = lift64(&[0x66, 0x65, 0x83, 0x3c, 0x25, 0xa4, 0x01, 0x00, 0x00, 0x00]);
        assert!(matches!(
            &ops[0].op,
            Op::Load {
                dst: VReg::Temp(10),
                addr,
            } if addr.segment.as_deref() == Some("gs")
                && addr.disp == 0x1a4
                && addr.size == 2
        ));
        assert!(ops.iter().any(|i| matches!(&i.op, Op::Cmp { .. })));
        assert!(!ops
            .iter()
            .any(|i| matches!(&i.op, Op::Unknown { mnemonic } if mnemonic == "cmp")));
    }

    #[test]
    fn test_mem_imm_emits_load_and_flags() {
        // test byte ptr [rip + 0], 1
        let ops = lift64(&[0xf6, 0x05, 0x00, 0x00, 0x00, 0x00, 0x01]);
        assert!(matches!(
            &ops[0].op,
            Op::Load {
                dst: VReg::Temp(10),
                addr,
            } if addr.base.is_none() && addr.disp == 0x1007 && addr.size == 1
        ));
        assert!(ops.iter().any(|i| matches!(
            &i.op,
            Op::Cmp {
                dst: VReg::Flag(Flag::Z),
                ..
            }
        )));
        assert!(!ops
            .iter()
            .any(|i| matches!(&i.op, Op::Unknown { mnemonic } if mnemonic == "test")));
    }

    #[test]
    fn inc_rax_lifts_to_bin_add_one() {
        // inc rax (48 ff c0)
        let ops = lift64(&[0x48, 0xff, 0xc0]);
        match &ops
            .iter()
            .find(|ins| matches!(ins.op, Op::Bin { op: BinOp::Add, .. }))
            .expect("INC result")
            .op
        {
            Op::Bin {
                dst,
                op: BinOp::Add,
                rhs: Value::Const(1),
                ..
            } => assert_eq!(*dst, VReg::phys("rax")),
            other => panic!("expected Bin Add +1, got {:?}", other),
        }
    }

    #[test]
    fn dec_rax_lifts_to_bin_sub_one() {
        // dec rax (48 ff c8)
        let ops = lift64(&[0x48, 0xff, 0xc8]);
        match &ops
            .iter()
            .find(|ins| matches!(ins.op, Op::Bin { op: BinOp::Sub, .. }))
            .expect("DEC result")
            .op
        {
            Op::Bin {
                dst,
                op: BinOp::Sub,
                rhs: Value::Const(1),
                ..
            } => assert_eq!(*dst, VReg::phys("rax")),
            other => panic!("expected Bin Sub 1, got {:?}", other),
        }
    }

    #[test]
    fn inc_mem_lifts_to_load_add_store() {
        // inc qword ptr [rax+8] (48 ff 40 08)
        let ops = lift64(&[0x48, 0xff, 0x40, 0x08]);
        match &ops[0].op {
            Op::Load { dst, addr } => {
                assert_eq!(*dst, VReg::Temp(0));
                assert_eq!(addr.base, Some(VReg::phys("rax")));
                assert_eq!(addr.disp, 8);
                assert_eq!(addr.size, 8);
            }
            other => panic!("expected Load, got {:?}", other),
        }
        match &ops
            .iter()
            .find(|ins| matches!(ins.op, Op::Bin { op: BinOp::Add, .. }))
            .expect("INC memory result")
            .op
        {
            Op::Bin {
                dst,
                op: BinOp::Add,
                lhs: Value::Reg(lhs),
                rhs: Value::Const(1),
            } => {
                assert_eq!(*dst, VReg::Temp(0));
                assert_eq!(*lhs, VReg::Temp(0));
            }
            other => panic!("expected Bin Add +1, got {:?}", other),
        }
        match &ops.last().expect("store").op {
            Op::Store {
                addr,
                src: Value::Reg(src),
            } => {
                assert_eq!(addr.base, Some(VReg::phys("rax")));
                assert_eq!(addr.disp, 8);
                assert_eq!(addr.size, 8);
                assert_eq!(*src, VReg::Temp(0));
            }
            other => panic!("expected Store, got {:?}", other),
        }
    }

    #[test]
    fn dec_mem_lifts_to_load_sub_store() {
        // dec qword ptr [rax+0x10] (48 ff 48 10)
        let ops = lift64(&[0x48, 0xff, 0x48, 0x10]);
        assert!(matches!(
            &ops[0].op,
            Op::Load {
                dst: VReg::Temp(0),
                addr,
            } if addr.base == Some(VReg::phys("rax")) && addr.disp == 0x10 && addr.size == 8
        ));
        assert!(matches!(
            &ops.iter()
                .find(|ins| matches!(ins.op, Op::Bin { op: BinOp::Sub, .. }))
                .expect("DEC memory result")
                .op,
            Op::Bin {
                dst: VReg::Temp(0),
                op: BinOp::Sub,
                lhs: Value::Reg(VReg::Temp(0)),
                rhs: Value::Const(1),
            }
        ));
        assert!(matches!(
            &ops.last().expect("store").op,
            Op::Store {
                addr,
                src: Value::Reg(VReg::Temp(0)),
            } if addr.base == Some(VReg::phys("rax")) && addr.disp == 0x10 && addr.size == 8
        ));
    }

    #[test]
    fn xadd_mem_reg_lifts_to_load_add_store_and_old_value_assign() {
        // lock xadd dword ptr [rcx], eax (f0 0f c1 01)
        let ops = lift64(&[0xf0, 0x0f, 0xc1, 0x01]);
        assert!(matches!(
            &ops[0].op,
            Op::Load {
                dst: VReg::Temp(0),
                addr,
            } if addr.base == Some(VReg::phys("rcx")) && addr.size == 4
        ));
        assert!(ops.iter().any(|ins| matches!(
            &ins.op,
            Op::Bin {
                dst: VReg::Temp(1),
                op: BinOp::Add,
                lhs: Value::Reg(VReg::Temp(1)),
                rhs: Value::Reg(VReg::Phys(src)),
            } if src == "eax"
        )));
        assert!(ops.iter().any(|ins| matches!(
            &ins.op,
            Op::Store {
                addr,
                src: Value::Reg(VReg::Temp(1)),
            } if addr.base == Some(VReg::phys("rcx")) && addr.size == 4
        )));
        assert!(matches!(
            &ops.last().expect("old-value writeback").op,
            Op::Assign {
                dst: VReg::Phys(dst),
                src: Value::Reg(VReg::Temp(0)),
            } if dst == "eax"
        ));
    }

    #[test]
    fn xadd_reg_reg_lifts_to_exchange_after_add() {
        // xadd eax, ebx (0f c1 d8)
        let ops = lift64(&[0x0f, 0xc1, 0xd8]);
        assert!(matches!(
            &ops[0].op,
            Op::Assign {
                dst: VReg::Temp(0),
                src: Value::Reg(VReg::Phys(src)),
            } if src == "eax"
        ));
        assert!(ops.iter().any(|ins| matches!(
            &ins.op,
            Op::Bin {
                dst: VReg::Phys(dst),
                op: BinOp::Add,
                lhs: Value::Reg(VReg::Phys(lhs)),
                rhs: Value::Reg(VReg::Phys(rhs)),
            } if dst == "eax" && lhs == "eax" && rhs == "ebx"
        )));
        assert!(matches!(
            &ops.last().expect("old-value writeback").op,
            Op::Assign {
                dst: VReg::Phys(dst),
                src: Value::Reg(VReg::Temp(0)),
            } if dst == "ebx"
        ));
    }

    #[test]
    fn leave_lifts_to_three_ops() {
        // leave (c9)
        let ops = lift64(&[0xc9]);
        assert_eq!(ops.len(), 3);
        // First: rsp = rbp
        assert!(matches!(
            &ops[0].op,
            Op::Assign { dst, src: Value::Reg(r) }
            if *dst == VReg::phys("rsp") && *r == VReg::phys("rbp")
        ));
        // Second: rbp = load [rsp]
        assert!(matches!(&ops[1].op, Op::Load { .. }));
        // Third: rsp = rsp + 8
        assert!(matches!(
            &ops[2].op,
            Op::Bin {
                dst,
                op: BinOp::Add,
                rhs: Value::Const(8),
                ..
            } if *dst == VReg::phys("rsp")
        ));
    }

    #[test]
    fn push_of_memory_lifts_to_load_plus_store() {
        // push qword [rsi]  (ff 36)
        let ops = lift64(&[0xff, 0x36]);
        // Expect: tmp = load [rsi]; rsp = rsp - 8; *[rsp] = tmp.
        assert_eq!(ops.len(), 3, "got: {:#?}", ops);
        assert!(matches!(
            &ops[0].op,
            Op::Load {
                dst: VReg::Temp(0),
                ..
            }
        ));
        assert!(matches!(
            &ops[1].op,
            Op::Bin { dst, op: BinOp::Sub, rhs: Value::Const(8), .. }
            if *dst == VReg::phys("rsp")
        ));
        assert!(matches!(&ops[2].op, Op::Store { .. }));
    }

    #[test]
    fn unknown_mnemonic_preserved() {
        // sysenter (0f 34) — not in our lifter set
        let ops = lift64(&[0x0f, 0x34]);
        assert_eq!(ops.len(), 1);
        match &ops[0].op {
            Op::Unknown { mnemonic } => {
                assert!(!mnemonic.is_empty());
            }
            other => panic!("expected Unknown, got {:?}", other),
        }
    }

    #[test]
    fn round_trip_prologue_end_to_end() {
        // A canonical x86-64 function prologue:
        //   push rbp           (55)           -> 2 ops (sub rsp + store)
        //   mov  rbp, rsp      (48 89 e5)     -> 1 op
        //   sub  rsp, 0x10     (48 83 ec 10)  -> 1 op
        //   xor  eax, eax      (31 c0)        -> 1 op
        //   leave              (c9)           -> 3 ops (rsp=rbp, pop rbp)
        //   ret                (c3)           -> 1 op
        let bytes = [
            0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x10, 0x31, 0xc0, 0xc9, 0xc3,
        ];
        let ops = lift_bytes(&bytes, 0x4000, 64);

        // 2 + 1 + 1 + 1 + 3 + 1 = 9 ops total.
        assert!(ops.len() >= 9, "got {} ops: {:#?}", ops.len(), ops);
        assert_eq!(ops[0].va, 0x4000);
        assert_eq!(ops.last().unwrap().op, Op::Return);
        // `leave` now lifts cleanly: expect at least one `rsp = rbp` somewhere.
        assert!(
            ops.iter().any(|i| matches!(
                &i.op,
                Op::Assign { dst, src: Value::Reg(r) }
                    if *dst == VReg::phys("rsp") && *r == VReg::phys("rbp")
            )),
            "leave did not produce `rsp = rbp`: {:#?}",
            ops
        );
    }

    /// `83 c0 ff` is `add eax, -1` — an imm8 SIGN-EXTENDED to 32 bits. iced only
    /// populates `immediate32()` for a true `Immediate32`; on an `Immediate8to32`
    /// it hands back the raw byte, so the decrement lifted as `+255`.
    ///
    /// clang -O0 spells `n--` exactly this way, so `factorial`'s loop counter went
    /// up by 255 instead of down by one. The 64-bit forms already had this fixed —
    /// the comment in `value_of_operand` says each extended form has its own
    /// accessor — and the 8-to-32 and 8-to-16 forms were simply missed.
    #[test]
    fn an_imm8_sign_extended_to_32_bits_keeps_its_sign() {
        // add eax, -1
        let ops: Vec<Op> = lift64(&[0x83, 0xc0, 0xff])
            .into_iter()
            .map(|i| i.op)
            .collect();
        let found = ops.iter().find_map(|o| match o {
            Op::Bin {
                op: BinOp::Add,
                rhs: Value::Const(c),
                ..
            } => Some(*c),
            _ => None,
        });
        assert_eq!(found, Some(-1), "expected `add eax, -1`, got:\n{ops:#?}");
    }

    /// The same encoding for a subtract, and for a 16-bit destination.
    #[test]
    fn other_sign_extended_imm8_forms_keep_their_sign() {
        // sub eax, -8   (83 e8 f8)
        let ops: Vec<Op> = lift64(&[0x83, 0xe8, 0xf8])
            .into_iter()
            .map(|i| i.op)
            .collect();
        assert!(
            ops.iter().any(|o| matches!(
                o,
                Op::Bin {
                    op: BinOp::Sub,
                    rhs: Value::Const(-8),
                    ..
                }
            )),
            "expected `sub eax, -8`, got:\n{ops:#?}"
        );
        // add ax, -1    (66 83 c0 ff) — Immediate8to16
        let ops16: Vec<Op> = lift64(&[0x66, 0x83, 0xc0, 0xff])
            .into_iter()
            .map(|i| i.op)
            .collect();
        assert!(
            format!("{ops16:#?}").contains("-1"),
            "expected a -1 immediate for `add ax, -1`, got:\n{ops16:#?}"
        );
    }

    /// Bounded property test (roadmap safety-plan item: "fuzz decoders,
    /// register contracts, lifters..."): `lift_bytes` must never panic and
    /// must always terminate on ARBITRARY bytes, including bytes that are
    /// not valid x86 at all and bytes that happen to decode as unusual-but-
    /// valid instructions this file has no example-based test for.
    ///
    /// This is deliberately not a real fuzzer (no corpus, no coverage
    /// guidance, no crate dependency beyond what's already linked) — it is
    /// one seeded, reproducible property test so a regression here shows up
    /// in `cargo test` rather than needing `cargo fuzz` set up separately.
    /// A splitmix64 PRNG is used instead of adding the `rand` crate, which
    /// is not currently a dependency of this crate.
    #[test]
    fn lift_bytes_never_panics_or_hangs_on_arbitrary_input() {
        fn splitmix64(state: &mut u64) -> u64 {
            *state = state.wrapping_add(0x9E3779B97F4A7C15);
            let mut z = *state;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
            z ^ (z >> 31)
        }

        // Fixed seed: reproducible across runs/machines, no external entropy
        // source needed. Any future failure reported by this test reproduces
        // exactly by re-running it.
        let mut state: u64 = 0xD1CE_C0DE_F00D_BA5E;
        const ITERATIONS: usize = 4_000;
        const MAX_LEN: usize = 32;

        for iter in 0..ITERATIONS {
            let len = (splitmix64(&mut state) as usize % MAX_LEN) + 1;
            let mut buf = vec![0u8; len];
            for b in &mut buf {
                *b = (splitmix64(&mut state) & 0xFF) as u8;
            }
            // Every start VA and bit-width the lifter's callers actually use
            // (see `python_bindings::ir::lift_bytes_py`): 16/32/64-bit modes,
            // and a start VA with high bits set so any VA-dependent RIP-math
            // path gets exercised too, not just small offsets from zero.
            for bits in [16u32, 32, 64] {
                let start_va = 0xFFFF_FFFF_0000_1000u64 ^ (iter as u64);
                // Panicking here fails the test with the exact `buf`/`bits`
                // in the backtrace; looping forever would hang `cargo test`
                // instead of passing, which is exactly the "terminates"
                // half of the property.
                let _ = std::hint::black_box(lift_bytes(&buf, start_va, bits));
            }
        }
    }
}
