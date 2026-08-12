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

use iced_x86::{Code, Decoder, DecoderOptions, Mnemonic, OpKind, Register};

use crate::ir::regview;
use crate::ir::types::*;

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
fn partial_gp_view(name: &str) -> Option<regview::RegView> {
    regview::view(regview::Arch::X86_64, name).filter(|v| v.preserves_parent())
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
        Some(v) if v.zero_extends() => Value::Const((c as u64 & v.value_mask()) as i64),
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
        rhs: Value::Const(v.keep_mask() as i64),
    }];
    let value_mask = (v.value_mask() >> v.offset) as i64;
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
    let mask = (v.value_mask() >> v.offset) as i64;
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
    let mask = (v.value_mask() >> v.offset) as i64;
    let mut ops = read_view_ops(v, acc.clone());

    let rhs = match &src {
        Value::Reg(VReg::Phys(n)) if n == v.view => Value::Reg(acc.clone()),
        Value::Reg(VReg::Phys(n)) => match regview::view(regview::Arch::X86_64, n) {
            // A partial-view SOURCE needs the same treatment, or it too is just a
            // name (e.g. `add %ah,%al`).
            Some(sv) if sv.preserves_parent() => {
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
        rhs: Value::Const(v.keep_mask() as i64),
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

fn mem_op_of(instr: &iced_x86::Instruction) -> MemOp {
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

/// Give a signed comparison the value at the machine operand's width.
fn signed_cmp_value(value: Value, width: Width, temp: VReg, ops: &mut Vec<Op>) -> Value {
    if width.bits() < 64 && matches!(&value, Value::Reg(_)) {
        ops.push(Op::SExt {
            dst: temp.clone(),
            src: value,
            from: width,
            to: Width::W64,
        });
        Value::Reg(temp)
    } else {
        value
    }
}

/// Give equality/carry predicates the unsigned word the machine actually
/// observes at `width`. Canonical parent registers may otherwise carry
/// different high halves depending on whether their latest 32-bit source was
/// made explicit, even though x86 ZF/CF compare only the encoded low word.
fn unsigned_cmp_value(value: Value, width: Width, temp: VReg, ops: &mut Vec<Op>) -> Value {
    if width.bits() >= 64 {
        return value;
    }
    match value {
        value @ Value::Reg(_) => {
            ops.push(Op::ZExt {
                dst: temp.clone(),
                src: value,
                from: width,
                to: Width::W64,
            });
            Value::Reg(temp)
        }
        Value::Const(value) => {
            let bits = width.bits();
            let mask = if bits == 0 { 0 } else { (1u64 << bits) - 1 };
            Value::Const((value as u64 & mask) as i64)
        }
        other => other,
    }
}

/// Emit LLIR for a reg/reg or reg/imm binary op (`dst = dst <op> src`).
fn emit_bin(dst: VReg, op: BinOp, src: Value) -> Op {
    Op::Bin {
        dst: dst.clone(),
        op,
        lhs: Value::Reg(dst),
        rhs: src,
    }
}

fn undef_flag(flag: Flag, reason: impl Into<String>) -> Op {
    Op::Undef {
        dst: VReg::Flag(flag),
        reason: reason.into(),
    }
}

fn append_undef_flags(ops: &mut Vec<Op>, flags: &[Flag], reason: &str) {
    ops.extend(flags.iter().map(|flag| undef_flag(*flag, reason)));
}

/// Define ZF and the actual architectural SF for `result` at `width`.
fn zero_sign_flags(result: Value, width: Width, signed_temp: u32, ops: &mut Vec<Op>) {
    let unsigned = unsigned_cmp_value(result.clone(), width, VReg::Temp(signed_temp + 100), ops);
    ops.push(Op::Cmp {
        dst: VReg::Flag(Flag::Z),
        op: CmpOp::Eq,
        lhs: unsigned,
        rhs: Value::Const(0),
    });
    let signed = signed_cmp_value(result, width, VReg::Temp(signed_temp), ops);
    ops.push(Op::Cmp {
        dst: VReg::Flag(Flag::S),
        op: CmpOp::Slt,
        lhs: signed,
        rhs: Value::Const(0),
    });
}

/// Exact ZF/CF/SF/OF effects of subtraction, plus explicit poison for the two
/// defined-but-not-yet-materialised low-bit flags. `cmp` uses the same helper
/// with `write_result = false` semantics encoded by its private result temp.
fn emit_sub_with_flags(dst: VReg, rhs: Value, width: Width) -> Vec<Op> {
    let mut ops = Vec::new();
    let lhs = Value::Reg(dst.clone());
    let signed_lhs = signed_cmp_value(lhs.clone(), width, VReg::Temp(30), &mut ops);
    let signed_rhs = signed_cmp_value(rhs.clone(), width, VReg::Temp(31), &mut ops);
    let unsigned_lhs = unsigned_cmp_value(lhs.clone(), width, VReg::Temp(34), &mut ops);
    let unsigned_rhs = unsigned_cmp_value(rhs.clone(), width, VReg::Temp(35), &mut ops);
    let signed_less = VReg::Temp(32);
    ops.push(Op::Cmp {
        dst: signed_less.clone(),
        op: CmpOp::Slt,
        lhs: signed_lhs,
        rhs: signed_rhs,
    });
    ops.push(Op::Cmp {
        dst: VReg::Flag(Flag::C),
        op: CmpOp::Ult,
        lhs: unsigned_lhs,
        rhs: unsigned_rhs,
    });
    ops.push(emit_bin(dst.clone(), BinOp::Sub, rhs));
    zero_sign_flags(Value::Reg(dst), width, 33, &mut ops);
    // For subtraction, signed-less == SF xor OF, therefore OF == signed-less xor SF.
    ops.push(Op::Bin {
        dst: VReg::Flag(Flag::O),
        op: BinOp::Xor,
        lhs: Value::Reg(signed_less),
        rhs: Value::Reg(VReg::Flag(Flag::S)),
    });
    append_undef_flags(
        &mut ops,
        &[Flag::P, Flag::A],
        "x86 SUB defines PF/AF, but their exact low-bit expressions are not modelled",
    );
    ops
}

fn cmp_flag_ops(lhs: Value, rhs: Value, width: Width) -> Vec<Op> {
    let mut ops = Vec::new();
    let signed_lhs = signed_cmp_value(lhs.clone(), width, VReg::Temp(30), &mut ops);
    let signed_rhs = signed_cmp_value(rhs.clone(), width, VReg::Temp(31), &mut ops);
    let unsigned_lhs = unsigned_cmp_value(lhs.clone(), width, VReg::Temp(35), &mut ops);
    let unsigned_rhs = unsigned_cmp_value(rhs.clone(), width, VReg::Temp(36), &mut ops);
    let signed_less = VReg::Temp(32);
    let result = VReg::Temp(33);
    ops.extend([
        Op::Cmp {
            dst: signed_less.clone(),
            op: CmpOp::Slt,
            lhs: signed_lhs,
            rhs: signed_rhs,
        },
        Op::Bin {
            dst: result.clone(),
            op: BinOp::Sub,
            lhs: lhs.clone(),
            rhs: rhs.clone(),
        },
        Op::Cmp {
            dst: VReg::Flag(Flag::Z),
            op: CmpOp::Eq,
            lhs: unsigned_lhs.clone(),
            rhs: unsigned_rhs.clone(),
        },
        Op::Cmp {
            dst: VReg::Flag(Flag::C),
            op: CmpOp::Ult,
            lhs: unsigned_lhs,
            rhs: unsigned_rhs,
        },
    ]);
    zero_sign_flags(Value::Reg(result), width, 34, &mut ops);
    // `zero_sign_flags` also emitted a result-based ZF. Preserve the cleaner,
    // exact `lhs == rhs` definition above by removing only that duplicate.
    let result_zf = ops
        .iter()
        .rposition(|op| {
            matches!(
                op,
                Op::Cmp {
                    dst: VReg::Flag(Flag::Z),
                    ..
                }
            )
        })
        .expect("zero_sign_flags emits ZF");
    ops.remove(result_zf);
    ops.push(Op::Bin {
        dst: VReg::Flag(Flag::O),
        op: BinOp::Xor,
        lhs: Value::Reg(signed_less),
        rhs: Value::Reg(VReg::Flag(Flag::S)),
    });
    append_undef_flags(
        &mut ops,
        &[Flag::P, Flag::A],
        "x86 CMP defines PF/AF, but their exact low-bit expressions are not modelled",
    );
    ops
}

/// Exact ZF/CF/SF/OF effects of addition. PF/AF are new poisoned values rather
/// than stale values until their low-bit expressions are materialised.
fn emit_add_with_flags(dst: VReg, rhs: Value, width: Width) -> Vec<Op> {
    let mut ops = Vec::new();
    let original = VReg::Temp(30);
    ops.push(Op::Assign {
        dst: original.clone(),
        src: Value::Reg(dst.clone()),
    });
    let signed_lhs = signed_cmp_value(
        Value::Reg(original.clone()),
        width,
        VReg::Temp(31),
        &mut ops,
    );
    let signed_rhs = signed_cmp_value(rhs.clone(), width, VReg::Temp(32), &mut ops);
    let lhs_negative = VReg::Temp(33);
    let rhs_negative = VReg::Temp(34);
    ops.extend([
        Op::Cmp {
            dst: lhs_negative.clone(),
            op: CmpOp::Slt,
            lhs: signed_lhs,
            rhs: Value::Const(0),
        },
        Op::Cmp {
            dst: rhs_negative.clone(),
            op: CmpOp::Slt,
            lhs: signed_rhs,
            rhs: Value::Const(0),
        },
        emit_bin(dst.clone(), BinOp::Add, rhs),
    ]);
    zero_sign_flags(Value::Reg(dst.clone()), width, 35, &mut ops);
    let unsigned_result =
        unsigned_cmp_value(Value::Reg(dst.clone()), width, VReg::Temp(38), &mut ops);
    let unsigned_original = unsigned_cmp_value(
        Value::Reg(original.clone()),
        width,
        VReg::Temp(39),
        &mut ops,
    );
    ops.push(Op::Cmp {
        dst: VReg::Flag(Flag::C),
        op: CmpOp::Ult,
        lhs: unsigned_result,
        rhs: unsigned_original,
    });
    let same_sign = VReg::Temp(36);
    let sign_changed = VReg::Temp(37);
    ops.extend([
        Op::Cmp {
            dst: same_sign.clone(),
            op: CmpOp::Eq,
            lhs: Value::Reg(lhs_negative),
            rhs: Value::Reg(rhs_negative),
        },
        Op::Cmp {
            dst: sign_changed.clone(),
            op: CmpOp::Ne,
            lhs: Value::Reg(VReg::Flag(Flag::S)),
            rhs: Value::Reg(VReg::Temp(33)),
        },
        Op::Bin {
            dst: VReg::Flag(Flag::O),
            op: BinOp::And,
            lhs: Value::Reg(same_sign),
            rhs: Value::Reg(sign_changed),
        },
    ]);
    append_undef_flags(
        &mut ops,
        &[Flag::P, Flag::A],
        "x86 ADD defines PF/AF, but their exact low-bit expressions are not modelled",
    );
    ops
}

fn emit_logic_with_flags(dst: VReg, op: BinOp, rhs: Value, width: Width) -> Vec<Op> {
    let mut ops = vec![emit_bin(dst.clone(), op, rhs)];
    zero_sign_flags(Value::Reg(dst), width, 30, &mut ops);
    ops.extend([
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
            "x86 logic defines PF, but its exact low-byte parity expression is not modelled",
        ),
        undef_flag(Flag::A, "x86 logic leaves AF architecturally undefined"),
    ]);
    ops
}

fn emit_shift_with_flags(dst: VReg, op: BinOp, rhs: Value, width: Width) -> Vec<Op> {
    let mask = if width.bits() == 64 { 63 } else { 31 };
    match rhs {
        Value::Const(raw) => {
            let count = raw & mask;
            if count == 0 {
                // A masked zero count preserves the destination and every flag.
                return vec![Op::Nop];
            }
            let mut ops = vec![emit_bin(dst.clone(), op, Value::Const(count))];
            zero_sign_flags(Value::Reg(dst), width, 30, &mut ops);
            ops.push(undef_flag(
                Flag::C,
                "x86 shift defines CF, but the shifted-out-bit expression is not modelled",
            ));
            ops.push(if count == 1 {
                undef_flag(
                    Flag::O,
                    "x86 one-bit shift defines OF, but its exact expression is not modelled",
                )
            } else {
                undef_flag(
                    Flag::O,
                    "x86 multi-bit shift leaves OF architecturally undefined",
                )
            });
            ops.extend([
                undef_flag(
                    Flag::P,
                    "x86 shift defines PF, but its exact low-byte parity expression is not modelled",
                ),
                undef_flag(Flag::A, "x86 shift leaves AF architecturally undefined"),
            ]);
            ops
        }
        variable => {
            // Every x86 variable-count shift masks CL before executing: five
            // bits for 8/16/32-bit operands and six for 64-bit operands. C does
            // not—it makes a count at least as wide as the promoted left
            // operand undefined—so leaving the raw count in the AST changes
            // executable behavior for precisely those values. Preserve the
            // architectural count as ordinary dataflow.
            let masked_count = VReg::Temp(29);
            let mut ops = vec![
                Op::Bin {
                    dst: masked_count.clone(),
                    op: BinOp::And,
                    lhs: variable,
                    rhs: Value::Const(mask),
                },
                emit_bin(dst, op, Value::Reg(masked_count)),
            ];
            append_undef_flags(
                &mut ops,
                &[Flag::C, Flag::O, Flag::Z, Flag::S, Flag::P, Flag::A],
                "x86 variable-count shift has count-sensitive flag effects not yet modelled",
            );
            ops
        }
    }
}

/// Append the two flag effects of a non-zero ROL/ROR.  ZF/SF/PF/AF are
/// architecturally preserved and therefore deliberately absent.
fn append_rotate_flags(ops: &mut Vec<Op>, dst: VReg, rotate_left: bool, width: Width, count: i64) {
    let top_shift = (width.bits() - 1) as i64;
    if rotate_left {
        ops.push(Op::Bin {
            dst: VReg::Flag(Flag::C),
            op: BinOp::And,
            lhs: Value::Reg(dst.clone()),
            rhs: Value::Const(1),
        });
    } else {
        let top = VReg::Temp(50);
        ops.extend([
            Op::Bin {
                dst: top.clone(),
                op: BinOp::Shr,
                lhs: Value::Reg(dst.clone()),
                rhs: Value::Const(top_shift),
            },
            Op::Bin {
                dst: VReg::Flag(Flag::C),
                op: BinOp::And,
                lhs: Value::Reg(top),
                rhs: Value::Const(1),
            },
        ]);
    }

    if count != 1 {
        ops.push(undef_flag(
            Flag::O,
            "x86 multi-bit rotate leaves OF architecturally undefined",
        ));
        return;
    }

    let top = VReg::Temp(51);
    ops.push(Op::Bin {
        dst: top.clone(),
        op: BinOp::Shr,
        lhs: Value::Reg(dst.clone()),
        rhs: Value::Const(top_shift),
    });
    if rotate_left {
        ops.push(Op::Bin {
            dst: VReg::Flag(Flag::O),
            op: BinOp::Xor,
            lhs: Value::Reg(top),
            rhs: Value::Reg(VReg::Flag(Flag::C)),
        });
    } else {
        let next = VReg::Temp(52);
        ops.extend([
            Op::Bin {
                dst: next.clone(),
                op: BinOp::Shr,
                lhs: Value::Reg(dst),
                rhs: Value::Const(top_shift - 1),
            },
            Op::Bin {
                dst: next.clone(),
                op: BinOp::And,
                lhs: Value::Reg(next.clone()),
                rhs: Value::Const(1),
            },
            Op::Bin {
                dst: VReg::Flag(Flag::O),
                op: BinOp::Xor,
                lhs: Value::Reg(top),
                rhs: Value::Reg(next),
            },
        ]);
    }
}

fn emit_bin_with_flags(dst: VReg, op: BinOp, rhs: Value, width: Width) -> Vec<Op> {
    match op {
        BinOp::Add => emit_add_with_flags(dst, rhs, width),
        BinOp::Sub => emit_sub_with_flags(dst, rhs, width),
        BinOp::And | BinOp::Or | BinOp::Xor => emit_logic_with_flags(dst, op, rhs, width),
        BinOp::Shl | BinOp::Shr | BinOp::Sar => emit_shift_with_flags(dst, op, rhs, width),
        BinOp::Mul => {
            let mut ops = vec![emit_bin(dst, op, rhs)];
            append_undef_flags(
                &mut ops,
                &[Flag::C, Flag::O],
                "x86 IMUL defines CF/OF, but product truncation overflow is not modelled",
            );
            append_undef_flags(
                &mut ops,
                &[Flag::Z, Flag::S, Flag::P, Flag::A],
                "x86 IMUL leaves ZF/SF/PF/AF architecturally undefined",
            );
            ops
        }
        BinOp::Div => {
            let mut ops = vec![emit_bin(dst, op, rhs)];
            append_undef_flags(
                &mut ops,
                &[Flag::C, Flag::O, Flag::Z, Flag::S, Flag::P, Flag::A],
                "x86 DIV leaves arithmetic flags architecturally undefined",
            );
            ops
        }
        BinOp::LogicalAnd | BinOp::LogicalOr => {
            unreachable!("source-level short-circuit operators are not x86 ALU operations")
        }
    }
}

/// Apply an x86 ALU operation at its encoded operand width, even though the
/// downstream SSA model canonicalises GP sub-registers to their full parent.
///
/// Most low-word arithmetic happens to retain the right low bits when computed
/// at 64 bits, but right shifts do not: `sar eax,1` must replicate bit 31, not
/// the already-zeroed bit 63, and `shr` must never shift stale parent bits down
/// into the low word. Make that read width explicit before the operation. A
/// 32-bit GP destination on x86-64 then zero-extends into its parent, so record
/// that write effect explicitly after the flag values have consumed the result.
///
/// The narrowing is stated against the IR's CANONICAL 64-bit value width on both
/// x86-64 and i386, not against the target's register width. On i386 a 32-bit
/// operand is the whole machine register, so the extension looks redundant — but
/// the IR value it names is 64 bits wide, and the recovered C is rebuilt at the
/// host word, where a `long` local really can carry bits above 31. Omitting it
/// there made `t >>= 8` on a negative `int` shift a sign-extended 64-bit value:
/// `03_loop_shapes:i386:O0:dowhile_recompute` ran eight loop iterations instead
/// of four.
fn emit_machine_bin_with_flags(
    dst: VReg,
    op: BinOp,
    rhs: Value,
    width: Width,
    bits: u32,
) -> Vec<Op> {
    let machine_width = Width::W64;
    let mut ops = Vec::new();
    if width < machine_width && matches!(op, BinOp::Shr | BinOp::Sar) {
        let src = Value::Reg(dst.clone());
        ops.push(if op == BinOp::Sar {
            Op::SExt {
                dst: dst.clone(),
                src,
                from: width,
                to: machine_width,
            }
        } else {
            Op::ZExt {
                dst: dst.clone(),
                src,
                from: width,
                to: machine_width,
            }
        });
    }
    ops.extend(emit_bin_with_flags(dst.clone(), op, rhs, width));
    let zero_extends_parent = bits == 64
        && width == Width::W32
        && matches!(
            &dst,
            VReg::Phys(name)
                if regview::view(regview::Arch::X86_64, name).is_some_and(|view| view.zero_extends())
        );
    if zero_extends_parent {
        ops.push(Op::ZExt {
            dst: dst.clone(),
            src: Value::Reg(dst),
            from: Width::W32,
            to: Width::W64,
        });
    }
    ops
}

fn emit_inc_dec_with_flags(dst: VReg, increment: bool, width: Width) -> Vec<Op> {
    let original = VReg::Temp(40);
    let mut ops = vec![Op::Assign {
        dst: original.clone(),
        src: Value::Reg(dst.clone()),
    }];
    ops.push(emit_bin(
        dst.clone(),
        if increment { BinOp::Add } else { BinOp::Sub },
        Value::Const(1),
    ));
    zero_sign_flags(Value::Reg(dst), width, 41, &mut ops);
    let signed_original = signed_cmp_value(Value::Reg(original), width, VReg::Temp(42), &mut ops);
    let boundary = if increment {
        if width.bits() == 64 {
            i64::MAX
        } else {
            (1_i64 << (width.bits() - 1)) - 1
        }
    } else if width.bits() == 64 {
        i64::MIN
    } else {
        -(1_i64 << (width.bits() - 1))
    };
    ops.push(Op::Cmp {
        dst: VReg::Flag(Flag::O),
        op: CmpOp::Eq,
        lhs: signed_original,
        rhs: Value::Const(boundary),
    });
    append_undef_flags(
        &mut ops,
        &[Flag::P, Flag::A],
        if increment {
            "x86 INC defines PF/AF, but their exact low-bit expressions are not modelled"
        } else {
            "x86 DEC defines PF/AF, but their exact low-bit expressions are not modelled"
        },
    );
    // CF is intentionally absent: INC/DEC preserve it.
    ops
}

fn bin_for(mnem: Mnemonic) -> Option<BinOp> {
    Some(match mnem {
        Mnemonic::Add => BinOp::Add,
        Mnemonic::Sub => BinOp::Sub,
        Mnemonic::And => BinOp::And,
        Mnemonic::Or => BinOp::Or,
        Mnemonic::Xor => BinOp::Xor,
        Mnemonic::Shl => BinOp::Shl,
        Mnemonic::Shr => BinOp::Shr,
        Mnemonic::Sar => BinOp::Sar,
        Mnemonic::Imul => BinOp::Mul,
        _ => return None,
    })
}

fn condition_suffix(mnem: Mnemonic, prefix: &str) -> Option<String> {
    let name = format!("{:?}", mnem).to_ascii_lowercase();
    name.strip_prefix(prefix).map(str::to_string)
}

#[derive(Debug, Clone)]
enum ConditionCode {
    Overflow,
    Below,
    Equal,
    BelowEqual,
    Sign,
    Parity,
    Less,
    LessEqual,
}

#[derive(Debug, Clone)]
struct Condition {
    code: ConditionCode,
    inverted: bool,
}

fn condition_for_suffix(suffix: &str) -> Option<Condition> {
    let (code, inverted) = match suffix {
        "e" | "z" => (ConditionCode::Equal, false),
        "ne" | "nz" => (ConditionCode::Equal, true),
        "b" | "c" | "nae" => (ConditionCode::Below, false),
        "ae" | "nb" | "nc" => (ConditionCode::Below, true),
        "be" | "na" => (ConditionCode::BelowEqual, false),
        "a" | "nbe" => (ConditionCode::BelowEqual, true),
        "l" | "nge" => (ConditionCode::Less, false),
        "ge" | "nl" => (ConditionCode::Less, true),
        "le" | "ng" => (ConditionCode::LessEqual, false),
        "g" | "nle" => (ConditionCode::LessEqual, true),
        "s" => (ConditionCode::Sign, false),
        "ns" => (ConditionCode::Sign, true),
        "o" => (ConditionCode::Overflow, false),
        "no" => (ConditionCode::Overflow, true),
        "p" | "pe" => (ConditionCode::Parity, false),
        "np" | "po" => (ConditionCode::Parity, true),
        _ => return None,
    };
    Some(Condition { code, inverted })
}

/// Materialise one of x86's eight positive condition families from the six
/// architectural status flags. Derived conditions are ordinary typed boolean
/// temporaries, never mutable pseudo-flags.
fn materialize_condition(condition: &Condition) -> (Vec<Op>, VReg) {
    let atom = |flag| (Vec::new(), VReg::Flag(flag));
    match condition.code {
        ConditionCode::Overflow => atom(Flag::O),
        ConditionCode::Below => atom(Flag::C),
        ConditionCode::Equal => atom(Flag::Z),
        ConditionCode::Sign => atom(Flag::S),
        ConditionCode::Parity => atom(Flag::P),
        ConditionCode::BelowEqual => {
            let out = VReg::Temp(20);
            (
                vec![Op::Bin {
                    dst: out.clone(),
                    op: BinOp::Or,
                    lhs: Value::Reg(VReg::Flag(Flag::C)),
                    rhs: Value::Reg(VReg::Flag(Flag::Z)),
                }],
                out,
            )
        }
        ConditionCode::Less => {
            let out = VReg::Temp(20);
            (
                vec![Op::Bin {
                    dst: out.clone(),
                    op: BinOp::Xor,
                    lhs: Value::Reg(VReg::Flag(Flag::S)),
                    rhs: Value::Reg(VReg::Flag(Flag::O)),
                }],
                out,
            )
        }
        ConditionCode::LessEqual => {
            let less = VReg::Temp(20);
            let out = VReg::Temp(21);
            (
                vec![
                    Op::Bin {
                        dst: less.clone(),
                        op: BinOp::Xor,
                        lhs: Value::Reg(VReg::Flag(Flag::S)),
                        rhs: Value::Reg(VReg::Flag(Flag::O)),
                    },
                    Op::Bin {
                        dst: out.clone(),
                        op: BinOp::Or,
                        lhs: Value::Reg(VReg::Flag(Flag::Z)),
                        rhs: Value::Reg(less),
                    },
                ],
                out,
            )
        }
    }
}

fn setcc_condition_for(mnem: Mnemonic) -> Option<Condition> {
    condition_suffix(mnem, "set").and_then(|suffix| condition_for_suffix(&suffix))
}

fn cmovcc_condition_for(mnem: Mnemonic) -> Option<Condition> {
    condition_suffix(mnem, "cmov").and_then(|suffix| condition_for_suffix(&suffix))
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

fn stos_width(mnem: Mnemonic) -> Option<u8> {
    match mnem {
        Mnemonic::Stosb => Some(1),
        Mnemonic::Stosw => Some(2),
        Mnemonic::Stosd => Some(4),
        Mnemonic::Stosq => Some(8),
        _ => None,
    }
}

fn push_ops(instr: &iced_x86::Instruction, bits: u32) -> Vec<Op> {
    // push <src>:
    //   rsp = rsp - width
    //   store [rsp], <src>
    let sp_name = if bits == 64 { "rsp" } else { "esp" };
    let sp = VReg::phys(sp_name);
    let width: u8 = if bits == 64 { 8 } else { 4 };

    // A memory source decomposes into a load-into-temp step first so the
    // store's `src` is always a Value the store op can carry.
    let mut ops: Vec<Op> = Vec::new();
    let src: Value = match instr.op_kind(0) {
        OpKind::Register => Value::Reg(VReg::phys(reg_name(instr.op_register(0)))),
        OpKind::Immediate8 => Value::Const(instr.immediate8() as i8 as i64),
        OpKind::Immediate16 => Value::Const(instr.immediate16() as i16 as i64),
        OpKind::Immediate32 => Value::Const(instr.immediate32() as i32 as i64),
        // See `value_of_operand`: a sign-extended imm8 needs its own accessor or
        // the sign is lost.
        OpKind::Immediate8to16 => Value::Const(instr.immediate8to16() as i64),
        OpKind::Immediate8to32 => Value::Const(instr.immediate8to32() as i64),
        OpKind::Immediate64 => Value::Const(instr.immediate64() as i64),
        OpKind::Immediate8to64 => Value::Const(instr.immediate8to64()),
        OpKind::Immediate32to64 => Value::Const(instr.immediate32to64()),
        OpKind::Memory => {
            // push qword [mem]: tmp = load [mem]; rsp -= width; *[rsp] = tmp.
            let tmp = VReg::Temp(0);
            ops.push(Op::Load {
                dst: tmp.clone(),
                addr: mem_op_of(instr),
            });
            Value::Reg(tmp)
        }
        _ => {
            return vec![Op::Unknown {
                mnemonic: "push".to_string(),
            }];
        }
    };
    ops.push(Op::Bin {
        dst: sp.clone(),
        op: BinOp::Sub,
        lhs: Value::Reg(sp.clone()),
        rhs: Value::Const(width as i64),
    });
    ops.push(Op::Store {
        addr: MemOp {
            base: Some(sp),
            index: None,
            scale: 0,
            disp: 0,
            size: width,
            segment: None,
            endian: Endian::Little,
        },
        src,
    });
    ops
}

fn pop_ops(instr: &iced_x86::Instruction, bits: u32) -> Vec<Op> {
    // pop <dst>:
    //   <dst> = load [rsp]
    //   rsp = rsp + width
    let sp_name = if bits == 64 { "rsp" } else { "esp" };
    let sp = VReg::phys(sp_name);
    let width: u8 = if bits == 64 { 8 } else { 4 };
    let dst = match instr.op_kind(0) {
        OpKind::Register => VReg::phys(reg_name(instr.op_register(0))),
        _ => {
            return vec![Op::Unknown {
                mnemonic: "pop".to_string(),
            }];
        }
    };
    vec![
        Op::Load {
            dst,
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

fn stos_ops(instr: &iced_x86::Instruction, mnem: Mnemonic, bits: u32) -> Vec<Op> {
    let Some(width) = stos_width(mnem) else {
        return vec![Op::Unknown {
            mnemonic: format!("{:?}", mnem).to_ascii_lowercase(),
        }];
    };
    let dst = VReg::phys(if bits == 64 { "rdi" } else { "edi" });
    let count = VReg::phys(if bits == 64 { "rcx" } else { "ecx" });
    let acc = VReg::phys(accumulator_name_for_width(width, bits));
    if instr.has_rep_prefix() || instr.has_repne_prefix() {
        let pointer_width = if bits == 64 { Width::W64 } else { Width::W32 };
        let pointer_bytes = if bits == 64 { 8 } else { 4 };
        let pointer = VReg::Temp(0);
        let remaining = VReg::Temp(1);
        let byte_count = VReg::Temp(2);
        let negative_byte_count = VReg::Temp(3);
        let pointer_delta = VReg::Temp(4);
        return vec![
            Op::Assign {
                dst: pointer.clone(),
                src: Value::Reg(dst.clone()),
            },
            Op::Assign {
                dst: remaining.clone(),
                src: Value::Reg(count.clone()),
            },
            // One architecture-neutral, typed memory effect. The scratch
            // pointer/count are private loop state for AST lowering; the
            // architectural RDI/RCX updates remain ordinary LLIR below so SSA
            // does not need a multi-output intrinsic exception.
            Op::Intrinsic {
                name: format!("memory.fill.{width}.word{pointer_bytes}"),
                ins: vec![
                    Value::Reg(pointer),
                    Value::Reg(remaining),
                    Value::Reg(acc),
                    Value::Reg(VReg::Flag(Flag::D)),
                ],
                outs: Vec::new(),
                reads_mem: false,
                writes_mem: true,
            },
            Op::Bin {
                dst: byte_count.clone(),
                op: BinOp::Mul,
                lhs: Value::Reg(count.clone()),
                rhs: Value::Const(i64::from(width)),
            },
            Op::Un {
                dst: negative_byte_count.clone(),
                op: UnOp::Neg,
                src: Value::Reg(byte_count.clone()),
            },
            Op::Ite {
                dst: pointer_delta.clone(),
                cond: VReg::Flag(Flag::D),
                t: Value::Reg(negative_byte_count),
                e: Value::Reg(byte_count),
                width: pointer_width,
            },
            Op::Bin {
                dst: dst.clone(),
                op: BinOp::Add,
                lhs: Value::Reg(dst),
                rhs: Value::Reg(pointer_delta),
            },
            Op::Assign {
                dst: count,
                src: Value::Const(0),
            },
        ];
    }
    let pointer_width = if bits == 64 { Width::W64 } else { Width::W32 };
    let step = VReg::Temp(0);
    vec![
        Op::Store {
            addr: MemOp {
                base: Some(dst.clone()),
                index: None,
                scale: 0,
                disp: 0,
                size: width,
                segment: None,
                endian: Endian::Little,
            },
            src: Value::Reg(acc),
        },
        // A non-repeated STOS performs exactly one directional step.
        Op::Ite {
            dst: step.clone(),
            cond: VReg::Flag(Flag::D),
            t: Value::Const(-i64::from(width)),
            e: Value::Const(i64::from(width)),
            width: pointer_width,
        },
        Op::Bin {
            dst: dst.clone(),
            op: BinOp::Add,
            lhs: Value::Reg(dst),
            rhs: Value::Reg(step),
        },
    ]
}

fn string_movs_ops(width: u8, bits: u32) -> Vec<Op> {
    let src_ptr = VReg::phys(if bits == 64 { "rsi" } else { "esi" });
    let dst_ptr = VReg::phys(if bits == 64 { "rdi" } else { "edi" });
    let tmp = VReg::Temp(0);
    vec![
        Op::Load {
            dst: tmp.clone(),
            addr: MemOp {
                base: Some(src_ptr.clone()),
                index: None,
                scale: 0,
                disp: 0,
                size: width,
                segment: None,
                endian: Endian::Little,
            },
        },
        Op::Store {
            addr: MemOp {
                base: Some(dst_ptr.clone()),
                index: None,
                scale: 0,
                disp: 0,
                size: width,
                segment: None,
                endian: Endian::Little,
            },
            src: Value::Reg(tmp),
        },
        Op::Bin {
            dst: src_ptr.clone(),
            op: BinOp::Add,
            lhs: Value::Reg(src_ptr),
            rhs: Value::Const(i64::from(width)),
        },
        Op::Bin {
            dst: dst_ptr.clone(),
            op: BinOp::Add,
            lhs: Value::Reg(dst_ptr),
            rhs: Value::Const(i64::from(width)),
        },
    ]
}

fn scalar_move_ops(instr: &iced_x86::Instruction, width: u8, mnemonic: &str) -> Vec<Op> {
    if instr.op_count() != 2 {
        return vec![Op::Unknown {
            mnemonic: mnemonic.into(),
        }];
    }
    match (instr.op_kind(0), instr.op_kind(1)) {
        (OpKind::Register, OpKind::Register) => vec![Op::Assign {
            dst: VReg::phys(reg_name(instr.op_register(0))),
            src: Value::Reg(VReg::phys(reg_name(instr.op_register(1)))),
        }],
        (OpKind::Register, OpKind::Memory) => {
            let mut addr = mem_op_of(instr);
            addr.size = width;
            vec![Op::Load {
                dst: VReg::phys(reg_name(instr.op_register(0))),
                addr,
            }]
        }
        (OpKind::Memory, OpKind::Register) => {
            let mut addr = mem_op_of(instr);
            addr.size = width;
            vec![Op::Store {
                addr,
                src: Value::Reg(VReg::phys(reg_name(instr.op_register(1)))),
            }]
        }
        _ => vec![Op::Unknown {
            mnemonic: mnemonic.into(),
        }],
    }
}

/// Lift a scalar SSE arithmetic instruction with its real register footprint.
///
/// The integer LLIR cannot yet express IEEE-754 arithmetic, so representing
/// these as `Bin` would silently assign the wrong semantics.  A typed
/// intrinsic still records the architectural destination and inputs, which is
/// enough for SSA, liveness, and ABI output recovery to remain sound while the
/// float value/type lattice is introduced.
fn scalar_float_binary_ops(instr: &iced_x86::Instruction, width: Width, mnemonic: &str) -> Vec<Op> {
    if instr.op_count() != 2 || instr.op_kind(0) != OpKind::Register {
        return vec![Op::Unknown {
            mnemonic: mnemonic.into(),
        }];
    }

    let dst = VReg::phys(reg_name(instr.op_register(0)));
    let mut ops = Vec::new();
    let rhs = match instr.op_kind(1) {
        OpKind::Register => Value::Reg(VReg::phys(reg_name(instr.op_register(1)))),
        OpKind::Memory => {
            let tmp = VReg::Temp(12);
            let mut addr = mem_op_of(instr);
            addr.size = u8::try_from(width.bytes()).expect("scalar SSE width fits MemOp");
            ops.push(Op::Load {
                dst: tmp.clone(),
                addr,
            });
            Value::Reg(tmp)
        }
        _ => {
            return vec![Op::Unknown {
                mnemonic: mnemonic.into(),
            }];
        }
    };
    ops.push(Op::Intrinsic {
        name: mnemonic.into(),
        ins: vec![Value::Reg(dst.clone()), rhs],
        outs: vec![(dst, width)],
        reads_mem: false,
        writes_mem: false,
    });
    ops
}

/// `shrd dst, src, imm8` / `shld dst, src, imm8` — the double-precision shift.
///
/// This is how a 32-bit compiler shifts a 64-bit value held in a register pair:
/// `add eax,ecx ; adc edx,ebx ; shrd eax,edx,2 ; sar edx,2` is `(int64_t)x / 4`.
/// The `adc` half has been modelled since this lifter learned x86 CF; the
/// `shrd` half had not, so every one of those sequences lost its low word to an
/// opaque comment. All four i386 fixtures that compute in a register pair
/// (`28_euler_ode`, `30_finite_difference`, both optimisation levels) fail on
/// exactly that.
///
/// The lowering is exact, and the operand width is what makes it exact. A
/// canonicalised `eax` lives in a 64-bit `rax` whose high half this IR never
/// clears, so `dst >> count` on the raw value would shift bits that are not the
/// machine's, and `src << (32 - count)` would leave a result no 32-bit register
/// can hold. Both operands are therefore zero-extended from their encoded width
/// first and the joined result masked back to it — the same `unsigned_cmp_value`
/// discipline that lets `add`/`adc` claim a provable carry.
///
/// Deliberately narrow:
/// * only the immediate-count form. `shrd dst, src, cl` shifts by a value this
///   lifter would have to mask and branch on at lift time, and a count of zero
///   is architecturally a *no-op that leaves the flags alone* — not something a
///   single shift expression can say.
/// * only a register destination; the memory form would need a load/store pair
///   with the same masking and does not occur in the corpus.
/// * the flags are declared undefined rather than guessed, exactly as
///   `adc_sbb_ops` does. x86 defines CF as the last bit shifted out and leaves
///   OF/AF undefined for counts above 1; a later `jb` reading a fabricated CF
///   would render a branch the CPU never evaluated.
fn double_shift_ops(instr: &iced_x86::Instruction, right: bool) -> Vec<Op> {
    let mnemonic = if right { "shrd" } else { "shld" };
    let unsupported = || {
        vec![Op::Unknown {
            mnemonic: mnemonic.into(),
        }]
    };
    if instr.op_count() != 3
        || instr.op_kind(0) != OpKind::Register
        || instr.op_kind(1) != OpKind::Register
        || !matches!(instr.op_kind(2), OpKind::Immediate8)
    {
        return unsupported();
    }
    let dst_name = reg_name(instr.op_register(0));
    let src_name = reg_name(instr.op_register(1));
    let Some(width) = phys_reg_width(&dst_name) else {
        return unsupported();
    };
    if !matches!(width, Width::W32 | Width::W64) || phys_reg_width(&src_name) != Some(width) {
        return unsupported();
    }
    let bits = u32::from(width.bits());
    // The architectural count mask: 5 bits for 32-bit operands, 6 for 64-bit.
    let count = u32::from(instr.immediate8()) & (bits - 1);
    if count == 0 {
        // Architecturally a complete no-op, flags included.
        return vec![Op::Nop];
    }
    let dst = VReg::phys(dst_name);
    let src = VReg::phys(src_name);
    let kept = VReg::Temp(0);
    let joined = VReg::Temp(1);
    let mut ops = Vec::new();

    // The destination's own contribution, at its real width.
    ops.push(Op::ZExt {
        dst: kept.clone(),
        src: Value::Reg(dst.clone()),
        from: width,
        to: Width::W64,
    });
    ops.push(Op::Bin {
        dst: kept.clone(),
        op: if right { BinOp::Shr } else { BinOp::Shl },
        lhs: Value::Reg(kept.clone()),
        rhs: Value::Const(i64::from(count)),
    });
    // The bits shifted in from the other half of the pair.
    ops.push(Op::ZExt {
        dst: joined.clone(),
        src: Value::Reg(src),
        from: width,
        to: Width::W64,
    });
    ops.push(Op::Bin {
        dst: joined.clone(),
        op: if right { BinOp::Shl } else { BinOp::Shr },
        lhs: Value::Reg(joined.clone()),
        rhs: Value::Const(i64::from(bits - count)),
    });
    ops.push(Op::Bin {
        dst: dst.clone(),
        op: BinOp::Or,
        lhs: Value::Reg(kept),
        rhs: Value::Reg(joined),
    });
    // At 32 bits one of the two halves is always shifted left past the
    // register, so the join has to be masked back down; at 64 bits the IR word
    // is the register and the shift truncates on its own.
    if bits < 64 {
        ops.push(Op::Bin {
            dst: dst.clone(),
            op: BinOp::And,
            lhs: Value::Reg(dst),
            rhs: Value::Const(((1u64 << bits) - 1) as i64),
        });
    }
    append_undef_flags(
        &mut ops,
        &[Flag::C, Flag::O, Flag::Z, Flag::S, Flag::P, Flag::A],
        "x86 SHRD/SHLD define CF from the last bit shifted out and leave OF/AF \
         undefined above a count of one; none of that is modelled",
    );
    ops
}

/// `bsr`/`bsf` — the x86 bit scans, lowered through the same exact `clz`
/// intrinsic the ARM lifter already emits (`ast::WideArithmetic::CountLeadingZeros`,
/// rendered as `((unsigned)(x) == 0 ? BITS : __builtin_clz((unsigned)(x)))`).
///
/// Left unmodelled these were an `Op::Unknown`, so the destination was never
/// defined and every consumer read an uninitialised local. `14_flag_effects`'s
/// `shift_until_zero` is exactly that: gcc -O2 compiles the shift-count loop to
/// `bsr %eax,%ecx ; add $1,%ecx ; test %eax,%eax ; cmovne %ecx,%eax`, and we
/// recovered `return ((arg0 != 0) ? (var1 + 1) : arg0);` with `var1` undefined.
///
/// **The x86 zero case is NOT ARM's.** `clz` answers the operand width; `bsr`
/// and `bsf` instead set ZF and leave the DESTINATION ALONE (AMD APM v3 states
/// "the destination is left unchanged"; Intel SDM calls it undefined, which
/// permits that). Modelling the scan as producing `32`, `0`, or `-1` would
/// invent a value the machine never wrote — so the scan result is gated behind
/// `Op::Ite` on `src != 0` with the destination's PRIOR value as the else arm.
/// `Op::Ite` rather than `Op::CondAssign` for the reason `cmovcc` uses it: a
/// `CondAssign` destination is a pure def, so dataflow cannot see that the old
/// value is still read and DCE drops whatever produced it.
///
/// The two identities, both exact for a nonzero operand at `BITS` bits:
///
/// * `bsr(x) = (BITS - 1) - clz(x)` — the index of the highest set bit.
/// * `bsf(x) = (BITS - 1) - clz(x ^ (x - 1))`. `x ^ (x - 1)` is the mask of the
///   trailing zeros together with the lowest set bit, so its highest set bit IS
///   the lowest set bit of `x`. It is used in preference to the more familiar
///   `x & -x` because it never negates: the operands stay non-negative in the C
///   this renders to.
///
/// Deliberately narrow:
/// * only 32- and 64-bit operands. The 16-bit form exists, but the `clz`
///   renderer spells a sub-64-bit count as `__builtin_clz((unsigned int)(x))` —
///   a count over 32 bits — so `x86.clz.16` would answer 16 too high. That is
///   the renderer's contract to widen, not this lifter's to guess around, and
///   `ast.rs` is not this change's file.
/// * only a register destination, which is the only form the ISA encodes.
/// * every flag other than ZF is architecturally undefined and is poisoned
///   rather than left stale.
fn bit_scan_ops(instr: &iced_x86::Instruction, forward: bool) -> Vec<Op> {
    let mnemonic = if forward { "bsf" } else { "bsr" };
    let unsupported = || {
        vec![Op::Unknown {
            mnemonic: mnemonic.into(),
        }]
    };
    if instr.op_count() != 2 || instr.op_kind(0) != OpKind::Register {
        return unsupported();
    }
    let dst_name = reg_name(instr.op_register(0));
    let Some(width) = phys_reg_width(&dst_name) else {
        return unsupported();
    };
    if !matches!(width, Width::W32 | Width::W64) {
        return unsupported();
    }

    let mut ops = Vec::new();
    let source = match instr.op_kind(1) {
        OpKind::Register => {
            if phys_reg_width(&reg_name(instr.op_register(1))) != Some(width) {
                return unsupported();
            }
            Value::Reg(VReg::phys(reg_name(instr.op_register(1))))
        }
        OpKind::Memory => {
            if Width::from_bytes(instr.memory_size().size() as u16) != width {
                return unsupported();
            }
            let loaded = VReg::Temp(0);
            ops.push(Op::Load {
                dst: loaded.clone(),
                addr: mem_op_of(instr),
            });
            Value::Reg(loaded)
        }
        _ => return unsupported(),
    };

    // The word the scan actually observes. A canonicalised 32-bit register
    // lives in a 64-bit parent whose high half this IR never clears, so both
    // the zero test and the leading-zero count have to name the encoded width.
    let operand = unsigned_cmp_value(source, width, VReg::Temp(1), &mut ops);
    let bits = i64::from(width.bits());
    let dst = VReg::phys(dst_name);

    // ZF is the one flag x86 defines here, and it is defined for BOTH cases.
    ops.push(Op::Cmp {
        dst: VReg::Flag(Flag::Z),
        op: CmpOp::Eq,
        lhs: operand.clone(),
        rhs: Value::Const(0),
    });

    // Move the bit being searched for into the most-significant position that
    // `clz` reports on. For a backward scan it is already there.
    let scanned = if forward {
        let lowered = VReg::Temp(2);
        ops.push(Op::Bin {
            dst: lowered.clone(),
            op: BinOp::Sub,
            lhs: operand.clone(),
            rhs: Value::Const(1),
        });
        ops.push(Op::Bin {
            dst: lowered.clone(),
            op: BinOp::Xor,
            lhs: operand.clone(),
            rhs: Value::Reg(lowered.clone()),
        });
        Value::Reg(lowered)
    } else {
        operand.clone()
    };

    let index = VReg::Temp(3);
    ops.push(Op::Intrinsic {
        name: format!("x86.clz.{bits}"),
        ins: vec![scanned],
        outs: vec![(index.clone(), width)],
        reads_mem: false,
        writes_mem: false,
    });
    ops.push(Op::Bin {
        dst: index.clone(),
        op: BinOp::Sub,
        lhs: Value::Const(bits - 1),
        rhs: Value::Reg(index.clone()),
    });

    // Intel leaves the destination UNDEFINED when the source is zero; only AMD
    // documents it as preserved. Writing the count unconditionally is therefore
    // architecturally faithful, and it is the only lowering that does not read
    // the destination before defining it.
    //
    // That read is not a cosmetic difference. A self-referential `dst = src ? f(src) : dst`
    // makes `dst` live-in on the zero path, and a live-in physical register in an
    // argument slot is exactly what parameter recovery promotes to a parameter —
    // so preserving a value no correct program can observe cost `shift_until_zero`
    // three phantom parameters and left the emitted C reading an unassigned local
    // in an arm the guard never selects.
    //
    // ZF above still distinguishes the two cases exactly, which is what callers
    // actually branch on. The zero case yields `bits - 1 - clz(0)`, a defined and
    // deterministic value where the architecture permits any.
    ops.push(Op::Assign {
        dst,
        src: Value::Reg(index),
    });
    append_undef_flags(
        &mut ops,
        &[Flag::C, Flag::O, Flag::S, Flag::P, Flag::A],
        "x86 BSR/BSF define ZF only; CF/OF/SF/PF/AF are architecturally undefined",
    );
    ops
}

/// Exact CF/ZF/SF/OF effects for one ADC/SBB destination.
///
/// The arithmetic is deliberately split into two machine-width steps. Besides
/// matching the instruction's dataflow, that gives carry/borrow two exact
/// predicates that work at 64 bits without trying to represent `2^64` in an IR
/// constant:
///
/// * ADC carry is `(partial < lhs) || (result < partial)`;
/// * SBB borrow is `(lhs < rhs) || (partial < old_cf)`.
///
/// Signed overflow follows the architectural sign relation. ADC overflows when
/// the operand signs agree and the result sign changes; SBB when they disagree
/// and the result sign changes. PF/AF remain explicit poison rather than stale
/// values because their low-bit expressions are not yet modelled.
fn emit_adc_sbb_with_flags(dst: VReg, rhs: Value, width: Width, add: bool) -> Vec<Op> {
    let arithmetic = if add { BinOp::Add } else { BinOp::Sub };
    let old_carry = VReg::Temp(60);
    let original = VReg::Temp(61);
    let partial = VReg::Temp(62);
    let mut ops = vec![
        Op::Assign {
            dst: old_carry.clone(),
            src: Value::Reg(VReg::Flag(Flag::C)),
        },
        Op::Assign {
            dst: original.clone(),
            src: Value::Reg(dst.clone()),
        },
    ];

    let unsigned_lhs = unsigned_cmp_value(
        Value::Reg(original.clone()),
        width,
        VReg::Temp(63),
        &mut ops,
    );
    let unsigned_rhs = unsigned_cmp_value(rhs.clone(), width, VReg::Temp(64), &mut ops);
    let signed_lhs = signed_cmp_value(Value::Reg(original), width, VReg::Temp(65), &mut ops);
    let signed_rhs = signed_cmp_value(rhs.clone(), width, VReg::Temp(66), &mut ops);
    let lhs_negative = VReg::Temp(67);
    let rhs_negative = VReg::Temp(68);
    ops.extend([
        Op::Cmp {
            dst: lhs_negative.clone(),
            op: CmpOp::Slt,
            lhs: signed_lhs,
            rhs: Value::Const(0),
        },
        Op::Cmp {
            dst: rhs_negative.clone(),
            op: CmpOp::Slt,
            lhs: signed_rhs,
            rhs: Value::Const(0),
        },
        emit_bin(dst.clone(), arithmetic, rhs),
    ]);
    if width.bits() < 64 {
        ops.push(Op::Trunc {
            dst: dst.clone(),
            src: Value::Reg(dst.clone()),
            from: Width::W64,
            to: width,
        });
    }
    ops.push(Op::Assign {
        dst: partial.clone(),
        src: Value::Reg(dst.clone()),
    });
    ops.push(emit_bin(
        dst.clone(),
        arithmetic,
        Value::Reg(old_carry.clone()),
    ));
    if width.bits() < 64 {
        ops.push(Op::Trunc {
            dst: dst.clone(),
            src: Value::Reg(dst.clone()),
            from: Width::W64,
            to: width,
        });
    }
    zero_sign_flags(Value::Reg(dst.clone()), width, 69, &mut ops);

    let unsigned_partial = unsigned_cmp_value(Value::Reg(partial), width, VReg::Temp(70), &mut ops);
    let unsigned_result = unsigned_cmp_value(Value::Reg(dst), width, VReg::Temp(71), &mut ops);
    let first_carry = VReg::Temp(72);
    let second_carry = VReg::Temp(73);
    if add {
        ops.extend([
            Op::Cmp {
                dst: first_carry.clone(),
                op: CmpOp::Ult,
                lhs: unsigned_partial.clone(),
                rhs: unsigned_lhs,
            },
            Op::Cmp {
                dst: second_carry.clone(),
                op: CmpOp::Ult,
                lhs: unsigned_result,
                rhs: unsigned_partial,
            },
        ]);
    } else {
        ops.extend([
            Op::Cmp {
                dst: first_carry.clone(),
                op: CmpOp::Ult,
                lhs: unsigned_lhs,
                rhs: unsigned_rhs,
            },
            Op::Cmp {
                dst: second_carry.clone(),
                op: CmpOp::Ult,
                lhs: unsigned_partial,
                rhs: Value::Reg(old_carry),
            },
        ]);
    }
    ops.push(Op::Bin {
        dst: VReg::Flag(Flag::C),
        op: BinOp::Or,
        lhs: Value::Reg(first_carry),
        rhs: Value::Reg(second_carry),
    });

    let operand_sign_relation = VReg::Temp(74);
    let result_sign_changed = VReg::Temp(75);
    ops.extend([
        Op::Cmp {
            dst: operand_sign_relation.clone(),
            op: if add { CmpOp::Eq } else { CmpOp::Ne },
            lhs: Value::Reg(lhs_negative.clone()),
            rhs: Value::Reg(rhs_negative),
        },
        Op::Cmp {
            dst: result_sign_changed.clone(),
            op: CmpOp::Ne,
            lhs: Value::Reg(VReg::Flag(Flag::S)),
            rhs: Value::Reg(lhs_negative),
        },
        Op::Bin {
            dst: VReg::Flag(Flag::O),
            op: BinOp::And,
            lhs: Value::Reg(operand_sign_relation),
            rhs: Value::Reg(result_sign_changed),
        },
    ]);
    append_undef_flags(
        &mut ops,
        &[Flag::P, Flag::A],
        if add {
            "x86 ADC defines PF/AF, but their exact low-bit expressions are not modelled"
        } else {
            "x86 SBB defines PF/AF, but their exact low-bit expressions are not modelled"
        },
    );
    ops
}

fn adc_sbb_ops(instr: &iced_x86::Instruction, add: bool) -> Vec<Op> {
    let mnemonic = if add { "adc" } else { "sbb" };
    if instr.op_count() != 2 {
        return vec![Op::Unknown {
            mnemonic: mnemonic.into(),
        }];
    }

    let width = operand_width(instr, 0);
    match instr.op_kind(0) {
        OpKind::Register => {
            let dst = VReg::phys(reg_name(instr.op_register(0)));
            let mut ops = Vec::new();
            let Some(rhs) = cmp_operand_as_value(instr, 1, VReg::Temp(0), &mut ops) else {
                return vec![Op::Unknown {
                    mnemonic: mnemonic.into(),
                }];
            };
            ops.extend(emit_adc_sbb_with_flags(dst, rhs, width, add));
            ops
        }
        OpKind::Memory => {
            let addr = mem_op_of(instr);
            let mut ops = Vec::new();
            let Some(rhs) = cmp_operand_as_value(instr, 1, VReg::Temp(1), &mut ops) else {
                return vec![Op::Unknown {
                    mnemonic: mnemonic.into(),
                }];
            };
            let tmp = VReg::Temp(0);
            ops.insert(
                0,
                Op::Load {
                    dst: tmp.clone(),
                    addr: addr.clone(),
                },
            );
            ops.extend(emit_adc_sbb_with_flags(tmp.clone(), rhs, width, add));
            ops.push(Op::Store {
                addr,
                src: Value::Reg(tmp),
            });
            ops
        }
        _ => vec![Op::Unknown {
            mnemonic: mnemonic.into(),
        }],
    }
}

fn adc_ops(instr: &iced_x86::Instruction) -> Vec<Op> {
    adc_sbb_ops(instr, true)
}

fn sbb_ops(instr: &iced_x86::Instruction) -> Vec<Op> {
    adc_sbb_ops(instr, false)
}

fn xorps_ops(instr: &iced_x86::Instruction) -> Vec<Op> {
    packed_dword_binary_ops(instr, BinOp::Xor)
}

fn cmpxchg_ops(instr: &iced_x86::Instruction, bits: u32) -> Vec<Op> {
    if instr.op_count() != 2 || instr.op_kind(1) != OpKind::Register {
        return vec![Op::Unknown {
            mnemonic: "cmpxchg".into(),
        }];
    }

    let src = Value::Reg(VReg::phys(reg_name(instr.op_register(1))));
    let old = VReg::Temp(0);
    let width = operand_width(instr, 0);
    let acc = match instr.op_kind(0) {
        OpKind::Register => {
            let dst = instr.op_register(0);
            VReg::phys(accumulator_name_for_width(reg_size(dst), bits))
        }
        OpKind::Memory => VReg::phys(accumulator_name_for_width(
            instr.memory_size().size() as u8,
            bits,
        )),
        _ => {
            return vec![Op::Unknown {
                mnemonic: "cmpxchg".into(),
            }];
        }
    };

    let mut ops = Vec::new();
    match instr.op_kind(0) {
        OpKind::Register => {
            let dst = VReg::phys(reg_name(instr.op_register(0)));
            ops.push(Op::Assign {
                dst: old.clone(),
                src: Value::Reg(dst.clone()),
            });
            ops.extend(cmp_flag_ops(
                Value::Reg(acc.clone()),
                Value::Reg(old.clone()),
                width,
            ));
            // CMPXCHG is a two-input select for the destination.  The false
            // arm must be explicit: it reads the destination value captured
            // above, rather than defining an otherwise-uninitialized register.
            ops.push(Op::Ite {
                cond: VReg::Flag(Flag::Z),
                t: src,
                e: Value::Reg(dst.clone()),
                dst,
                width,
            });
        }
        OpKind::Memory => {
            let addr = mem_op_of(instr);
            ops.push(Op::Load {
                dst: old.clone(),
                addr: addr.clone(),
            });
            ops.extend(cmp_flag_ops(
                Value::Reg(acc.clone()),
                Value::Reg(old.clone()),
                width,
            ));
            // On comparison failure x86 leaves memory unchanged.  Model the
            // memory effect itself as conditional so the false path performs
            // no access and cannot store an undefined select temporary.
            ops.push(Op::CondStore {
                cond: VReg::Flag(Flag::Z),
                inverted: false,
                addr,
                src,
            });
        }
        _ => unreachable!("checked above"),
    }

    let not_equal = VReg::Temp(2);
    ops.push(Op::Cmp {
        dst: not_equal.clone(),
        op: CmpOp::Eq,
        lhs: Value::Reg(VReg::Flag(Flag::Z)),
        rhs: Value::Const(0),
    });
    // The accumulator changes only on failure.  Its success-path prior value
    // is an input, not an implicit side effect hidden from SSA/use-def.
    ops.push(Op::Ite {
        cond: not_equal,
        t: Value::Reg(old),
        e: Value::Reg(acc.clone()),
        dst: acc,
        width,
    });
    ops
}

/// One signed/unsigned 32-bit lane of an XMM register.
///
/// Packed integer operations are not scalar 128-bit arithmetic. Representing
/// the four dword lanes independently lets the existing scalar LLIR, SSA, and C
/// backend preserve exact lane dataflow without adding a second vector AST.
fn packed_dword_lane(register: Register, lane: usize) -> VReg {
    crate::ir::types::packed_dword_lane(&reg_name(register), lane)
}

fn is_xmm_register(register: Register) -> bool {
    reg_name(register)
        .strip_prefix("xmm")
        .is_some_and(|index| index.parse::<u8>().is_ok())
}

/// Define both scalar-LLIR views of a zeroed XMM register. Scalar floating
/// moves consume the whole-register name while packed operations consume four
/// dword lanes; a self-XOR proves all five values simultaneously.
fn xmm_zero_ops(register: Register) -> Vec<Op> {
    let mut ops = vec![Op::Assign {
        dst: VReg::phys(reg_name(register)),
        src: Value::Const(0),
    }];
    ops.extend((0..4).map(|lane| Op::Assign {
        dst: packed_dword_lane(register, lane),
        src: Value::Const(0),
    }));
    ops
}

fn packed_dword_move_ops(instr: &iced_x86::Instruction) -> Vec<Op> {
    if instr.op_count() != 2 {
        return vec![Op::Unknown {
            mnemonic: format!("{:?}", instr.mnemonic()).to_ascii_lowercase(),
        }];
    }
    match (instr.op_kind(0), instr.op_kind(1)) {
        (OpKind::Register, OpKind::Memory) if is_xmm_register(instr.op_register(0)) => (0..4)
            .map(|lane| {
                let mut addr = mem_op_of(instr);
                addr.disp = addr.disp.saturating_add((lane * 4) as i64);
                addr.size = 4;
                Op::Load {
                    dst: packed_dword_lane(instr.op_register(0), lane),
                    addr,
                }
            })
            .collect(),
        (OpKind::Memory, OpKind::Register) if is_xmm_register(instr.op_register(1)) => (0..4)
            .map(|lane| {
                let mut addr = mem_op_of(instr);
                addr.disp = addr.disp.saturating_add((lane * 4) as i64);
                addr.size = 4;
                Op::Store {
                    addr,
                    src: Value::Reg(packed_dword_lane(instr.op_register(1), lane)),
                }
            })
            .collect(),
        (OpKind::Register, OpKind::Register)
            if is_xmm_register(instr.op_register(0)) && is_xmm_register(instr.op_register(1)) =>
        {
            (0..4)
                .map(|lane| Op::Assign {
                    dst: packed_dword_lane(instr.op_register(0), lane),
                    src: Value::Reg(packed_dword_lane(instr.op_register(1), lane)),
                })
                .collect()
        }
        _ => vec![Op::Unknown {
            mnemonic: format!("{:?}", instr.mnemonic()).to_ascii_lowercase(),
        }],
    }
}

/// Move the low 64 bits of an XMM register as two explicit dword lanes.
///
/// The XMM load/register forms clear the upper 64 bits; the memory store form
/// writes only the two low lanes. MMX and general-purpose-register MOVQ forms
/// deliberately remain unsupported rather than being given XMM semantics.
fn packed_qword_move_ops(instr: &iced_x86::Instruction) -> Vec<Op> {
    if instr.op_count() != 2 {
        return vec![Op::Unknown {
            mnemonic: "movq".into(),
        }];
    }
    match (instr.op_kind(0), instr.op_kind(1)) {
        (OpKind::Register, OpKind::Memory) if is_xmm_register(instr.op_register(0)) => {
            let dst = instr.op_register(0);
            let mut ops: Vec<_> = (0..2)
                .map(|lane| {
                    let mut addr = mem_op_of(instr);
                    addr.disp = addr.disp.saturating_add((lane * 4) as i64);
                    addr.size = 4;
                    Op::Load {
                        dst: packed_dword_lane(dst, lane),
                        addr,
                    }
                })
                .collect();
            ops.extend((2..4).map(|lane| Op::Assign {
                dst: packed_dword_lane(dst, lane),
                src: Value::Const(0),
            }));
            ops
        }
        (OpKind::Memory, OpKind::Register) if is_xmm_register(instr.op_register(1)) => {
            let src = instr.op_register(1);
            (0..2)
                .map(|lane| {
                    let mut addr = mem_op_of(instr);
                    addr.disp = addr.disp.saturating_add((lane * 4) as i64);
                    addr.size = 4;
                    Op::Store {
                        addr,
                        src: Value::Reg(packed_dword_lane(src, lane)),
                    }
                })
                .collect()
        }
        (OpKind::Register, OpKind::Register)
            if is_xmm_register(instr.op_register(0)) && is_xmm_register(instr.op_register(1)) =>
        {
            let dst = instr.op_register(0);
            let src = instr.op_register(1);
            let mut ops: Vec<_> = (0..2)
                .map(|lane| Op::Assign {
                    dst: packed_dword_lane(dst, lane),
                    src: Value::Reg(packed_dword_lane(src, lane)),
                })
                .collect();
            ops.extend((2..4).map(|lane| Op::Assign {
                dst: packed_dword_lane(dst, lane),
                src: Value::Const(0),
            }));
            ops
        }
        (OpKind::Register, OpKind::Register)
            if is_xmm_register(instr.op_register(0))
                && !is_xmm_register(instr.op_register(1))
                && phys_reg_width(&reg_name(instr.op_register(1))) == Some(Width::W64) =>
        {
            let dst = instr.op_register(0);
            let src = VReg::phys(reg_name(instr.op_register(1)));
            vec![
                Op::Trunc {
                    dst: packed_dword_lane(dst, 0),
                    src: Value::Reg(src.clone()),
                    from: Width::W64,
                    to: Width::W32,
                },
                Op::Extract {
                    dst: packed_dword_lane(dst, 1),
                    src: Value::Reg(src),
                    hi: 64,
                    lo: 32,
                },
                Op::Assign {
                    dst: packed_dword_lane(dst, 2),
                    src: Value::Const(0),
                },
                Op::Assign {
                    dst: packed_dword_lane(dst, 3),
                    src: Value::Const(0),
                },
            ]
        }
        (OpKind::Register, OpKind::Register)
            if !is_xmm_register(instr.op_register(0))
                && is_xmm_register(instr.op_register(1))
                && phys_reg_width(&reg_name(instr.op_register(0))) == Some(Width::W64) =>
        {
            vec![Op::Concat {
                dst: VReg::phys(reg_name(instr.op_register(0))),
                hi: Value::Reg(packed_dword_lane(instr.op_register(1), 1)),
                lo: Value::Reg(packed_dword_lane(instr.op_register(1), 0)),
            }]
        }
        _ => vec![Op::Unknown {
            mnemonic: "movq".into(),
        }],
    }
}

fn packed_dword_binary_ops(instr: &iced_x86::Instruction, op: BinOp) -> Vec<Op> {
    if instr.op_count() != 2
        || instr.op_kind(0) != OpKind::Register
        || !is_xmm_register(instr.op_register(0))
    {
        return vec![Op::Unknown {
            mnemonic: format!("{:?}", instr.mnemonic()).to_ascii_lowercase(),
        }];
    }
    if op == BinOp::Xor
        && instr.op_kind(1) == OpKind::Register
        && instr.op_register(1) == instr.op_register(0)
    {
        return xmm_zero_ops(instr.op_register(0));
    }
    let Some((mut ops, sources)) = packed_dword_sources(instr, 92) else {
        return vec![Op::Unknown {
            mnemonic: format!("{:?}", instr.mnemonic()).to_ascii_lowercase(),
        }];
    };
    for (lane, source) in sources.into_iter().enumerate() {
        let dst = packed_dword_lane(instr.op_register(0), lane);
        ops.push(Op::Bin {
            dst: dst.clone(),
            op,
            lhs: Value::Reg(dst),
            rhs: source,
        });
    }
    ops
}

/// SHUFPS treats its operands as four 32-bit bit-pattern lanes. The low two
/// selectors address the old destination and the high two address the source.
fn packed_float_shuffle_ops(instr: &iced_x86::Instruction) -> Vec<Op> {
    if instr.op_count() != 3
        || instr.op_kind(0) != OpKind::Register
        || instr.op_kind(1) != OpKind::Register
        || instr.op_kind(2) != OpKind::Immediate8
        || !is_xmm_register(instr.op_register(0))
        || !is_xmm_register(instr.op_register(1))
    {
        return vec![Op::Unknown {
            mnemonic: "shufps".into(),
        }];
    }
    let dst = instr.op_register(0);
    let src = instr.op_register(1);
    let control = instr.immediate8();
    let mut ops = Vec::with_capacity(12);
    for lane in 0..4 {
        ops.push(Op::Assign {
            dst: VReg::Temp(84 + lane as u32),
            src: Value::Reg(packed_dword_lane(dst, lane)),
        });
        ops.push(Op::Assign {
            dst: VReg::Temp(88 + lane as u32),
            src: Value::Reg(packed_dword_lane(src, lane)),
        });
    }
    for lane in 0..4 {
        let selected = ((control >> (lane * 2)) & 0x3) as u32;
        let temporary = if lane < 2 {
            84 + selected
        } else {
            88 + selected
        };
        ops.push(Op::Assign {
            dst: packed_dword_lane(dst, lane),
            src: Value::Reg(VReg::Temp(temporary)),
        });
    }
    ops
}

/// MOVMSKPS packs each dword lane's sign bit into a four-bit GPR mask.
fn packed_float_sign_mask_ops(instr: &iced_x86::Instruction) -> Vec<Op> {
    if instr.op_count() != 2
        || instr.op_kind(0) != OpKind::Register
        || instr.op_kind(1) != OpKind::Register
        || is_xmm_register(instr.op_register(0))
        || !is_xmm_register(instr.op_register(1))
    {
        return vec![Op::Unknown {
            mnemonic: "movmskps".into(),
        }];
    }
    let dst = VReg::phys(reg_name(instr.op_register(0)));
    let src = instr.op_register(1);
    let mut ops = vec![Op::Assign {
        dst: dst.clone(),
        src: Value::Const(0),
    }];
    for lane in 0..4 {
        let sign = VReg::Temp(120 + lane as u32 * 2);
        let shifted = VReg::Temp(121 + lane as u32 * 2);
        ops.push(Op::Cmp {
            dst: sign.clone(),
            op: CmpOp::Slt,
            lhs: Value::Reg(packed_dword_lane(src, lane)),
            rhs: Value::Const(0),
        });
        ops.push(Op::Bin {
            dst: shifted.clone(),
            op: BinOp::Shl,
            lhs: Value::Reg(sign),
            rhs: Value::Const(lane as i64),
        });
        ops.push(Op::Bin {
            dst: dst.clone(),
            op: BinOp::Or,
            lhs: Value::Reg(dst.clone()),
            rhs: Value::Reg(shifted),
        });
    }
    ops
}

/// PEXTRW zero-extends one selected 16-bit XMM word into a 32-bit GPR.
fn packed_word_extract_ops(instr: &iced_x86::Instruction) -> Vec<Op> {
    if instr.op_count() != 3
        || instr.op_kind(0) != OpKind::Register
        || instr.op_kind(1) != OpKind::Register
        || instr.op_kind(2) != OpKind::Immediate8
        || is_xmm_register(instr.op_register(0))
        || !is_xmm_register(instr.op_register(1))
    {
        return vec![Op::Unknown {
            mnemonic: "pextrw".into(),
        }];
    }
    let word = usize::from(instr.immediate8() & 7);
    let lane = word / 2;
    let extracted = VReg::Temp(128);
    let mut ops = if word % 2 == 0 {
        vec![Op::Trunc {
            dst: extracted.clone(),
            src: Value::Reg(packed_dword_lane(instr.op_register(1), lane)),
            from: Width::W32,
            to: Width::W16,
        }]
    } else {
        vec![Op::Extract {
            dst: extracted.clone(),
            src: Value::Reg(packed_dword_lane(instr.op_register(1), lane)),
            hi: 32,
            lo: 16,
        }]
    };
    ops.push(Op::ZExt {
        dst: VReg::phys(reg_name(instr.op_register(0))),
        src: Value::Reg(extracted),
        from: Width::W16,
        to: Width::W32,
    });
    ops
}

/// Lift PSLLD's immediate form as four independent 32-bit lane shifts.
///
/// Intel specifies a zero result, rather than a masked shift count, when the
/// immediate is greater than 31. Register/memory count operands remain
/// unsupported until the low-64-bit count extraction is represented exactly.
fn packed_dword_immediate_shift_left_ops(instr: &iced_x86::Instruction) -> Vec<Op> {
    if instr.op_count() != 2
        || instr.op_kind(0) != OpKind::Register
        || instr.op_kind(1) != OpKind::Immediate8
        || !is_xmm_register(instr.op_register(0))
    {
        return vec![Op::Unknown {
            mnemonic: "pslld".into(),
        }];
    }
    let count = instr.immediate8();
    (0..4)
        .map(|lane| {
            let dst = packed_dword_lane(instr.op_register(0), lane);
            if count > 31 {
                Op::Assign {
                    dst,
                    src: Value::Const(0),
                }
            } else {
                Op::Bin {
                    dst: dst.clone(),
                    op: BinOp::Shl,
                    lhs: Value::Reg(dst),
                    rhs: Value::Const(i64::from(count)),
                }
            }
        })
        .collect()
}

/// Lift PSRLD's immediate form as four independent unsigned 32-bit shifts.
/// Like PSLLD, Intel defines counts above 31 to clear each complete lane.
fn packed_dword_immediate_logical_shift_right_ops(instr: &iced_x86::Instruction) -> Vec<Op> {
    if instr.op_count() != 2
        || instr.op_kind(0) != OpKind::Register
        || instr.op_kind(1) != OpKind::Immediate8
        || !is_xmm_register(instr.op_register(0))
    {
        return vec![Op::Unknown {
            mnemonic: "psrld".into(),
        }];
    }
    let count = instr.immediate8();
    let mut ops = Vec::with_capacity(if count > 31 { 4 } else { 8 });
    for lane in 0..4 {
        let dst = packed_dword_lane(instr.op_register(0), lane);
        if count > 31 {
            ops.push(Op::Assign {
                dst,
                src: Value::Const(0),
            });
        } else {
            let narrowed = VReg::Temp(140 + lane as u32);
            ops.push(Op::Trunc {
                dst: narrowed.clone(),
                src: Value::Reg(dst.clone()),
                from: Width::W64,
                to: Width::W32,
            });
            ops.push(Op::Bin {
                dst,
                op: BinOp::Shr,
                lhs: Value::Reg(narrowed),
                rhs: Value::Const(i64::from(count)),
            });
        }
    }
    ops
}

/// Lift PSRAD's immediate form as four signed 32-bit lane shifts.
///
/// Counts above the lane width produce the sign mask, which is equivalent to
/// shifting each signed dword by 31. Non-immediate count operands remain
/// unsupported until their low-64-bit count extraction is represented.
fn packed_dword_immediate_arithmetic_shift_right_ops(instr: &iced_x86::Instruction) -> Vec<Op> {
    if instr.op_count() != 2
        || instr.op_kind(0) != OpKind::Register
        || instr.op_kind(1) != OpKind::Immediate8
        || !is_xmm_register(instr.op_register(0))
    {
        return vec![Op::Unknown {
            mnemonic: "psrad".into(),
        }];
    }
    let count = instr.immediate8().min(31);
    (0..4)
        .map(|lane| {
            let dst = packed_dword_lane(instr.op_register(0), lane);
            Op::Bin {
                dst: dst.clone(),
                op: BinOp::Sar,
                lhs: Value::Reg(dst),
                rhs: Value::Const(i64::from(count)),
            }
        })
        .collect()
}

/// Snapshot two low dwords from each operand and write the requested lane order.
fn packed_low_unpack_ops(
    instr: &iced_x86::Instruction,
    mnemonic: &str,
    lane_order: [u32; 4],
) -> Vec<Op> {
    if instr.op_count() != 2
        || instr.op_kind(0) != OpKind::Register
        || !is_xmm_register(instr.op_register(0))
    {
        return vec![Op::Unknown {
            mnemonic: mnemonic.into(),
        }];
    }
    let Some((mut ops, sources)) = packed_dword_sources(instr, 92) else {
        return vec![Op::Unknown {
            mnemonic: mnemonic.into(),
        }];
    };
    let dst = instr.op_register(0);
    for (temporary, source) in [
        (104, Value::Reg(packed_dword_lane(dst, 0))),
        (105, Value::Reg(packed_dword_lane(dst, 1))),
        (106, sources[0].clone()),
        (107, sources[1].clone()),
    ] {
        ops.push(Op::Assign {
            dst: VReg::Temp(temporary),
            src: source,
        });
    }
    for (lane, temporary) in lane_order.into_iter().enumerate() {
        ops.push(Op::Assign {
            dst: packed_dword_lane(dst, lane),
            src: Value::Reg(VReg::Temp(temporary)),
        });
    }
    ops
}

/// Interleave the low two dwords: `[dst0, src0, dst1, src1]`.
///
/// All inputs are snapshotted before the destination is overwritten, which
/// preserves the in-place form (`punpckldq xmm0,xmm0`) exactly.
fn packed_dword_unpack_low_ops(instr: &iced_x86::Instruction) -> Vec<Op> {
    packed_low_unpack_ops(instr, "punpckldq", [104, 106, 105, 107])
}

/// Interleave the complete low qwords: `[dst0, dst1, src0, src1]`.
fn packed_qword_unpack_low_ops(instr: &iced_x86::Instruction) -> Vec<Op> {
    packed_low_unpack_ops(instr, "punpcklqdq", [104, 105, 106, 107])
}

/// Add two packed 64-bit lanes while retaining carry between their dword views.
fn packed_qword_binary_ops(instr: &iced_x86::Instruction, op: BinOp, mnemonic: &str) -> Vec<Op> {
    if instr.op_count() != 2
        || instr.op_kind(0) != OpKind::Register
        || !is_xmm_register(instr.op_register(0))
    {
        return vec![Op::Unknown {
            mnemonic: mnemonic.into(),
        }];
    }
    let Some((mut ops, sources)) = packed_dword_sources(instr, 92) else {
        return vec![Op::Unknown {
            mnemonic: mnemonic.into(),
        }];
    };
    let dst = instr.op_register(0);
    for qword in 0..2 {
        let low_lane = qword * 2;
        let high_lane = low_lane + 1;
        let lhs = VReg::Temp(108 + qword as u32 * 3);
        let rhs = VReg::Temp(109 + qword as u32 * 3);
        let sum = VReg::Temp(110 + qword as u32 * 3);
        ops.extend([
            Op::Concat {
                dst: lhs.clone(),
                hi: Value::Reg(packed_dword_lane(dst, high_lane)),
                lo: Value::Reg(packed_dword_lane(dst, low_lane)),
            },
            Op::Concat {
                dst: rhs.clone(),
                hi: sources[high_lane].clone(),
                lo: sources[low_lane].clone(),
            },
            Op::Bin {
                dst: sum.clone(),
                op,
                lhs: Value::Reg(lhs),
                rhs: Value::Reg(rhs),
            },
            Op::Trunc {
                dst: packed_dword_lane(dst, low_lane),
                src: Value::Reg(sum.clone()),
                from: Width::W64,
                to: Width::W32,
            },
            Op::Extract {
                dst: packed_dword_lane(dst, high_lane),
                src: Value::Reg(sum),
                hi: 64,
                lo: 32,
            },
        ]);
    }
    ops
}

/// Snapshot the four dword lanes of a packed instruction's second operand.
/// Register operands already have independent lane names; memory operands need
/// explicit scalar loads so the ordinary readonly-data pass can materialise
/// their bytes into portable constants later in the AST pipeline.
fn packed_dword_sources(
    instr: &iced_x86::Instruction,
    first_temp: u32,
) -> Option<(Vec<Op>, Vec<Value>)> {
    match instr.op_kind(1) {
        OpKind::Register if is_xmm_register(instr.op_register(1)) => Some((
            Vec::new(),
            (0..4)
                .map(|lane| Value::Reg(packed_dword_lane(instr.op_register(1), lane)))
                .collect(),
        )),
        OpKind::Memory => {
            let mut ops = Vec::with_capacity(4);
            let mut values = Vec::with_capacity(4);
            for lane in 0..4 {
                let temporary = VReg::Temp(first_temp + lane as u32);
                let mut addr = mem_op_of(instr);
                addr.disp = addr.disp.saturating_add((lane * 4) as i64);
                addr.size = 4;
                ops.push(Op::Load {
                    dst: temporary.clone(),
                    addr,
                });
                values.push(Value::Reg(temporary));
            }
            Some((ops, values))
        }
        _ => None,
    }
}

/// Lift PANDN's lane-wise `dst = (~dst) & src` semantics.
///
/// This cannot use [`packed_dword_binary_ops`]: unlike ordinary packed binary
/// operations, PANDN complements the old destination before combining it with
/// the source. Snapshot that complemented value in a temporary so the write to
/// each destination lane remains explicit for SSA and the C backend.
fn packed_dword_and_not_ops(instr: &iced_x86::Instruction) -> Vec<Op> {
    if instr.op_count() != 2
        || instr.op_kind(0) != OpKind::Register
        || instr.op_kind(1) != OpKind::Register
        || !is_xmm_register(instr.op_register(0))
        || !is_xmm_register(instr.op_register(1))
    {
        return vec![Op::Unknown {
            mnemonic: "pandn".into(),
        }];
    }
    let mut ops = Vec::with_capacity(8);
    for lane in 0..4 {
        let dst = packed_dword_lane(instr.op_register(0), lane);
        let complemented = VReg::Temp(88 + lane as u32);
        ops.push(Op::Un {
            dst: complemented.clone(),
            op: UnOp::Not,
            src: Value::Reg(dst.clone()),
        });
        ops.push(Op::Bin {
            dst,
            op: BinOp::And,
            lhs: Value::Reg(complemented),
            rhs: Value::Reg(packed_dword_lane(instr.op_register(1), lane)),
        });
    }
    ops
}

fn packed_dword_compare_greater_ops(instr: &iced_x86::Instruction) -> Vec<Op> {
    if instr.op_count() != 2
        || instr.op_kind(0) != OpKind::Register
        || instr.op_kind(1) != OpKind::Register
        || !is_xmm_register(instr.op_register(0))
        || !is_xmm_register(instr.op_register(1))
    {
        return vec![Op::Unknown {
            mnemonic: "pcmpgtd".into(),
        }];
    }
    let mut ops = Vec::with_capacity(8);
    for lane in 0..4 {
        let dst = packed_dword_lane(instr.op_register(0), lane);
        let src = packed_dword_lane(instr.op_register(1), lane);
        let condition = VReg::Temp(80 + lane as u32);
        // dst > src is the signed comparison src < dst. PCMPGTD writes an
        // all-ones mask for true, not the boolean value one.
        ops.push(Op::Cmp {
            dst: condition.clone(),
            op: CmpOp::Slt,
            lhs: Value::Reg(src),
            rhs: Value::Reg(dst.clone()),
        });
        ops.push(Op::Ite {
            dst,
            cond: condition,
            t: Value::Const(-1),
            e: Value::Const(0),
            width: Width::W32,
        });
    }
    ops
}

fn packed_dword_compare_equal_ops(instr: &iced_x86::Instruction) -> Vec<Op> {
    if instr.op_count() != 2
        || instr.op_kind(0) != OpKind::Register
        || !is_xmm_register(instr.op_register(0))
    {
        return vec![Op::Unknown {
            mnemonic: "pcmpeqd".into(),
        }];
    }
    if instr.op_kind(1) == OpKind::Register && instr.op_register(0) == instr.op_register(1) {
        return (0..4)
            .map(|lane| Op::Assign {
                dst: packed_dword_lane(instr.op_register(0), lane),
                src: Value::Const(-1),
            })
            .collect();
    }
    let Some((mut ops, sources)) = packed_dword_sources(instr, 92) else {
        return vec![Op::Unknown {
            mnemonic: "pcmpeqd".into(),
        }];
    };
    for (lane, source) in sources.into_iter().enumerate() {
        let dst = packed_dword_lane(instr.op_register(0), lane);
        let condition = VReg::Temp(96 + lane as u32);
        ops.push(Op::Cmp {
            dst: condition.clone(),
            op: CmpOp::Eq,
            lhs: Value::Reg(dst.clone()),
            rhs: source,
        });
        ops.push(Op::Ite {
            dst,
            cond: condition,
            t: Value::Const(-1),
            e: Value::Const(0),
            width: Width::W32,
        });
    }
    ops
}

fn packed_dword_shuffle_ops(instr: &iced_x86::Instruction) -> Vec<Op> {
    if instr.op_count() != 3
        || instr.op_kind(0) != OpKind::Register
        || instr.op_kind(1) != OpKind::Register
        || instr.op_kind(2) != OpKind::Immediate8
        || !is_xmm_register(instr.op_register(0))
        || !is_xmm_register(instr.op_register(1))
    {
        return vec![Op::Unknown {
            mnemonic: "pshufd".into(),
        }];
    }
    let control = instr.immediate8();
    let mut ops = Vec::with_capacity(8);
    // Snapshot all input lanes first: PSHUFD permits an in-place destination,
    // and sequential assignments must not feed later selections from a lane
    // already overwritten by this same machine instruction.
    for lane in 0..4 {
        ops.push(Op::Assign {
            dst: VReg::Temp(84 + lane as u32),
            src: Value::Reg(packed_dword_lane(instr.op_register(1), lane)),
        });
    }
    for lane in 0..4 {
        let selected = ((control >> (lane * 2)) & 0x3) as u32;
        ops.push(Op::Assign {
            dst: packed_dword_lane(instr.op_register(0), lane),
            src: Value::Reg(VReg::Temp(84 + selected)),
        });
    }
    ops
}

/// Exact one-operand x86 multiply: `hi:lo = accumulator * source`.
///
/// Snapshot both inputs before defining either architectural output. Express the
/// low half with the ordinary width-truncated multiply and the high half as a
/// typed, single-output intrinsic. A multi-output intrinsic cannot currently be
/// renamed by the SSA/value-numbering layer, which is precisely how the magic
/// constant remainder sequences emitted by GCC and Clang lost `rdx`.
fn wide_mul_ops(instr: &iced_x86::Instruction, signed: bool) -> Option<Vec<Op>> {
    if instr.op_count() != 1 {
        return None;
    }
    let width = operand_width(instr, 0);
    let (lo_name, hi_name) = match width.bits() {
        64 => ("rax", "rdx"),
        32 => ("eax", "edx"),
        16 => ("ax", "dx"),
        _ => return None,
    };
    let mut ops = Vec::new();
    let source = cmp_operand_as_value(instr, 0, VReg::Temp(59), &mut ops)?;
    ops.extend([
        Op::Assign {
            dst: VReg::Temp(60),
            src: Value::Reg(VReg::phys(lo_name)),
        },
        Op::Assign {
            dst: VReg::Temp(61),
            src: source,
        },
        Op::Bin {
            dst: VReg::phys(lo_name),
            op: BinOp::Mul,
            lhs: Value::Reg(VReg::Temp(60)),
            rhs: Value::Reg(VReg::Temp(61)),
        },
        Op::Intrinsic {
            name: format!(
                "x86.{}mul_hi.{}",
                if signed { "s" } else { "u" },
                width.bits()
            ),
            ins: vec![Value::Reg(VReg::Temp(60)), Value::Reg(VReg::Temp(61))],
            outs: vec![(VReg::phys(hi_name), width)],
            reads_mem: false,
            writes_mem: false,
        },
    ]);
    append_undef_flags(
        &mut ops,
        &[Flag::C, Flag::O],
        "x86 wide multiply defines CF/OF from whether the high half extends the low half",
    );
    append_undef_flags(
        &mut ops,
        &[Flag::Z, Flag::S, Flag::P, Flag::A],
        "x86 wide multiply leaves ZF/SF/PF/AF architecturally undefined",
    );
    Some(ops)
}

/// Exact x86 wide division with independently renameable quotient/remainder.
fn wide_div_ops(instr: &iced_x86::Instruction, signed: bool) -> Option<Vec<Op>> {
    if instr.op_count() != 1 {
        return None;
    }
    let width = operand_width(instr, 0);
    let (lo_name, hi_name) = match width.bits() {
        64 => ("rax", "rdx"),
        32 => ("eax", "edx"),
        16 => ("ax", "dx"),
        _ => return None,
    };
    let mut ops = Vec::new();
    let divisor = cmp_operand_as_value(instr, 0, VReg::Temp(69), &mut ops)?;
    ops.extend([
        Op::Assign {
            dst: VReg::Temp(70),
            src: Value::Reg(VReg::phys(hi_name)),
        },
        Op::Assign {
            dst: VReg::Temp(71),
            src: Value::Reg(VReg::phys(lo_name)),
        },
        Op::Assign {
            dst: VReg::Temp(72),
            src: divisor,
        },
    ]);
    let kind = if signed { "sdiv" } else { "udiv" };
    let inputs = vec![
        Value::Reg(VReg::Temp(70)),
        Value::Reg(VReg::Temp(71)),
        Value::Reg(VReg::Temp(72)),
    ];
    ops.extend([
        Op::Intrinsic {
            name: format!("x86.{kind}_quot.{}", width.bits()),
            ins: inputs.clone(),
            outs: vec![(VReg::phys(lo_name), width)],
            reads_mem: false,
            writes_mem: false,
        },
        Op::Intrinsic {
            name: format!("x86.{kind}_rem.{}", width.bits()),
            ins: inputs,
            outs: vec![(VReg::phys(hi_name), width)],
            reads_mem: false,
            writes_mem: false,
        },
    ]);
    append_undef_flags(
        &mut ops,
        &[Flag::C, Flag::O, Flag::Z, Flag::S, Flag::P, Flag::A],
        if signed {
            "x86 IDIV leaves arithmetic flags architecturally undefined"
        } else {
            "x86 DIV leaves arithmetic flags architecturally undefined"
        },
    );
    Some(ops)
}

fn movd_ops(instr: &iced_x86::Instruction, bits: u32) -> Vec<Op> {
    if instr.op_count() != 2 {
        return vec![Op::Unknown {
            mnemonic: "movd".into(),
        }];
    }
    match (instr.op_kind(0), instr.op_kind(1)) {
        (OpKind::Register, OpKind::Register) => {
            let dst = instr.op_register(0);
            let src = instr.op_register(1);
            let dst_name = reg_name(dst);
            let src_name = reg_name(src);
            if dst_name.starts_with("xmm") {
                let mut ops = vec![Op::Assign {
                    dst: packed_dword_lane(dst, 0),
                    src: Value::Reg(VReg::phys(src_name)),
                }];
                ops.extend((1..4).map(|lane| Op::Assign {
                    dst: packed_dword_lane(dst, lane),
                    src: Value::Const(0),
                }));
                ops
            } else if src_name.starts_with("xmm") {
                let src = Value::Reg(packed_dword_lane(src, 0));
                if bits == 64 && zero_extending_gp_view(&dst_name, bits).is_some() {
                    vec![Op::ZExt {
                        dst: VReg::phys(dst_name),
                        src,
                        from: Width::W32,
                        to: Width::W64,
                    }]
                } else {
                    vec![Op::Assign {
                        dst: VReg::phys(dst_name),
                        src,
                    }]
                }
            } else {
                vec![Op::Unknown {
                    mnemonic: "movd".into(),
                }]
            }
        }
        (OpKind::Register, OpKind::Memory) if is_xmm_register(instr.op_register(0)) => {
            let dst = instr.op_register(0);
            let mut addr = mem_op_of(instr);
            addr.size = 4;
            let mut ops = vec![Op::Load {
                dst: packed_dword_lane(dst, 0),
                addr,
            }];
            ops.extend((1..4).map(|lane| Op::Assign {
                dst: packed_dword_lane(dst, lane),
                src: Value::Const(0),
            }));
            ops
        }
        (OpKind::Memory, OpKind::Register) if is_xmm_register(instr.op_register(1)) => {
            let mut addr = mem_op_of(instr);
            addr.size = 4;
            vec![Op::Store {
                addr,
                src: Value::Reg(packed_dword_lane(instr.op_register(1), 0)),
            }]
        }
        _ => vec![Op::Unknown {
            mnemonic: "movd".into(),
        }],
    }
}

/// Lift a single iced instruction into zero or more LLIR ops.
fn lift_one(instr: &iced_x86::Instruction, bits: u32) -> Vec<Op> {
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
                    // A partial (8-/16-bit, low or high-byte) GP write preserves
                    // the parent's other bits; a plain Assign would drop them and
                    // later `eax`/`rax` reads would see a stale value (e.g. gcc's
                    // low-byte-clear `mov $0, %al`).
                    if let Some(v) = partial_gp_view(&dst_name) {
                        return partial_write_ops(v, src);
                    }
                    if zero_extending_gp_view(&dst_name, bits).is_some()
                        && !matches!(src, Value::Const(_))
                    {
                        return vec![Op::ZExt {
                            dst: VReg::phys(dst_name),
                            src,
                            from: Width::W32,
                            to: Width::W64,
                        }];
                    }
                    let src = const_written_through_view(&dst_name, src, bits);
                    vec![Op::Assign {
                        dst: VReg::phys(dst_name),
                        src,
                    }]
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
                    append_undef_flags(
                        &mut ops,
                        &[Flag::C, Flag::O],
                        "x86 IMUL defines CF/OF, but product truncation overflow is not modelled",
                    );
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
        // bt reg, imm/reg: CF = (reg >> (offset & (w-1))) & 1. (bts/btr/btc,
        // which also modify the bit, and memory forms are not modelled yet.)
        Mnemonic::Bt => {
            if instr.op_count() == 2 && instr.op_kind(0) == OpKind::Register {
                let r_name = reg_name(instr.op_register(0));
                let w = phys_reg_width(&r_name).unwrap_or(Width::W64);
                let wmask = (w.bits() as i64) - 1;
                if let Some(raw_bit) = value_of_operand(instr, 1) {
                    let r = VReg::phys(r_name);
                    let mut ops = Vec::new();
                    let bit = match raw_bit {
                        Value::Const(c) => Value::Const(c & wmask),
                        other => {
                            let t0 = VReg::Temp(0);
                            ops.push(Op::Bin {
                                dst: t0.clone(),
                                op: BinOp::And,
                                lhs: other,
                                rhs: Value::Const(wmask),
                            });
                            Value::Reg(t0)
                        }
                    };
                    let t1 = VReg::Temp(1);
                    ops.push(Op::Bin {
                        dst: t1.clone(),
                        op: BinOp::Shr,
                        lhs: Value::Reg(r),
                        rhs: bit,
                    });
                    let t2 = VReg::Temp(2);
                    ops.push(Op::Bin {
                        dst: t2.clone(),
                        op: BinOp::And,
                        lhs: Value::Reg(t1),
                        rhs: Value::Const(1),
                    });
                    ops.push(Op::Assign {
                        dst: VReg::Flag(Flag::C),
                        src: Value::Reg(t2),
                    });
                    append_undef_flags(
                        &mut ops,
                        &[Flag::O, Flag::Z, Flag::S, Flag::P, Flag::A],
                        "x86 BT leaves OF/ZF/SF/PF/AF architecturally undefined",
                    );
                    return ops;
                }
            }
            vec![Op::Unknown {
                mnemonic: "bt".into(),
            }]
        }
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
                ops.push(Op::Assign {
                    dst,
                    src: Value::Reg(tmp),
                });
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
        Mnemonic::Movsd => {
            if instr.code() == Code::Movsd_m32_m32 {
                string_movs_ops(4, bits)
            } else {
                scalar_move_ops(instr, 8, "movsd")
            }
        }
        Mnemonic::Addss => scalar_float_binary_ops(instr, Width::W32, "addss"),
        Mnemonic::Subss => scalar_float_binary_ops(instr, Width::W32, "subss"),
        Mnemonic::Mulss => scalar_float_binary_ops(instr, Width::W32, "mulss"),
        Mnemonic::Divss => scalar_float_binary_ops(instr, Width::W32, "divss"),
        Mnemonic::Addsd => scalar_float_binary_ops(instr, Width::W64, "addsd"),
        Mnemonic::Subsd => scalar_float_binary_ops(instr, Width::W64, "subsd"),
        Mnemonic::Mulsd => scalar_float_binary_ops(instr, Width::W64, "mulsd"),
        Mnemonic::Divsd => scalar_float_binary_ops(instr, Width::W64, "divsd"),
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
                let r = VReg::phys(reg_name(instr.op_register(0)));
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
        Mnemonic::Movd => movd_ops(instr, bits),
        Mnemonic::Movq => packed_qword_move_ops(instr),
        Mnemonic::Pextrw => packed_word_extract_ops(instr),
        Mnemonic::Xorps => xorps_ops(instr),
        Mnemonic::Andps => packed_dword_binary_ops(instr, BinOp::And),
        Mnemonic::Shufps => packed_float_shuffle_ops(instr),
        Mnemonic::Movmskps => packed_float_sign_mask_ops(instr),
        Mnemonic::Push => push_ops(instr, bits),
        Mnemonic::Pop => pop_ops(instr, bits),
        Mnemonic::Stosb | Mnemonic::Stosw | Mnemonic::Stosd | Mnemonic::Stosq => {
            stos_ops(instr, mnem, bits)
        }
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
            OpKind::Memory => vec![Op::Call {
                // Indirect call through memory: we surface it as Indirect
                // with the memory operand recovered into a temp.
                target: CallTarget::Indirect(Value::Addr(instr.memory_displacement64())),
                effects: None,
            }],
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
    let mut out = Vec::new();
    let mut decoder = Decoder::new(bits, bytes, DecoderOptions::NONE);
    decoder.set_ip(start_va);
    while decoder.can_decode() {
        let instr = decoder.decode();
        if instr.is_invalid() {
            break;
        }
        let va = instr.ip();
        for op in lift_one(&instr, bits) {
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
    // The flags architecture (docs/design/x86-flags.md).
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
            ("bt", &[0x0f, 0xba, 0xe0, 0x00], &all),
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
        match &ops[1].op {
            Op::Bin {
                op: BinOp::Mul,
                rhs: Value::Const(3),
                ..
            } => {}
            other => panic!("expected a multiply by 3, got {other:?}"),
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

    /// The `cl`-count form shifts by a value that is only known at run time and
    /// whose zero case must leave the flags alone. That is not one expression,
    /// so it stays unlifted rather than becoming a wrong one.
    #[test]
    fn a_variable_count_double_shift_is_not_guessed() {
        // 0f ad d0 -> shrd eax, edx, cl
        let ops: Vec<Op> = lift_bytes(&[0x0f, 0xad, 0xd0], 0x1000, 32)
            .into_iter()
            .map(|i| i.op)
            .collect();
        assert!(
            ops.iter()
                .all(|op| matches!(op, Op::Unknown { mnemonic } if mnemonic == "shrd")),
            "got: {ops:#?}"
        );
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

    #[test]
    fn movsd_scalar_reg_reg_lifts_to_assign() {
        let ops = lift64(&[0xf2, 0x0f, 0x10, 0xc1]);
        assert_eq!(ops.len(), 1, "got: {ops:#?}");
        assert!(matches!(
            &ops[0].op,
            Op::Assign {
                dst,
                src: Value::Reg(src),
            } if *dst == VReg::phys("xmm0") && *src == VReg::phys("xmm1")
        ));
    }

    #[test]
    fn movsd_string_lifts_to_copy_and_pointer_advance() {
        let ops = lift64(&[0xa5]);
        assert_eq!(ops.len(), 4, "got: {ops:#?}");
        assert!(matches!(
            &ops[0].op,
            Op::Load {
                dst: VReg::Temp(0),
                addr: MemOp {
                    base: Some(src),
                    size: 4,
                    ..
                },
            } if *src == VReg::phys("rsi")
        ));
        assert!(matches!(
            &ops[1].op,
            Op::Store {
                addr: MemOp {
                    base: Some(dst),
                    size: 4,
                    ..
                },
                src: Value::Reg(VReg::Temp(0)),
            } if *dst == VReg::phys("rdi")
        ));
        assert!(matches!(
            &ops[2].op,
            Op::Bin {
                dst,
                op: BinOp::Add,
                rhs: Value::Const(4),
                ..
            } if *dst == VReg::phys("rsi")
        ));
        assert!(matches!(
            &ops[3].op,
            Op::Bin {
                dst,
                op: BinOp::Add,
                rhs: Value::Const(4),
                ..
            } if *dst == VReg::phys("rdi")
        ));
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
        let ops = lift64(&[0x0f, 0x28, 0xc1]);
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
        let ops = lift64(&[0xf3, 0x0f, 0x6f, 0x07]);
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
        let xmm_ops = lift64(&[0x66, 0x0f, 0x72, 0xf2, 0x20]); // pslld xmm2,32
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

        let mmx_ops = lift64(&[0x0f, 0x72, 0xf2, 0x05]); // pslld mm2,5
        assert_eq!(mmx_ops.len(), 1, "got: {mmx_ops:#?}");
        assert!(matches!(
            &mmx_ops[0].op,
            Op::Unknown { mnemonic } if mnemonic == "pslld"
        ));
    }

    #[test]
    fn packed_dword_logical_right_shift_preserves_all_lanes_and_zeroes_large_counts() {
        let ops = lift64(&[0x66, 0x0f, 0x72, 0xd4, 0x1f]); // psrld xmm4,31
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

        let large = lift64(&[0x66, 0x0f, 0x72, 0xd4, 0x20]); // psrld xmm4,32
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
        let ops = lift64(&[0x66, 0x0f, 0x76, 0xe4]); // pcmpeqd xmm4,xmm4
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
        let ops = lift64(&[
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
        let ops = lift64(&[
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
        assert!(ops.iter().any(|instruction| matches!(
            &instruction.op,
            Op::Concat {
                dst: VReg::Phys(dst),
                hi: Value::Reg(VReg::Phys(hi)),
                lo: Value::Reg(VReg::Phys(lo)),
            } if dst == "rax" && hi == "xmm0_d1" && lo == "xmm0_d0"
        )));
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
}
