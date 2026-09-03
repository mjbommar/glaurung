//! x86 stack and string-operation lowering: `push`/`pop` and the `stos`/`movs`
//! primitives.
//!
//! These share one property that separates them from the rest of the lifter:
//! a single machine instruction is not one LLIR op but a *sequence* with an
//! implicit pointer side effect. `push` is an rsp-adjust plus a store, `pop` a
//! load plus an rsp-adjust, and the string ops step RDI/RSI by the operand
//! width in whichever direction DF selects. Keeping them together keeps that
//! stack-and-pointer discipline in one place.
//!
//! `rep stos` and `rep movs` are the two cases that do not decompose into
//! ordinary ops: they emit a typed `memory.fill` / `memory.copy` intrinsic for
//! the AST lowering to recognise, and then re-state the architectural
//! RDI/RSI/RCX updates as ordinary LLIR so SSA never needs a multi-output
//! intrinsic exception.
//!
//! The accumulator-name helper these ops need deliberately stays in the parent:
//! `cmpxchg` lowering uses it too, and it is reachable here as
//! `super::accumulator_name_for_width` without widening anything.

use iced_x86::{Mnemonic, OpKind};

use crate::ir::types::*;

use super::{accumulator_name_for_width, mem_op_of, reg_name};

fn stos_width(mnem: Mnemonic) -> Option<u8> {
    match mnem {
        Mnemonic::Stosb => Some(1),
        Mnemonic::Stosw => Some(2),
        Mnemonic::Stosd => Some(4),
        Mnemonic::Stosq => Some(8),
        _ => None,
    }
}

pub(super) fn push_ops(instr: &iced_x86::Instruction, bits: u32) -> Vec<Op> {
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

pub(super) fn pop_ops(instr: &iced_x86::Instruction, bits: u32) -> Vec<Op> {
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

pub(super) fn push_flags_ops(bits: u32) -> Vec<Op> {
    let sp = VReg::phys(if bits == 64 { "rsp" } else { "esp" });
    let width = if bits == 64 { Width::W64 } else { Width::W32 };
    let bytes = width.bytes() as u8;
    let packed = VReg::Temp(12);
    vec![
        // The IR represents the status bits listed here but not the complete
        // architectural flags word. Keep that full word unknown-valued while
        // exposing every represented input to dataflow.
        Op::Intrinsic {
            name: "x86.pack_rflags".into(),
            ins: [
                Flag::C,
                Flag::P,
                Flag::A,
                Flag::Z,
                Flag::S,
                Flag::D,
                Flag::O,
            ]
            .into_iter()
            .map(|flag| Value::Reg(VReg::Flag(flag)))
            .collect(),
            outs: vec![(packed.clone(), width)],
            reads_mem: false,
            writes_mem: false,
        },
        Op::Bin {
            dst: sp.clone(),
            op: BinOp::Sub,
            lhs: Value::Reg(sp.clone()),
            rhs: Value::Const(i64::from(bytes)),
        },
        Op::Store {
            addr: MemOp {
                base: Some(sp),
                index: None,
                scale: 0,
                disp: 0,
                size: bytes,
                segment: None,
                endian: Endian::Little,
            },
            src: Value::Reg(packed),
        },
    ]
}

pub(super) fn pop_flags_ops(bits: u32) -> Vec<Op> {
    let sp = VReg::phys(if bits == 64 { "rsp" } else { "esp" });
    let bytes = if bits == 64 { 8 } else { 4 };
    let packed = VReg::Temp(12);
    let mut ops = vec![Op::Load {
        dst: packed.clone(),
        addr: MemOp {
            base: Some(sp.clone()),
            index: None,
            scale: 0,
            disp: 0,
            size: bytes,
            segment: None,
            endian: Endian::Little,
        },
    }];
    for (flag, bit) in [
        (Flag::C, 0),
        (Flag::P, 2),
        (Flag::A, 4),
        (Flag::Z, 6),
        (Flag::S, 7),
        (Flag::D, 10),
        (Flag::O, 11),
    ] {
        ops.push(Op::Extract {
            dst: VReg::Flag(flag),
            src: Value::Reg(packed.clone()),
            hi: bit + 1,
            lo: bit,
        });
    }
    ops.push(Op::Bin {
        dst: sp.clone(),
        op: BinOp::Add,
        lhs: Value::Reg(sp),
        rhs: Value::Const(i64::from(bytes)),
    });
    ops
}

pub(super) fn stos_ops(instr: &iced_x86::Instruction, mnem: Mnemonic, bits: u32) -> Vec<Op> {
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

/// The element width of a string MOVS, or `None` for anything that is not one.
///
/// `MOVSD` is the awkward member: `iced_x86` gives the dword string move and
/// the SSE scalar double move the SAME mnemonic, and only the `Code` separates
/// them. Every other member has a mnemonic of its own.
pub(super) fn movs_width(instr: &iced_x86::Instruction, mnem: Mnemonic) -> Option<u8> {
    match mnem {
        Mnemonic::Movsb => Some(1),
        Mnemonic::Movsw => Some(2),
        Mnemonic::Movsd if instr.code() == iced_x86::Code::Movsd_m32_m32 => Some(4),
        Mnemonic::Movsq => Some(8),
        _ => None,
    }
}

/// `movs` — the string move, in both its single-step and `rep` forms.
///
/// The instruction copies one element from `[rsi]` to `[rdi]` and then steps
/// BOTH pointers by the element width; under `rep` it does that `rcx` times and
/// leaves `rcx` zero. Those pointer updates are the whole reason this needed an
/// arm at all. Left unmodelled, `movsb` and `movsq` were the third and fourth
/// largest entries in `lift_x86`'s silent-register-write census — 242 and 134
/// occurrences over the committed amd64 corpus — and an `Op::Unknown` declares
/// no register write, so register dataflow concluded RDI and RSI were never
/// touched. Every glibc `memcpy` built on `rep movsq` therefore recovered with
/// its source and destination pointers still holding their pre-loop values.
///
/// **This is deliberately not the shape `stos` uses.** `stos*` has EMPTY `outs`
/// on its `memory.fill` intrinsic because its only value write is to memory;
/// its RDI/RCX updates are the ordinary LLIR beside it. `movs` needs the same
/// treatment for its memory effect and, additionally, an honest RSI. Inheriting
/// `stos`' empty `outs` without the pointer arithmetic would be the exact bug
/// this arm exists to close.
///
/// **The direction flag is honoured, not assumed.** The sign of the step is
/// `DF`, which this emits as an `Op::Ite` on `VReg::Flag(Flag::D)` — the same
/// spelling `stos_ops` uses. That is a real read, so
/// `lift_function`'s direction-flag seeding materialises the ABI fact that both
/// the SysV and Microsoft conventions require DF clear at a function boundary,
/// and any `cld`/`std` inside the function replaces it through ordinary SSA.
/// Nothing here assumes DF is clear; it assumes only what the ABI already
/// guarantees at the entry block, and an explicit `std` overrides it.
pub(super) fn movs_ops(instr: &iced_x86::Instruction, width: u8, bits: u32) -> Vec<Op> {
    let src_ptr = VReg::phys(if bits == 64 { "rsi" } else { "esi" });
    let dst_ptr = VReg::phys(if bits == 64 { "rdi" } else { "edi" });
    let count = VReg::phys(if bits == 64 { "rcx" } else { "ecx" });
    let pointer_width = if bits == 64 { Width::W64 } else { Width::W32 };
    let element = |base: &VReg| MemOp {
        base: Some(base.clone()),
        index: None,
        scale: 0,
        disp: 0,
        size: width,
        segment: None,
        endian: Endian::Little,
    };

    // `repne movs` is architecturally the same repeat as `rep movs`: MOVS
    // writes no flags, so there is no ZF for REPNE to terminate on and both
    // prefixes decrement RCX to zero. Treating them alike is exact, and it
    // matches what `stos_ops` already does.
    if instr.has_rep_prefix() || instr.has_repne_prefix() {
        let pointer_bytes = if bits == 64 { 8 } else { 4 };
        let destination_cursor = VReg::Temp(0);
        let source_cursor = VReg::Temp(1);
        let remaining = VReg::Temp(2);
        let byte_count = VReg::Temp(3);
        let negative_byte_count = VReg::Temp(4);
        let pointer_delta = VReg::Temp(5);
        return vec![
            Op::Assign {
                dst: destination_cursor.clone(),
                src: Value::Reg(dst_ptr.clone()),
            },
            Op::Assign {
                dst: source_cursor.clone(),
                src: Value::Reg(src_ptr.clone()),
            },
            Op::Assign {
                dst: remaining.clone(),
                src: Value::Reg(count.clone()),
            },
            // One architecture-neutral, typed memory effect over PRIVATE
            // cursors, exactly as `rep stos` does: mutating them in the AST
            // loop cannot overwrite the architectural registers whose
            // post-operation values the ordinary LLIR below states.
            Op::Intrinsic {
                name: format!("memory.copy.{width}.word{pointer_bytes}"),
                ins: vec![
                    Value::Reg(destination_cursor),
                    Value::Reg(source_cursor),
                    Value::Reg(remaining),
                    Value::Reg(VReg::Flag(Flag::D)),
                ],
                outs: Vec::new(),
                reads_mem: true,
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
                dst: dst_ptr.clone(),
                op: BinOp::Add,
                lhs: Value::Reg(dst_ptr),
                rhs: Value::Reg(pointer_delta.clone()),
            },
            Op::Bin {
                dst: src_ptr.clone(),
                op: BinOp::Add,
                lhs: Value::Reg(src_ptr),
                rhs: Value::Reg(pointer_delta),
            },
            Op::Assign {
                dst: count,
                src: Value::Const(0),
            },
        ];
    }

    // The single-step form. It is a different instruction in effect: RCX is not
    // read and not written, and exactly one element moves.
    let element_value = VReg::Temp(0);
    let step = VReg::Temp(1);
    vec![
        Op::Load {
            dst: element_value.clone(),
            addr: element(&src_ptr),
        },
        Op::Store {
            addr: element(&dst_ptr),
            src: Value::Reg(element_value),
        },
        Op::Ite {
            dst: step.clone(),
            cond: VReg::Flag(Flag::D),
            t: Value::Const(-i64::from(width)),
            e: Value::Const(i64::from(width)),
            width: pointer_width,
        },
        Op::Bin {
            dst: src_ptr.clone(),
            op: BinOp::Add,
            lhs: Value::Reg(src_ptr),
            rhs: Value::Reg(step.clone()),
        },
        Op::Bin {
            dst: dst_ptr.clone(),
            op: BinOp::Add,
            lhs: Value::Reg(dst_ptr),
            rhs: Value::Reg(step),
        },
    ]
}
