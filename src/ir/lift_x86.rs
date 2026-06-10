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
//! * `movsd` / `stos*` string ops → representative copy/store + pointer advance
//! * common SSE moves/zeroing (`movsd`, `movaps`, `xorps`) → assign/load/store/bin
//! * `cmp` → [`Op::Cmp`] writing `ZF`/`CF`/`SF`
//! * `test` → [`Op::Cmp`] writing `ZF`/`SF`
//! * `setcc` → [`Op::Assign`] / [`Op::Store`] from the corresponding flag
//! * `cmovcc` → [`Op::CondAssign`]
//! * `push` / `pop` → decomposed into rsp-adjust + load/store
//! * `call` near direct / indirect → [`Op::Call`]
//! * `ret` → [`Op::Return`]
//! * `jmp` near direct → [`Op::Jump`]
//! * `jcc` (je, jne, jl, jg, …) → [`Op::CondJump`] reading the appropriate flag
//! * `lea` with rip-relative memory → [`Op::Assign`] of absolute VA
//!
//! Anything outside this set becomes [`Op::Unknown`] with the source mnemonic.

use iced_x86::{Code, Decoder, DecoderOptions, Mnemonic, OpKind, Register};

use crate::ir::types::*;

fn reg_name(r: Register) -> String {
    format!("{:?}", r).to_ascii_lowercase()
}

fn reg_size(r: Register) -> u8 {
    let s = r.size();
    if s == 0 {
        8
    } else {
        s as u8
    }
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
        disp: instr.memory_displacement64() as i64,
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
        OpKind::Immediate16 | OpKind::Immediate8to16 => {
            Some(Value::Const(instr.immediate16() as i16 as i64))
        }
        OpKind::Immediate32 | OpKind::Immediate8to32 => {
            Some(Value::Const(instr.immediate32() as i32 as i64))
        }
        OpKind::Immediate64 | OpKind::Immediate8to64 | OpKind::Immediate32to64 => {
            Some(Value::Const(instr.immediate64() as i64))
        }
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
        return Some(Value::Reg(VReg::phys(reg_name(instr.op_register(idx)))));
    }
    value_of_operand(instr, idx)
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
struct Condition {
    flag: VReg,
    inverted: bool,
}

fn condition_for_suffix(suffix: &str) -> Option<Condition> {
    let (flag, inverted) = match suffix {
        "e" | "z" => (Flag::Z, false),
        "ne" | "nz" => (Flag::Z, true),
        "b" | "c" | "nae" => (Flag::C, false),
        "ae" | "nb" | "nc" => (Flag::C, true),
        "be" | "na" => (Flag::Ule, false),
        "a" | "nbe" => (Flag::Ule, true),
        "l" | "nge" => (Flag::Slt, false),
        "ge" | "nl" => (Flag::Slt, true),
        "le" | "ng" => (Flag::Sle, false),
        "g" | "nle" => (Flag::Sle, true),
        "s" => (Flag::S, false),
        "ns" => (Flag::S, true),
        "o" => (Flag::O, false),
        "no" => (Flag::O, true),
        "p" | "pe" => (Flag::P, false),
        "np" | "po" => (Flag::P, true),
        _ => return None,
    };
    Some(Condition {
        flag: VReg::Flag(flag),
        inverted,
    })
}

/// Map a conditional-jump mnemonic onto the flag virtual register family that
/// controls the branch. `Op::CondJump` does not yet carry polarity, so negated
/// siblings (Jne, Jae, Jge, ...) intentionally share the positive flag as the
/// existing approximation. `setcc` and `cmovcc` materialize inverted forms
/// explicitly because they produce dataflow values.
fn cond_flag_for(mnem: Mnemonic) -> Option<VReg> {
    condition_suffix(mnem, "j").and_then(|suffix| condition_for_suffix(&suffix).map(|c| c.flag))
}

fn setcc_condition_for(mnem: Mnemonic) -> Option<Condition> {
    condition_suffix(mnem, "set").and_then(|suffix| condition_for_suffix(&suffix))
}

fn cmovcc_condition_for(mnem: Mnemonic) -> Option<Condition> {
    condition_suffix(mnem, "cmov").and_then(|suffix| condition_for_suffix(&suffix))
}

fn div_accumulator_name(instr: &iced_x86::Instruction, bits: u32) -> &'static str {
    let width = match instr.op_kind(0) {
        OpKind::Register => reg_size(instr.op_register(0)),
        OpKind::Memory => instr.memory_size().size() as u8,
        _ => 0,
    };
    match width {
        1 => "al",
        2 => "ax",
        4 => "eax",
        8 => "rax",
        _ if bits == 64 => "rax",
        _ => "eax",
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
        OpKind::Immediate32 | OpKind::Immediate8to32 => {
            Value::Const(instr.immediate32() as i32 as i64)
        }
        OpKind::Immediate64 | OpKind::Immediate8to64 | OpKind::Immediate32to64 => {
            Value::Const(instr.immediate64() as i64)
        }
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
            }]
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
            }]
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

fn stos_ops(mnem: Mnemonic, bits: u32) -> Vec<Op> {
    let Some(width) = stos_width(mnem) else {
        return vec![Op::Unknown {
            mnemonic: format!("{:?}", mnem).to_ascii_lowercase(),
        }];
    };
    let dst = VReg::phys(if bits == 64 { "rdi" } else { "edi" });
    let acc = VReg::phys(accumulator_name_for_width(width, bits));
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
        // Direction-flag-aware repetition is a future mid-IR concern. The
        // common compiler pattern clears DF, so advance once to preserve the
        // observable pointer dataflow without emitting unknown(stos*).
        Op::Bin {
            dst: dst.clone(),
            op: BinOp::Add,
            lhs: Value::Reg(dst),
            rhs: Value::Const(i64::from(width)),
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

fn sbb_ops(instr: &iced_x86::Instruction) -> Vec<Op> {
    if instr.op_count() != 2 {
        return vec![Op::Unknown {
            mnemonic: "sbb".into(),
        }];
    }

    let carry = Value::Reg(VReg::Flag(Flag::C));
    match instr.op_kind(0) {
        OpKind::Register => {
            let dst = VReg::phys(reg_name(instr.op_register(0)));
            let mut ops = Vec::new();
            let Some(rhs) = cmp_operand_as_value(instr, 1, VReg::Temp(0), &mut ops) else {
                return vec![Op::Unknown {
                    mnemonic: "sbb".into(),
                }];
            };
            ops.push(Op::Bin {
                dst: dst.clone(),
                op: BinOp::Sub,
                lhs: Value::Reg(dst.clone()),
                rhs,
            });
            ops.push(Op::Bin {
                dst: dst.clone(),
                op: BinOp::Sub,
                lhs: Value::Reg(dst),
                rhs: carry,
            });
            ops
        }
        OpKind::Memory => {
            let addr = mem_op_of(instr);
            let mut ops = Vec::new();
            let Some(rhs) = cmp_operand_as_value(instr, 1, VReg::Temp(1), &mut ops) else {
                return vec![Op::Unknown {
                    mnemonic: "sbb".into(),
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
            ops.push(Op::Bin {
                dst: tmp.clone(),
                op: BinOp::Sub,
                lhs: Value::Reg(tmp.clone()),
                rhs,
            });
            ops.push(Op::Bin {
                dst: tmp.clone(),
                op: BinOp::Sub,
                lhs: Value::Reg(tmp.clone()),
                rhs: carry,
            });
            ops.push(Op::Store {
                addr,
                src: Value::Reg(tmp),
            });
            ops
        }
        _ => vec![Op::Unknown {
            mnemonic: "sbb".into(),
        }],
    }
}

fn xorps_ops(instr: &iced_x86::Instruction) -> Vec<Op> {
    if instr.op_count() != 2 || instr.op_kind(0) != OpKind::Register {
        return vec![Op::Unknown {
            mnemonic: "xorps".into(),
        }];
    }
    let dst = VReg::phys(reg_name(instr.op_register(0)));
    match instr.op_kind(1) {
        OpKind::Register => {
            let src = VReg::phys(reg_name(instr.op_register(1)));
            if src == dst {
                return vec![Op::Assign {
                    dst,
                    src: Value::Const(0),
                }];
            }
            vec![Op::Bin {
                dst: dst.clone(),
                op: BinOp::Xor,
                lhs: Value::Reg(dst),
                rhs: Value::Reg(src),
            }]
        }
        OpKind::Memory => {
            let tmp = VReg::Temp(0);
            let mut addr = mem_op_of(instr);
            addr.size = 16;
            vec![
                Op::Load {
                    dst: tmp.clone(),
                    addr,
                },
                Op::Bin {
                    dst: dst.clone(),
                    op: BinOp::Xor,
                    lhs: Value::Reg(dst),
                    rhs: Value::Reg(tmp),
                },
            ]
        }
        _ => vec![Op::Unknown {
            mnemonic: "xorps".into(),
        }],
    }
}

fn cmpxchg_ops(instr: &iced_x86::Instruction, bits: u32) -> Vec<Op> {
    if instr.op_count() != 2 || instr.op_kind(1) != OpKind::Register {
        return vec![Op::Unknown {
            mnemonic: "cmpxchg".into(),
        }];
    }

    let src = Value::Reg(VReg::phys(reg_name(instr.op_register(1))));
    let old = VReg::Temp(0);
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
            }]
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
            ops.push(Op::Cmp {
                dst: VReg::Flag(Flag::Z),
                op: CmpOp::Eq,
                lhs: Value::Reg(acc.clone()),
                rhs: Value::Reg(old.clone()),
            });
            ops.push(Op::CondAssign {
                dst,
                cond: VReg::Flag(Flag::Z),
                src,
            });
        }
        OpKind::Memory => {
            let addr = mem_op_of(instr);
            let new_value = VReg::Temp(1);
            ops.push(Op::Load {
                dst: old.clone(),
                addr: addr.clone(),
            });
            ops.push(Op::Cmp {
                dst: VReg::Flag(Flag::Z),
                op: CmpOp::Eq,
                lhs: Value::Reg(acc.clone()),
                rhs: Value::Reg(old.clone()),
            });
            ops.push(Op::Assign {
                dst: new_value.clone(),
                src: Value::Reg(old.clone()),
            });
            ops.push(Op::CondAssign {
                dst: new_value.clone(),
                cond: VReg::Flag(Flag::Z),
                src,
            });
            ops.push(Op::Store {
                addr,
                src: Value::Reg(new_value),
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
    ops.push(Op::CondAssign {
        dst: acc,
        cond: not_equal,
        src: Value::Reg(old),
    });
    ops
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
                    let dst = VReg::phys(reg_name(instr.op_register(0)));
                    if let Some(src) = value_of_operand(instr, 1) {
                        return vec![emit_bin(dst, op, src)];
                    } else if instr.op_kind(1) == OpKind::Memory {
                        // dst_reg = op(dst_reg, load([mem]))
                        // We introduce a temp to keep three-address form.
                        let tmp = VReg::Temp(0);
                        return vec![
                            Op::Load {
                                dst: tmp.clone(),
                                addr: mem_op_of(instr),
                            },
                            emit_bin(dst, op, Value::Reg(tmp)),
                        ];
                    }
                }
                OpKind::Memory => {
                    // mem op= src (reg or imm): load-modify-store.
                    let addr = mem_op_of(instr);
                    if let Some(src) = value_of_operand(instr, 1) {
                        let tmp = VReg::Temp(0);
                        return vec![
                            Op::Load {
                                dst: tmp.clone(),
                                addr: addr.clone(),
                            },
                            Op::Bin {
                                dst: tmp.clone(),
                                op,
                                lhs: Value::Reg(tmp.clone()),
                                rhs: src,
                            },
                            Op::Store {
                                addr,
                                src: Value::Reg(tmp),
                            },
                        ];
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
                (OpKind::Register, OpKind::Memory) => vec![Op::Load {
                    dst: VReg::phys(reg_name(instr.op_register(0))),
                    addr: mem_op_of(instr),
                }],
                (OpKind::Memory, _) => {
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
                    if let Some(src) = value_of_operand(instr, 1) {
                        vec![Op::Assign {
                            dst: VReg::phys(reg_name(instr.op_register(0))),
                            src,
                        }]
                    } else {
                        vec![Op::Unknown {
                            mnemonic: "mov".into(),
                        }]
                    }
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
                    let src = Value::Reg(VReg::phys(src_name));
                    if signed {
                        vec![Op::SExt { dst, src, from, to }]
                    } else {
                        vec![Op::ZExt { dst, src, from, to }]
                    }
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
        Mnemonic::Cdqe => vec![Op::Assign {
            dst: VReg::phys("rax"),
            src: Value::Reg(VReg::phys("eax")),
        }],
        // 3-operand imul: `imul dst, src, imm` → dst = src * imm. (The 2-operand
        // form is handled by the binary-op path above.)
        Mnemonic::Imul => {
            if instr.op_count() == 3 && instr.op_kind(0) == OpKind::Register {
                let dst = VReg::phys(reg_name(instr.op_register(0)));
                if let (Some(lhs), Some(rhs)) =
                    (value_of_operand(instr, 1), value_of_operand(instr, 2))
                {
                    return vec![Op::Bin {
                        dst,
                        op: BinOp::Mul,
                        lhs,
                        rhs,
                    }];
                }
            }
            vec![Op::Unknown {
                mnemonic: "imul".into(),
            }]
        }
        // Rotate by an immediate: `rol`/`ror r, imm` lifts to
        // `(x << n) | (x >> (w-n))` (the consuming `or`'s width comes from the
        // physical dst, so the temps need no explicit width). Rotate-by-cl and
        // memory forms remain unmodelled for now.
        Mnemonic::Rol | Mnemonic::Ror => {
            if instr.op_count() == 2 && instr.op_kind(0) == OpKind::Register {
                if let Some(Value::Const(cnt)) = value_of_operand(instr, 1) {
                    let dst_name = reg_name(instr.op_register(0));
                    let w = phys_reg_width(&dst_name).unwrap_or(Width::W64).bits() as i64;
                    let n = ((cnt % w) + w) % w;
                    if n == 0 {
                        return vec![Op::Nop];
                    }
                    let dst = VReg::phys(dst_name);
                    let (t1, t2) = (VReg::Temp(0), VReg::Temp(1));
                    let (a_op, a_sh, b_op, b_sh) = if matches!(mnem, Mnemonic::Rol) {
                        (BinOp::Shl, n, BinOp::Shr, w - n)
                    } else {
                        (BinOp::Shr, n, BinOp::Shl, w - n)
                    };
                    return vec![
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
                            dst,
                            op: BinOp::Or,
                            lhs: Value::Reg(t1),
                            rhs: Value::Reg(t2),
                        },
                    ];
                }
            }
            vec![Op::Unknown {
                mnemonic: format!("{:?}", mnem).to_ascii_lowercase(),
            }]
        }
        // mul reg: unsigned multiply, hi:lo = accumulator * src. Typed intrinsic
        // executed by a two-output helper. (8-bit and memory forms deferred.)
        Mnemonic::Mul => {
            if instr.op_count() == 1 && instr.op_kind(0) == OpKind::Register {
                let src_name = reg_name(instr.op_register(0));
                let w = phys_reg_width(&src_name).unwrap_or(Width::W64);
                let acc = match w.bits() {
                    64 => Some(("rax", "rdx")),
                    32 => Some(("eax", "edx")),
                    16 => Some(("ax", "dx")),
                    _ => None,
                };
                if let Some((lo, hi)) = acc {
                    return vec![Op::Intrinsic {
                        name: "mul".into(),
                        ins: vec![Value::Reg(VReg::phys(lo)), Value::Reg(VReg::phys(src_name))],
                        outs: vec![(VReg::phys(lo), w), (VReg::phys(hi), w)],
                        reads_mem: false,
                        writes_mem: false,
                    }];
                }
            }
            vec![Op::Unknown {
                mnemonic: "mul".into(),
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
                let disp = instr.memory_displacement64() as i64;

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
        // 128-bit SSE/SSE2 moves. We treat them as plain Load/Store/Assign
        // with a 16-byte access size so the operand pipeline works. We lose
        // the xmm-register distinction in favour of using capstone-reported
        // register names verbatim (iced gives us `xmm0`, etc.).
        Mnemonic::Movaps | Mnemonic::Movups | Mnemonic::Movdqa | Mnemonic::Movdqu => {
            if instr.op_count() != 2 {
                return vec![Op::Unknown {
                    mnemonic: format!("{:?}", mnem).to_ascii_lowercase(),
                }];
            }
            match (instr.op_kind(0), instr.op_kind(1)) {
                (OpKind::Register, OpKind::Memory) => {
                    // mov* xmmN, [mem]  — load 16 bytes.
                    let dst = VReg::phys(reg_name(instr.op_register(0)));
                    let mut addr = mem_op_of(instr);
                    addr.size = 16;
                    return vec![Op::Load { dst, addr }];
                }
                (OpKind::Memory, OpKind::Register) => {
                    let mut addr = mem_op_of(instr);
                    addr.size = 16;
                    return vec![Op::Store {
                        addr,
                        src: Value::Reg(VReg::phys(reg_name(instr.op_register(1)))),
                    }];
                }
                (OpKind::Register, OpKind::Register) => {
                    return vec![Op::Assign {
                        dst: VReg::phys(reg_name(instr.op_register(0))),
                        src: Value::Reg(VReg::phys(reg_name(instr.op_register(1)))),
                    }];
                }
                _ => {
                    return vec![Op::Unknown {
                        mnemonic: format!("{:?}", mnem).to_ascii_lowercase(),
                    }];
                }
            }
        }
        Mnemonic::Movsd => {
            if instr.code() == Code::Movsd_m32_m32 {
                string_movs_ops(4, bits)
            } else {
                scalar_move_ops(instr, 8, "movsd")
            }
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
                // A machine `cmp` updates ZF, SF, CF, OF, AF, PF, but jcc
                // semantics ultimately depend on five composite conditions:
                // equal (ZF), unsigned-less (CF), signed-less (SF^OF),
                // unsigned-less-or-equal (CF|ZF), signed-less-or-equal
                // (ZF|SF^OF), and raw sign (SF). We write each directly as
                // an LLIR flag so conditional
                // branches can read a single flag with faithful semantics.
                // The raw sign is derived by materialising `lhs - rhs` into
                // a temp and comparing to zero.
                let sub_tmp = VReg::Temp(0);
                let mut ops = preamble;
                ops.extend(vec![
                    Op::Cmp {
                        dst: VReg::Flag(Flag::Z),
                        op: CmpOp::Eq,
                        lhs: lhs.clone(),
                        rhs: rhs.clone(),
                    },
                    Op::Cmp {
                        dst: VReg::Flag(Flag::C),
                        op: CmpOp::Ult,
                        lhs: lhs.clone(),
                        rhs: rhs.clone(),
                    },
                    Op::Cmp {
                        dst: VReg::Flag(Flag::Ule),
                        op: CmpOp::Ule,
                        lhs: lhs.clone(),
                        rhs: rhs.clone(),
                    },
                    Op::Cmp {
                        dst: VReg::Flag(Flag::Slt),
                        op: CmpOp::Slt,
                        lhs: lhs.clone(),
                        rhs: rhs.clone(),
                    },
                    Op::Cmp {
                        dst: VReg::Flag(Flag::Sle),
                        op: CmpOp::Sle,
                        lhs: lhs.clone(),
                        rhs: rhs.clone(),
                    },
                    Op::Bin {
                        dst: sub_tmp.clone(),
                        op: BinOp::Sub,
                        lhs,
                        rhs,
                    },
                    Op::Cmp {
                        dst: VReg::Flag(Flag::S),
                        op: CmpOp::Slt,
                        lhs: Value::Reg(sub_tmp),
                        rhs: Value::Const(0),
                    },
                ]);
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
                // test sets ZF = ((lhs & rhs) == 0) and SF = msb(lhs & rhs).
                // Materialise the AND into a temp and emit the two flag
                // writes against it. `Flag::Slt` is also written so that the
                // Jl/Jge siblings (rare after test, but emitted by some
                // compilers) read something reasonable instead of a stale
                // flag — it coincides with the sign bit here because the
                // second comparand is 0.
                let tmp = VReg::Temp(0);
                let mut ops = preamble;
                ops.extend(vec![
                    Op::Bin {
                        dst: tmp.clone(),
                        op: BinOp::And,
                        lhs,
                        rhs,
                    },
                    Op::Cmp {
                        dst: VReg::Flag(Flag::Z),
                        op: CmpOp::Eq,
                        lhs: Value::Reg(tmp.clone()),
                        rhs: Value::Const(0),
                    },
                    Op::Cmp {
                        dst: VReg::Flag(Flag::S),
                        op: CmpOp::Slt,
                        lhs: Value::Reg(tmp),
                        rhs: Value::Const(0),
                    },
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
                match instr.op_kind(0) {
                    OpKind::Register => {
                        let dst = VReg::phys(reg_name(instr.op_register(0)));
                        if condition.inverted {
                            return vec![Op::Cmp {
                                dst,
                                op: CmpOp::Eq,
                                lhs: Value::Reg(condition.flag),
                                rhs: Value::Const(0),
                            }];
                        }
                        return vec![Op::Assign {
                            dst,
                            src: Value::Reg(condition.flag),
                        }];
                    }
                    OpKind::Memory => {
                        if condition.inverted {
                            let tmp = VReg::Temp(0);
                            return vec![
                                Op::Cmp {
                                    dst: tmp.clone(),
                                    op: CmpOp::Eq,
                                    lhs: Value::Reg(condition.flag),
                                    rhs: Value::Const(0),
                                },
                                Op::Store {
                                    addr: mem_op_of(instr),
                                    src: Value::Reg(tmp),
                                },
                            ];
                        }
                        return vec![Op::Store {
                            addr: mem_op_of(instr),
                            src: Value::Reg(condition.flag),
                        }];
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
                let mut ops = Vec::new();
                let cond = if condition.inverted {
                    let tmp = VReg::Temp(1);
                    ops.push(Op::Cmp {
                        dst: tmp.clone(),
                        op: CmpOp::Eq,
                        lhs: Value::Reg(condition.flag),
                        rhs: Value::Const(0),
                    });
                    tmp
                } else {
                    condition.flag
                };
                match instr.op_kind(1) {
                    OpKind::Register => {
                        ops.push(Op::CondAssign {
                            dst,
                            cond,
                            src: Value::Reg(VReg::phys(reg_name(instr.op_register(1)))),
                        });
                        return ops;
                    }
                    OpKind::Memory => {
                        let tmp = VReg::Temp(0);
                        ops.push(Op::Load {
                            dst: tmp.clone(),
                            addr: mem_op_of(instr),
                        });
                        ops.push(Op::CondAssign {
                            dst,
                            cond,
                            src: Value::Reg(tmp),
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
                return vec![Op::Un {
                    dst: r.clone(),
                    op: UnOp::Neg,
                    src: Value::Reg(r),
                }];
            }
            vec![Op::Unknown {
                mnemonic: "neg".into(),
            }]
        }
        Mnemonic::Div | Mnemonic::Idiv => {
            if instr.op_count() == 1 {
                let acc = VReg::phys(div_accumulator_name(instr, bits));
                let mut ops = Vec::new();
                let divisor = match instr.op_kind(0) {
                    OpKind::Register => Value::Reg(VReg::phys(reg_name(instr.op_register(0)))),
                    OpKind::Memory => {
                        let tmp = VReg::Temp(0);
                        ops.push(Op::Load {
                            dst: tmp.clone(),
                            addr: mem_op_of(instr),
                        });
                        Value::Reg(tmp)
                    }
                    _ => {
                        return vec![Op::Unknown {
                            mnemonic: format!("{:?}", mnem).to_ascii_lowercase(),
                        }]
                    }
                };
                // x86 div/idiv also writes the high-half remainder register.
                // This first-pass lift preserves the quotient dataflow that
                // tends to feed later buffer and bounds calculations.
                ops.push(Op::Bin {
                    dst: acc.clone(),
                    op: BinOp::Div,
                    lhs: Value::Reg(acc),
                    rhs: divisor,
                });
                return ops;
            }
            vec![Op::Unknown {
                mnemonic: format!("{:?}", mnem).to_ascii_lowercase(),
            }]
        }
        Mnemonic::Sbb => sbb_ops(instr),
        Mnemonic::Xorps => xorps_ops(instr),
        Mnemonic::Push => push_ops(instr, bits),
        Mnemonic::Pop => pop_ops(instr, bits),
        Mnemonic::Stosb | Mnemonic::Stosw | Mnemonic::Stosd | Mnemonic::Stosq => {
            stos_ops(mnem, bits)
        }
        Mnemonic::Cmpxchg => cmpxchg_ops(instr, bits),
        Mnemonic::Inc => {
            if instr.op_count() == 1 {
                match instr.op_kind(0) {
                    OpKind::Register => {
                        let r = VReg::phys(reg_name(instr.op_register(0)));
                        return vec![Op::Bin {
                            dst: r.clone(),
                            op: BinOp::Add,
                            lhs: Value::Reg(r),
                            rhs: Value::Const(1),
                        }];
                    }
                    OpKind::Memory => {
                        let addr = mem_op_of(instr);
                        let tmp = VReg::Temp(0);
                        return vec![
                            Op::Load {
                                dst: tmp.clone(),
                                addr: addr.clone(),
                            },
                            Op::Bin {
                                dst: tmp.clone(),
                                op: BinOp::Add,
                                lhs: Value::Reg(tmp.clone()),
                                rhs: Value::Const(1),
                            },
                            Op::Store {
                                addr,
                                src: Value::Reg(tmp),
                            },
                        ];
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
                        let r = VReg::phys(reg_name(instr.op_register(0)));
                        return vec![Op::Bin {
                            dst: r.clone(),
                            op: BinOp::Sub,
                            lhs: Value::Reg(r),
                            rhs: Value::Const(1),
                        }];
                    }
                    OpKind::Memory => {
                        let addr = mem_op_of(instr);
                        let tmp = VReg::Temp(0);
                        return vec![
                            Op::Load {
                                dst: tmp.clone(),
                                addr: addr.clone(),
                            },
                            Op::Bin {
                                dst: tmp.clone(),
                                op: BinOp::Sub,
                                lhs: Value::Reg(tmp.clone()),
                                rhs: Value::Const(1),
                            },
                            Op::Store {
                                addr,
                                src: Value::Reg(tmp),
                            },
                        ];
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
                        return vec![
                            Op::Assign {
                                dst: old.clone(),
                                src: Value::Reg(dst.clone()),
                            },
                            Op::Bin {
                                dst: dst.clone(),
                                op: BinOp::Add,
                                lhs: Value::Reg(dst),
                                rhs: Value::Reg(src.clone()),
                            },
                            Op::Assign {
                                dst: src,
                                src: Value::Reg(old),
                            },
                        ];
                    }
                    OpKind::Memory => {
                        let addr = mem_op_of(instr);
                        let old = VReg::Temp(0);
                        let sum = VReg::Temp(1);
                        return vec![
                            Op::Load {
                                dst: old.clone(),
                                addr: addr.clone(),
                            },
                            Op::Bin {
                                dst: sum.clone(),
                                op: BinOp::Add,
                                lhs: Value::Reg(old.clone()),
                                rhs: Value::Reg(src.clone()),
                            },
                            Op::Store {
                                addr,
                                src: Value::Reg(sum),
                            },
                            Op::Assign {
                                dst: src,
                                src: Value::Reg(old),
                            },
                        ];
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
            OpKind::Register => vec![Op::Call {
                // Indirect jumps get encoded as calls for now because we do
                // not yet have a dedicated IndirectJump op; downstream
                // analyses treat both the same.
                target: CallTarget::Indirect(Value::Reg(VReg::phys(reg_name(
                    instr.op_register(0),
                )))),
            }],
            OpKind::Memory => vec![Op::Call {
                // See the register-indirect case above: model tail jumps
                // through an import slot as indirect calls until LLIR grows a
                // dedicated indirect-jump operation.
                target: CallTarget::Indirect(Value::Addr(instr.memory_displacement64())),
            }],
            _ => vec![Op::Unknown {
                mnemonic: "jmp".into(),
            }],
        },
        Mnemonic::Call => match instr.op_kind(0) {
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
                vec![Op::Call {
                    target: CallTarget::Direct(instr.near_branch_target()),
                }]
            }
            OpKind::Register => vec![Op::Call {
                target: CallTarget::Indirect(Value::Reg(VReg::phys(reg_name(
                    instr.op_register(0),
                )))),
            }],
            OpKind::Memory => vec![Op::Call {
                // Indirect call through memory: we surface it as Indirect
                // with the memory operand recovered into a temp.
                target: CallTarget::Indirect(Value::Addr(instr.memory_displacement64())),
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
                        return vec![Op::CondJump {
                            cond: condition.flag,
                            target: instr.near_branch_target(),
                            inverted: condition.inverted,
                        }];
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
        assert_eq!(ops.len(), 1);
        match &ops[0].op {
            Op::Bin { dst, op, lhs, rhs } => {
                assert_eq!(*dst, VReg::phys("rax"));
                assert_eq!(*op, BinOp::Add);
                assert_eq!(*lhs, Value::Reg(VReg::phys("rax")));
                assert_eq!(*rhs, Value::Const(5));
            }
            other => panic!("expected Bin, got {:?}", other),
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
    fn jmp_rip_memory_records_indirect_tail_call_slot() {
        // jmp qword ptr [rip+0x1234] (ff 25 34 12 00 00) from 0x1000.
        let ops = lift64(&[0xff, 0x25, 0x34, 0x12, 0x00, 0x00]);
        assert_eq!(ops.len(), 1);
        match &ops[0].op {
            Op::Call {
                target: CallTarget::Indirect(Value::Addr(addr)),
            } => assert_eq!(*addr, 0x223a),
            other => panic!("expected indirect Call through memory, got {:?}", other),
        }
    }

    #[test]
    fn cmp_emits_composite_flag_writes_plus_sign_materialisation() {
        // cmp rax, rbx (48 39 d8) — lifter writes Z, C, Slt, Sle, S (via a
        // `tmp = lhs - rhs; %sf = slt(tmp, 0)` sequence so that Js/Jns read a
        // faithful bit).
        let ops = lift64(&[0x48, 0x39, 0xd8]);
        // 5 Cmp flag writes + 1 Sub temp materialisation + 1 Cmp for %sf = 7.
        assert_eq!(ops.len(), 7, "cmp should lift to 7 LLIR ops: {:#?}", ops);
        let flags: Vec<_> = ops
            .iter()
            .filter_map(|i| match &i.op {
                Op::Cmp { dst, .. } => Some(dst.clone()),
                _ => None,
            })
            .collect();
        for want in [
            VReg::Flag(Flag::Z),
            VReg::Flag(Flag::C),
            VReg::Flag(Flag::Ule),
            VReg::Flag(Flag::Slt),
            VReg::Flag(Flag::Sle),
            VReg::Flag(Flag::S),
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
        assert_eq!(cj.0, VReg::Flag(Flag::Sle));
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
        assert_eq!(cj, VReg::Flag(Flag::Slt));
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
        assert_eq!(cj.0, VReg::Flag(Flag::Ule));
        assert_eq!(cj.1, 0x1007);
    }

    #[test]
    fn sete_lifts_to_flag_assign() {
        // sete al  (0f 94 c0)
        let ops = lift64(&[0x0f, 0x94, 0xc0]);
        assert_eq!(ops.len(), 1, "got: {:#?}", ops);
        match &ops[0].op {
            Op::Assign {
                dst,
                src: Value::Reg(cond),
            } => {
                assert_eq!(*dst, VReg::phys("al"));
                assert_eq!(*cond, VReg::Flag(Flag::Z));
            }
            other => panic!("expected flag Assign, got {:?}", other),
        }
    }

    #[test]
    fn cmovne_lifts_to_conditional_assign() {
        // cmovne rax, rbx  (48 0f 45 c3)
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
            Op::CondAssign {
                dst,
                cond,
                src: Value::Reg(src),
            } => {
                assert_eq!(*dst, VReg::phys("rax"));
                assert_eq!(*cond, VReg::Temp(1));
                assert_eq!(*src, VReg::phys("rbx"));
            }
            other => panic!("expected CondAssign, got {:?}", other),
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
    fn stosq_lifts_to_store_and_destination_advance() {
        // rep stosq  (f3 48 ab). Repetition is not modelled yet, but the
        // representative store and rdi advance preserve the core dataflow.
        let ops = lift64(&[0xf3, 0x48, 0xab]);
        assert_eq!(ops.len(), 2, "got: {:#?}", ops);
        match &ops[0].op {
            Op::Store {
                addr:
                    MemOp {
                        base: Some(base),
                        size: 8,
                        ..
                    },
                src: Value::Reg(src),
            } => {
                assert_eq!(*base, VReg::phys("rdi"));
                assert_eq!(*src, VReg::phys("rax"));
            }
            other => panic!("expected stosq store, got {:?}", other),
        }
        assert!(matches!(
            &ops[1].op,
            Op::Bin {
                dst,
                op: BinOp::Add,
                lhs: Value::Reg(lhs),
                rhs: Value::Const(8),
            } if *dst == VReg::phys("rdi") && *lhs == VReg::phys("rdi")
        ));
    }

    #[test]
    fn cmpxchg_reg_reg_lifts_to_compare_and_conditional_updates() {
        // cmpxchg rbx, rcx  (48 0f b1 cb)
        let ops = lift64(&[0x48, 0x0f, 0xb1, 0xcb]);
        assert_eq!(ops.len(), 5, "got: {:#?}", ops);
        assert!(matches!(
            &ops[0].op,
            Op::Assign {
                dst: VReg::Temp(0),
                src: Value::Reg(src),
            } if *src == VReg::phys("rbx")
        ));
        assert!(matches!(
            &ops[1].op,
            Op::Cmp {
                dst: VReg::Flag(Flag::Z),
                op: CmpOp::Eq,
                lhs: Value::Reg(lhs),
                rhs: Value::Reg(VReg::Temp(0)),
            } if *lhs == VReg::phys("rax")
        ));
        assert!(matches!(
            &ops[2].op,
            Op::CondAssign {
                dst,
                cond: VReg::Flag(Flag::Z),
                src: Value::Reg(src),
            } if *dst == VReg::phys("rbx") && *src == VReg::phys("rcx")
        ));
        assert!(matches!(
            &ops[4].op,
            Op::CondAssign {
                dst,
                cond: VReg::Temp(2),
                src: Value::Reg(VReg::Temp(0)),
            } if *dst == VReg::phys("rax")
        ));
    }

    #[test]
    fn cmpxchg_mem_reg_lifts_to_conditional_store_shape() {
        // cmpxchg qword ptr [rip+0x10], rcx  (48 0f b1 0d 10 00 00 00)
        let ops = lift64(&[0x48, 0x0f, 0xb1, 0x0d, 0x10, 0x00, 0x00, 0x00]);
        assert_eq!(ops.len(), 7, "got: {:#?}", ops);
        assert!(matches!(
            &ops[0].op,
            Op::Load {
                dst: VReg::Temp(0),
                addr: MemOp { size: 8, .. },
            }
        ));
        assert!(matches!(
            &ops[3].op,
            Op::CondAssign {
                dst: VReg::Temp(1),
                cond: VReg::Flag(Flag::Z),
                src: Value::Reg(src),
            } if *src == VReg::phys("rcx")
        ));
        assert!(matches!(
            &ops[4].op,
            Op::Store {
                src: Value::Reg(VReg::Temp(1)),
                ..
            }
        ));
        assert!(matches!(
            &ops[6].op,
            Op::CondAssign {
                dst,
                cond: VReg::Temp(2),
                src: Value::Reg(VReg::Temp(0)),
            } if *dst == VReg::phys("rax")
        ));
    }

    #[test]
    fn int3_lifts_to_nop() {
        let ops = lift64(&[0xcc]);
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].op, Op::Nop);
    }

    #[test]
    fn div_reg_lifts_to_accumulator_divide() {
        // div rcx  (48 f7 f1)
        let ops = lift64(&[0x48, 0xf7, 0xf1]);
        assert_eq!(ops.len(), 1, "got: {:#?}", ops);
        match &ops[0].op {
            Op::Bin {
                dst,
                op: BinOp::Div,
                lhs: Value::Reg(lhs),
                rhs: Value::Reg(rhs),
            } => {
                assert_eq!(*dst, VReg::phys("rax"));
                assert_eq!(*lhs, VReg::phys("rax"));
                assert_eq!(*rhs, VReg::phys("rcx"));
            }
            other => panic!("expected accumulator Div, got {:?}", other),
        }
    }

    #[test]
    fn cdqe_lifts_to_rax_from_eax_assign() {
        let ops = lift64(&[0x48, 0x98]);
        assert_eq!(ops.len(), 1, "got: {ops:#?}");
        assert!(matches!(
            &ops[0].op,
            Op::Assign {
                dst,
                src: Value::Reg(src),
            } if *dst == VReg::phys("rax") && *src == VReg::phys("eax")
        ));
    }

    #[test]
    fn sbb_reg_reg_lifts_to_sub_with_carry_dependency() {
        let ops = lift64(&[0x48, 0x19, 0xc8]);
        assert_eq!(ops.len(), 2, "got: {ops:#?}");
        assert!(matches!(
            &ops[0].op,
            Op::Bin {
                dst,
                op: BinOp::Sub,
                lhs: Value::Reg(lhs),
                rhs: Value::Reg(rhs),
            } if *dst == VReg::phys("rax")
                && *lhs == VReg::phys("rax")
                && *rhs == VReg::phys("rcx")
        ));
        assert!(matches!(
            &ops[1].op,
            Op::Bin {
                dst,
                op: BinOp::Sub,
                lhs: Value::Reg(lhs),
                rhs: Value::Reg(rhs),
            } if *dst == VReg::phys("rax")
                && *lhs == VReg::phys("rax")
                && *rhs == VReg::Flag(Flag::C)
        ));
    }

    #[test]
    fn xorps_self_lifts_to_zero_assign() {
        let ops = lift64(&[0x0f, 0x57, 0xc0]);
        assert_eq!(ops.len(), 1, "got: {ops:#?}");
        assert!(matches!(
            &ops[0].op,
            Op::Assign {
                dst,
                src: Value::Const(0),
            } if *dst == VReg::phys("xmm0")
        ));
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
        assert_eq!(ops.len(), 1);
        match &ops[0].op {
            Op::Assign { dst, src } => {
                assert!(matches!(dst, VReg::Phys(n) if n == "xmm0"));
                assert!(matches!(src, Value::Reg(VReg::Phys(n)) if n == "xmm1"));
            }
            other => panic!("expected Assign, got {:?}", other),
        }
    }

    #[test]
    fn movdqu_reg_mem_lifts_to_16_byte_load() {
        // MOVDQU xmm0, [rdi]   (f3 0f 6f 07)
        let ops = lift64(&[0xf3, 0x0f, 0x6f, 0x07]);
        assert_eq!(ops.len(), 1);
        match &ops[0].op {
            Op::Load { addr, .. } => assert_eq!(addr.size, 16),
            other => panic!("expected Load, got {:?}", other),
        }
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
        // Subsequent ops should be the usual cmp flag writes, all of which
        // read the temp rather than a bare memory operand.
        let flag_count = ops
            .iter()
            .filter(|i| matches!(i.op, Op::Cmp { .. }))
            .count();
        assert!(flag_count >= 4, "expected ≥4 Cmp writes, got {flag_count}");
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
        assert_eq!(ops.len(), 1);
        match &ops[0].op {
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
        assert_eq!(ops.len(), 1);
        match &ops[0].op {
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
        assert_eq!(ops.len(), 3);
        match &ops[0].op {
            Op::Load { dst, addr } => {
                assert_eq!(*dst, VReg::Temp(0));
                assert_eq!(addr.base, Some(VReg::phys("rax")));
                assert_eq!(addr.disp, 8);
                assert_eq!(addr.size, 8);
            }
            other => panic!("expected Load, got {:?}", other),
        }
        match &ops[1].op {
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
        match &ops[2].op {
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
        assert_eq!(ops.len(), 3);
        assert!(matches!(
            &ops[0].op,
            Op::Load {
                dst: VReg::Temp(0),
                addr,
            } if addr.base == Some(VReg::phys("rax")) && addr.disp == 0x10 && addr.size == 8
        ));
        assert!(matches!(
            &ops[1].op,
            Op::Bin {
                dst: VReg::Temp(0),
                op: BinOp::Sub,
                lhs: Value::Reg(VReg::Temp(0)),
                rhs: Value::Const(1),
            }
        ));
        assert!(matches!(
            &ops[2].op,
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
        assert_eq!(ops.len(), 4);
        assert!(matches!(
            &ops[0].op,
            Op::Load {
                dst: VReg::Temp(0),
                addr,
            } if addr.base == Some(VReg::phys("rcx")) && addr.size == 4
        ));
        assert!(matches!(
            &ops[1].op,
            Op::Bin {
                dst: VReg::Temp(1),
                op: BinOp::Add,
                lhs: Value::Reg(VReg::Temp(0)),
                rhs: Value::Reg(VReg::Phys(src)),
            } if src == "eax"
        ));
        assert!(matches!(
            &ops[2].op,
            Op::Store {
                addr,
                src: Value::Reg(VReg::Temp(1)),
            } if addr.base == Some(VReg::phys("rcx")) && addr.size == 4
        ));
        assert!(matches!(
            &ops[3].op,
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
        assert_eq!(ops.len(), 3);
        assert!(matches!(
            &ops[0].op,
            Op::Assign {
                dst: VReg::Temp(0),
                src: Value::Reg(VReg::Phys(src)),
            } if src == "eax"
        ));
        assert!(matches!(
            &ops[1].op,
            Op::Bin {
                dst: VReg::Phys(dst),
                op: BinOp::Add,
                lhs: Value::Reg(VReg::Phys(lhs)),
                rhs: Value::Reg(VReg::Phys(rhs)),
            } if dst == "eax" && lhs == "eax" && rhs == "ebx"
        ));
        assert!(matches!(
            &ops[2].op,
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
}
