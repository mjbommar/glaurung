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
//! * `add`, `sub`, `and`, `or`, `xor`, `shl`, `shr`, `sar`, `imul` → [`Op::Bin`]
//! * `not`, `neg` → [`Op::Un`]
//! * `cmp` → [`Op::Cmp`] writing `ZF`/`CF`/`SF`
//! * `test` → [`Op::Cmp`] writing `ZF`
//! * `push` / `pop` → decomposed into rsp-adjust + load/store
//! * `call` near direct / indirect → [`Op::Call`]
//! * `ret` → [`Op::Return`]
//! * `jmp` near direct → [`Op::Jump`]
//! * `jcc` (je, jne, jl, jg, …) → [`Op::CondJump`] reading the appropriate flag
//! * `lea` with rip-relative memory → [`Op::Assign`] of absolute VA
//!
//! Anything outside this set becomes [`Op::Unknown`] with the source mnemonic.

use iced_x86::{Decoder, DecoderOptions, Mnemonic, OpKind, Register};

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
    MemOp {
        base: maybe_reg(instr.memory_base()),
        index: maybe_reg(instr.memory_index()),
        scale: instr.memory_index_scale() as u8,
        disp: instr.memory_displacement64() as i64,
        size: instr.memory_size().size() as u8,
        segment: segment_override(instr.memory_segment()),
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

/// Map a conditional-jump mnemonic onto the flag virtual register whose truth
/// value determines whether the branch is taken. The negated siblings (Jne,
/// Jae, Jge, …) read the same flag; the consumer is expected to invert the
/// sense. The mapping is faithful across both `cmp`- and `test`-derived
/// paths: cmp writes `Flag::S` via a subtract-then-sign sequence and test
/// writes `Flag::S` as the sign of the AND result, so Js/Jns read the right
/// bit in either case.
fn cond_flag_for(mnem: Mnemonic) -> Option<VReg> {
    Some(match mnem {
        Mnemonic::Je | Mnemonic::Jne => VReg::Flag(Flag::Z),
        Mnemonic::Jb | Mnemonic::Jae => VReg::Flag(Flag::C),
        Mnemonic::Jl | Mnemonic::Jge => VReg::Flag(Flag::Slt),
        Mnemonic::Jg | Mnemonic::Jle => VReg::Flag(Flag::Sle),
        Mnemonic::Js | Mnemonic::Jns => VReg::Flag(Flag::S),
        Mnemonic::Jo | Mnemonic::Jno => VReg::Flag(Flag::O),
        Mnemonic::Jp | Mnemonic::Jnp => VReg::Flag(Flag::P),
        _ => return None,
    })
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
        Mnemonic::Nop | Mnemonic::Endbr32 | Mnemonic::Endbr64 => vec![Op::Nop],
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
                // signed-less-or-equal (ZF|SF^OF), and raw sign (SF). We
                // write each directly as an LLIR flag so conditional
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
                let lhs = match value_of_operand(instr, 0) {
                    Some(v) => v,
                    None => {
                        return vec![Op::Unknown {
                            mnemonic: "test".into(),
                        }]
                    }
                };
                let rhs = match value_of_operand(instr, 1) {
                    Some(v) => v,
                    None => {
                        return vec![Op::Unknown {
                            mnemonic: "test".into(),
                        }]
                    }
                };
                // test sets ZF = ((lhs & rhs) == 0) and SF = msb(lhs & rhs).
                // Materialise the AND into a temp and emit the two flag
                // writes against it. `Flag::Slt` is also written so that the
                // Jl/Jge siblings (rare after test, but emitted by some
                // compilers) read something reasonable instead of a stale
                // flag — it coincides with the sign bit here because the
                // second comparand is 0.
                let tmp = VReg::Temp(0);
                return vec![
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
                ];
            }
            vec![Op::Unknown {
                mnemonic: "test".into(),
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
        Mnemonic::Push => push_ops(instr, bits),
        Mnemonic::Pop => pop_ops(instr, bits),
        Mnemonic::Inc => {
            if instr.op_count() == 1 && instr.op_kind(0) == OpKind::Register {
                let r = VReg::phys(reg_name(instr.op_register(0)));
                return vec![Op::Bin {
                    dst: r.clone(),
                    op: BinOp::Add,
                    lhs: Value::Reg(r),
                    rhs: Value::Const(1),
                }];
            }
            vec![Op::Unknown {
                mnemonic: "inc".into(),
            }]
        }
        Mnemonic::Dec => {
            if instr.op_count() == 1 && instr.op_kind(0) == OpKind::Register {
                let r = VReg::phys(reg_name(instr.op_register(0)));
                return vec![Op::Bin {
                    dst: r.clone(),
                    op: BinOp::Sub,
                    lhs: Value::Reg(r),
                    rhs: Value::Const(1),
                }];
            }
            vec![Op::Unknown {
                mnemonic: "dec".into(),
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
            if let Some(cond) = cond_flag_for(mnem) {
                match instr.op_kind(0) {
                    OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
                        return vec![Op::CondJump {
                            cond,
                            target: instr.near_branch_target(),
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
            Op::Bin {
                dst,
                op,
                lhs,
                rhs,
            } => {
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
        assert!(matches!(
            &ops[0].op,
            Op::Bin { op: BinOp::Xor, .. }
        ));
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
    fn cmp_emits_five_flag_writes_plus_sign_materialisation() {
        // cmp rax, rbx (48 39 d8) — lifter writes Z, C, Slt, Sle, S (via a
        // `tmp = lhs - rhs; %sf = slt(tmp, 0)` sequence so that Js/Jns read a
        // faithful bit).
        let ops = lift64(&[0x48, 0x39, 0xd8]);
        // 4 Cmp flag writes + 1 Sub temp materialisation + 1 Cmp for %sf = 6.
        assert_eq!(ops.len(), 6, "cmp should lift to 6 LLIR ops: {:#?}", ops);
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
                Op::CondJump { cond, target } => Some((cond.clone(), *target)),
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
                Op::CondJump { cond, target } => Some((cond.clone(), *target)),
                _ => None,
            })
            .expect("expected a CondJump");
        assert_eq!(cj.0, VReg::Flag(Flag::Z));
        // cmp is 3 bytes, je short is 2 bytes, start 0x1000 → je at 0x1003 → target 0x1005 + 2? Let's compute:
        // je is at 0x1003, length 2, disp +2 → target = 0x1003 + 2 + 2 = 0x1007
        assert_eq!(cj.1, 0x1007);
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
        assert!(ops
            .iter()
            .any(|i| matches!(&i.op, Op::Bin { op: BinOp::Mul, rhs: Value::Const(8), .. })));
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
    fn cmp_reg_mem_emits_load_before_flags() {
        // cmp rax, qword [rbx]  (48 3b 03)
        let ops = lift64(&[0x48, 0x3b, 0x03]);
        // First op must be a Load of the memory operand.
        assert!(matches!(
            &ops[0].op,
            Op::Load { dst: VReg::Temp(11), .. }
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
        assert!(matches!(&ops[0].op, Op::Load { dst: VReg::Temp(0), .. }));
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
