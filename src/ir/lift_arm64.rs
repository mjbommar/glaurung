//! AArch64 → LLIR lifter.
//!
//! Decodes fixed-width 4-byte ARM64 instructions using the existing
//! [`crate::disasm::capstone::CapstoneDisassembler`] and emits LLIR ops.
//!
//! Coverage (v1):
//!
//! * `nop` → [`Op::Nop`]
//! * `mov`, `movz` → [`Op::Assign`]
//! * `add`, `sub`, `and`, `orr`, `eor`, `lsl`, `lsr`, `asr` → [`Op::Bin`]
//! * `cmp` → four [`Op::Cmp`] writes (Z, C, Slt, Sle) — same as x86
//! * `adrp` → [`Op::Assign`] of the resolved page address (capstone folds the
//!   PC arithmetic into the immediate operand)
//! * `ldr`/`ldrb`/`ldrh`/`ldrsw` with `[base, #disp]` → [`Op::Load`]
//! * `str`/`strb`/`strh` with `[base, #disp]` → [`Op::Store`]
//! * `b` (near target), `b.<cond>`, `cbz`/`cbnz` → [`Op::Jump`] / [`Op::CondJump`]
//! * `bl` (direct), `blr` / `br` (indirect) → [`Op::Call`]
//! * `ret` → [`Op::Return`]
//!
//! Anything else becomes [`Op::Unknown`] carrying the capstone mnemonic so
//! downstream passes can flag unsupported instructions.

use crate::core::address::{Address, AddressKind};
use crate::core::binary::Endianness;
use crate::core::disassembler::{Architecture, Disassembler};
use crate::core::instruction::{Instruction, Operand, OperandKind};
use crate::disasm::capstone::CapstoneDisassembler;

use crate::ir::types::*;

fn operand_reg(op: &Operand) -> Option<VReg> {
    if matches!(op.kind, OperandKind::Register) {
        op.register.clone().map(VReg::phys)
    } else {
        None
    }
}

fn operand_to_value(op: &Operand) -> Option<Value> {
    match op.kind {
        OperandKind::Register => op.register.clone().map(|n| Value::Reg(VReg::phys(n))),
        OperandKind::Immediate => op.immediate.map(Value::Const),
        _ => None,
    }
}

fn operand_to_memop(op: &Operand) -> Option<MemOp> {
    if !matches!(op.kind, OperandKind::Memory) {
        return None;
    }
    let base = op.base.clone().map(VReg::phys);
    let index = op.index.clone().map(VReg::phys);
    let disp = op.displacement.unwrap_or(0);
    Some(MemOp {
        base,
        index,
        scale: op.scale.unwrap_or(0),
        disp,
        size: 8, // capstone doesn't give a precise width; 8 is a safe default for 64-bit
        segment: None, // ARM64 has no segment registers
    })
}

fn bin_for_mnem(m: &str) -> Option<BinOp> {
    Some(match m {
        "add" => BinOp::Add,
        "sub" => BinOp::Sub,
        "and" => BinOp::And,
        "orr" => BinOp::Or,
        "eor" => BinOp::Xor,
        "lsl" => BinOp::Shl,
        "lsr" => BinOp::Shr,
        "asr" => BinOp::Sar,
        "mul" => BinOp::Mul,
        _ => return None,
    })
}

/// Map a `b.<cond>` mnemonic (e.g. "b.eq") onto the LLIR flag whose truth
/// determines whether the branch is taken. The negated sibling (`b.ne` vs
/// `b.eq`) reads the same flag and the consumer inverts the sense.
fn cond_flag_for_bcond(suffix: &str) -> Option<VReg> {
    Some(match suffix {
        "eq" | "ne" => VReg::Flag(Flag::Z),
        // AArch64 uses "LO" (same as CS / unsigned lower) and "HS" (HI or
        // equal) for unsigned-less-than.
        "lo" | "cc" | "cs" | "hs" => VReg::Flag(Flag::C),
        "lt" | "ge" => VReg::Flag(Flag::Slt),
        "le" | "gt" => VReg::Flag(Flag::Sle),
        // MI/PL read the raw sign; with cmp-driven flows this coincides with
        // signed-less-than, so we approximate similarly to x86 Js/Jns.
        "mi" | "pl" => VReg::Flag(Flag::Slt),
        "vs" | "vc" => VReg::Flag(Flag::O),
        _ => return None,
    })
}

fn lift_one(ins: &Instruction) -> Vec<Op> {
    let mnem = ins.mnemonic.to_ascii_lowercase();

    // Three-operand arithmetic: <op> Xd, Xn, <reg|imm>
    if let Some(op) = bin_for_mnem(&mnem) {
        if ins.operands.len() == 3 {
            let (Some(dst), Some(lhs), Some(rhs)) = (
                operand_reg(&ins.operands[0]),
                operand_to_value(&ins.operands[1]),
                operand_to_value(&ins.operands[2]),
            ) else {
                return vec![Op::Unknown { mnemonic: mnem }];
            };
            return vec![Op::Bin { dst, op, lhs, rhs }];
        }
    }

    // b.<cond> conditional branches.
    if let Some(suffix) = mnem.strip_prefix("b.") {
        if let Some(cond) = cond_flag_for_bcond(suffix) {
            if let Some(target) = ins.operands.first().and_then(|o| o.immediate) {
                return vec![Op::CondJump {
                    cond,
                    target: target as u64,
                }];
            }
        }
        return vec![Op::Unknown { mnemonic: mnem }];
    }

    match mnem.as_str() {
        "nop" => vec![Op::Nop],
        "mov" => {
            if ins.operands.len() == 2 {
                let Some(dst) = operand_reg(&ins.operands[0]) else {
                    return vec![Op::Unknown { mnemonic: mnem }];
                };
                if let Some(src) = operand_to_value(&ins.operands[1]) {
                    return vec![Op::Assign { dst, src }];
                }
            }
            vec![Op::Unknown { mnemonic: mnem }]
        }
        "movz" => {
            // movz <Xd>, #imm — low 16-bit move-with-zero; we emit Assign for
            // the simple (no-shift) case. More general movz + movk sequences
            // are handled by a later materialization pass.
            if ins.operands.len() >= 2 {
                let Some(dst) = operand_reg(&ins.operands[0]) else {
                    return vec![Op::Unknown { mnemonic: mnem }];
                };
                if let Some(imm) = ins.operands[1].immediate {
                    return vec![Op::Assign {
                        dst,
                        src: Value::Const(imm),
                    }];
                }
            }
            vec![Op::Unknown { mnemonic: mnem }]
        }
        "adrp" => {
            // adrp <Xd>, #<page>. Capstone already resolves the page VA into
            // the immediate operand. We surface it as an absolute address so
            // xref recovery can pair it with the subsequent add/ldr.
            if ins.operands.len() == 2 {
                let Some(dst) = operand_reg(&ins.operands[0]) else {
                    return vec![Op::Unknown { mnemonic: mnem }];
                };
                if let Some(imm) = ins.operands[1].immediate {
                    return vec![Op::Assign {
                        dst,
                        src: Value::Addr(imm as u64),
                    }];
                }
            }
            vec![Op::Unknown { mnemonic: mnem }]
        }
        "cmp" => {
            if ins.operands.len() == 2 {
                let Some(lhs) = operand_to_value(&ins.operands[0]) else {
                    return vec![Op::Unknown { mnemonic: mnem }];
                };
                let Some(rhs) = operand_to_value(&ins.operands[1]) else {
                    return vec![Op::Unknown { mnemonic: mnem }];
                };
                return vec![
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
                        lhs,
                        rhs,
                    },
                ];
            }
            vec![Op::Unknown { mnemonic: mnem }]
        }
        "ldr" | "ldrb" | "ldrh" | "ldrsb" | "ldrsh" | "ldrsw" => {
            if ins.operands.len() >= 2 {
                let Some(dst) = operand_reg(&ins.operands[0]) else {
                    return vec![Op::Unknown { mnemonic: mnem }];
                };
                if let Some(addr) = operand_to_memop(&ins.operands[1]) {
                    let base_reg = addr.base.clone();
                    let mut out = vec![Op::Load {
                        dst,
                        addr,
                    }];
                    // Post-indexed: 3rd operand is the writeback amount.
                    if ins.operands.len() == 3 {
                        if let (Some(base), Some(off)) =
                            (base_reg, ins.operands[2].immediate)
                        {
                            out.push(Op::Bin {
                                dst: base.clone(),
                                op: BinOp::Add,
                                lhs: Value::Reg(base),
                                rhs: Value::Const(off),
                            });
                        }
                    }
                    return out;
                }
                // PC-relative literal (2-operand form).
                if ins.operands.len() == 2 {
                    if let Some(abs) = ins.operands[1].immediate {
                        let size: u8 = match mnem.as_str() {
                            "ldrb" | "ldrsb" => 1,
                            "ldrh" | "ldrsh" => 2,
                            "ldrsw" => 4,
                            _ => 8,
                        };
                        return vec![Op::Load {
                            dst,
                            addr: MemOp {
                                base: None,
                                index: None,
                                scale: 0,
                                disp: abs,
                                size,
                                segment: None,
                            },
                        }];
                    }
                }
            }
            vec![Op::Unknown { mnemonic: mnem }]
        }
        "str" | "strb" | "strh" => {
            if ins.operands.len() == 2 {
                let Some(src) = operand_to_value(&ins.operands[0]) else {
                    return vec![Op::Unknown { mnemonic: mnem }];
                };
                if let Some(addr) = operand_to_memop(&ins.operands[1]) {
                    return vec![Op::Store { addr, src }];
                }
            }
            vec![Op::Unknown { mnemonic: mnem }]
        }
        // Load-pair / store-pair: `ldp Xt1, Xt2, [base, #disp]` transfers two
        // consecutive 8-byte words. We decompose into two ordinary
        // Load/Store ops so the rest of the pipeline (stack locals, dead
        // stores, push/pop recognition) doesn't need to know about pairs.
        "ldp" => {
            if ins.operands.len() >= 3 {
                let Some(dst1) = operand_reg(&ins.operands[0]) else {
                    return vec![Op::Unknown { mnemonic: mnem }];
                };
                let Some(dst2) = operand_reg(&ins.operands[1]) else {
                    return vec![Op::Unknown { mnemonic: mnem }];
                };
                if let Some(mut addr) = operand_to_memop(&ins.operands[2]) {
                    let base_reg = addr.base.clone();
                    let pair_off = 8i64;
                    let addr2 = MemOp {
                        disp: addr.disp.wrapping_add(pair_off),
                        ..addr.clone()
                    };
                    addr.size = 8;
                    let mut out = vec![
                        Op::Load { dst: dst1, addr },
                        Op::Load { dst: dst2, addr: addr2 },
                    ];
                    // Post-indexed: 4th operand is the writeback amount.
                    if ins.operands.len() == 4 {
                        if let (Some(base), Some(off)) =
                            (base_reg, ins.operands[3].immediate)
                        {
                            out.push(Op::Bin {
                                dst: base.clone(),
                                op: BinOp::Add,
                                lhs: Value::Reg(base),
                                rhs: Value::Const(off),
                            });
                        }
                    }
                    return out;
                }
            }
            vec![Op::Unknown { mnemonic: mnem }]
        }
        "stp" => {
            if ins.operands.len() >= 3 {
                let Some(src1) = operand_to_value(&ins.operands[0]) else {
                    return vec![Op::Unknown { mnemonic: mnem }];
                };
                let Some(src2) = operand_to_value(&ins.operands[1]) else {
                    return vec![Op::Unknown { mnemonic: mnem }];
                };
                if let Some(mut addr) = operand_to_memop(&ins.operands[2]) {
                    let base_reg = addr.base.clone();
                    let pair_off = 8i64;
                    let addr2 = MemOp {
                        disp: addr.disp.wrapping_add(pair_off),
                        ..addr.clone()
                    };
                    addr.size = 8;
                    let mut out = vec![
                        Op::Store { addr, src: src1 },
                        Op::Store { addr: addr2, src: src2 },
                    ];
                    if ins.operands.len() == 4 {
                        if let (Some(base), Some(off)) =
                            (base_reg, ins.operands[3].immediate)
                        {
                            out.push(Op::Bin {
                                dst: base.clone(),
                                op: BinOp::Add,
                                lhs: Value::Reg(base),
                                rhs: Value::Const(off),
                            });
                        }
                    }
                    return out;
                }
            }
            vec![Op::Unknown { mnemonic: mnem }]
        }
        "cbz" | "cbnz" => {
            // cbz <Xn>, <label>: compare <Xn> to zero, branch if (non)zero.
            // Emit: %zf = (Xn == 0); cond_jump %zf <label>
            if ins.operands.len() == 2 {
                let Some(reg_val) = operand_to_value(&ins.operands[0]) else {
                    return vec![Op::Unknown { mnemonic: mnem }];
                };
                if let Some(target) = ins.operands[1].immediate {
                    return vec![
                        Op::Cmp {
                            dst: VReg::Flag(Flag::Z),
                            op: CmpOp::Eq,
                            lhs: reg_val,
                            rhs: Value::Const(0),
                        },
                        Op::CondJump {
                            cond: VReg::Flag(Flag::Z),
                            target: target as u64,
                        },
                    ];
                }
            }
            vec![Op::Unknown { mnemonic: mnem }]
        }
        "b" => {
            if let Some(target) = ins.operands.first().and_then(|o| o.immediate) {
                return vec![Op::Jump {
                    target: target as u64,
                }];
            }
            vec![Op::Unknown { mnemonic: mnem }]
        }
        "bl" => {
            if let Some(target) = ins.operands.first().and_then(|o| o.immediate) {
                return vec![Op::Call {
                    target: CallTarget::Direct(target as u64),
                }];
            }
            vec![Op::Unknown { mnemonic: mnem }]
        }
        "br" | "blr" => {
            if let Some(reg) = ins.operands.first().and_then(operand_reg) {
                return vec![Op::Call {
                    target: CallTarget::Indirect(Value::Reg(reg)),
                }];
            }
            vec![Op::Unknown { mnemonic: mnem }]
        }
        "ret" => vec![Op::Return],
        _ => vec![Op::Unknown { mnemonic: mnem }],
    }
}

/// Lift a byte window of AArch64 machine code into LLIR.
///
/// Returns an empty vector if the capstone backend cannot be constructed
/// (should not happen at runtime on supported platforms) or if decoding
/// fails on the very first instruction.
pub fn lift_bytes(bytes: &[u8], start_va: u64) -> Vec<LlirInstr> {
    let Some(cs) = CapstoneDisassembler::new(Architecture::ARM64, Endianness::Little) else {
        return vec![];
    };
    let mut out = Vec::new();
    let mut off = 0usize;
    let mut va = start_va;
    while off + 4 <= bytes.len() {
        let Ok(addr) = Address::new(AddressKind::VA, va, 64, None, None) else {
            break;
        };
        let ins = match cs.disassemble_instruction(&addr, &bytes[off..]) {
            Ok(i) => i,
            Err(_) => break,
        };
        if ins.length == 0 {
            break;
        }
        for op in lift_one(&ins) {
            out.push(LlirInstr { va, op });
        }
        off += ins.length as usize;
        va = va.saturating_add(ins.length as u64);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // NOTE: ARM64 is 4-byte little-endian for data and wide-immediate fields.
    // The byte sequences below are hand-assembled from instruction encodings
    // in the Arm ARM (ARM DDI 0487) so tests are hermetic and don't need a
    // real binary.

    fn last_op_mnem(out: &[LlirInstr]) -> String {
        match &out.last().unwrap().op {
            Op::Unknown { mnemonic } => mnemonic.clone(),
            other => format!("{:?}", other),
        }
    }

    #[test]
    fn nop_lifts_to_nop() {
        // NOP = 0xd503201f (little-endian: 1f 20 03 d5)
        let out = lift_bytes(&[0x1f, 0x20, 0x03, 0xd5], 0x1000);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].op, Op::Nop);
        assert_eq!(out[0].va, 0x1000);
    }

    #[test]
    fn ret_lifts_to_return() {
        // RET (x30) = 0xd65f03c0 (LE: c0 03 5f d6)
        let out = lift_bytes(&[0xc0, 0x03, 0x5f, 0xd6], 0x2000);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].op, Op::Return);
    }

    #[test]
    fn add_x0_x0_x1_lifts_to_bin_add() {
        // ADD X0, X0, X1  =  0x8b010000  (LE: 00 00 01 8b)
        let out = lift_bytes(&[0x00, 0x00, 0x01, 0x8b], 0x1000);
        assert_eq!(out.len(), 1, "expected one op; got {:?}", out);
        match &out[0].op {
            Op::Bin {
                dst,
                op: BinOp::Add,
                lhs,
                rhs,
            } => {
                assert_eq!(*dst, VReg::phys("x0"));
                assert_eq!(*lhs, Value::Reg(VReg::phys("x0")));
                assert_eq!(*rhs, Value::Reg(VReg::phys("x1")));
            }
            other => panic!("expected Bin Add; got {:?}", other),
        }
    }

    #[test]
    fn cmp_x0_x1_emits_four_flag_writes() {
        // CMP X0, X1 = SUBS XZR, X0, X1  = 0xeb01001f (LE: 1f 00 01 eb)
        let out = lift_bytes(&[0x1f, 0x00, 0x01, 0xeb], 0x1000);
        assert_eq!(out.len(), 4, "cmp should lift to 4 LLIR ops: {:?}", out);
        let flags: Vec<VReg> = out
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
        ] {
            assert!(flags.contains(&want), "missing {:?} in {:?}", want, flags);
        }
    }

    #[test]
    fn bl_to_direct_target_lifts_to_call_direct() {
        // BL +0x20 from 0x1000:  target = 0x1020. Encoding:
        //   0x94000008  (imm26 = 0x8 = 32/4). LE: 08 00 00 94
        let out = lift_bytes(&[0x08, 0x00, 0x00, 0x94], 0x1000);
        assert_eq!(out.len(), 1);
        match &out[0].op {
            Op::Call {
                target: CallTarget::Direct(addr),
            } => assert_eq!(*addr, 0x1020),
            other => panic!("expected Call Direct; got {:?}", other),
        }
    }

    #[test]
    fn b_to_direct_target_lifts_to_jump() {
        // B +0x10 from 0x2000: 0x14000004  (LE: 04 00 00 14) — target 0x2010
        let out = lift_bytes(&[0x04, 0x00, 0x00, 0x14], 0x2000);
        assert_eq!(out.len(), 1);
        match &out[0].op {
            Op::Jump { target } => assert_eq!(*target, 0x2010),
            other => panic!("expected Jump; got {:?}", other),
        }
    }

    #[test]
    fn movz_x0_imm_lifts_to_assign() {
        // MOVZ X0, #0x1234 = 0xd2824680  (LE: 80 46 82 d2)
        // imm16 = 0x1234, hw = 0.
        let out = lift_bytes(&[0x80, 0x46, 0x82, 0xd2], 0x1000);
        assert_eq!(out.len(), 1);
        match &out[0].op {
            Op::Assign {
                dst,
                src: Value::Const(v),
            } => {
                assert_eq!(*dst, VReg::phys("x0"));
                assert_eq!(*v, 0x1234);
            }
            other => panic!("expected Assign of const; got {:?}", other),
        }
    }

    #[test]
    fn pre_indexed_stp_emits_sp_writeback() {
        // STP fp, lr, [sp, #-0x30]!   encoding 0xa9bd7bfd (LE fd 7b bd a9)
        // Real glibc-style ARM64 prologue. Pre-indexed form — capstone's
        // writeback flag is set and the memory operand's disp is -0x30.
        let out = lift_bytes(&[0xfd, 0x7b, 0xbd, 0xa9], 0x1000);
        // We want: two Stores at [sp - 0x30] and [sp - 0x28], followed by
        // an explicit sp += -0x30 writeback.
        let stores: Vec<_> = out
            .iter()
            .filter(|i| matches!(i.op, Op::Store { .. }))
            .collect();
        assert_eq!(stores.len(), 2, "expected two stores; got {:#?}", out);
        let has_sp_writeback = out.iter().any(|i| {
            matches!(
                &i.op,
                Op::Bin {
                    dst,
                    op: BinOp::Add,
                    rhs: Value::Const(-0x30),
                    ..
                } if *dst == VReg::phys("sp")
            )
        });
        assert!(
            has_sp_writeback,
            "pre-indexed STP must emit an sp writeback: {:#?}",
            out
        );
    }

    #[test]
    fn stp_pair_decomposes_into_two_stores() {
        // STP X29, X30, [SP, #-16]!   = 0xa9bf7bfd  (LE: fd 7b bf a9)
        // Pre-index form with SP writeback. Capstone reports the memory
        // operand's base as SP and disp as -16 (writeback is modeled by
        // capstone separately; we don't model writeback yet and treat this
        // as a plain memory store pair).
        let out = lift_bytes(&[0xfd, 0x7b, 0xbf, 0xa9], 0x1000);
        // Should decompose into two stores.
        let stores: Vec<_> = out
            .iter()
            .filter(|i| matches!(i.op, Op::Store { .. }))
            .collect();
        assert_eq!(stores.len(), 2, "expected two stores; got {:#?}", out);
        // The two store displacements must differ by 8 bytes.
        let disps: Vec<i64> = out
            .iter()
            .filter_map(|i| match &i.op {
                Op::Store {
                    addr: MemOp { disp, .. },
                    ..
                } => Some(*disp),
                _ => None,
            })
            .collect();
        assert_eq!(disps.len(), 2);
        assert_eq!((disps[1] - disps[0]).abs(), 8);
    }

    #[test]
    fn ldp_pair_decomposes_into_two_loads() {
        // LDP X29, X30, [SP, #16]   (immediate-offset form, no writeback)
        //   encoded: imm7=2 (scaled by 8 = 16), Rt2=30, Rn=31(SP), Rt=29.
        //   raw = 0xa9417bfd  (LE: fd 7b 41 a9)
        let out = lift_bytes(&[0xfd, 0x7b, 0x41, 0xa9], 0x1000);
        let loads: Vec<_> = out
            .iter()
            .filter(|i| matches!(i.op, Op::Load { .. }))
            .collect();
        assert_eq!(loads.len(), 2, "expected two loads; got {:#?}", out);
    }

    #[test]
    fn unknown_mnemonic_preserves_source() {
        // MRS X0, NZCV = 0xd53b4200  (LE: 00 42 3b d5) — not in our lifter set.
        let out = lift_bytes(&[0x00, 0x42, 0x3b, 0xd5], 0x1000);
        assert_eq!(out.len(), 1);
        match &out[0].op {
            Op::Unknown { mnemonic } => assert!(!mnemonic.is_empty(), "empty mnemonic in Unknown"),
            other => panic!(
                "expected Unknown preserving mnemonic ({}); got {:?}",
                last_op_mnem(&out),
                other
            ),
        }
    }

    #[test]
    fn real_arm64_binary_entry_lift_no_panic() {
        // End-to-end smoke against the committed ARM64 sample.
        let sample = std::path::Path::new(
            "samples/binaries/platforms/linux/arm64/export/cross/arm64/hello-arm64-gcc",
        );
        if !sample.exists() {
            eprintln!("sample missing: {}", sample.display());
            return;
        }
        let data = std::fs::read(sample).expect("read sample");
        let info = crate::analysis::entry::detect_entry(&data).expect("detect entry");
        let foff = info.file_offset.expect("file offset");
        let window = &data[foff..(foff + 128).min(data.len())];
        let ops = lift_bytes(window, info.entry_va);
        assert!(!ops.is_empty(), "no LLIR produced");
        // A compiled C entry invariably contains a call or branch within 128
        // bytes.
        assert!(
            ops.iter().any(|i| matches!(
                &i.op,
                Op::Call { .. } | Op::Jump { .. } | Op::CondJump { .. } | Op::Return
            )),
            "expected some control-flow op in {:#?}",
            ops
        );
    }
}
