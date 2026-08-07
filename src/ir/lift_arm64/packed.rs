//! AArch64 packed-lane lowering into the shared scalar LLIR.
//!
//! Vector operands retain their decoded lane shape, but downstream dataflow
//! stays architecture-neutral: each packed dword is an ordinary 32-bit virtual
//! register. This is the same representation used by the x86 SIMD lifter.

use crate::core::instruction::Instruction;
use crate::ir::types::{BinOp, Endian, MemOp, Op, VReg, Value};

use super::{operand_reg, operand_to_memop, scaled_memop};

/// Canonical full-vector spelling shared by the `qN` transfer view and `vN`
/// packed-operation view.
pub(super) fn vector_name(register: &VReg) -> Option<String> {
    let VReg::Phys(name) = register else {
        return None;
    };
    let index = name
        .strip_prefix('q')
        .or_else(|| name.strip_prefix('v'))?
        .parse::<u8>()
        .ok()
        .filter(|index| *index <= 31)?;
    Some(format!("v{index}"))
}

#[derive(Clone, Copy)]
pub(super) enum Transfer {
    Load,
    Store,
}

fn dword_transfers(register: &VReg, addr: &MemOp, transfer: Transfer) -> Option<Vec<Op>> {
    let register = vector_name(register)?;
    Some(
        (0..4)
            .map(|lane| {
                let mut lane_addr = addr.clone();
                lane_addr.disp = lane_addr.disp.saturating_add((lane * 4) as i64);
                lane_addr.size = 4;
                let lane = crate::ir::types::packed_dword_lane(&register, lane);
                match transfer {
                    Transfer::Load => Op::Load {
                        dst: lane,
                        addr: lane_addr,
                    },
                    Transfer::Store => Op::Store {
                        addr: lane_addr,
                        src: Value::Reg(lane),
                    },
                }
            })
            .collect(),
    )
}

fn append_base_writeback(
    ins: &Instruction,
    base: Option<VReg>,
    operand_index: usize,
    out: &mut Vec<Op>,
) {
    let Some((base, offset)) = base.zip(
        ins.operands
            .get(operand_index)
            .and_then(|operand| operand.immediate),
    ) else {
        return;
    };
    out.push(Op::Bin {
        dst: base.clone(),
        op: BinOp::Add,
        lhs: Value::Reg(base),
        rhs: Value::Const(offset),
    });
}

pub(super) fn memory_transfer(
    ins: &Instruction,
    register: &VReg,
    memory_index: usize,
    writeback_index: usize,
    transfer: Transfer,
) -> Option<Vec<Op>> {
    let operand = ins.operands.get(memory_index)?;
    let addr = operand_to_memop(operand, 4).or_else(|| {
        matches!(transfer, Transfer::Load).then_some(MemOp {
            base: None,
            index: None,
            scale: 0,
            disp: operand.immediate?,
            size: 4,
            segment: None,
            endian: Endian::Little,
        })
    })?;
    let base = addr.base.clone();
    let mut out = Vec::new();
    let addr = scaled_memop(ins, addr, &mut out);
    out.extend(dword_transfers(register, &addr, transfer)?);
    append_base_writeback(ins, base, writeback_index, &mut out);
    Some(out)
}

pub(super) fn pair_transfer(
    ins: &Instruction,
    first: &VReg,
    second: &VReg,
    transfer: Transfer,
) -> Option<Vec<Op>> {
    let addr = operand_to_memop(ins.operands.get(2)?, 4)?;
    let base = addr.base.clone();
    let mut out = Vec::new();
    let addr = scaled_memop(ins, addr, &mut out);
    let mut second_addr = addr.clone();
    second_addr.disp = second_addr.disp.saturating_add(16);
    out.extend(dword_transfers(first, &addr, transfer)?);
    out.extend(dword_transfers(second, &second_addr, transfer)?);
    append_base_writeback(ins, base, 3, &mut out);
    Some(out)
}

pub(super) fn dword_binary(ins: &Instruction, op: BinOp) -> Option<Vec<Op>> {
    if ins.operands.len() != 3 {
        return None;
    }
    let shape = ins
        .operands
        .iter()
        .find_map(|operand| operand.vector_shape)?;
    if (shape.lanes, shape.element_bits) != (4, 32)
        || ins
            .operands
            .iter()
            .any(|operand| operand.vector_shape.is_some_and(|other| other != shape))
    {
        return None;
    }
    let dst = vector_name(&operand_reg(&ins.operands[0])?)?;
    let lhs = vector_name(&operand_reg(&ins.operands[1])?)?;
    let rhs = vector_name(&operand_reg(&ins.operands[2])?)?;
    Some(
        (0..4)
            .map(|lane| Op::Bin {
                dst: crate::ir::types::packed_dword_lane(&dst, lane),
                op,
                lhs: Value::Reg(crate::ir::types::packed_dword_lane(&lhs, lane)),
                rhs: Value::Reg(crate::ir::types::packed_dword_lane(&rhs, lane)),
            })
            .collect(),
    )
}

pub(super) fn dword_horizontal_add(ins: &Instruction) -> Option<Vec<Op>> {
    if ins.operands.len() != 2 {
        return None;
    }
    let dst = operand_reg(&ins.operands[0])?;
    let src = vector_name(&operand_reg(&ins.operands[1])?)?;
    let shape = ins.operands[1].vector_shape?;
    if (shape.lanes, shape.element_bits) != (4, 32)
        || !matches!(&dst, VReg::Phys(name) if numbered_register(name, 's', 31))
    {
        return None;
    }
    let dst = scalar_dword_lane(&dst)?;
    let mut out = vec![Op::Assign {
        dst: dst.clone(),
        src: Value::Reg(crate::ir::types::packed_dword_lane(&src, 0)),
    }];
    out.extend((1..4).map(|lane| Op::Bin {
        dst: dst.clone(),
        op: BinOp::Add,
        lhs: Value::Reg(dst.clone()),
        rhs: Value::Reg(crate::ir::types::packed_dword_lane(&src, lane)),
    }));
    Some(out)
}

fn numbered_register(name: &str, prefix: char, max: u8) -> bool {
    name.strip_prefix(prefix)
        .is_some_and(|index| index.parse::<u8>().is_ok_and(|index| index <= max))
}

fn scalar_dword_lane(register: &VReg) -> Option<VReg> {
    let VReg::Phys(name) = register else {
        return None;
    };
    let index = name
        .strip_prefix('s')?
        .parse::<u8>()
        .ok()
        .filter(|index| *index <= 31)?;
    Some(crate::ir::types::packed_dword_lane(&format!("v{index}"), 0))
}

pub(super) fn scalar_fmov(ins: &Instruction) -> Option<Op> {
    if ins.operands.len() != 2 {
        return None;
    }
    let dst = operand_reg(&ins.operands[0])?;
    let src = operand_reg(&ins.operands[1])?;
    let VReg::Phys(name) = &dst else {
        return None;
    };
    numbered_register(name, 'w', 30).then_some(Op::Assign {
        dst,
        src: Value::Reg(scalar_dword_lane(&src)?),
    })
}

#[cfg(test)]
mod tests {
    use super::super::lift_bytes;
    use super::*;
    use crate::ir::types::LlirInstr;

    #[test]
    fn packed_dword_horizontal_sum_has_explicit_lane_semantics() {
        // GCC 15 -O2 `for_sum(const int *)`:
        //   ldp  q31, q30, [x0]
        //   add  v30.4s, v31.4s, v30.4s
        //   addv s31, v30.4s
        //   fmov w0, s31
        let out = lift_bytes(
            &[
                0x1f, 0x78, 0x40, 0xad, 0xfe, 0x87, 0xbe, 0x4e, 0xdf, 0xbb, 0xb1, 0x4e, 0xe0, 0x03,
                0x26, 0x1e, 0xc0, 0x03, 0x5f, 0xd6,
            ],
            0x8a0,
        );
        assert!(
            out.iter()
                .all(|instruction| !matches!(instruction.op, Op::Unknown { .. })),
            "the real reduction sequence retains opaque holes: {out:#?}"
        );

        let load_layout: Vec<_> = out
            .iter()
            .filter_map(|instruction| match &instruction.op {
                Op::Load { dst, addr } => Some((dst.clone(), addr.disp, addr.size)),
                _ => None,
            })
            .collect();
        assert_eq!(load_layout.len(), 8, "both Q registers need four lanes");
        assert_eq!(
            load_layout
                .iter()
                .map(|(_, disp, size)| (*disp, *size))
                .collect::<Vec<_>>(),
            (0..8).map(|lane| (lane * 4, 4)).collect::<Vec<_>>()
        );
        for register in ["v31", "v30"] {
            for lane in 0..4 {
                let lane_name = format!("{register}_d{lane}");
                assert!(
                    out.iter().any(|instruction| matches!(
                        &instruction.op,
                        Op::Load { dst: VReg::Phys(dst), .. } if dst == &lane_name
                    )),
                    "missing {lane_name}: {out:#?}"
                );
            }
        }
        for lane in 0..4 {
            let destination = format!("v30_d{lane}");
            let lhs = format!("v31_d{lane}");
            assert!(
                out.iter().any(|instruction| matches!(
                    &instruction.op,
                    Op::Bin {
                        dst: VReg::Phys(dst),
                        op: BinOp::Add,
                        lhs: Value::Reg(VReg::Phys(left)),
                        rhs: Value::Reg(VReg::Phys(right)),
                    } if dst == &destination && left == &lhs && right == &destination
                )),
                "lane {lane} is not added independently: {out:#?}"
            );
        }
        assert!(
            out.iter().any(|instruction| matches!(
                &instruction.op,
                Op::Bin { dst, op: BinOp::Add, .. } if *dst == VReg::phys("v31_d0")
            )),
            "ADDV does not define its scalar destination: {out:#?}"
        );
        assert!(
            out.iter().any(|instruction| matches!(
                &instruction.op,
                Op::Assign {
                    dst,
                    src: Value::Reg(src),
                } if *dst == VReg::phys("w0") && *src == VReg::phys("v31_d0")
            )),
            "FMOV does not carry the reduction into w0: {out:#?}"
        );
    }

    #[test]
    fn unsupported_qword_fmov_remains_fail_closed() {
        // The packed model in this slice proves 32-bit lanes only. Treating
        // D31 as an unrelated scalar can manufacture a false passing result.
        let out = lift_bytes(&0x9e6603e0u32.to_le_bytes(), 0x1000); // fmov x0,d31
        assert!(matches!(
            &out[..],
            [LlirInstr {
                op: Op::Unknown { mnemonic },
                ..
            }] if mnemonic == "fmov"
        ));
    }

    #[test]
    fn reverse_dword_fmov_remains_fail_closed() {
        // `fmov s31, w0` also defines the upper vector bits. This slice does
        // not model that write contract, so only the proven Wd <- Sn direction
        // is accepted.
        let out = lift_bytes(&0x1e27001fu32.to_le_bytes(), 0x1000);
        assert!(matches!(
            &out[..],
            [LlirInstr {
                op: Op::Unknown { mnemonic },
                ..
            }] if mnemonic == "fmov"
        ));
    }

    #[test]
    fn literal_q_load_keeps_all_four_dwords() {
        // Assembled `ldr q0, .+0x10` = 0x9c000080. Literal loads carry an
        // absolute immediate rather than a structured memory operand.
        let out = lift_bytes(&0x9c000080u32.to_le_bytes(), 0x1000);
        let layout: Vec<_> = out
            .iter()
            .filter_map(|instruction| match &instruction.op {
                Op::Load { dst, addr } => Some((dst.clone(), addr.clone())),
                _ => None,
            })
            .collect();
        assert_eq!(layout.len(), 4, "literal Q load lost lanes: {out:#?}");
        for (lane, (dst, addr)) in layout.iter().enumerate() {
            assert_eq!(*dst, crate::ir::types::packed_dword_lane("v0", lane));
            assert_eq!(addr.base, None);
            assert_eq!(addr.disp, 0x1010 + (lane * 4) as i64);
            assert_eq!(addr.size, 4);
        }
    }
}
