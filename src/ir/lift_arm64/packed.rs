//! AArch64 packed-lane lowering into the shared scalar LLIR.
//!
//! Vector operands retain their decoded lane shape, but downstream dataflow
//! stays architecture-neutral: each packed dword is an ordinary 32-bit virtual
//! register. This is the same representation used by the x86 SIMD lifter.

use crate::core::instruction::Instruction;
use crate::ir::types::{BinOp, CmpOp, Endian, MemOp, Op, VReg, Value, Width};

use super::{instruction_word, operand_reg, operand_to_memop, scaled_memop, temp_for};

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

fn dword_register_triplet(ins: &Instruction) -> Option<(String, String, String)> {
    if ins.operands.len() != 3 {
        return None;
    }
    if ins.operands.iter().any(|operand| {
        !operand
            .vector_shape
            .is_some_and(|shape| (shape.lanes, shape.element_bits) == (4, 32))
    }) {
        return None;
    }
    let dst = vector_name(&operand_reg(&ins.operands[0])?)?;
    let lhs = vector_name(&operand_reg(&ins.operands[1])?)?;
    let rhs = vector_name(&operand_reg(&ins.operands[2])?)?;
    Some((dst, lhs, rhs))
}

fn dword_register_pair(ins: &Instruction) -> Option<(String, String)> {
    if ins.operands.len() != 2
        || ins.operands.iter().any(|operand| {
            !operand
                .vector_shape
                .is_some_and(|shape| (shape.lanes, shape.element_bits) == (4, 32))
        })
    {
        return None;
    }
    let dst = vector_name(&operand_reg(&ins.operands[0])?)?;
    let src = vector_name(&operand_reg(&ins.operands[1])?)?;
    Some((dst, src))
}

pub(super) fn dword_binary(ins: &Instruction, op: BinOp) -> Option<Vec<Op>> {
    let (dst, lhs, rhs) = dword_register_triplet(ins)?;
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

/// Broadcast an exact unshifted immediate into every dword lane.
///
/// AArch64's other modified-immediate forms may shift or replicate the encoded
/// immediate. The raw `cmode` check keeps those forms opaque until the operand
/// representation carries their modifier explicitly.
pub(super) fn dword_immediate_splat(ins: &Instruction, inverted: bool) -> Option<Vec<Op>> {
    if ins.operands.len() != 2 {
        return None;
    }
    let shape = ins.operands[0].vector_shape?;
    if (shape.lanes, shape.element_bits) != (4, 32) {
        return None;
    }
    // Advanced-SIMD modified-immediate encodings reuse the same decoded
    // immediate for shifted and replicated forms. Only cmode=0000 is the exact
    // unshifted 32-bit splat represented by our structured operands.
    let word = instruction_word(ins)?;
    if ((word >> 12) & 0xf) != 0 || ((word >> 11) & 1) != 0 {
        return None;
    }
    let immediate = ins.operands[1].immediate?;
    if !(0..=u8::MAX.into()).contains(&immediate) {
        return None;
    }
    let value = if inverted {
        i64::from(!u32::try_from(immediate).ok()?)
    } else {
        immediate
    };
    let dst = vector_name(&operand_reg(&ins.operands[0])?)?;
    Some(
        (0..4)
            .map(|lane| Op::Assign {
                dst: crate::ir::types::packed_dword_lane(&dst, lane),
                src: Value::Const(value),
            })
            .collect(),
    )
}

/// Broadcast a general-purpose 32-bit value into every 4S lane.
pub(super) fn dword_duplicate(ins: &Instruction) -> Option<Vec<Op>> {
    if ins.operands.len() != 2
        || !ins.operands[0]
            .vector_shape
            .is_some_and(|shape| (shape.lanes, shape.element_bits) == (4, 32))
    {
        return None;
    }
    let dst = vector_name(&operand_reg(&ins.operands[0])?)?;
    let src = operand_reg(&ins.operands[1])?;
    let VReg::Phys(name) = &src else {
        return None;
    };
    if !numbered_register(name, 'w', 30) {
        return None;
    }
    Some(
        (0..4)
            .map(|lane| Op::Assign {
                dst: crate::ir::types::packed_dword_lane(&dst, lane),
                src: Value::Reg(src.clone()),
            })
            .collect(),
    )
}

/// Per-lane two's-complement negation for the 4S arrangement.
pub(super) fn dword_negate(ins: &Instruction) -> Option<Vec<Op>> {
    let (dst, src) = dword_register_pair(ins)?;
    Some(
        (0..4)
            .map(|lane| Op::Un {
                dst: crate::ir::types::packed_dword_lane(&dst, lane),
                op: crate::ir::types::UnOp::Neg,
                src: Value::Reg(crate::ir::types::packed_dword_lane(&src, lane)),
            })
            .collect(),
    )
}

/// AArch64 USHL with a signed per-lane shift count.
///
/// The shared scalar AST lowers this named operation with guarded unsigned
/// shifts, including the architectural zero result when the magnitude is at
/// least the lane width. One intrinsic per lane keeps ordinary SSA exact.
pub(super) fn dword_unsigned_shift(ins: &Instruction) -> Option<Vec<Op>> {
    let (dst, value, count) = dword_register_triplet(ins)?;
    Some(
        (0..4)
            .map(|lane| Op::Intrinsic {
                name: "packed_signed_shift_u32".to_string(),
                ins: vec![
                    Value::Reg(crate::ir::types::packed_dword_lane(&value, lane)),
                    Value::Reg(crate::ir::types::packed_dword_lane(&count, lane)),
                ],
                outs: vec![(crate::ir::types::packed_dword_lane(&dst, lane), Width::W32)],
                reads_mem: false,
                writes_mem: false,
            })
            .collect(),
    )
}

/// Per-lane compare-and-mask for `CMTST Vd.4S,Vn.4S,Vm.4S`.
pub(super) fn dword_compare_test(ins: &Instruction) -> Option<Vec<Op>> {
    let (dst, lhs, rhs) = dword_register_triplet(ins)?;
    let mut out = Vec::with_capacity(12);
    for lane in 0..4 {
        let tested = temp_for(ins, lane as u32);
        let nonzero = temp_for(ins, 4 + lane as u32);
        out.push(Op::Bin {
            dst: tested.clone(),
            op: BinOp::And,
            lhs: Value::Reg(crate::ir::types::packed_dword_lane(&lhs, lane)),
            rhs: Value::Reg(crate::ir::types::packed_dword_lane(&rhs, lane)),
        });
        out.push(Op::Cmp {
            dst: nonzero.clone(),
            op: CmpOp::Ne,
            lhs: Value::Reg(tested),
            rhs: Value::Const(0),
        });
        out.push(Op::Ite {
            dst: crate::ir::types::packed_dword_lane(&dst, lane),
            cond: nonzero,
            t: Value::Const(i64::from(u32::MAX)),
            e: Value::Const(0),
            width: Width::W32,
        });
    }
    Some(out)
}

/// Pairwise unsigned maximum across two 4S inputs.
///
/// Snapshot all eight inputs before defining any destination lane: UMAXP reads
/// adjacent lanes and commonly aliases its destination with both sources.
pub(super) fn dword_pairwise_unsigned_max(ins: &Instruction) -> Option<Vec<Op>> {
    let (dst, lhs, rhs) = dword_register_triplet(ins)?;
    let mut out = Vec::with_capacity(20);
    let lhs_snapshot: Vec<_> = (0..4).map(|lane| temp_for(ins, lane)).collect();
    let rhs_snapshot: Vec<_> = (0..4).map(|lane| temp_for(ins, 4 + lane)).collect();
    for lane in 0..4 {
        out.push(Op::Assign {
            dst: lhs_snapshot[lane].clone(),
            src: Value::Reg(crate::ir::types::packed_dword_lane(&lhs, lane)),
        });
        out.push(Op::Assign {
            dst: rhs_snapshot[lane].clone(),
            src: Value::Reg(crate::ir::types::packed_dword_lane(&rhs, lane)),
        });
    }
    for lane in 0..4 {
        let source = if lane < 2 {
            &lhs_snapshot
        } else {
            &rhs_snapshot
        };
        let pair = (lane % 2) * 2;
        let less = temp_for(ins, 8 + lane as u32);
        out.push(Op::Cmp {
            dst: less.clone(),
            op: CmpOp::Ult,
            lhs: Value::Reg(source[pair].clone()),
            rhs: Value::Reg(source[pair + 1].clone()),
        });
        out.push(Op::Ite {
            dst: crate::ir::types::packed_dword_lane(&dst, lane),
            cond: less,
            t: Value::Reg(source[pair + 1].clone()),
            e: Value::Reg(source[pair].clone()),
            width: Width::W32,
        });
    }
    Some(out)
}

/// Signed per-lane maximum for the 4S vector arrangement.
pub(super) fn dword_signed_max(ins: &Instruction) -> Option<Vec<Op>> {
    let (dst, lhs, rhs) = dword_register_triplet(ins)?;
    let mut out = Vec::with_capacity(8);
    for lane in 0..4 {
        let dst = crate::ir::types::packed_dword_lane(&dst, lane);
        let lhs = crate::ir::types::packed_dword_lane(&lhs, lane);
        let rhs = crate::ir::types::packed_dword_lane(&rhs, lane);
        let condition = temp_for(ins, lane as u32);
        out.push(Op::Cmp {
            dst: condition.clone(),
            op: CmpOp::Slt,
            lhs: Value::Reg(lhs.clone()),
            rhs: Value::Reg(rhs.clone()),
        });
        out.push(Op::Ite {
            dst,
            cond: condition,
            t: Value::Reg(rhs),
            e: Value::Reg(lhs),
            width: Width::W32,
        });
    }
    Some(out)
}

/// One-register AArch64 `TBL` as four architecture-neutral dword results.
///
/// The semantic intrinsic consumes four snapshotted table dwords and one index
/// dword. Emitting one single-output intrinsic per result lane keeps the ordinary
/// def/use and SSA model exact; snapshotting both inputs first is required when
/// the destination aliases either the table or index vector.
pub(super) fn byte_table_16(ins: &Instruction) -> Option<Vec<Op>> {
    if ins.operands.len() != 3
        || ins.operands.iter().any(|operand| {
            !operand
                .vector_shape
                .is_some_and(|shape| (shape.lanes, shape.element_bits) == (16, 8))
        })
    {
        return None;
    }
    let dst = vector_name(&operand_reg(&ins.operands[0])?)?;
    let table = vector_name(&operand_reg(&ins.operands[1])?)?;
    let indices = vector_name(&operand_reg(&ins.operands[2])?)?;

    let mut out = Vec::with_capacity(12);
    let table_snapshot: Vec<_> = (0..4).map(|lane| temp_for(ins, lane)).collect();
    let index_snapshot: Vec<_> = (0..4).map(|lane| temp_for(ins, 4 + lane)).collect();
    for lane in 0..4 {
        out.push(Op::Assign {
            dst: table_snapshot[lane].clone(),
            src: Value::Reg(crate::ir::types::packed_dword_lane(&table, lane)),
        });
        out.push(Op::Assign {
            dst: index_snapshot[lane].clone(),
            src: Value::Reg(crate::ir::types::packed_dword_lane(&indices, lane)),
        });
    }
    for lane in 0..4 {
        let mut inputs: Vec<_> = table_snapshot.iter().cloned().map(Value::Reg).collect();
        inputs.push(Value::Reg(index_snapshot[lane].clone()));
        out.push(Op::Intrinsic {
            name: "packed_byte_table_16".to_string(),
            ins: inputs,
            outs: vec![(crate::ir::types::packed_dword_lane(&dst, lane), Width::W32)],
            reads_mem: false,
            writes_mem: false,
        });
    }
    Some(out)
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

pub(super) fn scalar_fmov(ins: &Instruction) -> Option<Vec<Op>> {
    if ins.operands.len() != 2 {
        return None;
    }
    let dst = operand_reg(&ins.operands[0])?;
    let src = operand_reg(&ins.operands[1])?;
    let VReg::Phys(name) = &dst else {
        return None;
    };
    if numbered_register(name, 'w', 30) {
        return Some(vec![Op::Assign {
            dst,
            src: Value::Reg(scalar_dword_lane(&src)?),
        }]);
    }
    if !numbered_register(name, 'x', 30) {
        return None;
    }
    let VReg::Phys(src_name) = &src else {
        return None;
    };
    let index = src_name
        .strip_prefix('d')?
        .parse::<u8>()
        .ok()
        .filter(|index| *index <= 31)?;
    let vector = format!("v{index}");
    let low = temp_for(ins, 0);
    let high = temp_for(ins, 1);
    Some(vec![
        Op::ZExt {
            dst: low.clone(),
            src: Value::Reg(crate::ir::types::packed_dword_lane(&vector, 0)),
            from: Width::W32,
            to: Width::W64,
        },
        Op::ZExt {
            dst: high.clone(),
            src: Value::Reg(crate::ir::types::packed_dword_lane(&vector, 1)),
            from: Width::W32,
            to: Width::W64,
        },
        Op::Bin {
            dst: high.clone(),
            op: BinOp::Shl,
            lhs: Value::Reg(high.clone()),
            rhs: Value::Const(32),
        },
        Op::Bin {
            dst,
            op: BinOp::Or,
            lhs: Value::Reg(low),
            rhs: Value::Reg(high),
        },
    ])
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
    fn packed_signed_max_sequence_keeps_negative_lanes_out_of_the_sum() {
        // GCC 15 -O2 `loop_continue(const int *)` replaces the source loop with:
        //   ldp  q31, q29, [x0]
        //   movi v30.4s, #0
        //   smax v31.4s, v31.4s, v30.4s
        //   smax v29.4s, v29.4s, v30.4s
        //   add  v29.4s, v31.4s, v29.4s
        //   addv s31, v29.4s
        //   fmov w0, s31
        let out = lift_bytes(
            &[
                0x1f, 0x74, 0x40, 0xad, 0x1e, 0x04, 0x00, 0x4f, 0xff, 0x67, 0xbe, 0x4e, 0xbd, 0x67,
                0xbe, 0x4e, 0xfd, 0x87, 0xbd, 0x4e, 0xbf, 0xbb, 0xb1, 0x4e, 0xe0, 0x03, 0x26, 0x1e,
                0xc0, 0x03, 0x5f, 0xd6,
            ],
            0xac8,
        );
        assert!(
            out.iter()
                .all(|instruction| !matches!(instruction.op, Op::Unknown { .. })),
            "the real signed-lane reduction retains opaque holes: {out:#?}"
        );

        for lane in 0..4 {
            let zero = crate::ir::types::packed_dword_lane("v30", lane);
            assert!(
                out.iter().any(|instruction| matches!(
                    &instruction.op,
                    Op::Assign { dst, src: Value::Const(0) } if dst == &zero
                )),
                "MOVI did not define zero in lane {lane}: {out:#?}"
            );
        }
        assert_eq!(
            out.iter()
                .filter(|instruction| matches!(
                    instruction.op,
                    Op::Cmp {
                        op: crate::ir::types::CmpOp::Slt,
                        ..
                    }
                ))
                .count(),
            8,
            "each SMAX needs one signed comparison per lane: {out:#?}"
        );
        assert_eq!(
            out.iter()
                .filter(|instruction| matches!(
                    instruction.op,
                    Op::Ite {
                        width: crate::ir::types::Width::W32,
                        ..
                    }
                ))
                .count(),
            8,
            "each signed comparison must select one complete lane value: {out:#?}"
        );
    }

    #[test]
    fn packed_find_first_set_prescan_has_no_opaque_or_whole_vector_steps() {
        // GCC 15 -O2 `find_first_set(unsigned)` vectorizes its outer scan:
        //   dup   v27.4s, w0
        //   movi  v28.4s, #1
        //   movi  v25.4s, #4
        //   mvni  v26.4s, #3
        //   neg   v31.4s, v30.4s
        //   ushl  v31.4s, v27.4s, v31.4s
        //   cmtst v31.4s, v31.4s, v28.4s
        //   umaxp v31.4s, v31.4s, v31.4s
        //   fmov  x0, d31
        // Every operation participates in the branch selecting the scalar
        // fallback window. Dropping even one produces a plausible loop with
        // undefined bounds rather than the machine's result.
        let out = lift_bytes(
            &[
                0x1b, 0x0c, 0x04, 0x4e, 0x3c, 0x04, 0x00, 0x4f, 0x99, 0x04, 0x00, 0x4f, 0x7a, 0x04,
                0x00, 0x6f, 0xdf, 0xbb, 0xa0, 0x6e, 0x7f, 0x47, 0xbf, 0x6e, 0xff, 0x8f, 0xbc, 0x4e,
                0xff, 0xa7, 0xbf, 0x6e, 0xe0, 0x03, 0x66, 0x9e,
            ],
            0x780,
        );

        assert!(
            out.iter()
                .all(|instruction| !matches!(instruction.op, Op::Unknown { .. })),
            "the real prescan sequence retains opaque holes: {out:#?}"
        );
        assert!(
            out.iter().all(|instruction| {
                let (defs, uses) = crate::ir::use_def::def_uses(&instruction.op);
                defs.into_iter()
                    .chain(uses)
                    .all(|register| vector_name(&register).is_none())
            }),
            "packed operations escaped as whole-vector scalar values: {out:#?}"
        );
    }

    #[test]
    fn packed_byte_table_sequence_declares_every_input_and_output_lane() {
        // GCC 15 -O2 `mutate_reverse(int *)` uses a read-only byte-index vector
        // and two one-table TBL operations to reverse the eight dwords:
        //   adrp x1, mask_page
        //   ldp  q31, q30, [x0]
        //   ldr  q29, [x1, mask_offset]
        //   tbl  v30.16b, {v30.16b}, v29.16b
        //   tbl  v29.16b, {v31.16b}, v29.16b
        //   stp  q30, q29, [x0]
        let out = lift_bytes(
            &[
                0x01, 0x00, 0x00, 0x90, 0x1f, 0x78, 0x40, 0xad, 0x3d, 0x18, 0xc3, 0x3d, 0xde, 0x03,
                0x1d, 0x4e, 0xfd, 0x03, 0x1d, 0x4e, 0x1e, 0x74, 0x00, 0xad, 0xc0, 0x03, 0x5f, 0xd6,
            ],
            0xc28,
        );
        assert!(
            out.iter()
                .all(|instruction| !matches!(instruction.op, Op::Unknown { .. })),
            "the real byte-table permutation retains opaque holes: {out:#?}"
        );
        let table_outputs: Vec<_> = out
            .iter()
            .filter_map(|instruction| match &instruction.op {
                Op::Intrinsic {
                    name,
                    ins,
                    outs,
                    reads_mem,
                    writes_mem,
                } if name == "packed_byte_table_16" => {
                    Some((ins.len(), outs.clone(), *reads_mem, *writes_mem))
                }
                _ => None,
            })
            .collect();
        assert_eq!(table_outputs.len(), 8, "each TBL defines four dwords");
        assert!(table_outputs
            .iter()
            .all(|(inputs, outputs, reads, writes)| {
                *inputs == 5
                    && outputs.len() == 1
                    && outputs[0].1 == Width::W32
                    && !reads
                    && !writes
            }));
    }

    #[test]
    fn qword_fmov_joins_the_two_low_dword_lanes() {
        // D31 is the low 64-bit view of V31, not unrelated scalar storage.
        let out = lift_bytes(&0x9e6603e0u32.to_le_bytes(), 0x1000); // fmov x0,d31
        assert_eq!(out.len(), 4, "the lane join changed shape: {out:#?}");
        assert!(matches!(
            &out[0].op,
            Op::ZExt {
                src: Value::Reg(src),
                from: Width::W32,
                to: Width::W64,
                ..
            } if *src == VReg::phys("v31_d0")
        ));
        assert!(matches!(
            &out[1].op,
            Op::ZExt {
                src: Value::Reg(src),
                from: Width::W32,
                to: Width::W64,
                ..
            } if *src == VReg::phys("v31_d1")
        ));
        assert!(matches!(
            &out[3].op,
            Op::Bin {
                dst,
                op: BinOp::Or,
                ..
            } if *dst == VReg::phys("x0")
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
