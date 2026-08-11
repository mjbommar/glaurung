//! Bit-level demand evidence over SSA values.
//!
//! Register SSA deliberately versions canonical storage (for example AArch64
//! `w12` and `x12`) as one value.  That is the right whole-register model, but
//! partial updates such as `BFI` preserve lanes that a function may never
//! observe.  Treating every syntactic read as a whole-value read then invents
//! live-in values and, after leaving SSA, uninitialised C locals.
//!
//! This module keeps the LLIR unchanged and computes a side-car proof: which
//! bits of every SSA value, and of every individual use, can reach an observable
//! effect.  Rewrites consume that proof and remain deliberately narrow.  An
//! unknown operation or width expands demand rather than guessing, so failure
//! loses an optimisation instead of changing program behaviour.

use std::collections::{HashMap, HashSet};

use crate::ir::abi;
use crate::ir::call_args::CallConv;
use crate::ir::ssa::{SsaInfo, SsaValue};
use crate::ir::types::{BinOp, LlirFunction, Op, UnOp, VReg, Value, Width};
use crate::ir::use_def::{def_uses, InstrAddr};

const FULL: u64 = u64::MAX;

/// Backward bit-demand facts keyed by stable SSA and instruction identities.
#[derive(Debug, Default, Clone)]
pub struct BitDemandOracle {
    values: HashMap<SsaValue, u64>,
    uses: HashMap<(InstrAddr, usize), u64>,
}

impl BitDemandOracle {
    /// Compute a conservative backward demand fixed point.
    pub fn analyze(function: &LlirFunction, ssa: &SsaInfo, cc: CallConv) -> Self {
        let mut oracle = Self::default();
        let has_unresolved_return = function
            .blocks
            .iter()
            .flat_map(|block| &block.instrs)
            .any(|instruction| matches!(instruction.op, Op::Return | Op::CondReturn { .. }));
        let va_to_idx = has_unresolved_return.then(|| {
            function
                .blocks
                .iter()
                .enumerate()
                .map(|(index, block)| (block.start_va, index))
                .collect::<HashMap<_, _>>()
        });

        // Memory/control/call operands are observable independently of whether
        // the operation defines a subsequently-used register.
        for (block_idx, block) in function.blocks.iter().enumerate() {
            for (instr_idx, instruction) in block.instrs.iter().enumerate() {
                let addr = InstrAddr {
                    block_idx,
                    instr_idx,
                };
                if has_observable_uses(&instruction.op) {
                    let (_, uses) = def_uses(&instruction.op);
                    for use_index in 0..uses.len() {
                        oracle.demand_use(function, ssa, addr, use_index, FULL);
                    }
                }

                // An unresolved machine return still lacks an operand. Demand
                // only result-bank definitions which can actually reach one;
                // an overwritten scratch lifetime is not observable. Direct
                // outputs use `ReturnValue` and follow the ordinary use edge
                // above, so this compatibility path disappears as prototype
                // coverage grows.
                if let (Some(va_to_idx), Some(value)) =
                    (va_to_idx.as_ref(), ssa.def_value(function, addr))
                {
                    if let VReg::Phys(name) = &value.base {
                        if let Some(class) = abi::return_register_class(cc, name) {
                            if crate::ir::value_number::def_reaches_unresolved_return(
                                function, class, va_to_idx, block_idx, instr_idx,
                            ) {
                                oracle.demand_value(value, FULL);
                            }
                        }
                    }
                }
            }
        }

        loop {
            let mut changed = false;

            for phi in &ssa.phis {
                let dst = SsaValue {
                    base: phi.base.clone(),
                    version: phi.dst_version,
                };
                let demanded = oracle.value_demand(&dst);
                if demanded == 0 {
                    continue;
                }
                for (_, version) in &phi.incoming {
                    changed |= oracle.demand_value(
                        SsaValue {
                            base: phi.base.clone(),
                            version: *version,
                        },
                        demanded,
                    );
                }
            }

            for (block_idx, block) in function.blocks.iter().enumerate() {
                for (instr_idx, instruction) in block.instrs.iter().enumerate() {
                    let addr = InstrAddr {
                        block_idx,
                        instr_idx,
                    };
                    let Some(dst) = ssa.def_value(function, addr) else {
                        continue;
                    };
                    let demanded = oracle.value_demand(&dst);
                    if demanded == 0 {
                        continue;
                    }
                    for (use_index, mask) in transfer_masks(&instruction.op, demanded) {
                        changed |= oracle.demand_use(function, ssa, addr, use_index, mask);
                    }
                }
            }

            if !changed {
                break;
            }
        }

        oracle
    }

    /// Bits of `value` that may reach an observable effect.
    pub fn value_demand(&self, value: &SsaValue) -> u64 {
        self.values.get(value).copied().unwrap_or(0)
    }

    /// Bits demanded from one source-order use of an instruction.
    pub fn use_demand(&self, addr: InstrAddr, use_index: usize) -> u64 {
        self.uses.get(&(addr, use_index)).copied().unwrap_or(0)
    }

    fn demand_value(&mut self, value: SsaValue, mask: u64) -> bool {
        if mask == 0 {
            return false;
        }
        let demanded = self.values.entry(value).or_default();
        let before = *demanded;
        *demanded |= mask;
        *demanded != before
    }

    fn demand_use(
        &mut self,
        function: &LlirFunction,
        ssa: &SsaInfo,
        addr: InstrAddr,
        use_index: usize,
        mask: u64,
    ) -> bool {
        if mask == 0 {
            return false;
        }
        let demanded = self.uses.entry((addr, use_index)).or_default();
        let before = *demanded;
        *demanded |= mask;
        let mut changed = *demanded != before;
        if let Some(value) = ssa.use_value(function, addr, use_index) {
            changed |= self.demand_value(value, mask);
        }
        changed
    }
}

/// Replace only a proof-dead register input of a constant mask operation.
///
/// This is the machine-independent shape emitted for preserved lanes in BFI,
/// sub-register writes, and packed-lane inserts.  A zero-demand input cannot
/// affect any observable bit, but replacing other pure dead expressions would
/// create unnecessary textual churn, so this pass intentionally stops here.
pub fn erase_unobserved_masked_inputs(
    function: &mut LlirFunction,
    ssa: &SsaInfo,
    oracle: &BitDemandOracle,
) -> usize {
    let demanded_definitions: HashSet<InstrAddr> = ssa
        .def_versions
        .keys()
        .copied()
        .filter(|addr| {
            ssa.def_value(function, *addr)
                .is_some_and(|value| oracle.value_demand(&value) != 0)
        })
        .collect();
    let mut rewritten = 0;
    for (block_idx, block) in function.blocks.iter_mut().enumerate() {
        for (instr_idx, instruction) in block.instrs.iter_mut().enumerate() {
            let addr = InstrAddr {
                block_idx,
                instr_idx,
            };
            if !demanded_definitions.contains(&addr) {
                continue;
            }
            let Op::Bin {
                op: BinOp::And,
                lhs,
                rhs,
                ..
            } = &mut instruction.op
            else {
                continue;
            };

            let lhs_is_reg = matches!(lhs, Value::Reg(_));
            let rhs_is_reg = matches!(rhs, Value::Reg(_));
            let lhs_use = lhs_is_reg.then_some(0);
            let rhs_use = rhs_is_reg.then_some(usize::from(lhs_is_reg));

            if matches!(rhs, Value::Const(_))
                && lhs_use.is_some_and(|index| oracle.use_demand(addr, index) == 0)
            {
                *lhs = Value::Const(0);
                rewritten += 1;
            }
            if matches!(lhs, Value::Const(_))
                && rhs_use.is_some_and(|index| oracle.use_demand(addr, index) == 0)
            {
                *rhs = Value::Const(0);
                rewritten += 1;
            }
        }
    }
    rewritten
}

fn has_observable_uses(op: &Op) -> bool {
    matches!(
        op,
        Op::Load { .. }
            | Op::CondLoad { .. }
            | Op::Store { .. }
            | Op::CondStore { .. }
            | Op::IndirectJump { .. }
            | Op::CondJump { .. }
            | Op::CondReturn { .. }
            | Op::CondReturnValue { .. }
            | Op::ReturnValue { .. }
            | Op::Call { .. }
            | Op::Intrinsic { .. }
    )
}

fn transfer_masks(op: &Op, demanded: u64) -> Vec<(usize, u64)> {
    let mut masks = Vec::new();
    let mut use_index = 0;

    fn value(masks: &mut Vec<(usize, u64)>, use_index: &mut usize, operand: &Value, mask: u64) {
        if matches!(operand, Value::Reg(_)) {
            masks.push((*use_index, mask));
            *use_index += 1;
        }
    }

    match op {
        Op::Assign { src, .. } => value(&mut masks, &mut use_index, src, demanded),
        Op::Bin { op, lhs, rhs, .. } => {
            let lhs_mask = bin_operand_mask(*op, lhs, rhs, demanded, true);
            let rhs_mask = bin_operand_mask(*op, rhs, lhs, demanded, false);
            value(&mut masks, &mut use_index, lhs, lhs_mask);
            value(&mut masks, &mut use_index, rhs, rhs_mask);
        }
        Op::Un { op, src, .. } => value(
            &mut masks,
            &mut use_index,
            src,
            match op {
                UnOp::Not => demanded,
                UnOp::Neg => dependency_prefix(demanded),
            },
        ),
        Op::Cmp { lhs, rhs, .. } => {
            value(&mut masks, &mut use_index, lhs, FULL);
            value(&mut masks, &mut use_index, rhs, FULL);
        }
        Op::ZExt { src, from, .. } | Op::Trunc { src, from, .. } => value(
            &mut masks,
            &mut use_index,
            src,
            demanded & width_mask(*from),
        ),
        Op::SExt { src, from, .. } => {
            let low = demanded & width_mask(*from);
            let high = demanded & !width_mask(*from);
            let sign = if high != 0 && from.bits() != 0 && from.bits() <= 64 {
                1_u64 << (from.bits() - 1)
            } else {
                0
            };
            value(&mut masks, &mut use_index, src, low | sign);
        }
        Op::Extract { src, lo, .. } => value(
            &mut masks,
            &mut use_index,
            src,
            if *lo < 64 { demanded << *lo } else { FULL },
        ),
        Op::Concat { hi, lo, .. } => {
            // Concat does not yet carry operand widths.  Keep both operands
            // whole until that missing type evidence exists.
            value(&mut masks, &mut use_index, hi, FULL);
            value(&mut masks, &mut use_index, lo, FULL);
        }
        Op::Ite { cond: _, t, e, .. } => {
            masks.push((0, FULL));
            use_index = 1;
            value(&mut masks, &mut use_index, t, demanded);
            value(&mut masks, &mut use_index, e, demanded);
        }
        // Observable operands were seeded before the fixed point.  Loads and
        // calls may also define a result, but its demand does not change their
        // already-conservative inputs.
        Op::Undef { .. }
        | Op::Load { .. }
        | Op::CondLoad { .. }
        | Op::Store { .. }
        | Op::CondStore { .. }
        | Op::IndirectJump { .. }
        | Op::Jump { .. }
        | Op::CondJump { .. }
        | Op::CondReturn { .. }
        | Op::CondReturnValue { .. }
        | Op::Call { .. }
        | Op::ReturnValue { .. }
        | Op::Return
        | Op::Nop
        | Op::Intrinsic { .. }
        | Op::Unknown { .. } => {}
    }
    masks
}

fn bin_operand_mask(op: BinOp, operand: &Value, other: &Value, demanded: u64, is_lhs: bool) -> u64 {
    match op {
        BinOp::And => match other {
            Value::Const(mask) => demanded & (*mask as u64),
            _ => demanded,
        },
        BinOp::Or => match other {
            Value::Const(bits) => demanded & !(*bits as u64),
            _ => demanded,
        },
        BinOp::Xor => demanded,
        BinOp::Shl if is_lhs => constant_shift(other)
            .map(|shift| if shift < 64 { demanded >> shift } else { FULL })
            .unwrap_or(FULL),
        BinOp::Shr if is_lhs => constant_shift(other)
            .map(|shift| if shift < 64 { demanded << shift } else { FULL })
            .unwrap_or(FULL),
        BinOp::Shl | BinOp::Shr | BinOp::Sar if !is_lhs => {
            if matches!(operand, Value::Reg(_)) {
                FULL
            } else {
                0
            }
        }
        BinOp::Shl | BinOp::Shr => FULL,
        BinOp::Sar => FULL,
        BinOp::Add | BinOp::Sub | BinOp::Mul => dependency_prefix(demanded),
        BinOp::Div | BinOp::LogicalAnd | BinOp::LogicalOr => FULL,
    }
}

fn constant_shift(value: &Value) -> Option<u32> {
    match value {
        Value::Const(shift) if *shift >= 0 => u32::try_from(*shift).ok(),
        _ => None,
    }
}

fn dependency_prefix(mask: u64) -> u64 {
    if mask == 0 {
        0
    } else {
        let highest = u64::BITS - mask.leading_zeros();
        FULL.checked_shr(u64::BITS - highest).unwrap_or(FULL)
    }
}

fn width_mask(width: Width) -> u64 {
    match width.bits() {
        0 => 0,
        bits if bits < 64 => (1_u64 << bits) - 1,
        _ => FULL,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::ssa::compute_ssa;
    use crate::ir::types::{Flag, LlirBlock, LlirInstr};

    fn instruction(va: u64, op: Op) -> LlirInstr {
        LlirInstr { va, op }
    }

    #[test]
    fn preserved_bfi_lane_is_not_a_live_in_when_only_inserted_lane_is_observed() {
        // entry -> loop; loop writes x12 and either repeats or exits to use.
        // This is the architecture-independent LLIR shape of
        //   bfi x12, x4, #32, #32; lsr x0, x12, #32
        let mut function = LlirFunction {
            entry_va: 0x1000,
            blocks: vec![
                LlirBlock {
                    start_va: 0x1000,
                    end_va: 0x1004,
                    instrs: vec![],
                    succs: vec![0x1010],
                },
                LlirBlock {
                    start_va: 0x1010,
                    end_va: 0x1020,
                    instrs: vec![
                        instruction(
                            0x1010,
                            Op::Bin {
                                dst: VReg::Temp(0),
                                op: BinOp::And,
                                lhs: Value::Reg(VReg::phys("x12")),
                                rhs: Value::Const(0xffff_ffff),
                            },
                        ),
                        instruction(
                            0x1014,
                            Op::Bin {
                                dst: VReg::phys("x12"),
                                op: BinOp::Or,
                                lhs: Value::Reg(VReg::Temp(0)),
                                rhs: Value::Const(0x1_0000_0000),
                            },
                        ),
                    ],
                    succs: vec![0x1010, 0x1020],
                },
                LlirBlock {
                    start_va: 0x1020,
                    end_va: 0x1028,
                    instrs: vec![
                        instruction(
                            0x1020,
                            Op::Bin {
                                dst: VReg::phys("x0"),
                                op: BinOp::Shr,
                                lhs: Value::Reg(VReg::phys("x12")),
                                rhs: Value::Const(32),
                            },
                        ),
                        instruction(0x1024, Op::Return),
                    ],
                    succs: vec![],
                },
            ],
        };

        let initial_ssa = compute_ssa(&function);
        let oracle = BitDemandOracle::analyze(&function, &initial_ssa, CallConv::Aarch64);
        let masked_use = InstrAddr {
            block_idx: 1,
            instr_idx: 0,
        };
        assert_eq!(oracle.use_demand(masked_use, 0), 0);
        assert_eq!(
            erase_unobserved_masked_inputs(&mut function, &initial_ssa, &oracle),
            1
        );
        assert!(matches!(
            function.blocks[1].instrs[0].op,
            Op::Bin {
                lhs: Value::Const(0),
                ..
            }
        ));

        let final_ssa = compute_ssa(&function);
        let (numbered, _, _) = crate::ir::value_number::value_number_with_parameter_slots(
            &function,
            &final_ssa,
            CallConv::Aarch64,
        );
        assert!(
            numbered
                .blocks
                .iter()
                .flat_map(|block| &block.instrs)
                .all(|instruction| !matches!(
                    &instruction.op,
                    Op::Assign {
                        src: Value::Reg(VReg::Phys(source)),
                        ..
                    } if source == "x12"
                )),
            "the dead preserved lane must not materialise a live-in phi copy"
        );
    }

    #[test]
    fn observed_preserved_lane_is_kept() {
        let function = LlirFunction {
            entry_va: 0x1000,
            blocks: vec![LlirBlock {
                start_va: 0x1000,
                end_va: 0x100c,
                instrs: vec![
                    instruction(
                        0x1000,
                        Op::Bin {
                            dst: VReg::phys("x12"),
                            op: BinOp::And,
                            lhs: Value::Reg(VReg::phys("x12")),
                            rhs: Value::Const(0xffff_ffff),
                        },
                    ),
                    instruction(
                        0x1004,
                        Op::Assign {
                            dst: VReg::phys("x0"),
                            src: Value::Reg(VReg::phys("x12")),
                        },
                    ),
                    instruction(0x1008, Op::Return),
                ],
                succs: vec![],
            }],
        };
        let ssa = compute_ssa(&function);
        let oracle = BitDemandOracle::analyze(&function, &ssa, CallConv::Aarch64);
        assert_eq!(
            oracle.use_demand(
                InstrAddr {
                    block_idx: 0,
                    instr_idx: 0,
                },
                0,
            ),
            0xffff_ffff
        );
    }

    #[test]
    fn overwritten_return_storage_is_not_an_observable_result() {
        let function = LlirFunction {
            entry_va: 0x1000,
            blocks: vec![LlirBlock {
                start_va: 0x1000,
                end_va: 0x100c,
                instrs: vec![
                    instruction(
                        0x1000,
                        Op::Assign {
                            dst: VReg::phys("x0"),
                            src: Value::Const(0x1111),
                        },
                    ),
                    instruction(
                        0x1004,
                        Op::Assign {
                            dst: VReg::phys("x0"),
                            src: Value::Const(0x2222),
                        },
                    ),
                    instruction(0x1008, Op::Return),
                ],
                succs: vec![],
            }],
        };
        let ssa = compute_ssa(&function);
        let oracle = BitDemandOracle::analyze(&function, &ssa, CallConv::Aarch64);
        let first = ssa
            .def_value(
                &function,
                InstrAddr {
                    block_idx: 0,
                    instr_idx: 0,
                },
            )
            .expect("first x0 definition");
        let second = ssa
            .def_value(
                &function,
                InstrAddr {
                    block_idx: 0,
                    instr_idx: 1,
                },
            )
            .expect("second x0 definition");

        assert_eq!(oracle.value_demand(&first), 0);
        assert_eq!(oracle.value_demand(&second), FULL);
    }

    #[test]
    fn unresolved_fallback_does_not_demand_another_result_bank_on_explicit_path() {
        let function = LlirFunction {
            entry_va: 0x1000,
            blocks: vec![
                LlirBlock {
                    start_va: 0x1000,
                    end_va: 0x1004,
                    instrs: vec![instruction(
                        0x1000,
                        Op::CondJump {
                            cond: VReg::phys("rdi"),
                            target: 0x1020,
                            inverted: false,
                        },
                    )],
                    succs: vec![0x1010, 0x1020],
                },
                LlirBlock {
                    start_va: 0x1010,
                    end_va: 0x1018,
                    instrs: vec![
                        instruction(
                            0x1010,
                            Op::Assign {
                                dst: VReg::phys("rax"),
                                src: Value::Const(0x1111),
                            },
                        ),
                        instruction(
                            0x1014,
                            Op::ReturnValue {
                                value: Value::Reg(VReg::phys("xmm0")),
                            },
                        ),
                    ],
                    succs: vec![],
                },
                LlirBlock {
                    start_va: 0x1020,
                    end_va: 0x1028,
                    instrs: vec![
                        instruction(
                            0x1020,
                            Op::Assign {
                                dst: VReg::phys("rax"),
                                src: Value::Const(0x2222),
                            },
                        ),
                        instruction(0x1024, Op::Return),
                    ],
                    succs: vec![],
                },
            ],
        };
        let ssa = compute_ssa(&function);
        let oracle = BitDemandOracle::analyze(&function, &ssa, CallConv::SysVAmd64);
        let explicit_path_scratch = ssa
            .def_value(
                &function,
                InstrAddr {
                    block_idx: 1,
                    instr_idx: 0,
                },
            )
            .expect("explicit-path rax scratch");
        let unresolved_path_result = ssa
            .def_value(
                &function,
                InstrAddr {
                    block_idx: 2,
                    instr_idx: 0,
                },
            )
            .expect("unresolved-path rax result");

        assert_eq!(oracle.value_demand(&explicit_path_scratch), 0);
        assert_eq!(oracle.value_demand(&unresolved_path_result), FULL);
    }

    #[test]
    fn byte_comparison_demands_only_the_architectural_byte_view() {
        // Optimized SysV callees commonly copy an incoming EDX parameter and
        // then observe only DL/R8B.  Register SSA correctly keeps those aliases
        // in one storage identity, but the bit-demand sidecar must retain the
        // exact architectural view or prototype recovery cannot distinguish a
        // source byte from an observed machine word.
        let function = LlirFunction {
            entry_va: 0x1000,
            blocks: vec![LlirBlock {
                start_va: 0x1000,
                end_va: 0x1010,
                instrs: vec![
                    instruction(
                        0x1000,
                        Op::Assign {
                            dst: VReg::phys("r8d"),
                            src: Value::Reg(VReg::phys("edx")),
                        },
                    ),
                    instruction(
                        0x1004,
                        Op::Bin {
                            dst: VReg::Temp(0),
                            op: BinOp::And,
                            lhs: Value::Reg(VReg::phys("r8")),
                            rhs: Value::Const(0xff),
                        },
                    ),
                    instruction(
                        0x1008,
                        Op::Cmp {
                            dst: VReg::Flag(Flag::Z),
                            op: crate::ir::types::CmpOp::Eq,
                            lhs: Value::Reg(VReg::Temp(0)),
                            rhs: Value::Const(0),
                        },
                    ),
                    instruction(
                        0x100c,
                        Op::CondJump {
                            cond: VReg::Flag(Flag::Z),
                            target: 0x1010,
                            inverted: false,
                        },
                    ),
                ],
                succs: vec![0x1010],
            }],
        };
        let ssa = compute_ssa(&function);
        let oracle = BitDemandOracle::analyze(&function, &ssa, CallConv::SysVAmd64);
        let input = SsaValue {
            base: VReg::phys("rdx"),
            version: 0,
        };

        assert_eq!(oracle.value_demand(&input), 0xff);
    }
}
