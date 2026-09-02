//! Width inference for SSA temporaries: the first CFR prerequisite.
//!
//! `VReg::width()` answers for a physical register (looked up by ISA name) and
//! for a flag (one bit), and returns `None` for `VReg::Temp` -- a temporary's
//! width "is not encoded in the name; it is tracked by the producing op". The
//! CFR node seed needs one, because width is the *only* thing a register
//! contributes to a label once its name is masked. A node with no width is a
//! node that says nothing.
//!
//! This is a **local** pass. It does not widen `VReg::Temp`, does not touch
//! `src/ir/`, and computes nothing the IR is expected to remember: it reads an
//! `LlirFunction` and its `SsaInfo` and produces a side table keyed by
//! [`SsaValue`].
//!
//! # The lattice and why it terminates
//!
//! A value's width starts absent and only ever moves to a known width, and a
//! known width only ever grows. Widths are clamped at [`MAX_BITS`], so the
//! lattice is finite and the fixed point terminates; [`MAX_ROUNDS`] is a
//! backstop, not the mechanism.
//!
//! # Unknown is a class, not a guess
//!
//! A value the pass cannot resolve keeps [`WidthClass::Unknown`], which is a
//! distinct label from every real width. Guessing a machine word would merge it
//! with genuine 64-bit values and the error would be invisible; leaving it
//! distinct makes the rate measurable, and [`WidthInference::census`] reports
//! it.

use std::collections::{BTreeMap, BTreeSet};

use super::labels::WidthClass;
use super::operands::{operands, Operand};
use crate::ir::ssa::{SsaInfo, SsaValue};
use crate::ir::types::{BinOp, LlirFunction, Op};
use crate::ir::use_def::InstrAddr;

/// Widest value the pass will record. Above this a width is a symptom, not a
/// fact: no ISA Glaurung lifts has a register wider than 512 bits, so a larger
/// number can only come from a `Concat` chain feeding a loop-carried phi.
pub const MAX_BITS: u16 = 512;

/// Backstop on the fixed-point sweep count.
///
/// The lattice is finite and monotone, so the fixed point is reached on its
/// own; this bound exists so a future IR change that breaks monotonicity fails
/// as a slightly worse signature rather than as a hang.
pub const MAX_ROUNDS: usize = 32;

/// How many SSA values got a width, and how many did not.
///
/// The `unknown` rate over a real corpus is the honest measure of this pass;
/// see `docs/analysis/function-identity-cfr.md` for the number.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WidthCensus {
    /// SSA values the function mentions at all.
    pub total: usize,
    /// Of those, the ones left at [`WidthClass::Unknown`].
    pub unknown: usize,
}

impl WidthCensus {
    /// Fraction of values with no derived width, or `0.0` for an empty function.
    pub fn unknown_rate(self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            self.unknown as f64 / self.total as f64
        }
    }
}

/// Derived bit widths for every SSA value in one function.
#[derive(Debug, Clone, Default)]
pub struct WidthInference {
    bits: BTreeMap<SsaValue, u16>,
    seen: BTreeSet<SsaValue>,
}

impl WidthInference {
    /// The width class of one SSA value.
    pub fn class_of(&self, value: &SsaValue) -> WidthClass {
        self.bits
            .get(value)
            .map_or(WidthClass::Unknown, |bits| WidthClass::from_bits(*bits))
    }

    /// The raw bit width of one SSA value, where one was derived.
    pub fn bits_of(&self, value: &SsaValue) -> Option<u16> {
        self.bits.get(value).copied()
    }

    /// How much of the function the pass could resolve.
    pub fn census(&self) -> WidthCensus {
        WidthCensus {
            total: self.seen.len(),
            unknown: self.seen.len() - self.bits.len(),
        }
    }

    /// Record a width, keeping the wider of the two. Returns whether it changed.
    fn widen(&mut self, value: &SsaValue, bits: u16) -> bool {
        let bits = bits.min(MAX_BITS);
        if bits == 0 {
            return false;
        }
        match self.bits.get_mut(value) {
            Some(current) if *current >= bits => false,
            Some(current) => {
                *current = bits;
                true
            }
            None => {
                self.bits.insert(value.clone(), bits);
                true
            }
        }
    }

    fn note(&mut self, value: &SsaValue) {
        if !self.seen.contains(value) {
            self.seen.insert(value.clone());
        }
    }
}

/// Infer a width for every SSA value of `function`.
///
/// Seeds come from three places, in order of authority: the storage location
/// itself (a physical register's ISA width, a flag's one bit), the defining
/// operation (a load's access size, an extension's target width, a comparison's
/// single bit), and finally the operands, for operations that merely propagate
/// a width (a move, a bitwise operation, a negation).
pub fn infer(function: &LlirFunction, ssa: &SsaInfo) -> WidthInference {
    let mut inference = WidthInference::default();

    // Pass one: note every SSA value the function mentions and seed the ones
    // whose storage location already answers.
    for (block_idx, block) in function.blocks.iter().enumerate() {
        for (instr_idx, instruction) in block.instrs.iter().enumerate() {
            let addr = InstrAddr {
                block_idx,
                instr_idx,
            };
            for value in ssa.def_values(function, addr) {
                seed_from_storage(&mut inference, &value);
            }
            for operand in operands(&instruction.op) {
                if let Operand::Reg { use_index } = operand {
                    if let Some(value) = ssa.use_value_ref(function, addr, use_index) {
                        seed_from_storage(&mut inference, value);
                    }
                }
            }
        }
    }
    for phi in &ssa.phis {
        let result = SsaValue {
            base: phi.base.clone(),
            version: phi.dst_version,
        };
        seed_from_storage(&mut inference, &result);
        for (_, version) in &phi.incoming {
            let incoming = SsaValue {
                base: phi.base.clone(),
                version: *version,
            };
            seed_from_storage(&mut inference, &incoming);
        }
    }

    // Pass two: propagate until nothing moves.
    for _ in 0..MAX_ROUNDS {
        let mut changed = false;
        for (block_idx, block) in function.blocks.iter().enumerate() {
            for (instr_idx, instruction) in block.instrs.iter().enumerate() {
                let addr = InstrAddr {
                    block_idx,
                    instr_idx,
                };
                changed |=
                    propagate_instruction(&mut inference, function, ssa, addr, &instruction.op);
            }
        }
        for phi in &ssa.phis {
            changed |= propagate_phi(&mut inference, phi);
        }
        if !changed {
            break;
        }
    }
    inference
}

fn seed_from_storage(inference: &mut WidthInference, value: &SsaValue) {
    inference.note(value);
    if let Some(width) = value.base.width() {
        inference.widen(value, width.bits());
    }
}

/// Width of one positional operand, where the operand has an intrinsic one.
///
/// A literal has none: `8` is eight bits, thirty-two bits or sixty-four
/// depending entirely on what consumes it, so claiming a width here would be
/// the guess this pass exists to avoid.
fn operand_bits(
    inference: &WidthInference,
    function: &LlirFunction,
    ssa: &SsaInfo,
    addr: InstrAddr,
    operand: Operand,
) -> Option<u16> {
    match operand {
        Operand::Reg { use_index } => ssa
            .use_value_ref(function, addr, use_index)
            .and_then(|value| inference.bits_of(value)),
        Operand::Const(_) | Operand::Addr(_) | Operand::Absent => None,
    }
}

fn propagate_instruction(
    inference: &mut WidthInference,
    function: &LlirFunction,
    ssa: &SsaInfo,
    addr: InstrAddr,
    op: &Op,
) -> bool {
    let defs = ssa.def_values(function, addr);
    if defs.is_empty() {
        return false;
    }
    let ops = operands(op);
    let bits_of = |index: usize, inference: &WidthInference| {
        ops.get(index)
            .and_then(|operand| operand_bits(inference, function, ssa, addr, *operand))
    };

    let derived: Option<u16> = match op {
        // The access size is the width, verbatim. `MemOp::size` is in bytes.
        Op::Load { addr: memory, .. } | Op::CondLoad { addr: memory, .. } => {
            Some(u16::from(memory.size).saturating_mul(8))
        }
        // Extensions and truncations state their own target width.
        Op::ZExt { to, .. } | Op::SExt { to, .. } | Op::Trunc { to, .. } => Some(to.bits()),
        Op::Extract { hi, lo, .. } => hi.checked_sub(*lo),
        Op::Ite { width, .. } => Some(width.bits()),
        // A comparison result is a predicate, whatever its inputs were.
        Op::Cmp { .. } => Some(1),
        Op::Concat { .. } => match (bits_of(0, inference), bits_of(1, inference)) {
            (Some(high), Some(low)) => Some(high.saturating_add(low)),
            _ => None,
        },
        // A shift's result is as wide as the value shifted, never as wide as
        // the shift distance.
        Op::Bin {
            op: BinOp::Shl | BinOp::Shr | BinOp::Sar,
            ..
        } => bits_of(0, inference),
        // Every other binary operation is width-uniform in its inputs, so the
        // wider operand carries: a 32-bit constant folded against a 64-bit
        // register yields a 64-bit result.
        Op::Bin { .. } => match (bits_of(0, inference), bits_of(1, inference)) {
            (Some(left), Some(right)) => Some(left.max(right)),
            (Some(only), None) | (None, Some(only)) => Some(only),
            (None, None) => None,
        },
        Op::Un { .. } | Op::Assign { .. } => bits_of(0, inference),
        Op::Intrinsic { outs, .. } => {
            // Each output declares its own width, so this arm handles the
            // whole instruction and returns early.
            let mut changed = false;
            for (index, value) in defs.iter().enumerate() {
                if let Some((_, width)) = outs.get(index) {
                    changed |= inference.widen(value, width.bits());
                }
            }
            return changed;
        }
        _ => None,
    };

    let Some(bits) = derived else { return false };
    let mut changed = false;
    for value in &defs {
        changed |= inference.widen(value, bits);
    }
    changed
}

/// A phi is as wide as its widest incoming value.
///
/// In a well-formed SSA the incoming widths agree, and this is then an
/// identity. They can disagree after sub-register merging -- `eax` and `rax`
/// are one SSA value, so a 32-bit and a 64-bit definition can meet -- and the
/// merged location is the wider of the two, because that is the storage the
/// canonicalised value occupies.
fn propagate_phi(inference: &mut WidthInference, phi: &crate::ir::ssa::Phi) -> bool {
    let mut widest = 0u16;
    for (_, version) in &phi.incoming {
        let incoming = SsaValue {
            base: phi.base.clone(),
            version: *version,
        };
        if let Some(bits) = inference.bits_of(&incoming) {
            widest = widest.max(bits);
        }
    }
    if widest == 0 {
        return false;
    }
    let result = SsaValue {
        base: phi.base.clone(),
        version: phi.dst_version,
    };
    inference.widen(&result, widest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::ssa::compute_ssa;
    use crate::ir::types::{LlirBlock, LlirInstr, MemOp, VReg, Value, Width};

    fn one_block(ops: Vec<Op>) -> LlirFunction {
        LlirFunction {
            entry_va: 0x1000,
            blocks: vec![LlirBlock {
                start_va: 0x1000,
                end_va: 0x1000 + ops.len() as u64,
                instrs: ops
                    .into_iter()
                    .enumerate()
                    .map(|(index, op)| LlirInstr {
                        va: 0x1000 + index as u64,
                        op,
                    })
                    .collect(),
                succs: vec![],
            }],
        }
    }

    fn width_of(function: &LlirFunction, temp: u32) -> WidthClass {
        let ssa = compute_ssa(function);
        let inference = infer(function, &ssa);
        let mut found = WidthClass::Unknown;
        for (block_idx, block) in function.blocks.iter().enumerate() {
            for (instr_idx, _) in block.instrs.iter().enumerate() {
                let addr = InstrAddr {
                    block_idx,
                    instr_idx,
                };
                for value in ssa.def_values(function, addr) {
                    if value.base == VReg::Temp(temp) {
                        found = inference.class_of(&value);
                    }
                }
            }
        }
        found
    }

    #[test]
    fn a_load_gives_its_temporary_the_access_width() {
        let function = one_block(vec![Op::Load {
            dst: VReg::Temp(0),
            addr: MemOp::plain(Some(VReg::phys("rbp")), None, 0, -4, 4),
        }]);
        assert_eq!(width_of(&function, 0), WidthClass::W32);
    }

    #[test]
    fn a_temporary_inherits_the_width_of_a_physical_operand() {
        let function = one_block(vec![Op::Bin {
            dst: VReg::Temp(0),
            op: BinOp::Add,
            lhs: Value::Reg(VReg::phys("rdi")),
            rhs: Value::Const(1),
        }]);
        assert_eq!(width_of(&function, 0), WidthClass::W64);
    }

    #[test]
    fn a_shift_takes_the_width_of_the_value_not_the_distance() {
        let function = one_block(vec![
            Op::Assign {
                dst: VReg::Temp(0),
                src: Value::Reg(VReg::phys("cl")),
            },
            Op::Bin {
                dst: VReg::Temp(1),
                op: BinOp::Shl,
                lhs: Value::Reg(VReg::phys("rax")),
                rhs: Value::Reg(VReg::Temp(0)),
            },
        ]);
        assert_eq!(width_of(&function, 0), WidthClass::W8);
        assert_eq!(width_of(&function, 1), WidthClass::W64);
    }

    #[test]
    fn a_chain_of_temporaries_resolves_through_the_fixed_point() {
        let function = one_block(vec![
            Op::Load {
                dst: VReg::Temp(0),
                addr: MemOp::plain(Some(VReg::phys("rbp")), None, 0, -2, 2),
            },
            Op::Assign {
                dst: VReg::Temp(1),
                src: Value::Reg(VReg::Temp(0)),
            },
            Op::Un {
                dst: VReg::Temp(2),
                op: crate::ir::types::UnOp::Not,
                src: Value::Reg(VReg::Temp(1)),
            },
        ]);
        assert_eq!(width_of(&function, 2), WidthClass::W16);
    }

    #[test]
    fn an_extension_states_its_own_width() {
        let function = one_block(vec![Op::SExt {
            dst: VReg::Temp(0),
            src: Value::Reg(VReg::phys("eax")),
            from: Width::W32,
            to: Width::W64,
        }]);
        assert_eq!(width_of(&function, 0), WidthClass::W64);
    }

    #[test]
    fn an_unresolvable_temporary_stays_unknown_and_is_counted() {
        // Nothing says how wide a bare constant assignment is.
        let function = one_block(vec![Op::Assign {
            dst: VReg::Temp(0),
            src: Value::Const(3),
        }]);
        assert_eq!(width_of(&function, 0), WidthClass::Unknown);
        let ssa = compute_ssa(&function);
        let census = infer(&function, &ssa).census();
        assert_eq!(census.total, 1);
        assert_eq!(census.unknown, 1);
        assert!((census.unknown_rate() - 1.0).abs() < f64::EPSILON);
    }
}
