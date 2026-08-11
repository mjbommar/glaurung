//! Exact-byte evidence for SysV integer function inputs.
//!
//! Calling conventions transport narrow C integers in wider register slots.
//! Register-view recovery therefore cannot decide a source parameter's width
//! from the first machine copy alone. This owner projects the existing
//! bit-demand proof back onto one exact SSA live-in, but accepts only the
//! complete-low-byte SysV shape. Partial-bit masks, word/halfword masks, other
//! ABIs, pointers, and non-integer classifications fail closed.

use crate::ir::call_args::CallConv;
use crate::ir::definedness::BitDemandOracle;
use crate::ir::ssa::{SsaInfo, SsaValue};
use crate::ir::types::LlirFunction;
use crate::ir::types_recover::TypeHint;

/// Function-scoped observable-width facts shared by every recovered parameter.
pub(crate) struct ObservableParameterWidths {
    demand: BitDemandOracle,
    cc: CallConv,
}

impl ObservableParameterWidths {
    /// Analyze one lifted function once rather than rebuilding demand per slot.
    pub(crate) fn analyze(function: &LlirFunction, ssa: &SsaInfo, cc: CallConv) -> Self {
        Self {
            demand: BitDemandOracle::analyze(function, ssa, cc),
            cc,
        }
    }

    /// Refine an integer hint for the exact complete-low-byte SysV shape.
    pub(crate) fn refine(&self, value: &SsaValue, hint: TypeHint) -> TypeHint {
        let TypeHint::Int { signed, width } = hint else {
            return hint;
        };
        // This is deliberately an exact, architecture-specific evidence rule.
        // An arbitrary low-bit mask only constrains the implementation's value
        // range (`int bit & 1` is still an int), and AAPCS transports all of
        // these scalars in word registers.  The complete-byte SysV shape is the
        // one for which register-view demand adds useful evidence without those
        // two known ambiguities.
        if self.cc != CallConv::SysVAmd64 || self.demand.value_demand(value) != 0xff || width <= 1 {
            return hint;
        }
        TypeHint::Int { signed, width: 1 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::ssa::compute_ssa;
    use crate::ir::types::{BinOp, CmpOp, Flag, LlirBlock, LlirInstr, Op, VReg, Value};

    fn function(ops: Vec<Op>) -> LlirFunction {
        LlirFunction {
            entry_va: 0x1000,
            blocks: vec![LlirBlock {
                start_va: 0x1000,
                end_va: 0x1000 + 4 * ops.len() as u64,
                instrs: ops
                    .into_iter()
                    .enumerate()
                    .map(|(index, op)| LlirInstr {
                        va: 0x1000 + 4 * index as u64,
                        op,
                    })
                    .collect(),
                succs: vec![0x1100],
            }],
        }
    }

    fn observed_low_byte(extra: Vec<Op>) -> LlirFunction {
        let mut ops = vec![
            Op::Assign {
                dst: VReg::phys("r8d"),
                src: Value::Reg(VReg::phys("edx")),
            },
            Op::Bin {
                dst: VReg::Temp(0),
                op: BinOp::And,
                lhs: Value::Reg(VReg::phys("r8")),
                rhs: Value::Const(0xff),
            },
            Op::Cmp {
                dst: VReg::Flag(Flag::Z),
                op: CmpOp::Eq,
                lhs: Value::Reg(VReg::Temp(0)),
                rhs: Value::Const(0),
            },
            Op::CondJump {
                cond: VReg::Flag(Flag::Z),
                target: 0x1100,
                inverted: false,
            },
        ];
        ops.extend(extra);
        function(ops)
    }

    fn rdx_input() -> SsaValue {
        SsaValue {
            base: VReg::phys("rdx"),
            version: 0,
        }
    }

    #[test]
    fn copy_whose_only_observable_use_is_a_byte_narrows_the_integer_input() {
        let function = observed_low_byte(vec![]);
        let ssa = compute_ssa(&function);
        let widths = ObservableParameterWidths::analyze(&function, &ssa, CallConv::SysVAmd64);

        assert_eq!(
            widths.refine(
                &rdx_input(),
                TypeHint::Int {
                    signed: true,
                    width: 4,
                },
            ),
            TypeHint::Int {
                signed: true,
                width: 1,
            }
        );
    }

    #[test]
    fn a_full_width_observation_preserves_the_machine_word() {
        let function = observed_low_byte(vec![Op::ReturnValue {
            value: Value::Reg(VReg::phys("r8")),
        }]);
        let ssa = compute_ssa(&function);
        let widths = ObservableParameterWidths::analyze(&function, &ssa, CallConv::SysVAmd64);

        assert_eq!(
            widths.refine(
                &rdx_input(),
                TypeHint::Int {
                    signed: true,
                    width: 4,
                },
            ),
            TypeHint::Int {
                signed: true,
                width: 4,
            }
        );
    }

    #[test]
    fn observable_width_never_retypes_a_pointer() {
        let function = observed_low_byte(vec![]);
        let ssa = compute_ssa(&function);
        let widths = ObservableParameterWidths::analyze(&function, &ssa, CallConv::SysVAmd64);
        let pointer = TypeHint::Pointer { pointee_width: 1 };

        assert_eq!(widths.refine(&rdx_input(), pointer), pointer);
    }

    #[test]
    fn low_word_demand_does_not_narrow_a_machine_word_contract() {
        // A source `long` may deliberately mask its value to 32 bits.  Unlike
        // byte/halfword register views, that is not a narrow SysV scalar ABI
        // class and must not rewrite the public contract merely because this
        // body currently ignores the high half.
        let function = function(vec![
            Op::Bin {
                dst: VReg::Temp(0),
                op: BinOp::And,
                lhs: Value::Reg(VReg::phys("rdi")),
                rhs: Value::Const(0xffff_ffff),
            },
            Op::Cmp {
                dst: VReg::Flag(Flag::Z),
                op: CmpOp::Eq,
                lhs: Value::Reg(VReg::Temp(0)),
                rhs: Value::Const(0),
            },
            Op::CondJump {
                cond: VReg::Flag(Flag::Z),
                target: 0x1100,
                inverted: false,
            },
        ]);
        let ssa = compute_ssa(&function);
        let widths = ObservableParameterWidths::analyze(&function, &ssa, CallConv::SysVAmd64);
        let input = SsaValue {
            base: VReg::phys("rdi"),
            version: 0,
        };

        assert_eq!(
            widths.refine(
                &input,
                TypeHint::Int {
                    signed: false,
                    width: 8,
                },
            ),
            TypeHint::Int {
                signed: false,
                width: 8,
            }
        );
    }

    #[test]
    fn a_single_observed_bit_does_not_imply_a_byte_parameter() {
        // `void put_bit(int bit) { state |= bit & 1; }` still has an `int`
        // contract.  Rounding an arbitrary low-bit demand up to one byte would
        // confuse implementation range restriction with source type evidence.
        let function = function(vec![
            Op::Bin {
                dst: VReg::Temp(0),
                op: BinOp::And,
                lhs: Value::Reg(VReg::phys("rsi")),
                rhs: Value::Const(1),
            },
            Op::Store {
                addr: crate::ir::types::MemOp::plain(None, None, 1, 0x2000, 4),
                src: Value::Reg(VReg::Temp(0)),
            },
        ]);
        let ssa = compute_ssa(&function);
        let widths = ObservableParameterWidths::analyze(&function, &ssa, CallConv::SysVAmd64);
        let input = SsaValue {
            base: VReg::phys("rsi"),
            version: 0,
        };

        assert_eq!(
            widths.refine(
                &input,
                TypeHint::Int {
                    signed: true,
                    width: 4,
                },
            ),
            TypeHint::Int {
                signed: true,
                width: 4,
            }
        );
    }

    #[test]
    fn aapcs_word_register_demand_does_not_rewrite_the_source_contract() {
        let function = observed_low_byte(vec![]);
        let ssa = compute_ssa(&function);
        let widths = ObservableParameterWidths::analyze(&function, &ssa, CallConv::Arm);

        assert_eq!(
            widths.refine(
                &rdx_input(),
                TypeHint::Int {
                    signed: false,
                    width: 4,
                },
            ),
            TypeHint::Int {
                signed: false,
                width: 4,
            }
        );
    }
}
