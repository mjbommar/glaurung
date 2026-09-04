//! Per-use integer interpretation constraints.
//!
//! Machine operations choose a signed or unsigned interpretation for one use;
//! they do not permanently change the source declaration of the value.  This
//! is the first deliberately small WP6 constraint slice.  It keeps those facts
//! separate and resolves a declaration signedness only when every informative
//! use agrees.  Equality, address indexing, and x86's implicit 32-bit write
//! zero-extension are neutral.

use std::collections::BTreeSet;

use crate::ir::types::{BinOp, CmpOp, Op};
use crate::ir::use_def::InstrAddr;

/// The interpretation one machine operation requires for one operand use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum SignednessUse {
    Signed,
    Unsigned,
}

/// Deterministic signedness evidence for one exact SSA value.
#[derive(Debug, Default)]
pub(super) struct SignednessConstraints {
    facts: BTreeSet<(SignednessUse, InstrAddr, usize)>,
}

impl SignednessConstraints {
    /// Record an informative operand use, if this operation has one.
    pub(super) fn record(&mut self, op: &Op, at: InstrAddr, use_index: usize) {
        if let Some(fact) = signedness_use(op, use_index) {
            self.facts.insert((fact, at, use_index));
        }
    }

    /// Resolve only unanimous evidence; absence or conflict stays unknown.
    pub(super) fn resolved(&self) -> Option<bool> {
        let signed = self
            .facts
            .iter()
            .any(|(fact, _, _)| *fact == SignednessUse::Signed);
        let unsigned = self
            .facts
            .iter()
            .any(|(fact, _, _)| *fact == SignednessUse::Unsigned);
        match (signed, unsigned) {
            (true, false) => Some(true),
            (false, true) => Some(false),
            _ => None,
        }
    }
}

fn signedness_use(op: &Op, use_index: usize) -> Option<SignednessUse> {
    match op {
        Op::SExt { .. } if use_index == 0 => Some(SignednessUse::Signed),
        // Extending a byte or halfword is an explicit interpretation.  A
        // 32-to-64 ZExt is also how x86 models every write to a dword register,
        // including ordinary argument shuffles, so it is not declaration
        // evidence.
        Op::ZExt { from, .. } if use_index == 0 && from.bytes() < 4 => {
            Some(SignednessUse::Unsigned)
        }
        Op::Bin { op: BinOp::Shr, .. } if use_index == 0 => Some(SignednessUse::Unsigned),
        Op::Bin { op: BinOp::Sar, .. } if use_index == 0 => Some(SignednessUse::Signed),
        Op::Cmp {
            op: CmpOp::Ult | CmpOp::Ule,
            ..
        } if use_index <= 1 => Some(SignednessUse::Unsigned),
        Op::Cmp {
            op: CmpOp::Slt | CmpOp::Sle,
            ..
        } if use_index <= 1 => Some(SignednessUse::Signed),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::types::{VReg, Value, Width};

    fn at(index: usize) -> InstrAddr {
        InstrAddr {
            block_idx: 0,
            instr_idx: index,
        }
    }

    #[test]
    fn x86_dword_write_extension_is_not_unsigned_declaration_evidence() {
        let op = Op::ZExt {
            dst: VReg::phys("rdi"),
            src: Value::Reg(VReg::phys("esi")),
            from: Width(32),
            to: Width(64),
        };
        let mut constraints = SignednessConstraints::default();
        constraints.record(&op, at(0), 0);
        assert_eq!(constraints.resolved(), None);
    }

    #[test]
    fn explicit_narrow_extensions_resolve_their_interpretation() {
        let mut unsigned = SignednessConstraints::default();
        unsigned.record(
            &Op::ZExt {
                dst: VReg::Temp(0),
                src: Value::Reg(VReg::phys("dil")),
                from: Width(8),
                to: Width(32),
            },
            at(0),
            0,
        );
        assert_eq!(unsigned.resolved(), Some(false));

        let mut signed = SignednessConstraints::default();
        signed.record(
            &Op::SExt {
                dst: VReg::Temp(1),
                src: Value::Reg(VReg::phys("dil")),
                from: Width(8),
                to: Width(32),
            },
            at(0),
            0,
        );
        assert_eq!(signed.resolved(), Some(true));
    }

    #[test]
    fn contradictory_uses_remain_unresolved() {
        let mut constraints = SignednessConstraints::default();
        constraints.record(
            &Op::Bin {
                dst: VReg::Temp(0),
                op: BinOp::Shr,
                lhs: Value::Reg(VReg::phys("edi")),
                rhs: Value::Const(1),
            },
            at(0),
            0,
        );
        constraints.record(
            &Op::Bin {
                dst: VReg::Temp(1),
                op: BinOp::Sar,
                lhs: Value::Reg(VReg::phys("edi")),
                rhs: Value::Const(1),
            },
            at(1),
            0,
        );
        assert_eq!(constraints.resolved(), None);
    }
}
