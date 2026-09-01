//! Cortex-M special registers (`mrs` / `msr`).
//!
//! These are machine state, not memory. Lifting them as typed intrinsics keeps
//! def-use honest: an `mrs` DEFINES its destination, so without an output the
//! register reads as undefined everywhere downstream; an `msr` CONSUMES its
//! source, so without an input a real dependency disappears and the producing
//! computation looks dead. Claiming memory effects instead would make every
//! surrounding load and store unorderable.
//!
//! The system register is part of the intrinsic name, which keeps
//! `BASEPRI_MAX` distinct from `BASEPRI` -- their update semantics differ,
//! `BASEPRI_MAX` only ever raising the priority ceiling. An unrecognised
//! encoding still yields a named intrinsic rather than nothing: an empty lift
//! discards the enclosing function, which is the failure this path exists to
//! prevent (DecBench class F2a, 31 rows).
//!
//! Reaching this code at all depends on the Cortex-M fallback decoder in
//! [`crate::disasm::capstone`]: in generic ARM mode Capstone rejects these
//! encodings outright.

use crate::core::instruction::Operand;
use crate::ir::types::*;

/// Whether `mnem` is a system-register transfer this module handles.
pub(super) fn is_system_register_transfer(mnem: &str, ops: &[Operand]) -> bool {
    (mnem == "mrs" || mnem == "msr") && ops.len() == 2
}

/// Lift `mrs Rd, SYS` / `msr SYS, Rn` to a typed, non-memory intrinsic.
pub(super) fn lift(
    mnem: &str,
    ops: &[Operand],
    operand_reg: impl Fn(&Operand) -> Option<VReg>,
) -> Vec<Op> {
    let is_mrs = mnem == "mrs";
    // Capstone renders the special register as a bare name in the operand it
    // cannot type as a GPR, so the GPR side is identified by position rather
    // than by shape.
    let (gpr, sysreg) = if is_mrs {
        (&ops[0], &ops[1])
    } else {
        (&ops[1], &ops[0])
    };
    let sys_name = operand_reg(sysreg)
        .map(|r| match r {
            VReg::Phys(n) => n.to_ascii_lowercase(),
            other => format!("{other:?}").to_ascii_lowercase(),
        })
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| "unknown".to_string());
    let name = format!("arm32.{mnem}.{sys_name}");
    let Some(reg) = operand_reg(gpr) else {
        return vec![Op::Intrinsic {
            name,
            ins: vec![],
            outs: vec![],
            reads_mem: false,
            writes_mem: false,
        }];
    };
    vec![if is_mrs {
        Op::Intrinsic {
            name,
            ins: vec![],
            outs: vec![(reg, Width::W32)],
            reads_mem: false,
            writes_mem: false,
        }
    } else {
        Op::Intrinsic {
            name,
            ins: vec![Value::Reg(reg)],
            outs: vec![],
            reads_mem: false,
            writes_mem: false,
        }
    }]
}
