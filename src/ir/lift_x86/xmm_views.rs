//! Reconciling the two spellings an XMM register has in this LLIR.
//!
//! [`super::packed`] describes an XMM register as four independent 32-bit dword
//! lanes (`xmm0_d0`..`xmm0_d3`); [`super::scalar_float`] writes and reads the
//! whole-register name (`xmm0`). Both name the same bits, and SSA treats them as
//! unrelated storage. This module is the bridge run once per lifted instruction,
//! after its ops are emitted, so neither producer has to know about the other's
//! spelling.

use crate::ir::types::{Op, VReg, Value};

/// Keep an XMM register's two representations in step.
///
/// This LLIR gives an XMM register two names: the whole-register spelling that
/// the scalar float operations read and write, and four `_dN` dword lanes that
/// the packed operations do. They describe the same bits and nothing kept them
/// in agreement, so a value written through one view was invisible through the
/// other. GCC's `-O0` float return is exactly that crossing —
/// `movsd -8(%rbp),%xmm0 ; movq %xmm0,%rax ; movq %rax,%xmm0` — and it returned
/// a zero reconstructed from lanes no scalar store had ever written.
///
/// So: after any instruction that writes lane 0 or 1, the whole-register name
/// is redefined from those lanes. The converse direction is handled at the
/// producers (a scalar write defines the scalar name, which the MOVQ and MOVD
/// GPR forms now read), and the two together make the views interchangeable.
///
/// Only the low two lanes participate. They are the 64 bits every scalar
/// operation and every GPR transfer can address; a 128-bit packed value has no
/// scalar spelling to agree with in the first place.
pub(super) fn synchronise_xmm_views(ops: &mut Vec<Op>) {
    use std::collections::BTreeSet;

    let mut already_defined: BTreeSet<String> = BTreeSet::new();
    let mut lane_written: BTreeSet<String> = BTreeSet::new();
    for op in ops.iter() {
        let (definition, _) = crate::ir::use_def::def_uses(op);
        let Some(VReg::Phys(name)) = definition else {
            continue;
        };
        match name.split_once("_d") {
            Some((register, lane)) if matches!(lane, "0" | "1") => {
                lane_written.insert(register.to_string());
            }
            Some(_) => {}
            None => {
                already_defined.insert(name);
            }
        }
    }
    for register in lane_written {
        if already_defined.contains(&register) {
            continue;
        }
        // A register-to-register packed move copies lane N from lane N of ONE
        // source. Rebuilding the destination's scalar view from its own lanes
        // would be correct only if those lanes had been written — and after a
        // `movss`/`movsd` they have not, because a scalar store writes the
        // whole-register name instead. Carrying the SOURCE's scalar view across
        // propagates whichever representation is actually live, which is what
        // `movaps %xmm1,%xmm2` in a float argument setup needs.
        if let Some(source) = single_source_of_lane_copy(ops, &register) {
            ops.push(Op::Assign {
                dst: VReg::phys(&register),
                src: Value::Reg(VReg::phys(source)),
            });
            continue;
        }
        ops.push(Op::Concat {
            dst: VReg::phys(&register),
            hi: Value::Reg(VReg::phys(format!("{register}_d1"))),
            lo: Value::Reg(VReg::phys(format!("{register}_d0"))),
        });
    }
}

/// The single XMM register every written lane of `register` was copied from,
/// when this instruction is a plain lane-for-lane register move.
///
/// `None` as soon as any lane is computed, loaded, zeroed, or taken from a
/// different register — in those cases the destination's own lanes are the only
/// description of its value and the concat above is the right bridge.
fn single_source_of_lane_copy(ops: &[Op], register: &str) -> Option<String> {
    let mut source: Option<String> = None;
    let mut lanes_seen = 0usize;
    for op in ops {
        let Op::Assign {
            dst: VReg::Phys(dst),
            src: Value::Reg(VReg::Phys(src)),
        } = op
        else {
            continue;
        };
        let Some((dst_register, dst_lane)) = dst.split_once("_d") else {
            continue;
        };
        if dst_register != register {
            continue;
        }
        let (src_register, src_lane) = src.split_once("_d")?;
        if src_lane != dst_lane {
            return None;
        }
        match &source {
            Some(known) if known != src_register => return None,
            Some(_) => {}
            None => source = Some(src_register.to_string()),
        }
        lanes_seen += 1;
    }
    // Every lane the instruction wrote must be accounted for by the copy.
    (lanes_seen == 4).then_some(source?)
}
