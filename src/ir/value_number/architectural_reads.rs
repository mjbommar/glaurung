//! Which value-numbered names a *genuine* machine operand reads.
//!
//! Two consumers ask exactly this question and must get the same answer:
//! parameter-slot inference (a laundered call may-use is not evidence of a
//! parameter) and phi-copy coalescing (a live-in reached only through
//! plumbing is not a proven phi input). The boundary between an
//! architectural read and out-of-SSA plumbing therefore lives here, with
//! one reason to change: what counts as plumbing.

use std::collections::HashSet;

use crate::ir::types::{LlirFunction, Op, VReg, Value};
use crate::ir::use_def::{for_each_use, use_is_proven_input};

/// The `(destination, source)` register names of a phi copy: an `Assign` between
/// two SSA versions of the *same* physical register.
///
/// `insert_phi_copies` is what produces that shape — a phi's incoming lanes all
/// share `phi.base`, so leaving SSA writes `x3#1 = x3`. The only other way to
/// reach it is a lifted self-move, which is an architectural no-op; classifying
/// that as plumbing too is right rather than merely harmless, because a no-op
/// says nothing about whether the incoming value is read. What decides the
/// question either way is whether the copy's DESTINATION is read — see
/// [`architecturally_read_names`] below.
///
/// Returns `None` on the raw (non-value-numbered) LLIR: without `#version` tags,
/// equal bases mean equal names, which the `dst != src` guard rejects.
pub(crate) fn phi_copy_operands(op: &Op) -> Option<(&str, &str)> {
    let Op::Assign {
        dst: VReg::Phys(dst),
        src: Value::Reg(VReg::Phys(src)),
    } = op
    else {
        return None;
    };
    let (dst, src) = (dst.as_str(), src.as_str());
    (dst != src && crate::ir::abi::ssa_base(dst) == crate::ir::abi::ssa_base(src))
        .then_some((dst, src))
}

/// The value-numbered names read by a *genuine* architectural operand.
///
/// Two use classes are excluded, for the same reason: neither observes that this
/// function reads the value.
///
/// * A call's argument-register list, which [`crate::ir::abi::annotate_calls`]
///   hangs on **every** call as a may-use so liveness and DCE stay sound.
/// * A phi copy, which exists only to leave SSA.
///
/// The phi copies are then folded back in to a fixed point: a copy `d = s`
/// really reads `s` exactly when `d` is itself really read. This mirrors the
/// liveness fixpoint of the phi graph — with the difference that that
/// one (in `insert_phi_copies`) deliberately counts the call may-uses, because an argument register a
/// callee might read must stay defined.
pub(crate) fn architecturally_read_names(lf: &LlirFunction) -> HashSet<String> {
    let mut read: HashSet<String> = HashSet::new();
    let mut phi_copies: Vec<(&str, &str)> = Vec::new();
    for block in &lf.blocks {
        for ins in &block.instrs {
            if let Some(pair) = phi_copy_operands(&ins.op) {
                phi_copies.push(pair);
                continue;
            }
            // Borrowed walk: the collecting form clones the spelling of
            // every operand, and all but the first sighting of a name is then
            // dropped by the set.
            let mut use_index = 0;
            for_each_use(&ins.op, |used| {
                let index = use_index;
                use_index += 1;
                if !use_is_proven_input(&ins.op, index) {
                    return;
                }
                if let VReg::Phys(name) = used {
                    if !read.contains(name.as_str()) {
                        read.insert(name.clone());
                    }
                }
            });
        }
    }
    loop {
        let mut changed = false;
        for (dst, src) in &phi_copies {
            if read.contains(*dst) && !read.contains(*src) {
                read.insert((*src).to_string());
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    read
}
