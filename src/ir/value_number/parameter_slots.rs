//! Which argument slots of a function are genuine live-in parameters.
//!
//! This is signature evidence, not liveness: a register in an argument slot
//! that is written before it is read is scratch reuse and must not inflate
//! the recovered arity. Its one reason to change is the rule that decides
//! that question.

use crate::ir::call_args::CallConv;
use crate::ir::types::{LlirFunction, Op, VReg, Value};
use crate::ir::use_def::{def_ref, for_each_use, use_is_proven_input, InstrAddr};

use super::architectural_reads::{architecturally_read_names, phi_copy_operands};

/// Argument-passing registers in positional order (with width sub-names) per `cc`.
fn arg_slot_names(cc: CallConv) -> &'static [&'static [&'static str]] {
    crate::ir::abi::argument_slots(cc)
}

/// The argument slots of `lf` that are genuine **live-in parameters**: a slot is
/// a parameter iff some path reachable from the entry reads its incoming value
/// before defining that slot. A register written before every reachable read is
/// scratch reuse (e.g. an O2 function using `rdx`/`rcx` as temporaries) and must
/// NOT inflate the recovered arity.
///
/// Works on the value-numbered LLIR: register names may carry a `#version` tag,
/// and it sees parameters whose only later uses were dropped by structuring/DCE
/// (the LLIR predates those passes). Mirrors `naming::live_in_arg_slots` but
/// authoritative for the signature arity + typing.
///
/// A READ is evidence only when its exact identity is **version zero**. The
/// CFG walk deliberately ignores block storage/address order. This matters for
/// switch arms: a lower-address arm may define an argument register as scratch
/// while a sibling arm reads the incoming value first. The join is existential
/// (OR): one reachable read-before-definition path is enough to prove the slot.
pub fn live_in_arg_slots_llir(lf: &LlirFunction, cc: CallConv) -> std::collections::HashSet<usize> {
    live_in_arg_slots_llir_with_identities(lf, cc, None)
}

pub fn live_in_arg_slots_llir_with_identities(
    lf: &LlirFunction,
    cc: CallConv,
    identities: Option<&super::ValueIdentities>,
) -> std::collections::HashSet<usize> {
    let mut slot_of: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for (i, names) in arg_slot_names(cc).iter().enumerate() {
        for n in *names {
            slot_of.insert(n, i);
        }
    }
    // Which value-numbered names a real machine operand reads. Needed because a
    // phi copy launders the call may-uses this scan already refuses to trust:
    // the copy is an ordinary `Assign`, so the `Op::Call` guard below never sees
    // it, and its source is the bare (version-zero) live-in name.
    let really_read = architecturally_read_names(lf);
    let alignment_padding =
        crate::ir::arm_input_evidence::ArmAlignmentPadding::classify(lf, cc, identities);
    let base_slot = |name: &str| slot_of.get(name.split('#').next().unwrap_or(name)).copied();
    let register_slot = |register: &VReg, require_entry: bool| match identities {
        Some(identities) => {
            let candidates = identities.candidates(register)?;
            let mut slots = candidates.iter().map(|identity| {
                if require_entry && identity.version != 0 {
                    return None;
                }
                identity
                    .canonical_physical_base()
                    .and_then(|name| crate::ir::abi::argument_slot_of(cc, name))
            });
            let first = slots.next()??;
            slots.all(|slot| slot == Some(first)).then_some(first)
        }
        None => match register {
            VReg::Phys(name) => (!require_entry || !name.contains('#'))
                .then(|| base_slot(name))
                .flatten(),
            _ => None,
        },
    };
    // The slot a READ is evidence for. Production consults the opaque identity
    // and requires version zero; callers without the sidecar retain the legacy
    // `tag_phys` spelling convention as an explicit compatibility path.
    let read_slot = |register: &VReg| register_slot(register, true);
    let block_by_va: std::collections::HashMap<u64, usize> = lf
        .blocks
        .iter()
        .enumerate()
        .map(|(index, block)| (block.start_va, index))
        .collect();
    let Some(&entry_idx) = block_by_va.get(&lf.entry_va) else {
        return Default::default();
    };

    let mut parameters = std::collections::HashSet::new();
    for slot in 0..arg_slot_names(cc).len() {
        // The only propagated state is "the caller-supplied value can still be
        // present". A definition kills that path. Because joins are OR, each
        // block needs visiting at most once while that state is true.
        let mut work = std::collections::VecDeque::from([entry_idx]);
        let mut visited = std::collections::HashSet::new();
        let mut found_read = false;

        while let Some(block_idx) = work.pop_front() {
            if !visited.insert(block_idx) {
                continue;
            }
            let block = &lf.blocks[block_idx];
            let mut killed = false;
            for (instr_idx, ins) in block.instrs.iter().enumerate() {
                // `xor reg, reg` and `sub reg, reg` are architectural zero idioms:
                // their result does not depend on the incoming register value even
                // though the generic Bin representation has two syntactic uses.
                // Treat the idiom as the definition it really is before ordinary
                // read-before-write classification. This is especially important
                // for O2 accumulators such as `xor edx, edx`, where otherwise the
                // scratch register invents a third source parameter.
                if let Op::Bin {
                    dst: VReg::Phys(dst),
                    op: crate::ir::types::BinOp::Xor | crate::ir::types::BinOp::Sub,
                    lhs: Value::Reg(VReg::Phys(lhs)),
                    rhs: Value::Reg(VReg::Phys(rhs)),
                } = &ins.op
                {
                    let slots = (
                        register_slot(&VReg::Phys(dst.clone()), false),
                        register_slot(&VReg::Phys(lhs.clone()), false),
                        register_slot(&VReg::Phys(rhs.clone()), false),
                    );
                    if let (Some(dst_slot), Some(lhs_slot), Some(rhs_slot)) = slots {
                        if dst_slot == lhs_slot && lhs_slot == rhs_slot {
                            if dst_slot == slot {
                                killed = true;
                                break;
                            }
                            continue;
                        }
                    }
                }
                // A CALL's argument-register uses say what the CALLEE may read. They are
                // not evidence that THIS function has a parameter. Over-approximating uses
                // is right for liveness and dead-code elimination, which is why `def_uses`
                // reports them; it is wrong for inferring a signature, which is what this
                // function does.
                //
                // Honest scope: this is a correctness argument, not a measured fix. It was
                // written expecting it to explain a DecBench type_match drop; measuring
                // before and after showed NO difference on that corpus (arities were right
                // either way — the first touch of an argument register in these functions
                // is its `-O0` spill, which precedes any call). Kept because the inference
                // should not depend on `def_uses` continuing to under-report call effects.
                // ... and a phi copy is that same may-use laundered into an ordinary
                // `Assign`. `insert_phi_copies` materialises a copy for every phi
                // whose destination is READ, and its notion of "read" is `def_uses`,
                // so a call's argument-register list alone is enough to keep the
                // copy. The result — `x3#1 = x3` in the entry block of any loop that
                // calls anything and later writes `x3` — reads the bare version-zero
                // live-in name and would make every trailing argument register of
                // every such function a parameter. It is real evidence only when the
                // phi destination is really read; then the copy's SOURCE is what the
                // function reads, and the destination is not an architectural
                // definition of the register at all.
                if let Some((dst, src)) = phi_copy_operands(&ins.op) {
                    if really_read.contains(dst) {
                        // `read_slot`, not `base_slot`: the copy in the ENTRY
                        // predecessor of a loop-header phi reads the bare live-in
                        // name and is real evidence; the one in the latch reads the
                        // loop's own definition and is not.
                        if read_slot(&VReg::phys(src)) == Some(slot) {
                            found_read = true;
                            break;
                        }
                    }
                    continue;
                }
                // Reads first, then the def — a use and a def of the same slot in one
                // op (`rdx = rdx + 1`) counts as a read (the incoming value is used).
                let mut use_index = 0;
                for_each_use(&ins.op, |u| {
                    if found_read {
                        return;
                    }
                    let index = use_index;
                    use_index += 1;
                    if !use_is_proven_input(&ins.op, index) {
                        return;
                    }
                    if alignment_padding.excludes_use(
                        InstrAddr {
                            block_idx,
                            instr_idx,
                        },
                        u,
                        identities,
                    ) {
                        return;
                    }
                    if read_slot(u) == Some(slot) {
                        found_read = true;
                    }
                });
                if found_read {
                    break;
                }
                if let Some(definition) = def_ref(&ins.op) {
                    if register_slot(definition, false) == Some(slot) {
                        killed = true;
                        break;
                    }
                }
            }
            if found_read {
                break;
            }
            if !killed {
                work.extend(
                    block
                        .succs
                        .iter()
                        .filter_map(|successor| block_by_va.get(successor).copied()),
                );
            }
        }
        if found_read {
            parameters.insert(slot);
        }
    }
    parameters
}
