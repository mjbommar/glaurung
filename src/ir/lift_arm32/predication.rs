//! Thumb-2 IT blocks: turning a predicated instruction into conditional LLIR.
//!
//! `it`/`itt`/`ite`/... makes the next one to four instructions execute only
//! when a condition holds, and capstone reports the member instructions with
//! the condition folded into the mnemonic rather than as an operand. This
//! module owns both ends of that: recognising the introducer and its mask
//! ([`is_it_mnemonic`], [`it_conditions`]), recovering the base mnemonic a
//! member was assembled from ([`mnemonic_in_it`], [`strip_qualifier`]), and
//! rewriting the lifted op sequence so the condition is carried in the IR
//! ([`make_conditional`]).
//!
//! [`make_conditional`] is deliberately two-tier. A single op with a
//! conditional LLIR form (a jump, a load, a store, a return) becomes that form
//! directly. Anything else goes through [`predicate_sequence`], which commits
//! every write through an [`Op::Ite`] against the guard so the unpredicated
//! path observes the old value -- and which fails closed, refusing to
//! predicate an effect it cannot make side-effect-free.

use crate::core::instruction::Instruction;
use crate::ir::types::*;

use super::flags::cond_flag_for;

/// Strip the `.w`/`.n` Thumb-2 width qualifier from a lowercased mnemonic.
pub(super) fn strip_qualifier(m: &str) -> &str {
    m.strip_suffix(".w")
        .or_else(|| m.strip_suffix(".n"))
        .unwrap_or(m)
}

/// True for an IT-block introducer: `it` optionally followed by up to three
/// `t`/`e` mask characters (`it`, `itt`, `ite`, `itte`, `itttt`, …).
pub(super) fn is_it_mnemonic(m: &str) -> bool {
    matches!(m.len(), 2..=5)
        && m.starts_with("it")
        && m[2..].bytes().all(|b| b == b't' || b == b'e')
}

/// Apply Thumb's `setflags = !InITBlock` rule to the narrow ADD/SUB forms.
///
/// Their 16-bit encodings have no explicit S bit.  Disassemblers conventionally
/// print them as `adds`/`subs`, but inside an IT block the architecture suppresses
/// those implicit writes.  Keeping the printed suffix would both clobber the
/// condition that predicates the remaining slots and turn the one arithmetic
/// write into a multi-op flag expansion that cannot be conditionally selected.
pub(super) fn mnemonic_in_it<'a>(ins: &Instruction, mnem: &'a str) -> &'a str {
    if ins.length == 2 && matches!(mnem, "adds" | "subs") {
        &mnem[..mnem.len() - 1]
    } else {
        mnem
    }
}

/// Per-slot (flag, inverted) conditions for the instructions an IT block
/// predicates. Capstone reports the mask in the mnemonic (`it`/`ite`/`itt`/…)
/// and the base condition as the first operand (a pseudo-register named `lt`,
/// `ge`, …). Slot 0 is always the base condition (the implicit `t`); each mask
/// character then adds a slot — `t` reuses the base polarity, `e` inverts it.
pub(super) fn it_conditions(mnem: &str, cond_name: &str) -> Vec<(VReg, bool)> {
    let Some((flag, inv)) = cond_flag_for(cond_name) else {
        return Vec::new();
    };
    let mut out = vec![(flag.clone(), inv)];
    for c in mnem.as_bytes()[2..].iter() {
        out.push((flag.clone(), if *c == b'e' { !inv } else { inv }));
    }
    out
}

/// Wrap an unconditionally-lifted instruction's ops so its architectural writes
/// take effect only when `cond` holds (an IT-block predicated instruction).
pub(super) fn make_conditional(ops: Vec<Op>, cond: VReg, inverted: bool) -> Vec<Op> {
    // Ite is `dst = cond ? t : e`; for `if !cond` we swap the two arms.
    let pick = |new: Value, keep: Value| -> (Value, Value) {
        if inverted {
            (keep, new)
        } else {
            (new, keep)
        }
    };
    if ops.len() != 1 {
        return predicate_sequence(ops, cond, inverted);
    }
    match ops.into_iter().next().unwrap() {
        Op::Assign { dst, src } => {
            let (t, e) = pick(src, Value::Reg(dst.clone()));
            vec![Op::Ite {
                dst,
                cond,
                t,
                e,
                width: Width::W32,
            }]
        }
        Op::Bin { dst, op, lhs, rhs } => {
            let tmp = VReg::Temp(1);
            let (t, e) = pick(Value::Reg(tmp.clone()), Value::Reg(dst.clone()));
            vec![
                Op::Bin {
                    dst: tmp,
                    op,
                    lhs,
                    rhs,
                },
                Op::Ite {
                    dst,
                    cond,
                    t,
                    e,
                    width: Width::W32,
                },
            ]
        }
        Op::Un { dst, op, src } => {
            let tmp = VReg::Temp(1);
            let (t, e) = pick(Value::Reg(tmp.clone()), Value::Reg(dst.clone()));
            vec![
                Op::Un { dst: tmp, op, src },
                Op::Ite {
                    dst,
                    cond,
                    t,
                    e,
                    width: Width::W32,
                },
            ]
        }
        Op::Load { dst, addr } => {
            let fallback = Value::Reg(dst.clone());
            vec![Op::CondLoad {
                dst,
                cond,
                inverted,
                addr,
                fallback,
            }]
        }
        Op::Store { addr, src } => vec![Op::CondStore {
            cond,
            inverted,
            addr,
            src,
        }],
        Op::Return => vec![Op::CondReturn { cond, inverted }],
        // Reuse the multi-op machinery for pure one-result operations. It
        // computes into scratch and commits only on the taken path; control or
        // opaque side effects below fail closed rather than becoming
        // unconditional.
        other => predicate_sequence(vec![other], cond, inverted),
    }
}

/// First temporary reserved for predicating multi-operation lifts.
const PRED_TEMP_BASE: u32 = 64;

/// Compute a multi-operation instruction into scratch and conditionally commit
/// each architectural write. Memory effects and returns remain guarded through
/// their typed conditional LLIR operations.
fn predicate_sequence(mut ops: Vec<Op>, cond: VReg, inverted: bool) -> Vec<Op> {
    use crate::ir::use_def::def_mut;
    use crate::ir::value_number::for_each_vreg_mut;

    // A conditional multi-register pop may end in a return. Predicate all of
    // its register/stack effects, then make only the taken path return.
    let conditional_return = matches!(ops.last(), Some(Op::Return));
    if conditional_return {
        ops.pop();
    }

    let unpredicatable = ops.iter().any(|op| {
        matches!(
            op,
            Op::CondLoad { .. }
                | Op::CondStore { .. }
                | Op::Jump { .. }
                | Op::CondJump { .. }
                | Op::CondReturn { .. }
                | Op::IndirectJump { .. }
                | Op::Call { .. }
                | Op::Return
                | Op::Unknown { .. }
        ) || matches!(
            op,
            Op::Intrinsic {
                outs,
                reads_mem,
                writes_mem,
                ..
            } if *reads_mem || *writes_mem || outs.len() > 1
        )
    });
    if unpredicatable {
        return vec![Op::Unknown {
            mnemonic: "predicated control effect".to_string(),
        }];
    }

    fn is_architectural(register: &VReg) -> bool {
        matches!(register, VReg::Phys(_) | VReg::Flag(_))
    }

    let mut renamed: Vec<(VReg, VReg)> = Vec::new();
    let mut current: Vec<(VReg, VReg)> = Vec::new();
    let mut next_temp = PRED_TEMP_BASE;
    let mut out = Vec::with_capacity(ops.len() + 5);

    // Snapshot a predicate that the instruction itself writes. Otherwise the
    // first flag commit can change the condition used by all later commits.
    let cond_written = ops
        .iter()
        .any(|op| crate::ir::use_def::def_uses(op).0.as_ref() == Some(&cond));
    let commit_cond = if cond_written {
        let snapshot = VReg::Temp(next_temp);
        next_temp += 1;
        out.push(Op::Assign {
            dst: snapshot.clone(),
            src: Value::Reg(cond.clone()),
        });
        snapshot
    } else {
        cond
    };

    for mut op in ops {
        let definition = crate::ir::use_def::def_uses(&op).0;
        for_each_vreg_mut(&mut op, &mut |register| {
            if let Some((_, temp)) = current.iter().find(|(current, _)| current == register) {
                *register = temp.clone();
            }
        });

        if let Op::Store { addr, src } = op {
            out.push(Op::CondStore {
                cond: commit_cond.clone(),
                inverted,
                addr,
                src,
            });
            continue;
        }

        // A predicated load must not dereference memory on the false path.
        // Multi-op lifts compute architectural results in scratch before the
        // conditional commit below, so a false scratch value may be zero: it
        // cannot escape when the predicate is false.  The single-op path above
        // instead retains the architectural destination directly.
        if let Op::Load { dst, addr } = op {
            let conditional_dst = if let Some(definition) = definition.filter(is_architectural) {
                let temp = VReg::Temp(next_temp);
                next_temp += 1;
                match current
                    .iter_mut()
                    .find(|(register, _)| *register == definition)
                {
                    Some((_, held)) => *held = temp.clone(),
                    None => current.push((definition.clone(), temp.clone())),
                }
                if !renamed.iter().any(|(register, _)| *register == definition) {
                    renamed.push((definition, temp.clone()));
                }
                temp
            } else {
                dst
            };
            out.push(Op::CondLoad {
                dst: conditional_dst,
                cond: commit_cond.clone(),
                inverted,
                addr,
                fallback: Value::Const(0),
            });
            continue;
        }

        if let Some(definition) = definition.filter(is_architectural) {
            let temp = VReg::Temp(next_temp);
            next_temp += 1;
            if let Some(destination) = def_mut(&mut op) {
                *destination = temp.clone();
            }
            match current
                .iter_mut()
                .find(|(register, _)| *register == definition)
            {
                Some((_, held)) => *held = temp.clone(),
                None => current.push((definition.clone(), temp.clone())),
            }
            if !renamed.iter().any(|(register, _)| *register == definition) {
                renamed.push((definition, temp));
            }
        }
        out.push(op);
    }

    for (register, _) in renamed {
        let Some((_, temp)) = current.iter().find(|(current, _)| *current == register) else {
            continue;
        };
        let computed = Value::Reg(temp.clone());
        let retained = Value::Reg(register.clone());
        let (t, e) = if inverted {
            (retained, computed)
        } else {
            (computed, retained)
        };
        let width = if matches!(register, VReg::Flag(_)) {
            Width::W1
        } else {
            Width::W32
        };
        out.push(Op::Ite {
            dst: register,
            cond: commit_cond.clone(),
            t,
            e,
            width,
        });
    }
    if conditional_return {
        out.push(Op::CondReturn {
            cond: commit_cond,
            inverted,
        });
    }
    out
}
