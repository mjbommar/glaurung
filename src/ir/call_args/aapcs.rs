//! ARM/AAPCS32 outgoing-argument recovery.
//!
//! AAPCS is the one convention here whose parameters are not a flat prefix of a
//! single register bank. The core (r0-r3) and VFP (s0-s15/d0-d7) banks advance
//! INDEPENDENTLY, so `int, float, int` occupies `r0, s0, r1` while two floats
//! occupy `s0, s1` -- an order no liveness-derived register prefix can
//! reconstruct. Everything in this module therefore works from a proof: either a
//! locked catalog prototype (`known_arm_*`) or an unambiguous single-bank setup
//! window (`fold_one_arm_hard_float_call`), and declines otherwise rather than
//! inventing an argument order.
//!
//! `super::fold_one_call` is the sole caller of every entry point here. The
//! convention-generic `fold_one_recovered_layout_call` deliberately stays in the
//! parent: it consumes the layouts produced here, but non-ARM paths call it too.

use crate::ir::ast::{Expr, Stmt};
use crate::ir::types::VReg;

use super::{ssa_base, CallConv};

/// Exact core-register arity of a fixed AAPCS32 library call.
///
/// Register liveness alone cannot distinguish call inputs from caller-local
/// scratch state. Thumb GCC, for example, writes `r3` for stack-canary
/// bookkeeping after setting up the three arguments to `memset`; A32 GCC may
/// also leave multiple shadowed definitions of one argument register. A locked
/// catalog declaration proves both that r0..rN-1 are inputs and that later core
/// registers are not. Only one-word scalar parameters qualify here. Wider,
/// variadic, and otherwise unrepresentable layouts stay on the conservative
/// evidence-only path until the ABI layout model can describe them exactly.
pub(super) fn known_arm_core_register_arity(statement: &Stmt) -> Option<usize> {
    let name = match statement {
        Stmt::Call {
            target: Expr::Named { name, .. },
            ..
        } => name,
        _ => return None,
    };
    let contract = crate::ir::call_contracts::lookup(name)?;
    if contract.is_variadic || contract.params.len() > 4 {
        return None;
    }
    for parameter in &contract.params {
        let c_type = crate::ir::call_contracts::standalone_c_type(&parameter.c_type)?;
        let fits_one_core_register = c_type == "float"
            || c_type.ends_with('*')
            || crate::ir::call_contracts::integer_c_type_width(&c_type, 4)
                .is_some_and(|width| width <= 4);
        if !fits_one_core_register {
            return None;
        }
    }
    Some(contract.params.len())
}

/// Source-ordered AAPCS-VFP storage selected by a locked library prototype.
///
/// The core and VFP banks advance independently. This is exactly why a flat
/// liveness-derived register prefix cannot reconstruct mixed hard-float calls:
/// `int, float, int` occupies `r0, s0, r1`, while two floats occupy `s0, s1`.
/// Stack-spilled and variadic layouts are withheld until the AST models their
/// outgoing storage explicitly.
pub(super) fn known_arm_hard_float_layout(statement: &Stmt) -> Option<Vec<VReg>> {
    let name = match statement {
        Stmt::Call {
            target: Expr::Named { name, .. },
            ..
        } => name,
        _ => return None,
    };
    let contract = crate::ir::call_contracts::lookup(name)?;
    if contract.is_variadic {
        return None;
    }

    let mut core_slot = 0usize;
    let mut vfp_slot = 0usize;
    let mut layout = Vec::with_capacity(contract.params.len());
    for parameter in contract.params {
        let c_type = parameter.c_type.trim();
        let storage = match c_type {
            "float" => {
                if vfp_slot >= 16 {
                    return None;
                }
                let register = VReg::phys(format!("s{vfp_slot}"));
                vfp_slot += 1;
                register
            }
            "double" => {
                vfp_slot += vfp_slot % 2;
                if vfp_slot + 1 >= 16 {
                    return None;
                }
                let register = VReg::phys(format!("d{}", vfp_slot / 2));
                vfp_slot += 2;
                register
            }
            "long double" | "long long" | "unsigned long long" | "int64_t" | "uint64_t" => {
                return None;
            }
            _ if c_type.contains('*')
                || matches!(
                    c_type,
                    "char"
                        | "signed char"
                        | "unsigned char"
                        | "short"
                        | "unsigned short"
                        | "int"
                        | "unsigned int"
                        | "long"
                        | "unsigned long"
                        | "pid_t"
                        | "socklen_t"
                        | "useconds_t"
                        | "size_t"
                        | "ssize_t"
                        | "intptr_t"
                        | "uintptr_t"
                        | "time_t"
                        | "clock_t"
                        | "pthread_t"
                ) =>
            {
                if core_slot >= 4 {
                    return None;
                }
                let register = VReg::phys(format!("r{core_slot}"));
                core_slot += 1;
                register
            }
            _ => return None,
        };
        layout.push(storage);
    }
    Some(layout)
}

/// Whether a source-ordered AAPCS layout is exactly the contiguous r0-r3
/// prefix used by one-word scalar parameters.
pub(super) fn aapcs_core_register_arity(layout: &[VReg]) -> Option<usize> {
    if layout.len() > 4 {
        return None;
    }
    layout
        .iter()
        .enumerate()
        .all(|(slot, storage)| {
            matches!(storage, VReg::Phys(name) if ssa_base(name) == format!("r{slot}"))
        })
        .then_some(layout.len())
}

fn arm_hard_float_slot_of(name: &str) -> Option<usize> {
    let base = ssa_base(name);
    crate::ir::abi::arm_hard_float_argument_slots()
        .iter()
        .position(|aliases| aliases.contains(&base))
}

/// Fold a proven pure-VFP call setup.
///
/// AAPCS-VFP has two independent allocation banks, so flattening r0-r3 and
/// s0-s15 into one invented order would corrupt mixed signatures. This helper
/// handles the unambiguous case: a contiguous s0..sN setup with no core-bank
/// argument write in the same setup window. Mixed calls remain on the existing
/// core-bank path until a recovered callee prototype supplies source order.
pub(super) fn fold_one_arm_hard_float_call(body: &mut Vec<Stmt>, call_idx: usize) -> bool {
    let slots = crate::ir::abi::arm_hard_float_argument_slots();
    let mut found: Vec<Option<(usize, Expr)>> = vec![None; slots.len()];
    let mut saw_vfp = false;
    let mut saw_core = false;
    let mut index = call_idx;

    while index > 0 {
        index -= 1;
        match &body[index] {
            Stmt::Assign {
                dst: VReg::Phys(name),
                src,
            } => {
                if let Some(slot) = arm_hard_float_slot_of(name) {
                    saw_vfp = true;
                    if found[slot].is_none() {
                        found[slot] = Some((index, src.clone()));
                    }
                    continue;
                }
                if crate::ir::abi::argument_slot_of(CallConv::Arm, name).is_some() {
                    saw_core = true;
                }
                if saw_vfp {
                    break;
                }
            }
            Stmt::Nop | Stmt::Comment(_) => {}
            _ => break,
        }
    }

    if !saw_vfp || saw_core {
        return false;
    }
    let Some(last) = found.iter().rposition(Option::is_some) else {
        return false;
    };
    if found[..=last].iter().any(Option::is_none) {
        return false;
    }

    let args = found[..=last]
        .iter()
        .map(|slot| {
            slot.as_ref()
                .expect("checked contiguous VFP prefix")
                .1
                .clone()
        })
        .collect();
    if let Stmt::Call {
        args: call_args, ..
    } = &mut body[call_idx]
    {
        *call_args = args;
    } else {
        return false;
    }

    let mut used: Vec<usize> = found[..=last]
        .iter()
        .map(|slot| slot.as_ref().expect("checked contiguous VFP prefix").0)
        .collect();
    used.sort_unstable_by(|left, right| right.cmp(left));
    for statement in used {
        body.remove(statement);
    }
    true
}

/// Number of source-ordered stack parameters in an integer-only AAPCS layout.
///
/// `argN` is the prototype layer's explicit marker for a locked source
/// parameter that has no entry-register SSA identity. Requiring the exact
/// `r0..r3, arg4..argN` sequence keeps this proof separate from mixed VFP
/// layouts, whose two allocation banks need their own stack-location model.
pub(super) fn aapcs_integer_stack_suffix(layout: &[VReg]) -> Option<usize> {
    if layout.len() <= 4 {
        return None;
    }
    for (slot, storage) in layout.iter().enumerate() {
        let VReg::Phys(name) = storage else {
            return None;
        };
        let expected = if slot < 4 {
            format!("r{slot}")
        } else {
            format!("arg{slot}")
        };
        if ssa_base(name) != expected {
            return None;
        }
    }
    Some(layout.len() - 4)
}

/// Recover an exact preallocated AAPCS outgoing stack suffix.
///
/// ARM compilers routinely interleave `[sp,#N]` argument stores with pure
/// register setup and reuse r2/r3 for the stack values before installing the
/// final core-register arguments. The locked callee layout supplies the exact
/// number of stack parameters. Within the current straight-line call window we
/// then require one nearest 4-byte store for every offset `0,4,..`; a call,
/// control boundary, stack-pointer write, unrelated store, duplicate, or gap
/// rejects the whole candidate.
pub(super) fn outgoing_aapcs_stack_area(
    body: &[Stmt],
    call_index: usize,
    expected_args: usize,
) -> Option<(Vec<Expr>, Vec<usize>)> {
    if expected_args == 0 {
        return None;
    }
    let expected_bytes = i64::try_from(expected_args).ok()?.checked_mul(4)?;
    let mut by_offset = std::collections::BTreeMap::new();
    let mut cursor = call_index;
    while cursor > 0 {
        let index = cursor - 1;
        match &body[index] {
            Stmt::Store { addr, src, size: 4 } => {
                let disp = match addr {
                    Expr::Reg(VReg::Phys(base)) if ssa_base(base) == "sp" => 0,
                    Expr::Lea {
                        base: Some(VReg::Phys(base)),
                        index: None,
                        disp,
                        ..
                    } if ssa_base(base) == "sp" => *disp,
                    _ => return None,
                };
                if disp < 0 || disp >= expected_bytes || disp % 4 != 0 {
                    return None;
                }
                if by_offset.insert(disp, (index, src.clone())).is_some() {
                    return None;
                }
                if by_offset.len() == expected_args {
                    break;
                }
            }
            Stmt::Assign {
                dst: VReg::Phys(name),
                ..
            } if ssa_base(name) == "sp" => return None,
            Stmt::Assign { .. } => {}
            Stmt::Comment(_) | Stmt::Nop => {}
            // Do not cross a prior call/control boundary or an unproved memory
            // side effect to assemble one call from unrelated stack state.
            _ => return None,
        }
        cursor = index;
    }
    if by_offset.len() != expected_args {
        return None;
    }
    let mut arguments = Vec::with_capacity(expected_args);
    let mut indices = Vec::with_capacity(expected_args);
    for (slot, (offset, (index, value))) in by_offset.into_iter().enumerate() {
        if offset != i64::try_from(slot).ok()?.checked_mul(4)? {
            return None;
        }
        arguments.push(value);
        indices.push(index);
    }
    Some((arguments, indices))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reg(n: &str) -> VReg {
        VReg::phys(n)
    }

    fn call_to(name: &str) -> Stmt {
        Stmt::Call {
            target: Expr::Named {
                va: 0x2000,
                name: name.into(),
            },
            args: vec![],
            dst: None,
            call_spec: None,
        }
    }

    #[test]
    fn aapcs_stack_area_does_not_cross_an_intervening_call() {
        let store = |disp, value| Stmt::Store {
            addr: Expr::Lea {
                base: Some(reg("sp")),
                index: None,
                scale: 1,
                disp,
                segment: None,
            },
            src: Expr::Const(value),
            size: 4,
        };
        let body = vec![
            store(4, 6),
            call_to("clobber"),
            store(0, 5),
            call_to("callee"),
        ];

        assert_eq!(
            outgoing_aapcs_stack_area(&body, 3, 2),
            None,
            "stack slots separated by a call are not one outgoing area"
        );
    }
}
