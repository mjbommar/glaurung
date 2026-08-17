//! Return-value folds: turning a machine result carrier into a `return`.
//!
//! The lowered body writes a function's result to the ABI return register and
//! then executes an operand-free `Return`. C has no such shape, so these folds
//! rewrite it into the direct `return E;` a source reader expects:
//!
//! * [`fold_returns`] collapses `result = E; return result;` in place, and is
//!   run inside `lower`.
//! * [`fold_exhaustive_if_returns`] and [`fold_exhaustive_switch_returns`] move
//!   a *shared* trailing return into every arm of a total branch, so each arm
//!   ends in its own `return`.
//! * [`remove_redundant_return_constant_assignments`] is the late cleanup for
//!   the assignment a fold left behind because the return already carried the
//!   same constant.
//!
//! All four are transformations of an already-lowered [`Function`]; none of
//! them consult LLIR. The result-storage question — whether a given `VReg` is
//! genuinely the machine's return slot rather than a coalesced local — belongs
//! to [`crate::ir::direct_output`] and is asked there, not restated here.

use super::{is_promoted_local, Expr, Function, Stmt};
use crate::ir::types::VReg;

/// Collapse `result = E; [comments]; return result;` into a direct `return E`,
/// retaining provenance comments in place.
///
/// Both operand-free and explicit returns require proven machine result storage.
/// [`crate::ir::direct_output::is_exact_return_storage`] accepts its exact SSA
/// spelling (for example `rax#7`) while rejecting a returned source local or
/// coalesced parameter. Recurses into nested If / While bodies. Only
/// comments/Nops may intervene, so the expression stays at the same observable
/// point and no state-changing operation is crossed.
pub(super) fn fold_returns(body: &mut Vec<Stmt>) {
    // Recurse first so inner bodies are folded before we inspect an outer
    // fall-through return.
    for s in body.iter_mut() {
        match s {
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                fold_returns(then_body);
                if let Some(eb) = else_body {
                    fold_returns(eb);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => fold_returns(body),
            Stmt::For { body, .. } => fold_returns(body),
            Stmt::Switch { cases, default, .. } => {
                for (_, body) in cases.iter_mut() {
                    fold_returns(body);
                }
                if let Some(b) = default {
                    fold_returns(b);
                }
            }
            _ => {}
        }
    }

    let mut i = 0;
    while i < body.len() {
        let Some(dst) = (match &body[i] {
            Stmt::Assign { dst, .. } if crate::ir::direct_output::is_exact_return_storage(dst) => {
                Some(dst.clone())
            }
            _ => None,
        }) else {
            i += 1;
            continue;
        };
        let mut return_index = i + 1;
        while matches!(body.get(return_index), Some(Stmt::Comment(_) | Stmt::Nop)) {
            return_index += 1;
        }
        let fold_here = match body.get(return_index) {
            Some(Stmt::Return { value: None }) => true,
            Some(Stmt::Return {
                value: Some(Expr::Reg(returned)),
            }) => returned == &dst,
            _ => false,
        };
        if fold_here {
            let Stmt::Assign { src, .. } = body.remove(i) else {
                unreachable!()
            };
            body[return_index - 1] = Stmt::Return { value: Some(src) };
            continue;
        }
        i += 1;
    }
}

/// Remove an ABI return-register assignment immediately before an identical
/// constant return. This deliberately runs after structural recovery: the
/// assignment may still identify a shared switch destination while the CFG is
/// being reconstructed, but it is redundant in the final source AST.
pub(crate) fn remove_redundant_return_constant_assignments(body: &mut Vec<Stmt>) {
    for stmt in body.iter_mut() {
        match stmt {
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                remove_redundant_return_constant_assignments(then_body);
                if let Some(else_body) = else_body {
                    remove_redundant_return_constant_assignments(else_body);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
                remove_redundant_return_constant_assignments(body);
            }
            Stmt::Switch { cases, default, .. } => {
                for (_, case_body) in cases {
                    remove_redundant_return_constant_assignments(case_body);
                }
                if let Some(default_body) = default {
                    remove_redundant_return_constant_assignments(default_body);
                }
            }
            _ => {}
        }
    }

    let mut index = 0;
    while index < body.len() {
        let assigned = match &body[index] {
            Stmt::Assign {
                dst,
                src: Expr::Const(value),
            } if crate::ir::direct_output::is_return_reg(dst) => Some(*value),
            _ => None,
        };
        let Some(assigned) = assigned else {
            index += 1;
            continue;
        };
        let mut return_index = index + 1;
        while matches!(body.get(return_index), Some(Stmt::Comment(_) | Stmt::Nop)) {
            return_index += 1;
        }
        let identical_return = matches!(
            body.get(return_index),
            Some(Stmt::Return {
                value: Some(Expr::Const(returned)),
            }) if *returned == assigned
        );
        if identical_return {
            body.remove(index);
            continue;
        }
        index += 1;
    }
}

/// Turn an exhaustive switch that defines one result immediately consumed by a
/// trailing return into returns in each arm.
///
/// An explicit default makes the switch exhaustive for every discriminator.
/// Requiring the same destination in every arm, immediately at the arm's end,
/// proves that the join contains no additional state transition to preserve.
/// The optional terminal `Break` is the structured spelling of the edge to that
/// join and disappears with the join itself.
pub fn fold_exhaustive_switch_returns(function: &mut Function) {
    // Typed/lossless range recovery can expose the switch only after an
    // adjacent `ret = cast(join); return ret` pair was first prepared. Normalize
    // that pair here as well so every caller sees the same join shape.
    fold_returns(&mut function.body);
    fold_exhaustive_switch_returns_body(&mut function.body);
}

/// Move a joined result return into terminating arms of an exhaustive `if` tree.
///
/// Both arms must end by defining the exact returned value (possibly through
/// another exhaustive `if`).  Calls and other statements earlier in an arm stay
/// in place; only its terminal definition becomes a return.  Machine-epilogue
/// comments and nops may separate the `if` from the joined return because they
/// carry no source-level state.  If only the `then` arm defines the joined
/// result, it becomes an early return and the original `else` arm becomes
/// ordinary fallthrough before the still-shared return.  This is the same
/// control flow with one unnecessary region join removed.
pub fn fold_exhaustive_if_returns(function: &mut Function) {
    fold_returns(&mut function.body);
    fold_exhaustive_if_returns_body(&mut function.body);
}

fn fold_exhaustive_if_returns_body(body: &mut Vec<Stmt>) {
    for statement in body.iter_mut() {
        match statement {
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                fold_exhaustive_if_returns_body(then_body);
                if let Some(else_body) = else_body {
                    fold_exhaustive_if_returns_body(else_body);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
                fold_exhaustive_if_returns_body(body)
            }
            Stmt::Switch { cases, default, .. } => {
                for (_, case_body) in cases {
                    fold_exhaustive_if_returns_body(case_body);
                }
                if let Some(default_body) = default {
                    fold_exhaustive_if_returns_body(default_body);
                }
            }
            _ => {}
        }
    }

    let mut index = 0;
    while index + 1 < body.len() {
        let mut return_index = index + 1;
        while match body.get(return_index) {
            Some(Stmt::Nop) => true,
            Some(Stmt::Comment(text)) => text.starts_with("x86-64 epilogue:"),
            _ => false,
        } {
            return_index += 1;
        }
        let Some((result, return_template)) = (match body.get(return_index) {
            Some(Stmt::Return { value: Some(value) }) => {
                cast_chain_root_reg(value).map(|result| (result.clone(), value.clone()))
            }
            _ => None,
        }) else {
            index += 1;
            continue;
        };
        let Stmt::If {
            cond,
            mut then_body,
            else_body: Some(mut else_body),
        } = body[index].clone()
        else {
            index += 1;
            continue;
        };
        let fallthrough_body = else_body.clone();
        if !turn_terminal_result_into_return(&mut then_body, &result, &return_template) {
            index += 1;
            continue;
        }
        if !turn_terminal_result_into_return(&mut else_body, &result, &return_template) {
            body[index] = Stmt::If {
                cond,
                then_body,
                else_body: None,
            };
            body.splice(index + 1..index + 1, fallthrough_body);
            index += 1;
            continue;
        }

        body[index] = Stmt::If {
            cond,
            then_body,
            else_body: Some(else_body),
        };
        body.drain(index + 1..=return_index);
        index += 1;
    }
}

fn fold_exhaustive_switch_returns_body(body: &mut Vec<Stmt>) {
    for statement in body.iter_mut() {
        match statement {
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                fold_exhaustive_switch_returns_body(then_body);
                if let Some(else_body) = else_body {
                    fold_exhaustive_switch_returns_body(else_body);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
                fold_exhaustive_switch_returns_body(body);
            }
            Stmt::Switch { cases, default, .. } => {
                for (_, case_body) in cases {
                    fold_exhaustive_switch_returns_body(case_body);
                }
                if let Some(default_body) = default {
                    fold_exhaustive_switch_returns_body(default_body);
                }
            }
            _ => {}
        }
    }

    let mut index = 0;
    while index + 1 < body.len() {
        // Frame recognisers retain provenance comments at the machine epilogue.
        // They carry no state, so they do not invalidate an otherwise immediate
        // switch-result join.
        let mut return_index = index + 1;
        while matches!(body.get(return_index), Some(Stmt::Comment(_) | Stmt::Nop)) {
            return_index += 1;
        }
        let Some((result, return_template)) = (match body.get(return_index) {
            Some(Stmt::Return { value: Some(value) }) => {
                cast_chain_root_reg(value).map(|result| (result.clone(), value.clone()))
            }
            _ => None,
        }) else {
            index += 1;
            continue;
        };
        let Stmt::Switch {
            discriminant,
            mut cases,
            default: Some(mut default),
        } = body[index].clone()
        else {
            index += 1;
            continue;
        };

        if !cases.iter_mut().all(|(_, case_body)| {
            turn_terminal_result_into_return(case_body, &result, &return_template)
        }) || !turn_terminal_result_into_return(&mut default, &result, &return_template)
        {
            index += 1;
            continue;
        }

        body[index] = Stmt::Switch {
            discriminant,
            cases,
            default: Some(default),
        };
        body.remove(return_index);
        index += 1;
    }
}

fn cast_chain_root_reg(expr: &Expr) -> Option<&VReg> {
    match expr {
        Expr::Reg(reg) => Some(reg),
        Expr::Cast { expr, .. } => cast_chain_root_reg(expr),
        _ => None,
    }
}

fn apply_return_cast_template(template: &Expr, result: &VReg, value: Expr) -> Option<Expr> {
    match template {
        Expr::Reg(reg) if reg == result => Some(value),
        Expr::Cast {
            signed,
            width,
            expr,
        } => Some(Expr::Cast {
            signed: *signed,
            width: *width,
            expr: Box::new(apply_return_cast_template(expr, result, value)?),
        }),
        _ => None,
    }
}

fn turn_terminal_result_into_return(
    body: &mut Vec<Stmt>,
    result: &VReg,
    return_template: &Expr,
) -> bool {
    if matches!(body.last(), Some(Stmt::Break)) {
        body.pop();
    }
    let Some(last) = body.last_mut() else {
        return false;
    };
    match last {
        Stmt::Assign { dst, src } if dst == result => {
            let Some(value) = apply_return_cast_template(return_template, result, src.clone())
            else {
                return false;
            };
            *last = Stmt::Return { value: Some(value) };
            true
        }
        Stmt::Store {
            addr: Expr::Reg(dst),
            src,
            ..
        } if dst == result && matches!(&*dst, VReg::Phys(name) if is_promoted_local(name)) => {
            let Some(value) = apply_return_cast_template(return_template, result, src.clone())
            else {
                return false;
            };
            *last = Stmt::Return { value: Some(value) };
            true
        }
        Stmt::Return { .. } => true,
        Stmt::If {
            then_body,
            else_body: Some(else_body),
            ..
        } => {
            let mut converted_then = then_body.clone();
            let mut converted_else = else_body.clone();
            if !turn_terminal_result_into_return(&mut converted_then, result, return_template)
                || !turn_terminal_result_into_return(&mut converted_else, result, return_template)
            {
                return false;
            }
            *then_body = converted_then;
            *else_body = converted_else;
            true
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn return_fold_collapses_an_exact_ssa_result_carrier() {
        let mut body = vec![
            Stmt::Assign {
                dst: VReg::phys("rax#7"),
                src: Expr::Const(42),
            },
            Stmt::Return {
                value: Some(Expr::Reg(VReg::phys("rax#7"))),
            },
        ];

        fold_returns(&mut body);

        assert_eq!(
            body,
            vec![Stmt::Return {
                value: Some(Expr::Const(42)),
            }]
        );
    }

    #[test]
    fn late_return_cleanup_removes_redundant_identical_constant_assignment() {
        let mut body = vec![
            Stmt::Assign {
                dst: VReg::phys("ret"),
                src: Expr::Const(-1),
            },
            Stmt::Return {
                value: Some(Expr::Const(-1)),
            },
        ];

        remove_redundant_return_constant_assignments(&mut body);

        assert_eq!(
            body,
            vec![Stmt::Return {
                value: Some(Expr::Const(-1)),
            }]
        );
    }

    #[test]
    fn late_return_cleanup_preserves_mismatched_constant_assignment() {
        let mut body = vec![
            Stmt::Assign {
                dst: VReg::phys("ret"),
                src: Expr::Const(-1),
            },
            Stmt::Return {
                value: Some(Expr::Const(0)),
            },
        ];
        let expected = body.clone();

        remove_redundant_return_constant_assignments(&mut body);

        assert_eq!(body, expected);
    }
}
