//! Drop labels whose VA is never referenced by a `goto`.
//!
//! Each unstructured block lowers to a `Stmt::Label(va)` + its statements.
//! When structural analysis recognises a Seq/If/While region, the blocks
//! inside stop needing a Label because control arrives through structured
//! flow. But a few labels still survive — typically in the Unstructured
//! fallback — and clutter the output.
//!
//! This pass walks the body, collects every `Stmt::Goto { target }`'s VA
//! (plus every If/While cond-jump target we can observe), and removes any
//! `Stmt::Label(va)` whose VA doesn't appear in that set.

use std::collections::HashSet;

use crate::ir::ast::{Expr, Function, Stmt};

/// Remove labels whose VA is never referenced by a `goto` within `f`.
pub fn prune_unreferenced_labels(f: &mut Function) {
    let mut referenced: HashSet<u64> = HashSet::new();
    collect_goto_targets(&f.body, &mut referenced);
    drop_unreferenced(&mut f.body, &referenced);
}

/// Remove statements that cannot be reached by sequential execution after an
/// unconditional terminator, then discard labels whose only incoming goto was
/// itself in the removed tail.
///
/// Every surviving label is conservatively treated as a possible entry while
/// scanning a statement list. This means the pass can remove a tail after
/// `return`, `goto`, `break`, or an indirect goto without pretending to solve
/// cross-region reachability. Repeating tail removal and target-based label
/// pruning reaches the useful fixed point for compiler-generated shared-return
/// epilogues while preserving every externally referenced label.
pub fn prune_unreachable_tails(f: &mut Function) {
    loop {
        let before = f.clone();
        prune_unreachable_body(&mut f.body);
        prune_unreferenced_labels(f);
        if *f == before {
            break;
        }
    }
}

fn prune_unreachable_body(body: &mut Vec<Stmt>) {
    for statement in body.iter_mut() {
        match statement {
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                prune_unreachable_body(then_body);
                if let Some(else_body) = else_body {
                    prune_unreachable_body(else_body);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
                prune_unreachable_body(body)
            }
            Stmt::Switch { cases, default, .. } => {
                for (_, case_body) in cases {
                    prune_unreachable_body(case_body);
                }
                if let Some(default) = default {
                    prune_unreachable_body(default);
                }
            }
            _ => {}
        }
    }

    let mut reachable = true;
    body.retain(|statement| {
        if matches!(statement, Stmt::Label(_)) {
            // A label may be entered by a goto from any nested region. Target
            // pruning below will remove it on the next iteration if no such
            // edge survives.
            reachable = true;
        }
        if !reachable {
            return false;
        }
        if matches!(
            statement,
            Stmt::Return { .. } | Stmt::Goto { .. } | Stmt::IndirectGoto { .. } | Stmt::Break
        ) {
            reachable = false;
        }
        true
    });
}

/// Collect every concrete goto target in an already-lowered AST.
///
/// Lowering uses this too: raw block terminators can survive inside a recovered
/// switch even though they are not represented as `Region::Goto` nodes.  A
/// second, target-aware lowering pass then puts labels on the blocks those
/// statements actually reach.
pub(crate) fn collect_goto_targets(body: &[Stmt], out: &mut HashSet<u64>) {
    for s in body {
        match s {
            Stmt::Goto { target } => {
                out.insert(*target);
            }
            Stmt::If {
                cond,
                then_body,
                else_body,
            } => {
                collect_expr_goto(cond, out);
                collect_goto_targets(then_body, out);
                if let Some(eb) = else_body {
                    collect_goto_targets(eb, out);
                }
            }
            Stmt::While { cond, body } => {
                collect_expr_goto(cond, out);
                collect_goto_targets(body, out);
            }
            Stmt::For {
                init,
                cond,
                step,
                body,
            } => {
                collect_goto_targets(std::slice::from_ref(init.as_ref()), out);
                collect_expr_goto(cond, out);
                collect_goto_targets(body, out);
                collect_goto_targets(std::slice::from_ref(step.as_ref()), out);
            }
            Stmt::DoWhile { body, cond } => {
                collect_goto_targets(body, out);
                collect_expr_goto(cond, out);
            }
            Stmt::Switch {
                discriminant,
                cases,
                default,
            } => {
                collect_expr_goto(discriminant, out);
                for (_, case_body) in cases {
                    collect_goto_targets(case_body, out);
                }
                if let Some(default_body) = default {
                    collect_goto_targets(default_body, out);
                }
            }
            _ => {}
        }
    }
}

fn collect_expr_goto(_e: &Expr, _out: &mut HashSet<u64>) {
    // Expressions don't carry goto targets in our AST. Left as a no-op
    // for future-proofing (e.g. if we ever model computed goto).
}

fn drop_unreferenced(body: &mut Vec<Stmt>, referenced: &HashSet<u64>) {
    // Recurse into nested bodies first so inner arms are pruned
    // independently.
    for s in body.iter_mut() {
        match s {
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                drop_unreferenced(then_body, referenced);
                if let Some(eb) = else_body {
                    drop_unreferenced(eb, referenced);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
                drop_unreferenced(body, referenced)
            }
            Stmt::For { body, .. } => drop_unreferenced(body, referenced),
            Stmt::Switch { cases, default, .. } => {
                for (_, case_body) in cases {
                    drop_unreferenced(case_body, referenced);
                }
                if let Some(default_body) = default {
                    drop_unreferenced(default_body, referenced);
                }
            }
            _ => {}
        }
    }

    // An imported/thunk region can end in an indirect jump or in the Call +
    // Return produced by tail-call recovery. Region recovery may place that
    // stub before the current function's lexical fallthrough. The following
    // label is then the only remaining boundary for that fallthrough because
    // structuring consumed its explicit conditional edge. Keep every label
    // immediately after an unconditional terminator: without CFG provenance at
    // this layer, deleting such a boundary is not a sound reachability proof.
    let after_terminator: HashSet<u64> =
        body.windows(2)
            .filter_map(|pair| match pair {
                [Stmt::Return { .. }
                | Stmt::Goto { .. }
                | Stmt::IndirectGoto { .. }
                | Stmt::Break, Stmt::Label(va)] => Some(*va),
                _ => None,
            })
            .collect();
    body.retain(|s| {
        !matches!(s, Stmt::Label(va) if !referenced.contains(va) && !after_terminator.contains(va))
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::ast::{Function, Stmt};

    #[test]
    fn unreferenced_label_is_dropped() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![Stmt::Label(0x100), Stmt::Nop, Stmt::Return { value: None }],
        };
        prune_unreferenced_labels(&mut f);
        assert_eq!(f.body.len(), 2);
        assert!(matches!(&f.body[0], Stmt::Nop));
        assert!(matches!(&f.body[1], Stmt::Return { .. }));
    }

    #[test]
    fn referenced_label_is_kept() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Goto { target: 0x100 },
                Stmt::Label(0x100),
                Stmt::Return { value: None },
            ],
        };
        let orig = f.clone();
        prune_unreferenced_labels(&mut f);
        assert_eq!(f, orig);
    }

    #[test]
    fn label_inside_if_is_pruned_when_unreferenced() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![Stmt::If {
                cond: Expr::Const(1),
                then_body: vec![Stmt::Label(0x200), Stmt::Nop],
                else_body: None,
            }],
        };
        prune_unreferenced_labels(&mut f);
        if let Stmt::If { then_body, .. } = &f.body[0] {
            assert_eq!(then_body.len(), 1);
            assert!(matches!(&then_body[0], Stmt::Nop));
        }
    }

    #[test]
    fn label_is_kept_when_only_referenced_from_nested_arm() {
        // `if (...) { goto L_100; }  L_100: return;`
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::If {
                    cond: Expr::Const(1),
                    then_body: vec![Stmt::Goto { target: 0x100 }],
                    else_body: None,
                },
                Stmt::Label(0x100),
                Stmt::Return { value: None },
            ],
        };
        prune_unreferenced_labels(&mut f);
        // Label 0x100 must survive.
        assert!(f.body.iter().any(|s| matches!(s, Stmt::Label(0x100))));
    }

    #[test]
    fn label_is_kept_when_only_referenced_from_switch_arm() {
        // A jump-table arm may converge on a loop latch emitted after the
        // switch.  That edge is just as real as one nested in an `if`; pruning
        // its target changes the jump into the renderer's trailing empty label.
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Switch {
                    discriminant: Expr::Reg(crate::ir::types::VReg::phys("state")),
                    cases: vec![(Some(0), vec![Stmt::Goto { target: 0x100 }])],
                    default: None,
                },
                Stmt::Label(0x100),
                Stmt::Return { value: None },
            ],
        };

        prune_unreferenced_labels(&mut f);

        assert!(f.body.iter().any(|s| matches!(s, Stmt::Label(0x100))));
    }

    #[test]
    fn return_prunes_trailing_statements_then_their_now_unreferenced_label() {
        let result = crate::ir::types::VReg::phys("local_4");
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Store {
                    addr: Expr::Reg(result.clone()),
                    src: Expr::Const(0),
                    size: 4,
                },
                Stmt::Label(0x100),
                Stmt::Return {
                    value: Some(Expr::Reg(result.clone())),
                },
                Stmt::Store {
                    addr: Expr::Reg(result),
                    src: Expr::Const(1),
                    size: 4,
                },
                Stmt::Goto { target: 0x100 },
            ],
        };

        prune_unreachable_tails(&mut f);

        assert_eq!(
            f.body.len(),
            2,
            "unreachable tail and dead label: {:?}",
            f.body
        );
        assert!(matches!(f.body[0], Stmt::Store { .. }));
        assert!(matches!(f.body[1], Stmt::Return { .. }));
    }

    #[test]
    fn referenced_label_after_return_remains_a_reachable_entry() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::If {
                    cond: Expr::Reg(crate::ir::types::VReg::phys("cond")),
                    then_body: vec![Stmt::Goto { target: 0x100 }],
                    else_body: None,
                },
                Stmt::Return { value: None },
                Stmt::Label(0x100),
                Stmt::Return {
                    value: Some(Expr::Const(1)),
                },
            ],
        };

        let expected = f.clone();
        prune_unreachable_tails(&mut f);

        assert_eq!(f, expected, "a live goto keeps its target entry reachable");
    }

    #[test]
    fn block_after_indirect_tail_jump_remains_a_region_entry() {
        // Real `describe_change` contains imported tail-call blocks in the
        // recovered region before the function's conditional fallthrough.
        // The fallthrough label has no explicit Goto after structuring, but it
        // is still the boundary that prevents unreachable-tail cleanup from
        // deleting the rest of the function after the imported IndirectGoto.
        let mut f = Function {
            name: "describe_change".into(),
            entry_va: 0x3630,
            body: vec![
                Stmt::IndirectGoto {
                    target: Expr::Reg(crate::ir::types::VReg::phys("plt_target")),
                },
                Stmt::Label(0x364a),
                Stmt::Assign {
                    dst: crate::ir::types::VReg::phys("result"),
                    src: Expr::Const(7),
                },
                Stmt::Return {
                    value: Some(Expr::Reg(crate::ir::types::VReg::phys("result"))),
                },
            ],
        };

        prune_unreachable_tails(&mut f);

        assert_eq!(
            f.body.len(),
            4,
            "fallthrough region was deleted: {:#?}",
            f.body
        );
        assert!(matches!(f.body[1], Stmt::Label(0x364a)));
        assert!(matches!(f.body[2], Stmt::Assign { .. }));
    }

    #[test]
    fn block_after_recovered_tail_call_return_remains_a_region_entry() {
        // Tail-call recovery turns the indirect PLT jump into Call + Return
        // before label cleanup. `describe_change` therefore reaches this exact
        // spelling when its real fallthrough region follows imported stubs.
        let mut f = Function {
            name: "describe_change".into(),
            entry_va: 0x3630,
            body: vec![
                Stmt::Call {
                    target: Expr::Named {
                        va: 0x2480,
                        name: "free".into(),
                    },
                    args: vec![],
                    dst: None,
                },
                Stmt::Return { value: None },
                Stmt::Label(0x364a),
                Stmt::Assign {
                    dst: crate::ir::types::VReg::phys("result"),
                    src: Expr::Const(7),
                },
                Stmt::Return {
                    value: Some(Expr::Reg(crate::ir::types::VReg::phys("result"))),
                },
            ],
        };

        prune_unreachable_tails(&mut f);

        assert_eq!(
            f.body.len(),
            5,
            "fallthrough region was deleted: {:#?}",
            f.body
        );
        assert!(matches!(f.body[2], Stmt::Label(0x364a)));
        assert!(matches!(f.body[3], Stmt::Assign { .. }));
    }
}
