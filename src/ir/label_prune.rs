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

fn collect_goto_targets(body: &[Stmt], out: &mut HashSet<u64>) {
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
            Stmt::While { body, .. } => drop_unreferenced(body, referenced),
            _ => {}
        }
    }

    body.retain(|s| !matches!(s, Stmt::Label(va) if !referenced.contains(va)));
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
            body: vec![
                Stmt::Label(0x100),
                Stmt::Nop,
                Stmt::Return { value: None },
            ],
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
}
