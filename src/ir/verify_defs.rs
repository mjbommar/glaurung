//! Definition-before-use verification over the decompiled AST.
//!
//! A decompilation that reads a value it never produced is not "slightly wrong":
//! the emitted C reads an uninitialised variable, so the recompiled function
//! returns garbage. This is the single most common shape of value-model
//! corruption in this pipeline — a pass drops a definition while its uses
//! survive — and it is invisible to type_match / GED / byte_match.
//!
//! WHY IT RUNS HERE, ON THIS AST
//!
//! An earlier attempt checked the AST *before* rendering and had to be reverted:
//! `render_decbench_typed` folded copy chains while printing, so the checked AST
//! was not the AST that was emitted, and correct functions (`rt_u8`) were flagged.
//! That folding is now an explicit pass ([`crate::ir::ast::prepare_for_decbench`])
//! that runs before rendering, and the renderer is formatting-only. So there is a
//! single AST that is exactly what gets printed, and it is the one this module
//! checks.
//!
//! WHAT IS CHECKED
//!
//! Only names the decompiler itself invents and must therefore define:
//! `ret`, `varN`, `local_*`, `stack_*`, and lifter temporaries. Parameters
//! (`argN`) are defined by the ABI, and raw machine registers (`rsp`, `rbp`,
//! `rip`, …) are live-in state, so neither is a violation.
//!
//! Two rules, both chosen to have NO false positives:
//!
//! * [`ViolationKind::NeverDefined`] — the name is read but never assigned
//!   anywhere in the function. Control flow cannot rescue this: no path defines
//!   it. Always checked.
//! * [`ViolationKind::UsedBeforeDefinition`] — flow-sensitive, and deliberately
//!   *may*-defined rather than must-defined: a name defined in only one arm of an
//!   `if` counts as defined at the join, and a loop body is checked with its own
//!   definitions pre-seeded (a later iteration may have produced the value). Only
//!   attempted for structured bodies; a function containing `goto`/labels has
//!   flow this walk does not model, so the rule is skipped there rather than
//!   guessed at.

use std::collections::BTreeSet;

use crate::ir::ast::{Expr, Function, Stmt};
use crate::ir::types::VReg;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ViolationKind {
    /// Read somewhere, assigned nowhere in the function.
    NeverDefined,
    /// Read on a path that reaches no definition of it.
    UsedBeforeDefinition,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Violation {
    pub name: String,
    pub kind: ViolationKind,
}

impl std::fmt::Display for Violation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.kind {
            ViolationKind::NeverDefined => write!(f, "{} is read but never defined", self.name),
            ViolationKind::UsedBeforeDefinition => {
                write!(f, "{} is read before it is defined", self.name)
            }
        }
    }
}

/// The name of a value the decompiler invents and is therefore responsible for
/// defining, or `None` for parameters, machine registers, and flags.
fn checked_name(v: &VReg) -> Option<String> {
    match v {
        VReg::Phys(n) => {
            let invented = n == "ret"
                || n.starts_with("local_")
                || n.starts_with("stack_")
                || (n.starts_with("var") && n[3..].chars().all(|c| c.is_ascii_digit()) && n.len() > 3);
            invented.then(|| n.clone())
        }
        // A lifter temporary that survives into the emitted AST must have been
        // assigned there too.
        VReg::Temp(i) => Some(format!("t{i}")),
        VReg::Flag(_) => None,
    }
}

/// The ABI return-register role name: a `call` defines it (the callee's return
/// value lands there), so `foo(); return ret;` is not a use before definition.
const RETURN_ROLE: &str = "ret";

/// A store whose address is a bare promoted stack slot (`local_4`, `stack_0`) is a
/// DEFINITION of that slot, not a pointer store through it: the renderer prints it
/// as `local_4 = ...` (see `write_stmt_dec`'s `is_promoted_local` arm). Reading it
/// as a use of the address instead is how a first version of this checker managed
/// to flag half the corpus — including functions whose decompilation executes
/// correctly. The name must be a promoted slot: after parameter coalescing the
/// address can be an `argN`, and `*arg0 = x` really is a store through a pointer.
fn stored_slot(addr: &Expr) -> Option<String> {
    match addr {
        Expr::Reg(VReg::Phys(n)) if n.starts_with("local_") || n.starts_with("stack_") => {
            Some(n.clone())
        }
        _ => None,
    }
}

fn reads_expr(e: &Expr, out: &mut Vec<String>) {
    match e {
        Expr::Reg(v) => out.extend(checked_name(v)),
        Expr::Const(_)
        | Expr::Addr(_)
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::Unknown(_) => {}
        Expr::Lea { base, index, .. } | Expr::PdbFieldAddr { base, index, .. } => {
            out.extend(base.as_ref().and_then(checked_name));
            out.extend(index.as_ref().and_then(checked_name));
        }
        Expr::Deref { addr, .. } => reads_expr(addr, out),
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            reads_expr(lhs, out);
            reads_expr(rhs, out);
        }
        Expr::Un { src, .. } => reads_expr(src, out),
        Expr::Cast { expr, .. } => reads_expr(expr, out),
    }
}

fn reads_of(e: &Expr) -> Vec<String> {
    let mut v = Vec::new();
    reads_expr(e, &mut v);
    v
}

/// Every name defined anywhere in `body`, including nested bodies.
fn defs_in(body: &[Stmt], out: &mut BTreeSet<String>) {
    for s in body {
        match s {
            Stmt::Assign { dst, .. } => out.extend(checked_name(dst)),
            Stmt::Store { addr, .. } => out.extend(stored_slot(addr)),
            Stmt::Pop { target } => out.extend(checked_name(target)),
            // A call writes the return register.
            Stmt::Call { .. } => {
                out.insert(RETURN_ROLE.to_string());
            }
            Stmt::If { then_body, else_body, .. } => {
                defs_in(then_body, out);
                if let Some(e) = else_body {
                    defs_in(e, out);
                }
            }
            Stmt::While { body, .. } => defs_in(body, out),
            Stmt::Switch { cases, default, .. } => {
                for (_, b) in cases {
                    defs_in(b, out);
                }
                if let Some(d) = default {
                    defs_in(d, out);
                }
            }
            _ => {}
        }
    }
}

/// Does this body contain flow this walk does not model (a label or a goto)?
fn has_unstructured_flow(body: &[Stmt]) -> bool {
    body.iter().any(|s| match s {
        Stmt::Label(_) | Stmt::Goto { .. } => true,
        Stmt::If { then_body, else_body, .. } => {
            has_unstructured_flow(then_body)
                || else_body.as_deref().is_some_and(has_unstructured_flow)
        }
        Stmt::While { body, .. } => has_unstructured_flow(body),
        Stmt::Switch { cases, default, .. } => {
            cases.iter().any(|(_, b)| has_unstructured_flow(b))
                || default.as_deref().is_some_and(has_unstructured_flow)
        }
        _ => false,
    })
}

/// Names an expression reads that are not yet (maybe-)defined.
fn undefined_reads(e: &Expr, defined: &BTreeSet<String>, found: &mut BTreeSet<String>) {
    for name in reads_of(e) {
        if !defined.contains(&name) {
            found.insert(name);
        }
    }
}

/// Walk `body` forward, accumulating maybe-defined names in `defined` and
/// recording reads that no definition reaches.
fn walk(body: &[Stmt], defined: &mut BTreeSet<String>, found: &mut BTreeSet<String>) {
    for s in body {
        match s {
            Stmt::Assign { dst, src } => {
                // The source is evaluated first: `x = x + 1` reads x before this
                // definition of it.
                undefined_reads(src, defined, found);
                defined.extend(checked_name(dst));
            }
            Stmt::Store { addr, src, .. } => {
                undefined_reads(src, defined, found);
                match stored_slot(addr) {
                    // `local_4 = src` — a definition of the slot, not a use of it.
                    Some(slot) => {
                        defined.insert(slot);
                    }
                    None => undefined_reads(addr, defined, found),
                }
            }
            Stmt::Call { target, args } => {
                undefined_reads(target, defined, found);
                for a in args {
                    undefined_reads(a, defined, found);
                }
                defined.insert(RETURN_ROLE.to_string());
            }
            Stmt::Return { value } => {
                if let Some(v) = value {
                    undefined_reads(v, defined, found);
                }
            }
            Stmt::Push { value } => undefined_reads(value, defined, found),
            Stmt::Pop { target } => {
                defined.extend(checked_name(target));
            }
            Stmt::If { cond, then_body, else_body } => {
                undefined_reads(cond, defined, found);
                // Both arms start from the same state; the join takes the UNION
                // (maybe-defined), so a definition in one arm satisfies a use
                // after the `if`.
                let mut then_defined = defined.clone();
                walk(then_body, &mut then_defined, found);
                let mut else_defined = defined.clone();
                if let Some(e) = else_body {
                    walk(e, &mut else_defined, found);
                }
                defined.extend(then_defined);
                defined.extend(else_defined);
            }
            Stmt::While { cond, body } => {
                // A value the body defines is available to the condition and to
                // the body itself on every iteration after the first, so seed
                // both with the body's definitions.
                let mut body_defs = BTreeSet::new();
                defs_in(body, &mut body_defs);
                let mut loop_defined = defined.clone();
                loop_defined.extend(body_defs);
                undefined_reads(cond, &loop_defined, found);
                let mut inner = loop_defined.clone();
                walk(body, &mut inner, found);
                defined.extend(loop_defined);
            }
            Stmt::Switch { discriminant, cases, default } => {
                undefined_reads(discriminant, defined, found);
                let mut joined = defined.clone();
                for (_, b) in cases {
                    let mut arm = defined.clone();
                    walk(b, &mut arm, found);
                    joined.extend(arm);
                }
                if let Some(d) = default {
                    let mut arm = defined.clone();
                    walk(d, &mut arm, found);
                    joined.extend(arm);
                }
                *defined = joined;
            }
            Stmt::Label(_)
            | Stmt::Goto { .. }
            | Stmt::Break
            | Stmt::Nop
            | Stmt::Unknown(_)
            | Stmt::Comment(_) => {}
        }
    }
}

/// Collect every name read anywhere in `body`.
fn all_reads(body: &[Stmt], out: &mut BTreeSet<String>) {
    fn push(e: &Expr, out: &mut BTreeSet<String>) {
        out.extend(reads_of(e));
    }
    for s in body {
        match s {
            Stmt::Assign { src, .. } => push(src, out),
            Stmt::Store { addr, src, .. } => {
                if stored_slot(addr).is_none() {
                    push(addr, out);
                }
                push(src, out);
            }
            Stmt::Call { target, args } => {
                push(target, out);
                for a in args {
                    push(a, out);
                }
            }
            Stmt::Return { value } => {
                if let Some(v) = value {
                    push(v, out);
                }
            }
            Stmt::Push { value } => push(value, out),
            Stmt::If { cond, then_body, else_body } => {
                push(cond, out);
                all_reads(then_body, out);
                if let Some(e) = else_body {
                    all_reads(e, out);
                }
            }
            Stmt::While { cond, body } => {
                push(cond, out);
                all_reads(body, out);
            }
            Stmt::Switch { discriminant, cases, default } => {
                push(discriminant, out);
                for (_, b) in cases {
                    all_reads(b, out);
                }
                if let Some(d) = default {
                    all_reads(d, out);
                }
            }
            _ => {}
        }
    }
}

/// Verify `f`, returning every violation found (sorted, deduplicated by name and
/// kind). An empty result means every invented value the function reads has a
/// definition that reaches it.
pub fn check(f: &Function) -> Vec<Violation> {
    let mut defined = BTreeSet::new();
    defs_in(&f.body, &mut defined);
    let mut reads = BTreeSet::new();
    all_reads(&f.body, &mut reads);

    let mut out: Vec<Violation> = reads
        .difference(&defined)
        .map(|name| Violation {
            name: name.clone(),
            kind: ViolationKind::NeverDefined,
        })
        .collect();

    if !has_unstructured_flow(&f.body) {
        let mut flow_defined = BTreeSet::new();
        let mut found = BTreeSet::new();
        walk(&f.body, &mut flow_defined, &mut found);
        for name in found {
            // Already reported as never-defined; do not double-report.
            if defined.contains(&name) {
                out.push(Violation {
                    name,
                    kind: ViolationKind::UsedBeforeDefinition,
                });
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::ast::Expr;
    use crate::ir::types::{BinOp, CmpOp};

    fn phys(n: &str) -> VReg {
        VReg::phys(n)
    }

    fn reg(n: &str) -> Expr {
        Expr::Reg(phys(n))
    }

    fn assign(dst: &str, src: Expr) -> Stmt {
        Stmt::Assign {
            dst: phys(dst),
            src,
        }
    }

    fn func(body: Vec<Stmt>) -> Function {
        Function {
            name: "f".into(),
            entry_va: 0x1000,
            body,
        }
    }

    fn names(v: &[Violation]) -> Vec<String> {
        v.iter().map(|x| x.name.clone()).collect()
    }

    #[test]
    fn a_genuine_use_before_definition_is_reported() {
        // local_1 = ret;  ret = (u8)local_1;   <- `ret` is read with no def:
        // exactly the rt_u8 corruption the decbench lowering used to produce.
        let f = func(vec![
            assign("local_1", reg("ret")),
            assign("ret", reg("local_1")),
            Stmt::Return {
                value: Some(reg("ret")),
            },
        ]);
        let v = check(&f);
        assert!(
            v.iter()
                .any(|x| x.name == "ret" && x.kind == ViolationKind::UsedBeforeDefinition),
            "expected a use-before-definition for `ret`, got {v:?}"
        );
    }

    #[test]
    fn a_name_read_but_never_assigned_is_reported() {
        let f = func(vec![Stmt::Return {
            value: Some(reg("var7")),
        }]);
        let v = check(&f);
        assert_eq!(names(&v), vec!["var7"]);
        assert_eq!(v[0].kind, ViolationKind::NeverDefined);
    }

    #[test]
    fn the_correct_rt_u8_shape_is_not_flagged() {
        // The CORRECT lowering of `uint8_t rt_u8(long x){ return (uint8_t)x; }`:
        // every invented value is defined before it is read. This shape produced a
        // false positive in the reverted pre-render checker.
        let f = func(vec![
            assign("ret", reg("arg0")),
            assign("local_14", reg("ret")),
            assign(
                "ret",
                Expr::Cast {
                    signed: false,
                    width: 1,
                    expr: Box::new(reg("local_14")),
                },
            ),
            Stmt::Return {
                value: Some(reg("ret")),
            },
        ]);
        assert_eq!(check(&f), vec![], "correct output must not be flagged");
    }

    #[test]
    fn parameters_and_machine_registers_are_not_definitions_we_owe() {
        let f = func(vec![
            assign("var0", reg("arg3")),
            assign("var1", reg("rsp")),
            assign("var2", reg("rbp")),
            Stmt::Return {
                value: Some(reg("var0")),
            },
        ]);
        assert_eq!(check(&f), vec![]);
    }

    #[test]
    fn a_branch_local_definition_satisfies_a_use_at_the_join() {
        // if (arg0) { var1 = 1; } else { var1 = 2; }  return var1;
        let f = func(vec![
            Stmt::If {
                cond: reg("arg0"),
                then_body: vec![assign("var1", Expr::Const(1))],
                else_body: Some(vec![assign("var1", Expr::Const(2))]),
            },
            Stmt::Return {
                value: Some(reg("var1")),
            },
        ]);
        assert_eq!(check(&f), vec![]);
    }

    #[test]
    fn a_definition_in_only_one_arm_is_accepted_as_maybe_defined() {
        // Deliberately permissive: a def on one path is enough. The checker must
        // never cry wolf about a shape a compiler could legitimately produce.
        let f = func(vec![
            Stmt::If {
                cond: reg("arg0"),
                then_body: vec![assign("var1", Expr::Const(1))],
                else_body: None,
            },
            Stmt::Return {
                value: Some(reg("var1")),
            },
        ]);
        assert_eq!(check(&f), vec![]);
    }

    #[test]
    fn a_use_inside_a_branch_before_any_definition_is_reported() {
        let f = func(vec![
            Stmt::If {
                cond: reg("arg0"),
                then_body: vec![assign("var2", reg("var1"))],
                else_body: Some(vec![assign("var1", Expr::Const(2))]),
            },
            Stmt::Return {
                value: Some(reg("var2")),
            },
        ]);
        let v = check(&f);
        assert!(
            v.iter()
                .any(|x| x.name == "var1" && x.kind == ViolationKind::UsedBeforeDefinition),
            "got {v:?}"
        );
    }

    #[test]
    fn a_loop_carried_value_is_not_a_use_before_definition() {
        // while (var1 < 10) { var1 = var1 + 1; }  — the condition reads a value the
        // body defines on the previous iteration.
        let f = func(vec![
            assign("var1", Expr::Const(0)),
            Stmt::While {
                cond: Expr::Cmp {
                    op: CmpOp::Slt,
                    lhs: Box::new(reg("var1")),
                    rhs: Box::new(Expr::Const(10)),
                },
                body: vec![assign(
                    "var1",
                    Expr::Bin {
                        op: BinOp::Add,
                        lhs: Box::new(reg("var1")),
                        rhs: Box::new(Expr::Const(1)),
                    },
                )],
            },
            Stmt::Return {
                value: Some(reg("var1")),
            },
        ]);
        assert_eq!(check(&f), vec![]);
    }

    #[test]
    fn a_value_only_defined_in_a_loop_body_satisfies_a_later_use() {
        let f = func(vec![
            Stmt::While {
                cond: reg("arg0"),
                body: vec![assign("var3", Expr::Const(7))],
            },
            Stmt::Return {
                value: Some(reg("var3")),
            },
        ]);
        assert_eq!(check(&f), vec![]);
    }

    #[test]
    fn a_call_defines_the_return_register() {
        // foo(); return ret;  — the callee's return value lands in `ret`.
        let f = func(vec![
            Stmt::Call {
                target: Expr::Named {
                    va: 0x2000,
                    name: "foo".into(),
                },
                args: vec![],
            },
            Stmt::Return {
                value: Some(reg("ret")),
            },
        ]);
        assert_eq!(check(&f), vec![]);
    }

    #[test]
    fn unstructured_flow_disables_only_the_flow_sensitive_rule() {
        // With a label/goto present the walk cannot model the flow, so no
        // use-before-definition is claimed — but a name defined NOWHERE is still a
        // violation, because no control flow can rescue it.
        let f = func(vec![
            Stmt::Label(0x1010),
            assign("var1", reg("var9")),
            Stmt::Goto { target: 0x1010 },
        ]);
        let v = check(&f);
        assert_eq!(names(&v), vec!["var9"]);
        assert_eq!(v[0].kind, ViolationKind::NeverDefined);

        // A backward goto whose definition appears textually later is NOT reported
        // (the flow-sensitive rule is off for this body).
        let f2 = func(vec![
            Stmt::Label(0x1010),
            assign("var1", reg("var2")),
            assign("var2", Expr::Const(1)),
            Stmt::Goto { target: 0x1010 },
        ]);
        assert_eq!(check(&f2), vec![]);
    }

    #[test]
    fn a_store_to_a_promoted_slot_defines_it() {
        // The real `-O0` shape of `for (i = 0; i < n; i++)`: the slot is DEFINED by
        // a store whose address is the slot itself, which the renderer prints as
        // `local_4 = 0;`. Treating that address as a *use* is exactly how a first
        // version of this checker flagged half the fixture corpus, including
        // functions whose decompilation executes correctly.
        let f = func(vec![
            Stmt::Store {
                addr: reg("local_4"),
                src: Expr::Const(0),
                size: 4,
            },
            Stmt::While {
                cond: Expr::Cmp {
                    op: CmpOp::Slt,
                    lhs: Box::new(reg("local_4")),
                    rhs: Box::new(reg("arg1")),
                },
                body: vec![Stmt::Store {
                    addr: reg("local_4"),
                    src: Expr::Bin {
                        op: BinOp::Add,
                        lhs: Box::new(reg("local_4")),
                        rhs: Box::new(Expr::Const(1)),
                    },
                    size: 4,
                }],
            },
            Stmt::Return {
                value: Some(reg("local_4")),
            },
        ]);
        assert_eq!(check(&f), vec![], "a slot store is a definition of the slot");
    }

    #[test]
    fn a_store_through_a_pointer_parameter_is_not_a_definition() {
        // `*arg0 = local_8;` — the address is a parameter, so this is a real store
        // through a pointer, and the VALUE it stores is still a use.
        let f = func(vec![Stmt::Store {
            addr: reg("arg0"),
            src: reg("local_8"),
            size: 4,
        }]);
        assert_eq!(names(&check(&f)), vec!["local_8"]);
    }

    #[test]
    fn stack_slots_and_promoted_locals_are_checked() {
        let f = func(vec![Stmt::Return {
            value: Some(Expr::Bin {
                op: BinOp::Add,
                lhs: Box::new(reg("local_14")),
                rhs: Box::new(reg("stack_0")),
            }),
        }]);
        assert_eq!(names(&check(&f)), vec!["local_14", "stack_0"]);
    }

    #[test]
    fn reads_through_derefs_and_addresses_are_seen() {
        let f = func(vec![Stmt::Store {
            addr: Expr::Lea {
                base: Some(phys("var1")),
                index: Some(phys("var2")),
                scale: 4,
                disp: 0,
                segment: None,
            },
            src: Expr::Deref {
                addr: Box::new(reg("var3")),
                size: 4,
            },
            size: 4,
        }]);
        assert_eq!(names(&check(&f)), vec!["var1", "var2", "var3"]);
    }

    #[test]
    fn a_temporary_that_survives_lowering_must_be_defined() {
        let f = func(vec![Stmt::Return {
            value: Some(Expr::Reg(VReg::Temp(3))),
        }]);
        assert_eq!(names(&check(&f)), vec!["t3"]);
    }

    #[test]
    fn a_var_prefixed_name_that_is_not_a_scratch_value_is_ignored() {
        // `variable_x` is not the `varN` scratch convention.
        let f = func(vec![Stmt::Return {
            value: Some(reg("variable_x")),
        }]);
        assert_eq!(check(&f), vec![]);
    }

    #[test]
    fn switch_arms_join_like_branches() {
        let f = func(vec![
            Stmt::Switch {
                discriminant: reg("arg0"),
                cases: vec![
                    (Some(0), vec![assign("var1", Expr::Const(1))]),
                    (Some(1), vec![assign("var1", Expr::Const(2))]),
                ],
                default: Some(vec![assign("var1", Expr::Const(3))]),
            },
            Stmt::Return {
                value: Some(reg("var1")),
            },
        ]);
        assert_eq!(check(&f), vec![]);
    }
}
