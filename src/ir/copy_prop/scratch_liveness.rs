//! Which scratch values can influence the output at all?
//!
//! The read counts in [`super::reads`] answer "does anything read this name?",
//! and that question cannot retire loop-carried SSA residue: `a = b; ... b = a`
//! gives every name a reader while the whole graph only feeds itself. GCC `-O0`
//! Dijkstra threads a reused address register through several such names even
//! though the value never reaches a condition, a memory access, a call, or a
//! return.
//!
//! So this module asks the question from the other end. It collects the
//! *observable roots* -- conditions, addresses, stored values, call targets and
//! arguments, returns, throws, indirect-goto targets, and writes to source-level
//! stack locals -- then keeps only the scratch assignments in their transitive
//! dependency closure. Everything outside that closure is a closed graph that
//! cannot be seen, and is removed.
//!
//! It is deliberately name-conservative, not SSA-exact: if value numbering left
//! several definitions sharing a name, their dependencies are unioned, so one
//! live use keeps every possibly-reaching source. Two shapes are treated as
//! roots even when their result is unused -- an assignment whose source contains
//! a call (a lazy `Select` can hide one), and the boxed `init`/`step` header
//! statements of a `For`, which this pass cannot delete without changing that
//! statement's representation. A `Stmt::Unknown` may read any scratch value at
//! all, so it aborts the pass rather than deleting dataflow across semantics we
//! do not model.

use crate::ir::ast::{Expr, Function, Stmt};
use crate::ir::types::VReg;

use super::alias::is_scratch_reg;
use super::hash::{RegMap, RegSet};
use super::reads::{visit_expr_reads, visit_stmt_reads};

/// Remove closed scratch-value graphs that cannot influence observable output.
///
/// A whole-function read count cannot eliminate loop-carried SSA residue such
/// as `a = b; ... b = a`: every name has a reader even when the graph only feeds
/// itself. Compute liveness from semantic roots instead—conditions, addresses,
/// stores, calls, returns, and writes to source-level stack locals—and retain
/// only scratch assignments in their transitive dependency closure.
///
/// This is intentionally name-conservative. If value numbering left multiple
/// definitions with one name, their dependencies are unioned, so one live use
/// keeps every possibly reaching source. Most assignment expressions are pure,
/// but a lazy select can contain a value-producing call. Such definitions are
/// observable roots even when their result is unused; ordinary non-volatile
/// loads remain removable.
/// Returns whether any assignment was removed.
pub(super) fn prune_unobservable_scratch_dataflow(f: &mut Function) -> bool {
    /// Add every register `expr` reads to `into`.
    ///
    /// This used to build a `RegMap<usize>` histogram per expression and
    /// throw the counts away, so every root and every dependency edge cost one
    /// map allocation plus a rehash of each name into a second collection.
    fn add_regs(expr: &Expr, into: &mut RegSet) {
        visit_expr_reads(expr, &mut |register| {
            if !into.contains(register) {
                into.insert(register.clone());
            }
            true
        });
    }

    fn add_roots(expr: &Expr, roots: &mut RegSet) {
        add_regs(expr, roots);
    }

    fn collect_body(
        body: &[Stmt],
        dependencies: &mut RegMap<RegSet>,
        roots: &mut RegSet,
        has_unknown: &mut bool,
    ) {
        for statement in body {
            match statement {
                Stmt::Assign { dst, src } if is_scratch_reg(dst) => {
                    add_regs(src, dependencies.entry(dst.clone()).or_default());
                    if src.contains_call() {
                        roots.insert(dst.clone());
                    }
                }
                Stmt::Assign { src, .. } => add_roots(src, roots),
                Stmt::Store { addr, src, .. } => {
                    add_roots(addr, roots);
                    add_roots(src, roots);
                }
                Stmt::Call {
                    target, args, dst, ..
                } => {
                    add_roots(target, roots);
                    for argument in args {
                        add_roots(argument, roots);
                    }
                    if let Some(dst) = dst {
                        dependencies.entry(dst.clone()).or_default();
                    }
                }
                Stmt::Return { value } => {
                    if let Some(value) = value {
                        add_roots(value, roots);
                    }
                }
                Stmt::Throw { value } => add_roots(value, roots),
                Stmt::TryCatch { try_body, catches } => {
                    collect_body(try_body, dependencies, roots, has_unknown);
                    for catch in catches {
                        collect_body(&catch.body, dependencies, roots, has_unknown);
                    }
                }
                Stmt::IndirectGoto { target } => add_roots(target, roots),
                Stmt::If {
                    cond,
                    then_body,
                    else_body,
                } => {
                    add_roots(cond, roots);
                    collect_body(then_body, dependencies, roots, has_unknown);
                    if let Some(else_body) = else_body {
                        collect_body(else_body, dependencies, roots, has_unknown);
                    }
                }
                Stmt::While { cond, body } | Stmt::DoWhile { cond, body } => {
                    add_roots(cond, roots);
                    collect_body(body, dependencies, roots, has_unknown);
                }
                Stmt::For {
                    init,
                    cond,
                    step,
                    body,
                } => {
                    // A For owns boxed header statements that this pass cannot
                    // delete without changing its representation. Treat their
                    // complete dataflow as observable and prune only the body.
                    let mut add_root = |register: &VReg| {
                        if !roots.contains(register) {
                            roots.insert(register.clone());
                        }
                        true
                    };
                    visit_stmt_reads(init, &mut add_root);
                    visit_stmt_reads(step, &mut add_root);
                    if let Stmt::Assign { dst, .. } = &**init {
                        roots.insert(dst.clone());
                    }
                    if let Stmt::Assign { dst, .. } = &**step {
                        roots.insert(dst.clone());
                    }
                    add_roots(cond, roots);
                    collect_body(body, dependencies, roots, has_unknown);
                }
                Stmt::Push { value } => add_roots(value, roots),
                Stmt::Switch {
                    discriminant,
                    cases,
                    default,
                } => {
                    add_roots(discriminant, roots);
                    for (_, case_body) in cases {
                        collect_body(case_body, dependencies, roots, has_unknown);
                    }
                    if let Some(default_body) = default {
                        collect_body(default_body, dependencies, roots, has_unknown);
                    }
                }
                // An opaque machine statement may read any scratch value. Abort
                // rather than deleting dataflow across semantics we do not know.
                Stmt::Unknown(_) => *has_unknown = true,
                Stmt::Pop { .. }
                | Stmt::Label(_)
                | Stmt::Goto { .. }
                | Stmt::Break
                | Stmt::Nop
                | Stmt::Comment(_) => {}
            }
        }
    }

    fn prune_body(body: &mut Vec<Stmt>, live: &RegSet) -> bool {
        let before = body.len();
        body.retain(|statement| {
            !matches!(statement, Stmt::Assign { dst, .. } if is_scratch_reg(dst) && !live.contains(dst))
        });
        let mut pruned = body.len() != before;
        for statement in body {
            match statement {
                Stmt::If {
                    then_body,
                    else_body,
                    ..
                } => {
                    pruned |= prune_body(then_body, live);
                    if let Some(else_body) = else_body {
                        pruned |= prune_body(else_body, live);
                    }
                }
                Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
                    pruned |= prune_body(body, live);
                }
                Stmt::Switch { cases, default, .. } => {
                    for (_, case_body) in cases {
                        pruned |= prune_body(case_body, live);
                    }
                    if let Some(default_body) = default {
                        pruned |= prune_body(default_body, live);
                    }
                }
                Stmt::TryCatch { try_body, catches } => {
                    pruned |= prune_body(try_body, live);
                    for catch in catches {
                        pruned |= prune_body(&mut catch.body, live);
                    }
                }
                _ => {}
            }
        }
        pruned
    }

    let mut dependencies: RegMap<RegSet> = RegMap::default();
    let mut live = RegSet::default();
    let mut has_unknown = false;
    collect_body(&f.body, &mut dependencies, &mut live, &mut has_unknown);
    if has_unknown {
        return false;
    }

    let mut frontier: Vec<VReg> = live.iter().cloned().collect();
    while let Some(value) = frontier.pop() {
        let Some(inputs) = dependencies.get(&value) else {
            continue;
        };
        for input in inputs {
            if live.insert(input.clone()) {
                frontier.push(input.clone());
            }
        }
    }
    prune_body(&mut f.body, &live)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::ast::Expr;
    use crate::ir::types::CmpOp;

    fn reg(n: &str) -> VReg {
        VReg::phys(n)
    }

    #[test]
    fn a_closed_loop_carried_scratch_copy_graph_is_dead() {
        // GCC -O0 Dijkstra threads a reused address register through several
        // SSA names even though that value never reaches a condition, memory
        // access, call, or return. Name-wide read counts keep the cycle alive;
        // observable-root liveness should remove the whole closed graph.
        let mut f = Function {
            name: "closed_copy_graph".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("var15"),
                    src: Expr::Reg(reg("arg3")),
                },
                Stmt::While {
                    cond: Expr::Cmp {
                        op: CmpOp::Slt,
                        lhs: Box::new(Expr::Reg(reg("local_30"))),
                        rhs: Box::new(Expr::Reg(reg("arg1"))),
                    },
                    body: vec![
                        Stmt::Assign {
                            dst: reg("var18"),
                            src: Expr::Reg(reg("var15")),
                        },
                        Stmt::If {
                            cond: Expr::Reg(reg("zf_1")),
                            then_body: vec![Stmt::Assign {
                                dst: reg("var22"),
                                src: Expr::Reg(reg("var18")),
                            }],
                            else_body: Some(vec![Stmt::Assign {
                                dst: reg("var22"),
                                src: Expr::Reg(reg("local_28")),
                            }]),
                        },
                        Stmt::Assign {
                            dst: reg("var15"),
                            src: Expr::Reg(reg("var22")),
                        },
                    ],
                },
                Stmt::Return {
                    value: Some(Expr::Reg(reg("local_30"))),
                },
            ],
        };

        prune_unobservable_scratch_dataflow(&mut f);

        let rendered = format!("{f:#?}");
        for dead in ["var15", "var18", "var22", "arg3", "local_28"] {
            assert!(
                !rendered.contains(dead),
                "closed scratch dataflow kept {dead}: {rendered}"
            );
        }
        assert!(rendered.contains("local_30"));
        assert!(rendered.contains("arg1"));
        assert!(rendered.contains("zf_1"));
    }

    #[test]
    fn a_loop_carried_copy_graph_feeding_a_return_stays_live() {
        let mut f = Function {
            name: "live_copy_graph".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("var0"),
                    src: Expr::Reg(reg("arg0")),
                },
                Stmt::While {
                    cond: Expr::Reg(reg("zf_1")),
                    body: vec![
                        Stmt::Assign {
                            dst: reg("var1"),
                            src: Expr::Reg(reg("var0")),
                        },
                        Stmt::Assign {
                            dst: reg("var0"),
                            src: Expr::Reg(reg("var1")),
                        },
                    ],
                },
                Stmt::Return {
                    value: Some(Expr::Reg(reg("var0"))),
                },
            ],
        };

        prune_unobservable_scratch_dataflow(&mut f);

        let rendered = format!("{f:#?}");
        assert!(
            rendered.contains("var0"),
            "return value was deleted: {rendered}"
        );
        assert!(
            rendered.contains("var1"),
            "live dependency was deleted: {rendered}"
        );
        assert!(
            rendered.contains("arg0"),
            "live source was deleted: {rendered}"
        );
    }
}
