//! Copy propagation + dead-copy elimination on the structured AST.
//!
//! `-O0` code (and our own lifting) is full of short-lived copies: every switch
//! comparison reloads its discriminant into a scratch register
//! (`t10 = local_3; if (t10 == K)`), and the loop-condition setup copies locals
//! into temporaries (`ret = local_c; t11 = local_4; while (ret < t11)`). Left
//! alone these copies survive into the rendered C as extra statements, which
//! inflates the control-flow graph the GED metric compares against ground truth
//! and clutters the output.
//!
//! This pass performs conservative, within-linear-run copy propagation: a copy
//! `A = <pure>` (a register/local/constant source) is substituted into later
//! uses of `A` until `A` or the source is overwritten. Copies do not cross
//! control-flow edges (the active set is cleared at `if`/`while`/`switch`,
//! labels, gotos, and calls), so the transform is sound without dataflow
//! analysis. A follow-up dead-copy elimination drops register copies whose
//! destination is then never read.
//!
//! # What is in this file, and what is not
//!
//! This file is the pass's entry point and its two linear-run walkers.
//! [`propagate_copies`] is the schedule -- count, propagate, eliminate, repeat
//! to a bounded fixpoint, then clean up -- and [`propagate_run`] /
//! [`propagate_run_counted`] are the walk that carries an environment along a
//! straight-line run and drops it at every control-flow boundary. The two
//! differ in one rule: the counted walk will also carry a NON-pure expression
//! whose scratch destination has exactly one whole-function read.
//!
//! Everything the walk asks a question of lives beside it:
//!
//! * [`env`] -- the copy environment, what may be recorded, and when a record
//!   dies;
//! * [`subst`] -- applying that environment to an expression;
//! * [`alias`] -- may this store have written the bytes a pending load reads;
//! * [`reads`] -- how many times is a name read;
//! * [`dead`] -- deleting a write nothing observes;
//! * [`scratch_liveness`] -- liveness from observable roots, which is what
//!   retires a closed loop-carried copy graph that read counts cannot;
//! * [`adjacent`] -- the narrow local def-use proofs that MOVE one expression
//!   into its sole adjacent consumer rather than replaying it;
//! * [`switch_entry`] -- carrying a dominating straight-line alias into the arms
//!   of a switch, once the compiler range guard in front of it is gone;
//! * [`hash`] -- the hasher every register-keyed map here uses.

use crate::ir::ast::{Expr, Function, Stmt};

mod adjacent;
mod alias;
mod dead;
mod env;
mod hash;
mod reads;
mod scratch_liveness;
mod subst;
mod switch_entry;

pub use adjacent::{
    move_adjacent_effectful_scratch_values, propagate_adjacent_guard_values,
    propagate_adjacent_overwritten_values, propagate_adjacent_promoted_values,
    propagate_adjacent_typed_promoted_values,
};
pub use switch_entry::propagate_switch_entry_copies;

use alias::{invalidate_loads, invalidate_loads_for_store, is_scratch_reg};
use dead::{dead_store_runs, eliminate_dead_copies};
use env::{
    copies_stable_across_loop, invalidate, is_pure_copyable, is_repeatable_versioned_flag_expr,
    is_self_ref, Copies,
};
use hash::RegMap;
use reads::count_reads_body;
use scratch_liveness::prune_unobservable_scratch_dataflow;
use subst::{subst, subst_store_addr};

/// Exact whole-function read count for one structured value identity.
///
/// Exposed to effect-moving passes so they can prove a call result has one
/// consumer without duplicating this module's complete statement/expr walk.
pub(crate) fn register_read_count(function: &Function, target: &crate::ir::types::VReg) -> usize {
    let mut reads: RegMap<usize> = RegMap::default();
    count_reads_body(&function.body, &mut reads);
    reads.get(target).copied().unwrap_or(0)
}

/// Run copy propagation then dead-copy elimination over `f`'s body.
///
/// Returns whether the body was changed.
///
/// # The answer has to be honest
///
/// [`crate::ir::ast::prepare`] runs this and `const_fold::fold_constants` to a
/// bounded fixpoint and stops as soon as a round reports no change. A `false`
/// here over a body that WAS edited truncates that fixpoint and silently emits
/// different C. Every step below therefore reports, and each reports from the
/// mutation itself rather than from a proof that the mutation mattered:
///
/// * `propagate_run_counted` / `propagate_run` edit the AST only through
///   [`subst`] and [`subst_store_addr`], and thread that pair's answer out;
/// * `eliminate_dead_copies` already returned whether it deleted a statement,
///   and the loop below only continues when it did;
/// * [`dead_store_runs`] and [`prune_unobservable_scratch_dataflow`] report
///   whether their `retain` dropped anything.
///
/// Over-reporting is harmless — one more fixpoint round over a body that is
/// already at its fixed point produces the same body — so none of these tries
/// to prove that the value it wrote differs from the value it replaced.
pub fn propagate_copies(f: &mut Function) -> bool {
    #[cfg(debug_assertions)]
    let before = f.clone();
    // Global read counts. With SSA value-numbering upstream every scratch value
    // is single-def, so a value read exactly once can have its defining
    // *expression* propagated to that one use without duplicating any work — this
    // reassembles a split address computation (`t = i*4; p = base + t; *p`) into
    // `*(base + i*4)` and removes the scratch locals value-numbering created.
    //
    // Recount after every DCE round. Machine flag calculations often add a
    // second, ultimately dead read of an address/load temporary. The first DCE
    // round removes that flag chain; only a fresh count can then see that the
    // useful read is unique and fold the expression. This is the same fixpoint
    // contract as ordinary SSA simplification, bounded here to keep it cheap.
    let mut changed = false;
    let mut reads: RegMap<usize> = RegMap::default();
    count_reads_body(&f.body, &mut reads);
    propagate_run_counted(&mut f.body, &reads, &mut changed);
    propagate_run(&mut f.body, &mut changed);
    for _ in 0..8 {
        if !eliminate_dead_copies(&mut f.body) {
            break;
        }
        changed = true;
        let mut reads: RegMap<usize> = RegMap::default();
        count_reads_body(&f.body, &mut reads);
        propagate_run_counted(&mut f.body, &reads, &mut changed);
    }
    // Copy propagation exposes local dead stores (`ret = local_c; ret =
    // (local_c >> 1)` — the first write is overwritten before any read once the
    // reload was folded away). Remove those within each straight-line run.
    changed |= dead_store_runs(&mut f.body);
    changed |= prune_unobservable_scratch_dataflow(f);
    #[cfg(debug_assertions)]
    audit_change_report("copy_prop::propagate_copies", changed, &before, f);
    changed
}

/// Debug-only audit of a pass's "did I change anything?" answer.
///
/// The [`crate::ir::ast::prepare::settle_copies_and_constants`] fixpoint stops
/// on `false`, so an under-reporting pass truncates it and silently emits
/// different C — a failure no output test would obviously attribute. This
/// re-derives the answer the expensive way (clone the body, compare it
/// structurally) and asserts the cheap answer never says "unchanged" over a
/// body that moved.
///
/// It runs in debug builds only, which is where `cargo test` runs: the whole
/// suite is the audit harness, on every function every test builds. Release
/// builds — including the maturin extension the pipeline actually uses — pay
/// nothing, and over-reporting is deliberately not flagged because it is safe.
#[cfg(debug_assertions)]
fn audit_change_report(pass: &str, changed: bool, before: &Function, after: &Function) {
    assert!(
        changed || before == after,
        "{pass} reported no change but edited the body; the prepare.rs fixpoint \
         would stop a round early and emit different C"
    );
}

/// Whether an `if` arm cannot contribute state to the lexical fallthrough.
///
/// This intentionally recognises only the exact one-statement return arm. A
/// call followed by a return is also nonjoining, but retaining aliases around
/// richer bodies needs an effect proof this local propagation pass does not
/// attempt.
fn is_exact_return_guard(then_body: &[Stmt], else_body: &Option<Vec<Stmt>>) -> bool {
    else_body.is_none() && matches!(then_body, [Stmt::Return { .. }])
}

fn propagate_run(stmts: &mut [Stmt], changed: &mut bool) -> Copies {
    let mut copies = Copies::new();
    for s in stmts.iter_mut() {
        match s {
            Stmt::Assign { dst, src } => {
                *changed |= subst(src, &copies);
                invalidate(&mut copies, dst);
                if (is_pure_copyable(src) || is_repeatable_versioned_flag_expr(dst, src))
                    && !is_self_ref(dst, src)
                {
                    copies.insert(dst.clone(), src.clone());
                }
            }
            Stmt::Store { addr, src, .. } => {
                *changed |= subst_store_addr(addr, &copies);
                *changed |= subst(src, &copies);
                // A store to a bare promoted local writes that variable.
                if let Expr::Reg(r) = addr {
                    invalidate(&mut copies, r);
                }
            }
            Stmt::Push { value } => *changed |= subst(value, &copies),
            Stmt::Return { value } => {
                if let Some(e) = value {
                    *changed |= subst(e, &copies);
                }
            }
            Stmt::Pop { target } => invalidate(&mut copies, target),
            Stmt::Call { target, args, .. } => {
                *changed |= subst(target, &copies);
                for a in args.iter_mut() {
                    *changed |= subst(a, &copies);
                }
                // A call clobbers caller-saved registers — drop everything.
                copies.clear();
            }
            Stmt::If {
                cond,
                then_body,
                else_body,
            } => {
                let return_guard = is_exact_return_guard(then_body, else_body);
                *changed |= subst(cond, &copies);
                propagate_run(then_body, changed);
                if let Some(eb) = else_body {
                    propagate_run(eb, changed);
                }
                if !return_guard {
                    copies.clear();
                }
            }
            Stmt::While { cond, body } => {
                *changed |= subst(cond, &copies_stable_across_loop(&copies, body));
                propagate_run(body, changed);
                copies.clear();
            }
            Stmt::For {
                init,
                cond,
                step,
                body,
            } => {
                propagate_run(std::slice::from_mut(init.as_mut()), changed);
                *changed |= subst(cond, &copies);
                propagate_run(body, changed);
                propagate_run(std::slice::from_mut(step.as_mut()), changed);
                copies.clear();
            }
            Stmt::DoWhile { body, cond } => {
                // Unlike a pre-tested loop, the condition observes the tail of
                // the body on every iteration.  Carry only the body's final
                // straight-line copies into it; any branch, call, or other
                // control-flow boundary clears that set conservatively.
                let tail_copies = propagate_run(body, changed);
                *changed |= subst(cond, &tail_copies);
                copies.clear();
            }
            Stmt::Switch {
                discriminant,
                cases,
                default,
            } => {
                *changed |= subst(discriminant, &copies);
                for (_, body) in cases.iter_mut() {
                    propagate_run(body, changed);
                }
                if let Some(b) = default {
                    propagate_run(b, changed);
                }
                copies.clear();
            }
            // Control-flow boundaries: a label may be a join target and a goto
            // leaves the run — clear so nothing propagates across the edge.
            // Substitute THEN end the run: the dispatch reads its target, so a
            // copy that reaches it has to be applied before the barrier.
            Stmt::IndirectGoto { target } => {
                *changed |= subst(target, &copies);
                copies.clear();
            }
            Stmt::Label(_) | Stmt::Goto { .. } => copies.clear(),
            Stmt::Break
            | Stmt::Nop
            | Stmt::Unknown(_)
            | Stmt::Comment(_)
            | Stmt::Throw { .. }
            | Stmt::TryCatch { .. } => {}
        }
    }
    copies
}

/// Like [`propagate_run`], but also propagates a *non-pure* expression whose
/// scratch destination is read exactly once in the whole body — safe because
/// value-numbering makes each such destination single-def, so folding it in
/// duplicates no computation. Copies still do not cross control-flow edges.
fn propagate_run_counted(stmts: &mut [Stmt], reads: &RegMap<usize>, changed: &mut bool) -> Copies {
    let mut copies = Copies::new();
    for s in stmts.iter_mut() {
        match s {
            Stmt::Assign { dst, src } => {
                *changed |= subst(src, &copies);
                invalidate(&mut copies, dst);
                if !is_self_ref(dst, src) {
                    let record = is_pure_copyable(src)
                        || is_repeatable_versioned_flag_expr(dst, src)
                        || (is_scratch_reg(dst)
                            && reads.get(dst).copied().unwrap_or(0) == 1
                            // A single use prevents duplicate *reads* but does
                            // not let this in-place pass delete the original
                            // definition. Recording a call here would therefore
                            // invoke it once at the definition and again at the
                            // substituted use. The dedicated adjacent mover
                            // removes the definition atomically when that proof
                            // is available.
                            && !src.contains_call()
                            // A 128-bit load cannot be represented by the
                            // scalar expression that would replace this use.
                            // Keep its value identity so the C backend can
                            // materialize a full-width temporary and preserve
                            // load-before-store ordering across sibling XMM
                            // moves.
                            && !matches!(src, Expr::Deref { size: 16, .. })
                            && !matches!(src, Expr::Unknown(_)));
                    if record {
                        copies.insert(dst.clone(), src.clone());
                    }
                }
            }
            Stmt::Store { addr, src, size } => {
                *changed |= subst_store_addr(addr, &copies);
                *changed |= subst(src, &copies);
                if let Expr::Reg(r) = addr {
                    invalidate(&mut copies, r);
                }
                // The store may alias a pending single-use load; folding that
                // load past this point would read the post-store value. Only a
                // load this store provably cannot touch survives.
                crate::ir::pass_stats::attempt("copyprop_load_barrier");
                invalidate_loads_for_store(&mut copies, addr, *size);
            }
            Stmt::Push { value } => {
                *changed |= subst(value, &copies);
                // A push has no AST address to reason about.
                invalidate_loads(&mut copies);
            }
            Stmt::Return { value } => {
                if let Some(e) = value {
                    *changed |= subst(e, &copies);
                }
            }
            Stmt::Pop { target } => invalidate(&mut copies, target),
            Stmt::Call { target, args, .. } => {
                *changed |= subst(target, &copies);
                for a in args.iter_mut() {
                    *changed |= subst(a, &copies);
                }
                copies.clear();
            }
            Stmt::If {
                cond,
                then_body,
                else_body,
            } => {
                let return_guard = is_exact_return_guard(then_body, else_body);
                *changed |= subst(cond, &copies);
                propagate_run_counted(then_body, reads, changed);
                if let Some(eb) = else_body {
                    propagate_run_counted(eb, reads, changed);
                }
                if !return_guard {
                    copies.clear();
                }
            }
            Stmt::While { cond, body } => {
                *changed |= subst(cond, &copies_stable_across_loop(&copies, body));
                propagate_run_counted(body, reads, changed);
                copies.clear();
            }
            Stmt::For {
                init,
                cond,
                step,
                body,
            } => {
                propagate_run_counted(std::slice::from_mut(init.as_mut()), reads, changed);
                *changed |= subst(cond, &copies);
                propagate_run_counted(body, reads, changed);
                propagate_run_counted(std::slice::from_mut(step.as_mut()), reads, changed);
                copies.clear();
            }
            Stmt::DoWhile { body, cond } => {
                let tail_copies = propagate_run_counted(body, reads, changed);
                *changed |= subst(cond, &tail_copies);
                copies.clear();
            }
            Stmt::Switch {
                discriminant,
                cases,
                default,
            } => {
                *changed |= subst(discriminant, &copies);
                for (_, body) in cases.iter_mut() {
                    propagate_run_counted(body, reads, changed);
                }
                if let Some(b) = default {
                    propagate_run_counted(b, reads, changed);
                }
                copies.clear();
            }
            // Substitute THEN end the run: the dispatch reads its target, so a
            // copy that reaches it has to be applied before the barrier.
            Stmt::IndirectGoto { target } => {
                *changed |= subst(target, &copies);
                copies.clear();
            }
            Stmt::Label(_) | Stmt::Goto { .. } => copies.clear(),
            Stmt::Break
            | Stmt::Nop
            | Stmt::Unknown(_)
            | Stmt::Comment(_)
            | Stmt::Throw { .. }
            | Stmt::TryCatch { .. } => {}
        }
    }
    copies
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::ast::{Function, Stmt};
    use crate::ir::types::{BinOp, CmpOp, VReg};

    fn reg(n: &str) -> VReg {
        VReg::phys(n)
    }

    #[test]
    fn an_unobserved_call_expression_remains_an_effect_root() {
        let mut function = Function {
            name: "effectful_call_result".into(),
            entry_va: 0,
            body: vec![Stmt::Assign {
                dst: reg("var0"),
                src: Expr::Select {
                    cond: Box::new(Expr::Reg(reg("enabled"))),
                    if_true: Box::new(Expr::Call {
                        target: Box::new(Expr::Named {
                            va: 0x2000,
                            name: "write_event".into(),
                        }),
                        args: vec![Expr::Reg(reg("arg0"))],
                        call_spec: None,
                        result_width: Some(8),
                    }),
                    if_false: Box::new(Expr::Const(0)),
                    width: 8,
                },
            }],
        };

        propagate_copies(&mut function);

        assert!(matches!(
            function.body.as_slice(),
            [Stmt::Assign {
                src: Expr::Select { if_true, .. },
                ..
            }] if matches!(if_true.as_ref(), Expr::Call { .. })
        ));
    }

    #[test]
    fn a_single_use_call_expression_is_never_copied() {
        let call = Expr::Call {
            target: Box::new(Expr::Named {
                va: 0x2000,
                name: "next_value".into(),
            }),
            args: Vec::new(),
            call_spec: None,
            result_width: Some(8),
        };
        let mut function = Function {
            name: "one_effectful_definition".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("var0"),
                    src: call.clone(),
                },
                Stmt::Return {
                    value: Some(Expr::Reg(reg("var0"))),
                },
            ],
        };

        propagate_copies(&mut function);

        assert_eq!(
            function.body,
            vec![
                Stmt::Assign {
                    dst: reg("var0"),
                    src: call,
                },
                Stmt::Return {
                    value: Some(Expr::Reg(reg("var0"))),
                },
            ],
            "counted propagation must not copy a call while retaining its effect root"
        );
    }

    #[test]
    fn ordinary_copy_propagation_does_not_freeze_loop_carried_pointer_load() {
        // Clang -O2 list_find seeds `cursor = arg0`, reads cursor->val in the
        // loop guard, and advances `cursor = cursor->next` in the body.  An
        // entry copy is valid for the first test only; substituting arg0 into
        // the structured While condition freezes every later iteration.
        let cursor = reg("cursor");
        let original_guard = Expr::Cmp {
            op: CmpOp::Ne,
            lhs: Box::new(Expr::Deref {
                addr: Box::new(Expr::Bin {
                    op: BinOp::Add,
                    lhs: Box::new(Expr::Reg(cursor.clone())),
                    rhs: Box::new(Expr::Const(8)),
                }),
                size: 4,
            }),
            rhs: Box::new(Expr::Reg(reg("arg1"))),
        };
        let mut function = Function {
            name: "list_find".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: cursor.clone(),
                    src: Expr::Reg(reg("arg0")),
                },
                Stmt::While {
                    cond: original_guard.clone(),
                    body: vec![Stmt::Assign {
                        dst: cursor.clone(),
                        src: Expr::Deref {
                            addr: Box::new(Expr::Reg(cursor)),
                            size: 8,
                        },
                    }],
                },
            ],
        };

        propagate_copies(&mut function);

        let cond = function.body.iter().find_map(|statement| match statement {
            Stmt::While { cond, .. } => Some(cond),
            _ => None,
        });
        let Some(cond) = cond else {
            panic!("expected the pointer scan loop")
        };
        assert_eq!(
            cond, &original_guard,
            "the cursor is loop-carried, not arg0"
        );
    }

    #[test]
    fn a_pointer_scratch_store_does_not_become_a_promoted_local_assignment() {
        // Stack promotion overloads a bare promoted-local Store address as an
        // assignment to that local. `address = local_20; *address = value` is
        // instead an indirect write through the pointer held in local_20.
        // Replacing the address scratch by a bare local changes the lvalue kind
        // and corrupts output parameters such as heap_pop's `removed` buffer.
        let address = reg("ret");
        let local = reg("local_20");
        let mut function = Function {
            name: "write_output".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: address.clone(),
                    src: Expr::Reg(local),
                },
                Stmt::Store {
                    addr: Expr::Lea {
                        base: Some(address.clone()),
                        index: None,
                        scale: 1,
                        disp: 0,
                        segment: None,
                    },
                    src: Expr::Const(7),
                    size: 4,
                },
            ],
        };

        propagate_copies(&mut function);

        assert!(
            matches!(
                function.body.as_slice(),
                [Stmt::Store {
                    addr: Expr::Lea {
                        base: Some(store_address),
                        index: None,
                        disp: 0,
                        ..
                    },
                    ..
                }] if store_address == &reg("local_20")
            ),
            "the indirect store must retain an address expression: {:#?}",
            function.body
        );
    }

    #[test]
    fn single_use_address_folds_into_deref_inside_loop() {
        // var5 = arg0 + (local_4 * 4); s = s + *var5   (var5 scratch, single-use)
        // Expected: var5 folds into the deref -> s = s + *(arg0 + local_4*4).
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![Stmt::While {
                cond: Expr::Cmp {
                    op: CmpOp::Slt,
                    lhs: Box::new(Expr::Reg(reg("local_4"))),
                    rhs: Box::new(Expr::Reg(reg("arg1"))),
                },
                body: vec![
                    Stmt::Assign {
                        dst: reg("var5"),
                        src: Expr::Bin {
                            op: BinOp::Add,
                            lhs: Box::new(Expr::Reg(reg("arg0"))),
                            rhs: Box::new(Expr::Bin {
                                op: BinOp::Mul,
                                lhs: Box::new(Expr::Reg(reg("local_4"))),
                                rhs: Box::new(Expr::Const(4)),
                            }),
                        },
                    },
                    Stmt::Assign {
                        dst: reg("local_8"),
                        src: Expr::Bin {
                            op: BinOp::Add,
                            lhs: Box::new(Expr::Reg(reg("local_8"))),
                            // The lifter wraps the deref address in a trivial Lea
                            // (base only) — the real shape the fold must see through.
                            rhs: Box::new(Expr::Deref {
                                addr: Box::new(Expr::Lea {
                                    base: Some(reg("var5")),
                                    index: None,
                                    scale: 1,
                                    disp: 0,
                                    segment: None,
                                }),
                                size: 4,
                            }),
                        },
                    },
                ],
            }],
        };
        propagate_copies(&mut f);
        let dump = format!("{:?}", f.body);
        assert!(
            !dump.contains("var5"),
            "var5 should have folded into its single use, got:\n{}",
            dump
        );
    }

    #[test]
    fn nontrivial_lea_inlines_a_single_use_computed_index() {
        // Clang -O0 materialises the sign-extended loop index in a scratch and
        // then addresses `base + scratch`. Keeping Lea's index as VReg-only
        // strands that scratch in source C; expanding the address lets the
        // typed Cast travel to the byte load.
        let mut f = Function {
            name: "index".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("var_index"),
                    src: Expr::Cast {
                        signed: true,
                        width: 8,
                        expr: Box::new(Expr::Cast {
                            signed: true,
                            width: 4,
                            expr: Box::new(Expr::Reg(reg("local_i"))),
                        }),
                    },
                },
                Stmt::Assign {
                    dst: reg("value"),
                    src: Expr::Deref {
                        addr: Box::new(Expr::Lea {
                            base: Some(reg("arg0")),
                            index: Some(reg("var_index")),
                            scale: 1,
                            disp: 0,
                            segment: None,
                        }),
                        size: 1,
                    },
                },
                Stmt::Return {
                    value: Some(Expr::Reg(reg("value"))),
                },
            ],
        };

        propagate_copies(&mut f);

        let dump = format!("{:?}", f.body);
        assert!(
            !dump.contains("var_index"),
            "index scratch survived: {dump}"
        );
        assert!(
            matches!(
                f.body.as_slice(),
                [Stmt::Return {
                    value: Some(Expr::Deref { addr, size: 1 })
                }] if matches!(
                    addr.as_ref(),
                    Expr::Bin {
                        op: BinOp::Add,
                        lhs,
                        rhs,
                    } if matches!(lhs.as_ref(), Expr::Reg(r) if r == &reg("arg0"))
                        && matches!(rhs.as_ref(), Expr::Cast { width: 8, .. })
                )
            ),
            "computed index should be explicit address arithmetic: {:?}",
            f.body
        );
    }

    #[test]
    fn newly_single_use_address_and_load_fold_after_dead_flag_cleanup() {
        // Real GCC -O0 array loops compute flags for the address arithmetic and
        // loaded value even though the subsequent branch never reads them.  On
        // the first read-count pass those dead flag temporaries make `var3` and
        // `var6` look multi-use.  Once DCE removes the flag chain, propagation
        // must reconsider the surviving one-use address/load chain rather than
        // strand it in the emitted C.
        let mut f = Function {
            name: "sum_array_shape".into(),
            entry_va: 0,
            body: vec![Stmt::While {
                cond: Expr::Const(1),
                body: vec![
                    Stmt::Assign {
                        dst: reg("var3"),
                        src: Expr::Bin {
                            op: BinOp::Mul,
                            lhs: Box::new(Expr::Reg(reg("local_4"))),
                            rhs: Box::new(Expr::Const(4)),
                        },
                    },
                    Stmt::Assign {
                        dst: reg("dead_addr_sign"),
                        src: Expr::Cmp {
                            op: CmpOp::Slt,
                            lhs: Box::new(Expr::Reg(reg("var3"))),
                            rhs: Box::new(Expr::Const(0)),
                        },
                    },
                    Stmt::Assign {
                        dst: reg("var5"),
                        src: Expr::Bin {
                            op: BinOp::Add,
                            lhs: Box::new(Expr::Reg(reg("arg0"))),
                            rhs: Box::new(Expr::Reg(reg("var3"))),
                        },
                    },
                    Stmt::Assign {
                        dst: reg("var6"),
                        src: Expr::Deref {
                            addr: Box::new(Expr::Reg(reg("var5"))),
                            size: 4,
                        },
                    },
                    Stmt::Assign {
                        dst: reg("dead_load_sign"),
                        src: Expr::Cmp {
                            op: CmpOp::Slt,
                            lhs: Box::new(Expr::Reg(reg("var6"))),
                            rhs: Box::new(Expr::Const(0)),
                        },
                    },
                    Stmt::Assign {
                        dst: reg("local_8"),
                        src: Expr::Bin {
                            op: BinOp::Add,
                            lhs: Box::new(Expr::Reg(reg("local_8"))),
                            rhs: Box::new(Expr::Reg(reg("var6"))),
                        },
                    },
                ],
            }],
        };

        propagate_copies(&mut f);
        let dump = format!("{:?}", f.body);
        for dead in ["var3", "var5", "var6", "dead_addr_sign", "dead_load_sign"] {
            assert!(
                !dump.contains(dead),
                "{dead} should disappear after propagation/DCE reaches a fixpoint:\n{dump}"
            );
        }
        assert!(dump.contains("Deref") && dump.contains("Mul"), "{dump}");
    }

    #[test]
    fn repeated_versioned_flag_expressions_expose_signed_relation() {
        // x86 signed conditions consume SF ^ OF.  SUB/CMP defines
        // OF = signed_less ^ SF, so substituting the pure versioned flag
        // definitions must expose SF ^ (signed_less ^ SF) for algebraic
        // folding even when a CMOV-style select reads the predicate twice.
        let sf = VReg::FlagValue {
            flag: crate::ir::types::Flag::S,
            version: 1,
        };
        let of = VReg::FlagValue {
            flag: crate::ir::types::Flag::O,
            version: 1,
        };
        let less = Expr::Cmp {
            op: CmpOp::Slt,
            lhs: Box::new(Expr::Reg(reg("arg0"))),
            rhs: Box::new(Expr::Reg(reg("arg1"))),
        };
        let raw_sign = Expr::Cmp {
            op: CmpOp::Slt,
            lhs: Box::new(Expr::Reg(reg("result"))),
            rhs: Box::new(Expr::Const(0)),
        };
        let predicate = || Expr::Bin {
            op: BinOp::Xor,
            lhs: Box::new(Expr::Reg(sf.clone())),
            rhs: Box::new(Expr::Reg(of.clone())),
        };
        let mut f = Function {
            name: "classify_shape".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: sf.clone(),
                    src: raw_sign,
                },
                Stmt::Assign {
                    dst: of.clone(),
                    src: Expr::Bin {
                        op: BinOp::Xor,
                        lhs: Box::new(less.clone()),
                        rhs: Box::new(Expr::Reg(sf.clone())),
                    },
                },
                Stmt::Return {
                    value: Some(Expr::Select {
                        cond: Box::new(predicate()),
                        if_true: Box::new(Expr::Const(1)),
                        if_false: Box::new(Expr::Select {
                            cond: Box::new(predicate()),
                            if_true: Box::new(Expr::Const(2)),
                            if_false: Box::new(Expr::Const(3)),
                            width: 4,
                        }),
                        width: 4,
                    }),
                },
            ],
        };

        propagate_copies(&mut f);
        crate::ir::const_fold::fold_constants(&mut f);
        propagate_copies(&mut f);

        let dump = format!("{:#?}", f.body);
        assert!(
            !dump.contains("FlagValue"),
            "flag algebra stayed opaque:\n{dump}"
        );
        assert_eq!(dump.matches("op: Slt").count(), 2, "{dump}");
    }

    #[test]
    fn versioned_predicates_survive_a_nonjoining_return_guard() {
        let sf = VReg::FlagValue {
            flag: crate::ir::types::Flag::S,
            version: 1,
        };
        let of = VReg::FlagValue {
            flag: crate::ir::types::Flag::O,
            version: 1,
        };
        let zf = VReg::FlagValue {
            flag: crate::ir::types::Flag::Z,
            version: 1,
        };
        let lhs = Expr::Reg(reg("arg0"));
        let rhs = Expr::Reg(reg("arg1"));
        let equality = Expr::Cmp {
            op: CmpOp::Eq,
            lhs: Box::new(lhs.clone()),
            rhs: Box::new(rhs.clone()),
        };
        let less = Expr::Cmp {
            op: CmpOp::Slt,
            lhs: Box::new(lhs.clone()),
            rhs: Box::new(rhs.clone()),
        };
        let sign = Expr::Cmp {
            op: CmpOp::Slt,
            lhs: Box::new(Expr::Reg(reg("difference"))),
            rhs: Box::new(Expr::Const(0)),
        };
        let mut function = Function {
            name: "return_guarded_predicate".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: zf.clone(),
                    src: equality.clone(),
                },
                Stmt::Assign {
                    dst: sf.clone(),
                    src: sign.clone(),
                },
                Stmt::Assign {
                    dst: of.clone(),
                    src: Expr::Bin {
                        op: BinOp::Xor,
                        lhs: Box::new(less),
                        rhs: Box::new(sign),
                    },
                },
                Stmt::If {
                    cond: Expr::Reg(zf.clone()),
                    then_body: vec![Stmt::Return {
                        value: Some(Expr::Const(0)),
                    }],
                    else_body: None,
                },
                Stmt::Assign {
                    dst: reg("predicate"),
                    src: Expr::Bin {
                        op: BinOp::Or,
                        lhs: Box::new(Expr::Reg(zf)),
                        rhs: Box::new(Expr::Bin {
                            op: BinOp::Xor,
                            lhs: Box::new(Expr::Reg(sf)),
                            rhs: Box::new(Expr::Reg(of)),
                        }),
                    },
                },
                Stmt::Return {
                    value: Some(Expr::Reg(reg("predicate"))),
                },
            ],
        };

        propagate_copies(&mut function);
        crate::ir::const_fold::fold_constants(&mut function);
        propagate_copies(&mut function);

        let dump = format!("{:#?}", function.body);
        assert!(!dump.contains("FlagValue"), "{dump}");
        assert!(
            dump.contains("op: Sle") && !dump.contains("op: Slt"),
            "{dump}"
        );
        assert!(matches!(
            &function.body[0],
            Stmt::If {
                cond,
                then_body,
                else_body: None,
            } if cond == &equality && matches!(then_body.as_slice(), [Stmt::Return { .. }])
        ));
    }

    #[test]
    fn reload_temp_is_propagated_and_removed() {
        // t10 = local_3; zf = (t10 == 7); return zf
        // t10 folds into the comparison (reading local_3); zf, read once, folds
        // into the return -> `return (local_3 == 7)`.
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("t10"),
                    src: Expr::Reg(reg("local_3")),
                },
                Stmt::Assign {
                    dst: reg("zf"),
                    src: Expr::Cmp {
                        op: CmpOp::Eq,
                        lhs: Box::new(Expr::Reg(reg("t10"))),
                        rhs: Box::new(Expr::Const(7)),
                    },
                },
                Stmt::Return {
                    value: Some(Expr::Reg(reg("zf"))),
                },
            ],
        };
        propagate_copies(&mut f);
        assert_eq!(f.body.len(), 1, "temps should be folded away: {:?}", f.body);
        match &f.body[0] {
            Stmt::Return {
                value: Some(Expr::Cmp { lhs, .. }),
            } => assert_eq!(**lhs, Expr::Reg(reg("local_3"))),
            other => panic!("expected folded `return (local_3 == 7)`, got {:?}", other),
        }
    }

    #[test]
    fn single_use_select_folds_into_its_only_consumer() {
        let selected = reg("var0");
        let mut f = Function {
            name: "select".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: selected.clone(),
                    src: Expr::Select {
                        cond: Box::new(Expr::Reg(reg("cond"))),
                        if_true: Box::new(Expr::Reg(reg("yes"))),
                        if_false: Box::new(Expr::Reg(reg("no"))),
                        width: 8,
                    },
                },
                Stmt::Return {
                    value: Some(Expr::Bin {
                        op: BinOp::Add,
                        lhs: Box::new(Expr::Reg(selected)),
                        rhs: Box::new(Expr::Const(1)),
                    }),
                },
            ],
        };

        propagate_copies(&mut f);

        assert!(
            matches!(
                f.body.as_slice(),
                [Stmt::Return {
                    value: Some(Expr::Bin { lhs, .. })
                }] if matches!(lhs.as_ref(), Expr::Select { .. })
            ),
            "a single-use select should stay a value while losing its scratch: {:?}",
            f.body
        );
    }

    #[test]
    fn do_while_condition_observes_tail_copy() {
        // The latch comparison is evaluated after the body.  A reload emitted
        // at the body tail therefore reaches the condition and must fold there;
        // leaving it as a separate wide scratch lets later width recovery change
        // a signed `local_c > 0` into an unsigned comparison.
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![Stmt::DoWhile {
                body: vec![Stmt::Assign {
                    dst: reg("t10"),
                    src: Expr::Reg(reg("local_c")),
                }],
                cond: Expr::Cmp {
                    op: CmpOp::Slt,
                    lhs: Box::new(Expr::Const(0)),
                    rhs: Box::new(Expr::Reg(reg("t10"))),
                },
            }],
        };

        propagate_copies(&mut f);

        let Stmt::DoWhile { body, cond } = &f.body[0] else {
            panic!("expected do-while, got {:?}", f.body[0]);
        };
        assert!(
            body.is_empty(),
            "folded latch reload must be dead: {body:?}"
        );
        assert_eq!(
            *cond,
            Expr::Cmp {
                op: CmpOp::Slt,
                lhs: Box::new(Expr::Const(0)),
                rhs: Box::new(Expr::Reg(reg("local_c"))),
            }
        );
    }

    #[test]
    fn single_use_load_not_folded_across_store() {
        // t = *p; *q = 5; return t
        // Even though `t` is read exactly once, its defining load must NOT be
        // folded past the store (the store may alias `p`). The load stays put.
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("t0"),
                    src: Expr::Deref {
                        addr: Box::new(Expr::Reg(reg("p"))),
                        size: 8,
                    },
                },
                Stmt::Store {
                    addr: Expr::Reg(reg("q")),
                    src: Expr::Const(5),
                    size: 8,
                },
                Stmt::Return {
                    value: Some(Expr::Reg(reg("t0"))),
                },
            ],
        };
        propagate_copies(&mut f);
        // The load must survive as its own statement (t0 = *p), read by the
        // return — it must not have been substituted into the return expression.
        assert!(
            f.body.iter().any(|s| matches!(
                s,
                Stmt::Assign { dst, src: Expr::Deref { .. } } if *dst == reg("t0")
            )),
            "load must not be folded across the store: {:?}",
            f.body
        );
        assert!(
            matches!(f.body.last(), Some(Stmt::Return { value: Some(Expr::Reg(r)) }) if *r == reg("t0")),
            "return must still read the loaded temp, not the moved load: {:?}",
            f.body
        );
    }

    /// `t0 = *(&object + load_off); *(&store_addr) = 5; return t0`
    ///
    /// Returns true when the load was folded into the return.
    fn load_folds_across_store(load_addr: Expr, store_addr: Expr) -> bool {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("t0"),
                    src: Expr::Deref {
                        addr: Box::new(load_addr),
                        size: 4,
                    },
                },
                Stmt::Store {
                    addr: store_addr,
                    src: Expr::Const(5),
                    size: 4,
                },
                Stmt::Return {
                    value: Some(Expr::Reg(reg("t0"))),
                },
            ],
        };
        propagate_copies(&mut f);
        matches!(
            f.body.last(),
            Some(Stmt::Return {
                value: Some(Expr::Deref { .. })
            })
        )
    }

    fn frame_slot(object: &str, offset: i64) -> Expr {
        let base = Expr::StackAddr {
            object: reg(object),
            size: 64,
        };
        if offset == 0 {
            return base;
        }
        Expr::Bin {
            op: BinOp::Add,
            lhs: Box::new(base),
            rhs: Box::new(Expr::Const(offset)),
        }
    }

    #[test]
    fn single_use_load_folded_across_disjoint_frame_slot() {
        // A 4-byte store at `local_10 + 0` cannot touch the 4 bytes at
        // `local_10 + 8`, so the pending load survives the barrier. This is
        // the dominant real shape: 1,308 of 1,989 recoverable corpus cases.
        assert!(
            load_folds_across_store(frame_slot("local_10", 8), frame_slot("local_10", 0)),
            "disjoint constant offsets of one frame object must fold"
        );
        // ...and symmetrically with the store above the load.
        assert!(
            load_folds_across_store(frame_slot("local_10", 0), frame_slot("local_10", 8)),
            "order of the two disjoint slots must not matter"
        );
    }

    #[test]
    fn single_use_load_not_folded_across_overlapping_frame_slot() {
        // 4 bytes at +8 and 4 bytes at +10 share two bytes.
        assert!(
            !load_folds_across_store(frame_slot("local_10", 10), frame_slot("local_10", 8)),
            "partially overlapping frame slots must keep the conservative drop"
        );
        // Exactly the same address is the degenerate overlap.
        assert!(
            !load_folds_across_store(frame_slot("local_10", 8), frame_slot("local_10", 8)),
            "identical frame slots must keep the conservative drop"
        );
    }

    #[test]
    fn single_use_load_not_folded_across_distinct_frame_objects() {
        // Deliberately unproven: stack promotion can name an interior cell of
        // a larger byte object, so two different names are not two different
        // storages. Measured at 9 corpus occurrences — not worth the risk.
        assert!(
            !load_folds_across_store(frame_slot("local_20", 0), frame_slot("local_10", 0)),
            "two differently-named frame objects must not be claimed disjoint"
        );
    }

    #[test]
    fn single_use_load_not_folded_across_indexed_frame_store() {
        // `local_10 + i` has no constant displacement, so nothing is proven.
        let indexed = Expr::Bin {
            op: BinOp::Add,
            lhs: Box::new(Expr::StackAddr {
                object: reg("local_10"),
                size: 64,
            }),
            rhs: Box::new(Expr::Reg(reg("i"))),
        };
        assert!(
            !load_folds_across_store(frame_slot("local_10", 8), indexed),
            "an indexed frame store must keep the conservative drop"
        );
    }

    #[test]
    fn single_use_load_folded_across_store_to_image_address() {
        // Frame storage and a fixed image address are different storage.
        assert!(
            load_folds_across_store(frame_slot("local_10", 0), Expr::Addr(0x4000)),
            "a store to a fixed image address cannot touch the frame"
        );
        assert!(
            load_folds_across_store(Expr::Addr(0x4000), frame_slot("local_10", 0)),
            "a store to the frame cannot touch a fixed image address"
        );
    }

    #[test]
    fn single_use_load_not_folded_across_store_through_pointer_into_frame() {
        // The store address is an arbitrary pointer. It may well point into
        // `local_10`, and nothing here proves otherwise.
        assert!(
            !load_folds_across_store(frame_slot("local_10", 8), Expr::Reg(reg("p"))),
            "a store through an unproven pointer must keep the conservative drop"
        );
    }

    #[test]
    fn copy_invalidated_when_source_overwritten() {
        // ret = local_c; local_c = local_c + 1; x = ret
        // The `x = ret` must NOT become `x = local_c` (local_c changed).
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("ret"),
                    src: Expr::Reg(reg("local_c")),
                },
                Stmt::Store {
                    addr: Expr::Reg(reg("local_c")),
                    src: Expr::Bin {
                        op: BinOp::Add,
                        lhs: Box::new(Expr::Reg(reg("local_c"))),
                        rhs: Box::new(Expr::Const(1)),
                    },
                    size: 8,
                },
                Stmt::Assign {
                    dst: reg("x"),
                    src: Expr::Reg(reg("ret")),
                },
                // Keep `x` live so it isn't dead-eliminated; we want to inspect it.
                Stmt::Return {
                    value: Some(Expr::Reg(reg("x"))),
                },
            ],
        };
        propagate_copies(&mut f);
        // The returned value must be `ret` (which captured local_c *before* the
        // store), never the post-store `local_c`. That's the invalidation
        // invariant: the stale copy was not propagated across the write.
        let ret_val = f
            .body
            .iter()
            .find_map(|s| match s {
                Stmt::Return { value } => value.clone(),
                _ => None,
            })
            .expect("a return");
        assert_eq!(
            ret_val,
            Expr::Reg(reg("ret")),
            "return must use captured `ret`, not the overwritten local_c"
        );
    }

    #[test]
    fn pure_register_view_propagates_to_multiple_linear_uses() {
        let view = Expr::Cast {
            signed: false,
            width: 8,
            expr: Box::new(Expr::Cast {
                signed: false,
                width: 4,
                expr: Box::new(Expr::Reg(reg("arg0"))),
            }),
        };
        let mut f = Function {
            name: "views".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("var0"),
                    src: view.clone(),
                },
                Stmt::Store {
                    addr: Expr::Addr(0x4000),
                    src: Expr::Reg(reg("var0")),
                    size: 8,
                },
                Stmt::Return {
                    value: Some(Expr::Reg(reg("var0"))),
                },
            ],
        };

        propagate_copies(&mut f);

        assert!(
            !format!("{f:?}").contains("var0"),
            "a pure view alias should not survive as a fake source variable: {f:#?}"
        );
        let Stmt::Store { src, .. } = &f.body[0] else {
            panic!("expected the first consumer")
        };
        assert!(format!("{src:?}").contains("arg0"));
        assert!(matches!(
            &f.body[1],
            Stmt::Return { value: Some(value) } if value == &view
        ));
    }

    #[test]
    fn overwritten_scratch_write_is_dead_store_eliminated() {
        // ret = local_c; ret = (local_c >> 1); return ret
        // The first write is overwritten before any read -> dead, removed.
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("ret"),
                    src: Expr::Reg(reg("local_c")),
                },
                Stmt::Assign {
                    dst: reg("ret"),
                    src: Expr::Bin {
                        op: BinOp::Shr,
                        lhs: Box::new(Expr::Reg(reg("local_c"))),
                        rhs: Box::new(Expr::Const(1)),
                    },
                },
                Stmt::Return {
                    value: Some(Expr::Reg(reg("ret"))),
                },
            ],
        };
        propagate_copies(&mut f);
        // The dead first write is removed and the shift (read once by the return)
        // folds into it -> `return (local_c >> 1)`.
        assert_eq!(
            f.body.len(),
            1,
            "dead write removed + shift folded: {:?}",
            f.body
        );
        assert!(
            matches!(
                &f.body[0],
                Stmt::Return {
                    value: Some(Expr::Bin { op: BinOp::Shr, .. })
                }
            ),
            "surviving statement must be the folded return: {:?}",
            f.body[0]
        );
    }

    #[test]
    fn write_read_before_overwrite_is_kept() {
        // ret = local_c; x = ret; ret = 5; return x  -> first write is READ, kept.
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("ret"),
                    src: Expr::Reg(reg("local_c")),
                },
                Stmt::Store {
                    addr: Expr::Reg(reg("local_9")),
                    src: Expr::Reg(reg("ret")),
                    size: 8,
                },
                Stmt::Assign {
                    dst: reg("ret"),
                    src: Expr::Const(5),
                },
                Stmt::Return {
                    value: Some(Expr::Reg(reg("ret"))),
                },
            ],
        };
        propagate_copies(&mut f);
        // The store consumes the first `ret`, so it must not be eliminated; the
        // store keeps a value derived from local_c.
        assert!(
            f.body.iter().any(|s| matches!(s, Stmt::Store { .. })),
            "store must remain: {:?}",
            f.body
        );
    }

    #[test]
    fn copies_do_not_cross_control_flow() {
        // t = local_0; if (...) { store local_5 = t }  -> the copy is cleared at
        // the `if`, so the store inside the branch keeps `t` (NOT local_0).
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("t"),
                    src: Expr::Reg(reg("local_0")),
                },
                Stmt::If {
                    cond: Expr::Reg(reg("zf")),
                    then_body: vec![Stmt::Store {
                        addr: Expr::Reg(reg("local_5")),
                        src: Expr::Reg(reg("t")),
                        size: 8,
                    }],
                    else_body: None,
                },
            ],
        };
        propagate_copies(&mut f);
        if let Stmt::If { then_body, .. } = &f.body[1] {
            assert_eq!(
                then_body[0],
                Stmt::Store {
                    addr: Expr::Reg(reg("local_5")),
                    src: Expr::Reg(reg("t")),
                    size: 8,
                },
                "copy must not cross the if boundary"
            );
        } else {
            panic!("expected if");
        }
    }

    #[test]
    fn promoted_local_load_is_not_deferred_into_a_later_use() {
        // Even a one-use promoted local must keep a memory load at its original
        // evaluation point: the intervening store may alias it.
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Store {
                    addr: Expr::Reg(reg("local_tmp")),
                    src: Expr::Deref {
                        addr: Box::new(Expr::Reg(reg("p"))),
                        size: 4,
                    },
                    size: 4,
                },
                Stmt::Store {
                    addr: Expr::Reg(reg("q")),
                    src: Expr::Const(9),
                    size: 4,
                },
                Stmt::Return {
                    value: Some(Expr::Reg(reg("local_tmp"))),
                },
            ],
        };

        propagate_copies(&mut f);

        assert!(
            matches!(
                f.body.first(),
                Some(Stmt::Store {
                    addr: Expr::Reg(dst),
                    src: Expr::Deref { .. },
                    ..
                }) if dst == &reg("local_tmp")
            ),
            "the load must remain rooted before the aliasing store: {:?}",
            f.body
        );
        assert!(
            matches!(
                f.body.last(),
                Some(Stmt::Return {
                    value: Some(Expr::Reg(value))
                }) if value == &reg("local_tmp")
            ),
            "the return must still read the rooted promoted local: {:?}",
            f.body
        );
    }
}
