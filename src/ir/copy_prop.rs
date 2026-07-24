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

use std::collections::HashMap;

use crate::ir::ast::{Expr, Function, Stmt};
use crate::ir::types::VReg;

/// Run copy propagation then dead-copy elimination over `f`'s body.
pub fn propagate_copies(f: &mut Function) {
    // Global read counts. With SSA value-numbering upstream every scratch value
    // is single-def, so a value read exactly once can have its defining
    // *expression* propagated to that one use without duplicating any work — this
    // reassembles a split address computation (`t = i*4; p = base + t; *p`) into
    // `*(base + i*4)` and removes the scratch locals value-numbering created.
    let mut reads: HashMap<VReg, usize> = HashMap::new();
    count_reads_body(&f.body, &mut reads);
    propagate_run_counted(&mut f.body, &reads);
    propagate_run(&mut f.body);
    // Iterate DCE to a fixpoint: removing one dead copy can make the copy that
    // fed it dead too. Bounded to keep it cheap.
    for _ in 0..8 {
        if !eliminate_dead_copies(&mut f.body) {
            break;
        }
    }
    // Copy propagation exposes local dead stores (`ret = local_c; ret =
    // (local_c >> 1)` — the first write is overwritten before any read once the
    // reload was folded away). Remove those within each straight-line run.
    dead_store_runs(&mut f.body);
}

/// Is `e` safe to record as a copy source and duplicate into use sites? Only
/// pure, stable values: a register/local reference, a constant, or a resolved
/// address/name. Memory loads (`Deref`) and arithmetic are excluded — their
/// value can change or their operands be clobbered before the use.
fn is_pure_copyable(e: &Expr) -> bool {
    matches!(
        e,
        Expr::Reg(_) | Expr::Const(_) | Expr::Addr(_) | Expr::Named { .. } | Expr::StringLit { .. }
    )
}

type Copies = HashMap<VReg, Expr>;

/// Invalidate every copy whose destination *is* `written`, or whose source
/// *reads* `written` (its recorded value is now stale).
fn invalidate(copies: &mut Copies, written: &VReg) {
    copies.retain(|dst, src| dst != written && !contains_reg(src, written));
}

fn propagate_run(stmts: &mut [Stmt]) {
    let mut copies: Copies = HashMap::new();
    for s in stmts.iter_mut() {
        match s {
            Stmt::Assign { dst, src } => {
                subst(src, &copies);
                invalidate(&mut copies, dst);
                if is_pure_copyable(src) && !is_self_ref(dst, src) {
                    copies.insert(dst.clone(), src.clone());
                }
            }
            Stmt::Store { addr, src } => {
                subst(addr, &copies);
                subst(src, &copies);
                // A store to a bare promoted local writes that variable.
                if let Expr::Reg(r) = addr {
                    invalidate(&mut copies, r);
                }
            }
            Stmt::Push { value } => subst(value, &copies),
            Stmt::Return { value } => {
                if let Some(e) = value {
                    subst(e, &copies);
                }
            }
            Stmt::Pop { target } => invalidate(&mut copies, target),
            Stmt::Call { target, args } => {
                subst(target, &copies);
                for a in args.iter_mut() {
                    subst(a, &copies);
                }
                // A call clobbers caller-saved registers — drop everything.
                copies.clear();
            }
            Stmt::If {
                cond,
                then_body,
                else_body,
            } => {
                subst(cond, &copies);
                propagate_run(then_body);
                if let Some(eb) = else_body {
                    propagate_run(eb);
                }
                copies.clear();
            }
            Stmt::While { cond, body } => {
                subst(cond, &copies);
                propagate_run(body);
                copies.clear();
            }
            Stmt::Switch {
                discriminant,
                cases,
                default,
            } => {
                subst(discriminant, &copies);
                for (_, body) in cases.iter_mut() {
                    propagate_run(body);
                }
                if let Some(b) = default {
                    propagate_run(b);
                }
                copies.clear();
            }
            // Control-flow boundaries: a label may be a join target and a goto
            // leaves the run — clear so nothing propagates across the edge.
            Stmt::Label(_) | Stmt::Goto { .. } => copies.clear(),
            Stmt::Nop | Stmt::Unknown(_) | Stmt::Comment(_) => {}
        }
    }
}

fn is_self_ref(dst: &VReg, src: &Expr) -> bool {
    matches!(src, Expr::Reg(r) if r == dst)
}

/// Like [`propagate_run`], but also propagates a *non-pure* expression whose
/// scratch destination is read exactly once in the whole body — safe because
/// value-numbering makes each such destination single-def, so folding it in
/// duplicates no computation. Copies still do not cross control-flow edges.
fn propagate_run_counted(stmts: &mut [Stmt], reads: &HashMap<VReg, usize>) {
    let mut copies: Copies = HashMap::new();
    for s in stmts.iter_mut() {
        match s {
            Stmt::Assign { dst, src } => {
                subst(src, &copies);
                invalidate(&mut copies, dst);
                if !is_self_ref(dst, src) {
                    let record = is_pure_copyable(src)
                        || (is_scratch_reg(dst) && reads.get(dst).copied().unwrap_or(0) == 1);
                    if record {
                        copies.insert(dst.clone(), src.clone());
                    }
                }
            }
            Stmt::Store { addr, src } => {
                subst(addr, &copies);
                subst(src, &copies);
                if let Expr::Reg(r) = addr {
                    invalidate(&mut copies, r);
                }
                // The store may alias a pending single-use load; folding that
                // load past this point would read the post-store value.
                invalidate_loads(&mut copies);
            }
            Stmt::Push { value } => {
                subst(value, &copies);
                invalidate_loads(&mut copies);
            }
            Stmt::Return { value } => {
                if let Some(e) = value {
                    subst(e, &copies);
                }
            }
            Stmt::Pop { target } => invalidate(&mut copies, target),
            Stmt::Call { target, args } => {
                subst(target, &copies);
                for a in args.iter_mut() {
                    subst(a, &copies);
                }
                copies.clear();
            }
            Stmt::If {
                cond,
                then_body,
                else_body,
            } => {
                subst(cond, &copies);
                propagate_run_counted(then_body, reads);
                if let Some(eb) = else_body {
                    propagate_run_counted(eb, reads);
                }
                copies.clear();
            }
            Stmt::While { cond, body } => {
                subst(cond, &copies);
                propagate_run_counted(body, reads);
                copies.clear();
            }
            Stmt::Switch {
                discriminant,
                cases,
                default,
            } => {
                subst(discriminant, &copies);
                for (_, body) in cases.iter_mut() {
                    propagate_run_counted(body, reads);
                }
                if let Some(b) = default {
                    propagate_run_counted(b, reads);
                }
                copies.clear();
            }
            Stmt::Label(_) | Stmt::Goto { .. } => copies.clear(),
            Stmt::Nop | Stmt::Unknown(_) | Stmt::Comment(_) => {}
        }
    }
}

/// Within each straight-line run, drop a scratch-register write that is
/// overwritten by a later write before any intervening read (a dead store).
/// Conservative: resets at every control-flow boundary and only removes writes
/// whose source is side-effect-free.
fn dead_store_runs(body: &mut Vec<Stmt>) {
    // last_write[reg] = index of the most recent not-yet-consumed removable
    // write to `reg` in this run.
    let mut last_write: HashMap<VReg, usize> = HashMap::new();
    let mut dead: Vec<usize> = Vec::new();
    for (i, s) in body.iter().enumerate() {
        match s {
            Stmt::Assign { dst, src } => {
                // Reads in `src` consume any pending write of those regs.
                let mut r: HashMap<VReg, usize> = HashMap::new();
                count_reads_expr(src, &mut r);
                for reg in r.keys() {
                    last_write.remove(reg);
                }
                // This write shadows a pending one to `dst` with no read between.
                if let Some(prev) = last_write.remove(dst) {
                    dead.push(prev);
                }
                if is_pure_copyable(src) && is_scratch_reg(dst) && !is_self_ref(dst, src) {
                    last_write.insert(dst.clone(), i);
                }
            }
            other => {
                // Any read anywhere consumes pending writes; be safe and clear
                // on anything that isn't a pure Assign (stores, calls, control
                // flow, returns all either read or branch).
                let mut r: HashMap<VReg, usize> = HashMap::new();
                count_reads_stmt(other, &mut r);
                for reg in r.keys() {
                    last_write.remove(reg);
                }
                if !matches!(other, Stmt::Nop | Stmt::Comment(_)) {
                    last_write.clear();
                }
            }
        }
    }
    if !dead.is_empty() {
        let dead: std::collections::HashSet<usize> = dead.into_iter().collect();
        let mut i = 0;
        body.retain(|_| {
            let keep = !dead.contains(&i);
            i += 1;
            keep
        });
    }
    // Recurse into nested bodies.
    for s in body.iter_mut() {
        match s {
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                dead_store_runs(then_body);
                if let Some(eb) = else_body {
                    dead_store_runs(eb);
                }
            }
            Stmt::While { body, .. } => dead_store_runs(body),
            Stmt::Switch { cases, default, .. } => {
                for (_, b) in cases.iter_mut() {
                    dead_store_runs(b);
                }
                if let Some(b) = default {
                    dead_store_runs(b);
                }
            }
            _ => {}
        }
    }
}

/// Remove register copies (`A = <pure>`) whose destination is never read in the
/// whole body. Returns whether anything was removed. Promoted stack locals
/// (`local_*`/`stack_*`) are left to the dedicated dead-store pass; here we only
/// clean scratch registers/temporaries the copy-prop just made dead.
fn eliminate_dead_copies(body: &mut Vec<Stmt>) -> bool {
    // Count reads of every register across the whole (nested) body.
    let mut reads: HashMap<VReg, usize> = HashMap::new();
    count_reads_body(body, &mut reads);
    remove_dead(body, &reads)
}

fn remove_dead(body: &mut Vec<Stmt>, reads: &HashMap<VReg, usize>) -> bool {
    let mut changed = false;
    body.retain(|s| {
        // Every `Assign` source is side-effect-free (registers, constants,
        // arithmetic, loads — never a call), so a scratch destination that is
        // never read is dead and safe to drop, whatever the source shape.
        if let Stmt::Assign { dst, .. } = s {
            if is_scratch_reg(dst) && reads.get(dst).copied().unwrap_or(0) == 0 {
                changed = true;
                return false;
            }
        }
        true
    });
    for s in body.iter_mut() {
        match s {
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                changed |= remove_dead(then_body, reads);
                if let Some(eb) = else_body {
                    changed |= remove_dead(eb, reads);
                }
            }
            Stmt::While { body, .. } => changed |= remove_dead(body, reads),
            Stmt::Switch { cases, default, .. } => {
                for (_, b) in cases.iter_mut() {
                    changed |= remove_dead(b, reads);
                }
                if let Some(b) = default {
                    changed |= remove_dead(b, reads);
                }
            }
            _ => {}
        }
    }
    changed
}

/// A register we're willing to delete a dead copy to: physical scratch/role
/// registers and temporaries, but NOT promoted stack locals (owned by
/// dead-store elimination) and NOT flags.
fn is_scratch_reg(v: &VReg) -> bool {
    match v {
        VReg::Temp(_) => true,
        VReg::Phys(n) => !n.starts_with("local_") && !n.starts_with("stack_"),
        VReg::Flag(_) => false,
    }
}

// --- expression/statement read-counting and substitution ---------------------

fn contains_reg(e: &Expr, target: &VReg) -> bool {
    count_reg_uses(e, target) > 0
}

/// True if `e` reads memory (contains a `Deref`). A recorded copy whose source
/// reads memory must be dropped at any intervening store/push, since the store
/// may alias the loaded location — folding the load past it would read the
/// post-store value.
fn contains_deref(e: &Expr) -> bool {
    match e {
        Expr::Deref { .. } => true,
        Expr::Const(_)
        | Expr::Addr(_)
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::Unknown(_)
        | Expr::Reg(_)
        | Expr::Lea { .. }
        | Expr::PdbFieldAddr { .. } => false,
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            contains_deref(lhs) || contains_deref(rhs)
        }
        Expr::Un { src, .. } => contains_deref(src),
    }
}

/// Drop every recorded copy whose source reads memory (a pending load that a
/// store/push could alias).
fn invalidate_loads(copies: &mut Copies) {
    copies.retain(|_, src| !contains_deref(src));
}

fn count_reg_uses(e: &Expr, target: &VReg) -> usize {
    match e {
        Expr::Reg(r) => (r == target) as usize,
        Expr::Const(_)
        | Expr::Addr(_)
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::Unknown(_) => 0,
        Expr::Lea { base, index, .. } | Expr::PdbFieldAddr { base, index, .. } => {
            (base.as_ref() == Some(target)) as usize + (index.as_ref() == Some(target)) as usize
        }
        Expr::Deref { addr, .. } => count_reg_uses(addr, target),
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            count_reg_uses(lhs, target) + count_reg_uses(rhs, target)
        }
        Expr::Un { src, .. } => count_reg_uses(src, target),
    }
}

fn count_reads_expr(e: &Expr, reads: &mut HashMap<VReg, usize>) {
    match e {
        Expr::Reg(r) => *reads.entry(r.clone()).or_insert(0) += 1,
        Expr::Const(_)
        | Expr::Addr(_)
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::Unknown(_) => {}
        Expr::Lea { base, index, .. } | Expr::PdbFieldAddr { base, index, .. } => {
            if let Some(r) = base {
                *reads.entry(r.clone()).or_insert(0) += 1;
            }
            if let Some(r) = index {
                *reads.entry(r.clone()).or_insert(0) += 1;
            }
        }
        Expr::Deref { addr, .. } => count_reads_expr(addr, reads),
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            count_reads_expr(lhs, reads);
            count_reads_expr(rhs, reads);
        }
        Expr::Un { src, .. } => count_reads_expr(src, reads),
    }
}

fn count_reads_stmt(s: &Stmt, reads: &mut HashMap<VReg, usize>) {
    match s {
        // The destination of an Assign is a WRITE, not a read.
        Stmt::Assign { src, .. } => count_reads_expr(src, reads),
        Stmt::Store { addr, src } => {
            count_reads_expr(addr, reads);
            count_reads_expr(src, reads);
        }
        Stmt::Call { target, args } => {
            count_reads_expr(target, reads);
            for a in args {
                count_reads_expr(a, reads);
            }
        }
        Stmt::Return { value } => {
            if let Some(e) = value {
                count_reads_expr(e, reads);
            }
        }
        Stmt::Push { value } => count_reads_expr(value, reads),
        Stmt::If {
            cond,
            then_body,
            else_body,
        } => {
            count_reads_expr(cond, reads);
            count_reads_body(then_body, reads);
            if let Some(eb) = else_body {
                count_reads_body(eb, reads);
            }
        }
        Stmt::While { cond, body } => {
            count_reads_expr(cond, reads);
            count_reads_body(body, reads);
        }
        Stmt::Switch {
            discriminant,
            cases,
            default,
        } => {
            count_reads_expr(discriminant, reads);
            for (_, b) in cases {
                count_reads_body(b, reads);
            }
            if let Some(b) = default {
                count_reads_body(b, reads);
            }
        }
        Stmt::Pop { .. }
        | Stmt::Goto { .. }
        | Stmt::Label(_)
        | Stmt::Nop
        | Stmt::Unknown(_)
        | Stmt::Comment(_) => {}
    }
}

fn count_reads_body(body: &[Stmt], reads: &mut HashMap<VReg, usize>) {
    for s in body {
        count_reads_stmt(s, reads);
    }
}

/// Substitute every active copy `dst -> src` into `e`.
fn subst(e: &mut Expr, copies: &Copies) {
    if copies.is_empty() {
        return;
    }
    // A trivial `Lea` — base only, no index, zero displacement — denotes exactly
    // its base register. When that base has a recorded copy (which for a single-
    // use address is an arithmetic expression, not a bare register), fold the
    // whole `Lea` to the copied value. This is what lets a reassembled address
    // (`p = base + i*4`) inline into its `*p` use, since an `Lea` base/index slot
    // must otherwise stay a register.
    let trivial_lea_repl = match e {
        Expr::Lea {
            base: Some(r),
            index: None,
            disp,
            ..
        } if *disp == 0 => copies.get(r).cloned(),
        _ => None,
    };
    if let Some(repl) = trivial_lea_repl {
        *e = repl;
        subst(e, copies); // substitute within the inlined expression too
        return;
    }
    match e {
        Expr::Reg(r) => {
            if let Some(src) = copies.get(r) {
                *e = src.clone();
            }
        }
        Expr::Const(_)
        | Expr::Addr(_)
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::Unknown(_) => {}
        Expr::Lea { base, index, .. } | Expr::PdbFieldAddr { base, index, .. } => {
            // Only substitute when the replacement is itself a bare register
            // (an Lea base/index must stay a register).
            if let Some(r) = base {
                if let Some(Expr::Reg(nr)) = copies.get(r) {
                    *base = Some(nr.clone());
                }
            }
            if let Some(r) = index {
                if let Some(Expr::Reg(nr)) = copies.get(r) {
                    *index = Some(nr.clone());
                }
            }
        }
        Expr::Deref { addr, .. } => subst(addr, copies),
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            subst(lhs, copies);
            subst(rhs, copies);
        }
        Expr::Un { src, .. } => subst(src, copies),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::ast::{Function, Stmt};
    use crate::ir::types::{BinOp, CmpOp};

    fn reg(n: &str) -> VReg {
        VReg::phys(n)
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
        assert_eq!(f.body.len(), 1, "dead write removed + shift folded: {:?}", f.body);
        assert!(
            matches!(&f.body[0], Stmt::Return { value: Some(Expr::Bin { op: BinOp::Shr, .. }) }),
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
                    src: Expr::Reg(reg("t"))
                },
                "copy must not cross the if boundary"
            );
        } else {
            panic!("expected if");
        }
    }
}
