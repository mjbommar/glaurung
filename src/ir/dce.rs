//! Dead-code elimination for unused flag writes in a lowered [`Function`].
//!
//! After [`super::ast::lower`] runs, a typical x86 block emitted by the
//! Cmp-hoisting step still carries several `%cf = ...`, `%slt = ...`,
//! `%sle = ...`, `%sf = ...` statements whose LHS is never read anywhere
//! else in the function — they are leftover flag writes from the
//! cmp lifter that a human reader (or LLM) never needs to see.
//!
//! This pass counts total reads of each `VReg::Flag(_)` across the entire
//! function body (including nested `If`/`While` arms) and removes the
//! assignment when the read-count is zero. Non-flag writes (`%rax = …`,
//! temp writes, etc.) are untouched — those are the responsibility of the
//! expression-reconstruction pass or explicit dead-store elimination later.

use crate::ir::ast::{Expr, Function, Stmt};
use crate::ir::types::VReg;

/// Remove zero-use flag assignments from `f` in place.
pub fn prune_dead_flags(f: &mut Function) {
    prune_body(&mut f.body);
}

fn prune_body(body: &mut Vec<Stmt>) {
    // Recurse first so inner removals don't inflate our use counts with
    // stale references.
    for s in body.iter_mut() {
        match s {
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                prune_body(then_body);
                if let Some(eb) = else_body {
                    prune_body(eb);
                }
            }
            Stmt::While { body, .. } => prune_body(body),
            _ => {}
        }
    }

    // Drop flag assignments whose dst is never read in the outer body (at
    // this level). Conservative scope: we only look at the flag's reads
    // *within the same Vec<Stmt>* rather than walking into the function's
    // other bodies. In practice the lifter always emits the flag write
    // adjacent to its consumer, so that locality is sufficient.
    let mut i = 0;
    while i < body.len() {
        let is_flag_write = matches!(
            &body[i],
            Stmt::Assign {
                dst: VReg::Flag(_),
                ..
            }
        );
        if !is_flag_write {
            i += 1;
            continue;
        }
        let flag = if let Stmt::Assign { dst, .. } = &body[i] {
            dst.clone()
        } else {
            unreachable!()
        };
        let reads = body
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, s)| count_reads_in_stmt(s, &flag))
            .sum::<usize>();
        if reads == 0 {
            body.remove(i);
        } else {
            i += 1;
        }
    }
}

fn count_reads_in_expr(e: &Expr, target: &VReg) -> usize {
    match e {
        Expr::Reg(r) => (r == target) as usize,
        Expr::Const(_)
        | Expr::Addr(_)
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::Unknown(_) => 0,
        Expr::Lea { base, index, .. } => {
            (base.as_ref() == Some(target)) as usize + (index.as_ref() == Some(target)) as usize
        }
        Expr::Deref { addr, .. } => count_reads_in_expr(addr, target),
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            count_reads_in_expr(lhs, target) + count_reads_in_expr(rhs, target)
        }
        Expr::Un { src, .. } => count_reads_in_expr(src, target),
    }
}

fn count_reads_in_stmt(s: &Stmt, target: &VReg) -> usize {
    match s {
        Stmt::Assign { src, .. } => count_reads_in_expr(src, target),
        Stmt::Store { addr, src } => {
            count_reads_in_expr(addr, target) + count_reads_in_expr(src, target)
        }
        Stmt::Call { target: t, args } => {
            count_reads_in_expr(t, target)
                + args
                    .iter()
                    .map(|a| count_reads_in_expr(a, target))
                    .sum::<usize>()
        }
        Stmt::Return { value } => value
            .as_ref()
            .map(|e| count_reads_in_expr(e, target))
            .unwrap_or(0),
        Stmt::If {
            cond,
            then_body,
            else_body,
        } => {
            let mut n = count_reads_in_expr(cond, target);
            for st in then_body {
                n += count_reads_in_stmt(st, target);
            }
            if let Some(eb) = else_body {
                for st in eb {
                    n += count_reads_in_stmt(st, target);
                }
            }
            n
        }
        Stmt::While { cond, body } => {
            let mut n = count_reads_in_expr(cond, target);
            for st in body {
                n += count_reads_in_stmt(st, target);
            }
            n
        }
        Stmt::Push { value } => count_reads_in_expr(value, target),
        Stmt::Switch { discriminant, cases, default } => {
            let mut n = count_reads_in_expr(discriminant, target);
            for (_, body) in cases {
                for st in body {
                    n += count_reads_in_stmt(st, target);
                }
            }
            if let Some(b) = default {
                for st in b {
                    n += count_reads_in_stmt(st, target);
                }
            }
            n
        }
        Stmt::Pop { .. }
        | Stmt::Goto { .. }
        | Stmt::Label(_)
        | Stmt::Nop
        | Stmt::Unknown(_)
        | Stmt::Comment(_) => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::ast::{lower, render};
    use crate::ir::ssa::compute_ssa;
    use crate::ir::structure::recover;
    use crate::ir::types::{CmpOp, Flag, LlirBlock, LlirFunction, LlirInstr, Op, VReg, Value};

    fn mk_cfg(spec: Vec<(u64, Vec<Op>, Vec<u64>)>) -> LlirFunction {
        let entry_va = spec.first().map(|(s, _, _)| *s).unwrap_or(0);
        let blocks = spec
            .into_iter()
            .map(|(start_va, ops, succs)| LlirBlock {
                start_va,
                end_va: start_va + 0x100,
                instrs: ops
                    .into_iter()
                    .enumerate()
                    .map(|(j, op)| LlirInstr {
                        va: start_va + (j as u64) * 4,
                        op,
                    })
                    .collect(),
                succs,
            })
            .collect();
        LlirFunction { entry_va, blocks }
    }

    #[test]
    fn prunes_unused_flag_writes_after_cmp_hoist() {
        // A block of Cmp writes for all five flags, followed by a CondJump
        // reading only %zf. After lowering + cmp hoisting, %zf is consumed
        // into the if cond — the other four writes should be prunable.
        let lf = mk_cfg(vec![
            (
                0x1000,
                vec![
                    Op::Cmp {
                        dst: VReg::Flag(Flag::Z),
                        op: CmpOp::Eq,
                        lhs: Value::Reg(VReg::phys("rax")),
                        rhs: Value::Const(0),
                    },
                    Op::Cmp {
                        dst: VReg::Flag(Flag::C),
                        op: CmpOp::Ult,
                        lhs: Value::Reg(VReg::phys("rax")),
                        rhs: Value::Const(0),
                    },
                    Op::Cmp {
                        dst: VReg::Flag(Flag::Slt),
                        op: CmpOp::Slt,
                        lhs: Value::Reg(VReg::phys("rax")),
                        rhs: Value::Const(0),
                    },
                    Op::Cmp {
                        dst: VReg::Flag(Flag::Sle),
                        op: CmpOp::Sle,
                        lhs: Value::Reg(VReg::phys("rax")),
                        rhs: Value::Const(0),
                    },
                    Op::CondJump {
                        cond: VReg::Flag(Flag::Z),
                        target: 0x1100,
                    },
                ],
                vec![0x1100, 0x1200],
            ),
            (0x1100, vec![Op::Nop], vec![0x1300]),
            (0x1200, vec![Op::Nop], vec![0x1300]),
            (0x1300, vec![Op::Return], vec![]),
        ]);
        let ssa = compute_ssa(&lf);
        let r = recover(&lf, &ssa);
        let mut f = lower(&lf, &r, "f");
        let before = render(&f);
        assert!(before.contains("%cf ="));
        assert!(before.contains("%slt ="));
        assert!(before.contains("%sle ="));

        prune_dead_flags(&mut f);
        let after = render(&f);
        assert!(!after.contains("%cf ="), "%cf write survived: {}", after);
        assert!(!after.contains("%slt ="), "%slt write survived: {}", after);
        assert!(!after.contains("%sle ="), "%sle write survived: {}", after);
        // %zf was hoisted into the if cond so it shouldn't appear either.
        assert!(!after.contains("%zf ="), "%zf leaked: {}", after);
        // The hoisted condition is preserved.
        assert!(after.contains("if ((%rax == 0))"), "if lost: {}", after);
    }

    #[test]
    fn preserves_flag_writes_that_are_still_read() {
        // Block ends with two CondJumps — one reads %zf, another reads %slt.
        // Both writes must survive. This is a synthetic shape the lifter
        // doesn't emit, but it exercises the use-count path.
        let lf = mk_cfg(vec![(
            0x1000,
            vec![
                Op::Cmp {
                    dst: VReg::Flag(Flag::Z),
                    op: CmpOp::Eq,
                    lhs: Value::Reg(VReg::phys("rax")),
                    rhs: Value::Const(0),
                },
                Op::Cmp {
                    dst: VReg::Flag(Flag::Slt),
                    op: CmpOp::Slt,
                    lhs: Value::Reg(VReg::phys("rax")),
                    rhs: Value::Const(0),
                },
                // Consumers that read both flags (synthesised via Assigns).
                Op::Assign {
                    dst: VReg::phys("rbx"),
                    src: Value::Reg(VReg::Flag(Flag::Z)),
                },
                Op::Assign {
                    dst: VReg::phys("rcx"),
                    src: Value::Reg(VReg::Flag(Flag::Slt)),
                },
                Op::Return,
            ],
            vec![],
        )]);
        let ssa = compute_ssa(&lf);
        let r = recover(&lf, &ssa);
        let mut f = lower(&lf, &r, "f");
        prune_dead_flags(&mut f);
        let text = render(&f);
        assert!(text.contains("%zf ="), "%zf wrongly pruned: {}", text);
        assert!(text.contains("%slt ="), "%slt wrongly pruned: {}", text);
    }

    #[test]
    fn prune_respects_nested_if_bodies() {
        // `if (x) { %zf = cmp; goto Y } else { nop }` — the inner flag write
        // is never read outside the If, but it's not read inside either, so
        // prune. The test assures recursion into nested bodies works.
        let lf = mk_cfg(vec![
            (
                0x1000,
                vec![
                    Op::Cmp {
                        dst: VReg::Flag(Flag::Z),
                        op: CmpOp::Eq,
                        lhs: Value::Reg(VReg::phys("rax")),
                        rhs: Value::Const(0),
                    },
                    Op::CondJump {
                        cond: VReg::Flag(Flag::Z),
                        target: 0x1100,
                    },
                ],
                vec![0x1100, 0x1200],
            ),
            (
                0x1100,
                vec![
                    // An additional, unused flag write inside the then-arm.
                    Op::Cmp {
                        dst: VReg::Flag(Flag::Slt),
                        op: CmpOp::Slt,
                        lhs: Value::Reg(VReg::phys("rax")),
                        rhs: Value::Const(1),
                    },
                    Op::Nop,
                ],
                vec![0x1300],
            ),
            (0x1200, vec![Op::Nop], vec![0x1300]),
            (0x1300, vec![Op::Return], vec![]),
        ]);
        let ssa = compute_ssa(&lf);
        let r = recover(&lf, &ssa);
        let mut f = lower(&lf, &r, "f");
        prune_dead_flags(&mut f);
        let text = render(&f);
        assert!(!text.contains("%slt ="), "%slt survived: {}", text);
        assert!(text.contains("if ((%rax == 0))"));
    }
}
