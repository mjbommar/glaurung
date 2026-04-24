//! Fold LLIR-lifter temporaries back into their single consumer.
//!
//! The lifter emits `VReg::Temp(_)` values as scratch space when a single
//! machine instruction decomposes into several LLIR ops (e.g. `test` →
//! `%t0 = lhs & rhs; %zf = (t0 == 0); %sf = (t0 s< 0)` or x86's `cmp` →
//! `%t0 = lhs - rhs; %sf = (t0 s< 0)`). The lowering pass turns those into
//! flat `Stmt::Assign`s — legible but noisy.
//!
//! This pass walks the lowered [`Function`] body and, for any
//! `Stmt::Assign { dst: Temp(_), src: E }` whose very next statement uses
//! that temp exactly once, splices `E` into the consumer and deletes the
//! temp definition. We only inline into the *immediately following*
//! statement to avoid moving side-effectful reads across stores without a
//! proper alias analysis.
//!
//! After this pass runs, an x86 `test rax, rax` block printed as
//! ```text
//! %t0 = (%rax & %rax);
//! %zf = (%t0 == 0);
//! %sf = (%t0 < 0);
//! ```
//! collapses to
//! ```text
//! %zf = ((%rax & %rax) == 0);
//! %sf = ((%rax & %rax) < 0);
//! ```
//! (Note: `test` uses the temp twice, once per flag write, so reconstruction
//! doesn't fire there — but the single-use cases after e.g. `cmp`'s subtract
//! do collapse. The test suite below pins down both behaviours.)

use crate::ir::ast::{Expr, Function, Stmt};
use crate::ir::types::VReg;

/// Run expression reconstruction on a lowered function in place.
pub fn reconstruct(f: &mut Function) {
    reconstruct_body(&mut f.body);
}

fn reconstruct_body(stmts: &mut Vec<Stmt>) {
    // Recurse into nested If / While bodies first so inlining composes.
    for s in stmts.iter_mut() {
        match s {
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                reconstruct_body(then_body);
                if let Some(eb) = else_body {
                    reconstruct_body(eb);
                }
            }
            Stmt::While { body, .. } => reconstruct_body(body),
            _ => {}
        }
    }

    // Walk pairwise and inline when safe. A temp def is inlineable when:
    //   (a) the temp's RHS doesn't reference itself (no implicit prior def),
    //   (b) the temp is read exactly once across all subsequent statements
    //       up to (but not including) the next write to that same temp, and
    //   (c) that single use is in the immediately following statement — this
    //       bounds reordering across intervening side-effectful stmts
    //       without a real alias analysis.
    let mut i = 0;
    while i + 1 < stmts.len() {
        let (temp, def_expr) = match &stmts[i] {
            Stmt::Assign {
                dst: dst @ VReg::Temp(_),
                src,
            } => (dst.clone(), src.clone()),
            _ => {
                i += 1;
                continue;
            }
        };

        if contains_reg(&def_expr, &temp) {
            i += 1;
            continue;
        }

        // Scan forward from i+1 counting uses of this temp. A subsequent
        // `%t0 = E` statement redefines the temp; we must count any use in
        // its RHS (self-referential reads happen before the new write) and
        // then stop scanning further — downstream reads would see the new
        // def, not ours.
        let mut total_uses = 0usize;
        let mut first_use_idx: Option<usize> = None;
        for j in (i + 1)..stmts.len() {
            let n = count_reg_uses_in_stmt(&stmts[j], &temp);
            if n > 0 && first_use_idx.is_none() {
                first_use_idx = Some(j);
            }
            total_uses += n;
            if total_uses > 1 {
                break;
            }
            // Stop scanning at the next def of the same temp (after
            // counting uses in its RHS, which the helper already does).
            if matches!(&stmts[j], Stmt::Assign { dst, .. } if dst == &temp) {
                break;
            }
        }
        if total_uses == 1 && first_use_idx == Some(i + 1) {
            substitute_in_stmt(&mut stmts[i + 1], &temp, &def_expr);
            stmts.remove(i);
            // Don't advance — the next iteration may inline a chained temp.
            continue;
        }
        i += 1;
    }
}

// -- Reg-reference utilities --------------------------------------------------

fn contains_reg(e: &Expr, target: &VReg) -> bool {
    match e {
        Expr::Reg(r) => r == target,
        Expr::Const(_)
        | Expr::Addr(_)
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::Unknown(_) => false,
        Expr::Lea { base, index, .. } => {
            base.as_ref().map(|r| r == target).unwrap_or(false)
                || index.as_ref().map(|r| r == target).unwrap_or(false)
        }
        Expr::Deref { addr, .. } => contains_reg(addr, target),
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            contains_reg(lhs, target) || contains_reg(rhs, target)
        }
        Expr::Un { src, .. } => contains_reg(src, target),
    }
}

fn count_reg_uses(e: &Expr, target: &VReg) -> usize {
    match e {
        Expr::Reg(r) => (r == target) as usize,
        Expr::Const(_)
        | Expr::Addr(_)
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::Unknown(_) => 0,
        Expr::Lea { base, index, .. } => {
            let mut n = 0;
            if base.as_ref() == Some(target) {
                n += 1;
            }
            if index.as_ref() == Some(target) {
                n += 1;
            }
            n
        }
        Expr::Deref { addr, .. } => count_reg_uses(addr, target),
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            count_reg_uses(lhs, target) + count_reg_uses(rhs, target)
        }
        Expr::Un { src, .. } => count_reg_uses(src, target),
    }
}

fn count_reg_uses_in_stmt(s: &Stmt, target: &VReg) -> usize {
    match s {
        Stmt::Assign { src, .. } => count_reg_uses(src, target),
        Stmt::Store { addr, src } => count_reg_uses(addr, target) + count_reg_uses(src, target),
        Stmt::Call { target: t, args } => {
            count_reg_uses(t, target)
                + args.iter().map(|a| count_reg_uses(a, target)).sum::<usize>()
        }
        Stmt::If { cond, .. } | Stmt::While { cond, .. } => count_reg_uses(cond, target),
        Stmt::Return { value } => value.as_ref().map(|e| count_reg_uses(e, target)).unwrap_or(0),
        Stmt::Push { value } => count_reg_uses(value, target),
        Stmt::Pop { .. }
        | Stmt::Goto { .. }
        | Stmt::Label(_)
        | Stmt::Nop
        | Stmt::Unknown(_)
        | Stmt::Comment(_) => 0,
    }
}

fn substitute_in_expr(e: &mut Expr, target: &VReg, with: &Expr) {
    let take = std::mem::replace(e, Expr::Unknown(String::new()));
    *e = match take {
        Expr::Reg(r) if &r == target => with.clone(),
        Expr::Reg(r) => Expr::Reg(r),
        Expr::Const(c) => Expr::Const(c),
        Expr::Addr(a) => Expr::Addr(a),
        Expr::Named { va, name } => Expr::Named { va, name },
        Expr::StringLit { value } => Expr::StringLit { value },
        Expr::Unknown(s) => Expr::Unknown(s),
        Expr::Lea {
            base,
            index,
            scale,
            disp,
            segment,
        } => {
            // Lea with a base == target turns into the inlined expression
            // plus the original offsets — but that requires fabricating an
            // Expr::Bin. For conservative v1, only substitute when neither
            // base nor index matches; otherwise leave the Lea untouched.
            Expr::Lea {
                base,
                index,
                scale,
                disp,
                segment,
            }
        }
        Expr::Deref { mut addr, size } => {
            substitute_in_expr(&mut addr, target, with);
            Expr::Deref { addr, size }
        }
        Expr::Bin {
            op,
            mut lhs,
            mut rhs,
        } => {
            substitute_in_expr(&mut lhs, target, with);
            substitute_in_expr(&mut rhs, target, with);
            Expr::Bin { op, lhs, rhs }
        }
        Expr::Un { op, mut src } => {
            substitute_in_expr(&mut src, target, with);
            Expr::Un { op, src }
        }
        Expr::Cmp {
            op,
            mut lhs,
            mut rhs,
        } => {
            substitute_in_expr(&mut lhs, target, with);
            substitute_in_expr(&mut rhs, target, with);
            Expr::Cmp { op, lhs, rhs }
        }
    };
}

fn substitute_in_stmt(s: &mut Stmt, target: &VReg, with: &Expr) {
    match s {
        Stmt::Assign { src, .. } => substitute_in_expr(src, target, with),
        Stmt::Store { addr, src } => {
            substitute_in_expr(addr, target, with);
            substitute_in_expr(src, target, with);
        }
        Stmt::Call { target: t, args } => {
            substitute_in_expr(t, target, with);
            for a in args {
                substitute_in_expr(a, target, with);
            }
        }
        Stmt::If { cond, .. } | Stmt::While { cond, .. } => substitute_in_expr(cond, target, with),
        Stmt::Return { value } => {
            if let Some(e) = value {
                substitute_in_expr(e, target, with);
            }
        }
        Stmt::Push { value } => substitute_in_expr(value, target, with),
        Stmt::Pop { .. }
        | Stmt::Goto { .. }
        | Stmt::Label(_)
        | Stmt::Nop
        | Stmt::Unknown(_)
        | Stmt::Comment(_) => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::ast::{lower, render};
    use crate::ir::ssa::compute_ssa;
    use crate::ir::structure::recover;
    use crate::ir::types::{BinOp, CmpOp, Flag, LlirBlock, LlirFunction, LlirInstr, Op, VReg, Value};

    fn mk_single_block(ops: Vec<Op>) -> LlirFunction {
        LlirFunction {
            entry_va: 0x1000,
            blocks: vec![LlirBlock {
                start_va: 0x1000,
                end_va: 0x1100,
                instrs: ops
                    .into_iter()
                    .enumerate()
                    .map(|(j, op)| LlirInstr {
                        va: 0x1000 + (j as u64) * 4,
                        op,
                    })
                    .collect(),
                succs: vec![],
            }],
        }
    }

    #[test]
    fn single_use_temp_collapses_into_consumer() {
        // cmp rax, rbx (lifted): includes `%t0 = rax - rbx; %sf = (t0 s< 0);`
        // — %t0 is used exactly once in %sf's definition and should inline.
        let lf = mk_single_block(vec![
            Op::Bin {
                dst: VReg::Temp(0),
                op: BinOp::Sub,
                lhs: Value::Reg(VReg::phys("rax")),
                rhs: Value::Reg(VReg::phys("rbx")),
            },
            Op::Cmp {
                dst: VReg::Flag(Flag::S),
                op: CmpOp::Slt,
                lhs: Value::Reg(VReg::Temp(0)),
                rhs: Value::Const(0),
            },
            Op::Return,
        ]);
        let ssa = compute_ssa(&lf);
        let r = recover(&lf, &ssa);
        let mut f = lower(&lf, &r, "f");
        reconstruct(&mut f);
        let text = render(&f);
        assert!(
            text.contains("%sf = ((%rax - %rbx) < 0);"),
            "unexpected text after reconstruction: {}",
            text
        );
        // The original %t0 line must be gone.
        assert!(
            !text.contains("%t0 ="),
            "temp definition not removed: {}",
            text
        );
    }

    #[test]
    fn multi_use_temp_is_not_inlined() {
        // `test rax, rax` lifts to %t0 = rax & rax; %zf = (t0 == 0); %sf = (t0 s< 0);
        // The temp is used twice — reconstruction should leave it alone.
        let lf = mk_single_block(vec![
            Op::Bin {
                dst: VReg::Temp(0),
                op: BinOp::And,
                lhs: Value::Reg(VReg::phys("rax")),
                rhs: Value::Reg(VReg::phys("rax")),
            },
            Op::Cmp {
                dst: VReg::Flag(Flag::Z),
                op: CmpOp::Eq,
                lhs: Value::Reg(VReg::Temp(0)),
                rhs: Value::Const(0),
            },
            Op::Cmp {
                dst: VReg::Flag(Flag::S),
                op: CmpOp::Slt,
                lhs: Value::Reg(VReg::Temp(0)),
                rhs: Value::Const(0),
            },
            Op::Return,
        ]);
        let ssa = compute_ssa(&lf);
        let r = recover(&lf, &ssa);
        let mut f = lower(&lf, &r, "f");
        reconstruct(&mut f);
        let text = render(&f);
        // Confirm both flag-writes still reference %t0 and the definition
        // survived (reconstruction conservatively leaves multi-use temps).
        assert!(text.contains("%t0 = (%rax & %rax);"), "lost temp def: {}", text);
        assert!(text.contains("%zf = (%t0 == 0);"), "lost zf use: {}", text);
        assert!(text.contains("%sf = (%t0 < 0);"), "lost sf use: {}", text);
    }

    #[test]
    fn self_referential_temp_is_left_alone() {
        // `%t0 = t0 + 1; %rax = t0` — inlining would duplicate the prior %t0
        // read. Reconstruction must leave it.
        let lf = mk_single_block(vec![
            Op::Bin {
                dst: VReg::Temp(0),
                op: BinOp::Add,
                lhs: Value::Reg(VReg::Temp(0)),
                rhs: Value::Const(1),
            },
            Op::Assign {
                dst: VReg::phys("rax"),
                src: Value::Reg(VReg::Temp(0)),
            },
            Op::Return,
        ]);
        let ssa = compute_ssa(&lf);
        let r = recover(&lf, &ssa);
        let mut f = lower(&lf, &r, "f");
        reconstruct(&mut f);
        let text = render(&f);
        // Self-ref blocks inlining of line 1; return-folding then turns the
        // `%rax = %t0; return;` pair into `return %t0;`.
        assert!(text.contains("%t0 = (%t0 + 1);"), "got: {}", text);
        assert!(text.contains("return %t0;"), "got: {}", text);
    }

    #[test]
    fn chained_temps_collapse_fully() {
        // `%t0 = rax + 1; %t0 = t0 * 2; %rbx = t0` — correct final shape is
        // `%rbx = (rax + 1) * 2;`. The algorithm walks left-to-right: after
        // inlining step 1 into step 2 (which reads %t0 exactly once before
        // the next def of %t0), step 2 becomes `%t0 = (rax+1)*2`; then step
        // 3 reads %t0 exactly once and inlines the compound expression.
        let lf = mk_single_block(vec![
            Op::Bin {
                dst: VReg::Temp(0),
                op: BinOp::Add,
                lhs: Value::Reg(VReg::phys("rax")),
                rhs: Value::Const(1),
            },
            Op::Bin {
                dst: VReg::Temp(0),
                op: BinOp::Mul,
                lhs: Value::Reg(VReg::Temp(0)),
                rhs: Value::Const(2),
            },
            Op::Assign {
                dst: VReg::phys("rbx"),
                src: Value::Reg(VReg::Temp(0)),
            },
            Op::Return,
        ]);
        let ssa = compute_ssa(&lf);
        let r = recover(&lf, &ssa);
        let mut f = lower(&lf, &r, "f");
        reconstruct(&mut f);
        let text = render(&f);
        assert!(
            text.contains("%rbx = ((%rax + 1) * 2);"),
            "chain did not fully collapse: {}",
            text
        );
        assert!(!text.contains("%t0 ="), "temp defs still present: {}", text);
    }

    #[test]
    fn reconstructs_within_nested_if_body() {
        // if (cond) { %t0 = rax+1; %rbx = t0 }
        // After reconstruction the if-body should have one line: %rbx = rax+1.
        let inner = vec![
            Stmt::Assign {
                dst: VReg::Temp(0),
                src: Expr::Bin {
                    op: BinOp::Add,
                    lhs: Box::new(Expr::Reg(VReg::phys("rax"))),
                    rhs: Box::new(Expr::Const(1)),
                },
            },
            Stmt::Assign {
                dst: VReg::phys("rbx"),
                src: Expr::Reg(VReg::Temp(0)),
            },
        ];
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![Stmt::If {
                cond: Expr::Const(1),
                then_body: inner,
                else_body: None,
            }],
        };
        reconstruct(&mut f);
        // Dig into the if body.
        let Stmt::If { then_body, .. } = &f.body[0] else {
            panic!("lost if");
        };
        assert_eq!(then_body.len(), 1);
        match &then_body[0] {
            Stmt::Assign { dst, src } => {
                assert_eq!(*dst, VReg::phys("rbx"));
                match src {
                    Expr::Bin { op: BinOp::Add, .. } => {}
                    other => panic!("expected Bin Add; got {:?}", other),
                }
            }
            other => panic!("expected Assign; got {:?}", other),
        }
    }

    #[test]
    fn real_binary_end_to_end() {
        // Sanity: reconstruction on real-binary output doesn't panic and
        // doesn't increase statement counts.
        use crate::analysis::cfg::{analyze_functions_bytes, Budgets};
        use crate::core::binary::Arch;
        use crate::ir::lift_function::lift_function_from_bytes;
        let path = std::path::Path::new(
            "samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-gcc-O2",
        );
        if !path.exists() {
            return;
        }
        let data = std::fs::read(path).unwrap();
        let (funcs, _) = analyze_functions_bytes(
            &data,
            &Budgets {
                max_functions: 4,
                max_blocks: 128,
                max_instructions: 2000,
                timeout_ms: 500,
            },
        );
        for fn_ in &funcs {
            if let Some(lf) = lift_function_from_bytes(&data, fn_, Arch::X86_64) {
                let ssa = compute_ssa(&lf);
                let r = recover(&lf, &ssa);
                let mut f = lower(&lf, &r, fn_.name.clone());
                let before = count_stmts(&f.body);
                reconstruct(&mut f);
                let after = count_stmts(&f.body);
                assert!(
                    after <= before,
                    "reconstruction must not grow the stmt count ({} -> {})",
                    before,
                    after
                );
            }
        }
    }

    fn count_stmts(body: &[Stmt]) -> usize {
        let mut n = body.len();
        for s in body {
            match s {
                Stmt::If {
                    then_body,
                    else_body,
                    ..
                } => {
                    n += count_stmts(then_body);
                    if let Some(eb) = else_body {
                        n += count_stmts(eb);
                    }
                }
                Stmt::While { body, .. } => n += count_stmts(body),
                _ => {}
            }
        }
        n
    }
}
