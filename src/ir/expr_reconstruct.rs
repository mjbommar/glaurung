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
    // Recurse into nested control-flow bodies first so inlining composes.
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
            Stmt::DoWhile { body, cond } => reconstruct_do_while(body, cond),
            Stmt::For { body, .. } => reconstruct_body(body),
            _ => {}
        }
    }

    // Walk pairwise and inline when safe. A temp def is inlineable when:
    //   (a) the temp's RHS doesn't reference itself (no implicit prior def),
    //   (b) the temp is read exactly once across all subsequent statements
    //       up to (but not including) the next write to that same temp, and
    //   (c) that single use is in the immediately following statement — this
    //       bounds reordering across intervening side-effectful stmts
    //       without a real alias analysis, and
    //   (d) the RHS is not a pure select, which must stay statement-rooted so
    //       the renderer can preserve its one-armed control-flow form.
    // A whole-list read census, taken once. `substitute_in_stmt` MOVES the
    // definition's RHS into its single consumer and the definition statement is
    // removed in the same step, so no read is ever duplicated and this stays an
    // upper bound for the rest of the walk with no maintenance. See
    // `count_temp_reads_in_body` for why an upper bound is the safe direction.
    let mut temp_reads = std::collections::HashMap::new();
    count_temp_reads_in_body(stmts, &mut temp_reads);

    let mut i = 0;
    while i + 1 < stmts.len() {
        // Conditions (a) and (d) are decided against a BORROW of the RHS. The
        // previous form cloned `src` — a whole expression tree — for every
        // temp assignment in the body, including the ones the very next two
        // lines reject, and including every one whose forward scan then
        // declined to inline. The clone now happens only on the accepting
        // path, where `Vec::remove` hands the expression over by value and it
        // is not a clone at all.
        let temp = match &stmts[i] {
            Stmt::Assign {
                dst: dst @ VReg::Temp(_),
                src,
            } => {
                if contains_reg(src, dst) || matches!(src, Expr::Select { .. }) {
                    i += 1;
                    continue;
                }
                dst.clone()
            }
            _ => {
                i += 1;
                continue;
            }
        };

        // Condition (c) requires the sole use to be the IMMEDIATELY following
        // statement, so a next statement that does not read the temp exactly
        // once can never satisfy the test below: zero reads there means the
        // first use is not at `i + 1`, and two or more means the use is not
        // sole. Deciding that from one statement, before scanning anything
        // else, is what keeps this loop off the rest of the list.
        //
        // The old code scanned forward to the end of the statement list for
        // EVERY temp definition, including the overwhelming majority whose
        // successor never mentions the temp — a full-tail walk per statement,
        // which is quadratic in the length of a block and is why cost here
        // tracked block LENGTH rather than function size.
        if count_reg_uses_in_stmt_recursive(&stmts[i + 1], &temp) != 1 {
            i += 1;
            continue;
        }

        // The sole-use proof is now down to one question: does a SECOND use
        // appear after `i + 1` before the next definition of the same temp? A
        // subsequent `%t0 = E` redefines it, so reads past that point see the
        // new definition, not ours — and any use inside that statement's own
        // RHS has already been counted by the recursive helper.
        //
        // The census answers that outright whenever the whole list holds at
        // most one read: the read just found at `i + 1` IS that read, and
        // nothing is left to prove. That is the ordinary shape of a lifter
        // temporary, and it is what takes the forward scan off the common
        // path — without it every ACCEPTED inline still walked to the end of
        // the block looking for a second use the census already rules out.
        let census_proves_sole_use = temp_reads.get(&temp).copied().unwrap_or(0) <= 1;
        if !census_proves_sole_use
            && !matches!(&stmts[i + 1], Stmt::Assign { dst, .. } if dst == &temp)
        {
            let mut second_use = false;
            for j in (i + 2)..stmts.len() {
                if count_reg_uses_in_stmt_recursive(&stmts[j], &temp) > 0 {
                    second_use = true;
                    break;
                }
                if matches!(&stmts[j], Stmt::Assign { dst, .. } if dst == &temp) {
                    break;
                }
            }
            if second_use {
                i += 1;
                continue;
            }
        }

        // `substitute_in_stmt` deliberately rewrites only expressions
        // evaluated by this statement itself, never a conditional/loop body
        // whose evaluation frequency differs from the definition.
        if count_reg_uses_in_stmt(&stmts[i + 1], &temp) != 1 {
            i += 1;
            continue;
        }
        // (e) the use is somewhere `substitute_in_expr` can actually write.
        // An `Expr::Lea` base/index is a REGISTER slot, not an expression,
        // so substitution silently declines — and deleting the definition
        // anyway leaves the address reading a name nothing assigns.
        if reads_as_address_register(&stmts[i + 1], &temp) {
            i += 1;
            continue;
        }
        // Remove first and take the RHS by value; `stmts[i]` is then the
        // former `stmts[i + 1]`, so the rewrite and the resulting list are
        // exactly what substitute-then-remove produced.
        let Stmt::Assign { src: def_expr, .. } = stmts.remove(i) else {
            unreachable!("guarded by the `Stmt::Assign` match above")
        };
        substitute_in_stmt(&mut stmts[i], &temp, &def_expr);
        // Don't advance — the next iteration may inline a chained temp.
    }
}

/// Total reads of every `VReg::Temp` in `body`, descending into nested bodies.
///
/// This exists so the sole-use proof in [`reconstruct_body`] does not have to
/// walk the rest of the statement list. It is deliberately a CONSERVATIVE
/// SUPERSET of what [`count_reg_uses_in_stmt_recursive`] counts: it visits
/// every expression a statement holds and every nested body, and records a temp
/// in any register slot. Only assignment / call / pop DESTINATIONS and a catch
/// binding are excluded, because those are writes, not reads.
///
/// The asymmetry is the point. The caller uses `== 1` only as a licence to SKIP
/// the forward scan and falls back to that scan for anything larger, so an
/// over-count costs time and nothing else. An under-count would license an
/// unsound inline, which is why both matches below are exhaustive: a new `Expr`
/// or `Stmt` variant has to fail to compile rather than silently read as zero.
fn count_temp_reads_in_body(body: &[Stmt], out: &mut std::collections::HashMap<VReg, u32>) {
    for stmt in body {
        count_temp_reads_in_stmt(stmt, out);
    }
}

/// Record one read of `r` in the census, ignoring anything that is not a temp.
fn note_temp(r: &VReg, out: &mut std::collections::HashMap<VReg, u32>) {
    if matches!(r, VReg::Temp(_)) {
        *out.entry(r.clone()).or_insert(0) += 1;
    }
}

fn count_temp_reads_in_expr(e: &Expr, out: &mut std::collections::HashMap<VReg, u32>) {
    match e {
        Expr::Reg(r) => note_temp(r, out),
        Expr::StackAddr { object, .. } => note_temp(object, out),
        Expr::Const(_)
        | Expr::FloatConst { .. }
        | Expr::Addr(_)
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::Unknown(_) => {}
        Expr::Lea { base, index, .. } | Expr::PdbFieldAddr { base, index, .. } => {
            if let Some(base) = base {
                note_temp(base, out);
            }
            if let Some(index) = index {
                note_temp(index, out);
            }
        }
        Expr::Deref { addr, .. } => count_temp_reads_in_expr(addr, out),
        Expr::Call {
            target: call_target,
            args,
            ..
        } => {
            count_temp_reads_in_expr(call_target, out);
            for argument in args {
                count_temp_reads_in_expr(argument, out);
            }
        }
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            count_temp_reads_in_expr(lhs, out);
            count_temp_reads_in_expr(rhs, out);
        }
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => {
            count_temp_reads_in_expr(cond, out);
            count_temp_reads_in_expr(if_true, out);
            count_temp_reads_in_expr(if_false, out);
        }
        Expr::Un { src, .. } => count_temp_reads_in_expr(src, out),
        Expr::Cast { expr, .. } | Expr::NumericConvert { expr, .. } => {
            count_temp_reads_in_expr(expr, out)
        }
        Expr::FunctionTableEntry { index, .. } => count_temp_reads_in_expr(index, out),
        Expr::WideArithmetic { args, .. } => {
            for argument in args {
                count_temp_reads_in_expr(argument, out);
            }
        }
    }
}

fn count_temp_reads_in_stmt(s: &Stmt, out: &mut std::collections::HashMap<VReg, u32>) {
    match s {
        Stmt::Assign { dst: _, src } => count_temp_reads_in_expr(src, out),
        Stmt::Store { addr, src, .. } => {
            count_temp_reads_in_expr(addr, out);
            count_temp_reads_in_expr(src, out);
        }
        Stmt::Call {
            target,
            args,
            dst: _,
            call_spec: _,
        } => {
            count_temp_reads_in_expr(target, out);
            for argument in args {
                count_temp_reads_in_expr(argument, out);
            }
        }
        Stmt::Return { value } => {
            if let Some(e) = value {
                count_temp_reads_in_expr(e, out);
            }
        }
        Stmt::Throw { value } => count_temp_reads_in_expr(value, out),
        Stmt::TryCatch { try_body, catches } => {
            count_temp_reads_in_body(try_body, out);
            for catch in catches {
                count_temp_reads_in_body(&catch.body, out);
            }
        }
        Stmt::IndirectGoto { target } => count_temp_reads_in_expr(target, out),
        Stmt::If {
            cond,
            then_body,
            else_body,
        } => {
            count_temp_reads_in_expr(cond, out);
            count_temp_reads_in_body(then_body, out);
            if let Some(body) = else_body {
                count_temp_reads_in_body(body, out);
            }
        }
        Stmt::While { cond, body } => {
            count_temp_reads_in_expr(cond, out);
            count_temp_reads_in_body(body, out);
        }
        Stmt::For {
            init,
            cond,
            step,
            body,
        } => {
            count_temp_reads_in_stmt(init, out);
            count_temp_reads_in_expr(cond, out);
            count_temp_reads_in_stmt(step, out);
            count_temp_reads_in_body(body, out);
        }
        Stmt::DoWhile { body, cond } => {
            count_temp_reads_in_body(body, out);
            count_temp_reads_in_expr(cond, out);
        }
        Stmt::Push { value } => count_temp_reads_in_expr(value, out),
        Stmt::Switch {
            discriminant,
            cases,
            default,
        } => {
            count_temp_reads_in_expr(discriminant, out);
            for (_, body) in cases {
                count_temp_reads_in_body(body, out);
            }
            if let Some(body) = default {
                count_temp_reads_in_body(body, out);
            }
        }
        Stmt::Label(_)
        | Stmt::Goto { .. }
        | Stmt::Break
        | Stmt::Nop
        | Stmt::Unknown(_)
        | Stmt::Comment(_)
        | Stmt::Pop { .. } => {}
    }
}

/// Reconstruct a post-tested loop as one ordered sequence: body, then latch.
///
/// Treating the body in isolation under-counts a temporary that is read once in
/// the body and again by the condition. The body-only walk then removes its
/// definition after substituting the first read, leaving the latch undefined.
/// A temporary `If` statement lets the existing linear-run logic see the latch
/// as the final consumer without giving it any branch semantics.
fn reconstruct_do_while(body: &mut Vec<Stmt>, cond: &mut Expr) {
    body.push(Stmt::If {
        cond: std::mem::replace(cond, Expr::Const(1)),
        then_body: Vec::new(),
        else_body: None,
    });
    reconstruct_body(body);
    let Some(Stmt::If {
        cond: reconstructed,
        then_body,
        else_body: None,
    }) = body.pop()
    else {
        unreachable!("the synthetic do-while latch must remain last")
    };
    debug_assert!(then_body.is_empty());
    *cond = reconstructed;
}

// -- Reg-reference utilities --------------------------------------------------

fn contains_reg(e: &Expr, target: &VReg) -> bool {
    match e {
        Expr::Reg(r) => r == target,
        Expr::StackAddr { object, .. } => object == target,
        Expr::Const(_)
        | Expr::FloatConst { .. }
        | Expr::Addr(_)
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::Unknown(_) => false,
        Expr::Lea { base, index, .. } | Expr::PdbFieldAddr { base, index, .. } => {
            base.as_ref().map(|r| r == target).unwrap_or(false)
                || index.as_ref().map(|r| r == target).unwrap_or(false)
        }
        Expr::Deref { addr, .. } => contains_reg(addr, target),
        Expr::Call {
            target: call_target,
            args,
            ..
        } => {
            contains_reg(call_target, target)
                || args.iter().any(|argument| contains_reg(argument, target))
        }
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            contains_reg(lhs, target) || contains_reg(rhs, target)
        }
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => {
            contains_reg(cond, target)
                || contains_reg(if_true, target)
                || contains_reg(if_false, target)
        }
        Expr::Un { src, .. } => contains_reg(src, target),
        Expr::Cast { expr, .. } | Expr::NumericConvert { expr, .. } => contains_reg(expr, target),
        Expr::FunctionTableEntry { index, .. } => contains_reg(index, target),
        Expr::WideArithmetic { args, .. } => {
            args.iter().any(|argument| contains_reg(argument, target))
        }
    }
}

/// Does `target` appear in a slot that only holds a register — an `Expr::Lea` or
/// `Expr::PdbFieldAddr` base or index — anywhere in this statement?
///
/// Such a use is invisible to [`substitute_in_expr`], which leaves those nodes
/// untouched by design, so its definition must be kept.
fn reads_as_address_register(s: &Stmt, target: &VReg) -> bool {
    fn in_expr(e: &Expr, target: &VReg) -> bool {
        match e {
            Expr::Lea { base, index, .. } | Expr::PdbFieldAddr { base, index, .. } => {
                base.as_ref() == Some(target) || index.as_ref() == Some(target)
            }
            Expr::Reg(_)
            | Expr::StackAddr { .. }
            | Expr::Const(_)
            | Expr::FloatConst { .. }
            | Expr::Addr(_)
            | Expr::Named { .. }
            | Expr::StringLit { .. }
            | Expr::Unknown(_) => false,
            Expr::Deref { addr, .. } => in_expr(addr, target),
            Expr::Call {
                target: call_target,
                args,
                ..
            } => {
                in_expr(call_target, target)
                    || args.iter().any(|argument| in_expr(argument, target))
            }
            Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
                in_expr(lhs, target) || in_expr(rhs, target)
            }
            Expr::Select {
                cond,
                if_true,
                if_false,
                ..
            } => in_expr(cond, target) || in_expr(if_true, target) || in_expr(if_false, target),
            Expr::Un { src, .. } => in_expr(src, target),
            Expr::Cast { expr, .. } | Expr::NumericConvert { expr, .. } => in_expr(expr, target),
            Expr::FunctionTableEntry { index, .. } => in_expr(index, target),
            Expr::WideArithmetic { args, .. } => {
                args.iter().any(|argument| in_expr(argument, target))
            }
        }
    }
    let mut found = false;
    for_each_expr_in_stmt(s, &mut |e| found |= in_expr(e, target));
    found
}

/// Visit every top-level expression of a statement.
fn for_each_expr_in_stmt(s: &Stmt, visit: &mut impl FnMut(&Expr)) {
    match s {
        Stmt::IndirectGoto { target } => visit(target),
        Stmt::Assign { src, .. } => visit(src),
        Stmt::Store { addr, src, .. } => {
            visit(addr);
            visit(src);
        }
        Stmt::Call { target, args, .. } => {
            visit(target);
            for a in args {
                visit(a);
            }
        }
        Stmt::If { cond, .. } | Stmt::While { cond, .. } | Stmt::DoWhile { cond, .. } => {
            visit(cond)
        }
        Stmt::Return { value } => {
            if let Some(e) = value {
                visit(e);
            }
        }
        Stmt::Push { value } => visit(value),
        Stmt::Switch { discriminant, .. } => visit(discriminant),
        _ => {}
    }
}

fn count_reg_uses(e: &Expr, target: &VReg) -> usize {
    match e {
        Expr::Reg(r) => (r == target) as usize,
        Expr::StackAddr { object, .. } => (object == target) as usize,
        Expr::Const(_)
        | Expr::FloatConst { .. }
        | Expr::Addr(_)
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::Unknown(_) => 0,
        Expr::Lea { base, index, .. } | Expr::PdbFieldAddr { base, index, .. } => {
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
        Expr::Call {
            target: call_target,
            args,
            ..
        } => {
            count_reg_uses(call_target, target)
                + args
                    .iter()
                    .map(|argument| count_reg_uses(argument, target))
                    .sum::<usize>()
        }
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            count_reg_uses(lhs, target) + count_reg_uses(rhs, target)
        }
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => {
            count_reg_uses(cond, target)
                + count_reg_uses(if_true, target)
                + count_reg_uses(if_false, target)
        }
        Expr::Un { src, .. } => count_reg_uses(src, target),
        Expr::Cast { expr, .. } | Expr::NumericConvert { expr, .. } => count_reg_uses(expr, target),
        Expr::FunctionTableEntry { index, .. } => count_reg_uses(index, target),
        Expr::WideArithmetic { args, .. } => args
            .iter()
            .map(|argument| count_reg_uses(argument, target))
            .sum(),
    }
}

fn count_reg_uses_in_stmt(s: &Stmt, target: &VReg) -> usize {
    match s {
        Stmt::IndirectGoto { target: t } => count_reg_uses(t, target),
        Stmt::Assign { src, .. } => count_reg_uses(src, target),
        Stmt::Store { addr, src, .. } => count_reg_uses(addr, target) + count_reg_uses(src, target),
        Stmt::Call {
            target: t, args, ..
        } => {
            count_reg_uses(t, target)
                + args
                    .iter()
                    .map(|a| count_reg_uses(a, target))
                    .sum::<usize>()
        }
        Stmt::If { cond, .. } | Stmt::While { cond, .. } | Stmt::DoWhile { cond, .. } => {
            count_reg_uses(cond, target)
        }
        Stmt::For {
            init, cond, step, ..
        } => {
            count_reg_uses_in_stmt(init, target)
                + count_reg_uses(cond, target)
                + count_reg_uses_in_stmt(step, target)
        }
        Stmt::Return { value } => value
            .as_ref()
            .map(|e| count_reg_uses(e, target))
            .unwrap_or(0),
        Stmt::Push { value } => count_reg_uses(value, target),
        Stmt::Switch { discriminant, .. } => count_reg_uses(discriminant, target),
        Stmt::Pop { .. }
        | Stmt::Goto { .. }
        | Stmt::Label(_)
        | Stmt::Break
        | Stmt::Nop
        | Stmt::Unknown(_)
        | Stmt::Comment(_)
        | Stmt::Throw { .. }
        | Stmt::TryCatch { .. } => 0,
    }
}

/// Count reads through every nested control-flow body.
///
/// Expression reconstruction may substitute only into the immediate
/// statement, but its single-use proof must include descendants. Otherwise a
/// loop counter read once by the guard and once by the update looks like a
/// one-use temporary; deleting its initializer freezes the guard while leaving
/// the carried update attached to an undefined value.
fn count_reg_uses_in_stmt_recursive(s: &Stmt, target: &VReg) -> usize {
    let direct = count_reg_uses_in_stmt(s, target);
    direct
        + match s {
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                count_reg_uses_in_body_recursive(then_body, target)
                    + else_body
                        .as_deref()
                        .map_or(0, |body| count_reg_uses_in_body_recursive(body, target))
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
                count_reg_uses_in_body_recursive(body, target)
            }
            Stmt::For { body, .. } => count_reg_uses_in_body_recursive(body, target),
            Stmt::Switch { cases, default, .. } => {
                cases
                    .iter()
                    .map(|(_, body)| count_reg_uses_in_body_recursive(body, target))
                    .sum::<usize>()
                    + default
                        .as_deref()
                        .map_or(0, |body| count_reg_uses_in_body_recursive(body, target))
            }
            Stmt::TryCatch { try_body, catches } => {
                count_reg_uses_in_body_recursive(try_body, target)
                    + catches
                        .iter()
                        .map(|catch| count_reg_uses_in_body_recursive(&catch.body, target))
                        .sum::<usize>()
            }
            _ => 0,
        }
}

fn count_reg_uses_in_body_recursive(body: &[Stmt], target: &VReg) -> usize {
    body.iter()
        .map(|statement| count_reg_uses_in_stmt_recursive(statement, target))
        .sum()
}

fn substitute_in_expr(e: &mut Expr, target: &VReg, with: &Expr) {
    let take = std::mem::replace(e, Expr::Unknown(String::new()));
    *e = match take {
        Expr::Reg(r) if &r == target => with.clone(),
        Expr::Reg(r) => Expr::Reg(r),
        Expr::StackAddr { object, size } => Expr::StackAddr { object, size },
        Expr::NumericConvert { from, to, mut expr } => {
            substitute_in_expr(&mut expr, target, with);
            Expr::NumericConvert { from, to, expr }
        }
        Expr::Const(c) => Expr::Const(c),
        Expr::FloatConst { bits, width } => Expr::FloatConst { bits, width },
        Expr::Addr(a) => Expr::Addr(a),
        Expr::Named { va, name } => Expr::Named { va, name },
        Expr::StringLit { value } => Expr::StringLit { value },
        Expr::FunctionTableEntry {
            table_va,
            table_name,
            pointer_size,
            mut index,
            targets,
        } => {
            substitute_in_expr(&mut index, target, with);
            Expr::FunctionTableEntry {
                table_va,
                table_name,
                pointer_size,
                index,
                targets,
            }
        }
        Expr::Call {
            target: mut call_target,
            mut args,
            call_spec,
            result_width,
        } => {
            substitute_in_expr(&mut call_target, target, with);
            for argument in &mut args {
                substitute_in_expr(argument, target, with);
            }
            Expr::Call {
                target: call_target,
                args,
                call_spec,
                result_width,
            }
        }
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
        Expr::PdbFieldAddr {
            base,
            index,
            scale,
            disp,
            segment,
            hints,
        } => Expr::PdbFieldAddr {
            base,
            index,
            scale,
            disp,
            segment,
            hints,
        },
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
        Expr::Cast {
            signed,
            width,
            mut expr,
        } => {
            substitute_in_expr(&mut expr, target, with);
            Expr::Cast {
                signed,
                width,
                expr,
            }
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
        Expr::Select {
            mut cond,
            mut if_true,
            mut if_false,
            width,
        } => {
            substitute_in_expr(&mut cond, target, with);
            substitute_in_expr(&mut if_true, target, with);
            substitute_in_expr(&mut if_false, target, with);
            Expr::Select {
                cond,
                if_true,
                if_false,
                width,
            }
        }
        Expr::WideArithmetic {
            op,
            mut args,
            width,
        } => {
            for argument in &mut args {
                substitute_in_expr(argument, target, with);
            }
            Expr::WideArithmetic { op, args, width }
        }
    };
}

fn substitute_in_stmt(s: &mut Stmt, target: &VReg, with: &Expr) {
    match s {
        Stmt::IndirectGoto { target: t } => substitute_in_expr(t, target, with),
        Stmt::Assign { src, .. } => substitute_in_expr(src, target, with),
        Stmt::Store { addr, src, .. } => {
            substitute_in_expr(addr, target, with);
            substitute_in_expr(src, target, with);
        }
        Stmt::Call {
            target: t, args, ..
        } => {
            substitute_in_expr(t, target, with);
            for a in args {
                substitute_in_expr(a, target, with);
            }
        }
        Stmt::If { cond, .. } | Stmt::While { cond, .. } | Stmt::DoWhile { cond, .. } => {
            substitute_in_expr(cond, target, with)
        }
        Stmt::For {
            init, cond, step, ..
        } => {
            substitute_in_stmt(init, target, with);
            substitute_in_expr(cond, target, with);
            substitute_in_stmt(step, target, with);
        }
        Stmt::Return { value } => {
            if let Some(e) = value {
                substitute_in_expr(e, target, with);
            }
        }
        Stmt::Push { value } => substitute_in_expr(value, target, with),
        Stmt::Switch { discriminant, .. } => substitute_in_expr(discriminant, target, with),
        Stmt::Pop { .. }
        | Stmt::Goto { .. }
        | Stmt::Label(_)
        | Stmt::Break
        | Stmt::Nop
        | Stmt::Unknown(_)
        | Stmt::Comment(_)
        | Stmt::Throw { .. }
        | Stmt::TryCatch { .. } => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::ast::{lower, render};
    use crate::ir::ssa::compute_ssa;
    use crate::ir::structure::recover;
    use crate::ir::types::{
        BinOp, CmpOp, Flag, LlirBlock, LlirFunction, LlirInstr, MemOp, Op, VReg, Value, Width,
    };

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
    fn loop_carried_temp_copy_is_not_inlined_only_into_the_guard() {
        let counter = VReg::Temp(1);
        let mut function = Function {
            name: "fill".into(),
            entry_va: 0x1000,
            body: vec![
                Stmt::Assign {
                    dst: counter.clone(),
                    src: Expr::Reg(VReg::phys("rcx#1")),
                },
                Stmt::While {
                    cond: Expr::Cmp {
                        op: CmpOp::Ne,
                        lhs: Box::new(Expr::Reg(counter.clone())),
                        rhs: Box::new(Expr::Const(0)),
                    },
                    body: vec![Stmt::Assign {
                        dst: counter.clone(),
                        src: Expr::Bin {
                            op: BinOp::Sub,
                            lhs: Box::new(Expr::Reg(counter)),
                            rhs: Box::new(Expr::Const(1)),
                        },
                    }],
                },
            ],
        };
        let before = function.clone();

        reconstruct(&mut function);

        assert_eq!(
            function, before,
            "the loop counter is carried across iterations"
        );
    }

    /// A temporary whose only use is an address's index survives.
    ///
    /// `substitute_in_expr` deliberately refuses to rewrite inside an
    /// `Expr::Lea`, whose base and index are *registers*, not expressions.
    /// Removing the definition anyway left the address reading a name nothing
    /// ever assigned — undefined behaviour in the recovered C, and a wrong
    /// answer from the recompiled function.
    ///
    /// Latent until AArch64: a `Lea` slot only ever held a physical register, so
    /// this loop — which inlines `VReg::Temp` definitions only — could not reach
    /// it. `ldr x0,[x1, w2, sxtw #2]` puts the widened index in a temporary and
    /// does.
    #[test]
    fn a_temp_used_only_as_an_address_index_keeps_its_definition() {
        let lf = mk_single_block(vec![
            Op::SExt {
                dst: VReg::Temp(0),
                src: Value::Reg(VReg::phys("w2")),
                from: Width::W32,
                to: Width::W64,
            },
            Op::Load {
                dst: VReg::phys("w0"),
                addr: MemOp {
                    base: Some(VReg::phys("x1")),
                    index: Some(VReg::Temp(0)),
                    scale: 4,
                    disp: 0,
                    size: 4,
                    segment: None,
                    endian: crate::ir::types::Endian::Little,
                },
            },
            Op::Return,
        ]);
        let ssa = compute_ssa(&lf);
        let r = recover(&lf, &ssa);
        let mut f = lower(&lf, &r, "f");
        reconstruct(&mut f);
        let text = render(&f);
        assert!(
            text.contains("%t0 ="),
            "the index temp's definition was removed but its use was not \
             substituted, so the address reads an undefined name:\n{text}"
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
        assert!(
            text.contains("%t0 = (%rax & %rax);"),
            "lost temp def: {}",
            text
        );
        assert!(text.contains("%zf = (%t0 == 0);"), "lost zf use: {}", text);
        assert!(text.contains("%sf = (%t0 < 0);"), "lost sf use: {}", text);
    }

    #[test]
    fn a_select_temp_stays_statement_rooted_for_one_armed_rendering() {
        let selected = VReg::Temp(0);
        let mut f = Function {
            name: "select".into(),
            entry_va: 0x1000,
            body: vec![
                Stmt::Assign {
                    dst: selected.clone(),
                    src: Expr::Select {
                        cond: Box::new(Expr::Reg(VReg::phys("cond"))),
                        if_true: Box::new(Expr::Reg(VReg::phys("yes"))),
                        if_false: Box::new(Expr::Reg(VReg::phys("no"))),
                        width: 8,
                    },
                },
                Stmt::Return {
                    value: Some(Expr::Reg(selected)),
                },
            ],
        };

        reconstruct(&mut f);

        assert!(
            matches!(
                f.body.as_slice(),
                [
                    Stmt::Assign {
                        src: Expr::Select { .. },
                        ..
                    },
                    Stmt::Return { .. }
                ]
            ),
            "a select must stay at statement scope for one-armed rendering: {:?}",
            f.body
        );
    }

    #[test]
    fn do_while_latch_counts_as_a_later_temp_use() {
        let temp = VReg::Temp(0);
        let mut f = Function {
            name: "post_test".into(),
            entry_va: 0,
            body: vec![Stmt::DoWhile {
                body: vec![
                    Stmt::Assign {
                        dst: temp.clone(),
                        src: Expr::Reg(VReg::phys("rax")),
                    },
                    Stmt::Assign {
                        dst: VReg::Flag(Flag::S),
                        src: Expr::Cmp {
                            op: CmpOp::Slt,
                            lhs: Box::new(Expr::Reg(temp.clone())),
                            rhs: Box::new(Expr::Const(0)),
                        },
                    },
                ],
                cond: Expr::Cmp {
                    op: CmpOp::Ne,
                    lhs: Box::new(Expr::Reg(temp.clone())),
                    rhs: Box::new(Expr::Const(0)),
                },
            }],
        };

        reconstruct(&mut f);

        let Stmt::DoWhile { body, .. } = &f.body[0] else {
            panic!("lost do-while: {:?}", f.body);
        };
        assert!(
            matches!(body.first(), Some(Stmt::Assign { dst, .. }) if dst == &temp),
            "the latch's second read must keep the temp definition: {body:?}"
        );
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
                total_timeout_ms: 0,
            },
        );
        for fn_ in &funcs {
            if let Ok(lf) = lift_function_from_bytes(&data, fn_, Arch::X86_64) {
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


    /// The census may over-count; it must never under-count.
    ///
    /// `reconstruct_body` uses `count_temp_reads_in_body(..) <= 1` as a licence
    /// to skip the forward sole-use scan, so a census entry BELOW the number of
    /// reads `count_reg_uses_in_stmt_recursive` can find would inline a
    /// temporary that has a second consumer and change the recovered C. Checked
    /// against real lifted bodies rather than a hand-built one, because the
    /// hazard is a statement or expression shape the census walker forgets.
    #[test]
    fn temp_read_census_never_undercounts_the_reference_walker() {
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
                max_functions: 16,
                max_blocks: 256,
                max_instructions: 8000,
                timeout_ms: 2000,
                total_timeout_ms: 0,
            },
        );
        let mut checked_temps = 0usize;
        for fn_ in &funcs {
            let Ok(lf) = lift_function_from_bytes(&data, fn_, Arch::X86_64) else {
                continue;
            };
            let ssa = compute_ssa(&lf);
            let r = recover(&lf, &ssa);
            let f = lower(&lf, &r, fn_.name.clone());

            let mut census = std::collections::HashMap::new();
            count_temp_reads_in_body(&f.body, &mut census);
            for (temp, counted) in &census {
                let reference: usize = f
                    .body
                    .iter()
                    .map(|stmt| count_reg_uses_in_stmt_recursive(stmt, temp))
                    .sum();
                assert!(
                    *counted as usize >= reference,
                    "census under-counted {temp:?} in {}: {counted} < {reference}",
                    fn_.name
                );
                checked_temps += 1;
            }
            // A temp the reference walker can see must appear in the census at
            // all — a missing key reads as zero, which is the same hazard.
            for stmt in &f.body {
                if let Stmt::Assign {
                    dst: dst @ VReg::Temp(_),
                    ..
                } = stmt
                {
                    let reference: usize = f
                        .body
                        .iter()
                        .map(|s| count_reg_uses_in_stmt_recursive(s, dst))
                        .sum();
                    if reference > 0 {
                        assert!(
                            census.contains_key(dst),
                            "census omitted {dst:?}, which the reference walker reads {reference} time(s)"
                        );
                    }
                }
            }
        }
        assert!(checked_temps > 0, "no temporaries reached the comparison");
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
                Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => n += count_stmts(body),
                Stmt::For { body, .. } => n += 2 + count_stmts(body),
                _ => {}
            }
        }
        n
    }
}
