//! Dead-code elimination for unused flag writes in a lowered [`Function`].
//!
//! After [`super::ast::lower`] runs, a typical x86 block emitted by the
//! Cmp-hoisting step can still carry several versioned `%cf_1 = ...`,
//! `%zf_2 = ...`, `%sf_1 = ...` statements whose LHS is never read anywhere
//! else in the function — they are leftover flag writes from the
//! cmp lifter that a human reader (or LLM) never needs to see.
//!
//! This pass counts total reads of each architectural or SSA-versioned flag
//! function body (including nested `If`/`While` arms) and removes the
//! assignment when the read-count is zero. Non-flag writes (`%rax = …`,
//! temp writes, etc.) are untouched — those are the responsibility of the
//! expression-reconstruction pass or explicit dead-store elimination later.

use crate::ir::ast::{Expr, Function, Stmt};
use crate::ir::types::VReg;

/// Every flag [`VReg`] the `reads_flag` reference walker would report for
/// this expression.
///
/// It must mirror that walker EXACTLY, including which nodes it declines
/// to descend into: this pass's decisions are not conservative in either
/// direction, so a broader walk would keep definitions the narrow one drops
/// and a narrower walk would drop definitions it keeps.
fn collect_flags_read(e: &Expr, out: &mut Vec<VReg>) {
    match e {
        Expr::Reg(v) => {
            if matches!(v, VReg::Flag(_) | VReg::FlagValue { .. }) {
                out.push(v.clone());
            }
        }
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            collect_flags_read(lhs, out);
            collect_flags_read(rhs, out);
        }
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => {
            collect_flags_read(cond, out);
            collect_flags_read(if_true, out);
            collect_flags_read(if_false, out);
        }
        Expr::Un { src, .. } => collect_flags_read(src, out),
        Expr::Cast { expr, .. } => collect_flags_read(expr, out),
        Expr::Deref { addr, .. } => collect_flags_read(addr, out),
        _ => {}
    }
}

/// Remove flag assignments that a LATER write to the same flag overwrites unread.
///
/// [`prune_dead_flags`] counts reads of the exact [`VReg`].  After value numbering,
/// every predicate definition is a distinct [`VReg::FlagValue`], so an unrelated
/// later ZF use cannot keep an earlier dead ZF definition alive.
///
/// Measured cost of that on `statemachine:gcc:O2`: eleven flag writes rendered as
/// statements against a single flag read in a condition. Ten statements the source does
/// not contain, and graph-edit distance charges for every one. It is concentrated at -O2
/// because that is where the compiler branches on arithmetic instead of emitting a
/// separate `cmp`.
///
/// This pass is a per-DEFINITION peephole, deliberately narrow enough to be obviously
/// sound: within one statement list, a flag write is dead when a later write to the SAME
/// flag is reached without passing
///
/// * a read of that flag,
/// * a label or goto (control flow this walk does not model — something could jump in
///   between and observe the value), or
/// * a nested block (`If`/`While`/`Switch`), whose arms might read it.
///
/// Anything it cannot prove, it leaves alone.  This pass remains useful before value
/// numbering, where the lifter still names architectural [`VReg::Flag`] values, and is
/// exact per definition after value numbering.
pub fn prune_overwritten_flags(f: &mut Function) {
    fn reads_flag(e: &Expr, flag: &VReg) -> bool {
        match e {
            Expr::Reg(v) => v == flag,
            Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
                reads_flag(lhs, flag) || reads_flag(rhs, flag)
            }
            Expr::Select {
                cond,
                if_true,
                if_false,
                ..
            } => reads_flag(cond, flag) || reads_flag(if_true, flag) || reads_flag(if_false, flag),
            Expr::Un { src, .. } => reads_flag(src, flag),
            Expr::Cast { expr, .. } => reads_flag(expr, flag),
            Expr::Deref { addr, .. } => reads_flag(addr, flag),
            _ => false,
        }
    }

    fn prune(body: &mut Vec<Stmt>) {
        // Recurse first so nested lists are handled independently.
        for st in body.iter_mut() {
            match st {
                Stmt::If {
                    then_body,
                    else_body,
                    ..
                } => {
                    prune(then_body);
                    if let Some(e) = else_body {
                        prune(e);
                    }
                }
                Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => prune(body),
                Stmt::For { body, .. } => prune(body),
                Stmt::Switch { cases, default, .. } => {
                    for (_, b) in cases.iter_mut() {
                        prune(b);
                    }
                    if let Some(b) = default {
                        prune(b);
                    }
                }
                _ => {}
            }
        }

        // One forward sweep instead of a forward scan per definition.
        //
        // `pending[F]` is the most recent definition of flag `F` that nothing
        // decisive has happened to yet, which is exactly the state the old
        // inner loop rediscovered from scratch for every `i`. A definition
        // leaves `pending` in one of three ways, and they are the same three
        // the per-definition scan looked for:
        //
        // * a statement reads `F` — the definition is live, drop the candidate;
        // * a statement redefines `F` — the candidate was overwritten unread,
        //   so mark it dead and become the new candidate; or
        // * control flow this walk does not model arrives, which clears every
        //   candidate at once.
        //
        // The reads are collected once per statement rather than tested once
        // per (definition, statement) pair. That is the whole difference: on a
        // long straight-line block with a dense flag web, nothing in the old
        // inner loop broke early, so it walked to the end of the block for
        // every flag write in it.
        let mut drop_at = vec![false; body.len()];
        let mut pending: std::collections::HashMap<VReg, usize> = std::collections::HashMap::new();
        let mut reads: Vec<VReg> = Vec::new();
        for j in 0..body.len() {
            match &body[j] {
                // Anything with flow we do not model, or a nested reader: give up.
                Stmt::Label(_)
                | Stmt::Goto { .. }
                | Stmt::If { .. }
                | Stmt::While { .. }
                | Stmt::For { .. }
                | Stmt::DoWhile { .. }
                | Stmt::Switch { .. }
                | Stmt::Call { .. }
                | Stmt::Return { .. } => pending.clear(),
                Stmt::Assign { dst, src } => {
                    reads.clear();
                    collect_flags_read(src, &mut reads);
                    for read in &reads {
                        pending.remove(read); // read before overwrite: live
                    }
                    if matches!(dst, VReg::Flag(_) | VReg::FlagValue { .. }) {
                        if let Some(previous) = pending.insert(dst.clone(), j) {
                            drop_at[previous] = true; // overwritten unread: dead
                        }
                    }
                }
                Stmt::Store { addr, src, .. } => {
                    reads.clear();
                    collect_flags_read(addr, &mut reads);
                    collect_flags_read(src, &mut reads);
                    for read in &reads {
                        pending.remove(read);
                    }
                }
                _ => {}
            }
        }
        let mut k = 0;
        body.retain(|_| {
            let keep = !drop_at[k];
            k += 1;
            keep
        });
    }

    prune(&mut f.body);
}

/// Backward per-definition liveness for raw, unversioned architectural flags.
///
/// The SSA path gives every definition a distinct `FlagValue`, but the human
/// renderer intentionally lowers raw LLIR too.  In that path, a single early
/// read of `%zf` must not keep an unrelated `%zf = ...` at function exit.  A
/// name-wide use count cannot make that distinction; backward liveness can.
fn prune_dead_unversioned_flags(f: &mut Function) {
    fn flag_regs() -> Vec<VReg> {
        use crate::ir::types::Flag;
        [
            Flag::Z,
            Flag::C,
            Flag::Ule,
            Flag::S,
            Flag::Slt,
            Flag::Sle,
            Flag::O,
            Flag::P,
            Flag::A,
            Flag::D,
            Flag::Bit,
        ]
        .into_iter()
        .map(VReg::Flag)
        .collect()
    }

    // `flags` is every `Flag` variant, so "some flag in `flags` is read here"
    // is exactly "some `VReg::Flag` is read here" — one traversal answers it
    // for all eleven at once. The `flags` parameter is retained only so the
    // callers below read the same; it is no longer scanned per flag.
    fn add_expr_reads(expr: &Expr, live: &mut std::collections::BTreeSet<VReg>, _flags: &[VReg]) {
        collect_flag_reads_in_expr(expr, live, false);
    }

    fn add_stmt_reads(stmt: &Stmt, live: &mut std::collections::BTreeSet<VReg>, _flags: &[VReg]) {
        collect_flag_reads_in_stmt(stmt, live, false);
    }

    fn prune_body(
        body: &mut Vec<Stmt>,
        live_out: &std::collections::BTreeSet<VReg>,
        flags: &[VReg],
    ) -> std::collections::BTreeSet<VReg> {
        let mut live = live_out.clone();
        let mut drop_at = vec![false; body.len()];
        for index in (0..body.len()).rev() {
            match &mut body[index] {
                Stmt::Assign { dst, src } if matches!(dst, VReg::Flag(_)) => {
                    if !live.contains(dst) {
                        drop_at[index] = true;
                    } else {
                        live.remove(dst);
                        add_expr_reads(src, &mut live, flags);
                    }
                }
                Stmt::If {
                    cond,
                    then_body,
                    else_body,
                } => {
                    let then_live = prune_body(then_body, &live, flags);
                    let else_live = else_body
                        .as_mut()
                        .map(|branch| prune_body(branch, &live, flags))
                        .unwrap_or_else(|| live.clone());
                    live.extend(then_live);
                    live.extend(else_live);
                    add_expr_reads(cond, &mut live, flags);
                }
                Stmt::Switch {
                    discriminant,
                    cases,
                    default,
                } => {
                    let branch_out = live.clone();
                    for (_, case_body) in cases.iter_mut() {
                        live.extend(prune_body(case_body, &branch_out, flags));
                    }
                    if let Some(default_body) = default {
                        live.extend(prune_body(default_body, &branch_out, flags));
                    } else {
                        live.extend(branch_out);
                    }
                    add_expr_reads(discriminant, &mut live, flags);
                }
                // A loop can carry a flag from its tail to its next condition.
                // Seed its body with every flag read anywhere in the loop; this
                // is conservative (it may keep a dead write) but cannot delete a
                // loop-carried definition.
                stmt @ (Stmt::While { .. } | Stmt::DoWhile { .. } | Stmt::For { .. }) => {
                    add_stmt_reads(stmt, &mut live, flags);
                }
                // With unstructured entry points, a predecessor outside this
                // lexical list may observe any architectural flag. Stop pruning
                // definitions that precede the boundary.
                stmt @ (Stmt::Label(_) | Stmt::Goto { .. } | Stmt::IndirectGoto { .. }) => {
                    live.extend(flags.iter().cloned());
                    add_stmt_reads(stmt, &mut live, flags);
                }
                stmt => add_stmt_reads(stmt, &mut live, flags),
            }
        }
        let mut index = 0;
        body.retain(|_| {
            let keep = !drop_at[index];
            index += 1;
            keep
        });
        live
    }

    let flags = flag_regs();
    prune_body(&mut f.body, &std::collections::BTreeSet::new(), &flags);
}

/// Remove zero-use flag assignments from `f` in place.
pub fn prune_dead_flags(f: &mut Function) {
    prune_dead_unversioned_flags(f);

    fn collect_flag_defs(body: &[Stmt], out: &mut std::collections::BTreeSet<VReg>) {
        for stmt in body {
            match stmt {
                Stmt::Assign { dst, .. }
                    if matches!(dst, VReg::Flag(_) | VReg::FlagValue { .. }) =>
                {
                    out.insert(dst.clone());
                }
                Stmt::If {
                    then_body,
                    else_body,
                    ..
                } => {
                    collect_flag_defs(then_body, out);
                    if let Some(else_body) = else_body {
                        collect_flag_defs(else_body, out);
                    }
                }
                Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
                    collect_flag_defs(body, out)
                }
                Stmt::For {
                    init, step, body, ..
                } => {
                    collect_flag_defs(std::slice::from_ref(init.as_ref()), out);
                    collect_flag_defs(body, out);
                    collect_flag_defs(std::slice::from_ref(step.as_ref()), out);
                }
                Stmt::Switch { cases, default, .. } => {
                    for (_, case_body) in cases {
                        collect_flag_defs(case_body, out);
                    }
                    if let Some(default_body) = default {
                        collect_flag_defs(default_body, out);
                    }
                }
                _ => {}
            }
        }
    }

    fn retain_live(body: &mut Vec<Stmt>, live: &std::collections::BTreeSet<VReg>) {
        for stmt in body.iter_mut() {
            match stmt {
                Stmt::If {
                    then_body,
                    else_body,
                    ..
                } => {
                    retain_live(then_body, live);
                    if let Some(else_body) = else_body {
                        retain_live(else_body, live);
                    }
                }
                Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => retain_live(body, live),
                Stmt::For {
                    init, step, body, ..
                } => {
                    if matches!(
                        init.as_ref(),
                        Stmt::Assign { dst, src }
                            if matches!(dst, VReg::Flag(_) | VReg::FlagValue { .. })
                                && !live.contains(dst)
                                && !src.contains_call()
                    ) {
                        **init = Stmt::Nop;
                    }
                    retain_live(body, live);
                    if matches!(
                        step.as_ref(),
                        Stmt::Assign { dst, src }
                            if matches!(dst, VReg::Flag(_) | VReg::FlagValue { .. })
                                && !live.contains(dst)
                                && !src.contains_call()
                    ) {
                        **step = Stmt::Nop;
                    }
                }
                Stmt::Switch { cases, default, .. } => {
                    for (_, case_body) in cases {
                        retain_live(case_body, live);
                    }
                    if let Some(default_body) = default {
                        retain_live(default_body, live);
                    }
                }
                _ => {}
            }
        }
        body.retain(|stmt| {
            !matches!(
                stmt,
                Stmt::Assign { dst, src }
                    if matches!(dst, VReg::Flag(_) | VReg::FlagValue { .. })
                        && !live.contains(dst)
                        && !src.contains_call()
            )
        });
    }

    loop {
        let mut defs = std::collections::BTreeSet::new();
        collect_flag_defs(&f.body, &mut defs);
        // One traversal recording every flag read anywhere in the body, then
        // an intersection. The predicate below is `read-count > 0`, so which
        // flags are read is all that is needed — the previous form re-walked
        // the WHOLE body once per flag definition, which on a dense spill web
        // (thousands of `%sf_N` definitions over tens of thousands of
        // statements) is the quadratic that dominated this pass.
        let mut read = std::collections::BTreeSet::new();
        for stmt in &f.body {
            collect_flag_reads_in_stmt(stmt, &mut read, true);
        }
        let live: std::collections::BTreeSet<VReg> = defs
            .iter()
            .filter(|flag| read.contains(*flag))
            .cloned()
            .collect();
        if live.len() == defs.len() {
            break;
        }
        retain_live(&mut f.body, &live);
    }
}

/// Collect, in ONE traversal, every flag [`VReg`] that appears in a READ
/// position of `e`.
///
/// This is the set form of [`count_reads_in_expr`]: it visits exactly the same
/// positions, but answers "which flags are read" for all flags at once instead
/// of "how many times is THIS flag read" for one. The two callers below only
/// ever compared the count against zero, and both were paying a full traversal
/// per candidate flag — `prune_dead_flags` once per flag definition in the
/// function, `prune_dead_unversioned_flags` eleven times per statement.
///
/// `versioned` selects which flag spellings are recorded:
/// `false` keeps only raw architectural [`VReg::Flag`] (what the unversioned
/// pass's `flags` list contains), `true` also keeps [`VReg::FlagValue`].
fn collect_flag_reads_in_expr(
    e: &Expr,
    out: &mut std::collections::BTreeSet<VReg>,
    versioned: bool,
) {
    fn note(r: &VReg, out: &mut std::collections::BTreeSet<VReg>, versioned: bool) {
        let is_flag = match r {
            VReg::Flag(_) => true,
            VReg::FlagValue { .. } => versioned,
            _ => false,
        };
        if is_flag && !out.contains(r) {
            out.insert(r.clone());
        }
    }
    match e {
        Expr::Reg(r) => note(r, out, versioned),
        Expr::StackAddr { object, .. } => note(object, out, versioned),
        Expr::Const(_)
        | Expr::FloatConst { .. }
        | Expr::Addr(_)
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::Unknown(_) => {}
        Expr::Lea { base, index, .. } | Expr::PdbFieldAddr { base, index, .. } => {
            if let Some(base) = base {
                note(base, out, versioned);
            }
            if let Some(index) = index {
                note(index, out, versioned);
            }
        }
        Expr::Deref { addr, .. } => collect_flag_reads_in_expr(addr, out, versioned),
        Expr::Call {
            target: call_target,
            args,
            ..
        } => {
            collect_flag_reads_in_expr(call_target, out, versioned);
            for argument in args {
                collect_flag_reads_in_expr(argument, out, versioned);
            }
        }
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            collect_flag_reads_in_expr(lhs, out, versioned);
            collect_flag_reads_in_expr(rhs, out, versioned);
        }
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => {
            collect_flag_reads_in_expr(cond, out, versioned);
            collect_flag_reads_in_expr(if_true, out, versioned);
            collect_flag_reads_in_expr(if_false, out, versioned);
        }
        Expr::Un { src, .. } => collect_flag_reads_in_expr(src, out, versioned),
        Expr::Cast { expr, .. } | Expr::NumericConvert { expr, .. } => {
            collect_flag_reads_in_expr(expr, out, versioned)
        }
        Expr::FunctionTableEntry { index, .. } => collect_flag_reads_in_expr(index, out, versioned),
        Expr::WideArithmetic { args, .. } => {
            for argument in args {
                collect_flag_reads_in_expr(argument, out, versioned);
            }
        }
    }
}

/// Set form of [`count_reads_in_stmt`] — same traversal, all flags at once.
///
/// Note the deliberate matches with the counting version, including that
/// `TryCatch` is NOT descended into: this must record exactly the reads the
/// count would have found, or the liveness decisions change.
fn collect_flag_reads_in_stmt(
    s: &Stmt,
    out: &mut std::collections::BTreeSet<VReg>,
    versioned: bool,
) {
    match s {
        Stmt::IndirectGoto { target } => collect_flag_reads_in_expr(target, out, versioned),
        Stmt::Assign { src, .. } => collect_flag_reads_in_expr(src, out, versioned),
        Stmt::Store { addr, src, .. } => {
            collect_flag_reads_in_expr(addr, out, versioned);
            collect_flag_reads_in_expr(src, out, versioned);
        }
        Stmt::Call {
            target: t, args, ..
        } => {
            collect_flag_reads_in_expr(t, out, versioned);
            for a in args {
                collect_flag_reads_in_expr(a, out, versioned);
            }
        }
        Stmt::Return { value } => {
            if let Some(e) = value {
                collect_flag_reads_in_expr(e, out, versioned);
            }
        }
        Stmt::If {
            cond,
            then_body,
            else_body,
        } => {
            collect_flag_reads_in_expr(cond, out, versioned);
            for st in then_body {
                collect_flag_reads_in_stmt(st, out, versioned);
            }
            if let Some(eb) = else_body {
                for st in eb {
                    collect_flag_reads_in_stmt(st, out, versioned);
                }
            }
        }
        Stmt::While { cond, body } => {
            collect_flag_reads_in_expr(cond, out, versioned);
            for st in body {
                collect_flag_reads_in_stmt(st, out, versioned);
            }
        }
        Stmt::For {
            init,
            cond,
            step,
            body,
        } => {
            collect_flag_reads_in_stmt(init, out, versioned);
            collect_flag_reads_in_expr(cond, out, versioned);
            for st in body {
                collect_flag_reads_in_stmt(st, out, versioned);
            }
            collect_flag_reads_in_stmt(step, out, versioned);
        }
        Stmt::DoWhile { body, cond } => {
            for st in body {
                collect_flag_reads_in_stmt(st, out, versioned);
            }
            collect_flag_reads_in_expr(cond, out, versioned);
        }
        Stmt::Push { value } => collect_flag_reads_in_expr(value, out, versioned),
        Stmt::Switch {
            discriminant,
            cases,
            default,
        } => {
            collect_flag_reads_in_expr(discriminant, out, versioned);
            for (_, body) in cases {
                for st in body {
                    collect_flag_reads_in_stmt(st, out, versioned);
                }
            }
            if let Some(b) = default {
                for st in b {
                    collect_flag_reads_in_stmt(st, out, versioned);
                }
            }
        }
        Stmt::Pop { .. }
        | Stmt::Goto { .. }
        | Stmt::Label(_)
        | Stmt::Break
        | Stmt::Continue
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
    use crate::ir::types::{CmpOp, Flag, LlirBlock, LlirFunction, LlirInstr, Op, VReg, Value};

    // ---------------------------------------------------------------
    // Reference walkers.
    //
    // These are the exact per-target traversals the pass used to run once
    // per candidate flag. They are kept as the specification the
    // single-traversal collectors above are checked against: the
    // collectors decide which flag definitions survive, so a collector
    // that visits one node more or fewer than these do changes the
    // recovered C rather than merely the time it takes to recover it.
    // ---------------------------------------------------------------

    fn count_reads_in_expr(e: &Expr, target: &VReg) -> usize {
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
                (base.as_ref() == Some(target)) as usize + (index.as_ref() == Some(target)) as usize
            }
            Expr::Deref { addr, .. } => count_reads_in_expr(addr, target),
            Expr::Call {
                target: call_target,
                args,
                ..
            } => {
                count_reads_in_expr(call_target, target)
                    + args
                        .iter()
                        .map(|argument| count_reads_in_expr(argument, target))
                        .sum::<usize>()
            }
            Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
                count_reads_in_expr(lhs, target) + count_reads_in_expr(rhs, target)
            }
            Expr::Select {
                cond,
                if_true,
                if_false,
                ..
            } => {
                count_reads_in_expr(cond, target)
                    + count_reads_in_expr(if_true, target)
                    + count_reads_in_expr(if_false, target)
            }
            Expr::Un { src, .. } => count_reads_in_expr(src, target),
            Expr::Cast { expr, .. } | Expr::NumericConvert { expr, .. } => {
                count_reads_in_expr(expr, target)
            }
            Expr::FunctionTableEntry { index, .. } => count_reads_in_expr(index, target),
            Expr::WideArithmetic { args, .. } => args
                .iter()
                .map(|argument| count_reads_in_expr(argument, target))
                .sum(),
        }
    }

    fn count_reads_in_stmt(s: &Stmt, target: &VReg) -> usize {
        match s {
            Stmt::IndirectGoto { target: t } => count_reads_in_expr(t, target),
            Stmt::Assign { src, .. } => count_reads_in_expr(src, target),
            Stmt::Store { addr, src, .. } => {
                count_reads_in_expr(addr, target) + count_reads_in_expr(src, target)
            }
            Stmt::Call {
                target: t, args, ..
            } => {
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
            Stmt::For {
                init,
                cond,
                step,
                body,
            } => {
                count_reads_in_stmt(init, target)
                    + count_reads_in_expr(cond, target)
                    + body
                        .iter()
                        .map(|stmt| count_reads_in_stmt(stmt, target))
                        .sum::<usize>()
                    + count_reads_in_stmt(step, target)
            }
            Stmt::DoWhile { body, cond } => {
                let mut n = body
                    .iter()
                    .map(|st| count_reads_in_stmt(st, target))
                    .sum::<usize>();
                n += count_reads_in_expr(cond, target);
                n
            }
            Stmt::Push { value } => count_reads_in_expr(value, target),
            Stmt::Switch {
                discriminant,
                cases,
                default,
            } => {
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
            | Stmt::Break
            | Stmt::Continue
            | Stmt::Nop
            | Stmt::Unknown(_)
            | Stmt::Comment(_)
            | Stmt::Throw { .. }
            | Stmt::TryCatch { .. } => 0,
        }
    }

    /// The narrow read test `prune_overwritten_flags` was written against.
    fn reads_flag(e: &Expr, flag: &VReg) -> bool {
        match e {
            Expr::Reg(v) => v == flag,
            Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
                reads_flag(lhs, flag) || reads_flag(rhs, flag)
            }
            Expr::Select {
                cond,
                if_true,
                if_false,
                ..
            } => reads_flag(cond, flag) || reads_flag(if_true, flag) || reads_flag(if_false, flag),
            Expr::Un { src, .. } => reads_flag(src, flag),
            Expr::Cast { expr, .. } => reads_flag(expr, flag),
            Expr::Deref { addr, .. } => reads_flag(addr, flag),
            _ => false,
        }
    }

    /// A body reaching every statement and expression shape the collectors
    /// walk, so the differential tests below compare traversals rather than
    /// just the handful of shapes the behavioural tests happen to build.
    fn shape_zoo() -> (Vec<Stmt>, Vec<VReg>) {
        let zf = VReg::Flag(Flag::Z);
        let cf = VReg::Flag(Flag::C);
        let sf = VReg::Flag(Flag::S);
        let of = VReg::Flag(Flag::O);
        let zf1 = VReg::FlagValue {
            flag: Flag::Z,
            version: 1,
        };
        let cf2 = VReg::FlagValue {
            flag: Flag::C,
            version: 2,
        };
        let rax = VReg::Phys("rax".into());

        let deep = Expr::Bin {
            op: crate::ir::types::BinOp::Add,
            lhs: Box::new(Expr::Cast {
                signed: true,
                width: 4,
                expr: Box::new(Expr::Reg(zf.clone())),
            }),
            rhs: Box::new(Expr::Un {
                op: crate::ir::types::UnOp::Not,
                src: Box::new(Expr::Deref {
                    addr: Box::new(Expr::Reg(cf.clone())),
                    size: 4,
                }),
            }),
        };
        let selected = Expr::Select {
            cond: Box::new(Expr::Reg(zf1.clone())),
            if_true: Box::new(Expr::Reg(sf.clone())),
            if_false: Box::new(Expr::Cmp {
                op: CmpOp::Eq,
                lhs: Box::new(Expr::Reg(of.clone())),
                rhs: Box::new(Expr::Const(0)),
            }),
            width: 8,
        };

        let body = vec![
            Stmt::Assign {
                dst: zf1.clone(),
                src: deep.clone(),
            },
            Stmt::Store {
                addr: Expr::Reg(cf2.clone()),
                src: selected.clone(),
                size: 8,
            },
            Stmt::Call {
                target: Expr::Reg(rax.clone()),
                args: vec![Expr::Reg(sf.clone()), deep.clone()],
                dst: Some(rax.clone()),
                call_spec: None,
            },
            Stmt::Push {
                value: Expr::Reg(of.clone()),
            },
            Stmt::IndirectGoto {
                target: Expr::Reg(cf.clone()),
            },
            Stmt::Return {
                value: Some(selected.clone()),
            },
            Stmt::If {
                cond: Expr::Reg(zf.clone()),
                then_body: vec![Stmt::Assign {
                    dst: cf2.clone(),
                    src: Expr::Reg(sf.clone()),
                }],
                else_body: Some(vec![Stmt::Return {
                    value: Some(Expr::Reg(zf1.clone())),
                }]),
            },
            Stmt::While {
                cond: Expr::Reg(cf.clone()),
                body: vec![Stmt::Push {
                    value: Expr::Reg(zf.clone()),
                }],
            },
            Stmt::DoWhile {
                body: vec![Stmt::Assign {
                    dst: sf.clone(),
                    src: Expr::Reg(of.clone()),
                }],
                cond: deep.clone(),
            },
            Stmt::For {
                init: Box::new(Stmt::Assign {
                    dst: zf.clone(),
                    src: Expr::Reg(cf2.clone()),
                }),
                cond: Expr::Reg(sf.clone()),
                step: Box::new(Stmt::Assign {
                    dst: cf.clone(),
                    src: Expr::Reg(zf1.clone()),
                }),
                body: vec![Stmt::Store {
                    addr: Expr::Reg(of.clone()),
                    src: Expr::Reg(zf.clone()),
                    size: 4,
                }],
            },
            Stmt::Switch {
                discriminant: Expr::Reg(cf2.clone()),
                cases: vec![
                    (
                        Some(0),
                        vec![Stmt::Assign {
                            dst: of.clone(),
                            src: Expr::Reg(zf.clone()),
                        }],
                    ),
                    (
                        Some(1),
                        vec![Stmt::Push {
                            value: Expr::Reg(cf.clone()),
                        }],
                    ),
                ],
                default: Some(vec![Stmt::Return {
                    value: Some(Expr::Reg(sf.clone())),
                }]),
            },
            Stmt::Label(0x40),
            Stmt::Goto { target: 0x40 },
            Stmt::Nop,
            Stmt::Break,
            Stmt::Comment("c".into()),
            Stmt::Unknown("u".into()),
            Stmt::Pop {
                target: rax.clone(),
            },
        ];
        (body, vec![zf, cf, sf, of, zf1, cf2, rax])
    }

    #[test]
    fn flag_read_collector_matches_the_reference_counter() {
        let (body, targets) = shape_zoo();
        for versioned in [false, true] {
            let mut collected = std::collections::BTreeSet::new();
            for stmt in &body {
                collect_flag_reads_in_stmt(stmt, &mut collected, versioned);
            }
            for target in &targets {
                let counted: usize = body
                    .iter()
                    .map(|stmt| count_reads_in_stmt(stmt, target))
                    .sum();
                let is_flag = match target {
                    VReg::Flag(_) => true,
                    VReg::FlagValue { .. } => versioned,
                    _ => false,
                };
                assert_eq!(
                    collected.contains(target),
                    counted > 0 && is_flag,
                    "collector and reference counter disagree on {target:?} (versioned={versioned})"
                );
            }
        }
    }

    #[test]
    fn narrow_flag_read_collector_matches_reads_flag() {
        let (body, targets) = shape_zoo();
        // `reads_flag` is an EXPRESSION test, so compare it expression by
        // expression over every expression the zoo contains.
        let mut exprs: Vec<Expr> = Vec::new();
        fn gather(body: &[Stmt], out: &mut Vec<Expr>) {
            for stmt in body {
                match stmt {
                    Stmt::Assign { src, .. } => out.push(src.clone()),
                    Stmt::Store { addr, src, .. } => {
                        out.push(addr.clone());
                        out.push(src.clone());
                    }
                    Stmt::Call { target, args, .. } => {
                        out.push(target.clone());
                        out.extend(args.iter().cloned());
                    }
                    Stmt::Return { value: Some(e) } => out.push(e.clone()),
                    Stmt::Push { value } => out.push(value.clone()),
                    Stmt::IndirectGoto { target } => out.push(target.clone()),
                    Stmt::If {
                        cond,
                        then_body,
                        else_body,
                    } => {
                        out.push(cond.clone());
                        gather(then_body, out);
                        if let Some(body) = else_body {
                            gather(body, out);
                        }
                    }
                    Stmt::While { cond, body } | Stmt::DoWhile { body, cond } => {
                        out.push(cond.clone());
                        gather(body, out);
                    }
                    Stmt::For {
                        init,
                        cond,
                        step,
                        body,
                    } => {
                        out.push(cond.clone());
                        gather(std::slice::from_ref(init.as_ref()), out);
                        gather(std::slice::from_ref(step.as_ref()), out);
                        gather(body, out);
                    }
                    Stmt::Switch {
                        discriminant,
                        cases,
                        default,
                    } => {
                        out.push(discriminant.clone());
                        for (_, case) in cases {
                            gather(case, out);
                        }
                        if let Some(body) = default {
                            gather(body, out);
                        }
                    }
                    _ => {}
                }
            }
        }
        gather(&body, &mut exprs);
        assert!(exprs.len() > 20, "zoo should reach many expressions");

        for expr in &exprs {
            let mut collected = Vec::new();
            collect_flags_read(expr, &mut collected);
            assert!(
                collected
                    .iter()
                    .all(|r| matches!(r, VReg::Flag(_) | VReg::FlagValue { .. })),
                "collect_flags_read recorded a non-flag register in {expr:?}"
            );
            for target in &targets {
                // The pass only ever asks about a flag: `flag` comes from an
                // `Assign` destination already matched as `Flag`/`FlagValue`.
                if !matches!(target, VReg::Flag(_) | VReg::FlagValue { .. }) {
                    continue;
                }
                assert_eq!(
                    collected.contains(target),
                    reads_flag(expr, target),
                    "collect_flags_read and reads_flag disagree on {target:?} in {expr:?}"
                );
            }
        }
    }

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
    fn prunes_only_the_unused_versioned_predicate_definition() {
        let zf_1 = VReg::FlagValue {
            flag: Flag::Z,
            version: 1,
        };
        let zf_2 = VReg::FlagValue {
            flag: Flag::Z,
            version: 2,
        };
        let mut f = Function {
            name: "versioned_flags".into(),
            entry_va: 0x1000,
            body: vec![
                Stmt::Assign {
                    dst: zf_1.clone(),
                    src: Expr::Const(0),
                },
                Stmt::Assign {
                    dst: zf_2.clone(),
                    src: Expr::Const(1),
                },
                Stmt::If {
                    cond: Expr::Reg(zf_2.clone()),
                    then_body: vec![Stmt::Nop],
                    else_body: None,
                },
            ],
        };

        prune_dead_flags(&mut f);

        assert_eq!(f.body.len(), 2);
        assert!(!f
            .body
            .iter()
            .any(|stmt| { matches!(stmt, Stmt::Assign { dst, .. } if dst == &zf_1) }));
        assert!(f
            .body
            .iter()
            .any(|stmt| { matches!(stmt, Stmt::Assign { dst, .. } if dst == &zf_2) }));
    }

    #[test]
    fn prunes_a_trailing_unversioned_write_after_an_earlier_read() {
        let zf = VReg::Flag(Flag::Z);
        let mut f = Function {
            name: "raw_flags".into(),
            entry_va: 0x1000,
            body: vec![
                Stmt::Assign {
                    dst: zf.clone(),
                    src: Expr::Const(1),
                },
                Stmt::If {
                    cond: Expr::Reg(zf.clone()),
                    then_body: vec![Stmt::Nop],
                    else_body: None,
                },
                Stmt::Assign {
                    dst: zf.clone(),
                    src: Expr::Const(0),
                },
                Stmt::Return { value: None },
            ],
        };

        prune_dead_flags(&mut f);

        assert_eq!(
            f.body
                .iter()
                .filter(|stmt| matches!(stmt, Stmt::Assign { dst, .. } if dst == &zf))
                .count(),
            1,
            "the read must keep its reaching write, but not a later trailing write: {:#?}",
            f.body
        );
    }

    #[test]
    fn keeps_a_predicate_defined_in_a_do_while_body_and_read_by_its_latch() {
        let zf = VReg::FlagValue {
            flag: Flag::Z,
            version: 5,
        };
        let mut f = Function {
            name: "shift_until_zero".into(),
            entry_va: 0x1000,
            body: vec![Stmt::DoWhile {
                body: vec![Stmt::Assign {
                    dst: zf.clone(),
                    src: Expr::Cmp {
                        op: CmpOp::Eq,
                        lhs: Box::new(Expr::Reg(VReg::phys("value"))),
                        rhs: Box::new(Expr::Const(0)),
                    },
                }],
                cond: Expr::Cmp {
                    op: CmpOp::Eq,
                    lhs: Box::new(Expr::Reg(zf.clone())),
                    rhs: Box::new(Expr::Const(0)),
                },
            }],
        };

        prune_dead_flags(&mut f);

        let Stmt::DoWhile { body, .. } = &f.body[0] else {
            panic!("fixture changed shape")
        };
        assert!(matches!(
            body.as_slice(),
            [Stmt::Assign { dst, .. }] if dst == &zf
        ));
    }

    #[test]
    fn dead_predicate_dependency_chains_are_pruned_to_a_fixpoint() {
        let sf = VReg::FlagValue {
            flag: Flag::S,
            version: 1,
        };
        let of = VReg::FlagValue {
            flag: Flag::O,
            version: 1,
        };
        let mut f = Function {
            name: "dead_chain".into(),
            entry_va: 0x1000,
            body: vec![
                Stmt::Assign {
                    dst: sf.clone(),
                    src: Expr::Const(0),
                },
                Stmt::Assign {
                    dst: of,
                    src: Expr::Bin {
                        op: crate::ir::types::BinOp::Xor,
                        lhs: Box::new(Expr::Reg(sf)),
                        rhs: Box::new(Expr::Const(1)),
                    },
                },
                Stmt::Return { value: None },
            ],
        };

        prune_dead_flags(&mut f);

        assert_eq!(f.body, vec![Stmt::Return { value: None }]);
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
                        inverted: false,
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
                        inverted: false,
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
