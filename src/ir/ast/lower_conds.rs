//! Flag-condition hoisting, and the safety predicates that gate code motion.
//!
//! Two kinds of movement happen here, and both are refusals by default:
//!
//! * [`hoist_inline_flag_conds`] folds a comparison into the condition that
//!   consumes its flag, so the printer emits `if (a < b)` rather than the
//!   opaque `if (%zf)`. [`lower_block`] runs it over every lowered block.
//! * [`hoisting_the_header_is_safe`] decides whether a loop header's leftover
//!   preamble may be lifted above the `while`. Its caller,
//!   [`super::lower_region`], emits `while (1) { pre; if (!cond) break; body }`
//!   when it declines.
//!
//! The predicates below (`can_eagerly_evaluate`, `expr_reads_memory`,
//! `stmt_may_change_condition_input`, `moving_condition_to_end_is_safe`) are
//! shared by both and are deliberately conservative: every one of them is
//! consulted to *forbid* a rewrite, so an over-approximation only costs
//! prettiness while an under-approximation costs correctness.

use super::lower_ops::lower_op;
use super::{Expr, Stmt, WideArithmetic};
use crate::ir::types::{BinOp, CmpOp, LlirBlock, LlirFunction, LlirInstr, Op, UnOp, VReg};

/// May the loop header's leftover statements be hoisted above the `while`?
///
/// Only when they are **loop-invariant**: hoisting per-iteration work leaves the
/// condition reading a value nothing updates, and the loop never ends.
///
/// Establishing that needs the BODY, not just the preamble. An earlier version of
/// this checked only the preamble and rejected two shapes — a memory read, and a
/// register updating itself (`p = p + 1`). Both rejections are still necessary and
/// neither is sufficient, because a preamble can read a register the *body*
/// assigns:
///
/// ```text
/// t = i + 1;                            <- hoisted: not a self-reference,
/// while (t < n) { ...; i = i + 1; }         reads no memory, still wrong
/// ```
///
/// `t` never changes and the loop spins forever. So the real rule is a def-use
/// question: every register the preamble reads, other than one it defines itself
/// earlier in the chain, must not be assigned anywhere in the body.
///
/// The preamble is *itself* part of that body. It executes at the top of every
/// iteration, so a register it assigns is loop-carried exactly like one the body
/// assigns, and a statement that reads such a register **before** the preamble
/// reassigns it is reading the previous iteration's value:
///
/// ```text
/// cursor = estimate;                    <- reads the carried value
/// estimate = (cursor + n / cursor) / 2; <- and produces the next one
/// while (cursor > estimate) { ... }
/// ```
///
/// Hoisting that runs the recurrence once and leaves the condition comparing two
/// values nothing updates. Checking only the body missed it because the body here
/// is just the latch. `newton_isqrt` at `gcc -O2` is the measured case: its whole
/// Newton step moved out of the loop and the function returned the first estimate.
///

/// What remains disqualifying regardless of the body:
///
/// * a MEMORY read — the body may store through the same pointer via a `Stmt::Store`
///   this analysis does not alias-track, and a reload is exactly what a
///   `while ((c = *s++))` header is doing;
/// * a register that updates ITSELF — a per-iteration side effect;
/// * anything with an effect (a store, a call, a push).
///
/// When this declines, the caller emits `while (1) { pre; if (!cond) break; body }`,
/// which is always correct and merely less pretty. Declining is cheap; hoisting
/// wrongly produces a program that does not terminate.
pub(super) fn hoisting_the_header_is_safe(pre: &[Stmt], body: &[Stmt]) -> bool {
    fn expr_reads_memory(e: &Expr) -> bool {
        match e {
            Expr::Deref { .. } | Expr::Call { .. } => true,
            Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
                expr_reads_memory(lhs) || expr_reads_memory(rhs)
            }
            Expr::Select {
                cond,
                if_true,
                if_false,
                ..
            } => {
                expr_reads_memory(cond) || expr_reads_memory(if_true) || expr_reads_memory(if_false)
            }
            Expr::Un { src, .. } => expr_reads_memory(src),
            Expr::Cast { expr, .. } => expr_reads_memory(expr),
            _ => false,
        }
    }
    // Every register the body assigns, at any nesting depth. Over-approximating this
    // is the safe direction: a register listed here merely blocks a hoist.
    fn collect_assigned(stmts: &[Stmt], out: &mut std::collections::HashSet<String>) {
        for s in stmts {
            match s {
                Stmt::Assign {
                    dst: VReg::Phys(n), ..
                } => {
                    out.insert(n.clone());
                }
                Stmt::Call {
                    dst: Some(VReg::Phys(n)),
                    ..
                } => {
                    out.insert(n.clone());
                }
                Stmt::If {
                    then_body,
                    else_body,
                    ..
                } => {
                    collect_assigned(then_body, out);
                    if let Some(e) = else_body {
                        collect_assigned(e, out);
                    }
                }
                Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
                    collect_assigned(body, out)
                }
                Stmt::For {
                    init, step, body, ..
                } => {
                    collect_assigned(std::slice::from_ref(init.as_ref()), out);
                    collect_assigned(body, out);
                    collect_assigned(std::slice::from_ref(step.as_ref()), out);
                }
                Stmt::Switch { cases, default, .. } => {
                    for (_, b) in cases {
                        collect_assigned(b, out);
                    }
                    if let Some(b) = default {
                        collect_assigned(b, out);
                    }
                }
                _ => {}
            }
        }
    }
    fn collect_read(e: &Expr, out: &mut std::collections::HashSet<String>) {
        match e {
            Expr::Reg(VReg::Phys(n)) => {
                out.insert(n.clone());
            }
            Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
                collect_read(lhs, out);
                collect_read(rhs, out);
            }
            Expr::Select {
                cond,
                if_true,
                if_false,
                ..
            } => {
                collect_read(cond, out);
                collect_read(if_true, out);
                collect_read(if_false, out);
            }
            Expr::Un { src, .. } => collect_read(src, out),
            Expr::Cast { expr, .. } => collect_read(expr, out),
            Expr::Deref { addr, .. } => collect_read(addr, out),
            Expr::Call { target, args, .. } => {
                collect_read(target, out);
                for argument in args {
                    collect_read(argument, out);
                }
            }
            // `Lea` and `PdbFieldAddr` name their base/index as registers directly,
            // not as sub-expressions: an address computed from a register the body
            // bumps is loop-carried just as much as an arithmetic one.
            Expr::Lea { base, index, .. } | Expr::PdbFieldAddr { base, index, .. } => {
                for r in [base, index].into_iter().flatten() {
                    if let VReg::Phys(n) = r {
                        out.insert(n.clone());
                    }
                }
            }
            _ => {}
        }
    }

    let mut body_assigns = std::collections::HashSet::new();
    collect_assigned(body, &mut body_assigns);

    // Everything one iteration can change: the body's writes AND the preamble's
    // own, since the preamble runs once per iteration too.
    let mut carried = body_assigns.clone();
    collect_assigned(pre, &mut carried);

    // Registers the preamble has defined so far: reading one of those is reading a
    // value this chain produced, not a loop-carried one.
    let mut defined_here: std::collections::HashSet<String> = std::collections::HashSet::new();

    for s in pre {
        match s {
            Stmt::Assign { dst, src } => {
                if expr_reads_memory(src) {
                    return false;
                }
                // Self-referential update: a per-iteration side effect.
                if matches!(dst, VReg::Phys(n) if count_reg_uses_in_expr(src, &VReg::phys(n)) > 0) {
                    return false;
                }
                // Loop-invariance: nothing this statement reads may be assigned by
                // the body, unless the preamble itself produced it.
                let mut reads = std::collections::HashSet::new();
                collect_read(src, &mut reads);
                for r in &reads {
                    if carried.contains(r) && !defined_here.contains(r) {
                        return false;
                    }
                }
                if let VReg::Phys(n) = dst {
                    // A preamble that redefines a register the body also assigns is
                    // itself loop-carried work: hoisting it drops the update.
                    if body_assigns.contains(n) {
                        return false;
                    }
                    defined_here.insert(n.clone());
                }
            }
            Stmt::Nop | Stmt::Comment(_) => {}
            // A store, a call, a push — anything with an effect stays put.
            _ => return false,
        }
    }
    true
}

/// Lower every op in a block to stmts.
pub(super) fn lower_block(b: &LlirBlock, lower_scalar_float: bool) -> Vec<Stmt> {
    let mut out = Vec::with_capacity(b.instrs.len());
    for ins in &b.instrs {
        out.extend(lower_op(&ins.op, lower_scalar_float));
    }
    hoist_inline_flag_conds(out)
}

/// Peephole pass: for each control-flow condition or pure select condition whose
/// flag was assigned by a `Stmt::Assign { dst: flag, src: Expr::Cmp(..) }` earlier
/// in the same block (with no intervening read of the flag), fold the comparison
/// into the condition. Raw architectural flags can be removed immediately;
/// versioned predicates are retained for whole-function DCE because the same SSA
/// value may also be consumed in a successor block.
///
/// The structurer's `extract_cond_and_strip` already does this for
/// conditionals that end a block (recognised as `Region::IfThen` /
/// `Region::While` / `Region::IfThenElse`). But when CFG recovery fails
/// to recognise a structured pattern, the conditional jump is lowered as
/// a bare mid-block `Stmt::If { cond: Expr::Reg(flag), then_body: [Goto] }`
/// — and without this hoist the printer emits the opaque `if (%zf) goto L;`.
/// On real PE binaries (e.g. wkssvc!WsOpenCreateConnectionSpecifyImpersonation)
/// most conditionals fall through to this path and produce unreadable output.
pub(super) fn hoist_inline_flag_conds(stmts: Vec<Stmt>) -> Vec<Stmt> {
    fn take_reaching_cmp(out: &mut Vec<Stmt>, flag: &VReg) -> Option<Expr> {
        for i in (0..out.len()).rev() {
            match &out[i] {
                Stmt::Assign { dst, src } if dst == flag => {
                    if matches!(src, Expr::Cmp { .. }) {
                        let reads: usize = out[i + 1..]
                            .iter()
                            .map(|stmt| count_reg_uses_in_stmt(stmt, flag))
                            .sum();
                        if reads == 0 && moving_condition_to_end_is_safe(src, &out[i + 1..]) {
                            if matches!(flag, VReg::FlagValue { .. }) {
                                // A local scan cannot prove a versioned predicate
                                // dead: a successor block may read this exact SSA
                                // value (GCC's `cmp; jb; ...; cmova` does). Clone
                                // for the condition and let whole-function DCE
                                // remove the definition only when no read remains.
                                return Some(src.clone());
                            }
                            if let Stmt::Assign { src, .. } = out.remove(i) {
                                return Some(src);
                            }
                        }
                    }
                    return None;
                }
                other if count_reg_uses_in_stmt(other, flag) > 0 => return None,
                _ => {}
            }
        }
        None
    }

    let mut out: Vec<Stmt> = Vec::with_capacity(stmts.len());
    for stmt in stmts {
        let stmt = match stmt {
            Stmt::Assign {
                dst,
                src:
                    Expr::Select {
                        mut cond,
                        if_true,
                        if_false,
                        width,
                    },
            } => {
                let flag = match cond.as_ref() {
                    Expr::Reg(flag) => Some(flag.clone()),
                    _ => None,
                };
                if let Some(flag) = flag {
                    let arm_reads = count_reg_uses_in_expr(&if_true, &flag)
                        + count_reg_uses_in_expr(&if_false, &flag);
                    if arm_reads == 0 {
                        if let Some(cmp) = take_reaching_cmp(&mut out, &flag) {
                            cond = Box::new(cmp);
                        }
                    }
                }
                Stmt::Assign {
                    dst,
                    src: Expr::Select {
                        cond,
                        if_true,
                        if_false,
                        width,
                    },
                }
            }
            other => other,
        };
        // Match both `Stmt::If { cond: Reg(flag), .. }` (non-inverted
        // CondJump) and `Stmt::If { cond: Un(Not, Reg(flag)), .. }`
        // (inverted CondJump from JNE / JAE / ...).
        let (flag, was_inverted, then_body, else_body) = match stmt {
            Stmt::If {
                cond: Expr::Reg(flag),
                then_body,
                else_body,
            } => (Some(flag), false, then_body, else_body),
            Stmt::If {
                cond: Expr::Un { op: UnOp::Not, src },
                then_body,
                else_body,
            } => match *src {
                Expr::Reg(flag) => (Some(flag), true, then_body, else_body),
                other => {
                    out.push(Stmt::If {
                        cond: Expr::Un {
                            op: UnOp::Not,
                            src: Box::new(other),
                        },
                        then_body,
                        else_body,
                    });
                    continue;
                }
            },
            Stmt::If {
                cond:
                    Expr::Cmp {
                        op: CmpOp::Eq,
                        lhs,
                        rhs,
                    },
                then_body,
                else_body,
            } if matches!(rhs.as_ref(), Expr::Const(0)) => match *lhs {
                Expr::Reg(flag) => (Some(flag), true, then_body, else_body),
                other => {
                    out.push(Stmt::If {
                        cond: Expr::Cmp {
                            op: CmpOp::Eq,
                            lhs: Box::new(other),
                            rhs,
                        },
                        then_body,
                        else_body,
                    });
                    continue;
                }
            },
            stmt => {
                out.push(stmt);
                continue;
            }
        };

        let flag = flag.expect("Some by match above");
        let hoisted = take_reaching_cmp(&mut out, &flag);

        let cond_expr = match (hoisted, was_inverted) {
            (Some(expr), true) => negate_cmp_expr(expr),
            (Some(expr), false) => expr,
            (None, true) => Expr::Cmp {
                op: CmpOp::Eq,
                lhs: Box::new(Expr::Reg(flag)),
                rhs: Box::new(Expr::Const(0)),
            },
            (None, false) => Expr::Reg(flag),
        };
        out.push(Stmt::If {
            cond: cond_expr,
            then_body,
            else_body,
        });
    }
    out
}

/// If `expr` is an `Expr::Cmp { op, .. }`, return the Cmp with the inverted
/// CmpOp (Eq <-> Ne, Ult <-> Uge — but Uge isn't in CmpOp so we wrap, ...).
/// Anything else becomes `expr == 0`, a logical negation that stays boolean.
pub(crate) fn negate_cmp_expr(expr: Expr) -> Expr {
    if let Expr::Cmp { op, lhs, rhs } = expr {
        // Invert the comparison itself so the result stays a boolean `Cmp`, not a
        // wrapped `Un{Not}` — which would render as C's *bitwise* `~` and, applied
        // to a 0/1 boolean, is always true. There are no `>`/`>=` ops in `CmpOp`,
        // so negate `<`/`<=` by swapping the operands:
        //   !(a <  b) == (b <= a)      !(a <= b) == (b <  a)
        match op {
            CmpOp::Eq => Expr::Cmp {
                op: CmpOp::Ne,
                lhs,
                rhs,
            },
            CmpOp::Ne => Expr::Cmp {
                op: CmpOp::Eq,
                lhs,
                rhs,
            },
            CmpOp::Slt => Expr::Cmp {
                op: CmpOp::Sle,
                lhs: rhs,
                rhs: lhs,
            },
            CmpOp::Sle => Expr::Cmp {
                op: CmpOp::Slt,
                lhs: rhs,
                rhs: lhs,
            },
            CmpOp::Ult => Expr::Cmp {
                op: CmpOp::Ule,
                lhs: rhs,
                rhs: lhs,
            },
            CmpOp::Ule => Expr::Cmp {
                op: CmpOp::Ult,
                lhs: rhs,
                rhs: lhs,
            },
        }
    } else if let Expr::Un { op: UnOp::Not, src } = expr {
        // Double negation cancels.
        *src
    } else {
        Expr::Cmp {
            op: CmpOp::Eq,
            lhs: Box::new(expr),
            rhs: Box::new(Expr::Const(0)),
        }
    }
}

/// Given a block that ends a conditional, return the "cond" expression for
/// the generated If/While. We extract the final LLIR op — which the lifter
/// emits as a CondJump — and use its flag register as the boolean value.
/// Also strips that CondJump from the lowered-body stmts so we don't emit
/// both the structured `if` and a trailing goto.
///
/// When the flag was immediately preceded by `Stmt::Assign { dst: flag,
/// src: Expr::Cmp { .. } }`, we hoist that comparison into the condition
/// and drop the now-dead flag assignment so the printer outputs
/// `if (rax == 0)` rather than `if (%zf)`.
/// Drop the back-edge `goto` from the tail of a loop body.
///
/// A jump to the loop header at the END of the body is the back-edge, which the
/// `while` already expresses; anywhere else it is a `continue` and is left alone
/// (rendering it as a `goto` is ugly but correct, and inventing a `continue`
/// statement is a separate change). Recurses into the tail of trailing branches,
/// because a rotated loop whose body ends in an `if` puts the jump inside it.
pub(super) fn strip_back_edge(body: &mut Vec<Stmt>, header_va: u64) {
    match body.last_mut() {
        Some(Stmt::Goto { target }) if *target == header_va => {
            body.pop();
        }
        Some(Stmt::If {
            then_body,
            else_body,
            ..
        }) => {
            strip_back_edge(then_body, header_va);
            if let Some(e) = else_body {
                strip_back_edge(e, header_va);
            }
        }
        _ => {}
    }
}

/// True when the header's conditional branch, if TAKEN, leaves the loop.
///
/// A `while` states the condition under which the loop CONTINUES, but the header
/// carries the condition under which its branch is taken. Those coincide only when
/// the taken edge re-enters the body. gcc -O0 lays loops out that way; clang -O0
/// and gcc -O2 rotate them, so the taken edge is the exit and the condition has to
/// be negated. Returns false when the shape cannot be established, which keeps the
/// previous behaviour for anything unrecognised.
pub(super) fn exit_is_taken_branch(lf: &LlirFunction, header: usize, exit: Option<usize>) -> bool {
    let Some(exit) = exit else { return false };
    let Some(exit_va) = lf.blocks.get(exit).map(|b| b.start_va) else {
        return false;
    };
    matches!(
        lf.blocks.get(header).and_then(|b| b.instrs.last()),
        Some(LlirInstr { op: Op::CondJump { target, .. }, .. }) if *target == exit_va
    )
}

pub(super) fn extract_cond_and_strip<'a>(
    block: &LlirBlock,
    mut stmts: Vec<Stmt>,
) -> (Expr, Vec<Stmt>) {
    if let Some(LlirInstr {
        op: Op::CondJump { cond, inverted, .. },
        ..
    }) = block.instrs.last()
    {
        let inverted = *inverted;
        // Pop trailing `if (cond) goto ...` we just synthesised. If the
        // inline-hoist pass has already folded a Cmp into that If's
        // condition (because CFG recovery didn't yet recognise this
        // block as structured), use that hoisted condition directly —
        // the trailing-Goto body has no semantics for the structurer
        // since we're rebuilding the whole If anyway.
        if let Some(Stmt::If { cond, .. }) = stmts.last() {
            // For a non-trivial cond (Cmp / negated form) the hoist
            // already accounted for `inverted`; just adopt it.
            if !matches!(cond, Expr::Reg(_))
                && !matches!(
                    cond,
                    Expr::Un {
                        op: UnOp::Not,
                        src: _
                    }
                )
            {
                let cond_expr = cond.clone();
                stmts.pop();
                return (cond_expr, stmts);
            }
            // If the cond is still `!flag` (no Cmp was available to fold),
            // keep the negation and fall through to the lookup.
            if let Expr::Un { op: UnOp::Not, src } = cond {
                if matches!(src.as_ref(), Expr::Cmp { .. }) {
                    let cond_expr = cond.clone();
                    stmts.pop();
                    return (cond_expr, stmts);
                }
            }
            stmts.pop();
        }

        // Try to hoist the Cmp that produced `cond`. We scan from the end of
        // the body for the most recent assignment to that flag; if its RHS
        // is an Expr::Cmp, we pull it out and use it as the condition.
        for i in (0..stmts.len()).rev() {
            if let Stmt::Assign { dst, src } = &stmts[i] {
                if dst == cond {
                    if matches!(src, Expr::Cmp { .. }) {
                        // Ensure the flag isn't also read elsewhere in the
                        // remaining body. If it is, leave everything alone
                        // to avoid losing semantics.
                        let usages = stmts
                            .iter()
                            .enumerate()
                            .filter(|(j, _)| *j != i)
                            .map(|(_, s)| count_reg_uses_in_stmt(s, cond))
                            .sum::<usize>();
                        if usages == 0 && moving_condition_to_end_is_safe(src, &stmts[i + 1..]) {
                            if let Stmt::Assign { src, .. } = stmts.remove(i) {
                                let cond_expr = if inverted { negate_cmp_expr(src) } else { src };
                                return (cond_expr, stmts);
                            }
                        }
                    }
                    break;
                }
            }
        }
        let fallback = if inverted {
            Expr::Cmp {
                op: CmpOp::Eq,
                lhs: Box::new(Expr::Reg(cond.clone())),
                rhs: Box::new(Expr::Const(0)),
            }
        } else {
            Expr::Reg(cond.clone())
        };
        return (fallback, stmts);
    }
    // Fallback — no CondJump, synthesise a generic truthy condition.
    (Expr::Const(1), stmts)
}

fn count_reg_uses_in_expr(e: &Expr, target: &VReg) -> usize {
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
        Expr::Deref { addr, .. } => count_reg_uses_in_expr(addr, target),
        Expr::Call {
            target: call_target,
            args,
            ..
        } => {
            count_reg_uses_in_expr(call_target, target)
                + args
                    .iter()
                    .map(|argument| count_reg_uses_in_expr(argument, target))
                    .sum::<usize>()
        }
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            count_reg_uses_in_expr(lhs, target) + count_reg_uses_in_expr(rhs, target)
        }
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => {
            count_reg_uses_in_expr(cond, target)
                + count_reg_uses_in_expr(if_true, target)
                + count_reg_uses_in_expr(if_false, target)
        }
        Expr::Un { src, .. } => count_reg_uses_in_expr(src, target),
        Expr::Cast { expr, .. } | Expr::NumericConvert { expr, .. } => {
            count_reg_uses_in_expr(expr, target)
        }
        Expr::FunctionTableEntry { index, .. } => count_reg_uses_in_expr(index, target),
        Expr::WideArithmetic { args, .. } => args
            .iter()
            .map(|argument| count_reg_uses_in_expr(argument, target))
            .sum(),
    }
}

/// Whether evaluating `condition` after `following` observes the same state as
/// evaluating it before those statements.
///
/// A machine predicate is a value snapshot.  Folding its defining comparison
/// into a later C `if`/`while` condition is only legal when no intervening
/// statement changes a register or memory read by that comparison.  This is the
/// same ordering distinction Ghidra, angr, and Kuna preserve explicitly for
/// `cmp rax, rcx; mov rdx, rcx; jb ...`.
fn moving_condition_to_end_is_safe(condition: &Expr, following: &[Stmt]) -> bool {
    !following
        .iter()
        .any(|stmt| stmt_may_change_condition_input(stmt, condition))
}

fn expr_reads_memory(expr: &Expr) -> bool {
    match expr {
        Expr::Deref { .. } | Expr::FunctionTableEntry { .. } | Expr::Call { .. } => true,
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            expr_reads_memory(lhs) || expr_reads_memory(rhs)
        }
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => expr_reads_memory(cond) || expr_reads_memory(if_true) || expr_reads_memory(if_false),
        Expr::Un { src, .. }
        | Expr::Cast { expr: src, .. }
        | Expr::NumericConvert { expr: src, .. } => expr_reads_memory(src),
        Expr::WideArithmetic { args, .. } => args.iter().any(expr_reads_memory),
        Expr::Const(_)
        | Expr::FloatConst { .. }
        | Expr::Addr(_)
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::Unknown(_)
        | Expr::Reg(_)
        | Expr::StackAddr { .. }
        | Expr::Lea { .. }
        | Expr::PdbFieldAddr { .. } => false,
    }
}

fn stmt_may_change_condition_input(stmt: &Stmt, condition: &Expr) -> bool {
    let writes_read_register = |dst: &VReg| count_reg_uses_in_expr(condition, dst) > 0;
    match stmt {
        Stmt::Assign { dst, .. } => writes_read_register(dst),
        Stmt::Store { addr, .. } => {
            let promoted_local_write = matches!(addr,
                Expr::Reg(VReg::Phys(name))
                    if (name.starts_with("local_") || name.starts_with("stack_"))
                        && count_reg_uses_in_expr(condition, &VReg::phys(name)) > 0
            );
            promoted_local_write || expr_reads_memory(condition)
        }
        // Calls may change memory and caller-saved registers whose implicit
        // clobbers are not all represented by the structured Call statement.
        Stmt::Call { .. } | Stmt::Push { .. } | Stmt::Pop { .. } | Stmt::Unknown(_) => true,
        Stmt::If {
            then_body,
            else_body,
            ..
        } => {
            then_body
                .iter()
                .any(|stmt| stmt_may_change_condition_input(stmt, condition))
                || else_body.as_ref().is_some_and(|body| {
                    body.iter()
                        .any(|stmt| stmt_may_change_condition_input(stmt, condition))
                })
        }
        Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => body
            .iter()
            .any(|stmt| stmt_may_change_condition_input(stmt, condition)),
        Stmt::For {
            init, step, body, ..
        } => {
            stmt_may_change_condition_input(init, condition)
                || body
                    .iter()
                    .any(|stmt| stmt_may_change_condition_input(stmt, condition))
                || stmt_may_change_condition_input(step, condition)
        }
        Stmt::Switch { cases, default, .. } => {
            cases.iter().any(|(_, body)| {
                body.iter()
                    .any(|stmt| stmt_may_change_condition_input(stmt, condition))
            }) || default.as_ref().is_some_and(|body| {
                body.iter()
                    .any(|stmt| stmt_may_change_condition_input(stmt, condition))
            })
        }
        Stmt::IndirectGoto { .. }
        | Stmt::Return { .. }
        | Stmt::Goto { .. }
        | Stmt::Label(_)
        | Stmt::Break
        | Stmt::Nop
        | Stmt::Comment(_)
        | Stmt::Throw { .. } => false,
        Stmt::TryCatch { try_body, catches } => {
            try_body
                .iter()
                .any(|stmt| stmt_may_change_condition_input(stmt, condition))
                || catches.iter().any(|catch| {
                    catch
                        .body
                        .iter()
                        .any(|stmt| stmt_may_change_condition_input(stmt, condition))
                })
        }
    }
}

/// Whether evaluating `expr` speculatively is side-effect and fault free.
///
/// A one-armed select evaluates its initializer even when the other arm is
/// selected. Register arithmetic is safe to evaluate early; memory reads and
/// opaque expressions are not.
fn can_eagerly_evaluate(expr: &Expr) -> bool {
    match expr {
        Expr::Deref { .. }
        | Expr::FunctionTableEntry { .. }
        | Expr::Call { .. }
        | Expr::Unknown(_) => false,
        Expr::Bin { op: BinOp::Div, .. } => false,
        Expr::WideArithmetic {
            op:
                WideArithmetic::UnsignedDivQuotient
                | WideArithmetic::UnsignedDivRemainder
                | WideArithmetic::SignedDivQuotient
                | WideArithmetic::SignedDivRemainder,
            ..
        } => false,
        Expr::WideArithmetic { args, .. } => args.iter().all(can_eagerly_evaluate),
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            can_eagerly_evaluate(lhs) && can_eagerly_evaluate(rhs)
        }
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => {
            can_eagerly_evaluate(cond)
                && can_eagerly_evaluate(if_true)
                && can_eagerly_evaluate(if_false)
        }
        Expr::Un { src, .. } => can_eagerly_evaluate(src),
        Expr::Cast { expr, .. } | Expr::NumericConvert { expr, .. } => can_eagerly_evaluate(expr),
        Expr::Reg(_)
        | Expr::StackAddr { .. }
        | Expr::Const(_)
        | Expr::FloatConst { .. }
        | Expr::Addr(_)
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::Lea { .. }
        | Expr::PdbFieldAddr { .. } => true,
    }
}

/// Choose a semantics-preserving one-armed rendering for a pure select.
///
/// The initializer executes before the condition in the rendered form, so the
/// condition must not read `dst`. The conditional arm also executes after the
/// initializer has overwritten `dst`, so that arm must not read the old value.
/// The initializer itself may read `dst`: C evaluates its RHS before the write.
/// If neither orientation is safe, callers retain the expression-level ternary.
pub(super) fn one_armed_select<'a>(
    dst: &VReg,
    src: &'a Expr,
) -> Option<(&'a Expr, &'a Expr, &'a Expr, bool)> {
    let Expr::Select {
        cond,
        if_true,
        if_false,
        ..
    } = src
    else {
        return None;
    };
    if count_reg_uses_in_expr(cond, dst) != 0 {
        return None;
    }
    if can_eagerly_evaluate(if_false) && count_reg_uses_in_expr(if_true, dst) == 0 {
        return Some((cond, if_false, if_true, false));
    }
    if can_eagerly_evaluate(if_true) && count_reg_uses_in_expr(if_false, dst) == 0 {
        return Some((cond, if_true, if_false, true));
    }
    None
}

fn count_reg_uses_in_stmt(s: &Stmt, target: &VReg) -> usize {
    match s {
        Stmt::Assign { src, .. } => count_reg_uses_in_expr(src, target),
        Stmt::Store { addr, src, .. } => {
            count_reg_uses_in_expr(addr, target) + count_reg_uses_in_expr(src, target)
        }
        Stmt::Call {
            target: t, args, ..
        } => {
            count_reg_uses_in_expr(t, target)
                + args
                    .iter()
                    .map(|a| count_reg_uses_in_expr(a, target))
                    .sum::<usize>()
        }
        Stmt::If { cond, .. } | Stmt::While { cond, .. } | Stmt::DoWhile { cond, .. } => {
            count_reg_uses_in_expr(cond, target)
        }
        Stmt::For {
            init, cond, step, ..
        } => {
            count_reg_uses_in_stmt(init, target)
                + count_reg_uses_in_expr(cond, target)
                + count_reg_uses_in_stmt(step, target)
        }
        Stmt::Return { value } => value
            .as_ref()
            .map(|e| count_reg_uses_in_expr(e, target))
            .unwrap_or(0),
        Stmt::Push { value } => count_reg_uses_in_expr(value, target),
        // It reads the value it jumps through — counting it as zero would let
        // DCE delete the index computation the dispatch depends on.
        Stmt::IndirectGoto { target: t } => count_reg_uses_in_expr(t, target),
        Stmt::Pop { .. }
        | Stmt::Goto { .. }
        | Stmt::Label(_)
        | Stmt::Break
        | Stmt::Nop
        | Stmt::Unknown(_)
        | Stmt::Comment(_) => 0,
        Stmt::Switch { discriminant, .. } => count_reg_uses_in_expr(discriminant, target),
        Stmt::Throw { value } => count_reg_uses_in_expr(value, target),
        Stmt::TryCatch { try_body, catches } => {
            try_body
                .iter()
                .map(|stmt| count_reg_uses_in_stmt(stmt, target))
                .sum::<usize>()
                + catches
                    .iter()
                    .flat_map(|catch| &catch.body)
                    .map(|stmt| count_reg_uses_in_stmt(stmt, target))
                    .sum::<usize>()
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::ir::ast::{Expr, Stmt};
    use crate::ir::types::VReg;

    /// The old rule was UNSOUND, and this is the counterexample.
    ///
    /// `t = i + 1` reads no memory and is not a self-reference, so the previous
    /// preamble-only check hoisted it above the loop. But the body assigns `i`, so
    /// `t` is loop-carried: hoisted, the condition `t < n` never changes and the
    /// loop does not terminate. Rejecting only memory reads and self-references was
    /// necessary and nowhere near sufficient — invariance is a def-use property of
    /// the preamble AND the body, and cannot be decided from the preamble alone.
    #[test]
    fn a_preamble_reading_a_body_modified_register_is_not_hoistable() {
        let pre = vec![Stmt::Assign {
            dst: VReg::phys("t"),
            src: Expr::Bin {
                op: crate::ir::types::BinOp::Add,
                lhs: Box::new(Expr::Reg(VReg::phys("i"))),
                rhs: Box::new(Expr::Const(1)),
            },
        }];
        let body = vec![Stmt::Assign {
            dst: VReg::phys("i"),
            src: Expr::Bin {
                op: crate::ir::types::BinOp::Add,
                lhs: Box::new(Expr::Reg(VReg::phys("i"))),
                rhs: Box::new(Expr::Const(1)),
            },
        }];
        assert!(
            !super::hoisting_the_header_is_safe(&pre, &body),
            "hoisting `t = i + 1` out of a loop whose body bumps `i` freezes the \
             condition and the loop never ends"
        );
        // The same preamble IS hoistable when the body leaves `i` alone.
        let inert = vec![Stmt::Assign {
            dst: VReg::phys("s"),
            src: Expr::Const(0),
        }];
        assert!(
            super::hoisting_the_header_is_safe(&pre, &inert),
            "a genuinely invariant preamble must still hoist, or every rotated loop \
             regresses to `while (1) {{ ... }}`"
        );
    }

    /// Nesting must not hide the assignment. A body that bumps `i` inside an `if`
    /// or an inner loop is still a body that bumps `i`.
    #[test]
    fn a_nested_body_assignment_still_blocks_the_hoist() {
        let bump = Stmt::Assign {
            dst: VReg::phys("i"),
            src: Expr::Bin {
                op: crate::ir::types::BinOp::Add,
                lhs: Box::new(Expr::Reg(VReg::phys("i"))),
                rhs: Box::new(Expr::Const(1)),
            },
        };
        let pre = vec![Stmt::Assign {
            dst: VReg::phys("t"),
            src: Expr::Reg(VReg::phys("i")),
        }];
        for body in [
            vec![Stmt::If {
                cond: Expr::Const(1),
                then_body: vec![bump.clone()],
                else_body: None,
            }],
            vec![Stmt::If {
                cond: Expr::Const(1),
                then_body: vec![],
                else_body: Some(vec![bump.clone()]),
            }],
            vec![Stmt::While {
                cond: Expr::Const(1),
                body: vec![bump.clone()],
            }],
        ] {
            assert!(
                !super::hoisting_the_header_is_safe(&pre, &body),
                "a nested assignment to `i` must block the hoist: {body:?}"
            );
        }
    }

    /// The preamble is part of the loop, so a register IT assigns is loop-carried
    /// too. `newton_isqrt` at `gcc -O2` is the measured case: once value-number
    /// coalescing removed the out-of-SSA copies that had been hiding the shape,
    /// the whole Newton step sat in the header reading `estimate` and then
    /// rewriting it, with only the iteration counter left in the body. Hoisting it
    /// ran the recurrence exactly once and the function returned the first
    /// estimate.
    #[test]
    fn a_preamble_reading_a_register_it_later_assigns_is_not_hoistable() {
        let pre = vec![
            Stmt::Assign {
                dst: VReg::phys("cursor"),
                src: Expr::Reg(VReg::phys("estimate")),
            },
            Stmt::Assign {
                dst: VReg::phys("estimate"),
                src: Expr::Bin {
                    op: crate::ir::types::BinOp::Add,
                    lhs: Box::new(Expr::Reg(VReg::phys("cursor"))),
                    rhs: Box::new(Expr::Const(1)),
                },
            },
        ];
        // The body only decrements the trip counter — it never touches `estimate`,
        // which is exactly why checking the body alone said "safe".
        let body = vec![Stmt::Assign {
            dst: VReg::phys("counter"),
            src: Expr::Bin {
                op: crate::ir::types::BinOp::Sub,
                lhs: Box::new(Expr::Reg(VReg::phys("counter"))),
                rhs: Box::new(Expr::Const(1)),
            },
        }];
        assert!(
            !super::hoisting_the_header_is_safe(&pre, &body),
            "`cursor = estimate` reads the value the next preamble statement \
             produces, so the chain is loop-carried through the header itself"
        );
        // Reading a register the preamble assigns EARLIER is still fine: that is
        // this chain's own value, not the previous iteration's.
        let forward = vec![
            Stmt::Assign {
                dst: VReg::phys("scratch"),
                src: Expr::Const(4),
            },
            Stmt::Assign {
                dst: VReg::phys("limit"),
                src: Expr::Reg(VReg::phys("scratch")),
            },
        ];
        assert!(
            super::hoisting_the_header_is_safe(&forward, &body),
            "a forward-only preamble chain is invariant and must still hoist"
        );
    }

    #[test]
    fn an_expression_call_in_a_loop_header_is_not_hoistable() {
        let pre = vec![Stmt::Assign {
            dst: VReg::phys("next"),
            src: Expr::Call {
                target: Box::new(Expr::Named {
                    va: 0x2000,
                    name: "advance".into(),
                }),
                args: vec![Expr::Reg(VReg::phys("cursor"))],
                call_spec: None,
                result_width: Some(8),
            },
        }];

        assert!(
            !super::hoisting_the_header_is_safe(&pre, &[]),
            "hoisting a value-producing call out of a loop changes its observable call count"
        );
    }
}
