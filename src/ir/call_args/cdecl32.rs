//! Recover 32-bit cdecl call arguments from the outgoing `esp` area, and keep
//! the stack pointer honest once that setup is folded into the call.
//!
//! A cdecl caller passes everything in memory, so the register-ABI
//! reconstruction in the parent module sees no arguments at all. The single
//! entry point, [`fold_one_cdecl32_call`], is one dispatch arm of `fold_one_call`;
//! everything else here exists to serve it — the post-call cleanup proof that
//! bounds how much stack traffic belongs to the call, and the `esp` rebasing that
//! keeps surviving displacements and the epilogue balanced after the pushes are
//! removed.

use crate::ir::ast::{Expr, Stmt};
use crate::ir::types::{BinOp, VReg};

use super::{is_pure_arg_normalisation, ssa_base, stack_pointer_sub_width};

/// Recover 32-bit cdecl arguments from stores into the outgoing ESP area.
///
/// A typical caller emits `mov [esp], a0; mov [esp+4], a1; call f`. These are
/// not register assignments, so the register-ABI reconstruction above sees no
/// arguments at all. Walk backward only to the nearest call/stack adjustment or
/// control-flow boundary, retain the latest store at each non-negative offset,
/// and accept an exactly contiguous layout beginning at `[esp]`.
pub(super) fn fold_one_cdecl32_call(body: &mut Vec<Stmt>, call_idx: usize) {
    let mut by_offset: std::collections::BTreeMap<i64, (usize, Expr, u8)> =
        std::collections::BTreeMap::new();
    let mut pushed_args = Vec::new();
    let mut used = Vec::new();
    // How many bytes the CALLER pops after the call, if it does. cdecl makes the
    // caller clean up its own outgoing area, so this is an independent proof of
    // how much of the preceding stack traffic belongs to this call — and it is
    // what makes it safe to step over a statement sitting between the last push
    // and the call. See `proven_outgoing_cleanup`.
    let cleanup = proven_outgoing_cleanup(body, call_idx);
    let mut skipped_before_setup = 0usize;
    let mut cursor = call_idx;
    while cursor > 0 {
        let i = cursor - 1;
        match &body[i] {
            Stmt::Call { .. }
            | Stmt::Label(_)
            | Stmt::Goto { .. }
            | Stmt::IndirectGoto { .. }
            | Stmt::Return { .. }
            | Stmt::If { .. }
            | Stmt::While { .. }
            | Stmt::DoWhile { .. }
            | Stmt::For { .. }
            | Stmt::Switch { .. }
            | Stmt::Push { .. }
            | Stmt::Pop { .. } => break,
            Stmt::Assign {
                dst: VReg::Phys(frame),
                src: Expr::Reg(VReg::Phys(stack)),
            } if matches!(frame.as_str(), "ebp" | "rbp")
                && matches!(stack.as_str(), "esp" | "rsp") =>
            {
                break;
            }
            Stmt::Assign {
                dst: VReg::Phys(name),
                ..
            } if name == "esp" || name == "rsp" => break,
            Stmt::Store {
                addr:
                    Expr::Lea {
                        base: Some(VReg::Phys(base)),
                        index: None,
                        disp,
                        ..
                    },
                src,
                size,
            } if matches!(base.as_str(), "esp" | "rsp") && *disp >= 0 && *size > 0 => {
                // Iced lowers `push X` to `sp -= width; [sp] = X`. Walking
                // backward encounters cdecl's right-to-left pushes in source
                // argument order: arg0, arg1, ... . Absorb both halves of each
                // pair, but stop at an unrelated stack adjustment (alignment,
                // local allocation, or cleanup) rather than guessing across it.
                if *disp == 0
                    && i > 0
                    && stack_pointer_sub_width(&body[i - 1]) == Some(i64::from(*size))
                {
                    pushed_args.push(src.clone());
                    used.extend([i, i - 1]);
                    cursor = i - 1;
                    continue;
                }
                if pushed_args.is_empty() {
                    by_offset
                        .entry(*disp)
                        .or_insert_with(|| (i, src.clone(), *size));
                } else {
                    break;
                }
            }
            Stmt::Comment(_) | Stmt::Nop => {}
            // 32-bit PIC puts `mov %eax,%ebx` (the materialised
            // `_GLOBAL_OFFSET_TABLE_`) between the last push and the call, which
            // ended the scan before it saw a single argument: `forward_sum6` and
            // `tailcall_to_sum4` came out as zero-argument calls at -O0. Step
            // over a bounded run of pure value statements, but only when the
            // caller's own post-call cleanup proves an outgoing area exists —
            // a callee-saved prologue is balanced by POPS in the epilogue, never
            // by an `add $N,%esp` after a call, so that shape still stops here.
            statement
                if pushed_args.is_empty()
                    && by_offset.is_empty()
                    && cleanup.is_some()
                    && skipped_before_setup < 4
                    && is_pure_register_value(statement) =>
            {
                skipped_before_setup += 1;
            }
            _ if pushed_args.is_empty() && by_offset.is_empty() => {
                // Outgoing cdecl setup must reach the call directly (apart
                // from comments/no-ops).  Scanning backward across an ordinary
                // value statement can otherwise reach a frame-pointer-omitted
                // callee-save prologue and consume `push edi/esi/ebx` as three
                // arguments to a later zero-argument call.  Besides fabricating
                // a prototype, removing those pushes loses the stack delta that
                // identifies this function's own incoming parameters.
                break;
            }
            _ => {}
        }
        cursor = i;
    }

    let args = if pushed_args.is_empty() {
        let mut args = Vec::new();
        let mut expected_offset = 0i64;
        for (offset, (stmt_idx, value, size)) in by_offset {
            if offset != expected_offset {
                break;
            }
            args.push(value);
            used.push(stmt_idx);
            let slot_size = i64::from(size).max(4);
            expected_offset = expected_offset.saturating_add((slot_size + 3) & !3);
        }
        args
    } else {
        pushed_args
    };
    if args.is_empty() {
        return;
    }

    // An argument that reads `esp` names a different slot once it is hoisted to
    // the call, where `esp` sits below its own pushes. Rather than guess the
    // per-argument offset, leave the whole call alone: an unfolded call renders
    // the pushes verbatim, while a folded one with mis-based arguments is a
    // confidently wrong prototype.
    if args.iter().any(mentions_stack_pointer) {
        return;
    }
    // Never fold more stack traffic than the caller proved it owns.
    let pushed_bytes: i64 = used
        .iter()
        .filter_map(|&index| stack_pointer_sub_width(&body[index]))
        .sum();
    if let Some(cleanup) = cleanup {
        if pushed_bytes > cleanup {
            return;
        }
    } else if skipped_before_setup > 0 {
        return;
    }

    if let Stmt::Call {
        args: call_args, ..
    } = &mut body[call_idx]
    {
        *call_args = args;
    }
    used.sort_unstable_by(|left, right| right.cmp(left));
    let removed_pushes: Vec<(usize, i64)> = used
        .iter()
        .filter_map(|&index| stack_pointer_sub_width(&body[index]).map(|width| (index, width)))
        .collect();
    let folded_bytes: i64 = removed_pushes.iter().map(|(_, width)| *width).sum();
    rebase_esp_after_removed_pushes(body, call_idx, &removed_pushes);
    let removed_before_call = used.iter().filter(|&&index| index < call_idx).count();
    for stmt_idx in used {
        body.remove(stmt_idx);
    }
    if folded_bytes > 0 {
        body.insert(
            call_idx - removed_before_call,
            folded_push_adjustment(folded_bytes),
        );
    }
}

/// Keep the stack pointer honest after `push` setup statements are folded away.
///
/// Absorbing `esp -= 4; [esp] = X` into the call's argument list deletes the
/// decrements, and everything downstream reads `esp` as if they never happened.
/// Two things then go wrong, and both are silent:
///
/// * an argument the caller loads THROUGH `esp` moves under its own pushes. gcc
///   -O2 forwards six stacked parameters with six identical `push 0x2c(%esp)`
///   instructions — identical precisely because `esp` drops four bytes between
///   each — so with the decrements gone all six read the same slot and
///   `forward_sum6(a0..a5)` was recovered as `sum_arg6(a5, a5, a5, a5, a5, a5)`;
/// * the epilogue's own `esp` arithmetic is off by the folded bytes, which moves
///   every frame slot named after the call.
///
/// So: shift each surviving `esp`-relative displacement in the folded span by
/// the decrements removed BEFORE it, and reinstate the total as one adjustment
/// immediately before the call. `stack_locals` then recovers exactly the slots
/// the machine addressed.
fn rebase_esp_after_removed_pushes(
    body: &mut [Stmt],
    call_idx: usize,
    removed_pushes: &[(usize, i64)],
) {
    if removed_pushes.is_empty() {
        return;
    }
    let first = removed_pushes
        .iter()
        .map(|(index, _)| *index)
        .min()
        .unwrap_or(call_idx);
    let removed: std::collections::HashSet<usize> =
        removed_pushes.iter().map(|(index, _)| *index).collect();
    let mut shifted = 0i64;
    for index in first..call_idx {
        if let Some(&(_, width)) = removed_pushes.iter().find(|(at, _)| *at == index) {
            shifted += width;
            continue;
        }
        if removed.contains(&index) || shifted == 0 {
            continue;
        }
        shift_stack_pointer_displacements(&mut body[index], shifted);
    }
}

/// The net stack decrement the folded pushes performed, as one statement.
///
/// The call site is where the machine's `esp` sits lowest. Reinstating the total
/// immediately before the call keeps the post-call `add $N,%esp` cleanup and the
/// epilogue balanced; without it every frame slot named after the call moves by
/// the folded bytes.
fn folded_push_adjustment(total: i64) -> Stmt {
    Stmt::Assign {
        dst: VReg::phys("esp"),
        src: Expr::Bin {
            op: BinOp::Sub,
            lhs: Box::new(Expr::Reg(VReg::phys("esp"))),
            rhs: Box::new(Expr::Const(total)),
        },
    }
}

/// True when `expr` reads the stack pointer, so hoisting it to the call site
/// would change which slot it names.
fn mentions_stack_pointer(expr: &Expr) -> bool {
    let mut found = false;
    visit_expr(expr, &mut |node| {
        let named = match node {
            Expr::Reg(VReg::Phys(name)) => Some(name),
            Expr::Lea {
                base: Some(VReg::Phys(name)),
                ..
            } => Some(name),
            _ => None,
        };
        if named.is_some_and(|name| matches!(ssa_base(name), "esp" | "rsp")) {
            found = true;
        }
    });
    found
}

fn visit_expr(expr: &Expr, f: &mut impl FnMut(&Expr)) {
    f(expr);
    match expr {
        Expr::Deref { addr, .. } => visit_expr(addr, f),
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            visit_expr(lhs, f);
            visit_expr(rhs, f);
        }
        Expr::Un { src, .. } | Expr::Cast { expr: src, .. } => visit_expr(src, f),
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => {
            visit_expr(cond, f);
            visit_expr(if_true, f);
            visit_expr(if_false, f);
        }
        Expr::WideArithmetic { args, .. } => args.iter().for_each(|arg| visit_expr(arg, f)),
        Expr::FunctionTableEntry { index, .. } => visit_expr(index, f),
        _ => {}
    }
}

fn visit_expr_mut(expr: &mut Expr, f: &mut impl FnMut(&mut Expr)) {
    f(expr);
    match expr {
        Expr::Deref { addr, .. } => visit_expr_mut(addr, f),
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            visit_expr_mut(lhs, f);
            visit_expr_mut(rhs, f);
        }
        Expr::Un { src, .. } | Expr::Cast { expr: src, .. } => visit_expr_mut(src, f),
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => {
            visit_expr_mut(cond, f);
            visit_expr_mut(if_true, f);
            visit_expr_mut(if_false, f);
        }
        Expr::WideArithmetic { args, .. } => args.iter_mut().for_each(|arg| visit_expr_mut(arg, f)),
        Expr::FunctionTableEntry { index, .. } => visit_expr_mut(index, f),
        _ => {}
    }
}

/// Subtract `bytes` from every `esp`/`rsp`-relative displacement in `stmt`.
fn shift_stack_pointer_displacements(stmt: &mut Stmt, bytes: i64) {
    match stmt {
        Stmt::Assign { src, .. } => shift_stack_pointer_displacements_in_expr(src, bytes),
        Stmt::Store { addr, src, .. } => {
            shift_stack_pointer_displacements_in_expr(addr, bytes);
            shift_stack_pointer_displacements_in_expr(src, bytes);
        }
        Stmt::Push { value } => shift_stack_pointer_displacements_in_expr(value, bytes),
        Stmt::Return { value: Some(value) } => {
            shift_stack_pointer_displacements_in_expr(value, bytes)
        }
        _ => {}
    }
}

fn shift_stack_pointer_displacements_in_expr(expr: &mut Expr, bytes: i64) {
    visit_expr_mut(expr, &mut |node| {
        if let Expr::Lea {
            base: Some(VReg::Phys(base)),
            index: None,
            disp,
            ..
        } = node
        {
            if matches!(ssa_base(base), "esp" | "rsp") {
                *disp -= bytes;
            }
        }
    });
}

/// The bytes the caller pops immediately after `call_idx`, if it demonstrably does.
///
/// cdecl leaves the outgoing argument area for the CALLER to release, so an
/// `add $N,%esp` after the call is an independent statement of how large that
/// area was. Flag and temporary assignments the lifter emits for the arithmetic
/// itself are stepped over; anything else ends the search, because a cleanup
/// that is not adjacent proves nothing about this call.
fn proven_outgoing_cleanup(body: &[Stmt], call_idx: usize) -> Option<i64> {
    for statement in body.iter().skip(call_idx + 1).take(16) {
        if let Stmt::Assign {
            dst: VReg::Phys(dst),
            src:
                Expr::Bin {
                    op: BinOp::Add,
                    lhs,
                    rhs,
                },
        } = statement
        {
            if matches!(ssa_base(dst), "esp" | "rsp")
                && matches!(lhs.as_ref(), Expr::Reg(VReg::Phys(base)) if ssa_base(base) == ssa_base(dst))
            {
                return match rhs.as_ref() {
                    Expr::Const(bytes) if *bytes > 0 => Some(*bytes),
                    _ => None,
                };
            }
        }
        match statement {
            Stmt::Comment(_) | Stmt::Nop => {}
            Stmt::Assign { dst, src } if is_pure_arg_normalisation(src) => match dst {
                VReg::Temp(_) | VReg::Flag(_) | VReg::FlagValue { .. } => {}
                VReg::Phys(_) => return None,
            },
            _ => return None,
        }
    }
    None
}

/// A statement that only computes a value into a register, touching neither
/// memory nor the stack pointer.
fn is_pure_register_value(statement: &Stmt) -> bool {
    let Stmt::Assign { dst, src } = statement else {
        return false;
    };
    if let VReg::Phys(name) = dst {
        if matches!(ssa_base(name), "esp" | "rsp") {
            return false;
        }
    }
    is_pure_arg_normalisation(src) && !mentions_stack_pointer(src)
}
