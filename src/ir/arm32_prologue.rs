//! ARM32 prologue / epilogue recognition.
//!
//! AAPCS frame setup and teardown are machine bookkeeping, not source-level
//! arithmetic on a C local named `sp`.  This pass is intentionally
//! transactional: it collapses a frame only when its saved-register widths,
//! local allocation, and every lexical return path balance exactly.

use crate::ir::ast::{Expr, Function, Stmt};
use crate::ir::types::{BinOp, VReg};

#[derive(Debug)]
struct SavedRegister {
    name: String,
    slot: StackLocation,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct StackLocation {
    object: VReg,
    offset: i64,
}

#[derive(Debug)]
struct SaveGroup {
    width: i64,
    registers: Vec<SavedRegister>,
}

#[derive(Debug)]
struct Arm32Frame {
    start: usize,
    end: usize,
    local_width: i64,
    save_groups: Vec<SaveGroup>,
}

impl Arm32Frame {
    fn total_width(&self) -> i64 {
        self.local_width
            + self
                .save_groups
                .iter()
                .map(|group| group.width)
                .sum::<i64>()
    }

    fn saved_names(&self) -> Vec<&str> {
        self.save_groups
            .iter()
            .flat_map(|group| group.registers.iter())
            .map(|register| register.name.as_str())
            .collect()
    }
}

/// Collapse a proven-balanced AAPCS machine frame in `f`.
pub fn recognise_arm32_frame(f: &mut Function) {
    let Some(frame) = parse_prologue(&f.body) else {
        return;
    };

    // Work on a clone so one malformed return path cannot leave a partially
    // rewritten function behind.
    let mut candidate = f.body.clone();
    let Some(return_count) = collapse_epilogues(&mut candidate, &frame) else {
        return;
    };
    if return_count == 0 {
        return;
    }

    candidate.drain(frame.start..frame.end);
    candidate.insert(
        frame.start,
        Stmt::Comment(format!(
            "arm32 prologue: save {}, frame {} bytes",
            frame.saved_names().join("/"),
            frame.total_width()
        )),
    );

    // Stack-local promotion should have converted every source-level object to
    // a semantic stack slot. A remaining architectural `sp` is therefore a
    // dynamic or otherwise unproved use; retain the original frame rather than
    // changing its meaning.
    if candidate.iter().any(stmt_mentions_sp) {
        return;
    }
    f.body = candidate;
}

fn parse_prologue(body: &[Stmt]) -> Option<Arm32Frame> {
    let mut start = 0;
    while matches!(body.get(start), Some(Stmt::Nop | Stmt::Label(_))) {
        start += 1;
    }

    let mut cursor = start;
    let mut save_groups = Vec::new();
    while let Some(width) = sp_adjust(body.get(cursor)?, BinOp::Sub) {
        let mut group_cursor = cursor + 1;
        let mut stored_width = 0i64;
        let mut registers = Vec::new();
        while let Some((slot, name, size)) = body.get(group_cursor).and_then(saved_register_store) {
            if stored_width + i64::from(size) > width {
                break;
            }
            stored_width += i64::from(size);
            registers.push(SavedRegister { name, slot });
            group_cursor += 1;
            if stored_width == width {
                break;
            }
        }
        // A32 `push {fp, lr}; add fp, sp, #4` can reach stack promotion with
        // the incoming fp already rewritten as the address of its own save
        // slot. Recover that first word only when the next word is a proven LR
        // save and the immediately following setup uses the same address.
        if registers.is_empty() {
            if let Some((fp_slot, saved_fp_address)) =
                body.get(group_cursor).and_then(aliased_frame_pointer_store)
            {
                if let Some((lr_slot, lr_name, lr_size)) =
                    body.get(group_cursor + 1).and_then(saved_register_store)
                {
                    let setup_matches = body
                        .get(group_cursor + 2)
                        .and_then(frame_pointer_setup)
                        .is_some_and(|location| location == saved_fp_address);
                    if lr_name == "lr" && lr_size == 4 && width == 8 && setup_matches {
                        registers.push(SavedRegister {
                            name: "fp".to_string(),
                            slot: fp_slot,
                        });
                        registers.push(SavedRegister {
                            name: lr_name,
                            slot: lr_slot,
                        });
                        stored_width = 8;
                        group_cursor += 2;
                    }
                }
            }
        }
        if registers.is_empty() || stored_width != width {
            break;
        }
        save_groups.push(SaveGroup { width, registers });
        cursor = group_cursor;
    }

    if save_groups.is_empty()
        || !save_groups
            .iter()
            .flat_map(|group| group.registers.iter())
            .any(|register| register.name == "lr")
    {
        return None;
    }

    // A32 establishes fp immediately after the push, whereas Thumb commonly
    // allocates locals first and then establishes r7. Accept both exact
    // orderings.
    if body.get(cursor).is_some_and(|statement| {
        frame_pointer_setup(statement).is_some_and(|location| {
            save_groups
                .iter()
                .flat_map(|group| group.registers.iter())
                .any(|saved| saved.slot.object == location.object)
        })
    }) {
        cursor += 1;
    }

    let local_width = body
        .get(cursor)
        .and_then(|statement| sp_adjust(statement, BinOp::Sub))
        .unwrap_or(0);
    if local_width > 0 {
        cursor += 1;
    }

    // Stack promotion represents Thumb's `add r7, sp, #0` as the address of
    // the promoted frame-record object. It is part of the machine frame, not
    // a source assignment. Require that address to name storage already
    // proven by the save group so an arbitrary source pointer assignment is
    // never consumed.
    if body.get(cursor).is_some_and(|statement| {
        frame_pointer_setup(statement).is_some_and(|location| {
            local_width > 0
                || save_groups
                    .iter()
                    .flat_map(|group| group.registers.iter())
                    .any(|saved| saved.slot.object == location.object)
        })
    }) {
        cursor += 1;
    }

    Some(Arm32Frame {
        start,
        end: cursor,
        local_width,
        save_groups,
    })
}

fn saved_register_store(statement: &Stmt) -> Option<(StackLocation, String, u8)> {
    let Stmt::Store {
        addr,
        src: Expr::Reg(register),
        size,
    } = statement
    else {
        return None;
    };
    let slot = stack_location(addr)?;
    let name = canonical_saved_register(register)?;
    let expected_size = if name.starts_with('d') { 8 } else { 4 };
    (*size == expected_size).then(|| (slot, name, *size))
}

fn aliased_frame_pointer_store(statement: &Stmt) -> Option<(StackLocation, StackLocation)> {
    let Stmt::Store { addr, src, size: 4 } = statement else {
        return None;
    };
    Some((stack_location(addr)?, stack_location(src)?))
}

fn collapse_epilogues(body: &mut Vec<Stmt>, frame: &Arm32Frame) -> Option<usize> {
    let mut return_count = 0;
    for statement in body.iter_mut() {
        return_count += match statement {
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                let then_count = collapse_epilogues(then_body, frame)?;
                let else_count = else_body
                    .as_mut()
                    .map_or(Some(0), |else_body| collapse_epilogues(else_body, frame))?;
                then_count + else_count
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
                collapse_epilogues(body, frame)?
            }
            Stmt::Switch { cases, default, .. } => {
                let mut nested_count = 0;
                for (_, case_body) in cases {
                    nested_count += collapse_epilogues(case_body, frame)?;
                }
                if let Some(default_body) = default {
                    nested_count += collapse_epilogues(default_body, frame)?;
                }
                nested_count
            }
            _ => 0,
        };
    }

    let return_positions: Vec<usize> = body
        .iter()
        .enumerate()
        .filter_map(|(index, statement)| matches!(statement, Stmt::Return { .. }).then_some(index))
        .collect();
    return_count += return_positions.len();
    for return_index in return_positions.into_iter().rev() {
        let start = match_epilogue(body, return_index, frame)?;
        body.drain(start..return_index);
        body.insert(
            start,
            Stmt::Comment("arm32 epilogue: restore machine frame".to_string()),
        );
    }
    Some(return_count)
}

fn match_epilogue(body: &[Stmt], return_index: usize, frame: &Arm32Frame) -> Option<usize> {
    // Locate the contiguous machine-only suffix, then validate its exact order
    // below. Large GCC frames restore SP from the frame pointer rather than by
    // adding the allocation width, so a numeric-width sum is not sufficient.
    let mut start = return_index;
    while start > 0 {
        match &body[start - 1] {
            statement if sp_adjust(statement, BinOp::Add).is_some() => start -= 1,
            statement if restored_register(statement).is_some() => start -= 1,
            statement if frame_deallocation_piece(statement, frame) => start -= 1,
            _ => break,
        }
    }

    let mut cursor = start;
    let a32_restores_sp_from_fp = body.get(cursor).is_some_and(|statement| {
        matches!(
            statement,
            Stmt::Assign {
                dst,
                src: Expr::Reg(source),
            } if is_sp(dst)
                && canonical_saved_register(source).as_deref() == Some("fp")
        )
    });
    if frame.local_width > 0 {
        cursor = match_frame_deallocation(body, cursor, frame)?;
    }

    for group in frame.save_groups.iter().rev() {
        for saved in &group.registers {
            if saved.name == "lr" {
                // `pop {..., pc}` and `ldr pc, [sp], #4` consume the saved link
                // slot as the return target, so no assignment to `lr` appears.
                if body
                    .get(cursor)
                    .and_then(restored_register)
                    .is_some_and(|(name, slot)| name == "lr" && slot == saved.slot)
                {
                    cursor += 1;
                }
                continue;
            }
            let (name, slot) = body.get(cursor).and_then(restored_register)?;
            let promoted_stack_top_alias = a32_restores_sp_from_fp
                && saved.name == "fp"
                && first_saved_slot(frame) == Some(&saved.slot)
                && slot.offset == 0
                && matches!(&slot.object, VReg::Phys(name) if base_name(name) == "stack_top");
            if name != saved.name || (slot != saved.slot && !promoted_stack_top_alias) {
                return None;
            }
            cursor += 1;
        }
        if sp_adjust(body.get(cursor)?, BinOp::Add)? != group.width {
            return None;
        }
        cursor += 1;
    }

    (cursor == return_index).then_some(start)
}

fn first_saved_slot(frame: &Arm32Frame) -> Option<&StackLocation> {
    frame
        .save_groups
        .first()
        .and_then(|group| group.registers.first())
        .map(|saved| &saved.slot)
}

fn frame_deallocation_piece(statement: &Stmt, frame: &Arm32Frame) -> bool {
    match statement {
        Stmt::Assign { dst, src } if is_sp(dst) => {
            matches!(src, Expr::Reg(register) if matches!(canonical_saved_register(register).as_deref(), Some("r7" | "fp")))
                || matches!(
                    src,
                    Expr::Bin { op: BinOp::Sub, lhs, rhs }
                        if matches!(lhs.as_ref(), Expr::Reg(register) if canonical_saved_register(register).as_deref() == Some("fp"))
                            && matches!(rhs.as_ref(), Expr::Const(4))
                )
        }
        Stmt::Assign { dst, src } => {
            canonical_saved_register(dst).as_deref() == Some("r7")
                && stack_location(src).as_ref() == first_saved_slot(frame)
        }
        _ => false,
    }
}

fn match_frame_deallocation(body: &[Stmt], cursor: usize, frame: &Arm32Frame) -> Option<usize> {
    if sp_adjust(body.get(cursor)?, BinOp::Add) == Some(frame.local_width) {
        return Some(cursor + 1);
    }

    // Clang A32 commonly establishes `fp = sp` after the save and tears local
    // storage down with the exact inverse `sp = fp`.
    if matches!(
        body.get(cursor),
        Some(Stmt::Assign {
            dst,
            src: Expr::Reg(source),
        }) if is_sp(dst)
            && canonical_saved_register(source).as_deref() == Some("fp")
    ) {
        return Some(cursor + 1);
    }

    // Thumb: `add r7, sp, #0` established the bottom of the local allocation;
    // GCC tears it down as `mov sp, r7`, which promotion spells by first
    // rematerialising the saved-frame object address into r7.
    if let (
        Some(Stmt::Assign { dst: anchor, src }),
        Some(Stmt::Assign {
            dst,
            src: Expr::Reg(source),
        }),
    ) = (body.get(cursor), body.get(cursor + 1))
    {
        if canonical_saved_register(anchor).as_deref() == Some("r7")
            && stack_location(src).as_ref() == first_saved_slot(frame)
            && is_sp(dst)
            && source == anchor
        {
            return Some(cursor + 2);
        }
    }

    // A32: `add fp, sp, #4` makes the first pushed word live at `fp - 4`.
    if matches!(
        body.get(cursor),
        Some(Stmt::Assign {
            dst,
            src: Expr::Bin { op: BinOp::Sub, lhs, rhs },
        }) if is_sp(dst)
            && matches!(lhs.as_ref(), Expr::Reg(register) if canonical_saved_register(register).as_deref() == Some("fp"))
            && matches!(rhs.as_ref(), Expr::Const(4))
    ) {
        return Some(cursor + 1);
    }

    None
}

fn restored_register(statement: &Stmt) -> Option<(String, StackLocation)> {
    let Stmt::Assign { dst, src } = statement else {
        return None;
    };
    let slot = match src {
        Expr::Reg(slot) if is_promoted_stack_slot(slot) => StackLocation {
            object: slot.clone(),
            offset: 0,
        },
        Expr::Deref { addr, size } if *size == 4 || *size == 8 => stack_location(addr)?,
        _ => return None,
    };
    canonical_saved_register(dst).map(|name| (name, slot))
}

fn stack_location(expression: &Expr) -> Option<StackLocation> {
    match expression {
        Expr::Reg(slot) if is_promoted_stack_slot(slot) => Some(StackLocation {
            object: slot.clone(),
            offset: 0,
        }),
        Expr::StackAddr { object, .. } => Some(StackLocation {
            object: object.clone(),
            offset: 0,
        }),
        Expr::Bin {
            op: BinOp::Add,
            lhs,
            rhs,
        } => match rhs.as_ref() {
            Expr::Const(offset) => {
                let mut location = stack_location(lhs)?;
                location.offset = location.offset.checked_add(*offset)?;
                Some(location)
            }
            _ => None,
        },
        _ => None,
    }
}

fn frame_pointer_setup(statement: &Stmt) -> Option<StackLocation> {
    let Stmt::Assign { dst, src } = statement else {
        return None;
    };
    let name = canonical_saved_register(dst)?;
    ((name == "r7" || name == "fp") && stack_location(src).is_some())
        .then(|| stack_location(src))
        .flatten()
}

fn sp_adjust(statement: &Stmt, expected_op: BinOp) -> Option<i64> {
    let Stmt::Assign {
        dst,
        src: Expr::Bin { op, lhs, rhs },
    } = statement
    else {
        return None;
    };
    if *op != expected_op
        || !is_sp(dst)
        || !matches!(lhs.as_ref(), Expr::Reg(register) if register == dst)
    {
        return None;
    }
    match rhs.as_ref() {
        Expr::Const(width) if *width > 0 => Some(*width),
        _ => None,
    }
}

fn canonical_saved_register(register: &VReg) -> Option<String> {
    let VReg::Phys(name) = register else {
        return None;
    };
    let name = base_name(name);
    if name == "lr" || name == "r14" {
        return Some("lr".to_string());
    }
    if name == "fp" || name == "r11" {
        return Some("fp".to_string());
    }
    let core = name
        .strip_prefix('r')
        .and_then(|index| index.parse::<u8>().ok())
        .is_some_and(|index| (4..=11).contains(&index));
    let vfp = name
        .strip_prefix('d')
        .and_then(|index| index.parse::<u8>().ok())
        .is_some_and(|index| (8..=15).contains(&index));
    (core || vfp).then(|| name.to_string())
}

fn is_promoted_stack_slot(register: &VReg) -> bool {
    matches!(register, VReg::Phys(name) if name == "stack_top" || name.starts_with("stack_"))
}

fn is_sp(register: &VReg) -> bool {
    matches!(register, VReg::Phys(name) if base_name(name) == "sp")
}

fn base_name(name: &str) -> &str {
    name.split_once('#').map_or(name, |(base, _)| base)
}

fn expr_mentions_sp(expression: &Expr) -> bool {
    match expression {
        Expr::Reg(register) => is_sp(register),
        Expr::StackAddr { object, .. } => is_sp(object),
        Expr::Lea { base, index, .. } | Expr::PdbFieldAddr { base, index, .. } => {
            base.iter().chain(index.iter()).any(is_sp)
        }
        Expr::Deref { addr, .. } => expr_mentions_sp(addr),
        Expr::Call { target, args, .. } => {
            expr_mentions_sp(target) || args.iter().any(expr_mentions_sp)
        }
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            expr_mentions_sp(lhs) || expr_mentions_sp(rhs)
        }
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => expr_mentions_sp(cond) || expr_mentions_sp(if_true) || expr_mentions_sp(if_false),
        Expr::Un { src, .. } => expr_mentions_sp(src),
        Expr::Cast { expr, .. } | Expr::NumericConvert { expr, .. } => expr_mentions_sp(expr),
        Expr::FunctionTableEntry { index, .. } => expr_mentions_sp(index),
        Expr::WideArithmetic { args, .. } => args.iter().any(expr_mentions_sp),
        Expr::Const(_)
        | Expr::FloatConst { .. }
        | Expr::Addr(_)
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::Unknown(_) => false,
    }
}

fn stmt_mentions_sp(statement: &Stmt) -> bool {
    match statement {
        Stmt::Assign { dst, src } => is_sp(dst) || expr_mentions_sp(src),
        Stmt::Store { addr, src, .. } => expr_mentions_sp(addr) || expr_mentions_sp(src),
        Stmt::Call {
            target, args, dst, ..
        } => {
            expr_mentions_sp(target)
                || args.iter().any(expr_mentions_sp)
                || dst.as_ref().is_some_and(is_sp)
        }
        Stmt::Return { value } => value.as_ref().is_some_and(expr_mentions_sp),
        Stmt::If {
            cond,
            then_body,
            else_body,
        } => {
            expr_mentions_sp(cond)
                || then_body.iter().any(stmt_mentions_sp)
                || else_body
                    .as_ref()
                    .is_some_and(|body| body.iter().any(stmt_mentions_sp))
        }
        Stmt::While { cond, body } | Stmt::DoWhile { body, cond } => {
            expr_mentions_sp(cond) || body.iter().any(stmt_mentions_sp)
        }
        Stmt::For {
            init,
            cond,
            step,
            body,
        } => {
            stmt_mentions_sp(init)
                || expr_mentions_sp(cond)
                || stmt_mentions_sp(step)
                || body.iter().any(stmt_mentions_sp)
        }
        Stmt::Push { value } => expr_mentions_sp(value),
        Stmt::Pop { target } => is_sp(target),
        Stmt::Switch {
            discriminant,
            cases,
            default,
        } => {
            expr_mentions_sp(discriminant)
                || cases
                    .iter()
                    .any(|(_, body)| body.iter().any(stmt_mentions_sp))
                || default
                    .as_ref()
                    .is_some_and(|body| body.iter().any(stmt_mentions_sp))
        }
        Stmt::IndirectGoto { target } => expr_mentions_sp(target),
        Stmt::Goto { .. }
        | Stmt::Label(_)
        | Stmt::Break
        | Stmt::Nop
        | Stmt::Unknown(_)
        | Stmt::Comment(_)
        | Stmt::Throw { .. }
        | Stmt::TryCatch { .. } => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::ast::{Expr, Stmt};
    use crate::ir::types::{BinOp, VReg};

    fn reg(name: &str) -> VReg {
        VReg::phys(name)
    }

    fn sp_sub(width: i64) -> Stmt {
        Stmt::Assign {
            dst: reg("sp"),
            src: Expr::Bin {
                op: BinOp::Sub,
                lhs: Box::new(Expr::Reg(reg("sp"))),
                rhs: Box::new(Expr::Const(width)),
            },
        }
    }

    fn sp_add(width: i64) -> Stmt {
        Stmt::Assign {
            dst: reg("sp"),
            src: Expr::Bin {
                op: BinOp::Add,
                lhs: Box::new(Expr::Reg(reg("sp"))),
                rhs: Box::new(Expr::Const(width)),
            },
        }
    }

    fn save(slot: &str, register: &str, size: u8) -> Stmt {
        Stmt::Store {
            addr: Expr::Reg(reg(slot)),
            src: Expr::Reg(reg(register)),
            size,
        }
    }

    fn restore(register: &str, slot: &str) -> Stmt {
        Stmt::Assign {
            dst: reg(register),
            src: Expr::Reg(reg(slot)),
        }
    }

    fn object_addr(object: &str, offset: i64) -> Expr {
        let base = Expr::StackAddr {
            object: reg(object),
            size: 8,
        };
        if offset == 0 {
            base
        } else {
            Expr::Bin {
                op: BinOp::Add,
                lhs: Box::new(base),
                rhs: Box::new(Expr::Const(offset)),
            }
        }
    }

    fn function(body: Vec<Stmt>) -> Function {
        Function {
            name: "fixture".into(),
            entry_va: 0x1000,
            body,
        }
    }

    fn base_name(name: &str) -> &str {
        name.split_once('#').map_or(name, |(base, _)| base)
    }

    fn mentions_sp(statement: &Stmt) -> bool {
        fn expr_mentions_sp(expression: &Expr) -> bool {
            match expression {
                Expr::Reg(VReg::Phys(name)) => base_name(name) == "sp",
                Expr::Lea { base, index, .. } | Expr::PdbFieldAddr { base, index, .. } => {
                    base.iter().chain(index.iter()).any(
                        |register| matches!(register, VReg::Phys(name) if base_name(name) == "sp"),
                    )
                }
                Expr::Deref { addr, .. } => expr_mentions_sp(addr),
                Expr::Call { target, args, .. } => {
                    expr_mentions_sp(target) || args.iter().any(expr_mentions_sp)
                }
                Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
                    expr_mentions_sp(lhs) || expr_mentions_sp(rhs)
                }
                Expr::Select {
                    cond,
                    if_true,
                    if_false,
                    ..
                } => {
                    expr_mentions_sp(cond)
                        || expr_mentions_sp(if_true)
                        || expr_mentions_sp(if_false)
                }
                Expr::Un { src, .. } => expr_mentions_sp(src),
                Expr::Cast { expr, .. } | Expr::NumericConvert { expr, .. } => {
                    expr_mentions_sp(expr)
                }
                Expr::FunctionTableEntry { index, .. } => expr_mentions_sp(index),
                Expr::WideArithmetic { args, .. } => args.iter().any(expr_mentions_sp),
                Expr::StackAddr { .. }
                | Expr::Const(_)
                | Expr::FloatConst { .. }
                | Expr::Addr(_)
                | Expr::Named { .. }
                | Expr::StringLit { .. }
                | Expr::Unknown(_)
                | Expr::Reg(_) => false,
            }
        }

        match statement {
            Stmt::Assign { dst, src } => {
                matches!(dst, VReg::Phys(name) if base_name(name) == "sp") || expr_mentions_sp(src)
            }
            Stmt::Store { addr, src, .. } => expr_mentions_sp(addr) || expr_mentions_sp(src),
            Stmt::Return { value } => value.as_ref().is_some_and(expr_mentions_sp),
            Stmt::If {
                cond,
                then_body,
                else_body,
            } => {
                expr_mentions_sp(cond)
                    || then_body.iter().any(mentions_sp)
                    || else_body
                        .as_ref()
                        .is_some_and(|body| body.iter().any(mentions_sp))
            }
            Stmt::While { cond, body } | Stmt::DoWhile { body, cond } => {
                expr_mentions_sp(cond) || body.iter().any(mentions_sp)
            }
            Stmt::For {
                init,
                cond,
                step,
                body,
            } => {
                mentions_sp(init)
                    || expr_mentions_sp(cond)
                    || mentions_sp(step)
                    || body.iter().any(mentions_sp)
            }
            Stmt::Call { target, args, .. } => {
                expr_mentions_sp(target) || args.iter().any(expr_mentions_sp)
            }
            Stmt::Push { value } => expr_mentions_sp(value),
            Stmt::Pop { target } => matches!(target, VReg::Phys(name) if name == "sp"),
            Stmt::Switch {
                discriminant,
                cases,
                default,
            } => {
                expr_mentions_sp(discriminant)
                    || cases.iter().any(|(_, body)| body.iter().any(mentions_sp))
                    || default
                        .as_ref()
                        .is_some_and(|body| body.iter().any(mentions_sp))
            }
            Stmt::IndirectGoto { target } => expr_mentions_sp(target),
            Stmt::Goto { .. }
            | Stmt::Label(_)
            | Stmt::Break
            | Stmt::Nop
            | Stmt::Unknown(_)
            | Stmt::Comment(_)
            | Stmt::Throw { .. }
            | Stmt::TryCatch { .. } => false,
        }
    }

    #[test]
    fn lighthouse_core_vfp_and_local_frame_collapses_exactly() {
        let mut f = function(vec![
            sp_sub(4),
            save("stack_top", "lr", 4),
            sp_sub(8),
            save("stack_top", "d8", 8),
            sp_sub(44),
            Stmt::Nop,
            sp_add(44),
            restore("d8#1", "stack_top"),
            sp_add(8),
            sp_add(4),
            Stmt::Return { value: None },
        ]);

        recognise_arm32_frame(&mut f);

        assert!(matches!(
            f.body.first(),
            Some(Stmt::Comment(text)) if text == "arm32 prologue: save lr/d8, frame 56 bytes"
        ));
        assert!(matches!(f.body.last(), Some(Stmt::Return { .. })));
        assert!(
            !f.body.iter().any(mentions_sp),
            "machine stack arithmetic leaked after a balanced collapse: {:#?}",
            f.body
        );
    }

    #[test]
    fn multi_register_core_save_and_pop_pc_collapses() {
        let mut f = function(vec![
            sp_sub(12),
            save("stack_0", "r4", 4),
            save("stack_4", "r5", 4),
            save("stack_8", "lr", 4),
            Stmt::Nop,
            restore("r4#1", "stack_0"),
            restore("r5#1", "stack_4"),
            sp_add(12),
            Stmt::Return { value: None },
        ]);

        recognise_arm32_frame(&mut f);

        assert!(!f.body.iter().any(mentions_sp), "{:#?}", f.body);
        assert!(matches!(f.body.last(), Some(Stmt::Return { .. })));
    }

    #[test]
    fn promoted_thumb_frame_record_object_collapses_as_one_machine_save() {
        let mut f = function(vec![
            sp_sub(8),
            Stmt::Store {
                addr: object_addr("local_8", 0),
                src: Expr::Reg(reg("r7")),
                size: 4,
            },
            Stmt::Store {
                addr: object_addr("local_8", 4),
                src: Expr::Reg(reg("lr")),
                size: 4,
            },
            Stmt::Assign {
                dst: reg("r7#1"),
                src: object_addr("local_8", 0),
            },
            Stmt::Nop,
            Stmt::Assign {
                dst: reg("r7#2"),
                src: Expr::Deref {
                    addr: Box::new(object_addr("local_8", 0)),
                    size: 4,
                },
            },
            sp_add(8),
            Stmt::Return { value: None },
        ]);

        recognise_arm32_frame(&mut f);

        assert!(matches!(
            f.body.first(),
            Some(Stmt::Comment(text))
                if text == "arm32 prologue: save r7/lr, frame 8 bytes"
        ));
        assert!(matches!(f.body.get(1), Some(Stmt::Nop)));
        assert!(matches!(
            f.body.get(2),
            Some(Stmt::Comment(text)) if text == "arm32 epilogue: restore machine frame"
        ));
        assert!(matches!(f.body.last(), Some(Stmt::Return { value: None })));
        assert!(
            !format!("{:#?}", f.body).contains("local_8"),
            "promoted frame record leaked after collapse: {:#?}",
            f.body
        );
    }

    #[test]
    fn clang_a32_fp_frame_record_collapses_as_machine_bookkeeping() {
        let mut f = function(vec![
            sp_sub(8),
            Stmt::Store {
                addr: object_addr("local_8", 0),
                src: Expr::Reg(reg("r11")),
                size: 4,
            },
            Stmt::Store {
                addr: object_addr("local_8", 4),
                src: Expr::Reg(reg("lr")),
                size: 4,
            },
            Stmt::Assign {
                dst: reg("fp"),
                src: object_addr("local_8", 0),
            },
            sp_sub(8),
            Stmt::Nop,
            Stmt::Assign {
                dst: reg("sp"),
                src: Expr::Reg(reg("r11#1")),
            },
            Stmt::Assign {
                dst: reg("fp"),
                src: Expr::Reg(reg("stack_top")),
            },
            sp_add(8),
            Stmt::Return {
                value: Some(Expr::Const(0)),
            },
        ]);

        recognise_arm32_frame(&mut f);

        assert!(matches!(
            f.body.first(),
            Some(Stmt::Comment(text))
                if text == "arm32 prologue: save fp/lr, frame 16 bytes"
        ));
        assert!(matches!(f.body.get(1), Some(Stmt::Nop)));
        assert!(matches!(
            f.body.get(2),
            Some(Stmt::Comment(text)) if text == "arm32 epilogue: restore machine frame"
        ));
        assert!(matches!(
            f.body.last(),
            Some(Stmt::Return {
                value: Some(Expr::Const(0))
            })
        ));
        assert!(!format!("{:#?}", f.body).contains("local_8"));
    }

    #[test]
    fn mismatched_vfp_restore_width_leaves_function_untouched() {
        let mut f = function(vec![
            sp_sub(4),
            save("stack_top", "lr", 4),
            sp_sub(8),
            save("stack_top", "d8", 8),
            Stmt::Nop,
            restore("d8#1", "stack_top"),
            sp_add(4),
            sp_add(4),
            Stmt::Return { value: None },
        ]);
        let original = f.clone();

        recognise_arm32_frame(&mut f);

        assert_eq!(f, original);
    }

    #[test]
    fn semantic_stack_pointer_use_leaves_function_untouched() {
        let mut f = function(vec![
            sp_sub(4),
            save("stack_top", "lr", 4),
            Stmt::Assign {
                dst: reg("r4#1"),
                src: Expr::Reg(reg("sp")),
            },
            sp_add(4),
            Stmt::Return { value: None },
        ]);
        let original = f.clone();

        recognise_arm32_frame(&mut f);

        assert_eq!(f, original);
    }

    #[test]
    fn one_unbalanced_nested_return_rejects_the_whole_frame() {
        let mut f = function(vec![
            sp_sub(4),
            save("stack_top", "lr", 4),
            Stmt::If {
                cond: Expr::Reg(reg("zf_1")),
                then_body: vec![sp_add(4), Stmt::Return { value: None }],
                else_body: Some(vec![Stmt::Return { value: None }]),
            },
        ]);
        let original = f.clone();

        recognise_arm32_frame(&mut f);

        assert_eq!(f, original, "the rewrite must be all-or-nothing");
    }

    #[test]
    fn balanced_nested_return_paths_collapse_transactionally() {
        let mut f = function(vec![
            sp_sub(4),
            save("stack_top", "lr", 4),
            Stmt::If {
                cond: Expr::Reg(reg("zf_1")),
                then_body: vec![sp_add(4), Stmt::Return { value: None }],
                else_body: Some(vec![sp_add(4), Stmt::Return { value: None }]),
            },
        ]);

        recognise_arm32_frame(&mut f);

        assert!(
            !f.body.iter().any(mentions_sp),
            "balanced branch epilogues leaked machine stack state: {:#?}",
            f.body
        );
        let Stmt::If {
            then_body,
            else_body: Some(else_body),
            ..
        } = &f.body[1]
        else {
            panic!("structured branch was not preserved: {:#?}", f.body);
        };
        assert!(matches!(then_body.last(), Some(Stmt::Return { .. })));
        assert!(matches!(else_body.last(), Some(Stmt::Return { .. })));
    }
}
