//! x86-64 prologue / epilogue pattern recognition.
//!
//! Mirror of [`crate::ir::arm64_prologue`] for x86-64. Recognises the
//! canonical GCC/Clang rbp-framed prologue:
//!
//! ```text
//!   push rbp
//!   mov  rbp, rsp
//!   sub  rsp, N         (optional — absent in leaf functions)
//! ```
//!
//! …which after our pipeline lowers to:
//!
//! ```text
//!   push %rbp;
//!   %rbp = %rsp;
//!   %rsp = (%rsp - N);      (optional)
//! ```
//!
//! and collapses it to `// x86-64 prologue: save rbp[, frame N bytes]`.
//! The mirror epilogue (from a `leave; ret;` sequence our lifter
//! decomposes into `rsp = rbp; pop rbp; return;`) collapses into
//! `// x86-64 epilogue: restore rbp` followed by `return;`.
//!
//! Functions compiled with `-fomit-frame-pointer` (the default at -O2)
//! skip the rbp dance and are handled by the pre-existing
//! [`crate::ir::stack_idiom`] pass that turns `push`/`rsp` pairs into
//! `push %X;` and drops the trailing `rsp += N; return;`.

use crate::ir::ast::{Expr, Function, Stmt};
use crate::ir::types::{BinOp, CmpOp, VReg};

/// Run the pass over `f`'s body.
pub fn recognise_x86_prologue(f: &mut Function) {
    collapse_omit_frame_pointer_frame(&mut f.body);
    collapse_prologue(&mut f.body);
    collapse_epilogue(&mut f.body);
}

#[derive(Clone)]
struct SavedSlot {
    object: VReg,
    object_size: u16,
    offset: i64,
    width: u8,
    value: VReg,
}

/// Collapse an omit-frame-pointer frame only when entry saves and every exit
/// prove one balanced transaction.
///
/// Optimised x86 commonly uses a final `push rax` purely for alignment, after
/// saving the non-volatile registers. Stack promotion turns those pushes into
/// stores at the contiguous high end of one recovered object, while each pop
/// becomes the reverse fixed-slot load plus `rsp += 8`. Keeping that lowering
/// in source C invents an uninitialised `rsp` variable and exposes ABI state
/// that Ghidra/angr correctly hide. This recogniser deliberately fails closed:
/// the save area must be contiguous, every return must restore it exactly, and
/// the fixed save slots may have no reads beyond those restores.
fn collapse_omit_frame_pointer_frame(body: &mut Vec<Stmt>) {
    let mut start = 0usize;
    while start < body.len() && is_leading_frame_metadata(&body[start]) {
        start += 1;
    }

    let mut cursor = start;
    let mut saves = Vec::new();
    while cursor + 1 < body.len() {
        let Some(width) = rsp_sub_width(&body[cursor]).and_then(|n| u8::try_from(n).ok()) else {
            break;
        };
        let Stmt::Store {
            addr,
            src: Expr::Reg(value),
            size,
        } = &body[cursor + 1]
        else {
            break;
        };
        let Some((object, offset, object_size)) = fixed_promoted_stack_address(addr) else {
            break;
        };
        if *size != width || width == 0 {
            break;
        }
        saves.push(SavedSlot {
            object,
            object_size,
            offset,
            width,
            value: value.clone(),
        });
        cursor += 2;
    }
    if saves.is_empty() {
        return;
    }

    // A canonical `push rbp; mov rbp, rsp` frame belongs to the stricter
    // recogniser below, not this omit-frame-pointer path.
    if cursor < body.len()
        && matches!(
            &body[cursor],
            Stmt::Assign { dst, src: Expr::Reg(source) }
                if is_rbp(dst) && is_rsp(source)
        )
    {
        return;
    }

    let first = &saves[0];
    if first.offset < 0 || first.offset + i64::from(first.width) != i64::from(first.object_size) {
        return;
    }
    for pair in saves.windows(2) {
        if pair[1].object != first.object
            || pair[1].object_size != first.object_size
            || pair[1].width != first.width
            || pair[1].offset != pair[0].offset - i64::from(first.width)
        {
            return;
        }
    }

    // All saves except an optional final volatile alignment word must be
    // ABI-preserved registers. A volatile value in the middle is not a frame
    // signature and therefore blocks the transformation.
    if saves[..saves.len().saturating_sub(1)]
        .iter()
        .any(|save| !is_sysv_callee_saved(&save.value))
    {
        return;
    }
    if !is_sysv_callee_saved(&saves.last().expect("non-empty").value)
        && !matches!(&saves.last().expect("non-empty").value, VReg::Phys(name) if base_name(name) != "rsp")
    {
        return;
    }

    let mut candidate = body.clone();
    let Some((return_count, padding_restore_count)) =
        collapse_balanced_exit_bodies(&mut candidate, &saves)
    else {
        return;
    };
    if return_count == 0 {
        return;
    }

    // The only fixed reads of a non-volatile save slot must be its one restore
    // at each return. Alignment padding has no restore load at all.
    for save in &saves {
        let expected = if is_sysv_callee_saved(&save.value) {
            return_count
        } else {
            padding_restore_count
        };
        if count_fixed_slot_reads(body, save) != expected {
            return;
        }
    }

    candidate.drain(start..cursor);
    let frame_size: u64 = saves.iter().map(|save| u64::from(save.width)).sum();
    candidate.insert(
        start,
        Stmt::Comment(format!(
            "x86-64 prologue: save callee registers, frame {frame_size} bytes"
        )),
    );
    *body = candidate;
}

fn is_leading_frame_metadata(statement: &Stmt) -> bool {
    matches!(statement, Stmt::Nop | Stmt::Label(_))
        || matches!(statement, Stmt::Comment(text) if text.starts_with("frame:"))
}

fn base_name(name: &str) -> &str {
    name.split_once('#').map_or(name, |(base, _)| base)
}

fn is_sysv_callee_saved(register: &VReg) -> bool {
    matches!(
        register,
        VReg::Phys(name)
            if matches!(base_name(name), "rbp" | "rbx" | "r12" | "r13" | "r14" | "r15")
    )
}

fn fixed_promoted_stack_address(expression: &Expr) -> Option<(VReg, i64, u16)> {
    match expression {
        Expr::StackAddr { object, size } if is_promoted_stack_slot(object) => {
            Some((object.clone(), 0, *size))
        }
        Expr::Bin {
            op: BinOp::Add,
            lhs,
            rhs,
        } => match (lhs.as_ref(), rhs.as_ref()) {
            (Expr::StackAddr { object, size }, Expr::Const(offset))
                if is_promoted_stack_slot(object) =>
            {
                Some((object.clone(), *offset, *size))
            }
            (Expr::Const(offset), Expr::StackAddr { object, size })
                if is_promoted_stack_slot(object) =>
            {
                Some((object.clone(), *offset, *size))
            }
            _ => None,
        },
        _ => None,
    }
}

fn is_rsp_add_width(statement: &Stmt, width: u8) -> bool {
    matches!(
        statement,
        Stmt::Assign {
            dst,
            src: Expr::Bin { op: BinOp::Add, lhs, rhs },
        } if is_rsp(dst)
            && matches!(lhs.as_ref(), Expr::Reg(register) if register == dst)
            && matches!(rhs.as_ref(), Expr::Const(amount) if *amount == i64::from(width))
    )
}

fn is_restore_load(statement: &Stmt, save: &SavedSlot) -> bool {
    let Stmt::Assign {
        dst: VReg::Phys(destination),
        src: Expr::Deref { addr, size },
    } = statement
    else {
        return false;
    };
    let VReg::Phys(saved_name) = &save.value else {
        return false;
    };
    if base_name(destination) != base_name(saved_name) || *size != save.width {
        return false;
    }
    fixed_promoted_stack_address(addr).is_some_and(|(object, offset, object_size)| {
        object == save.object && offset == save.offset && object_size == save.object_size
    })
}

fn is_padding_restore_load(statement: &Stmt, save: &SavedSlot) -> bool {
    let Stmt::Assign {
        dst: VReg::Phys(destination),
        src: Expr::Deref { addr, size },
    } = statement
    else {
        return false;
    };
    if base_name(destination) == "rsp" || *size != save.width {
        return false;
    }
    fixed_promoted_stack_address(addr).is_some_and(|(object, offset, object_size)| {
        object == save.object && offset == save.offset && object_size == save.object_size
    })
}

fn contains_deref(expression: &Expr) -> bool {
    match expression {
        Expr::Deref { .. } | Expr::Call { .. } => true,
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            contains_deref(lhs) || contains_deref(rhs)
        }
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => contains_deref(cond) || contains_deref(if_true) || contains_deref(if_false),
        Expr::Un { src, .. } | Expr::Cast { expr: src, .. } => contains_deref(src),
        Expr::FunctionTableEntry { index, .. } => contains_deref(index),
        Expr::WideArithmetic { args, .. } => args.iter().any(contains_deref),
        _ => false,
    }
}

fn is_dead_machine_temporary(statement: &Stmt) -> bool {
    matches!(
        statement,
        Stmt::Assign {
            dst: VReg::Temp(_) | VReg::Flag(_) | VReg::FlagValue { .. },
            src,
        } if !contains_deref(src)
    )
}

fn balanced_exit_start(
    body: &[Stmt],
    return_index: usize,
    saves: &[SavedSlot],
) -> Option<(usize, usize)> {
    let mut cursor = return_index;
    let mut padding_restores = 0usize;
    for save in saves {
        while cursor > 0 && is_dead_machine_temporary(&body[cursor - 1]) {
            cursor -= 1;
        }
        if cursor == 0 || !is_rsp_add_width(&body[cursor - 1], save.width) {
            return None;
        }
        cursor -= 1;
        if is_sysv_callee_saved(&save.value) {
            if cursor == 0 || !is_restore_load(&body[cursor - 1], save) {
                return None;
            }
            cursor -= 1;
        } else if cursor > 0 && is_padding_restore_load(&body[cursor - 1], save) {
            cursor -= 1;
            padding_restores += 1;
        }
    }
    while cursor > 0 && is_dead_machine_temporary(&body[cursor - 1]) {
        cursor -= 1;
    }
    Some((cursor, padding_restores))
}

fn collapse_balanced_exit_bodies(
    body: &mut Vec<Stmt>,
    saves: &[SavedSlot],
) -> Option<(usize, usize)> {
    let mut count = 0usize;
    let mut padding_restores = 0usize;
    for statement in body.iter_mut() {
        match statement {
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                let nested = collapse_balanced_exit_bodies(then_body, saves)?;
                count += nested.0;
                padding_restores += nested.1;
                if let Some(else_body) = else_body {
                    let nested = collapse_balanced_exit_bodies(else_body, saves)?;
                    count += nested.0;
                    padding_restores += nested.1;
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
                let nested = collapse_balanced_exit_bodies(body, saves)?;
                count += nested.0;
                padding_restores += nested.1;
            }
            Stmt::Switch { cases, default, .. } => {
                for (_, case_body) in cases {
                    let nested = collapse_balanced_exit_bodies(case_body, saves)?;
                    count += nested.0;
                    padding_restores += nested.1;
                }
                if let Some(default_body) = default {
                    let nested = collapse_balanced_exit_bodies(default_body, saves)?;
                    count += nested.0;
                    padding_restores += nested.1;
                }
            }
            Stmt::TryCatch { try_body, catches } => {
                let nested = collapse_balanced_exit_bodies(try_body, saves)?;
                count += nested.0;
                padding_restores += nested.1;
                for catch in catches {
                    let nested = collapse_balanced_exit_bodies(&mut catch.body, saves)?;
                    count += nested.0;
                    padding_restores += nested.1;
                }
            }
            _ => {}
        }
    }

    let returns: Vec<usize> = body
        .iter()
        .enumerate()
        .filter_map(|(index, statement)| matches!(statement, Stmt::Return { .. }).then_some(index))
        .collect();
    for return_index in returns.into_iter().rev() {
        let (start, restored_padding) = balanced_exit_start(body, return_index, saves)?;
        body.drain(start..return_index);
        body.insert(
            start,
            Stmt::Comment("x86-64 epilogue: restore callee registers".to_string()),
        );
        count += 1;
        padding_restores += restored_padding;
    }
    Some((count, padding_restores))
}

fn count_fixed_slot_reads(body: &[Stmt], save: &SavedSlot) -> usize {
    fn expression_reads(expression: &Expr, save: &SavedSlot) -> usize {
        match expression {
            Expr::Deref { addr, .. } => {
                usize::from(fixed_promoted_stack_address(addr).is_some_and(
                    |(object, offset, object_size)| {
                        object == save.object
                            && offset == save.offset
                            && object_size == save.object_size
                    },
                )) + expression_reads(addr, save)
            }
            Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
                expression_reads(lhs, save) + expression_reads(rhs, save)
            }
            Expr::Select {
                cond,
                if_true,
                if_false,
                ..
            } => {
                expression_reads(cond, save)
                    + expression_reads(if_true, save)
                    + expression_reads(if_false, save)
            }
            Expr::Un { src, .. } | Expr::Cast { expr: src, .. } => expression_reads(src, save),
            Expr::FunctionTableEntry { index, .. } => expression_reads(index, save),
            Expr::WideArithmetic { args, .. } => args
                .iter()
                .map(|argument| expression_reads(argument, save))
                .sum(),
            _ => 0,
        }
    }
    fn statement_reads(statement: &Stmt, save: &SavedSlot) -> usize {
        match statement {
            Stmt::Assign { src, .. } => expression_reads(src, save),
            Stmt::Store { addr, src, .. } => {
                expression_reads(addr, save) + expression_reads(src, save)
            }
            Stmt::Call { target, args, .. } => {
                expression_reads(target, save)
                    + args
                        .iter()
                        .map(|argument| expression_reads(argument, save))
                        .sum::<usize>()
            }
            Stmt::Return { value } => value
                .as_ref()
                .map_or(0, |expression| expression_reads(expression, save)),
            Stmt::Throw { value } => expression_reads(value, save),
            Stmt::IndirectGoto { target } => expression_reads(target, save),
            Stmt::If {
                cond,
                then_body,
                else_body,
            } => {
                expression_reads(cond, save)
                    + count_fixed_slot_reads(then_body, save)
                    + else_body
                        .as_ref()
                        .map_or(0, |body| count_fixed_slot_reads(body, save))
            }
            Stmt::While { cond, body } | Stmt::DoWhile { cond, body } => {
                expression_reads(cond, save) + count_fixed_slot_reads(body, save)
            }
            Stmt::For {
                init,
                cond,
                step,
                body,
            } => {
                statement_reads(init, save)
                    + expression_reads(cond, save)
                    + statement_reads(step, save)
                    + count_fixed_slot_reads(body, save)
            }
            Stmt::TryCatch { try_body, catches } => {
                count_fixed_slot_reads(try_body, save)
                    + catches
                        .iter()
                        .map(|catch| count_fixed_slot_reads(&catch.body, save))
                        .sum::<usize>()
            }
            Stmt::Push { value } => expression_reads(value, save),
            Stmt::Switch {
                discriminant,
                cases,
                default,
            } => {
                expression_reads(discriminant, save)
                    + cases
                        .iter()
                        .map(|(_, body)| count_fixed_slot_reads(body, save))
                        .sum::<usize>()
                    + default
                        .as_ref()
                        .map_or(0, |body| count_fixed_slot_reads(body, save))
            }
            _ => 0,
        }
    }
    body.iter()
        .map(|statement| statement_reads(statement, save))
        .sum()
}

fn is_rbp(v: &VReg) -> bool {
    matches!(v, VReg::Phys(n) if n == "rbp" || n == "ebp")
}

fn is_rsp(v: &VReg) -> bool {
    matches!(v, VReg::Phys(n) if n == "rsp" || n == "esp")
}

fn is_promoted_stack_slot(v: &VReg) -> bool {
    matches!(
        v,
        VReg::Phys(name)
            if name == "stack_top"
                || name.starts_with("stack_")
                || name.starts_with("local_")
    )
}

fn rsp_sub_width(stmt: &Stmt) -> Option<i64> {
    let Stmt::Assign {
        dst,
        src: Expr::Bin {
            op: BinOp::Sub,
            lhs,
            rhs,
        },
    } = stmt
    else {
        return None;
    };
    if !is_rsp(dst) || !matches!(lhs.as_ref(), Expr::Reg(reg) if reg == dst) {
        return None;
    }
    match rhs.as_ref() {
        Expr::Const(width) if *width > 0 => Some(*width),
        _ => None,
    }
}

/// Return the stack-allocation width when `predicate` is dead flag bookkeeping
/// generated for the immediately following `sub rsp, N`.
///
/// `lift_x86::emit_sub_with_flags` emits both a signed-less temporary and the
/// architectural unsigned carry before the actual
/// subtraction. Dead-flag pruning may leave either one adjacent to the write,
/// so both exact comparisons are valid witnesses. Liveness below remains the
/// guard against hiding a predicate the recovered program actually reads.
fn dead_rsp_sub_predicate(predicate: &Stmt, sub: &Stmt, suffix: &[Stmt]) -> Option<i64> {
    let width = rsp_sub_width(sub)?;
    let Stmt::Assign {
        dst: VReg::Temp(temp),
        src:
            Expr::Cmp {
                op: CmpOp::Ult | CmpOp::Slt,
                lhs,
                rhs,
            },
    } = predicate
    else {
        return None;
    };
    if !matches!(lhs.as_ref(), Expr::Reg(reg) if is_rsp(reg))
        || !matches!(rhs.as_ref(), Expr::Const(n) if *n == width)
    {
        return None;
    }
    let predicate_reg = VReg::Temp(*temp);
    (!suffix
        .iter()
        .any(|stmt| crate::ir::dead_stores::stmt_reads(stmt, &predicate_reg)))
    .then_some(width)
}

fn collapse_prologue(body: &mut Vec<Stmt>) {
    // Skip leading nops (the lifter emits them for ENDBR64).
    let mut i = 0usize;
    while i < body.len() && matches!(&body[i], Stmt::Nop) {
        i += 1;
    }
    if body.len() - i < 2 {
        return;
    }

    // Step 1: `push %rbp;`. Stack-slot normalisation may preserve the lifter's
    // two-statement form (`rsp -= 8; stack_0 = rbp`) instead of rematerialising
    // `Stmt::Push`; accept it only when the decrement exactly equals the store
    // width and is immediately followed by the canonical frame-pointer setup.
    let set_fp_idx = if matches!(&body[i], Stmt::Push { value: Expr::Reg(v) } if is_rbp(v)) {
        i + 1
    } else if body.len() - i >= 3 {
        match (&body[i + 1], rsp_sub_width(&body[i])) {
            (
                Stmt::Store {
                    addr: Expr::Reg(slot),
                    src: Expr::Reg(value),
                    size,
                },
                Some(width),
            ) if is_promoted_stack_slot(slot) && is_rbp(value) && width == i64::from(*size) => {
                i + 2
            }
            _ => return,
        }
    } else {
        return;
    };
    // Step 2: `%rbp = %rsp;`
    if !matches!(
        &body[set_fp_idx],
        Stmt::Assign { dst, src: Expr::Reg(s) } if is_rbp(dst) && is_rsp(s)
    ) {
        return;
    }
    // Step 3 (optional): `%rsp = (%rsp - N);` or `%rsp = (%rsp + -N);`
    let mut end = set_fp_idx + 1;
    let mut frame_size: Option<i64> = None;
    if end + 1 < body.len() {
        if let Some(width) = dead_rsp_sub_predicate(&body[end], &body[end + 1], &body[end + 2..]) {
            frame_size = Some(width);
            end += 2;
        }
    }
    if frame_size.is_none() && end < body.len() {
        if let Stmt::Assign {
            dst,
            src: Expr::Bin { op, lhs, rhs },
        } = &body[end]
        {
            if is_rsp(dst)
                && matches!(lhs.as_ref(), Expr::Reg(r) if r == dst)
                && matches!(rhs.as_ref(), Expr::Const(_))
            {
                if let Expr::Const(n) = rhs.as_ref() {
                    let delta = match op {
                        BinOp::Sub if *n > 0 => Some(*n),
                        BinOp::Add if *n < 0 => Some(-*n),
                        _ => None,
                    };
                    if let Some(d) = delta {
                        frame_size = Some(d);
                        end += 1;
                    }
                }
            }
        }
    }

    let comment = match frame_size {
        Some(n) => format!("x86-64 prologue: save rbp, frame {} bytes", n),
        None => "x86-64 prologue: save rbp".to_string(),
    };
    body.drain(i..end);
    body.insert(i, Stmt::Comment(comment));
}

fn collapse_epilogue(body: &mut Vec<Stmt>) {
    // Returns can remain inside recovered branches/loops. Collapse those
    // lexical epilogues before handling this statement list itself.
    for statement in body.iter_mut() {
        match statement {
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                collapse_epilogue(then_body);
                if let Some(else_body) = else_body {
                    collapse_epilogue(else_body);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
                collapse_epilogue(body);
            }
            Stmt::Switch { cases, default, .. } => {
                for (_, case_body) in cases {
                    collapse_epilogue(case_body);
                }
                if let Some(default_body) = default {
                    collapse_epilogue(default_body);
                }
            }
            _ => {}
        }
    }

    // For every Return, check if the preceding stmts are `rsp = rbp; pop rbp`.
    let return_positions: Vec<usize> = body
        .iter()
        .enumerate()
        .filter(|(_, s)| matches!(s, Stmt::Return { .. }))
        .map(|(i, _)| i)
        .collect();
    for ret_idx in return_positions.into_iter().rev() {
        let mut ret_idx = ret_idx;
        // GCC's `-fzero-call-used-regs=all` clears the caller-owned x87 stack
        // by pushing eight zeroes and popping all eight values immediately
        // before `ret`.  The lifter retains those unsupported x87 operations
        // as `Unknown` nodes, so ordinary dead-store elimination cannot prove
        // them irrelevant.  Match the complete balanced sequence only: a partial
        // or differently ordered x87 program remains visible.  Consecutive
        // positive RSP adjustments directly before the scrub are the same
        // return's frame teardown (multiple pops are common).
        if ret_idx >= 16
            && body[ret_idx - 16..ret_idx - 8]
                .iter()
                .all(|statement| matches!(statement, Stmt::Unknown(mnemonic) if mnemonic == "fldz"))
            && body[ret_idx - 8..ret_idx]
                .iter()
                .all(|statement| matches!(statement, Stmt::Unknown(mnemonic) if mnemonic == "fstp"))
        {
            let mut start = ret_idx - 16;
            while start > 0 && is_rsp_add(&body[start - 1]) {
                start -= 1;
            }
            let text = if start < ret_idx - 16 {
                "x86-64 epilogue: clear call-used x87 and tear down frame"
            } else {
                "x86-64 epilogue: clear call-used x87"
            };
            body.drain(start..ret_idx);
            body.insert(start, Stmt::Comment(text.to_string()));
            continue;
        }
        // An earlier recognition round may already have replaced `pop rbp`
        // with its provenance comment while leaving the preceding frame-size
        // adjustment in place.  The second idempotent round must still consume
        // that machine-only adjustment; otherwise it renders as a fake mutable
        // source variable immediately before the return.
        if ret_idx >= 2
            && matches!(
                &body[ret_idx - 1],
                Stmt::Comment(text) if text.starts_with("x86-64 epilogue:")
            )
        {
            let mut cursor = ret_idx - 1;
            while cursor > 0
                && matches!(
                    &body[cursor - 1],
                    Stmt::Nop
                        | Stmt::Assign {
                            dst: VReg::Temp(_),
                            ..
                        }
                )
            {
                cursor -= 1;
            }
            if cursor > 0 && is_rsp_add(&body[cursor - 1]) {
                body.remove(cursor - 1);
                ret_idx -= 1;
            }
        }
        // The pre-rematerialised POP spelling has the stack increment AFTER
        // the promoted load: `rbp = stack_N; rsp += 8`.  Handle it before the
        // generic frame-teardown case below consumes only the increment and
        // leaves an undefined stack-slot read behind.  A preceding
        // `rsp = rbp` makes this the full lowering of `leave` and belongs to
        // the same machine-only epilogue.
        if ret_idx >= 2
            && is_rsp_add(&body[ret_idx - 1])
            && matches!(
                &body[ret_idx - 2],
                Stmt::Assign { dst, src: Expr::Reg(slot) }
                    if is_rbp(dst) && is_promoted_stack_slot(slot)
            )
        {
            let start = if ret_idx >= 3
                && matches!(
                    &body[ret_idx - 3],
                    Stmt::Assign { dst, src: Expr::Reg(s) }
                        if is_rsp(dst) && is_rbp(s)
                ) {
                ret_idx - 3
            } else {
                ret_idx - 2
            };
            body.drain(start..ret_idx);
            body.insert(
                start,
                Stmt::Comment("x86-64 epilogue: restore rbp".to_string()),
            );
            continue;
        }
        // Pattern A (from `leave`): `rsp = rbp; pop rbp; return;`
        if ret_idx >= 2
            && matches!(&body[ret_idx - 1], Stmt::Pop { target: t } if is_rbp(t))
            && matches!(
                &body[ret_idx - 2],
                Stmt::Assign { dst, src: Expr::Reg(s) } if is_rsp(dst) && is_rbp(s)
            )
        {
            body.drain(ret_idx - 2..ret_idx);
            ret_idx -= 2;
            body.insert(
                ret_idx,
                Stmt::Comment("x86-64 epilogue: restore rbp".to_string()),
            );
            continue;
        }
        // Pattern B: `pop rbp; return;` (no leave, just pop), optionally
        // preceded by a `%rsp = (%rsp + N);` teardown.
        if ret_idx >= 1 && matches!(&body[ret_idx - 1], Stmt::Pop { target: t } if is_rbp(t)) {
            body.remove(ret_idx - 1);
            ret_idx -= 1;
            // Pattern B': `%rsp += N;` immediately before the pop — fold it
            // into the same epilogue collapse.
            if ret_idx > 0 && is_rsp_add(&body[ret_idx - 1]) {
                body.remove(ret_idx - 1);
                ret_idx -= 1;
            }
            body.insert(
                ret_idx,
                Stmt::Comment("x86-64 epilogue: restore rbp".to_string()),
            );
            continue;
        }
        // Pattern B in the pre-rematerialised stack-slot form:
        // `rbp = stack_N; return`, optionally after the frame teardown.
        if ret_idx >= 1
            && matches!(
                &body[ret_idx - 1],
                Stmt::Assign { dst, src: Expr::Reg(slot) }
                    if is_rbp(dst) && is_promoted_stack_slot(slot)
            )
        {
            body.remove(ret_idx - 1);
            ret_idx -= 1;
            if ret_idx > 0 && is_rsp_add(&body[ret_idx - 1]) {
                body.remove(ret_idx - 1);
                ret_idx -= 1;
            }
            body.insert(
                ret_idx,
                Stmt::Comment("x86-64 epilogue: restore rbp".to_string()),
            );
            continue;
        }
        // Pattern C: `%rsp += N; return;` with no rbp restore at all.
        // This is common for -fomit-frame-pointer code where the only
        // epilogue work is tearing down the allocated frame.
        if ret_idx >= 1 && is_rsp_add(&body[ret_idx - 1]) {
            body.remove(ret_idx - 1);
            ret_idx -= 1;
            body.insert(
                ret_idx,
                Stmt::Comment("x86-64 epilogue: tear down frame".to_string()),
            );
        }
    }
}

fn is_rsp_add(s: &Stmt) -> bool {
    matches!(
        s,
        Stmt::Assign {
            dst,
            src: Expr::Bin { op: BinOp::Add, lhs, rhs },
        } if is_rsp(dst)
            && matches!(lhs.as_ref(), Expr::Reg(r) if r == dst)
            && matches!(rhs.as_ref(), Expr::Const(k) if *k > 0)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::ast::{Function, Stmt};

    fn reg(n: &str) -> VReg {
        VReg::phys(n)
    }

    fn push_rbp() -> Stmt {
        Stmt::Push {
            value: Expr::Reg(reg("rbp")),
        }
    }
    fn mov_rbp_rsp() -> Stmt {
        Stmt::Assign {
            dst: reg("rbp"),
            src: Expr::Reg(reg("rsp")),
        }
    }
    fn sub_rsp(n: i64) -> Stmt {
        Stmt::Assign {
            dst: reg("rsp"),
            src: Expr::Bin {
                op: BinOp::Sub,
                lhs: Box::new(Expr::Reg(reg("rsp"))),
                rhs: Box::new(Expr::Const(n)),
            },
        }
    }

    #[test]
    fn an_expression_call_is_not_dead_epilogue_bookkeeping() {
        let statement = Stmt::Assign {
            dst: VReg::Temp(7),
            src: Expr::Call {
                target: Box::new(Expr::Named {
                    va: 0x2000,
                    name: "notify".into(),
                }),
                args: Vec::new(),
                call_spec: None,
                result_width: Some(8),
            },
        };

        assert!(
            !is_dead_machine_temporary(&statement),
            "an unused result does not make the call itself dead"
        );
    }

    #[test]
    fn full_prologue_collapses_with_frame_size() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                push_rbp(),
                mov_rbp_rsp(),
                sub_rsp(0x20),
                Stmt::Return { value: None },
            ],
        };
        recognise_x86_prologue(&mut f);
        assert!(matches!(
            &f.body[0],
            Stmt::Comment(s) if s.contains("x86-64 prologue") && s.contains("32")
        ));
        assert!(matches!(&f.body[1], Stmt::Return { .. }));
    }

    #[test]
    fn dead_stack_allocation_carry_does_not_split_the_frame_prologue() {
        // Lowering `sub rsp, 0x30` records its unsigned-borrow predicate before
        // the stack-pointer write.  The predicate is machine-only when no later
        // statement reads it, so it must not strand the allocation in emitted C.
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                push_rbp(),
                mov_rbp_rsp(),
                Stmt::Assign {
                    dst: VReg::Temp(32),
                    src: Expr::Cmp {
                        op: crate::ir::types::CmpOp::Ult,
                        lhs: Box::new(Expr::Reg(reg("rsp"))),
                        rhs: Box::new(Expr::Const(0x30)),
                    },
                },
                sub_rsp(0x30),
                Stmt::Return { value: None },
            ],
        };

        recognise_x86_prologue(&mut f);

        assert_eq!(f.body.len(), 2, "stranded frame setup: {:#?}", f.body);
        assert!(matches!(
            &f.body[0],
            Stmt::Comment(text) if text == "x86-64 prologue: save rbp, frame 48 bytes"
        ));
        assert!(matches!(&f.body[1], Stmt::Return { .. }));
    }

    #[test]
    fn dead_stack_allocation_signed_less_temp_does_not_split_the_frame_prologue() {
        // `emit_sub_with_flags` computes both the unsigned carry and a signed-
        // less temporary before writing rsp. Dead-flag pruning can remove the
        // carry first and leave this exact Slt node adjacent to `sub rsp, N`.
        // It is machine flag bookkeeping, not source control flow, and must be
        // consumed with the frame allocation when nothing reads it.
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                push_rbp(),
                mov_rbp_rsp(),
                Stmt::Assign {
                    dst: VReg::Temp(32),
                    src: Expr::Cmp {
                        op: CmpOp::Slt,
                        lhs: Box::new(Expr::Reg(reg("rsp"))),
                        rhs: Box::new(Expr::Const(0x10)),
                    },
                },
                sub_rsp(0x10),
                Stmt::Return { value: None },
            ],
        };

        recognise_x86_prologue(&mut f);

        assert_eq!(f.body.len(), 2, "stranded frame setup: {:#?}", f.body);
        assert!(matches!(
            &f.body[0],
            Stmt::Comment(text) if text == "x86-64 prologue: save rbp, frame 16 bytes"
        ));
        assert!(matches!(&f.body[1], Stmt::Return { .. }));
    }

    #[test]
    fn live_stack_allocation_predicate_is_not_hidden() {
        let predicate = VReg::Temp(32);
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                push_rbp(),
                mov_rbp_rsp(),
                Stmt::Assign {
                    dst: predicate.clone(),
                    src: Expr::Cmp {
                        op: CmpOp::Ult,
                        lhs: Box::new(Expr::Reg(reg("rsp"))),
                        rhs: Box::new(Expr::Const(0x30)),
                    },
                },
                sub_rsp(0x30),
                Stmt::If {
                    cond: Expr::Reg(predicate),
                    then_body: vec![Stmt::Return { value: None }],
                    else_body: None,
                },
            ],
        };

        recognise_x86_prologue(&mut f);

        assert!(matches!(
            &f.body[0],
            Stmt::Comment(text) if text == "x86-64 prologue: save rbp"
        ));
        assert!(matches!(
            &f.body[1],
            Stmt::Assign { dst, .. } if dst == &VReg::Temp(32)
        ));
        assert!(matches!(&f.body[2], Stmt::Assign { dst, .. } if is_rsp(dst)));
    }

    #[test]
    fn prologue_without_sub_still_collapses() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![push_rbp(), mov_rbp_rsp(), Stmt::Return { value: None }],
        };
        recognise_x86_prologue(&mut f);
        assert!(matches!(
            &f.body[0],
            Stmt::Comment(s) if s.contains("x86-64 prologue") && !s.contains("frame")
        ));
    }

    #[test]
    fn promoted_stack_slot_prologue_and_epilogue_collapse() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                sub_rsp(8),
                Stmt::Store {
                    addr: Expr::Reg(reg("stack_0")),
                    src: Expr::Reg(reg("rbp")),
                    size: 8,
                },
                mov_rbp_rsp(),
                sub_rsp(32),
                rsp_add(32),
                Stmt::Assign {
                    dst: reg("rbp"),
                    src: Expr::Reg(reg("stack_0")),
                },
                Stmt::Return { value: None },
            ],
        };

        recognise_x86_prologue(&mut f);

        assert!(matches!(
            &f.body[0],
            Stmt::Comment(text) if text == "x86-64 prologue: save rbp, frame 32 bytes"
        ));
        assert!(matches!(
            &f.body[1],
            Stmt::Comment(text) if text == "x86-64 epilogue: restore rbp"
        ));
        assert!(matches!(&f.body[2], Stmt::Return { .. }));
    }

    #[test]
    fn balanced_omit_frame_pointer_save_area_collapses_at_every_return() {
        fn slot(offset: i64) -> Expr {
            Expr::Bin {
                op: BinOp::Add,
                lhs: Box::new(Expr::StackAddr {
                    object: reg("stack_1"),
                    size: 24,
                }),
                rhs: Box::new(Expr::Const(offset)),
            }
        }
        fn save(offset: i64, value: &str) -> Stmt {
            Stmt::Store {
                addr: slot(offset),
                src: Expr::Reg(reg(value)),
                size: 8,
            }
        }
        fn restore(offset: i64, value: &str) -> Stmt {
            Stmt::Assign {
                dst: VReg::phys(format!("{value}#9")),
                src: Expr::Deref {
                    addr: Box::new(slot(offset)),
                    size: 8,
                },
            }
        }
        fn epilogue() -> Vec<Stmt> {
            vec![
                // The final volatile push is alignment padding: it has an
                // adjustment but deliberately no restore load.
                Stmt::Assign {
                    dst: VReg::Temp(40),
                    src: Expr::Const(0),
                },
                rsp_add(8),
                restore(8, "rbx"),
                rsp_add(8),
                restore(16, "rbp"),
                rsp_add(8),
                Stmt::Return { value: None },
            ]
        }

        let mut then_body = epilogue();
        let mut final_epilogue = epilogue();
        // Newer Clang spells the alignment pop as `pop rcx`, while older
        // Clang uses `add rsp, 8`. Both are balanced machine bookkeeping.
        final_epilogue.insert(1, restore(0, "rcx"));
        let mut body = vec![
            Stmt::Comment("frame: 24 bytes".into()),
            sub_rsp(8),
            save(16, "rbp"),
            sub_rsp(8),
            save(8, "rbx"),
            sub_rsp(8),
            save(0, "rax"),
            Stmt::If {
                cond: Expr::Reg(reg("cond")),
                then_body: std::mem::take(&mut then_body),
                else_body: None,
            },
        ];
        body.extend(final_epilogue);
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body,
        };

        let mut unbalanced = f.clone();
        let Stmt::If { then_body, .. } = &mut unbalanced.body[7] else {
            panic!("expected guarded early return");
        };
        then_body.remove(5); // omit rbp's final stack-pointer restore
        recognise_x86_prologue(&mut unbalanced);
        assert!(
            matches!(&unbalanced.body[1], Stmt::Assign { dst, .. } if is_rsp(dst)),
            "one malformed exit must preserve the entry save transaction"
        );
        assert!(!unbalanced.body.iter().any(
            |statement| matches!(statement, Stmt::Comment(text) if text.contains("save callee registers"))
        ));

        recognise_x86_prologue(&mut f);

        assert!(matches!(
            &f.body[1],
            Stmt::Comment(text) if text == "x86-64 prologue: save callee registers, frame 24 bytes"
        ));
        assert!(matches!(
            &f.body[2],
            Stmt::If { then_body, .. }
                if matches!(then_body.as_slice(), [Stmt::Comment(_), Stmt::Return { .. }])
        ));
        assert!(matches!(&f.body[3], Stmt::Comment(text) if text.contains("epilogue")));
        assert!(matches!(&f.body[4], Stmt::Return { .. }));
    }

    #[test]
    fn promoted_local_object_callee_saves_are_recognised() {
        let slot = |offset: i64| Expr::Bin {
            op: BinOp::Add,
            lhs: Box::new(Expr::StackAddr {
                // Stack promotion uses the source-facing `local_<offset>`
                // spelling for real recovered objects, not only `stack_N`.
                object: reg("local_68"),
                size: 16,
            }),
            rhs: Box::new(Expr::Const(offset)),
        };
        let save = |offset: i64, value: &str| Stmt::Store {
            addr: slot(offset),
            src: Expr::Reg(reg(value)),
            size: 8,
        };
        let restore = |offset: i64, value: &str| Stmt::Assign {
            dst: VReg::phys(format!("{value}#9")),
            src: Expr::Deref {
                addr: Box::new(slot(offset)),
                size: 8,
            },
        };
        let mut f = Function {
            name: "shared_exit".into(),
            entry_va: 0,
            body: vec![
                Stmt::Comment("frame: 16 bytes".into()),
                sub_rsp(8),
                save(8, "rbp"),
                sub_rsp(8),
                save(0, "rax"),
                rsp_add(8),
                restore(8, "rbp"),
                rsp_add(8),
                Stmt::Return {
                    value: Some(Expr::Const(0)),
                },
            ],
        };

        recognise_x86_prologue(&mut f);

        assert!(f.body.iter().any(
            |statement| matches!(statement, Stmt::Comment(text) if text.contains("save callee registers"))
        ));
        assert!(!format!("{:#?}", f.body).contains("StackAddr"));
    }

    #[test]
    fn promoted_stack_slot_epilogue_collapses_inside_a_branch() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![Stmt::If {
                cond: Expr::Reg(reg("cond")),
                then_body: vec![
                    Stmt::Assign {
                        dst: reg("rbp"),
                        src: Expr::Reg(reg("stack_0")),
                    },
                    Stmt::Return { value: None },
                ],
                else_body: None,
            }],
        };

        recognise_x86_prologue(&mut f);

        assert!(matches!(
            &f.body[0],
            Stmt::If { then_body, .. }
                if matches!(
                    then_body.as_slice(),
                    [Stmt::Comment(text), Stmt::Return { .. }]
                        if text == "x86-64 epilogue: restore rbp"
                )
        ));
    }

    #[test]
    fn lowered_leave_epilogue_collapses_before_rsp_adjust_is_rewritten() {
        // The raw `leave` expansion is `rsp = rbp; rbp = [rsp]; rsp += 8`.
        // Stack-local promotion changes the load to `rbp = stack_top`.  This
        // pass runs before stack-op rematerialisation, so it must consume the
        // complete three-statement spelling itself; otherwise the generic
        // `rsp += N; return` case inserts a comment between the load and return,
        // permanently stranding an undefined `stack_top` read in emitted C.
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("rsp"),
                    src: Expr::Reg(reg("rbp")),
                },
                Stmt::Assign {
                    dst: reg("rbp"),
                    src: Expr::Reg(reg("stack_top")),
                },
                rsp_add(8),
                Stmt::Return { value: None },
            ],
        };

        recognise_x86_prologue(&mut f);

        assert_eq!(f.body.len(), 2, "stranded leave fragment: {:#?}", f.body);
        assert!(matches!(
            &f.body[0],
            Stmt::Comment(text) if text == "x86-64 epilogue: restore rbp"
        ));
        assert!(matches!(&f.body[1], Stmt::Return { .. }));
    }

    #[test]
    fn prologue_without_mov_rbp_rsp_is_not_collapsed() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![push_rbp(), sub_rsp(0x20), Stmt::Return { value: None }],
        };
        let orig = f.clone();
        recognise_x86_prologue(&mut f);
        assert_eq!(f, orig);
    }

    #[test]
    fn leave_style_epilogue_collapses() {
        // `rsp = rbp; pop rbp; return;`  — the three ops our `leave` lifter
        // emits.
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("rsp"),
                    src: Expr::Reg(reg("rbp")),
                },
                Stmt::Pop { target: reg("rbp") },
                Stmt::Return { value: None },
            ],
        };
        recognise_x86_prologue(&mut f);
        assert_eq!(f.body.len(), 2);
        assert!(matches!(
            &f.body[0],
            Stmt::Comment(s) if s.contains("x86-64 epilogue")
        ));
    }

    #[test]
    fn pop_rbp_then_ret_collapses() {
        // Non-leave functions may just `pop rbp; ret`.
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Pop { target: reg("rbp") },
                Stmt::Return { value: None },
            ],
        };
        recognise_x86_prologue(&mut f);
        assert_eq!(f.body.len(), 2);
        assert!(matches!(&f.body[0], Stmt::Comment(_)));
    }

    fn rsp_add(n: i64) -> Stmt {
        Stmt::Assign {
            dst: reg("rsp"),
            src: Expr::Bin {
                op: BinOp::Add,
                lhs: Box::new(Expr::Reg(reg("rsp"))),
                rhs: Box::new(Expr::Const(n)),
            },
        }
    }

    #[test]
    fn pop_rbp_epilogue_also_swallows_preceding_rsp_add() {
        // `%rsp += 0x20; pop %rbp; return;` collapses.
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                rsp_add(0x20),
                Stmt::Pop { target: reg("rbp") },
                Stmt::Return { value: None },
            ],
        };
        recognise_x86_prologue(&mut f);
        assert_eq!(f.body.len(), 2);
        assert!(matches!(
            &f.body[0],
            Stmt::Comment(s) if s.contains("x86-64 epilogue")
        ));
    }

    #[test]
    fn second_epilogue_round_swallows_rsp_add_before_existing_comment() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                rsp_add(0x20),
                Stmt::Comment("x86-64 epilogue: restore rbp".into()),
                Stmt::Return { value: None },
            ],
        };

        recognise_x86_prologue(&mut f);

        assert_eq!(f.body.len(), 2, "stranded frame teardown: {:#?}", f.body);
        assert!(matches!(&f.body[0], Stmt::Comment(text) if text.contains("epilogue")));
        assert!(matches!(&f.body[1], Stmt::Return { .. }));
    }

    #[test]
    fn second_epilogue_round_finds_rsp_add_before_dead_flag_temporaries() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                rsp_add(0x20),
                Stmt::Assign {
                    dst: VReg::Temp(900),
                    src: Expr::Const(0),
                },
                Stmt::Comment("x86-64 epilogue: restore rbp".into()),
                Stmt::Return { value: None },
            ],
        };

        recognise_x86_prologue(&mut f);

        assert!(
            !f.body.iter().any(is_rsp_add),
            "stranded frame teardown: {:#?}",
            f.body
        );
        assert!(matches!(&f.body[1], Stmt::Comment(text) if text.contains("epilogue")));
        assert!(matches!(&f.body[2], Stmt::Return { .. }));
    }

    #[test]
    fn fomit_frame_pointer_epilogue_collapses() {
        // `%rsp += 8; return;` (no rbp involved) collapses to a teardown comment.
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![rsp_add(8), Stmt::Return { value: None }],
        };
        recognise_x86_prologue(&mut f);
        assert_eq!(f.body.len(), 2);
        assert!(matches!(
            &f.body[0],
            Stmt::Comment(s) if s.contains("tear down frame")
        ));
    }

    #[test]
    fn zero_call_used_x87_scrub_is_machine_epilogue() {
        let mut body = vec![rsp_add(8), rsp_add(8), rsp_add(8)];
        body.extend((0..8).map(|_| Stmt::Unknown("fldz".into())));
        body.extend((0..8).map(|_| Stmt::Unknown("fstp".into())));
        body.push(Stmt::Return {
            value: Some(Expr::Const(-6)),
        });
        let mut f = Function {
            name: "hardened_return".into(),
            entry_va: 0,
            body,
        };

        recognise_x86_prologue(&mut f);

        assert_eq!(f.body.len(), 2, "machine scrub leaked: {:#?}", f.body);
        assert!(matches!(
            &f.body[0],
            Stmt::Comment(text) if text == "x86-64 epilogue: clear call-used x87 and tear down frame"
        ));
        assert!(matches!(
            &f.body[1],
            Stmt::Return {
                value: Some(Expr::Const(-6))
            }
        ));
    }

    #[test]
    fn incomplete_x87_sequence_is_not_discarded_as_machine_epilogue() {
        let mut body = vec![rsp_add(8)];
        body.extend((0..7).map(|_| Stmt::Unknown("fldz".into())));
        body.extend((0..8).map(|_| Stmt::Unknown("fstp".into())));
        body.push(Stmt::Return { value: None });
        let mut f = Function {
            name: "unknown_x87_effect".into(),
            entry_va: 0,
            body: body.clone(),
        };

        recognise_x86_prologue(&mut f);

        assert_eq!(f.body, body);
    }

    #[test]
    fn nops_before_prologue_are_tolerated() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Nop,
                Stmt::Nop,
                push_rbp(),
                mov_rbp_rsp(),
                Stmt::Return { value: None },
            ],
        };
        recognise_x86_prologue(&mut f);
        // Expect: Nop, Nop, Comment, Return.
        assert!(matches!(
            &f.body[2],
            Stmt::Comment(s) if s.contains("x86-64 prologue")
        ));
    }
}
