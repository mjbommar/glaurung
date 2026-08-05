//! Algebraic identity folding over the AST.
//!
//! Rewrites common compiler idioms that obscure the real semantics:
//!
//! | Before           | After |
//! |------------------|-------|
//! | `(X ^ X)`        | `0`   |
//! | `(X - X)`        | `0`   |
//! | `(X & X)`        | `X`   |
//! | `(X \| X)`       | `X`   |
//! | `(X + 0)`        | `X`   |
//! | `(0 + X)`        | `X`   |
//! | `(X - 0)`        | `X`   |
//! | `(X * 1)`        | `X`   |
//! | `(1 * X)`        | `X`   |
//! | `(X * 0)`        | `0`   |
//! | `(X & 0)`        | `0`   |
//! | `(X & -1)`       | `X`   |
//! | `(X \| 0)`       | `X`   |
//! | `X ^ (Y ^ X)`    | `Y`   |
//! | `(X == Y) \| (X < Y)` | `X <= Y` |
//! | `(X < Y) == 0`   | `Y <= X` |
//! | `(c1 op c2)`     | folded constant when the op is safe |
//!
//! The pass is purely syntactic — it doesn't require any dataflow info —
//! and recurses bottom-up so nested patterns collapse in one walk.

use crate::ir::ast::{Expr, Function, Stmt};
use crate::ir::types::{BinOp, CmpOp};
use crate::ir::types_recover::TypeMap;

/// Rewrite `f`'s body in place, folding the patterns above.
pub fn fold_constants(f: &mut Function) {
    fold_body(&mut f.body);
}

/// Remove matching extension pairs from comparisons only when recovered C
/// declarations prove that the uncast operands already have the exact source
/// width and signedness. The untyped algebraic pass cannot make this decision:
/// a zero-extended 32-bit load may live in a default-`long` scratch, and dropping
/// its signed cast changes a negative machine value into a positive C value.
pub fn fold_typed_comparison_extensions(f: &mut Function, tm: &TypeMap) {
    fn declared_source_type(expr: &Expr, signed: bool, width: u8, tm: &TypeMap) -> bool {
        matches!(
            expr,
            Expr::Reg(crate::ir::types::VReg::Phys(name))
                if crate::ir::ast::declared_int_type(name, Some(tm)) == Some((signed, width))
        )
    }

    fn expression(expr: &mut Expr, tm: &TypeMap) {
        match expr {
            Expr::Deref { addr, .. } => expression(addr, tm),
            Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
                expression(lhs, tm);
                expression(rhs, tm);
            }
            Expr::Un { src, .. } => expression(src, tm),
            Expr::Select {
                cond,
                if_true,
                if_false,
                ..
            } => {
                expression(cond, tm);
                expression(if_true, tm);
                expression(if_false, tm);
            }
            Expr::Cast { expr, .. } => expression(expr, tm),
            Expr::FunctionTableEntry { index, .. } => expression(index, tm),
            Expr::WideArithmetic { args, .. } => {
                for argument in args {
                    expression(argument, tm);
                }
            }
            Expr::Reg(_)
            | Expr::FloatConst { .. }
            | Expr::Const(_)
            | Expr::Addr(_)
            | Expr::Named { .. }
            | Expr::StringLit { .. }
            | Expr::StackAddr { .. }
            | Expr::Lea { .. }
            | Expr::PdbFieldAddr { .. }
            | Expr::Unknown(_) => {}
        }

        let Expr::Cmp { op, lhs, rhs } = expr else {
            return;
        };
        let (Some(left), Some(right)) = (
            common_extended_operand(lhs, *op),
            common_extended_operand(rhs, *op),
        ) else {
            return;
        };
        if left.0 == right.0
            && left.1 == right.1
            && left.2 == right.2
            && declared_source_type(left.3, left.0, left.2, tm)
            && declared_source_type(right.3, right.0, right.2, tm)
        {
            **lhs = left.3.clone();
            **rhs = right.3.clone();
        }
    }

    fn body(statements: &mut [Stmt], tm: &TypeMap) {
        for statement in statements {
            match statement {
                Stmt::Assign { src, .. } | Stmt::Return { value: Some(src) } => {
                    expression(src, tm);
                }
                Stmt::Store { addr, src, .. } => {
                    expression(addr, tm);
                    expression(src, tm);
                }
                Stmt::Call { target, args, .. } => {
                    expression(target, tm);
                    for arg in args {
                        expression(arg, tm);
                    }
                }
                Stmt::IndirectGoto { target } | Stmt::Push { value: target } => {
                    expression(target, tm);
                }
                Stmt::If {
                    cond,
                    then_body,
                    else_body,
                } => {
                    expression(cond, tm);
                    body(then_body, tm);
                    if let Some(else_body) = else_body {
                        body(else_body, tm);
                    }
                }
                Stmt::While {
                    cond,
                    body: loop_body,
                }
                | Stmt::DoWhile {
                    cond,
                    body: loop_body,
                } => {
                    expression(cond, tm);
                    body(loop_body, tm);
                }
                Stmt::For {
                    init,
                    cond,
                    step,
                    body: loop_body,
                } => {
                    body(std::slice::from_mut(init.as_mut()), tm);
                    expression(cond, tm);
                    body(std::slice::from_mut(step.as_mut()), tm);
                    body(loop_body, tm);
                }
                Stmt::Switch {
                    discriminant,
                    cases,
                    default,
                } => {
                    expression(discriminant, tm);
                    for (_, case_body) in cases {
                        body(case_body, tm);
                    }
                    if let Some(default) = default {
                        body(default, tm);
                    }
                }
                Stmt::Return { value: None }
                | Stmt::Pop { .. }
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
    }

    body(&mut f.body, tm);
}

/// Remove a matching *zero-extension* view around a register whose recovered C
/// declaration already has the exact inner width and unsignedness.
///
/// The lossless AST retains machine views until types are known. At this late
/// boundary the declaration supplies that view in every rvalue context; the
/// subsequent widening pass reintroduces an explicit extension only where a
/// wider consumer genuinely needs one. Signed extensions must stay explicit:
/// erasing `movsxd` would make the widening pass reconstruct the bare signed
/// declaration as a machine-register zero-extension. Mismatched signedness or
/// width is left untouched as well.
pub fn fold_typed_declared_views(f: &mut Function, tm: &TypeMap) {
    fn expression(expr: &mut Expr, tm: &TypeMap) {
        match expr {
            Expr::Deref { addr, .. } => expression(addr, tm),
            Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
                expression(lhs, tm);
                expression(rhs, tm);
            }
            Expr::Un { src, .. } => expression(src, tm),
            Expr::Select {
                cond,
                if_true,
                if_false,
                ..
            } => {
                expression(cond, tm);
                expression(if_true, tm);
                expression(if_false, tm);
            }
            Expr::Cast { expr, .. } => expression(expr, tm),
            Expr::FunctionTableEntry { index, .. } => expression(index, tm),
            Expr::WideArithmetic { args, .. } => {
                for argument in args {
                    expression(argument, tm);
                }
            }
            Expr::Reg(_)
            | Expr::FloatConst { .. }
            | Expr::Const(_)
            | Expr::Addr(_)
            | Expr::Named { .. }
            | Expr::StringLit { .. }
            | Expr::StackAddr { .. }
            | Expr::Lea { .. }
            | Expr::PdbFieldAddr { .. }
            | Expr::Unknown(_) => {}
        }

        let replacement = match expr {
            Expr::Cast {
                signed: outer_signed,
                width: outer_width,
                expr: inner,
            } => match inner.as_ref() {
                Expr::Cast {
                    signed: inner_signed,
                    width: inner_width,
                    expr: source,
                } if inner_width < outer_width && !*outer_signed && !*inner_signed => {
                    match source.as_ref() {
                        Expr::Reg(crate::ir::types::VReg::Phys(name))
                            if crate::ir::ast::declared_int_type(name, Some(tm))
                                == Some((*inner_signed, *inner_width)) =>
                        {
                            Some(source.as_ref().clone())
                        }
                        _ => None,
                    }
                }
                _ => None,
            },
            _ => None,
        };
        if let Some(replacement) = replacement {
            *expr = replacement;
        }
    }

    fn body(statements: &mut [Stmt], tm: &TypeMap) {
        for statement in statements {
            match statement {
                Stmt::Assign { src, .. } => expression(src, tm),
                Stmt::Store { addr, src, .. } => {
                    expression(addr, tm);
                    expression(src, tm);
                }
                Stmt::Call { target, args, .. } => {
                    expression(target, tm);
                    for arg in args {
                        expression(arg, tm);
                    }
                }
                Stmt::IndirectGoto { target } | Stmt::Push { value: target } => {
                    expression(target, tm);
                }
                Stmt::If {
                    cond,
                    then_body,
                    else_body,
                } => {
                    expression(cond, tm);
                    body(then_body, tm);
                    if let Some(else_body) = else_body {
                        body(else_body, tm);
                    }
                }
                Stmt::While {
                    cond,
                    body: loop_body,
                }
                | Stmt::DoWhile {
                    cond,
                    body: loop_body,
                } => {
                    expression(cond, tm);
                    body(loop_body, tm);
                }
                Stmt::For {
                    init,
                    cond,
                    step,
                    body: loop_body,
                } => {
                    body(std::slice::from_mut(init.as_mut()), tm);
                    expression(cond, tm);
                    body(std::slice::from_mut(step.as_mut()), tm);
                    body(loop_body, tm);
                }
                Stmt::Switch {
                    discriminant,
                    cases,
                    default,
                } => {
                    expression(discriminant, tm);
                    for (_, case_body) in cases {
                        body(case_body, tm);
                    }
                    if let Some(default) = default {
                        body(default, tm);
                    }
                }
                // A root return extension also carries the source-level return
                // width (notably signed-char/short promoted to `int`). Keep it
                // until the signature is bound; erasing it here narrows the
                // declaration even when the expression value is unchanged.
                Stmt::Return { .. }
                | Stmt::Pop { .. }
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
    }

    body(&mut f.body, tm);
}

fn fold_body(body: &mut [Stmt]) {
    for s in body.iter_mut() {
        match s {
            Stmt::IndirectGoto { target } => fold_expr(target),
            Stmt::Assign { src, .. } => fold_expr(src),
            Stmt::Store { addr, src, size } => {
                fold_expr(addr);
                fold_expr(src);
                fold_stored_value(src, *size);
            }
            Stmt::Call { target, args, .. } => {
                fold_expr(target);
                for a in args {
                    fold_expr(a);
                }
            }
            Stmt::Return { value } => {
                if let Some(e) = value {
                    fold_expr(e);
                }
            }
            Stmt::If {
                cond,
                then_body,
                else_body,
            } => {
                fold_expr(cond);
                fold_body(then_body);
                if let Some(eb) = else_body {
                    fold_body(eb);
                }
            }
            Stmt::While { cond, body } => {
                fold_expr(cond);
                fold_body(body);
            }
            Stmt::For {
                init,
                cond,
                step,
                body,
            } => {
                fold_body(std::slice::from_mut(init.as_mut()));
                fold_expr(cond);
                fold_body(body);
                fold_body(std::slice::from_mut(step.as_mut()));
            }
            Stmt::DoWhile { body, cond } => {
                fold_body(body);
                fold_expr(cond);
            }
            Stmt::Push { value } => fold_expr(value),
            Stmt::Switch {
                discriminant,
                cases,
                default,
            } => {
                fold_expr(discriminant);
                for (_, body) in cases.iter_mut() {
                    fold_body(body);
                }
                if let Some(b) = default {
                    fold_body(b);
                }
            }
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
}

fn fold_stored_value(src: &mut Expr, size: u8) {
    if size == 0 {
        return;
    }
    // A machine store observes only its low `size` bytes. Integer casts whose
    // target is at least that wide cannot change those bits, so retaining the
    // zero/sign-extension in source C only changes instruction selection.
    loop {
        let replacement = match src {
            Expr::Cast { width, expr, .. } if *width >= size => Some(expr.as_ref().clone()),
            _ => None,
        };
        let Some(replacement) = replacement else {
            break;
        };
        *src = replacement;
    }

    // Likewise, a mask that keeps every stored low bit is unobservable after
    // the truncating write (`store8(x & 0xff) == store8(x)`).
    let required = if size >= 8 {
        u64::MAX
    } else {
        (1u64 << (u32::from(size) * 8)) - 1
    };
    if let Some(replacement) = fold_observed_mask(src, required as i64) {
        *src = replacement;
        fold_expr(src);
    }
    let replacement = match src {
        Expr::Bin {
            op: BinOp::And,
            lhs,
            rhs,
        } => match (lhs.as_ref(), rhs.as_ref()) {
            (value, Expr::Const(mask)) | (Expr::Const(mask), value)
                if (*mask as u64) & required == required =>
            {
                Some(value.clone())
            }
            _ => None,
        },
        _ => None,
    };
    if let Some(replacement) = replacement {
        *src = replacement;
    }
}

fn fold_expr(e: &mut Expr) {
    // Recurse first — bottom-up folding composes naturally.
    match e {
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            fold_expr(lhs);
            fold_expr(rhs);
        }
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => {
            fold_expr(cond);
            fold_expr(if_true);
            fold_expr(if_false);
        }
        Expr::Un { src, .. } => fold_expr(src),
        Expr::Cast { expr, .. } => fold_expr(expr),
        Expr::Deref { addr, .. } => fold_expr(addr),
        _ => {}
    }

    // `castN(castM(x)) == castN(x)` whenever `M >= N`: the outer cast observes
    // only the low N bits, and an inner cast to an equal-or-wider width cannot
    // have altered them. The inner cast's signedness is irrelevant for the same
    // reason — sign extension only writes bits above M, which N discards.
    //
    // This is the general form of the round-trip rule below, and it is what
    // collapses the chains that actually appear in output:
    // `(unsigned long)((unsigned long)((unsigned int)(...)))`. It must NOT fire
    // when the inner cast narrows (`M < N`), because then the truncation is
    // real and observable.
    let subsumed_inner_cast = match e {
        Expr::Cast {
            signed,
            width,
            expr: inner,
        } => match inner.as_ref() {
            Expr::Cast {
                width: inner_width,
                expr: source,
                ..
            } if inner_width >= width => Some(Expr::Cast {
                signed: *signed,
                width: *width,
                expr: Box::new(source.as_ref().clone()),
            }),
            _ => None,
        },
        _ => None,
    };
    if let Some(replacement) = subsumed_inner_cast {
        *e = replacement;
        // Re-run: a chain of three or more collapses one layer per visit.
        fold_expr(e);
        return;
    }

    // `castN(extW(castN(x))) == castN(x)`: the widening step cannot alter the
    // low N bits that the outer cast immediately observes. Preserve the outer
    // cast's signedness because a later wider consumer may depend on it.
    let narrowed_round_trip = match e {
        Expr::Cast {
            signed,
            width,
            expr: widened,
        } => match widened.as_ref() {
            Expr::Cast {
                width: widened_width,
                expr: original_narrow,
                ..
            } if widened_width > width => match original_narrow.as_ref() {
                Expr::Cast {
                    width: original_width,
                    expr: source,
                    ..
                } if original_width == width => Some(Expr::Cast {
                    signed: *signed,
                    width: *width,
                    expr: Box::new(source.as_ref().clone()),
                }),
                _ => None,
            },
            _ => None,
        },
        _ => None,
    };
    if let Some(replacement) = narrowed_round_trip {
        *e = replacement;
        return;
    }

    // Propagating a pure machine view to more than one use can expose the
    // idempotent composition
    // `extW(castN(extW(castN(x))))`. The first pair already guarantees that
    // the value is a canonical N-bit integer in W bits, so applying the exact
    // same view again cannot change any bit.
    let repeated_view = match e {
        Expr::Cast {
            signed: outer_signed,
            width: outer_width,
            expr: outer_inner,
        } => match outer_inner.as_ref() {
            Expr::Cast {
                signed: inner_signed,
                width: inner_width,
                expr: prior_outer,
            } => match prior_outer.as_ref() {
                Expr::Cast {
                    signed: prior_outer_signed,
                    width: prior_outer_width,
                    expr: prior_inner,
                } => match prior_inner.as_ref() {
                    Expr::Cast {
                        signed: prior_inner_signed,
                        width: prior_inner_width,
                        ..
                    } if outer_signed == prior_outer_signed
                        && outer_width == prior_outer_width
                        && inner_signed == prior_inner_signed
                        && inner_width == prior_inner_width =>
                    {
                        Some(prior_outer.as_ref().clone())
                    }
                    _ => None,
                },
                _ => None,
            },
            _ => None,
        },
        _ => None,
    };
    if let Some(replacement) = repeated_view {
        *e = replacement;
        return;
    }

    // Now try to collapse the current node.
    if let Expr::Cast {
        signed,
        width,
        expr,
    } = e
    {
        let replacement = match expr.as_ref() {
            Expr::Const(value) if cast_preserves_constant(*value, *signed, *width) => {
                Some(Expr::Const(*value))
            }
            // Boolean expressions are exactly zero or one, so every supported
            // integer cast preserves their complete value and signedness is
            // irrelevant. This includes logical trees recovered below, not
            // only a single comparison leaf.
            boolean if *width > 0 && is_exact_boolean(boolean) => Some(boolean.clone()),
            _ => None,
        };
        if let Some(replacement) = replacement {
            *e = replacement;
            return;
        }
    }

    if let Expr::Bin { op, lhs, rhs } = e {
        let op = *op;

        // XOR cancellation through one associative layer.  This is the
        // canonical shape of x86 signed predicates: SF ^ OF, where OF is
        // itself the XOR of a signed comparison and SF.
        if op == BinOp::Xor {
            let replacement = match (lhs.as_ref(), rhs.as_ref()) {
                (
                    a,
                    Expr::Bin {
                        op: BinOp::Xor,
                        lhs: b,
                        rhs: c,
                    },
                ) if a == c.as_ref() => Some(b.as_ref().clone()),
                (
                    a,
                    Expr::Bin {
                        op: BinOp::Xor,
                        lhs: b,
                        rhs: c,
                    },
                ) if a == b.as_ref() => Some(c.as_ref().clone()),
                (
                    Expr::Bin {
                        op: BinOp::Xor,
                        lhs: b,
                        rhs: c,
                    },
                    a,
                ) if a == c.as_ref() => Some(b.as_ref().clone()),
                (
                    Expr::Bin {
                        op: BinOp::Xor,
                        lhs: b,
                        rhs: c,
                    },
                    a,
                ) if a == b.as_ref() => Some(c.as_ref().clone()),
                _ => None,
            };
            if let Some(replacement) = replacement {
                *e = replacement;
                return;
            }
        }

        // Inclusive comparisons are emitted by x86 as equality OR strict
        // comparison.  Recover the source-level relation once both sides use
        // the same operands and signedness.
        if op == BinOp::Or {
            if let Some(replacement) =
                merge_equality_and_less(lhs, rhs).or_else(|| merge_equality_and_less(rhs, lhs))
            {
                *e = replacement;
                return;
            }
        }

        // Observe only the requested bits of nested partial-register merges.
        // This is the algebra behind x86 `setcc al; movzx eax, al`: high bits
        // preserved in the architectural parent cannot affect a later low-byte
        // (or low-bit) read.
        if op == BinOp::And {
            let masked = match (lhs.as_ref(), rhs.as_ref()) {
                (value, Expr::Const(mask)) | (Expr::Const(mask), value) => {
                    fold_observed_mask(value, *mask)
                }
                _ => None,
            };
            if let Some(replacement) = masked {
                *e = replacement;
                // The replacement is strictly shallower (one merge or mask
                // layer disappeared), so finish any newly adjacent identity.
                fold_expr(e);
                return;
            }
        }

        // Same-operand identities (X op X).
        if lhs == rhs {
            match op {
                BinOp::Xor | BinOp::Sub => {
                    *e = Expr::Const(0);
                    return;
                }
                BinOp::And | BinOp::Or => {
                    // (X & X) == X; replace with X.
                    let x = std::mem::replace(lhs.as_mut(), Expr::Const(0));
                    *e = x;
                    return;
                }
                _ => {}
            }
        }

        // Constant-with-anything identities.
        if let Expr::Const(0) = **rhs {
            match op {
                BinOp::Add
                | BinOp::Sub
                | BinOp::Or
                | BinOp::Xor
                | BinOp::Shl
                | BinOp::Shr
                | BinOp::Sar => {
                    let x = std::mem::replace(lhs.as_mut(), Expr::Const(0));
                    *e = x;
                    return;
                }
                BinOp::Mul | BinOp::And => {
                    *e = Expr::Const(0);
                    return;
                }
                BinOp::LogicalOr if is_exact_boolean(lhs) => {
                    let x = std::mem::replace(lhs.as_mut(), Expr::Const(0));
                    *e = x;
                    return;
                }
                _ => {}
            }
        }
        if let Expr::Const(0) = **lhs {
            if matches!(op, BinOp::Add | BinOp::Or | BinOp::Xor) {
                let x = std::mem::replace(rhs.as_mut(), Expr::Const(0));
                *e = x;
                return;
            }
            if matches!(op, BinOp::Mul | BinOp::And) {
                *e = Expr::Const(0);
                return;
            }
            if op == BinOp::LogicalOr && is_exact_boolean(rhs) {
                let x = std::mem::replace(rhs.as_mut(), Expr::Const(0));
                *e = x;
                return;
            }
        }
        if let Expr::Const(1) = **rhs {
            if matches!(op, BinOp::Mul) {
                let x = std::mem::replace(lhs.as_mut(), Expr::Const(0));
                *e = x;
                return;
            }
            if op == BinOp::LogicalAnd && is_exact_boolean(lhs) {
                let x = std::mem::replace(lhs.as_mut(), Expr::Const(0));
                *e = x;
                return;
            }
        }
        if let Expr::Const(1) = **lhs {
            if matches!(op, BinOp::Mul) {
                let x = std::mem::replace(rhs.as_mut(), Expr::Const(0));
                *e = x;
                return;
            }
            if op == BinOp::LogicalAnd && is_exact_boolean(rhs) {
                let x = std::mem::replace(rhs.as_mut(), Expr::Const(0));
                *e = x;
                return;
            }
        }
        if let Expr::Const(-1) = **rhs {
            if matches!(op, BinOp::And) {
                let x = std::mem::replace(lhs.as_mut(), Expr::Const(0));
                *e = x;
                return;
            }
            if matches!(op, BinOp::Or) {
                *e = Expr::Const(-1);
                return;
            }
        }

        // Addr ± Const fold — how AArch64 and ARM32 name a global at all.
        //
        // x86-64 materialises the address of a string or global in one
        // instruction (`lea rax, [rip+disp]`), which lifts straight to
        // `Value::Addr(abs)`, so `name_resolve` and `strings_fold` see a
        // complete VA and do their work. AArch64 needs two: `adrp` supplies the
        // 4 KiB page and a following `add`/`ldr` supplies the low 12 bits. The
        // page alone resolves to nothing, so without this fold every string and
        // global reference on AArch64 stayed an arithmetic expression over a
        // bare number — measured as 0.00 string literals per function on both
        // ARM targets against 5.68 for Ghidra.
        //
        // Only `Add`/`Sub` are folded, and only against an address: an address
        // that has been masked, shifted or multiplied is no longer a reference
        // to the same object, and quietly renaming it would be a lie.
        if matches!(op, BinOp::Add | BinOp::Sub) {
            // A `Named` base folds too, and its name is deliberately DISCARDED.
            // An `adrp` page is a 4 KiB-aligned number that frequently collides
            // with some unrelated symbol's address — `read_counter`'s page
            // resolved to `__cxa_finalize`, so the reference to the volatile
            // counter at page+0x1c printed as `__cxa_finalize + 28` and never
            // folded, leaving a raw original-image address the recompiled C
            // dereferenced as a wild pointer. `base + offset` is a DIFFERENT
            // object from `base`, so carrying the base's name forward would be
            // the same lie the masked-address case below refuses to tell; the
            // folded VA is re-resolved against the symbol table instead.
            let as_base = |e: &Expr| match e {
                Expr::Addr(base) | Expr::Named { va: base, .. } => Some(*base),
                _ => None,
            };
            let addr_and_offset = match (lhs.as_ref(), rhs.as_ref()) {
                (base, Expr::Const(off)) if as_base(base).is_some() => {
                    as_base(base).map(|base| (base, *off))
                }
                // `Const + Addr` is the same value; `Const - Addr` is not an
                // address at all, so it is deliberately not matched.
                (Expr::Const(off), base) if matches!(op, BinOp::Add) => {
                    as_base(base).map(|base| (base, *off))
                }
                _ => None,
            };
            if let Some((base, off)) = addr_and_offset {
                let folded = if matches!(op, BinOp::Add) {
                    base.wrapping_add(off as u64)
                } else {
                    base.wrapping_sub(off as u64)
                };
                *e = Expr::Addr(folded);
                return;
            }
        }

        // Const × Const fold.
        if let (Expr::Const(a), Expr::Const(b)) = (lhs.as_ref(), rhs.as_ref()) {
            let (a, b) = (*a, *b);
            let folded = match op {
                BinOp::Add => a.wrapping_add(b),
                BinOp::Sub => a.wrapping_sub(b),
                BinOp::Mul => a.wrapping_mul(b),
                BinOp::Div => {
                    if b == 0 {
                        return;
                    }
                    a.wrapping_div(b)
                }
                BinOp::LogicalAnd => i64::from(a != 0 && b != 0),
                BinOp::LogicalOr => i64::from(a != 0 || b != 0),
                BinOp::And => a & b,
                BinOp::Or => a | b,
                BinOp::Xor => a ^ b,
                BinOp::Shl => {
                    if (0..64).contains(&b) {
                        a.wrapping_shl(b as u32)
                    } else {
                        return;
                    }
                }
                BinOp::Shr => {
                    if (0..64).contains(&b) {
                        ((a as u64) >> (b as u32)) as i64
                    } else {
                        return;
                    }
                }
                BinOp::Sar => {
                    if (0..64).contains(&b) {
                        a.wrapping_shr(b as u32)
                    } else {
                        return;
                    }
                }
            };
            *e = Expr::Const(folded);
        }
    }

    // Comparisons are boolean-valued.  Comparing one to zero is logical
    // negation, not a bitwise operation; invert it into the corresponding
    // relation so it remains readable and type-correct.
    if let Expr::Cmp { op, lhs, rhs } = e {
        // Subtraction sets x86's zero flag: `(X - Y) == 0` is exactly
        // `X == Y` (and likewise for `!=`) in modular machine arithmetic.
        // Recover that relation before merging ZF with CF/SF into inclusive
        // comparisons below.
        let subtraction_relation = match (&*op, lhs.as_ref(), rhs.as_ref()) {
            (
                op @ (CmpOp::Eq | CmpOp::Ne),
                Expr::Bin {
                    op: BinOp::Sub,
                    lhs: sub_lhs,
                    rhs: sub_rhs,
                },
                Expr::Const(0),
            ) => Some(Expr::Cmp {
                op: *op,
                lhs: sub_lhs.clone(),
                rhs: sub_rhs.clone(),
            }),
            (
                op @ (CmpOp::Eq | CmpOp::Ne),
                Expr::Const(0),
                Expr::Bin {
                    op: BinOp::Sub,
                    lhs: sub_lhs,
                    rhs: sub_rhs,
                },
            ) => Some(Expr::Cmp {
                op: *op,
                lhs: sub_lhs.clone(),
                rhs: sub_rhs.clone(),
            }),
            _ => None,
        };
        if let Some(replacement) = subtraction_relation {
            *e = replacement;
            return;
        }

        // Clang sometimes lowers a source-level short-circuit guard into a
        // byte-valued SETcc tree, combines it eagerly, then widens and tests the
        // result. The byte view is the crucial provenance: a bare `cmp | cmp`
        // can just as legitimately be source-level bitwise C — and, far more
        // often here, is our OWN flag model for `jle`/`jbe`, which
        // `bool_guard` recovers as one inclusive comparison rather than two
        // short-circuit operands. Dropping the byte-view requirement would turn
        // every such flag pair into a `||` and invent a basic block the source
        // never had. Recover only the complete terminal test, and only when
        // every leaf is side-effect-free.
        //
        // Both polarities are accepted. The compiler picks whichever of
        // `jne`/`je` reaches the arm it wants, so the same eager tree arrives
        // tested against zero in either direction; `== 0` is De Morgan's exact
        // negation of the same recovered guard.
        let zero_test_polarity = *op;
        if matches!(zero_test_polarity, CmpOp::Ne | CmpOp::Eq) {
            let candidate = match (lhs.as_ref(), rhs.as_ref()) {
                (candidate, Expr::Const(0)) | (Expr::Const(0), candidate) => {
                    recover_eager_boolean_guard(candidate)
                }
                _ => None,
            };
            if let Some((logical, leaves, saw_byte_view)) = candidate {
                if leaves >= 2 && saw_byte_view {
                    let recovered = if zero_test_polarity == CmpOp::Ne {
                        Some(logical)
                    } else {
                        negate_logical_tree(&logical)
                    };
                    if let Some(recovered) = recovered {
                        *e = recovered;
                        return;
                    }
                }
            }
        }

        let inner = match (lhs.as_ref(), rhs.as_ref()) {
            (inner, Expr::Const(0)) | (Expr::Const(0), inner) if is_exact_boolean(inner) => {
                Some(inner)
            }
            _ => None,
        };
        if let Some(inner) = inner {
            let replacement = match (op, inner) {
                (CmpOp::Ne, boolean) => Some(boolean.clone()),
                (
                    CmpOp::Eq,
                    Expr::Cmp {
                        op: inner_op,
                        lhs: inner_lhs,
                        rhs: inner_rhs,
                    },
                ) => Some(invert_comparison(*inner_op, inner_lhs, inner_rhs)),
                _ => None,
            };
            if let Some(replacement) = replacement {
                *e = replacement;
            }
        }
    }
}

fn cast_preserves_constant(value: i64, signed: bool, width: u8) -> bool {
    let bits = u32::from(width) * 8;
    if bits == 0 || bits > 64 {
        return false;
    }
    if signed {
        if bits == 64 {
            true
        } else {
            let limit = 1i64 << (bits - 1);
            (-limit..limit).contains(&value)
        }
    } else if bits == 64 {
        value >= 0
    } else {
        value >= 0 && (value as u64) < (1u64 << bits)
    }
}

/// Whether an expression's complete integer value is provably either zero or
/// one. This is a value fact only; callers that change evaluation order must
/// additionally use [`is_short_circuit_safe_boolean`].
fn is_exact_boolean(expr: &Expr) -> bool {
    match expr {
        Expr::Cmp { .. } => true,
        Expr::Const(value) => matches!(value, 0 | 1),
        Expr::Cast { width, expr, .. } => *width > 0 && is_exact_boolean(expr),
        Expr::Bin {
            op: BinOp::LogicalAnd | BinOp::LogicalOr,
            lhs,
            rhs,
        } => is_exact_boolean(lhs) && is_exact_boolean(rhs),
        _ => false,
    }
}

/// A boolean whose evaluation is free of memory reads and machine operations
/// that can trap. Such an expression may safely move from eager bitwise
/// evaluation to C short-circuit evaluation without changing observable
/// behavior.
fn is_short_circuit_safe_boolean(expr: &Expr) -> bool {
    match expr {
        Expr::Cmp { lhs, rhs, .. } => {
            is_short_circuit_safe_value(lhs) && is_short_circuit_safe_value(rhs)
        }
        Expr::Const(value) => matches!(value, 0 | 1),
        Expr::Cast { width, expr, .. } => *width > 0 && is_short_circuit_safe_boolean(expr),
        Expr::Bin {
            op: BinOp::LogicalAnd | BinOp::LogicalOr,
            lhs,
            rhs,
        } => is_short_circuit_safe_boolean(lhs) && is_short_circuit_safe_boolean(rhs),
        _ => false,
    }
}

fn is_short_circuit_safe_value(expr: &Expr) -> bool {
    match expr {
        Expr::Reg(_)
        | Expr::Const(_)
        | Expr::FloatConst { .. }
        | Expr::Addr(_)
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::StackAddr { .. }
        | Expr::Lea { .. }
        | Expr::PdbFieldAddr { .. } => true,
        Expr::Cast { expr, .. } | Expr::Un { src: expr, .. } => is_short_circuit_safe_value(expr),
        Expr::Bin { op, lhs, rhs } => {
            *op != BinOp::Div
                && is_short_circuit_safe_value(lhs)
                && is_short_circuit_safe_value(rhs)
        }
        Expr::Cmp { lhs, rhs, .. } => {
            is_short_circuit_safe_value(lhs) && is_short_circuit_safe_value(rhs)
        }
        Expr::Deref { .. }
        | Expr::FunctionTableEntry { .. }
        | Expr::Select { .. }
        | Expr::WideArithmetic { .. }
        | Expr::Unknown(_) => false,
    }
}

/// Recover a complete eager boolean tree that feeds an explicit `!= 0` test.
/// The tuple carries the logical expression, predicate-leaf count, and whether
/// the machine tree included a byte cast/mask characteristic of SETcc output.
fn recover_eager_boolean_guard(expr: &Expr) -> Option<(Expr, usize, bool)> {
    match expr {
        comparison @ Expr::Cmp { .. } if is_short_circuit_safe_boolean(comparison) => {
            Some((comparison.clone(), 1, false))
        }
        Expr::Cast {
            width, expr: inner, ..
        } => {
            let (logical, leaves, saw_byte_view) = recover_eager_boolean_guard(inner)?;
            Some((logical, leaves, saw_byte_view || *width == 1))
        }
        Expr::Bin {
            op: BinOp::And,
            lhs,
            rhs,
        } => {
            let masked = match (lhs.as_ref(), rhs.as_ref()) {
                (inner, Expr::Const(mask)) | (Expr::Const(mask), inner) if mask & 1 == 1 => {
                    Some((inner, *mask))
                }
                _ => None,
            };
            if let Some((inner, mask)) = masked {
                let (logical, leaves, saw_byte_view) = recover_eager_boolean_guard(inner)?;
                return Some((logical, leaves, saw_byte_view || mask == 255));
            }
            recover_eager_boolean_pair(BinOp::LogicalAnd, lhs, rhs)
        }
        Expr::Bin {
            op: BinOp::Or,
            lhs,
            rhs,
        } => recover_eager_boolean_pair(BinOp::LogicalOr, lhs, rhs),
        _ => None,
    }
}

fn recover_eager_boolean_pair(
    logical_op: BinOp,
    lhs: &Expr,
    rhs: &Expr,
) -> Option<(Expr, usize, bool)> {
    let (lhs, lhs_leaves, lhs_byte_view) = recover_eager_boolean_guard(lhs)?;
    let (rhs, rhs_leaves, rhs_byte_view) = recover_eager_boolean_guard(rhs)?;
    Some((
        Expr::Bin {
            op: logical_op,
            lhs: Box::new(lhs),
            rhs: Box::new(rhs),
        },
        lhs_leaves + rhs_leaves,
        lhs_byte_view || rhs_byte_view,
    ))
}

/// `(outer)(inner)x` when both casts have the signedness required by `op` and
/// strictly widen from the common inner machine width. Returns the cast shape
/// plus `x`, allowing the caller to prove both operands use the same extension.
fn common_extended_operand(expr: &Expr, op: CmpOp) -> Option<(bool, u8, u8, &Expr)> {
    let Expr::Cast {
        signed: outer_signed,
        width: outer_width,
        expr: outer_expr,
    } = expr
    else {
        return None;
    };
    let Expr::Cast {
        signed: inner_signed,
        width: inner_width,
        expr: inner_expr,
    } = outer_expr.as_ref()
    else {
        return None;
    };
    if outer_signed != inner_signed || inner_width >= outer_width {
        return None;
    }
    let signedness_matches = match op {
        CmpOp::Slt | CmpOp::Sle => *outer_signed,
        CmpOp::Ult | CmpOp::Ule => !*outer_signed,
        CmpOp::Eq | CmpOp::Ne => true,
    };
    signedness_matches.then_some((
        *outer_signed,
        *outer_width,
        *inner_width,
        inner_expr.as_ref(),
    ))
}

fn fold_observed_mask(value: &Expr, observed_mask: i64) -> Option<Expr> {
    // Boolean expressions are exactly 0 or 1. Only the low bit of the mask
    // matters, including for a recovered logical predicate tree.
    if is_exact_boolean(value) {
        return Some(if observed_mask & 1 == 1 {
            value.clone()
        } else {
            Expr::Const(0)
        });
    }

    // `(X & A) & B == X & (A & B)`; combining the constants exposes both
    // zero masks and boolean low-bit reads.
    if let Some((inner, inner_mask)) = and_with_constant(value) {
        return Some(Expr::Bin {
            op: BinOp::And,
            lhs: Box::new(inner.clone()),
            rhs: Box::new(Expr::Const(inner_mask & observed_mask)),
        });
    }

    // `((X & KEEP) | Y) & OBSERVED == Y & OBSERVED` when KEEP and OBSERVED
    // are disjoint. Handle either OR ordering; no assumption about Y is needed.
    if let Expr::Bin {
        op: BinOp::Or,
        lhs,
        rhs,
    } = value
    {
        if masked_term_is_disjoint(lhs, observed_mask) {
            return Some(Expr::Bin {
                op: BinOp::And,
                lhs: rhs.clone(),
                rhs: Box::new(Expr::Const(observed_mask)),
            });
        }
        if masked_term_is_disjoint(rhs, observed_mask) {
            return Some(Expr::Bin {
                op: BinOp::And,
                lhs: lhs.clone(),
                rhs: Box::new(Expr::Const(observed_mask)),
            });
        }
    }
    None
}

fn and_with_constant(expr: &Expr) -> Option<(&Expr, i64)> {
    let Expr::Bin {
        op: BinOp::And,
        lhs,
        rhs,
    } = expr
    else {
        return None;
    };
    match (lhs.as_ref(), rhs.as_ref()) {
        (value, Expr::Const(mask)) | (Expr::Const(mask), value) => Some((value, *mask)),
        _ => None,
    }
}

fn masked_term_is_disjoint(expr: &Expr, observed_mask: i64) -> bool {
    and_with_constant(expr).is_some_and(|(_, mask)| mask & observed_mask == 0)
}

fn merge_equality_and_less(equality: &Expr, less: &Expr) -> Option<Expr> {
    let Expr::Cmp {
        op: CmpOp::Eq,
        lhs: equality_lhs,
        rhs: equality_rhs,
    } = equality
    else {
        return None;
    };
    let Expr::Cmp {
        op,
        lhs: less_lhs,
        rhs: less_rhs,
    } = less
    else {
        return None;
    };
    // Keep cast signedness as comparison provenance.  Treating equal-width
    // signed and unsigned views as interchangeable here is value-correct for
    // the equality alone, but prematurely rewrites GCC switch range flags into
    // inequalities and destroys the comparison ladder before switch recovery.
    if equality_lhs != less_lhs || equality_rhs != less_rhs {
        return None;
    }
    let op = match op {
        CmpOp::Slt => CmpOp::Sle,
        CmpOp::Ult => CmpOp::Ule,
        _ => return None,
    };
    Some(Expr::Cmp {
        op,
        lhs: equality_lhs.clone(),
        rhs: equality_rhs.clone(),
    })
}

/// De Morgan's exact negation of a recovered short-circuit tree.
///
/// `!(a && b)` is `!a || !b` and `!(a || b)` is `!a && !b`. Both are exact
/// whenever every leaf is 0/1-valued, which a tree from
/// [`recover_eager_boolean_guard`] always is: its leaves are [`Expr::Cmp`] nodes
/// that passed [`is_short_circuit_safe_boolean`]. Leaf negation goes through
/// [`invert_comparison`], which swaps operands instead of introducing a bitwise
/// `~` (always true on a 0/1 boolean) and never reinterprets a signed relation
/// as an unsigned one. Any leaf that is not a comparison returns `None` rather
/// than being guessed at, so the caller keeps the eager form.
fn negate_logical_tree(expr: &Expr) -> Option<Expr> {
    match expr {
        Expr::Cmp { op, lhs, rhs } => Some(invert_comparison(*op, lhs, rhs)),
        Expr::Bin {
            op: op @ (BinOp::LogicalAnd | BinOp::LogicalOr),
            lhs,
            rhs,
        } => Some(Expr::Bin {
            op: if *op == BinOp::LogicalAnd {
                BinOp::LogicalOr
            } else {
                BinOp::LogicalAnd
            },
            lhs: Box::new(negate_logical_tree(lhs)?),
            rhs: Box::new(negate_logical_tree(rhs)?),
        }),
        _ => None,
    }
}

fn invert_comparison(op: CmpOp, lhs: &Expr, rhs: &Expr) -> Expr {
    let (op, lhs, rhs) = match op {
        CmpOp::Eq => (CmpOp::Ne, lhs, rhs),
        CmpOp::Ne => (CmpOp::Eq, lhs, rhs),
        CmpOp::Slt => (CmpOp::Sle, rhs, lhs),
        CmpOp::Sle => (CmpOp::Slt, rhs, lhs),
        CmpOp::Ult => (CmpOp::Ule, rhs, lhs),
        CmpOp::Ule => (CmpOp::Ult, rhs, lhs),
    };
    Expr::Cmp {
        op,
        lhs: Box::new(lhs.clone()),
        rhs: Box::new(rhs.clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::ast::{Expr, Function, Stmt};
    use crate::ir::types::VReg;

    fn reg(n: &str) -> VReg {
        VReg::phys(n)
    }
    fn bin(op: BinOp, lhs: Expr, rhs: Expr) -> Expr {
        Expr::Bin {
            op,
            lhs: Box::new(lhs),
            rhs: Box::new(rhs),
        }
    }

    fn one_stmt(src: Expr) -> Function {
        Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![Stmt::Assign {
                dst: reg("rax"),
                src,
            }],
        }
    }

    #[test]
    fn xor_self_collapses_to_zero() {
        let mut f = one_stmt(bin(
            BinOp::Xor,
            Expr::Reg(reg("rax")),
            Expr::Reg(reg("rax")),
        ));
        fold_constants(&mut f);
        if let Stmt::Assign { src, .. } = &f.body[0] {
            assert_eq!(*src, Expr::Const(0));
        }
    }

    #[test]
    fn sub_self_collapses_to_zero() {
        let mut f = one_stmt(bin(
            BinOp::Sub,
            Expr::Reg(reg("rax")),
            Expr::Reg(reg("rax")),
        ));
        fold_constants(&mut f);
        if let Stmt::Assign { src, .. } = &f.body[0] {
            assert_eq!(*src, Expr::Const(0));
        }
    }

    #[test]
    fn and_self_collapses_to_operand() {
        let mut f = one_stmt(bin(
            BinOp::And,
            Expr::Reg(reg("rax")),
            Expr::Reg(reg("rax")),
        ));
        fold_constants(&mut f);
        if let Stmt::Assign { src, .. } = &f.body[0] {
            assert_eq!(*src, Expr::Reg(reg("rax")));
        }
    }

    #[test]
    fn add_zero_collapses_to_operand() {
        let mut f = one_stmt(bin(BinOp::Add, Expr::Reg(reg("rbx")), Expr::Const(0)));
        fold_constants(&mut f);
        if let Stmt::Assign { src, .. } = &f.body[0] {
            assert_eq!(*src, Expr::Reg(reg("rbx")));
        }
    }

    #[test]
    fn mul_one_left_and_right_collapse() {
        let mut f = one_stmt(bin(BinOp::Mul, Expr::Const(1), Expr::Reg(reg("rcx"))));
        fold_constants(&mut f);
        if let Stmt::Assign { src, .. } = &f.body[0] {
            assert_eq!(*src, Expr::Reg(reg("rcx")));
        }
        let mut g = one_stmt(bin(BinOp::Mul, Expr::Reg(reg("rcx")), Expr::Const(1)));
        fold_constants(&mut g);
        if let Stmt::Assign { src, .. } = &g.body[0] {
            assert_eq!(*src, Expr::Reg(reg("rcx")));
        }
    }

    #[test]
    fn mul_zero_and_and_zero_collapse_to_zero() {
        let mut f = one_stmt(bin(BinOp::Mul, Expr::Reg(reg("rcx")), Expr::Const(0)));
        fold_constants(&mut f);
        if let Stmt::Assign { src, .. } = &f.body[0] {
            assert_eq!(*src, Expr::Const(0));
        }
        let mut g = one_stmt(bin(BinOp::And, Expr::Reg(reg("rcx")), Expr::Const(0)));
        fold_constants(&mut g);
        if let Stmt::Assign { src, .. } = &g.body[0] {
            assert_eq!(*src, Expr::Const(0));
        }
    }

    #[test]
    fn and_minus_one_collapses_to_operand() {
        let mut f = one_stmt(bin(BinOp::And, Expr::Reg(reg("rcx")), Expr::Const(-1)));
        fold_constants(&mut f);
        if let Stmt::Assign { src, .. } = &f.body[0] {
            assert_eq!(*src, Expr::Reg(reg("rcx")));
        }
    }

    #[test]
    fn const_times_const_folds() {
        let mut f = one_stmt(bin(BinOp::Add, Expr::Const(2), Expr::Const(3)));
        fold_constants(&mut f);
        if let Stmt::Assign { src, .. } = &f.body[0] {
            assert_eq!(*src, Expr::Const(5));
        }
    }

    /// `adrp` + `add` must reassemble into one address.
    ///
    /// This is the AArch64 spelling of `lea rax, [rip+disp]`, and without the
    /// fold the low 12 bits never rejoin the page, so no string or global on
    /// AArch64 ever resolves to a name.
    #[test]
    fn addr_plus_const_folds_to_the_addressed_va() {
        let mut f = one_stmt(bin(BinOp::Add, Expr::Addr(0x1f000), Expr::Const(0x2a8)));
        fold_constants(&mut f);
        let Stmt::Assign { src, .. } = &f.body[0] else {
            panic!("expected assignment");
        };
        assert_eq!(*src, Expr::Addr(0x1f2a8));
    }

    /// A NAMED base folds too, and loses the name.
    ///
    /// An `adrp` page is 4 KiB-aligned and routinely collides with an unrelated
    /// symbol: `read_counter`'s page resolved to `__cxa_finalize`, so the
    /// volatile counter at page+0x1c printed as `__cxa_finalize + 28`, never
    /// folded, and the recovered C dereferenced a raw original-image address.
    /// `base + offset` is a different object from `base`, so the name must not
    /// survive the fold — the resulting VA is re-resolved on its own merits.
    #[test]
    fn a_named_page_base_plus_const_folds_to_the_addressed_va() {
        let mut f = one_stmt(bin(
            BinOp::Add,
            Expr::Named {
                va: 0x20000,
                name: "__cxa_finalize".into(),
            },
            Expr::Const(0x1c),
        ));
        fold_constants(&mut f);
        let Stmt::Assign { src, .. } = &f.body[0] else {
            panic!("expected assignment");
        };
        assert_eq!(*src, Expr::Addr(0x2001c));
    }

    /// Operand order is irrelevant to the value, so both spellings must fold.
    #[test]
    fn const_plus_addr_folds_the_same_way() {
        let mut f = one_stmt(bin(BinOp::Add, Expr::Const(0x2a8), Expr::Addr(0x1f000)));
        fold_constants(&mut f);
        let Stmt::Assign { src, .. } = &f.body[0] else {
            panic!("expected assignment");
        };
        assert_eq!(*src, Expr::Addr(0x1f2a8));
    }

    /// An address that has been masked is no longer a reference to that object,
    /// so folding it into a new address would invent a symbol.
    #[test]
    fn addr_under_non_additive_arithmetic_is_left_alone() {
        let original = bin(BinOp::And, Expr::Addr(0x1f2a8), Expr::Const(0xfff));
        let mut f = one_stmt(original.clone());
        fold_constants(&mut f);
        let Stmt::Assign { src, .. } = &f.body[0] else {
            panic!("expected assignment");
        };
        assert!(
            !matches!(src, Expr::Addr(_)),
            "masked address must not become an address literal: {src:?}"
        );
    }

    #[test]
    fn nested_xor_self_inside_larger_expression() {
        // (rax + (rcx ^ rcx))  →  (rax + 0)  →  rax
        let mut f = one_stmt(bin(
            BinOp::Add,
            Expr::Reg(reg("rax")),
            bin(BinOp::Xor, Expr::Reg(reg("rcx")), Expr::Reg(reg("rcx"))),
        ));
        fold_constants(&mut f);
        if let Stmt::Assign { src, .. } = &f.body[0] {
            assert_eq!(*src, Expr::Reg(reg("rax")));
        }
    }

    #[test]
    fn xor_cancellation_recovers_signed_relation() {
        let less = Expr::Cmp {
            op: CmpOp::Slt,
            lhs: Box::new(Expr::Reg(reg("rax"))),
            rhs: Box::new(Expr::Reg(reg("rbx"))),
        };
        let sign = Expr::Reg(reg("sf"));
        let mut f = one_stmt(bin(
            BinOp::Xor,
            sign.clone(),
            bin(BinOp::Xor, less.clone(), sign),
        ));
        fold_constants(&mut f);
        if let Stmt::Assign { src, .. } = &f.body[0] {
            assert_eq!(*src, less);
        }
    }

    #[test]
    fn equality_or_less_merges_to_less_equal() {
        let lhs = Expr::Reg(reg("rax"));
        let rhs = Expr::Reg(reg("rbx"));
        let mut f = one_stmt(bin(
            BinOp::Or,
            Expr::Cmp {
                op: CmpOp::Eq,
                lhs: Box::new(lhs.clone()),
                rhs: Box::new(rhs.clone()),
            },
            Expr::Cmp {
                op: CmpOp::Slt,
                lhs: Box::new(lhs.clone()),
                rhs: Box::new(rhs.clone()),
            },
        ));
        fold_constants(&mut f);
        if let Stmt::Assign { src, .. } = &f.body[0] {
            assert_eq!(
                *src,
                Expr::Cmp {
                    op: CmpOp::Sle,
                    lhs: Box::new(lhs),
                    rhs: Box::new(rhs),
                }
            );
        }
    }

    #[test]
    fn equality_view_signedness_blocks_premature_inclusive_comparison() {
        fn view(expr: Expr, signed: bool) -> Expr {
            Expr::Cast {
                signed,
                width: 8,
                expr: Box::new(Expr::Cast {
                    signed,
                    width: 4,
                    expr: Box::new(expr),
                }),
            }
        }

        let lhs = Expr::Reg(reg("lhs"));
        let rhs = Expr::Reg(reg("rhs"));
        let expression = bin(
            BinOp::Or,
            Expr::Cmp {
                op: CmpOp::Eq,
                lhs: Box::new(view(lhs.clone(), false)),
                rhs: Box::new(view(rhs.clone(), false)),
            },
            Expr::Cmp {
                op: CmpOp::Slt,
                lhs: Box::new(view(lhs.clone(), true)),
                rhs: Box::new(view(rhs.clone(), true)),
            },
        );
        let mut function = one_stmt(expression.clone());

        fold_constants(&mut function);

        let Stmt::Assign { src, .. } = &function.body[0] else {
            panic!("fixture assignment disappeared: {:#?}", function.body);
        };
        assert_eq!(src, &expression);
    }

    #[test]
    fn x86_below_or_equal_flag_identity_recovers_unsigned_less_equal() {
        let lhs = Expr::Reg(reg("state"));
        let rhs = Expr::Const(3);
        let mut f = one_stmt(Expr::Cmp {
            op: CmpOp::Ne,
            lhs: Box::new(bin(
                BinOp::Or,
                Expr::Cmp {
                    op: CmpOp::Ult,
                    lhs: Box::new(lhs.clone()),
                    rhs: Box::new(rhs.clone()),
                },
                Expr::Cmp {
                    op: CmpOp::Eq,
                    lhs: Box::new(bin(BinOp::Sub, lhs.clone(), rhs.clone())),
                    rhs: Box::new(Expr::Const(0)),
                },
            )),
            rhs: Box::new(Expr::Const(0)),
        });

        fold_constants(&mut f);

        let Stmt::Assign { src, .. } = &f.body[0] else {
            panic!("expected assignment")
        };
        assert_eq!(
            *src,
            Expr::Cmp {
                op: CmpOp::Ule,
                lhs: Box::new(lhs),
                rhs: Box::new(rhs),
            }
        );
    }

    #[test]
    fn masked_partial_register_merge_keeps_only_the_observed_low_bit() {
        let old = Expr::Reg(reg("old_parent"));
        let predicate = Expr::Cmp {
            op: CmpOp::Eq,
            lhs: Box::new(Expr::Reg(reg("state"))),
            rhs: Box::new(Expr::Const(3)),
        };
        let merged = bin(
            BinOp::Or,
            bin(BinOp::And, old, Expr::Const(-256)),
            bin(
                BinOp::And,
                bin(BinOp::And, predicate.clone(), Expr::Const(255)),
                Expr::Const(1),
            ),
        );
        let mut f = one_stmt(bin(BinOp::And, merged, Expr::Const(255)));

        fold_constants(&mut f);

        let Stmt::Assign { src, .. } = &f.body[0] else {
            panic!("expected assignment")
        };
        assert_eq!(*src, predicate);
    }

    #[test]
    fn casts_of_in_range_constants_and_predicates_keep_the_same_value() {
        let predicate = Expr::Cmp {
            op: CmpOp::Eq,
            lhs: Box::new(Expr::Reg(reg("state"))),
            rhs: Box::new(Expr::Const(3)),
        };
        let mut zero = one_stmt(Expr::Cast {
            signed: false,
            width: 8,
            expr: Box::new(Expr::Cast {
                signed: false,
                width: 4,
                expr: Box::new(Expr::Const(0)),
            }),
        });
        let mut boolean = one_stmt(Expr::Cast {
            signed: false,
            width: 4,
            expr: Box::new(Expr::Cast {
                signed: false,
                width: 1,
                expr: Box::new(predicate.clone()),
            }),
        });

        fold_constants(&mut zero);
        fold_constants(&mut boolean);

        assert!(matches!(
            zero.body[0],
            Stmt::Assign {
                src: Expr::Const(0),
                ..
            }
        ));
        assert!(matches!(
            &boolean.body[0],
            Stmt::Assign { src, .. } if src == &predicate
        ));
    }

    #[test]
    fn repeated_identical_machine_view_collapses_to_one_view() {
        let view = Expr::Cast {
            signed: false,
            width: 8,
            expr: Box::new(Expr::Cast {
                signed: false,
                width: 4,
                expr: Box::new(Expr::Reg(reg("arg0"))),
            }),
        };
        let mut f = one_stmt(Expr::Cast {
            signed: false,
            width: 8,
            expr: Box::new(Expr::Cast {
                signed: false,
                width: 4,
                expr: Box::new(view.clone()),
            }),
        });

        fold_constants(&mut f);

        assert!(matches!(
            &f.body[0],
            Stmt::Assign { src, .. } if src == &view
        ));
    }

    #[test]
    fn narrowing_after_a_same_width_extension_discards_the_round_trip() {
        let expected = Expr::Cast {
            signed: true,
            width: 8,
            expr: Box::new(Expr::Cast {
                signed: true,
                width: 4,
                expr: Box::new(Expr::Reg(reg("arg0"))),
            }),
        };
        let mut f = one_stmt(Expr::Cast {
            signed: true,
            width: 8,
            expr: Box::new(Expr::Cast {
                signed: true,
                width: 4,
                expr: Box::new(Expr::Cast {
                    signed: false,
                    width: 8,
                    expr: Box::new(Expr::Cast {
                        signed: false,
                        width: 4,
                        expr: Box::new(Expr::Reg(reg("arg0"))),
                    }),
                }),
            }),
        });

        fold_constants(&mut f);

        assert!(matches!(
            &f.body[0],
            Stmt::Assign { src, .. } if src == &expected
        ));
    }

    #[test]
    fn exact_typed_register_view_is_removed_before_contextual_widening() {
        use crate::ir::types_recover::{TypeHint, TypeMap};

        let mut f = one_stmt(Expr::Cast {
            signed: false,
            width: 8,
            expr: Box::new(Expr::Cast {
                signed: false,
                width: 4,
                expr: Box::new(Expr::Reg(reg("arg0"))),
            }),
        });
        let mut tm = TypeMap::default();
        tm.upsert_public(
            reg("arg0"),
            TypeHint::Int {
                signed: false,
                width: 4,
            },
        );

        fold_typed_declared_views(&mut f, &tm);

        assert!(matches!(
            &f.body[0],
            Stmt::Assign {
                src: Expr::Reg(source),
                ..
            } if source == &reg("arg0")
        ));
    }

    #[test]
    fn narrow_fact_does_not_erase_a_machine_word_locals_comparison_view() {
        use crate::ir::types_recover::{TypeHint, TypeMap};

        // The DecBench renderer deliberately keeps raw machine roles such as
        // `ret` declared as `long`: one physical return register can carry a
        // canary, loop counter, and final ABI result in the same function.  A
        // value-specific 32-bit fact therefore cannot make the C declaration
        // narrow, and must not erase this zero-extension before a comparison.
        let view = Expr::Cast {
            signed: false,
            width: 8,
            expr: Box::new(Expr::Cast {
                signed: false,
                width: 4,
                expr: Box::new(Expr::Reg(reg("ret"))),
            }),
        };
        let mut f = one_stmt(Expr::Cmp {
            op: CmpOp::Ne,
            lhs: Box::new(view.clone()),
            rhs: Box::new(Expr::Const(0xffff_ffff)),
        });
        let mut tm = TypeMap::default();
        tm.upsert_public(
            reg("ret"),
            TypeHint::Int {
                signed: false,
                width: 4,
            },
        );

        fold_typed_declared_views(&mut f, &tm);

        assert!(
            matches!(
                &f.body[0],
                Stmt::Assign {
                    src: Expr::Cmp { lhs, .. },
                    ..
                } if lhs.as_ref() == &view
            ),
            "machine-word local lost its narrowing view: {f:#?}"
        );
    }

    #[test]
    fn typed_register_view_with_different_signedness_is_preserved() {
        use crate::ir::types_recover::{TypeHint, TypeMap};

        let view = Expr::Cast {
            signed: false,
            width: 8,
            expr: Box::new(Expr::Cast {
                signed: false,
                width: 4,
                expr: Box::new(Expr::Reg(reg("arg0"))),
            }),
        };
        let mut f = one_stmt(view.clone());
        let mut tm = TypeMap::default();
        tm.upsert_public(
            reg("arg0"),
            TypeHint::Int {
                signed: true,
                width: 4,
            },
        );

        fold_typed_declared_views(&mut f, &tm);

        assert!(matches!(
            &f.body[0],
            Stmt::Assign { src, .. } if src == &view
        ));
    }

    #[test]
    fn typed_declared_view_keeps_a_return_promotion_explicit() {
        use crate::ir::types_recover::{TypeHint, TypeMap};

        let promoted = Expr::Cast {
            signed: true,
            width: 4,
            expr: Box::new(Expr::Cast {
                signed: true,
                width: 1,
                expr: Box::new(Expr::Reg(reg("local_1"))),
            }),
        };
        let mut f = Function {
            name: "sext_i8".into(),
            entry_va: 0,
            body: vec![Stmt::Return {
                value: Some(promoted.clone()),
            }],
        };
        let mut tm = TypeMap::default();
        tm.upsert_public(
            reg("local_1"),
            TypeHint::Int {
                signed: true,
                width: 1,
            },
        );

        fold_typed_declared_views(&mut f, &tm);

        assert!(matches!(
            &f.body[0],
            Stmt::Return { value: Some(value) } if value == &promoted
        ));
    }

    #[test]
    fn equal_sign_extensions_fold_only_with_matching_declared_types() {
        use crate::ir::types_recover::{TypeHint, TypeMap};

        let extended = |name| Expr::Cast {
            signed: true,
            width: 8,
            expr: Box::new(Expr::Cast {
                signed: true,
                width: 4,
                expr: Box::new(Expr::Reg(reg(name))),
            }),
        };
        let mut f = one_stmt(Expr::Cmp {
            op: CmpOp::Slt,
            lhs: Box::new(extended("arg0")),
            rhs: Box::new(extended("arg1")),
        });

        fold_constants(&mut f);

        assert!(
            matches!(
                &f.body[0],
                Stmt::Assign {
                    src: Expr::Cmp { lhs, rhs, .. },
                    ..
                } if matches!(lhs.as_ref(), Expr::Cast { .. })
                    && matches!(rhs.as_ref(), Expr::Cast { .. })
            ),
            "an untyped fold must preserve machine-width casts: {f:#?}"
        );

        let mut tm = TypeMap::default();
        for name in ["arg0", "arg1"] {
            tm.upsert_public(
                reg(name),
                TypeHint::Int {
                    signed: true,
                    width: 4,
                },
            );
        }
        fold_typed_comparison_extensions(&mut f, &tm);

        assert!(matches!(
            &f.body[0],
            Stmt::Assign {
                src: Expr::Cmp {
                    op: CmpOp::Slt,
                    lhs,
                    rhs,
                },
                ..
            } if matches!(lhs.as_ref(), Expr::Reg(r) if r == &reg("arg0"))
                    && matches!(rhs.as_ref(), Expr::Reg(r) if r == &reg("arg1"))
        ));
    }

    #[test]
    fn a_store_width_consumes_redundant_casts_and_low_bit_masks() {
        let address = Expr::Reg(reg("local_value"));
        let update = Expr::Bin {
            op: BinOp::Add,
            lhs: Box::new(Expr::Reg(reg("local_value"))),
            rhs: Box::new(Expr::Const(1)),
        };
        let mut f = Function {
            name: "stores".into(),
            entry_va: 0,
            body: vec![
                Stmt::Store {
                    addr: address.clone(),
                    src: Expr::Cast {
                        signed: false,
                        width: 8,
                        expr: Box::new(Expr::Cast {
                            signed: false,
                            width: 4,
                            expr: Box::new(update.clone()),
                        }),
                    },
                    size: 4,
                },
                Stmt::Store {
                    addr: Expr::Reg(reg("local_byte")),
                    src: Expr::Bin {
                        op: BinOp::Or,
                        lhs: Box::new(Expr::Bin {
                            op: BinOp::And,
                            lhs: Box::new(Expr::Reg(reg("old_parent"))),
                            rhs: Box::new(Expr::Const(-256)),
                        }),
                        rhs: Box::new(Expr::Bin {
                            op: BinOp::And,
                            lhs: Box::new(Expr::Deref {
                                addr: Box::new(Expr::Reg(reg("p"))),
                                size: 1,
                            }),
                            rhs: Box::new(Expr::Const(255)),
                        }),
                    },
                    size: 1,
                },
            ],
        };

        fold_constants(&mut f);

        assert!(matches!(
            &f.body[0],
            Stmt::Store { addr, src, size: 4 } if addr == &address && src == &update
        ));
        assert!(matches!(
            &f.body[1],
            Stmt::Store {
                src: Expr::Deref { size: 1, .. },
                size: 1,
                ..
            }
        ));
    }

    #[test]
    fn logical_not_of_comparison_reverses_relation() {
        let lhs = Expr::Reg(reg("rax"));
        let rhs = Expr::Reg(reg("rbx"));
        let mut f = one_stmt(Expr::Cmp {
            op: CmpOp::Eq,
            lhs: Box::new(Expr::Cmp {
                op: CmpOp::Slt,
                lhs: Box::new(lhs.clone()),
                rhs: Box::new(rhs.clone()),
            }),
            rhs: Box::new(Expr::Const(0)),
        });
        fold_constants(&mut f);
        if let Stmt::Assign { src, .. } = &f.body[0] {
            assert_eq!(
                *src,
                Expr::Cmp {
                    op: CmpOp::Sle,
                    lhs: Box::new(rhs),
                    rhs: Box::new(lhs),
                }
            );
        }
    }

    #[test]
    fn pure_boolean_bitwise_tree_recovers_logical_disjunction() {
        let cmp = |name: &str, value: i64| Expr::Cmp {
            op: CmpOp::Eq,
            lhs: Box::new(Expr::Reg(reg(name))),
            rhs: Box::new(Expr::Const(value)),
        };
        let first = cmp("arg0", 0);
        let second = cmp("arg1", 1);
        let third = cmp("arg2", 2);
        let masked_pair = bin(
            BinOp::And,
            Expr::Cast {
                signed: false,
                width: 1,
                expr: Box::new(bin(BinOp::Or, first.clone(), second.clone())),
            },
            Expr::Const(255),
        );
        let mut f = one_stmt(Expr::Cmp {
            op: CmpOp::Ne,
            lhs: Box::new(Expr::Cast {
                signed: false,
                width: 8,
                expr: Box::new(bin(BinOp::Or, masked_pair, third.clone())),
            }),
            rhs: Box::new(Expr::Const(0)),
        });

        fold_constants(&mut f);

        assert_eq!(
            f.body[0],
            Stmt::Assign {
                dst: reg("rax"),
                src: bin(
                    BinOp::LogicalOr,
                    bin(BinOp::LogicalOr, first, second),
                    third,
                ),
            }
        );
    }

    #[test]
    fn inverted_pure_boolean_bitwise_tree_recovers_de_morgan_conjunction() {
        let cmp = |name: &str, value: i64| Expr::Cmp {
            op: CmpOp::Eq,
            lhs: Box::new(Expr::Reg(reg(name))),
            rhs: Box::new(Expr::Const(value)),
        };
        let first = cmp("arg0", 0);
        let second = cmp("arg1", 1);
        // The same SETcc byte tree the compiler tests with `jne`, tested with
        // `je` instead: `!(a == 0 || b == 1)` is `a != 0 && b != 1`.
        let mut f = one_stmt(Expr::Cmp {
            op: CmpOp::Eq,
            lhs: Box::new(Expr::Cast {
                signed: false,
                width: 8,
                expr: Box::new(bin(
                    BinOp::And,
                    Expr::Cast {
                        signed: false,
                        width: 1,
                        expr: Box::new(bin(BinOp::Or, first, second)),
                    },
                    Expr::Const(255),
                )),
            }),
            rhs: Box::new(Expr::Const(0)),
        });

        fold_constants(&mut f);

        assert_eq!(
            f.body[0],
            Stmt::Assign {
                dst: reg("rax"),
                src: bin(
                    BinOp::LogicalAnd,
                    Expr::Cmp {
                        op: CmpOp::Ne,
                        lhs: Box::new(Expr::Reg(reg("arg0"))),
                        rhs: Box::new(Expr::Const(0)),
                    },
                    Expr::Cmp {
                        op: CmpOp::Ne,
                        lhs: Box::new(Expr::Reg(reg("arg1"))),
                        rhs: Box::new(Expr::Const(1)),
                    },
                ),
            }
        );
    }

    #[test]
    fn inverted_boolean_bitwise_tree_without_byte_view_stays_eager() {
        // Our own `jle` flag model is a bare `cmp | cmp` tested against zero.
        // Recovering it as `||` would invent a basic block the source never had,
        // so the byte-view requirement must hold for the inverted polarity too.
        let original = Expr::Cmp {
            op: CmpOp::Eq,
            lhs: Box::new(bin(
                BinOp::Or,
                Expr::Cmp {
                    op: CmpOp::Eq,
                    lhs: Box::new(Expr::Reg(reg("arg0"))),
                    rhs: Box::new(Expr::Const(7)),
                },
                Expr::Cmp {
                    op: CmpOp::Slt,
                    lhs: Box::new(Expr::Reg(reg("arg1"))),
                    rhs: Box::new(Expr::Const(7)),
                },
            )),
            rhs: Box::new(Expr::Const(0)),
        };
        let mut f = one_stmt(original.clone());

        fold_constants(&mut f);

        assert_eq!(f.body[0], one_stmt(original).body[0]);
    }

    #[test]
    fn boolean_bitwise_tree_with_memory_read_stays_eager() {
        let load_comparison = Expr::Cmp {
            op: CmpOp::Eq,
            lhs: Box::new(Expr::Deref {
                addr: Box::new(Expr::Reg(reg("arg0"))),
                size: 4,
            }),
            rhs: Box::new(Expr::Const(0)),
        };
        let register_comparison = Expr::Cmp {
            op: CmpOp::Eq,
            lhs: Box::new(Expr::Reg(reg("arg1"))),
            rhs: Box::new(Expr::Const(0)),
        };
        let original = bin(BinOp::Or, register_comparison, load_comparison);
        let mut f = one_stmt(original.clone());

        fold_constants(&mut f);

        assert!(matches!(
            &f.body[0],
            Stmt::Assign {
                src: Expr::Bin { op: BinOp::Or, .. },
                ..
            }
        ));
        assert_eq!(f.body[0], one_stmt(original).body[0]);
    }

    #[test]
    fn unobserved_pure_boolean_bitwise_tree_stays_eager() {
        let original = bin(
            BinOp::Or,
            Expr::Cmp {
                op: CmpOp::Eq,
                lhs: Box::new(Expr::Reg(reg("arg0"))),
                rhs: Box::new(Expr::Const(0)),
            },
            Expr::Cmp {
                op: CmpOp::Slt,
                lhs: Box::new(Expr::Reg(reg("arg1"))),
                rhs: Box::new(Expr::Const(0)),
            },
        );
        let mut f = one_stmt(original.clone());

        fold_constants(&mut f);

        assert_eq!(f.body[0], one_stmt(original).body[0]);
    }

    #[test]
    fn shift_by_zero_is_identity() {
        let mut f = one_stmt(bin(BinOp::Shl, Expr::Reg(reg("rax")), Expr::Const(0)));
        fold_constants(&mut f);
        if let Stmt::Assign { src, .. } = &f.body[0] {
            assert_eq!(*src, Expr::Reg(reg("rax")));
        }
    }

    #[test]
    fn real_binary_end_to_end() {
        // Compose with the full pipeline; we just want to confirm the fold
        // runs to fixed point without panicking on a real function body.
        use crate::analysis::cfg::{analyze_functions_bytes, Budgets};
        use crate::core::binary::Arch;
        use crate::ir::ast::{lower, render};
        use crate::ir::expr_reconstruct::reconstruct;
        use crate::ir::lift_function::lift_function_from_bytes;
        use crate::ir::ssa::compute_ssa;
        use crate::ir::structure::recover;

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
                max_functions: 2,
                max_blocks: 64,
                max_instructions: 1000,
                timeout_ms: 500,
                total_timeout_ms: 0,
            },
        );
        for f in &funcs {
            if let Some(lf) = lift_function_from_bytes(&data, f, Arch::X86_64) {
                let ssa = compute_ssa(&lf);
                let r = recover(&lf, &ssa);
                let mut ast = lower(&lf, &r, f.name.clone());
                reconstruct(&mut ast);
                fold_constants(&mut ast);
                let text = render(&ast);
                // xor-self idioms are pervasive in compiler-emitted prologues;
                // we can't assert the exact count, but the output should no
                // longer contain a plain `(%X ^ %X)` for any X.
                assert!(
                    !text.contains("= (%ret ^ %ret);"),
                    "xor-self survived fold: {}",
                    text
                );
            }
        }
    }

    /// `castN(castM(x))` collapses to `castN(x)` when the inner cast is no
    /// narrower — the outer only observes the low N bits, which a widening
    /// inner cast cannot have touched.
    #[test]
    fn equal_or_wider_inner_cast_is_subsumed() {
        // (u32)((u64)rax)  ->  (u32)rax
        let mut f = one_stmt(Expr::Cast {
            signed: false,
            width: 4,
            expr: Box::new(Expr::Cast {
                signed: false,
                width: 8,
                expr: Box::new(Expr::Reg(reg("rax"))),
            }),
        });
        fold_constants(&mut f);
        let Stmt::Assign { src, .. } = &f.body[0] else {
            panic!()
        };
        assert_eq!(
            *src,
            Expr::Cast {
                signed: false,
                width: 4,
                expr: Box::new(Expr::Reg(reg("rax")))
            }
        );
    }

    /// A three-deep chain collapses completely, which is the shape that
    /// actually appears in output.
    #[test]
    fn deep_identical_cast_chain_collapses() {
        let inner = Expr::Cast {
            signed: false,
            width: 8,
            expr: Box::new(Expr::Reg(reg("rax"))),
        };
        let mut f = one_stmt(Expr::Cast {
            signed: false,
            width: 8,
            expr: Box::new(Expr::Cast {
                signed: false,
                width: 8,
                expr: Box::new(inner),
            }),
        });
        fold_constants(&mut f);
        let Stmt::Assign { src, .. } = &f.body[0] else {
            panic!()
        };
        assert_eq!(
            *src,
            Expr::Cast {
                signed: false,
                width: 8,
                expr: Box::new(Expr::Reg(reg("rax")))
            },
            "chain did not fully collapse: {src:?}"
        );
    }

    /// A NARROWING inner cast is a real truncation and must survive: dropping
    /// it would silently widen the value the outer cast sees.
    #[test]
    fn narrowing_inner_cast_is_preserved() {
        // (u64)((u8)rax) must keep the u8 truncation.
        let original = Expr::Cast {
            signed: false,
            width: 8,
            expr: Box::new(Expr::Cast {
                signed: false,
                width: 1,
                expr: Box::new(Expr::Reg(reg("rax"))),
            }),
        };
        let mut f = one_stmt(original.clone());
        fold_constants(&mut f);
        let Stmt::Assign { src, .. } = &f.body[0] else {
            panic!()
        };
        assert_eq!(*src, original, "truncation was folded away");
    }
}
