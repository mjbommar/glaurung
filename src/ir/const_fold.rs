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

#[derive(Clone, Copy)]
enum ParameterAuthority<'a> {
    LegacySpelling,
    Identities(&'a crate::ir::value_number::ValueIdentities),
}

impl ParameterAuthority<'_> {
    fn owns(self, name: &str) -> bool {
        match self {
            Self::LegacySpelling => crate::ir::ast::parse_arg_index(name).is_some(),
            Self::Identities(identities) => identities
                .parameter_slot(&crate::ir::types::VReg::phys(name))
                .is_some(),
        }
    }
}

/// Overwrite `slot` and record that this pass changed the AST.
///
/// **Every** write the `fold_constants` traversal makes to the AST goes through
/// here — `fold_stored_value` and `fold_expr_at` contain no other assignment
/// through a `&mut Expr`, which is what makes the `bool` those functions
/// thread out an honest answer rather than an optimistic one. The fixpoint in
/// [`crate::ir::ast::prepare`] stops when a round reports no change, so a
/// missed site here would truncate that fixpoint and silently change output.
/// A missed site cannot be introduced quietly: `fold_expr_at` has no bare
/// `*e = ` assignment left in it, so a new one stands out.
///
/// Reporting a change that did not happen is safe (one extra fixpoint round
/// over an unchanged body, which changes nothing); reporting no change when one
/// happened is not. So `rewrite` sets the flag unconditionally, without first
/// proving `*slot != value`.
fn rewrite(slot: &mut Expr, value: Expr, changed: &mut bool) {
    *slot = value;
    *changed = true;
}

/// Rewrite `f`'s body in place, folding the patterns above.
///
/// Returns whether anything was rewritten — see [`rewrite`].
pub fn fold_constants(f: &mut Function) -> bool {
    fold_constants_with_parameter_authority(f, ParameterAuthority::LegacySpelling)
}

/// Fold constants while recognizing parameters only from exact AST identities.
pub(crate) fn fold_constants_with_identities(
    f: &mut Function,
    identities: &crate::ir::value_number::ValueIdentities,
) -> bool {
    fold_constants_with_parameter_authority(f, ParameterAuthority::Identities(identities))
}

fn fold_constants_with_parameter_authority(
    f: &mut Function,
    parameter_authority: ParameterAuthority<'_>,
) -> bool {
    #[cfg(debug_assertions)]
    let before = f.clone();
    let mut changed = false;
    fold_body(&mut f.body, &mut changed, parameter_authority);
    #[cfg(debug_assertions)]
    assert!(
        changed || before == *f,
        "const_fold::fold_constants reported no change but edited the body; the \
         prepare.rs fixpoint would stop a round early and emit different C"
    );
    changed
}

/// Remove matching extension pairs from comparisons only when recovered C
/// declarations prove that the uncast operands already have the exact source
/// width and signedness. The untyped algebraic pass cannot make this decision:
/// a zero-extended 32-bit load may live in a default-`long` scratch, and dropping
/// its signed cast changes a negative machine value into a positive C value.
pub fn fold_typed_comparison_extensions(f: &mut Function, tm: &TypeMap) {
    fold_typed_comparison_extensions_with_identities(f, tm, None);
}

/// Remove matching comparison extensions using exact opaque SSA identities.
pub fn fold_typed_comparison_extensions_with_identities(
    f: &mut Function,
    tm: &TypeMap,
    identities: Option<&crate::ir::value_number::ValueIdentities>,
) {
    fn declared_source_type(
        expr: &Expr,
        signed: bool,
        width: u8,
        tm: &TypeMap,
        identities: Option<&crate::ir::value_number::ValueIdentities>,
    ) -> bool {
        matches!(
            expr.semantic(),
            Expr::Reg(crate::ir::types::VReg::Phys(name))
                if crate::ir::ast::declared_int_type_with_identities(
                    name,
                    Some(tm),
                    identities,
                ) == Some((signed, width))
        )
    }

    fn expression(
        expr: &mut Expr,
        tm: &TypeMap,
        identities: Option<&crate::ir::value_number::ValueIdentities>,
    ) {
        match expr {
            Expr::Origin { expr, .. } => expression(expr, tm, identities),
            Expr::Deref { addr, .. } => expression(addr, tm, identities),
            Expr::Call { target, args, .. } => {
                expression(target, tm, identities);
                for argument in args {
                    expression(argument, tm, identities);
                }
            }
            Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
                expression(lhs, tm, identities);
                expression(rhs, tm, identities);
            }
            Expr::Un { src, .. } => expression(src, tm, identities),
            Expr::Select {
                cond,
                if_true,
                if_false,
                ..
            } => {
                expression(cond, tm, identities);
                expression(if_true, tm, identities);
                expression(if_false, tm, identities);
            }
            Expr::Cast { expr, .. } | Expr::NumericConvert { expr, .. } => {
                expression(expr, tm, identities)
            }
            Expr::FunctionTableEntry { index, .. } => expression(index, tm, identities),
            Expr::WideArithmetic { args, .. } => {
                for argument in args {
                    expression(argument, tm, identities);
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
        if left.0 == right.0 && left.1 == right.1 && left.2 == right.2 {
            if matches!(op, CmpOp::Eq | CmpOp::Ne) {
                // Extending both values in the same way cannot change whether
                // they are equal. Keep the exact source-width casts, rather
                // than requiring the underlying values to be named registers:
                // aggregate-field loads are expressions, not declarations.
                // Keeping the inner casts also preserves the machine's signed
                // or unsigned interpretation without forcing a wider compare.
                **lhs = Expr::Cast {
                    signed: left.0,
                    width: left.2,
                    expr: Box::new(left.3.clone()),
                }
                .with_optional_origins((!left.4.is_empty()).then_some(left.4));
                **rhs = Expr::Cast {
                    signed: right.0,
                    width: right.2,
                    expr: Box::new(right.3.clone()),
                }
                .with_optional_origins((!right.4.is_empty()).then_some(right.4));
            } else if declared_source_type(left.3, left.0, left.2, tm, identities)
                && declared_source_type(right.3, right.0, right.2, tm, identities)
            {
                **lhs = left
                    .3
                    .clone()
                    .with_optional_origins((!left.4.is_empty()).then_some(left.4));
                **rhs = right
                    .3
                    .clone()
                    .with_optional_origins((!right.4.is_empty()).then_some(right.4));
            }
        }
    }

    fn body(
        statements: &mut [Stmt],
        tm: &TypeMap,
        identities: Option<&crate::ir::value_number::ValueIdentities>,
    ) {
        for statement in statements {
            match statement {
                Stmt::Origin { stmt, .. } => {
                    body(std::slice::from_mut(stmt.as_mut()), tm, identities)
                }
                Stmt::Assign { src, .. } | Stmt::Return { value: Some(src) } => {
                    expression(src, tm, identities);
                }
                Stmt::Store { addr, src, .. } => {
                    expression(addr, tm, identities);
                    expression(src, tm, identities);
                }
                Stmt::Call { target, args, .. } => {
                    expression(target, tm, identities);
                    for arg in args {
                        expression(arg, tm, identities);
                    }
                }
                Stmt::IndirectGoto { target } | Stmt::Push { value: target } => {
                    expression(target, tm, identities);
                }
                Stmt::If {
                    cond,
                    then_body,
                    else_body,
                } => {
                    expression(cond, tm, identities);
                    body(then_body, tm, identities);
                    if let Some(else_body) = else_body {
                        body(else_body, tm, identities);
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
                    expression(cond, tm, identities);
                    body(loop_body, tm, identities);
                }
                Stmt::For {
                    init,
                    cond,
                    step,
                    body: loop_body,
                } => {
                    body(std::slice::from_mut(init.as_mut()), tm, identities);
                    expression(cond, tm, identities);
                    body(std::slice::from_mut(step.as_mut()), tm, identities);
                    body(loop_body, tm, identities);
                }
                Stmt::Switch {
                    discriminant,
                    cases,
                    default,
                } => {
                    expression(discriminant, tm, identities);
                    for (_, case_body) in cases {
                        body(case_body, tm, identities);
                    }
                    if let Some(default) = default {
                        body(default, tm, identities);
                    }
                }
                Stmt::Return { value: None }
                | Stmt::Pop { .. }
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
    }

    body(&mut f.body, tm, identities);
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
    fold_typed_declared_views_with_identities(f, tm, None);
}

/// Remove redundant declared views using exact opaque SSA identities.
pub fn fold_typed_declared_views_with_identities(
    f: &mut Function,
    tm: &TypeMap,
    identities: Option<&crate::ir::value_number::ValueIdentities>,
) {
    fn expression(
        expr: &mut Expr,
        tm: &TypeMap,
        identities: Option<&crate::ir::value_number::ValueIdentities>,
    ) {
        if let Expr::Origin { origins, expr } = expr {
            expression(expr, tm, identities);
            if matches!(expr.as_ref(), Expr::Origin { .. }) {
                let nested = std::mem::replace(expr.as_mut(), Expr::Unknown(String::new()));
                let (semantic, nested_origins) = nested.into_semantic_with_origins();
                if let Some(nested_origins) = nested_origins {
                    origins.merge(&nested_origins);
                }
                **expr = semantic;
            }
            return;
        }
        match expr {
            Expr::Origin { .. } => unreachable!("origin carrier returned above"),
            Expr::Deref { addr, .. } => expression(addr, tm, identities),
            Expr::Call { target, args, .. } => {
                expression(target, tm, identities);
                for argument in args {
                    expression(argument, tm, identities);
                }
            }
            Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
                expression(lhs, tm, identities);
                expression(rhs, tm, identities);
            }
            Expr::Un { src, .. } => expression(src, tm, identities),
            Expr::Select {
                cond,
                if_true,
                if_false,
                ..
            } => {
                expression(cond, tm, identities);
                expression(if_true, tm, identities);
                expression(if_false, tm, identities);
            }
            Expr::Cast { expr, .. } | Expr::NumericConvert { expr, .. } => {
                expression(expr, tm, identities)
            }
            Expr::FunctionTableEntry { index, .. } => expression(index, tm, identities),
            Expr::WideArithmetic { args, .. } => {
                for argument in args {
                    expression(argument, tm, identities);
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

        let replacement =
            match expr {
                Expr::Cast {
                    signed: outer_signed,
                    width: outer_width,
                    expr: inner,
                } => match inner.semantic() {
                    Expr::Cast {
                        signed: inner_signed,
                        width: inner_width,
                        expr: source,
                    } if inner_width < outer_width && !*outer_signed && !*inner_signed => {
                        match source.semantic() {
                            Expr::Reg(crate::ir::types::VReg::Phys(name))
                                if crate::ir::ast::declared_int_type_with_identities(
                                    name,
                                    Some(tm),
                                    identities,
                                ) == Some((*inner_signed, *inner_width)) =>
                            {
                                let origins =
                                    inner.origins().into_iter().chain(source.origins()).fold(
                                        crate::ir::ast::OriginSet::empty(),
                                        |owners, next| owners.union(next),
                                    );
                                Some(source.semantic().clone().with_optional_origins(
                                    (!origins.is_empty()).then_some(origins),
                                ))
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

    fn body(
        statements: &mut [Stmt],
        tm: &TypeMap,
        identities: Option<&crate::ir::value_number::ValueIdentities>,
    ) {
        for statement in statements {
            match statement {
                Stmt::Origin { stmt, .. } => {
                    body(std::slice::from_mut(stmt.as_mut()), tm, identities)
                }
                Stmt::Assign { src, .. } => expression(src, tm, identities),
                Stmt::Store { addr, src, .. } => {
                    expression(addr, tm, identities);
                    expression(src, tm, identities);
                }
                Stmt::Call { target, args, .. } => {
                    expression(target, tm, identities);
                    for arg in args {
                        expression(arg, tm, identities);
                    }
                }
                Stmt::IndirectGoto { target } | Stmt::Push { value: target } => {
                    expression(target, tm, identities);
                }
                Stmt::If {
                    cond,
                    then_body,
                    else_body,
                } => {
                    expression(cond, tm, identities);
                    body(then_body, tm, identities);
                    if let Some(else_body) = else_body {
                        body(else_body, tm, identities);
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
                    expression(cond, tm, identities);
                    body(loop_body, tm, identities);
                }
                Stmt::For {
                    init,
                    cond,
                    step,
                    body: loop_body,
                } => {
                    body(std::slice::from_mut(init.as_mut()), tm, identities);
                    expression(cond, tm, identities);
                    body(std::slice::from_mut(step.as_mut()), tm, identities);
                    body(loop_body, tm, identities);
                }
                Stmt::Switch {
                    discriminant,
                    cases,
                    default,
                } => {
                    expression(discriminant, tm, identities);
                    for (_, case_body) in cases {
                        body(case_body, tm, identities);
                    }
                    if let Some(default) = default {
                        body(default, tm, identities);
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
                | Stmt::Continue
                | Stmt::Nop
                | Stmt::Unknown(_)
                | Stmt::Comment(_)
                | Stmt::Throw { .. }
                | Stmt::TryCatch { .. } => {}
            }
        }
    }

    body(&mut f.body, tm, identities);
}

fn fold_body(body: &mut [Stmt], changed: &mut bool, parameter_authority: ParameterAuthority<'_>) {
    for s in body.iter_mut() {
        match s {
            Stmt::Origin { stmt, .. } => fold_body(
                std::slice::from_mut(stmt.as_mut()),
                changed,
                parameter_authority,
            ),
            Stmt::IndirectGoto { target } => fold_expr(target, changed, parameter_authority),
            Stmt::Assign { src, .. } => fold_expr(src, changed, parameter_authority),
            Stmt::Store { addr, src, size } => {
                fold_expr(addr, changed, parameter_authority);
                fold_expr(src, changed, parameter_authority);
                fold_stored_value(src, *size, changed, parameter_authority);
            }
            Stmt::Call { target, args, .. } => {
                fold_expr(target, changed, parameter_authority);
                for a in args {
                    fold_expr(a, changed, parameter_authority);
                }
            }
            Stmt::Return { value } => {
                if let Some(e) = value {
                    fold_expr(e, changed, parameter_authority);
                }
            }
            Stmt::If {
                cond,
                then_body,
                else_body,
            } => {
                fold_expr(cond, changed, parameter_authority);
                fold_body(then_body, changed, parameter_authority);
                if let Some(eb) = else_body {
                    fold_body(eb, changed, parameter_authority);
                }
            }
            Stmt::While { cond, body } => {
                fold_expr(cond, changed, parameter_authority);
                fold_body(body, changed, parameter_authority);
            }
            Stmt::For {
                init,
                cond,
                step,
                body,
            } => {
                fold_body(
                    std::slice::from_mut(init.as_mut()),
                    changed,
                    parameter_authority,
                );
                fold_expr(cond, changed, parameter_authority);
                fold_body(body, changed, parameter_authority);
                fold_body(
                    std::slice::from_mut(step.as_mut()),
                    changed,
                    parameter_authority,
                );
            }
            Stmt::DoWhile { body, cond } => {
                fold_body(body, changed, parameter_authority);
                fold_expr(cond, changed, parameter_authority);
            }
            Stmt::Push { value } => fold_expr(value, changed, parameter_authority),
            Stmt::Switch {
                discriminant,
                cases,
                default,
            } => {
                fold_expr(discriminant, changed, parameter_authority);
                for (_, body) in cases.iter_mut() {
                    fold_body(body, changed, parameter_authority);
                }
                if let Some(b) = default {
                    fold_body(b, changed, parameter_authority);
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
}

fn fold_stored_value(
    src: &mut Expr,
    size: u8,
    changed: &mut bool,
    parameter_authority: ParameterAuthority<'_>,
) {
    if size == 0 {
        return;
    }
    // Storage context is semantic, so an origin carrier must not hide the
    // cast/mask that the write width proves redundant. Recurse inside it, then
    // flatten any carrier produced by the replacement into one canonical set.
    if let Expr::Origin { origins, expr } = src {
        fold_stored_value(expr, size, changed, parameter_authority);
        if matches!(expr.as_ref(), Expr::Origin { .. }) {
            let nested = std::mem::replace(expr.as_mut(), Expr::Unknown(String::new()));
            let (semantic, nested_origins) = nested.into_semantic_with_origins();
            if let Some(nested_origins) = nested_origins {
                origins.merge(&nested_origins);
            }
            **expr = semantic;
        }
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
        rewrite(src, replacement, changed);
    }

    // Likewise, a mask that keeps every stored low bit is unobservable after
    // the truncating write (`store8(x & 0xff) == store8(x)`).
    let required = if size >= 8 {
        u64::MAX
    } else {
        (1u64 << (u32::from(size) * 8)) - 1
    };
    if let Some(replacement) = fold_observed_mask(src, required as i64) {
        rewrite(src, replacement, changed);
        fold_expr(src, changed, parameter_authority);
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
        rewrite(src, replacement, changed);
    }
}

fn fold_expr(e: &mut Expr, changed: &mut bool, parameter_authority: ParameterAuthority<'_>) {
    fold_expr_at(e, false, changed, parameter_authority);
}

/// `shift_left_operand` marks the one position where a widening cast over a
/// LITERAL carries meaning rather than restating it.
///
/// C gives a shift the type of its promoted LEFT operand, so `(uint64_t)1 << 40`
/// and `1 << 40` are not the same expression: the first is 2^40, the second is
/// undefined behaviour that x86 answers as `1 << 8`. Everywhere else a cast over
/// a constant only spells out a value the literal already has, and collapsing it
/// is what keeps the recovered source readable — so the suppression is exactly
/// one edge wide.
///
/// Measured, not supposed. `bts %rsi,%rax` lifts to `dst | (mask << index)` with
/// `mask` the widened literal one; with the cast collapsed the recovered
/// `value | (1 << (index & 63))` disagreed with the original for EVERY index at
/// or above 32, and at 63 returned 0xffffffff80000000 where the machine returns
/// 0x8000000000000000.
fn fold_expr_at(
    e: &mut Expr,
    shift_left_operand: bool,
    changed: &mut bool,
    parameter_authority: ParameterAuthority<'_>,
) {
    // Recurse first — bottom-up folding composes naturally.
    match e {
        Expr::Origin { origins, expr } => {
            fold_expr_at(expr, shift_left_operand, changed, parameter_authority);
            if matches!(expr.as_ref(), Expr::Origin { .. }) {
                let nested = std::mem::replace(expr.as_mut(), Expr::Unknown(String::new()));
                let (semantic, nested_origins) = nested.into_semantic_with_origins();
                if let Some(nested_origins) = nested_origins {
                    origins.merge(&nested_origins);
                }
                **expr = semantic;
            }
        }
        Expr::Bin { op, lhs, rhs } => {
            let shift = matches!(op, BinOp::Shl | BinOp::Shr | BinOp::Sar);
            fold_expr_at(lhs, shift, changed, parameter_authority);
            fold_expr(rhs, changed, parameter_authority);
        }
        Expr::Cmp { lhs, rhs, .. } => {
            fold_expr(lhs, changed, parameter_authority);
            fold_expr(rhs, changed, parameter_authority);
        }
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => {
            fold_expr(cond, changed, parameter_authority);
            fold_expr(if_true, changed, parameter_authority);
            fold_expr(if_false, changed, parameter_authority);
        }
        Expr::Un { src, .. } => fold_expr(src, changed, parameter_authority),
        Expr::Cast { expr, .. } => fold_expr(expr, changed, parameter_authority),
        Expr::Deref { addr, .. } => fold_expr(addr, changed, parameter_authority),
        _ => {}
    }

    // A full-width load through the address of a scalar ABI parameter is the
    // parameter itself. Cdecl32 exposes incoming arguments as stack objects,
    // so stack promotion can retain `Deref(StackAddr(argN))` even after DWARF
    // has proved the source parameter. Keep partial loads explicit: reading
    // one byte of an `int` is not an `int` read, and aggregate/local objects
    // are deliberately outside this parameter-only identity.
    let parameter_address_load = match e {
        Expr::Deref { addr, size } => match addr.semantic() {
            Expr::StackAddr {
                object: crate::ir::types::VReg::Phys(name),
                size: object_size,
            } if usize::from(*size) == usize::from(*object_size)
                && parameter_authority.owns(name) =>
            {
                Some(
                    Expr::Reg(crate::ir::types::VReg::phys(name.clone()))
                        .with_optional_origins(addr.origins().cloned()),
                )
            }
            _ => None,
        },
        _ => None,
    };
    if let Some(replacement) = parameter_address_load {
        rewrite(e, replacement, changed);
        return;
    }

    // A select whose predicate became literal has exactly one reachable arm.
    // Both arms were folded above, so replacing the node cannot hide additional
    // work and removes the unreachable expression without changing evaluation.
    let selected_arm = match e {
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => {
            let selected = match cond.semantic() {
                Expr::Const(0) => Some(if_false.as_ref()),
                Expr::Const(_) => Some(if_true.as_ref()),
                _ => None,
            };
            selected.map(|arm| arm.clone().with_optional_origins(cond.origins().cloned()))
        }
        _ => None,
    };
    if let Some(replacement) = selected_arm {
        rewrite(e, replacement, changed);
        return;
    }

    // ARM predication can spell one hardware condition twice while carrying
    // the destination's prior value through the unreachable inner arm:
    // `c ? (c ? yes : prior) : no`.  Once the outer select chose its true arm,
    // the identical inner condition is necessarily true, so `prior` cannot be
    // read.  The dual false-arm form follows the same argument.  Require a
    // repeatable register/arithmetic condition: collapsing a call or load here
    // could remove an observable second evaluation.
    fn repeatable_condition(expr: &Expr) -> bool {
        match expr {
            Expr::Origin { expr, .. } => repeatable_condition(expr),
            Expr::Reg(_) | Expr::Const(_) => true,
            Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
                repeatable_condition(lhs) && repeatable_condition(rhs)
            }
            Expr::Un { src, .. }
            | Expr::Cast { expr: src, .. }
            | Expr::NumericConvert { expr: src, .. } => repeatable_condition(src),
            Expr::Deref { .. }
            | Expr::Call { .. }
            | Expr::Select { .. }
            | Expr::FloatConst { .. }
            | Expr::Addr(_)
            | Expr::StackAddr { .. }
            | Expr::FunctionTableEntry { .. }
            | Expr::WideArithmetic { .. }
            | Expr::Named { .. }
            | Expr::StringLit { .. }
            | Expr::Lea { .. }
            | Expr::PdbFieldAddr { .. }
            | Expr::Unknown(_) => false,
        }
    }

    let dominated_select = match e {
        Expr::Select {
            cond,
            if_true,
            if_false,
            width,
        } if repeatable_condition(cond) => {
            let make_replacement = |inner_select: &Expr,
                                    inner_cond: &Expr,
                                    inner_true: Box<Expr>,
                                    inner_false: Box<Expr>| {
                let origins = inner_select
                    .origins()
                    .into_iter()
                    .chain(inner_cond.origins())
                    .fold(crate::ir::ast::OriginSet::empty(), |owners, next| {
                        owners.union(next)
                    });
                Expr::Select {
                    cond: cond.clone(),
                    if_true: inner_true,
                    if_false: inner_false,
                    width: *width,
                }
                .with_optional_origins((!origins.is_empty()).then_some(origins))
            };

            if let Expr::Select {
                cond: inner_cond,
                if_true: inner_true,
                ..
            } = if_true.semantic()
            {
                (inner_cond.semantic() == cond.semantic()).then(|| {
                    make_replacement(if_true, inner_cond, inner_true.clone(), if_false.clone())
                })
            } else if let Expr::Select {
                cond: inner_cond,
                if_false: inner_false,
                ..
            } = if_false.semantic()
            {
                (inner_cond.semantic() == cond.semantic()).then(|| {
                    make_replacement(if_false, inner_cond, if_true.clone(), inner_false.clone())
                })
            } else {
                None
            }
        }
        _ => None,
    };
    if let Some(replacement) = dominated_select {
        rewrite(e, replacement, changed);
        return;
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
        } => match inner.semantic() {
            Expr::Cast {
                width: inner_width,
                expr: source,
                ..
            } if inner_width >= width => Some(
                Expr::Cast {
                    signed: *signed,
                    width: *width,
                    expr: Box::new(source.as_ref().clone()),
                }
                .with_optional_origins(inner.origins().cloned()),
            ),
            _ => None,
        },
        _ => None,
    };
    if let Some(replacement) = subsumed_inner_cast {
        rewrite(e, replacement, changed);
        // Re-run: a chain of three or more collapses one layer per visit.
        fold_expr_at(e, shift_left_operand, changed, parameter_authority);
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
        rewrite(e, replacement, changed);
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
        rewrite(e, replacement, changed);
        return;
    }

    // Now try to collapse the current node.
    if let Expr::Cast {
        signed,
        width,
        expr,
    } = e
    {
        let replacement = match expr.semantic() {
            // Ordered before the two collapses below so a literal on a shift's
            // left operand cannot reach either of them — `is_exact_boolean`
            // accepts the constants 0 and 1, so guarding only the arm that
            // names `Expr::Const` would leave `(uint64_t)1 << n` collapsing
            // through the boolean one.
            Expr::Const(_) if shift_left_operand => None,
            Expr::Const(value) if cast_preserves_constant(*value, *signed, *width) => {
                Some(Expr::Const(*value))
            }
            // Boolean expressions are exactly zero or one, so every supported
            // integer cast preserves their complete value and signedness is
            // irrelevant. This includes logical trees recovered below, not
            // only a single comparison leaf.
            boolean if *width > 0 && is_exact_boolean(boolean) => Some(boolean.clone()),
            _ => None,
        }
        .map(|replacement| replacement.with_optional_origins(expr.origins().cloned()));
        if let Some(replacement) = replacement {
            rewrite(e, replacement, changed);
            return;
        }
    }

    if let Expr::Bin { op, lhs, rhs } = e {
        let op = *op;

        // XOR cancellation through one associative layer.  This is the
        // canonical shape of x86 signed predicates: SF ^ OF, where OF is
        // itself the XOR of a signed comparison and SF.
        if op == BinOp::Xor {
            let cancel = |a: &Expr, nested: &Expr| {
                let Expr::Bin {
                    op: BinOp::Xor,
                    lhs: b,
                    rhs: c,
                } = nested.semantic()
                else {
                    return None;
                };
                let survivor = if a.semantic() == c.semantic() {
                    b.as_ref()
                } else if a.semantic() == b.semantic() {
                    c.as_ref()
                } else {
                    return None;
                };
                let origins = [a, nested, b.as_ref(), c.as_ref()]
                    .into_iter()
                    .filter_map(Expr::origins)
                    .fold(crate::ir::ast::OriginSet::empty(), |owners, next| {
                        owners.union(next)
                    });
                Some(
                    survivor
                        .semantic()
                        .clone()
                        .with_optional_origins((!origins.is_empty()).then_some(origins)),
                )
            };
            let replacement = cancel(lhs, rhs).or_else(|| cancel(rhs, lhs));
            if let Some(replacement) = replacement {
                rewrite(e, replacement, changed);
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
                rewrite(e, replacement, changed);
                return;
            }
        }

        // Observe only the requested bits of nested partial-register merges.
        // This is the algebra behind x86 `setcc al; movzx eax, al`: high bits
        // preserved in the architectural parent cannot affect a later low-byte
        // (or low-bit) read.
        if op == BinOp::And {
            let masked = match (lhs.semantic(), rhs.semantic()) {
                (_, Expr::Const(mask)) => fold_observed_mask(lhs, *mask)
                    .map(|replacement| (replacement, rhs.origins().cloned())),
                (Expr::Const(mask), _) => fold_observed_mask(rhs, *mask)
                    .map(|replacement| (replacement, lhs.origins().cloned())),
                _ => None,
            };
            if let Some((replacement, mask_origins)) = masked {
                rewrite(e, replacement.with_optional_origins(mask_origins), changed);
                // The replacement is strictly shallower (one merge or mask
                // layer disappeared), so finish any newly adjacent identity.
                fold_expr(e, changed, parameter_authority);
                return;
            }
        }

        // Same-operand identities (X op X).
        if lhs.semantic() == rhs.semantic() {
            let origins = lhs
                .origins()
                .into_iter()
                .chain(rhs.origins())
                .fold(crate::ir::ast::OriginSet::empty(), |owners, next| {
                    owners.union(next)
                });
            let replacement = match op {
                BinOp::Xor | BinOp::Sub => Some(Expr::Const(0)),
                // (X & X) == X; retain both copies' owners on the survivor.
                BinOp::And | BinOp::Or => Some(lhs.semantic().clone()),
                _ => None,
            };
            if let Some(replacement) = replacement {
                rewrite(
                    e,
                    replacement.with_optional_origins((!origins.is_empty()).then_some(origins)),
                    changed,
                );
                return;
            }
        }

        // Constant-with-anything identities. Carrier metadata does not change
        // the value being matched. A neutral constant contributes its owner to
        // the surviving value; an annihilated operand does not donate an
        // unrelated owner to the constant result.
        let attributed = |replacement: Expr, contributors: &[&Expr]| {
            let origins = contributors
                .iter()
                .filter_map(|contributor| contributor.origins())
                .fold(crate::ir::ast::OriginSet::empty(), |owners, next| {
                    owners.union(next)
                });
            replacement.with_optional_origins((!origins.is_empty()).then_some(origins))
        };
        let identity_replacement = if matches!(rhs.semantic(), Expr::Const(0)) {
            match op {
                BinOp::Add
                | BinOp::Sub
                | BinOp::Or
                | BinOp::Xor
                | BinOp::Shl
                | BinOp::Shr
                | BinOp::Sar => Some(attributed(lhs.semantic().clone(), &[lhs, rhs])),
                BinOp::Mul | BinOp::And => Some(attributed(Expr::Const(0), &[rhs])),
                BinOp::LogicalOr if is_exact_boolean(lhs) => {
                    Some(attributed(lhs.semantic().clone(), &[lhs, rhs]))
                }
                _ => None,
            }
        } else if matches!(lhs.semantic(), Expr::Const(0)) {
            match op {
                BinOp::Add | BinOp::Or | BinOp::Xor => {
                    Some(attributed(rhs.semantic().clone(), &[lhs, rhs]))
                }
                BinOp::Mul | BinOp::And => Some(attributed(Expr::Const(0), &[lhs])),
                BinOp::LogicalOr if is_exact_boolean(rhs) => {
                    Some(attributed(rhs.semantic().clone(), &[lhs, rhs]))
                }
                _ => None,
            }
        } else if matches!(rhs.semantic(), Expr::Const(1)) {
            match op {
                BinOp::Mul => Some(attributed(lhs.semantic().clone(), &[lhs, rhs])),
                BinOp::LogicalAnd if is_exact_boolean(lhs) => {
                    Some(attributed(lhs.semantic().clone(), &[lhs, rhs]))
                }
                _ => None,
            }
        } else if matches!(lhs.semantic(), Expr::Const(1)) {
            match op {
                BinOp::Mul => Some(attributed(rhs.semantic().clone(), &[lhs, rhs])),
                BinOp::LogicalAnd if is_exact_boolean(rhs) => {
                    Some(attributed(rhs.semantic().clone(), &[lhs, rhs]))
                }
                _ => None,
            }
        } else if matches!(rhs.semantic(), Expr::Const(-1)) {
            match op {
                BinOp::And => Some(attributed(lhs.semantic().clone(), &[lhs, rhs])),
                BinOp::Or => Some(attributed(Expr::Const(-1), &[rhs])),
                _ => None,
            }
        } else {
            None
        };
        if let Some(replacement) = identity_replacement {
            rewrite(e, replacement, changed);
            return;
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
            let as_base = |e: &Expr| match e.semantic() {
                Expr::Addr(base) | Expr::Named { va: base, .. } => Some(*base),
                _ => None,
            };
            let addr_and_offset = match (lhs.semantic(), rhs.semantic()) {
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
                let origins = lhs
                    .origins()
                    .into_iter()
                    .chain(rhs.origins())
                    .fold(crate::ir::ast::OriginSet::empty(), |owners, next| {
                        owners.union(next)
                    });
                rewrite(
                    e,
                    Expr::Addr(folded)
                        .with_optional_origins((!origins.is_empty()).then_some(origins)),
                    changed,
                );
                return;
            }
        }

        // Const × Const fold.
        if let (Expr::Const(a), Expr::Const(b)) = (lhs.semantic(), rhs.semantic()) {
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
            let origins = lhs
                .origins()
                .into_iter()
                .chain(rhs.origins())
                .fold(crate::ir::ast::OriginSet::empty(), |owners, next| {
                    owners.union(next)
                });
            rewrite(
                e,
                Expr::Const(folded).with_optional_origins((!origins.is_empty()).then_some(origins)),
                changed,
            );
        }
    }

    // Comparisons are boolean-valued.  Comparing one to zero is logical
    // negation, not a bitwise operation; invert it into the corresponding
    // relation so it remains readable and type-correct.
    if let Expr::Cmp { op, lhs, rhs } = e {
        if let (Expr::Const(lhs_value), Expr::Const(rhs_value)) = (lhs.semantic(), rhs.semantic()) {
            let value = match op {
                CmpOp::Eq => lhs_value == rhs_value,
                CmpOp::Ne => lhs_value != rhs_value,
                CmpOp::Ult => (*lhs_value as u64) < (*rhs_value as u64),
                CmpOp::Ule => (*lhs_value as u64) <= (*rhs_value as u64),
                CmpOp::Slt => lhs_value < rhs_value,
                CmpOp::Sle => lhs_value <= rhs_value,
            };
            let origins = lhs
                .origins()
                .into_iter()
                .chain(rhs.origins())
                .fold(crate::ir::ast::OriginSet::empty(), |owners, next| {
                    owners.union(next)
                });
            rewrite(
                e,
                Expr::Const(i64::from(value))
                    .with_optional_origins((!origins.is_empty()).then_some(origins)),
                changed,
            );
            return;
        }
        // Subtraction sets x86's zero flag: `(X - Y) == 0` is exactly
        // `X == Y` (and likewise for `!=`) in modular machine arithmetic.
        // Recover that relation before merging ZF with CF/SF into inclusive
        // comparisons below.
        let subtraction_relation = if matches!(op, CmpOp::Eq | CmpOp::Ne) {
            let operands = if matches!(rhs.semantic(), Expr::Const(0)) {
                Some((lhs.as_ref(), rhs.as_ref()))
            } else if matches!(lhs.semantic(), Expr::Const(0)) {
                Some((rhs.as_ref(), lhs.as_ref()))
            } else {
                None
            };
            operands.and_then(|(subtraction, zero)| {
                let Expr::Bin {
                    op: BinOp::Sub,
                    lhs: sub_lhs,
                    rhs: sub_rhs,
                } = subtraction.semantic()
                else {
                    return None;
                };
                let origins = subtraction
                    .origins()
                    .into_iter()
                    .chain(zero.origins())
                    .fold(crate::ir::ast::OriginSet::empty(), |owners, next| {
                        owners.union(next)
                    });
                Some(
                    Expr::Cmp {
                        op: *op,
                        lhs: sub_lhs.clone(),
                        rhs: sub_rhs.clone(),
                    }
                    .with_optional_origins((!origins.is_empty()).then_some(origins)),
                )
            })
        } else {
            None
        };
        if let Some(replacement) = subtraction_relation {
            rewrite(e, replacement, changed);
            return;
        }

        // A terminal x86 `jg` predicate commonly arrives as
        // `((u64)(u32)x == K | (i64)(i32)x < K) == 0`.  The unsigned and
        // signed extension spellings prevent the general inclusive-relation
        // fold above (correctly: an unobserved eager flag tree may belong to
        // switch recovery).  Under this exact terminal negation, however,
        // equality has the same truth value through either extension when K
        // is representable at the shared signed source width.  Fuse the whole
        // predicate at once; never expose an intermediate mixed-view `<=`.
        if *op == CmpOp::Eq {
            let operands = if matches!(rhs.semantic(), Expr::Const(0)) {
                Some((lhs.as_ref(), rhs.as_ref()))
            } else if matches!(lhs.semantic(), Expr::Const(0)) {
                Some((rhs.as_ref(), lhs.as_ref()))
            } else {
                None
            };
            let candidate = operands.and_then(|(candidate, zero)| {
                invert_mixed_view_equal_or_signed_less(candidate)
                    .map(|replacement| replacement.with_optional_origins(zero.origins().cloned()))
            });
            if let Some(replacement) = candidate {
                rewrite(e, replacement, changed);
                return;
            }
        }

        // Clang sometimes lowers a source-level short-circuit guard into a
        // byte-valued SETcc tree, combines it eagerly, then widens and tests the
        // result. The byte view is the crucial provenance: a bare `cmp | cmp`
        // can just as legitimately be source-level bitwise C, and changing it
        // globally damages CFG fidelity. Recover only the complete terminal
        // test, and only when every leaf is side-effect-free.
        if *op == CmpOp::Ne {
            let operands = if matches!(rhs.semantic(), Expr::Const(0)) {
                Some((lhs.as_ref(), rhs.as_ref()))
            } else if matches!(lhs.semantic(), Expr::Const(0)) {
                Some((rhs.as_ref(), lhs.as_ref()))
            } else {
                None
            };
            let candidate = operands.and_then(|(candidate, zero)| {
                recover_eager_boolean_guard(candidate).map(|(logical, leaves, saw_byte_view)| {
                    (
                        logical.with_optional_origins(zero.origins().cloned()),
                        leaves,
                        saw_byte_view,
                    )
                })
            });
            if let Some((logical, leaves, saw_byte_view)) = candidate {
                if leaves >= 2 && saw_byte_view {
                    rewrite(e, logical, changed);
                    return;
                }
            }
        }

        let inner = if matches!(rhs.semantic(), Expr::Const(0)) && is_exact_boolean(lhs) {
            Some((lhs.as_ref(), rhs.as_ref()))
        } else if matches!(lhs.semantic(), Expr::Const(0)) && is_exact_boolean(rhs) {
            Some((rhs.as_ref(), lhs.as_ref()))
        } else {
            None
        };
        if let Some((inner, zero)) = inner {
            let replacement = match (op, inner.semantic()) {
                (CmpOp::Ne, boolean) => Some(
                    boolean
                        .clone()
                        .with_optional_origins(inner.origins().cloned()),
                ),
                (
                    CmpOp::Eq,
                    Expr::Cmp {
                        op: inner_op,
                        lhs: inner_lhs,
                        rhs: inner_rhs,
                    },
                ) => Some(
                    invert_comparison(*inner_op, inner_lhs, inner_rhs)
                        .with_optional_origins(inner.origins().cloned()),
                ),
                _ => None,
            }
            .map(|replacement| replacement.with_optional_origins(zero.origins().cloned()));
            if let Some(replacement) = replacement {
                rewrite(e, replacement, changed);
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
pub(crate) fn is_exact_boolean(expr: &Expr) -> bool {
    match expr {
        Expr::Origin { expr, .. } => is_exact_boolean(expr),
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
pub(crate) fn is_short_circuit_safe_boolean(expr: &Expr) -> bool {
    match expr {
        Expr::Origin { expr, .. } => is_short_circuit_safe_boolean(expr),
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
        Expr::Origin { expr, .. } => is_short_circuit_safe_value(expr),
        Expr::Reg(_)
        | Expr::Const(_)
        | Expr::FloatConst { .. }
        | Expr::Addr(_)
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::StackAddr { .. }
        | Expr::Lea { .. }
        | Expr::PdbFieldAddr { .. } => true,
        Expr::Cast { expr, .. }
        | Expr::NumericConvert { expr, .. }
        | Expr::Un { src: expr, .. } => is_short_circuit_safe_value(expr),
        Expr::Bin { op, lhs, rhs } => {
            *op != BinOp::Div
                && is_short_circuit_safe_value(lhs)
                && is_short_circuit_safe_value(rhs)
        }
        Expr::Cmp { lhs, rhs, .. } => {
            is_short_circuit_safe_value(lhs) && is_short_circuit_safe_value(rhs)
        }
        Expr::Deref { .. }
        | Expr::Call { .. }
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
        Expr::Origin { origins, expr } => {
            let (logical, leaves, saw_byte_view) = recover_eager_boolean_guard(expr)?;
            Some((logical.with_origins(origins.clone()), leaves, saw_byte_view))
        }
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
            let masked = match (lhs.semantic(), rhs.semantic()) {
                (_, Expr::Const(mask)) if mask & 1 == 1 => {
                    Some((lhs.as_ref(), *mask, rhs.origins().cloned()))
                }
                (Expr::Const(mask), _) if mask & 1 == 1 => {
                    Some((rhs.as_ref(), *mask, lhs.origins().cloned()))
                }
                _ => None,
            };
            if let Some((inner, mask, mask_origins)) = masked {
                let (logical, leaves, saw_byte_view) = recover_eager_boolean_guard(inner)?;
                return Some((
                    logical.with_optional_origins(mask_origins),
                    leaves,
                    saw_byte_view || mask == 255,
                ));
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
fn common_extended_operand(
    expr: &Expr,
    op: CmpOp,
) -> Option<(bool, u8, u8, &Expr, crate::ir::ast::OriginSet)> {
    let Expr::Cast {
        signed: outer_signed,
        width: outer_width,
        expr: outer_expr,
    } = expr.semantic()
    else {
        return None;
    };
    let Expr::Cast {
        signed: inner_signed,
        width: inner_width,
        expr: inner_expr,
    } = outer_expr.semantic()
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
    let cast_origins = expr
        .origins()
        .into_iter()
        .chain(outer_expr.origins())
        .fold(crate::ir::ast::OriginSet::empty(), |owners, next| {
            owners.union(next)
        });
    signedness_matches.then_some((
        *outer_signed,
        *outer_width,
        *inner_width,
        inner_expr.as_ref(),
        cast_origins,
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

    if let Expr::Origin { origins, expr } = value {
        let replacement = fold_observed_mask(expr, observed_mask)?;
        return Some(if matches!(replacement.semantic(), Expr::Const(0)) {
            replacement
        } else {
            replacement.with_origins(origins.clone())
        });
    }

    // `(X & A) & B == X & (A & B)`; combining the constants exposes both
    // zero masks and boolean low-bit reads.
    if let Some((inner, inner_mask, mask_origins)) = and_with_constant(value) {
        return Some(
            Expr::Bin {
                op: BinOp::And,
                lhs: Box::new(inner.clone()),
                rhs: Box::new(Expr::Const(inner_mask & observed_mask)),
            }
            .with_optional_origins((!mask_origins.is_empty()).then_some(mask_origins)),
        );
    }

    // `((X & KEEP) | Y) & OBSERVED == Y & OBSERVED` when KEEP and OBSERVED
    // are disjoint. Handle either OR ordering; no assumption about Y is needed.
    if let Expr::Bin {
        op: BinOp::Or,
        lhs,
        rhs,
    } = value
    {
        if let Some(mask_origins) = masked_term_disjoint_origins(lhs, observed_mask) {
            return Some(
                Expr::Bin {
                    op: BinOp::And,
                    lhs: rhs.clone(),
                    rhs: Box::new(Expr::Const(observed_mask)),
                }
                .with_optional_origins((!mask_origins.is_empty()).then_some(mask_origins)),
            );
        }
        if let Some(mask_origins) = masked_term_disjoint_origins(rhs, observed_mask) {
            return Some(
                Expr::Bin {
                    op: BinOp::And,
                    lhs: lhs.clone(),
                    rhs: Box::new(Expr::Const(observed_mask)),
                }
                .with_optional_origins((!mask_origins.is_empty()).then_some(mask_origins)),
            );
        }
    }
    None
}

fn and_with_constant(expr: &Expr) -> Option<(&Expr, i64, crate::ir::ast::OriginSet)> {
    let Expr::Bin {
        op: BinOp::And,
        lhs,
        rhs,
    } = expr.semantic()
    else {
        return None;
    };
    let (value, mask, mask_origins) = match (lhs.semantic(), rhs.semantic()) {
        (_, Expr::Const(mask)) => Some((lhs.as_ref(), *mask, rhs.origins())),
        (Expr::Const(mask), _) => Some((rhs.as_ref(), *mask, lhs.origins())),
        _ => None,
    }?;
    let origins = expr
        .origins()
        .into_iter()
        .chain(mask_origins)
        .fold(crate::ir::ast::OriginSet::empty(), |owners, next| {
            owners.union(next)
        });
    Some((value, mask, origins))
}

fn masked_term_disjoint_origins(
    expr: &Expr,
    observed_mask: i64,
) -> Option<crate::ir::ast::OriginSet> {
    and_with_constant(expr)
        .filter(|(_, mask, _)| mask & observed_mask == 0)
        .map(|(_, _, origins)| origins)
}

fn merge_equality_and_less(equality: &Expr, less: &Expr) -> Option<Expr> {
    let Expr::Cmp {
        op: CmpOp::Eq,
        lhs: equality_lhs,
        rhs: equality_rhs,
    } = equality.semantic()
    else {
        return None;
    };
    let Expr::Cmp {
        op,
        lhs: less_lhs,
        rhs: less_rhs,
    } = less.semantic()
    else {
        return None;
    };
    // Keep cast signedness as comparison provenance.  Treating equal-width
    // signed and unsigned views as interchangeable here is value-correct for
    // the equality alone, but prematurely rewrites GCC switch range flags into
    // inequalities and destroys the comparison ladder before switch recovery.
    if equality_lhs.semantic() != less_lhs.semantic()
        || equality_rhs.semantic() != less_rhs.semantic()
    {
        return None;
    }
    let op = match op {
        CmpOp::Slt => CmpOp::Sle,
        CmpOp::Ult => CmpOp::Ule,
        _ => return None,
    };
    let origins = equality
        .origins()
        .into_iter()
        .chain(less.origins())
        .fold(crate::ir::ast::OriginSet::empty(), |owners, next| {
            owners.union(next)
        });
    let merge_operand = |first: &Expr, second: &Expr| {
        let origins = first
            .origins()
            .into_iter()
            .chain(second.origins())
            .fold(crate::ir::ast::OriginSet::empty(), |owners, next| {
                owners.union(next)
            });
        first
            .semantic()
            .clone()
            .with_optional_origins((!origins.is_empty()).then_some(origins))
    };
    Some(
        Expr::Cmp {
            op,
            lhs: Box::new(merge_operand(equality_lhs, less_lhs)),
            rhs: Box::new(merge_operand(equality_rhs, less_rhs)),
        }
        .with_optional_origins((!origins.is_empty()).then_some(origins)),
    )
}

/// Prove and invert `(unsigned(x) == K) | (signed(x) < K)` as `K < signed(x)`.
///
/// Both views must be strict widenings of the same expression from the same
/// source width, and K must be non-negative and signed-representable there.
/// This deliberately recognizes only the terminal-negation use above.
fn invert_mixed_view_equal_or_signed_less(expr: &Expr) -> Option<Expr> {
    let Expr::Bin {
        op: BinOp::Or,
        lhs,
        rhs,
    } = expr.semantic()
    else {
        return None;
    };
    let (equality, less) = if matches!(lhs.semantic(), Expr::Cmp { op: CmpOp::Eq, .. }) {
        (lhs.as_ref(), rhs.as_ref())
    } else if matches!(rhs.semantic(), Expr::Cmp { op: CmpOp::Eq, .. }) {
        (rhs.as_ref(), lhs.as_ref())
    } else {
        return None;
    };
    let Expr::Cmp {
        lhs: equality_lhs,
        rhs: equality_rhs,
        ..
    } = equality.semantic()
    else {
        return None;
    };
    let Expr::Cmp {
        op: CmpOp::Slt,
        lhs: less_lhs,
        rhs: less_rhs,
    } = less.semantic()
    else {
        return None;
    };
    let Expr::Const(equality_constant) = equality_rhs.semantic() else {
        return None;
    };
    let Expr::Const(less_constant) = less_rhs.semantic() else {
        return None;
    };
    if equality_constant != less_constant {
        return None;
    }
    let (equality_signed, equality_outer, equality_inner, equality_value, equality_origins) =
        common_extended_operand(equality_lhs, CmpOp::Eq)?;
    let (less_signed, less_outer, less_inner, less_value, less_origins) =
        common_extended_operand(less_lhs, CmpOp::Slt)?;
    if equality_signed
        || !less_signed
        || equality_outer != less_outer
        || equality_inner != less_inner
        || equality_value.semantic() != less_value.semantic()
        || *equality_constant < 0
        || !cast_preserves_constant(*equality_constant, true, equality_inner)
    {
        return None;
    }
    let origins = expr
        .origins()
        .into_iter()
        .chain(equality.origins())
        .chain(less.origins())
        .chain((!equality_origins.is_empty()).then_some(&equality_origins))
        .chain((!less_origins.is_empty()).then_some(&less_origins))
        .chain(equality_value.origins())
        .chain(less_value.origins())
        .fold(crate::ir::ast::OriginSet::empty(), |owners, next| {
            owners.union(next)
        });
    let constant_origins = equality_rhs
        .origins()
        .into_iter()
        .chain(less_rhs.origins())
        .fold(crate::ir::ast::OriginSet::empty(), |owners, next| {
            owners.union(next)
        });
    Some(
        Expr::Cmp {
            op: CmpOp::Slt,
            lhs: Box::new(
                Expr::Const(*less_constant).with_optional_origins(
                    (!constant_origins.is_empty()).then_some(constant_origins),
                ),
            ),
            rhs: less_lhs.clone(),
        }
        .with_optional_origins((!origins.is_empty()).then_some(origins)),
    )
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

    fn extended_view(value: Expr, signed: bool, outer_width: u8, inner_width: u8) -> Expr {
        Expr::Cast {
            signed,
            width: outer_width,
            expr: Box::new(Expr::Cast {
                signed,
                width: inner_width,
                expr: Box::new(value),
            }),
        }
    }

    fn mixed_view_relation(
        equality_value: Expr,
        equality_constant: i64,
        less_value: Expr,
        less_constant: i64,
        less_op: CmpOp,
        equality_widths: (u8, u8),
        less_widths: (u8, u8),
    ) -> Expr {
        bin(
            BinOp::Or,
            Expr::Cmp {
                op: CmpOp::Eq,
                lhs: Box::new(extended_view(
                    equality_value,
                    false,
                    equality_widths.0,
                    equality_widths.1,
                )),
                rhs: Box::new(Expr::Const(equality_constant)),
            },
            Expr::Cmp {
                op: less_op,
                lhs: Box::new(extended_view(
                    less_value,
                    true,
                    less_widths.0,
                    less_widths.1,
                )),
                rhs: Box::new(Expr::Const(less_constant)),
            },
        )
    }

    #[test]
    fn constant_comparison_select_keeps_only_the_selected_value() {
        let mut function = one_stmt(Expr::Select {
            cond: Box::new(Expr::Cmp {
                op: CmpOp::Eq,
                lhs: Box::new(Expr::Const(13)),
                rhs: Box::new(Expr::Const(13)),
            }),
            if_true: Box::new(Expr::Reg(reg("selected"))),
            if_false: Box::new(Expr::Reg(reg("discarded"))),
            width: 4,
        });

        fold_constants(&mut function);

        let Stmt::Assign { src, .. } = &function.body[0] else {
            panic!("fixture assignment disappeared: {:#?}", function.body);
        };
        assert_eq!(src, &Expr::Reg(reg("selected")));
    }

    #[test]
    fn attributed_constant_select_hoists_selected_and_control_origins() {
        let select_owner = crate::ir::ast::OriginSet::one(0x1000);
        let condition_owner = crate::ir::ast::OriginSet::one(0x1004);
        let selected_owner = crate::ir::ast::OriginSet::one(0x1008);
        let unreachable_owner = crate::ir::ast::OriginSet::one(0x100c);
        let mut function = one_stmt(
            Expr::Select {
                cond: Box::new(Expr::Const(1).with_origins(condition_owner.clone())),
                if_true: Box::new(Expr::Reg(reg("selected")).with_origins(selected_owner.clone())),
                if_false: Box::new(
                    Expr::Reg(reg("unreachable")).with_origins(unreachable_owner.clone()),
                ),
                width: 8,
            }
            .with_origins(select_owner.clone()),
        );

        fold_constants(&mut function);

        let Stmt::Assign { src, .. } = &function.body[0] else {
            panic!("expected assignment")
        };
        assert_eq!(src.semantic(), &Expr::Reg(reg("selected")));
        let expected = select_owner.union(&condition_owner).union(&selected_owner);
        assert_eq!(src.origins(), Some(&expected));
        assert!(!src
            .origins()
            .expect("selected value must remain attributed")
            .addresses()
            .contains(&0x100c));
    }

    #[test]
    fn repeated_select_condition_drops_unreachable_prior_values() {
        let condition = Expr::Cmp {
            op: CmpOp::Ule,
            lhs: Box::new(Expr::Reg(reg("count"))),
            rhs: Box::new(Expr::Const(64)),
        };
        let mut function = one_stmt(Expr::Select {
            cond: Box::new(condition.clone()),
            if_true: Box::new(Expr::Select {
                cond: Box::new(condition),
                if_true: Box::new(Expr::Const(0)),
                if_false: Box::new(Expr::Reg(reg("undefined_prior"))),
                width: 4,
            }),
            if_false: Box::new(Expr::Const(1)),
            width: 4,
        });

        fold_constants(&mut function);

        let Stmt::Assign { src, .. } = &function.body[0] else {
            panic!("fixture assignment disappeared: {:#?}", function.body);
        };
        assert!(
            matches!(src, Expr::Select { if_true, .. } if if_true.as_ref() == &Expr::Const(0)),
            "{src:#?}"
        );
        assert!(!format!("{src:?}").contains("undefined_prior"));
    }

    #[test]
    fn attributed_repeated_select_unions_removed_control_origins() {
        let condition = || Expr::Cmp {
            op: CmpOp::Ule,
            lhs: Box::new(Expr::Reg(reg("count"))),
            rhs: Box::new(Expr::Const(64)),
        };
        let outer_select_owner = crate::ir::ast::OriginSet::one(0x1000);
        let outer_condition_owner = crate::ir::ast::OriginSet::one(0x1004);
        let inner_select_owner = crate::ir::ast::OriginSet::one(0x1008);
        let inner_condition_owner = crate::ir::ast::OriginSet::one(0x100c);
        let unreachable_owner = crate::ir::ast::OriginSet::one(0x1010);
        let mut function = one_stmt(
            Expr::Select {
                cond: Box::new(condition().with_origins(outer_condition_owner)),
                if_true: Box::new(
                    Expr::Select {
                        cond: Box::new(condition().with_origins(inner_condition_owner.clone())),
                        if_true: Box::new(Expr::Const(0)),
                        if_false: Box::new(
                            Expr::Reg(reg("undefined_prior"))
                                .with_origins(unreachable_owner.clone()),
                        ),
                        width: 4,
                    }
                    .with_origins(inner_select_owner.clone()),
                ),
                if_false: Box::new(Expr::Const(1)),
                width: 4,
            }
            .with_origins(outer_select_owner.clone()),
        );

        fold_constants(&mut function);

        let Stmt::Assign { src, .. } = &function.body[0] else {
            panic!("expected assignment")
        };
        assert!(matches!(src.semantic(), Expr::Select { if_true, .. }
            if if_true.semantic() == &Expr::Const(0)));
        let expected = outer_select_owner
            .union(&inner_select_owner)
            .union(&inner_condition_owner);
        assert_eq!(src.origins(), Some(&expected));
        assert!(!format!("{src:?}").contains("undefined_prior"));
        assert!(!src
            .origins()
            .expect("collapsed select must remain attributed")
            .addresses()
            .contains(&unreachable_owner.addresses()[0]));
    }

    #[test]
    fn repeated_effectful_select_condition_is_not_collapsed() {
        let condition = Expr::Call {
            target: Box::new(Expr::Addr(0x1234)),
            args: Vec::new(),
            call_spec: None,
            result_width: Some(4),
        };
        let original = Expr::Select {
            cond: Box::new(condition.clone()),
            if_true: Box::new(Expr::Select {
                cond: Box::new(condition),
                if_true: Box::new(Expr::Const(0)),
                if_false: Box::new(Expr::Reg(reg("prior"))),
                width: 4,
            }),
            if_false: Box::new(Expr::Const(1)),
            width: 4,
        };
        let mut function = one_stmt(original.clone());

        fold_constants(&mut function);

        let Stmt::Assign { src, .. } = &function.body[0] else {
            panic!("fixture assignment disappeared: {:#?}", function.body);
        };
        assert_eq!(src, &original);
    }

    #[test]
    fn repeated_false_arm_condition_drops_unreachable_prior_value() {
        let condition = Expr::Reg(reg("condition"));
        let mut function = one_stmt(Expr::Select {
            cond: Box::new(condition.clone()),
            if_true: Box::new(Expr::Const(1)),
            if_false: Box::new(Expr::Select {
                cond: Box::new(condition),
                if_true: Box::new(Expr::Reg(reg("undefined_prior"))),
                if_false: Box::new(Expr::Const(0)),
                width: 4,
            }),
            width: 4,
        });

        fold_constants(&mut function);

        let Stmt::Assign { src, .. } = &function.body[0] else {
            panic!("fixture assignment disappeared: {:#?}", function.body);
        };
        assert!(
            matches!(src, Expr::Select { if_false, .. } if if_false.as_ref() == &Expr::Const(0)),
            "{src:#?}"
        );
        assert!(!format!("{src:?}").contains("undefined_prior"));
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

    #[test]
    fn attributed_constant_arithmetic_folds_and_unions_origins() {
        let outer_owner = crate::ir::ast::OriginSet::one(0x1000);
        let lhs_owner = crate::ir::ast::OriginSet::one(0x1004);
        let rhs_owner = crate::ir::ast::OriginSet::one(0x1008);
        let mut f = one_stmt(
            bin(
                BinOp::Mul,
                Expr::Const(6).with_origins(lhs_owner.clone()),
                Expr::Const(7).with_origins(rhs_owner.clone()),
            )
            .with_origins(outer_owner.clone()),
        );

        fold_constants(&mut f);

        let Stmt::Assign { src, .. } = &f.body[0] else {
            panic!("expected assignment");
        };
        assert_eq!(src.semantic(), &Expr::Const(42));
        assert_eq!(
            src.origins(),
            Some(&outer_owner.union(&lhs_owner).union(&rhs_owner))
        );
    }

    #[test]
    fn attributed_constant_comparison_folds_and_unions_origins() {
        let outer_owner = crate::ir::ast::OriginSet::one(0x1010);
        let lhs_owner = crate::ir::ast::OriginSet::one(0x1014);
        let rhs_owner = crate::ir::ast::OriginSet::one(0x1018);
        let mut f = one_stmt(
            Expr::Cmp {
                op: CmpOp::Slt,
                lhs: Box::new(Expr::Const(3).with_origins(lhs_owner.clone())),
                rhs: Box::new(Expr::Const(5).with_origins(rhs_owner.clone())),
            }
            .with_origins(outer_owner.clone()),
        );

        fold_constants(&mut f);

        let Stmt::Assign { src, .. } = &f.body[0] else {
            panic!("expected assignment");
        };
        assert_eq!(src.semantic(), &Expr::Const(1));
        assert_eq!(
            src.origins(),
            Some(&outer_owner.union(&lhs_owner).union(&rhs_owner))
        );
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

    #[test]
    fn attributed_address_reconstruction_unions_base_and_offset_origins() {
        let add_owner = crate::ir::ast::OriginSet::one(0x1060);
        let page_owner = crate::ir::ast::OriginSet::one(0x1064);
        let offset_owner = crate::ir::ast::OriginSet::one(0x1068);
        let mut f = one_stmt(
            bin(
                BinOp::Add,
                Expr::Addr(0x1f000).with_origins(page_owner.clone()),
                Expr::Const(0x2a8).with_origins(offset_owner.clone()),
            )
            .with_origins(add_owner.clone()),
        );

        fold_constants(&mut f);

        let Stmt::Assign { src, .. } = &f.body[0] else {
            panic!("expected assignment")
        };
        assert_eq!(src.semantic(), &Expr::Addr(0x1f2a8));
        assert_eq!(
            src.origins(),
            Some(&add_owner.union(&page_owner).union(&offset_owner))
        );
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
    fn attributed_xor_cancellation_retains_origin() {
        let less = Expr::Cmp {
            op: CmpOp::Slt,
            lhs: Box::new(Expr::Reg(reg("rax"))),
            rhs: Box::new(Expr::Reg(reg("rbx"))),
        };
        let sign = Expr::Reg(reg("sf"));
        let owner = crate::ir::ast::OriginSet::one(0x1000);
        let mut f = one_stmt(
            bin(
                BinOp::Xor,
                sign.clone(),
                bin(BinOp::Xor, less.clone(), sign),
            )
            .with_origins(owner.clone()),
        );

        fold_constants(&mut f);

        let Stmt::Assign { src, .. } = &f.body[0] else {
            panic!("expected assignment")
        };
        assert_eq!(src.semantic(), &less);
        assert_eq!(src.origins(), Some(&owner));
    }

    #[test]
    fn attributed_xor_cancellation_unions_consumed_flag_origins() {
        let outer_owner = crate::ir::ast::OriginSet::one(0x1070);
        let first_flag_owner = crate::ir::ast::OriginSet::one(0x1074);
        let nested_owner = crate::ir::ast::OriginSet::one(0x1078);
        let relation_owner = crate::ir::ast::OriginSet::one(0x107c);
        let repeated_flag_owner = crate::ir::ast::OriginSet::one(0x1080);
        let relation = Expr::Cmp {
            op: CmpOp::Slt,
            lhs: Box::new(Expr::Reg(reg("rax"))),
            rhs: Box::new(Expr::Reg(reg("rbx"))),
        };
        let mut function = one_stmt(
            bin(
                BinOp::Xor,
                Expr::Reg(reg("sf")).with_origins(first_flag_owner.clone()),
                bin(
                    BinOp::Xor,
                    relation.clone().with_origins(relation_owner.clone()),
                    Expr::Reg(reg("sf")).with_origins(repeated_flag_owner.clone()),
                )
                .with_origins(nested_owner.clone()),
            )
            .with_origins(outer_owner.clone()),
        );

        fold_constants(&mut function);

        let Stmt::Assign { src, .. } = &function.body[0] else {
            panic!("expected assignment")
        };
        assert_eq!(src.semantic(), &relation);
        assert_eq!(
            src.origins(),
            Some(
                &outer_owner
                    .union(&first_flag_owner)
                    .union(&nested_owner)
                    .union(&relation_owner)
                    .union(&repeated_flag_owner)
            )
        );
    }

    #[test]
    fn attributed_same_operand_identity_unions_both_owners() {
        let outer_owner = crate::ir::ast::OriginSet::one(0x1020);
        let lhs_owner = crate::ir::ast::OriginSet::one(0x1024);
        let rhs_owner = crate::ir::ast::OriginSet::one(0x1028);
        let mut f = one_stmt(
            bin(
                BinOp::Xor,
                Expr::Reg(reg("rax")).with_origins(lhs_owner.clone()),
                Expr::Reg(reg("rax")).with_origins(rhs_owner.clone()),
            )
            .with_origins(outer_owner.clone()),
        );

        fold_constants(&mut f);

        let Stmt::Assign { src, .. } = &f.body[0] else {
            panic!("expected assignment")
        };
        assert_eq!(src.semantic(), &Expr::Const(0));
        assert_eq!(
            src.origins(),
            Some(&outer_owner.union(&lhs_owner).union(&rhs_owner))
        );
    }

    #[test]
    fn attributed_constant_identities_keep_only_semantic_contributors() {
        let neutral_outer = crate::ir::ast::OriginSet::one(0x1030);
        let neutral_value = crate::ir::ast::OriginSet::one(0x1034);
        let neutral_zero = crate::ir::ast::OriginSet::one(0x1038);
        let absorbing_outer = crate::ir::ast::OriginSet::one(0x1040);
        let discarded_value = crate::ir::ast::OriginSet::one(0x1044);
        let absorbing_zero = crate::ir::ast::OriginSet::one(0x1048);
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("rax"),
                    src: bin(
                        BinOp::Add,
                        Expr::Reg(reg("value")).with_origins(neutral_value.clone()),
                        Expr::Const(0).with_origins(neutral_zero.clone()),
                    )
                    .with_origins(neutral_outer.clone()),
                },
                Stmt::Assign {
                    dst: reg("rbx"),
                    src: bin(
                        BinOp::Mul,
                        Expr::Reg(reg("discarded")).with_origins(discarded_value.clone()),
                        Expr::Const(0).with_origins(absorbing_zero.clone()),
                    )
                    .with_origins(absorbing_outer.clone()),
                },
            ],
        };

        fold_constants(&mut f);

        let Stmt::Assign { src: neutral, .. } = &f.body[0] else {
            panic!("expected neutral assignment")
        };
        assert_eq!(neutral.semantic(), &Expr::Reg(reg("value")));
        assert_eq!(
            neutral.origins(),
            Some(&neutral_outer.union(&neutral_value).union(&neutral_zero))
        );

        let Stmt::Assign { src: absorbing, .. } = &f.body[1] else {
            panic!("expected absorbing assignment")
        };
        assert_eq!(absorbing.semantic(), &Expr::Const(0));
        assert_eq!(
            absorbing.origins(),
            Some(&absorbing_outer.union(&absorbing_zero))
        );
    }

    #[test]
    fn zero_test_inverts_attributed_comparison_and_retains_origin() {
        let owner = crate::ir::ast::OriginSet::one(0x1000);
        let comparison = Expr::Cmp {
            op: CmpOp::Slt,
            lhs: Box::new(Expr::Reg(reg("a"))),
            rhs: Box::new(Expr::Reg(reg("b"))),
        }
        .with_origins(owner.clone());
        let mut function = one_stmt(Expr::Cmp {
            op: CmpOp::Eq,
            lhs: Box::new(comparison),
            rhs: Box::new(Expr::Const(0)),
        });

        fold_constants(&mut function);

        let Stmt::Assign { src, .. } = &function.body[0] else {
            panic!("expected assignment")
        };
        assert!(matches!(
            src.semantic(),
            Expr::Cmp { op: CmpOp::Sle, lhs, rhs }
                if matches!(lhs.as_ref(), Expr::Reg(register) if register == &reg("b"))
                    && matches!(rhs.as_ref(), Expr::Reg(register) if register == &reg("a"))
        ));
        assert_eq!(src.origins(), Some(&owner));
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
    fn attributed_equality_or_less_merges_and_unions_origins() {
        let lhs = Expr::Reg(reg("rax"));
        let rhs = Expr::Reg(reg("rbx"));
        let equality_owner = crate::ir::ast::OriginSet::one(0x1000);
        let less_owner = crate::ir::ast::OriginSet::one(0x1004);
        let equality_lhs_owner = crate::ir::ast::OriginSet::one(0x1008);
        let equality_rhs_owner = crate::ir::ast::OriginSet::one(0x100c);
        let less_lhs_owner = crate::ir::ast::OriginSet::one(0x1010);
        let less_rhs_owner = crate::ir::ast::OriginSet::one(0x1014);
        let mut function = one_stmt(bin(
            BinOp::Or,
            Expr::Cmp {
                op: CmpOp::Eq,
                lhs: Box::new(lhs.clone().with_origins(equality_lhs_owner.clone())),
                rhs: Box::new(rhs.clone().with_origins(equality_rhs_owner.clone())),
            }
            .with_origins(equality_owner.clone()),
            Expr::Cmp {
                op: CmpOp::Slt,
                lhs: Box::new(lhs.clone().with_origins(less_lhs_owner.clone())),
                rhs: Box::new(rhs.clone().with_origins(less_rhs_owner.clone())),
            }
            .with_origins(less_owner.clone()),
        ));

        fold_constants(&mut function);

        let Stmt::Assign { src, .. } = &function.body[0] else {
            panic!("expected assignment")
        };
        assert!(matches!(
            src.semantic(),
            Expr::Cmp { op: CmpOp::Sle, lhs, rhs }
                if matches!(lhs.semantic(), Expr::Reg(register) if register == &reg("rax"))
                    && matches!(rhs.semantic(), Expr::Reg(register) if register == &reg("rbx"))
        ));
        assert_eq!(src.origins(), Some(&equality_owner.union(&less_owner)));
        let Expr::Cmp {
            lhs: merged_lhs,
            rhs: merged_rhs,
            ..
        } = src.semantic()
        else {
            unreachable!()
        };
        assert_eq!(
            merged_lhs.origins(),
            Some(&equality_lhs_owner.union(&less_lhs_owner))
        );
        assert_eq!(
            merged_rhs.origins(),
            Some(&equality_rhs_owner.union(&less_rhs_owner))
        );
    }

    #[test]
    fn attributed_subtraction_zero_test_recovers_relation_and_unions_origins() {
        let lhs = Expr::Reg(reg("rax"));
        let rhs = Expr::Reg(reg("rbx"));
        let comparison_owner = crate::ir::ast::OriginSet::one(0x1000);
        let subtraction_owner = crate::ir::ast::OriginSet::one(0x1004);
        let subtraction =
            bin(BinOp::Sub, lhs.clone(), rhs.clone()).with_origins(subtraction_owner.clone());
        let mut function = one_stmt(
            Expr::Cmp {
                op: CmpOp::Eq,
                lhs: Box::new(subtraction),
                rhs: Box::new(Expr::Const(0)),
            }
            .with_origins(comparison_owner.clone()),
        );

        fold_constants(&mut function);

        let Stmt::Assign { src, .. } = &function.body[0] else {
            panic!("expected assignment")
        };
        assert_eq!(
            src.semantic(),
            &Expr::Cmp {
                op: CmpOp::Eq,
                lhs: Box::new(lhs),
                rhs: Box::new(rhs),
            }
        );
        assert_eq!(
            src.origins(),
            Some(&comparison_owner.union(&subtraction_owner))
        );
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
    fn terminal_mixed_view_equal_or_signed_less_recovers_greater_than() {
        let value = Expr::Reg(reg("arg0"));
        let view = |signed: bool, value: Expr| Expr::Cast {
            signed,
            width: 8,
            expr: Box::new(Expr::Cast {
                signed,
                width: 4,
                expr: Box::new(value),
            }),
        };
        let signed_value = view(true, value.clone());
        let mut function = one_stmt(Expr::Cmp {
            op: CmpOp::Eq,
            lhs: Box::new(bin(
                BinOp::Or,
                Expr::Cmp {
                    op: CmpOp::Eq,
                    lhs: Box::new(view(false, value)),
                    rhs: Box::new(Expr::Const(100)),
                },
                Expr::Cmp {
                    op: CmpOp::Slt,
                    lhs: Box::new(signed_value.clone()),
                    rhs: Box::new(Expr::Const(100)),
                },
            )),
            rhs: Box::new(Expr::Const(0)),
        });

        fold_constants(&mut function);

        let Stmt::Assign { src, .. } = &function.body[0] else {
            panic!("expected assignment")
        };
        assert_eq!(
            *src,
            Expr::Cmp {
                op: CmpOp::Slt,
                lhs: Box::new(Expr::Const(100)),
                rhs: Box::new(signed_value),
            }
        );
    }

    #[test]
    fn attributed_terminal_mixed_view_relation_unions_consumed_origins() {
        let value = Expr::Reg(reg("arg0"));
        let view = |signed: bool, value: Expr| Expr::Cast {
            signed,
            width: 8,
            expr: Box::new(Expr::Cast {
                signed,
                width: 4,
                expr: Box::new(value),
            }),
        };
        let terminal_owner = crate::ir::ast::OriginSet::one(0x1000);
        let relation_owner = crate::ir::ast::OriginSet::one(0x1004);
        let equality_owner = crate::ir::ast::OriginSet::one(0x1008);
        let less_owner = crate::ir::ast::OriginSet::one(0x100c);
        let zero_owner = crate::ir::ast::OriginSet::one(0x1010);
        let equality_constant_owner = crate::ir::ast::OriginSet::one(0x1014);
        let less_constant_owner = crate::ir::ast::OriginSet::one(0x1018);
        let equality_value_owner = crate::ir::ast::OriginSet::one(0x101c);
        let less_value_owner = crate::ir::ast::OriginSet::one(0x1020);
        let signed_value = view(true, value.clone().with_origins(less_value_owner.clone()));
        let relation = bin(
            BinOp::Or,
            Expr::Cmp {
                op: CmpOp::Eq,
                lhs: Box::new(view(
                    false,
                    value.with_origins(equality_value_owner.clone()),
                )),
                rhs: Box::new(Expr::Const(100).with_origins(equality_constant_owner.clone())),
            }
            .with_origins(equality_owner.clone()),
            Expr::Cmp {
                op: CmpOp::Slt,
                lhs: Box::new(signed_value.clone()),
                rhs: Box::new(Expr::Const(100).with_origins(less_constant_owner.clone())),
            }
            .with_origins(less_owner.clone()),
        )
        .with_origins(relation_owner.clone());
        let mut function = one_stmt(
            Expr::Cmp {
                op: CmpOp::Eq,
                lhs: Box::new(relation),
                rhs: Box::new(Expr::Const(0).with_origins(zero_owner.clone())),
            }
            .with_origins(terminal_owner.clone()),
        );

        fold_constants(&mut function);

        let Stmt::Assign { src, .. } = &function.body[0] else {
            panic!("expected assignment")
        };
        let Expr::Cmp {
            op: CmpOp::Slt,
            lhs,
            rhs,
        } = src.semantic()
        else {
            panic!("expected recovered signed relation: {src:#?}")
        };
        assert_eq!(lhs.semantic(), &Expr::Const(100));
        assert_eq!(rhs.semantic(), signed_value.semantic());
        assert_eq!(
            lhs.origins(),
            Some(&equality_constant_owner.union(&less_constant_owner))
        );
        let expected = terminal_owner
            .union(&relation_owner)
            .union(&equality_owner)
            .union(&less_owner)
            .union(&zero_owner)
            .union(&equality_value_owner)
            .union(&less_value_owner);
        assert_eq!(src.origins(), Some(&expected));
    }

    #[test]
    fn terminal_mixed_view_relation_refuses_an_unsigned_only_constant() {
        let value = Expr::Reg(reg("arg0"));
        let view = |signed: bool, value: Expr| Expr::Cast {
            signed,
            width: 8,
            expr: Box::new(Expr::Cast {
                signed,
                width: 4,
                expr: Box::new(value),
            }),
        };
        let original = Expr::Cmp {
            op: CmpOp::Eq,
            lhs: Box::new(bin(
                BinOp::Or,
                Expr::Cmp {
                    op: CmpOp::Eq,
                    lhs: Box::new(view(false, value.clone())),
                    rhs: Box::new(Expr::Const(-1)),
                },
                Expr::Cmp {
                    op: CmpOp::Slt,
                    lhs: Box::new(view(true, value)),
                    rhs: Box::new(Expr::Const(-1)),
                },
            )),
            rhs: Box::new(Expr::Const(0)),
        };
        let mut function = one_stmt(original.clone());

        fold_constants(&mut function);

        assert_eq!(function.body[0], one_stmt(original).body[0]);
    }

    #[test]
    fn terminal_mixed_view_relation_refuses_different_values() {
        let relation = mixed_view_relation(
            Expr::Reg(reg("lhs")),
            100,
            Expr::Reg(reg("rhs")),
            100,
            CmpOp::Slt,
            (8, 4),
            (8, 4),
        );

        assert!(invert_mixed_view_equal_or_signed_less(&relation).is_none());
    }

    #[test]
    fn terminal_mixed_view_relation_refuses_different_constants() {
        let value = Expr::Reg(reg("arg0"));
        let relation =
            mixed_view_relation(value.clone(), 100, value, 101, CmpOp::Slt, (8, 4), (8, 4));

        assert!(invert_mixed_view_equal_or_signed_less(&relation).is_none());
    }

    #[test]
    fn terminal_mixed_view_relation_refuses_unsigned_less() {
        let value = Expr::Reg(reg("arg0"));
        let relation =
            mixed_view_relation(value.clone(), 100, value, 100, CmpOp::Ult, (8, 4), (8, 4));

        assert!(invert_mixed_view_equal_or_signed_less(&relation).is_none());
    }

    #[test]
    fn terminal_mixed_view_relation_refuses_mixed_widths() {
        let value = Expr::Reg(reg("arg0"));
        let relation =
            mixed_view_relation(value.clone(), 100, value, 100, CmpOp::Slt, (8, 4), (8, 2));

        assert!(invert_mixed_view_equal_or_signed_less(&relation).is_none());
    }

    #[test]
    fn terminal_mixed_view_relation_requires_terminal_equality_to_zero() {
        let value = Expr::Reg(reg("arg0"));
        let relation =
            mixed_view_relation(value.clone(), 100, value, 100, CmpOp::Slt, (8, 4), (8, 4));
        let original = Expr::Cmp {
            op: CmpOp::Ne,
            lhs: Box::new(relation),
            rhs: Box::new(Expr::Const(0)),
        };
        let mut function = one_stmt(original.clone());

        fold_constants(&mut function);

        assert_eq!(function.body[0], one_stmt(original).body[0]);
    }

    #[test]
    fn terminal_mixed_view_relation_requires_extension_provenance() {
        let value = Expr::Reg(reg("arg0"));
        let relation = bin(
            BinOp::Or,
            Expr::Cmp {
                op: CmpOp::Eq,
                lhs: Box::new(value.clone()),
                rhs: Box::new(Expr::Const(100)),
            },
            Expr::Cmp {
                op: CmpOp::Slt,
                lhs: Box::new(value),
                rhs: Box::new(Expr::Const(100)),
            },
        );

        assert!(invert_mixed_view_equal_or_signed_less(&relation).is_none());
    }

    #[test]
    fn terminal_mixed_view_relation_is_exhaustively_equivalent_at_8_and_16_bits() {
        for width in [1_u8, 2_u8] {
            let bits = u32::from(width) * 8;
            let modulus = 1_u64 << bits;
            let sign_bit = 1_u64 << (bits - 1);
            let signed_max = sign_bit - 1;
            for constant in [0_u64, 1, signed_max / 2, signed_max] {
                for raw in 0..modulus {
                    let signed_value = if raw & sign_bit == 0 {
                        i64::try_from(raw).unwrap()
                    } else {
                        i64::try_from(raw).unwrap() - i64::try_from(modulus).unwrap()
                    };
                    let constant = i64::try_from(constant).unwrap();
                    let original =
                        !(raw == u64::try_from(constant).unwrap() || signed_value < constant);
                    let fused = constant < signed_value;
                    assert_eq!(
                        original, fused,
                        "width={width} raw={raw:#x} signed={signed_value} constant={constant}"
                    );
                }
            }
        }
    }

    #[test]
    fn terminal_mixed_view_relation_wide_boundaries_and_seeded_values_are_equivalent() {
        for width in [4_u8, 8_u8] {
            let bits = u32::from(width) * 8;
            let sign_bit = 1_u64 << (bits - 1);
            let mask = if width == 8 {
                u64::MAX
            } else {
                (1_u64 << bits) - 1
            };
            let signed_max = sign_bit - 1;
            for constant in [0_u64, 1, 100, signed_max] {
                let mut values = vec![
                    0,
                    constant.saturating_sub(1),
                    constant,
                    constant.saturating_add(1) & mask,
                    signed_max,
                    sign_bit,
                    mask,
                ];
                let mut seed = 0x4a47_5eed_c1a5_51f1_u64;
                for _ in 0..4096 {
                    seed = seed
                        .wrapping_mul(6364136223846793005)
                        .wrapping_add(1442695040888963407);
                    values.push(seed & mask);
                }
                for raw in values {
                    let signed_value = if width == 8 {
                        raw as i64
                    } else if raw & sign_bit == 0 {
                        i64::try_from(raw).unwrap()
                    } else {
                        i64::try_from(raw).unwrap() - (1_i64 << bits)
                    };
                    let constant = i64::try_from(constant).unwrap();
                    let original =
                        !(raw == u64::try_from(constant).unwrap() || signed_value < constant);
                    let fused = constant < signed_value;
                    assert_eq!(
                        original, fused,
                        "width={width} raw={raw:#x} signed={signed_value} constant={constant}"
                    );
                }
            }
        }
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
    fn attributed_observed_mask_keeps_surviving_low_bit_origins() {
        let observed_owner = crate::ir::ast::OriginSet::one(0x1000);
        let merge_owner = crate::ir::ast::OriginSet::one(0x1004);
        let predicate_owner = crate::ir::ast::OriginSet::one(0x1008);
        let discarded_owner = crate::ir::ast::OriginSet::one(0x100c);
        let mask_owner = crate::ir::ast::OriginSet::one(0x1010);
        let discarded_mask_tree_owner = crate::ir::ast::OriginSet::one(0x1014);
        let discarded_mask_owner = crate::ir::ast::OriginSet::one(0x1018);
        let old = Expr::Reg(reg("old_parent")).with_origins(discarded_owner.clone());
        let predicate = Expr::Cmp {
            op: CmpOp::Eq,
            lhs: Box::new(Expr::Reg(reg("state"))),
            rhs: Box::new(Expr::Const(3)),
        }
        .with_origins(predicate_owner.clone());
        let merged = bin(
            BinOp::Or,
            bin(
                BinOp::And,
                old,
                Expr::Const(-256).with_origins(discarded_mask_owner.clone()),
            )
            .with_origins(discarded_mask_tree_owner.clone()),
            bin(
                BinOp::And,
                bin(BinOp::And, predicate, Expr::Const(255)),
                Expr::Const(1),
            ),
        )
        .with_origins(merge_owner.clone());
        let mut function = one_stmt(
            bin(
                BinOp::And,
                merged,
                Expr::Const(255).with_origins(mask_owner.clone()),
            )
            .with_origins(observed_owner.clone()),
        );

        fold_constants(&mut function);

        let Stmt::Assign { src, .. } = &function.body[0] else {
            panic!("expected assignment")
        };
        assert!(matches!(src.semantic(), Expr::Cmp { op: CmpOp::Eq, .. }));
        let expected = observed_owner
            .union(&merge_owner)
            .union(&predicate_owner)
            .union(&mask_owner)
            .union(&discarded_mask_tree_owner)
            .union(&discarded_mask_owner);
        assert_eq!(src.origins(), Some(&expected));
        assert!(!src
            .origins()
            .expect("observed predicate must remain attributed")
            .addresses()
            .contains(&discarded_owner.addresses()[0]));
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
    fn exact_opaque_identity_removes_its_redundant_unsigned_view() {
        use crate::ir::types_recover::{TypeHint, TypeMap};

        let value = reg("opaque_value");
        let mut function = one_stmt(Expr::Cast {
            signed: false,
            width: 8,
            expr: Box::new(Expr::Cast {
                signed: false,
                width: 4,
                expr: Box::new(Expr::Reg(value.clone())),
            }),
        });
        let mut types = TypeMap::default();
        types.upsert_public(
            value.clone(),
            TypeHint::Int {
                signed: false,
                width: 4,
            },
        );
        let mut identities = crate::ir::value_number::ValueIdentities::default();
        identities.record(
            value.clone(),
            crate::ir::ssa::SsaValue {
                base: reg("eax"),
                version: 1,
            },
        );

        fold_typed_declared_views_with_identities(&mut function, &types, Some(&identities));

        assert!(matches!(
            &function.body[0],
            Stmt::Assign { src: Expr::Reg(source), .. } if source == &value
        ));
    }

    #[test]
    fn ambiguous_opaque_identity_keeps_its_unsigned_view() {
        use crate::ir::types_recover::{TypeHint, TypeMap};

        let value = reg("opaque_value");
        let view = Expr::Cast {
            signed: false,
            width: 8,
            expr: Box::new(Expr::Cast {
                signed: false,
                width: 4,
                expr: Box::new(Expr::Reg(value.clone())),
            }),
        };
        let mut function = one_stmt(view.clone());
        let mut types = TypeMap::default();
        types.upsert_public(
            value.clone(),
            TypeHint::Int {
                signed: false,
                width: 4,
            },
        );
        let mut identities = crate::ir::value_number::ValueIdentities::default();
        for (base, version) in [("eax", 1), ("ebx", 2)] {
            identities.record(
                value.clone(),
                crate::ir::ssa::SsaValue {
                    base: reg(base),
                    version,
                },
            );
        }

        fold_typed_declared_views_with_identities(&mut function, &types, Some(&identities));

        assert!(matches!(
            &function.body[0],
            Stmt::Assign { src, .. } if src == &view
        ));
    }

    #[test]
    fn attributed_typed_register_view_unions_both_cast_and_source_origins() {
        use crate::ir::types_recover::{TypeHint, TypeMap};

        let outer_owner = crate::ir::ast::OriginSet::one(0x10a0);
        let inner_owner = crate::ir::ast::OriginSet::one(0x10a4);
        let source_owner = crate::ir::ast::OriginSet::one(0x10a8);
        let mut function = one_stmt(
            Expr::Cast {
                signed: false,
                width: 8,
                expr: Box::new(
                    Expr::Cast {
                        signed: false,
                        width: 4,
                        expr: Box::new(Expr::Reg(reg("arg0")).with_origins(source_owner.clone())),
                    }
                    .with_origins(inner_owner.clone()),
                ),
            }
            .with_origins(outer_owner.clone()),
        );
        let mut types = TypeMap::default();
        types.upsert_public(
            reg("arg0"),
            TypeHint::Int {
                signed: false,
                width: 4,
            },
        );

        fold_typed_declared_views(&mut function, &types);

        let Stmt::Assign { src, .. } = &function.body[0] else {
            panic!("expected assignment")
        };
        assert_eq!(src.semantic(), &Expr::Reg(reg("arg0")));
        assert_eq!(
            src.origins(),
            Some(&outer_owner.union(&inner_owner).union(&source_owner))
        );
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
    fn exact_opaque_identities_remove_matching_comparison_extensions() {
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
        let mut function = one_stmt(Expr::Cmp {
            op: CmpOp::Slt,
            lhs: Box::new(extended("opaque_left")),
            rhs: Box::new(extended("opaque_right")),
        });
        let mut types = TypeMap::default();
        let mut identities = crate::ir::value_number::ValueIdentities::default();
        for (name, base) in [("opaque_left", "eax"), ("opaque_right", "ebx")] {
            types.upsert_public(
                reg(name),
                TypeHint::Int {
                    signed: true,
                    width: 4,
                },
            );
            identities.record(
                reg(name),
                crate::ir::ssa::SsaValue {
                    base: reg(base),
                    version: 1,
                },
            );
        }

        fold_typed_comparison_extensions_with_identities(&mut function, &types, Some(&identities));

        assert!(matches!(
            &function.body[0],
            Stmt::Assign {
                src: Expr::Cmp { lhs, rhs, .. },
                ..
            } if matches!(lhs.as_ref(), Expr::Reg(value) if value == &reg("opaque_left"))
                && matches!(rhs.as_ref(), Expr::Reg(value) if value == &reg("opaque_right"))
        ));
    }

    #[test]
    fn ambiguous_opaque_identity_keeps_comparison_extensions() {
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
        let mut function = one_stmt(Expr::Cmp {
            op: CmpOp::Slt,
            lhs: Box::new(extended("opaque_left")),
            rhs: Box::new(extended("opaque_right")),
        });
        let mut types = TypeMap::default();
        let mut identities = crate::ir::value_number::ValueIdentities::default();
        for name in ["opaque_left", "opaque_right"] {
            types.upsert_public(
                reg(name),
                TypeHint::Int {
                    signed: true,
                    width: 4,
                },
            );
        }
        identities.record(
            reg("opaque_left"),
            crate::ir::ssa::SsaValue {
                base: reg("eax"),
                version: 1,
            },
        );
        for (base, version) in [("ebx", 1), ("ecx", 2)] {
            identities.record(
                reg("opaque_right"),
                crate::ir::ssa::SsaValue {
                    base: reg(base),
                    version,
                },
            );
        }

        fold_typed_comparison_extensions_with_identities(&mut function, &types, Some(&identities));

        assert!(matches!(
            &function.body[0],
            Stmt::Assign {
                src: Expr::Cmp { lhs, rhs, .. },
                ..
            } if matches!(lhs.as_ref(), Expr::Cast { width: 8, .. })
                && matches!(rhs.as_ref(), Expr::Cast { width: 8, .. })
        ));
    }

    #[test]
    fn typed_comparison_views_preserve_cast_and_source_origins() {
        use crate::ir::types_recover::{TypeHint, TypeMap};

        let extended = |name, base| {
            Expr::Cast {
                signed: true,
                width: 8,
                expr: Box::new(
                    Expr::Cast {
                        signed: true,
                        width: 4,
                        expr: Box::new(
                            Expr::Reg(reg(name))
                                .with_origins(crate::ir::ast::OriginSet::one(base + 8)),
                        ),
                    }
                    .with_origins(crate::ir::ast::OriginSet::one(base + 4)),
                ),
            }
            .with_origins(crate::ir::ast::OriginSet::one(base))
        };
        let mut function = one_stmt(Expr::Cmp {
            op: CmpOp::Slt,
            lhs: Box::new(extended("arg0", 0x1000)),
            rhs: Box::new(extended("arg1", 0x1010)),
        });
        let mut types = TypeMap::default();
        for name in ["arg0", "arg1"] {
            types.upsert_public(
                reg(name),
                TypeHint::Int {
                    signed: true,
                    width: 4,
                },
            );
        }

        fold_typed_comparison_extensions(&mut function, &types);

        assert!(matches!(
            &function.body[0],
            Stmt::Assign {
                src: Expr::Cmp { lhs, rhs, .. },
                ..
            } if matches!(lhs.semantic(), Expr::Reg(register) if register == &reg("arg0"))
                && matches!(rhs.semantic(), Expr::Reg(register) if register == &reg("arg1"))
                && lhs.origins() == Some(&crate::ir::ast::OriginSet::from_addresses([
                    0x1000, 0x1004, 0x1008,
                ]))
                && rhs.origins() == Some(&crate::ir::ast::OriginSet::from_addresses([
                    0x1010, 0x1014, 0x1018,
                ]))
        ));
    }

    #[test]
    fn equal_zero_extensions_keep_the_source_width_without_a_wide_compare() {
        use crate::ir::types_recover::{TypeHint, TypeMap};

        let extended = |expression| Expr::Cast {
            signed: false,
            width: 8,
            expr: Box::new(Expr::Cast {
                signed: false,
                width: 4,
                expr: Box::new(expression),
            }),
        };
        let mut f = one_stmt(Expr::Cmp {
            op: CmpOp::Eq,
            lhs: Box::new(extended(Expr::Deref {
                addr: Box::new(Expr::Reg(reg("arg0"))),
                size: 4,
            })),
            rhs: Box::new(extended(Expr::Reg(reg("arg1")))),
        });
        let mut tm = TypeMap::default();
        tm.upsert_public(
            reg("arg1"),
            TypeHint::Int {
                signed: true,
                width: 4,
            },
        );

        fold_typed_comparison_extensions(&mut f, &tm);

        assert!(
            matches!(
                &f.body[0],
                Stmt::Assign {
                    src: Expr::Cmp { lhs, rhs, .. },
                    ..
                } if matches!(lhs.as_ref(), Expr::Cast { width: 4, .. })
                    && matches!(rhs.as_ref(), Expr::Cast { width: 4, .. })
            ),
            "equal same-width values do not need a wider comparison: {f:#?}"
        );
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
    fn attributed_store_width_fold_unions_cast_and_value_origins() {
        let cast_owner = crate::ir::ast::OriginSet::one(0x1090);
        let value_owner = crate::ir::ast::OriginSet::one(0x1094);
        let mut function = Function {
            name: "store".into(),
            entry_va: 0,
            body: vec![Stmt::Store {
                addr: Expr::Reg(reg("destination")),
                src: Expr::Cast {
                    signed: false,
                    width: 4,
                    expr: Box::new(Expr::Reg(reg("value")).with_origins(value_owner.clone())),
                }
                .with_origins(cast_owner.clone()),
                size: 1,
            }],
        };

        fold_constants(&mut function);

        let Stmt::Store { src, .. } = &function.body[0] else {
            panic!("expected store")
        };
        assert_eq!(src.semantic(), &Expr::Reg(reg("value")));
        assert_eq!(src.origins(), Some(&cast_owner.union(&value_owner)));
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
    fn attributed_eager_boolean_tree_recovers_logical_origins() {
        let terminal_owner = crate::ir::ast::OriginSet::one(0x1000);
        let cast_owner = crate::ir::ast::OriginSet::one(0x1004);
        let tree_owner = crate::ir::ast::OriginSet::one(0x1008);
        let first_owner = crate::ir::ast::OriginSet::one(0x100c);
        let second_owner = crate::ir::ast::OriginSet::one(0x1010);
        let mask_tree_owner = crate::ir::ast::OriginSet::one(0x1014);
        let mask_owner = crate::ir::ast::OriginSet::one(0x1018);
        let comparison = |name: &str, owner: crate::ir::ast::OriginSet| {
            Expr::Cmp {
                op: CmpOp::Eq,
                lhs: Box::new(Expr::Reg(reg(name))),
                rhs: Box::new(Expr::Const(0)),
            }
            .with_origins(owner)
        };
        let eager = bin(
            BinOp::Or,
            comparison("arg0", first_owner.clone()),
            comparison("arg1", second_owner.clone()),
        )
        .with_origins(tree_owner.clone());
        let mut function = one_stmt(
            Expr::Cmp {
                op: CmpOp::Ne,
                lhs: Box::new(
                    Expr::Cast {
                        signed: false,
                        width: 1,
                        expr: Box::new(
                            bin(
                                BinOp::And,
                                eager,
                                Expr::Const(255).with_origins(mask_owner.clone()),
                            )
                            .with_origins(mask_tree_owner.clone()),
                        ),
                    }
                    .with_origins(cast_owner.clone()),
                ),
                rhs: Box::new(Expr::Const(0)),
            }
            .with_origins(terminal_owner.clone()),
        );

        fold_constants(&mut function);

        let Stmt::Assign { src, .. } = &function.body[0] else {
            panic!("expected assignment")
        };
        let Expr::Bin {
            op: BinOp::LogicalOr,
            lhs,
            rhs,
        } = src.semantic()
        else {
            panic!("expected logical disjunction: {src:#?}")
        };
        assert_eq!(
            src.origins(),
            Some(
                &terminal_owner
                    .union(&cast_owner)
                    .union(&mask_tree_owner)
                    .union(&mask_owner)
                    .union(&tree_owner),
            )
        );
        assert_eq!(lhs.origins(), Some(&first_owner));
        assert_eq!(rhs.origins(), Some(&second_owner));
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
            if let Ok(lf) = lift_function_from_bytes(&data, f, Arch::X86_64) {
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
    /// A widening cast over a LITERAL is load-bearing in exactly one position:
    /// the left operand of a shift, whose type C takes as the type of the whole
    /// expression. Collapsing it there turns `(uint64_t)1 << 40` into
    /// `1 << 40`, which is undefined behaviour that x86 answers as `1 << 8`.
    ///
    /// This is the shape `bts`/`btr`/`btc` lift to (`dst | (mask << index)`),
    /// and with the cast collapsed the recovered C disagreed with the original
    /// for every bit index at or above 32.
    #[test]
    fn a_widening_cast_over_a_literal_survives_on_a_shifts_left_operand() {
        let widened_one = Expr::Cast {
            signed: false,
            width: 8,
            expr: Box::new(Expr::Const(1)),
        };
        let mut function = one_stmt(Expr::Bin {
            op: BinOp::Shl,
            lhs: Box::new(widened_one.clone()),
            rhs: Box::new(Expr::Reg(reg("rcx"))),
        });
        fold_constants(&mut function);
        let Stmt::Assign { src, .. } = &function.body[0] else {
            panic!()
        };
        assert_eq!(
            *src,
            Expr::Bin {
                op: BinOp::Shl,
                lhs: Box::new(widened_one),
                rhs: Box::new(Expr::Reg(reg("rcx"))),
            },
            "the shifted literal lost the width that gives the shift its type"
        );
    }

    /// The suppression above is exactly one edge wide. Anywhere else the cast
    /// only restates a value the literal already has, and collapsing it is what
    /// keeps the recovered source readable — including the shift's COUNT, whose
    /// type C does not propagate to the result.
    #[test]
    fn a_widening_cast_over_a_literal_still_collapses_everywhere_else() {
        let widened = |value: i64| Expr::Cast {
            signed: false,
            width: 8,
            expr: Box::new(Expr::Const(value)),
        };
        for expression in [
            Expr::Bin {
                op: BinOp::Add,
                lhs: Box::new(widened(1)),
                rhs: Box::new(Expr::Reg(reg("rcx"))),
            },
            Expr::Bin {
                op: BinOp::Shl,
                lhs: Box::new(Expr::Reg(reg("rcx"))),
                rhs: Box::new(widened(3)),
            },
            Expr::Un {
                op: crate::ir::types::UnOp::Not,
                src: Box::new(widened(1)),
            },
        ] {
            let mut function = one_stmt(expression.clone());
            fold_constants(&mut function);
            let Stmt::Assign { src, .. } = &function.body[0] else {
                panic!()
            };
            let rendered = format!("{src:?}");
            assert!(
                !rendered.contains("Cast"),
                "{expression:?} kept a cast that restates its literal: {rendered}"
            );
        }
    }

    #[test]
    fn attributed_redundant_literal_cast_unions_cast_and_value_origins() {
        let cast_owner = crate::ir::ast::OriginSet::one(0x1050);
        let value_owner = crate::ir::ast::OriginSet::one(0x1054);
        let mut function = one_stmt(
            Expr::Cast {
                signed: false,
                width: 8,
                expr: Box::new(Expr::Const(7).with_origins(value_owner.clone())),
            }
            .with_origins(cast_owner.clone()),
        );

        fold_constants(&mut function);

        let Stmt::Assign { src, .. } = &function.body[0] else {
            panic!("expected assignment")
        };
        assert_eq!(src.semantic(), &Expr::Const(7));
        assert_eq!(src.origins(), Some(&cast_owner.union(&value_owner)));
    }

    #[test]
    fn attributed_equal_or_wider_inner_cast_is_subsumed_with_origins() {
        let outer_owner = crate::ir::ast::OriginSet::one(0x1000);
        let inner_owner = crate::ir::ast::OriginSet::one(0x1004);
        let source_owner = crate::ir::ast::OriginSet::one(0x1008);
        let mut function = one_stmt(
            Expr::Cast {
                signed: false,
                width: 4,
                expr: Box::new(
                    Expr::Cast {
                        signed: true,
                        width: 8,
                        expr: Box::new(Expr::Reg(reg("rax")).with_origins(source_owner.clone())),
                    }
                    .with_origins(inner_owner.clone()),
                ),
            }
            .with_origins(outer_owner.clone()),
        );

        fold_constants(&mut function);

        let Stmt::Assign { src, .. } = &function.body[0] else {
            panic!("expected assignment")
        };
        let Expr::Cast {
            signed: false,
            width: 4,
            expr,
        } = src.semantic()
        else {
            panic!("expected one surviving outer cast: {src:#?}")
        };
        assert_eq!(expr.semantic(), &Expr::Reg(reg("rax")));
        assert_eq!(expr.origins(), Some(&source_owner));
        assert_eq!(src.origins(), Some(&outer_owner.union(&inner_owner)));
    }

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

    #[test]
    fn full_width_load_of_parameter_address_is_the_parameter() {
        let mut function = one_stmt(Expr::Deref {
            addr: Box::new(Expr::StackAddr {
                object: reg("arg0"),
                size: 4,
            }),
            size: 4,
        });

        assert!(fold_constants(&mut function));

        assert!(matches!(
            &function.body[0],
            Stmt::Assign {
                src: Expr::Reg(parameter),
                ..
            } if parameter == &reg("arg0")
        ));
    }

    #[test]
    fn parameter_address_load_requires_a_typed_parameter_role() {
        let original = Expr::Deref {
            addr: Box::new(Expr::StackAddr {
                object: reg("arg0"),
                size: 4,
            }),
            size: 4,
        };
        let mut unowned = one_stmt(original.clone());
        let identities = crate::ir::value_number::ValueIdentities::default();

        assert!(!fold_constants_with_identities(&mut unowned, &identities));
        assert!(matches!(
            &unowned.body[0],
            Stmt::Assign { src, .. } if src == &original
        ));

        let parameter = identities.with_role_aliases_and_parameter_slots(
            &std::collections::HashMap::new(),
            &std::collections::HashSet::from([0]),
        );
        let mut owned = one_stmt(original);
        assert!(fold_constants_with_identities(&mut owned, &parameter));
        assert!(matches!(
            &owned.body[0],
            Stmt::Assign {
                src: Expr::Reg(value),
                ..
            } if value == &reg("arg0")
        ));

        let mut slot_unowned = one_stmt(Expr::Deref {
            addr: Box::new(Expr::StackAddr {
                object: reg("arg0"),
                size: 4,
            }),
            size: 4,
        });
        assert!(!fold_constants_with_identities(
            &mut slot_unowned,
            &identities,
        ));
        let stack_parameter =
            identities.with_parameter_slots(&std::collections::HashSet::from([0]));
        assert!(fold_constants_with_identities(
            &mut slot_unowned,
            &stack_parameter,
        ));
    }

    #[test]
    fn attributed_full_width_parameter_load_unions_address_and_load_origins() {
        let load_owner = crate::ir::ast::OriginSet::one(0x1000);
        let address_owner = crate::ir::ast::OriginSet::one(0x1004);
        let mut function = one_stmt(
            Expr::Deref {
                addr: Box::new(
                    Expr::StackAddr {
                        object: reg("arg0"),
                        size: 4,
                    }
                    .with_origins(address_owner.clone()),
                ),
                size: 4,
            }
            .with_origins(load_owner.clone()),
        );

        assert!(fold_constants(&mut function));

        let Stmt::Assign { src, .. } = &function.body[0] else {
            panic!("expected assignment")
        };
        assert_eq!(src.semantic(), &Expr::Reg(reg("arg0")));
        assert_eq!(src.origins(), Some(&load_owner.union(&address_owner)));
    }

    #[test]
    fn partial_load_of_parameter_address_is_not_widened() {
        let original = Expr::Deref {
            addr: Box::new(Expr::StackAddr {
                object: reg("arg0"),
                size: 4,
            }),
            size: 1,
        };
        let mut function = one_stmt(original.clone());

        fold_constants(&mut function);

        assert!(matches!(
            &function.body[0],
            Stmt::Assign { src, .. } if src == &original
        ));
    }
}
