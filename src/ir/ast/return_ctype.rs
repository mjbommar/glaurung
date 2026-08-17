//! What C type a value — and a function's return — is declared with.
//!
//! Separate from width *recovery*: by the time these run the `TypeMap` is
//! settled, and the question is which C spelling the render will actually emit
//! for an identifier ([`declared_int_type`]), for an expression
//! ([`expr_ctype`]), and for the function's result ([`infer_return_ctype`]).
//! The return answer is derived from the value actually returned rather than
//! from a register literally named `ret`, because value renaming can move the
//! returned value onto a promoted local.
//!
//! [`crate::ir::widen`], `const_fold`, and `typed_simplify` consult these
//! answers too: a `return` is not automatically a 64-bit context, and an
//! operand's declared width decides whether a fold is legal. The one
//! transformation here, [`fold_typed_return_abi_extensions`], is the
//! consequence of the answer rather than part of computing it — it drops the
//! machine-only zero-extension around a returned narrow integer once the
//! recovered signature proves the exact width.

use super::{
    ctype_for, hint_to_ctype, int_ctype, is_high_variable, is_promoted_local, parse_arg_index,
    target_int_ctype, Expr, Function, Stmt, TypeHint, TypeMap, VReg,
};

/// The `(signed, byte-width)` an identifier is actually **declared** with in the
/// DecBench render, or `None` when it is not an integer.
///
/// This is the one rule, shared with the declaration printer and with
/// [`crate::ir::widen`]: arguments and promoted stack slots take their recovered
/// integer type. Exact SSA-derived `varN` identities use their value-specific
/// integer fact when one exists; otherwise they remain machine-word integers
/// unless the prepared high-variable proof classifies them as pointers. Other
/// raw machine registers and temps are also declared `long`.
pub(crate) fn declared_int_type(ident: &str, tm: Option<&TypeMap>) -> Option<(bool, u8)> {
    if is_high_variable(ident) {
        return match tm.and_then(|types| types.get(&VReg::Phys(ident.to_string()))) {
            Some(TypeHint::Int { signed, width }) => Some((signed, width)),
            Some(TypeHint::Pointer { .. } | TypeHint::CodePointer | TypeHint::Float { .. }) => None,
            _ => Some((true, 8)),
        };
    }
    if parse_arg_index(ident).is_none() && !is_promoted_local(ident) {
        // Declared `long`: already machine-wide, never narrowed.
        return Some((true, 8));
    }
    match tm?.get(&VReg::Phys(ident.to_string()))? {
        TypeHint::Int { signed, width } => Some((signed, width)),
        _ => None,
    }
}

/// The C type of an expression from recovered types, when determinable. Value-
/// keyed: types the value the expression denotes, not a fixed register name.
fn expr_ctype(e: &Expr, tm: Option<&TypeMap>) -> Option<&'static str> {
    match e {
        Expr::Reg(VReg::Phys(n)) => tm
            .and_then(|m| m.get(&VReg::Phys(n.clone())))
            .map(hint_to_ctype),
        // A 32-bit x86 return write is represented losslessly as
        // `zext64(cast32(value))`. The outer cast is ABI register
        // housekeeping, not evidence that the source function returned
        // `unsigned long`. Prefer the inner value's recovered integer type,
        // then the recovered return hint, when either has the exact inner
        // width. This also prevents an unrelated earlier pointer use of `rax`
        // from deciding the signature.
        Expr::Cast {
            signed: false,
            width: 8,
            expr: inner,
        } if matches!(inner.as_ref(), Expr::Cast { width: 1..=4, .. }) => {
            let Expr::Cast {
                signed,
                width,
                expr: value,
            } = inner.as_ref()
            else {
                unreachable!()
            };
            expr_ctype(value, tm)
                .filter(|ctype| integer_ctype_width(ctype) == Some(*width))
                .or_else(|| {
                    tm.and_then(|types| types.get(&VReg::phys("ret")))
                        .and_then(|hint| match hint {
                            TypeHint::Int {
                                signed,
                                width: recovered_width,
                            } if recovered_width == *width => {
                                Some(int_ctype(signed, recovered_width))
                            }
                            _ => None,
                        })
                })
                .or_else(|| Some(target_int_ctype(*signed, *width)))
        }
        // `Expr::Cast` is an integer cast by construction. Its target type is
        // stronger return-type evidence than a flow-insensitive physical
        // register hint.
        Expr::Cast { signed, width, .. } if tm.is_some() => Some(target_int_ctype(*signed, *width)),
        // C comparison operators produce `int`.  This is an expression-level
        // language rule and therefore outranks whichever narrow sub-register
        // (`al` for SETcc) happened to materialise the value on the machine.
        Expr::Cmp { .. } if tm.is_some() => Some("int"),
        // A bare integer literal return (`return 0;`) — most often a function
        // whose real return value was lost to structuring — is an `int`. Only
        // claim this on the typed render path; the untyped path (`tm` is None)
        // stays blanket-`long` by contract.
        Expr::Const(_) if tm.is_some() => Some("int"),
        Expr::FloatConst { width: 4, .. } if tm.is_some() => Some("float"),
        Expr::FloatConst { .. } if tm.is_some() => Some("double"),
        _ => None,
    }
}

fn integer_ctype_width(ctype: &str) -> Option<u8> {
    match ctype {
        "signed char" | "unsigned char" | "char" => Some(1),
        "short" | "unsigned short" => Some(2),
        "int" | "unsigned int" => Some(4),
        "long" | "unsigned long" => Some(8),
        _ => None,
    }
}

/// The function's C return type, derived from the value *actually returned*
/// rather than from a register literally named `ret`. Walks to the first
/// `return <expr>` and types that expression; falls back to `ctype_for("ret")`
/// (finally `long`) when the returned value has no recovered type.
///
/// This is the value-keyed replacement for the bare-`ret` string lookup, which
/// silently defaulted to `long` whenever value renaming moved the return value
/// off the `ret` name (e.g. a return computed as a promoted local `local_8`).
pub(crate) fn infer_return_ctype(body: &[Stmt], tm: Option<&TypeMap>) -> &'static str {
    let ret = VReg::phys("ret");
    if let Some(types) = tm.filter(|types| types.is_locked(&ret)) {
        return types.get(&ret).map(hint_to_ctype).unwrap_or("long");
    }
    first_return_value_ctype(body, tm).unwrap_or_else(|| ctype_for("ret", tm))
}

/// The byte width of the return type this render will declare.
///
/// [`crate::ir::widen`] needs it: a `return` is not automatically a 64-bit context.
/// A function declared to return `int` returns a value the machine computed in 32
/// bits, and widening its operands would compute at 64 (`wrap_sub_u32`'s borrow
/// must not escape the low word).
pub(crate) fn inferred_return_width(body: &[Stmt], tm: Option<&TypeMap>) -> u8 {
    match infer_return_ctype(body, tm) {
        "signed char" | "unsigned char" | "char" => 1,
        "short" | "unsigned short" => 2,
        "int" | "unsigned int" | "float" => 4,
        _ => 8,
    }
}

/// Remove a machine-only zero-extension around a returned narrow integer once
/// the recovered C signature proves that the return conversion has that exact
/// narrow width.
///
/// The typed AST deliberately retains `zext64(cast32(value))` until this late
/// boundary so dataflow, predicates, and widening see the real machine value.
/// Printing the outer wrapper in `return`, however, turns ABI bookkeeping into
/// noisy source C. A function declared to return the inner width performs that
/// widening at the ABI boundary, so the outer cast alone is removed. The inner
/// cast remains because it may carry a real truncation or signedness conversion;
/// arbitrary casts and wide-return signatures remain untouched.
pub(crate) fn fold_typed_return_abi_extensions(f: &mut Function, tm: &TypeMap) {
    let return_width = inferred_return_width(&f.body, Some(tm));
    fold_return_abi_extensions_body(&mut f.body, return_width);
}

fn fold_return_abi_extensions_body(body: &mut [Stmt], return_width: u8) {
    for statement in body {
        match statement {
            Stmt::Return { value: Some(value) } => {
                let replacement = match value {
                    Expr::Cast {
                        signed: false,
                        width: 8,
                        expr: inner,
                    } => match inner.as_ref() {
                        Expr::Cast { width, .. } if *width <= 4 && *width == return_width => {
                            Some(inner.as_ref().clone())
                        }
                        _ => None,
                    },
                    _ => None,
                };
                if let Some(replacement) = replacement {
                    *value = replacement;
                }
            }
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                fold_return_abi_extensions_body(then_body, return_width);
                if let Some(else_body) = else_body {
                    fold_return_abi_extensions_body(else_body, return_width);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
                fold_return_abi_extensions_body(body, return_width);
            }
            Stmt::Switch { cases, default, .. } => {
                for (_, case_body) in cases {
                    fold_return_abi_extensions_body(case_body, return_width);
                }
                if let Some(default) = default {
                    fold_return_abi_extensions_body(default, return_width);
                }
            }
            _ => {}
        }
    }
}

fn first_return_value_ctype(body: &[Stmt], tm: Option<&TypeMap>) -> Option<&'static str> {
    for s in body {
        match s {
            Stmt::Return { value: Some(e) } => {
                if let Some(t) = expr_ctype(e, tm) {
                    return Some(t);
                }
            }
            // A bare machine return renders a synthesized `return 0;` only
            // because lowering could not express the output operation. An
            // SSA-qualified prototype result is stronger evidence than that
            // placeholder. Fall back to `int` only when no result type exists.
            Stmt::Return { value: None } if tm.is_some() => {
                return tm
                    .and_then(|types| types.get(&VReg::phys("ret")))
                    .map(hint_to_ctype)
                    .or(Some("int"));
            }
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                if let Some(t) = first_return_value_ctype(then_body, tm) {
                    return Some(t);
                }
                if let Some(eb) = else_body {
                    if let Some(t) = first_return_value_ctype(eb, tm) {
                        return Some(t);
                    }
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
                if let Some(t) = first_return_value_ctype(body, tm) {
                    return Some(t);
                }
            }
            Stmt::For { body, .. } => {
                if let Some(t) = first_return_value_ctype(body, tm) {
                    return Some(t);
                }
            }
            Stmt::Switch { cases, default, .. } => {
                for (_, b) in cases {
                    if let Some(t) = first_return_value_ctype(b, tm) {
                        return Some(t);
                    }
                }
                if let Some(b) = default {
                    if let Some(t) = first_return_value_ctype(b, tm) {
                        return Some(t);
                    }
                }
            }
            _ => {}
        }
    }
    None
}
