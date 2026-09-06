//! What a lowered value *is*, and what an operator does to one.
//!
//! Split from [`super::expr`], which walks the tree and decides *which*
//! operator applies to *which* operands. This file answers the other half: a
//! [`Val`] is one C value in canonical form, and everything here maps a C
//! operator onto the ops `src/exec` can execute. Nothing in this file looks at
//! the parse tree beyond taking a [`NodeId`] to attribute an error to, which is
//! what makes the two halves separable at all.
//!
//! # Canonical form
//!
//! Every `Val` holds its value already reduced modulo its C type and
//! sign-extended to 64 bits, so a comparison or a store never has to ask where
//! the value came from. [`canonicalize`] is what establishes that, and every
//! operator here re-establishes it on its result.

use crate::csource::lex::TokenKind;
use crate::ir::types::{BinOp, CmpOp, Op, UnOp, VReg, Value, Width};
use crate::syntax::ids::NodeId;

use super::ctype::IntType;
use super::func::{Local, Lowerer};
use super::LowerError;

/// A lowered value: the temporary holding it, in the canonical 64-bit form for
/// its type (see the module docs of [`super`]), and the type itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Val {
    /// The register holding the canonical value.
    pub reg: VReg,
    /// The C type of the expression, as an integer.
    ///
    /// A pointer is an unsigned pointer-width integer here, which is what
    /// makes comparison, assignment and argument passing work without a
    /// special case at every use site.
    pub ty: IntType,
    /// What this points at, when it is a pointer.
    ///
    /// Carried beside `ty` rather than replacing it because a dereference is
    /// the *only* operation that needs it, and widening `ty` to a full
    /// `CType` would touch every arithmetic and comparison rule to answer a
    /// question none of them asks. `None` means "not a pointer, or a pointer
    /// to something this model does not distinguish" --- and a dereference of
    /// the second is refused rather than guessed at a width.
    pub pointee: Option<IntType>,
}

impl Val {
    /// A value of integer type that points at nothing.
    pub fn plain(reg: VReg, ty: IntType) -> Val {
        Val {
            reg,
            ty,
            pointee: None,
        }
    }
}

/// Read a local into a canonical temporary.
pub(crate) fn load_local(low: &mut Lowerer<'_, '_>, var: Local) -> Val {
    // An array name *decays*: it is worth the address of its storage, and
    // there is no cell to load it from. Every use site downstream then sees an
    // ordinary pointer, which is why subscript needs no array-specific rule.
    if var.elements.is_some() {
        let out = low.b.temp();
        low.b.assign_const(&out, var.addr as i64);
        return Val {
            reg: out,
            ty: var.ty,
            pointee: var.pointee,
        };
    }
    let raw = low.b.temp();
    low.b
        .load_abs(&raw, var.addr, var.ty.width.bytes().max(1) as u8);
    let out = low.b.temp();
    low.b.normalize(&out, &raw, var.ty.width, var.ty.signed);
    Val {
        reg: out,
        ty: var.ty,
        // Loading a pointer local yields a pointer: the pointee has to survive
        // the load or a dereference has no width.
        pointee: var.pointee,
    }
}

/// Convert a canonical value to `ty`.
///
/// Correct for any source type, because a canonical value already holds the
/// exact C value and a conversion in C is "reduce mod 2^width, reinterpret per
/// signedness" --- neither of which mentions where the value came from.
///
/// `_Bool` is the exception the standard writes into 6.3.1.2: a conversion to
/// `_Bool` compares against zero, it does not truncate. Getting this wrong is
/// not academic --- `89_bool_semantics.c` and `194_narrow_return_widths.c`
/// exist to catch exactly it, and they caught this lowering, which was
/// truncating `(_Bool)(x & 4)` to `4` where C says `1`.
pub(crate) fn convert(low: &mut Lowerer<'_, '_>, value: &Val, ty: IntType) -> Val {
    if value.ty == ty {
        return value.clone();
    }
    Val {
        reg: canonicalize(low, &value.reg, ty),
        ty,
        // A conversion to an integer type discards pointee-ness: the result is
        // the integer that was asked for.
        pointee: None,
    }
}

/// Put a raw 64-bit result into the canonical form for `ty`.
///
/// The one funnel every produced value passes through, so the `_Bool` rule is
/// stated once rather than at each site that happens to produce a boolean.
pub(crate) fn canonicalize(low: &mut Lowerer<'_, '_>, raw: &VReg, ty: IntType) -> VReg {
    if ty.rank == 0 {
        return low.b.truth(raw);
    }
    let out = low.b.temp();
    low.b.normalize(&out, raw, ty.width, ty.signed);
    out
}

/// Load through a pointer.
///
/// The pointee width is what decides how many bytes to read, which is why
/// [`Val::pointee`] exists at all. A value with no pointee is refused rather
/// than assumed to be a `long`: guessing the width would read the wrong bytes
/// and the interpreter would happily execute it.
pub(crate) fn deref(low: &mut Lowerer<'_, '_>, node: NodeId, ptr: &Val) -> Result<Val, LowerError> {
    let Some(pointee) = ptr.pointee else {
        return Err(LowerError::new(
            "dereference of a pointer with no known pointee width",
            low.ctx.offset_of(node),
        ));
    };
    let raw = low.b.temp();
    low.b
        .load_reg(&raw, &ptr.reg, pointee.width.bytes().max(1) as u8);
    let out = low.b.temp();
    low.b.normalize(&out, &raw, pointee.width, pointee.signed);
    Ok(Val::plain(out, pointee))
}

/// A prefix operator applied to a lowered value.
pub(crate) fn unary(
    low: &mut Lowerer<'_, '_>,
    node: NodeId,
    op: TokenKind,
    value: Val,
) -> Result<Val, LowerError> {
    match op {
        TokenKind::Bang => {
            let out = low.b.temp();
            low.b.emit(Op::Cmp {
                dst: out.clone(),
                op: CmpOp::Eq,
                lhs: Value::Reg(value.reg),
                rhs: Value::Const(0),
            });
            Ok(Val {
                reg: out,
                ty: IntType::INT,
                // An arithmetic or conversion result is not a pointer.
                pointee: None,
            })
        }
        TokenKind::Plus => Ok(convert(low, &value, value.ty.promote())),
        TokenKind::Minus | TokenKind::Tilde => {
            let ty = value.ty.promote();
            let operand = convert(low, &value, ty);
            let raw = low.b.temp();
            low.b.unop(
                &raw,
                if op == TokenKind::Minus {
                    UnOp::Neg
                } else {
                    UnOp::Not
                },
                &operand.reg,
            );
            let out = low.b.temp();
            low.b.normalize(&out, &raw, ty.width, ty.signed);
            Ok(Val::plain(out, ty))
        }
        other => Err(LowerError::new(
            format!("prefix operator `{}`", other.name()),
            low.ctx.offset_of(node),
        )),
    }
}

/// A binary operator applied to two lowered values.
pub(crate) fn binary(
    low: &mut Lowerer<'_, '_>,
    node: NodeId,
    op: TokenKind,
    lhs: Val,
    rhs: Val,
) -> Result<Val, LowerError> {
    use TokenKind::*;

    // Pointer arithmetic scales by the pointee size, and this is the one
    // arithmetic rule the differential caught us getting wrong by omission:
    // `128_qualifier_combinations:pointer_to_const_walks` returned 0 from the
    // lowering against 0x2464c45 from the real binary, because `cursor += 1`
    // on an `int32_t *` walked one byte instead of four. It was a named
    // refusal until the scaling existed; it now exists.
    if matches!(op, Plus | Minus) && (lhs.pointee.is_some() || rhs.pointee.is_some()) {
        return pointer_arithmetic(low, node, op, &lhs, &rhs);
    }

    // Shifts do not take the usual arithmetic conversions: the result type is
    // the promoted *left* operand and the right operand promotes on its own.
    if matches!(op, Shl | Shr) {
        let ty = lhs.ty.promote();
        let a = convert(low, &lhs, ty);
        let count = convert(low, &rhs, rhs.ty.promote());
        // A count at or above the promoted operand width is undefined in C, and
        // defined identically by every machine this lowering targets: the count
        // is taken modulo the width the shift executes at. That width is not
        // ours to pick implicitly. `Builder::binop` emits width-less ops that
        // evaluate on 64-bit temporaries and `Builder::normalize` truncates
        // afterwards, which is transparent for add, sub and mul because their
        // low bits do not depend on the evaluation width --- but a shift's do.
        // Unmasked, `1u << 32` is 2^32 evaluated at 64 bits and truncates to 0,
        // where a 32-bit shift masks the count to 0 and yields 1 (gcc 15.2.0,
        // -O0 and -O1). `promote` floors at `int`, so this is 31 or 63, exactly
        // the mask x86 and ARM apply.
        let count = if ty.width.bits() < 64 {
            let mask = low.b.temp();
            low.b.assign_const(&mask, i64::from(ty.width.bits()) - 1);
            let masked = low.b.temp();
            low.b.binop(&masked, BinOp::And, &count.reg, &mask);
            masked
        } else {
            count.reg
        };
        let raw = low.b.temp();
        let kind = match (op, ty.signed) {
            (Shl, _) => BinOp::Shl,
            (_, true) => BinOp::Sar,
            (_, false) => BinOp::Shr,
        };
        low.b.binop(&raw, kind, &a.reg, &count);
        let out = low.b.temp();
        low.b.normalize(&out, &raw, ty.width, ty.signed);
        return Ok(Val::plain(out, ty));
    }

    let ty = lhs.ty.common(rhs.ty);
    let a = convert(low, &lhs, ty);
    let b = convert(low, &rhs, ty);

    if let Some(cmp) = comparison(op, ty.signed) {
        let out = low.b.temp();
        let (left, right) = if swaps(op) {
            (&b.reg, &a.reg)
        } else {
            (&a.reg, &b.reg)
        };
        low.b.cmp(&out, cmp, left, right);
        // A comparison yields `int` 0 or 1, whose canonical form is itself.
        return Ok(Val {
            reg: out,
            ty: IntType::INT,
            // An arithmetic or conversion result is not a pointer.
            pointee: None,
        });
    }

    let raw = match op {
        Plus => arith(low, BinOp::Add, &a, &b),
        Minus => arith(low, BinOp::Sub, &a, &b),
        Star => arith(low, BinOp::Mul, &a, &b),
        Amp => arith(low, BinOp::And, &a, &b),
        Pipe => arith(low, BinOp::Or, &a, &b),
        Caret => arith(low, BinOp::Xor, &a, &b),
        Slash => divide(low, &a, &b, ty, false),
        Percent => divide(low, &a, &b, ty, true),
        other => {
            return Err(LowerError::new(
                format!("binary operator `{}`", other.name()),
                low.ctx.offset_of(node),
            ))
        }
    };
    let out = low.b.temp();
    low.b.normalize(&out, &raw, ty.width, ty.signed);
    Ok(Val::plain(out, ty))
}

fn arith(low: &mut Lowerer<'_, '_>, op: BinOp, a: &Val, b: &Val) -> VReg {
    let out = low.b.temp();
    low.b.binop(&out, op, &a.reg, &b.reg);
    out
}

/// Whether the comparison is spelled with its operands the other way round.
fn swaps(op: TokenKind) -> bool {
    matches!(op, TokenKind::Gt | TokenKind::Ge)
}

/// The LLIR comparison for a C relational/equality operator at a signedness.
fn comparison(op: TokenKind, signed: bool) -> Option<CmpOp> {
    use TokenKind::*;
    Some(match (op, signed) {
        (EqEq, _) => CmpOp::Eq,
        (Ne, _) => CmpOp::Ne,
        (Lt, true) | (Gt, true) => CmpOp::Slt,
        (Lt, false) | (Gt, false) => CmpOp::Ult,
        (Le, true) | (Ge, true) => CmpOp::Sle,
        (Le, false) | (Ge, false) => CmpOp::Ule,
        _ => return None,
    })
}

/// `a / b` or `a % b`, at the canonical 64-bit width.
///
/// `BinOp::Div` is **unsigned only** --- `src/exec/concrete.rs` says so, and
/// there is no signed-divide primitive anywhere in the `Domain` trait. So the
/// signed case is built here out of ops that do exist: divide the magnitudes,
/// then apply the sign, which is C's truncate-toward-zero rule. There is no
/// remainder op at all, so `%` is always `a - (a / b) * b`.
///
/// The magnitudes are exact because the operands are canonical at 64 bits and
/// the C types in the corpus are at most 64 bits wide; only a 64-bit operand of
/// exactly `INT64_MIN` would not fit its own magnitude, and dividing that by
/// `-1` is undefined in C anyway.
fn divide(low: &mut Lowerer<'_, '_>, a: &Val, b: &Val, ty: IntType, remainder: bool) -> VReg {
    let quotient = if ty.signed {
        let a_abs = magnitude(low, &a.reg);
        let b_abs = magnitude(low, &b.reg);
        let raw = low.b.temp();
        low.b.binop(&raw, BinOp::Div, &a_abs.1, &b_abs.1);
        let negated = low.b.temp();
        low.b.unop(&negated, UnOp::Neg, &raw);
        let sign = low.b.temp();
        low.b.binop(&sign, BinOp::Xor, &a_abs.0, &b_abs.0);
        let sign_bit = low.b.truth(&sign);
        let out = low.b.temp();
        low.b.emit(Op::Ite {
            dst: out.clone(),
            cond: sign_bit,
            t: Value::Reg(negated),
            e: Value::Reg(raw),
            width: Width::W64,
        });
        out
    } else {
        let out = low.b.temp();
        low.b.binop(&out, BinOp::Div, &a.reg, &b.reg);
        out
    };
    if !remainder {
        return quotient;
    }
    let product = low.b.temp();
    low.b.binop(&product, BinOp::Mul, &quotient, &b.reg);
    let out = low.b.temp();
    low.b.binop(&out, BinOp::Sub, &a.reg, &product);
    out
}

/// `(is_negative, |value|)` of a canonical signed 64-bit value.
fn magnitude(low: &mut Lowerer<'_, '_>, value: &VReg) -> (VReg, VReg) {
    let negative = low.b.temp();
    low.b.emit(Op::Cmp {
        dst: negative.clone(),
        op: CmpOp::Slt,
        lhs: Value::Reg(value.clone()),
        rhs: Value::Const(0),
    });
    let negated = low.b.temp();
    low.b.unop(&negated, UnOp::Neg, value);
    let out = low.b.temp();
    low.b.emit(Op::Ite {
        dst: out.clone(),
        cond: negative.clone(),
        t: Value::Reg(negated),
        e: Value::Reg(value.clone()),
        width: Width::W64,
    });
    (negative, out)
}

/// How many bytes one element of `pointee` occupies.
///
/// The pointee is an [`IntType`], so this is its width --- the model has no
/// pointer to an aggregate, and a pointer whose pointee it cannot name carries
/// `None` and is refused by the caller rather than given a size.
fn element_bytes(pointee: IntType) -> i64 {
    i64::from(pointee.width.bytes().max(1))
}

/// `p + n`, `n + p`, `p - n` and `p - q`.
///
/// Split out of [`binary`] because none of the usual arithmetic conversions
/// apply: the result of `p + n` is a *pointer*, not the common type of a
/// pointer and an integer, and `p - q` is a signed `ptrdiff_t` however
/// unsigned the addresses were.
///
/// The index is converted to signed 64-bit before scaling, which is what makes
/// `p + (-1)` walk backwards: an `int` -1 sign-extends to -1 rather than to
/// 4294967295, and multiplying the wrong one by the element size would land
/// 16GB away instead of one element back.
fn pointer_arithmetic(
    low: &mut Lowerer<'_, '_>,
    node: NodeId,
    op: TokenKind,
    lhs: &Val,
    rhs: &Val,
) -> Result<Val, LowerError> {
    let refuse = |what: &str| Err(LowerError::new(what.to_string(), low.ctx.offset_of(node)));

    match (lhs.pointee, rhs.pointee) {
        // `p - q`: the number of elements between two pointers into the same
        // object. C requires they point into one array, so a difference that is
        // not a whole number of elements is undefined and the truncating
        // division below is as correct as anything can be.
        (Some(a), Some(b)) => {
            if op != TokenKind::Minus {
                return refuse("arithmetic on two pointers other than subtraction");
            }
            if a.width != b.width {
                return refuse("subtraction of pointers to different types");
            }
            let bytes = low.b.temp();
            low.b.binop(&bytes, BinOp::Sub, &lhs.reg, &rhs.reg);
            let size = element_bytes(a);
            if size == 1 {
                return Ok(Val::plain(bytes, IntType::LONG));
            }
            // Through `divide` rather than a bare `BinOp::Div`, which is
            // *unsigned*: `q - p` where `q` precedes `p` is a negative
            // difference, and dividing it unsigned yields an enormous positive
            // count instead of a small negative one.
            let numerator = Val::plain(bytes, IntType::LONG);
            let divisor = low.b.temp();
            low.b.assign_const(&divisor, size);
            let raw = divide(
                low,
                &numerator,
                &Val::plain(divisor, IntType::LONG),
                IntType::LONG,
                false,
            );
            Ok(Val::plain(
                canonicalize(low, &raw, IntType::LONG),
                IntType::LONG,
            ))
        }
        // `p + n` and `p - n`.
        (Some(pointee), None) => {
            let offset = scaled_offset(low, rhs, pointee);
            let raw = low.b.temp();
            let kind = if op == TokenKind::Plus {
                BinOp::Add
            } else {
                BinOp::Sub
            };
            low.b.binop(&raw, kind, &lhs.reg, &offset);
            Ok(Val {
                reg: canonicalize(low, &raw, IntType::ULONG),
                ty: IntType::ULONG,
                pointee: Some(pointee),
            })
        }
        // `n + p`. `n - p` is not C: an integer minus a pointer has no meaning
        // and no compiler accepts it, so it is refused rather than commuted.
        (None, Some(pointee)) => {
            if op != TokenKind::Plus {
                return refuse("integer minus pointer");
            }
            let offset = scaled_offset(low, lhs, pointee);
            let raw = low.b.temp();
            low.b.binop(&raw, BinOp::Add, &rhs.reg, &offset);
            Ok(Val {
                reg: canonicalize(low, &raw, IntType::ULONG),
                ty: IntType::ULONG,
                pointee: Some(pointee),
            })
        }
        // Reached only when a pointer-typed value carries no pointee, which is
        // `void *` and a pointer to something the model does not distinguish.
        // Scaling by an unknown size is exactly the silent-wrong-address defect
        // this arm exists to avoid.
        (None, None) => refuse("pointer arithmetic on a pointer with no known pointee width"),
    }
}

/// `index * sizeof(*p)`, in signed 64-bit.
fn scaled_offset(low: &mut Lowerer<'_, '_>, index: &Val, pointee: IntType) -> VReg {
    let widened = convert(low, index, IntType::LONG);
    let size = element_bytes(pointee);
    if size == 1 {
        return widened.reg;
    }
    let scale = low.b.temp();
    low.b.assign_const(&scale, size);
    let out = low.b.temp();
    low.b.binop(&out, BinOp::Mul, &widened.reg, &scale);
    out
}

/// The address of `base[index]`, as a pointer value.
///
/// C defines `a[i]` as `*(a + i)`, so this is [`pointer_arithmetic`]'s `Plus`
/// case reached from the subscript syntax --- including `i[a]`, which is the
/// same expression written the other way round and which real code does use in
/// obfuscated form.
pub(crate) fn index_address(
    low: &mut Lowerer<'_, '_>,
    node: NodeId,
    base: &Val,
    index: &Val,
) -> Result<Val, LowerError> {
    if base.pointee.is_none() && index.pointee.is_none() {
        return Err(LowerError::new(
            "subscript of a value that is not a pointer or array",
            low.ctx.offset_of(node),
        ));
    }
    pointer_arithmetic(low, node, TokenKind::Plus, base, index)
}
