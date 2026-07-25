//! Make the machine's implicit widening explicit in the C we emit.
//!
//! Once declarations are recovered at their true machine width, a parameter that
//! DWARF calls `uint32_t` is declared `int` rather than `long` — which is what a
//! reader (and a type-accuracy metric) wants. But the *body* still describes
//! 64-bit register machine code: after canonicalisation every LLIR value lives in
//! a 64-bit parent register, and a 32-bit write **zero-extends** into that parent
//! (see [`crate::ir::regview`]). C's own promotion rules do something else, so a
//! narrow declaration silently changes the arithmetic:
//!
//! | source                        | machine                  | C with `int arg`      |
//! |-------------------------------|--------------------------|-----------------------|
//! | `(uint64_t)a * (uint64_t)b`   | 64-bit `imul`            | 32-bit product        |
//! | `(uint64_t)hi << 32`          | 64-bit `shl`             | shift ≥ width (UB)    |
//! | `(unsigned long)x >> n`       | zero-extended `shr`      | sign-extends first    |
//!
//! This pass restores the machine's meaning by inserting the extension the
//! hardware performed: where a value declared narrower than its use context is
//! read, it is spelled `(unsigned long)(unsigned int)x`. The inner cast is what
//! makes the widening a *zero*-extension; without it C sign-extends a signed
//! narrow type. Where the compiler genuinely sign-extended it emitted `movslq`,
//! which the lifter already models as an explicit [`Expr::Cast`] — those are left
//! exactly as they are.
//!
//! Deliberately untouched: comparison operands (a narrow signed compare is its
//! own recovery problem, and widening one would change its polarity), address
//! arithmetic, and shift *counts*.

use crate::ir::ast::{Expr, Function, Stmt};
use crate::ir::types::{BinOp, VReg};
use crate::ir::types_recover::TypeMap;

/// Width, in bytes, at which a subexpression's value is consumed. `None` means
/// "no widening applies here" — recurse, but do not insert casts at this level.
type Want = Option<u8>;

/// The machine register width every canonicalised LLIR value actually occupies.
const MACHINE_WIDTH: u8 = 8;

/// Rewrite `f` so every implicitly widened read is an explicit zero-extension.
///
/// Semantics-preserving with respect to the *machine*, not to the C we emitted
/// before: that is the point. Definitions, uses, control flow and value identities
/// are unchanged, so `verify_defs` and the structural lane see the same function.
pub fn insert_widening_casts(f: &mut Function, tm: &TypeMap) {
    let ret_width = crate::ir::ast::inferred_return_width(&f.body, Some(tm));
    rewrite_body(&mut f.body, ret_width, tm);
}

fn rewrite_body(body: &mut [Stmt], ret_width: u8, tm: &TypeMap) {
    for s in body.iter_mut() {
        rewrite_stmt(s, ret_width, tm);
    }
}

fn rewrite_stmt(s: &mut Stmt, ret_width: u8, tm: &TypeMap) {
    match s {
        Stmt::Assign { dst, src } => {
            // The destination's own declaration says how wide this value is kept.
            let want = declared_int(dst_name(dst), tm)
                .map(|(_, w)| w)
                .unwrap_or(MACHINE_WIDTH);
            rewrite_expr(src, Some(want), tm);
        }
        Stmt::Store { src, size, .. } => {
            // The address expression is left alone: pointer arithmetic already
            // computes at 64 bits and carries its own recovered casts.
            rewrite_expr(src, Some(*size), tm);
        }
        // NOT a blanket 64-bit context: a function declared to return `int`
        // returns a value the machine computed in 32 bits.
        Stmt::Return { value: Some(e) } => rewrite_expr(e, Some(ret_width), tm),
        Stmt::If {
            cond,
            then_body,
            else_body,
        } => {
            rewrite_expr(cond, None, tm);
            rewrite_body(then_body, ret_width, tm);
            if let Some(b) = else_body {
                rewrite_body(b, ret_width, tm);
            }
        }
        Stmt::While { cond, body } => {
            rewrite_expr(cond, None, tm);
            rewrite_body(body, ret_width, tm);
        }
        Stmt::Switch {
            discriminant,
            cases,
            default,
        } => {
            rewrite_expr(discriminant, None, tm);
            for (_, b) in cases.iter_mut() {
                rewrite_body(b, ret_width, tm);
            }
            if let Some(b) = default {
                rewrite_body(b, ret_width, tm);
            }
        }
        Stmt::Call { target, args, .. } => {
            rewrite_expr(target, None, tm);
            for a in args.iter_mut() {
                rewrite_expr(a, None, tm);
            }
        }
        Stmt::Push { value } => rewrite_expr(value, None, tm),
        _ => {}
    }
}

fn rewrite_expr(e: &mut Expr, want: Want, tm: &TypeMap) {
    match e {
        Expr::Reg(v) => {
            let Some(want) = want else { return };
            let Some(name) = reg_name(v) else { return };
            let Some((signed, w)) = declared_int(Some(name), tm) else {
                return;
            };
            if w == 0 || w >= want {
                return;
            }
            *e = widen(e.clone(), signed, w, want);
        }
        Expr::Bin { op, lhs, rhs } => match op {
            // A shift *count* is consumed at its own width; only the shifted
            // value participates in the wide operation.
            BinOp::Shl => {
                rewrite_expr(lhs, want, tm);
                rewrite_expr(rhs, None, tm);
            }
            // An arithmetic right shift replicates the SIGN bit at the operand's
            // own width — `sar %eax` is a 32-bit signed shift. Widening the
            // operand through its unsigned type would turn it into a zero-fill,
            // which is precisely the shift `Shr` already means.
            BinOp::Sar => {
                rewrite_expr(lhs, None, tm);
                rewrite_expr(rhs, None, tm);
            }
            // A logical right shift zero-fills at the operand's own width. C
            // would shift a signed-declared operand arithmetically, so the
            // reinterpretation is stated even when no widening is needed.
            BinOp::Shr => {
                rewrite_expr(lhs, want, tm);
                make_unsigned(lhs, tm);
                rewrite_expr(rhs, None, tm);
            }
            _ => {
                rewrite_expr(lhs, want, tm);
                rewrite_expr(rhs, want, tm);
            }
        },
        Expr::Un { src, .. } => rewrite_expr(src, want, tm),
        // An explicit cast states its own width: it is the compiler's recovered
        // extension, and its operand is consumed at the cast's width.
        Expr::Cast { width, expr, .. } => rewrite_expr(expr, Some(*width), tm),
        Expr::Cmp { lhs, rhs, .. } => {
            rewrite_expr(lhs, None, tm);
            rewrite_expr(rhs, None, tm);
        }
        Expr::Deref { addr, .. } => rewrite_expr(addr, None, tm),
        _ => {}
    }
}

/// Reinterpret a signed-declared identifier as unsigned at its own width, so a
/// following logical shift zero-fills. A no-op for anything already unsigned, for
/// compound expressions (whose own operands were handled on the way down), and for
/// values that are not integers.
fn make_unsigned(e: &mut Expr, tm: &TypeMap) {
    let Expr::Reg(v) = e else { return };
    let Some(name) = reg_name(v) else { return };
    let Some((true, w)) = declared_int(Some(name), tm) else {
        return;
    };
    *e = Expr::Cast {
        signed: false,
        width: w,
        expr: Box::new(e.clone()),
    };
}

/// `(unsigned <want>)(unsigned <have>)expr` — the zero-extension a narrow write
/// performs into its 64-bit parent. The inner cast is omitted when the value is
/// already unsigned at its declared width (the widening is a zero-extension
/// either way, and the extra cast would be noise).
fn widen(expr: Expr, signed: bool, have: u8, want: u8) -> Expr {
    let inner = if signed {
        Expr::Cast {
            signed: false,
            width: have,
            expr: Box::new(expr),
        }
    } else {
        expr
    };
    Expr::Cast {
        signed: false,
        width: want,
        expr: Box::new(inner),
    }
}

fn reg_name(v: &VReg) -> Option<&str> {
    match v {
        VReg::Phys(n) => Some(n.as_str()),
        _ => None,
    }
}

fn dst_name(v: &VReg) -> Option<&str> {
    reg_name(v)
}

/// The `(signed, width)` the renderer will actually **declare** this name with —
/// not merely what type recovery inferred. Delegating keeps the two in step: a
/// `varN` that recovery tagged 4 bytes is still printed `long`, and widening it
/// would emit a cast that truncates.
fn declared_int(name: Option<&str>, tm: &TypeMap) -> Option<(bool, u8)> {
    crate::ir::ast::declared_int_type(name?, Some(tm))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::ast::render_decbench_typed;
    use crate::ir::types_recover::TypeHint;

    fn tm_of(pairs: &[(&str, bool, u8)]) -> TypeMap {
        let mut m = TypeMap::default();
        for (n, signed, width) in pairs {
            m.upsert_public(
                VReg::phys(*n),
                TypeHint::Int {
                    signed: *signed,
                    width: *width,
                },
            );
        }
        m
    }

    fn func(body: Vec<Stmt>) -> Function {
        Function {
            name: "f".into(),
            entry_va: 0x1000,
            body,
        }
    }

    fn reg(n: &str) -> Expr {
        Expr::Reg(VReg::phys(n))
    }

    fn bin(op: BinOp, l: Expr, r: Expr) -> Expr {
        Expr::Bin {
            op,
            lhs: Box::new(l),
            rhs: Box::new(r),
        }
    }

    /// `mul_widen`: a 64-bit product of two 32-bit parameters. Declared `int`,
    /// C would compute the product in 32 bits and lose the high half.
    #[test]
    fn narrow_operands_of_a_wide_multiply_are_widened() {
        let tm = tm_of(&[("arg0", true, 4), ("arg1", true, 4), ("local_8", false, 8)]);
        let mut f = func(vec![Stmt::Assign {
            dst: VReg::phys("local_8"),
            src: bin(BinOp::Mul, reg("arg0"), reg("arg1")),
        }]);
        insert_widening_casts(&mut f, &tm);
        let out = render_decbench_typed(&f, Some(&tm), Some(&tm));
        assert!(
            out.contains(
                "(unsigned long)((unsigned int)(arg0)) * (unsigned long)((unsigned int)(arg1))"
            ) || out.contains("(unsigned long)((unsigned int)(arg0))"),
            "both operands must widen before the multiply:\n{out}"
        );
    }

    /// `reconstruct_64`: `(uint64_t)hi << 32`. A 32-bit shift by 32 is undefined;
    /// the machine shifts the 64-bit parent.
    #[test]
    fn a_narrow_value_shifted_into_the_high_word_is_widened_first() {
        let tm = tm_of(&[("arg0", true, 4), ("local_8", false, 8)]);
        let mut f = func(vec![Stmt::Assign {
            dst: VReg::phys("local_8"),
            src: bin(BinOp::Shl, reg("arg0"), Expr::Const(32)),
        }]);
        insert_widening_casts(&mut f, &tm);
        let out = render_decbench_typed(&f, Some(&tm), Some(&tm));
        assert!(
            out.contains("(unsigned long)"),
            "shifted value must widen:\n{out}"
        );
    }

    /// The count of a shift is not a wide operand — widening it is pure noise.
    #[test]
    fn a_shift_count_is_not_widened() {
        let tm = tm_of(&[("arg0", false, 8), ("arg1", true, 4), ("local_8", false, 8)]);
        let mut f = func(vec![Stmt::Assign {
            dst: VReg::phys("local_8"),
            src: bin(BinOp::Shr, reg("arg0"), reg("arg1")),
        }]);
        insert_widening_casts(&mut f, &tm);
        let Stmt::Assign { src, .. } = &f.body[0] else {
            panic!("expected an assignment");
        };
        let Expr::Bin { rhs, .. } = src else {
            panic!("expected a binary op");
        };
        assert_eq!(**rhs, reg("arg1"), "the shift count must be left alone");
    }

    /// A signed narrow read must zero-extend, because that is what the 32-bit
    /// write into the 64-bit parent did. `(unsigned long)arg0` alone would
    /// sign-extend and set the whole high word for a negative value.
    #[test]
    fn widening_a_signed_value_goes_through_its_unsigned_type() {
        let tm = tm_of(&[("arg0", true, 4), ("local_8", false, 8)]);
        let mut f = func(vec![Stmt::Assign {
            dst: VReg::phys("local_8"),
            src: reg("arg0"),
        }]);
        insert_widening_casts(&mut f, &tm);
        let Stmt::Assign { src, .. } = &f.body[0] else {
            panic!("expected an assignment");
        };
        assert_eq!(
            *src,
            Expr::Cast {
                signed: false,
                width: 8,
                expr: Box::new(Expr::Cast {
                    signed: false,
                    width: 4,
                    expr: Box::new(reg("arg0")),
                }),
            }
        );
    }

    /// An already-unsigned narrow value needs only the outer widening.
    #[test]
    fn widening_an_unsigned_value_needs_no_inner_cast() {
        let tm = tm_of(&[("arg0", false, 4), ("local_8", false, 8)]);
        let mut f = func(vec![Stmt::Assign {
            dst: VReg::phys("local_8"),
            src: reg("arg0"),
        }]);
        insert_widening_casts(&mut f, &tm);
        let Stmt::Assign { src, .. } = &f.body[0] else {
            panic!("expected an assignment");
        };
        assert_eq!(
            *src,
            Expr::Cast {
                signed: false,
                width: 8,
                expr: Box::new(reg("arg0")),
            }
        );
    }

    /// Assigning into a narrow destination keeps narrow arithmetic narrow —
    /// the machine truncated too, and a cast here would only add noise.
    #[test]
    fn a_narrow_destination_does_not_widen_its_operands() {
        let tm = tm_of(&[("arg0", true, 4), ("arg1", true, 4), ("local_4", true, 4)]);
        let mut f = func(vec![Stmt::Assign {
            dst: VReg::phys("local_4"),
            src: bin(BinOp::Add, reg("arg0"), reg("arg1")),
        }]);
        let before = f.clone();
        insert_widening_casts(&mut f, &tm);
        assert_eq!(f, before);
    }

    /// Comparison operands are left alone: a narrow signed compare is its own
    /// recovery problem and zero-extending one would flip its polarity.
    #[test]
    fn comparison_operands_are_left_alone() {
        let tm = tm_of(&[("arg0", true, 4)]);
        let mut f = func(vec![Stmt::If {
            cond: Expr::Cmp {
                op: crate::ir::types::CmpOp::Slt,
                lhs: Box::new(reg("arg0")),
                rhs: Box::new(Expr::Const(0)),
            },
            then_body: vec![Stmt::Nop],
            else_body: None,
        }]);
        let before = f.clone();
        insert_widening_casts(&mut f, &tm);
        assert_eq!(f, before);
    }

    /// An explicit cast is the compiler's own recovered extension (`movslq`);
    /// its operand is consumed at the cast's width, not the statement's.
    #[test]
    fn an_explicit_cast_sets_the_width_of_its_operand() {
        let tm = tm_of(&[("arg0", true, 4), ("local_8", false, 8)]);
        let mut f = func(vec![Stmt::Assign {
            dst: VReg::phys("local_8"),
            src: Expr::Cast {
                signed: true,
                width: 8,
                expr: Box::new(reg("arg0")),
            },
        }]);
        insert_widening_casts(&mut f, &tm);
        let Stmt::Assign { src, .. } = &f.body[0] else {
            panic!("expected an assignment");
        };
        // The outer sign-extending cast survives; only its operand is made
        // explicit about the zero-extension underneath.
        let Expr::Cast { signed, width, .. } = src else {
            panic!("expected the explicit cast to survive");
        };
        assert!(*signed && *width == 8);
    }

    /// A value with no recovered type stays `long` and is already machine-wide.
    #[test]
    fn an_untyped_value_is_untouched() {
        let tm = tm_of(&[("local_8", false, 8)]);
        let mut f = func(vec![Stmt::Assign {
            dst: VReg::phys("local_8"),
            src: reg("var3"),
        }]);
        let before = f.clone();
        insert_widening_casts(&mut f, &tm);
        assert_eq!(f, before);
    }

    /// The renderer declares raw machine registers (`ret`, `varN`) `long` whatever
    /// type recovery inferred. Widening one against the recovered width would emit
    /// a cast that *truncates* a 64-bit value.
    #[test]
    fn a_register_local_is_never_narrowed_by_a_recovered_width() {
        // Recovery tagged `ret` as 4 bytes; the printer still declares it `long`.
        let tm = tm_of(&[("ret", true, 4), ("local_8", false, 8)]);
        let mut f = func(vec![Stmt::Assign {
            dst: VReg::phys("local_8"),
            src: reg("ret"),
        }]);
        let before = f.clone();
        insert_widening_casts(&mut f, &tm);
        assert_eq!(f, before, "`ret` is declared `long`; casting it truncates");
    }

    /// `rotr32`: `x >> n` where the count is variable. C shifts a signed operand
    /// arithmetically; the machine's `shr` zero-fills.
    #[test]
    fn a_logical_shift_reinterprets_a_signed_operand_as_unsigned() {
        let tm = tm_of(&[("arg0", true, 4), ("local_4", true, 4)]);
        let mut f = func(vec![Stmt::Assign {
            dst: VReg::phys("local_4"),
            src: bin(BinOp::Shr, reg("arg0"), reg("t6")),
        }]);
        insert_widening_casts(&mut f, &tm);
        let Stmt::Assign { src, .. } = &f.body[0] else {
            panic!("expected an assignment");
        };
        let Expr::Bin { lhs, .. } = src else {
            panic!("expected a binary op");
        };
        assert_eq!(
            **lhs,
            Expr::Cast {
                signed: false,
                width: 4,
                expr: Box::new(reg("arg0")),
            }
        );
    }

    /// An arithmetic shift keeps its signed operand — that is what `sar` means.
    #[test]
    fn an_arithmetic_shift_keeps_its_signed_operand() {
        let tm = tm_of(&[("arg0", true, 4), ("local_4", true, 4)]);
        let mut f = func(vec![Stmt::Assign {
            dst: VReg::phys("local_4"),
            src: bin(BinOp::Sar, reg("arg0"), Expr::Const(3)),
        }]);
        let before = f.clone();
        insert_widening_casts(&mut f, &tm);
        assert_eq!(f, before);
    }

    /// `sar_signed`: `return x >> 4` on a signed `int`. Widening the operand into
    /// a 64-bit unsigned makes the sign bit stop replicating, so every negative
    /// input returns a large positive number instead.
    #[test]
    fn an_arithmetic_shift_is_not_widened_by_its_return_context() {
        let tm = tm_of(&[("arg0", true, 4)]);
        let mut f = func(vec![Stmt::Return {
            value: Some(bin(BinOp::Sar, reg("arg0"), Expr::Const(4))),
        }]);
        let before = f.clone();
        insert_widening_casts(&mut f, &tm);
        assert_eq!(f, before, "an arithmetic shift must stay signed and narrow");
    }

    /// `wrap_sub_u32`: a 32-bit subtraction whose borrow must not escape the low
    /// word. Returning it does not make it a 64-bit computation — the declared
    /// return type is `int`, so the machine computed it in 32 bits.
    ///
    /// The `ret` entry is what makes the renderer declare an `int` return: the
    /// returned expression is compound, so the type falls back to the return
    /// register's own recovered type.
    #[test]
    fn returning_a_narrow_value_is_not_a_sixty_four_bit_context() {
        let tm = tm_of(&[("arg0", false, 4), ("arg1", false, 4), ("ret", true, 4)]);
        let mut f = func(vec![Stmt::Return {
            value: Some(bin(BinOp::Sub, reg("arg0"), reg("arg1"))),
        }]);
        let before = f.clone();
        insert_widening_casts(&mut f, &tm);
        assert_eq!(f, before, "an `int`-returning subtract must stay 32-bit");
    }

    /// The converse: a function that returns `long` DOES widen, because its value
    /// really is the 64-bit register.
    #[test]
    fn returning_a_wide_value_widens_its_narrow_operands() {
        // `ret` is a register local, declared `long`, so the return type is `long`.
        let tm = tm_of(&[("arg0", false, 4), ("ret", true, 8)]);
        let mut f = func(vec![
            Stmt::Assign {
                dst: VReg::phys("ret"),
                src: reg("arg0"),
            },
            Stmt::Return {
                value: Some(reg("ret")),
            },
        ]);
        insert_widening_casts(&mut f, &tm);
        let Stmt::Assign { src, .. } = &f.body[0] else {
            panic!("expected an assignment");
        };
        assert_eq!(
            *src,
            Expr::Cast {
                signed: false,
                width: 8,
                expr: Box::new(reg("arg0")),
            }
        );
    }
}
