//! The CALLEE side of a two-register integer result.
//!
//! [`crate::ir::call_result_split`] and `recovered_call_prototype` between them
//! already get the CALL boundary right: a caller of a function whose System V
//! return class is [`ReturnClass::IntegerPair`] declares it `unsigned __int128`
//! and reads the high eightbyte back out of that value. Nothing did the same
//! for a function whose OWN result is such an aggregate, and a roundtrip
//! wrapper cannot expose the gap because it only ever exercises the caller.
//!
//! What the gap looks like: `bv195_make_quad` computes four `int32_t` members
//! into a frame object and ends `mov rax,[obj]; mov rdx,[obj+8]; ret`. With the
//! signature one machine word wide, `rdx` is read by nothing, dead-store
//! elimination deletes its definition, and the emitted C returns the FIRST
//! eightbyte only — members `c` and `d` are computed and discarded. The body
//! was already correct; only the result contract was not.
//!
//! This pass states that contract in the AST: each `return E` becomes
//!
//! ```text
//!   return (wide)E | ((wide)high << bits);
//! ```
//!
//! where `high` is the second result register and `wide` is the double-word
//! integer type that has exactly this ABI storage — the same spelling the call
//! boundary already uses, so the two sides of the boundary agree by
//! construction and no source aggregate has to be reconstructed.
//!
//! It runs EARLY, next to [`crate::ir::direct_output`] and before dead-store
//! elimination, for one reason: the high register's definition must still be
//! there to be kept alive. Running after the fact would have to resurrect a
//! statement that no longer exists.
//!
//! Only [`ReturnClass::IntegerPair`] is handled. The other multi-register
//! classes (`rax`+`xmm0`, `xmm0:xmm1`, an AAPCS64 HFA) have no builtin C
//! spelling at all: they need a synthesised `struct` tag, and a tag needs a
//! definition ABOVE the signature line — which the DecBench slicing contract
//! (`decbench_render`'s `no_stack_protector` note) discards. Those stay on
//! their existing path rather than acquire a declaration that would not survive
//! being sliced out.

use crate::ir::abi::{wide_integer_return_pair, wide_integer_return_width, ReturnClass};
use crate::ir::ast::{Expr, Function, Stmt};
use crate::ir::call_args::CallConv;
use crate::ir::types::{BinOp, VReg};
use crate::ir::types_recover::RecoveredPrototype;

/// The double-word integer spelling a two-register INTEGER result occupies, or
/// `None` when this convention has no such contract.
///
/// Public so the renderer can declare the definition's signature with the same
/// answer the rewrite below composes a value for. Two spellings of one fact is
/// how the callee and the call boundary drifted apart in the first place.
pub fn pair_return_c_type(cc: CallConv) -> Option<&'static str> {
    let width = wide_integer_return_width(cc);
    wide_integer_return_pair(cc, width)?;
    Some(match width {
        16 => "unsigned __int128",
        _ => "unsigned long long",
    })
}

/// Rewrite every `return` into the two-register composition its declared result
/// class requires. Returns `true` when the body changed.
///
/// ALL OR NOTHING. A `return` this pass cannot give a proven high half would
/// leave a function whose SIGNATURE is two words wide handing back one, which
/// is a different wrong answer from today's rather than a smaller one. When any
/// return is unprovable the body is left exactly as it was, and
/// [`returns_are_pair_composed`] then tells the renderer to keep the old
/// signature too — the two decisions are one decision, and they read the same
/// AST to make it.
pub fn compose_pair_returns(
    function: &mut Function,
    cc: CallConv,
    prototype: Option<&RecoveredPrototype>,
) -> bool {
    let Some(prototype) = prototype else {
        return false;
    };
    if prototype.return_class() != ReturnClass::IntegerPair {
        return false;
    }
    let Some((width, _low, high)) = pair_storage(cc) else {
        return false;
    };
    let mut composed = function.body.clone();
    if !compose_body(&mut composed, high, width, None) {
        return false;
    }
    function.body = composed;
    true
}

/// The `(double-word width, low register, high register)` of a convention's
/// two-register INTEGER result, when it has one and this module can spell it.
fn pair_storage(cc: CallConv) -> Option<(u8, &'static str, &'static str)> {
    pair_return_c_type(cc)?;
    let width = wide_integer_return_width(cc);
    let (low, high) = wide_integer_return_pair(cc, width)?;
    Some((width, low, high))
}

/// Rewrite the returns in `body`, threading the SSA value of the high half that
/// REACHES each one. Returns `false` as soon as a return has none.
///
/// The version matters: at this point in the pipeline the AST still names
/// `%rdx#3`, not `%rdx`, so a bare register reference would read a value no
/// definition in the body produces. Nested control flow is handled
/// conservatively — a branch that redefines the high half invalidates the
/// reaching value for everything after it, because which arm ran is exactly
/// what a linear walk cannot know.
fn compose_body(body: &mut [Stmt], high: &str, width: u8, incoming: Option<VReg>) -> bool {
    let mut reaching = incoming;
    for statement in body.iter_mut() {
        match statement {
            Stmt::Assign { dst, .. } | Stmt::Call { dst: Some(dst), .. }
                if is_high_half(dst, high) =>
            {
                reaching = Some(dst.clone());
            }
            Stmt::Return { value } => {
                let Some(high_value) = reaching.clone() else {
                    return false;
                };
                // A BARE machine return has no low half to widen. Lowering left
                // it operand-free because it could not express the output at
                // all, and inventing one here would fabricate a result.
                let Some(low_value) = value.clone() else {
                    return false;
                };
                *value = Some(Expr::Bin {
                    op: BinOp::Or,
                    lhs: Box::new(wide_cast(low_value, width)),
                    rhs: Box::new(Expr::Bin {
                        op: BinOp::Shl,
                        lhs: Box::new(wide_cast(Expr::Reg(high_value), width)),
                        rhs: Box::new(Expr::Const(i64::from(width) * 4)),
                    }),
                });
            }
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                if !compose_body(then_body, high, width, reaching.clone()) {
                    return false;
                }
                let mut redefined = defines_high_half(then_body, high);
                if let Some(else_body) = else_body {
                    if !compose_body(else_body, high, width, reaching.clone()) {
                        return false;
                    }
                    redefined |= defines_high_half(else_body, high);
                }
                if redefined {
                    reaching = None;
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
                if !compose_body(body, high, width, reaching.clone()) {
                    return false;
                }
                if defines_high_half(body, high) {
                    reaching = None;
                }
            }
            Stmt::Switch { cases, default, .. } => {
                let mut redefined = false;
                for (_, case_body) in cases.iter_mut() {
                    if !compose_body(case_body, high, width, reaching.clone()) {
                        return false;
                    }
                    redefined |= defines_high_half(case_body, high);
                }
                if let Some(default) = default {
                    if !compose_body(default, high, width, reaching.clone()) {
                        return false;
                    }
                    redefined |= defines_high_half(default, high);
                }
                if redefined {
                    reaching = None;
                }
            }
            Stmt::TryCatch { try_body, catches } => {
                if !compose_body(try_body, high, width, reaching.clone()) {
                    return false;
                }
                let mut redefined = defines_high_half(try_body, high);
                for catch in catches.iter_mut() {
                    if !compose_body(&mut catch.body, high, width, reaching.clone()) {
                        return false;
                    }
                    redefined |= defines_high_half(&catch.body, high);
                }
                if redefined {
                    reaching = None;
                }
            }
            // A label is a join: something else may reach it, so whatever this
            // walk believed about the high half stops holding here.
            Stmt::Label(_) => reaching = None,
            _ => {}
        }
    }
    true
}

/// Whether every `return` in `body` carries the composition this module
/// installs, and therefore whether the definition may be DECLARED at the
/// double-word type.
///
/// Read from the final AST rather than remembered from the pass: a later
/// transform that rewrote a composed return would otherwise leave the signature
/// asserting a contract the body no longer meets.
pub fn returns_are_pair_composed(body: &[Stmt], cc: CallConv) -> bool {
    let Some((width, _low, _high)) = pair_storage(cc) else {
        return false;
    };
    let mut seen = false;
    if !every_return_is_composed(body, width, &mut seen) {
        return false;
    }
    seen
}

fn every_return_is_composed(body: &[Stmt], width: u8, seen: &mut bool) -> bool {
    body.iter().all(|statement| match statement {
        Stmt::Return { value } => {
            *seen = true;
            matches!(
                value,
                Some(Expr::Bin {
                    op: BinOp::Or,
                    lhs,
                    rhs,
                }) if matches!(
                    lhs.as_ref(),
                    Expr::Cast { signed: false, width: cast, .. } if *cast == width
                ) && matches!(
                    rhs.as_ref(),
                    Expr::Bin { op: BinOp::Shl, lhs, .. }
                        if matches!(
                            lhs.as_ref(),
                            Expr::Cast { signed: false, width: cast, .. } if *cast == width
                        )
                )
            )
        }
        Stmt::If {
            then_body,
            else_body,
            ..
        } => {
            every_return_is_composed(then_body, width, seen)
                && else_body
                    .as_deref()
                    .is_none_or(|body| every_return_is_composed(body, width, seen))
        }
        Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
            every_return_is_composed(body, width, seen)
        }
        Stmt::Switch { cases, default, .. } => {
            cases
                .iter()
                .all(|(_, body)| every_return_is_composed(body, width, seen))
                && default
                    .as_deref()
                    .is_none_or(|body| every_return_is_composed(body, width, seen))
        }
        Stmt::TryCatch { try_body, catches } => {
            every_return_is_composed(try_body, width, seen)
                && catches
                    .iter()
                    .all(|catch| every_return_is_composed(&catch.body, width, seen))
        }
        _ => true,
    })
}

/// One half's value viewed at the double-word type, through an explicit
/// UNSIGNED MACHINE-WORD view.
///
/// Both casts are load-bearing and each was measured:
///
/// * unsigned, because the halves are STORAGE. `*(long *)&obj` is signed, and
///   widening it directly sign-filled the whole second eightbyte whenever the
///   first one's top bit was set — `bv195_make_quad` at `-O0` returned
///   `ffffffff...` for members `c` and `d` on every negative seed.
/// * at the machine word, because `widen::insert_widening_casts` consumes a
///   cast's operand AT THE CAST'S WIDTH. Handed the double word directly it
///   pushed that width down through the `|` into the shift underneath, turning
///   the machine's 64-bit `shl rdi,0x21` into a 128-bit one whose overflow
///   landed in the high eightbyte instead of falling off the end
///   (`198:clang:O2:agr198_make_trio`).
fn wide_cast(expr: Expr, width: u8) -> Expr {
    Expr::Cast {
        signed: false,
        width,
        expr: Box::new(Expr::Cast {
            signed: false,
            width: width / 2,
            expr: Box::new(expr),
        }),
    }
}

/// Whether `value` is a definition of the high result register, at any SSA
/// version. Sub-register spellings do not need listing: `regview::ssa_parent`
/// has already canonicalised every total write onto its 64-bit parent.
fn is_high_half(value: &VReg, high: &str) -> bool {
    matches!(value, VReg::Phys(name) if crate::ir::abi::ssa_base(name) == high)
}

fn defines_high_half(body: &[Stmt], high: &str) -> bool {
    body.iter().any(|statement| match statement {
        Stmt::Assign { dst, .. } | Stmt::Call { dst: Some(dst), .. } => is_high_half(dst, high),
        Stmt::If {
            then_body,
            else_body,
            ..
        } => {
            defines_high_half(then_body, high)
                || else_body
                    .as_deref()
                    .is_some_and(|body| defines_high_half(body, high))
        }
        Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
            defines_high_half(body, high)
        }
        Stmt::Switch { cases, default, .. } => {
            cases.iter().any(|(_, body)| defines_high_half(body, high))
                || default
                    .as_deref()
                    .is_some_and(|body| defines_high_half(body, high))
        }
        Stmt::TryCatch { try_body, catches } => {
            defines_high_half(try_body, high)
                || catches
                    .iter()
                    .any(|catch| defines_high_half(&catch.body, high))
        }
        _ => false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::types_recover::{RecoveredOutputKind, RecoveredPrototype};

    fn reg(name: &str) -> VReg {
        VReg::phys(name)
    }

    fn pair_prototype(class: ReturnClass) -> RecoveredPrototype {
        let mut prototype = RecoveredPrototype::default();
        prototype.apply_locked_output(RecoveredOutputKind::Direct, None);
        prototype.apply_return_class(class);
        prototype
    }

    /// SSA-VERSIONED, because that is what the AST actually carries where this
    /// pass runs: the register renaming that turns `%rax#17` into `%ret` is
    /// three passes later, and matching the bare name found nothing.
    fn quad_body() -> Vec<Stmt> {
        vec![
            Stmt::Assign {
                dst: reg("rax#17"),
                src: Expr::Const(1),
            },
            Stmt::Assign {
                dst: reg("rdx#3"),
                src: Expr::Const(2),
            },
            Stmt::Return {
                value: Some(Expr::Reg(reg("rax#17"))),
            },
        ]
    }

    fn function(body: Vec<Stmt>) -> Function {
        Function {
            name: "make_quad".to_string(),
            entry_va: 0,
            body,
        }
    }

    #[test]
    fn an_integer_pair_result_returns_both_eightbytes() {
        let mut f = function(quad_body());
        assert!(compose_pair_returns(
            &mut f,
            CallConv::SysVAmd64,
            Some(&pair_prototype(ReturnClass::IntegerPair)),
        ));
        let Some(Stmt::Return { value: Some(value) }) = f.body.last() else {
            panic!("no return: {f:#?}");
        };
        let Expr::Bin {
            op: BinOp::Or,
            lhs,
            rhs,
        } = value
        else {
            panic!("result is not a composition: {value:#?}");
        };
        // Through an UNSIGNED MACHINE-WORD view in both halves — see
        // `wide_cast`; a bare widening sign-fills the high eightbyte, and a
        // bare double-word cast pushes 128-bit arithmetic down into the low
        // half's own shifts.
        let half = |name: &str| Expr::Cast {
            signed: false,
            width: 16,
            expr: Box::new(Expr::Cast {
                signed: false,
                width: 8,
                expr: Box::new(Expr::Reg(reg(name))),
            }),
        };
        assert_eq!(lhs.as_ref(), &half("rax#17"), "{value:#?}");
        assert_eq!(
            rhs.as_ref(),
            &Expr::Bin {
                op: BinOp::Shl,
                // The EXACT reaching version. A bare `%rdx` is a value no
                // definition in this body produces.
                lhs: Box::new(half("rdx#3")),
                rhs: Box::new(Expr::Const(64)),
            },
            "{value:#?}"
        );
        assert!(returns_are_pair_composed(&f.body, CallConv::SysVAmd64));
    }

    /// The renderer and the rewrite must agree, and they agree by reading the
    /// same AST. An uncomposed body must not be DECLARED at the double-word
    /// type: the signature would assert a contract the body does not meet.
    #[test]
    fn an_uncomposed_body_is_not_declared_at_the_pair_type() {
        let f = function(quad_body());
        assert!(!returns_are_pair_composed(&f.body, CallConv::SysVAmd64));
    }

    /// A second return with no reaching high half fails the WHOLE function.
    /// Composing only the provable returns would leave one arm handing back a
    /// single word through a two-word signature.
    #[test]
    fn one_unprovable_return_leaves_every_return_alone() {
        let mut f = function(vec![
            Stmt::Return {
                value: Some(Expr::Const(-1)),
            },
            Stmt::Assign {
                dst: reg("rdx#3"),
                src: Expr::Const(2),
            },
            Stmt::Return {
                value: Some(Expr::Reg(reg("rax#17"))),
            },
        ]);
        let before = f.body.clone();
        assert!(!compose_pair_returns(
            &mut f,
            CallConv::SysVAmd64,
            Some(&pair_prototype(ReturnClass::IntegerPair)),
        ));
        assert_eq!(f.body, before);
    }

    /// The control. A scalar result keeps the one-register contract it has
    /// always had; without this the pass would retype every ordinary function.
    #[test]
    fn a_single_class_result_is_untouched() {
        let mut f = function(quad_body());
        let before = f.body.clone();
        assert!(!compose_pair_returns(
            &mut f,
            CallConv::SysVAmd64,
            Some(&pair_prototype(ReturnClass::Single)),
        ));
        assert_eq!(f.body, before);
    }

    /// A body that never writes the high register did not produce a
    /// two-register result, whatever the declared shape says. Composing one
    /// would read a value the machine never defined.
    #[test]
    fn a_body_that_never_defines_the_high_half_is_untouched() {
        let mut f = function(vec![
            Stmt::Assign {
                dst: reg("rax#17"),
                src: Expr::Const(1),
            },
            Stmt::Return {
                value: Some(Expr::Reg(reg("rax#17"))),
            },
        ]);
        let before = f.body.clone();
        assert!(!compose_pair_returns(
            &mut f,
            CallConv::SysVAmd64,
            Some(&pair_prototype(ReturnClass::IntegerPair)),
        ));
        assert_eq!(f.body, before);
    }

    /// AAPCS64's pair is `x0:x1` and is the same contract one architecture
    /// over — the caller side landed weeks before this one, so the callee must
    /// not be System V only.
    #[test]
    fn aapcs64_composes_x0_and_x1() {
        let mut f = function(vec![
            Stmt::Assign {
                dst: reg("x0"),
                src: Expr::Const(1),
            },
            Stmt::Assign {
                dst: reg("x1"),
                src: Expr::Const(2),
            },
            Stmt::Return {
                value: Some(Expr::Reg(reg("x0"))),
            },
        ]);
        assert!(compose_pair_returns(
            &mut f,
            CallConv::Aarch64,
            Some(&pair_prototype(ReturnClass::IntegerPair)),
        ));
        let Some(Stmt::Return { value: Some(value) }) = f.body.last() else {
            panic!("no return: {f:#?}");
        };
        assert!(
            format!("{value:?}").contains("x1"),
            "the high half is missing: {value:#?}"
        );
    }

    /// Win64 has no register-pair result at all, so there is nothing to
    /// compose and nothing to declare.
    #[test]
    fn win64_has_no_pair_spelling() {
        assert_eq!(pair_return_c_type(CallConv::Win64), None);
        assert_eq!(
            pair_return_c_type(CallConv::SysVAmd64),
            Some("unsigned __int128")
        );
        assert_eq!(
            pair_return_c_type(CallConv::Arm),
            Some("unsigned long long")
        );
    }
}
