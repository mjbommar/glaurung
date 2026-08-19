//! The CALLEE side of a result the ABI splits across two register BANKS.
//!
//! [`crate::ir::callee_return_pair`] states the definition-site contract for
//! the one multi-register class that has a builtin C spelling: a double-word
//! INTEGER result is `rax:rdx`, and `unsigned __int128` IS that storage, so the
//! composition `(wide)lo | ((wide)hi << 64)` is an ordinary scalar expression.
//!
//! The other three classes cannot be spelled that way, and the reason is not
//! notation. `xmm0:xmm1`, `rax`+`xmm0` and an AAPCS64 HFA put the two halves in
//! DIFFERENT REGISTER BANKS, so no arithmetic on one half can produce the
//! other: widening the `xmm1` half converts the NUMBER, not the bits, because
//! the reaching value is float-typed in the AST. Those classes need a
//! synthesised `struct` tag — [`crate::ir::abi::sse_pair_return_tag`] and
//! friends, the same tags every CALLER of such a function is already declared
//! with — and `Stmt::Return` carries one `Expr`, which has no aggregate-literal
//! variant.
//!
//! It does not need one. At `-O0` the result genuinely LIVES in one frame
//! object: every member is stored into it and the return registers are loaded
//! back out of it, which is exactly the mirror of the call site's
//!
//! ```text
//!   *(struct __glaurung_sse_pair *)(&var1[0]) = callee(...);
//! ```
//!
//! So the callee side is `return *(struct __glaurung_sse_pair *)(&local_20[0]);`
//! — a sixteen-byte load through a cast, one existing [`Expr::Deref`], and the
//! two sides of the boundary agree by construction.
//!
//! What is PROVEN before that spelling is used, all of it from the AST that is
//! about to be printed:
//!
//! * the DECLARED result class is one of the three (never machine evidence —
//!   see [`crate::ir::return_class`] for why liveness cannot decide this);
//! * every `return` in the body reads its value out of ONE stack object, either
//!   directly or through a local whose only reaching definition is that load;
//! * that object's recovered extent is EXACTLY the declared result's size, so
//!   the aggregate is the whole object rather than a prefix of a larger frame
//!   slot that happens to start there;
//! * the object is stored into at an offset inside the SECOND bank. This is the
//!   load-bearing one: it is what proves the high half's bytes are in the
//!   object at all, and it is the half that a one-expression `return` cannot
//!   otherwise keep alive.
//!
//! Any of those failing leaves the body and the signature exactly as they were.
//! Declaring the wider result while returning one bank's worth of it is a
//! different wrong answer from today's, not a smaller one — the same all-or-
//! nothing rule [`crate::ir::callee_return_pair`] states.
//!
//! At `-O2` the value never lands in memory, so this pass declines there and
//! those lanes keep their existing (single-bank) spelling.

use crate::ir::abi::{hfa_return_tag, split_bank_return_tag, sse_pair_return_tag, ReturnClass};
use crate::ir::ast::{Expr, Function, Stmt};
use crate::ir::call_args::CallConv;
use crate::ir::types::{BinOp, VReg};
use crate::ir::types_recover::RecoveredPrototype;

/// What a multi-bank result contract requires of the frame object that holds it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BankContract {
    /// The synthesised C tag the definition is declared at.
    tag: &'static str,
    /// The declared result's size, which the object's extent must equal.
    bytes: u16,
    /// The first byte offset belonging to the SECOND bank.
    second_bank: u16,
}

/// The contract a convention and declared class impose, when this module can
/// spell them.
///
/// Win64 is absent deliberately: it returns every over-wide aggregate through a
/// hidden pointer, so it has no two-bank class to state.
fn bank_contract(cc: CallConv, class: ReturnClass) -> Option<BankContract> {
    match (cc, class) {
        // Both eightbytes are SSE. `high_bytes` carries how much of the second
        // one the callee defined, which is also how large the whole result is.
        (CallConv::SysVAmd64, ReturnClass::SsePair { high_bytes }) => {
            sse_pair_return_tag(high_bytes).map(|tag| BankContract {
                tag,
                bytes: 8 + u16::from(high_bytes),
                second_bank: 8,
            })
        }
        // One eightbyte in each bank: sixteen bytes whichever way round.
        (CallConv::SysVAmd64, ReturnClass::SplitBanks { integer_first }) => Some(BankContract {
            tag: split_bank_return_tag(integer_first),
            bytes: 16,
            second_bank: 8,
        }),
        // An HFA's "banks" are its member registers, so the second one starts
        // at the second member.
        (
            CallConv::Aarch64,
            ReturnClass::HomogeneousFloat {
                member_bytes,
                members,
            },
        ) => hfa_return_tag(member_bytes, members).map(|tag| BankContract {
            tag,
            bytes: u16::from(member_bytes) * u16::from(members),
            second_bank: u16::from(member_bytes),
        }),
        _ => None,
    }
}

/// Rewrite every `return` into the whole-object load its declared result class
/// requires. Returns `true` when the body changed.
///
/// ALL OR NOTHING, for the reason in the module note.
pub fn compose_bank_returns(
    function: &mut Function,
    cc: CallConv,
    prototype: Option<&RecoveredPrototype>,
) -> bool {
    let Some(contract) = prototype.and_then(|p| bank_contract(cc, p.return_class())) else {
        return false;
    };
    let Some((object, size)) = returned_stack_object(&function.body) else {
        return false;
    };
    if size != contract.bytes {
        return false;
    }
    if !stores_second_bank(&function.body, &object, contract) {
        return false;
    }
    rewrite_returns(&mut function.body, &object, size);
    true
}

/// The synthesised tag a body composed by [`compose_bank_returns`] may be
/// DECLARED at, or `None` for every other body.
///
/// Read from the final AST rather than remembered from the pass, for the same
/// reason [`crate::ir::callee_return_pair::returns_are_pair_composed`] is: a
/// later transform that rewrote a composed return would otherwise leave the
/// signature asserting a contract the body no longer meets.
pub fn bank_return_c_type(
    body: &[Stmt],
    cc: CallConv,
    prototype: Option<&RecoveredPrototype>,
) -> Option<&'static str> {
    let contract = prototype.and_then(|p| bank_contract(cc, p.return_class()))?;
    let mut seen: Option<(VReg, u16)> = None;
    if !every_return_loads_one_object(body, &mut seen) {
        return None;
    }
    let (_, size) = seen?;
    (size == contract.bytes).then_some(contract.tag)
}

/// Whether every `return` in `body` is the exact whole-object load this module
/// installs, and all of them name the same object.
fn every_return_loads_one_object(body: &[Stmt], seen: &mut Option<(VReg, u16)>) -> bool {
    body.iter().all(|statement| match statement {
        Stmt::Return { value } => {
            let Some(Expr::Deref { addr, .. }) = value else {
                return false;
            };
            let Expr::StackAddr { object, size } = addr.as_ref() else {
                return false;
            };
            match seen {
                Some(known) => *known == (object.clone(), *size),
                None => {
                    *seen = Some((object.clone(), *size));
                    true
                }
            }
        }
        _ => nested_bodies(statement)
            .into_iter()
            .all(|nested| every_return_loads_one_object(nested, seen)),
    })
}

/// The one stack object every `return` in `body` takes its value from, with
/// that object's recovered extent, or `None` when they do not agree on one.
fn returned_stack_object(body: &[Stmt]) -> Option<(VReg, u16)> {
    let mut found: Option<(VReg, u16)> = None;
    let mut any = false;
    if !scan_returns(
        body,
        &mut std::collections::HashMap::new(),
        &mut found,
        &mut any,
    ) {
        return None;
    }
    any.then_some(())?;
    found
}

/// Thread the loads-from-an-object environment through a linear walk, checking
/// each `return` against it.
///
/// `locals` maps a local whose reaching definition is an object load to that
/// object. A label is a join, so nothing a linear walk believed survives it,
/// and a nested body inherits a COPY: what a branch assigned cannot be assumed
/// after it.
fn scan_returns(
    body: &[Stmt],
    locals: &mut std::collections::HashMap<VReg, (VReg, u16)>,
    found: &mut Option<(VReg, u16)>,
    any: &mut bool,
) -> bool {
    for statement in body {
        match statement {
            Stmt::Assign { dst, src } => match stack_object_load(src) {
                Some(object) => {
                    locals.insert(dst.clone(), object);
                }
                None => {
                    locals.remove(dst);
                }
            },
            // A write to a PROMOTED SCALAR local is an assignment, not a
            // pointer store: `local_c = *(long *)(&local_18[0])` is spelled
            // `Stmt::Store` with a bare register address, which is exactly the
            // form `hfa197_make_trio3f` reaches its result through. A store
            // through anything else is a pointer write and defines no local,
            // so it is left alone.
            Stmt::Store {
                addr: Expr::Reg(destination),
                src,
                ..
            } if crate::ir::types::is_promoted_local_reg(destination) => {
                match stack_object_load(src) {
                    Some(object) => {
                        locals.insert(destination.clone(), object);
                    }
                    None => {
                        locals.remove(destination);
                    }
                }
            }
            Stmt::Call { dst: Some(dst), .. } => {
                locals.remove(dst);
            }
            Stmt::Return { value } => {
                *any = true;
                let Some(value) = value else {
                    return false;
                };
                let Some(object) = stack_object_load(value).or_else(|| match value {
                    Expr::Reg(register) => locals.get(register).cloned(),
                    _ => None,
                }) else {
                    return false;
                };
                match found {
                    Some(known) if *known != object => return false,
                    Some(_) => {}
                    None => *found = Some(object),
                }
            }
            Stmt::Label(_) => locals.clear(),
            _ => {
                for nested in nested_bodies(statement) {
                    if !scan_returns(nested, &mut locals.clone(), found, any) {
                        return false;
                    }
                }
            }
        }
    }
    true
}

/// Replace each `return` with the whole-object load.
fn rewrite_returns(body: &mut [Stmt], object: &VReg, size: u16) {
    for statement in body.iter_mut() {
        match statement {
            Stmt::Return { value } => {
                *value = Some(Expr::Deref {
                    addr: Box::new(Expr::StackAddr {
                        object: object.clone(),
                        size,
                    }),
                    // A machine-word access width. The pointee TYPE is the
                    // synthesised tag and comes from the declared result, not
                    // from here; this width only has to name a load.
                    size: size.min(8) as u8,
                });
            }
            _ => {
                for nested in nested_bodies_mut(statement) {
                    rewrite_returns(nested, object, size);
                }
            }
        }
    }
}

/// Whether `body` stores into `object` at an offset inside the second bank.
///
/// This is what proves the high half's bytes are in the object. Without it the
/// pass would declare a two-bank result over an object only the first bank was
/// ever written to, and hand back whatever the frame happened to hold.
fn stores_second_bank(body: &[Stmt], object: &VReg, contract: BankContract) -> bool {
    body.iter().any(|statement| match statement {
        Stmt::Store { addr, .. } => stack_object_offset(addr).is_some_and(|(base, _, offset)| {
            base == *object
                && offset >= i64::from(contract.second_bank)
                && offset < i64::from(contract.bytes)
        }),
        _ => nested_bodies(statement)
            .into_iter()
            .any(|nested| stores_second_bank(nested, object, contract)),
    })
}

/// The stack object an expression LOADS from, with its recovered extent.
fn stack_object_load(expr: &Expr) -> Option<(VReg, u16)> {
    let Expr::Deref { addr, .. } = expr else {
        return None;
    };
    stack_object_offset(addr).map(|(object, size, _)| (object, size))
}

/// The stack object an ADDRESS expression names, its recovered extent, and the
/// constant byte offset into it.
fn stack_object_offset(expr: &Expr) -> Option<(VReg, u16, i64)> {
    match expr {
        Expr::StackAddr { object, size } => Some((object.clone(), *size, 0)),
        Expr::Bin {
            op: BinOp::Add,
            lhs,
            rhs,
        } => match (lhs.as_ref(), rhs.as_ref()) {
            (base, Expr::Const(offset)) => {
                stack_object_offset(base).map(|(object, size, at)| (object, size, at + offset))
            }
            (Expr::Const(offset), base) => {
                stack_object_offset(base).map(|(object, size, at)| (object, size, at + offset))
            }
            _ => None,
        },
        _ => None,
    }
}

/// The statement lists a compound statement owns.
fn nested_bodies(statement: &Stmt) -> Vec<&[Stmt]> {
    match statement {
        Stmt::If {
            then_body,
            else_body,
            ..
        } => std::iter::once(then_body.as_slice())
            .chain(else_body.as_deref())
            .collect(),
        Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
            vec![body.as_slice()]
        }
        Stmt::Switch { cases, default, .. } => cases
            .iter()
            .map(|(_, case)| case.as_slice())
            .chain(default.as_deref())
            .collect(),
        Stmt::TryCatch { try_body, catches } => std::iter::once(try_body.as_slice())
            .chain(catches.iter().map(|catch| catch.body.as_slice()))
            .collect(),
        _ => Vec::new(),
    }
}

/// [`nested_bodies`], for a rewrite.
fn nested_bodies_mut(statement: &mut Stmt) -> Vec<&mut Vec<Stmt>> {
    let mut bodies: Vec<&mut Vec<Stmt>> = Vec::new();
    match statement {
        Stmt::If {
            then_body,
            else_body,
            ..
        } => {
            bodies.push(then_body);
            if let Some(else_body) = else_body {
                bodies.push(else_body);
            }
        }
        Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
            bodies.push(body);
        }
        Stmt::Switch { cases, default, .. } => {
            for (_, body) in cases.iter_mut() {
                bodies.push(body);
            }
            if let Some(default) = default {
                bodies.push(default);
            }
        }
        Stmt::TryCatch { try_body, catches } => {
            bodies.push(try_body);
            for catch in catches.iter_mut() {
                bodies.push(&mut catch.body);
            }
        }
        _ => {}
    }
    bodies
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::types_recover::{RecoveredOutputKind, RecoveredPrototype};

    fn object() -> VReg {
        VReg::phys("local_20")
    }

    fn load(offset: i64, size: u16) -> Expr {
        let base = Expr::StackAddr {
            object: object(),
            size,
        };
        let addr = if offset == 0 {
            base
        } else {
            Expr::Bin {
                op: BinOp::Add,
                lhs: Box::new(base),
                rhs: Box::new(Expr::Const(offset)),
            }
        };
        Expr::Deref {
            addr: Box::new(addr),
            size: 8,
        }
    }

    fn store(offset: i64, size: u16) -> Stmt {
        let base = Expr::StackAddr {
            object: object(),
            size,
        };
        Stmt::Store {
            addr: if offset == 0 {
                base
            } else {
                Expr::Bin {
                    op: BinOp::Add,
                    lhs: Box::new(base),
                    rhs: Box::new(Expr::Const(offset)),
                }
            },
            src: Expr::Const(1),
            size: 8,
        }
    }

    fn prototype(class: ReturnClass) -> RecoveredPrototype {
        let mut recovered = RecoveredPrototype::default();
        recovered.apply_locked_output(RecoveredOutputKind::Direct, None);
        recovered.apply_return_class(class);
        recovered
    }

    fn function(body: Vec<Stmt>) -> Function {
        Function {
            name: "f".to_string(),
            entry_va: 0,
            body,
        }
    }

    #[test]
    fn sse_pair_return_becomes_a_whole_object_load() {
        let mut f = function(vec![
            store(0, 16),
            store(8, 16),
            Stmt::Return {
                value: Some(load(0, 16)),
            },
        ]);
        let declared = prototype(ReturnClass::SsePair { high_bytes: 8 });
        assert!(compose_bank_returns(
            &mut f,
            CallConv::SysVAmd64,
            Some(&declared)
        ));
        assert_eq!(
            bank_return_c_type(&f.body, CallConv::SysVAmd64, Some(&declared)),
            Some("struct __glaurung_sse_pair")
        );
    }

    #[test]
    fn a_return_reading_the_second_bank_still_names_the_whole_object() {
        // `bv195_make_mixed` returns the SSE half, which is at offset 8. The
        // object is the result either way.
        let mut f = function(vec![
            store(0, 16),
            store(8, 16),
            Stmt::Return {
                value: Some(load(8, 16)),
            },
        ]);
        let declared = prototype(ReturnClass::SplitBanks {
            integer_first: true,
        });
        assert!(compose_bank_returns(
            &mut f,
            CallConv::SysVAmd64,
            Some(&declared)
        ));
        assert_eq!(
            bank_return_c_type(&f.body, CallConv::SysVAmd64, Some(&declared)),
            Some("struct __glaurung_split_is")
        );
    }

    #[test]
    fn a_return_through_a_local_copy_is_composed() {
        // `hfa197_make_trio3f` assigns the low eightbyte to a local first.
        let copy = VReg::phys("local_c");
        let mut f = function(vec![
            store(0, 12),
            store(8, 12),
            Stmt::Store {
                addr: Expr::Reg(copy.clone()),
                src: load(0, 12),
                size: 8,
            },
            Stmt::Return {
                value: Some(Expr::Reg(copy)),
            },
        ]);
        let declared = prototype(ReturnClass::SsePair { high_bytes: 4 });
        assert!(compose_bank_returns(
            &mut f,
            CallConv::SysVAmd64,
            Some(&declared)
        ));
        assert_eq!(
            bank_return_c_type(&f.body, CallConv::SysVAmd64, Some(&declared)),
            Some("struct __glaurung_sse_pair_half")
        );
    }

    #[test]
    fn an_object_the_second_bank_was_never_stored_to_is_declined() {
        let mut f = function(vec![
            store(0, 16),
            Stmt::Return {
                value: Some(load(0, 16)),
            },
        ]);
        let declared = prototype(ReturnClass::SsePair { high_bytes: 8 });
        assert!(!compose_bank_returns(
            &mut f,
            CallConv::SysVAmd64,
            Some(&declared)
        ));
        assert_eq!(
            bank_return_c_type(&f.body, CallConv::SysVAmd64, Some(&declared)),
            Some("struct __glaurung_sse_pair"),
            "the shape check alone cannot see the missing store; the pass is \
             what declines, and an uncomposed body never reaches the type"
        );
    }

    #[test]
    fn an_object_wider_than_the_result_is_declined() {
        let mut f = function(vec![
            store(0, 32),
            store(8, 32),
            Stmt::Return {
                value: Some(load(0, 32)),
            },
        ]);
        let declared = prototype(ReturnClass::SsePair { high_bytes: 8 });
        assert!(!compose_bank_returns(
            &mut f,
            CallConv::SysVAmd64,
            Some(&declared)
        ));
        assert_eq!(
            bank_return_c_type(&f.body, CallConv::SysVAmd64, Some(&declared)),
            None
        );
    }

    #[test]
    fn a_return_with_no_object_declines_the_whole_body() {
        let mut f = function(vec![
            store(0, 16),
            store(8, 16),
            Stmt::If {
                cond: Expr::Const(1),
                then_body: vec![Stmt::Return {
                    value: Some(Expr::Const(0)),
                }],
                else_body: None,
            },
            Stmt::Return {
                value: Some(load(0, 16)),
            },
        ]);
        let declared = prototype(ReturnClass::SsePair { high_bytes: 8 });
        assert!(!compose_bank_returns(
            &mut f,
            CallConv::SysVAmd64,
            Some(&declared)
        ));
    }

    #[test]
    fn the_integer_pair_class_is_left_to_its_own_module() {
        assert_eq!(
            bank_contract(CallConv::SysVAmd64, ReturnClass::IntegerPair),
            None
        );
        assert_eq!(
            bank_contract(
                CallConv::Win64,
                ReturnClass::SplitBanks {
                    integer_first: true
                }
            ),
            None
        );
    }

    #[test]
    fn an_aapcs64_hfa_has_a_contract() {
        assert_eq!(
            bank_contract(
                CallConv::Aarch64,
                ReturnClass::HomogeneousFloat {
                    member_bytes: 4,
                    members: 3,
                }
            ),
            Some(BankContract {
                tag: "struct __glaurung_hfa_3f",
                bytes: 12,
                second_bank: 4,
            })
        );
    }
}
