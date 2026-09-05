//! Indirect aggregate-result buffers at call sites.
//!
//! Every other return class in this crate lands in a register, so recovering it
//! is a question about WHICH register. This one is in no register at all. The
//! Arm Procedure Call Standard (IHI 0055, "Result return") says that when the
//! result type is a Composite Type larger than 16 bytes and not an HFA or HVA,
//! the caller reserves a block of memory and "shall pass its address in `x8`" —
//! the Indirect Result Location Register, which sits OUTSIDE `x0`-`x7` and
//! shifts no argument.
//!
//! That last clause is why this cannot reuse [`crate::ir::abi::ReturnClass::Memory`].
//! On System V the hidden pointer IS argument zero, so ordinary argument
//! reconstruction sees it. It still needs to declare the pointed-to stack
//! extent as one object, however, or a bare `rsp` argument survives promotion
//! and renders as an uninitialised scalar instead of `&buffer`. `x8` is invisible
//! to argument reconstruction entirely: a caller's
//! `add x0, sp, #0x10 ; mov x8, x0` looks like two dead moves, dead-store
//! elimination removes them, and the call renders as `f(seed)` with the result
//! buffer never written. The reads that follow are individually correct and read
//! a buffer nothing filled.
//!
//! There is exactly one way to make a C compiler emit an `x8` setup: declare the
//! callee as RETURNING an object larger than sixteen bytes, and assign the call
//! to storage. No argument list can name `x8`. So the recovery is two steps:
//!
//! 1. [`indirect_result_buffer_hints`], before stack promotion, tells
//!    `stack_locals` that the bytes at the address `x8` received are ONE object
//!    of the declared size. Without it a `-O2` caller's twenty-byte buffer
//!    promotes as five unrelated four-byte slots and there is no single
//!    destination to assign to;
//! 2. [`bind_indirect_result_buffers`], after stack promotion, makes that object
//!    the call's destination, which the renderer then spells through
//!    [`crate::ir::abi::indirect_return_tag`].
//!
//! Both are fail-closed: a call whose `x8` evidence this reader cannot follow
//! keeps exactly the behaviour it has today.

use crate::ir::ast::{Expr, Function, Stmt};
use crate::ir::call_args::CallConv;
use crate::ir::stack_locals::StackObjectHint;
use crate::ir::types::{BinOp, VReg};
use std::collections::HashMap;

/// The declared buffer size of a call that returns through `x8`, or `None`.
fn indirect_result_bytes(
    call_spec: Option<&crate::ir::call_contracts::CallSiteSpec>,
) -> Option<u16> {
    crate::ir::abi::indirect_return_bytes(&call_spec?.call_prototype.return_type)
}

fn sysv_hidden_result_bytes(
    call_spec: Option<&crate::ir::call_contracts::CallSiteSpec>,
) -> Option<u16> {
    let spelling = call_spec?.call_prototype.parameter_types.first()?;
    let width = spelling
        .strip_prefix("char (*)[")?
        .strip_suffix(']')?
        .parse::<u16>()
        .ok()?;
    (width != 0).then_some(width)
}

/// Whether `name` is a frame base this reader will accept a coordinate against.
///
/// Only the two the ABI defines: the stack pointer and the frame pointer. A
/// coordinate against anything else is not one `stack_locals` keys a slot with,
/// so following it would produce a hint for storage nothing promotes.
fn frame_base(name: &str) -> Option<&'static str> {
    match crate::ir::abi::ssa_base(name) {
        "sp" => Some("sp"),
        "fp" | "x29" => Some("x29"),
        "rsp" => Some("rsp"),
        "rbp" => Some("rbp"),
        _ => None,
    }
}

/// Resolve an expression to a frame coordinate, following copies recorded so far.
fn frame_address(expr: &Expr, known: &HashMap<String, (String, i64)>) -> Option<(String, i64)> {
    match expr {
        Expr::Reg(VReg::Phys(name)) => frame_base(name)
            .map(|base| (base.to_string(), 0))
            .or_else(|| known.get(crate::ir::abi::ssa_base(name)).cloned()),
        Expr::Lea {
            base: Some(VReg::Phys(name)),
            index: None,
            disp,
            segment: None,
            ..
        } => frame_base(name).map(|base| (base.to_string(), *disp)),
        Expr::Bin {
            op: BinOp::Add,
            lhs,
            rhs,
        } => match (frame_address(lhs, known), rhs.as_ref()) {
            (Some((base, offset)), Expr::Const(delta)) => {
                Some((base, offset.saturating_add(*delta)))
            }
            _ => None,
        },
        _ => None,
    }
}

/// The promoted stack object an expression names, if it is one.
fn promoted_object(expr: &Expr, known: &HashMap<String, VReg>) -> Option<VReg> {
    match expr {
        Expr::StackAddr { object, .. } => Some(object.clone()),
        Expr::Reg(VReg::Phys(name)) => known.get(crate::ir::abi::ssa_base(name)).cloned(),
        _ => None,
    }
}

/// The statement lists a compound statement owns.
fn nested_bodies(statement: &mut Stmt) -> Vec<&mut Vec<Stmt>> {
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

/// Declare each `x8` result buffer as ONE object of its callee's declared size.
///
/// Run BEFORE `stack_locals::promote_stack_locals_with_facts`, whose hint list
/// this extends. At `-O0` the buffer is already one twenty-byte object because
/// every member is written through the same base; at `-O2` the five members are
/// five independent four-byte accesses and promote as `stack_top`, `stack_4`,
/// `stack_5`, ... with no object to assign the call to. The hint has the same
/// shape DWARF supplies for a named local, and it is derived from the ABI rather
/// than from debug info — which matters because the `-O2` build of
/// `198_aggregate_return_edges:aarch64:agr198_five_roundtrip` describes no local
/// for that buffer at all (measured 2026-08-18: `stack object hints` is empty).
///
/// The tracked map is per statement LIST and is cleared at every call and at
/// every compound statement. Fail-closed on purpose: a coordinate that survived
/// a call would be this reader inventing a buffer, and `x8` is caller-saved.
pub fn indirect_result_buffer_hints(f: &Function, cc: CallConv) -> Vec<StackObjectHint> {
    let mut hints = Vec::new();
    match cc {
        CallConv::Aarch64 => collect_hints(&f.body, &mut hints),
        CallConv::SysVAmd64 => collect_sysv_hints(&f.body, 0, &mut hints),
        _ => {}
    }
    hints
}

/// Record the object named by a SysV memory-return call's hidden first argument.
/// Argument reconstruction has already folded setup copies, so accept only a
/// direct frame coordinate in the argument expression and otherwise decline.
fn sysv_entry_frame_address(expr: &Expr, stack_delta: i64) -> Option<(String, i64)> {
    match expr {
        Expr::Reg(VReg::Phys(name)) if crate::ir::abi::ssa_base(name) == "rsp" => {
            Some(("entry_rsp".to_string(), stack_delta))
        }
        Expr::Lea {
            base: Some(VReg::Phys(name)),
            index: None,
            disp,
            segment: None,
            ..
        } if crate::ir::abi::ssa_base(name) == "rsp" => {
            Some(("entry_rsp".to_string(), stack_delta.saturating_add(*disp)))
        }
        _ => None,
    }
}

fn sysv_stack_adjustment(statement: &Stmt) -> Option<i64> {
    let Stmt::Assign {
        dst: VReg::Phys(dst),
        src: Expr::Bin { op, lhs, rhs },
    } = statement
    else {
        return None;
    };
    if crate::ir::abi::ssa_base(dst) != "rsp"
        || !matches!(lhs.as_ref(), Expr::Reg(VReg::Phys(src)) if crate::ir::abi::ssa_base(src) == "rsp")
    {
        return None;
    }
    let Expr::Const(width) = rhs.as_ref() else {
        return None;
    };
    match op {
        BinOp::Add => Some(*width),
        BinOp::Sub => Some(width.saturating_neg()),
        _ => None,
    }
}

fn collect_sysv_hints(body: &[Stmt], mut stack_delta: i64, hints: &mut Vec<StackObjectHint>) {
    for statement in body {
        if let Some(adjustment) = sysv_stack_adjustment(statement) {
            stack_delta = stack_delta.saturating_add(adjustment);
        }
        if let Stmt::Call {
            args, call_spec, ..
        } = statement
        {
            if let (Some(bytes), Some((base, disp))) = (
                sysv_hidden_result_bytes(call_spec.as_ref()),
                args.first()
                    .and_then(|argument| sysv_entry_frame_address(argument, stack_delta)),
            ) {
                hints.push(StackObjectHint {
                    base,
                    disp,
                    size: bytes,
                    aggregate: true,
                    source_name: None,
                    c_type: None,
                    cfa_relative: false,
                });
            }
        }
        match statement {
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                collect_sysv_hints(then_body, stack_delta, hints);
                if let Some(else_body) = else_body {
                    collect_sysv_hints(else_body, stack_delta, hints);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
                collect_sysv_hints(body, stack_delta, hints);
            }
            Stmt::Switch { cases, default, .. } => {
                for (_, body) in cases {
                    collect_sysv_hints(body, stack_delta, hints);
                }
                if let Some(default) = default {
                    collect_sysv_hints(default, stack_delta, hints);
                }
            }
            Stmt::TryCatch { try_body, catches } => {
                collect_sysv_hints(try_body, stack_delta, hints);
                for catch in catches {
                    collect_sysv_hints(&catch.body, stack_delta, hints);
                }
            }
            _ => {}
        }
    }
}

fn collect_hints(body: &[Stmt], hints: &mut Vec<StackObjectHint>) {
    let mut known: HashMap<String, (String, i64)> = HashMap::new();
    for statement in body {
        match statement {
            Stmt::Assign { dst, src } => {
                let resolved = frame_address(src, &known);
                if let VReg::Phys(name) = dst {
                    // SSA versions are stripped: the map answers "what does
                    // THIS REGISTER hold", and `x8#1` is a version of `x8`.
                    let base = crate::ir::abi::ssa_base(name);
                    match resolved {
                        Some(address) => known.insert(base.to_string(), address),
                        None => known.remove(base),
                    };
                }
            }
            Stmt::Call { call_spec, .. } => {
                if let (Some(bytes), Some((base, disp))) = (
                    indirect_result_bytes(call_spec.as_ref()),
                    known.get("x8").cloned(),
                ) {
                    hints.push(StackObjectHint {
                        base,
                        disp,
                        size: bytes,
                        aggregate: true,
                        source_name: None,
                        c_type: None,
                        cfa_relative: false,
                    });
                }
                known.clear();
            }
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                collect_hints(then_body, hints);
                if let Some(else_body) = else_body {
                    collect_hints(else_body, hints);
                }
                known.clear();
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
                collect_hints(body, hints);
                known.clear();
            }
            Stmt::Switch { cases, default, .. } => {
                for (_, body) in cases {
                    collect_hints(body, hints);
                }
                if let Some(default) = default {
                    collect_hints(default, hints);
                }
                known.clear();
            }
            Stmt::TryCatch { try_body, catches } => {
                collect_hints(try_body, hints);
                for catch in catches {
                    collect_hints(&catch.body, hints);
                }
                known.clear();
            }
            _ => known.clear(),
        }
    }
}

/// Make each `x8` result buffer the destination of the call that fills it.
///
/// Run AFTER stack promotion, which is what turns the frame coordinate into a
/// named object the renderer can take the address of: the caller's
/// `%x8 = (%sp + 16)` has become `%x8 = &%local_30` by this point, so the
/// destination is read off the `x8` expression rather than off the coordinate.
///
/// Returns how many calls were bound, so the pass is observable.
pub fn bind_indirect_result_buffers(f: &mut Function, cc: CallConv) -> usize {
    let mut bound = 0;
    if matches!(cc, CallConv::Aarch64) {
        bind_bodies(&mut f.body, &mut bound);
    }
    bound
}

fn bind_bodies(body: &mut Vec<Stmt>, bound: &mut usize) {
    let mut known: HashMap<String, VReg> = HashMap::new();
    for statement in body.iter_mut() {
        match statement {
            Stmt::Assign { dst, src } => {
                let resolved = promoted_object(src, &known);
                if let VReg::Phys(name) = dst {
                    let base = crate::ir::abi::ssa_base(name);
                    match resolved {
                        Some(object) => known.insert(base.to_string(), object),
                        None => known.remove(base),
                    };
                }
            }
            Stmt::Call { dst, call_spec, .. } => {
                let buffer = indirect_result_bytes(call_spec.as_ref())
                    .and_then(|_| known.get("x8").cloned());
                if let Some(buffer) = buffer {
                    *dst = Some(buffer);
                    *bound += 1;
                }
                known.clear();
            }
            _ => {
                for nested in nested_bodies(statement) {
                    bind_bodies(nested, bound);
                }
                known.clear();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::call_contracts::{CallPrototype, CallPrototypeAuthority, CallSiteSpec};

    fn indirect_spec(bytes: u16) -> Option<CallSiteSpec> {
        Some(CallSiteSpec {
            call_prototype: CallPrototype {
                return_type: crate::ir::abi::indirect_return_tag(bytes)
                    .expect("a size past the register cutoff has a tag"),
                parameter_types: vec!["int".to_string()],
                variadic: false,
                authority: CallPrototypeAuthority::Recovered,
            },
            callee_prototype: None,
        })
    }

    fn call(spec: Option<CallSiteSpec>, dst: Option<VReg>) -> Stmt {
        Stmt::Call {
            target: Expr::Named {
                va: 0x1000,
                name: "make_five".to_string(),
            },
            args: vec![Expr::Reg(VReg::phys("x0"))],
            dst,
            call_spec: spec,
        }
    }

    /// `-O0` shape: the address is computed into a scratch register first.
    #[test]
    fn an_indirect_result_buffer_is_hinted_through_the_copy_that_reaches_x8() {
        let f = Function {
            name: "caller".to_string(),
            entry_va: 0x1000,
            body: vec![
                Stmt::Assign {
                    dst: VReg::phys("x0"),
                    src: Expr::Bin {
                        op: BinOp::Add,
                        lhs: Box::new(Expr::Reg(VReg::phys("sp"))),
                        rhs: Box::new(Expr::Const(16)),
                    },
                },
                Stmt::Assign {
                    dst: VReg::phys("x8"),
                    src: Expr::Reg(VReg::phys("x0")),
                },
                call(indirect_spec(20), None),
            ],
        };
        let hints = indirect_result_buffer_hints(&f, CallConv::Aarch64);
        assert_eq!(hints.len(), 1);
        assert_eq!((hints[0].base.as_str(), hints[0].disp), ("sp", 16));
        assert_eq!(hints[0].size, 20);
        assert!(hints[0].aggregate);
        // These conventions do not use AAPCS64's x8 and do not infer a buffer
        // from this ordinary x0 argument.
        for cc in [
            CallConv::Win64,
            CallConv::Cdecl32,
            CallConv::Arm,
            CallConv::ArmHardFloat,
        ] {
            assert!(
                indirect_result_buffer_hints(&f, cc).is_empty(),
                "{cc:?} acquired the AAPCS64 indirect result buffer"
            );
        }
    }

    #[test]
    fn sysv_hidden_first_argument_hints_one_aggregate_stack_object() {
        let mut spec = indirect_spec(32).expect("indirect spec");
        spec.call_prototype.parameter_types[0] = "char (*)[32]".to_string();
        let mut hidden_call = call(Some(spec), None);
        let Stmt::Call { args, .. } = &mut hidden_call else {
            unreachable!()
        };
        *args = vec![Expr::Reg(VReg::phys("rsp")), Expr::Reg(VReg::phys("rsi"))];
        let f = Function {
            name: "caller".to_string(),
            entry_va: 0x1000,
            body: vec![hidden_call],
        };

        let hints = indirect_result_buffer_hints(&f, CallConv::SysVAmd64);
        assert_eq!(hints.len(), 1);
        assert_eq!((hints[0].base.as_str(), hints[0].disp), ("entry_rsp", 0));
        assert_eq!(hints[0].size, 32);
        assert!(hints[0].aggregate);
    }

    /// `-O2` shape: `mov x8, sp`, and the buffer is the whole frame base.
    #[test]
    fn a_bare_frame_base_in_x8_is_a_buffer_at_offset_zero() {
        let f = Function {
            name: "caller".to_string(),
            entry_va: 0x1000,
            body: vec![
                Stmt::Assign {
                    dst: VReg::phys("x8"),
                    src: Expr::Reg(VReg::phys("sp")),
                },
                call(indirect_spec(32), None),
            ],
        };
        let hints = indirect_result_buffer_hints(&f, CallConv::Aarch64);
        assert_eq!(hints.len(), 1);
        assert_eq!((hints[0].base.as_str(), hints[0].disp), ("sp", 0));
        assert_eq!(hints[0].size, 32);
    }

    /// THE REFUSALS. A buffer this reader cannot prove must not be invented:
    /// a call with no indirect class, an `x8` holding something that is not a
    /// frame address, and an `x8` set before an intervening call (which
    /// clobbers it) all produce nothing.
    #[test]
    fn unprovable_x8_evidence_produces_no_hint_and_no_binding() {
        let scalar = Some(CallSiteSpec {
            call_prototype: CallPrototype {
                return_type: "long".to_string(),
                parameter_types: vec!["int".to_string()],
                variadic: false,
                authority: CallPrototypeAuthority::Recovered,
            },
            callee_prototype: None,
        });
        let body = |setup: Stmt, spec: Option<CallSiteSpec>| Function {
            name: "caller".to_string(),
            entry_va: 0x1000,
            body: vec![setup, call(spec, None)],
        };
        let x8_from_frame = Stmt::Assign {
            dst: VReg::phys("x8"),
            src: Expr::Reg(VReg::phys("sp")),
        };
        // No indirect class on the callee.
        assert!(indirect_result_buffer_hints(
            &body(x8_from_frame.clone(), scalar),
            CallConv::Aarch64
        )
        .is_empty());
        // `x8` holds a heap pointer, not a frame coordinate.
        assert!(indirect_result_buffer_hints(
            &body(
                Stmt::Assign {
                    dst: VReg::phys("x8"),
                    src: Expr::Reg(VReg::phys("x19")),
                },
                indirect_spec(20)
            ),
            CallConv::Aarch64
        )
        .is_empty());
        // An intervening call clobbers `x8`.
        let clobbered = Function {
            name: "caller".to_string(),
            entry_va: 0x1000,
            body: vec![
                x8_from_frame,
                call(None, None),
                call(indirect_spec(20), None),
            ],
        };
        assert!(indirect_result_buffer_hints(&clobbered, CallConv::Aarch64).is_empty());
    }

    /// After promotion the coordinate is gone and the object is named; the
    /// binding must follow that spelling, and only for a proven indirect call.
    #[test]
    fn a_promoted_buffer_becomes_the_call_destination() {
        let promoted = |spec: Option<CallSiteSpec>| Function {
            name: "caller".to_string(),
            entry_va: 0x1000,
            body: vec![
                Stmt::Assign {
                    dst: VReg::phys("x8"),
                    src: Expr::StackAddr {
                        object: VReg::phys("local_30"),
                        size: 20,
                    },
                },
                call(spec, None),
            ],
        };
        let mut f = promoted(indirect_spec(20));
        assert_eq!(bind_indirect_result_buffers(&mut f, CallConv::Aarch64), 1);
        assert!(
            matches!(&f.body[1], Stmt::Call { dst: Some(VReg::Phys(name)), .. } if name == "local_30")
        );
        // The negative: an ordinary scalar callee keeps its destination
        // untouched even with a frame address sitting in `x8`.
        let mut scalar = promoted(None);
        assert_eq!(
            bind_indirect_result_buffers(&mut scalar, CallConv::Aarch64),
            0
        );
        assert!(matches!(&scalar.body[1], Stmt::Call { dst: None, .. }));
        // And no other convention binds anything.
        let mut other = promoted(indirect_spec(20));
        assert_eq!(
            bind_indirect_result_buffers(&mut other, CallConv::SysVAmd64),
            0
        );
    }
}
