//! Source-arity evidence derived from balanced outgoing stack arguments.

use std::collections::HashSet;

use crate::ir::ast::{Expr, Function, Stmt};
use crate::ir::call_args::{
    outgoing_stack_cleanup_with_identities, outgoing_sysv_stack_push_with_identities,
    register_is_storage, stack_pointer_sub_width_with_identities, CallConv,
};
use crate::ir::types::VReg;
use crate::ir::value_number::ValueIdentities;

/// Direct calls whose balanced outgoing stack area bounds a fixed arity candidate.
///
/// Register liveness alone cannot distinguish arguments from caller-local
/// scratch values. Once a SysV caller writes one or more outgoing stack slots
/// and independently consumes the exact same byte count after the call, the ABI
/// establishes a six-register prefix plus an upper bound from push-shaped words.
/// One such word may be alignment padding, so the program environment applies a
/// stricter multi-caller policy before treating the candidate as exact.
#[cfg(test)]
pub(crate) fn stack_proven_direct_call_arities(
    function: &Function,
    cc: CallConv,
    requested_targets: &HashSet<u64>,
) -> Vec<(u64, usize)> {
    stack_proven_direct_call_arities_with_identities(function, cc, requested_targets, None)
}

pub(crate) fn stack_proven_direct_call_arities_with_identities(
    function: &Function,
    cc: CallConv,
    requested_targets: &HashSet<u64>,
    identities: Option<&ValueIdentities>,
) -> Vec<(u64, usize)> {
    fn visit(
        body: &[Stmt],
        cc: CallConv,
        requested_targets: &HashSet<u64>,
        found: &mut Vec<(u64, usize)>,
        identities: Option<&ValueIdentities>,
    ) {
        for (call_index, statement) in body.iter().enumerate() {
            let Stmt::Call { target, .. } = statement.semantic() else {
                match statement.semantic() {
                    Stmt::Origin { .. } => {
                        unreachable!("semantic statement cannot be an origin wrapper")
                    }
                    Stmt::If {
                        then_body,
                        else_body,
                        ..
                    } => {
                        visit(then_body, cc, requested_targets, found, identities);
                        if let Some(else_body) = else_body {
                            visit(else_body, cc, requested_targets, found, identities);
                        }
                    }
                    Stmt::While { body, .. }
                    | Stmt::DoWhile { body, .. }
                    | Stmt::For { body, .. } => {
                        visit(body, cc, requested_targets, found, identities)
                    }
                    Stmt::Switch { cases, default, .. } => {
                        for (_, case) in cases {
                            visit(case, cc, requested_targets, found, identities);
                        }
                        if let Some(default) = default {
                            visit(default, cc, requested_targets, found, identities);
                        }
                    }
                    Stmt::TryCatch { try_body, catches } => {
                        visit(try_body, cc, requested_targets, found, identities);
                        for catch in catches {
                            visit(&catch.body, cc, requested_targets, found, identities);
                        }
                    }
                    _ => {}
                }
                continue;
            };
            let target = match target {
                Expr::Addr(address) | Expr::Named { va: address, .. }
                    if requested_targets.contains(address) =>
                {
                    *address
                }
                _ => continue,
            };
            let Some(arity) =
                stack_proven_fixed_arity_with_identities(body, call_index, cc, identities)
            else {
                continue;
            };
            found.push((target, arity));
        }
    }

    let mut found = Vec::new();
    visit(
        &function.body,
        cc,
        requested_targets,
        &mut found,
        identities,
    );
    found
}

#[cfg(test)]
fn stack_proven_fixed_arity(body: &[Stmt], call_index: usize, cc: CallConv) -> Option<usize> {
    stack_proven_fixed_arity_with_identities(body, call_index, cc, None)
}

fn stack_proven_fixed_arity_with_identities(
    body: &[Stmt],
    call_index: usize,
    cc: CallConv,
    identities: Option<&ValueIdentities>,
) -> Option<usize> {
    if cc != CallConv::SysVAmd64 {
        return None;
    }
    let mut cursor = call_index;
    let mut stack_arguments = 0usize;
    let mut argument_bytes = 0i64;
    let mut padding_bytes = 0i64;
    while cursor > 0 {
        let index = cursor - 1;
        if let Some((_, width)) = outgoing_sysv_stack_push_with_identities(body, index, identities)
        {
            stack_arguments = stack_arguments.checked_add(1)?;
            argument_bytes = argument_bytes.checked_add(width)?;
            cursor = index.checked_sub(1)?;
            continue;
        }
        if stack_arguments > 0
            && padding_bytes == 0
            && stack_pointer_sub_width_with_identities(&body[index], identities) == Some(8)
        {
            padding_bytes = 8;
            cursor = index;
            continue;
        }
        if matches!(
            body[index].semantic(),
            Stmt::Assign {
                dst: VReg::Phys(name),
                ..
            } if !register_is_storage(&VReg::Phys(name.clone()), "rsp", identities)
        ) || matches!(
            body[index].semantic(),
            Stmt::Assign {
                dst: VReg::Temp(_) | VReg::Flag(_) | VReg::FlagValue { .. },
                ..
            }
        ) || matches!(body[index].semantic(), Stmt::Comment(_) | Stmt::Nop)
        {
            cursor = index;
            continue;
        }
        break;
    }
    if stack_arguments == 0 {
        return None;
    }
    outgoing_stack_cleanup_with_identities(
        body,
        call_index,
        argument_bytes.checked_add(padding_bytes)?,
        identities,
    )?;
    crate::ir::abi::argument_slots(cc)
        .len()
        .checked_add(stack_arguments)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::types::BinOp;

    fn reg(name: &str) -> VReg {
        VReg::phys(name)
    }

    fn assign(dst: &str, value: i64) -> Stmt {
        Stmt::Assign {
            dst: reg(dst),
            src: Expr::Const(value),
        }
    }

    fn call_to(name: &str) -> Stmt {
        Stmt::Call {
            target: Expr::Named {
                va: 0x2000,
                name: name.into(),
            },
            args: vec![],
            dst: None,
            call_spec: None,
        }
    }

    fn sysv_stack_push(value: i64) -> [Stmt; 2] {
        [
            Stmt::Assign {
                dst: reg("rsp"),
                src: Expr::Bin {
                    op: BinOp::Sub,
                    lhs: Box::new(Expr::Reg(reg("rsp"))),
                    rhs: Box::new(Expr::Const(8)),
                },
            },
            Stmt::Store {
                addr: Expr::Lea {
                    base: Some(reg("rsp")),
                    index: None,
                    scale: 1,
                    disp: 0,
                    segment: None,
                },
                src: Expr::Const(value),
                size: 8,
            },
        ]
    }

    fn stack_add(width: i64) -> Stmt {
        Stmt::Assign {
            dst: reg("rsp"),
            src: Expr::Bin {
                op: BinOp::Add,
                lhs: Box::new(Expr::Reg(reg("rsp"))),
                rhs: Box::new(Expr::Const(width)),
            },
        }
    }

    #[test]
    fn requires_stack_arguments_and_exact_cleanup() {
        let mut exact = Vec::new();
        exact.extend(sysv_stack_push(7));
        exact.extend(sysv_stack_push(6));
        exact.push(call_to("callee"));
        exact.push(stack_add(16));
        assert_eq!(
            stack_proven_fixed_arity(&exact, 4, CallConv::SysVAmd64),
            Some(8)
        );

        let mut missing_cleanup = exact.clone();
        missing_cleanup.pop();
        assert_eq!(
            stack_proven_fixed_arity(&missing_cleanup, 4, CallConv::SysVAmd64),
            None
        );

        let register_only = vec![assign("rdi", 0), call_to("callee")];
        assert_eq!(
            stack_proven_fixed_arity(&register_only, 1, CallConv::SysVAmd64),
            None
        );
        assert_eq!(stack_proven_fixed_arity(&exact, 4, CallConv::Aarch64), None);
    }

    #[test]
    fn caller_stack_arity_uses_exact_identity_not_display_spelling() {
        let stack_sub = |dst: &str| Stmt::Assign {
            dst: reg(dst),
            src: Expr::Bin {
                op: BinOp::Sub,
                lhs: Box::new(Expr::Reg(reg(dst))),
                rhs: Box::new(Expr::Const(8)),
            },
        };
        let stack_add = |dst: &str| Stmt::Assign {
            dst: reg(dst),
            src: Expr::Bin {
                op: BinOp::Add,
                lhs: Box::new(Expr::Reg(reg(dst))),
                rhs: Box::new(Expr::Const(8)),
            },
        };
        let body = vec![
            stack_sub("opaque_stack"),
            Stmt::Store {
                addr: Expr::Lea {
                    base: Some(reg("opaque_stack")),
                    index: None,
                    scale: 1,
                    disp: 0,
                    segment: None,
                },
                src: Expr::Const(7),
                size: 8,
            },
            assign("rsp#looks_like_stack", 1),
            call_to("callee"),
            stack_add("opaque_stack"),
        ];
        let mut identities = ValueIdentities::default();
        identities.record(
            reg("opaque_stack"),
            crate::ir::ssa::SsaValue {
                base: reg("rsp"),
                version: 4,
            },
        );
        identities.record(
            reg("rsp#looks_like_stack"),
            crate::ir::ssa::SsaValue {
                base: reg("rax"),
                version: 4,
            },
        );

        assert_eq!(
            stack_proven_fixed_arity_with_identities(
                &body,
                3,
                CallConv::SysVAmd64,
                Some(&identities),
            ),
            Some(7)
        );
    }

    #[test]
    fn accepts_one_alignment_word_and_lowered_pop_cleanup() {
        let mut aligned = vec![Stmt::Assign {
            dst: reg("rsp"),
            src: Expr::Bin {
                op: BinOp::Sub,
                lhs: Box::new(Expr::Reg(reg("rsp"))),
                rhs: Box::new(Expr::Const(8)),
            },
        }];
        aligned.extend(sysv_stack_push(6));
        aligned.push(call_to("callee"));
        aligned.push(stack_add(16));
        assert_eq!(
            stack_proven_fixed_arity(&aligned, 3, CallConv::SysVAmd64),
            Some(7)
        );

        let lowered_pop = |dst: &str| {
            [
                Stmt::Assign {
                    dst: reg(dst),
                    src: Expr::Deref {
                        addr: Box::new(Expr::Lea {
                            base: Some(reg("rsp")),
                            index: None,
                            scale: 1,
                            disp: 0,
                            segment: None,
                        }),
                        size: 8,
                    },
                },
                stack_add(8),
            ]
        };
        let mut popped = Vec::new();
        popped.extend(sysv_stack_push(7));
        popped.extend(sysv_stack_push(6));
        popped.push(call_to("callee"));
        popped.extend(lowered_pop("rdx"));
        popped.extend(lowered_pop("rcx"));
        assert_eq!(
            stack_proven_fixed_arity(&popped, 4, CallConv::SysVAmd64),
            Some(8)
        );
    }

    #[test]
    fn attributed_stack_call_sequence_keeps_its_arity_evidence() {
        let mut body = Vec::new();
        body.extend(sysv_stack_push(7));
        body.extend(sysv_stack_push(6));
        body.push(call_to("callee"));
        body.push(stack_add(16));
        let body = body
            .into_iter()
            .enumerate()
            .map(|(index, statement)| {
                statement.with_origins(crate::ir::ast::OriginSet::one(
                    0x1000 + u64::try_from(index).expect("small fixture") * 4,
                ))
            })
            .collect();
        let function = Function {
            name: "caller".into(),
            entry_va: 0x1000,
            body,
        };

        assert_eq!(
            stack_proven_direct_call_arities(
                &function,
                CallConv::SysVAmd64,
                &HashSet::from([0x2000]),
            ),
            vec![(0x2000, 8)]
        );
    }
}
