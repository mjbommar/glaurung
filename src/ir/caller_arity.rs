//! Source-arity evidence derived from balanced outgoing stack arguments.

use std::collections::HashSet;

use crate::ir::ast::{Expr, Function, Stmt};
use crate::ir::call_args::{
    outgoing_stack_cleanup, outgoing_sysv_stack_push, ssa_base, stack_pointer_sub_width, CallConv,
};
use crate::ir::types::VReg;

/// Direct calls whose balanced outgoing stack area bounds a fixed arity candidate.
///
/// Register liveness alone cannot distinguish arguments from caller-local
/// scratch values. Once a SysV caller writes one or more outgoing stack slots
/// and independently consumes the exact same byte count after the call, the ABI
/// establishes a six-register prefix plus an upper bound from push-shaped words.
/// One such word may be alignment padding, so the program environment applies a
/// stricter multi-caller policy before treating the candidate as exact.
pub(crate) fn stack_proven_direct_call_arities(
    function: &Function,
    cc: CallConv,
    requested_targets: &HashSet<u64>,
) -> Vec<(u64, usize)> {
    fn visit(
        body: &[Stmt],
        cc: CallConv,
        requested_targets: &HashSet<u64>,
        found: &mut Vec<(u64, usize)>,
    ) {
        for (call_index, statement) in body.iter().enumerate() {
            let Stmt::Call { target, .. } = statement else {
                match statement {
                    Stmt::If {
                        then_body,
                        else_body,
                        ..
                    } => {
                        visit(then_body, cc, requested_targets, found);
                        if let Some(else_body) = else_body {
                            visit(else_body, cc, requested_targets, found);
                        }
                    }
                    Stmt::While { body, .. }
                    | Stmt::DoWhile { body, .. }
                    | Stmt::For { body, .. } => visit(body, cc, requested_targets, found),
                    Stmt::Switch { cases, default, .. } => {
                        for (_, case) in cases {
                            visit(case, cc, requested_targets, found);
                        }
                        if let Some(default) = default {
                            visit(default, cc, requested_targets, found);
                        }
                    }
                    Stmt::TryCatch { try_body, catches } => {
                        visit(try_body, cc, requested_targets, found);
                        for catch in catches {
                            visit(&catch.body, cc, requested_targets, found);
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
            let Some(arity) = stack_proven_fixed_arity(body, call_index, cc) else {
                continue;
            };
            found.push((target, arity));
        }
    }

    let mut found = Vec::new();
    visit(&function.body, cc, requested_targets, &mut found);
    found
}

fn stack_proven_fixed_arity(body: &[Stmt], call_index: usize, cc: CallConv) -> Option<usize> {
    if cc != CallConv::SysVAmd64 {
        return None;
    }
    let mut cursor = call_index;
    let mut stack_arguments = 0usize;
    let mut argument_bytes = 0i64;
    let mut padding_bytes = 0i64;
    while cursor > 0 {
        let index = cursor - 1;
        if let Some((_, width)) = outgoing_sysv_stack_push(body, index) {
            stack_arguments = stack_arguments.checked_add(1)?;
            argument_bytes = argument_bytes.checked_add(width)?;
            cursor = index.checked_sub(1)?;
            continue;
        }
        if stack_arguments > 0
            && padding_bytes == 0
            && stack_pointer_sub_width(&body[index]) == Some(8)
        {
            padding_bytes = 8;
            cursor = index;
            continue;
        }
        if matches!(
            &body[index],
            Stmt::Assign {
                dst: VReg::Phys(name),
                ..
            } if ssa_base(name) != "rsp"
        ) || matches!(
            &body[index],
            Stmt::Assign {
                dst: VReg::Temp(_) | VReg::Flag(_) | VReg::FlagValue { .. },
                ..
            }
        ) || matches!(&body[index], Stmt::Comment(_) | Stmt::Nop)
        {
            cursor = index;
            continue;
        }
        break;
    }
    if stack_arguments == 0 {
        return None;
    }
    outgoing_stack_cleanup(body, call_index, argument_bytes.checked_add(padding_bytes)?)?;
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
}
