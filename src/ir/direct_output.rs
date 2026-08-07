//! Projection of machine return storage onto source-level AST returns.
//!
//! Lowering preserves a bare machine `RET` as `Return { value: None }`. This
//! module materializes a value only when either the body writes a known return
//! register or an authoritative prototype proves that the live-in parameter is
//! itself the direct result. Keeping that policy outside the renderer prevents
//! `return 0` fabrication while leaving void and unknown outputs untouched.

use crate::ir::ast::{Expr, Function, Stmt};
use crate::ir::call_args::CallConv;
use crate::ir::types::VReg;
use crate::ir::types_recover::{RecoveredOutputKind, RecoveredPrototype};

/// Project a body-written return register onto every remaining bare return.
pub(crate) fn materialize_direct_output(function: &mut Function) {
    materialize_direct_output_with_live_in(function, None);
}

/// Project a prototype-proven direct output, including identity functions whose
/// machine body is only `ret` and therefore has no in-function result write.
pub(crate) fn materialize_prototype_output(
    function: &mut Function,
    cc: CallConv,
    prototype: Option<&RecoveredPrototype>,
) {
    let live_in_result = prototype.and_then(|prototype| {
        if prototype.output_kind() != RecoveredOutputKind::Direct
            || !prototype.output_is_locked()
            || !prototype.parameter_arity_is_locked()
        {
            return None;
        }
        let result = prototype.result()?;
        if !result.values.is_empty() {
            return None;
        }
        let parameter = prototype.parameter(0)?;
        match &parameter.value.base {
            VReg::Phys(name) if crate::ir::abi::is_return_register(cc, name) => {
                Some(&parameter.value.base)
            }
            _ => None,
        }
    });
    let live_in_result =
        live_in_result.filter(|_| !body_writes_abi_return_storage(&function.body, cc));
    materialize_direct_output_with_live_in(function, live_in_result);
}

fn body_writes_abi_return_storage(body: &[Stmt], cc: CallConv) -> bool {
    body.iter().any(|statement| match statement {
        Stmt::Assign {
            dst: VReg::Phys(name),
            ..
        }
        | Stmt::Call {
            dst: Some(VReg::Phys(name)),
            ..
        } => crate::ir::abi::is_return_register(cc, name) || name == "ret",
        Stmt::If {
            then_body,
            else_body,
            ..
        } => {
            body_writes_abi_return_storage(then_body, cc)
                || else_body
                    .as_deref()
                    .is_some_and(|body| body_writes_abi_return_storage(body, cc))
        }
        Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
            body_writes_abi_return_storage(body, cc)
        }
        Stmt::For {
            init, step, body, ..
        } => {
            body_writes_abi_return_storage(std::slice::from_ref(init), cc)
                || body_writes_abi_return_storage(std::slice::from_ref(step), cc)
                || body_writes_abi_return_storage(body, cc)
        }
        Stmt::Switch { cases, default, .. } => {
            cases
                .iter()
                .any(|(_, body)| body_writes_abi_return_storage(body, cc))
                || default
                    .as_deref()
                    .is_some_and(|body| body_writes_abi_return_storage(body, cc))
        }
        Stmt::TryCatch { try_body, catches } => {
            body_writes_abi_return_storage(try_body, cc)
                || catches
                    .iter()
                    .any(|catch| body_writes_abi_return_storage(&catch.body, cc))
        }
        _ => false,
    })
}

fn materialize_direct_output_with_live_in(function: &mut Function, live_in_result: Option<&VReg>) {
    if let Some(return_register) = find_written_return_reg(&function.body) {
        apply_default_return(&mut function.body, &return_register);
    } else if let Some(return_register) = live_in_result.filter(|value| is_return_reg(value)) {
        apply_default_return(&mut function.body, return_register);
    }
}

/// Remove machine output operands once prototype recovery has established that
/// the source function is `void`.
pub(crate) fn clear_return_values(function: &mut Function) {
    clear_body_return_values(&mut function.body);
}

fn clear_body_return_values(body: &mut [Stmt]) {
    for statement in body {
        match statement {
            Stmt::Return { value } => *value = None,
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                clear_body_return_values(then_body);
                if let Some(else_body) = else_body {
                    clear_body_return_values(else_body);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => clear_body_return_values(body),
            Stmt::For { body, .. } => clear_body_return_values(body),
            Stmt::Switch { cases, default, .. } => {
                for (_, body) in cases {
                    clear_body_return_values(body);
                }
                if let Some(body) = default {
                    clear_body_return_values(body);
                }
            }
            Stmt::TryCatch { try_body, catches } => {
                clear_body_return_values(try_body);
                for catch in catches {
                    clear_body_return_values(&mut catch.body);
                }
            }
            _ => {}
        }
    }
}

fn find_written_return_reg(body: &[Stmt]) -> Option<VReg> {
    for statement in body {
        let found = match statement {
            Stmt::Assign { dst, .. }
                if is_return_reg(dst) || matches!(dst, VReg::Phys(name) if name == "ret") =>
            {
                Some(dst.clone())
            }
            Stmt::Call { dst: Some(dst), .. }
                if is_return_reg(dst) || matches!(dst, VReg::Phys(name) if name == "ret") =>
            {
                Some(dst.clone())
            }
            Stmt::If {
                then_body,
                else_body,
                ..
            } => find_written_return_reg(then_body)
                .or_else(|| else_body.as_deref().and_then(find_written_return_reg)),
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => find_written_return_reg(body),
            Stmt::For { body, .. } => find_written_return_reg(body),
            Stmt::Switch { cases, default, .. } => cases
                .iter()
                .find_map(|(_, body)| find_written_return_reg(body))
                .or_else(|| default.as_deref().and_then(find_written_return_reg)),
            _ => None,
        };
        if found.is_some() {
            return found;
        }
    }
    None
}

fn apply_default_return(body: &mut [Stmt], return_register: &VReg) {
    for statement in body {
        match statement {
            Stmt::Return { value } if value.is_none() => {
                *value = Some(Expr::Reg(return_register.clone()));
            }
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                apply_default_return(then_body, return_register);
                if let Some(else_body) = else_body {
                    apply_default_return(else_body, return_register);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
                apply_default_return(body, return_register)
            }
            Stmt::For { body, .. } => apply_default_return(body, return_register),
            Stmt::Switch { cases, default, .. } => {
                for (_, body) in cases {
                    apply_default_return(body, return_register);
                }
                if let Some(body) = default {
                    apply_default_return(body, return_register);
                }
            }
            _ => {}
        }
    }
}

const RETURN_REGS: &[&str] = &[
    "rax", "eax", "ax", "al", // x86 / x86-64
    "x0", "w0", // AArch64
    "r0", // ARM32 AAPCS
    "s0", "d0",  // ARM32 AAPCS hard-float
    "ret", // canonical role name after apply_role_names
];

pub(crate) fn is_return_reg(value: &VReg) -> bool {
    matches!(value, VReg::Phys(name) if RETURN_REGS.iter().any(|register| name == *register))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::types_recover::TypeHint;

    fn bare_return_function() -> Function {
        Function {
            name: "identity".into(),
            entry_va: 0,
            body: vec![Stmt::Return { value: None }],
        }
    }

    fn int32() -> TypeHint {
        TypeHint::Int {
            signed: false,
            width: 4,
        }
    }

    #[test]
    fn locked_aarch64_identity_materializes_the_live_in_result() {
        let mut prototype = RecoveredPrototype::default();
        prototype.apply_locked_parameters(CallConv::Aarch64, &[Some(int32())]);
        prototype.apply_locked_output(RecoveredOutputKind::Direct, Some(int32()));
        let mut function = bare_return_function();

        materialize_prototype_output(&mut function, CallConv::Aarch64, Some(&prototype));

        assert_eq!(
            function.body,
            vec![Stmt::Return {
                value: Some(Expr::Reg(VReg::phys("x0"))),
            }]
        );
    }

    #[test]
    fn identity_fallback_requires_locked_output_and_aliased_parameter_storage() {
        let mut function = bare_return_function();
        materialize_direct_output(&mut function);
        assert_eq!(function, bare_return_function());

        let mut prototype = RecoveredPrototype::default();
        prototype.apply_locked_parameters(CallConv::SysVAmd64, &[Some(int32())]);
        prototype.apply_locked_output(RecoveredOutputKind::Direct, Some(int32()));
        materialize_prototype_output(&mut function, CallConv::SysVAmd64, Some(&prototype));
        assert_eq!(
            function,
            bare_return_function(),
            "SysV arg0 is rdi and cannot be invented as the rax result"
        );

        let mut aarch64 = RecoveredPrototype::default();
        aarch64.apply_locked_parameters(CallConv::Aarch64, &[Some(int32())]);
        aarch64.apply_locked_output(RecoveredOutputKind::Direct, Some(int32()));
        let mut written_version = Function {
            name: "written_result".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: VReg::phys("x0#1"),
                    src: Expr::Const(42),
                },
                Stmt::Return { value: None },
            ],
        };
        materialize_prototype_output(&mut written_version, CallConv::Aarch64, Some(&aarch64));
        assert_eq!(
            written_version.body.last(),
            Some(&Stmt::Return { value: None }),
            "a versioned output write must block the live-in fallback rather than return stale arg0"
        );
    }
}
