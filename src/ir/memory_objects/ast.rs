//! Prepared-AST compatibility adapter for the common memory-object model.

use std::collections::HashSet;

use crate::ir::ast::{Expr, Function, Stmt};
use crate::ir::memory_objects::{
    AccessRole, AccessSource, LayoutConflict, MemoryObjectBuilder, MemoryObjectModel, ObjectOrigin,
    RawAccess,
};
use crate::ir::types::{is_promoted_local_reg, BinOp, VReg};

#[derive(Debug, Default)]
struct Observations {
    objects: MemoryObjectBuilder,
    unclassified_definitions: HashSet<VReg>,
    non_address_uses: HashSet<VReg>,
    next_statement: u32,
}

/// Infer object/access constraints from the prepared structured AST.
pub(crate) fn infer_from_ast(function: &Function) -> MemoryObjectModel {
    let mut observations = Observations::default();
    observe_body(&function.body, &mut observations);
    for base in observations.unclassified_definitions {
        observations
            .objects
            .conflict(base, LayoutConflict::UnclassifiedDefinition);
    }
    for base in observations.non_address_uses {
        observations
            .objects
            .conflict(base, LayoutConflict::NonAddressUse);
    }
    observations.objects.finish()
}

fn observe_body(body: &[Stmt], observations: &mut Observations) {
    for statement in body {
        let source = AccessSource::AstStatement(observations.next_statement);
        observations.next_statement = observations.next_statement.saturating_add(1);
        match statement {
            Stmt::Assign { dst, src } => {
                observe_definition(dst, src, source, observations);
                observe_expr(src, ExprContext::Value, source, observations);
            }
            Stmt::Store { addr, src, size } => {
                // Stack promotion retains source locals as stores to their
                // semantic identity. The renderer emits these as assignments;
                // treating them as `*local = value` here creates a fake object
                // access and loses the cursor's origin/stride definitions.
                if let Expr::Reg(dst) = addr {
                    if is_promoted_local_reg(dst) {
                        observe_definition(dst, src, source, observations);
                        observe_expr(src, ExprContext::Value, source, observations);
                        continue;
                    }
                }
                record_access(addr, *size, AccessRole::Write, source, observations);
                observe_expr(addr, ExprContext::Address, source, observations);
                observe_expr(src, ExprContext::Escape, source, observations);
            }
            Stmt::Call {
                target, args, dst, ..
            } => {
                observe_expr(target, ExprContext::CallTarget, source, observations);
                for argument in args {
                    observe_expr(argument, ExprContext::Escape, source, observations);
                }
                if let Some(dst) = dst {
                    observations
                        .objects
                        .observe_origin(dst.clone(), ObjectOrigin::CallResult(source));
                }
            }
            Stmt::Return { value } => {
                if let Some(value) = value {
                    observe_expr(value, ExprContext::Escape, source, observations);
                }
            }
            Stmt::Throw { value } | Stmt::Push { value } => {
                observe_expr(value, ExprContext::Escape, source, observations)
            }
            Stmt::IndirectGoto { target } => {
                observe_expr(target, ExprContext::Integer, source, observations)
            }
            Stmt::If {
                cond,
                then_body,
                else_body,
            } => {
                observe_expr(cond, ExprContext::Comparison, source, observations);
                observe_body(then_body, observations);
                if let Some(else_body) = else_body {
                    observe_body(else_body, observations);
                }
            }
            Stmt::While { cond, body } | Stmt::DoWhile { body, cond } => {
                observe_expr(cond, ExprContext::Comparison, source, observations);
                observe_body(body, observations);
            }
            Stmt::For {
                init,
                cond,
                step,
                body,
            } => {
                observe_body(std::slice::from_ref(init), observations);
                observe_expr(cond, ExprContext::Comparison, source, observations);
                observe_body(body, observations);
                observe_body(std::slice::from_ref(step), observations);
            }
            Stmt::Switch {
                discriminant,
                cases,
                default,
            } => {
                observe_expr(discriminant, ExprContext::Integer, source, observations);
                for (_, case) in cases {
                    observe_body(case, observations);
                }
                if let Some(default) = default {
                    observe_body(default, observations);
                }
            }
            Stmt::TryCatch { try_body, catches } => {
                observe_body(try_body, observations);
                for catch in catches {
                    observe_body(&catch.body, observations);
                }
            }
            Stmt::Label(_)
            | Stmt::Goto { .. }
            | Stmt::Break
            | Stmt::Nop
            | Stmt::Unknown(_)
            | Stmt::Comment(_)
            | Stmt::Pop { .. } => {}
        }
    }
}

fn observe_definition(
    dst: &VReg,
    src: &Expr,
    source: AccessSource,
    observations: &mut Observations,
) {
    if let Some((base, displacement)) = affine_address(src) {
        if &base == dst {
            if displacement != 0 {
                observations
                    .objects
                    .observe_stride(dst.clone(), displacement);
            }
        } else {
            observations.objects.observe_origin(
                dst.clone(),
                ObjectOrigin::Copy {
                    base,
                    offset: displacement,
                },
            );
        }
    } else if let Some(origin) = object_origin(src, source) {
        observations.objects.observe_origin(dst.clone(), origin);
    } else {
        observations.unclassified_definitions.insert(dst.clone());
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExprContext {
    Address,
    Comparison,
    Escape,
    CallTarget,
    Value,
    Integer,
}

fn observe_expr(
    expression: &Expr,
    context: ExprContext,
    source: AccessSource,
    observations: &mut Observations,
) {
    match expression {
        Expr::Reg(register) => {
            if matches!(context, ExprContext::Integer) {
                observations.non_address_uses.insert(register.clone());
            }
        }
        Expr::Deref { addr, size } => {
            record_access(addr, *size, AccessRole::Read, source, observations);
            observe_expr(addr, ExprContext::Address, source, observations);
        }
        Expr::Bin { op, lhs, rhs } => {
            let affine =
                matches!(op, BinOp::Add | BinOp::Sub) && affine_address(expression).is_some();
            if affine && !matches!(context, ExprContext::Integer) {
                observe_expr(lhs, ExprContext::Address, source, observations);
                observe_expr(rhs, ExprContext::Value, source, observations);
            } else {
                observe_expr(lhs, ExprContext::Integer, source, observations);
                observe_expr(rhs, ExprContext::Integer, source, observations);
            }
        }
        Expr::Cmp { lhs, rhs, .. } => {
            observe_expr(lhs, ExprContext::Comparison, source, observations);
            observe_expr(rhs, ExprContext::Comparison, source, observations);
        }
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => {
            observe_expr(cond, ExprContext::Comparison, source, observations);
            observe_expr(if_true, context, source, observations);
            observe_expr(if_false, context, source, observations);
        }
        Expr::Call { target, args, .. } => {
            observe_expr(target, ExprContext::CallTarget, source, observations);
            for argument in args {
                observe_expr(argument, ExprContext::Escape, source, observations);
            }
        }
        Expr::Un { src, .. }
        | Expr::Cast { expr: src, .. }
        | Expr::NumericConvert { expr: src, .. } => {
            observe_expr(src, ExprContext::Integer, source, observations)
        }
        Expr::FunctionTableEntry { index, .. } => {
            observe_expr(index, ExprContext::Integer, source, observations)
        }
        Expr::WideArithmetic { args, .. } => {
            for argument in args {
                observe_expr(argument, ExprContext::Integer, source, observations);
            }
        }
        Expr::Lea { base, index, .. } | Expr::PdbFieldAddr { base, index, .. } => {
            if let Some(base) = base {
                if matches!(context, ExprContext::Integer) {
                    observations.non_address_uses.insert(base.clone());
                }
            }
            if let Some(index) = index {
                observations.non_address_uses.insert(index.clone());
            }
        }
        Expr::StackAddr { object, .. } => {
            if matches!(context, ExprContext::Integer) {
                observations.non_address_uses.insert(object.clone());
            }
        }
        Expr::Const(_)
        | Expr::FloatConst { .. }
        | Expr::Addr(_)
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::Unknown(_) => {}
    }
}

fn record_access(
    address: &Expr,
    width: u8,
    role: AccessRole,
    source: AccessSource,
    observations: &mut Observations,
) {
    let Some((base, offset)) = affine_address(address) else {
        return;
    };
    observations.objects.observe_access(
        base.clone(),
        RawAccess {
            cursor: base.into(),
            offset,
            width,
            role,
            source,
            memory_region: None,
            memory_state: None,
            mir_access: None,
        },
    );
}

fn affine_address(expression: &Expr) -> Option<(VReg, i64)> {
    match expression {
        Expr::Reg(register) => Some((register.clone(), 0)),
        Expr::Bin { op, lhs, rhs } => match (op, lhs.as_ref(), rhs.as_ref()) {
            (BinOp::Add, base, Expr::Const(displacement)) => {
                let (base, offset) = affine_address(base)?;
                Some((base, offset.checked_add(*displacement)?))
            }
            (BinOp::Add, Expr::Const(displacement), base) => {
                let (base, offset) = affine_address(base)?;
                Some((base, offset.checked_add(*displacement)?))
            }
            (BinOp::Sub, base, Expr::Const(displacement)) => {
                let (base, offset) = affine_address(base)?;
                Some((base, offset.checked_sub(*displacement)?))
            }
            _ => None,
        },
        Expr::Lea {
            base: Some(base),
            index: None,
            disp,
            segment: None,
            ..
        }
        | Expr::PdbFieldAddr {
            base: Some(base),
            index: None,
            disp,
            segment: None,
            ..
        } => Some((base.clone(), *disp)),
        _ => None,
    }
}

fn object_origin(expression: &Expr, source: AccessSource) -> Option<ObjectOrigin> {
    match expression {
        Expr::Deref { addr, .. } => match addr.as_ref() {
            Expr::Addr(address) | Expr::Named { va: address, .. } => {
                Some(ObjectOrigin::GlobalPointerSlot(*address))
            }
            _ => None,
        },
        Expr::Addr(address) | Expr::Named { va: address, .. } => {
            Some(ObjectOrigin::Address(*address))
        }
        Expr::StackAddr { object, .. } => Some(ObjectOrigin::StackObject(object.clone())),
        Expr::Call { .. } => Some(ObjectOrigin::CallResult(source)),
        Expr::Reg(register) => Some(ObjectOrigin::Copy {
            base: register.clone(),
            offset: 0,
        }),
        Expr::Const(0) => Some(ObjectOrigin::Null),
        _ => None,
    }
}
