//! Prepared-AST compatibility adapter for the common memory-object model.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use crate::ir::ast::{Expr, Function, Stmt};
use crate::ir::memory_objects::{
    AccessPath, AccessRole, AccessSource, LayoutConflict, MemoryObject, MemoryObjectModel,
    ObjectId, ObjectOrigin,
};
use crate::ir::types::{is_promoted_local_reg, BinOp, VReg};

#[derive(Debug, Clone)]
struct RawAccess {
    base: VReg,
    offset: i64,
    width: u8,
    role: AccessRole,
    source: AccessSource,
}

#[derive(Debug, Default)]
struct Observations {
    accesses: Vec<RawAccess>,
    strides: HashMap<VReg, Vec<i64>>,
    origins: HashMap<VReg, Vec<ObjectOrigin>>,
    unclassified_definitions: HashSet<VReg>,
    non_address_uses: HashSet<VReg>,
    next_statement: u32,
}

/// Infer object/access constraints from the prepared structured AST.
pub(crate) fn infer_from_ast(function: &Function) -> MemoryObjectModel {
    let mut observations = Observations::default();
    observe_body(&function.body, &mut observations);

    let mut grouped: BTreeMap<VReg, Vec<RawAccess>> = BTreeMap::new();
    for access in observations.accesses {
        grouped.entry(access.base.clone()).or_default().push(access);
    }

    let mut objects = Vec::with_capacity(grouped.len());
    let mut by_base = BTreeMap::new();
    for (base, accesses) in grouped {
        let id = ObjectId(objects.len() as u32);
        let mut conflicts = BTreeSet::new();
        let origins = observations.origins.remove(&base).unwrap_or_default();
        if origins.is_empty() {
            conflicts.insert(LayoutConflict::MissingOrigin);
        } else if !origins_compatible(&origins) {
            conflicts.insert(LayoutConflict::ConflictingOrigins);
        }
        if accesses.iter().any(|access| access.width == 0) {
            conflicts.insert(LayoutConflict::ZeroWidthAccess);
        }
        if observations.unclassified_definitions.contains(&base) {
            conflicts.insert(LayoutConflict::UnclassifiedDefinition);
        }

        let observed_strides = observations.strides.remove(&base).unwrap_or_default();
        let stride_set = observed_strides
            .into_iter()
            .filter_map(i64::checked_abs)
            .filter_map(|stride| u64::try_from(stride).ok())
            .filter(|stride| *stride != 0)
            .collect::<BTreeSet<_>>();
        let stride = match stride_set.len() {
            0 => {
                conflicts.insert(LayoutConflict::MissingStride);
                None
            }
            1 => stride_set.first().copied(),
            _ => {
                conflicts.insert(LayoutConflict::ConflictingStrides);
                None
            }
        };
        if observations.non_address_uses.contains(&base) {
            conflicts.insert(LayoutConflict::NonAddressUse);
        }

        let mut access_paths = accesses
            .into_iter()
            .map(|access| AccessPath {
                object: id,
                offset: access.offset,
                width: access.width,
                alignment: inferred_alignment(access.offset, access.width),
                role: access.role,
                source: access.source,
                memory_version: None,
            })
            .collect::<Vec<_>>();
        access_paths
            .sort_by_key(|access| (access.offset, access.width, access.role, access.source));
        access_paths.dedup_by(|left, right| {
            left.offset == right.offset
                && left.width == right.width
                && left.role == right.role
                && left.source == right.source
        });

        let extent = stride.and_then(|stride| {
            if access_paths.iter().any(|access| access.offset < 0) {
                conflicts.insert(LayoutConflict::NegativeOffset);
                return None;
            }
            let fits = access_paths.iter().all(|access| {
                u64::try_from(access.offset)
                    .ok()
                    .and_then(|offset| offset.checked_add(u64::from(access.width)))
                    .is_some_and(|end| end <= stride)
            });
            if !fits {
                conflicts.insert(LayoutConflict::AccessPastStride);
                return None;
            }
            Some(stride)
        });

        by_base.insert(base.clone(), id);
        objects.push(MemoryObject {
            id,
            base,
            origins,
            accesses: access_paths,
            stride,
            extent,
            conflicts,
        });
    }
    MemoryObjectModel { objects, by_base }
}

fn origins_compatible(origins: &[ObjectOrigin]) -> bool {
    let non_null = origins
        .iter()
        .filter(|origin| !matches!(origin, ObjectOrigin::Null))
        .collect::<Vec<_>>();
    let Some(first) = non_null.first() else {
        return false;
    };
    non_null.iter().all(|origin| *origin == *first)
}

fn inferred_alignment(offset: i64, width: u8) -> u8 {
    let width = width.max(1);
    let offset = offset.unsigned_abs();
    let mut alignment = 1;
    while alignment < width
        && alignment <= u8::MAX / 2
        && offset.is_multiple_of(u64::from(alignment.saturating_mul(2)))
    {
        alignment = alignment.saturating_mul(2);
    }
    alignment.min(width)
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
                        .origins
                        .entry(dst.clone())
                        .or_default()
                        .push(ObjectOrigin::CallResult(source));
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
                    .strides
                    .entry(dst.clone())
                    .or_default()
                    .push(displacement);
            }
        } else {
            observations
                .origins
                .entry(dst.clone())
                .or_default()
                .push(ObjectOrigin::Copy {
                    base,
                    offset: displacement,
                });
        }
    } else if let Some(origin) = object_origin(src, source) {
        observations
            .origins
            .entry(dst.clone())
            .or_default()
            .push(origin);
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
        Expr::Un { src, .. } | Expr::Cast { expr: src, .. } => {
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
    observations.accesses.push(RawAccess {
        base,
        offset,
        width,
        role,
        source,
    });
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
