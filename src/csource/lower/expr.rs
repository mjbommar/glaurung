//! Expression lowering, on an explicit job stack.
//!
//! The stack is not a style choice. `roadmap.md` section 0 records the incident
//! it exists to prevent: a recursive scan in the sibling workspace overflowed
//! the process stack, so no per-function result could be reported and the
//! harness read the exit as a crash. Decompiler C --- nested casts,
//! parenthesised spines, long `||` chains --- is adversarial in exactly that
//! way.
//!
//! # Evaluation order
//!
//! Operands are evaluated strictly left to right. C does not require that, and
//! a compiler is free to choose another order for an expression with two
//! side-effecting operands. Where the fixture corpus contains such an
//! expression the differential can legitimately disagree with the binary, and
//! that disagreement is a property of the C standard, not a lowering defect ---
//! it must be read as such rather than fixed.

use crate::csource::lex::TokenKind;
use crate::csource::parse::tag::NodeTag;
use crate::ir::types::{BinOp, CmpOp, Op, UnOp, VReg, Value, Width};
use crate::syntax::ids::NodeId;

use super::build::BlockRef;
use super::ctype::{CType, IntType};
use super::func::{Local, Lowerer};
use super::literal::parse_literal;
use super::{unsupported, LowerError};

/// A lowered value: the temporary holding it, in the canonical 64-bit form for
/// its type (see the module docs of [`super`]), and the type itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Val {
    /// The register holding the canonical value.
    pub reg: VReg,
    /// The C type of the expression.
    pub ty: IntType,
}

/// One step of the expression walk.
enum Job {
    /// Lower the expression rooted at this node.
    Eval(NodeId),
    /// Apply a binary operator to the top two values.
    Bin { node: NodeId, op: TokenKind },
    /// Apply a prefix operator to the top value.
    Unary { node: NodeId, op: TokenKind },
    /// Convert the top value to a type (a cast).
    Convert { ty: IntType },
    /// Pop and discard the top value (a comma operator's left operand).
    Discard,
    /// Store the top value into a local; the assignment's value replaces it.
    Store { var: Local },
    /// Apply a compound assignment to a local using the top value.
    Compound {
        var: Local,
        op: TokenKind,
        node: NodeId,
    },
    /// One short-circuit test: continue into a fresh block or jump to `end`.
    Test { end: BlockRef, is_and: bool },
    /// Every short-circuit test passed: write the final result and join.
    TestEnd {
        end: BlockRef,
        result: VReg,
        value: i64,
    },
    /// The condition of a `?:` is on the stack; open the arms.
    CondSetup { then_n: NodeId, else_n: NodeId },
    /// The then-arm is on the stack; write it and switch to the else-arm.
    CondThen {
        result: VReg,
        else_b: BlockRef,
        join: BlockRef,
    },
    /// The else-arm is on the stack; write it, join, and convert.
    CondJoin { result: VReg, join: BlockRef },
}

/// Lower one expression, leaving its value in a temporary.
pub fn lower_expr(low: &mut Lowerer<'_, '_>, node: NodeId) -> Result<Val, LowerError> {
    let mut jobs: Vec<Job> = vec![Job::Eval(node)];
    let mut values: Vec<Val> = Vec::new();
    // The then-arm types of `?:` expressions still in flight. A job cannot
    // carry it, because the job that learns it is created before the job that
    // needs it.
    let mut arm_types: Vec<IntType> = Vec::new();
    // Every iteration pops one job; a job may push more, but only for nodes
    // strictly inside the one it was created for, so the walk terminates on the
    // finite tree. The counter is the belt to that braces: a tree the arena
    // built cyclic would otherwise spin here forever.
    let mut fuel = 1_000_000u32;

    while let Some(job) = jobs.pop() {
        fuel = fuel.checked_sub(1).ok_or_else(|| {
            LowerError::new("expression too large to lower", low.ctx.offset_of(node))
        })?;
        match job {
            Job::Eval(n) => eval(low, n, &mut jobs, &mut values)?,
            Job::Bin { node, op } => {
                let rhs = pop(&mut values, node, low)?;
                let lhs = pop(&mut values, node, low)?;
                let out = binary(low, node, op, lhs, rhs)?;
                values.push(out);
            }
            Job::Unary { node, op } => {
                let v = pop(&mut values, node, low)?;
                let out = unary(low, node, op, v)?;
                values.push(out);
            }
            Job::Convert { ty } => {
                let v = pop(&mut values, node, low)?;
                values.push(convert(low, &v, ty));
            }
            Job::Discard => {
                pop(&mut values, node, low)?;
            }
            Job::Store { var } => {
                let v = pop(&mut values, node, low)?;
                let stored = convert(low, &v, var.ty);
                low.b
                    .store_abs(var.addr, var.ty.width.bytes().max(1) as u8, &stored.reg);
                values.push(stored);
            }
            Job::Compound { var, op, node } => {
                let rhs = pop(&mut values, node, low)?;
                let lhs = load_local(low, var);
                let combined = binary(low, node, op, lhs, rhs)?;
                let stored = convert(low, &combined, var.ty);
                low.b
                    .store_abs(var.addr, var.ty.width.bytes().max(1) as u8, &stored.reg);
                values.push(stored);
            }
            Job::Test { end, is_and } => {
                let v = pop(&mut values, node, low)?;
                let truth = low.b.truth(&v.reg);
                let next = low.b.new_block();
                if is_and {
                    low.b.branch(&truth, next, end);
                } else {
                    low.b.branch(&truth, end, next);
                }
                low.b.switch_to(next);
            }
            Job::TestEnd { end, result, value } => {
                low.b.assign_const(&result, value);
                low.b.jump(end);
                low.b.switch_to(end);
                values.push(Val {
                    reg: result,
                    ty: IntType::INT,
                });
            }
            Job::CondSetup { then_n, else_n } => {
                let cond = pop(&mut values, node, low)?;
                let truth = low.b.truth(&cond.reg);
                let then_b = low.b.new_block();
                let else_b = low.b.new_block();
                let join = low.b.new_block();
                let result = low.b.temp();
                low.b.branch(&truth, then_b, else_b);
                low.b.switch_to(then_b);
                jobs.push(Job::CondJoin {
                    result: result.clone(),
                    join,
                });
                jobs.push(Job::Eval(else_n));
                jobs.push(Job::CondThen {
                    result,
                    else_b,
                    join,
                });
                jobs.push(Job::Eval(then_n));
            }
            Job::CondThen {
                result,
                else_b,
                join,
            } => {
                let v = pop(&mut values, node, low)?;
                low.b.assign(&result, &v.reg);
                low.b.jump(join);
                low.b.switch_to(else_b);
                arm_types.push(v.ty);
            }
            Job::CondJoin { result, join } => {
                let v = pop(&mut values, node, low)?;
                low.b.assign(&result, &v.reg);
                low.b.jump(join);
                low.b.switch_to(join);
                let then_ty = arm_types.pop().unwrap_or(v.ty);
                let common = then_ty.common(v.ty);
                // Both arms wrote `result` in their own canonical form.
                // Converting once here is sound precisely because the
                // conversion depends only on the destination type.
                values.push(convert(
                    low,
                    &Val {
                        reg: result,
                        ty: common,
                    },
                    common,
                ));
            }
        }
    }

    values
        .pop()
        .ok_or_else(|| LowerError::new("expression produced no value", low.ctx.offset_of(node)))
}

fn pop(values: &mut Vec<Val>, node: NodeId, low: &Lowerer<'_, '_>) -> Result<Val, LowerError> {
    values
        .pop()
        .ok_or_else(|| LowerError::new("malformed expression", low.ctx.offset_of(node)))
}

/// Dispatch on a node's tag, pushing the jobs its operands need.
fn eval(
    low: &mut Lowerer<'_, '_>,
    node: NodeId,
    jobs: &mut Vec<Job>,
    values: &mut Vec<Val>,
) -> Result<(), LowerError> {
    let ctx = low.ctx;
    let Some(tag) = ctx.tag(node) else {
        return unsupported("node with no C tag", node, ctx);
    };
    match tag {
        NodeTag::Literal => {
            let v = literal(low, node)?;
            values.push(v);
            Ok(())
        }
        NodeTag::NameRef => {
            let name = ctx.text_of(node);
            let Some(var) = low.lookup(name) else {
                return Err(LowerError::new(
                    format!("reference to non-local `{name}`"),
                    ctx.offset_of(node),
                ));
            };
            values.push(load_local(low, var));
            Ok(())
        }
        NodeTag::ParenExpr => match ctx.children(node).first().copied() {
            Some(inner) => {
                jobs.push(Job::Eval(inner));
                Ok(())
            }
            None => unsupported("empty parenthesised expression", node, ctx),
        },
        NodeTag::CastExpr => cast(low, node, jobs),
        NodeTag::UnaryExpr => prefix(low, node, jobs, values),
        NodeTag::PostfixExpr => postfix(low, node, jobs, values),
        NodeTag::BinaryExpr => binary_node(low, node, jobs),
        NodeTag::CondExpr => {
            let kids = ctx.children(node);
            let [cond, then_n, else_n] = kids[..] else {
                return unsupported("conditional operator with missing arm", node, ctx);
            };
            jobs.push(Job::CondSetup { then_n, else_n });
            jobs.push(Job::Eval(cond));
            Ok(())
        }
        NodeTag::CommaExpr => {
            let kids = ctx.children(node);
            if kids.is_empty() {
                return unsupported("empty comma expression", node, ctx);
            }
            for (index, child) in kids.iter().copied().enumerate().rev() {
                if index + 1 < kids.len() {
                    jobs.push(Job::Discard);
                }
                jobs.push(Job::Eval(child));
            }
            Ok(())
        }
        NodeTag::AssignExpr => assign_node(low, node, jobs),
        NodeTag::SizeofType | NodeTag::AlignofType => {
            unsupported("sizeof/_Alignof of a type", node, ctx)
        }
        NodeTag::StmtExpr => unsupported("statement expression", node, ctx),
        NodeTag::CompoundLiteral => unsupported("compound literal", node, ctx),
        NodeTag::BuiltinExpr => unsupported("compiler builtin expression", node, ctx),
        NodeTag::LabelAddr => unsupported("label address (computed goto)", node, ctx),
        NodeTag::Error => unsupported("unparsed construct", node, ctx),
        other => Err(LowerError::new(
            format!("{} in expression position", other.name()),
            ctx.offset_of(node),
        )),
    }
}

/// `(T) e`.
fn cast(low: &mut Lowerer<'_, '_>, node: NodeId, jobs: &mut Vec<Job>) -> Result<(), LowerError> {
    let ctx = low.ctx;
    let kids = ctx.children(node);
    let type_name = kids
        .iter()
        .copied()
        .find(|c| ctx.tag(*c) == Some(NodeTag::TypeName));
    let operand = kids
        .iter()
        .copied()
        .find(|c| ctx.tag(*c) != Some(NodeTag::TypeName));
    let (Some(type_name), Some(operand)) = (type_name, operand) else {
        return unsupported("cast with no operand", node, ctx);
    };
    let Some((first, end)) = ctx.extent(type_name) else {
        return unsupported("cast to an empty type", node, ctx);
    };
    // The `TypeName` run is `( ... )`; a `*` or `[` in it makes it a pointer.
    let inner: Vec<u32> = ((first + 1)..end.saturating_sub(1)).collect();
    if inner.iter().any(|&i| {
        matches!(
            ctx.kind_at(i),
            Some(TokenKind::Star) | Some(TokenKind::LBracket)
        )
    }) {
        return unsupported("cast to a pointer type", node, ctx);
    }
    let words: Vec<&str> = inner.iter().map(|&i| ctx.text_at(i)).collect();
    let Some(ty) = super::ctype::from_specifier_tokens(words.iter().copied()) else {
        return Err(LowerError::new(
            format!("cast to `{}`", words.join(" ")),
            ctx.offset_of(type_name),
        ));
    };
    match ty {
        CType::Int(ty) => {
            jobs.push(Job::Convert { ty });
            jobs.push(Job::Eval(operand));
            Ok(())
        }
        CType::Void => {
            // `(void) e` discards; the statement lowering drops it anyway, but
            // the expression must still produce a value for the stack.
            jobs.push(Job::Convert { ty: IntType::INT });
            jobs.push(Job::Eval(operand));
            Ok(())
        }
        other => Err(LowerError::new(
            format!("cast to a {}", other.unsupported_reason().unwrap_or("type")),
            ctx.offset_of(type_name),
        )),
    }
}

/// A prefix operator, `sizeof`, or a prefix `++` / `--`.
fn prefix(
    low: &mut Lowerer<'_, '_>,
    node: NodeId,
    jobs: &mut Vec<Job>,
    values: &mut Vec<Val>,
) -> Result<(), LowerError> {
    let ctx = low.ctx;
    let Some(op_tok) = ctx.main_token(node) else {
        return unsupported("prefix expression with no operator", node, ctx);
    };
    let Some(op) = ctx.kind_at(op_tok.raw()) else {
        return unsupported("prefix expression with no operator", node, ctx);
    };
    let Some(operand) = ctx.children(node).first().copied() else {
        return unsupported("prefix operator with no operand", node, ctx);
    };
    match op {
        TokenKind::PlusPlus | TokenKind::MinusMinus => {
            let var = lvalue(low, operand)?;
            let (_, new) = step_local(low, var, op == TokenKind::PlusPlus)?;
            values.push(new);
            Ok(())
        }
        TokenKind::Amp => unsupported("address-of operator", node, ctx),
        TokenKind::Star => unsupported("pointer dereference", node, ctx),
        TokenKind::KwSizeof => unsupported("sizeof of an expression", node, ctx),
        TokenKind::KwReal | TokenKind::KwImag => unsupported("complex-number operator", node, ctx),
        TokenKind::Plus | TokenKind::Minus | TokenKind::Tilde | TokenKind::Bang => {
            jobs.push(Job::Unary { node, op });
            jobs.push(Job::Eval(operand));
            Ok(())
        }
        other => Err(LowerError::new(
            format!("prefix operator `{}`", other.name()),
            ctx.offset_of(node),
        )),
    }
}

/// A postfix chain: a call, a subscript, a member access, or `++` / `--`.
fn postfix(
    low: &mut Lowerer<'_, '_>,
    node: NodeId,
    _jobs: &mut Vec<Job>,
    values: &mut Vec<Val>,
) -> Result<(), LowerError> {
    let ctx = low.ctx;
    let kids = ctx.children(node);
    let Some((&primary, suffixes)) = kids.split_first() else {
        return unsupported("empty postfix expression", node, ctx);
    };
    for suffix in suffixes {
        match ctx.tag(*suffix) {
            // A call needs the callee's body: `Machine::run_function` surfaces
            // `Op::Call` as `Outcome::CalledOut` and stops, so a lowered call
            // could not be executed even if it were emitted.
            Some(NodeTag::CallArgs) => return unsupported("call expression", node, ctx),
            Some(NodeTag::IndexSuffix) => return unsupported("array subscript", node, ctx),
            Some(NodeTag::MemberSuffix) => return unsupported("struct member access", node, ctx),
            Some(NodeTag::IncDecSuffix) => {}
            _ => return unsupported("postfix suffix", node, ctx),
        }
    }
    if suffixes.len() != 1 {
        return unsupported("chained postfix increment", node, ctx);
    }
    let var = lvalue(low, primary)?;
    let increment = ctx.text_of(suffixes[0]).starts_with("++");
    let (old, _) = step_local(low, var, increment)?;
    values.push(old);
    Ok(())
}

/// A flat binary node: `n` operands with `n - 1` operators of one precedence
/// level between them, left-associative.
fn binary_node(
    low: &mut Lowerer<'_, '_>,
    node: NodeId,
    jobs: &mut Vec<Job>,
) -> Result<(), LowerError> {
    let ctx = low.ctx;
    let kids = ctx.children(node);
    if kids.len() < 2 {
        return unsupported("binary expression with one operand", node, ctx);
    }
    let mut ops = Vec::with_capacity(kids.len() - 1);
    for window in kids.windows(2) {
        let (_, end) = ctx
            .extent(window[0])
            .ok_or_else(|| LowerError::new("operand with no tokens", ctx.offset_of(node)))?;
        let Some(kind) = ctx.kind_at(end) else {
            return unsupported("binary operator not found between operands", node, ctx);
        };
        ops.push(kind);
    }

    if matches!(ops[0], TokenKind::AmpAmp | TokenKind::PipePipe) {
        let is_and = ops[0] == TokenKind::AmpAmp;
        let end = low.b.new_block();
        let result = low.b.temp();
        // `&&` starts false and becomes true only if every test passes; `||`
        // starts true and becomes false only if every test fails.
        low.b.assign_const(&result, i64::from(!is_and));
        jobs.push(Job::TestEnd {
            end,
            result,
            value: i64::from(is_and),
        });
        for child in kids.iter().copied().rev() {
            jobs.push(Job::Test { end, is_and });
            jobs.push(Job::Eval(child));
        }
        return Ok(());
    }

    // Left-associative fold: push in reverse of execution order.
    for (index, child) in kids.iter().copied().enumerate().rev() {
        if index > 0 {
            jobs.push(Job::Bin {
                node,
                op: ops[index - 1],
            });
        }
        jobs.push(Job::Eval(child));
    }
    Ok(())
}

/// A flat assignment chain, `a = b = c`, right-associative.
fn assign_node(
    low: &mut Lowerer<'_, '_>,
    node: NodeId,
    jobs: &mut Vec<Job>,
) -> Result<(), LowerError> {
    let ctx = low.ctx;
    let kids = ctx.children(node);
    if kids.len() < 2 {
        return unsupported("assignment with one operand", node, ctx);
    }
    let mut ops = Vec::with_capacity(kids.len() - 1);
    for window in kids.windows(2) {
        let (_, end) = ctx
            .extent(window[0])
            .ok_or_else(|| LowerError::new("operand with no tokens", ctx.offset_of(node)))?;
        let Some(kind) = ctx.kind_at(end) else {
            return unsupported("assignment operator not found", node, ctx);
        };
        ops.push(kind);
    }
    // The last child is the value; every earlier child is a target, applied
    // right to left.
    for (index, op) in ops.iter().copied().enumerate() {
        let var = lvalue(low, kids[index])?;
        let job = if op == TokenKind::Eq {
            Job::Store { var }
        } else {
            Job::Compound {
                var,
                op: compound_base(op).ok_or_else(|| {
                    LowerError::new(
                        format!("assignment operator `{}`", op.name()),
                        ctx.offset_of(node),
                    )
                })?,
                node,
            }
        };
        jobs.push(job);
    }
    jobs.push(Job::Eval(kids[kids.len() - 1]));
    Ok(())
}

/// The arithmetic operator inside a compound assignment.
fn compound_base(op: TokenKind) -> Option<TokenKind> {
    Some(match op {
        TokenKind::PlusEq => TokenKind::Plus,
        TokenKind::MinusEq => TokenKind::Minus,
        TokenKind::StarEq => TokenKind::Star,
        TokenKind::SlashEq => TokenKind::Slash,
        TokenKind::PercentEq => TokenKind::Percent,
        TokenKind::ShlEq => TokenKind::Shl,
        TokenKind::ShrEq => TokenKind::Shr,
        TokenKind::AmpEq => TokenKind::Amp,
        TokenKind::CaretEq => TokenKind::Caret,
        TokenKind::PipeEq => TokenKind::Pipe,
        _ => return None,
    })
}

/// Resolve an assignable expression to the local it names.
pub(crate) fn lvalue(low: &Lowerer<'_, '_>, node: NodeId) -> Result<Local, LowerError> {
    let ctx = low.ctx;
    let mut current = node;
    // Unwrap parentheses without recursion; the depth is bounded by the tree.
    for _ in 0..1024 {
        match ctx.tag(current) {
            Some(NodeTag::ParenExpr) => match ctx.children(current).first().copied() {
                Some(inner) => current = inner,
                None => return unsupported("empty parenthesised lvalue", node, ctx),
            },
            Some(NodeTag::NameRef) => {
                let name = ctx.text_of(current);
                return low.lookup(name).ok_or_else(|| {
                    LowerError::new(
                        format!("assignment to non-local `{name}`"),
                        ctx.offset_of(node),
                    )
                });
            }
            _ => return unsupported("assignment to a non-variable lvalue", node, ctx),
        }
    }
    unsupported("parenthesis nesting beyond the lowering's bound", node, ctx)
}

/// `++x` / `x++` on a local: returns `(old value, new value)`.
fn step_local(
    low: &mut Lowerer<'_, '_>,
    var: Local,
    increment: bool,
) -> Result<(Val, Val), LowerError> {
    let old = load_local(low, var);
    let one = low.b.temp();
    low.b.assign_const(&one, 1);
    let raw = low.b.temp();
    low.b.binop(
        &raw,
        if increment { BinOp::Add } else { BinOp::Sub },
        &old.reg,
        &one,
    );
    let new = canonicalize(low, &raw, var.ty);
    low.b
        .store_abs(var.addr, var.ty.width.bytes().max(1) as u8, &new);
    Ok((
        old,
        Val {
            reg: new,
            ty: var.ty,
        },
    ))
}

/// Read a local into a canonical temporary.
pub(crate) fn load_local(low: &mut Lowerer<'_, '_>, var: Local) -> Val {
    let raw = low.b.temp();
    low.b
        .load_abs(&raw, var.addr, var.ty.width.bytes().max(1) as u8);
    let out = low.b.temp();
    low.b.normalize(&out, &raw, var.ty.width, var.ty.signed);
    Val {
        reg: out,
        ty: var.ty,
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

/// A prefix operator applied to a lowered value.
fn unary(
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
            Ok(Val { reg: out, ty })
        }
        other => Err(LowerError::new(
            format!("prefix operator `{}`", other.name()),
            low.ctx.offset_of(node),
        )),
    }
}

/// A binary operator applied to two lowered values.
fn binary(
    low: &mut Lowerer<'_, '_>,
    node: NodeId,
    op: TokenKind,
    lhs: Val,
    rhs: Val,
) -> Result<Val, LowerError> {
    use TokenKind::*;
    // Shifts do not take the usual arithmetic conversions: the result type is
    // the promoted *left* operand and the right operand promotes on its own.
    if matches!(op, Shl | Shr) {
        let ty = lhs.ty.promote();
        let a = convert(low, &lhs, ty);
        let count = convert(low, &rhs, rhs.ty.promote());
        let raw = low.b.temp();
        let kind = match (op, ty.signed) {
            (Shl, _) => BinOp::Shl,
            (_, true) => BinOp::Sar,
            (_, false) => BinOp::Shr,
        };
        low.b.binop(&raw, kind, &a.reg, &count.reg);
        let out = low.b.temp();
        low.b.normalize(&out, &raw, ty.width, ty.signed);
        return Ok(Val { reg: out, ty });
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
    Ok(Val { reg: out, ty })
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

/// An integer or character constant, with its C type.
fn literal(low: &mut Lowerer<'_, '_>, node: NodeId) -> Result<Val, LowerError> {
    let ctx = low.ctx;
    let text = ctx.text_of(node);
    let (bits, ty) = parse_literal(text)
        .ok_or_else(|| LowerError::new(format!("literal `{text}`"), ctx.offset_of(node)))?;
    let out = low.b.temp();
    low.b.assign_const(&out, bits);
    Ok(Val { reg: out, ty })
}
