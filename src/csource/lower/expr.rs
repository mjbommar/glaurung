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
//!
//! # What is *not* here
//!
//! What an operator *means* --- conversion, arithmetic, comparison,
//! dereference --- lives in [`super::value`]. This file decides which operator
//! applies to which operands and in what order; that one turns a C operator
//! into ops `src/exec` can execute. The cut is at the parse tree: nothing in
//! `value` reads it.

use crate::csource::lex::TokenKind;
use crate::csource::parse::tag::NodeTag;
use crate::ir::types::{BinOp, VReg};
use crate::syntax::ids::NodeId;

use super::build::BlockRef;
use super::ctype::{CType, IntType};
use super::func::{Local, Lowerer};
use super::literal::parse_literal;
use super::value::{binary, canonicalize, convert, deref, load_local, unary, Val};
use super::{unsupported, LowerError};

/// One step of the expression walk.
enum Job {
    /// Lower the expression rooted at this node.
    Eval(NodeId),
    /// Load through the pointer on top of the stack.
    Deref { node: NodeId },
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
            Job::Deref { node } => {
                let v = pop(&mut values, node, low)?;
                let out = deref(low, node, &v)?;
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
                    // An arithmetic or conversion result is not a pointer.
                    pointee: None,
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
                        // An arithmetic or conversion result is not a pointer.
                        pointee: None,
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
            // A name with no local binding may still be an object-like macro
            // constant: this parser has no preprocessor, so `#define N 8`
            // leaves `N` looking exactly like a global. The local is tried
            // first, which is safe -- C expands macros before scoping, so a
            // file that both defines `N` and declares a local `N` does not
            // compile.
            if low.lookup(name).is_none() {
                if let Some(value) = ctx.macro_value(name) {
                    let out = low.b.temp();
                    low.b.assign_const(&out, value as i64);
                    values.push(Val::plain(out, IntType::INT));
                    return Ok(());
                }
            }
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
        TokenKind::Amp => {
            // `&x` on a local is its frame address, which the lowering already
            // knows: `Local::addr`. Only a bare local is handled --- `&a[i]`
            // and `&s.f` need the arithmetic that pointer scaling would bring,
            // and are refused by `lvalue` rather than approximated here.
            let var = lvalue(low, operand)?;
            let out = low.b.temp();
            low.b.assign_const(&out, var.addr as i64);
            values.push(Val {
                reg: out,
                ty: crate::csource::lower::ctype::IntType::ULONG,
                pointee: Some(var.ty),
            });
            Ok(())
        }
        TokenKind::Star => {
            jobs.push(Job::Deref { node });
            jobs.push(Job::Eval(operand));
            Ok(())
        }
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
            // An arithmetic or conversion result is not a pointer.
            pointee: None,
        },
    ))
}

/// An integer or character constant, with its C type.
fn literal(low: &mut Lowerer<'_, '_>, node: NodeId) -> Result<Val, LowerError> {
    let ctx = low.ctx;
    let text = ctx.text_of(node);
    let (bits, ty) = parse_literal(text)
        .ok_or_else(|| LowerError::new(format!("literal `{text}`"), ctx.offset_of(node)))?;
    let out = low.b.temp();
    low.b.assign_const(&out, bits);
    Ok(Val::plain(out, ty))
}
