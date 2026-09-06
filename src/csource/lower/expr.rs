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
use super::value::{binary, canonicalize, convert, deref, index_address, load_local, unary, Val};
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
    /// Combine the top two values into the address of `base[index]`.
    ///
    /// Leaves a *pointer* on the stack, not the element: a subscript in rvalue
    /// position is this followed by [`Job::Deref`], and one in lvalue position
    /// is this alone. That is C's own definition, `a[i]` is `*(a + i)`, and
    /// splitting at the address is what lets both positions share it.
    Index { node: NodeId },
    /// Store the top value into a local; the assignment's value replaces it.
    Store { var: Local },
    /// Store the top value through the address below it on the stack.
    ///
    /// The width comes from the address value's [`Val::pointee`], so `*p = v`
    /// and `a[i] = v` need no separate static type for the target.
    StoreIndirect { node: NodeId },
    /// Compound-assign through the address below the top value.
    ///
    /// The address is evaluated once and read *and* written through, which is
    /// what `a[i++] += 1` requires: C increments `i` exactly once.
    CompoundIndirect { node: NodeId, op: TokenKind },
    /// `++` or `--` on the object at the address on top of the stack.
    StepIndirect {
        node: NodeId,
        increment: bool,
        /// Whether the expression's value is the old one (`x++`) or the new
        /// one (`++x`).
        post: bool,
    },
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
            Job::Index { node } => {
                let index = pop(&mut values, node, low)?;
                let base = pop(&mut values, node, low)?;
                values.push(index_address(low, node, &base, &index)?);
            }
            Job::Store { var } => {
                let v = pop(&mut values, node, low)?;
                let stored = convert(low, &v, var.ty);
                low.b
                    .store_abs(var.addr, var.ty.width.bytes().max(1) as u8, &stored.reg);
                values.push(stored);
            }
            Job::StoreIndirect { node } => {
                let v = pop(&mut values, node, low)?;
                let addr = pop(&mut values, node, low)?;
                let ty = pointee_of(low, node, &addr)?;
                let stored = convert(low, &v, ty);
                low.b
                    .store_reg(&addr.reg, ty.width.bytes().max(1) as u8, &stored.reg);
                values.push(stored);
            }
            Job::CompoundIndirect { node, op } => {
                let rhs = pop(&mut values, node, low)?;
                let addr = pop(&mut values, node, low)?;
                let ty = pointee_of(low, node, &addr)?;
                let lhs = deref(low, node, &addr)?;
                let combined = binary(low, node, op, lhs, rhs)?;
                let stored = convert(low, &combined, ty);
                low.b
                    .store_reg(&addr.reg, ty.width.bytes().max(1) as u8, &stored.reg);
                values.push(stored);
            }
            Job::StepIndirect {
                node,
                increment,
                post,
            } => {
                let addr = pop(&mut values, node, low)?;
                let ty = pointee_of(low, node, &addr)?;
                let old = deref(low, node, &addr)?;
                let one = low.b.temp();
                low.b.assign_const(&one, 1);
                let raw = low.b.temp();
                low.b.binop(
                    &raw,
                    if increment { BinOp::Add } else { BinOp::Sub },
                    &old.reg,
                    &one,
                );
                let new = canonicalize(low, &raw, ty);
                low.b
                    .store_reg(&addr.reg, ty.width.bytes().max(1) as u8, &new);
                values.push(if post { old } else { Val::plain(new, ty) });
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
            let increment = op == TokenKind::PlusPlus;
            match place_of(low, operand)? {
                Place::Var(var) => {
                    let (_, new) = step_local(low, var, increment)?;
                    values.push(new);
                }
                Place::Indirect(target) => {
                    jobs.push(Job::StepIndirect {
                        node,
                        increment,
                        post: false,
                    });
                    push_address(low, target, jobs)?;
                }
            }
            Ok(())
        }
        TokenKind::Amp => {
            // `&x` on a local is its frame address, which the lowering already
            // knows: `Local::addr`. `&a[i]` and `&*p` are the *address* half of
            // a subscript or dereference with the load left off, which is
            // exactly what `push_address` produces --- so taking an address is
            // the one operation that needs no code of its own beyond this.
            match place_of(low, operand)? {
                Place::Var(var) => {
                    let out = low.b.temp();
                    low.b.assign_const(&out, var.addr as i64);
                    values.push(Val {
                        reg: out,
                        ty: IntType::ULONG,
                        pointee: Some(var.ty),
                    });
                }
                Place::Indirect(target) => push_address(low, target, jobs)?,
            }
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
    jobs: &mut Vec<Job>,
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
            Some(NodeTag::MemberSuffix) => return unsupported("struct member access", node, ctx),
            Some(NodeTag::IndexSuffix) | Some(NodeTag::IncDecSuffix) => {}
            _ => return unsupported("postfix suffix", node, ctx),
        }
    }
    // Subscripts come first in any chain this admits: `a[i]++` is a subscript
    // then an increment, and `a++[i]` is legal C but subscripts the *old*
    // pointer, which is a distinction not worth carrying.
    let subscripts = suffixes
        .iter()
        .take_while(|s| ctx.tag(**s) == Some(NodeTag::IndexSuffix))
        .count();
    match &suffixes[subscripts..] {
        [] if subscripts == 0 => {
            jobs.push(Job::Eval(primary));
            Ok(())
        }
        [] => push_subscripts(low, primary, &suffixes[..subscripts], jobs, true),
        [step] if ctx.tag(*step) == Some(NodeTag::IncDecSuffix) => {
            let increment = ctx.text_of(*step).starts_with("++");
            if subscripts == 0 {
                return match place_of(low, primary)? {
                    Place::Var(var) => {
                        let (old, _) = step_local(low, var, increment)?;
                        values.push(old);
                        Ok(())
                    }
                    Place::Indirect(target) => {
                        jobs.push(Job::StepIndirect {
                            node,
                            increment,
                            post: true,
                        });
                        push_address(low, target, jobs)
                    }
                };
            }
            jobs.push(Job::StepIndirect {
                node,
                increment,
                post: true,
            });
            push_subscripts(low, primary, &suffixes[..subscripts], jobs, false)
        }
        _ => unsupported("chained postfix suffix", node, ctx),
    }
}

/// Push the jobs for `primary[i0][i1]...`, leaving the element on the stack
/// when `load` is set and its address when it is not.
///
/// A chain past the first subscript is admitted but rarely survives: the first
/// element of an `int *` is an `int`, which carries no pointee, so `p[i][j]`
/// reaches [`index_address`]'s refusal rather than a wrong address. That is the
/// intended outcome --- [`Local::pointee`] is one level deep, so a real
/// two-dimensional array is refused at its declaration.
fn push_subscripts(
    low: &Lowerer<'_, '_>,
    primary: NodeId,
    suffixes: &[NodeId],
    jobs: &mut Vec<Job>,
    load: bool,
) -> Result<(), LowerError> {
    let ctx = low.ctx;
    // Reverse of execution order: the primary is pushed last so it runs first.
    for (position, suffix) in suffixes.iter().copied().enumerate().rev() {
        if load || position + 1 < suffixes.len() {
            jobs.push(Job::Deref { node: suffix });
        }
        jobs.push(Job::Index { node: suffix });
        let Some(index) = ctx.children(suffix).first().copied() else {
            return unsupported("empty subscript", suffix, ctx);
        };
        jobs.push(Job::Eval(index));
    }
    jobs.push(Job::Eval(primary));
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
    let places: Vec<Place> = ops
        .iter()
        .enumerate()
        .map(|(index, _)| place_of(low, kids[index]))
        .collect::<Result<_, _>>()?;

    for (index, op) in ops.iter().copied().enumerate() {
        let base = if op == TokenKind::Eq {
            None
        } else {
            Some(compound_base(op).ok_or_else(|| {
                LowerError::new(
                    format!("assignment operator `{}`", op.name()),
                    ctx.offset_of(node),
                )
            })?)
        };
        jobs.push(match (places[index], base) {
            (Place::Var(var), None) => Job::Store { var },
            (Place::Var(var), Some(op)) => Job::Compound { var, op, node },
            (Place::Indirect(target), None) => Job::StoreIndirect { node: target },
            (Place::Indirect(target), Some(op)) => Job::CompoundIndirect { node: target, op },
        });
    }
    jobs.push(Job::Eval(kids[kids.len() - 1]));
    // Every target address is computed *before* the value, so the value stack
    // is `[addr0, .., addrN, value]` and each store pops the value it just
    // produced and the address immediately beneath it. C leaves the order of a
    // target's address and the assigned value unspecified, so choosing one is
    // legal; choosing *this* one is what makes the stack discipline work.
    for index in (0..ops.len()).rev() {
        if let Place::Indirect(target) = places[index] {
            push_address(low, target, jobs)?;
        }
    }
    Ok(())
}

/// What an assignment, an increment or an `&` acts on.
#[derive(Debug, Clone, Copy)]
enum Place {
    /// A named local at a fixed frame address.
    Var(Local),
    /// An object at an address that must be computed: `*p` or `a[i]`. The node
    /// is the whole target expression, and [`push_address`] pushes the jobs
    /// that leave its address on the value stack.
    ///
    /// The *type* of the object is not carried here: it is the `pointee` of
    /// the address value, which the address computation already knows. That is
    /// what keeps this from needing a static type checker for expressions.
    Indirect(NodeId),
}

/// Classify an assignable expression without emitting anything.
///
/// Emitting nothing is the point: [`assign_node`] must know the shape of every
/// target before it pushes a single job, and the addresses have to be computed
/// in a different order from the one they are discovered in.
fn place_of(low: &Lowerer<'_, '_>, node: NodeId) -> Result<Place, LowerError> {
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
                let var = low.lookup(name).ok_or_else(|| {
                    LowerError::new(
                        format!("assignment to non-local `{name}`"),
                        ctx.offset_of(node),
                    )
                })?;
                // An array name is not a modifiable lvalue in C, and `&a` is a
                // pointer to the array rather than to its first element --- a
                // type this model does not have. Both are refused here rather
                // than approximated at the three call sites.
                if var.elements.is_some() {
                    return unsupported("array name where a scalar object is required", node, ctx);
                }
                return Ok(Place::Var(var));
            }
            Some(NodeTag::UnaryExpr) if unary_operator(low, current) == Some(TokenKind::Star) => {
                return Ok(Place::Indirect(current));
            }
            Some(NodeTag::PostfixExpr) if ends_in_subscript(low, current) => {
                return Ok(Place::Indirect(current));
            }
            _ => return unsupported("assignment to a non-variable lvalue", node, ctx),
        }
    }
    unsupported("parenthesis nesting beyond the lowering's bound", node, ctx)
}

/// The operator of a prefix expression.
fn unary_operator(low: &Lowerer<'_, '_>, node: NodeId) -> Option<TokenKind> {
    let token = low.ctx.main_token(node)?;
    low.ctx.kind_at(token.raw())
}

/// Whether every suffix of a postfix expression is a subscript.
///
/// A trailing `++` or a call makes the whole thing an rvalue, so only a pure
/// subscript chain is a place.
fn ends_in_subscript(low: &Lowerer<'_, '_>, node: NodeId) -> bool {
    let kids = low.ctx.children(node);
    match kids.split_first() {
        Some((_, suffixes)) if !suffixes.is_empty() => suffixes
            .iter()
            .all(|s| low.ctx.tag(*s) == Some(NodeTag::IndexSuffix)),
        _ => false,
    }
}

/// Push the jobs that leave the address of an indirect place on the stack.
///
/// The value they leave is a *pointer* value, so its `pointee` says how wide
/// the object is --- which is why a store through it needs no other type
/// information. Paired with [`place_of`], which decides that `node` is one of
/// the two shapes handled here.
fn push_address(
    low: &Lowerer<'_, '_>,
    node: NodeId,
    jobs: &mut Vec<Job>,
) -> Result<(), LowerError> {
    let ctx = low.ctx;
    match ctx.tag(node) {
        // `*p` --- the address is `p` itself, with the load left off.
        Some(NodeTag::UnaryExpr) => {
            let Some(operand) = ctx.children(node).first().copied() else {
                return unsupported("dereference with no operand", node, ctx);
            };
            jobs.push(Job::Eval(operand));
            Ok(())
        }
        // `a[i]` --- the subscript chain with the final load left off.
        Some(NodeTag::PostfixExpr) => {
            let kids = ctx.children(node);
            let Some((&primary, suffixes)) = kids.split_first() else {
                return unsupported("empty postfix expression", node, ctx);
            };
            push_subscripts(low, primary, suffixes, jobs, false)
        }
        _ => unsupported("address of a non-place expression", node, ctx),
    }
}

/// The type of the object an address value points at.
fn pointee_of(low: &Lowerer<'_, '_>, node: NodeId, addr: &Val) -> Result<IntType, LowerError> {
    addr.pointee.ok_or_else(|| {
        LowerError::new(
            "store through a pointer with no known pointee width",
            low.ctx.offset_of(node),
        )
    })
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

/// `++x` / `x++` on a local: returns `(old value, new value)`.
fn step_local(
    low: &mut Lowerer<'_, '_>,
    var: Local,
    increment: bool,
) -> Result<(Val, Val), LowerError> {
    let old = load_local(low, var);
    // `p++` on an `int32_t *` advances four bytes, the same rule `p + 1`
    // follows. A non-pointer steps by one because its `pointee` is `None`.
    let step = var
        .pointee
        .map_or(1, |pointee| i64::from(pointee.width.bytes().max(1)));
    let one = low.b.temp();
    low.b.assign_const(&one, step);
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
            // Incrementing a pointer yields a pointer: `*++p` needs the
            // pointee to survive the step or the dereference has no width.
            pointee: var.pointee,
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
