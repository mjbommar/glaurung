//! Statement lowering, on an explicit job stack.
//!
//! Same discipline as [`super::expr`], for the same recorded reason: no native
//! recursion over user input. A construct that has work to do *after* its body
//! --- an `else` arm to open, a loop latch to close, a scope to pop --- pushes a
//! resumption job rather than keeping a stack frame.

use std::collections::BTreeMap;

use crate::csource::lex::TokenKind;
use crate::csource::parse::tag::NodeTag;
use crate::ir::types::{Op, VReg, Value};
use crate::syntax::ids::NodeId;

use super::build::BlockRef;
use super::expr::lower_expr;
use super::func::{token_words, LoopTargets, Lowerer, RESULT_REG};
use super::{unsupported, LowerError};

/// One step of the statement walk.
enum SJob {
    /// Lower this statement.
    Stmt(NodeId),
    /// Leave the innermost lexical scope.
    PopScope,
    /// The then-arm is finished: join, then open the else-arm.
    ElseArm { else_b: BlockRef, join: BlockRef },
    /// A conditional's last arm is finished: join.
    Join { join: BlockRef },
    /// A `while` body is finished: jump back to the header.
    WhileEnd { header: BlockRef, exit: BlockRef },
    /// A `do` body is finished: lower the trailing condition.
    DoEnd {
        cond: NodeId,
        body: BlockRef,
        cond_b: BlockRef,
        exit: BlockRef,
    },
    /// A `for` body is finished: run the step, then jump back to the header.
    ForEnd {
        step: Option<NodeId>,
        step_b: BlockRef,
        header: BlockRef,
        exit: BlockRef,
    },
}

/// Lower a function body (a `CompoundStmt`) into the builder.
pub fn lower_body(low: &mut Lowerer<'_, '_>, body: NodeId) -> Result<(), LowerError> {
    let mut jobs: Vec<SJob> = vec![SJob::Stmt(body)];
    // A statement job only ever pushes jobs for nodes strictly inside its own,
    // so the walk terminates; the counter catches a malformed arena instead of
    // spinning.
    let mut fuel = 1_000_000u32;
    while let Some(job) = jobs.pop() {
        fuel = fuel.checked_sub(1).ok_or_else(|| {
            LowerError::new("function too large to lower", low.ctx.offset_of(body))
        })?;
        match job {
            SJob::Stmt(node) => statement(low, node, &mut jobs)?,
            SJob::PopScope => {
                low.scopes.pop();
            }
            SJob::ElseArm { else_b, join } => {
                low.b.jump(join);
                low.b.switch_to(else_b);
            }
            SJob::Join { join } => {
                low.b.jump(join);
                low.b.switch_to(join);
            }
            SJob::WhileEnd { header, exit } => {
                low.b.jump(header);
                low.b.switch_to(exit);
                low.loops.pop();
            }
            SJob::DoEnd {
                cond,
                body,
                cond_b,
                exit,
            } => {
                low.b.jump(cond_b);
                low.b.switch_to(cond_b);
                let value = lower_expr(low, cond)?;
                let truth = low.b.truth(&value.reg);
                low.b.branch(&truth, body, exit);
                low.b.switch_to(exit);
                low.loops.pop();
            }
            SJob::ForEnd {
                step,
                step_b,
                header,
                exit,
            } => {
                low.b.jump(step_b);
                low.b.switch_to(step_b);
                if let Some(step) = step {
                    lower_expr(low, step)?;
                }
                low.b.jump(header);
                low.b.switch_to(exit);
                low.loops.pop();
                low.scopes.pop();
            }
        }
    }
    Ok(())
}

/// Lower one statement, pushing whatever resumptions it needs.
fn statement(
    low: &mut Lowerer<'_, '_>,
    node: NodeId,
    jobs: &mut Vec<SJob>,
) -> Result<(), LowerError> {
    let ctx = low.ctx;
    let Some(tag) = ctx.tag(node) else {
        return unsupported("node with no C tag", node, ctx);
    };
    match tag {
        NodeTag::CompoundStmt => {
            low.scopes.push(BTreeMap::new());
            jobs.push(SJob::PopScope);
            for child in ctx.children(node).into_iter().rev() {
                jobs.push(SJob::Stmt(child));
            }
            Ok(())
        }
        NodeTag::NullStmt | NodeTag::PpDirective => Ok(()),
        NodeTag::ExprStmt => {
            if let Some(inner) = ctx.children(node).first().copied() {
                lower_expr(low, inner)?;
            }
            Ok(())
        }
        NodeTag::Decl => declaration(low, node),
        NodeTag::ReturnStmt => {
            match ctx.children(node).first().copied() {
                Some(inner) => {
                    let value = lower_expr(low, inner)?;
                    let Some(ret) = low.ret.as_int() else {
                        return unsupported("value returned from a void function", node, ctx);
                    };
                    let converted = super::expr::convert(low, &value, ret);
                    low.b.emit(Op::Assign {
                        dst: VReg::phys(RESULT_REG),
                        src: Value::Reg(converted.reg),
                    });
                }
                None => {
                    if low.ret.as_int().is_some() {
                        // `return;` in a non-void function leaves the result
                        // unspecified; the binary leaves whatever is in the
                        // register, so nothing is written here either.
                    }
                }
            }
            low.b.emit(Op::Return);
            let dead = low.b.new_block();
            low.b.switch_to(dead);
            Ok(())
        }
        NodeTag::BreakStmt | NodeTag::ContinueStmt => {
            let Some(targets) = low.loops.last().copied() else {
                return unsupported("break or continue outside a loop", node, ctx);
            };
            let target = if tag == NodeTag::BreakStmt {
                targets.break_to
            } else {
                targets.continue_to
            };
            low.b.jump(target);
            let dead = low.b.new_block();
            low.b.switch_to(dead);
            Ok(())
        }
        NodeTag::IfStmt => if_stmt(low, node, jobs),
        NodeTag::WhileStmt => while_stmt(low, node, jobs),
        NodeTag::DoWhileStmt => do_stmt(low, node, jobs),
        NodeTag::ForStmt => for_stmt(low, node, jobs),
        NodeTag::SwitchStmt => unsupported("switch statement", node, ctx),
        NodeTag::CaseLabel | NodeTag::DefaultLabel => unsupported("case label", node, ctx),
        NodeTag::LabelStmt => unsupported("labelled statement", node, ctx),
        NodeTag::GotoStmt => unsupported("goto statement", node, ctx),
        NodeTag::Asm => unsupported("inline assembly", node, ctx),
        NodeTag::StaticAssert => Ok(()),
        NodeTag::LocalLabel => unsupported("GNU local label", node, ctx),
        NodeTag::Error => unsupported("unparsed construct", node, ctx),
        other => Err(LowerError::new(
            format!("{} in statement position", other.name()),
            ctx.offset_of(node),
        )),
    }
}

/// `if (c) A` and `if (c) A else B`.
fn if_stmt(
    low: &mut Lowerer<'_, '_>,
    node: NodeId,
    jobs: &mut Vec<SJob>,
) -> Result<(), LowerError> {
    let ctx = low.ctx;
    let kids = ctx.children(node);
    let (Some(&cond), Some(&then_n)) = (kids.first(), kids.get(1)) else {
        return unsupported("if with no then-arm", node, ctx);
    };
    let else_n = kids.get(2).copied();

    let value = lower_expr(low, cond)?;
    let truth = low.b.truth(&value.reg);
    let then_b = low.b.new_block();
    let join = low.b.new_block();
    match else_n {
        Some(else_n) => {
            let else_b = low.b.new_block();
            low.b.branch(&truth, then_b, else_b);
            low.b.switch_to(then_b);
            jobs.push(SJob::Join { join });
            jobs.push(SJob::Stmt(else_n));
            jobs.push(SJob::ElseArm { else_b, join });
            jobs.push(SJob::Stmt(then_n));
        }
        None => {
            low.b.branch(&truth, then_b, join);
            low.b.switch_to(then_b);
            jobs.push(SJob::Join { join });
            jobs.push(SJob::Stmt(then_n));
        }
    }
    Ok(())
}

/// `while (c) B`.
fn while_stmt(
    low: &mut Lowerer<'_, '_>,
    node: NodeId,
    jobs: &mut Vec<SJob>,
) -> Result<(), LowerError> {
    let ctx = low.ctx;
    let kids = ctx.children(node);
    let (Some(&cond), Some(&body_n)) = (kids.first(), kids.get(1)) else {
        return unsupported("while with no body", node, ctx);
    };
    let header = low.b.new_block();
    let body = low.b.new_block();
    let exit = low.b.new_block();
    low.b.jump(header);
    low.b.switch_to(header);
    let value = lower_expr(low, cond)?;
    let truth = low.b.truth(&value.reg);
    low.b.branch(&truth, body, exit);
    low.b.switch_to(body);
    low.loops.push(LoopTargets {
        continue_to: header,
        break_to: exit,
    });
    jobs.push(SJob::WhileEnd { header, exit });
    jobs.push(SJob::Stmt(body_n));
    Ok(())
}

/// `do B while (c);`.
fn do_stmt(
    low: &mut Lowerer<'_, '_>,
    node: NodeId,
    jobs: &mut Vec<SJob>,
) -> Result<(), LowerError> {
    let ctx = low.ctx;
    let kids = ctx.children(node);
    let (Some(&body_n), Some(&cond)) = (kids.first(), kids.get(1)) else {
        return unsupported("do-while with no condition", node, ctx);
    };
    let body = low.b.new_block();
    let cond_b = low.b.new_block();
    let exit = low.b.new_block();
    low.b.jump(body);
    low.b.switch_to(body);
    low.loops.push(LoopTargets {
        continue_to: cond_b,
        break_to: exit,
    });
    jobs.push(SJob::DoEnd {
        cond,
        body,
        cond_b,
        exit,
    });
    jobs.push(SJob::Stmt(body_n));
    Ok(())
}

/// `for (init; cond; step) B`, both the C89 and the C99 forms.
fn for_stmt(
    low: &mut Lowerer<'_, '_>,
    node: NodeId,
    jobs: &mut Vec<SJob>,
) -> Result<(), LowerError> {
    let ctx = low.ctx;
    let kids = ctx.children(node);
    let clause = |tag: NodeTag| {
        kids.iter()
            .copied()
            .find(|c| ctx.tag(*c) == Some(tag))
            .and_then(|c| ctx.children(c).first().copied())
    };
    let init = clause(NodeTag::ForInit);
    let cond = clause(NodeTag::ForCond);
    let step = clause(NodeTag::ForStep);
    // `ForInit`, `ForCond` and `ForStep` all answer `is_statement()` --- they
    // sit inside the statement range of the tag table --- so the body is the
    // last child that is not one of the three clauses, never the first
    // statement-tagged one.
    let Some(&body_n) = kids.iter().rev().find(|c| {
        !matches!(
            ctx.tag(**c),
            Some(NodeTag::ForInit) | Some(NodeTag::ForCond) | Some(NodeTag::ForStep)
        )
    }) else {
        return unsupported("for with no body", node, ctx);
    };

    // The C99 init clause declares into a scope that encloses the body.
    low.scopes.push(BTreeMap::new());
    if let Some(init) = init {
        match ctx.tag(init) {
            Some(NodeTag::Decl) => declaration(low, init)?,
            Some(_) => {
                lower_expr(low, init)?;
            }
            None => return unsupported("for init clause with no tag", node, ctx),
        }
    }

    let header = low.b.new_block();
    let body = low.b.new_block();
    let step_b = low.b.new_block();
    let exit = low.b.new_block();
    low.b.jump(header);
    low.b.switch_to(header);
    match cond {
        Some(cond) => {
            let value = lower_expr(low, cond)?;
            let truth = low.b.truth(&value.reg);
            low.b.branch(&truth, body, exit);
        }
        // An omitted condition is `true`.
        None => low.b.jump(body),
    }
    low.b.switch_to(body);
    low.loops.push(LoopTargets {
        continue_to: step_b,
        break_to: exit,
    });
    jobs.push(SJob::ForEnd {
        step,
        step_b,
        header,
        exit,
    });
    jobs.push(SJob::Stmt(body_n));
    Ok(())
}

/// A block-scope declaration: one or more declarators of a shared type.
fn declaration(low: &mut Lowerer<'_, '_>, node: NodeId) -> Result<(), LowerError> {
    let ctx = low.ctx;
    let kids = ctx.children(node);
    let Some(specifiers) = kids
        .iter()
        .copied()
        .find(|c| ctx.tag(*c) == Some(NodeTag::DeclSpecifiers))
    else {
        return unsupported("declaration with no specifiers", node, ctx);
    };
    let words = token_words(ctx, specifiers);
    // A `static` local outlives the call and a `typedef` declares no object;
    // both would lower to an ordinary stack slot, which is wrong rather than
    // approximate.
    for word in &words {
        match word.as_str() {
            "static" => return unsupported("static local variable", node, ctx),
            "extern" => return unsupported("extern declaration in a function", node, ctx),
            "typedef" => return unsupported("local typedef", node, ctx),
            "_Thread_local" | "__thread" => return unsupported("thread-local variable", node, ctx),
            _ => {}
        }
    }
    let Some(base) = super::ctype::from_specifier_tokens(words.iter().map(String::as_str)) else {
        return Err(LowerError::new(
            format!("declaration type `{}`", words.join(" ")),
            ctx.offset_of(specifiers),
        ));
    };
    let Some(base) = base.as_int() else {
        let reason = base.unsupported_reason().unwrap_or("declaration type");
        return Err(LowerError::new(reason, ctx.offset_of(specifiers)));
    };

    // `Decl` children are the specifier run followed by declarator/initializer
    // pairs in source order.
    let mut index = 0usize;
    while index < kids.len() {
        let child = kids[index];
        index += 1;
        if ctx.tag(child) != Some(NodeTag::Declarator) {
            continue;
        }
        let (first, end) = ctx
            .extent(child)
            .ok_or_else(|| LowerError::new("declarator with no tokens", ctx.offset_of(node)))?;
        if (first..end).any(|i| {
            matches!(
                ctx.kind_at(i),
                Some(TokenKind::Star) | Some(TokenKind::LBracket) | Some(TokenKind::LParen)
            )
        }) {
            return unsupported("pointer, array or function declarator", child, ctx);
        }
        let Some(name_node) = ctx
            .children(child)
            .into_iter()
            .find(|c| ctx.tag(*c) == Some(NodeTag::DeclName))
        else {
            return unsupported("declarator with no name", child, ctx);
        };
        let name = ctx.text_of(name_node).to_string();

        let initializer = kids
            .get(index)
            .copied()
            .filter(|c| ctx.tag(*c) == Some(NodeTag::Initializer));
        // Evaluate the initializer *before* declaring the name: `int x = x;`
        // in an inner scope reads the outer `x`, and declaring first would
        // silently read the new slot.
        let value = match initializer {
            Some(init) => {
                index += 1;
                let Some(inner) = ctx.children(init).first().copied() else {
                    return unsupported("empty initializer", init, ctx);
                };
                if ctx.tag(inner) == Some(NodeTag::InitList) {
                    return unsupported("braced initializer", init, ctx);
                }
                Some(lower_expr(low, inner)?)
            }
            None => None,
        };
        let local = low.declare(&name, base);
        if let Some(value) = value {
            let stored = super::expr::convert(low, &value, base);
            low.b
                .store_abs(local.addr, base.width.bytes().max(1) as u8, &stored.reg);
        }
    }
    Ok(())
}
