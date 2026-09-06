//! Calls, lowered by substituting the callee's body.
//!
//! # Why substitution rather than a call
//!
//! There is nothing to call. `Machine::run_function` surfaces `Op::Call` as
//! `Outcome::CalledOut` and stops --- only a SimProcedure continues --- so an
//! emitted call could not be *executed*, and executing the lowering is the only
//! way the S4 differential can check it against the binary its own compiler
//! produced. Substituting the body keeps one flat `LlirFunction` that the
//! existing interpreter runs unchanged.
//!
//! The cost is that this terminates only on an acyclic call graph, so recursion
//! is refused by name rather than approximated. The mechanism that *does*
//! terminate on a cycle is `csource::dataflow::interproc`'s summaries, and a
//! non-substituting call would use those.
//!
//! # The other thing in here
//!
//! [`parenthesised_type`], because `(uint32_t)(x)` and `f(x)` are the same
//! shape to a parser with no type table, so the cast/call ambiguity is resolved
//! at the same place the call is.

use std::collections::BTreeMap;

use crate::csource::lex::TokenKind;
use crate::csource::parse::tag::NodeTag;
use crate::ir::types::{Op, VReg, Value};
use crate::syntax::ids::NodeId;

use super::ctype::{CType, IntType};
use super::expr::lower_expr;
use super::func::{InlineFrame, Lowerer, RESULT_REG};
use super::value::{canonicalize, convert, Val};
use super::{unsupported, LowerError};

/// The most nested inlined calls a single lowering will substitute.
///
/// Each level multiplies the emitted body, so a deep chain of small functions
/// costs exponentially in the worst case. Recursion is refused outright by the
/// name check, so this bounds *fan-in depth* rather than termination.
const MAX_INLINE_DEPTH: usize = 8;

/// Lower a call by substituting the callee's body into the caller.
///
/// # Why substitution rather than a call
///
/// There is nothing to call. `Machine::run_function` surfaces `Op::Call` as
/// `Outcome::CalledOut` and stops --- only a SimProcedure continues --- so an
/// emitted call could not be executed, and executing the lowering is the only
/// way the S4 differential can check it against the binary. Substituting the
/// body keeps one flat `LlirFunction` that the existing interpreter runs
/// unchanged.
///
/// # What the callee does *not* see
///
/// A fresh scope stack, so the callee cannot reach the caller's locals; an
/// empty loop stack, so a `break` in the callee cannot target the caller's
/// loop; and its own result type, so its `return` converts to its own
/// declaration rather than the caller's. All three are saved and restored
/// around the substitution, which is what makes this re-entrant.
///
/// Frame slots need no such care: [`super::build::FnBuilder::slot`] hands out
/// fresh addresses, so an inlined body's locals cannot alias the caller's. Two
/// calls to the same function get two sets of slots, and a call inside a loop
/// gets one set reused across iterations --- which is what a real frame does.
pub(crate) fn inline_call(
    low: &mut Lowerer<'_, '_>,
    node: NodeId,
    primary: NodeId,
    args_node: NodeId,
) -> Result<Val, LowerError> {
    let ctx = low.ctx;
    // `(g)(x)` is a call to `g`: the parentheses are grouping, and the shape is
    // common in decompiler output. Bounded rather than recursive, as elsewhere.
    let mut callee_node = primary;
    for _ in 0..1024 {
        if ctx.tag(callee_node) != Some(NodeTag::ParenExpr) {
            break;
        }
        match ctx.children(callee_node).first().copied() {
            Some(inner) => callee_node = inner,
            None => return unsupported("call through an empty expression", node, ctx),
        }
    }
    if ctx.tag(callee_node) != Some(NodeTag::NameRef) {
        return unsupported("call through a function pointer", node, ctx);
    }
    let name = ctx.text_of(callee_node).to_string();
    let Some(def) = ctx.function_named(&name).cloned() else {
        // Not defined in this translation unit: libc, another object, or a
        // function-like macro the parser could not expand. Each needs a model
        // rather than a body, and naming the callee is what lets the census
        // rank them.
        return Err(LowerError::new(
            format!("call to `{name}`, which is not defined in this file"),
            ctx.offset_of(node),
        ));
    };
    if low.outer.iter().any(|f| f == &name) {
        // Direct or mutual recursion. Substitution is not a fixpoint, so this
        // is a refusal rather than a depth cut: the interprocedural summaries
        // in `csource::dataflow::interproc` are the mechanism that *does*
        // terminate on a cycle, and they are what a non-substituting call
        // would use.
        return Err(LowerError::new(
            format!("recursive call to `{name}`"),
            ctx.offset_of(node),
        ));
    }
    if low.outer.len() > MAX_INLINE_DEPTH {
        return unsupported("call nesting beyond the lowering's bound", node, ctx);
    }
    let Some(body) = def.body else {
        return unsupported("call to a function with no body", node, ctx);
    };
    let (ret, params) = ctx.signature(&def)?;
    if let Some(reason) = ret.unsupported_reason() {
        return Err(LowerError::new(
            format!("{reason} as the result of `{name}`"),
            ctx.offset_of(node),
        ));
    }

    // Arguments are evaluated in the *caller's* scope, before any of the
    // callee's names exist. C leaves their relative order unspecified; left to
    // right is the order everything else in this lowering uses.
    let arg_nodes = ctx.children(args_node);
    let takes_nothing = params.len() == 1 && matches!(params[0].ty, CType::Void);
    let wanted = if takes_nothing { 0 } else { params.len() };
    if arg_nodes.len() != wanted {
        return Err(LowerError::new(
            format!(
                "call to `{name}` passes {} arguments where it declares {wanted}",
                arg_nodes.len()
            ),
            ctx.offset_of(node),
        ));
    }
    let mut arguments = Vec::with_capacity(arg_nodes.len());
    for arg in arg_nodes {
        arguments.push(lower_expr(low, arg)?);
    }

    let join = low.b.new_block();

    // Install the callee's context, keeping the caller's to put back.
    let saved_scopes = std::mem::replace(&mut low.scopes, vec![BTreeMap::new()]);
    let saved_loops = std::mem::take(&mut low.loops);
    let saved_ret = std::mem::replace(&mut low.ret, ret.clone());
    low.inlining.push(InlineFrame {
        callee: name.clone(),
        join,
    });
    low.outer.push(name.clone());

    let outcome = inline_body(low, &params, &arguments, body);

    // Restored before the error is propagated: a refusal deep inside a callee
    // must not leave the caller lowering in the callee's scope, and an early
    // `?` here would do exactly that.
    low.scopes = saved_scopes;
    low.loops = saved_loops;
    low.ret = saved_ret;
    low.inlining.pop();
    low.outer.pop();
    outcome?;

    // A body that ends without `return` falls through to the join; one that
    // returned already jumped there and left a dead block current, from which
    // this jump is unreachable and harmless.
    low.b.jump(join);
    low.b.switch_to(join);

    let Some(result) = ret.as_int() else {
        // A `void` callee's value cannot be used in valid C, but the expression
        // stack still needs something to pop.
        let out = low.b.temp();
        low.b.assign_const(&out, 0);
        return Ok(Val::plain(out, IntType::INT));
    };
    let raw = low.b.temp();
    low.b.emit(Op::Assign {
        dst: raw.clone(),
        src: Value::Reg(VReg::phys(RESULT_REG)),
    });
    Ok(Val {
        reg: canonicalize(low, &raw, result),
        ty: result,
        pointee: ret.pointee().and_then(|inner| inner.as_int()),
    })
}

/// Bind the callee's parameters and lower its body, with the callee's context
/// already installed.
///
/// Split out so [`inline_call`] can restore the caller's context on the error
/// path as well as the success path.
fn inline_body(
    low: &mut Lowerer<'_, '_>,
    params: &[super::func::ParamSlot],
    arguments: &[Val],
    body: NodeId,
) -> Result<(), LowerError> {
    for (param, value) in params.iter().zip(arguments.iter()) {
        let Some(ty) = param.ty.as_int() else {
            continue; // a `void` parameter list; nothing arrives
        };
        // Converted to the parameter's declared type before it is stored,
        // which is the callee's own truncation rather than an approximation:
        // passing an `int` to a `char` parameter narrows at the call.
        let stored = convert(low, value, ty);
        let pointee = param.ty.pointee().and_then(|inner| inner.as_int());
        let local = low.declare_typed(&param.name, ty, pointee);
        low.b
            .store_abs(local.addr, ty.width.bytes().max(1) as u8, &stored.reg);
    }
    super::stmt::lower_body(low, body)
}

/// The integer type a parenthesised type name denotes, when it is one.
///
/// `(uint32_t)` reaches here as an ordinary [`NodeTag::ParenExpr`], because the
/// parser cannot tell a type name from an identifier and does not try. The
/// answer is `None` for anything the type table does not know, which is what
/// keeps `(fp)(x)` a call and `(x)(y)` --- neither of which names a type --- an
/// error about a function pointer rather than a silent conversion.
pub(crate) fn parenthesised_type(low: &Lowerer<'_, '_>, node: NodeId) -> Option<IntType> {
    let ctx = low.ctx;
    if ctx.tag(node) != Some(NodeTag::ParenExpr) {
        return None;
    }
    let (first, end) = ctx.extent(node)?;
    // The run is `( ... )`; a `*` in it would make this a pointer cast, which
    // has no `IntType` to convert to and is refused by being left a call.
    let inner: Vec<u32> = ((first + 1)..end.saturating_sub(1)).collect();
    if inner.is_empty()
        || inner
            .iter()
            .any(|&i| ctx.kind_at(i) == Some(TokenKind::Star))
    {
        return None;
    }
    let words: Vec<&str> = inner.iter().map(|&i| ctx.text_at(i)).collect();
    // A local of the same name shadows a type name in C, and the lowering
    // already resolves names against its scopes; asking first keeps a variable
    // called `size_t` from turning its own call into a cast.
    if words.len() == 1 && low.lookup(words[0]).is_some() {
        return None;
    }
    match super::ctype::from_specifier_tokens(words.iter().copied())? {
        CType::Int(ty) => Some(ty),
        _ => None,
    }
}
