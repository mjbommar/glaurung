//! Function-level lowering: the tree context, the scope stack, the parameter
//! contract, and the entry point every caller uses.
//!
//! # The parameter contract is SysV AMD64, on purpose
//!
//! A lowered C function could pass its parameters any way it liked --- nothing
//! calls it but the interpreter. It uses the same ABI as the compiled fixture
//! (`rdi, rsi, rdx, rcx, r8, r9`, result in `rax`) because the gate in
//! `roadmap.md` section 6 compares a lowered function against *the same
//! function lifted from its binary*. Sharing the entry and exit contract is what
//! makes that comparison one experiment rather than two runs joined by a
//! translation nobody checked.
//!
//! The result register is written at 64 bits from the canonical value, so a
//! caller comparing against a lifted binary must mask `rax` to the return
//! type's width: a real callee returning `int` leaves the upper 32 bits of
//! `rax` undefined, and comparing them would report a divergence that the C
//! standard says is not one.

use std::collections::BTreeMap;

use crate::csource::lex::TokenKind;
use crate::csource::parse::tag::NodeTag;
use crate::csource::parse::{parse, FunctionDef, Tree};
use crate::ir::types::{LlirFunction, Op, VReg, Value, Width};
use crate::syntax::ids::{NodeId, Span, TokenId};

use super::build::FnBuilder;
use super::ctype::{CType, IntType};
use super::{unsupported, LowerError};

/// The SysV AMD64 integer argument registers, in order.
pub const ARG_REGS: [&str; 6] = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"];

/// The SysV AMD64 integer result register.
pub const RESULT_REG: &str = "rax";

/// A parameter of a lowered function: where its value comes in and what it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParamSlot {
    /// The declared name, empty for an unnamed parameter.
    pub name: String,
    /// The declared type.
    pub ty: CType,
    /// The ABI register the value arrives in.
    pub reg: &'static str,
}

/// A C function lowered to LLIR, with the contract needed to call it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoweredFunction {
    /// The function's declared name.
    pub name: String,
    /// The lowered body.
    pub func: LlirFunction,
    /// Parameters in declaration order.
    pub params: Vec<ParamSlot>,
    /// The declared result type.
    pub ret: CType,
}

impl LoweredFunction {
    /// The result register's meaningful width, or `None` for a `void` result.
    ///
    /// A caller comparing against a lifted binary must mask to this: see the
    /// module docs.
    pub fn result_width(&self) -> Option<Width> {
        match &self.ret {
            CType::Void => None,
            CType::Int(t) => Some(t.width),
            _ => Some(Width::W64),
        }
    }
}

/// A local variable or parameter: where it lives and what it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Local {
    /// Absolute address of its frame slot.
    pub addr: u64,
    /// Its integer type.
    pub ty: IntType,
}

/// Where `break` and `continue` go in the innermost enclosing loop.
#[derive(Debug, Clone, Copy)]
pub struct LoopTargets {
    /// The block `continue` jumps to.
    pub continue_to: super::build::BlockRef,
    /// The block `break` jumps to.
    pub break_to: super::build::BlockRef,
}

/// Read-only view of the parsed tree, with the token lookups the lowering does
/// constantly.
///
/// The token spans are computed once here rather than per node: `Tree::node_span`
/// re-lexes the whole file on every call, which a per-node walk would pay for
/// every identifier.
pub struct Ctx<'a> {
    tree: &'a Tree,
    text: &'a str,
    spans: Vec<Span>,
}

impl<'a> Ctx<'a> {
    /// Build a context over a parsed tree and the exact text it was parsed from.
    pub fn new(tree: &'a Tree, text: &'a str) -> Self {
        let spans = tree.token_spans(text);
        Self { tree, text, spans }
    }

    /// The node's tag, or `None` for a tag no C front end wrote.
    pub fn tag(&self, node: NodeId) -> Option<NodeTag> {
        self.tree.arena().tag(node).and_then(NodeTag::from_u16)
    }

    /// The node's children, in source order.
    pub fn children(&self, node: NodeId) -> Vec<NodeId> {
        self.tree.arena().children_iter(node).collect()
    }

    /// The node's half-open token range.
    pub fn extent(&self, node: NodeId) -> Option<(u32, u32)> {
        self.tree.arena().token_extent(node)
    }

    /// The first token the node consumed itself --- for a `UnaryExpr` or a
    /// `BinaryExpr` that is its operator.
    pub fn main_token(&self, node: NodeId) -> Option<TokenId> {
        self.tree.arena().main_token(node)
    }

    /// The kind of token `index`.
    pub fn kind_at(&self, index: u32) -> Option<TokenKind> {
        (index < self.tree.tokens().len() as u32)
            .then(|| TokenKind::from_u16(self.tree.tokens().kind(TokenId::new(index))))
            .flatten()
    }

    /// The exact source text of token `index`.
    pub fn text_at(&self, index: u32) -> &'a str {
        self.spans
            .get(index as usize)
            .and_then(|s| self.text.get(s.range()))
            .unwrap_or("")
    }

    /// The source text a node covers.
    pub fn text_of(&self, node: NodeId) -> &'a str {
        self.tree
            .arena()
            .span(node, &self.spans)
            .and_then(|s| self.text.get(s.range()))
            .unwrap_or("")
    }

    /// Byte offset the node starts at, for a [`LowerError`].
    pub fn offset_of(&self, node: NodeId) -> u32 {
        self.tree
            .arena()
            .span(node, &self.spans)
            .map_or(0, |s| s.lo)
    }
}

/// The mutable half of a lowering in progress.
pub struct Lowerer<'a, 'b> {
    /// The tree being lowered.
    pub ctx: &'a Ctx<'b>,
    /// The function under construction.
    pub b: FnBuilder,
    /// Lexical scopes, innermost last.
    pub scopes: Vec<BTreeMap<String, Local>>,
    /// Enclosing loops, innermost last.
    pub loops: Vec<LoopTargets>,
    /// The declared result type.
    pub ret: CType,
}

impl<'a, 'b> Lowerer<'a, 'b> {
    /// Find a name in the innermost scope that declares it.
    pub fn lookup(&self, name: &str) -> Option<Local> {
        self.scopes
            .iter()
            .rev()
            .find_map(|scope| scope.get(name).copied())
    }

    /// Declare `name` in the innermost scope, allocating its frame slot.
    ///
    /// A redeclaration in the *same* scope replaces the binding rather than
    /// aliasing it, which is what C's one-definition rule already guarantees;
    /// an inner scope shadows, which the scope stack gives for free.
    pub fn declare(&mut self, name: &str, ty: IntType) -> Local {
        let addr = self.b.slot(u64::from(ty.width.bytes().max(1)));
        let local = Local { addr, ty };
        if let Some(scope) = self.scopes.last_mut() {
            scope.insert(name.to_string(), local);
        }
        local
    }
}

/// Lower one function definition to LLIR.
///
/// `text` must be exactly the text `tree` was parsed from: node spans are byte
/// offsets into it, and a mismatched pair reads identifiers out of unrelated
/// source.
pub fn lower_function(
    tree: &Tree,
    text: &str,
    def: &FunctionDef,
) -> Result<LoweredFunction, LowerError> {
    let ctx = Ctx::new(tree, text);
    let ret = function_result_type(&ctx, def)?;
    if let Some(reason) = ret.unsupported_reason() {
        return Err(LowerError::new(
            format!("{reason} as a result"),
            ctx.offset_of(def.node),
        ));
    }
    let params = function_parameters(&ctx, def)?;
    for param in &params {
        if let Some(reason) = param.ty.unsupported_reason() {
            return Err(LowerError::new(
                format!("{reason} as a parameter"),
                ctx.offset_of(def.node),
            ));
        }
        if matches!(param.ty, CType::Void) && params.len() > 1 {
            return Err(LowerError::new(
                "void among several parameters",
                ctx.offset_of(def.node),
            ));
        }
    }
    let Some(body) = def.body else {
        return Err(LowerError::new(
            "function definition with no body",
            ctx.offset_of(def.node),
        ));
    };

    let mut low = Lowerer {
        ctx: &ctx,
        b: FnBuilder::new(),
        scopes: vec![BTreeMap::new()],
        loops: Vec::new(),
        ret: ret.clone(),
    };

    // Prologue: move each argument register into the parameter's frame slot,
    // converted to the parameter's declared type. A 32-bit parameter arrives in
    // the low half of its register with the upper half undefined, so the
    // truncation is the callee's own, not an approximation of it.
    for param in &params {
        let Some(ty) = param.ty.as_int() else {
            continue; // `void` parameter list; nothing arrives.
        };
        let raw = low.b.temp();
        low.b.emit(Op::Assign {
            dst: raw.clone(),
            src: Value::Reg(VReg::phys(param.reg)),
        });
        let value = low.b.temp();
        low.b.normalize(&value, &raw, ty.width, ty.signed);
        let local = low.declare(&param.name, ty);
        low.b
            .store_abs(local.addr, ty.width.bytes().max(1) as u8, &value);
    }

    super::stmt::lower_body(&mut low, body)?;

    // A function that runs off the end returns an unspecified value; the
    // terminator has to exist all the same, or `run_function` falls through to
    // `NO_FALLTHROUGH_VA` and reports `NoBlock`.
    low.b.emit(Op::Return);

    Ok(LoweredFunction {
        name: def.name.clone(),
        func: low.b.finish(),
        params,
        ret,
    })
}

/// Parse `text` and lower the function called `name`.
///
/// The convenience entry point for a test or a differential harness; a caller
/// lowering many functions from one file should parse once and call
/// [`lower_function`].
pub fn lower_named_function(text: &str, name: &str) -> Result<LoweredFunction, LowerError> {
    let tree = parse(text).into_parts().0;
    let functions = tree.functions(text);
    let def = functions
        .iter()
        .find(|f| f.name == name)
        .ok_or_else(|| LowerError::new(format!("no function named `{name}`"), 0))?;
    lower_function(&tree, text, def)
}

/// The declared result type, read from the definition's `DeclSpecifiers` and
/// the pointer stars its declarator opens with.
fn function_result_type(ctx: &Ctx<'_>, def: &FunctionDef) -> Result<CType, LowerError> {
    let children = ctx.children(def.node);
    let specifiers = children
        .iter()
        .copied()
        .find(|c| ctx.tag(*c) == Some(NodeTag::DeclSpecifiers));
    let Some(specifiers) = specifiers else {
        return unsupported("function with no declaration specifiers", def.node, ctx);
    };
    let words = token_words(ctx, specifiers);
    let Some(ty) = super::ctype::from_specifier_tokens(words.iter().map(String::as_str)) else {
        return Err(LowerError::new(
            format!("result type `{}`", words.join(" ")),
            ctx.offset_of(specifiers),
        ));
    };
    // `int *f(void)` puts the star in the declarator, not the specifiers.
    if let Some(declarator) = children
        .iter()
        .copied()
        .find(|c| ctx.tag(*c) == Some(NodeTag::Declarator))
    {
        if let Some((first, end)) = ctx.extent(declarator) {
            let name_start = declarator_name_token(ctx, declarator).unwrap_or(end);
            if (first..name_start).any(|i| ctx.kind_at(i) == Some(TokenKind::Star)) {
                return Ok(CType::Pointer);
            }
        }
    }
    Ok(ty)
}

/// The token index of a declarator's `DeclName`, if it has one.
fn declarator_name_token(ctx: &Ctx<'_>, declarator: NodeId) -> Option<u32> {
    ctx.children(declarator)
        .into_iter()
        .find(|c| ctx.tag(*c) == Some(NodeTag::DeclName))
        .and_then(|n| ctx.extent(n))
        .map(|(first, _)| first)
}

/// The parameters of a function definition.
///
/// The parser keeps a parameter list as an opaque token run --- `tag.rs` says
/// so explicitly, and the reason is that a parameter list has no control flow
/// and so earned no grammar. Re-reading it here is therefore expected work, not
/// a workaround: split the run at top-level commas and read each parameter's
/// specifier words and trailing name.
fn function_parameters(ctx: &Ctx<'_>, def: &FunctionDef) -> Result<Vec<ParamSlot>, LowerError> {
    let Some(declarator) = ctx
        .children(def.node)
        .into_iter()
        .find(|c| ctx.tag(*c) == Some(NodeTag::Declarator))
    else {
        return unsupported("function definition with no declarator", def.node, ctx);
    };
    let lists: Vec<NodeId> = ctx
        .children(declarator)
        .into_iter()
        .filter(|c| ctx.tag(*c) == Some(NodeTag::ParamList))
        .collect();
    let Some(list) = lists.first().copied() else {
        // `int f() { }` --- an unprototyped definition takes no arguments here.
        return Ok(Vec::new());
    };
    if lists.len() > 1 {
        return unsupported("function returning a function pointer", def.node, ctx);
    }
    let Some((first, end)) = ctx.extent(list) else {
        return Ok(Vec::new());
    };

    let mut params: Vec<ParamSlot> = Vec::new();
    let mut group: Vec<u32> = Vec::new();
    let mut depth = 0i32;
    // Skip the enclosing parentheses: the run is `( ... )`.
    for index in (first + 1)..end.saturating_sub(1) {
        match ctx.kind_at(index) {
            Some(TokenKind::LParen) | Some(TokenKind::LBracket) => depth += 1,
            Some(TokenKind::RParen) | Some(TokenKind::RBracket) => depth -= 1,
            Some(TokenKind::Comma) if depth == 0 => {
                push_param(ctx, list, &group, &mut params)?;
                group.clear();
                continue;
            }
            _ => {}
        }
        group.push(index);
    }
    if !group.is_empty() {
        push_param(ctx, list, &group, &mut params)?;
    }
    // `f(void)` declares no parameters at all.
    if params.len() == 1 && matches!(params[0].ty, CType::Void) && params[0].name.is_empty() {
        params.clear();
    }
    if params.len() > ARG_REGS.len() {
        return unsupported("more parameters than argument registers", def.node, ctx);
    }
    Ok(params)
}

/// Read one comma-separated parameter group into a [`ParamSlot`].
fn push_param(
    ctx: &Ctx<'_>,
    list: NodeId,
    group: &[u32],
    out: &mut Vec<ParamSlot>,
) -> Result<(), LowerError> {
    if group.is_empty() {
        return Ok(());
    }
    let offset = ctx.offset_of(list);
    let reg = *ARG_REGS
        .get(out.len())
        .ok_or_else(|| LowerError::new("more parameters than argument registers", offset))?;
    // Anything that makes the parameter a pointer, an array, a function
    // pointer or a variadic marker is named rather than modelled.
    for &index in group {
        match ctx.kind_at(index) {
            Some(TokenKind::Star) => {
                out.push(ParamSlot {
                    name: String::new(),
                    ty: CType::Pointer,
                    reg,
                });
                return Ok(());
            }
            Some(TokenKind::LBracket) => {
                out.push(ParamSlot {
                    name: String::new(),
                    ty: CType::Aggregate("array"),
                    reg,
                });
                return Ok(());
            }
            Some(TokenKind::Ellipsis) => {
                return Err(LowerError::new("variadic parameter list", offset));
            }
            _ => {}
        }
    }
    let words: Vec<&str> = group.iter().map(|&i| ctx.text_at(i)).collect();
    // The name, when present, is the last identifier and the specifiers are
    // everything before it. `int` alone is an unnamed parameter.
    let last_is_name = group.len() > 1
        && ctx.kind_at(group[group.len() - 1]) == Some(TokenKind::Identifier)
        && super::ctype::from_specifier_tokens(words[..words.len() - 1].iter().copied()).is_some();
    let (spec, name) = if last_is_name {
        (&words[..words.len() - 1], words[words.len() - 1])
    } else {
        (&words[..], "")
    };
    let Some(ty) = super::ctype::from_specifier_tokens(spec.iter().copied()) else {
        return Err(LowerError::new(
            format!("parameter type `{}`", spec.join(" ")),
            offset,
        ));
    };
    out.push(ParamSlot {
        name: name.to_string(),
        ty,
        reg,
    });
    Ok(())
}

/// The specifier lexemes a node covers, with GNU decoration removed.
///
/// `__attribute__((noinline))` sits *inside* the specifier run --- and the
/// fixture corpus marks almost every function with it, so reading the run
/// verbatim refused 648 of its 900 functions on a decoration that changes no
/// type. The parser already gives the decoration its own node, so skipping
/// those children is exact rather than a token-level guess.
pub(crate) fn token_words(ctx: &Ctx<'_>, node: NodeId) -> Vec<String> {
    let Some((first, end)) = ctx.extent(node) else {
        return Vec::new();
    };
    let skip: Vec<(u32, u32)> = ctx
        .children(node)
        .into_iter()
        .filter(|c| {
            matches!(
                ctx.tag(*c),
                Some(NodeTag::Attribute) | Some(NodeTag::Asm) | Some(NodeTag::StructBody)
            )
        })
        .filter_map(|c| ctx.extent(c))
        .collect();
    (first..end)
        .filter(|i| !skip.iter().any(|(lo, hi)| (*lo..*hi).contains(i)))
        .map(|i| ctx.text_at(i).to_string())
        .collect()
}
