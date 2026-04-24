//! C-like AST lowering for lifted functions.
//!
//! Given an [`LlirFunction`] and its recovered [`Region`] tree, [`lower`]
//! produces a [`Function`] whose body is a list of [`Stmt`] nodes in a
//! conventional C-style shape: assignments, stores, calls, conditionals,
//! loops. A companion printer (see `print` below) renders this to text.
//!
//! This is the first pass on the road from LLIR to readable decompiled
//! output. It deliberately does *not* try to reconstruct nested expressions
//! from SSA temporaries — that's a separate polish task. Every LLIR op maps
//! to a single flat statement so the decompiled text faithfully reflects the
//! lifted IR, one line per op.

use std::fmt::{self, Write};

use crate::ir::structure::Region;
use crate::ir::types::{
    BinOp, CallTarget, CmpOp, LlirBlock, LlirFunction, LlirInstr, MemOp, Op, UnOp, VReg, Value,
};
use crate::ir::types_recover::{TypeHint, TypeMap};

// -- Expressions ---------------------------------------------------------------

/// A C-level expression. v1 is deliberately shallow: we carry raw VReg
/// references and constants without reconstructing use-def chains. The
/// expression-reconstruction pass can later replace `Reg` with compound
/// subexpressions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expr {
    Reg(VReg),
    Const(i64),
    Addr(u64),
    /// A VA that the resolver has attached a symbol name to. The raw VA
    /// travels along so downstream consumers (e.g. a debugger view) can
    /// still cross-reference.
    Named {
        va: u64,
        name: String,
    },
    /// A C-string literal recovered from the binary's rodata. The printer
    /// renders this with proper `"..."` quoting and C-style escapes.
    StringLit {
        value: String,
    },
    /// Address-of a memory operand: `base + index*scale + disp`.
    Lea {
        base: Option<VReg>,
        index: Option<VReg>,
        scale: u8,
        disp: i64,
        /// Optional segment override (e.g. "fs" for x86-64 TLS).
        #[doc(hidden)]
        segment: Option<String>,
    },
    /// Dereference a memory operand with a given access width.
    Deref {
        addr: Box<Expr>,
        size: u8,
    },
    Bin {
        op: BinOp,
        lhs: Box<Expr>,
        rhs: Box<Expr>,
    },
    Un {
        op: UnOp,
        src: Box<Expr>,
    },
    Cmp {
        op: CmpOp,
        lhs: Box<Expr>,
        rhs: Box<Expr>,
    },
    /// Target of an indirect call / computed value we couldn't simplify.
    Unknown(String),
}

// -- Statements ---------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stmt {
    Assign {
        dst: VReg,
        src: Expr,
    },
    Store {
        addr: Expr,
        src: Expr,
    },
    Call {
        target: Expr,
        /// Reconstructed argument expressions, in platform calling-
        /// convention order. Empty until the argument-reconstruction pass
        /// runs.
        args: Vec<Expr>,
    },
    Return {
        value: Option<Expr>,
    },
    /// Labelled position (used for unstructured fallbacks and goto targets).
    Label(u64),
    Goto {
        target: u64,
    },
    If {
        cond: Expr,
        then_body: Vec<Stmt>,
        else_body: Option<Vec<Stmt>>,
    },
    While {
        cond: Expr,
        body: Vec<Stmt>,
    },
    Nop,
    /// Reserved for ops the lifter marked `Op::Unknown` — the raw mnemonic
    /// travels through so the printer can still show it.
    Unknown(String),
    /// Human-readable comment produced by higher-level passes (prologue /
    /// epilogue recognisers, etc.). The printer renders it as `// <text>`.
    Comment(String),
    /// Synthesised `push X;` — produced by the stack-idiom pass when it
    /// collapses a `rsp -= N; [rsp] = X;` pair. The printer renders it as
    /// a single line.
    Push {
        value: Expr,
    },
    /// Mirror of `Push`: `pop %X;` from a `X = [rsp]; rsp += N;` pair.
    Pop {
        target: VReg,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Function {
    pub name: String,
    pub entry_va: u64,
    pub body: Vec<Stmt>,
}

// -- Lowering ----------------------------------------------------------------

fn lower_value(v: &Value) -> Expr {
    match v {
        Value::Reg(r) => Expr::Reg(r.clone()),
        Value::Const(c) => Expr::Const(*c),
        Value::Addr(a) => Expr::Addr(*a),
    }
}

fn lower_memop(m: &MemOp) -> Expr {
    Expr::Deref {
        addr: Box::new(Expr::Lea {
            base: m.base.clone(),
            index: m.index.clone(),
            scale: m.scale,
            disp: m.disp,
            segment: m.segment.clone(),
        }),
        size: m.size,
    }
}

/// Lower a single LLIR op to one or more Stmts.
fn lower_op(op: &Op) -> Vec<Stmt> {
    match op {
        Op::Nop => vec![Stmt::Nop],
        Op::Assign { dst, src } => vec![Stmt::Assign {
            dst: dst.clone(),
            src: lower_value(src),
        }],
        Op::Bin {
            dst,
            op,
            lhs,
            rhs,
        } => vec![Stmt::Assign {
            dst: dst.clone(),
            src: Expr::Bin {
                op: *op,
                lhs: Box::new(lower_value(lhs)),
                rhs: Box::new(lower_value(rhs)),
            },
        }],
        Op::Un { dst, op, src } => vec![Stmt::Assign {
            dst: dst.clone(),
            src: Expr::Un {
                op: *op,
                src: Box::new(lower_value(src)),
            },
        }],
        Op::Cmp {
            dst,
            op,
            lhs,
            rhs,
        } => vec![Stmt::Assign {
            dst: dst.clone(),
            src: Expr::Cmp {
                op: *op,
                lhs: Box::new(lower_value(lhs)),
                rhs: Box::new(lower_value(rhs)),
            },
        }],
        Op::Load { dst, addr } => vec![Stmt::Assign {
            dst: dst.clone(),
            src: lower_memop(addr),
        }],
        Op::Store { addr, src } => vec![Stmt::Store {
            addr: Expr::Lea {
                base: addr.base.clone(),
                index: addr.index.clone(),
                scale: addr.scale,
                disp: addr.disp,
                segment: addr.segment.clone(),
            },
            src: lower_value(src),
        }],
        Op::Jump { target } => vec![Stmt::Goto { target: *target }],
        // A CondJump on its own (not absorbed into a structured If/While)
        // becomes a conditional goto.
        Op::CondJump { cond, target } => vec![Stmt::If {
            cond: Expr::Reg(cond.clone()),
            then_body: vec![Stmt::Goto { target: *target }],
            else_body: None,
        }],
        Op::Call { target } => {
            let target = match target {
                CallTarget::Direct(a) => Expr::Addr(*a),
                CallTarget::Indirect(v) => lower_value(v),
            };
            vec![Stmt::Call {
                target,
                args: Vec::new(),
            }]
        }
        Op::Return => vec![Stmt::Return { value: None }],
        Op::Unknown { mnemonic } => vec![Stmt::Unknown(mnemonic.clone())],
    }
}

/// Lower every op in a block to stmts.
fn lower_block(b: &LlirBlock) -> Vec<Stmt> {
    let mut out = Vec::with_capacity(b.instrs.len());
    for ins in &b.instrs {
        out.extend(lower_op(&ins.op));
    }
    out
}

/// Given a block that ends a conditional, return the "cond" expression for
/// the generated If/While. We extract the final LLIR op — which the lifter
/// emits as a CondJump — and use its flag register as the boolean value.
/// Also strips that CondJump from the lowered-body stmts so we don't emit
/// both the structured `if` and a trailing goto.
///
/// When the flag was immediately preceded by `Stmt::Assign { dst: flag,
/// src: Expr::Cmp { .. } }`, we hoist that comparison into the condition
/// and drop the now-dead flag assignment so the printer outputs
/// `if (rax == 0)` rather than `if (%zf)`.
fn extract_cond_and_strip<'a>(block: &LlirBlock, mut stmts: Vec<Stmt>) -> (Expr, Vec<Stmt>) {
    if let Some(LlirInstr {
        op: Op::CondJump { cond, .. },
        ..
    }) = block.instrs.last()
    {
        // Pop trailing `if (cond) goto ...` we just synthesised.
        if matches!(stmts.last(), Some(Stmt::If { .. })) {
            stmts.pop();
        }

        // Try to hoist the Cmp that produced `cond`. We scan from the end of
        // the body for the most recent assignment to that flag; if its RHS
        // is an Expr::Cmp, we pull it out and use it as the condition.
        for i in (0..stmts.len()).rev() {
            if let Stmt::Assign { dst, src } = &stmts[i] {
                if dst == cond {
                    if matches!(src, Expr::Cmp { .. }) {
                        // Ensure the flag isn't also read elsewhere in the
                        // remaining body. If it is, leave everything alone
                        // to avoid losing semantics.
                        let usages = stmts
                            .iter()
                            .enumerate()
                            .filter(|(j, _)| *j != i)
                            .map(|(_, s)| count_reg_uses_in_stmt(s, cond))
                            .sum::<usize>();
                        if usages == 0 {
                            if let Stmt::Assign { src, .. } = stmts.remove(i) {
                                return (src, stmts);
                            }
                        }
                    }
                    break;
                }
            }
        }
        return (Expr::Reg(cond.clone()), stmts);
    }
    // Fallback — no CondJump, synthesise a generic truthy condition.
    (Expr::Const(1), stmts)
}

fn count_reg_uses_in_expr(e: &Expr, target: &VReg) -> usize {
    match e {
        Expr::Reg(r) => (r == target) as usize,
        Expr::Const(_)
        | Expr::Addr(_)
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::Unknown(_) => 0,
        Expr::Lea { base, index, .. } => {
            (base.as_ref() == Some(target)) as usize + (index.as_ref() == Some(target)) as usize
        }
        Expr::Deref { addr, .. } => count_reg_uses_in_expr(addr, target),
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            count_reg_uses_in_expr(lhs, target) + count_reg_uses_in_expr(rhs, target)
        }
        Expr::Un { src, .. } => count_reg_uses_in_expr(src, target),
    }
}

fn count_reg_uses_in_stmt(s: &Stmt, target: &VReg) -> usize {
    match s {
        Stmt::Assign { src, .. } => count_reg_uses_in_expr(src, target),
        Stmt::Store { addr, src } => {
            count_reg_uses_in_expr(addr, target) + count_reg_uses_in_expr(src, target)
        }
        Stmt::Call { target: t, args } => {
            count_reg_uses_in_expr(t, target)
                + args
                    .iter()
                    .map(|a| count_reg_uses_in_expr(a, target))
                    .sum::<usize>()
        }
        Stmt::If { cond, .. } | Stmt::While { cond, .. } => count_reg_uses_in_expr(cond, target),
        Stmt::Return { value } => value.as_ref().map(|e| count_reg_uses_in_expr(e, target)).unwrap_or(0),
        Stmt::Push { value } => count_reg_uses_in_expr(value, target),
        Stmt::Pop { .. }
        | Stmt::Goto { .. }
        | Stmt::Label(_)
        | Stmt::Nop
        | Stmt::Unknown(_)
        | Stmt::Comment(_) => 0,
    }
}

fn lower_region(r: &Region, lf: &LlirFunction) -> Vec<Stmt> {
    match r {
        Region::Block(bi) => lower_block(&lf.blocks[*bi]),
        Region::Seq(parts) => {
            let mut out = Vec::new();
            for p in parts {
                out.extend(lower_region(p, lf));
            }
            out
        }
        Region::IfThen { cond, then_r, .. } => {
            let cond_stmts = lower_block(&lf.blocks[*cond]);
            let (cond_expr, mut pre) = extract_cond_and_strip(&lf.blocks[*cond], cond_stmts);
            let then_stmts = lower_region(then_r, lf);
            pre.push(Stmt::If {
                cond: cond_expr,
                then_body: then_stmts,
                else_body: None,
            });
            pre
        }
        Region::IfThenElse {
            cond,
            then_r,
            else_r,
            ..
        } => {
            let cond_stmts = lower_block(&lf.blocks[*cond]);
            let (cond_expr, mut pre) = extract_cond_and_strip(&lf.blocks[*cond], cond_stmts);
            let then_stmts = lower_region(then_r, lf);
            let else_stmts = lower_region(else_r, lf);
            pre.push(Stmt::If {
                cond: cond_expr,
                then_body: then_stmts,
                else_body: Some(else_stmts),
            });
            pre
        }
        Region::While { header, body, .. } => {
            let cond_stmts = lower_block(&lf.blocks[*header]);
            let (cond_expr, pre) = extract_cond_and_strip(&lf.blocks[*header], cond_stmts);
            let body_stmts = lower_region(body, lf);
            // Any "pre" stmts from the header that weren't the CondJump
            // belong *inside* the loop head — they are the loop-invariant
            // test setup that every iteration re-executes. We emit them
            // once before the while and let the textual printer show the
            // shape; future passes can hoist to a more faithful form.
            let mut out = pre;
            out.push(Stmt::While {
                cond: cond_expr,
                body: body_stmts,
            });
            out
        }
        Region::Unstructured(blocks) => {
            let mut out = Vec::new();
            for &bi in blocks {
                out.push(Stmt::Label(lf.blocks[bi].start_va));
                out.extend(lower_block(&lf.blocks[bi]));
            }
            out
        }
    }
}

/// Lower an entire function given its region tree.
pub fn lower(lf: &LlirFunction, region: &Region, name: impl Into<String>) -> Function {
    let mut f = Function {
        name: name.into(),
        entry_va: lf.entry_va,
        body: lower_region(region, lf),
    };
    fold_returns(&mut f.body);
    f
}

/// Common return registers across the ISAs we currently lift. We use a list
/// rather than a single name so this pass works on both x86/x86-64 and
/// AArch64 without having to thread arch info through the AST.
const RETURN_REGS: &[&str] = &[
    "rax", "eax", "ax", "al",            // x86 / x86-64
    "x0", "w0",                          // AArch64
];

fn is_return_reg(v: &VReg) -> bool {
    matches!(v, VReg::Phys(n) if RETURN_REGS.iter().any(|r| n == *r))
}

/// Collapse `Stmt::Assign { dst: return_reg, src: E }` immediately followed
/// by `Stmt::Return { value: None }` into `Stmt::Return { value: Some(E) }`.
///
/// Recurses into nested If / While bodies. Conservative — only fires on the
/// exact adjacent-pair shape so we never relocate a side-effectful
/// expression.
fn fold_returns(body: &mut Vec<Stmt>) {
    // Recurse first so inner bodies are folded before we inspect an outer
    // fall-through return.
    for s in body.iter_mut() {
        match s {
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                fold_returns(then_body);
                if let Some(eb) = else_body {
                    fold_returns(eb);
                }
            }
            Stmt::While { body, .. } => fold_returns(body),
            _ => {}
        }
    }

    let mut i = 0;
    while i + 1 < body.len() {
        let fold_here = matches!(
            (&body[i], &body[i + 1]),
            (
                Stmt::Assign { dst, .. },
                Stmt::Return { value: None }
            ) if is_return_reg(dst)
        );
        if fold_here {
            let Stmt::Assign { src, .. } = body.remove(i) else {
                unreachable!()
            };
            body[i] = Stmt::Return { value: Some(src) };
        }
        i += 1;
    }
}

// -- Text printer -------------------------------------------------------------

fn binop_sym(op: BinOp) -> &'static str {
    match op {
        BinOp::Add => "+",
        BinOp::Sub => "-",
        BinOp::Mul => "*",
        BinOp::And => "&",
        BinOp::Or => "|",
        BinOp::Xor => "^",
        BinOp::Shl => "<<",
        BinOp::Shr => ">>",
        BinOp::Sar => ">>>",
    }
}

fn unop_sym(op: UnOp) -> &'static str {
    match op {
        UnOp::Not => "~",
        UnOp::Neg => "-",
    }
}

fn cmpop_sym(op: CmpOp) -> &'static str {
    match op {
        CmpOp::Eq => "==",
        CmpOp::Ne => "!=",
        CmpOp::Ult => "u<",
        CmpOp::Slt => "<",
        CmpOp::Sle => "<=",
    }
}

/// True when `src` is of the form `Reg(dst) ± Const`, i.e. a pure
/// self-arithmetic expression on the given stack-pointer register.
fn is_self_arith_on_stack_ptr(dst: &VReg, src: &Expr) -> bool {
    if !matches!(dst, VReg::Phys(n) if n == "rsp" || n == "esp" || n == "sp") {
        return false;
    }
    match src {
        Expr::Bin {
            op: BinOp::Add | BinOp::Sub,
            lhs,
            rhs,
        } => matches!(lhs.as_ref(), Expr::Reg(r) if r == dst)
            && matches!(rhs.as_ref(), Expr::Const(_)),
        _ => false,
    }
}

/// Render `e` without type annotations, but only suppress the prefix on
/// references to `suppress_reg`. Other registers in the expression keep
/// whatever annotation the type map provides (which here is `None`, so
/// nothing extra is printed either way — this reduces to unannotated
/// rendering of the whole subtree).
fn write_expr_no_types_for(e: &Expr, _suppress_reg: &VReg, out: &mut String) {
    write_expr_ctx(e, None, out);
}

fn type_annotation(hint: TypeHint) -> Option<&'static str> {
    match hint {
        TypeHint::Pointer { pointee_width } => Some(match pointee_width {
            1 => "(u8*)",
            2 => "(u16*)",
            4 => "(u32*)",
            _ => "(u64*)",
        }),
        TypeHint::BoolLike => Some("(bool)"),
        TypeHint::CodePointer => Some("(fnptr)"),
        TypeHint::Int { .. } => None, // don't clutter — int is the default
    }
}

fn write_reg_with_type(v: &VReg, tm: Option<&TypeMap>, out: &mut String) {
    if let (Some(tm), VReg::Phys(_)) = (tm, v) {
        if let Some(h) = tm.get(v) {
            if let Some(ann) = type_annotation(h) {
                let _ = write!(out, "{}{}", ann, v);
                return;
            }
        }
    }
    let _ = write!(out, "{}", v);
}

fn write_expr_ctx(e: &Expr, tm: Option<&TypeMap>, out: &mut String) {
    match e {
        Expr::Reg(v) => {
            write_reg_with_type(v, tm, out);
        }
        Expr::Const(c) => {
            // Small constants print in decimal — loop counts, shift amounts,
            // struct-field offsets read better this way. Larger
            // address-like values stay in hex. A few well-known masks
            // surface with a `/*mask*/` comment so the reader sees intent
            // without hunting through `0xff` / `0xffff` / `0xffffffff`.
            if *c == 0 {
                out.push_str("0");
            } else if *c == -1 {
                out.push_str("-1");
            } else if *c >= -4096 && *c <= 4096 {
                let _ = write!(out, "{}", c);
            } else if matches!(*c, 0xff | 0xffff | 0xffff_ffff) {
                let bits = match *c {
                    0xff => 8,
                    0xffff => 16,
                    _ => 32,
                };
                let _ = write!(out, "0x{:x} /*u{}mask*/", c, bits);
            } else if *c < 0 {
                let _ = write!(out, "-0x{:x}", -c);
            } else {
                let _ = write!(out, "0x{:x}", c);
            }
        }
        Expr::Addr(a) => {
            let _ = write!(out, "0x{:x}", a);
        }
        Expr::Named { name, .. } => {
            let _ = write!(out, "{}", name);
        }
        Expr::StringLit { value } => {
            out.push('"');
            for ch in value.chars() {
                match ch {
                    '"' => out.push_str("\\\""),
                    '\\' => out.push_str("\\\\"),
                    '\n' => out.push_str("\\n"),
                    '\r' => out.push_str("\\r"),
                    '\t' => out.push_str("\\t"),
                    '\0' => out.push_str("\\0"),
                    c if (c as u32) < 0x20 || (c as u32) == 0x7f => {
                        let _ = write!(out, "\\x{:02x}", c as u32);
                    }
                    c => out.push(c),
                }
            }
            out.push('"');
        }
        Expr::Lea {
            base,
            index,
            scale,
            disp,
            segment,
        } => {
            if let Some(seg) = segment {
                let _ = write!(out, "{}:", seg);
            }
            out.push('&');
            out.push('[');
            let mut first = true;
            // Inside a Lea, the containing `&[...]` already tells the
            // reader we're forming an address — so the `(u64*)` prefix on
            // base/index is redundant. Print the register name bare.
            if let Some(b) = base {
                let _ = write!(out, "{}", b);
                first = false;
            }
            if let Some(i) = index {
                if !first {
                    out.push('+');
                }
                let _ = write!(out, "{}", i);
                if *scale > 1 {
                    let _ = write!(out, "*{}", scale);
                }
                first = false;
            }
            if *disp != 0 || first {
                if *disp < 0 {
                    let _ = write!(out, "-0x{:x}", -disp);
                } else {
                    if !first {
                        out.push('+');
                    }
                    let _ = write!(out, "0x{:x}", disp);
                }
            }
            out.push(']');
        }
        Expr::Deref { addr, size } => {
            let _ = write!(out, "*(u{})", size * 8);
            write_expr_ctx(addr, tm, out);
        }
        Expr::Bin { op, lhs, rhs } => {
            // Canonicalise sign: `x + -N` prints as `x - N`; `x - -N` as `x + N`.
            let (shown_op, shown_rhs) = match (*op, rhs.as_ref()) {
                (BinOp::Add, Expr::Const(c)) if *c < 0 => (BinOp::Sub, Expr::Const(-c)),
                (BinOp::Sub, Expr::Const(c)) if *c < 0 => (BinOp::Add, Expr::Const(-c)),
                _ => (*op, *rhs.clone()),
            };
            out.push('(');
            write_expr_ctx(lhs, tm, out);
            let _ = write!(out, " {} ", binop_sym(shown_op));
            write_expr_ctx(&shown_rhs, tm, out);
            out.push(')');
        }
        Expr::Un { op, src } => {
            out.push('(');
            let _ = write!(out, "{}", unop_sym(*op));
            write_expr_ctx(src, tm, out);
            out.push(')');
        }
        Expr::Cmp { op, lhs, rhs } => {
            out.push('(');
            write_expr_ctx(lhs, tm, out);
            let _ = write!(out, " {} ", cmpop_sym(*op));
            write_expr_ctx(rhs, tm, out);
            out.push(')');
        }
        Expr::Unknown(s) => {
            let _ = write!(out, "<{}>", s);
        }
    }
}

fn indent(out: &mut String, level: usize) {
    for _ in 0..level {
        out.push_str("    ");
    }
}

fn write_stmt(s: &Stmt, out: &mut String, level: usize) {
    write_stmt_ctx(s, None, out, level);
}

fn write_stmt_ctx(s: &Stmt, tm: Option<&TypeMap>, out: &mut String, level: usize) {
    match s {
        Stmt::Assign { dst, src } => {
            indent(out, level);
            // When the assignment is pure stack-pointer arithmetic
            // (`%rsp = %rsp ± const`), the type annotation on both sides is
            // redundant: it's the same register at the same type. Suppress
            // the prefix on this specific line to cut noise from prologue /
            // epilogue stmt. Other assignments keep their annotations.
            let suppress = is_self_arith_on_stack_ptr(dst, src);
            if suppress {
                let _ = write!(out, "{}", dst);
                out.push_str(" = ");
                write_expr_no_types_for(src, dst, out);
            } else {
                write_reg_with_type(dst, tm, out);
                out.push_str(" = ");
                write_expr_ctx(src, tm, out);
            }
            out.push_str(";\n");
        }
        Stmt::Store { addr, src } => {
            indent(out, level);
            out.push_str("store ");
            write_expr_ctx(addr, tm, out);
            out.push_str(" = ");
            write_expr_ctx(src, tm, out);
            out.push_str(";\n");
        }
        Stmt::Call { target, args } => {
            indent(out, level);
            out.push_str("call ");
            write_expr_ctx(target, tm, out);
            out.push('(');
            for (i, a) in args.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                write_expr_ctx(a, tm, out);
            }
            out.push(')');
            out.push_str(";\n");
        }
        Stmt::Return { value } => {
            indent(out, level);
            match value {
                Some(e) => {
                    out.push_str("return ");
                    write_expr_ctx(e, tm, out);
                    out.push_str(";\n");
                }
                None => out.push_str("return;\n"),
            }
        }
        Stmt::Nop => {
            indent(out, level);
            out.push_str("nop;\n");
        }
        Stmt::Unknown(s) => {
            indent(out, level);
            let _ = writeln!(out, "unknown({});", s);
        }
        Stmt::Comment(s) => {
            indent(out, level);
            let _ = writeln!(out, "// {}", s);
        }
        Stmt::Push { value } => {
            indent(out, level);
            out.push_str("push ");
            write_expr_ctx(value, tm, out);
            out.push_str(";\n");
        }
        Stmt::Pop { target } => {
            indent(out, level);
            out.push_str("pop ");
            write_reg_with_type(target, tm, out);
            out.push_str(";\n");
        }
        Stmt::Label(va) => {
            indent(out, level);
            let _ = writeln!(out, "L_{:x}:", va);
        }
        Stmt::Goto { target } => {
            indent(out, level);
            let _ = writeln!(out, "goto L_{:x};", target);
        }
        Stmt::If {
            cond,
            then_body,
            else_body,
        } => {
            indent(out, level);
            out.push_str("if (");
            write_expr_ctx(cond, tm, out);
            out.push_str(") {\n");
            for s in then_body {
                write_stmt_ctx(s, tm, out, level + 1);
            }
            indent(out, level);
            out.push('}');
            if let Some(eb) = else_body {
                out.push_str(" else {\n");
                for s in eb {
                    write_stmt_ctx(s, tm, out, level + 1);
                }
                indent(out, level);
                out.push('}');
            }
            out.push('\n');
        }
        Stmt::While { cond, body } => {
            indent(out, level);
            out.push_str("while (");
            write_expr_ctx(cond, tm, out);
            out.push_str(") {\n");
            for s in body {
                write_stmt_ctx(s, tm, out, level + 1);
            }
            indent(out, level);
            out.push_str("}\n");
        }
    }
}

impl fmt::Display for Function {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "function {} @ 0x{:x} {{", self.name, self.entry_va)?;
        // Only emit the generic `// frame: N bytes` header if the body
        // doesn't already begin with a prologue-recognition comment that
        // mentions the frame size (avoids duplicating the info on ARM64).
        let has_prologue_comment = body_starts_with_frame_comment(&self.body);
        if !has_prologue_comment {
            if let Some(sz) = compute_frame_size(&self.body) {
                writeln!(f, "    // frame: {} bytes", sz)?;
            }
        }
        let mut out = String::new();
        for s in &self.body {
            write_stmt(s, &mut out, 1);
        }
        f.write_str(&out)?;
        writeln!(f, "}}")
    }
}

fn body_starts_with_frame_comment(body: &[Stmt]) -> bool {
    matches!(body.first(), Some(Stmt::Comment(s)) if s.contains("frame"))
}

/// Convenience — render a function to a stable string.
pub fn render(f: &Function) -> String {
    format!("{}", f)
}

/// Sum up the prologue-phase stack-pointer adjustments in `body`, stopping
/// at the first call / return / structured control flow. Returns `None`
/// when the body doesn't appear to establish a frame.
pub fn compute_frame_size(body: &[Stmt]) -> Option<i64> {
    let mut total: i64 = 0;
    for s in body {
        match s {
            Stmt::Assign {
                dst,
                src:
                    Expr::Bin {
                        op: BinOp::Sub,
                        lhs,
                        rhs,
                    },
            } if is_stack_reg(dst) => {
                if let (Expr::Reg(r), Expr::Const(n)) = (lhs.as_ref(), rhs.as_ref()) {
                    if r == dst {
                        total = total.saturating_add(*n);
                        continue;
                    }
                }
                break;
            }
            Stmt::Assign {
                dst,
                src:
                    Expr::Bin {
                        op: BinOp::Add,
                        lhs,
                        rhs,
                    },
            } if is_stack_reg(dst) => {
                if let (Expr::Reg(r), Expr::Const(n)) = (lhs.as_ref(), rhs.as_ref()) {
                    if r == dst {
                        total = total.saturating_sub(*n);
                        continue;
                    }
                }
                break;
            }
            Stmt::Nop | Stmt::Label(_) | Stmt::Unknown(_) | Stmt::Comment(_) => continue,
            // Each `push` implicitly costs the stack-pointer width (8 on
            // 64-bit). We don't have the width threaded through the AST, so
            // conservatively account for an 8-byte push.
            Stmt::Push { .. } => {
                total = total.saturating_add(8);
                continue;
            }
            Stmt::Pop { .. } => break,
            // Stop at the first real work: a call, return, or structured
            // control flow all mean the prologue is over.
            Stmt::Call { .. }
            | Stmt::Return { .. }
            | Stmt::Goto { .. }
            | Stmt::If { .. }
            | Stmt::While { .. } => break,
            // Register-save stores (e.g. `store %stack_top = %var0`) and
            // unrelated register assigns are part of the prologue and
            // don't change the running frame size — continue walking.
            Stmt::Store { .. } | Stmt::Assign { .. } => continue,
        }
    }
    if total > 0 {
        Some(total)
    } else {
        None
    }
}

fn is_stack_reg(v: &VReg) -> bool {
    matches!(
        v,
        VReg::Phys(n) if n == "rsp" || n == "esp" || n == "sp"
    )
}

/// Render a function in a C-like mode that strips the register-prefix
/// (`%`) and type-annotation clutter present in the default output.
/// Fidelity trade-off: reads closer to C source but drops the
/// register-level detail the plain form preserves.
pub fn render_c(f: &Function) -> String {
    let mut out = String::new();
    // Trimmed header: `fn <name> {` — drop the VA suffix since C readers
    // don't typically care about it in the reading of the body. The VA
    // can still be recovered from the function's `entry_va` field.
    let _ = writeln!(out, "fn {} {{", f.name);
    for s in &f.body {
        write_stmt_c(s, &mut out, 1);
    }
    out.push_str("}\n");
    out
}

fn write_reg_c(v: &VReg, out: &mut String) {
    match v {
        VReg::Phys(n) => out.push_str(n),
        VReg::Temp(i) => {
            let _ = write!(out, "t{}", i);
        }
        VReg::Flag(_) => {
            // Flags still get their `%` prefix — there's no natural C
            // analogue and the leading `%` preserves the "synthetic bit"
            // cue for a reader.
            let _ = write!(out, "{}", v);
        }
    }
}

fn write_expr_c(e: &Expr, out: &mut String) {
    match e {
        Expr::Reg(v) => write_reg_c(v, out),
        Expr::Const(c) => {
            if *c == 0 {
                out.push('0');
            } else if *c == -1 {
                out.push_str("-1");
            } else if *c >= -4096 && *c <= 4096 {
                let _ = write!(out, "{}", c);
            } else if *c < 0 {
                let _ = write!(out, "-0x{:x}", -c);
            } else {
                let _ = write!(out, "0x{:x}", c);
            }
        }
        Expr::Addr(a) => {
            let _ = write!(out, "0x{:x}", a);
        }
        Expr::Named { name, .. } => {
            let _ = write!(out, "{}", name);
        }
        Expr::StringLit { value } => {
            out.push('"');
            for ch in value.chars() {
                match ch {
                    '"' => out.push_str("\\\""),
                    '\\' => out.push_str("\\\\"),
                    '\n' => out.push_str("\\n"),
                    '\r' => out.push_str("\\r"),
                    '\t' => out.push_str("\\t"),
                    '\0' => out.push_str("\\0"),
                    c if (c as u32) < 0x20 || (c as u32) == 0x7f => {
                        let _ = write!(out, "\\x{:02x}", c as u32);
                    }
                    c => out.push(c),
                }
            }
            out.push('"');
        }
        Expr::Lea {
            base,
            index,
            scale,
            disp,
            segment,
        } => {
            if let Some(seg) = segment {
                let _ = write!(out, "{}:", seg);
            }
            out.push('&');
            out.push('[');
            let mut first = true;
            if let Some(b) = base {
                write_reg_c(b, out);
                first = false;
            }
            if let Some(i) = index {
                if !first {
                    out.push('+');
                }
                write_reg_c(i, out);
                if *scale > 1 {
                    let _ = write!(out, "*{}", scale);
                }
                first = false;
            }
            if *disp != 0 || first {
                if *disp < 0 {
                    let _ = write!(out, "-0x{:x}", -disp);
                } else {
                    if !first {
                        out.push('+');
                    }
                    let _ = write!(out, "0x{:x}", disp);
                }
            }
            out.push(']');
        }
        Expr::Deref { addr, .. } => {
            out.push('*');
            write_expr_c(addr, out);
        }
        Expr::Bin { op, lhs, rhs } => {
            let (shown_op, shown_rhs) = match (*op, rhs.as_ref()) {
                (BinOp::Add, Expr::Const(c)) if *c < 0 => (BinOp::Sub, Expr::Const(-c)),
                (BinOp::Sub, Expr::Const(c)) if *c < 0 => (BinOp::Add, Expr::Const(-c)),
                _ => (*op, *rhs.clone()),
            };
            out.push('(');
            write_expr_c(lhs, out);
            let _ = write!(out, " {} ", binop_sym(shown_op));
            write_expr_c(&shown_rhs, out);
            out.push(')');
        }
        Expr::Un { op, src } => {
            out.push('(');
            let _ = write!(out, "{}", unop_sym(*op));
            write_expr_c(src, out);
            out.push(')');
        }
        Expr::Cmp { op, lhs, rhs } => {
            out.push('(');
            write_expr_c(lhs, out);
            let _ = write!(out, " {} ", cmpop_sym(*op));
            write_expr_c(rhs, out);
            out.push(')');
        }
        Expr::Unknown(s) => {
            let _ = write!(out, "<{}>", s);
        }
    }
}

fn write_stmt_c(s: &Stmt, out: &mut String, level: usize) {
    match s {
        Stmt::Assign { dst, src } => {
            indent(out, level);
            write_reg_c(dst, out);
            out.push_str(" = ");
            write_expr_c(src, out);
            out.push_str(";\n");
        }
        Stmt::Store { addr, src } => {
            indent(out, level);
            write_expr_c(addr, out);
            out.push_str(" = ");
            write_expr_c(src, out);
            out.push_str(";\n");
        }
        Stmt::Call { target, args } => {
            indent(out, level);
            write_expr_c(target, out);
            out.push('(');
            for (i, a) in args.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                write_expr_c(a, out);
            }
            out.push_str(");\n");
        }
        Stmt::Return { value } => {
            indent(out, level);
            match value {
                Some(e) => {
                    out.push_str("return ");
                    write_expr_c(e, out);
                    out.push_str(";\n");
                }
                None => out.push_str("return;\n"),
            }
        }
        Stmt::Nop => {
            indent(out, level);
            out.push_str("nop;\n");
        }
        Stmt::Unknown(s) => {
            indent(out, level);
            let _ = writeln!(out, "unknown({});", s);
        }
        Stmt::Comment(s) => {
            indent(out, level);
            let _ = writeln!(out, "// {}", s);
        }
        Stmt::Label(va) => {
            indent(out, level);
            let _ = writeln!(out, "L_{:x}:", va);
        }
        Stmt::Goto { target } => {
            indent(out, level);
            let _ = writeln!(out, "goto L_{:x};", target);
        }
        Stmt::If {
            cond,
            then_body,
            else_body,
        } => {
            indent(out, level);
            out.push_str("if (");
            write_expr_c(cond, out);
            out.push_str(") {\n");
            for s in then_body {
                write_stmt_c(s, out, level + 1);
            }
            indent(out, level);
            out.push('}');
            if let Some(eb) = else_body {
                out.push_str(" else {\n");
                for s in eb {
                    write_stmt_c(s, out, level + 1);
                }
                indent(out, level);
                out.push('}');
            }
            out.push('\n');
        }
        Stmt::While { cond, body } => {
            indent(out, level);
            out.push_str("while (");
            write_expr_c(cond, out);
            out.push_str(") {\n");
            for s in body {
                write_stmt_c(s, out, level + 1);
            }
            indent(out, level);
            out.push_str("}\n");
        }
        Stmt::Push { value } => {
            indent(out, level);
            out.push_str("push(");
            write_expr_c(value, out);
            out.push_str(");\n");
        }
        Stmt::Pop { target } => {
            indent(out, level);
            out.push_str("pop(");
            write_reg_c(target, out);
            out.push_str(");\n");
        }
    }
}

/// Render a function using the provided [`TypeMap`] for register-level
/// type annotations. Pointers print as `(u64*)%rbx`, booleans as `(bool)`,
/// code pointers as `(fnptr)`. Non-inferred registers print unchanged.
pub fn render_with_types(f: &Function, tm: &TypeMap) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "function {} @ 0x{:x} {{", f.name, f.entry_va);
    if !body_starts_with_frame_comment(&f.body) {
        if let Some(sz) = compute_frame_size(&f.body) {
            let _ = writeln!(out, "    // frame: {} bytes", sz);
        }
    }
    for s in &f.body {
        write_stmt_ctx(s, Some(tm), &mut out, 1);
    }
    out.push_str("}\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::ssa::compute_ssa;
    use crate::ir::structure::recover;
    use crate::ir::types::{Flag, LlirBlock, LlirInstr, VReg};

    fn mk_cfg(spec: Vec<(u64, Vec<Op>, Vec<u64>)>) -> LlirFunction {
        let entry_va = spec.first().map(|(s, _, _)| *s).unwrap_or(0);
        let blocks = spec
            .into_iter()
            .map(|(start_va, ops, succs)| LlirBlock {
                start_va,
                end_va: start_va + 0x100,
                instrs: ops
                    .into_iter()
                    .enumerate()
                    .map(|(j, op)| LlirInstr {
                        va: start_va + (j as u64) * 4,
                        op,
                    })
                    .collect(),
                succs,
            })
            .collect();
        LlirFunction { entry_va, blocks }
    }

    fn lower_and_render(lf: &LlirFunction, name: &str) -> String {
        let ssa = compute_ssa(lf);
        let r = recover(lf, &ssa);
        render(&lower(lf, &r, name))
    }

    #[test]
    fn straight_line_renders_as_linear_stmts() {
        // `%rax = 1; ret` — the return-value folding pass collapses the
        // preceding assignment into `return 1;`.
        let lf = mk_cfg(vec![(
            0x1000,
            vec![
                Op::Assign {
                    dst: VReg::phys("rax"),
                    src: Value::Const(1),
                },
                Op::Return,
            ],
            vec![],
        )]);
        let text = lower_and_render(&lf, "f");
        let expected = "\
function f @ 0x1000 {
    return 1;
}
";
        assert_eq!(text, expected);
    }

    #[test]
    fn return_fold_does_not_touch_non_return_regs() {
        // `%rbx = 1; ret` — %rbx is not a return register, so the fold must
        // leave both statements alone.
        let lf = mk_cfg(vec![(
            0x1000,
            vec![
                Op::Assign {
                    dst: VReg::phys("rbx"),
                    src: Value::Const(1),
                },
                Op::Return,
            ],
            vec![],
        )]);
        let text = lower_and_render(&lf, "f");
        assert!(text.contains("%rbx = 1;"), "fold ate non-return reg: {}", text);
        assert!(text.contains("return;"), "return line missing: {}", text);
        assert!(!text.contains("return 1"), "folded wrong reg: {}", text);
    }

    #[test]
    fn return_fold_detects_arm64_x0() {
        // `%x0 = 42; ret` — AArch64 return reg is x0.
        let lf = mk_cfg(vec![(
            0x1000,
            vec![
                Op::Assign {
                    dst: VReg::phys("x0"),
                    src: Value::Const(42),
                },
                Op::Return,
            ],
            vec![],
        )]);
        let text = lower_and_render(&lf, "f");
        assert!(text.contains("return 42;"), "arm64 return fold failed: {}", text);
    }

    #[test]
    fn cmp_is_hoisted_into_if_condition() {
        // B0 does `cmp rax, 0; je B1` then branches. Both arms merge at B3
        // (a diamond), which lets the structural pass recognise an
        // if-then-else.
        let lf = mk_cfg(vec![
            (
                0x1000,
                vec![
                    Op::Cmp {
                        dst: VReg::Flag(Flag::Z),
                        op: CmpOp::Eq,
                        lhs: Value::Reg(VReg::phys("rax")),
                        rhs: Value::Const(0),
                    },
                    Op::CondJump {
                        cond: VReg::Flag(Flag::Z),
                        target: 0x1100,
                    },
                ],
                vec![0x1100, 0x1200],
            ),
            (0x1100, vec![Op::Nop], vec![0x1300]),
            (0x1200, vec![Op::Nop], vec![0x1300]),
            (0x1300, vec![Op::Return], vec![]),
        ]);
        let text = lower_and_render(&lf, "f");
        // The opaque `if (%zf)` must have been replaced by the real compare.
        assert!(
            text.contains("if ((%rax == 0))"),
            "cmp was not hoisted: {}",
            text
        );
        assert!(!text.contains("if (%zf)"), "still opaque: {}", text);
        // The `%zf = ...` definition should be stripped.
        assert!(!text.contains("%zf ="), "flag assign leaked: {}", text);
    }

    #[test]
    fn diamond_lowers_to_if_else() {
        //    B0: cmp-like (ends in CondJump to B1 target, else falls to B2)
        //   /       \
        //  B1 body   B2 body
        //   \       /
        //    B3: return
        let lf = mk_cfg(vec![
            (
                0x1000,
                vec![
                    Op::Cmp {
                        dst: VReg::Flag(Flag::Z),
                        op: CmpOp::Eq,
                        lhs: Value::Reg(VReg::phys("rax")),
                        rhs: Value::Const(0),
                    },
                    Op::CondJump {
                        cond: VReg::Flag(Flag::Z),
                        target: 0x1100,
                    },
                ],
                vec![0x1100, 0x1200],
            ),
            (
                0x1100,
                vec![Op::Assign {
                    dst: VReg::phys("rbx"),
                    src: Value::Const(1),
                }],
                vec![0x1300],
            ),
            (
                0x1200,
                vec![Op::Assign {
                    dst: VReg::phys("rbx"),
                    src: Value::Const(2),
                }],
                vec![0x1300],
            ),
            (0x1300, vec![Op::Return], vec![]),
        ]);
        let text = lower_and_render(&lf, "f");
        // After Cmp hoisting, the condition reads the actual comparison.
        assert!(
            text.contains("if ((%rax == 0))"),
            "cmp not hoisted: {}",
            text
        );
        assert!(text.contains("} else {"), "no else in: {}", text);
        // Each arm contains the branch-specific assignment.
        assert!(text.contains("%rbx = 1;"), "missing then-body in: {}", text);
        assert!(text.contains("%rbx = 2;"), "missing else-body in: {}", text);
        assert!(text.contains("return;"), "missing return in: {}", text);
    }

    #[test]
    fn while_loop_lowers_to_while_stmt() {
        // Entry → Header{cond, CondJump body}, Body → Header, Exit: return.
        let lf = mk_cfg(vec![
            (0x1000, vec![Op::Nop], vec![0x1100]),
            (
                0x1100,
                vec![
                    Op::Cmp {
                        dst: VReg::Flag(Flag::Z),
                        op: CmpOp::Eq,
                        lhs: Value::Reg(VReg::phys("rax")),
                        rhs: Value::Const(0),
                    },
                    Op::CondJump {
                        cond: VReg::Flag(Flag::Z),
                        target: 0x1200,
                    },
                ],
                vec![0x1200, 0x1300],
            ),
            (
                0x1200,
                vec![Op::Bin {
                    dst: VReg::phys("rax"),
                    op: BinOp::Sub,
                    lhs: Value::Reg(VReg::phys("rax")),
                    rhs: Value::Const(1),
                }],
                vec![0x1100],
            ),
            (0x1300, vec![Op::Return], vec![]),
        ]);
        let text = lower_and_render(&lf, "loop_demo");
        assert!(
            text.contains("while ((%rax == 0))"),
            "cmp not hoisted into while: {}",
            text
        );
        assert!(
            text.contains("%rax = (%rax - 1);"),
            "missing body in: {}",
            text
        );
        assert!(text.contains("return;"));
    }

    #[test]
    fn frame_size_summary_appears_when_stack_is_adjusted() {
        // sub rsp, 0x20 ; ret  -> should emit "// frame: 32 bytes".
        let lf = mk_cfg(vec![(
            0x1000,
            vec![
                Op::Bin {
                    dst: VReg::phys("rsp"),
                    op: crate::ir::types::BinOp::Sub,
                    lhs: Value::Reg(VReg::phys("rsp")),
                    rhs: Value::Const(0x20),
                },
                Op::Return,
            ],
            vec![],
        )]);
        let text = lower_and_render(&lf, "f");
        assert!(text.contains("// frame: 32 bytes"), "got: {}", text);
    }

    #[test]
    fn frame_size_absent_when_no_stack_adjustment() {
        let lf = mk_cfg(vec![(0x1000, vec![Op::Return], vec![])]);
        let text = lower_and_render(&lf, "f");
        assert!(!text.contains("// frame"), "got: {}", text);
    }

    #[test]
    fn unknown_op_surfaces_as_unknown_stmt() {
        let lf = mk_cfg(vec![(
            0x1000,
            vec![
                Op::Unknown {
                    mnemonic: "leave".into(),
                },
                Op::Return,
            ],
            vec![],
        )]);
        let text = lower_and_render(&lf, "f");
        assert!(text.contains("unknown(leave);"), "got: {}", text);
    }

    #[test]
    fn render_with_types_annotates_pointer_and_bool() {
        use crate::ir::types::{MemOp, VReg};
        use crate::ir::types_recover::recover_types;
        // Two ops: `rax = load [rbp+0]` makes rbp a pointer, `cmp rcx, 0`
        // makes rcx bool-like. Render should annotate both.
        let lf = mk_cfg(vec![(
            0x1000,
            vec![
                Op::Load {
                    dst: VReg::phys("rax"),
                    addr: MemOp {
                        base: Some(VReg::phys("rbp")),
                        index: None,
                        scale: 0,
                        disp: 0,
                        size: 8,
                        ..Default::default()
                    },
                },
                Op::Cmp {
                    dst: VReg::Flag(Flag::Z),
                    op: CmpOp::Eq,
                    lhs: Value::Reg(VReg::phys("rcx")),
                    rhs: Value::Const(0),
                },
                Op::Return,
            ],
            vec![],
        )]);
        let ssa = compute_ssa(&lf);
        let r = recover(&lf, &ssa);
        let f = lower(&lf, &r, "f");
        let tm = recover_types(&lf);
        let text = render_with_types(&f, &tm);
        // Bool annotation survives on top-level `Expr::Reg` (inside a Cmp).
        assert!(text.contains("(bool)%rcx"), "bool not annotated: {}", text);
        // Pointer annotation is suppressed inside Lea-subexpressions (the
        // surrounding `&[...]` already conveys "this is an address"), so
        // the `(u64*)` prefix does NOT appear in a deref of `[%rbp]`.
        assert!(
            !text.contains("(u64*)%rbp"),
            "Lea base should not carry redundant pointer prefix: {}",
            text
        );
        // Plain render() must still work and not leak annotations.
        let plain = render(&f);
        assert!(!plain.contains("(u64*)"), "plain render leaked annotations: {}", plain);
        assert!(!plain.contains("(bool)"), "plain render leaked annotations: {}", plain);
    }

    #[test]
    fn real_binary_lowers_without_panic() {
        use crate::analysis::cfg::{analyze_functions_bytes, Budgets};
        use crate::core::binary::Arch;
        use crate::ir::lift_function::lift_function_from_bytes;
        let path = std::path::Path::new(
            "samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-gcc-O2",
        );
        if !path.exists() {
            return;
        }
        let data = std::fs::read(path).unwrap();
        let (funcs, _cg) = analyze_functions_bytes(
            &data,
            &Budgets {
                max_functions: 4,
                max_blocks: 128,
                max_instructions: 2000,
                timeout_ms: 500,
            },
        );
        for f in &funcs {
            if let Some(lf) = lift_function_from_bytes(&data, f, Arch::X86_64) {
                let ssa = compute_ssa(&lf);
                let r = recover(&lf, &ssa);
                let ast = lower(&lf, &r, f.name.clone());
                let text = render(&ast);
                assert!(text.starts_with("function "));
                assert!(text.trim_end().ends_with('}'));
                // Sanity: something substantive came through.
                assert!(text.len() > 30, "pseudocode too short: {}", text);
            }
        }
    }
}
