//! The generic, type-annotated ("ctx") expression and statement printer.
//!
//! [`render`] and [`render_with_types`] are this module's front doors:
//! `render` is the plain `%reg`-syntax renderer used throughout lowering and
//! its own test suite (`crate::ir::ast::render`), and `render_with_types` is
//! the same shape with [`TypeMap`]-derived annotations (`(u64*)%rbx`,
//! `(bool)%al`, `(fnptr)%rax`, ...) layered on — it is production-used from
//! three call sites in `python_bindings/ir.rs`. Both stay reachable at their
//! old `crate::ir::ast::` paths via the `pub use` re-export below; neither
//! changed visibility, since both were already `pub fn` before the move.
//!
//! This is distinct from the untyped "c" renderer (`render_c`, still in the
//! parent module), which strips the `%` prefix and type annotations for a
//! more C-source-like read, and from the typed "dec" renderer
//! (`dec_render`), which declares locals and emits full compilable C.
//!
//! A few helpers that look like they belong here stay in the parent module
//! instead, because the call graph — not their physical position in the old
//! file — says they are shared:
//! - [`call_target_name`](super::call_target_name) and
//!   [`write_call_proto_hint`](super::write_call_proto_hint) are also called
//!   from the untyped C renderer's `write_stmt_c`.
//! - `one_armed_select` is also called from `write_stmt_c`.
//! - `binop_sym`, `cmpop_sym`, and `unop_sym` are also called from
//!   `write_expr_c`.
//! - `int_ctype` is also called from `write_expr_c` and from the
//!   type-recovery helpers further down the parent module.
//! - `write_float_literal` and `write_pdb_field_hints` are also called from
//!   `write_expr_c` and from the dec renderer.
//! - `indent` is shared by every renderer in the file.
//!
//! Splitting those out too would either widen the newly-public surface
//! between this module and its parent for no reader benefit, or pull in
//! code the c/dec renderers still need.

use std::fmt::{self, Write};

use crate::ir::types::{BinOp, VReg};
use crate::ir::types_recover::{TypeHint, TypeMap};

use super::{
    binop_sym, cmpop_sym, indent, int_ctype, one_armed_select, unop_sym, write_call_proto_hint,
    write_float_literal, write_pdb_field_hints, Expr, Function, Stmt,
};

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
        } => {
            matches!(lhs.as_ref(), Expr::Reg(r) if r == dst)
                && matches!(rhs.as_ref(), Expr::Const(_))
        }
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
        TypeHint::Float { width: 4 } => Some("(float)"),
        TypeHint::Float { .. } => Some("(double)"),
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
                let _ = write!(out, "-0x{:x}", c.unsigned_abs());
            } else {
                let _ = write!(out, "0x{:x}", c);
            }
        }
        Expr::FloatConst { bits, width } => write_float_literal(*bits, *width, out),
        Expr::Addr(a) => {
            let _ = write!(out, "0x{:x}", a);
        }
        Expr::Named { name, .. } => {
            let _ = write!(out, "{}", name);
        }
        Expr::FunctionTableEntry {
            table_name, index, ..
        } => {
            let _ = write!(out, "{}[", table_name);
            write_expr_ctx(index, tm, out);
            out.push(']');
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
        Expr::StackAddr { object, .. } => {
            out.push('&');
            write_reg_with_type(object, tm, out);
        }
        Expr::Lea {
            base,
            index,
            scale,
            disp,
            segment,
        }
        | Expr::PdbFieldAddr {
            base,
            index,
            scale,
            disp,
            segment,
            ..
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
                    let _ = write!(out, "-0x{:x}", disp.unsigned_abs());
                } else {
                    if !first {
                        out.push('+');
                    }
                    let _ = write!(out, "0x{:x}", disp);
                }
            }
            out.push(']');
            if let Expr::PdbFieldAddr { hints, .. } = e {
                write_pdb_field_hints(hints, out);
            }
        }
        Expr::Deref { addr, size } => {
            let _ = write!(out, "*(u{})", size * 8);
            write_expr_ctx(addr, tm, out);
        }
        Expr::Call { target, args, .. } => {
            write_expr_ctx(target, tm, out);
            out.push('(');
            for (index, argument) in args.iter().enumerate() {
                if index > 0 {
                    out.push_str(", ");
                }
                write_expr_ctx(argument, tm, out);
            }
            out.push(')');
        }
        Expr::Bin { op, lhs, rhs } => {
            // Canonicalise sign: `x + -N` prints as `x - N`; `x - -N` as `x + N`.
            let (shown_op, shown_rhs) = match (*op, rhs.as_ref()) {
                (BinOp::Add, Expr::Const(c)) if *c < 0 && *c != i64::MIN => {
                    (BinOp::Sub, Expr::Const(-c))
                }
                (BinOp::Sub, Expr::Const(c)) if *c < 0 && *c != i64::MIN => {
                    (BinOp::Add, Expr::Const(-c))
                }
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
        Expr::Cast {
            signed,
            width,
            expr,
        } => {
            let _ = write!(out, "({})(", int_ctype(*signed, *width));
            write_expr_ctx(expr, tm, out);
            out.push(')');
        }
        Expr::NumericConvert { to, expr, .. } => {
            let _ = write!(out, "({})(", to.c_name());
            write_expr_ctx(expr, tm, out);
            out.push(')');
        }
        Expr::Cmp { op, lhs, rhs } => {
            out.push('(');
            write_expr_ctx(lhs, tm, out);
            let _ = write!(out, " {} ", cmpop_sym(*op));
            write_expr_ctx(rhs, tm, out);
            out.push(')');
        }
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => {
            out.push('(');
            write_expr_ctx(cond, tm, out);
            out.push_str(" ? ");
            write_expr_ctx(if_true, tm, out);
            out.push_str(" : ");
            write_expr_ctx(if_false, tm, out);
            out.push(')');
        }
        Expr::WideArithmetic { op, args, width } => {
            let _ = write!(out, "{}{}(", op.name(), width * 8);
            for (index, argument) in args.iter().enumerate() {
                if index > 0 {
                    out.push_str(", ");
                }
                write_expr_ctx(argument, tm, out);
            }
            out.push(')');
        }
        Expr::Unknown(s) => {
            let _ = write!(out, "<{}>", s);
        }
    }
}

fn write_stmt(s: &Stmt, out: &mut String, level: usize) {
    write_stmt_ctx(s, None, out, level);
}

fn write_for_clause(s: &Stmt, tm: Option<&TypeMap>, out: &mut String) {
    match s {
        Stmt::Assign { dst, src } => {
            write_reg_with_type(dst, tm, out);
            out.push_str(" = ");
            write_expr_ctx(src, tm, out);
        }
        Stmt::Store { addr, src, .. } => {
            write_expr_ctx(addr, tm, out);
            out.push_str(" = ");
            write_expr_ctx(src, tm, out);
        }
        _ => out.push_str("/* unsupported for-clause */"),
    }
}

fn write_stmt_ctx(s: &Stmt, tm: Option<&TypeMap>, out: &mut String, level: usize) {
    match s {
        Stmt::Assign { dst, src } => {
            if level > 1 {
                if let Expr::Select {
                    cond,
                    if_true,
                    if_false,
                    ..
                } = src
                {
                    indent(out, level);
                    out.push_str("if (");
                    write_expr_ctx(cond, tm, out);
                    out.push_str(") {\n");
                    indent(out, level + 1);
                    write_reg_with_type(dst, tm, out);
                    out.push_str(" = ");
                    write_expr_ctx(if_true, tm, out);
                    out.push_str(";\n");
                    indent(out, level);
                    out.push_str("} else {\n");
                    indent(out, level + 1);
                    write_reg_with_type(dst, tm, out);
                    out.push_str(" = ");
                    write_expr_ctx(if_false, tm, out);
                    out.push_str(";\n");
                    indent(out, level);
                    out.push_str("}\n");
                    return;
                }
            }
            if let Some((cond, init, update, inverted)) = one_armed_select(dst, src) {
                indent(out, level);
                write_reg_with_type(dst, tm, out);
                out.push_str(" = ");
                write_expr_ctx(init, tm, out);
                out.push_str(";\n");
                indent(out, level);
                out.push_str(if inverted { "if (!(" } else { "if (" });
                write_expr_ctx(cond, tm, out);
                out.push_str(if inverted { ")) {\n" } else { ") {\n" });
                indent(out, level + 1);
                write_reg_with_type(dst, tm, out);
                out.push_str(" = ");
                write_expr_ctx(update, tm, out);
                out.push_str(";\n");
                indent(out, level);
                out.push_str("}\n");
                return;
            }
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
        Stmt::Store { addr, src, .. } => {
            indent(out, level);
            out.push_str("store ");
            write_expr_ctx(addr, tm, out);
            out.push_str(" = ");
            write_expr_ctx(src, tm, out);
            out.push_str(";\n");
        }
        Stmt::Call { target, args, .. } => {
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
            out.push(';');
            write_call_proto_hint(target, out);
            out.push('\n');
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
        Stmt::Break => {
            indent(out, level);
            out.push_str("break;\n");
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
        // A computed transfer the structurer could not turn into a `switch`.
        // Emitted as a comment, not as code: there is no C for "jump wherever
        // this register points", and the previous modelling (an indirect call
        // whose result was assigned and dropped) rendered as something that
        // compiles and reads as understood, which is worse than admitting the
        // gap.
        Stmt::IndirectGoto { target } => {
            indent(out, level);
            out.push_str("/* unrecovered indirect jump through ");
            write_expr_ctx(target, tm, out);
            out.push_str(" */\n");
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
        Stmt::For {
            init,
            cond,
            step,
            body,
        } => {
            indent(out, level);
            out.push_str("for (");
            write_for_clause(init, tm, out);
            out.push_str("; ");
            write_expr_ctx(cond, tm, out);
            out.push_str("; ");
            write_for_clause(step, tm, out);
            out.push_str(") {\n");
            for s in body {
                write_stmt_ctx(s, tm, out, level + 1);
            }
            indent(out, level);
            out.push_str("}\n");
        }
        Stmt::DoWhile { body, cond } => {
            indent(out, level);
            out.push_str("do {\n");
            for s in body {
                write_stmt_ctx(s, tm, out, level + 1);
            }
            indent(out, level);
            out.push_str("} while (");
            write_expr_ctx(cond, tm, out);
            out.push_str(");\n");
        }
        Stmt::Switch {
            discriminant,
            cases,
            default,
        } => {
            indent(out, level);
            out.push_str("switch (");
            write_expr_ctx(discriminant, tm, out);
            out.push_str(") {\n");
            for (label, body) in cases {
                indent(out, level + 1);
                if let Some(n) = label {
                    out.push_str(&format!("case {}:\n", n));
                } else {
                    out.push_str("case _:\n");
                }
                for s in body {
                    write_stmt_ctx(s, tm, out, level + 2);
                }
                indent(out, level + 2);
                out.push_str("break;\n");
            }
            if let Some(def_body) = default {
                indent(out, level + 1);
                out.push_str("default:\n");
                for s in def_body {
                    write_stmt_ctx(s, tm, out, level + 2);
                }
                indent(out, level + 2);
                out.push_str("break;\n");
            }
            indent(out, level);
            out.push_str("}\n");
        }
        Stmt::Throw { value } => {
            indent(out, level);
            out.push_str("throw ");
            write_expr_ctx(value, tm, out);
            out.push_str(";\n");
        }
        Stmt::TryCatch { try_body, catches } => {
            indent(out, level);
            out.push_str("try {\n");
            for statement in try_body {
                write_stmt_ctx(statement, tm, out, level + 1);
            }
            indent(out, level);
            out.push('}');
            for catch in catches {
                out.push_str(" catch (");
                out.push_str(&catch.type_name);
                out.push(' ');
                write_reg_with_type(&catch.binding, tm, out);
                out.push_str(") {\n");
                for statement in &catch.body {
                    write_stmt_ctx(statement, tm, out, level + 1);
                }
                indent(out, level);
                out.push('}');
            }
            out.push('\n');
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
            Stmt::Nop
            | Stmt::Label(_)
            | Stmt::Unknown(_)
            | Stmt::Comment(_)
            | Stmt::IndirectGoto { .. } => continue,
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
            | Stmt::Break
            | Stmt::If { .. }
            | Stmt::While { .. }
            | Stmt::For { .. }
            | Stmt::DoWhile { .. }
            | Stmt::Switch { .. }
            | Stmt::Throw { .. }
            | Stmt::TryCatch { .. } => break,
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
