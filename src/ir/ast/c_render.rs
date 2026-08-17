//! The untyped, register-level ("c") expression and statement printer.
//!
//! [`render_c`] is this module's front door: a `%reg`-syntax-stripped,
//! C-source-like reading aid (`fn name { ... }`), as opposed to the plain
//! [`super::render`] (which keeps the `%` prefix) or the typed renderers
//! (`ctx_render`'s type-annotated form, `dec_render`'s compilable C). It is
//! `pub fn` before this move and stays reachable at its old
//! `crate::ir::ast::render_c` path via the `pub use` re-export below;
//! visibility did not change, since it was already `pub fn`. It is
//! production-used from `python_bindings/ir.rs`.
//!
//! A few helpers that look like they belong here stay in the parent module
//! instead, because the call graph — not their physical position in the old
//! file — says they are shared:
//! - [`indent`](super::indent), [`one_armed_select`](super::one_armed_select),
//!   [`binop_sym`](super::binop_sym), [`cmpop_sym`](super::cmpop_sym),
//!   [`unop_sym`](super::unop_sym), [`int_ctype`](super::int_ctype),
//!   [`write_float_literal`](super::write_float_literal),
//!   [`write_pdb_field_hints`](super::write_pdb_field_hints),
//!   [`write_call_proto_hint`](super::write_call_proto_hint), and
//!   [`write_unit_step`](super::write_unit_step) are also called from the ctx
//!   and/or dec renderers.
//! - `binop_sym_c` and `cmpop_sym_c` — despite sitting at the end of this
//!   renderer's old contiguous block, right after `write_for_clause_c` — stay
//!   in the parent module too: the dec renderer's `write_expr_dec` and
//!   `write_stmt_dec` call both directly (`super::{binop_sym_c, cmpop_sym_c}`
//!   in `dec_render.rs`'s import list), so they are shared vocabulary between
//!   this renderer and `dec_render`, not private helpers of `write_expr_c`
//!   alone. Moving them would have meant either widening their visibility to
//!   `pub(super)` so `dec_render` could reach them through a re-export, or
//!   leaving them where the call graph already lets every renderer see them
//!   for free — the latter costs nothing.
//!
//! Splitting those out too would either widen the newly-public surface
//! between this module and its parent for no reader benefit, or pull in code
//! the dec/ctx renderers still need.

use std::fmt::Write;

use crate::ir::types::{BinOp, VReg};

use super::{
    binop_sym, cmpop_sym, indent, int_ctype, one_armed_select, unop_sym, write_call_proto_hint,
    write_float_literal, write_pdb_field_hints, write_unit_step, Expr, Function, Stmt,
};

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
        VReg::Flag(_) | VReg::FlagValue { .. } => {
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
            write_expr_c(index, out);
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
            write_reg_c(object, out);
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
        Expr::Deref { addr, .. } => {
            out.push('*');
            write_expr_c(addr, out);
        }
        Expr::Call { target, args, .. } => {
            write_expr_c(target, out);
            out.push('(');
            for (index, argument) in args.iter().enumerate() {
                if index > 0 {
                    out.push_str(", ");
                }
                write_expr_c(argument, out);
            }
            out.push(')');
        }
        Expr::Bin { op, lhs, rhs } => {
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
        Expr::Cast {
            signed,
            width,
            expr,
        } => {
            let _ = write!(out, "({})(", int_ctype(*signed, *width));
            write_expr_c(expr, out);
            out.push(')');
        }
        Expr::NumericConvert { to, expr, .. } => {
            let _ = write!(out, "({})(", to.c_name());
            write_expr_c(expr, out);
            out.push(')');
        }
        Expr::Cmp { op, lhs, rhs } => {
            out.push('(');
            write_expr_c(lhs, out);
            let _ = write!(out, " {} ", cmpop_sym(*op));
            write_expr_c(rhs, out);
            out.push(')');
        }
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => {
            out.push('(');
            write_expr_c(cond, out);
            out.push_str(" ? ");
            write_expr_c(if_true, out);
            out.push_str(" : ");
            write_expr_c(if_false, out);
            out.push(')');
        }
        Expr::WideArithmetic { op, args, width } => {
            let _ = write!(out, "{}{}(", op.name(), width * 8);
            for (index, argument) in args.iter().enumerate() {
                if index > 0 {
                    out.push_str(", ");
                }
                write_expr_c(argument, out);
            }
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
                    write_expr_c(cond, out);
                    out.push_str(") {\n");
                    indent(out, level + 1);
                    write_reg_c(dst, out);
                    out.push_str(" = ");
                    write_expr_c(if_true, out);
                    out.push_str(";\n");
                    indent(out, level);
                    out.push_str("} else {\n");
                    indent(out, level + 1);
                    write_reg_c(dst, out);
                    out.push_str(" = ");
                    write_expr_c(if_false, out);
                    out.push_str(";\n");
                    indent(out, level);
                    out.push_str("}\n");
                    return;
                }
            }
            if let Some((cond, init, update, inverted)) = one_armed_select(dst, src) {
                indent(out, level);
                write_reg_c(dst, out);
                out.push_str(" = ");
                write_expr_c(init, out);
                out.push_str(";\n");
                indent(out, level);
                out.push_str(if inverted { "if (!(" } else { "if (" });
                write_expr_c(cond, out);
                out.push_str(if inverted { ")) {\n" } else { ") {\n" });
                indent(out, level + 1);
                write_reg_c(dst, out);
                out.push_str(" = ");
                write_expr_c(update, out);
                out.push_str(";\n");
                indent(out, level);
                out.push_str("}\n");
                return;
            }
            indent(out, level);
            write_reg_c(dst, out);
            out.push_str(" = ");
            write_expr_c(src, out);
            out.push_str(";\n");
        }
        Stmt::Store { addr, src, .. } => {
            indent(out, level);
            write_expr_c(addr, out);
            out.push_str(" = ");
            write_expr_c(src, out);
            out.push_str(";\n");
        }
        Stmt::Call {
            target, args, dst, ..
        } => {
            indent(out, level);
            if let Some(d) = dst {
                write_reg_c(d, out);
                out.push_str(" = ");
            }
            write_expr_c(target, out);
            out.push('(');
            for (i, a) in args.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                write_expr_c(a, out);
            }
            out.push_str(");");
            write_call_proto_hint(target, out);
            out.push('\n');
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
            write_expr_c(target, out);
            out.push_str(" */\n");
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
        Stmt::For {
            init,
            cond,
            step,
            body,
        } => {
            indent(out, level);
            out.push_str("for (");
            write_for_clause_c(init, out, false);
            out.push_str("; ");
            write_expr_c(cond, out);
            out.push_str("; ");
            write_for_clause_c(step, out, true);
            out.push_str(") {\n");
            for s in body {
                write_stmt_c(s, out, level + 1);
            }
            indent(out, level);
            out.push_str("}\n");
        }
        Stmt::DoWhile { body, cond } => {
            indent(out, level);
            out.push_str("do {\n");
            for s in body {
                write_stmt_c(s, out, level + 1);
            }
            indent(out, level);
            out.push_str("} while (");
            write_expr_c(cond, out);
            out.push_str(");\n");
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
        Stmt::Switch {
            discriminant,
            cases,
            default,
        } => {
            indent(out, level);
            out.push_str("switch (");
            write_expr_c(discriminant, out);
            out.push_str(") {\n");
            for (label, body) in cases {
                indent(out, level + 1);
                if let Some(n) = label {
                    let _ = writeln!(out, "case {}:", n);
                } else {
                    out.push_str("case _:\n");
                }
                for s in body {
                    write_stmt_c(s, out, level + 2);
                }
                indent(out, level + 2);
                out.push_str("break;\n");
            }
            if let Some(def_body) = default {
                indent(out, level + 1);
                out.push_str("default:\n");
                for s in def_body {
                    write_stmt_c(s, out, level + 2);
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
            write_expr_c(value, out);
            out.push_str(";\n");
        }
        Stmt::TryCatch { try_body, catches } => {
            indent(out, level);
            out.push_str("try {\n");
            for statement in try_body {
                write_stmt_c(statement, out, level + 1);
            }
            indent(out, level);
            out.push('}');
            for catch in catches {
                out.push_str(" catch (");
                out.push_str(&catch.type_name);
                out.push(' ');
                write_reg_c(&catch.binding, out);
                out.push_str(") {\n");
                for statement in &catch.body {
                    write_stmt_c(statement, out, level + 1);
                }
                indent(out, level);
                out.push('}');
            }
            out.push('\n');
        }
    }
}

fn write_for_clause_c(s: &Stmt, out: &mut String, prefer_increment: bool) {
    let (dst, src) = match s {
        Stmt::Assign { dst, src } => (dst, src),
        Stmt::Store {
            addr: Expr::Reg(dst),
            src,
            ..
        } => (dst, src),
        _ => {
            out.push_str("/* unsupported for-clause */");
            return;
        }
    };
    if prefer_increment && write_unit_step(dst, src, out, write_reg_c, false) {
        return;
    }
    write_reg_c(dst, out);
    out.push_str(" = ");
    write_expr_c(src, out);
}
