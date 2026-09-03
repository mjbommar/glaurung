//! The typed C ("dec") **statement** printer.
//!
//! The other half of the `dec_render` split. Its parent module prints
//! expressions; this module prints the statements those expressions sit
//! inside, and it is the module that owns
//! [`write_stmt_dec`] -- the single entry point the DecBench front door
//! ([`render_decbench_typed_with_output_and_prototype_and_dwarf_types_and_local_types`](crate::ir::ast))
//! calls once per top-level statement.
//!
//! The boundary is the call graph, not the file layout. Every function here
//! is reachable from `write_stmt_dec` and from nothing else; nothing in the
//! parent module calls into this one except through the re-exported
//! `write_stmt_dec`. The dependency runs strictly upward: the expression
//! printer is a closed sub-graph that never calls a statement printer, so
//! this module names twelve of the parent's functions and the parent names
//! none of ours. Being a *descendant* of `dec_render` is what makes that
//! free -- a child module already sees its parent's private items, so the
//! split widens nothing.
//!
//! Two functions that only `write_stmt_dec` calls deliberately stayed in the
//! parent anyway, because leaving a callee behind costs nothing while moving
//! it would split a family:
//!
//! - `dec_is_wide_local` is one of the five render-scoped thread-local
//!   accessors (`DEC_WIDE_LOCALS` and friends) that sit together at the top
//!   of `dec_render`; moving one of the five would scatter the accessor
//!   block across two files for eleven lines.
//! - `expression_has_pointer_representation` has three other callers on the
//!   expression side, so it is shared, not ours.

use std::fmt::Write;

use crate::ir::call_contracts::CallSiteSpec;
use crate::ir::types::{BinOp, VReg};

use super::super::{
    dec_global_name, dec_global_scalar_width, dec_plan, declared_reg_ctype, direct_global_address,
    indent, is_promoted_local, sanitize_c_ident, sanitize_comment, store_pointee_ctype,
    take_dec_inline_scalar_decl, write_unit_step, DeclarationPlan, Expr, Stmt,
};
use super::{
    call_prototype_for_render, dec_is_stack_object, dec_is_wide_local, expr_machine_width,
    expression_has_pointer_representation, float_rendered_width, renderable_field_access,
    try_array_index, write_array_access_dec, write_call_dec, write_expr_dec,
    write_field_access_dec, write_float_expr_dec, write_reg_lvalue_dec,
    write_representation_value_dec,
};

fn write_call_result_conversion_dec(
    target: &Expr,
    args: &[Expr],
    dst: &VReg,
    call_spec: Option<&CallSiteSpec>,
    out: &mut String,
) {
    let (call_spec, declaration, requires_cast) =
        call_prototype_for_render(target, args, Some(dst), call_spec);
    let return_type = if requires_cast {
        call_spec.call_prototype.return_type
    } else if let Some(declaration) = declaration {
        declaration.return_type
    } else {
        call_spec.call_prototype.return_type
    };
    let destination_type = declared_reg_ctype(dst);
    if return_type.ends_with('*') != destination_type.ends_with('*') {
        // The middle layer deliberately keeps unproven values as machine
        // words. State the representation conversion explicitly so the call
        // still uses its authoritative pointer/scalar ABI without relying on
        // an invalid implicit C conversion at the assignment boundary.
        let _ = write!(out, "({destination_type})");
    }
}

fn write_assign_dec(dst: &VReg, src: &Expr, out: &mut String) {
    if let VReg::Phys(name) = dst {
        if let Some(c_type) = take_dec_inline_scalar_decl(&sanitize_c_ident(name)) {
            let _ = write!(out, "{c_type} ");
        }
    }
    write_reg_lvalue_dec(dst, out);
    out.push_str(" = ");
    write_assignment_value_dec(dst, src, out);
}

/// Print a condition inside syntax that already supplies its own parentheses.
///
/// `Expr::Cmp` is parenthesized by the general expression renderer because it
/// may appear beneath another operator. In `if (...)`, `while (...)`, and the
/// condition field of `for (...)`, that outer pair is already present, so one
/// layer is redundant. Render first to preserve every specialized comparison
/// spelling, then remove exactly that known outer layer.
fn write_control_condition_dec(condition: &Expr, out: &mut String) {
    if !matches!(condition, Expr::Cmp { .. }) {
        write_expr_dec(condition, out);
        return;
    }
    let mut rendered = String::new();
    write_expr_dec(condition, &mut rendered);
    if let Some(inner) = rendered
        .strip_prefix('(')
        .and_then(|value| value.strip_suffix(')'))
    {
        out.push_str(inner);
    } else {
        out.push_str(&rendered);
    }
}

/// Prefer the source-level compound assignment for a proven 32-bit update.
///
/// The x86 lifter exposes both halves of `add r32, r32` through explicit
/// unsigned 32-bit views. When the destination is already declared `int`, a
/// simple lvalue compound assignment performs the same final conversion while
/// stating the source operation directly. Keep every other width, operator,
/// and destination on the representation-preserving assignment path.
fn write_int_compound_assignment_dec(dst: &VReg, src: &Expr, out: &mut String) -> bool {
    fn strip_casts(mut value: &Expr) -> (&Expr, u8) {
        let mut widest_cast = 0;
        while let Expr::Cast { width, expr, .. } = value {
            widest_cast = widest_cast.max(*width);
            value = expr;
        }
        (value, widest_cast)
    }

    let mut src = src;
    while let Expr::Cast {
        width: 4 | 8, expr, ..
    } = src
    {
        src = expr;
    }
    let Expr::Bin { op, lhs, rhs } = src else {
        return false;
    };
    let symbol = match op {
        BinOp::Add => "+=",
        BinOp::Sub => "-=",
        _ => return false,
    };
    if !matches!(
        declared_reg_ctype(dst).as_str(),
        "int" | "signed int" | "int32_t"
    ) {
        return false;
    }

    let (lhs_value, lhs_widest_cast) = strip_casts(lhs);
    let (rhs_value, rhs_widest_cast) = strip_casts(rhs);
    let (other, self_widest_cast) = if matches!(lhs_value, Expr::Reg(read) if read == dst) {
        (rhs.as_ref(), lhs_widest_cast)
    } else if *op == BinOp::Add && matches!(rhs_value, Expr::Reg(read) if read == dst) {
        // Integer addition is commutative. AArch64 GCC commonly materialises
        // `strlen(...) + sum` where x86 emits `sum + strlen(...)`; both carry
        // the same destination-read proof for `sum += strlen(...)`.
        (lhs.as_ref(), rhs_widest_cast)
    } else {
        return false;
    };

    // `int sum; sum = (long)sum + size_t_value` is precisely `sum +=
    // size_t_value`: C applies the same usual arithmetic conversions and then
    // converts the result back to the lvalue type. A widening cast on only the
    // left operand is removable only when the right operand proves arithmetic
    // at that same width. Retain the established GCC narrow-view shape too.
    let other = match other {
        Expr::Cast {
            signed: false,
            width: 4,
            expr,
        } => expr.as_ref(),
        other if self_widest_cast <= 4 => other,
        other if expr_machine_width(other).is_some_and(|width| width >= self_widest_cast) => other,
        _ => return false,
    };
    write_reg_lvalue_dec(dst, out);
    let _ = write!(out, " {symbol} ");
    write_expr_dec(other, out);
    true
}

/// Recover `global++`/`global--` when both sides name the same exact scalar
/// object and the only operation is a unit delta. Casts here are register-view
/// residue around the four-byte load; the scalar declaration already fixes the
/// operation's storage width.
fn write_global_unit_step_dec(address: u64, src: &Expr, out: &mut String) -> bool {
    fn without_casts(mut expression: &Expr) -> &Expr {
        while let Expr::Cast { expr, .. } = expression {
            expression = expr;
        }
        expression
    }

    let Expr::Bin { op, lhs, rhs } = without_casts(src) else {
        return false;
    };
    let Expr::Deref {
        addr,
        size: loaded_width,
    } = without_casts(lhs)
    else {
        return false;
    };
    if direct_global_address(addr) != Some(address)
        || dec_global_scalar_width(address) != Some(*loaded_width)
        || !matches!(without_casts(rhs), Expr::Const(1))
    {
        return false;
    }
    let suffix = match op {
        BinOp::Add => "++",
        BinOp::Sub => "--",
        _ => return false,
    };
    out.push_str(&dec_global_name(address));
    out.push_str(suffix);
    true
}

/// Render a value at an assignment boundary using both declarations.
///
/// Pointer ABI arguments are normally cast to `long` in rvalue position because
/// the machine-level AST performs byte arithmetic on them. A proven pointer
/// COPY must retain the pointer instead. Conversely, copying a proven pointer
/// high variable into a destination that remains a machine word needs the
/// explicit integer cast the old all-`long` renderer got implicitly.
fn write_assignment_value_dec(dst: &VReg, src: &Expr, out: &mut String) {
    write_representation_value_dec(&declared_reg_ctype(dst), src, out);
}

/// Render a value stored through the width-only memory model. A pointer-valued
/// high variable still carries machine address bits, while the current Store
/// node knows only the access width (not the destination's source pointee type).
/// State that representation conversion explicitly so a 32-bit pointer store
/// remains valid C and preserves the exact four-byte write.
fn write_store_value_dec(src: &Expr, size: u8, out: &mut String) {
    if expression_has_pointer_representation(src) {
        if let Expr::Reg(reg @ VReg::Phys(_)) = src {
            let _ = write!(out, "({})((long)", store_pointee_ctype(size));
            write_reg_lvalue_dec(reg, out);
            out.push(')');
        } else {
            let _ = write!(out, "({})((long)(", store_pointee_ctype(size));
            write_expr_dec(src, out);
            out.push_str("))");
        }
        return;
    }
    write_expr_dec(src, out);
}

/// Select a floating pointee only when the stored value's declaration proves
/// that storage class. Store nodes retain byte width but not source-level type;
/// using the exact producer declaration avoids turning an AAPCS-VFP return into
/// an integer conversion while leaving untyped four-byte stores unchanged.
///
/// The pointee is the whole fix on this path, and it is a *reinterpretation*:
/// `*(float *)(p) = (float)(x)` and `*(int *)(p) = (float)(x)` write the same
/// four bytes only if the second does not exist, because C converts the value
/// at that assignment (C23 6.3.1.4) and `movss` did not. Respelling the pointee
/// is the cheapest spelling that preserves the bits — a same-bank pointer cast,
/// with no union and no builtin — and it is available here precisely because
/// the destination type on this path is ours to choose (it comes from the
/// access WIDTH, not from a declaration). `197:*:O0:hfa197_make_tagged` wrote
/// `0x00000003` where the machine wrote `0x40400000`.
///
/// The width must MATCH the value's. Four bytes of a `double` are not that
/// `double`'s representation, so a narrow store of a wide float declines here
/// and keeps its integer pointee.
fn float_store_pointee_ctype(src: &Expr, size: u8) -> Option<&'static str> {
    match (float_rendered_width(src), size) {
        (Some(4), 4) => Some("float"),
        (Some(8), 8) => Some("double"),
        _ => None,
    }
}

pub(in crate::ir::ast) fn write_stmt_dec(s: &Stmt, out: &mut String, level: usize) {
    match s {
        Stmt::Assign { dst, src } => {
            if dec_is_wide_local(dst) {
                if let Expr::Deref {
                    addr: source,
                    size: 16,
                } = src
                {
                    indent(out, level);
                    out.push_str("__builtin_memcpy(");
                    write_reg_lvalue_dec(dst, out);
                    out.push_str(", ");
                    // The builtin takes `void *`; the middle layer keeps the
                    // machine address as an ordinary word, so it needs the same
                    // representation conversion as every other pointer
                    // boundary rather than an invalid implicit one.
                    write_representation_value_dec("void *", source, out);
                    out.push_str(", 16);\n");
                    return;
                }
            }
            // `Expr::Select` already carries lazy value semantics
            // (`cond ? true : false`), including a call in the selected arm.
            // Keep that typed middle-layer node visible in benchmark C instead
            // of inventing statement-level CFG or an eager initializer.
            indent(out, level);
            if !write_int_compound_assignment_dec(dst, src, out) {
                write_assign_dec(dst, src, out);
            }
            out.push_str(";\n");
        }
        Stmt::Store { addr, src, size } => {
            indent(out, level);
            if let Some(address) = direct_global_address(addr) {
                if dec_global_scalar_width(address) == Some(*size) {
                    if !write_global_unit_step_dec(address, src, out) {
                        out.push_str(&dec_global_name(address));
                        out.push_str(" = ");
                        write_store_value_dec(src, *size, out);
                    }
                    out.push_str(";\n");
                    return;
                }
            }
            // A 128-bit machine move is a complete load followed by a complete
            // store. The scalar AST cannot name that value without narrowing it
            // to `long`, so preserve the memory-to-memory form with an
            // overlap-safe builtin. Unlike `memcpy`, `memmove` also matches a
            // load-before-store instruction pair when the ranges overlap.
            if *size == 16 {
                let source = match src {
                    Expr::Deref {
                        addr: source,
                        size: 16,
                    } => Some(source.as_ref()),
                    Expr::Reg(register) if dec_is_wide_local(register) => Some(src),
                    _ => None,
                };
                if let Some(source) = source {
                    out.push_str("__builtin_memmove(");
                    write_representation_value_dec("void *", addr, out);
                    out.push_str(", ");
                    // A wide local is declared as a byte array and already
                    // decays to `void *`; only machine-word addresses need the
                    // representation conversion.
                    match source {
                        Expr::Reg(register) if dec_is_wide_local(register) => {
                            write_reg_lvalue_dec(register, out)
                        }
                        _ => write_representation_value_dec("void *", source, out),
                    }
                    out.push_str(", 16);\n");
                    return;
                }
            }
            // The integer C backend has no scalar 128-bit lvalue. A proven
            // zero vector still has exact byte semantics, so preserve the full
            // machine write instead of silently narrowing it to one `long`.
            if *size == 16 && matches!(src, Expr::Const(0)) {
                out.push_str("__builtin_memset(");
                write_representation_value_dec("void *", addr, out);
                out.push_str(", 0, 16);\n");
                return;
            }
            // A store whose address is a bare promoted stack local (`local_0`,
            // `stack_1`, …) is a plain variable assignment, not a pointer
            // write: emit `local_0 = src` rather than `*(long *)(local_0) = src`.
            if let Expr::Reg(VReg::Phys(name)) = addr {
                if is_promoted_local(name) && !dec_is_stack_object(name) {
                    let destination = VReg::phys(name);
                    if !write_int_compound_assignment_dec(&destination, src, out) {
                        if let Some(c_type) = take_dec_inline_scalar_decl(&sanitize_c_ident(name)) {
                            let _ = write!(out, "{c_type} ");
                        }
                        write_reg_lvalue_dec(&destination, out);
                        out.push_str(" = ");
                        write_assignment_value_dec(&destination, src, out);
                    }
                    out.push_str(";\n");
                    return;
                }
            }
            if let Some((base, index, hint)) = renderable_field_access(addr) {
                write_field_access_dec(base, index, hint, out);
                out.push_str(" = ");
                write_store_value_dec(src, *size, out);
                out.push_str(";\n");
                return;
            }
            if let Some((base, index)) = try_array_index(addr, *size) {
                write_array_access_dec(base, index, *size, out);
                out.push_str(" = ");
                write_store_value_dec(src, *size, out);
                out.push_str(";\n");
                return;
            }
            // Use the access width so a 4-byte store emits `*(int *)`, not a
            // blanket `*(long *)` that would clobber the adjacent element.
            let float_pointee = float_store_pointee_ctype(src, *size);
            let pointee_type = float_pointee.unwrap_or_else(|| store_pointee_ctype(*size));
            let _ = write!(out, "*({pointee_type} *)(");
            write_expr_dec(addr, out);
            out.push_str(") = ");
            match float_pointee {
                // The pointee and the value have to be decided together. Naming
                // a `float` pointee and then printing the value through the
                // integer renderer spells a floating divisor as the INTEGER
                // 0x40000000 (`201:gcc:O0:f201_f32_slot_values`), and C would
                // then convert that integer to 1073741824.0f rather than read
                // it as 2.0f. `write_float_expr_dec` is the same renderer the
                // LOAD side of this fixture already used, which is why the two
                // ends of one object disagreed about it.
                Some(_) => write_float_expr_dec(src, *size, out),
                None => write_store_value_dec(src, *size, out),
            }
            out.push_str(";\n");
        }
        Stmt::Call {
            target,
            args,
            dst,
            call_spec,
        } => {
            indent(out, level);
            // A result the ABI split across two result registers lands in a
            // frame object, not a scalar: the object is what the two register
            // identities are then read back out of. The destination is declared
            // as a byte array (it is address-taken by those reads), so the
            // aggregate assignment is spelled through the synthesised tag —
            // `__glaurung_split_is`/`_si` for the two BANKS, `__glaurung_sse_pair`
            // for `xmm0:xmm1`. Without the array declaration `&x[0]` would not
            // be valid C, so fall through to the ordinary scalar form whenever
            // the reads did not survive.
            let split_bank_store = match (dst, call_spec.as_ref()) {
                (Some(VReg::Phys(name)), Some(spec))
                    if dec_is_stack_object(&sanitize_c_ident(name)) =>
                {
                    crate::ir::abi::synthesised_return_definition(&spec.call_prototype.return_type)
                        .map(|_| spec.call_prototype.return_type.clone())
                }
                _ => None,
            };
            if let (Some(tag), Some(VReg::Phys(name))) = (&split_bank_store, dst) {
                let _ = write!(out, "*({tag} *)(&{}[0]) = ", sanitize_c_ident(name));
            } else {
                // A call's result must land somewhere: dropping it emitted
                // `f(x);` and then read the ARGUMENT where the return value belonged.
                if let Some(VReg::Phys(n)) = dst {
                    let _ = write!(out, "{} = ", sanitize_c_ident(n));
                }
                if let Some(dst) = dst {
                    write_call_result_conversion_dec(target, args, dst, call_spec.as_ref(), out);
                }
            }
            write_call_dec(target, args, dst.as_ref(), call_spec.as_ref(), out);
            out.push_str(";\n");
        }
        Stmt::Return { value } => {
            indent(out, level);
            match value {
                Some(e) => {
                    out.push_str("return ");
                    let return_type = dec_plan(|plan| plan.return_ctype().to_string());
                    // A result the ABI splits across two register BANKS is
                    // declared at a synthesised tag, and the value is the frame
                    // object it lives in — the exact mirror of the call site's
                    // `*(struct __glaurung_sse_pair *)(&var1[0]) = callee(...)`.
                    // The pointee TYPE has to come from the declaration: the
                    // scalar renderer would spell this load at one bank's width
                    // and hand back half the result. See
                    // `crate::ir::callee_return_bank`, which is what proves the
                    // whole object is the result before this spelling is used.
                    match (
                        crate::ir::abi::synthesised_return_definition(&return_type),
                        e,
                    ) {
                        (Some(_), Expr::Deref { addr, .. }) => {
                            let _ = write!(out, "*({return_type} *)(");
                            write_expr_dec(addr, out);
                            out.push(')');
                        }
                        _ => write_representation_value_dec(&return_type, e, out),
                    }
                    out.push_str(";\n");
                }
                None => {
                    if dec_plan(DeclarationPlan::returns_void) {
                        out.push_str("return;\n");
                    } else {
                        out.push_str("return 0;\n");
                    }
                }
            }
        }
        // No faithful, valid-C spelling — elide (Nop/Push/Pop) or comment out.
        Stmt::Break => {
            indent(out, level);
            out.push_str("break;\n");
        }
        Stmt::Nop | Stmt::Push { .. } | Stmt::Pop { .. } => {}
        Stmt::Unknown(mnemonic) => {
            indent(out, level);
            let _ = writeln!(out, "/* asm: {} */", sanitize_comment(mnemonic));
        }
        Stmt::Comment(text) => {
            indent(out, level);
            let _ = writeln!(out, "// {}", sanitize_comment(text));
        }
        Stmt::Label(va) => {
            indent(out, level);
            let _ = writeln!(out, "L_{:x}: ;", va);
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
            write_expr_dec(target, out);
            out.push_str(" */\n");
        }
        Stmt::If {
            cond,
            then_body,
            else_body,
        } => {
            indent(out, level);
            out.push_str("if (");
            write_control_condition_dec(cond, out);
            out.push_str(") {\n");
            for s in then_body {
                write_stmt_dec(s, out, level + 1);
            }
            indent(out, level);
            out.push('}');
            if let Some(eb) = else_body {
                out.push_str(" else {\n");
                for s in eb {
                    write_stmt_dec(s, out, level + 1);
                }
                indent(out, level);
                out.push('}');
            }
            out.push('\n');
        }
        Stmt::While { cond, body } => {
            indent(out, level);
            out.push_str("while (");
            write_control_condition_dec(cond, out);
            out.push_str(") {\n");
            for s in body {
                write_stmt_dec(s, out, level + 1);
            }
            indent(out, level);
            out.push_str("}\n");
        }
        Stmt::Throw { value } => {
            indent(out, level);
            out.push_str("throw ");
            write_expr_dec(value, out);
            out.push_str(";\n");
        }
        Stmt::TryCatch { try_body, catches } => {
            indent(out, level);
            out.push_str("try {\n");
            for statement in try_body {
                write_stmt_dec(statement, out, level + 1);
            }
            indent(out, level);
            out.push('}');
            for catch in catches {
                out.push_str(" catch (");
                out.push_str(&catch.type_name);
                out.push(' ');
                match &catch.binding {
                    VReg::Phys(name) => out.push_str(&sanitize_c_ident(name)),
                    other => out.push_str(&sanitize_c_ident(&other.to_string())),
                }
                out.push_str(") {\n");
                for statement in &catch.body {
                    write_stmt_dec(statement, out, level + 1);
                }
                indent(out, level);
                out.push('}');
            }
            out.push('\n');
        }
        Stmt::For {
            init,
            cond,
            step,
            body,
        } => {
            indent(out, level);
            out.push_str("for (");
            write_for_clause_dec(init, out, false);
            out.push_str("; ");
            write_control_condition_dec(cond, out);
            out.push_str("; ");
            write_for_clause_dec(step, out, true);
            out.push_str(") {\n");
            for s in body {
                write_stmt_dec(s, out, level + 1);
            }
            indent(out, level);
            out.push_str("}\n");
        }
        Stmt::DoWhile { body, cond } => {
            indent(out, level);
            out.push_str("do {\n");
            for s in body {
                write_stmt_dec(s, out, level + 1);
            }
            indent(out, level);
            out.push_str("} while (");
            write_control_condition_dec(cond, out);
            out.push_str(");\n");
        }
        Stmt::Switch {
            discriminant,
            cases,
            default,
        } => {
            indent(out, level);
            out.push_str("switch (");
            write_expr_dec(discriminant, out);
            out.push_str(") {\n");
            // C forbids duplicate case labels and `case _:`; keep the first of
            // each numeric label and fold every unlabelled / duplicate arm plus
            // the explicit default into a single `default:` block. Consecutive
            // labels with the same body came from multiple jump-table entries
            // targeting one case block, so emit stacked labels over that body
            // exactly once, as Ghidra and angr do.
            let mut seen: std::collections::HashSet<i64> = std::collections::HashSet::new();
            let mut default_arms: Vec<&Vec<Stmt>> = Vec::new();
            let mut case_groups: Vec<(Vec<i64>, &Vec<Stmt>)> = Vec::new();
            for (label, body) in cases {
                match label {
                    Some(n) if seen.insert(*n) => {
                        if case_groups
                            .last()
                            .is_some_and(|(_, grouped_body)| *grouped_body == body)
                        {
                            if let Some((labels, _)) = case_groups.last_mut() {
                                labels.push(*n);
                            }
                        } else {
                            case_groups.push((vec![*n], body));
                        }
                    }
                    _ => default_arms.push(body),
                }
            }
            for (labels, body) in case_groups {
                for label in labels {
                    indent(out, level + 1);
                    let _ = writeln!(out, "case {}:", label);
                }
                for s in body {
                    write_stmt_dec(s, out, level + 2);
                }
                if !case_body_has_terminal_transfer(body) {
                    indent(out, level + 2);
                    out.push_str("break;\n");
                }
            }
            if let Some(def_body) = default {
                default_arms.push(def_body);
            }
            if !default_arms.is_empty() {
                indent(out, level + 1);
                out.push_str("default:\n");
                for body in &default_arms {
                    for s in *body {
                        write_stmt_dec(s, out, level + 2);
                    }
                }
                if !default_arms
                    .last()
                    .is_some_and(|body| case_body_has_terminal_transfer(body))
                {
                    indent(out, level + 2);
                    out.push_str("break;\n");
                }
            }
            indent(out, level);
            out.push_str("}\n");
        }
    }
}

fn case_body_has_terminal_transfer(body: &[Stmt]) -> bool {
    matches!(
        body.last(),
        Some(Stmt::Return { .. } | Stmt::Goto { .. } | Stmt::Break)
    )
}

fn write_for_clause_dec(s: &Stmt, out: &mut String, prefer_increment: bool) {
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
    if prefer_increment && write_unit_step(dst, src, out, write_reg_lvalue_dec, true) {
        return;
    }
    if !prefer_increment {
        if let VReg::Phys(name) = dst {
            if let Some(c_type) = take_dec_inline_scalar_decl(&sanitize_c_ident(name)) {
                let _ = write!(out, "{c_type} ");
            }
        }
    }
    write_reg_lvalue_dec(dst, out);
    out.push_str(" = ");
    write_assignment_value_dec(dst, src, out);
}
