//! The typed C ("dec") **expression** printer.
//!
//! [`super::decbench_render::render_decbench_typed_with_output_and_prototype_and_dwarf_types_and_local_types`]
//! (the DecBench front door, in the parent module) installs a
//! [`DeclarationPlan`](super::DeclarationPlan) and a handful of render-scoped
//! thread-locals (global address set, wide-local set, named-call-prototype
//! table, renderable-struct set, pointer width, semantic-wide-cast flag) and
//! then calls [`write_stmt_dec`] once per top-level statement. Everything in
//! this module is the read-only consumer of that installed state: it walks
//! the already-lowered [`Expr`] tree and prints C text, consulting
//! the plan and thread-locals through the parent module's accessors
//! (`dec_plan`, `dec_ptr_arg_type`, `dec_ptr_width`, ...) rather than reading
//! them directly, for the same reason the plan itself exists: so a
//! declaration decision is made once, upstream, and every print site agrees
//! with it.
//!
//! The **statement** half lives in the [`stmt`] submodule and is re-exported
//! from here, so the front door's `write_stmt_dec` import is unchanged. The
//! split is the call graph's: `write_expr_dec` and its 43 helpers form a
//! closed sub-graph that never calls a statement printer, while
//! `write_stmt_dec` and its 7 helpers name twelve functions from this module
//! and are named by none of them. `stmt` is a *child* of this module rather
//! than a sibling for the same reason this module is a child of `ir::ast`:
//! a descendant already sees its parent's private items, so nothing had to
//! be widened to make the boundary legal.
//!
//! A few helpers that look like they belong here stay in the parent module
//! instead, because the call graph — not their physical position in the old
//! file — says they are shared:
//! - [`callee_display_name`](super::callee_display_name) and
//!   [`declared_reg_ctype`](super::declared_reg_ctype) are also called from
//!   the DecBench front door and its ident-collection pass.
//! - `write_unit_step` is also called by the untyped C renderer's
//!   `write_for_clause_c`, parameterised over which register-printer to use.
//! - `signed_shift_operand`, `expr_machine_width`, and
//!   `normalize_wrapped_scaled_index_constant` are exercised directly by
//!   dedicated unit tests in the parent module's `tests` submodule.
//!
//! Splitting those out too would either widen the newly-public surface
//! between this module and its parent for no reader benefit, or require
//! rewriting test call sites — neither of which this extraction does.

use std::fmt::Write;

use crate::ir::call_contracts::{CallPrototype, CallPrototypeAuthority, CallSiteSpec};
use crate::ir::types::{BinOp, CmpOp, UnOp, VReg};

use super::dwarf_render_types::{pointed_struct_name, valid_c_identifier};
use super::{
    binop_sym_c, callee_display_name, cmpop_sym_c, dec_global_name, dec_int_type, dec_plan,
    dec_ptr_arg_type, dec_ptr_width, declared_reg_ctype, expr_machine_width, flag_ident, int_ctype,
    normalize_wrapped_scaled_index_constant, parse_arg_index, sanitize_c_ident,
    signed_shift_operand, target_int_ctype, unop_sym, width_ctype, write_float_literal, Expr,
    PdbFieldHint, ScalarType, WideArithmetic, DEC_GLOBAL_ADDRS, DEC_NAMED_CALL_PROTOTYPES,
    DEC_POINTER_WIDTH, DEC_RENDERABLE_STRUCTS, DEC_SEMANTIC_WIDE_CAST, DEC_STRUCT_PTR_TYPES,
    DEC_WIDE_LOCALS,
};

mod stmt;

pub(super) use stmt::write_stmt_dec;

fn dec_is_global_addr(address: u64) -> bool {
    DEC_GLOBAL_ADDRS.with(|addresses| addresses.borrow().contains(&address))
}

fn dec_is_wide_local(register: &VReg) -> bool {
    let spelling = match register {
        VReg::Phys(name) => sanitize_c_ident(name),
        VReg::Temp(index) => format!("t{index}"),
        VReg::Flag(flag) => flag_ident(flag).to_string(),
        VReg::FlagValue { .. } => register
            .predicate_ident()
            .expect("FlagValue always has a predicate identifier"),
    };
    DEC_WIDE_LOCALS.with(|locals| locals.borrow().contains(&spelling))
}

fn selected_named_call_prototype(name: &str) -> Option<CallPrototype> {
    let displayed = sanitize_c_ident(callee_display_name(name));
    DEC_NAMED_CALL_PROTOTYPES.with(|selected| selected.borrow().get(&displayed).cloned())
}

fn dec_struct_ptr_type(name: &str) -> Option<String> {
    DEC_STRUCT_PTR_TYPES.with(|m| m.borrow().get(name).cloned())
}

fn dec_is_stack_object(name: &str) -> bool {
    let displayed = sanitize_c_ident(name);
    dec_plan(|plan| plan.is_stack_object(&displayed))
}

/// The unsigned-cast width for a logical right shift `lhs >> rhs`. The shift
/// must happen at the operand's machine width so a negative narrow value is not
/// sign-extended into the high half before the zero-fill. Narrowing is applied
/// only when (a) the operand's width is positively known from narrow-typed
/// identifiers, and (b) the shift amount is a constant that fits inside that
/// width — a `>> 32` on a value that is genuinely 64-bit (e.g. `mul_widen`'s
/// `(uint64_t)a*b`) must keep an eight-byte type.  A declared call-result local
/// is stronger evidence than its canonical SSA parent: on ILP32, `long` is
/// only four bytes while a proven `long long` destination remains eight.
fn shift_operand_ctype(lhs: &Expr, rhs: &Expr) -> &'static str {
    if let Expr::Reg(register) = lhs {
        let pointer_width = DEC_POINTER_WIDTH.with(std::cell::Cell::get);
        if let Some(width) = crate::ir::call_contracts::integer_c_type_width(
            &declared_reg_ctype(register),
            pointer_width,
        )
        .filter(|width| *width > pointer_width)
        {
            // A value declared at exactly two machine words must be shifted at
            // that width: `(unsigned long)(v) >> 64` on an LP64 target is a
            // shift by the operand's own width, which is undefined and in
            // practice yields nothing. The double-word spelling is the only one
            // under which extracting the high eightbyte of a `rax:rdx` result
            // means what it says.
            if width == pointer_width.saturating_mul(2) {
                return double_width_ctype(false, pointer_width);
            }
            return target_int_ctype(false, width);
        }
    }
    if let (Some(w), Expr::Const(k)) = (expr_machine_width(lhs), rhs) {
        if *k >= 0 && (*k as u64) < (w as u64) * 8 {
            // Target-parametric, not `int_ctype`: the two agree for one, two
            // and four bytes, and disagree for eight, where ILP32's `unsigned
            // long` is only a single machine word and would truncate the very
            // operand this cast exists to keep wide.
            return target_int_ctype(false, w);
        }
    }
    target_int_ctype(false, 8)
}

/// The `(wide)((narrow)x)` spellings a LEFT shift's operand needs when the
/// count is at least as wide as the operand's DECLARED type, or `None`.
///
/// `x << k` where `x` is declared `int32_t` and `k` is 33 is undefined in C
/// (C23 6.5.7p3) and in practice shifts by `k % 32`, which is not what the
/// machine did: `shl %rdi, $33` shifted the whole 64-bit register. The count
/// alone proves the operand was wider than its declaration says, so this is a
/// rule about a contradiction rather than a guess about intent —
/// `197:clang:O2:hfa197_make_tagged` composes `tag` into the high eightbyte
/// exactly this way.
///
/// The narrow cast is applied FIRST and is unsigned, which is the same
/// wraparound spelling `write_expr_dec` uses everywhere else: the caller
/// materialised the parameter with a 32-bit move, so the register's high half
/// is the ZERO extension of the declared value, not its sign extension.
///
/// Only a register with a declared integer type qualifies. Nothing else states
/// a width this can contradict, and a shift whose count already fits the
/// operand is left exactly as it was.
fn wide_left_shift_operand_ctypes(lhs: &Expr, rhs: &Expr) -> Option<(&'static str, &'static str)> {
    let Expr::Const(count) = rhs else {
        return None;
    };
    let Expr::Reg(register) = lhs else {
        return None;
    };
    let count = u64::try_from(*count).ok()?;
    let pointer_width = DEC_POINTER_WIDTH.with(std::cell::Cell::get);
    let width = crate::ir::call_contracts::integer_c_type_width(
        &declared_reg_ctype(register),
        pointer_width,
    )?;
    (count >= u64::from(width) * 8 && count < u64::from(pointer_width) * 8).then(|| {
        (
            target_int_ctype(false, pointer_width),
            target_int_ctype(false, width),
        )
    })
}

/// Recognise the array-index idiom `base + index*sizeof(T)` for a `T`-sized
/// access, where `base` is a pointer declared with pointee width == `size`.
/// Returns `(base name, index expr)` so the deref renders as `base[index]`,
/// dropping the byte-offset arithmetic and `(long)` cast. Correct because
/// `base[i]` is exactly `*(base + i)` and C scales the index by `sizeof(*base)`,
/// which equals `size` — the guard we check.
fn try_array_index<'a>(addr: &'a Expr, size: u8) -> Option<(&'a str, &'a Expr)> {
    let (lhs, rhs) = match addr {
        Expr::Bin {
            op: BinOp::Add,
            lhs,
            rhs,
        } => (lhs.as_ref(), rhs.as_ref()),
        _ => return None,
    };
    for (base_side, off_side) in [(lhs, rhs), (rhs, lhs)] {
        if let Expr::Reg(VReg::Phys(name)) = base_side {
            if dec_ptr_width(name) == Some(size) {
                if let Some(index) = scaled_index(off_side, size) {
                    return Some((name.as_str(), index));
                }
            }
        }
    }
    None
}

/// If `off` is `index * size` — a multiply or an equivalent left shift, possibly
/// wrapped in a redundant `+ 0` — return the (unscaled) index. `size == 1` needs
/// no scaling, so any expression is the index.
fn scaled_index<'a>(off: &'a Expr, size: u8) -> Option<&'a Expr> {
    // Strip a redundant `0 + x` / `x + 0` the lifter leaves on scaled indices.
    let off = match off {
        Expr::Bin {
            op: BinOp::Add,
            lhs,
            rhs,
        } => match (lhs.as_ref(), rhs.as_ref()) {
            (Expr::Const(0), x) | (x, Expr::Const(0)) => x,
            _ => off,
        },
        _ => off,
    };
    if size == 1 {
        return Some(strip_implicit_pointer_index_extension(off));
    }
    match off {
        Expr::Bin {
            op: BinOp::Mul,
            lhs,
            rhs,
        } => match (lhs.as_ref(), rhs.as_ref()) {
            (idx, Expr::Const(s)) | (Expr::Const(s), idx) if *s == size as i64 => Some(idx),
            _ => None,
        },
        Expr::Bin {
            op: BinOp::Shl,
            lhs,
            rhs,
        } => match rhs.as_ref() {
            Expr::Const(k) if *k >= 0 && *k < 63 && (1i64 << *k) == size as i64 => {
                Some(lhs.as_ref())
            }
            _ => None,
        },
        _ => None,
    }
}

fn index_with_addend(base: &Expr, addend: i64) -> Expr {
    if addend == 0 {
        return base.clone();
    }
    if addend < 0 {
        let magnitude = addend
            .checked_abs()
            .expect("normalized 32-bit index addend cannot be i64::MIN");
        return Expr::Bin {
            op: BinOp::Sub,
            lhs: Box::new(base.clone()),
            rhs: Box::new(Expr::Const(magnitude)),
        };
    }
    Expr::Bin {
        op: BinOp::Add,
        lhs: Box::new(base.clone()),
        rhs: Box::new(Expr::Const(addend)),
    }
}

/// Normalize only the constant term of a proven scaled array index. Dynamic
/// terms and non-affine expressions remain byte-for-byte identical.
fn normalize_wrapped_array_index(index: &Expr, element_size: u8) -> std::borrow::Cow<'_, Expr> {
    let pointer_width = DEC_POINTER_WIDTH.with(std::cell::Cell::get);
    let normalized = match index {
        Expr::Const(value) => {
            normalize_wrapped_scaled_index_constant(*value, element_size, pointer_width)
                .filter(|normalized| normalized != value)
                .map(Expr::Const)
        }
        Expr::Bin {
            op: BinOp::Add,
            lhs,
            rhs,
        } => match (lhs.as_ref(), rhs.as_ref()) {
            (base, Expr::Const(addend)) | (Expr::Const(addend), base) => {
                normalize_wrapped_scaled_index_constant(*addend, element_size, pointer_width)
                    .filter(|normalized| normalized != addend)
                    .map(|normalized| index_with_addend(base, normalized))
            }
            _ => None,
        },
        Expr::Bin {
            op: BinOp::Sub,
            lhs,
            rhs,
        } => match rhs.as_ref() {
            Expr::Const(subtrahend) => subtrahend.checked_neg().and_then(|addend| {
                normalize_wrapped_scaled_index_constant(addend, element_size, pointer_width)
                    .filter(|normalized| *normalized != addend)
                    .map(|normalized| index_with_addend(lhs, normalized))
            }),
            _ => None,
        },
        _ => None,
    };
    normalized.map_or(std::borrow::Cow::Borrowed(index), std::borrow::Cow::Owned)
}

/// Render one already-proven typed array access. Loads and stores must share
/// this path: otherwise an ILP32 wrapped index can be made safe on the read
/// side while the corresponding write still escapes as host-width arithmetic.
fn write_array_access_dec(base: &str, index: &Expr, element_size: u8, out: &mut String) {
    out.push_str(base);
    out.push('[');
    write_expr_dec(&normalize_wrapped_array_index(index, element_size), out);
    out.push(']');
}

fn strip_implicit_pointer_index_extension(expr: &Expr) -> &Expr {
    let Expr::Cast {
        signed: outer_signed,
        width: outer_width,
        expr: outer,
    } = expr
    else {
        return expr;
    };
    let Expr::Cast {
        signed: inner_signed,
        width: inner_width,
        expr: inner,
    } = outer.as_ref()
    else {
        return expr;
    };
    let Expr::Reg(VReg::Phys(name)) = inner.as_ref() else {
        return expr;
    };
    if outer_signed == inner_signed
        && inner_width < outer_width
        && dec_int_type(name) == Some((*inner_signed, *inner_width))
    {
        inner
    } else {
        expr
    }
}

/// Render a register in **rvalue** position. A pointer-typed argument or complete
/// stack object is cast to `long` here: our byte-offset arithmetic treats it as
/// an integer address, and leaving it a pointer would be an invalid operand for
/// `&`/`*`/`-`/pointer±pointer.
fn write_reg_dec(v: &VReg, out: &mut String) {
    if let VReg::Phys(n) = v {
        if dec_ptr_arg_type(n).is_some()
            || dec_struct_ptr_type(n).is_some()
            || dec_is_stack_object(n)
        {
            out.push_str("(long)");
            write_reg_lvalue_dec(v, out);
            return;
        }
    }
    write_reg_lvalue_dec(v, out);
}

/// Render an operand of machine-level byte arithmetic.
///
/// Exact DWARF local types can turn a machine address into a C pointer after
/// the AST was built.  A literal displacement in this IR is still measured in
/// bytes, so allowing C to scale `pointer + displacement` by the pointee size
/// would change the recovered program.  Keep ordinary pointer values intact at
/// calls and memory boundaries; cross to the integer representation only here.
fn write_machine_arithmetic_operand_dec(expr: &Expr, out: &mut String) {
    if let Expr::Reg(reg @ VReg::Phys(_)) = expr {
        if declared_reg_ctype(reg).ends_with('*') {
            out.push_str("(long)");
            write_reg_lvalue_dec(reg, out);
            return;
        }
    }
    // A nested native-pointer step still produces a pointer. The enclosing IR
    // operation is byte arithmetic, so cross back to an integer address before
    // adding a dynamic byte offset; otherwise C scales that offset a second
    // time (`(p + 1) + i*4` advances by `i*16` for `int *`).
    if let Expr::Bin { op, lhs, rhs } = expr {
        if scaled_pointer_offset(*op, lhs, rhs).is_some() {
            out.push_str("(long)(");
            write_expr_dec(expr, out);
            out.push(')');
            return;
        }
    }
    write_expr_dec(expr, out);
}

fn scaled_pointer_offset<'a>(op: BinOp, lhs: &'a Expr, rhs: &Expr) -> Option<(&'a VReg, i64)> {
    if !matches!(op, BinOp::Add | BinOp::Sub) {
        return None;
    }
    let Expr::Reg(reg @ VReg::Phys(name)) = lhs else {
        return None;
    };
    let Expr::Const(displacement) = rhs else {
        return None;
    };
    let width = dec_ptr_width(name).filter(|width| *width > 0)?;
    let declared = declared_reg_ctype(reg);
    let mut pointee = declared.strip_suffix('*').map(str::trim)?;
    while let Some(unqualified) = pointee
        .strip_prefix("const ")
        .or_else(|| pointee.strip_prefix("volatile "))
    {
        pointee = unqualified.trim();
    }
    let pointer_width = DEC_POINTER_WIDTH.with(std::cell::Cell::get);
    let declared_pointee_width =
        crate::ir::call_contracts::integer_c_type_width(pointee, pointer_width).or(match pointee {
            "float" => Some(4),
            "double" => Some(8),
            _ => None,
        });
    if declared_pointee_width != Some(width) {
        return None;
    }
    let width = i64::from(width);
    (displacement % width == 0).then_some((reg, displacement / width))
}

/// Prefer native C pointer arithmetic when an exact pointee width can express
/// the IR's byte displacement without loss.  This is equivalent to the
/// integer-address form but lets the compiler recover the original increment
/// shape (`p + 1` for an eight-byte pointer slot, not `(long)p + 8`).
fn write_scaled_pointer_offset_dec(op: BinOp, lhs: &Expr, rhs: &Expr, out: &mut String) -> bool {
    let Some((reg, scaled_displacement)) = scaled_pointer_offset(op, lhs, rhs) else {
        return false;
    };
    write_reg_lvalue_dec(reg, out);
    let _ = write!(out, " {} ", binop_sym_c(op));
    write_const_dec(scaled_displacement, out);
    true
}

/// Render a register in **lvalue** position (assignment target) — never cast,
/// since a cast is not a valid lvalue.
fn write_reg_lvalue_dec(v: &VReg, out: &mut String) {
    match v {
        VReg::Phys(n) => {
            if let Some(idx) = parse_arg_index(n) {
                let _ = write!(out, "arg{}", idx);
            } else {
                out.push_str(&sanitize_c_ident(n));
            }
        }
        VReg::Temp(i) => {
            let _ = write!(out, "t{}", i);
        }
        VReg::Flag(fl) => out.push_str(flag_ident(fl)),
        VReg::FlagValue { .. } => out.push_str(
            &v.predicate_ident()
                .expect("FlagValue always has a predicate identifier"),
        ),
    }
}

/// Write a `long`-valued integer constant using the same compact spelling as
/// the register-level renderer (small decimals, hex for wide values).
fn write_const_dec(c: i64, out: &mut String) {
    if c == 0 {
        out.push('0');
    } else if c == -1 {
        out.push_str("-1");
    } else if (-4096..=4096).contains(&c) {
        let _ = write!(out, "{}", c);
    } else if c == i64::MIN {
        // The magnitude of INT64_MIN is not representable as a signed literal.
        // Building it from two representable signed terms avoids both Rust-side
        // negation overflow and C's unsigned-hex unary-minus semantics.
        out.push_str("(-0x7fffffffffffffffLL - 1LL)");
    } else if c < 0 {
        // Unsuffixed hex chooses the first fitting type.  Magnitudes above
        // INT32_MAX therefore become `unsigned int`, so `-0x80000001` wraps to
        // positive 0x7fffffff before a surrounding long expression sees it.
        // Every remaining i64 magnitude fits signed long long exactly.
        let _ = write!(out, "-0x{:x}LL", c.unsigned_abs());
    } else {
        let _ = write!(out, "0x{:x}", c);
    }
}

/// Render `base + index*scale + disp` as a parenthesised `long` expression (an
/// address computed as an integer — no `&`, no segment). Used for `lea`/field
/// addresses; a parent `Deref`/`Store` wraps it in `*(long *)(...)`.
fn write_addr_arith_dec(
    base: &Option<VReg>,
    index: &Option<VReg>,
    scale: u8,
    disp: i64,
    out: &mut String,
) {
    out.push('(');
    let mut wrote = false;
    if let Some(b) = base {
        write_reg_dec(b, out);
        wrote = true;
    }
    if let Some(i) = index {
        if wrote {
            out.push_str(" + ");
        }
        write_reg_dec(i, out);
        if scale > 1 {
            let _ = write!(out, " * {}", scale);
        }
        wrote = true;
    }
    if disp != 0 || !wrote {
        if disp < 0 {
            out.push_str(if wrote { " - " } else { "-" });
            let _ = write!(out, "0x{:x}", disp.unsigned_abs());
        } else {
            if wrote {
                out.push_str(" + ");
            }
            let _ = write!(out, "0x{:x}", disp);
        }
    }
    out.push(')');
}

/// The C spelling of the *double-width* intermediate a `width`-byte
/// multiply-high or wide divide computes in.
///
/// `__int128` is a 64-bit-target extension: naming it for 32-bit operands makes
/// the fragment unbuildable for i386/ARM32/PE32 even though those are exactly
/// the targets where a 32x32 multiply-high is most common. The intermediate is
/// a property of the operand width, not of the host, so derive it.
fn double_width_ctype(signed: bool, width: u8) -> &'static str {
    match (signed, width) {
        (true, 1) => "short",
        (false, 1) => "unsigned short",
        (true, 2) => "int",
        (false, 2) => "unsigned int",
        (true, 4) => "long long",
        (false, 4) => "unsigned long long",
        (true, _) => "__int128",
        (false, _) => "unsigned __int128",
    }
}

fn write_wide_arithmetic_dec(op: WideArithmetic, args: &[Expr], width: u8, out: &mut String) {
    let signed = int_ctype(true, width);
    let unsigned = int_ctype(false, width);
    let wide_signed = double_width_ctype(true, width);
    let wide_unsigned = double_width_ctype(false, width);
    let bits = u16::from(width) * 8;
    match (op, args) {
        (WideArithmetic::UnsignedMulHigh, [lhs, rhs]) => {
            let _ = write!(out, "(({unsigned})((({wide_unsigned})({unsigned})(");
            write_expr_dec(lhs, out);
            let _ = write!(out, ") * ({wide_unsigned})({unsigned})(");
            write_expr_dec(rhs, out);
            let _ = write!(out, ")) >> {bits}))");
        }
        (WideArithmetic::SignedMulHigh, [lhs, rhs]) => {
            let _ = write!(
                out,
                "(({signed})((({wide_unsigned})(({wide_signed})({signed})("
            );
            write_expr_dec(lhs, out);
            let _ = write!(out, ") * ({wide_signed})({signed})(");
            write_expr_dec(rhs, out);
            let _ = write!(out, "))) >> {bits}))");
        }
        (
            operation
            @ (WideArithmetic::UnsignedDivQuotient | WideArithmetic::UnsignedDivRemainder),
            [hi, lo, divisor],
        ) => {
            let symbol = if matches!(operation, WideArithmetic::UnsignedDivQuotient) {
                "/"
            } else {
                "%"
            };
            let _ = write!(out, "(({unsigned})((((({wide_unsigned})({unsigned})(");
            write_expr_dec(hi, out);
            let _ = write!(out, ") << {bits}) | ({unsigned})(");
            write_expr_dec(lo, out);
            let _ = write!(out, ")) {symbol} ({unsigned})(");
            write_expr_dec(divisor, out);
            out.push_str("))))");
        }
        (
            operation @ (WideArithmetic::SignedDivQuotient | WideArithmetic::SignedDivRemainder),
            [hi, lo, divisor],
        ) => {
            let symbol = if matches!(operation, WideArithmetic::SignedDivQuotient) {
                "/"
            } else {
                "%"
            };
            let _ = write!(out, "(({signed})(((({wide_signed})({signed})(");
            write_expr_dec(hi, out);
            let _ = write!(out, ") * ((({wide_signed})1) << {bits})) + ({unsigned})(");
            write_expr_dec(lo, out);
            let _ = write!(out, ")) {symbol} ({signed})(");
            write_expr_dec(divisor, out);
            out.push_str(")))");
        }
        (WideArithmetic::CountLeadingZeros, [value]) => {
            // `clz(0)` is architecturally the operand's width in bits, and
            // `__builtin_clz` is UNDEFINED there — so the zero case is spelled
            // out rather than left to the builtin. The `({unsigned})` cast is
            // the other half of the exactness: the IR keeps a 32-bit machine
            // register at its canonical 64-bit width, and counting a 64-bit
            // quantity's leading zeros would answer 32 too high.
            //
            // The operand is written twice. It is a pure value expression here
            // (`can_eagerly_evaluate` governs what may reach an operand
            // position), so the duplication costs width in the output and
            // nothing in semantics — the same shape a compiler emits for this
            // idiom.
            let builtin = if bits >= 64 {
                "__builtin_clzll"
            } else {
                "__builtin_clz"
            };
            let operand = if bits >= 64 {
                "unsigned long long"
            } else {
                "unsigned int"
            };
            let _ = write!(out, "((({operand})(");
            write_expr_dec(value, out);
            let _ = write!(out, ") == 0) ? {bits} : {builtin}(({operand})(");
            write_expr_dec(value, out);
            out.push_str(")))");
        }
        (WideArithmetic::CountTrailingZeros, [value]) => {
            // The zero case is spelled out for the same reason the leading
            // count spells it out: `__builtin_ctz(0)` is UNDEFINED, while
            // `tzcnt` architecturally answers the operand width. The
            // `({operand})` cast is the other half — the IR keeps a 32-bit
            // machine register at its canonical 64-bit width, and counting a
            // 64-bit quantity's trailing zeros would answer 32 too high for
            // every operand whose low word is zero.
            let builtin = if bits >= 64 {
                "__builtin_ctzll"
            } else {
                "__builtin_ctz"
            };
            let operand = if bits >= 64 {
                "unsigned long long"
            } else {
                "unsigned int"
            };
            let _ = write!(out, "((({operand})(");
            write_expr_dec(value, out);
            let _ = write!(out, ") == 0) ? {bits} : {builtin}(({operand})(");
            write_expr_dec(value, out);
            out.push_str(")))");
        }
        (WideArithmetic::PopulationCount, [value]) => {
            // Total at every argument, so no zero case — but the width cast is
            // still load-bearing: a 32-bit `popcnt` must not count set bits in
            // the parent's stale high half.
            let builtin = if bits >= 64 {
                "__builtin_popcountll"
            } else {
                "__builtin_popcount"
            };
            let operand = if bits >= 64 {
                "unsigned long long"
            } else {
                "unsigned int"
            };
            let _ = write!(out, "({builtin}(({operand})(");
            write_expr_dec(value, out);
            out.push_str(")))");
        }
        _ => out.push_str("__unknown(0)"),
    }
}

fn write_expr_dec(e: &Expr, out: &mut String) {
    match e {
        Expr::Reg(v) => write_reg_dec(v, out),
        Expr::StackAddr { object, .. } => {
            if matches!(object, VReg::Phys(name) if parse_arg_index(name).is_some()) {
                out.push_str("(void *)(");
                write_reg_lvalue_dec(object, out);
                out.push(')');
            } else {
                out.push('&');
                write_reg_lvalue_dec(object, out);
                out.push_str("[0]");
            }
        }
        Expr::Const(c) => write_const_dec(*c, out),
        Expr::FloatConst { bits, width } => write_float_literal(*bits, *width, out),
        Expr::Addr(a) => {
            if dec_is_global_addr(*a) {
                let _ = write!(out, "&{}[0]", dec_global_name(*a));
            } else {
                let _ = write!(out, "0x{:x}", a);
            }
        }
        // In a value position a resolved symbol normally becomes its address
        // constant; the readable name is kept only where it is *called* (see
        // write_call_dec). A direct data dereference/store is the exception:
        // the collector marks its VA so the recompiled function addresses the
        // portable backing object rather than the old image mapping.
        Expr::Named { va, name } => {
            if dec_is_global_addr(*va) {
                let _ = write!(out, "&{}[0]", dec_global_name(*va));
            } else {
                // The identifier, when — and ONLY when — this render has
                // selected a prototype for it. That gate is the whole
                // difference from the 2026-08-05 attempt, which was measured
                // and reverted: it emitted `extern void <name>(void);`, which
                // conflicts with the callee's real signature once the whole
                // unit is compiled (`fixture_harness` and `arch_roundtrip` both
                // do). Cost then: 656 -> 633 and a CONTROL-lane regression.
                //
                // `selected_named_call_prototype` now answers from
                // `ir::symbol_env` — one agreed record per callee, keyed by the
                // identifier printed here — so the declaration this render
                // emits and the definition the unit contains are the same
                // signature by construction. A symbol with no such record keeps
                // its raw VA, which is the fail-closed answer.
                //
                // `__libc_start_main(main, ...)` is the shape this recovers: a
                // function's address passed as a value. GCC compiles the raw
                // literal to `mov $imm` where the original used `lea sym(%rip)`,
                // so byte_match could never agree.
                let displayed = sanitize_c_ident(callee_display_name(name));
                match selected_named_call_prototype(&displayed) {
                    Some(_) => {
                        let _ = write!(out, "(long)({})", displayed);
                    }
                    None => {
                        let _ = write!(out, "0x{:x}", va);
                    }
                }
            }
        }
        Expr::FunctionTableEntry {
            table_name, index, ..
        } => {
            out.push_str(&sanitize_c_ident(table_name));
            out.push('[');
            write_expr_dec(index, out);
            out.push(']');
        }
        Expr::StringLit { value } => write_string_lit(value, out),
        Expr::Lea {
            base,
            index,
            scale,
            disp,
            ..
        }
        | Expr::PdbFieldAddr {
            base,
            index,
            scale,
            disp,
            ..
        } => write_addr_arith_dec(base, index, *scale, *disp, out),
        Expr::Deref { addr, size } => {
            if let Some((base, index, hint)) = renderable_field_access(addr) {
                write_field_access_dec(base, index, hint, out);
                return;
            }
            // Array-index idiom: a `T`-sized read through `base + i*sizeof(T)`
            // where `base` is a declared `T *` renders as `base[i]`. This drops
            // the `(long)` cast + explicit scale, so the compiler re-emits its own
            // scaled-addressing (`lea (%rax,%rdx,4)`) instead of our `shl`+`add`.
            if let Some((base, index)) = try_array_index(addr, *size) {
                write_array_access_dec(base, index, *size, out);
            } else {
                // Use the recovered access width for the load cast (`*(int *)` for
                // a 4-byte read, not a blanket `*(long *)`). The width picks the
                // recompiled load instruction (`mov eax` vs `mov rax`), so matching
                // it to the original narrows byte_match's assembly diff.
                let _ = write!(out, "*({} *)(", width_ctype(*size));
                write_expr_dec(addr, out);
                out.push(')');
            }
        }
        Expr::Call {
            target,
            args,
            call_spec,
            ..
        } => write_call_dec(target, args, None, call_spec.as_ref(), out),
        Expr::Bin { op, lhs, rhs } => {
            // Logical (unsigned) right shift has no direct signed-`long` C form;
            // cast the operand to `unsigned long` so `>>` is the zero-filling
            // shift the IR means. Arithmetic shift (`Sar`) is plain `>>`.
            if matches!(op, BinOp::Shr) {
                // `widen::insert_widening_casts` states the reinterpretation
                // structurally when it has recovered types; re-stating it here
                // would only nest an identical cast.
                let stated = matches!(lhs.as_ref(), Expr::Cast { signed: false, .. });
                out.push('(');
                if stated {
                    write_expr_dec(lhs, out);
                } else {
                    let _ = write!(out, "({})(", shift_operand_ctype(lhs, rhs));
                    write_expr_dec(lhs, out);
                    out.push(')');
                }
                out.push_str(" >> ");
                write_expr_dec(rhs, out);
                out.push(')');
            } else if let Some((wide, narrow)) = matches!(op, BinOp::Shl)
                .then(|| wide_left_shift_operand_ctypes(lhs, rhs))
                .flatten()
            {
                let _ = write!(out, "(({wide})(({narrow})(");
                write_expr_dec(lhs, out);
                out.push_str(")) << ");
                write_expr_dec(rhs, out);
                out.push(')');
            } else if matches!(op, BinOp::Sar) {
                // Preserve both signedness and machine width at the point of
                // the shift. The explicit AST cast may otherwise be elided as
                // declaration-redundant even when copy propagation has replaced
                // the register with a wider unsigned producer.
                let (ctype, operand) = signed_shift_operand(lhs, rhs);
                let _ = write!(out, "(({ctype})(");
                write_expr_dec(operand, out);
                out.push_str(") >> ");
                write_expr_dec(rhs, out);
                out.push(')');
            } else {
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
                if !write_scaled_pointer_offset_dec(shown_op, lhs, &shown_rhs, out) {
                    write_machine_arithmetic_operand_dec(lhs, out);
                    let _ = write!(out, " {} ", binop_sym_c(shown_op));
                    write_machine_arithmetic_operand_dec(&shown_rhs, out);
                }
                out.push(')');
            }
        }
        Expr::Un { op, src } => {
            let _ = write!(out, "({}", unop_sym(*op));
            write_expr_dec(src, out);
            out.push(')');
        }
        Expr::Cast {
            signed,
            width,
            expr,
        } => {
            if let Some(reg) = redundant_declared_integer_cast(e) {
                write_reg_dec(reg, out);
            } else {
                // A DOUBLE-WORD cast is the one width `int_ctype` cannot spell:
                // it answers `long` for sixteen bytes, which silently halves
                // the value. That is the spelling a two-register INTEGER result
                // needs on both sides of the call boundary, and the extension
                // exists only on a 64-bit target — so it is derived from the
                // target's pointer width rather than named unconditionally.
                let pointer_width = DEC_POINTER_WIDTH.with(std::cell::Cell::get);
                let c_type = if *width == 16 && pointer_width == 8 {
                    double_width_ctype(*signed, pointer_width)
                } else if *width == 8 && DEC_SEMANTIC_WIDE_CAST.with(std::cell::Cell::get) {
                    target_int_ctype(*signed, *width)
                } else {
                    int_ctype(*signed, *width)
                };
                let _ = write!(out, "({c_type})(");
                // `Expr::Cast` is an INTEGER cast by construction — a width
                // and a signedness, nothing else — so an operand that RENDERS
                // as a `float` is a bit view of one, never a value to convert.
                // The machine agrees: `movd %xmm0, %eax` copies bits. Printing
                // the operand plainly made C perform its own float-to-integer
                // conversion instead, so a `float` member composed into an
                // INTEGER-class result handed back the NUMBER where the callee
                // had put the BIT PATTERN (`197:*:O2:hfa197_make_tagged`).
                //
                // The statement-level path (`write_representation_value_dec`)
                // has done this since the `fp174_float_bits` family was fixed;
                // this is the same rule in expression position, which is where
                // an optimised body puts it once the assignment is folded away.
                // A genuine conversion is `Expr::NumericConvert` and is
                // rendered by the arm below, untouched.
                match float_rendered_width(expr) {
                    Some(float_width) => write_float_bits_expr_dec(expr, float_width, out),
                    None => write_expr_dec(expr, out),
                }
                out.push(')');
            }
        }
        // The operand is spelled at the type it HAS before the conversion is
        // applied: a `float` source rendered as a machine word would convert
        // the bit pattern rather than the value, which is the same mistake the
        // union fallback makes and the reason this node exists.
        Expr::NumericConvert { from, to, expr } => {
            let _ = write!(out, "({})(", to.c_name());
            if from.is_float() {
                write_float_expr_dec(expr, from.width(), out);
            } else {
                // `from` is signed, and `write_expr_dec` spells integer
                // arithmetic through `(unsigned int)`/`(unsigned long)`
                // machine-width casts -- correct, and required, for wraparound.
                // Without restoring the declared type here, C converts an
                // UNSIGNED value: `(double)(seed * 6 + 1)` at `seed == -1`
                // returned 4294967291.0 instead of -5.0
                // (`197:*:*:hfa197_make_scalar`, failing on all four host lanes
                // and all eight cross lanes; diary Entry 59).
                //
                // Neither half was wrong on its own -- the conversion is right
                // and the wraparound casts are right -- and nothing between them
                // noticed the operand's C type had changed under the
                // conversion's feet. The comment above says the operand is
                // spelled at the type it HAS before the conversion; on this path
                // it was not.
                //
                // The cast also pins the WIDTH the machine actually reads:
                // `cvtsi2sd %eax` consumes 32 bits, so narrowing a wider
                // rendered operand to `from` is the instruction's own semantics,
                // not a loss.
                let _ = write!(out, "({})(", from.c_name());
                write_expr_dec(expr, out);
                out.push(')');
            }
            out.push(')');
        }
        Expr::Cmp { op, lhs, rhs } => {
            if write_unsigned_subtract_range_dec(*op, lhs, rhs, out) {
                return;
            }
            // Unsigned comparisons need explicit `unsigned long` casts; the
            // register-level `u<` / `u<=` spellings are not valid C.
            if matches!(op, CmpOp::Ult | CmpOp::Ule) {
                let sym = if matches!(op, CmpOp::Ult) { "<" } else { "<=" };
                out.push_str("((unsigned long)(");
                write_expr_dec(lhs, out);
                let _ = write!(out, ") {} (unsigned long)(", sym);
                write_expr_dec(rhs, out);
                out.push_str("))");
            } else {
                out.push('(');
                if !matches!(op, CmpOp::Eq | CmpOp::Ne)
                    || !matches!(rhs.as_ref(), Expr::Const(0))
                    || !write_direct_pointer_value_dec(lhs, out)
                {
                    write_expr_dec(lhs, out);
                }
                let _ = write!(out, " {} ", cmpop_sym_c(*op));
                if !matches!(op, CmpOp::Eq | CmpOp::Ne)
                    || !matches!(lhs.as_ref(), Expr::Const(0))
                    || !write_direct_pointer_value_dec(rhs, out)
                {
                    write_expr_dec(rhs, out);
                }
                out.push(')');
            }
        }
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => {
            let canonical_true =
                is_one_lazy_call_times_two(if_false) && unsigned_all_ones_width(if_true).is_some();
            let canonical_false =
                is_one_lazy_call_times_two(if_true) && unsigned_all_ones_width(if_false).is_some();
            let true_is_pointer = expression_has_pointer_representation(if_true);
            let false_is_pointer = expression_has_pointer_representation(if_false);
            let null_pointer_pair = (true_is_pointer
                && matches!(if_false.as_ref(), Expr::Const(0)))
                || (false_is_pointer && matches!(if_true.as_ref(), Expr::Const(0)));
            let mixed_representation = true_is_pointer != false_is_pointer && !null_pointer_pair;
            out.push('(');
            write_expr_dec(cond, out);
            out.push_str(" ? ");
            if mixed_representation {
                // A surrounding cast is too late: C resolves a conditional's
                // common type before applying it. Put both non-null arms in the
                // machine-word representation here so nested casts and stores
                // cannot emit an invalid pointer/integer conditional.
                write_representation_value_dec("long", if_true, out);
            } else {
                write_select_arm_dec(if_true, canonical_true, out);
            }
            out.push_str(" : ");
            if mixed_representation {
                write_representation_value_dec("long", if_false, out);
            } else {
                write_select_arm_dec(if_false, canonical_false, out);
            }
            out.push(')');
        }
        Expr::WideArithmetic { op, args, width } => {
            write_wide_arithmetic_dec(*op, args, *width, out);
        }
        // An unmodelled/indirect value: a call to an undeclared `__unknown`
        // (implicit-declaration warning only) keeps it a valid `long` rvalue.
        Expr::Unknown(_) => out.push_str("__unknown(0)"),
    }
}

fn strip_integer_casts(mut expression: &Expr) -> &Expr {
    while let Expr::Cast { expr, .. } = expression {
        expression = expr;
    }
    expression
}

fn unsigned_range_render_parts(expression: &Expr) -> Option<(&Expr, i64, u8)> {
    let mut narrowest = None;
    let mut current = expression;
    while let Expr::Cast { width, expr, .. } = current {
        narrowest = Some(narrowest.map_or(*width, |seen: u8| seen.min(*width)));
        current = expr;
    }
    let (value, low) = match current {
        Expr::Bin {
            op: BinOp::Sub,
            lhs,
            rhs,
        } => match strip_integer_casts(rhs) {
            Expr::Const(low) if *low >= 0 => (lhs.as_ref(), *low),
            _ => return None,
        },
        Expr::Bin {
            op: BinOp::Add,
            lhs,
            rhs,
        } => match strip_integer_casts(rhs) {
            Expr::Const(delta) if *delta < 0 => (lhs.as_ref(), delta.checked_neg()?),
            _ => return None,
        },
        _ => return None,
    };
    let width = narrowest.or_else(|| expr_machine_width(value))?;
    matches!(width, 1 | 2 | 4 | 8).then_some((value, low, width))
}

fn write_unsigned_range_value(value: &Expr, width: u8, out: &mut String) {
    let _ = write!(out, "({})(", int_ctype(false, width));
    write_expr_dec(value, out);
    out.push(')');
}

/// Render the compiler idiom `(unsigned W)(x - low) <= span` (or its reversed
/// rejecting form) as an explicit closed range. Width comes from the existing
/// typed render context and is restated on both uses of `x`.
fn write_unsigned_subtract_range_dec(op: CmpOp, lhs: &Expr, rhs: &Expr, out: &mut String) -> bool {
    if !matches!(op, CmpOp::Ult | CmpOp::Ule) {
        return false;
    }

    if let (Expr::Const(limit), Some((value, low, width))) =
        (strip_integer_casts(lhs), unsigned_range_render_parts(rhs))
    {
        let inside_op = if op == CmpOp::Ult {
            CmpOp::Ule
        } else {
            CmpOp::Ult
        };
        if let Some((low, high)) =
            crate::ir::cmp_fusion::unsigned_range_bounds(width, low, *limit, inside_op)
        {
            out.push('(');
            write_unsigned_range_value(value, width, out);
            let _ = write!(out, " < {low} || {high} < ");
            write_unsigned_range_value(value, width, out);
            out.push(')');
            return true;
        }
    }

    if let (Some((value, low, width)), Expr::Const(limit)) =
        (unsigned_range_render_parts(lhs), strip_integer_casts(rhs))
    {
        if let Some((low, high)) =
            crate::ir::cmp_fusion::unsigned_range_bounds(width, low, *limit, op)
        {
            out.push('(');
            let _ = write!(out, "{low} <= ");
            write_unsigned_range_value(value, width, out);
            out.push_str(" && ");
            write_unsigned_range_value(value, width, out);
            let _ = write!(out, " <= {high})");
            return true;
        }
    }
    false
}

fn unsigned_all_ones_width(expression: &Expr) -> Option<u8> {
    match expression {
        Expr::Cast {
            signed: false,
            width,
            expr,
        } if matches!(expr.as_ref(), Expr::Const(-1)) => Some(*width),
        _ => None,
    }
}

fn is_one_lazy_call_times_two(expression: &Expr) -> bool {
    matches!(
        expression,
        Expr::Bin {
            op: BinOp::Mul,
            lhs,
            rhs,
        } if (matches!(lhs.as_ref(), Expr::Call { .. })
            && matches!(rhs.as_ref(), Expr::Const(2)))
            || (matches!(rhs.as_ref(), Expr::Call { .. })
                && matches!(lhs.as_ref(), Expr::Const(2)))
    )
}

fn write_select_arm_dec(expression: &Expr, canonical_all_ones: bool, out: &mut String) {
    if canonical_all_ones {
        match unsigned_all_ones_width(expression) {
            Some(1) => out.push_str("0xffU"),
            Some(2) => out.push_str("0xffffU"),
            Some(4) => out.push_str("0xffffffffU"),
            Some(8) => out.push_str("0xffffffffffffffffULL"),
            _ => write_expr_dec(expression, out),
        }
    } else {
        write_expr_dec(expression, out);
    }
}

/// Render a declared pointer as a C pointer value rather than the integer
/// address representation used by generic machine arithmetic.
///
/// This is intentionally narrow: direct pointer identities (optionally behind
/// lossless machine casts) are safe in a null comparison. Arbitrary address
/// arithmetic still goes through `write_expr_dec`, where the integer spelling
/// is required for byte offsets and masks.
fn write_direct_pointer_value_dec(expression: &Expr, out: &mut String) -> bool {
    match expression {
        Expr::Reg(register @ VReg::Phys(name))
            if dec_ptr_arg_type(name).is_some()
                || dec_struct_ptr_type(name).is_some()
                || dec_is_stack_object(name) =>
        {
            write_reg_lvalue_dec(register, out);
            true
        }
        Expr::Cast { width, expr, .. }
            if *width == DEC_POINTER_WIDTH.with(std::cell::Cell::get) =>
        {
            write_direct_pointer_value_dec(expr, out)
        }
        _ => false,
    }
}

fn renderable_field_access(addr: &Expr) -> Option<(&VReg, Option<&VReg>, &PdbFieldHint)> {
    let Expr::PdbFieldAddr {
        base: Some(base),
        index,
        scale,
        hints,
        ..
    } = addr
    else {
        return None;
    };
    let [hint] = hints.as_slice() else {
        return None;
    };
    (hint.renderable
        && ((*scale == 1 && index.is_none()) || (*scale > 0 && index.is_some()))
        && valid_c_identifier(&hint.type_name)
        && valid_c_identifier(&hint.field_name)
        && DEC_RENDERABLE_STRUCTS.with(|selected| selected.borrow().contains(&hint.type_name)))
    .then_some((base, index.as_ref(), hint))
}

fn write_field_access_dec(
    base: &VReg,
    index: Option<&VReg>,
    hint: &PdbFieldHint,
    out: &mut String,
) {
    let base_is_declared = matches!(base, VReg::Phys(name) if dec_struct_ptr_type(name)
        .as_deref()
        .and_then(pointed_struct_name)
        == Some(hint.type_name.as_str()));
    if base_is_declared {
        write_reg_lvalue_dec(base, out);
    } else {
        let _ = write!(out, "((struct {} *)", hint.type_name);
        write_reg_lvalue_dec(base, out);
    }
    if let Some(index) = index {
        if base_is_declared {
            out.push('[');
        } else {
            out.push_str(")[");
        }
        if let (Some(signed), Some(width)) = (hint.index_signed, hint.index_width) {
            let _ = write!(out, "({})(", int_ctype(signed, width));
            write_reg_dec(index, out);
            out.push(')');
        } else {
            write_reg_dec(index, out);
        }
        let _ = write!(out, "].{}", hint.field_name);
    } else {
        let _ = write!(
            out,
            "{}{}",
            if base_is_declared { "->" } else { ")->" },
            hint.field_name
        );
    }
}

fn redundant_declared_integer_cast(expr: &Expr) -> Option<&VReg> {
    let Expr::Cast {
        signed,
        width,
        expr: inner,
    } = expr
    else {
        return None;
    };
    if let Expr::Reg(reg @ VReg::Phys(name)) = inner.as_ref() {
        return (dec_int_type(name) == Some((*signed, *width))).then_some(reg);
    }
    let Expr::Cast {
        signed: inner_signed,
        width: inner_width,
        expr: inner,
    } = inner.as_ref()
    else {
        return None;
    };
    let Expr::Reg(reg @ VReg::Phys(name)) = inner.as_ref() else {
        return None;
    };
    // C's integer promotions convert every 1/2-byte integer to signed int on
    // our target ABIs. If the declaration already states the inner cast, the
    // explicit two-cast chain has no source-level effect.
    (*signed
        && *width == 4
        && *inner_width < 4
        && dec_int_type(name) == Some((*inner_signed, *inner_width)))
    .then_some(reg)
}

/// Shared C-string quoting for the DecBench renderer.
fn write_string_lit(value: &str, out: &mut String) {
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

fn write_call_arg_dec(arg: &Expr, out: &mut String) {
    // `write_reg_dec` casts pointer arguments to integer addresses for machine
    // arithmetic. At a call boundary the recovered pointer declaration is the
    // stronger fact, so pass the pointer itself to the matching prototype.
    if let Expr::Reg(reg @ VReg::Phys(name)) = arg {
        if dec_ptr_arg_type(name).is_some() {
            write_reg_lvalue_dec(reg, out);
            return;
        }
    }
    write_expr_dec(arg, out);
}

/// The exact C pointer type a call argument renders as, when it is known.
///
/// Two different pointer types are still a type error, so "renders as a
/// pointer" is not enough to skip the boundary cast: the rendered type has to
/// be the declared parameter type. This oracle is consumed as a *proof of
/// equality* — every arm must answer the spelling `write_call_arg_dec` will
/// actually print, and anything it cannot name answers `None` so the caller
/// keeps the cast. Answering a spelling this renderer does not actually print
/// would suppress a needed cast and emit `-Wincompatible-pointer-types`, which
/// GCC 14 and later treat as an error.
fn call_argument_pointer_ctype(arg: &Expr) -> Option<String> {
    match arg {
        Expr::Reg(register @ VReg::Phys(_)) => {
            let declared = declared_reg_ctype(register);
            declared.ends_with('*').then_some(declared)
        }
        // A string literal has C type `char *` after array-to-pointer decay,
        // whatever pointee the callee's recovered prototype names.
        Expr::StringLit { .. } => Some("char *".to_string()),
        // `write_expr_dec` prints an incoming-argument frame object as
        // `(void *)(argN)` and every other frame object as `&local_N[0]` over
        // an `unsigned char local_N[..]` declaration.
        Expr::StackAddr { object, .. } => Some(
            if matches!(object, VReg::Phys(name) if parse_arg_index(name).is_some()) {
                "void *".to_string()
            } else {
                "unsigned char *".to_string()
            },
        ),
        _ => None,
    }
}

/// Whether a pointer parameter needs its argument reasserted with a cast.
///
/// C converts between object pointers only through `void *`; every other pair
/// of pointee types is a constraint violation that GCC 14 reports as an error.
/// So the cast is skipped exactly when the argument is PROVEN to render as a
/// pointer that C already accepts here: the same spelling, or a `void *` on
/// either side. An argument whose rendered spelling is unknown keeps the cast,
/// because that includes machine-word address arithmetic, which would
/// otherwise be an implicit integer-to-pointer conversion.
fn pointer_parameter_needs_cast(parameter_type: &str, arg: &Expr) -> bool {
    match call_argument_pointer_ctype(arg) {
        Some(rendered) => {
            rendered != parameter_type && rendered != "void *" && parameter_type != "void *"
        }
        None => true,
    }
}

/// Render a value proven to flow through scalar floating-point storage.
///
/// AAPCS-VFP commonly materialises a float field as `ldr r3, [base, #off]`
/// followed by `vmov sN, r3`. The move preserves bits; rendering the ordinary
/// width-only load as `*(int *)` and then applying `(float)` would perform a
/// numeric conversion and change every nontrivial value. In a proven VFP
/// expression, use a float-typed memory read. A surviving core-register value
/// is reinterpreted through a C99 union rather than numerically converted.
fn write_float_expr_dec(expr: &Expr, width: u8, out: &mut String) {
    let float_type = if width == 4 { "float" } else { "double" };
    match expr {
        Expr::FloatConst {
            width: literal_width,
            bits,
        } if *literal_width == width => write_float_literal(*bits, *literal_width, out),
        Expr::Reg(register @ VReg::Phys(_)) if declared_reg_ctype(register) == float_type => {
            write_reg_lvalue_dec(register, out);
        }
        // The OTHER float width is a numeric conversion, not a reinterpretation.
        // Only a value whose declared type is not floating point at all has
        // bits worth punning; `double` to `float` is `(float)x`, and taking its
        // bits instead hands back an unrelated number. i386 makes this routine
        // rather than exotic: `crate::ir::x87` models every x87 stack slot as
        // binary64, so a `float`-returning function's own result reaches a
        // four-byte context as a `double`-declared register, and
        // `172_float_double_widths::single_precision_horner` rendered its whole
        // Horner evaluation as bit patterns because of it.
        Expr::Reg(register @ VReg::Phys(_))
            if matches!(declared_reg_ctype(register).as_str(), "float" | "double") =>
        {
            let _ = write!(out, "({float_type})(");
            write_reg_lvalue_dec(register, out);
            out.push(')');
        }
        // A recovered conversion already states its own result type. Wrapping
        // it in the reinterpreting union below would take the bits of a value
        // that was just numerically converted — `(unsigned)((float)arg0)` —
        // and hand back a different number entirely.
        Expr::NumericConvert { to, .. } if *to == ScalarType::Float(width) => {
            write_expr_dec(expr, out);
        }
        // A conversion to the OTHER float width is still a number, so narrow or
        // widen it rather than punning it. `crate::ir::x87` widens every x87
        // load to binary64, which puts a `(double)` conversion in front of a
        // `float` context in every i386 single-precision function.
        Expr::NumericConvert {
            to: ScalarType::Float(_),
            ..
        } => {
            let _ = write!(out, "({float_type})(");
            write_expr_dec(expr, out);
            out.push(')');
        }
        Expr::Deref {
            addr,
            size: access_width,
        } if *access_width == width => {
            let _ = write!(out, "*({float_type} *)(");
            write_expr_dec(addr, out);
            out.push(')');
        }
        Expr::Bin { op, lhs, rhs }
            if matches!(op, BinOp::Add | BinOp::Sub | BinOp::Mul | BinOp::Div) =>
        {
            out.push('(');
            write_float_expr_dec(lhs, width, out);
            let _ = write!(out, " {} ", binop_sym_c(*op));
            write_float_expr_dec(rhs, width, out);
            out.push(')');
        }
        Expr::Un { op: UnOp::Neg, src } => {
            out.push_str("(-");
            write_float_expr_dec(src, width, out);
            out.push(')');
        }
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => {
            out.push('(');
            write_expr_dec(cond, out);
            out.push_str(" ? ");
            write_float_expr_dec(if_true, width, out);
            out.push_str(" : ");
            write_float_expr_dec(if_false, width, out);
            out.push(')');
        }
        _ if width == 4 => {
            out.push_str("((union { unsigned int bits; float value; }){ .bits = (unsigned int)(");
            write_expr_dec(expr, out);
            out.push_str(") }).value");
        }
        _ => {
            out.push_str(
                "((union { unsigned long long bits; double value; }){ .bits = (unsigned long long)(",
            );
            write_expr_dec(expr, out);
            out.push_str(") }).value");
        }
    }
}

/// The width of the C floating type a value RENDERS AS, when it renders as one.
///
/// The mirror of the question [`write_float_expr_dec`] answers. That direction
/// is asked "these are bits, how do I spell them as a `float`"; this one is
/// asked "this spelling IS a `float`, how do I spell its bits". Only a value
/// whose printed C type is genuinely floating point answers, because the
/// reinterpretation this gates is not free to apply to a value that was never
/// a `float`.
///
/// Four spellings qualify, and the boundary between them and everything else
/// is the reason this can be a rule rather than a heuristic:
///
///  * a register the type recovery declared `float`/`double` — the machine
///    moved it with `movss`/`movsd`/`vmov`, which copies bits;
///  * a recovered conversion whose stated result type is floating, which
///    `write_expr_dec` prints as `(float)(…)`/`(double)(…)`;
///  * a floating literal; and
///  * floating arithmetic over any of those.
///
/// A genuine `cvttss2si` is `NumericConvert { to: SignedInt }` and prints as
/// `(int)(…)`, so it answers `None` and keeps its arithmetic meaning. That is
/// what stops the reinterpretation from swallowing the conversions C really
/// does perform, and it is a structural distinction rather than a guess: the
/// lifter states the conversion's result type, and this reads it.
///
/// The recursion is deliberately NOT extended to `Expr::Select`, whose two arms
/// can disagree, or to a `Deref`, which has no type of its own beyond its
/// access width — neither has an instance in the fixture corpus and neither is
/// verified here.
fn float_rendered_width(expr: &Expr) -> Option<u8> {
    match expr {
        Expr::Reg(register @ VReg::Phys(_)) => match declared_reg_ctype(register).as_str() {
            "float" => Some(4),
            "double" => Some(8),
            _ => None,
        },
        Expr::NumericConvert {
            to: ScalarType::Float(width),
            ..
        } => Some(*width),
        Expr::FloatConst { width, .. } => Some(*width),
        // Floating ARITHMETIC, which `write_float_expr_dec` already renders
        // recursively — this only decides whether to ask it. One floating
        // operand is enough, because C's usual arithmetic conversions make the
        // whole expression floating (C23 6.3.1.8) and the machine agreed: the
        // instruction was `divss`, not `div`. Bounded to the four operators
        // that HAVE a floating form, so a bitwise or shift operand (which C
        // gives no floating operand at all) is not swept in here.
        Expr::Bin { op, lhs, rhs }
            if matches!(op, BinOp::Add | BinOp::Sub | BinOp::Mul | BinOp::Div) =>
        {
            float_rendered_width(lhs).or_else(|| float_rendered_width(rhs))
        }
        Expr::Un { op: UnOp::Neg, src } => float_rendered_width(src),
        _ => None,
    }
}

/// Render a floating value's BIT PATTERN, for a destination that is declared
/// an integer and cannot be respelled.
///
/// `unsigned int bits = value;` where `value` is a `float` is a C *value*
/// conversion — C23 6.3.1.4 truncates toward zero — so `1.5f` was written as
/// `1`, not `0x3FC00000`. The machine's `movss %xmm0, -0x14(%rbp)` is a bit
/// copy, and the C spelling for that is the same C99 union
/// [`write_float_expr_dec`] already uses for the other direction, read from
/// the member that was not written. `-fno-strict-aliasing` is not required:
/// reading a different member of a union whose value was set through another
/// member is what C23 6.5.3.4 footnote 106 defines, and it is the pun both GCC
/// and Clang document as supported.
///
/// The union's integer member is the width of the SOURCE, not of the
/// destination. Four bytes of `float` reaching an eight-byte lvalue is a
/// partial register write whose upper half the instruction never defined; the
/// zero extension C then applies is the same assumption
/// `write_float_expr_dec`'s fallback makes in the other direction.
fn write_float_bits_expr_dec(expr: &Expr, width: u8, out: &mut String) {
    if width == 4 {
        out.push_str("((union { unsigned int bits; float value; }){ .value = ");
    } else {
        out.push_str("((union { unsigned long long bits; double value; }){ .value = ");
    }
    write_float_expr_dec(expr, width, out);
    out.push_str(" }).bits");
}

/// Render one argument against the exact parameter type consumed by this call.
///
/// C validates a conditional expression's two arms before applying an outer
/// cast, so `(void *)(cond ? word : pointer)` is still ill-typed in C23.  Push
/// the call-boundary conversion into each arm while retaining the explicit
/// casts used for authoritative library prototypes.
fn write_typed_call_arg_dec(parameter_type: &str, arg: &Expr, out: &mut String) {
    if let Expr::Select {
        cond,
        if_true,
        if_false,
        ..
    } = arg
    {
        out.push('(');
        write_expr_dec(cond, out);
        out.push_str(" ? ");
        write_typed_call_arg_dec(parameter_type, if_true, out);
        out.push_str(" : ");
        write_typed_call_arg_dec(parameter_type, if_false, out);
        out.push(')');
        return;
    }

    if matches!(parameter_type, "float" | "double") {
        // A source-level parameter already declared with the exact scalar
        // floating type needs no conversion at the call boundary.  Retain the
        // explicit cast for machine-word carriers, where it is the evidence
        // that the bits belong to the VFP storage class rather than an integer
        // numeric conversion.
        if let Expr::Reg(register) = arg {
            if declared_reg_ctype(register) == parameter_type {
                write_call_arg_dec(arg, out);
                return;
            }
        }
        out.push('(');
        out.push_str(parameter_type);
        out.push_str(")(");
        write_float_expr_dec(arg, if parameter_type == "float" { 4 } else { 8 }, out);
        out.push(')');
        return;
    }

    if integer_call_arg_cast_is_redundant(parameter_type, arg) {
        write_call_arg_dec(arg, out);
        return;
    }
    out.push('(');
    out.push_str(parameter_type);
    out.push_str(")(");
    write_call_arg_dec(arg, out);
    out.push(')');
}

/// Whether the call-boundary cast onto `parameter_type` would convert nothing.
///
/// The cast exists because the argument's machine carrier is usually wider than
/// the parameter — `(int)(rsi)` on a `long`-declared register is a real
/// truncation and must stay. It is noise when the argument is already exactly
/// that type, and noise at a call boundary is not free: `arm_hf_mixed_callee(
/// (int)(7), arg0, (int)(arg1))` in place of `arm_hf_mixed_callee(7, arg0,
/// arg1)` is three casts a reader must check and discard.
///
/// Deliberately narrow. Only two things are admitted:
///
/// * a register whose OWN declaration in this render is that same type, so the
///   conversion is the identity by construction; and
/// * an integer literal the type represents exactly, where C's own conversion
///   at the (in-scope, declared) prototype does the same thing the cast would.
///
/// Anything else — a pointer, an expression, a type this does not recognise —
/// keeps its cast. Being wrong in that direction costs a redundant cast; being
/// wrong in the other direction silently drops a truncation.
fn integer_call_arg_cast_is_redundant(parameter_type: &str, arg: &Expr) -> bool {
    match arg {
        Expr::Reg(register @ VReg::Phys(_)) => declared_reg_ctype(register) == parameter_type,
        Expr::Const(value) => signed_integer_type_represents(parameter_type, *value),
        // A symbolised code address already renders as `(long)(name)`; the call
        // boundary would otherwise wrap that in a second identical cast.
        Expr::Named { .. } => parameter_type == "long",
        _ => false,
    }
}

/// Whether `c_type` is a signed integer type that holds `value` exactly.
fn signed_integer_type_represents(c_type: &str, value: i64) -> bool {
    let (low, high) = match c_type {
        "signed char" | "int8_t" => (i64::from(i8::MIN), i64::from(i8::MAX)),
        "short" | "int16_t" => (i64::from(i16::MIN), i64::from(i16::MAX)),
        "int" | "signed int" | "int32_t" => (i64::from(i32::MIN), i64::from(i32::MAX)),
        "long" | "long long" | "int64_t" => (i64::MIN, i64::MAX),
        _ => return false,
    };
    (low..=high).contains(&value)
}

/// Re-spell an unsigned-looking immediate in the signed destination's value
/// domain when the two spellings have the same two's-complement bit pattern.
///
/// The lifters preserve immediates as machine bit patterns, so a 32-bit
/// `0xffff_ffff` commonly reaches the typed renderer as positive `4294967295`.
/// Once the consuming declaration proves `int32_t`, C will truncate those bits
/// to that destination. Printing `-1` states the resulting source-level value
/// directly and avoids an implementation-defined out-of-range conversion.
/// Unknown, unsigned, boolean, pointer, and 64-bit destinations decline.
pub(super) fn signed_destination_literal(
    c_type: &str,
    value: i64,
    pointer_width: u8,
) -> Option<i64> {
    if value < 0 {
        return None;
    }
    let width = match c_type.trim() {
        "signed char" | "int8_t" => 1,
        "short" | "signed short" | "short int" | "signed short int" | "int16_t" => 2,
        "int" | "signed" | "signed int" | "int32_t" => 4,
        "long" | "signed long" | "long int" | "signed long int" => pointer_width,
        "long long" | "signed long long" | "long long int" | "signed long long int" | "int64_t" => {
            8
        }
        _ => return None,
    };
    // Expr::Const is i64, so an unsigned-looking 64-bit value with its sign
    // bit set cannot be represented as a positive input here. Negative i64
    // literals are already printed in their signed value domain.
    if width == 0 || width >= 8 {
        return None;
    }
    let bits = u32::from(width) * 8;
    let modulus = 1_i128 << bits;
    let raw = i128::from(value);
    if raw >= modulus || raw < modulus / 2 {
        return None;
    }
    i64::try_from(raw - modulus).ok()
}

fn effective_call_site_spec(
    target: &Expr,
    args: &[Expr],
    dst: Option<&VReg>,
    call_spec: Option<&CallSiteSpec>,
) -> CallSiteSpec {
    call_spec
        .cloned()
        .unwrap_or_else(|| crate::ir::call_contracts::recover_call_site_spec(target, args, dst))
}

fn call_prototype_for_render(
    target: &Expr,
    args: &[Expr],
    dst: Option<&VReg>,
    call_spec: Option<&CallSiteSpec>,
) -> (CallSiteSpec, Option<CallPrototype>, bool) {
    let call_spec = effective_call_site_spec(target, args, dst, call_spec);
    let declaration = match target {
        Expr::Named { name, .. } => selected_named_call_prototype(name),
        _ => None,
    };
    let requires_cast = declaration.as_ref().is_some_and(|declaration| {
        !crate::ir::call_contracts::prototype_accepts(declaration, &call_spec.call_prototype)
            || (dst.is_some() && declaration.return_type != call_spec.call_prototype.return_type)
    });
    (call_spec, declaration, requires_cast)
}

fn write_call_pointer_declarator(prototype: &CallPrototype, out: &mut String) {
    out.push_str(&prototype.return_type);
    out.push_str(" (*)(");
    if prototype.parameter_types.is_empty() {
        out.push_str("void");
    } else {
        for (index, parameter_type) in prototype.parameter_types.iter().enumerate() {
            if index > 0 {
                out.push_str(", ");
            }
            out.push_str(parameter_type);
        }
        if prototype.variadic {
            out.push_str(", ...");
        }
    }
    out.push(')');
}

fn write_call_dec(
    target: &Expr,
    args: &[Expr],
    dst: Option<&VReg>,
    call_spec: Option<&CallSiteSpec>,
    out: &mut String,
) {
    let (call_spec, declaration, requires_cast) =
        call_prototype_for_render(target, args, dst, call_spec);
    match target {
        Expr::Named { name, .. } => {
            let displayed = sanitize_c_ident(callee_display_name(name));
            if requires_cast {
                out.push_str("((");
                write_call_pointer_declarator(&call_spec.call_prototype, out);
                out.push(')');
                out.push_str(&displayed);
                out.push(')');
            } else {
                out.push_str(&displayed);
            }
        }
        _ => {
            out.push_str("((");
            write_call_pointer_declarator(&call_spec.call_prototype, out);
            out.push_str(")(");
            write_expr_dec(target, out);
            out.push_str("))");
        }
    }
    // The callee's source-level name, for the symbolic-constant annotation
    // below. Only a directly-named call can be looked up: an indirect call
    // through a pointer is not known to be `mprotect` just because it might
    // be.
    let annotated_callee = match target {
        Expr::Named { name, .. } => Some(sanitize_c_ident(callee_display_name(name))),
        _ => None,
    };
    out.push('(');
    for (i, a) in args.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        let emitted_prototype = if requires_cast || declaration.is_none() {
            &call_spec.call_prototype
        } else {
            declaration
                .as_ref()
                .expect("a direct uncast call has a selected declaration")
        };
        if let Some(parameter_type) = emitted_prototype.parameter_types.get(i) {
            // The expression and function-pointer declarator must consume the
            // same call-site type. This is essential for recovered pointer
            // parameters too: a machine-word carrier such as `rbp` otherwise
            // makes the generated C invalid even though the ABI fact is sound.
            let representation_mismatch =
                parameter_type.ends_with('*') != expression_has_pointer_representation(a);
            if emitted_prototype.authority == CallPrototypeAuthority::Authoritative
                // Address arithmetic is rendered in machine-word form even
                // when its base has pointer representation. Reassert every
                // recovered pointer parameter at the consuming boundary so C
                // sees the ABI pointer rather than an implicit integer cast.
                //
                // The cast is skipped only on PROOF that the argument already
                // renders as this exact pointer spelling. "Renders as some
                // pointer" is not that proof: a string literal is `char *` and
                // a frame object is `unsigned char *`, both incompatible with
                // a recovered `long *`/`int *` parameter, and C rejects the
                // call outright rather than converting.
                || (parameter_type.ends_with('*')
                    && pointer_parameter_needs_cast(parameter_type, a))
                || representation_mismatch
                // A recovered AAPCS-VFP parameter still proves the consuming
                // storage class.  Render its complete expression in float
                // context so core-loaded IEEE payloads remain bit-preserving;
                // C's ordinary implicit conversion would invent a `vcvt` that
                // is absent from the binary.
                || matches!(parameter_type.as_str(), "float" | "double")
            {
                write_typed_call_arg_dec(parameter_type, a, out);
            } else {
                write_call_arg_dec(a, out);
            }
        } else {
            // Variadic tails and unknown calls retain their recovered value
            // spelling; default argument promotions belong to the C compiler.
            write_call_arg_dec(a, out);
        }
        // Name the magic numbers. `mprotect(page, 4096, 5)` is correct and
        // nearly unreadable; the 5 is PROT_READ|PROT_EXEC, which is the most
        // interesting thing in the call. As a COMMENT and not a substitution,
        // because this render is recompiled by the execution differential and
        // a bare `PROT_READ` would need headers the renderer does not emit.
        if let Some(callee) = annotated_callee.as_deref() {
            if let Some(value) = crate::ir::named_constants::constant_argument_value(a) {
                if let Some(name) = crate::ir::named_constants::symbolic_name(callee, i, value) {
                    let _ = write!(out, " /* {name} */");
                }
            }
        }
    }
    out.push(')');
}

fn expression_has_pointer_representation(expr: &Expr) -> bool {
    match expr {
        Expr::Reg(VReg::Phys(name)) => {
            dec_ptr_arg_type(name).is_some()
                || dec_ptr_width(name).is_some()
                || dec_is_stack_object(name)
        }
        Expr::Named { .. }
        | Expr::FunctionTableEntry { .. }
        | Expr::StringLit { .. }
        | Expr::StackAddr { .. }
        | Expr::Lea { .. }
        | Expr::PdbFieldAddr { .. } => true,
        Expr::Select {
            if_true, if_false, ..
        } => {
            expression_has_pointer_representation(if_true)
                || expression_has_pointer_representation(if_false)
        }
        Expr::Bin {
            op: BinOp::Add,
            lhs,
            rhs,
        } => {
            expression_has_pointer_representation(lhs) || expression_has_pointer_representation(rhs)
        }
        Expr::Bin {
            op: BinOp::Sub,
            lhs,
            rhs,
        } => {
            expression_has_pointer_representation(lhs)
                && !expression_has_pointer_representation(rhs)
        }
        Expr::Deref { addr, .. } => renderable_field_access(addr).is_some_and(|(_, _, hint)| {
            hint.field_type
                .as_deref()
                .is_some_and(|field_type| field_type.trim_end().ends_with('*'))
        }),
        // A numeric conversion produces an arithmetic value by construction:
        // `(double)p` is not a pointer, whatever `p` was.
        Expr::NumericConvert { .. } => false,
        cast @ Expr::Cast { expr, .. } => {
            let direct_pointer = matches!(expr.as_ref(), Expr::Reg(VReg::Phys(name))
                if dec_ptr_arg_type(name).is_some() || dec_struct_ptr_type(name).is_some());
            direct_pointer
                || redundant_declared_integer_cast(cast).is_some_and(|reg| {
                    matches!(reg, VReg::Phys(name) if dec_ptr_arg_type(name).is_some()
                        || dec_struct_ptr_type(name).is_some()
                        || dec_ptr_width(name).is_some()
                        || dec_is_stack_object(name))
                })
        }
        // A direct image address that was proven to be writable static storage
        // is spelled `&glaurung_global_X[0]` — a real C pointer, not the
        // integer literal the address used to render as. The classifier has to
        // agree with the printer or every integer-typed consumer receives a
        // pointer without a conversion.
        Expr::Addr(address) => dec_is_global_addr(*address),
        Expr::Call { call_spec, .. } => call_spec
            .as_ref()
            .is_some_and(|spec| spec.call_prototype.return_type.trim_end().ends_with('*')),
        Expr::Reg(_)
        | Expr::Const(_)
        | Expr::FloatConst { .. }
        | Expr::Bin { .. }
        | Expr::Un { .. }
        | Expr::Cmp { .. }
        | Expr::WideArithmetic { .. }
        | Expr::Unknown(_) => false,
    }
}

fn write_expr_for_destination_dec(destination_type: &str, src: &Expr, out: &mut String) {
    let pointer_width = DEC_POINTER_WIDTH.with(std::cell::Cell::get);
    let semantic_wide =
        crate::ir::call_contracts::integer_c_type_width(destination_type, pointer_width)
            .is_some_and(|width| width > pointer_width);
    DEC_SEMANTIC_WIDE_CAST.with(|context| {
        let previous = context.replace(context.get() || semantic_wide);
        write_expr_dec(src, out);
        context.set(previous);
    });
}

/// Is `c_type` the C boolean, whose conversion is a zero test rather than a
/// truncation?
///
/// Both spellings reach the renderer: DWARF emits `_Bool` for C and `bool` for
/// C++, and `dwarf_render_types` passes the source spelling through unchanged.
fn is_bool_ctype(c_type: &str) -> bool {
    matches!(c_type.trim(), "_Bool" | "bool")
}

/// Is this expression already 0 or 1, so that converting it to `_Bool` cannot
/// change it?
///
/// A C relational or equality operator yields 0 or 1 by definition (C23
/// 6.5.8p6, 6.5.9p3), which is what a recovered `setcc`/`test` renders as, and
/// a literal states its own value. Narrowing either would be output churn with
/// no semantic content — and `nrw194_bool_bit` (`test $0x100 ; setne %al`) is
/// exactly that case, already passing.
fn is_normalised_boolean(e: &Expr) -> bool {
    match e {
        Expr::Cmp { .. } => true,
        Expr::Const(value) => matches!(value, 0 | 1),
        // An INTEGER cast (which `Expr::Cast` is by construction) cannot turn
        // 0 or 1 into anything else: truncation keeps both, and either
        // extension of them is itself. A float `NumericConvert` deliberately
        // does not qualify — `(int)3.5` is 3.
        Expr::Cast { expr, .. } => is_normalised_boolean(expr),
        _ => false,
    }
}

/// Render a value against the declaration that consumes it.
///
/// The AST retains machine values even when type recovery proves that one side
/// of the C boundary is a pointer. Explicit casts preserve those address bits
/// and keep the generated unit valid under the producer's real diagnostics;
/// implicit pointer/integer conversions are neither valid C23 nor useful
/// evidence about the recovered program.
fn write_representation_value_dec(destination_type: &str, src: &Expr, out: &mut String) {
    if let Expr::Select {
        cond,
        if_true,
        if_false,
        ..
    } = src
    {
        let canonical_true =
            is_one_lazy_call_times_two(if_false) && unsigned_all_ones_width(if_true).is_some();
        let canonical_false =
            is_one_lazy_call_times_two(if_true) && unsigned_all_ones_width(if_false).is_some();
        // C type-checks the two conditional operands before applying an outer
        // cast. Convert each arm at the recovered destination boundary so a
        // pointer-shaped literal and a machine word form one valid expression.
        out.push('(');
        write_expr_dec(cond, out);
        out.push_str(" ? ");
        if canonical_true {
            write_select_arm_dec(if_true, true, out);
        } else {
            write_representation_value_dec(destination_type, if_true, out);
        }
        out.push_str(" : ");
        if canonical_false {
            write_select_arm_dec(if_false, true, out);
        } else {
            write_representation_value_dec(destination_type, if_false, out);
        }
        out.push(')');
        return;
    }

    if let Expr::Cast {
        signed,
        width,
        expr,
    } = src
    {
        if let Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } = expr.as_ref()
        {
            let cast_type = int_ctype(*signed, *width);
            let destination_is_pointer = destination_type.ends_with('*');
            if destination_is_pointer {
                let _ = write!(out, "({destination_type})(");
            }
            let _ = write!(out, "({cast_type})(");
            write_expr_dec(cond, out);
            out.push_str(" ? ");
            // An outer integer cast does not make a pointer/integer conditional
            // valid: C resolves the two arms first. Convert each arm at the
            // cast's own representation boundary before forming the select.
            write_representation_value_dec(cast_type, if_true, out);
            out.push_str(" : ");
            write_representation_value_dec(cast_type, if_false, out);
            out.push_str(")");
            if destination_is_pointer {
                out.push(')');
            }
            return;
        }
    }

    if matches!(destination_type, "float" | "double") {
        write_float_expr_dec(src, if destination_type == "float" { 4 } else { 8 }, out);
        return;
    }

    if let Expr::Const(value) = src {
        let pointer_width = DEC_POINTER_WIDTH.with(std::cell::Cell::get);
        if let Some(signed_value) =
            signed_destination_literal(destination_type, *value, pointer_width)
        {
            write_const_dec(signed_value, out);
            return;
        }
    }

    // ...and the mirror of it, which did not exist. This function picks the
    // conversion from the DESTINATION type alone, so an integer-declared
    // destination fed by a value that renders as a `float` got C's arithmetic
    // conversion — a truncation toward zero — where the machine had done a bit
    // copy. GCC's `-O0` `memcpy(&bits, &value, 4)` is `movss %xmm0, -0x14(%rbp)`
    // then `mov -0x14(%rbp), %eax`, and rendering that as `bits = value;` wrote
    // `1` for `1.5f` (`174:*:O0:fp174_float_bits`, whose four callers are all
    // `fail`; `172:gcc:O0:double_precision_horner` is the `double` form).
    //
    // `_Bool` is excluded because C's conversion to it is a TEST against zero
    // (C23 6.3.1.2), which is meaningful on the floating value itself and is
    // what the arm below spells; punning first would test the bit pattern, and
    // `-0.0` would read as `true`. Pointers are excluded because a float has no
    // address semantics to preserve and the pointer arms below own that case.
    if !is_bool_ctype(destination_type) && !destination_type.ends_with('*') {
        if let Some(width) = float_rendered_width(src) {
            write_float_bits_expr_dec(src, width, out);
            return;
        }
    }

    if is_bool_ctype(destination_type)
        && !expression_has_pointer_representation(src)
        && !is_normalised_boolean(src)
    {
        // C converts a value to `_Bool` by comparing it against zero — 6.3.1.2,
        // "the result is 0 if the value compares equal to 0; otherwise 1" —
        // and to every OTHER integer type by reducing it modulo that type's
        // width (6.3.1.3). The modular case is exactly what the machine did, so
        // the conversion C already performs at the boundary is the right one
        // and spelling a cast for it would change nothing on the ~650
        // `int32_t`-returning functions in the corpus. `_Bool` is the sole type
        // where the language's conversion is a TEST rather than a truncation,
        // and therefore the sole type where the boundary has to be narrowed
        // explicitly first.
        //
        // It has to be narrowed because the ABI puts a `_Bool` result in `al`
        // alone and says nothing about the rest of the register (SysV AMD64
        // psABI 3.2.3; AAPCS64 4.1). `nrw194_bool_and` at clang -O2 is
        // `and %edi,%eax ; and $0x1,%al` — a bit-preserving byte AND whose
        // partial write this recovery models exactly, then returns the whole
        // merged register. For x == y == -64 the source answers 0 while
        // `(var8 & -256) | (var8 & 1)` is 0x1FFFFF00, which `!= 0` reads as
        // `true`.
        //
        // Narrowing to `unsigned char` and testing that is the ABI's own
        // reading of the register, and it is what the caller does.
        out.push_str("((unsigned char)(");
        write_expr_dec(src, out);
        out.push_str(") != 0)");
        return;
    }

    let destination_is_pointer = destination_type.ends_with('*');
    let source_is_pointer = expression_has_pointer_representation(src);
    if destination_is_pointer && source_is_pointer {
        if let Expr::Reg(reg @ VReg::Phys(_)) = src {
            let source_type = declared_reg_ctype(reg);
            // Pointer facts and emitted declarations intentionally have
            // different authorities. A recovered call result can retain its
            // machine-word declaration while later uses prove address
            // semantics; a stack object is emitted as a byte array even when
            // its promoted identity has a concrete pointee width. In both
            // cases, use the C declaration that the compiler actually sees to
            // decide whether this assignment needs an explicit conversion.
            let source_needs_cast = dec_is_stack_object(match reg {
                VReg::Phys(name) => name,
                _ => unreachable!("the pattern above admits only physical registers"),
            }) || !source_type.ends_with('*')
                || (source_type != destination_type
                    && source_type != "void *"
                    && destination_type != "void *");
            if source_needs_cast {
                let _ = write!(out, "({destination_type})");
                write_reg_lvalue_dec(reg, out);
                return;
            }
        }
        match src {
            // Register rvalues are normally rendered as machine words so byte
            // arithmetic remains valid.  At a pointer boundary, use the
            // declared pointer lvalue directly when no arithmetic is present.
            Expr::Reg(reg @ VReg::Phys(_)) => write_reg_lvalue_dec(reg, out),
            Expr::Cast { expr, .. }
                if matches!(expr.as_ref(), Expr::Reg(VReg::Phys(name))
                    if dec_ptr_arg_type(name).is_some()
                        || dec_struct_ptr_type(name).is_some()) =>
            {
                if let Expr::Reg(reg) = expr.as_ref() {
                    write_reg_lvalue_dec(reg, out);
                } else {
                    write_expr_dec(src, out);
                }
            }
            Expr::Deref { addr, .. }
                if renderable_field_access(addr).is_some_and(|(_, _, hint)| {
                    hint.field_type
                        .as_deref()
                        .is_some_and(|field_type| field_type.trim_end().ends_with('*'))
                }) =>
            {
                write_expr_dec(src, out);
            }
            // String literals already have the compatible `char *` family in
            // C. Recovered stack objects, however, are deliberately emitted as
            // unsigned-byte arrays. Their decay is compatible with `void *`
            // but needs an explicit conversion for every concrete pointee type.
            Expr::StringLit { .. } => write_expr_dec(src, out),
            Expr::StackAddr { .. } if destination_type == "void *" => write_expr_dec(src, out),
            Expr::StackAddr { .. } => {
                let _ = write!(out, "({destination_type})");
                write_expr_dec(src, out);
            }
            // Address arithmetic, named addresses, and LEA nodes retain a
            // pointer *representation* in the middle layer but deliberately
            // render as integer machine expressions.  Cast the completed
            // expression back at the consuming boundary.
            _ => {
                let _ = write!(out, "({destination_type})(");
                write_expr_dec(src, out);
                out.push(')');
            }
        }
        return;
    }
    if destination_is_pointer == source_is_pointer {
        write_expr_for_destination_dec(destination_type, src, out);
        return;
    }

    if source_is_pointer {
        if let Expr::Reg(reg @ VReg::Phys(_)) = src {
            let _ = write!(out, "({destination_type})");
            write_reg_lvalue_dec(reg, out);
            return;
        } else {
            let _ = write!(out, "({destination_type})(");
            write_expr_dec(src, out);
            out.push(')');
            return;
        }
    }

    let _ = write!(out, "({destination_type})(");
    write_expr_dec(src, out);
    out.push(')');
}
