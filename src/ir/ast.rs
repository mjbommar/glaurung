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

use std::fmt::Write;

use crate::ir::call_contracts::CallPrototype;
use crate::ir::types::{
    is_promoted_local_name as is_internal_promoted_local, BinOp, CmpOp, Flag, UnOp, VReg, Width,
};
use crate::ir::types_recover::{TypeHint, TypeMap};

// The lowering pipeline took the LLIR vocabulary with it (see `mod lower_ops`
// below), `mod named_calls` took the last product-code reader of
// `CallSiteSpec`, and `mod decbench_render` took the last product-code reader
// of `CallPrototypeAuthority`. These names remain in scope only for `mod tests`
// and the `ast_tests/` files, which build LLIR inputs and reach them through
// `use super::*`.
#[cfg(test)]
use crate::ir::call_contracts::{CallPrototypeAuthority, CallSiteSpec};
#[cfg(test)]
use crate::ir::structure::Region;
#[cfg(test)]
use crate::ir::types::{CallTarget, LlirFunction, MemOp, Op, Value};

/// Whether `name` is a stack slot the promotion pass named — i.e. a real local
/// variable, so a store *to* it is a plain assignment rather than a pointer
/// write.
fn is_promoted_local(name: &str) -> bool {
    DEC_SOURCE_LOCALS.with(|locals| is_promoted_local_in(name, &locals.borrow()))
}

/// The promoted-local predicate against an explicit source-local set.
///
/// [`declaration_plan::DeclarationPlan::compute`] is a pure function of values
/// and must not read the render's ambient source-local cell; it holds that set
/// directly. Sharing the predicate rather than restating it keeps the two
/// callers from drifting apart.
fn is_promoted_local_in(name: &str, source_locals: &std::collections::HashSet<String>) -> bool {
    is_internal_promoted_local(name) || source_locals.contains(name)
}

mod abi_widths;
mod c_render;
mod ctx_render;
mod dec_render;
mod decbench_render;
mod declaration_plan;
mod dwarf_render_types;
mod float_gate;
mod lower_conds;
mod lower_ops;
mod lower_region;
mod named_calls;
mod param_spills;
mod prepare;
mod return_ctype;
mod return_folds;
mod width_semantics;

pub use c_render::render_c;
pub use ctx_render::{render, render_with_types};
// The DecBench front door keeps its `ast::render_decbench*` paths: `mod tests`,
// the `ast_tests/` files and `python_bindings::ir` all name it there.
pub use decbench_render::{
    render_decbench, render_decbench_typed, render_decbench_typed_with_output,
    render_decbench_typed_with_output_and_prototype,
    render_decbench_typed_with_output_and_prototype_and_dwarf_types,
    render_decbench_typed_with_output_and_prototype_and_dwarf_types_and_local_types,
    render_decbench_typed_with_output_and_prototype_and_dwarf_types_and_local_types_and_parameter_names,
};
pub(crate) use dwarf_render_types::dwarf_prototype_type_is_renderable;
pub(crate) use lower_conds::negate_cmp_expr;
pub use lower_region::lower;
pub(crate) use prepare::{
    drop_machine_frame_comments, prepare_for_decbench_with_output_and_protected_locals,
};
pub use prepare::{
    prepare_for_decbench, prepare_for_decbench_with_output, settle_copies_and_constants,
};
pub(crate) use return_folds::remove_redundant_return_constant_assignments;
pub use return_folds::{fold_exhaustive_if_returns, fold_exhaustive_switch_returns};

#[cfg(test)]
pub(crate) use abi_widths::refine_decbench_abi_widths;
pub(crate) use abi_widths::refine_decbench_abi_widths_with_value_widths;
pub(crate) use return_ctype::{
    declared_int_type, fold_typed_return_abi_extensions, infer_return_ctype, inferred_return_width,
};

// Kept nameable as `ast::X` for the siblings and test modules that still reach
// these through `super::`: `float_gate` matches on `ScalarFloatOperation`,
// `c_render` and `ctx_render` call `one_armed_select`, `lower_region` and
// `prepare` call `fold_returns`, `width_semantics`'s and
// `ast_tests/memory_fill.rs`'s tests call `lower_op`, and `mod tests` below
// calls `hoist_inline_flag_conds`, `deduplicate_labels` and
// `scalar_float_semantics_are_closed`.
#[cfg(test)]
use float_gate::scalar_float_semantics_are_closed;
#[cfg(test)]
use lower_conds::hoist_inline_flag_conds;
use lower_conds::one_armed_select;
#[cfg(test)]
use lower_ops::lower_op;
use lower_ops::ScalarFloatOperation;
#[cfg(test)]
use lower_region::deduplicate_labels;
use named_calls::recover_named_call_prototypes;
use return_folds::fold_returns;

use dec_render::write_stmt_dec;
use declaration_plan::{DeclarationInputs, DeclarationPlan, LocalDeclaration};

// -- Expressions ---------------------------------------------------------------

/// PDB-backed field candidate for a memory operand offset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdbFieldHint {
    pub type_name: String,
    pub field_name: String,
    pub field_type: Option<String>,
    pub offset: u64,
    /// Integer view applied to a recovered aggregate subscript, when the
    /// machine address narrowed or sign-extended the index before scaling.
    pub index_signed: Option<bool>,
    pub index_width: Option<u8>,
    /// True only when the defining aggregate will be emitted with the C body.
    pub renderable: bool,
}

/// Exact callable target carried by a relocation-proven function-pointer table.
///
/// The address remains available for cross-reference while the symbol name lets
/// the standalone C renderer reconstruct a portable initializer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionTableTarget {
    pub va: u64,
    pub name: String,
}

/// Exact integer operations that C has no operator for, and that therefore need
/// their own renderer to survive the LLIR-to-AST boundary.
///
/// Originally this was only the operations whose machine result is *wider* than
/// an ordinary C scalar — keeping them typed is what prevents x86's implicit
/// high-half registers from disappearing. [`Self::CountLeadingZeros`] joins them
/// for the same structural reason rather than the same arithmetic one: it is
/// exactly representable in C, but only through a spelling no `BinOp`/`UnOp`
/// covers, and its operand's *width* is part of its meaning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WideArithmetic {
    UnsignedMulHigh,
    SignedMulHigh,
    UnsignedDivQuotient,
    UnsignedDivRemainder,
    SignedDivQuotient,
    SignedDivRemainder,
    /// `clz` — leading zeros of the operand at the declared width, with the
    /// architectural `clz(0) == width_in_bits` (ARM DDI 0487 C6.2.66; AArch64
    /// and ARM32 agree). NOT `__builtin_clz` alone, which is undefined at zero.
    CountLeadingZeros,
    /// `ctz` — trailing zeros of the operand at the declared width, with the
    /// architectural `ctz(0) == width_in_bits` (Intel SDM Vol. 2B, TZCNT; the
    /// AArch64 `rbit`+`clz` idiom and ARM32's `rbit` agree). NOT
    /// `__builtin_ctz` alone, which is undefined at zero.
    ///
    /// Separate from [`Self::CountLeadingZeros`] rather than expressed through
    /// it because the identity that relates them,
    /// `ctz(x) = width - 1 - clz(x ^ (x - 1))`, is exact only for a NONZERO
    /// operand — and the zero case is precisely the half of the meaning this
    /// enum exists to carry.
    CountTrailingZeros,
    /// `popcnt` — the number of set bits in the operand at the declared width.
    /// Total: unlike the two zero counts it has no undefined argument, so the
    /// width is the only thing that has to be stated.
    PopulationCount,
}

impl WideArithmetic {
    fn name(self) -> &'static str {
        match self {
            Self::UnsignedMulHigh => "umul_high",
            Self::SignedMulHigh => "smul_high",
            Self::UnsignedDivQuotient => "udiv_wide_quotient",
            Self::UnsignedDivRemainder => "udiv_wide_remainder",
            Self::SignedDivQuotient => "sdiv_wide_quotient",
            Self::SignedDivRemainder => "sdiv_wide_remainder",
            Self::CountLeadingZeros => "count_leading_zeros",
            Self::CountTrailingZeros => "count_trailing_zeros",
            Self::PopulationCount => "population_count",
        }
    }
}

/// A C-level expression. v1 is deliberately shallow: we carry raw VReg
/// references and constants without reconstructing use-def chains. The
/// expression-reconstruction pass can later replace `Reg` with compound
/// subexpressions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expr {
    Reg(VReg),
    Const(i64),
    /// Exact IEEE-754 literal payload recovered from a floating-point machine
    /// instruction. Storing bits rather than `f64` retains `Eq` and preserves
    /// signed zero and every finite source literal without decimal roundoff.
    FloatConst {
        bits: u64,
        width: u8,
    },
    Addr(u64),
    /// A VA that the resolver has attached a symbol name to. The raw VA
    /// travels along so downstream consumers (e.g. a debugger view) can
    /// still cross-reference.
    Named {
        va: u64,
        name: String,
    },
    /// One indexed element of a symbol-backed function-pointer table whose
    /// complete contents were proven by object relocations.
    ///
    /// This is deliberately distinct from a generic dereference.  Re-emitting
    /// the input image VA is not portable, while replacing a writable table by
    /// direct calls would discard its data semantics.  The DecBench renderer
    /// therefore materialises the table and indexes it by name.
    FunctionTableEntry {
        table_va: u64,
        table_name: String,
        pointer_size: u8,
        index: Box<Expr>,
        targets: Vec<FunctionTableTarget>,
    },
    /// A C-string literal recovered from the binary's rodata. The printer
    /// renders this with proper `"..."` quoting and C-style escapes.
    StringLit {
        value: String,
    },
    /// Address of a recovered stack object.
    ///
    /// This is semantic storage, not arithmetic on the machine frame pointer.
    /// Keeping it explicit prevents a valid machine expression such as
    /// `rbp - 0x20` from becoming a read of an uninitialised C local after the
    /// prologue is removed.
    StackAddr {
        object: VReg,
        /// Conservatively recovered storage extent in bytes. The DecBench C
        /// renderer uses an array of this size so a constructor may initialise
        /// the complete object, not overrun a pointer-sized scalar surrogate.
        size: u16,
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
    /// Address-of a memory operand with PDB-backed candidate field names
    /// for the displacement. Kept as a hint because v0 does not yet know
    /// the concrete struct type of the base register.
    PdbFieldAddr {
        base: Option<VReg>,
        index: Option<VReg>,
        scale: u8,
        disp: i64,
        #[doc(hidden)]
        segment: Option<String>,
        hints: Vec<PdbFieldHint>,
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
    /// A value-producing C call.
    ///
    /// Calls normally remain statement calls so their effects stay explicit.
    /// This expression form is introduced only when a proven assignment
    /// diamond places the original call inside one arm of a lazy select. C's
    /// conditional operator preserves that lazy evaluation; moving the call
    /// outside the select would not.
    Call {
        target: Box<Expr>,
        args: Vec<Expr>,
        call_spec: Option<crate::ir::call_contracts::CallSiteSpec>,
        /// Exact ABI result width under the active machine data model.
        result_width: Option<u8>,
    },
    /// A lazy three-input select: `cond ? if_true : if_false`.
    ///
    /// Unlike [`Stmt::If`], this does not introduce control flow. Both value
    /// arms remain explicit reads, matching [`Op::Ite`] use-def semantics.
    Select {
        cond: Box<Expr>,
        if_true: Box<Expr>,
        if_false: Box<Expr>,
        /// Width of the selected value in bytes.
        width: u8,
    },
    /// An exact multiply-high or double-width divide result.
    WideArithmetic {
        op: WideArithmetic,
        args: Vec<Expr>,
        /// Machine operand width in bytes (2, 4, or 8).
        width: u8,
    },
    /// A width/sign-changing cast: `(<ctype>)(expr)`. Carries the *target* integer
    /// type so zero/sign extension and truncation are preserved through lowering
    /// instead of collapsing to a bare assignment. `signed` picks the C type's
    /// signedness; `width` is the byte width (1/2/4/8).
    Cast {
        signed: bool,
        width: u8,
        expr: Box<Expr>,
    },
    /// A NUMERIC conversion between scalar arithmetic types — the meaning of
    /// every x86 `cvt*` and every ARM `vcvt`: `(double)f`, `(float)d`,
    /// `(double)i`, `(int)f`.
    ///
    /// Deliberately not [`Expr::Cast`], which is an integer width/sign change
    /// and cannot say "the operand is a `float`". Deliberately not a bare
    /// assignment either: `write_float_expr_dec` falls back to a C99 union when
    /// it cannot prove the operand is already at the destination's float type,
    /// and that union REINTERPRETS the bits. Reinterpreting is right for
    /// AAPCS-VFP's `vmov s0, r3` and wrong for `cvtss2sd`, and only the
    /// producing instruction knows which of the two it was. Recording the
    /// distinction here is what keeps `173_float_int_conversions` from
    /// returning a float's bit pattern where its value belongs.
    ///
    /// `from` is carried as well as `to` so the operand can be spelled at the
    /// type it actually has; without it a `float`-typed source would be
    /// rendered as a machine word and the conversion applied to the bits.
    NumericConvert {
        from: ScalarType,
        to: ScalarType,
        expr: Box<Expr>,
    },
    /// Target of an indirect call / computed value we couldn't simplify.
    Unknown(String),
}

impl Expr {
    /// Return whether evaluating this expression can invoke a callee.
    ///
    /// Calls may be nested in a lazy select arm. Passes that delete, duplicate,
    /// or move expressions must use this shared query instead of assuming every
    /// [`Stmt::Assign`] source is pure.
    pub(crate) fn contains_call(&self) -> bool {
        match self {
            Self::Call { .. } => true,
            Self::Deref { addr, .. }
            | Self::Un { src: addr, .. }
            | Self::Cast { expr: addr, .. }
            | Self::NumericConvert { expr: addr, .. }
            | Self::FunctionTableEntry { index: addr, .. } => addr.contains_call(),
            Self::Bin { lhs, rhs, .. } | Self::Cmp { lhs, rhs, .. } => {
                lhs.contains_call() || rhs.contains_call()
            }
            Self::Select {
                cond,
                if_true,
                if_false,
                ..
            } => cond.contains_call() || if_true.contains_call() || if_false.contains_call(),
            Self::WideArithmetic { args, .. } => args.iter().any(Self::contains_call),
            Self::Reg(_)
            | Self::Const(_)
            | Self::FloatConst { .. }
            | Self::Addr(_)
            | Self::Named { .. }
            | Self::StringLit { .. }
            | Self::StackAddr { .. }
            | Self::Lea { .. }
            | Self::PdbFieldAddr { .. }
            | Self::Unknown(_) => false,
        }
    }

    /// Return whether this expression reads `target` directly or through one
    /// of its recursively nested operands.
    pub(crate) fn contains_reg(&self, target: &VReg) -> bool {
        match self {
            Self::Reg(reg) => reg == target,
            Self::StackAddr { object, .. } => object == target,
            Self::Deref { addr, .. } => addr.contains_reg(target),
            Self::Bin { lhs, rhs, .. } | Self::Cmp { lhs, rhs, .. } => {
                lhs.contains_reg(target) || rhs.contains_reg(target)
            }
            Self::Select {
                cond,
                if_true,
                if_false,
                ..
            } => {
                cond.contains_reg(target)
                    || if_true.contains_reg(target)
                    || if_false.contains_reg(target)
            }
            Self::Call {
                target: call_target,
                args,
                ..
            } => {
                call_target.contains_reg(target)
                    || args.iter().any(|argument| argument.contains_reg(target))
            }
            Self::Un { src, .. } => src.contains_reg(target),
            Self::Cast { expr, .. } | Self::NumericConvert { expr, .. } => {
                expr.contains_reg(target)
            }
            Self::FunctionTableEntry { index, .. } => index.contains_reg(target),
            Self::WideArithmetic { args, .. } => {
                args.iter().any(|argument| argument.contains_reg(target))
            }
            Self::Lea { base, index, .. } | Self::PdbFieldAddr { base, index, .. } => {
                base.as_ref() == Some(target) || index.as_ref() == Some(target)
            }
            Self::Const(_)
            | Self::FloatConst { .. }
            | Self::Addr(_)
            | Self::Named { .. }
            | Self::StringLit { .. }
            | Self::Unknown(_) => false,
        }
    }
}

/// One end of an [`Expr::NumericConvert`]: a C arithmetic type, by family and
/// byte width.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScalarType {
    /// IEEE binary32 (`width == 4`) or binary64 (`width == 8`).
    Float(u8),
    /// A signed integer of this byte width.
    SignedInt(u8),
}

impl ScalarType {
    /// The C type name this end is spelled with.
    pub fn c_name(self) -> &'static str {
        match self {
            ScalarType::Float(4) => "float",
            ScalarType::Float(_) => "double",
            ScalarType::SignedInt(1) => "signed char",
            ScalarType::SignedInt(2) => "short",
            ScalarType::SignedInt(4) => "int",
            ScalarType::SignedInt(_) => "long long",
        }
    }

    /// Byte width of the type.
    pub fn width(self) -> u8 {
        match self {
            ScalarType::Float(width) | ScalarType::SignedInt(width) => width,
        }
    }

    /// Whether this end is a floating-point type.
    pub fn is_float(self) -> bool {
        matches!(self, ScalarType::Float(_))
    }
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
        /// Access width in bytes (from the LLIR `MemOp.size`), so the printer
        /// emits the correct pointee type (`*(int *)` for a 4-byte store, not a
        /// blanket `*(long *)` that clobbers adjacent memory).
        size: u8,
    },
    Call {
        target: Expr,
        /// Reconstructed argument expressions, in platform calling-
        /// convention order. Empty until the argument-reconstruction pass
        /// runs.
        args: Vec<Expr>,
        /// Where the callee's return value lands, once the ABI says so
        /// (`call_args::reconstruct_args`). `None` until then, and for a call whose
        /// result provably goes unused.
        ///
        /// Without this the value model has nowhere to record that a call PRODUCES
        /// something: `use_def::def_uses` reported `Op::Call` as defining nothing, so
        /// a read of the return register after a call saw the stale pre-call value —
        /// `fib` rendered `fib(); var4 = var2;`, taking the argument instead of the
        /// result.
        dst: Option<VReg>,
        /// Callee-level and recovered call-site prototype facts. Populated after
        /// argument reconstruction; later AST passes preserve it alongside the
        /// call rather than rebuilding a function-wide guess in the printer.
        call_spec: Option<crate::ir::call_contracts::CallSiteSpec>,
    },
    Return {
        value: Option<Expr>,
    },
    /// Source-level C++ throw recovered from the exact Itanium ABI
    /// allocate/store/`__cxa_throw` sequence.
    Throw {
        value: Expr,
    },
    /// Source-level C++ exception region backed by an LSDA-proven landing pad.
    TryCatch {
        try_body: Vec<Stmt>,
        catches: Vec<CatchClause>,
    },
    /// Labelled position (used for unstructured fallbacks and goto targets).
    Label(u64),
    Goto {
        target: u64,
    },
    /// A computed transfer the structurer did NOT turn into a `Switch` — an
    /// unresolved jump table, a tail call through a register, a vtable dispatch.
    ///
    /// It exists so the output cannot quietly imply control falls through. The
    /// previous modelling (an indirect `Op::Call`) rendered these as a call whose
    /// result was assigned and dropped, which reads as "we understood this" when
    /// the truth is the opposite.
    IndirectGoto {
        target: Expr,
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
    /// `for (init; cond; step) { body }` recovered after conservative loop
    /// structuring. `init` and `step` are boxed ordinary assignment/store nodes
    /// so value identity and promoted-stack-local semantics remain explicit.
    For {
        init: Box<Stmt>,
        cond: Expr,
        step: Box<Stmt>,
        body: Vec<Stmt>,
    },
    /// `do { body } while (cond);` — the condition is evaluated after the body.
    DoWhile {
        body: Vec<Stmt>,
        cond: Expr,
    },
    /// `break;` out of the nearest enclosing loop. Emitted when a loop whose
    /// per-iteration header work (test setup, or a do-while body) must run each
    /// iteration is lowered as `while (1) { <header work>; if (!cond) break; body }`.
    Break,
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
    /// Reconstructed `switch (discriminant) { case N: <body>; ... }`
    /// emitted by the structurer when it recognizes a multi-target
    /// dispatch (typically a jump-table-driven switch). Each case body
    /// implicitly ends with `break`; the renderer appends one. (#193)
    Switch {
        /// The dispatch expression. v0 leaves this as a placeholder
        /// `dispatch` register reference; later passes will recover the
        /// original switched value from the index computation.
        discriminant: Expr,
        /// Ordered list of (case-label, case-body) pairs. The label is
        /// the index into the jump table when known, else None for
        /// "default" / unreachable arms.
        cases: Vec<(Option<i64>, Vec<Stmt>)>,
        /// Optional default arm body, executed when no case matches.
        default: Option<Vec<Stmt>>,
    },
}

/// One typed handler owned by [`Stmt::TryCatch`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatchClause {
    pub type_name: String,
    pub binding: VReg,
    pub body: Vec<Stmt>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Function {
    pub name: String,
    pub entry_va: u64,
    pub body: Vec<Stmt>,
}

/// The C scalar type of a given memory-access byte width, for load/store casts.
fn width_ctype(size: u8) -> &'static str {
    match size {
        1 => "char",
        2 => "short",
        4 => "int",
        _ => "long",
    }
}

// -- Text printer -------------------------------------------------------------

fn binop_sym(op: BinOp) -> &'static str {
    match op {
        BinOp::Add => "+",
        BinOp::Sub => "-",
        BinOp::Mul => "*",
        BinOp::Div => "/",
        BinOp::LogicalAnd => "&&",
        BinOp::LogicalOr => "||",
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
        CmpOp::Ule => "u<=",
        CmpOp::Slt => "<",
        CmpOp::Sle => "<=",
    }
}

fn write_pdb_field_hints(hints: &[PdbFieldHint], out: &mut String) {
    if hints.is_empty() {
        return;
    }
    out.push_str(" /* ");
    for (i, hint) in hints.iter().enumerate() {
        if i > 0 {
            out.push_str(" | ");
        }
        let _ = write!(out, "{}.{}", hint.type_name, hint.field_name);
        if let Some(field_type) = &hint.field_type {
            if !field_type.is_empty() {
                let _ = write!(out, ": {}", field_type);
            }
        }
    }
    out.push_str(" */");
}

fn write_float_literal(bits: u64, width: u8, out: &mut String) {
    let (mut rendered, suffix) = if width == 4 {
        let value = f32::from_bits(bits as u32);
        if value.is_nan() {
            out.push_str("__builtin_nanf(\"\")");
            return;
        }
        if value == f32::INFINITY {
            out.push_str("__builtin_inff()");
            return;
        }
        if value == f32::NEG_INFINITY {
            out.push_str("-__builtin_inff()");
            return;
        }
        (value.to_string(), "f")
    } else {
        let value = f64::from_bits(bits);
        if value.is_nan() {
            out.push_str("__builtin_nan(\"\")");
            return;
        }
        if value == f64::INFINITY {
            out.push_str("__builtin_inf()");
            return;
        }
        if value == f64::NEG_INFINITY {
            out.push_str("-__builtin_inf()");
            return;
        }
        (value.to_string(), "")
    };
    if !rendered.contains(['.', 'e', 'E']) {
        rendered.push_str(".0");
    }
    out.push_str(&rendered);
    out.push_str(suffix);
}

fn indent(out: &mut String, level: usize) {
    for _ in 0..level {
        out.push_str("    ");
    }
}

fn call_target_name(target: &Expr) -> Option<&str> {
    match target {
        Expr::Named { name, .. } => Some(name.as_str()),
        Expr::Unknown(name) => Some(name.as_str()),
        _ => None,
    }
}

fn write_call_proto_hint(target: &Expr, out: &mut String) {
    let Some(name) = call_target_name(target) else {
        return;
    };
    let Some(proto) = crate::ir::winapi_prototypes::lookup(name) else {
        return;
    };
    out.push_str(" // proto: ");
    out.push_str(&crate::ir::winapi_prototypes::render_signature(proto));
}

fn binop_sym_c(op: BinOp) -> &'static str {
    match op {
        BinOp::Sar | BinOp::Shr => ">>",
        other => binop_sym(other),
    }
}

/// Like [`cmpop_sym`], but valid C. Unsigned comparisons are handled by the
/// caller with `unsigned long` casts; the signed/equality forms map directly.
fn cmpop_sym_c(op: CmpOp) -> &'static str {
    match op {
        CmpOp::Eq => "==",
        CmpOp::Ne => "!=",
        CmpOp::Slt => "<",
        CmpOp::Sle => "<=",
        // Unsigned forms are rendered with casts by the caller; keep a valid
        // fallback token so this is never a syntax error.
        CmpOp::Ult => "<",
        CmpOp::Ule => "<=",
    }
}

// -- DecBench parseable-C renderer -------------------------------------------
//
// `render_decbench` emits a *syntactically valid* C translation-unit fragment
// for one function, as opposed to `render_c` which is a register-level reading
// aid (`fn name { ... }`, `%zf` flags, `&[...]` address forms — none of which
// parse as C). External consumers such as the DecBench benchmark harness feed
// our output to a tolerant C front-end (Joern for the structural metric, or
// `gcc -fsyntax-only` as a sanity gate); a hard parse error there zeroes every
// downstream score. So this renderer holds a single contract: **the output
// parses.** It achieves that by
//   * synthesising a real signature `long name(long arg0, ...)` (arity from the
//     highest `argN` the naming pass left in the body),
//   * declaring `long <id>;` for every local identifier referenced (vars,
//     stack slots, temps, `ret`, flags) so nothing is undeclared,
//   * lowering memory to `*(long *)(addr)` loads/stores and addresses to plain
//     `long` arithmetic (no `&[...]`, no segment prefixes),
//   * spelling calls as `callee(args)` with a recovered block-scope prototype,
//     or a concrete per-call function-pointer prototype for indirect targets,
//     and
//   * turning constructs with no faithful C spelling — unmodelled instructions,
//     pushes/pops, nops — into comments or elisions rather than invalid tokens.
// Recovered types are used where the middle layer proves them; unresolved
// values retain the conservative `long` ABI-word fallback. See
// `docs/reference/decompiler-passes.md`.

/// The C integer type for a `(signed, byte-width)` pair — used to render
/// `Expr::Cast` (`(int)`, `(unsigned char)`, …).
fn int_ctype(signed: bool, width: u8) -> &'static str {
    match (signed, width) {
        (true, 1) => "signed char",
        (false, 1) => "unsigned char",
        (true, 2) => "short",
        (false, 2) => "unsigned short",
        (true, 4) => "int",
        (false, 4) => "unsigned int",
        (false, 8) => "unsigned long",
        _ => "long",
    }
}

/// C spelling for a byte width that is proven semantic rather than inherited
/// from the logical SSA parent register.
fn target_int_ctype(signed: bool, width: u8) -> &'static str {
    crate::ir::types_recover::c_type_for_hint_with_pointer_width(
        TypeHint::Int { signed, width },
        DEC_POINTER_WIDTH.with(std::cell::Cell::get),
    )
}

/// The pointee C type for a store of `size` bytes, so `*(T *)(addr) = v` writes
/// exactly `size` bytes (a 4-byte store must be `*(int *)`, not `*(long *)`).
fn store_pointee_ctype(size: u8) -> &'static str {
    match size {
        1 => "signed char",
        2 => "short",
        4 => "int",
        _ => "long",
    }
}

/// Map a recovered [`TypeHint`] to a concrete C type spelling. Widths and
/// signedness come from `types_recover`; pointers carry a pointee-width-derived
/// element type. This is what turns the blanket `long` into `int`/`unsigned
/// int`/`char *`/… for the DecBench renderer.
fn hint_to_ctype(hint: TypeHint) -> &'static str {
    // The general TypeMap still contains logical-parent widths (notably the
    // 64-bit SSA parent used to model i386 registers).  Until those storage
    // facts are split from proven source widths, only explicit-width AST
    // operations and recovered prototypes may use the target-parametric
    // spelling.  Treating every width-8 hint as semantic made ordinary ILP32
    // loop locals `long long` and changed their wrap behavior.
    crate::ir::types_recover::c_type_for_hint(hint)
}

/// The C type for an identifier: its recovered hint if the (already remapped)
/// TypeMap has one, else the safe `long` default. We never *guess* a narrower
/// type without a signal — an unknown value stays `long`.
fn ctype_for(ident: &str, tm: Option<&TypeMap>) -> &'static str {
    tm.and_then(|m| m.get(&VReg::Phys(ident.to_string())))
        .map(hint_to_ctype)
        .unwrap_or("long")
}

/// Identifiers and control-flow anchors gathered from a function body so the
/// DecBench renderer can declare every local and reconcile goto/label pairs.
#[derive(Default)]
struct DecIdents {
    /// Highest `argN` index seen (drives the synthesised signature arity).
    max_arg: Option<usize>,
    /// Every non-argument identifier that will appear in the body. Synthetic
    /// values retain their stable lexical order.
    locals: std::collections::BTreeSet<String>,
    /// Authoritative source locals in semantic first-use order. Declaration
    /// order affects stack layout and therefore recompilation fidelity at O0;
    /// sorting after a DWARF rename (`local_10` -> `s`, `local_14` -> `i`)
    /// reverses the original storage order merely because `i < s` lexically.
    source_local_order: Vec<String>,
    source_local_members: std::collections::HashSet<String>,
    /// Generated `varN`, lifter `tN`, and versioned predicate identifiers.
    temporaries: std::collections::BTreeSet<String>,
    /// Raw ISA registers which survived naming and will become C locals.
    physical_registers: std::collections::BTreeSet<String>,
    /// Recovered address-taken stack objects and their required byte extents.
    /// Kept separate from scalar locals so the C declaration reserves the
    /// complete object storage.
    stack_objects: std::collections::BTreeMap<String, u16>,
    /// VAs that appear as `Stmt::Label` (defined labels).
    labels: std::collections::BTreeSet<u64>,
    /// VAs that appear as `Stmt::Goto` targets (used labels).
    gotos: std::collections::BTreeSet<u64>,
    /// Direct goto occurrences (not merely unique targets).
    goto_count: usize,
    /// Computed transfers and unsupported instructions retained in the AST.
    unresolved_transfer_count: usize,
    /// The recovered body calls `__stack_chk_fail`, i.e. the ORIGINAL function
    /// was compiled with a stack protector. Gates the `no_stack_protector`
    /// suppression: a function that already had a canary must keep it.
    calls_stack_check: bool,
    /// At least one expression contains an explicit unknown/poison value and
    /// therefore needs the C23-compatible helper declaration.
    has_unknown_value: bool,
    /// Recursive statement count used only for the exceptional GCC RTL-ICE
    /// compilation guard in the DecBench renderer.
    statement_count: usize,
    /// Relocation-proven function tables referenced by the body, keyed by
    /// original VA so repeated call sites emit one stable local definition.
    function_tables: std::collections::BTreeMap<u64, (String, Vec<FunctionTableTarget>)>,
    /// Direct absolute storage VAs that need portable C objects rather than
    /// original-image process addresses, mapped to the byte extent each object
    /// must cover.
    ///
    /// Two independent proofs put a VA here, and the extent differs with the
    /// proof:
    ///
    /// * the body reads or writes **through** it (a `Deref` base, a `Store`
    ///   address) — the extent is the widest access the body performs;
    /// * the body only **takes** the address and hands it on (an argument, a
    ///   returned pointer) — there is no access to measure, so the extent comes
    ///   from the image's own storage layout (see
    ///   [`crate::ir::static_storage`]). Those are exactly the sites that used
    ///   to render as bare hex, and exactly the ones a callee may write far
    ///   past a nominal machine word: `snprintf(uid_str, 22, ...)`.
    ///
    /// Wider than `u8` because a storage-derived extent is not an access width
    /// and routinely exceeds 255 bytes.
    global_addresses: std::collections::BTreeMap<u64, u32>,
    /// Scalar names whose value is actually a complete 128-bit machine load.
    /// These render as byte arrays so no high half is discarded.
    wide_locals: std::collections::BTreeSet<String>,
    /// Exact source-level return type attached to each call destination.
    ///
    /// `None` records conflicting prototypes for the same identity and makes
    /// declaration fall back conservatively.  Normally call-result lifetime
    /// splitting gives every call a distinct `varN`, so a value here is a
    /// stronger declaration fact than the flow-insensitive TypeMap.
    call_result_types: std::collections::BTreeMap<String, Option<String>>,
}

/// If `name` is exactly `arg` followed by decimal digits, return that index.
///
/// Shared with the naming pass rather than duplicated there: the `argN` spelling is
/// one convention with several consumers, and a second copy is how they drift.
pub(crate) fn parse_arg_index(name: &str) -> Option<usize> {
    let rest = name.strip_prefix("arg")?;
    if rest.is_empty() || !rest.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let index: usize = rest.parse().ok()?;
    // A malformed stack displacement must never turn rendering into an
    // unbounded `for 0..argN` allocation. Keep the defensive ceiling high
    // enough for unusually large generated-C interfaces while rejecting the
    // multi-million/billion indices produced by corrupt displacements.
    (index < 1024).then_some(index)
}

fn is_generated_temporary(name: &str) -> bool {
    is_high_variable(name)
        || name.strip_prefix('t').is_some_and(|digits| {
            !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit())
        })
        || name.starts_with("pred_")
}

/// An exact source-value identity introduced from an SSA-versioned register.
/// Unlike frame/ABI registers, a `varN` covers one recovered value lifetime and
/// can consume facts proven on the prepared AST's definition graph.
fn is_high_variable(name: &str) -> bool {
    name.strip_prefix("var").is_some_and(|suffix| {
        !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
    })
}

/// The C-identifier spelling for a processor flag (`Flag::Z` -> `zf`).
fn flag_ident(fl: &Flag) -> &'static str {
    fl.ident()
}

/// Map an arbitrary name (function or register) to a valid C identifier: keep
/// `[A-Za-z0-9_]`, replace the rest with `_`, and prefix a leading digit.
pub fn sanitize_c_ident(name: &str) -> String {
    let mut s = String::with_capacity(name.len());
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            s.push(ch);
        } else {
            s.push('_');
        }
    }
    if s.is_empty() {
        return "fn_anon".to_string();
    }
    if s.as_bytes()[0].is_ascii_digit() {
        s.insert(0, '_');
    }
    s
}

/// Neutralise text going into a `/* ... */` or `// ...` comment: no early
/// terminator, no newlines.
fn sanitize_comment(s: &str) -> String {
    s.replace("*/", "* /").replace(['\n', '\r'], " ")
}

/// Record the (sanitised) spelling of a single register operand as either an
/// argument (updating `max_arg`) or a local.
fn collect_reg(v: &VReg, ids: &mut DecIdents) {
    let spelling = match v {
        VReg::Phys(n) => {
            if let Some(idx) = parse_arg_index(n) {
                ids.max_arg = Some(ids.max_arg.map_or(idx, |m| m.max(idx)));
                return;
            }
            if crate::ir::machine_register::is_machine_register_name(n) {
                ids.physical_registers.insert(n.clone());
            }
            if is_generated_temporary(n) {
                ids.temporaries.insert(n.clone());
            }
            sanitize_c_ident(n)
        }
        VReg::Temp(i) => {
            let name = format!("t{i}");
            ids.temporaries.insert(name.clone());
            name
        }
        VReg::Flag(fl) => flag_ident(fl).to_string(),
        VReg::FlagValue { .. } => {
            let name = v
                .predicate_ident()
                .expect("FlagValue always has a predicate identifier");
            ids.temporaries.insert(name.clone());
            name
        }
    };
    insert_local(ids, spelling);
}

fn insert_local(ids: &mut DecIdents, spelling: String) {
    ids.locals.insert(spelling.clone());
    let source_local = DEC_SOURCE_LOCALS.with(|locals| locals.borrow().contains(&spelling));
    if source_local && ids.source_local_members.insert(spelling.clone()) {
        ids.source_local_order.push(spelling);
    }
}

fn remove_local(ids: &mut DecIdents, spelling: &str) {
    ids.locals.remove(spelling);
    ids.source_local_members.remove(spelling);
    ids.source_local_order.retain(|local| local != spelling);
}

fn local_reg_spelling(v: &VReg) -> Option<String> {
    match v {
        VReg::Phys(name) if parse_arg_index(name).is_none() => Some(sanitize_c_ident(name)),
        VReg::Phys(_) => None,
        VReg::Temp(index) => Some(format!("t{index}")),
        VReg::Flag(flag) => Some(flag_ident(flag).to_string()),
        VReg::FlagValue { .. } => v.predicate_ident(),
    }
}

fn collect_idents_expr(e: &Expr, ids: &mut DecIdents) {
    match e {
        Expr::Reg(v) => collect_reg(v, ids),
        Expr::StackAddr { object, size } => {
            collect_reg(object, ids);
            if let VReg::Phys(name) = object {
                if parse_arg_index(name).is_none() {
                    let name = sanitize_c_ident(name);
                    ids.stack_objects
                        .entry(name)
                        .and_modify(|known| *known = (*known).max(*size))
                        .or_insert((*size).max(1));
                }
            }
        }
        Expr::Unknown(_) => ids.has_unknown_value = true,
        // An address in a *value* position: passed to a callee, returned, or
        // assigned to a local. Neither spelling proves the VA is data — the
        // same `Addr`/`Named` carries a function pointer and a `.rodata`
        // string, and a call-target `Named` never reaches here at all (see
        // `collect_idents_stmt`). The image's own storage layout supplies the
        // proof the body cannot, and refuses everything that is not writable
        // static storage.
        Expr::Addr(address) => note_address_taken_global(*address, ids),
        Expr::Named { va, .. } => note_address_taken_global(*va, ids),
        Expr::Const(_) | Expr::FloatConst { .. } | Expr::StringLit { .. } => {}
        Expr::FunctionTableEntry {
            table_va,
            table_name,
            index,
            targets,
            ..
        } => {
            collect_idents_expr(index, ids);
            ids.function_tables
                .entry(*table_va)
                .or_insert_with(|| (table_name.clone(), targets.clone()));
        }
        Expr::Lea { base, index, .. } | Expr::PdbFieldAddr { base, index, .. } => {
            if let Some(b) = base {
                collect_reg(b, ids);
            }
            if let Some(i) = index {
                collect_reg(i, ids);
            }
        }
        Expr::Deref { addr, size } => {
            if let Some(address) = direct_global_address(addr) {
                note_global_address(address, u32::from(*size), ids);
            }
            collect_idents_expr(addr, ids);
        }
        Expr::Call { target, args, .. } => {
            if !matches!(target.as_ref(), Expr::Named { .. }) {
                collect_idents_expr(target, ids);
            }
            for argument in args {
                collect_idents_expr(argument, ids);
            }
        }
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            collect_idents_expr(lhs, ids);
            collect_idents_expr(rhs, ids);
        }
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => {
            collect_idents_expr(cond, ids);
            collect_idents_expr(if_true, ids);
            collect_idents_expr(if_false, ids);
        }
        Expr::Un { src, .. } => collect_idents_expr(src, ids),
        Expr::Cast { expr, .. } | Expr::NumericConvert { expr, .. } => {
            collect_idents_expr(expr, ids)
        }
        Expr::WideArithmetic { args, .. } => {
            for argument in args {
                collect_idents_expr(argument, ids);
            }
        }
    }
}

fn collect_idents_stmt(s: &Stmt, ids: &mut DecIdents) {
    ids.statement_count = ids.statement_count.saturating_add(1);
    match s {
        Stmt::Assign { dst, src } => {
            collect_reg(dst, ids);
            if matches!(src, Expr::Deref { size: 16, .. }) {
                let spelling = match dst {
                    VReg::Phys(name) if parse_arg_index(name).is_none() => {
                        Some(sanitize_c_ident(name))
                    }
                    VReg::Temp(index) => Some(format!("t{index}")),
                    VReg::Flag(flag) => Some(flag_ident(flag).to_string()),
                    VReg::FlagValue { .. } => dst.predicate_ident(),
                    VReg::Phys(_) => None,
                };
                if let Some(spelling) = spelling {
                    ids.wide_locals.insert(spelling);
                }
            }
            collect_idents_expr(src, ids);
        }
        Stmt::Store { addr, src, size } => {
            if let Some(address) = direct_global_address(addr) {
                note_global_address(address, u32::from(*size), ids);
            }
            collect_idents_expr(addr, ids);
            collect_idents_expr(src, ids);
        }
        Stmt::Call {
            target,
            args,
            dst,
            call_spec,
        } => {
            // A `Named` target is a callee name, not a local; other targets are
            // rendered as value expressions and their registers must be declared.
            if let Expr::Named { name, .. } = target {
                // Evidence the ORIGINAL was built with a stack protector. The
                // rebuild is then free to add one too, because the code it is
                // being compared against already has it.
                // The callee is `__stack_chk_fail@plt` through a PLT thunk and
                // plain `__stack_chk_fail` when bound directly; the suffix is
                // stripped at print time, so split it the way `ir::canary` does.
                // On i386 `-fPIC` glibc routes the failure through its hidden
                // alias `__stack_chk_fail_local` instead, so match the prefix
                // rather than the exact name — otherwise every 32-bit protected
                // function keeps the suppression it must not have.
                if name
                    .split('@')
                    .next()
                    .is_some_and(|base| base.starts_with("__stack_chk_fail"))
                {
                    ids.calls_stack_check = true;
                }
            } else {
                collect_idents_expr(target, ids);
            }
            for a in args {
                collect_idents_expr(a, ids);
            }
            // The destination is assigned here, so it needs a declaration.
            if let Some(d) = dst {
                collect_reg(d, ids);
                if let (Some(spelling), Some(call_spec)) =
                    (local_reg_spelling(d), call_spec.as_ref())
                {
                    let recovered = call_spec.call_prototype.return_type.clone();
                    ids.call_result_types
                        .entry(spelling)
                        .and_modify(|selected| {
                            if selected.as_ref() != Some(&recovered) {
                                *selected = None;
                            }
                        })
                        .or_insert_with(|| Some(recovered));
                }
            }
        }
        Stmt::Return { value } => {
            if let Some(e) = value {
                collect_idents_expr(e, ids);
            }
        }
        Stmt::If {
            cond,
            then_body,
            else_body,
        } => {
            collect_idents_expr(cond, ids);
            for s in then_body {
                collect_idents_stmt(s, ids);
            }
            if let Some(eb) = else_body {
                for s in eb {
                    collect_idents_stmt(s, ids);
                }
            }
        }
        Stmt::While { cond, body } => {
            collect_idents_expr(cond, ids);
            for s in body {
                collect_idents_stmt(s, ids);
            }
        }
        Stmt::For {
            init,
            cond,
            step,
            body,
        } => {
            collect_idents_stmt(init, ids);
            collect_idents_expr(cond, ids);
            for s in body {
                collect_idents_stmt(s, ids);
            }
            collect_idents_stmt(step, ids);
        }
        Stmt::DoWhile { body, cond } => {
            for s in body {
                collect_idents_stmt(s, ids);
            }
            collect_idents_expr(cond, ids);
        }
        Stmt::Switch {
            discriminant,
            cases,
            default,
        } => {
            collect_idents_expr(discriminant, ids);
            for (_, body) in cases {
                for s in body {
                    collect_idents_stmt(s, ids);
                }
            }
            if let Some(b) = default {
                for s in b {
                    collect_idents_stmt(s, ids);
                }
            }
        }
        Stmt::Label(va) => {
            ids.labels.insert(*va);
        }
        Stmt::Goto { target } => {
            ids.gotos.insert(*target);
            ids.goto_count = ids.goto_count.saturating_add(1);
        }
        Stmt::IndirectGoto { target } => {
            ids.unresolved_transfer_count = ids.unresolved_transfer_count.saturating_add(1);
            collect_idents_expr(target, ids);
        }
        Stmt::Throw { value } => collect_idents_expr(value, ids),
        Stmt::TryCatch { try_body, catches } => {
            for statement in try_body {
                collect_idents_stmt(statement, ids);
            }
            for catch in catches {
                for statement in &catch.body {
                    collect_idents_stmt(statement, ids);
                }
                if let VReg::Phys(name) = &catch.binding {
                    remove_local(ids, &sanitize_c_ident(name));
                }
            }
        }
        // Push/Pop/Nop are elided by the renderer; Unknown/Comment become
        // comments; none introduce a declared identifier.
        Stmt::Push { .. } | Stmt::Pop { .. } | Stmt::Break | Stmt::Nop | Stmt::Comment(_) => {}
        Stmt::Unknown(_) => {
            ids.unresolved_transfer_count = ids.unresolved_transfer_count.saturating_add(1);
        }
    }
}

/// Identifier/control-flow counts shared by health instrumentation and rendering.
pub(crate) struct HealthIdentifiers {
    pub parameters: usize,
    pub declarations: usize,
    pub temporaries: usize,
    pub physical_registers: usize,
    pub gotos: usize,
    pub unresolved_transfers: usize,
    pub statements: usize,
}

pub(crate) fn health_identifiers(function: &Function) -> HealthIdentifiers {
    let mut identifiers = DecIdents::default();
    for statement in &function.body {
        collect_idents_stmt(statement, &mut identifiers);
    }
    HealthIdentifiers {
        parameters: identifiers.max_arg.map_or(0, |index| index + 1),
        declarations: identifiers.locals.len(),
        temporaries: identifiers.temporaries.len(),
        physical_registers: identifiers.physical_registers.len(),
        gotos: identifiers.goto_count,
        unresolved_transfers: identifiers.unresolved_transfer_count,
        statements: identifiers.statement_count,
    }
}

thread_local! {
    /// The declarations selected for the render in progress.
    ///
    /// This is the transport for ONE value, not a set of working registers: it
    /// is written exactly once per typed render, by the renderer, before any
    /// output is produced, and it is only read thereafter. Eight independent
    /// mutable cells used to live here — argument pointer types, declared C
    /// types, pointee widths, integer widths, integer types, stack objects, the
    /// void-output flag and the return type — filled from ten sites, one of
    /// which ran *while* the declaration block was printing. See
    /// [`declaration_plan`] for what the value now decides and why.
    ///
    /// Deliberately NOT cleared when a render finishes, which is the lifetime
    /// the eight cells had: they were reset at the start of the next typed
    /// render, not at the end of the current one. Nothing here relies on that,
    /// but changing it would change what an untyped render sees after a typed
    /// one in the same thread, and that is a separate question from this one.
    static DEC_PLAN: std::cell::RefCell<std::rc::Rc<DeclarationPlan>> =
        std::cell::RefCell::new(std::rc::Rc::new(DeclarationPlan::default()));

    /// Scalar locals whose first top-level definition is rendered as their C
    /// declaration initializer. The value is the exact type selected by
    /// `DeclarationPlan`; statement rendering only consumes this placement
    /// decision and never guesses a type independently.
    static DEC_INLINE_SCALAR_DECLS: std::cell::RefCell<std::collections::HashMap<String, String>> =
        std::cell::RefCell::new(std::collections::HashMap::new());

    /// Source-renamed promoted locals for the current render. Semantic passes
    /// retain their offset-bearing internal names; this presentation-only set
    /// preserves scalar assignment semantics after the final DWARF rename.
    static DEC_SOURCE_LOCALS: std::cell::RefCell<std::collections::HashSet<String>> =
        std::cell::RefCell::new(std::collections::HashSet::new());

    /// Target pointer width for the current render. Array-index syntax removes
    /// an explicit byte scale, so it must retain the width at which that scaled
    /// arithmetic wrapped before portable C promotes the index.
    static DEC_POINTER_WIDTH: std::cell::Cell<u8> = const { std::cell::Cell::new(8) };

    /// Whether an explicit eight-byte cast is currently consumed by a proven
    /// eight-byte source-level destination.  ILP32's logical SSA parent also
    /// creates width-8 casts as register bookkeeping; those must remain
    /// machine-word `long`, while this scoped context renders true 64-bit
    /// arithmetic as `long long`.
    static DEC_SEMANTIC_WIDE_CAST: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };

    /// The single declaration table selected for named calls in this render.
    /// Argument conversions and result representation conversions must consume
    /// this same object; independently consulting the library catalog after a
    /// declaration was downgraded would make the call and its prototype disagree.
    static DEC_NAMED_CALL_PROTOTYPES: std::cell::RefCell<
        std::collections::BTreeMap<String, CallPrototype>
    > = std::cell::RefCell::new(std::collections::BTreeMap::new());

    /// Aggregate names whose complete, ABI-compatible DWARF definitions were
    /// emitted for the current function. A field hint is printable only when
    /// its defining C type is present in this set.
    static DEC_RENDERABLE_STRUCTS: std::cell::RefCell<std::collections::BTreeSet<String>> =
        std::cell::RefCell::new(std::collections::BTreeSet::new());

    /// Exact source aggregate pointer types propagated from authoritative
    /// DWARF (`var0` -> `node *`) for the current render.
    static DEC_STRUCT_PTR_TYPES: std::cell::RefCell<std::collections::HashMap<String, String>> =
        std::cell::RefCell::new(std::collections::HashMap::new());

    /// Original-image VAs that denote writable static storage in this render.
    /// The body printer spells these through the portable tentative objects
    /// emitted above the function definition.
    static DEC_GLOBAL_ADDRS: std::cell::RefCell<std::collections::BTreeSet<u64>> =
        std::cell::RefCell::new(std::collections::BTreeSet::new());

    /// Exact symbol-backed scalar objects, keyed by image VA and carrying
    /// their byte width. Objects without matching symbol/access evidence stay
    /// byte arrays.
    static DEC_GLOBAL_SCALARS: std::cell::RefCell<std::collections::BTreeMap<u64, u8>> =
        std::cell::RefCell::new(std::collections::BTreeMap::new());

    /// Address-backed variables whose DWARF DIE is lexically nested under the
    /// function being rendered. Unlike ordinary image objects, these belong in
    /// the function body as C `static` locals.
    static DEC_FUNCTION_STATIC_LOCALS: std::cell::RefCell<std::collections::BTreeMap<u64, crate::debug::dwarf::DwarfStaticLocal>> =
        std::cell::RefCell::new(std::collections::BTreeMap::new());

    /// C identifiers whose recovered value occupies all 16 bytes of a vector
    /// register. They render as byte-array temporaries, never scalar `long`s.
    static DEC_WIDE_LOCALS: std::cell::RefCell<std::collections::BTreeSet<String>> =
        std::cell::RefCell::new(std::collections::BTreeSet::new());

    /// Source names for static storage, from the image's own symbol table.
    /// Consulted by [`dec_global_name`]; empty means every global keeps its
    /// synthetic address-derived spelling.
    static DEC_GLOBAL_NAMES: std::cell::RefCell<crate::ir::data_symbols::DataSymbols> =
        std::cell::RefCell::new(crate::ir::data_symbols::DataSymbols::new());
}

/// Install the data-symbol names used for the rest of this render.
///
/// Thread-local and render-scoped, matching the other `DEC_*` state above;
/// [`clear_dec_global_names`] must run at the end of a render or the next one
/// on this thread inherits the previous image's names.
pub fn install_dec_global_names(symbols: crate::ir::data_symbols::DataSymbols) {
    DEC_GLOBAL_NAMES.with(|names| *names.borrow_mut() = symbols);
}

/// Drop any installed data-symbol names.
pub fn clear_dec_global_names() {
    DEC_GLOBAL_NAMES
        .with(|names| *names.borrow_mut() = crate::ir::data_symbols::DataSymbols::new());
}

/// The C identifier for static storage at `address`.
///
/// Prefers the image's own name for the object when the symbol table names one
/// starting exactly there; otherwise falls back to the address-derived
/// spelling. See [`crate::ir::data_symbols`] for why the match is exact and
/// never a nearest-symbol search.
fn dec_global_name(address: u64) -> String {
    if let Some(name) = DEC_FUNCTION_STATIC_LOCALS.with(|locals| {
        locals
            .borrow()
            .get(&address)
            .map(|local| sanitize_c_ident(&local.source_name))
    }) {
        return name;
    }
    DEC_GLOBAL_NAMES
        .with(|names| names.borrow().name_for(address).map(str::to_string))
        .unwrap_or_else(|| format!("glaurung_global_{address:x}"))
}

/// Install authoritative function-local static objects for one render.
pub fn install_dec_function_static_locals(
    locals: impl IntoIterator<Item = crate::debug::dwarf::DwarfStaticLocal>,
) {
    DEC_FUNCTION_STATIC_LOCALS.with(|installed| {
        *installed.borrow_mut() = locals
            .into_iter()
            .map(|local| (local.address, local))
            .collect();
    });
}

/// Clear the function-local static-object environment after rendering.
pub fn clear_dec_function_static_locals() {
    DEC_FUNCTION_STATIC_LOCALS.with(|locals| locals.borrow_mut().clear());
}

fn dec_global_symbol_size(address: u64) -> Option<u64> {
    DEC_GLOBAL_NAMES.with(|names| names.borrow().size_for(address))
}

fn dec_global_initial_scalar(address: u64) -> Option<(u8, u64)> {
    DEC_GLOBAL_NAMES.with(|names| names.borrow().initial_scalar_for(address))
}

fn inferred_function_static_local(
    address: u64,
    function: &str,
) -> Option<crate::debug::dwarf::DwarfStaticLocal> {
    DEC_GLOBAL_NAMES.with(|names| {
        let names = names.borrow();
        let size = names.size_for(address)?;
        let width = u8::try_from(size)
            .ok()
            .filter(|width| [1, 2, 4, 8].contains(width))?;
        Some(crate::debug::dwarf::DwarfStaticLocal {
            address,
            byte_size: u16::from(width),
            source_name: names.function_static_name_for(address, function)?,
            c_type: width_ctype(width).to_string(),
        })
    })
}

fn dec_global_scalar_width(address: u64) -> Option<u8> {
    DEC_GLOBAL_SCALARS.with(|objects| objects.borrow().get(&address).copied())
}

/// The original-image identity of a direct static-storage access.
///
/// Symbol resolution represents the same operand in two legitimate ways:
/// stripped binaries retain `Addr`, while a binary with symbols upgrades it to
/// `Named`.  A dereference/store establishes that the value is data storage,
/// not a callable symbol, so both forms must receive the same portable backing
/// object in generated C.
fn direct_global_address(expr: &Expr) -> Option<u64> {
    match expr {
        Expr::Addr(address) | Expr::Named { va: address, .. } => Some(*address),
        _ => None,
    }
}

/// Record that `address` needs a portable object covering at least `bytes`.
///
/// Idempotent and commutative: the widest requirement across every site in the
/// body wins, so an 8-byte store and a 96-byte storage extent for the same VA
/// agree on 96 whichever is collected first.
fn note_global_address(address: u64, bytes: u32, ids: &mut DecIdents) {
    ids.global_addresses
        .entry(address)
        .and_modify(|known| *known = (*known).max(bytes))
        .or_insert(bytes);
}

/// Record an address that the body only *takes*, if the image says it is
/// writable static storage.
///
/// The extent must come from the image because there is no access in the body
/// to measure — that absence is the definition of this case. When no storage
/// layout is installed, or the VA is a hardware register, a `.text` function
/// address or a `.rodata` constant, nothing is recorded and the address keeps
/// rendering as the raw image VA it is today.
fn note_address_taken_global(address: u64, ids: &mut DecIdents) {
    let _ = address;
    let _ = ids;
}

/// The declared byte length of the portable object standing in for a VA.
///
/// This is the widest access the function proved, not an alignment-rounded
/// allocation. Alignment and extent are independent properties in C: a
/// four-byte object may be 16-byte aligned without becoming a 16-byte object.
/// Inflating every scalar to `[16]` loses a useful recovered fact (and made a
/// four-byte function-local static look like an unknown SIMD buffer). The
/// collector only records positive-width loads and stores, but retain a
/// one-byte floor defensively for hand-built ASTs.
fn dec_global_object_bytes(required: u32) -> u32 {
    required.max(1)
}

/// Ask the installed declaration plan a question.
///
/// The plan is immutable for the duration of a render, so nested reads (a
/// statement printer that consults the return type while the expression printer
/// under it consults a declared width) share one borrow safely.
fn dec_plan<R>(question: impl FnOnce(&DeclarationPlan) -> R) -> R {
    DEC_PLAN.with(|plan| question(&plan.borrow()))
}

fn take_dec_inline_scalar_decl(name: &str) -> Option<String> {
    DEC_INLINE_SCALAR_DECLS.with(|declarations| declarations.borrow_mut().remove(name))
}

fn dec_ptr_arg_type(name: &str) -> Option<String> {
    dec_plan(|plan| plan.pointer_parameter(name).map(str::to_string))
}

/// The pointee width of `name` if it is declared as a pointer in this render.
fn dec_ptr_width(name: &str) -> Option<u8> {
    dec_plan(|plan| plan.pointee_width(name))
}

/// The declared integer byte-width of `name` if it is an integer-typed
/// argument/local in this render.
fn dec_int_width(name: &str) -> Option<u8> {
    dec_plan(|plan| plan.integer_width(name))
}

fn dec_int_type(name: &str) -> Option<(bool, u8)> {
    dec_plan(|plan| plan.integer_type(name))
}

fn signed_shift_operand<'a>(lhs: &'a Expr, rhs: &Expr) -> (&'static str, &'a Expr) {
    if let Expr::Const(count) = rhs {
        if *count >= 0 {
            let mut current = lhs;
            let mut selected: Option<(u8, &Expr)> = None;
            while let Expr::Cast {
                signed,
                width,
                expr,
            } = current
            {
                if *signed
                    && (*count as u64) < u64::from(*width) * 8
                    && selected.is_none_or(|(selected_width, _)| *width < selected_width)
                {
                    selected = Some((*width, expr.as_ref()));
                }
                current = expr;
            }
            if let Some((width, operand)) = selected {
                return (int_ctype(true, width), operand);
            }
        }
    }
    let ctype = expr_machine_width(lhs)
        .filter(|width| matches!(width, 1 | 2 | 4 | 8))
        .map(|width| int_ctype(true, width))
        .unwrap_or("long");
    (ctype, lhs)
}

/// The machine byte-width of an integer expression, when it can be established
/// from narrow-typed identifiers. Single identifiers read their declared width
/// from `DEC_INT_WIDTHS`; width-preserving arithmetic (`a - b`, `a & b`, ...)
/// takes the wider operand, treating a bare constant as width-agnostic. Any
/// A load carries its exact access width in the AST. Any genuinely unknown
/// operand (such as an untyped local) yields `None`, so the shift render
/// conservatively keeps `unsigned long`.
///
/// An [`Expr::Cast`] is the AST's most explicit width statement — it is the
/// extension or truncation the machine actually performed — so it answers here
/// exactly and not through its operand. Missing that made every shift over a
/// recovered extension fall through to the eight-byte default: on ARM32,
/// `lsr r2, r3, #31` over a sign-extended byte rendered as
/// `(unsigned long long)(narrowed) >> 31`, which is `0x1ffffffff` for a
/// negative value rather than the sign bit the machine extracts. Widths with no
/// C integer spelling (a 16-byte aggregate transport) still answer `None`,
/// because the shift renderers turn this number straight into a cast.
fn expr_machine_width(e: &Expr) -> Option<u8> {
    match e {
        Expr::Named { name, .. } => dec_int_width(name),
        Expr::Reg(VReg::Phys(n)) => dec_int_width(n),
        Expr::Deref { size, .. } => Some(*size),
        Expr::Const(_) => None,
        Expr::Select { width, .. } => Some(*width),
        Expr::Cast { width, .. } => Some(*width).filter(|w| matches!(w, 1 | 2 | 4 | 8)),
        Expr::Call { result_width, .. } => *result_width,
        Expr::Bin { op, lhs, rhs } if is_width_preserving_arith(*op) => {
            let lw = expr_machine_width(lhs);
            let rw = expr_machine_width(rhs);
            // A `None` is acceptable only when it comes from a bare constant;
            // any other unknown-width operand could be 64-bit, so bail out.
            let ok = |w: Option<u8>, e: &Expr| w.is_some() || matches!(e, Expr::Const(_));
            if !ok(lw, lhs) || !ok(rw, rhs) {
                return None;
            }
            match (lw, rw) {
                (Some(a), Some(b)) => Some(a.max(b)),
                (Some(a), None) => Some(a),
                (None, Some(b)) => Some(b),
                (None, None) => None,
            }
        }
        _ => None,
    }
}

/// Arithmetic whose result width is the width of its (widest) operand — so a
/// shift of the result can be narrowed to that width. Shifts are excluded (a
/// nested shift's width is subtler) and so is division.
fn is_width_preserving_arith(op: BinOp) -> bool {
    matches!(
        op,
        BinOp::Add | BinOp::Sub | BinOp::Mul | BinOp::And | BinOp::Or | BinOp::Xor
    )
}

/// Re-express an array-index constant after the machine's scaled address
/// arithmetic wrapped at 32 bits.
///
/// GCC i386 commonly spells `a[i - 1]` as `add $0x3fffffff, %eax; lea
/// (,%eax,4)`. The quotient `0x3fffffff` is only `-1` after multiplication by
/// four wraps modulo 2^32. Once `dec_render::try_array_index` removes that
/// scale and the generated C is rebuilt for LP64, leaving the quotient
/// unchanged creates a four-gigabyte access. Recover the signed byte
/// displacement first and divide it back by the exact element size. If the
/// wrapped displacement is not divisible by that size, there is no exact C
/// array index and we refuse. (Not a link: that function is private to the
/// `dec_render` child module, so no path names it from here.)
fn normalize_wrapped_scaled_index_constant(
    index_constant: i64,
    element_size: u8,
    pointer_width: u8,
) -> Option<i64> {
    if pointer_width != 4 || element_size == 0 {
        return None;
    }
    let modulus = 1_i128 << 32;
    let sign_bit = 1_i128 << 31;
    let scale = i128::from(element_size);
    let residue = (i128::from(index_constant) * scale).rem_euclid(modulus);
    let signed_bytes = if residue >= sign_bit {
        residue - modulus
    } else {
        residue
    };
    if signed_bytes % scale != 0 {
        return None;
    }
    i64::try_from(signed_bytes / scale).ok()
}

/// Render a call: `callee(args)` for a resolved symbol, else cast an indirect
/// target to a concrete prototype derived from the call site's recovered value
/// types. An empty `(*)()` parameter list is not a prototype in C11 and means
/// zero parameters in C23, so it cannot truthfully or portably represent an
/// unknown call with arguments.
/// The name to call a PLT/IAT stub by: the function it forwards to.
///
/// The address map records a stub as `foo@plt` because that is what it IS, and
/// that spelling is right for an import listing or an xref view. In a call
/// EXPRESSION it is wrong: the source called `foo`, `foo@plt` sanitises to the
/// undeclared identifier `foo_plt`, and nothing in the program defines it.
pub fn callee_display_name(name: &str) -> &str {
    name.split_once('@').map_or(name, |(base, _)| base)
}

fn declared_reg_ctype(reg: &VReg) -> String {
    let VReg::Phys(name) = reg else {
        return "long".to_string();
    };
    let displayed = sanitize_c_ident(name);
    if let Some(selected) = dec_plan(|plan| plan.declared_ctype(&displayed).map(str::to_string)) {
        return selected;
    }
    dec_ptr_arg_type(name)
        .or_else(|| {
            dec_ptr_width(name)
                .map(|pointee_width| hint_to_ctype(TypeHint::Pointer { pointee_width }).to_string())
        })
        .or_else(|| dec_int_type(name).map(|(signed, width)| int_ctype(signed, width).to_string()))
        .unwrap_or_else(|| "long".to_string())
}

fn write_unit_step(
    dst: &VReg,
    src: &Expr,
    out: &mut String,
    write_reg: fn(&VReg, &mut String),
    allow_source_locals: bool,
) -> bool {
    let integer_local = match dst {
        VReg::Temp(_) => true,
        VReg::Phys(name) => {
            name.starts_with("local_")
                || name.starts_with("stack_")
                || (allow_source_locals
                    && DEC_SOURCE_LOCALS.with(|locals| locals.borrow().contains(name))
                    && !declared_reg_ctype(dst).ends_with('*'))
        }
        VReg::Flag(_) | VReg::FlagValue { .. } => false,
    };
    if !integer_local {
        return false;
    }
    fn without_casts(mut expr: &Expr) -> &Expr {
        while let Expr::Cast { expr: inner, .. } = expr {
            expr = inner;
        }
        expr
    }
    let Expr::Bin { op, lhs, rhs } = without_casts(src) else {
        return false;
    };
    if !matches!(without_casts(lhs), Expr::Reg(read) if read == dst)
        || !matches!(rhs.as_ref(), Expr::Const(1))
    {
        return false;
    }
    let suffix = match op {
        BinOp::Add => "++",
        BinOp::Sub => "--",
        _ => return false,
    };
    write_reg(dst, out);
    out.push_str(suffix);
    true
}

#[cfg(test)]
#[path = "ast_tests/ilp32_wide.rs"]
mod ilp32_wide_tests;

#[cfg(test)]
#[path = "ast_tests/memory_fill.rs"]
mod memory_fill_tests;

#[cfg(test)]
#[path = "ast_tests/memory_copy.rs"]
mod memory_copy_tests;

#[cfg(test)]
#[path = "ast_tests/deep_regions.rs"]
mod deep_regions_tests;

#[cfg(test)]
mod tests {

    use super::*;

    use crate::ir::ssa::compute_ssa;
    use crate::ir::structure::recover;
    use crate::ir::types::{CmpOp, Flag, LlirBlock, LlirInstr, VReg};

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
    fn a_pure_select_renders_as_a_one_armed_assignment() {
        let lf = mk_cfg(vec![(
            0x1000,
            vec![
                Op::Ite {
                    dst: VReg::phys("result"),
                    cond: VReg::phys("negative"),
                    t: Value::Reg(VReg::phys("negated")),
                    e: Value::Reg(VReg::phys("original")),
                    width: crate::ir::types::Width::W64,
                },
                Op::Return,
            ],
            vec![],
        )]);

        let rendered = lower_and_render(&lf, "select");

        assert!(
            rendered.contains("%result = %original;"),
            "the false value must initialize the destination: {rendered}"
        );
        assert!(
            rendered.contains("if (%negative) {\n        %result = %negated;"),
            "the true value must be the only conditional assignment: {rendered}"
        );
        assert!(
            !rendered.contains("else"),
            "a pure select must not expand to a two-armed conditional: {rendered}"
        );
    }

    #[test]
    fn a_select_nested_under_control_flow_preserves_two_armed_shape() {
        let result = VReg::phys("result");
        let f = Function {
            name: "nested_select".into(),
            entry_va: 0x1000,
            body: vec![Stmt::If {
                cond: Expr::Reg(VReg::phys("outer")),
                then_body: vec![Stmt::Assign {
                    dst: result,
                    src: Expr::Select {
                        cond: Box::new(Expr::Reg(VReg::phys("inner"))),
                        if_true: Box::new(Expr::Reg(VReg::phys("yes"))),
                        if_false: Box::new(Expr::Reg(VReg::phys("no"))),
                        width: 8,
                    },
                }],
                else_body: None,
            }],
        };

        let rendered = render(&f);

        assert!(
            rendered.contains("if (%inner) {\n            %result = %yes;\n        } else {"),
            "a select nested under control flow must retain both arms: {rendered}"
        );
    }

    #[test]
    fn a_select_with_a_memory_arm_is_not_eagerly_evaluated() {
        let f = Function {
            name: "memory_select".into(),
            entry_va: 0x1000,
            body: vec![Stmt::Assign {
                dst: VReg::phys("result"),
                src: Expr::Select {
                    cond: Box::new(Expr::Reg(VReg::phys("choose_load"))),
                    if_true: Box::new(Expr::Deref {
                        addr: Box::new(Expr::Reg(VReg::phys("pointer"))),
                        size: 8,
                    }),
                    if_false: Box::new(Expr::Deref {
                        addr: Box::new(Expr::Reg(VReg::phys("fallback_pointer"))),
                        size: 8,
                    }),
                    width: 8,
                },
            }],
        };

        let rendered = render(&f);

        assert!(
            rendered.contains("?"),
            "a conditional load must remain lazily evaluated: {rendered}"
        );
    }

    #[test]
    fn a_select_with_two_division_arms_is_not_eagerly_evaluated() {
        let divide = |divisor: &str| Expr::Bin {
            op: BinOp::Div,
            lhs: Box::new(Expr::Reg(VReg::phys("numerator"))),
            rhs: Box::new(Expr::Reg(VReg::phys(divisor))),
        };
        let f = Function {
            name: "division_select".into(),
            entry_va: 0x1000,
            body: vec![Stmt::Assign {
                dst: VReg::phys("result"),
                src: Expr::Select {
                    cond: Box::new(Expr::Reg(VReg::phys("choose_first"))),
                    if_true: Box::new(divide("first_divisor")),
                    if_false: Box::new(divide("second_divisor")),
                    width: 8,
                },
            }],
        };

        let rendered = render(&f);

        assert!(
            rendered.contains("?"),
            "a potentially trapping division must remain lazily evaluated: {rendered}"
        );
    }

    #[test]
    fn a_select_inlines_its_single_reaching_comparison() {
        let predicate = VReg::phys("negative");
        let lf = mk_cfg(vec![(
            0x1000,
            vec![
                Op::Cmp {
                    dst: predicate.clone(),
                    op: CmpOp::Slt,
                    lhs: Value::Reg(VReg::phys("value")),
                    rhs: Value::Const(0),
                },
                Op::Ite {
                    dst: VReg::phys("result"),
                    cond: predicate,
                    t: Value::Reg(VReg::phys("negated")),
                    e: Value::Reg(VReg::phys("original")),
                    width: crate::ir::types::Width::W64,
                },
                Op::Return,
            ],
            vec![],
        )]);

        let rendered = lower_and_render(&lf, "select");

        assert!(
            rendered.contains("if ((%value < 0)) {\n        %result = %negated;"),
            "the comparison must inline into the one conditional arm: {rendered}"
        );
        assert!(
            !rendered.contains("%negative ="),
            "a single-use predicate must not survive as a separate statement: {rendered}"
        );
    }

    #[test]
    fn a_select_arm_reading_the_predicate_keeps_its_definition() {
        let predicate = VReg::phys("negative");
        let lf = mk_cfg(vec![(
            0x1000,
            vec![
                Op::Cmp {
                    dst: predicate.clone(),
                    op: CmpOp::Slt,
                    lhs: Value::Reg(VReg::phys("value")),
                    rhs: Value::Const(0),
                },
                Op::Ite {
                    dst: VReg::phys("result"),
                    cond: predicate.clone(),
                    t: Value::Reg(predicate),
                    e: Value::Reg(VReg::phys("original")),
                    width: crate::ir::types::Width::W64,
                },
                Op::Return,
            ],
            vec![],
        )]);

        let rendered = lower_and_render(&lf, "select");

        assert!(
            rendered.contains("%negative = (%value < 0);"),
            "the value arm still reads the predicate, so its definition is live: {rendered}"
        );
        assert!(
            rendered.contains("if (%negative) {\n        %result = %negative;"),
            "the select must retain both predicate reads: {rendered}"
        );
    }

    #[test]
    fn a_true_arm_reading_the_destination_uses_the_inverted_orientation() {
        let result = VReg::phys("result");
        let lf = mk_cfg(vec![(
            0x1000,
            vec![
                Op::Ite {
                    dst: result.clone(),
                    cond: VReg::phys("choose_old"),
                    t: Value::Reg(result),
                    e: Value::Reg(VReg::phys("fallback")),
                    width: crate::ir::types::Width::W64,
                },
                Op::Return,
            ],
            vec![],
        )]);

        let rendered = lower_and_render(&lf, "select");

        assert!(
            rendered.contains("%result = %result;"),
            "the old destination must be captured before any overwrite: {rendered}"
        );
        assert!(
            rendered.contains("if (!(%choose_old)) {\n        %result = %fallback;"),
            "the non-self-referential arm must use the inverted condition: {rendered}"
        );
    }

    /// A ROTATED loop: the test sits at the TOP and its conditional branch leaves
    /// the loop, with an unconditional jump back at the bottom. clang -O0 emits
    /// every `while`/`for` this way, and gcc does too at -O2.
    ///
    /// The header's condition is the branch-TAKEN condition, so when the taken
    /// edge is the loop EXIT it is the exit test, and `while (cond)` states the
    /// opposite of the source. `loops.c:factorial` came out as
    /// `while (n <= 1) { ...; n = n - 1; }` for `while (n > 1)`, which both runs
    /// the wrong arm and never terminates the way the original does.
    #[test]
    fn a_rotated_loop_continues_on_the_negation_of_its_exit_test() {
        use crate::ir::types::{CmpOp, Flag, VReg};
        // b0: entry -> b1
        // b1: t = (n <= 1); if (t) goto b3   [taken edge LEAVES the loop]
        // b2: body -> b1
        // b3: return
        let lf = mk_cfg(vec![
            (0x1000, vec![Op::Nop], vec![0x1010]),
            (
                0x1010,
                vec![
                    Op::Cmp {
                        dst: VReg::Flag(Flag::Sle),
                        op: CmpOp::Sle,
                        lhs: Value::Reg(VReg::phys("rax")),
                        rhs: Value::Const(1),
                    },
                    Op::CondJump {
                        cond: VReg::Flag(Flag::Sle),
                        target: 0x1030,
                        inverted: false,
                    },
                ],
                vec![0x1020, 0x1030],
            ),
            (
                0x1020,
                vec![
                    Op::Bin {
                        dst: VReg::phys("rax"),
                        op: BinOp::Sub,
                        lhs: Value::Reg(VReg::phys("rax")),
                        rhs: Value::Const(1),
                    },
                    // The explicit back-jump real code carries.
                    Op::Jump { target: 0x1010 },
                ],
                vec![0x1010],
            ),
            (0x1030, vec![Op::Return], vec![]),
        ]);
        let out = lower_and_render(&lf, "rotated");
        // The loop must continue while the exit test is FALSE. `!(rax <= 1)` is
        // `rax > 1`, which the renderer spells with the constant on the left.
        assert!(
            out.contains("while ((1 < %rax))") || out.contains("while ((%rax > 1))"),
            "expected the negation of the exit test as the loop condition:\n{out}"
        );
        assert!(
            !out.contains("while ((%rax <= 1))"),
            "the EXIT test must not be used as the CONTINUE condition:\n{out}"
        );
        // The back-edge is what `while` MEANS; emitting it as a `goto` to the
        // header leaves a jump out of the loop body to a label the renderer then
        // pins after the `return`, so the body cannot repeat.
        assert!(
            !out.contains("goto L_1010"),
            "the back-edge must be implicit in the `while`, not a goto:\n{out}"
        );
    }

    /// The mirror shape, which must not regress: gcc -O0 puts the test at the
    /// bottom and its taken edge re-enters the body, so that condition already IS
    /// the continue test and must be emitted as-is.
    #[test]
    fn a_bottom_tested_loop_keeps_its_condition_as_written() {
        use crate::ir::types::{CmpOp, Flag, VReg};
        // b0 -> b1 (body) -> b2 (test); test taken -> b1, else -> b3
        let lf = mk_cfg(vec![
            (0x1000, vec![Op::Nop], vec![0x1010]),
            (
                0x1010,
                vec![Op::Bin {
                    dst: VReg::phys("rax"),
                    op: BinOp::Sub,
                    lhs: Value::Reg(VReg::phys("rax")),
                    rhs: Value::Const(1),
                }],
                vec![0x1020],
            ),
            (
                0x1020,
                vec![
                    Op::Cmp {
                        dst: VReg::Flag(Flag::Slt),
                        op: CmpOp::Slt,
                        lhs: Value::Const(1),
                        rhs: Value::Reg(VReg::phys("rax")),
                    },
                    Op::CondJump {
                        cond: VReg::Flag(Flag::Slt),
                        target: 0x1010,
                        inverted: false,
                    },
                ],
                vec![0x1010, 0x1030],
            ),
            (0x1030, vec![Op::Return], vec![]),
        ]);
        let out = lower_and_render(&lf, "bottom");
        assert!(
            out.contains("do {") && out.contains("} while ((1 < %rax));"),
            "a bottom-tested natural loop must retain its post-test shape:\n{out}"
        );
        assert!(
            !out.contains("while (!("),
            "a bottom-tested loop's condition is already the continue test:\n{out}"
        );
        assert!(
            !out.contains("goto L_1010"),
            "the do-while back-edge must be implicit, not a goto:\n{out}"
        );
    }

    /// A post-tested loop may update a comparison operand after the machine
    /// comparison but before its conditional jump.  Clang does exactly this in
    /// `mutate_reverse`: `cmp rax, rcx; mov rdx, rcx; jb loop`.  Moving the
    /// comparison into C's trailing `while (...)` re-evaluates it after the move
    /// and drops the final swap.  Preserve the predicate as a value snapshot.
    #[test]
    fn a_bottom_tested_loop_snapshots_a_condition_before_later_operand_write() {
        let lf = mk_cfg(vec![
            (
                0x1000,
                vec![
                    Op::Assign {
                        dst: VReg::phys("rax"),
                        src: Value::Const(7),
                    },
                    Op::Assign {
                        dst: VReg::phys("rcx"),
                        src: Value::Const(1),
                    },
                ],
                vec![0x1010],
            ),
            (
                0x1010,
                vec![
                    Op::Bin {
                        dst: VReg::phys("rax"),
                        op: BinOp::Sub,
                        lhs: Value::Reg(VReg::phys("rax")),
                        rhs: Value::Const(1),
                    },
                    Op::Bin {
                        dst: VReg::phys("rdx"),
                        op: BinOp::Add,
                        lhs: Value::Reg(VReg::phys("rcx")),
                        rhs: Value::Const(1),
                    },
                    Op::Cmp {
                        dst: VReg::Flag(Flag::C),
                        op: CmpOp::Ult,
                        lhs: Value::Reg(VReg::phys("rcx")),
                        rhs: Value::Reg(VReg::phys("rax")),
                    },
                    Op::Assign {
                        dst: VReg::phys("rcx"),
                        src: Value::Reg(VReg::phys("rdx")),
                    },
                    Op::CondJump {
                        cond: VReg::Flag(Flag::C),
                        target: 0x1010,
                        inverted: false,
                    },
                ],
                vec![0x1010, 0x1020],
            ),
            (0x1020, vec![Op::Return], vec![]),
        ]);

        let out = lower_and_render(&lf, "snapshot");
        let compare = out.find("%cf = (%rcx u< %rax);").unwrap_or_else(|| {
            panic!("the machine comparison must remain a predicate snapshot:\n{out}")
        });
        let overwrite = out
            .find("%rcx = %rdx;")
            .expect("the post-compare register update must remain in the latch");
        assert!(
            compare < overwrite,
            "the snapshot must precede the overwrite:\n{out}"
        );
        assert!(
            out.contains("} while (%cf);"),
            "the loop must consume the snapshotted predicate, not re-evaluate it:\n{out}"
        );
        assert!(
            !out.contains("} while ((%rcx u< %rax));"),
            "the moved comparison observes the wrong rcx value:\n{out}"
        );
    }

    #[test]
    fn winapi_calls_render_prototype_hints_without_changing_call_syntax() {
        let f = Function {
            name: "f".to_string(),
            entry_va: 0x1000,
            body: vec![Stmt::Call {
                target: Expr::Named {
                    va: 0x2000,
                    name: "ReadFile".to_string(),
                },
                args: vec![
                    Expr::Reg(VReg::phys("arg0")),
                    Expr::Reg(VReg::phys("arg1")),
                    Expr::Reg(VReg::phys("arg2")),
                ],
                dst: None,
                call_spec: None,
            }],
        };

        let plain = render(&f);
        assert!(plain.contains("call ReadFile(%arg0, %arg1, %arg2);"));
        assert!(plain.contains(
            "// proto: BOOL ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead"
        ));

        let c_style = render_c(&f);
        assert!(c_style.contains("ReadFile(arg0, arg1, arg2);"));
        assert!(c_style.contains(
            "// proto: BOOL ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead"
        ));
    }

    #[test]
    fn i64_min_constants_do_not_overflow_the_renderers() {
        // Regression: rendering `-0x...` for a negative constant/displacement
        // computed `-c`, which panics ("attempt to negate with overflow") when
        // the value is exactly i64::MIN. Both renderers must format the
        // magnitude instead of aborting.
        let f = Function {
            name: "m".to_string(),
            entry_va: 0x80,
            body: vec![
                Stmt::Assign {
                    dst: VReg::phys("rax"),
                    src: Expr::Const(i64::MIN),
                },
                Stmt::Store {
                    addr: Expr::Lea {
                        base: Some(VReg::phys("rbp")),
                        index: None,
                        scale: 1,
                        disp: i64::MIN,
                        segment: None,
                    },
                    src: Expr::Reg(VReg::phys("rax")),
                    size: 8,
                },
            ],
        };
        // Neither call may panic; the i64::MIN magnitude must appear.
        assert!(render(&f).contains("0x8000000000000000"));
        assert!(render_c(&f).contains("0x8000000000000000"));
    }

    #[test]
    fn decbench_negative_wide_constants_have_signed_c_semantics() {
        let f = Function {
            name: "signed_bounds".to_string(),
            entry_va: 0x80,
            body: vec![
                Stmt::Assign {
                    dst: VReg::phys("rax"),
                    src: Expr::Const(-0x8000_0001),
                },
                Stmt::Assign {
                    dst: VReg::phys("rbx"),
                    src: Expr::Const(i64::MIN),
                },
                Stmt::Return {
                    value: Some(Expr::Reg(VReg::phys("rax"))),
                },
            ],
        };

        let text = render_decbench(&f);
        assert!(
            text.contains("-0x80000001LL"),
            "an unsuffixed wide hex literal is unsigned before unary minus: {text}"
        );
        assert!(
            text.contains("(-0x7fffffffffffffffLL - 1LL)"),
            "INT64_MIN needs a representable signed construction: {text}"
        );
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
    fn a_jump_to_the_immediately_following_region_falls_through() {
        // Clang -O0 places a zero-distance jump block between a nested loop's
        // exit and the outer-loop increment. Keeping `goto increment` while
        // emitting that increment immediately next makes the statements after
        // the goto unreachable; label repair can only append an empty label at
        // function scope and cannot restore the lost outer iteration.
        let lf = mk_cfg(vec![
            (0x1000, vec![Op::Jump { target: 0x1010 }], vec![0x1010]),
            (
                0x1010,
                vec![Op::Assign {
                    dst: VReg::phys("outer_index"),
                    src: Value::Const(1),
                }],
                vec![],
            ),
        ]);
        let region = Region::Seq(vec![Region::Block(0), Region::Block(1)]);

        let lowered = lower(&lf, &region, "fallthrough");

        assert!(
            !lowered
                .body
                .iter()
                .any(|stmt| matches!(stmt, Stmt::Goto { target: 0x1010 })),
            "a jump to the next emitted region is redundant: {:#?}",
            lowered.body
        );
        assert!(
            lowered.body.iter().any(|stmt| {
                matches!(stmt, Stmt::Assign { dst, .. } if *dst == VReg::phys("outer_index"))
            }),
            "the following region's body must remain reachable: {:#?}",
            lowered.body
        );
    }

    #[test]
    fn a_raw_switch_arm_jump_labels_the_emitted_latch_block() {
        // Clang -O0 jump tables inside loops have case blocks that jump to a
        // shared increment/latch block.  These are raw `Op::Jump` terminators,
        // not synthetic `Region::Goto` nodes.  The latch is emitted once after
        // the switch and must carry its real address label; otherwise the C
        // renderer pins an empty label at function end and the case skips the
        // increment entirely.
        let lf = mk_cfg(vec![
            (
                0x1000,
                vec![Op::IndirectJump {
                    target: Value::Reg(VReg::phys("state")),
                    index: None,
                }],
                vec![0x1010, 0x1020],
            ),
            (0x1010, vec![Op::Jump { target: 0x1030 }], vec![0x1030]),
            (0x1020, vec![Op::Return], vec![]),
            (
                0x1030,
                vec![Op::Assign {
                    dst: VReg::phys("index"),
                    src: Value::Const(1),
                }],
                vec![],
            ),
        ]);
        let region = Region::Seq(vec![
            Region::Switch {
                guard: None,
                dispatch: 0,
                case_labels: vec![vec![0], vec![1]],
                arms: vec![Region::Block(1), Region::Block(2)],
                formal_default: None,
                join: None,
            },
            Region::Block(3),
        ]);

        let lowered = lower(&lf, &region, "switch_latch");
        let latch = lowered.body.windows(2).any(|pair| {
            matches!(pair[0], Stmt::Label(0x1030))
                && matches!(
                    &pair[1],
                    Stmt::Assign { dst, .. } if *dst == VReg::phys("index")
                )
        });

        assert!(
            latch,
            "the raw case goto must land on the emitted latch body: {:#?}",
            lowered.body
        );
    }

    #[test]
    fn a_raw_dispatch_loop_lowers_the_table_to_labelled_switch_edges() {
        let lf = mk_cfg(vec![
            (
                0x1000,
                vec![Op::IndirectJump {
                    target: Value::Reg(VReg::phys("target")),
                    index: Some(Value::Reg(VReg::phys("state"))),
                }],
                vec![0x1010, 0x1020, 0x1030],
            ),
            (0x1010, vec![Op::Jump { target: 0x1000 }], vec![0x1000]),
            (0x1020, vec![Op::Return], vec![]),
            (0x1030, vec![Op::Return], vec![]),
        ]);
        let region = Region::Seq(vec![
            Region::RawLoop {
                header: 0,
                blocks: vec![0, 1],
                exits: vec![2, 3],
            },
            Region::Unstructured(vec![2, 3]),
        ]);

        let lowered = lower(&lf, &region, "raw_dispatch_loop");
        let Some(Stmt::While { body, .. }) = lowered
            .body
            .iter()
            .find(|statement| matches!(statement, Stmt::While { .. }))
        else {
            panic!("expected raw while loop: {:#?}", lowered.body);
        };
        let Some(Stmt::Switch {
            discriminant,
            cases,
            default,
        }) = body
            .iter()
            .find(|statement| matches!(statement, Stmt::Switch { .. }))
        else {
            panic!("expected typed switch inside raw loop: {body:#?}");
        };
        assert_eq!(discriminant, &Expr::Reg(VReg::phys("state")));
        assert_eq!(
            cases,
            &vec![
                (Some(0), vec![Stmt::Goto { target: 0x1010 }]),
                (Some(1), vec![Stmt::Goto { target: 0x1020 }]),
                (Some(2), vec![Stmt::Goto { target: 0x1030 }]),
            ]
        );
        assert!(default.is_none());
        assert!(
            !body
                .iter()
                .any(|statement| matches!(statement, Stmt::IndirectGoto { .. })),
            "the switch replaces the computed machine transfer: {body:#?}"
        );
    }

    #[test]
    fn a_raw_dispatch_loop_coalesces_guard_default_table_slots() {
        // PIC switch tables commonly point every unused in-range slot at the
        // same block as the preceding bounds guard. Rendering each hole as a
        // separate C case preserves execution but invents source CFG nodes.
        // Once the guard proves the shared default target, those slots can be
        // represented exactly by one `default` arm.
        let lf = mk_cfg(vec![
            (
                0x1000,
                vec![Op::CondJump {
                    cond: VReg::Flag(Flag::A),
                    target: 0x1050,
                    inverted: false,
                }],
                vec![0x1010, 0x1050],
            ),
            (
                0x1010,
                vec![Op::IndirectJump {
                    target: Value::Reg(VReg::phys("target")),
                    index: Some(Value::Reg(VReg::phys("state"))),
                }],
                vec![0x1020, 0x1050, 0x1030, 0x1050],
            ),
            (0x1020, vec![Op::Jump { target: 0x1000 }], vec![0x1000]),
            (0x1030, vec![Op::Jump { target: 0x1000 }], vec![0x1000]),
            (0x1040, vec![Op::Return], vec![]),
            (0x1050, vec![Op::Return], vec![]),
        ]);
        let region = Region::Seq(vec![
            Region::RawLoop {
                header: 0,
                blocks: vec![0, 1, 2, 3],
                exits: vec![5],
            },
            Region::Block(5),
        ]);

        let lowered = lower(&lf, &region, "sparse_raw_dispatch_loop");
        let Some(Stmt::While { body, .. }) = lowered
            .body
            .iter()
            .find(|statement| matches!(statement, Stmt::While { .. }))
        else {
            panic!("expected raw while loop: {:#?}", lowered.body);
        };
        let Some(Stmt::Switch { cases, default, .. }) = body
            .iter()
            .find(|statement| matches!(statement, Stmt::Switch { .. }))
        else {
            panic!("expected typed switch inside raw loop: {body:#?}");
        };
        assert_eq!(
            cases,
            &vec![
                (Some(0), vec![Stmt::Goto { target: 0x1020 }]),
                (Some(2), vec![Stmt::Goto { target: 0x1030 }]),
            ]
        );
        assert_eq!(default, &Some(vec![Stmt::Goto { target: 0x1050 }]));
    }

    #[test]
    fn a_goto_to_a_do_while_latch_labels_the_in_loop_condition_site() {
        // A shared fallthrough inside one loop arm can require an explicit
        // goto to the bottom-test block. DoWhile lowering absorbs that block's
        // statements and condition, so the target label belongs immediately
        // before those latch statements inside the loop—not as an empty label
        // after the function return.
        let lf = mk_cfg(vec![
            (
                0x1000,
                vec![Op::Assign {
                    dst: VReg::phys("body_value"),
                    src: Value::Const(1),
                }],
                vec![0x1010],
            ),
            (
                0x1010,
                vec![
                    Op::Assign {
                        dst: VReg::phys("latch_value"),
                        src: Value::Const(2),
                    },
                    Op::CondJump {
                        cond: VReg::Flag(Flag::Z),
                        target: 0x1000,
                        inverted: false,
                    },
                ],
                vec![0x1000, 0x1020],
            ),
            (0x1020, vec![Op::Return], vec![]),
        ]);
        let region = Region::DoWhile {
            body: Box::new(Region::Seq(vec![Region::Block(0), Region::Goto(1)])),
            cond: 1,
            exit: Some(2),
        };

        let lowered = lower(&lf, &region, "latch_target");
        let Stmt::DoWhile { body, .. } = &lowered.body[0] else {
            panic!("expected do-while: {:#?}", lowered.body);
        };
        let label = body
            .iter()
            .position(|statement| matches!(statement, Stmt::Label(0x1010)));
        let latch = body.iter().position(
            |statement| matches!(statement, Stmt::Assign { dst, .. } if *dst == VReg::phys("latch_value")),
        );

        assert_eq!(
            label.zip(latch).map(|(label, latch)| latch - label),
            Some(1)
        );
        assert!(
            !lowered
                .body
                .iter()
                .skip(1)
                .any(|statement| matches!(statement, Stmt::Label(0x1010))),
            "the latch target escaped the loop: {:#?}",
            lowered.body
        );
    }

    #[test]
    fn switch_lowering_removes_dispatch_before_trailing_phi_copies() {
        // SSA inserts edge copies after the machine terminator in the dispatch
        // block. The indirect transfer still belongs to the Switch region even
        // when it is no longer the final lowered statement; leaving it in front
        // makes reachability pruning delete the entire structured switch.
        let lf = mk_cfg(vec![
            (
                0x1000,
                vec![
                    Op::IndirectJump {
                        target: Value::Reg(VReg::phys("target")),
                        index: Some(Value::Reg(VReg::phys("index"))),
                    },
                    Op::Assign {
                        dst: VReg::phys("phi_copy"),
                        src: Value::Const(7),
                    },
                ],
                vec![0x1010, 0x1020],
            ),
            (0x1010, vec![Op::Return], vec![]),
            (0x1020, vec![Op::Return], vec![]),
        ]);
        let region = Region::Switch {
            guard: None,
            dispatch: 0,
            case_labels: vec![vec![0], vec![1]],
            arms: vec![Region::Block(1), Region::Block(2)],
            formal_default: None,
            join: None,
        };

        let lowered = lower(&lf, &region, "switch_phi_copies");

        assert!(
            lowered
                .body
                .iter()
                .any(|stmt| matches!(stmt, Stmt::Switch { .. })),
            "the structured switch must survive lowering: {:#?}",
            lowered.body
        );
        assert!(
            !lowered
                .body
                .iter()
                .any(|stmt| matches!(stmt, Stmt::IndirectGoto { .. })),
            "the machine dispatch is represented by the switch: {:#?}",
            lowered.body
        );
    }

    #[test]
    fn switch_case_edges_to_its_join_become_fallthrough() {
        // A switch join is emitted immediately after the switch.  Its case
        // terminators therefore become ordinary `break`/fallthrough in C;
        // retaining raw gotos adds false CFG nodes and can strand the one
        // shared return inside a case when labels are materialised.
        let lf = mk_cfg(vec![
            (
                0x1000,
                vec![Op::IndirectJump {
                    target: Value::Reg(VReg::phys("state")),
                    index: None,
                }],
                vec![0x1010, 0x1020, 0x1030],
            ),
            (0x1010, vec![Op::Jump { target: 0x1040 }], vec![0x1040]),
            (0x1020, vec![Op::Jump { target: 0x1040 }], vec![0x1040]),
            (0x1030, vec![Op::Jump { target: 0x1040 }], vec![0x1040]),
            (0x1040, vec![Op::Return], vec![]),
        ]);
        let region = Region::Seq(vec![
            Region::Switch {
                guard: None,
                dispatch: 0,
                case_labels: vec![vec![0], vec![1], vec![2]],
                arms: vec![Region::Block(1), Region::Block(2), Region::Block(3)],
                formal_default: None,
                join: Some(4),
            },
            Region::Block(4),
        ]);

        let lowered = lower(&lf, &region, "switch_join");
        let Some(Stmt::Switch { cases, .. }) = lowered.body.first() else {
            panic!("expected switch first: {:#?}", lowered.body)
        };
        assert!(
            cases.iter().all(|(_, body)| !body
                .iter()
                .any(|stmt| matches!(stmt, Stmt::Goto { target: 0x1040 }))),
            "case-to-join edges must fall through: {:#?}",
            lowered.body
        );
        assert!(
            lowered
                .body
                .iter()
                .any(|stmt| matches!(stmt, Stmt::Return { .. })),
            "the shared return must remain after the switch: {:#?}",
            lowered.body
        );
    }

    #[test]
    fn duplicate_shared_block_labels_keep_the_shallow_destination() {
        let mut body = vec![
            Stmt::Switch {
                discriminant: Expr::Reg(VReg::phys("state")),
                cases: vec![(Some(0), vec![Stmt::Label(0x2000)])],
                default: None,
            },
            Stmt::Label(0x2000),
            Stmt::Return { value: None },
        ];

        deduplicate_labels(&mut body);

        let Stmt::Switch { cases, .. } = &body[0] else {
            panic!("expected switch")
        };
        assert!(
            !cases[0]
                .1
                .iter()
                .any(|stmt| matches!(stmt, Stmt::Label(0x2000))),
            "a nested clone must not own the shared label: {body:#?}"
        );
        assert!(matches!(body[1], Stmt::Label(0x2000)));
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
        assert!(
            text.contains("%rbx = 1;"),
            "fold ate non-return reg: {}",
            text
        );
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
        assert!(
            text.contains("return 42;"),
            "arm64 return fold failed: {}",
            text
        );
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
                        inverted: false,
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
    fn inverted_condjump_negates_cmp_op() {
        // [cmp rax, 16; jne L_err; ret] @ L_err
        // Without inverted-handling this rendered as `if (rax == 16) goto err`,
        // which was the WRONG polarity and the root cause of misreading
        // amdxe.sys AMDXE_GET_USER_INDEX size checks. With `inverted=true`
        // the printer must render `if (rax != 16) goto err`.
        let lf = mk_cfg(vec![
            (
                0x1000,
                vec![
                    Op::Cmp {
                        dst: VReg::Flag(Flag::Z),
                        op: CmpOp::Eq,
                        lhs: Value::Reg(VReg::phys("rax")),
                        rhs: Value::Const(16),
                    },
                    Op::CondJump {
                        cond: VReg::Flag(Flag::Z),
                        target: 0x1100,
                        inverted: true,
                    },
                    Op::Return,
                ],
                vec![0x1100],
            ),
            (0x1100, vec![Op::Return], vec![]),
        ]);
        let text = lower_and_render(&lf, "f");
        assert!(
            text.contains("(%rax != 16)"),
            "JNE-style negation lost: {}",
            text
        );
        assert!(
            !text.contains("(%rax == 16)"),
            "wrong polarity rendered: {}",
            text
        );
    }

    #[test]
    fn cmp_is_hoisted_for_mid_block_conditional() {
        // A single block contains [cmp; cjmp; nop; cmp; cjmp; ret] where
        // CFG recovery cannot find a clean structured shape — neither
        // CondJump ends the block, so they're lowered as bare mid-block
        // Stmt::If with cond=Reg(flag). Without the inline hoist the
        // output is the opaque `if (%zf) goto L;` pair that makes manual
        // review of real wkssvc/srvsvc functions misleading.
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
                        inverted: false,
                    },
                    Op::Nop,
                    Op::Cmp {
                        dst: VReg::Flag(Flag::Z),
                        op: CmpOp::Slt,
                        lhs: Value::Reg(VReg::phys("rbx")),
                        rhs: Value::Const(7),
                    },
                    Op::CondJump {
                        cond: VReg::Flag(Flag::Z),
                        target: 0x1100,
                        inverted: false,
                    },
                    Op::Return,
                ],
                vec![0x1100],
            ),
            (0x1100, vec![Op::Return], vec![]),
        ]);
        let text = lower_and_render(&lf, "f");
        assert!(
            text.contains("if ((%rax == 0))"),
            "first mid-block cmp was not hoisted: {}",
            text
        );
        assert!(
            text.contains("if ((%rbx < 7))"),
            "second mid-block cmp was not hoisted: {}",
            text
        );
        assert!(
            !text.contains("if (%zf)"),
            "opaque flag-based if remained: {}",
            text
        );
    }

    #[test]
    fn hoisting_one_use_keeps_a_versioned_predicate_for_a_later_consumer() {
        // GCC -O2 lowers the two comparisons in `cmp_unsigned` to one CMP whose
        // CF feeds the first JB and then also feeds a later CMOVA.  Hoisting CF
        // into the branch condition must not delete the SSA definition: the
        // select is in a successor block and still reads that exact flag value.
        let cf = VReg::FlagValue {
            flag: Flag::C,
            version: 1,
        };
        let stmts = vec![
            Stmt::Assign {
                dst: cf.clone(),
                src: Expr::Cmp {
                    op: CmpOp::Ult,
                    lhs: Box::new(Expr::Reg(VReg::phys("arg0"))),
                    rhs: Box::new(Expr::Reg(VReg::phys("arg1"))),
                },
            },
            Stmt::If {
                cond: Expr::Reg(cf.clone()),
                then_body: vec![Stmt::Goto { target: 0x113a }],
                else_body: None,
            },
            Stmt::Assign {
                dst: VReg::phys("ret"),
                src: Expr::Select {
                    cond: Box::new(Expr::Reg(cf.clone())),
                    if_true: Box::new(Expr::Const(55)),
                    if_false: Box::new(Expr::Const(66)),
                    width: 4,
                },
            },
        ];

        let lowered = hoist_inline_flag_conds(stmts);

        assert!(
            matches!(
                lowered.first(),
                Some(Stmt::Assign { dst, .. }) if dst == &cf
            ),
            "hoisting the branch consumed a predicate still read later: {lowered:#?}"
        );
        assert!(
            matches!(
                lowered.get(1),
                Some(Stmt::If {
                    cond: Expr::Cmp { op: CmpOp::Ult, .. },
                    ..
                })
            ),
            "the branch should still receive the inlined comparison: {lowered:#?}"
        );
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
                        inverted: false,
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
                        inverted: false,
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
    fn known_kernel_unknown_ops_render_as_semantic_comments() {
        let lf = mk_cfg(vec![(
            0x1000,
            vec![
                Op::Unknown {
                    mnemonic: "wrmsr".into(),
                },
                Op::Unknown {
                    mnemonic: "sgdt".into(),
                },
                Op::Return,
            ],
            vec![],
        )]);
        let text = lower_and_render(&lf, "f");
        assert!(
            text.contains("// wrmsr: write model-specific register"),
            "got: {}",
            text
        );
        assert!(
            text.contains("// sgdt: store global descriptor table register"),
            "got: {}",
            text
        );
        assert!(!text.contains("unknown(wrmsr);"), "got: {}", text);
        assert!(!text.contains("unknown(sgdt);"), "got: {}", text);
    }

    #[test]
    fn render_with_types_annotates_pointer_without_mistyping_cmp_operand_as_bool() {
        use crate::ir::types::{MemOp, VReg};
        use crate::ir::types_recover::recover_types;
        // `rax = load [rbp+0]` makes rbp a pointer. Comparing an integer with
        // zero does NOT make the integer itself a boolean: this is the normal
        // shape of zero/nonzero tests on counters, pointers, and bit-fields.
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
        assert!(
            !text.contains("(bool)%rcx"),
            "an integer merely compared with zero was mistyped as bool: {}",
            text
        );
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
        assert!(
            !plain.contains("(u64*)"),
            "plain render leaked annotations: {}",
            plain
        );
        assert!(
            !plain.contains("(bool)"),
            "plain render leaked annotations: {}",
            plain
        );
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
                total_timeout_ms: 0,
            },
        );
        for f in &funcs {
            if let Ok(lf) = lift_function_from_bytes(&data, f, Arch::X86_64) {
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
    // -- render_decbench (parseable-C) -----------------------------------------

    /// The DecBench pipeline as the product runs it: the explicit semantic
    /// transformation, then formatting. Tests that characterise the folding must go
    /// through it — `render_decbench` alone is formatting-only by design.
    fn dec_pipeline(f: &Function) -> String {
        render_decbench(&prepare_for_decbench(f))
    }

    /// The portable object is a file-scope definition, but DecBench scores one
    /// *function definition* sliced out of the submitted translation unit. A
    /// reference whose only declaration lives above the signature is undeclared
    /// in every consumer that slices, so the function body must declare it too.
    #[test]
    fn decbench_portable_static_storage_is_declared_inside_the_function() {
        let function = Function {
            name: "read_counter".to_string(),
            entry_va: 0x1150,
            body: vec![Stmt::Return {
                value: Some(Expr::Deref {
                    addr: Box::new(Expr::Addr(0x4024)),
                    size: 4,
                }),
            }],
        };

        let rendered = render_decbench(&function);
        let body = rendered
            .split_once('{')
            .expect("a rendered function has a body")
            .1;

        assert!(
            body.contains("extern unsigned char glaurung_global_4024[4];"),
            "the sliced function body must declare the object it reads:\n{rendered}"
        );
    }

    /// An exact sized OBJECT symbol plus an equal-width access proves a scalar
    /// C object. This is the ordinary function-local-static shape in unstripped
    /// GCC/Clang output; retaining the byte-array fallback here would discard
    /// both independent facts immediately before rendering.
    #[test]
    fn decbench_exact_sized_global_renders_as_a_scalar_object() {
        let function = Function {
            name: "increment_counter".to_string(),
            entry_va: 0x1150,
            body: vec![
                Stmt::Store {
                    addr: Expr::Addr(0x4024),
                    src: Expr::Bin {
                        op: BinOp::Add,
                        lhs: Box::new(Expr::Deref {
                            addr: Box::new(Expr::Addr(0x4024)),
                            size: 4,
                        }),
                        rhs: Box::new(Expr::Const(1)),
                    },
                    size: 4,
                },
                Stmt::Call {
                    target: Expr::Named {
                        va: 0x2000,
                        name: "printf".to_string(),
                    },
                    args: vec![
                        Expr::StringLit {
                            value: "%d".to_string(),
                        },
                        Expr::Cast {
                            signed: false,
                            width: 8,
                            expr: Box::new(Expr::Cast {
                                signed: false,
                                width: 4,
                                expr: Box::new(Expr::Deref {
                                    addr: Box::new(Expr::Addr(0x4024)),
                                    size: 4,
                                }),
                            }),
                        },
                    ],
                    dst: None,
                    call_spec: None,
                },
                Stmt::Return {
                    value: Some(Expr::Deref {
                        addr: Box::new(Expr::Addr(0x4024)),
                        size: 4,
                    }),
                },
            ],
        };
        install_dec_global_names(crate::ir::data_symbols::DataSymbols::from_entries([(
            0x4024u64,
            4u64,
            "increment_counter.counter",
        )]));

        let rendered = render_decbench(&function);
        clear_dec_global_names();

        assert!(
            rendered.contains("static int increment_counter_counter;"),
            "{rendered}"
        );
        assert!(
            rendered.contains("increment_counter_counter++;"),
            "{rendered}"
        );
        assert!(
            rendered.contains("return increment_counter_counter;"),
            "{rendered}"
        );
        assert!(
            rendered.contains("printf(\"%d\", increment_counter_counter);"),
            "{rendered}"
        );
        assert!(!rendered.contains("unsigned char"), "{rendered}");
    }

    #[test]
    fn dwarf_owned_static_object_renders_in_its_function_scope() {
        let function = Function {
            name: "counter".to_string(),
            entry_va: 0x1150,
            body: vec![
                Stmt::Store {
                    addr: Expr::Addr(0x4024),
                    src: Expr::Bin {
                        op: BinOp::Add,
                        lhs: Box::new(Expr::Deref {
                            addr: Box::new(Expr::Addr(0x4024)),
                            size: 4,
                        }),
                        rhs: Box::new(Expr::Const(1)),
                    },
                    size: 4,
                },
                Stmt::Return { value: None },
            ],
        };
        let mut symbols = crate::ir::data_symbols::DataSymbols::from_entries([(
            0x4024u64,
            4u64,
            "counter.value",
        )]);
        symbols.set_initial_scalar_for_test(0x4024, 4, 100);
        install_dec_global_names(symbols);
        install_dec_function_static_locals([crate::debug::dwarf::DwarfStaticLocal {
            address: 0x4024,
            byte_size: 4,
            source_name: "value".to_string(),
            c_type: "int".to_string(),
        }]);

        let rendered = render_decbench_typed_with_output(
            &function,
            None,
            None,
            crate::ir::types_recover::RecoveredOutputKind::Void,
        );
        clear_dec_function_static_locals();
        clear_dec_global_names();

        assert!(
            rendered.contains("    static int value = 100;"),
            "{rendered}"
        );
        assert!(rendered.contains("    value++;"), "{rendered}");
        assert!(!rendered.contains("extern int value;"), "{rendered}");
        assert!(
            !rendered.contains("static int counter_value;"),
            "{rendered}"
        );
    }

    #[test]
    fn compiler_scoped_data_symbol_renders_as_one_function_static_identity() {
        let function = Function {
            name: "static_function".to_string(),
            entry_va: 0x1200,
            body: vec![
                Stmt::Store {
                    addr: Expr::Addr(0x4040),
                    src: Expr::Bin {
                        op: BinOp::Add,
                        lhs: Box::new(Expr::Deref {
                            addr: Box::new(Expr::Addr(0x4040)),
                            size: 4,
                        }),
                        rhs: Box::new(Expr::Const(1)),
                    },
                    size: 4,
                },
                Stmt::Return { value: None },
            ],
        };
        install_dec_global_names(crate::ir::data_symbols::DataSymbols::from_entries([(
            0x4040u64,
            4u64,
            "static_function.static_var",
        )]));

        let rendered = render_decbench_typed_with_output(
            &function,
            None,
            None,
            crate::ir::types_recover::RecoveredOutputKind::Void,
        );
        clear_dec_function_static_locals();
        clear_dec_global_names();

        assert!(
            rendered.contains("    static int static_var;"),
            "{rendered}"
        );
        assert!(rendered.contains("    static_var++;"), "{rendered}");
        assert!(
            !rendered.contains("static_function_static_var"),
            "{rendered}"
        );
        assert!(!rendered.contains("extern int static_var"), "{rendered}");
    }

    /// A direct image address that became a portable object now renders as a C
    /// pointer (`&g[0]`). Every integer-typed consumer therefore needs the
    /// explicit machine-word conversion the classifier is responsible for.
    #[test]
    fn decbench_portable_static_storage_converts_into_integer_slots() {
        let function = Function {
            name: "use_counter".to_string(),
            entry_va: 0x1150,
            body: vec![
                // A dereference is what proves the VA denotes writable static
                // storage; the bare address uses below then denote its object.
                Stmt::Store {
                    addr: Expr::Addr(0x32300),
                    src: Expr::Const(0),
                    size: 8,
                },
                Stmt::Store {
                    addr: Expr::Addr(0x5c620),
                    src: Expr::Const(0),
                    size: 8,
                },
                Stmt::Assign {
                    dst: VReg::phys("var14"),
                    src: Expr::Addr(0x32300),
                },
                Stmt::Call {
                    target: Expr::Named {
                        va: 0x35100,
                        name: "sub_35100".to_string(),
                    },
                    args: vec![Expr::Addr(0x5c620)],
                    dst: Some(VReg::phys("var85")),
                    call_spec: None,
                },
            ],
        };

        let rendered = render_decbench(&function);

        assert!(
            !rendered.contains("var14 = &glaurung_global_32300[0];"),
            "a pointer cannot be assigned to a machine-word local:\n{rendered}"
        );
        assert!(
            rendered.contains("var14 = (long)(&glaurung_global_32300[0]);"),
            "the portable object address needs its machine-word conversion:\n{rendered}"
        );
        assert!(
            !rendered.contains("sub_35100(&glaurung_global_5c620[0])"),
            "an integer parameter cannot receive a bare object pointer:\n{rendered}"
        );
    }

    /// libacl's `getfacl::user_name`, reduced. `uid_str.1` at `0x82d0` is never
    /// read or written by this function: its address is only *taken* and handed
    /// to `snprintf`, then returned. Body evidence therefore cannot prove it is
    /// storage, and the address used to render as the bare literal `0x82d0` —
    /// which GCC compiles to `mov $imm` where the original had `lea ...(%rip)`,
    /// a form `byte_match` can never score as a match.
    ///
    /// The extent matters as much as the materialisation: `snprintf` writes up
    /// to 22 bytes, so the 16-byte object every other global gets would be a
    /// real overflow in the harnesses that COMPILE AND RUN the recovered C.
    /// `.bss` runs 0x8260..0x8328 here, bounding the object at 88 bytes.

    /// The same address with no storage layout installed — a stripped render, or
    /// any consumer that never had an image — keeps its previous output. The
    /// image fact is the only thing that admits an address-taken VA, so its
    /// absence has to be a refusal rather than a guess.

    /// Bare-metal firmware reads and passes hardware register addresses. They
    /// lie outside every section, so no extent is available and none is
    /// invented: materialising one would allocate RAM the peripheral never
    /// sees and silently drop the access to the device.

    /// `clz` is exactly representable, but only if BOTH halves of its meaning
    /// are stated: the operand's width (this IR keeps a 32-bit machine register
    /// at 64 bits, so counting the whole register answers 32 too high) and the
    /// architectural `clz(0) == 32`, which `__builtin_clz` leaves undefined.
    #[test]
    fn decbench_count_leading_zeros_states_its_width_and_its_zero_case() {
        let function = Function {
            name: "bitscan".to_string(),
            entry_va: 0x401000,
            body: vec![Stmt::Assign {
                dst: VReg::phys("var1"),
                src: Expr::WideArithmetic {
                    op: WideArithmetic::CountLeadingZeros,
                    args: vec![Expr::Reg(VReg::phys("arg0"))],
                    width: 4,
                },
            }],
        };

        let rendered = render_decbench(&function);

        assert!(
            rendered.contains("__builtin_clz("),
            "expected an exact leading-zero count:\n{rendered}"
        );
        assert!(
            !rendered.contains("__builtin_clzll"),
            "a 32-bit clz must not count a 64-bit quantity's zeros:\n{rendered}"
        );
        assert!(
            rendered.contains("(unsigned int)"),
            "the operand's 32-bit width is part of the operation:\n{rendered}"
        );
        assert!(
            rendered.contains("== 0) ? 32 :"),
            "clz(0) is 32 on ARM; __builtin_clz(0) is undefined:\n{rendered}"
        );

        let wide = Function {
            name: "bitscan64".to_string(),
            entry_va: 0x401000,
            body: vec![Stmt::Assign {
                dst: VReg::phys("var1"),
                src: Expr::WideArithmetic {
                    op: WideArithmetic::CountLeadingZeros,
                    args: vec![Expr::Reg(VReg::phys("arg0"))],
                    width: 8,
                },
            }],
        };
        let rendered = render_decbench(&wide);
        assert!(
            rendered.contains("__builtin_clzll(") && rendered.contains("== 0) ? 64 :"),
            "a 64-bit clz counts 64 bits and answers 64 at zero:\n{rendered}"
        );
    }

    /// `ctz` is the mirror of `clz` and needs both halves of its meaning stated
    /// for the same two reasons — with one difference that is x86's rather than
    /// ARM's: `tzcnt(0)` is architecturally the operand width, where the `bsf`
    /// this shares an encoding with instead leaves its destination alone.
    #[test]
    fn decbench_count_trailing_zeros_states_its_width_and_its_zero_case() {
        let narrow = Function {
            name: "trailing".to_string(),
            entry_va: 0x401000,
            body: vec![Stmt::Assign {
                dst: VReg::phys("var1"),
                src: Expr::WideArithmetic {
                    op: WideArithmetic::CountTrailingZeros,
                    args: vec![Expr::Reg(VReg::phys("arg0"))],
                    width: 4,
                },
            }],
        };
        let rendered = render_decbench(&narrow);
        assert!(
            rendered.contains("__builtin_ctz("),
            "expected an exact trailing-zero count:\n{rendered}"
        );
        assert!(
            !rendered.contains("__builtin_ctzll"),
            "a 32-bit ctz must not count a 64-bit quantity's zeros:\n{rendered}"
        );
        assert!(
            rendered.contains("(unsigned int)"),
            "the operand's 32-bit width is part of the operation:\n{rendered}"
        );
        assert!(
            rendered.contains("== 0) ? 32 :"),
            "tzcnt(0) is 32; __builtin_ctz(0) is undefined:\n{rendered}"
        );

        let wide = Function {
            name: "trailing64".to_string(),
            entry_va: 0x401000,
            body: vec![Stmt::Assign {
                dst: VReg::phys("var1"),
                src: Expr::WideArithmetic {
                    op: WideArithmetic::CountTrailingZeros,
                    args: vec![Expr::Reg(VReg::phys("arg0"))],
                    width: 8,
                },
            }],
        };
        let rendered = render_decbench(&wide);
        assert!(
            rendered.contains("__builtin_ctzll(") && rendered.contains("== 0) ? 64 :"),
            "a 64-bit ctz counts 64 bits and answers 64 at zero:\n{rendered}"
        );
    }

    /// `popcnt` is total, so it needs no zero case — but it still needs its
    /// width, because counting the set bits of a canonical 64-bit IR value
    /// would include whatever the parent's stale high half happens to hold.
    #[test]
    fn decbench_population_count_states_its_width() {
        let narrow = Function {
            name: "ones".to_string(),
            entry_va: 0x401000,
            body: vec![Stmt::Assign {
                dst: VReg::phys("var1"),
                src: Expr::WideArithmetic {
                    op: WideArithmetic::PopulationCount,
                    args: vec![Expr::Reg(VReg::phys("arg0"))],
                    width: 4,
                },
            }],
        };
        let rendered = render_decbench(&narrow);
        assert!(
            rendered.contains("__builtin_popcount((unsigned int)("),
            "expected an exact 32-bit population count:\n{rendered}"
        );
        assert!(
            !rendered.contains("__builtin_popcountll"),
            "a 32-bit popcnt must not count a 64-bit quantity's bits:\n{rendered}"
        );
        assert!(
            !rendered.contains("? 32 :"),
            "popcnt is defined at zero and needs no guard:\n{rendered}"
        );

        let wide = Function {
            name: "ones64".to_string(),
            entry_va: 0x401000,
            body: vec![Stmt::Assign {
                dst: VReg::phys("var1"),
                src: Expr::WideArithmetic {
                    op: WideArithmetic::PopulationCount,
                    args: vec![Expr::Reg(VReg::phys("arg0"))],
                    width: 8,
                },
            }],
        };
        let rendered = render_decbench(&wide);
        assert!(
            rendered.contains("__builtin_popcountll((unsigned long long)("),
            "a 64-bit popcnt counts 64 bits:\n{rendered}"
        );
    }

    /// `__int128` exists only on 64-bit targets. The double-width type belongs
    /// to the *operand* width, so a 32-bit multiply-high must widen to 64 bits
    /// and a 32-bit divide must not name a type the target cannot spell.
    #[test]
    fn decbench_wide_arithmetic_widens_to_the_operand_width() {
        let function = Function {
            name: "rand_step".to_string(),
            entry_va: 0x401000,
            body: vec![
                Stmt::Assign {
                    dst: VReg::phys("var18"),
                    src: Expr::WideArithmetic {
                        op: WideArithmetic::SignedMulHigh,
                        args: vec![Expr::Const(-0x7cb1f4a1), Expr::Reg(VReg::phys("var8"))],
                        width: 4,
                    },
                },
                Stmt::Assign {
                    dst: VReg::phys("var31"),
                    src: Expr::WideArithmetic {
                        op: WideArithmetic::UnsignedDivQuotient,
                        args: vec![
                            Expr::Reg(VReg::phys("var27")),
                            Expr::Reg(VReg::phys("var28")),
                            Expr::Const(10),
                        ],
                        width: 4,
                    },
                },
            ],
        };

        let rendered = render_decbench(&function);

        assert!(
            !rendered.contains("__int128"),
            "32-bit wide arithmetic must not name a 64-bit-only type:\n{rendered}"
        );
        assert!(
            rendered.contains("long long"),
            "a 32-bit multiply-high still needs a double-width type:\n{rendered}"
        );

        let wide = Function {
            name: "wide_step".to_string(),
            entry_va: 0x401000,
            body: vec![Stmt::Assign {
                dst: VReg::phys("var1"),
                src: Expr::WideArithmetic {
                    op: WideArithmetic::UnsignedMulHigh,
                    args: vec![Expr::Reg(VReg::phys("arg0")), Expr::Reg(VReg::phys("arg1"))],
                    width: 8,
                },
            }],
        };
        assert!(
            render_decbench(&wide).contains("unsigned __int128"),
            "64-bit operands still need the 128-bit intermediate"
        );
    }

    /// The 16-byte transport builtins take `void *`. Their address operands are
    /// ordinary machine-word expressions in the middle layer, so they need the
    /// same representation conversion every other pointer boundary applies.
    #[test]
    fn decbench_wide_copy_addresses_convert_to_object_pointers() {
        let function = Function {
            name: "copy_pair".to_string(),
            entry_va: 0x1000,
            body: vec![
                Stmt::Assign {
                    dst: VReg::phys("var47"),
                    src: Expr::Deref {
                        addr: Box::new(Expr::Bin {
                            op: BinOp::Add,
                            lhs: Box::new(Expr::Reg(VReg::phys("var41"))),
                            rhs: Box::new(Expr::Const(0x10)),
                        }),
                        size: 16,
                    },
                },
                Stmt::Store {
                    addr: Expr::Reg(VReg::phys("var13")),
                    src: Expr::Reg(VReg::phys("var47")),
                    size: 16,
                },
            ],
        };

        let rendered = render_decbench(&prepare_for_decbench(&function));

        assert!(
            rendered.contains("__builtin_memcpy(var47, (void *)((var41 + 16)), 16);"),
            "the copy source is an address, not an integer:\n{rendered}"
        );
        assert!(
            rendered.contains("__builtin_memmove((void *)(var13), var47, 16);"),
            "the copy destination is an address, not an integer:\n{rendered}"
        );
    }

    /// A recovered callee declaration and the argument the call actually passes
    /// must agree. Two *different* pointer types are still a type error, so the
    /// call site has to reassert the declared parameter type.
    #[test]
    fn decbench_recovered_pointer_parameter_is_reasserted_at_the_call() {
        let function = Function {
            name: "sub_801da04".to_string(),
            entry_va: 0x801da04,
            body: vec![Stmt::Call {
                target: Expr::Named {
                    va: 0x801d49c,
                    name: "sub_801d49c".to_string(),
                },
                args: vec![Expr::Reg(VReg::phys("arg0"))],
                dst: Some(VReg::phys("var3")),
                call_spec: Some(crate::ir::call_contracts::CallSiteSpec {
                    callee_prototype: Some(CallPrototype {
                        return_type: "int".into(),
                        parameter_types: vec!["int *".into()],
                        variadic: false,
                        authority: CallPrototypeAuthority::Recovered,
                    }),
                    call_prototype: CallPrototype {
                        return_type: "int".into(),
                        parameter_types: vec!["int *".into()],
                        variadic: false,
                        authority: CallPrototypeAuthority::Recovered,
                    },
                }),
            }],
        };

        let mut types = TypeMap::default();
        types.upsert_public(VReg::phys("arg0"), TypeHint::Pointer { pointee_width: 1 });
        let rendered = render_decbench_typed(&function, Some(&types), None);

        assert!(
            rendered.contains("sub_801d49c((int *)"),
            "a declared pointer parameter must be reasserted at the call:\n{rendered}"
        );
    }

    #[test]
    fn decbench_stack_address_is_cast_to_the_recovered_pointer_parameter() {
        let prototype = CallPrototype {
            return_type: "int".into(),
            parameter_types: vec!["int *".into()],
            variadic: false,
            authority: CallPrototypeAuthority::Recovered,
        };
        let function = Function {
            name: "stack_status".to_string(),
            entry_va: 0,
            body: vec![Stmt::Call {
                target: Expr::Named {
                    va: 0x2000,
                    name: "get_status".to_string(),
                },
                args: vec![Expr::StackAddr {
                    object: VReg::phys("local_20"),
                    size: 32,
                }],
                dst: Some(VReg::phys("var0")),
                call_spec: Some(crate::ir::call_contracts::CallSiteSpec {
                    callee_prototype: Some(prototype.clone()),
                    call_prototype: prototype,
                }),
            }],
        };

        let rendered = render_decbench_typed(&function, None, None);

        assert!(
            rendered.contains("get_status((int *)(&local_20[0]))"),
            "the stack object's byte-array representation must not violate the callee contract:\n{rendered}"
        );
    }

    // -- the prepare/render boundary -------------------------------------------
    //
    // These characterise the transformation that used to happen while printing.
    // Each asserts the AST ITSELF changes (so the change is verifiable), and that
    // the renderer alone does not make it (so the renderer is formatting-only).

    #[test]
    fn prepare_folds_a_uniquely_shared_bare_return_to_its_value() {
        let f = Function {
            name: "f".to_string(),
            entry_va: 0x10,
            body: vec![
                Stmt::Assign {
                    dst: VReg::phys("ret"),
                    src: Expr::Const(7),
                },
                Stmt::Goto { target: 0x20 },
                Stmt::Label(0x20),
                Stmt::Return { value: None },
            ],
        };
        let prepared = prepare_for_decbench(&f);
        assert_eq!(
            prepared.body,
            vec![Stmt::Return {
                value: Some(Expr::Const(7))
            }],
            "prepare must preserve and directly return the computed ABI value"
        );
        // The renderer must not do it on its own.
        assert!(
            !render_decbench(&f).contains("return ret;"),
            "the renderer must not change what is returned"
        );
    }

    #[test]
    fn recovered_void_output_erases_machine_register_residue_before_rendering() {
        let f = Function {
            name: "tick".to_string(),
            entry_va: 0x10,
            body: vec![
                Stmt::Assign {
                    dst: VReg::phys("ret"),
                    src: Expr::Const(7),
                },
                Stmt::Store {
                    addr: Expr::Const(0x4000),
                    src: Expr::Reg(VReg::phys("ret")),
                    size: 4,
                },
                Stmt::Return {
                    value: Some(Expr::Reg(VReg::phys("ret"))),
                },
            ],
        };

        let prepared = prepare_for_decbench_with_output(
            &f,
            crate::ir::types_recover::RecoveredOutputKind::Void,
        );
        assert_eq!(
            prepared.body.last(),
            Some(&Stmt::Store {
                addr: Expr::Const(0x4000),
                src: Expr::Const(7),
                size: 4,
            }),
            "a void prototype must erase the incidental machine output and terminal machine return"
        );
        let text = render_decbench_typed_with_output(
            &prepared,
            None,
            None,
            crate::ir::types_recover::RecoveredOutputKind::Void,
        );
        assert!(text.contains("void tick(void)"), "wrong signature:\n{text}");
        assert!(
            !text.contains("return"),
            "redundant return survived:\n{text}"
        );
        assert!(
            !text.contains("return ret;"),
            "machine residue leaked:\n{text}"
        );
    }

    #[test]
    fn recovered_void_output_does_not_recreate_a_saved_result_register_return() {
        let f = Function {
            name: "print_sum".to_string(),
            entry_va: 0x10,
            body: vec![
                Stmt::Store {
                    addr: Expr::Reg(VReg::phys("local_8")),
                    src: Expr::Reg(VReg::phys("ret")),
                    size: 8,
                },
                Stmt::Call {
                    target: Expr::Named {
                        va: 0x20,
                        name: "printf".to_string(),
                    },
                    args: vec![Expr::Const(0x4000)],
                    dst: None,
                    call_spec: None,
                },
                Stmt::Assign {
                    dst: VReg::phys("ret"),
                    src: Expr::Reg(VReg::phys("local_8")),
                },
                Stmt::Return {
                    value: Some(Expr::Reg(VReg::phys("ret"))),
                },
            ],
        };

        let prepared = prepare_for_decbench_with_output(
            &f,
            crate::ir::types_recover::RecoveredOutputKind::Void,
        );

        assert!(matches!(prepared.body.as_slice(), [Stmt::Call { .. }]));
    }

    #[test]
    fn prepare_folds_a_copy_chain_in_the_ast_not_at_print_time() {
        // var0 = arg0;  ret = var0;  return ret;   ->   ret = arg0
        let f = Function {
            name: "f".to_string(),
            entry_va: 0x10,
            body: vec![
                Stmt::Assign {
                    dst: VReg::phys("var0"),
                    src: Expr::Reg(VReg::phys("arg0")),
                },
                Stmt::Assign {
                    dst: VReg::phys("ret"),
                    src: Expr::Reg(VReg::phys("var0")),
                },
                Stmt::Return {
                    value: Some(Expr::Reg(VReg::phys("ret"))),
                },
            ],
        };
        let prepared = prepare_for_decbench(&f);
        let text = render_decbench(&prepared);
        assert!(
            !text.contains("var0"),
            "the copy chain must be gone from the AST before rendering:\n{text}"
        );
        // And it is gone from the AST, not just from the printed text.
        let mut names = Vec::new();
        for s in &prepared.body {
            if let Stmt::Assign { dst, .. } = s {
                names.push(format!("{dst}"));
            }
        }
        assert!(
            !names.iter().any(|n| n.contains("var0")),
            "var0 still defined in the prepared AST: {names:?}"
        );
    }

    #[test]
    fn prepare_recovers_a_head_tested_while_after_copy_folding() {
        // Real -O0 loop headers lower conservatively as
        //
        //   while (1) { t = i; if (t <= 1) break; i = i - 1; }
        //
        // Copy propagation proves the reload is redundant and removes it.  Once
        // the exit guard is literally the first statement, converting it to the
        // loop condition moves no computation and is semantics-preserving.
        let i = VReg::phys("local_4");
        let t = VReg::phys("t10");
        let mut f = Function {
            name: "factorial_shape".to_string(),
            entry_va: 0x10,
            body: vec![Stmt::While {
                cond: Expr::Const(1),
                body: vec![
                    Stmt::Assign {
                        dst: t.clone(),
                        src: Expr::Reg(i.clone()),
                    },
                    Stmt::If {
                        cond: Expr::Cmp {
                            op: CmpOp::Sle,
                            lhs: Box::new(Expr::Reg(t)),
                            rhs: Box::new(Expr::Const(1)),
                        },
                        then_body: vec![Stmt::Break],
                        else_body: None,
                    },
                    Stmt::Assign {
                        dst: i.clone(),
                        src: Expr::Bin {
                            op: BinOp::Sub,
                            lhs: Box::new(Expr::Reg(i.clone())),
                            rhs: Box::new(Expr::Const(1)),
                        },
                    },
                ],
            }],
        };

        f = prepare_for_decbench(&f);

        assert_eq!(
            f.body,
            vec![Stmt::While {
                cond: Expr::Cmp {
                    op: CmpOp::Slt,
                    lhs: Box::new(Expr::Const(1)),
                    rhs: Box::new(Expr::Reg(i.clone())),
                },
                body: vec![Stmt::Assign {
                    dst: i.clone(),
                    src: Expr::Bin {
                        op: BinOp::Sub,
                        lhs: Box::new(Expr::Reg(i)),
                        rhs: Box::new(Expr::Const(1)),
                    },
                }],
            }]
        );
    }

    #[test]
    fn prepare_coalesces_a_parameter_spill_slot_into_the_parameter() {
        // The `-O0` shape: the parameter is spilled to its frame slot (a Store to
        // the promoted local) and read back from it. That slot IS the parameter, so
        // the emitted C must use `arg0` directly — emitting `local_14 = arg0` and
        // then reading the slot recompiles to stack traffic the original never had.
        let f = Function {
            name: "f".to_string(),
            entry_va: 0x10,
            body: vec![
                Stmt::Store {
                    addr: Expr::Reg(VReg::phys("local_14")),
                    src: Expr::Reg(VReg::phys("arg0")),
                    size: 8,
                },
                Stmt::Assign {
                    dst: VReg::phys("ret"),
                    src: Expr::Bin {
                        op: BinOp::Add,
                        lhs: Box::new(Expr::Reg(VReg::phys("local_14"))),
                        rhs: Box::new(Expr::Const(1)),
                    },
                },
                Stmt::Return {
                    value: Some(Expr::Reg(VReg::phys("ret"))),
                },
            ],
        };
        let text = render_decbench(&prepare_for_decbench(&f));
        assert!(
            text.contains("arg0 + 1") && !text.contains("local_14"),
            "the spill slot must be folded into the parameter:\n{text}"
        );
        // The renderer alone must not do it.
        assert!(
            render_decbench(&f).contains("local_14"),
            "the renderer must not rewrite value identities"
        );
    }

    #[test]
    fn prepare_keeps_a_mutated_parameter_home_when_the_entry_value_remains_live() {
        let f = Function {
            name: "mutable_parameter_home".to_string(),
            entry_va: 0x1000,
            body: vec![
                Stmt::Store {
                    addr: Expr::Reg(VReg::phys("local_14")),
                    src: Expr::Reg(VReg::phys("arg0")),
                    size: 4,
                },
                Stmt::Store {
                    addr: Expr::Reg(VReg::phys("local_14")),
                    src: Expr::Const(7),
                    size: 4,
                },
                Stmt::Return {
                    value: Some(Expr::Bin {
                        op: BinOp::Add,
                        lhs: Box::new(Expr::Reg(VReg::phys("local_14"))),
                        rhs: Box::new(Expr::Reg(VReg::phys("arg0"))),
                    }),
                },
            ],
        };

        let prepared = prepare_for_decbench(&f);
        let text = render(&prepared);

        assert!(text.contains("%local_14"), "{text}");
        assert!(!text.contains("%arg0 = 7"), "{text}");
    }

    #[test]
    fn prepare_keeps_a_saved_parameter_home_across_output_register_reuse() {
        // AArch64 recursively calls through x0/arg0 after preserving the entry
        // parameter in x4 and spilling x4 around the call. The compatibility
        // call-result copy writes arg0 before x4 is restored. Coalescing the
        // spill directly into arg0 would therefore reload the call result, not
        // the saved entry parameter.
        let f = Function {
            name: "recursive_saved_parameter".to_string(),
            entry_va: 0x10,
            body: vec![
                Stmt::Assign {
                    dst: VReg::phys("saved_n"),
                    src: Expr::Reg(VReg::phys("arg0")),
                },
                Stmt::Store {
                    addr: Expr::Reg(VReg::phys("stack_n")),
                    src: Expr::Reg(VReg::phys("saved_n")),
                    size: 8,
                },
                Stmt::Call {
                    target: Expr::Named {
                        va: 0x10,
                        name: "recursive_saved_parameter".to_string(),
                    },
                    args: vec![Expr::Const(1)],
                    dst: Some(VReg::phys("call_result")),
                    call_spec: None,
                },
                Stmt::Assign {
                    dst: VReg::phys("arg0"),
                    src: Expr::Reg(VReg::phys("call_result")),
                },
                Stmt::Assign {
                    dst: VReg::phys("saved_n"),
                    src: Expr::Reg(VReg::phys("stack_n")),
                },
                Stmt::Return {
                    value: Some(Expr::Reg(VReg::phys("saved_n"))),
                },
            ],
        };

        let prepared = prepare_for_decbench(&f);
        let text = render_decbench(&prepared);

        assert!(text.contains("stack_n = arg0;"), "{text}");
        assert!(text.contains("return stack_n;"), "{text}");
        assert!(!text.contains("return call_result;"), "{text}");
    }

    #[test]
    fn a_cast_pointer_spill_does_not_turn_a_pointee_store_into_home_assignment() {
        // i386 materializes a pointer argument through a four-byte cast before
        // spilling it.  The later store is through a scratch loaded FROM that
        // home, not another write TO the home.  Failing to recognize the cast
        // spill leaves both operations named `local_1c` after copy propagation
        // and renders `local_1c = 0` instead of `*(int *)arg0 = 0`.
        let f = Function {
            name: "i386_pointer_home".to_string(),
            entry_va: 0x10,
            body: vec![
                Stmt::Assign {
                    dst: VReg::phys("eax_in"),
                    src: Expr::Reg(VReg::phys("arg0")),
                },
                Stmt::Store {
                    addr: Expr::Reg(VReg::phys("local_1c")),
                    src: Expr::Cast {
                        signed: false,
                        width: 4,
                        expr: Box::new(Expr::Reg(VReg::phys("eax_in"))),
                    },
                    size: 4,
                },
                Stmt::Assign {
                    dst: VReg::phys("eax"),
                    src: Expr::Reg(VReg::phys("local_1c")),
                },
                Stmt::Store {
                    addr: Expr::Reg(VReg::phys("eax")),
                    src: Expr::Const(0),
                    size: 4,
                },
                Stmt::Return {
                    value: Some(Expr::Deref {
                        addr: Box::new(Expr::Reg(VReg::phys("local_1c"))),
                        size: 4,
                    }),
                },
            ],
        };

        let prepared = prepare_for_decbench(&f);

        assert!(
            prepared.body.iter().any(|statement| matches!(
                statement,
                Stmt::Store {
                    addr,
                    src: Expr::Const(0),
                    size: 4,
                } if matches!(addr,
                    Expr::Reg(VReg::Phys(name)) if name == "arg0"
                ) || matches!(addr,
                    Expr::Cast { expr, .. }
                        if matches!(expr.as_ref(), Expr::Reg(VReg::Phys(name)) if name == "arg0")
                )
            )),
            "the pointee store must remain a store through arg0: {prepared:#?}"
        );
        assert!(
            !prepared.body.iter().any(|statement| matches!(
                statement,
                Stmt::Assign {
                    dst: VReg::Phys(name),
                    src: Expr::Const(0),
                } if name == "arg0" || name == "local_1c"
            )),
            "the pointee store was mistaken for a parameter assignment: {prepared:#?}"
        );
        assert!(
            !prepared.body.iter().any(|statement| matches!(
                statement,
                Stmt::Assign {
                    dst: VReg::Phys(dst),
                    src: Expr::Reg(VReg::Phys(src)),
                } if dst == src
            )),
            "late copy propagation must not leave a self-assignment: {prepared:#?}"
        );
    }

    #[test]
    fn a_protected_pointer_home_preserves_an_indirect_output_store() {
        let protected =
            std::collections::HashSet::from(["local_10".to_string(), "local_20".to_string()]);
        let function = Function {
            name: "copy_output".to_string(),
            entry_va: 0x10,
            body: vec![
                Stmt::Store {
                    addr: Expr::Reg(VReg::phys("local_10")),
                    src: Expr::Reg(VReg::phys("arg0")),
                    size: 8,
                },
                Stmt::Store {
                    addr: Expr::Reg(VReg::phys("local_20")),
                    src: Expr::Reg(VReg::phys("arg2")),
                    size: 8,
                },
                Stmt::Assign {
                    dst: VReg::phys("ret"),
                    src: Expr::Reg(VReg::phys("local_10")),
                },
                Stmt::Assign {
                    dst: VReg::phys("value"),
                    src: Expr::Deref {
                        addr: Box::new(Expr::Reg(VReg::phys("ret"))),
                        size: 4,
                    },
                },
                Stmt::Assign {
                    dst: VReg::phys("ret"),
                    src: Expr::Reg(VReg::phys("local_20")),
                },
                Stmt::Store {
                    addr: Expr::Reg(VReg::phys("ret")),
                    src: Expr::Reg(VReg::phys("value")),
                    size: 4,
                },
            ],
        };

        let prepared = prepare_for_decbench_with_output_and_protected_locals(
            &function,
            crate::ir::types_recover::RecoveredOutputKind::Void,
            &protected,
            8,
        );

        assert!(
            prepared.body.iter().any(|statement| matches!(
                statement,
                Stmt::Store {
                    addr: Expr::Reg(VReg::Phys(address)),
                    ..
                } if address == "ret"
            )),
            "the output write must remain indirect: {prepared:#?}"
        );
    }

    #[test]
    fn prepare_does_not_coalesce_a_parameter_spill_reused_for_a_status_value() {
        let f = Function {
            name: "spill_then_status".to_string(),
            entry_va: 0x10,
            body: vec![
                Stmt::Store {
                    addr: Expr::Reg(VReg::phys("local_20")),
                    src: Expr::Reg(VReg::phys("arg4")),
                    size: 8,
                },
                Stmt::Call {
                    target: Expr::Named {
                        va: 0x2000,
                        name: "consume_pointer".into(),
                    },
                    args: vec![Expr::Reg(VReg::phys("local_20"))],
                    dst: Some(VReg::phys("status")),
                    call_spec: None,
                },
                Stmt::Store {
                    addr: Expr::Reg(VReg::phys("local_20")),
                    src: Expr::Reg(VReg::phys("status")),
                    size: 4,
                },
                Stmt::Return {
                    value: Some(Expr::Reg(VReg::phys("local_20"))),
                },
            ],
        };

        let prepared = prepare_for_decbench(&f);
        let text = render_decbench(&prepared);

        assert!(
            text.contains("local_20 = consume_pointer(local_20)"),
            "{text}"
        );
        assert!(text.contains("return local_20"), "{text}");
        assert!(!text.contains("return arg4"), "{text}");
    }

    #[test]
    fn prepare_coalesces_an_immutable_parameter_spill_inside_a_frame_object() {
        let frame_slot = Expr::Bin {
            op: BinOp::Add,
            lhs: Box::new(Expr::StackAddr {
                object: VReg::phys("local_18"),
                size: 24,
            }),
            rhs: Box::new(Expr::Const(4)),
        };
        let f = Function {
            name: "arm_o0_pointer_spill".to_string(),
            entry_va: 0x10,
            body: vec![
                Stmt::Store {
                    addr: frame_slot.clone(),
                    src: Expr::Reg(VReg::phys("arg0")),
                    size: 4,
                },
                Stmt::Return {
                    value: Some(Expr::Deref {
                        addr: Box::new(frame_slot),
                        size: 4,
                    }),
                },
            ],
        };

        let prepared = prepare_for_decbench(&f);
        let text = render_decbench(&prepared);

        assert!(text.contains("return arg0;"), "{text}");
        assert!(
            !text.contains("local_18"),
            "the immutable frame subslot is the parameter's home, not a second C object:\n{text}"
        );
    }

    #[test]
    fn prepare_keeps_a_mutated_frame_object_parameter_home() {
        let frame_slot = Expr::Bin {
            op: BinOp::Add,
            lhs: Box::new(Expr::StackAddr {
                object: VReg::phys("local_18"),
                size: 24,
            }),
            rhs: Box::new(Expr::Const(4)),
        };
        let f = Function {
            name: "mutated_home".to_string(),
            entry_va: 0x10,
            body: vec![
                Stmt::Store {
                    addr: frame_slot.clone(),
                    src: Expr::Reg(VReg::phys("arg0")),
                    size: 4,
                },
                Stmt::Store {
                    addr: frame_slot.clone(),
                    src: Expr::Const(7),
                    size: 4,
                },
                Stmt::Return {
                    value: Some(Expr::Deref {
                        addr: Box::new(frame_slot),
                        size: 4,
                    }),
                },
            ],
        };

        let text = render_decbench(&prepare_for_decbench(&f));

        assert!(
            text.contains("local_18"),
            "mutable storage was erased:\n{text}"
        );
        assert!(
            text.contains("= 7;"),
            "the source-level mutation was erased:\n{text}"
        );
    }

    #[test]
    fn prepare_keeps_a_frame_parameter_home_reused_at_a_narrower_width() {
        let frame_slot = Expr::StackAddr {
            object: VReg::phys("local_20"),
            size: 32,
        };
        let f = Function {
            name: "mixed_width_reuse".to_string(),
            entry_va: 0x10,
            body: vec![
                Stmt::Store {
                    addr: frame_slot.clone(),
                    src: Expr::Reg(VReg::phys("arg4")),
                    size: 8,
                },
                Stmt::Call {
                    target: Expr::Named {
                        va: 0x2000,
                        name: "consume_pointer".into(),
                    },
                    args: vec![Expr::Deref {
                        addr: Box::new(frame_slot.clone()),
                        size: 8,
                    }],
                    dst: Some(VReg::phys("status")),
                    call_spec: None,
                },
                Stmt::Store {
                    addr: frame_slot.clone(),
                    src: Expr::Reg(VReg::phys("status")),
                    size: 4,
                },
                Stmt::Return {
                    value: Some(Expr::Deref {
                        addr: Box::new(frame_slot),
                        size: 4,
                    }),
                },
            ],
        };

        let text = render_decbench(&prepare_for_decbench(&f));

        assert!(text.contains("local_20"), "{text}");
        assert!(!text.contains("return arg4"), "{text}");
    }

    #[test]
    fn prepare_keeps_a_frame_store_read_only_through_an_alias() {
        let stack = Expr::StackAddr {
            object: VReg::phys("stack_0"),
            size: 64,
        };
        let f = Function {
            name: "graph_stack_seed".to_string(),
            entry_va: 0x10,
            body: vec![
                Stmt::Store {
                    addr: stack.clone(),
                    src: Expr::Reg(VReg::phys("arg2")),
                    size: 4,
                },
                Stmt::Assign {
                    dst: VReg::phys("rbp"),
                    src: stack,
                },
                Stmt::Return {
                    value: Some(Expr::Deref {
                        addr: Box::new(Expr::Reg(VReg::phys("rbp"))),
                        size: 4,
                    }),
                },
            ],
        };

        let prepared = prepare_for_decbench(&f);

        assert!(
            prepared
                .body
                .iter()
                .any(|statement| matches!(statement, Stmt::Store { src: Expr::Reg(VReg::Phys(name)), .. } if name == "arg2")),
            "the seed store cannot be erased when its load is reached through an alias: {prepared:#?}"
        );
    }

    #[test]
    fn an_in_place_update_of_a_coalesced_slot_is_an_assignment_not_a_pointer_store() {
        // The `-O0` shape of `n &= 31u` on a spilled parameter: the slot is stored
        // to from the parameter, then updated IN PLACE (a memory read-modify-write).
        // Coalescing renames the slot to `arg1`, after which the renderer can no
        // longer tell the store apart from `*arg1 = v` — and emitted a write through
        // a parameter that is not a pointer, segfaulting the recompiled function
        // (fixture `rotr32`).
        let f = Function {
            name: "f".to_string(),
            entry_va: 0x10,
            body: vec![
                Stmt::Store {
                    addr: Expr::Reg(VReg::phys("local_18")),
                    src: Expr::Reg(VReg::phys("arg1")),
                    size: 4,
                },
                Stmt::Store {
                    addr: Expr::Reg(VReg::phys("local_18")),
                    src: Expr::Bin {
                        op: BinOp::And,
                        lhs: Box::new(Expr::Reg(VReg::phys("local_18"))),
                        rhs: Box::new(Expr::Const(31)),
                    },
                    size: 4,
                },
                Stmt::Return {
                    value: Some(Expr::Reg(VReg::phys("local_18"))),
                },
            ],
        };
        let text = render_decbench(&prepare_for_decbench(&f));
        assert!(
            text.contains("arg1 = (arg1 & 31)"),
            "the in-place update must be an assignment to the parameter:\n{text}"
        );
        assert!(
            !text.contains("*(int *)(arg1)") && !text.contains("*(long *)(arg1)"),
            "must not write THROUGH the parameter:\n{text}"
        );
        // The redundant spill store collapses; the parameter is used directly.
        assert!(!text.contains("local_18"), "slot should be gone:\n{text}");
    }

    #[test]
    fn a_genuine_store_through_a_pointer_parameter_is_preserved() {
        // The other side of the same coin: with no slot coalesced into it, a store
        // whose address is a parameter really is a store through a pointer and must
        // stay one.
        let f = Function {
            name: "f".to_string(),
            entry_va: 0x10,
            body: vec![Stmt::Store {
                addr: Expr::Reg(VReg::phys("arg0")),
                src: Expr::Const(7),
                size: 4,
            }],
        };
        let text = render_decbench(&prepare_for_decbench(&f));
        assert!(
            text.contains("*(int *)(arg0) = 7"),
            "a pointer store must not become an assignment:\n{text}"
        );
    }

    #[test]
    fn rendering_the_same_prepared_ast_twice_is_identical_and_leaves_it_unchanged() {
        // Formatting-only means: no hidden state, no mutation, no dependence on
        // render order (the thread-locals the renderer uses are reset per call).
        let f = Function {
            name: "f".to_string(),
            entry_va: 0x10,
            body: vec![
                Stmt::Assign {
                    dst: VReg::phys("local_14"),
                    src: Expr::Reg(VReg::phys("arg0")),
                },
                Stmt::Return {
                    value: Some(Expr::Reg(VReg::phys("local_14"))),
                },
            ],
        };
        let prepared = prepare_for_decbench(&f);
        let before = prepared.clone();
        let a = render_decbench(&prepared);
        let b = render_decbench(&prepared);
        assert_eq!(a, b, "rendering is not deterministic");
        assert_eq!(prepared, before, "rendering mutated the AST");
    }

    #[test]
    fn prepare_is_idempotent() {
        let f = Function {
            name: "f".to_string(),
            entry_va: 0x10,
            body: vec![
                Stmt::Assign {
                    dst: VReg::phys("var0"),
                    src: Expr::Reg(VReg::phys("arg0")),
                },
                Stmt::Assign {
                    dst: VReg::phys("ret"),
                    src: Expr::Reg(VReg::phys("var0")),
                },
                Stmt::Return {
                    value: Some(Expr::Reg(VReg::phys("ret"))),
                },
            ],
        };
        let once = prepare_for_decbench(&f);
        let twice = prepare_for_decbench(&once);
        assert_eq!(once, twice, "prepare must reach a fixed point in one pass");
    }

    #[test]
    fn prepare_revisits_copy_propagation_after_mask_folding_changes_use_count() {
        let state = Expr::Reg(VReg::phys("state"));
        let predicate = Expr::Cmp {
            op: CmpOp::Eq,
            lhs: Box::new(state),
            rhs: Box::new(Expr::Const(3)),
        };
        let parent = VReg::phys("var_parent");
        let ret = VReg::phys("ret");
        let mut f = Function {
            name: "masked_return".to_string(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: parent.clone(),
                    src: Expr::Bin {
                        op: BinOp::Or,
                        lhs: Box::new(Expr::Bin {
                            op: BinOp::And,
                            lhs: Box::new(Expr::Reg(VReg::phys("old_parent"))),
                            rhs: Box::new(Expr::Const(-256)),
                        }),
                        rhs: Box::new(predicate.clone()),
                    },
                },
                Stmt::Assign {
                    dst: ret.clone(),
                    src: Expr::Bin {
                        op: BinOp::And,
                        lhs: Box::new(Expr::Bin {
                            op: BinOp::Or,
                            lhs: Box::new(Expr::Bin {
                                op: BinOp::And,
                                lhs: Box::new(Expr::Reg(parent.clone())),
                                rhs: Box::new(Expr::Const(-256)),
                            }),
                            rhs: Box::new(Expr::Bin {
                                op: BinOp::And,
                                lhs: Box::new(Expr::Reg(parent.clone())),
                                rhs: Box::new(Expr::Const(1)),
                            }),
                        }),
                        rhs: Box::new(Expr::Const(255)),
                    },
                },
                Stmt::Return {
                    value: Some(Expr::Reg(ret)),
                },
            ],
        };

        f = prepare_for_decbench(&f);

        assert_eq!(
            f.body,
            vec![Stmt::Return {
                value: Some(predicate),
            }]
        );
    }

    /// Assertions that must hold for *any* `render_decbench` output: no
    /// register `%` sigils, no `&[...]` address forms, no `<...>` unknowns, a
    /// real `long` signature, and a balanced brace at the end.
    fn assert_looks_like_c(text: &str) {
        let mut paren_depth = 0_i32;
        for (index, byte) in text.bytes().enumerate() {
            match byte {
                b'(' => paren_depth += 1,
                b')' => {
                    paren_depth -= 1;
                    assert!(
                        paren_depth >= 0,
                        "decbench output has an unmatched closing parenthesis:\n{}",
                        text
                    );
                }
                _ => {}
            }
            if byte == b'%' {
                let next = text.as_bytes().get(index + 1).copied();
                assert!(
                    !next.is_some_and(|next| next.is_ascii_alphabetic() || next == b'_'),
                    "decbench output still has a %register sigil:\n{}",
                    text
                );
            }
        }
        assert_eq!(
            paren_depth, 0,
            "decbench output has unmatched opening parentheses:\n{}",
            text
        );
        assert!(
            !text.contains("&["),
            "decbench output still has &[ address form:\n{}",
            text
        );
        // Reject angle-bracket-wrapped tokens (`<rax>`, `<unk>`) while allowing
        // legitimate C comparison/shift operators (`<`, `<=`, `<<`, `>>`): flag
        // only a `<`/`>` that is glued to an alphanumeric identifier character.
        let bytes = text.as_bytes();
        for (i, &b) in bytes.iter().enumerate() {
            if b == b'<' {
                if let Some(&n) = bytes.get(i + 1) {
                    assert!(
                        !n.is_ascii_alphanumeric(),
                        "decbench output has a `<ident>` token:\n{}",
                        text
                    );
                }
            }
            if b == b'>' && i > 0 {
                let p = bytes[i - 1];
                assert!(
                    !p.is_ascii_alphanumeric(),
                    "decbench output has an `ident>` token:\n{}",
                    text
                );
            }
        }
        assert!(
            text.contains("long "),
            "decbench output missing a long signature:\n{}",
            text
        );
        assert!(
            text.trim_end().ends_with('}'),
            "decbench output not brace-terminated:\n{}",
            text
        );
    }

    #[test]
    fn decbench_emits_signature_locals_and_return() {
        // arg0 flows to a local `var0` used twice (so it is not folded away),
        // which is then returned as `var0 * var0`.
        let f = Function {
            name: "add_one".to_string(),
            entry_va: 0x1230,
            body: vec![
                Stmt::Assign {
                    dst: VReg::phys("var0"),
                    src: Expr::Bin {
                        op: BinOp::Add,
                        lhs: Box::new(Expr::Reg(VReg::phys("arg0"))),
                        rhs: Box::new(Expr::Const(1)),
                    },
                },
                Stmt::Return {
                    value: Some(Expr::Bin {
                        op: BinOp::Mul,
                        lhs: Box::new(Expr::Reg(VReg::phys("var0"))),
                        rhs: Box::new(Expr::Reg(VReg::phys("var0"))),
                    }),
                },
            ],
        };
        let text = render_decbench(&f);
        assert!(text.contains("long add_one(long arg0) {"), "got:\n{}", text);
        assert!(text.contains("long var0;"), "missing local decl:\n{}", text);
        assert!(text.contains("var0 = (arg0 + 1);"), "body wrong:\n{}", text);
        assert!(
            text.contains("return (var0 * var0);"),
            "return wrong:\n{}",
            text
        );
        assert_looks_like_c(&text);
    }

    #[test]
    fn hint_to_ctype_covers_widths_signs_and_pointers() {
        use crate::ir::types_recover::TypeHint;
        assert_eq!(
            hint_to_ctype(TypeHint::Int {
                signed: true,
                width: 4
            }),
            "int"
        );
        assert_eq!(
            hint_to_ctype(TypeHint::Int {
                signed: false,
                width: 4
            }),
            "unsigned int"
        );
        assert_eq!(
            hint_to_ctype(TypeHint::Int {
                signed: true,
                width: 8
            }),
            "long"
        );
        assert_eq!(
            hint_to_ctype(TypeHint::Int {
                signed: false,
                width: 1
            }),
            "unsigned char"
        );
        assert_eq!(
            hint_to_ctype(TypeHint::Pointer { pointee_width: 1 }),
            "char *"
        );
        assert_eq!(
            hint_to_ctype(TypeHint::Pointer { pointee_width: 8 }),
            "long *"
        );
        assert_eq!(hint_to_ctype(TypeHint::BoolLike), "int");
        assert_eq!(hint_to_ctype(TypeHint::CodePointer), "void *");
        assert_eq!(hint_to_ctype(TypeHint::Float { width: 4 }), "float");
        assert_eq!(hint_to_ctype(TypeHint::Float { width: 8 }), "double");
    }

    #[test]
    fn decbench_typed_emits_recovered_float_return_type() {
        use crate::ir::types_recover::{RecoveredOutputKind, TypeHint, TypeMap};

        let f = Function {
            name: "square".to_string(),
            entry_va: 0x1000,
            body: vec![Stmt::Return {
                value: Some(Expr::Reg(VReg::phys("ret"))),
            }],
        };
        let mut tm = TypeMap::default();
        tm.upsert_public(VReg::phys("ret"), TypeHint::Float { width: 4 });

        let text = render_decbench_typed_with_output(
            &f,
            Some(&tm),
            Some(&tm),
            RecoveredOutputKind::Direct,
        );
        assert!(
            text.contains("float square(void)"),
            "wrong signature:\n{text}"
        );
    }

    #[test]
    fn late_integer_width_refinement_preserves_semantic_float_result() {
        use crate::ir::types_recover::{TypeHint, TypeMap};

        let f = Function {
            name: "square".to_string(),
            entry_va: 0x1000,
            body: vec![Stmt::Return { value: None }],
        };
        let mut tm = TypeMap::default();
        tm.upsert_public(VReg::phys("ret"), TypeHint::Float { width: 4 });

        refine_decbench_abi_widths(&f, &mut tm);
        assert_eq!(
            tm.get(&VReg::phys("ret")),
            Some(TypeHint::Float { width: 4 })
        );

        let text = render_decbench_typed_with_output(
            &f,
            Some(&tm),
            Some(&tm),
            crate::ir::types_recover::RecoveredOutputKind::Direct,
        );
        assert!(
            text.contains("float square(void)"),
            "a bare machine return overrode the recovered prototype:\n{text}"
        );
    }

    #[test]
    fn a_wide_scalar_definition_widens_a_coalesced_local_declaration() {
        use crate::ir::types_recover::{TypeHint, TypeMap};

        let f = Function {
            name: "wide_carrier".to_string(),
            entry_va: 0x1000,
            body: vec![Stmt::Assign {
                dst: VReg::phys("var0"),
                src: Expr::Cast {
                    signed: true,
                    width: 8,
                    expr: Box::new(Expr::Reg(VReg::phys("arg0"))),
                },
            }],
        };
        let mut tm = TypeMap::default();
        tm.upsert_public(
            VReg::phys("var0"),
            TypeHint::Int {
                signed: true,
                width: 4,
            },
        );

        refine_decbench_abi_widths(&f, &mut tm);

        assert_eq!(
            tm.get(&VReg::phys("var0")),
            Some(TypeHint::Int {
                signed: true,
                width: 8,
            })
        );
    }

    #[test]
    fn a_narrow_definition_does_not_inherit_a_wide_source_register_hint() {
        use crate::ir::types_recover::{TypeHint, TypeMap};

        let f = Function {
            name: "narrow_scratch".to_string(),
            entry_va: 0x1000,
            body: vec![
                Stmt::Assign {
                    dst: VReg::phys("var1"),
                    src: Expr::Const(8),
                },
                Stmt::Assign {
                    dst: VReg::phys("var0"),
                    src: Expr::Bin {
                        op: BinOp::Sub,
                        lhs: Box::new(Expr::Reg(VReg::phys("var1"))),
                        rhs: Box::new(Expr::Const(1)),
                    },
                },
            ],
        };
        let mut tm = TypeMap::default();
        tm.upsert_public(
            VReg::phys("var0"),
            TypeHint::Int {
                signed: false,
                width: 4,
            },
        );
        tm.upsert_public(
            VReg::phys("var1"),
            TypeHint::Int {
                signed: false,
                width: 8,
            },
        );

        refine_decbench_abi_widths(&f, &mut tm);

        assert_eq!(
            tm.get(&VReg::phys("var0")),
            Some(TypeHint::Int {
                signed: false,
                width: 4,
            }),
            "the source's parent-register width must not leak through its exact narrow definition"
        );
    }

    #[test]
    fn a_loop_carrier_copied_from_a_wide_result_keeps_the_result_width() {
        use crate::ir::types_recover::{TypeHint, TypeMap};

        let f = Function {
            name: "factorial_carrier".to_string(),
            entry_va: 0x1000,
            body: vec![
                Stmt::Assign {
                    dst: VReg::phys("var1"),
                    src: Expr::Cast {
                        signed: false,
                        width: 8,
                        expr: Box::new(Expr::Cast {
                            signed: false,
                            width: 4,
                            expr: Box::new(Expr::Reg(VReg::phys("arg0"))),
                        }),
                    },
                },
                Stmt::Assign {
                    dst: VReg::phys("var2"),
                    src: Expr::Const(1),
                },
                Stmt::DoWhile {
                    body: vec![
                        Stmt::Assign {
                            dst: VReg::phys("ret"),
                            src: Expr::Bin {
                                op: BinOp::Mul,
                                lhs: Box::new(Expr::Reg(VReg::phys("var2"))),
                                rhs: Box::new(Expr::Reg(VReg::phys("var1"))),
                            },
                        },
                        Stmt::Assign {
                            dst: VReg::phys("var2"),
                            src: Expr::Reg(VReg::phys("ret")),
                        },
                    ],
                    cond: Expr::Const(0),
                },
                Stmt::Return {
                    value: Some(Expr::Reg(VReg::phys("ret"))),
                },
            ],
        };
        let mut tm = TypeMap::default();
        let mut value_widths = std::collections::HashMap::new();
        for (name, width) in [("var1", 8), ("var2", 4), ("ret", 8)] {
            tm.upsert_public(
                VReg::phys(name),
                TypeHint::Int {
                    signed: true,
                    width,
                },
            );
        }
        value_widths.insert("var1".to_string(), 8);
        value_widths.insert("var2".to_string(), 8);
        value_widths.insert("ret".to_string(), 8);

        refine_decbench_abi_widths_with_value_widths(&f, &mut tm, Some(&value_widths));

        assert_eq!(
            tm.get(&VReg::phys("var2")),
            Some(TypeHint::Int {
                signed: true,
                width: 8,
            })
        );
    }

    #[test]
    fn decbench_typed_emits_recovered_return_and_arg_types() {
        use crate::ir::types_recover::{TypeHint, TypeMap};
        // Same body as the signature test, but with a TypeMap keyed by the
        // AST's role names: arg0 is a 32-bit signed int, the return is too.
        let f = Function {
            name: "add_one".to_string(),
            entry_va: 0x1230,
            body: vec![
                Stmt::Assign {
                    dst: VReg::phys("var0"),
                    src: Expr::Bin {
                        op: BinOp::Add,
                        lhs: Box::new(Expr::Reg(VReg::phys("arg0"))),
                        rhs: Box::new(Expr::Const(1)),
                    },
                },
                Stmt::Return {
                    value: Some(Expr::Bin {
                        op: BinOp::Mul,
                        lhs: Box::new(Expr::Reg(VReg::phys("var0"))),
                        rhs: Box::new(Expr::Reg(VReg::phys("var0"))),
                    }),
                },
            ],
        };
        let mut tm = TypeMap::default();
        tm.upsert_public(
            VReg::phys("arg0"),
            TypeHint::Int {
                signed: true,
                width: 4,
            },
        );
        tm.upsert_public(
            VReg::phys("ret"),
            TypeHint::Int {
                signed: true,
                width: 4,
            },
        );
        let text = render_decbench_typed(&f, Some(&tm), None);
        assert!(
            text.contains("int add_one(int arg0) {"),
            "typed signature wrong:\n{}",
            text
        );
        // Locals still default to `long` (their keys don't survive renaming).
        assert!(text.contains("long var0;"), "missing local decl:\n{}", text);
        assert_looks_like_c(&text);

        // Without a TypeMap the untyped path stays blanket-`long`.
        let untyped = render_decbench(&f);
        assert!(
            untyped.contains("long add_one(long arg0) {"),
            "untyped fallback changed:\n{}",
            untyped
        );
    }

    #[test]
    fn absurd_argument_indices_are_not_treated_as_signature_arity() {
        assert_eq!(parse_arg_index("arg1023"), Some(1023));
        assert_eq!(parse_arg_index("arg1024"), None);
        assert_eq!(parse_arg_index("arg536870912"), None);
    }

    #[test]
    fn decbench_uses_the_conventional_two_argument_main_signature() {
        let f = Function {
            name: "main".to_string(),
            entry_va: 0x1000,
            body: vec![
                Stmt::Assign {
                    dst: VReg::phys("local_0"),
                    src: Expr::Reg(VReg::phys("arg1")),
                },
                Stmt::Return {
                    value: Some(Expr::Reg(VReg::phys("arg0"))),
                },
            ],
        };

        let text = render_decbench(&f);
        assert!(
            text.contains("int main(int argc, char ** argv) {"),
            "main signature was not recovered:\n{text}"
        );
        assert!(text.contains("argv"), "argv uses were not renamed:\n{text}");
        assert!(text.contains("argc"), "argc uses were not renamed:\n{text}");
        assert_looks_like_c(&text);
    }

    #[test]
    fn decbench_abi_widths_preserve_high_halves_of_packed_arguments() {
        use crate::ir::types_recover::{TypeHint, TypeMap};

        // Optimized SysV code for two-register by-value aggregates uses the high
        // halves of the incoming INTEGER-class eightbytes. Narrow sub-register
        // uses elsewhere must not make either parameter (or the wide result)
        // render as `int`.
        let mut f = Function {
            name: "packed".to_string(),
            entry_va: 0x1000,
            body: vec![
                Stmt::Assign {
                    dst: VReg::phys("var0"),
                    src: Expr::Bin {
                        op: BinOp::Shr,
                        lhs: Box::new(Expr::Reg(VReg::phys("arg0"))),
                        rhs: Box::new(Expr::Const(32)),
                    },
                },
                Stmt::Assign {
                    dst: VReg::phys("var1"),
                    src: Expr::Bin {
                        op: BinOp::And,
                        lhs: Box::new(Expr::Reg(VReg::phys("arg1"))),
                        rhs: Box::new(Expr::Const(-0x1_0000_0000)),
                    },
                },
                Stmt::Return {
                    value: Some(Expr::Bin {
                        op: BinOp::Add,
                        lhs: Box::new(Expr::Reg(VReg::phys("var0"))),
                        rhs: Box::new(Expr::Reg(VReg::phys("var1"))),
                    }),
                },
            ],
        };
        let mut tm = TypeMap::default();
        for name in ["arg0", "arg1", "ret"] {
            tm.upsert_public(
                VReg::phys(name),
                TypeHint::Int {
                    signed: true,
                    width: 4,
                },
            );
        }

        refine_decbench_abi_widths(&f, &mut tm);
        crate::ir::widen::insert_widening_casts(&mut f, &tm);
        let text = render_decbench_typed(&f, Some(&tm), Some(&tm));

        assert!(
            text.contains("long packed(long arg0, long arg1) {"),
            "high-half consumers require complete eightbyte parameters and return:\n{text}"
        );
        assert!(
            !text.contains("(unsigned int)(arg1)"),
            "the high mask must not truncate its operand before reading it:\n{text}"
        );
    }

    #[test]
    fn decbench_abi_widths_do_not_widen_an_ordinary_int_shift() {
        use crate::ir::types_recover::{TypeHint, TypeMap};

        let f = Function {
            name: "small_shift".to_string(),
            entry_va: 0x1000,
            body: vec![Stmt::Return {
                value: Some(Expr::Bin {
                    op: BinOp::Shr,
                    lhs: Box::new(Expr::Reg(VReg::phys("arg0"))),
                    rhs: Box::new(Expr::Const(3)),
                }),
            }],
        };
        let mut tm = TypeMap::default();
        for name in ["arg0", "ret"] {
            tm.upsert_public(
                VReg::phys(name),
                TypeHint::Int {
                    signed: true,
                    width: 4,
                },
            );
        }

        refine_decbench_abi_widths(&f, &mut tm);
        let text = render_decbench_typed(&f, Some(&tm), Some(&tm));
        assert!(
            text.contains("int small_shift(int arg0) {"),
            "a sub-word shift is not evidence of a packed 64-bit parameter:\n{text}"
        );
    }

    #[test]
    fn signed_destination_spells_an_all_ones_literal_as_minus_one() {
        use crate::ir::types_recover::{TypeHint, TypeMap};

        let result = VReg::phys("var0");
        let f = Function {
            name: "typed_literal".to_string(),
            entry_va: 0x1000,
            body: vec![
                Stmt::Assign {
                    dst: result.clone(),
                    src: Expr::Const(0xffff_ffff),
                },
                Stmt::Return {
                    value: Some(Expr::Reg(result.clone())),
                },
            ],
        };
        let mut tm = TypeMap::default();
        tm.upsert_public(
            result,
            TypeHint::Int {
                signed: true,
                width: 4,
            },
        );

        let text = render_decbench_typed(&f, Some(&tm), Some(&tm));

        assert!(text.contains("var0 = -1;"), "got:\n{text}");
        assert!(!text.contains("var0 = 0xffffffff;"), "got:\n{text}");
    }

    #[test]
    fn signed_destination_literal_spelling_preserves_every_narrow_bit_pattern() {
        for (ctype, width) in [("signed char", 1_u8), ("short", 2_u8)] {
            let modulus = 1_u64 << (u32::from(width) * 8);
            let sign_bit = modulus / 2;
            for raw in 0..modulus {
                let spelled = super::dec_render::signed_destination_literal(
                    ctype,
                    i64::try_from(raw).expect("8/16-bit pattern fits i64"),
                    8,
                )
                .unwrap_or_else(|| i64::try_from(raw).expect("8/16-bit pattern fits i64"));
                let recovered_bits = if spelled < 0 {
                    i128::from(spelled) + i128::from(modulus)
                } else {
                    i128::from(spelled)
                };
                assert_eq!(
                    recovered_bits,
                    i128::from(raw),
                    "{ctype} raw={raw:#x} spelled={spelled}"
                );
                assert_eq!(spelled < 0, raw >= sign_bit);
            }
        }

        let signed32_cases = [
            (0x7fff_ffff_i64, None),
            (0x8000_0000_i64, Some(i64::from(i32::MIN))),
            (0xffff_ffff_i64, Some(-1)),
            (0x1_0000_0000_i64, None),
        ];
        for (raw, expected) in signed32_cases {
            assert_eq!(
                super::dec_render::signed_destination_literal("int32_t", raw, 8),
                expected,
                "int32_t raw={raw:#x}"
            );
        }
        for unsigned in [
            "unsigned char",
            "unsigned short",
            "unsigned int",
            "uint32_t",
        ] {
            assert_eq!(
                super::dec_render::signed_destination_literal(unsigned, 0xffff_ffff, 8),
                None,
                "unsigned destination {unsigned} must retain its bit-pattern spelling"
            );
        }
        assert_eq!(
            super::dec_render::signed_destination_literal("int64_t", i64::MAX, 8),
            None,
            "every positive i64 already lies in int64_t's signed value domain"
        );
    }

    #[test]
    fn typed_renderer_spells_reversed_unsigned_subtract_as_an_explicit_range() {
        use crate::ir::types_recover::{TypeHint, TypeMap};

        let argument = VReg::phys("arg0");
        let f = Function {
            name: "range_guard".to_string(),
            entry_va: 0x1000,
            body: vec![Stmt::If {
                cond: Expr::Cmp {
                    op: CmpOp::Ult,
                    lhs: Box::new(Expr::Const(15)),
                    rhs: Box::new(Expr::Bin {
                        op: BinOp::Add,
                        lhs: Box::new(Expr::Reg(argument.clone())),
                        rhs: Box::new(Expr::Const(-1)),
                    }),
                },
                then_body: vec![Stmt::Return {
                    value: Some(Expr::Const(-1)),
                }],
                else_body: None,
            }],
        };
        let mut types = TypeMap::default();
        types.upsert_public(
            argument,
            TypeHint::Int {
                signed: true,
                width: 4,
            },
        );

        let text = render_decbench_typed(&f, Some(&types), Some(&types));

        assert!(
            text.contains("(unsigned int)(arg0) < 1 || 16 < (unsigned int)(arg0)"),
            "got:\n{text}"
        );
        assert!(!text.contains("arg0 - 1"), "got:\n{text}");
    }

    #[test]
    fn decbench_abi_refines_a_stale_pointer_from_its_only_access_width() {
        use crate::ir::types_recover::{TypeHint, TypeMap};

        let f = Function {
            name: "byte_at".to_string(),
            entry_va: 0x1000,
            body: vec![Stmt::Return {
                value: Some(Expr::Deref {
                    addr: Box::new(Expr::Lea {
                        base: Some(VReg::phys("arg0")),
                        index: Some(VReg::phys("arg1")),
                        scale: 1,
                        disp: 0,
                        segment: None,
                    }),
                    size: 1,
                }),
            }],
        };
        let mut tm = TypeMap::default();
        tm.upsert_public(VReg::phys("arg0"), TypeHint::Pointer { pointee_width: 4 });
        tm.upsert_public(
            VReg::phys("arg1"),
            TypeHint::Int {
                signed: true,
                width: 4,
            },
        );

        refine_decbench_abi_widths(&f, &mut tm);

        assert_eq!(
            tm.get(&VReg::phys("arg0")),
            Some(TypeHint::Pointer { pointee_width: 1 }),
            "the prepared AST's sole byte access is stronger than stale register reuse"
        );
    }

    #[test]
    fn decbench_pointer_refinement_does_not_treat_local_assignment_as_a_deref() {
        use crate::ir::types_recover::{TypeHint, TypeMap};

        let local = VReg::phys("local_pointer");
        let f = Function {
            name: "local_byte".to_string(),
            entry_va: 0x1000,
            body: vec![
                Stmt::Store {
                    addr: Expr::Reg(local.clone()),
                    src: Expr::Reg(VReg::phys("arg0")),
                    size: 8,
                },
                Stmt::Return {
                    value: Some(Expr::Deref {
                        addr: Box::new(Expr::Lea {
                            base: Some(local.clone()),
                            index: Some(VReg::phys("arg1")),
                            scale: 1,
                            disp: 0,
                            segment: None,
                        }),
                        size: 1,
                    }),
                },
            ],
        };
        let mut tm = TypeMap::default();
        tm.upsert_public(local.clone(), TypeHint::Pointer { pointee_width: 4 });

        refine_decbench_abi_widths(&f, &mut tm);

        assert_eq!(
            tm.get(&local),
            Some(TypeHint::Pointer { pointee_width: 1 }),
            "the scalar assignment width must not conflict with the real byte dereference"
        );
    }

    #[test]
    fn decbench_uses_declared_integer_promotions_and_array_index_conversion() {
        use crate::ir::types_recover::{TypeHint, TypeMap};

        let byte = VReg::phys("local_byte");
        let index = VReg::phys("local_i");
        let f = Function {
            name: "typed_reads".to_string(),
            entry_va: 0x1000,
            body: vec![Stmt::Return {
                value: Some(Expr::Bin {
                    op: BinOp::Add,
                    lhs: Box::new(Expr::Cmp {
                        op: CmpOp::Eq,
                        lhs: Box::new(Expr::Cast {
                            signed: true,
                            width: 4,
                            expr: Box::new(Expr::Cast {
                                signed: true,
                                width: 1,
                                expr: Box::new(Expr::Reg(byte.clone())),
                            }),
                        }),
                        rhs: Box::new(Expr::Const(97)),
                    }),
                    rhs: Box::new(Expr::Deref {
                        addr: Box::new(Expr::Bin {
                            op: BinOp::Add,
                            lhs: Box::new(Expr::Reg(VReg::phys("arg0"))),
                            rhs: Box::new(Expr::Cast {
                                signed: true,
                                width: 8,
                                expr: Box::new(Expr::Cast {
                                    signed: true,
                                    width: 4,
                                    expr: Box::new(Expr::Reg(index.clone())),
                                }),
                            }),
                        }),
                        size: 1,
                    }),
                }),
            }],
        };
        let mut tm = TypeMap::default();
        tm.upsert_public(VReg::phys("arg0"), TypeHint::Pointer { pointee_width: 1 });
        tm.upsert_public(
            byte,
            TypeHint::Int {
                signed: true,
                width: 1,
            },
        );
        tm.upsert_public(
            index,
            TypeHint::Int {
                signed: true,
                width: 4,
            },
        );

        let text = render_decbench_typed(&f, Some(&tm), Some(&tm));

        assert!(
            text.contains("local_byte == 97"),
            "integer promotion:\n{text}"
        );
        assert!(
            text.contains("arg0[local_i]"),
            "pointer index conversion:\n{text}"
        );
        assert!(
            !text.contains("(signed char)(local_byte)"),
            "redundant cast:\n{text}"
        );
    }

    #[test]
    fn decbench_abi_widths_keep_x86_zero_extended_int_return_narrow() {
        use crate::ir::types_recover::{TypeHint, TypeMap};

        let f = Function {
            name: "area".to_string(),
            entry_va: 0x1000,
            body: vec![Stmt::Return {
                value: Some(Expr::Cast {
                    signed: false,
                    width: 8,
                    expr: Box::new(Expr::Cast {
                        signed: false,
                        width: 4,
                        expr: Box::new(Expr::Bin {
                            op: BinOp::Mul,
                            lhs: Box::new(Expr::Reg(VReg::phys("arg0"))),
                            rhs: Box::new(Expr::Reg(VReg::phys("arg1"))),
                        }),
                    }),
                }),
            }],
        };
        let mut tm = TypeMap::default();
        for name in ["arg0", "arg1", "ret"] {
            tm.upsert_public(
                VReg::phys(name),
                TypeHint::Int {
                    signed: true,
                    width: 4,
                },
            );
        }

        refine_decbench_abi_widths(&f, &mut tm);
        let text = render_decbench_typed(&f, Some(&tm), Some(&tm));
        assert!(
            text.contains("int area(int arg0, int arg1) {"),
            "zero-extension into rax is not evidence of a C long return:\n{text}"
        );
    }

    #[test]
    fn decbench_abi_zero_extension_return_uses_the_inner_typed_value() {
        use crate::ir::types_recover::{TypeHint, TypeMap};

        // `mov eax, local_4` is represented losslessly as a 32-to-64-bit zero
        // extension. The reused physical return register previously held an
        // address, but that stale pointer hint cannot outrank the typed value
        // that is actually returned.
        let f = Function {
            name: "str_len".to_string(),
            entry_va: 0x1000,
            body: vec![Stmt::Return {
                value: Some(Expr::Cast {
                    signed: false,
                    width: 8,
                    expr: Box::new(Expr::Cast {
                        signed: false,
                        width: 4,
                        expr: Box::new(Expr::Reg(VReg::phys("local_4"))),
                    }),
                }),
            }],
        };
        let mut tm = TypeMap::default();
        tm.upsert_public(
            VReg::phys("local_4"),
            TypeHint::Int {
                signed: true,
                width: 4,
            },
        );
        tm.upsert_public(VReg::phys("ret"), TypeHint::Pointer { pointee_width: 1 });

        let text = render_decbench_typed(&f, Some(&tm), Some(&tm));

        assert!(
            text.contains("int str_len(") && !text.contains("char * str_len("),
            "the returned int value must outrank stale physical-register uses:\n{text}"
        );
    }

    #[test]
    fn typed_return_conversion_removes_only_the_abi_zero_extension() {
        use crate::ir::types_recover::{TypeHint, TypeMap};

        let mut f = Function {
            name: "str_len".to_string(),
            entry_va: 0x1000,
            body: vec![Stmt::Return {
                value: Some(Expr::Cast {
                    signed: false,
                    width: 8,
                    expr: Box::new(Expr::Cast {
                        signed: false,
                        width: 4,
                        expr: Box::new(Expr::Reg(VReg::phys("local_4"))),
                    }),
                }),
            }],
        };
        let mut tm = TypeMap::default();
        tm.upsert_public(
            VReg::phys("local_4"),
            TypeHint::Int {
                signed: true,
                width: 4,
            },
        );
        tm.upsert_public(
            VReg::phys("ret"),
            TypeHint::Int {
                signed: true,
                width: 4,
            },
        );

        fold_typed_return_abi_extensions(&mut f, &tm);

        assert_eq!(
            f.body,
            vec![Stmt::Return {
                value: Some(Expr::Cast {
                    signed: false,
                    width: 4,
                    expr: Box::new(Expr::Reg(VReg::phys("local_4"))),
                }),
            }],
            "only the ABI-wide wrapper is redundant; the source-width cast remains"
        );
    }

    #[test]
    fn typed_return_conversion_preserves_an_explicit_wide_cast() {
        use crate::ir::types_recover::{TypeHint, TypeMap};

        let mut f = Function {
            name: "widen".to_string(),
            entry_va: 0x1000,
            body: vec![Stmt::Return {
                value: Some(Expr::Cast {
                    signed: false,
                    width: 8,
                    expr: Box::new(Expr::Reg(VReg::phys("arg0"))),
                }),
            }],
        };
        let expected = f.clone();
        let mut tm = TypeMap::default();
        tm.upsert_public(
            VReg::phys("ret"),
            TypeHint::Int {
                signed: false,
                width: 8,
            },
        );

        fold_typed_return_abi_extensions(&mut f, &tm);

        assert_eq!(
            f, expected,
            "a source-level 64-bit cast must remain explicit"
        );
    }

    #[test]
    fn decbench_return_type_comes_from_returned_value_not_bare_ret() {
        // Value-keyed return typing: the returned value is a promoted local
        // (`local_8`, an `int`) and there is *no* `ret` entry in the type map.
        // The signature return type must come from `local_8`, not silently
        // default to `long` because the bare `ret` name is untyped.
        let f = Function {
            name: "get".to_string(),
            entry_va: 0x1000,
            body: vec![Stmt::Return {
                value: Some(Expr::Reg(VReg::phys("local_8"))),
            }],
        };
        let mut tm = TypeMap::default();
        tm.upsert_public(
            VReg::phys("local_8"),
            TypeHint::Int {
                signed: true,
                width: 4,
            },
        );
        let text = render_decbench_typed(&f, Some(&tm), None);
        assert!(
            text.contains("int get(") && text.contains("return local_8;"),
            "return type should be `int` from the returned local, got:\n{}",
            text
        );
    }

    #[test]
    fn promoted_pointer_slot_store_uses_the_declared_local_as_an_lvalue() {
        use crate::debug::dwarf::{DwarfField, DwarfType, DwarfTypeKind};
        use crate::ir::types_recover::RecoveredOutputKind;

        let local = VReg::phys("local_8");
        let f = Function {
            name: "pointer_result".to_string(),
            entry_va: 0x1000,
            body: vec![
                Stmt::Store {
                    addr: Expr::Reg(local.clone()),
                    src: Expr::Reg(VReg::phys("arg0")),
                    size: 8,
                },
                Stmt::Return {
                    value: Some(Expr::Reg(local.clone())),
                },
            ],
        };
        let prototype = CallPrototype {
            return_type: "struct node *".to_string(),
            parameter_types: vec!["struct node *".to_string()],
            variadic: false,
            authority: CallPrototypeAuthority::Authoritative,
        };
        let layout = DwarfType {
            kind: DwarfTypeKind::Struct,
            name: "node".to_string(),
            byte_size: 8,
            fields: vec![DwarfField {
                offset: 0,
                name: "next".to_string(),
                c_type: "struct node *".to_string(),
                size: 8,
            }],
            variants: Vec::new(),
            typedef_target: None,
            source_file: Some("linkedlist.c".to_string()),
        };
        let pointer_types = std::collections::HashMap::from([
            (VReg::phys("arg0"), "node".to_string()),
            (local, "node".to_string()),
        ]);

        let text = render_decbench_typed_with_output_and_prototype_and_dwarf_types(
            &f,
            None,
            None,
            RecoveredOutputKind::Direct,
            Some(&prototype),
            &[layout],
            8,
            &pointer_types,
        );

        assert!(text.contains("local_8 = arg0;"), "{text}");
        assert!(!text.contains("(long)local_8 ="), "{text}");
    }

    #[test]
    fn dwarf_local_pointer_keeps_its_source_name_and_typedef() {
        use crate::debug::dwarf::{DwarfType, DwarfTypeKind};
        use crate::ir::types_recover::{RecoveredOutputKind, TypeHint, TypeMap};

        let f = Function {
            name: "balance".to_string(),
            entry_va: 0x1000,
            body: vec![
                Stmt::Store {
                    addr: Expr::Reg(VReg::phys("p")),
                    src: Expr::Reg(VReg::phys("arg0")),
                    size: 8,
                },
                Stmt::Return { value: None },
            ],
        };
        let types = [DwarfType {
            kind: DwarfTypeKind::Typedef,
            name: "COLUMN".to_string(),
            byte_size: 0,
            fields: Vec::new(),
            variants: Vec::new(),
            typedef_target: Some("struct column".to_string()),
            source_file: Some("balance.c".to_string()),
        }];
        let mut tm = TypeMap::default();
        tm.upsert_public(VReg::phys("p"), TypeHint::Pointer { pointee_width: 1 });

        let text = render_decbench_typed_with_output_and_prototype_and_dwarf_types_and_local_types(
            &f,
            Some(&tm),
            Some(&tm),
            RecoveredOutputKind::Void,
            None,
            &types,
            8,
            &std::collections::HashMap::new(),
            &std::collections::HashMap::from([("p".to_string(), "COLUMN *".to_string())]),
        );

        assert!(text.contains("typedef struct column COLUMN;"), "{text}");
        assert!(text.contains("COLUMN * p;"), "{text}");
        assert!(text.contains("p = (COLUMN *)(arg0);"), "{text}");
        assert!(!text.contains("*(long *)((long)p) ="), "{text}");
    }

    #[test]
    fn dwarf_local_pointer_arithmetic_keeps_machine_byte_offsets() {
        use crate::ir::types_recover::{RecoveredOutputKind, TypeHint, TypeMap};

        let f = Function {
            name: "advance".to_string(),
            entry_va: 0x1000,
            body: vec![
                Stmt::Assign {
                    dst: VReg::phys("p"),
                    src: Expr::Bin {
                        op: BinOp::Add,
                        lhs: Box::new(Expr::Reg(VReg::phys("p"))),
                        rhs: Box::new(Expr::Const(8)),
                    },
                },
                Stmt::Return { value: None },
            ],
        };
        let mut tm = TypeMap::default();
        tm.upsert_public(VReg::phys("p"), TypeHint::Pointer { pointee_width: 8 });

        let text = render_decbench_typed_with_output_and_prototype_and_dwarf_types_and_local_types(
            &f,
            Some(&tm),
            Some(&tm),
            RecoveredOutputKind::Void,
            None,
            &[],
            8,
            &std::collections::HashMap::new(),
            &std::collections::HashMap::from([("p".to_string(), "long *".to_string())]),
        );

        assert!(
            text.contains("p = (long *)(p + 1);") || text.contains("p = (long *)((p + 1));"),
            "an exact pointee width must scale the machine byte displacement:\n{text}"
        );
        assert!(!text.contains("p = (long *)(p + 8);"), "{text}");
    }

    #[test]
    fn declared_local_pointer_width_overrides_machine_carrier_width() {
        use crate::ir::types_recover::{RecoveredOutputKind, TypeHint, TypeMap};

        let pointer_result = CallPrototype {
            return_type: "int *".to_string(),
            parameter_types: Vec::new(),
            variadic: false,
            authority: CallPrototypeAuthority::Recovered,
        };
        let f = Function {
            name: "step_back".to_string(),
            entry_va: 0x1000,
            body: vec![
                Stmt::Call {
                    target: Expr::Named {
                        va: 0x2000,
                        name: "make_p".to_string(),
                    },
                    args: Vec::new(),
                    dst: Some(VReg::phys("p")),
                    call_spec: Some(CallSiteSpec {
                        callee_prototype: None,
                        call_prototype: pointer_result.clone(),
                    }),
                },
                Stmt::Call {
                    target: Expr::Named {
                        va: 0x2010,
                        name: "make_q".to_string(),
                    },
                    args: Vec::new(),
                    dst: Some(VReg::phys("q")),
                    call_spec: Some(CallSiteSpec {
                        callee_prototype: None,
                        call_prototype: pointer_result,
                    }),
                },
                Stmt::Assign {
                    dst: VReg::phys("p"),
                    src: Expr::Lea {
                        base: Some(VReg::phys("p")),
                        index: None,
                        scale: 1,
                        disp: -4,
                        segment: None,
                    },
                },
                Stmt::Assign {
                    dst: VReg::phys("q"),
                    src: Expr::Lea {
                        base: Some(VReg::phys("q")),
                        index: None,
                        scale: 1,
                        disp: -2,
                        segment: None,
                    },
                },
            ],
        };
        let mut type_map = TypeMap::default();
        // The recovered pointer fact describes the eight-byte machine carrier;
        // the stronger local declaration describes four-byte C elements.
        type_map.upsert_public(VReg::phys("p"), TypeHint::Pointer { pointee_width: 8 });
        type_map.upsert_public(VReg::phys("q"), TypeHint::Pointer { pointee_width: 8 });

        let text = render_decbench_typed_with_output_and_prototype_and_dwarf_types_and_local_types(
            &f,
            Some(&type_map),
            Some(&type_map),
            RecoveredOutputKind::Void,
            None,
            &[],
            8,
            &std::collections::HashMap::new(),
            &std::collections::HashMap::new(),
        );

        assert!(
            text.contains("p = (int *)(p - 1);") || text.contains("p = (int *)((p - 1));"),
            "the emitted int-pointer declaration must scale a four-byte displacement:\n{text}"
        );
        assert!(
            text.contains("(long)q - 0x2"),
            "a non-integral element displacement must remain byte arithmetic:\n{text}"
        );
        assert!(!text.contains("q - 2);"), "{text}");
    }

    #[test]
    fn nested_scaled_pointer_offset_returns_to_byte_arithmetic() {
        use crate::ir::types_recover::{RecoveredOutputKind, TypeHint, TypeMap};

        let f = Function {
            name: "indexed_after_advance".to_string(),
            entry_va: 0x1000,
            body: vec![Stmt::Assign {
                dst: VReg::phys("result"),
                src: Expr::Bin {
                    op: BinOp::Add,
                    lhs: Box::new(Expr::Bin {
                        op: BinOp::Add,
                        lhs: Box::new(Expr::Reg(VReg::phys("p"))),
                        rhs: Box::new(Expr::Const(8)),
                    }),
                    rhs: Box::new(Expr::Bin {
                        op: BinOp::Mul,
                        lhs: Box::new(Expr::Reg(VReg::phys("i"))),
                        rhs: Box::new(Expr::Const(8)),
                    }),
                },
            }],
        };
        let mut tm = TypeMap::default();
        tm.upsert_public(VReg::phys("p"), TypeHint::Pointer { pointee_width: 8 });

        let text = render_decbench_typed_with_output_and_prototype_and_dwarf_types_and_local_types(
            &f,
            Some(&tm),
            Some(&tm),
            RecoveredOutputKind::Void,
            None,
            &[],
            8,
            &std::collections::HashMap::new(),
            &std::collections::HashMap::from([("p".to_string(), "long *".to_string())]),
        );

        assert!(
            text.contains("(long)(p + 1)") || text.contains("(long)((p + 1))"),
            "a scaled pointer subexpression must return to a byte address before \
             the enclosing machine addition:\n{text}"
        );
        assert!(!text.contains("((p + 1) + (i * 8))"), "{text}");
    }

    #[test]
    fn authoritative_local_is_not_coalesced_with_its_initializer_parameter() {
        let f = Function {
            name: "mutable_copy".to_string(),
            entry_va: 0x1000,
            body: vec![
                Stmt::Store {
                    addr: Expr::Reg(VReg::phys("local_4")),
                    src: Expr::Reg(VReg::phys("arg0")),
                    size: 4,
                },
                Stmt::Store {
                    addr: Expr::Reg(VReg::phys("local_4")),
                    src: Expr::Const(0),
                    size: 4,
                },
                Stmt::Return {
                    value: Some(Expr::Reg(VReg::phys("arg0"))),
                },
            ],
        };
        let protected = std::collections::HashSet::from(["local_4".to_string()]);

        let prepared = prepare_for_decbench_with_output_and_protected_locals(
            &f,
            crate::ir::types_recover::RecoveredOutputKind::Direct,
            &protected,
            8,
        );
        let text = render(&prepared);

        assert!(text.contains("local_4"), "{text}");
        assert!(text.contains("return %arg0"), "{text}");
        assert!(!text.contains("%arg0 = 0"), "{text}");
    }

    #[test]
    fn parameter_home_exposed_by_folding_is_coalesced_after_copy_fixpoint() {
        let f = Function {
            name: "narrow_spill".to_string(),
            entry_va: 0x1000,
            body: vec![
                Stmt::Assign {
                    dst: VReg::phys("var1"),
                    src: Expr::Bin {
                        op: BinOp::Or,
                        lhs: Box::new(Expr::Reg(VReg::phys("arg1"))),
                        rhs: Box::new(Expr::Const(0)),
                    },
                },
                Stmt::Store {
                    addr: Expr::Reg(VReg::phys("local_5")),
                    src: Expr::Reg(VReg::phys("var1")),
                    size: 1,
                },
                Stmt::Return {
                    value: Some(Expr::Reg(VReg::phys("local_5"))),
                },
            ],
        };

        let prepared = prepare_for_decbench_with_output(
            &f,
            crate::ir::types_recover::RecoveredOutputKind::Direct,
        );
        let text = render(&prepared);

        assert!(!text.contains("local_5"), "{text}");
        assert!(text.contains("return %arg1"), "{text}");
    }

    #[test]
    fn source_local_declarations_follow_semantic_first_use_not_renamed_spelling() {
        let f = Function {
            name: "ordered_locals".to_string(),
            entry_va: 0x1000,
            body: vec![
                Stmt::Assign {
                    dst: VReg::phys("s"),
                    src: Expr::Const(0),
                },
                Stmt::For {
                    init: Box::new(Stmt::Assign {
                        dst: VReg::phys("i"),
                        src: Expr::Const(0),
                    }),
                    cond: Expr::Cmp {
                        op: CmpOp::Slt,
                        lhs: Box::new(Expr::Reg(VReg::phys("i"))),
                        rhs: Box::new(Expr::Const(4)),
                    },
                    step: Box::new(Stmt::Assign {
                        dst: VReg::phys("i"),
                        src: Expr::Bin {
                            op: BinOp::Add,
                            lhs: Box::new(Expr::Reg(VReg::phys("i"))),
                            rhs: Box::new(Expr::Const(1)),
                        },
                    }),
                    body: vec![Stmt::Assign {
                        dst: VReg::phys("s"),
                        src: Expr::Bin {
                            op: BinOp::Add,
                            lhs: Box::new(Expr::Reg(VReg::phys("s"))),
                            rhs: Box::new(Expr::Reg(VReg::phys("i"))),
                        },
                    }],
                },
                Stmt::Return {
                    value: Some(Expr::Reg(VReg::phys("s"))),
                },
            ],
        };
        let local_types = std::collections::HashMap::from([
            ("i".to_string(), "int".to_string()),
            ("s".to_string(), "int".to_string()),
        ]);

        let text = render_decbench_typed_with_output_and_prototype_and_dwarf_types_and_local_types(
            &f,
            None,
            None,
            crate::ir::types_recover::RecoveredOutputKind::Direct,
            None,
            &[],
            8,
            &std::collections::HashMap::new(),
            &local_types,
        );

        let sum = text.find("long s;").expect("sum declaration");
        let index = text.find("long i;").expect("index declaration");
        assert!(
            sum < index,
            "the first-defined stack object must stay first:\n{text}"
        );
    }

    #[test]
    fn authoritative_integer_local_keeps_unit_step_syntax() {
        use crate::ir::types_recover::RecoveredOutputKind;

        let i = VReg::phys("i");
        let f = Function {
            name: "count".to_string(),
            entry_va: 0x1000,
            body: vec![Stmt::For {
                init: Box::new(Stmt::Assign {
                    dst: i.clone(),
                    src: Expr::Const(0),
                }),
                cond: Expr::Cmp {
                    op: CmpOp::Slt,
                    lhs: Box::new(Expr::Reg(i.clone())),
                    rhs: Box::new(Expr::Const(3)),
                },
                step: Box::new(Stmt::Assign {
                    dst: i.clone(),
                    src: Expr::Cast {
                        signed: false,
                        width: 4,
                        expr: Box::new(Expr::Bin {
                            op: BinOp::Add,
                            lhs: Box::new(Expr::Reg(i)),
                            rhs: Box::new(Expr::Const(1)),
                        }),
                    },
                }),
                body: Vec::new(),
            }],
        };

        let text = render_decbench_typed_with_output_and_prototype_and_dwarf_types_and_local_types(
            &f,
            None,
            None,
            RecoveredOutputKind::Void,
            None,
            &[],
            8,
            &std::collections::HashMap::new(),
            &std::collections::HashMap::from([("i".to_string(), "int".to_string())]),
        );

        assert!(text.contains("; i++)"), "{text}");
    }

    #[test]
    fn opaque_aggregate_pointer_does_not_guess_c_pointee_scaling() {
        use crate::debug::dwarf::{DwarfType, DwarfTypeKind};
        use crate::ir::types_recover::{RecoveredOutputKind, TypeHint, TypeMap};

        let f = Function {
            name: "advance_column".to_string(),
            entry_va: 0x1000,
            body: vec![Stmt::Assign {
                dst: VReg::phys("p"),
                src: Expr::Bin {
                    op: BinOp::Add,
                    lhs: Box::new(Expr::Reg(VReg::phys("p"))),
                    rhs: Box::new(Expr::Const(8)),
                },
            }],
        };
        let types = [DwarfType {
            kind: DwarfTypeKind::Typedef,
            name: "COLUMN".to_string(),
            byte_size: 0,
            fields: Vec::new(),
            variants: Vec::new(),
            typedef_target: Some("struct column".to_string()),
            source_file: Some("column.c".to_string()),
        }];
        let mut tm = TypeMap::default();
        tm.upsert_public(VReg::phys("p"), TypeHint::Pointer { pointee_width: 1 });

        let text = render_decbench_typed_with_output_and_prototype_and_dwarf_types_and_local_types(
            &f,
            Some(&tm),
            Some(&tm),
            RecoveredOutputKind::Void,
            None,
            &types,
            8,
            &std::collections::HashMap::new(),
            &std::collections::HashMap::from([("p".to_string(), "COLUMN *".to_string())]),
        );

        assert!(
            text.contains("(long)p + 8"),
            "an opaque aggregate must keep byte arithmetic until its size is known:\n{text}"
        );
        assert!(!text.contains("((p + 8))"), "{text}");
    }

    #[test]
    fn aggregate_local_name_may_shadow_alias_without_breaking_casts() {
        use crate::debug::dwarf::{DwarfType, DwarfTypeKind};
        use crate::ir::types_recover::{RecoveredOutputKind, TypeHint, TypeMap};

        let f = Function {
            name: "lookup_user".to_string(),
            entry_va: 0x1000,
            body: vec![Stmt::Assign {
                dst: VReg::phys("passwd"),
                src: Expr::Reg(VReg::phys("arg0")),
            }],
        };
        let types = [DwarfType {
            kind: DwarfTypeKind::Struct,
            name: "passwd".to_string(),
            byte_size: 0,
            fields: Vec::new(),
            variants: Vec::new(),
            typedef_target: None,
            source_file: Some("pwd.h".to_string()),
        }];
        let mut tm = TypeMap::default();
        tm.upsert_public(VReg::phys("passwd"), TypeHint::Pointer { pointee_width: 1 });

        let text = render_decbench_typed_with_output_and_prototype_and_dwarf_types_and_local_types(
            &f,
            Some(&tm),
            Some(&tm),
            RecoveredOutputKind::Void,
            None,
            &types,
            8,
            &std::collections::HashMap::new(),
            &std::collections::HashMap::from([(
                "passwd".to_string(),
                "struct passwd *".to_string(),
            )]),
        );

        assert!(text.contains("struct passwd * passwd;"), "{text}");
        assert!(text.contains("passwd = (struct passwd *)(arg0);"), "{text}");
        assert_looks_like_c(&text);
    }

    #[test]
    fn optimized_away_dwarf_local_keeps_its_source_declaration() {
        use crate::ir::types_recover::{RecoveredOutputKind, TypeHint, TypeMap};

        let f = Function {
            name: "wait".to_string(),
            entry_va: 0x1000,
            body: vec![Stmt::Return { value: None }],
        };
        let mut tm = TypeMap::default();
        tm.apply_locked_fact(
            VReg::phys("i"),
            TypeHint::Int {
                signed: false,
                width: 4,
            },
        );

        let text = render_decbench_typed_with_output_and_prototype_and_dwarf_types_and_local_types(
            &f,
            Some(&tm),
            Some(&tm),
            RecoveredOutputKind::Void,
            None,
            &[],
            4,
            &std::collections::HashMap::new(),
            &std::collections::HashMap::from([("i".to_string(), "unsigned int".to_string())]),
        );

        assert!(text.contains("    unsigned int i;"), "{text}");
    }

    #[test]
    fn opaque_tagged_parameter_uses_a_self_contained_typedef_alias() {
        use crate::debug::dwarf::{DwarfField, DwarfType, DwarfTypeKind};
        use crate::ir::types_recover::RecoveredOutputKind;

        let f = Function {
            name: "consume".to_string(),
            entry_va: 0x1000,
            body: vec![
                Stmt::Assign {
                    dst: VReg::phys("var0"),
                    src: Expr::Reg(VReg::phys("arg0")),
                },
                Stmt::Return { value: None },
            ],
        };
        let prototype = CallPrototype {
            return_type: "void".to_string(),
            parameter_types: vec!["struct record *".to_string()],
            variadic: false,
            authority: CallPrototypeAuthority::Authoritative,
        };
        // A named layout makes the prototype authoritative, but the ABI-
        // dependent `long` field intentionally prevents emitting a guessed
        // complete definition. The tagged pointer still needs standalone C.
        let layout = DwarfType {
            kind: DwarfTypeKind::Struct,
            name: "record".to_string(),
            byte_size: 8,
            fields: vec![DwarfField {
                offset: 0,
                name: "value".to_string(),
                c_type: "long".to_string(),
                size: 8,
            }],
            variants: Vec::new(),
            typedef_target: None,
            source_file: Some("record.c".to_string()),
        };

        let text = render_decbench_typed_with_output_and_prototype_and_dwarf_types(
            &f,
            None,
            None,
            RecoveredOutputKind::Void,
            Some(&prototype),
            &[layout],
            8,
            &std::collections::HashMap::new(),
        );

        assert!(text.contains("typedef struct record record;"), "{text}");
        assert!(text.contains("void consume(record * arg0)"), "{text}");
        assert!(
            !text.contains("void consume(struct record * arg0)"),
            "{text}"
        );
    }

    #[test]
    fn aggregate_typedef_parameter_resolves_through_its_tagged_layout() {
        use crate::debug::dwarf::{DwarfField, DwarfType, DwarfTypeKind};
        use crate::ir::types_recover::RecoveredOutputKind;

        let f = Function {
            name: "initialise".to_string(),
            entry_va: 0x1000,
            body: vec![
                Stmt::Assign {
                    dst: VReg::phys("var0"),
                    src: Expr::Reg(VReg::phys("arg0")),
                },
                Stmt::Return { value: None },
            ],
        };
        let prototype = CallPrototype {
            return_type: "void".to_string(),
            parameter_types: vec!["List_t *const".to_string()],
            variadic: false,
            authority: CallPrototypeAuthority::Authoritative,
        };
        let types = vec![
            DwarfType {
                kind: DwarfTypeKind::Typedef,
                name: "List_t".to_string(),
                byte_size: 0,
                fields: Vec::new(),
                variants: Vec::new(),
                typedef_target: Some("struct xLIST".to_string()),
                source_file: Some("list.h".to_string()),
            },
            DwarfType {
                kind: DwarfTypeKind::Struct,
                name: "xLIST".to_string(),
                byte_size: 4,
                // Keep the layout intentionally opaque: an unsupported nested
                // typedef must not prevent using the authoritative pointer
                // contract or cause the renderer to invent a field layout.
                fields: vec![DwarfField {
                    offset: 0,
                    name: "item".to_string(),
                    c_type: "OpaqueItem_t".to_string(),
                    size: 4,
                }],
                variants: Vec::new(),
                typedef_target: None,
                source_file: Some("list.h".to_string()),
            },
        ];

        let text = render_decbench_typed_with_output_and_prototype_and_dwarf_types(
            &f,
            None,
            None,
            RecoveredOutputKind::Void,
            Some(&prototype),
            &types,
            4,
            &std::collections::HashMap::new(),
        );

        assert!(text.contains("typedef struct xLIST List_t;"), "{text}");
        assert!(
            text.contains("void initialise(List_t * const arg0)"),
            "{text}"
        );
        assert!(!text.contains("struct xLIST {"), "{text}");
    }

    #[test]
    fn aggregate_parameter_copy_to_different_pointer_type_is_explicit() {
        use crate::debug::dwarf::{DwarfType, DwarfTypeKind};
        use crate::ir::types_recover::{RecoveredOutputKind, TypeHint, TypeMap};

        let f = Function {
            name: "consume".to_string(),
            entry_va: 0x1000,
            body: vec![
                Stmt::Assign {
                    dst: VReg::phys("var0"),
                    src: Expr::Reg(VReg::phys("arg0")),
                },
                Stmt::Return { value: None },
            ],
        };
        let prototype = CallPrototype {
            return_type: "void".to_string(),
            parameter_types: vec!["Record_t *".to_string()],
            variadic: false,
            authority: CallPrototypeAuthority::Authoritative,
        };
        let types = [DwarfType {
            kind: DwarfTypeKind::Typedef,
            name: "Record_t".to_string(),
            byte_size: 0,
            fields: Vec::new(),
            variants: Vec::new(),
            typedef_target: Some("struct record".to_string()),
            source_file: Some("record.h".to_string()),
        }];
        let mut tm = TypeMap::default();
        tm.upsert_public(VReg::phys("var0"), TypeHint::Pointer { pointee_width: 1 });

        let text = render_decbench_typed_with_output_and_prototype_and_dwarf_types(
            &f,
            Some(&tm),
            Some(&tm),
            RecoveredOutputKind::Void,
            Some(&prototype),
            &types,
            8,
            &std::collections::HashMap::new(),
        );

        assert!(text.contains("var0 = (char *)arg0;"), "{text}");
    }

    #[test]
    fn by_value_aggregate_parameter_is_read_through_its_machine_carrier() {
        use crate::debug::dwarf::{DwarfField, DwarfType, DwarfTypeKind};
        use crate::ir::types_recover::RecoveredOutputKind;

        let function = Function {
            name: "consume_pair".to_string(),
            entry_va: 0x1000,
            body: vec![Stmt::Return {
                value: Some(Expr::Bin {
                    op: BinOp::Add,
                    lhs: Box::new(Expr::Reg(VReg::phys("arg0"))),
                    rhs: Box::new(Expr::Bin {
                        op: BinOp::Shr,
                        lhs: Box::new(Expr::Reg(VReg::phys("arg0"))),
                        rhs: Box::new(Expr::Const(32)),
                    }),
                }),
            }],
        };
        let prototype = CallPrototype {
            return_type: "int".to_string(),
            parameter_types: vec!["struct pair".to_string()],
            variadic: false,
            authority: CallPrototypeAuthority::Authoritative,
        };
        let layout = DwarfType {
            kind: DwarfTypeKind::Struct,
            name: "pair".to_string(),
            byte_size: 8,
            fields: vec![
                DwarfField {
                    offset: 0,
                    name: "a".to_string(),
                    c_type: "int".to_string(),
                    size: 4,
                },
                DwarfField {
                    offset: 4,
                    name: "b".to_string(),
                    c_type: "int".to_string(),
                    size: 4,
                },
            ],
            variants: Vec::new(),
            typedef_target: None,
            source_file: Some("pair.c".to_string()),
        };

        let text = render_decbench_typed_with_output_and_prototype_and_dwarf_types(
            &function,
            None,
            None,
            RecoveredOutputKind::Direct,
            Some(&prototype),
            &[layout],
            8,
            &std::collections::HashMap::new(),
        );

        assert!(
            text.contains("int consume_pair(struct pair arg0)"),
            "{text}"
        );
        assert!(
            text.matches("union { struct pair object; unsigned long long bits; }")
                .count()
                >= 2,
            "every scalar use must explicitly read the aggregate carrier:\n{text}"
        );
        assert_looks_like_c(&text);
    }

    #[test]
    fn by_value_aggregate_call_reconstructs_the_source_object_from_carrier_bits() {
        use crate::debug::dwarf::{DwarfField, DwarfType, DwarfTypeKind};
        use crate::ir::types_recover::RecoveredOutputKind;

        let aggregate = CallPrototype {
            return_type: "int".to_string(),
            parameter_types: vec!["struct pair".to_string()],
            variadic: false,
            authority: CallPrototypeAuthority::Authoritative,
        };
        let function = Function {
            name: "caller".to_string(),
            entry_va: 0x1000,
            body: vec![Stmt::Call {
                target: Expr::Named {
                    va: 0x2000,
                    name: "consume_pair".to_string(),
                },
                args: vec![Expr::Deref {
                    addr: Box::new(Expr::Reg(VReg::phys("rbp"))),
                    size: 8,
                }],
                dst: Some(VReg::phys("ret")),
                call_spec: Some(CallSiteSpec {
                    callee_prototype: Some(aggregate.clone()),
                    call_prototype: aggregate,
                }),
            }],
        };
        let layout = DwarfType {
            kind: DwarfTypeKind::Struct,
            name: "pair".to_string(),
            byte_size: 8,
            fields: vec![
                DwarfField {
                    offset: 0,
                    name: "a".to_string(),
                    c_type: "int".to_string(),
                    size: 4,
                },
                DwarfField {
                    offset: 4,
                    name: "b".to_string(),
                    c_type: "int".to_string(),
                    size: 4,
                },
            ],
            variants: Vec::new(),
            typedef_target: None,
            source_file: Some("pair.c".to_string()),
        };

        let text = render_decbench_typed_with_output_and_prototype_and_dwarf_types(
            &function,
            None,
            None,
            RecoveredOutputKind::Direct,
            None,
            &[layout],
            8,
            &std::collections::HashMap::new(),
        );

        assert!(
            text.contains("extern int consume_pair(struct pair);"),
            "{text}"
        );
        assert!(
            text.contains("union { struct pair object; unsigned long long bits; }")
                && text.contains(".object"),
            "the call must rebuild the source object without numeric conversion:\n{text}"
        );
        assert_looks_like_c(&text);
    }

    #[test]
    fn by_value_aggregate_return_reconstructs_the_source_object_from_carrier_bits() {
        use crate::debug::dwarf::{DwarfField, DwarfType, DwarfTypeKind};
        use crate::ir::types_recover::RecoveredOutputKind;

        let function = Function {
            name: "make_pair".to_string(),
            entry_va: 0x1000,
            body: vec![Stmt::Return {
                value: Some(Expr::Const(0x0000_0002_0000_0001)),
            }],
        };
        let prototype = CallPrototype {
            return_type: "struct pair".to_string(),
            parameter_types: Vec::new(),
            variadic: false,
            authority: CallPrototypeAuthority::Authoritative,
        };
        let layout = DwarfType {
            kind: DwarfTypeKind::Struct,
            name: "pair".to_string(),
            byte_size: 8,
            fields: vec![
                DwarfField {
                    offset: 0,
                    name: "a".to_string(),
                    c_type: "int".to_string(),
                    size: 4,
                },
                DwarfField {
                    offset: 4,
                    name: "b".to_string(),
                    c_type: "int".to_string(),
                    size: 4,
                },
            ],
            variants: Vec::new(),
            typedef_target: None,
            source_file: Some("pair.c".to_string()),
        };

        let text = render_decbench_typed_with_output_and_prototype_and_dwarf_types(
            &function,
            None,
            None,
            RecoveredOutputKind::Direct,
            Some(&prototype),
            &[layout],
            8,
            &std::collections::HashMap::new(),
        );

        assert!(text.contains("struct pair make_pair(void)"), "{text}");
        assert!(
            text.contains("return ((union { struct pair object; unsigned long long bits; }")
                && text.contains(".object;"),
            "the return must rebuild the source object without numeric conversion:\n{text}"
        );
        assert_looks_like_c(&text);
    }

    #[test]
    fn enum_typedef_return_keeps_its_authoritative_name() {
        use crate::debug::dwarf::{DwarfEnumVariant, DwarfType, DwarfTypeKind};
        use crate::ir::types_recover::RecoveredOutputKind;

        let f = Function {
            name: "begin_transaction".to_string(),
            entry_va: 0x1000,
            body: vec![Stmt::Return {
                value: Some(Expr::Const(0)),
            }],
        };
        let prototype = CallPrototype {
            return_type: "Status".to_string(),
            parameter_types: Vec::new(),
            variadic: false,
            authority: CallPrototypeAuthority::Authoritative,
        };
        let types = vec![
            DwarfType {
                kind: DwarfTypeKind::Typedef,
                name: "Status".to_string(),
                byte_size: 0,
                fields: Vec::new(),
                variants: Vec::new(),
                typedef_target: Some("enum Status_".to_string()),
                source_file: Some("status.h".to_string()),
            },
            DwarfType {
                kind: DwarfTypeKind::Enum,
                name: "Status_".to_string(),
                byte_size: 4,
                fields: Vec::new(),
                variants: vec![
                    DwarfEnumVariant {
                        name: "STATUS_ERROR".to_string(),
                        value: -1,
                    },
                    DwarfEnumVariant {
                        name: "STATUS_OK".to_string(),
                        value: 0,
                    },
                ],
                typedef_target: None,
                source_file: Some("status.h".to_string()),
            },
        ];

        let text = render_decbench_typed_with_output_and_prototype_and_dwarf_types(
            &f,
            None,
            None,
            RecoveredOutputKind::Direct,
            Some(&prototype),
            &types,
            8,
            &std::collections::HashMap::new(),
        );

        assert!(text.contains("typedef int Status;"), "{text}");
        assert!(text.contains("Status begin_transaction(void)"), "{text}");
    }

    #[test]
    fn declared_pointer_null_test_does_not_round_trip_through_an_integer() {
        let f = Function {
            name: "has_node".to_string(),
            entry_va: 0x1000,
            body: vec![Stmt::While {
                cond: Expr::Cmp {
                    op: CmpOp::Ne,
                    lhs: Box::new(Expr::Reg(VReg::phys("arg0"))),
                    rhs: Box::new(Expr::Const(0)),
                },
                body: vec![Stmt::Return {
                    value: Some(Expr::Const(1)),
                }],
            }],
        };
        let mut tm = TypeMap::default();
        tm.upsert_public(VReg::phys("arg0"), TypeHint::Pointer { pointee_width: 1 });

        let text = render_decbench_typed(&f, Some(&tm), Some(&tm));

        assert!(text.contains("while (arg0 != 0)"), "{text}");
        assert!(!text.contains("(long)arg0"), "{text}");
    }

    #[test]
    fn narrowing_pointer_cast_in_null_test_remains_explicit() {
        let f = Function {
            name: "low_address_is_nonzero".to_string(),
            entry_va: 0x1000,
            body: vec![Stmt::Return {
                value: Some(Expr::Cmp {
                    op: CmpOp::Ne,
                    lhs: Box::new(Expr::Cast {
                        signed: false,
                        width: 4,
                        expr: Box::new(Expr::Reg(VReg::phys("arg0"))),
                    }),
                    rhs: Box::new(Expr::Const(0)),
                }),
            }],
        };
        let mut tm = TypeMap::default();
        tm.upsert_public(VReg::phys("arg0"), TypeHint::Pointer { pointee_width: 1 });

        let text = render_decbench_typed(&f, Some(&tm), Some(&tm));

        assert!(text.contains("(unsigned int)"), "{text}");
        assert!(!text.contains("return (arg0 != 0);"), "{text}");
    }

    #[test]
    fn locked_wide_return_contract_outranks_a_narrow_branch_expression() {
        let f = Function {
            name: "fib".to_string(),
            entry_va: 0x1000,
            body: vec![Stmt::If {
                cond: Expr::Reg(VReg::phys("arg0")),
                then_body: vec![Stmt::Return {
                    value: Some(Expr::Reg(VReg::phys("local_8"))),
                }],
                else_body: Some(vec![Stmt::Return {
                    value: Some(Expr::Cast {
                        signed: true,
                        width: 4,
                        expr: Box::new(Expr::Reg(VReg::phys("arg0"))),
                    }),
                }]),
            }],
        };
        let mut tm = TypeMap::default();
        tm.upsert_public(
            VReg::phys("arg0"),
            TypeHint::Int {
                signed: true,
                width: 4,
            },
        );
        tm.apply_locked_fact(
            VReg::phys("ret"),
            TypeHint::Int {
                signed: true,
                width: 8,
            },
        );

        let text = render_decbench_typed(&f, Some(&tm), Some(&tm));

        assert!(text.contains("long fib(int arg0)"), "{text}");
    }

    #[test]
    fn decbench_abi_refines_a_stale_pointer_return_from_scalar_definitions() {
        use crate::ir::types_recover::{TypeHint, TypeMap};

        // Raw-register type recovery saw rax used for an address earlier in the
        // function and attached that pointer hint to the role name `ret`.  The
        // prepared value flow is stronger: every reaching definition is an
        // explicit integer value and the function returns that scalar.
        let mut f = Function {
            name: "state_result".to_string(),
            entry_va: 0x1000,
            body: vec![
                Stmt::Assign {
                    dst: VReg::phys("ret"),
                    src: Expr::Cast {
                        signed: false,
                        width: 4,
                        expr: Box::new(Expr::Reg(VReg::phys("local_byte"))),
                    },
                },
                Stmt::Assign {
                    dst: VReg::phys("ret"),
                    src: Expr::Cmp {
                        op: CmpOp::Eq,
                        lhs: Box::new(Expr::Reg(VReg::phys("local_state"))),
                        rhs: Box::new(Expr::Const(3)),
                    },
                },
                Stmt::Return {
                    value: Some(Expr::Reg(VReg::phys("ret"))),
                },
            ],
        };
        let mut tm = TypeMap::default();
        tm.upsert_public(VReg::phys("ret"), TypeHint::Pointer { pointee_width: 1 });

        refine_decbench_abi_widths(&f, &mut tm);
        assert_eq!(
            tm.get(&VReg::phys("ret")),
            Some(TypeHint::Int {
                signed: true,
                width: 4,
            })
        );
        crate::ir::widen::insert_widening_casts(&mut f, &tm);
        let text = render_decbench_typed(&f, Some(&tm), Some(&tm));
        assert!(text.contains("int state_result("), "got:\n{text}");
    }

    #[test]
    fn decbench_signed_comparison_refines_integer_parameter_signedness() {
        use crate::ir::types_recover::{TypeHint, TypeMap};

        let key = VReg::phys("arg2");
        let f = Function {
            name: "bisect_step".to_string(),
            entry_va: 0x1000,
            body: vec![Stmt::If {
                cond: Expr::Cmp {
                    op: CmpOp::Sle,
                    lhs: Box::new(Expr::Reg(key.clone())),
                    rhs: Box::new(Expr::Deref {
                        addr: Box::new(Expr::Reg(VReg::phys("arg0"))),
                        size: 4,
                    }),
                },
                then_body: vec![Stmt::Return {
                    value: Some(Expr::Const(-1)),
                }],
                else_body: None,
            }],
        };
        let mut tm = TypeMap::default();
        tm.upsert_public(
            key.clone(),
            TypeHint::Int {
                signed: false,
                width: 4,
            },
        );

        refine_decbench_abi_widths(&f, &mut tm);

        assert_eq!(
            tm.get(&key),
            Some(TypeHint::Int {
                signed: true,
                width: 4,
            })
        );
    }

    #[test]
    fn decbench_signed_comparison_refines_a_direct_sign_extended_parameter() {
        use crate::ir::types_recover::{TypeHint, TypeMap};

        let key = VReg::phys("arg0");
        let sign_extended = Expr::Cast {
            signed: true,
            width: 8,
            expr: Box::new(Expr::Cast {
                signed: true,
                width: 4,
                expr: Box::new(Expr::Reg(key.clone())),
            }),
        };
        let f = Function {
            name: "signs".to_string(),
            entry_va: 0x1000,
            body: vec![Stmt::Return {
                value: Some(Expr::Cmp {
                    op: CmpOp::Slt,
                    lhs: Box::new(sign_extended),
                    rhs: Box::new(Expr::Const(0)),
                }),
            }],
        };
        let mut tm = TypeMap::default();
        tm.upsert_public(
            key.clone(),
            TypeHint::Int {
                signed: false,
                width: 4,
            },
        );

        refine_decbench_abi_widths(&f, &mut tm);

        assert_eq!(
            tm.get(&key),
            Some(TypeHint::Int {
                signed: true,
                width: 4,
            })
        );
    }

    #[test]
    fn decbench_signed_comparison_does_not_overwrite_a_pointer_hint() {
        use crate::ir::types_recover::{TypeHint, TypeMap};

        let pointer = VReg::phys("arg0");
        let f = Function {
            name: "pointer_order".to_string(),
            entry_va: 0x1000,
            body: vec![Stmt::Return {
                value: Some(Expr::Cmp {
                    op: CmpOp::Slt,
                    lhs: Box::new(Expr::Reg(pointer.clone())),
                    rhs: Box::new(Expr::Const(0)),
                }),
            }],
        };
        let mut tm = TypeMap::default();
        tm.upsert_public(pointer.clone(), TypeHint::Pointer { pointee_width: 4 });

        refine_decbench_abi_widths(&f, &mut tm);

        assert_eq!(
            tm.get(&pointer),
            Some(TypeHint::Pointer { pointee_width: 4 })
        );
    }

    #[test]
    fn decbench_scalar_refinement_preserves_a_wide_integer_return_hint() {
        use crate::ir::types_recover::{TypeHint, TypeMap};

        let f = Function {
            name: "widen_mul".to_string(),
            entry_va: 0x1000,
            body: vec![
                Stmt::Assign {
                    dst: VReg::phys("ret"),
                    src: Expr::Bin {
                        op: BinOp::Mul,
                        lhs: Box::new(Expr::Reg(VReg::phys("arg0"))),
                        rhs: Box::new(Expr::Reg(VReg::phys("arg1"))),
                    },
                },
                Stmt::Return {
                    value: Some(Expr::Reg(VReg::phys("ret"))),
                },
            ],
        };
        let mut tm = TypeMap::default();
        for name in ["arg0", "arg1"] {
            tm.upsert_public(
                VReg::phys(name),
                TypeHint::Int {
                    signed: false,
                    width: 4,
                },
            );
        }
        tm.upsert_public(
            VReg::phys("ret"),
            TypeHint::Int {
                signed: false,
                width: 8,
            },
        );

        refine_decbench_abi_widths(&f, &mut tm);

        assert_eq!(
            tm.get(&VReg::phys("ret")),
            Some(TypeHint::Int {
                signed: false,
                width: 8,
            })
        );
    }

    #[test]
    fn decbench_abi_keeps_a_returned_address_pointer_typed() {
        use crate::ir::types_recover::{TypeHint, TypeMap};

        let f = Function {
            name: "address_result".to_string(),
            entry_va: 0x1000,
            body: vec![
                Stmt::Assign {
                    dst: VReg::phys("ret"),
                    src: Expr::Addr(0x4000),
                },
                Stmt::Return {
                    value: Some(Expr::Reg(VReg::phys("ret"))),
                },
            ],
        };
        let mut tm = TypeMap::default();
        tm.upsert_public(VReg::phys("ret"), TypeHint::Pointer { pointee_width: 1 });

        refine_decbench_abi_widths(&f, &mut tm);
        assert_eq!(
            tm.get(&VReg::phys("ret")),
            Some(TypeHint::Pointer { pointee_width: 1 })
        );
    }

    #[test]
    fn decbench_comparison_return_uses_c_int_type() {
        // In C, comparison operators produce `int`, even when x86 materialises
        // the final 0/1 through `setcc al`.  The expression's language type
        // must outrank the narrow last physical-register write.
        let f = Function {
            name: "is_zero".to_string(),
            entry_va: 0x1000,
            body: vec![Stmt::Return {
                value: Some(Expr::Cmp {
                    op: CmpOp::Eq,
                    lhs: Box::new(Expr::Reg(VReg::phys("arg0"))),
                    rhs: Box::new(Expr::Const(0)),
                }),
            }],
        };
        let mut tm = TypeMap::default();
        tm.upsert_public(
            VReg::phys("ret"),
            TypeHint::Int {
                signed: true,
                width: 1,
            },
        );
        let text = render_decbench_typed(&f, Some(&tm), None);
        assert!(
            text.contains("int is_zero(") && text.contains("return (arg0 == 0);"),
            "comparison return should use C's `int` result type:\n{}",
            text
        );
    }

    #[test]
    fn decbench_array_index_render_for_pointer_arg() {
        // `*(int*)(arg0 + i*4)` with `arg0` a declared `int *` renders as
        // `arg0[i]`, dropping the byte-offset arithmetic and `(long)` cast.
        let deref = Expr::Deref {
            addr: Box::new(Expr::Bin {
                op: BinOp::Add,
                lhs: Box::new(Expr::Reg(VReg::phys("arg0"))),
                rhs: Box::new(Expr::Bin {
                    op: BinOp::Add,
                    lhs: Box::new(Expr::Const(0)),
                    rhs: Box::new(Expr::Bin {
                        op: BinOp::Mul,
                        lhs: Box::new(Expr::Reg(VReg::phys("local_4"))),
                        rhs: Box::new(Expr::Const(4)),
                    }),
                }),
            }),
            size: 4,
        };
        let f = Function {
            name: "ai".to_string(),
            entry_va: 0x1000,
            body: vec![Stmt::Return { value: Some(deref) }],
        };
        let mut tm = TypeMap::default();
        tm.upsert_public(VReg::phys("arg0"), TypeHint::Pointer { pointee_width: 4 });
        let text = render_decbench_typed(&f, Some(&tm), None);
        assert!(
            text.contains("arg0[local_4]") && !text.contains("(long)arg0"),
            "expected array-index render `arg0[local_4]`, got:\n{}",
            text
        );

        // A common x86-64 index carries a width-only 32-bit register view
        // inside the signed pointer-width extension. Once the declaration
        // proves that value is an `int`, C's array subscript conversion already
        // performs the same extension and neither cast belongs in the source.
        let widened_index = Expr::Deref {
            addr: Box::new(Expr::Bin {
                op: BinOp::Add,
                lhs: Box::new(Expr::Reg(VReg::phys("arg0"))),
                rhs: Box::new(Expr::Bin {
                    op: BinOp::Mul,
                    lhs: Box::new(Expr::Cast {
                        signed: true,
                        width: 8,
                        expr: Box::new(Expr::Cast {
                            signed: false,
                            width: 4,
                            expr: Box::new(Expr::Reg(VReg::phys("local_4"))),
                        }),
                    }),
                    rhs: Box::new(Expr::Const(8)),
                }),
            }),
            size: 8,
        };
        let widened_function = Function {
            name: "wide_ai".to_string(),
            entry_va: 0x1010,
            body: vec![Stmt::Return {
                value: Some(widened_index),
            }],
        };
        let mut widened_types = TypeMap::default();
        widened_types.upsert_public(VReg::phys("arg0"), TypeHint::Pointer { pointee_width: 8 });
        widened_types.upsert_public(
            VReg::phys("local_4"),
            TypeHint::Int {
                signed: true,
                width: 4,
            },
        );
        let widened_text = render_decbench_typed(
            &widened_function,
            Some(&widened_types),
            Some(&widened_types),
        );
        assert!(
            widened_text.contains("arg0[local_4]") && !widened_text.contains("(long)(local_4)"),
            "declared int index retained machine-width casts:\n{widened_text}"
        );

        // Guard: a mismatched access width (2-byte read through an int* base)
        // must NOT array-index (the scale would be wrong) — keep the cast form.
        let deref2 = Expr::Deref {
            addr: Box::new(Expr::Bin {
                op: BinOp::Add,
                lhs: Box::new(Expr::Reg(VReg::phys("arg0"))),
                rhs: Box::new(Expr::Bin {
                    op: BinOp::Mul,
                    lhs: Box::new(Expr::Reg(VReg::phys("local_4"))),
                    rhs: Box::new(Expr::Const(4)),
                }),
            }),
            size: 2,
        };
        let f2 = Function {
            name: "ai2".to_string(),
            entry_va: 0x1000,
            body: vec![Stmt::Return {
                value: Some(deref2),
            }],
        };
        let text2 = render_decbench_typed(&f2, Some(&tm), None);
        assert!(
            !text2.contains("arg0[local_4]"),
            "width mismatch must not array-index, got:\n{}",
            text2
        );
    }

    #[test]
    fn decbench_recovers_int_compound_assignment_from_narrow_machine_views() {
        let f = Function {
            name: "sum_length".to_string(),
            entry_va: 0x1000,
            body: vec![Stmt::Store {
                addr: Expr::Reg(VReg::phys("local_8")),
                src: Expr::Cast {
                    signed: false,
                    width: 8,
                    expr: Box::new(Expr::Cast {
                        signed: false,
                        width: 4,
                        expr: Box::new(Expr::Bin {
                            op: BinOp::Add,
                            lhs: Box::new(Expr::Cast {
                                signed: false,
                                width: 4,
                                expr: Box::new(Expr::Reg(VReg::phys("local_8"))),
                            }),
                            rhs: Box::new(Expr::Cast {
                                signed: false,
                                width: 4,
                                expr: Box::new(Expr::Reg(VReg::phys("var1"))),
                            }),
                        }),
                    }),
                },
                size: 4,
            }],
        };
        let mut tm = TypeMap::default();
        tm.upsert_public(
            VReg::phys("local_8"),
            TypeHint::Int {
                signed: true,
                width: 4,
            },
        );
        tm.upsert_public(
            VReg::phys("var1"),
            TypeHint::Int {
                signed: false,
                width: 8,
            },
        );

        let text = render_decbench_typed(&f, Some(&tm), Some(&tm));
        assert!(
            text.contains("local_8 += var1;"),
            "narrow machine views obscured compound assignment:\n{text}"
        );
        assert_looks_like_c(&text);
    }

    #[test]
    fn decbench_recovers_int_compound_assignment_with_a_wide_call_operand() {
        let f = Function {
            name: "sum_length".to_string(),
            entry_va: 0x1000,
            body: vec![Stmt::Store {
                addr: Expr::Reg(VReg::phys("local_14")),
                src: Expr::Bin {
                    op: BinOp::Add,
                    lhs: Box::new(Expr::Cast {
                        signed: true,
                        width: 8,
                        expr: Box::new(Expr::Cast {
                            signed: true,
                            width: 4,
                            expr: Box::new(Expr::Reg(VReg::phys("local_14"))),
                        }),
                    }),
                    rhs: Box::new(Expr::Call {
                        target: Box::new(Expr::Named {
                            va: 0x2000,
                            name: "strlen".to_string(),
                        }),
                        args: vec![Expr::Reg(VReg::phys("arg0"))],
                        call_spec: None,
                        result_width: Some(8),
                    }),
                },
                size: 4,
            }],
        };
        let mut tm = TypeMap::default();
        tm.upsert_public(
            VReg::phys("local_14"),
            TypeHint::Int {
                signed: true,
                width: 4,
            },
        );
        tm.upsert_public(VReg::phys("arg0"), TypeHint::Pointer { pointee_width: 1 });

        let text = render_decbench_typed(&f, Some(&tm), Some(&tm));
        assert!(
            text.contains("local_14 += strlen(arg0);"),
            "wide call operand obscured compound assignment:\n{text}"
        );
        assert_looks_like_c(&text);
    }

    #[test]
    fn decbench_recovers_commuted_int_compound_assignment() {
        let f = Function {
            name: "sum_length".to_string(),
            entry_va: 0x1000,
            body: vec![Stmt::Store {
                addr: Expr::Reg(VReg::phys("local_14")),
                src: Expr::Bin {
                    op: BinOp::Add,
                    lhs: Box::new(Expr::Cast {
                        signed: false,
                        width: 4,
                        expr: Box::new(Expr::Call {
                            target: Box::new(Expr::Named {
                                va: 0x2000,
                                name: "strlen".to_string(),
                            }),
                            args: vec![Expr::Reg(VReg::phys("arg0"))],
                            call_spec: None,
                            result_width: Some(8),
                        }),
                    }),
                    rhs: Box::new(Expr::Cast {
                        signed: false,
                        width: 4,
                        expr: Box::new(Expr::Reg(VReg::phys("local_14"))),
                    }),
                },
                size: 4,
            }],
        };
        let mut tm = TypeMap::default();
        tm.upsert_public(
            VReg::phys("local_14"),
            TypeHint::Int {
                signed: true,
                width: 4,
            },
        );
        tm.upsert_public(VReg::phys("arg0"), TypeHint::Pointer { pointee_width: 1 });

        let text = render_decbench_typed(&f, Some(&tm), Some(&tm));
        assert!(
            text.contains("local_14 += strlen(arg0);"),
            "commuted machine addition obscured compound assignment:\n{text}"
        );
        assert_looks_like_c(&text);
    }

    #[test]
    fn decbench_passes_declared_int_directly_through_non_narrowing_views() {
        let f = Function {
            name: "caller".to_string(),
            entry_va: 0x1000,
            body: vec![Stmt::Call {
                target: Expr::Named {
                    va: 0x2000,
                    name: "consume_int".to_string(),
                },
                args: vec![Expr::Cast {
                    signed: false,
                    width: 8,
                    expr: Box::new(Expr::Cast {
                        signed: false,
                        width: 4,
                        expr: Box::new(Expr::Reg(VReg::phys("var0"))),
                    }),
                }],
                dst: None,
                call_spec: Some(CallSiteSpec {
                    callee_prototype: None,
                    call_prototype: CallPrototype {
                        return_type: "void".to_string(),
                        parameter_types: vec!["int".to_string()],
                        variadic: false,
                        authority: CallPrototypeAuthority::Authoritative,
                    },
                }),
            }],
        };
        let mut tm = TypeMap::default();
        tm.upsert_public(
            VReg::phys("var0"),
            TypeHint::Int {
                signed: true,
                width: 4,
            },
        );

        let text = render_decbench_typed(&f, Some(&tm), Some(&tm));
        assert!(
            text.contains("consume_int(var0);"),
            "non-narrowing views obscured declared int argument:\n{text}"
        );
        assert_looks_like_c(&text);
    }

    #[test]
    fn decbench_uses_literal_printf_format_to_type_variadic_int() {
        let f = Function {
            name: "report".to_string(),
            entry_va: 0x1000,
            body: vec![Stmt::Call {
                target: Expr::Named {
                    va: 0x2000,
                    name: "printf".to_string(),
                },
                args: vec![
                    Expr::StringLit {
                        value: "value: %d\n".to_string(),
                    },
                    Expr::Cast {
                        signed: false,
                        width: 8,
                        expr: Box::new(Expr::Cast {
                            signed: false,
                            width: 4,
                            expr: Box::new(Expr::Reg(VReg::phys("var0"))),
                        }),
                    },
                ],
                dst: None,
                call_spec: None,
            }],
        };
        let mut tm = TypeMap::default();
        tm.upsert_public(
            VReg::phys("var0"),
            TypeHint::Int {
                signed: true,
                width: 4,
            },
        );

        let text = render_decbench_typed(&f, Some(&tm), Some(&tm));
        assert!(
            text.contains("printf(\"value: %d\\n\", var0);"),
            "literal printf contract did not remove integer views:\n{text}"
        );
    }

    fn render_wrapped_array_index(index_constant: i64, pointer_width: u8) -> String {
        use crate::ir::types_recover::{RecoveredOutputKind, TypeHint, TypeMap};

        let deref = Expr::Deref {
            addr: Box::new(Expr::Bin {
                op: BinOp::Add,
                lhs: Box::new(Expr::Reg(VReg::phys("arg0"))),
                rhs: Box::new(Expr::Bin {
                    op: BinOp::Mul,
                    lhs: Box::new(Expr::Bin {
                        op: BinOp::Add,
                        lhs: Box::new(Expr::Reg(VReg::phys("local_4"))),
                        rhs: Box::new(Expr::Const(index_constant)),
                    }),
                    rhs: Box::new(Expr::Const(4)),
                }),
            }),
            size: 4,
        };
        let function = Function {
            name: "wrapped_index".to_string(),
            entry_va: 0x1000,
            body: vec![Stmt::Return { value: Some(deref) }],
        };
        let mut types = TypeMap::default();
        types.upsert_public(VReg::phys("arg0"), TypeHint::Pointer { pointee_width: 4 });
        render_decbench_typed_with_output_and_prototype_and_dwarf_types(
            &function,
            Some(&types),
            None,
            RecoveredOutputKind::Unknown,
            None,
            &[],
            pointer_width,
            &std::collections::HashMap::new(),
        )
    }

    fn render_wrapped_array_store(index_constant: i64, pointer_width: u8) -> String {
        use crate::ir::types_recover::{RecoveredOutputKind, TypeHint, TypeMap};

        let address = Expr::Bin {
            op: BinOp::Add,
            lhs: Box::new(Expr::Reg(VReg::phys("arg0"))),
            rhs: Box::new(Expr::Bin {
                op: BinOp::Mul,
                lhs: Box::new(Expr::Bin {
                    op: BinOp::Add,
                    lhs: Box::new(Expr::Reg(VReg::phys("local_4"))),
                    rhs: Box::new(Expr::Const(index_constant)),
                }),
                rhs: Box::new(Expr::Const(4)),
            }),
        };
        let function = Function {
            name: "wrapped_store".to_string(),
            entry_va: 0x1000,
            body: vec![Stmt::Store {
                addr: address,
                src: Expr::Const(7),
                size: 4,
            }],
        };
        let mut types = TypeMap::default();
        types.upsert_public(VReg::phys("arg0"), TypeHint::Pointer { pointee_width: 4 });
        render_decbench_typed_with_output_and_prototype_and_dwarf_types(
            &function,
            Some(&types),
            None,
            RecoveredOutputKind::Unknown,
            None,
            &[],
            pointer_width,
            &std::collections::HashMap::new(),
        )
    }

    #[test]
    fn ilp32_array_index_normalizes_negative_wrapped_scaled_offset() {
        let text = render_wrapped_array_index(0x3fff_ffff, 4);
        assert!(
            text.contains("arg0[(local_4 - 1)]"),
            "32-bit -4 byte offset must render as index -1:\n{text}"
        );
        assert!(!text.contains("0x3fffffff"), "{text}");
    }

    #[test]
    fn ilp32_array_index_normalizes_positive_wrapped_scaled_offset() {
        let text = render_wrapped_array_index(0x4000_0001, 4);
        assert!(
            text.contains("arg0[(local_4 + 1)]"),
            "32-bit wrapped +4 byte offset must render as index +1:\n{text}"
        );
        assert!(!text.contains("0x40000001"), "{text}");
    }

    #[test]
    fn ilp32_array_store_uses_the_same_wrapped_index_normalization() {
        let text = render_wrapped_array_store(0x3fff_ffff, 4);
        assert!(
            text.contains("arg0[(local_4 - 1)] = 7;"),
            "32-bit wrapped stores must not retain host-width arithmetic:\n{text}"
        );
        assert!(!text.contains("0x3fffffff"), "{text}");
    }

    #[test]
    fn wrapped_scaled_index_normalization_is_exact_for_non_power_of_two_scales() {
        assert_eq!(
            normalize_wrapped_scaled_index_constant(0x8000_0001, 6, 4),
            Some(1)
        );
        assert_eq!(
            normalize_wrapped_scaled_index_constant(0x7fff_ffff, 6, 4),
            Some(-1)
        );
        assert_eq!(
            normalize_wrapped_scaled_index_constant(0x5555_5555, 3, 4),
            None,
            "a wrapped byte displacement that is not divisible by the element size must fail closed"
        );
        assert_eq!(
            normalize_wrapped_scaled_index_constant(0x8000_0001, 6, 8),
            None,
            "LP64 arithmetic must never be normalized as an ILP32 wrap"
        );
    }

    #[test]
    fn lp64_array_index_preserves_the_same_constant_bits() {
        let text = render_wrapped_array_index(0x3fff_ffff, 8);
        assert!(
            text.contains("arg0[(local_4 + 0x3fffffff)]"),
            "64-bit pointer arithmetic must not apply an ILP32 wrap:\n{text}"
        );
    }

    #[test]
    fn decbench_shared_bare_return_preserves_the_computed_value() {
        // The value is computed into `ret` in one block, then returned from
        // another (goto-separated). Terminal-tail recovery makes that exact
        // return local, after which the adjacent fold may emit the expression
        // directly. Either way, it must never become the value-losing
        // `return 0;`.
        let f = Function {
            name: "f".to_string(),
            entry_va: 0x10,
            body: vec![
                Stmt::Assign {
                    dst: VReg::phys("ret"),
                    src: Expr::Bin {
                        op: BinOp::Add,
                        lhs: Box::new(Expr::Reg(VReg::phys("arg0"))),
                        rhs: Box::new(Expr::Const(1)),
                    },
                },
                Stmt::Goto { target: 0x20 },
                Stmt::Label(0x20),
                Stmt::Return { value: None },
            ],
        };
        let text = dec_pipeline(&f);
        assert!(
            text.contains("return (arg0 + 1);"),
            "shared bare return should preserve its computed value:\n{}",
            text
        );
        assert!(
            !text.contains("return 0;"),
            "must not lose the value as return 0:\n{}",
            text
        );
        assert_looks_like_c(&text);
    }

    #[test]
    fn decbench_no_args_renders_void_signature() {
        let f = Function {
            name: "noargs".to_string(),
            entry_va: 0x400,
            body: vec![Stmt::Return {
                value: Some(Expr::Const(0)),
            }],
        };
        let text = render_decbench(&f);
        assert!(text.contains("long noargs(void) {"), "got:\n{}", text);
        assert_looks_like_c(&text);
    }

    #[test]
    fn decbench_flags_lose_sigil_and_are_declared() {
        let f = Function {
            name: "f".to_string(),
            entry_va: 0x10,
            body: vec![Stmt::Assign {
                dst: VReg::Flag(Flag::Z),
                src: Expr::Cmp {
                    op: CmpOp::Eq,
                    lhs: Box::new(Expr::Reg(VReg::phys("arg0"))),
                    rhs: Box::new(Expr::Const(0)),
                },
            }],
        };
        let text = render_decbench(&f);
        assert!(text.contains("long zf;"), "flag not declared:\n{}", text);
        assert!(text.contains("zf = (arg0 == 0);"), "flag body:\n{}", text);
        assert_looks_like_c(&text);
    }

    #[test]
    fn decbench_lea_and_store_are_valid_c() {
        // *(long *)(rbp - 0x8) = arg0;
        let f = Function {
            name: "st".to_string(),
            entry_va: 0x20,
            body: vec![Stmt::Store {
                addr: Expr::Lea {
                    base: Some(VReg::phys("rbp")),
                    index: None,
                    scale: 1,
                    disp: -8,
                    segment: None,
                },
                src: Expr::Reg(VReg::phys("arg0")),
                size: 8,
            }],
        };
        let text = render_decbench(&f);
        assert!(
            text.contains("*(long *)((rbp - 0x8)) = arg0;"),
            "store wrong:\n{}",
            text
        );
        assert!(text.contains("long rbp;"), "base not declared:\n{}", text);
        assert_looks_like_c(&text);
    }

    #[test]
    fn decbench_stack_address_reserves_complete_object_storage() {
        let f = Function {
            name: "construct".to_string(),
            entry_va: 0x20,
            body: vec![Stmt::Call {
                target: Expr::Named {
                    va: 0x1000,
                    name: "Widget_ctor".to_string(),
                },
                args: vec![Expr::StackAddr {
                    object: VReg::phys("local_20"),
                    size: 32,
                }],
                dst: None,
                call_spec: None,
            }],
        };

        let text = render_decbench(&f);
        assert!(
            text.contains("unsigned char local_20[32];"),
            "address-taken storage must not be a pointer-sized scalar: {text}"
        );
        assert!(text.contains("Widget_ctor(&local_20[0])"), "got: {text}");
        assert_looks_like_c(&text);
    }

    #[test]
    fn decbench_sixteen_byte_zero_store_initializes_the_full_region() {
        let f = Function {
            name: "zero_vector".to_string(),
            entry_va: 0x20,
            body: vec![Stmt::Store {
                addr: Expr::StackAddr {
                    object: VReg::phys("local_10"),
                    size: 16,
                },
                src: Expr::Const(0),
                size: 16,
            }],
        };

        let text = render_decbench(&f);
        assert!(text.contains("unsigned char local_10[16];"), "{text}");
        assert!(
            text.contains("__builtin_memset(&local_10[0], 0, 16);"),
            "a 128-bit zero store must not degrade to one machine word: {text}"
        );
        assert_looks_like_c(&text);
    }

    #[test]
    fn decbench_adjacent_sixteen_byte_load_store_keeps_every_byte() {
        let loaded = VReg::phys("var0");
        let f = Function {
            name: "copy_vector".to_string(),
            entry_va: 0x20,
            body: vec![
                Stmt::Assign {
                    dst: loaded.clone(),
                    src: Expr::Deref {
                        addr: Box::new(Expr::Reg(VReg::phys("arg1"))),
                        size: 16,
                    },
                },
                Stmt::Store {
                    addr: Expr::Reg(VReg::phys("arg0")),
                    src: Expr::Reg(loaded),
                    size: 16,
                },
            ],
        };

        let prepared = prepare_for_decbench(&f);
        assert_eq!(prepared.body.len(), 2, "{prepared:#?}");
        let text = render_decbench(&prepared);
        assert!(
            text.contains("unsigned char var0[16] __attribute__((aligned(16)));")
                && text.contains("__builtin_memcpy(var0, (void *)(arg1), 16);")
                && text.contains("__builtin_memmove((void *)(arg0), var0, 16);"),
            "a 128-bit copy must not degrade to two 64-bit expressions: {text}"
        );
        assert!(!text.contains("long var0;"), "{text}");
        assert_looks_like_c(&text);
    }

    #[test]
    fn decbench_vector_load_batch_preserves_load_before_store_order() {
        let first = VReg::phys("var0");
        let second = VReg::phys("var1");
        let plus_sixteen = |argument: &str| Expr::Bin {
            op: BinOp::Add,
            lhs: Box::new(Expr::Reg(VReg::phys(argument))),
            rhs: Box::new(Expr::Const(16)),
        };
        let f = Function {
            name: "copy_two_vectors".to_string(),
            entry_va: 0x20,
            body: vec![
                Stmt::Assign {
                    dst: first.clone(),
                    src: Expr::Deref {
                        addr: Box::new(Expr::Reg(VReg::phys("arg1"))),
                        size: 16,
                    },
                },
                Stmt::Assign {
                    dst: second.clone(),
                    src: Expr::Deref {
                        addr: Box::new(plus_sixteen("arg1")),
                        size: 16,
                    },
                },
                Stmt::Store {
                    addr: Expr::Reg(VReg::phys("arg0")),
                    src: Expr::Reg(first),
                    size: 16,
                },
                Stmt::Store {
                    addr: plus_sixteen("arg0"),
                    src: Expr::Reg(second),
                    size: 16,
                },
            ],
        };

        let text = dec_pipeline(&f);
        assert!(
            text.contains("unsigned char var0[16] __attribute__((aligned(16)));")
                && text.contains("unsigned char var1[16] __attribute__((aligned(16)));"),
            "both complete vector values need storage: {text}"
        );
        assert_eq!(text.matches("__builtin_memcpy(").count(), 2, "{text}");
        assert_eq!(text.matches("__builtin_memmove(").count(), 2, "{text}");
        let second_load = text.find("__builtin_memcpy(var1").expect("second load");
        let first_store = text
            .find("__builtin_memmove((void *)(arg0)")
            .expect("first store");
        assert!(
            second_load < first_store,
            "all machine loads must precede the first store: {text}"
        );
        assert_looks_like_c(&text);
    }

    #[test]
    fn decbench_stack_object_decay_to_word_is_explicit() {
        let f = Function {
            name: "capture_address".to_string(),
            entry_va: 0x20,
            body: vec![
                Stmt::Call {
                    target: Expr::Named {
                        va: 0x1000,
                        name: "consume".to_string(),
                    },
                    args: vec![Expr::StackAddr {
                        object: VReg::phys("stack_26"),
                        size: 8,
                    }],
                    dst: None,
                    call_spec: None,
                },
                Stmt::Store {
                    addr: Expr::Reg(VReg::phys("stack_47")),
                    src: Expr::Cast {
                        signed: true,
                        width: 4,
                        expr: Box::new(Expr::Reg(VReg::phys("stack_26"))),
                    },
                    size: 8,
                },
            ],
        };

        let text = render_decbench(&f);
        assert!(text.contains("unsigned char stack_26[8];"), "{text}");
        assert!(
            text.contains("stack_47 = (int)((long)stack_26);")
                || text.contains("stack_47 = (int)(stack_26);")
                || text.contains("stack_47 = (long)(stack_26);")
                || text.contains("stack_47 = (long)stack_26;"),
            "array decay must cross an explicit machine-word boundary:\n{text}"
        );
        assert!(!text.contains("stack_47 = stack_26;"), "{text}");
    }

    #[test]
    fn decbench_stack_pointer_arithmetic_stored_as_integer_is_explicit() {
        let f = Function {
            name: "advance_stack_address".to_string(),
            entry_va: 0x20,
            body: vec![
                Stmt::Call {
                    target: Expr::Named {
                        va: 0x1000,
                        name: "consume".to_string(),
                    },
                    args: vec![Expr::StackAddr {
                        object: VReg::phys("stack_1"),
                        size: 4,
                    }],
                    dst: None,
                    call_spec: None,
                },
                Stmt::Store {
                    addr: Expr::Reg(VReg::phys("stack_1")),
                    src: Expr::Bin {
                        op: BinOp::Add,
                        lhs: Box::new(Expr::Reg(VReg::phys("stack_1"))),
                        rhs: Box::new(Expr::Const(1)),
                    },
                    size: 4,
                },
            ],
        };

        let text = render_decbench(&f);
        assert!(text.contains("unsigned char stack_1[4];"), "{text}");
        assert!(
            text.contains("= (int)((long)(") && text.contains("(long)stack_1 + 1"),
            "pointer arithmetic crossed an implicit pointer-to-int boundary:\n{text}"
        );
    }

    #[test]
    fn decbench_pointer_arithmetic_assigned_to_pointer_is_explicit() {
        use crate::ir::types_recover::{TypeHint, TypeMap};

        let f = Function {
            name: "advance_pointer".to_string(),
            entry_va: 0x20,
            body: vec![
                Stmt::Assign {
                    dst: VReg::phys("arg0"),
                    src: Expr::Bin {
                        op: BinOp::Add,
                        lhs: Box::new(Expr::Reg(VReg::phys("arg0"))),
                        rhs: Box::new(Expr::Reg(VReg::phys("arg1"))),
                    },
                },
                Stmt::Return {
                    value: Some(Expr::Reg(VReg::phys("arg0"))),
                },
            ],
        };
        let mut tm = TypeMap::default();
        tm.upsert_public(VReg::phys("arg0"), TypeHint::Pointer { pointee_width: 1 });
        tm.upsert_public(VReg::phys("ret"), TypeHint::Pointer { pointee_width: 1 });

        let text = render_decbench_typed(&f, Some(&tm), Some(&tm));
        assert!(
            text.contains("arg0 = (char *)((long)arg0 + arg1);")
                || text.contains("arg0 = (char *)(((long)arg0 + arg1));"),
            "pointer arithmetic crossed an implicit integer-to-pointer boundary:\n{text}"
        );
        assert_looks_like_c(&text);
    }

    #[test]
    fn decbench_pointer_assignment_casts_a_pointer_fact_with_integer_declaration() {
        let recovered_long = CallPrototype {
            return_type: "long".into(),
            parameter_types: vec![],
            variadic: false,
            authority: CallPrototypeAuthority::Recovered,
        };
        let function = Function {
            name: "copy_recovered_address".to_string(),
            entry_va: 0x40,
            body: vec![
                Stmt::Call {
                    target: Expr::Named {
                        va: 0x1000,
                        name: "sub_1000".to_string(),
                    },
                    args: vec![],
                    dst: Some(VReg::phys("var13")),
                    call_spec: Some(CallSiteSpec {
                        callee_prototype: Some(recovered_long.clone()),
                        call_prototype: recovered_long,
                    }),
                },
                Stmt::Assign {
                    dst: VReg::phys("var15"),
                    src: Expr::Reg(VReg::phys("var13")),
                },
                Stmt::Return {
                    value: Some(Expr::Const(0)),
                },
            ],
        };
        let mut types = TypeMap::default();
        types.upsert_public(VReg::phys("var13"), TypeHint::Pointer { pointee_width: 1 });
        types.upsert_public(VReg::phys("var15"), TypeHint::Pointer { pointee_width: 1 });

        let text = render_decbench_typed(&function, Some(&types), None);

        assert!(text.contains("long var13;"), "{text}");
        assert!(text.contains("char * var15;"), "{text}");
        assert!(
            text.contains("var15 = (char *)(var13);")
                || text.contains("var15 = (char *)var13;"),
            "the emitted declaration, not a hidden pointer fact, determines whether the copy needs a representation cast:\n{text}"
        );
        assert_looks_like_c(&text);
    }

    #[test]
    fn decbench_pointer_assignment_casts_a_stack_byte_array() {
        let function = Function {
            name: "bind_stack_fields".to_string(),
            entry_va: 0x50,
            body: vec![
                Stmt::Call {
                    target: Expr::Named {
                        va: 0x2000,
                        name: "touch".to_string(),
                    },
                    args: vec![Expr::StackAddr {
                        object: VReg::phys("local_100"),
                        size: 12,
                    }],
                    dst: None,
                    call_spec: None,
                },
                Stmt::Store {
                    addr: Expr::Reg(VReg::phys("local_140")),
                    src: Expr::StackAddr {
                        object: VReg::phys("local_100"),
                        size: 12,
                    },
                    size: 8,
                },
                Stmt::Assign {
                    dst: VReg::phys("scratch"),
                    src: Expr::Const(0),
                },
                Stmt::Return {
                    value: Some(Expr::Const(0)),
                },
            ],
        };
        let mut types = TypeMap::default();
        types.upsert_public(
            VReg::phys("local_100"),
            TypeHint::Pointer { pointee_width: 4 },
        );
        types.upsert_public(
            VReg::phys("local_140"),
            TypeHint::Pointer { pointee_width: 4 },
        );

        let text = render_decbench_typed(&function, Some(&types), None);

        assert!(text.contains("unsigned char local_100[12];"), "{text}");
        assert!(
            text.contains("int * local_140 = (int *)local_100;")
                || text.contains("int * local_140 = (int *)&local_100[0];")
                || text.contains("int * local_140 = (int *)(&local_100[0]);"),
            "the stack object's concrete byte-array declaration requires an explicit typed-pointer conversion:\n{text}"
        );
        assert_looks_like_c(&text);
    }

    #[test]
    fn decbench_casted_select_converts_pointer_and_integer_arms_before_selection() {
        let function = Function {
            name: "choose_path".to_string(),
            entry_va: 0x60,
            body: vec![Stmt::Assign {
                dst: VReg::phys("var0"),
                src: Expr::Cast {
                    signed: true,
                    width: 8,
                    expr: Box::new(Expr::Cast {
                        signed: true,
                        width: 8,
                        expr: Box::new(Expr::Select {
                            cond: Box::new(Expr::Reg(VReg::phys("zf_0"))),
                            if_true: Box::new(Expr::Bin {
                                op: BinOp::Add,
                                lhs: Box::new(Expr::Reg(VReg::phys("var154"))),
                                rhs: Box::new(Expr::Const(1)),
                            }),
                            if_false: Box::new(Expr::Reg(VReg::phys("local_2088"))),
                            width: 8,
                        }),
                    }),
                },
            }],
        };
        let mut types = TypeMap::default();
        types.upsert_public(VReg::phys("var154"), TypeHint::Pointer { pointee_width: 1 });

        let text = render_decbench_typed(&function, Some(&types), None);

        assert!(text.contains("char * var154;"), "{text}");
        assert!(
            text.contains("? (long)(var154 + 1) : local_2088")
                || text.contains("? (long)((var154 + 1)) : local_2088"),
            "C type-checks conditional arms before an outer cast, so the pointer arm must cross the representation boundary inside the select:\n{text}"
        );
        assert_looks_like_c(&text);
    }

    #[test]
    fn decbench_stack_address_reclassified_as_argument_stays_a_pointer_value() {
        let f = Function {
            name: "consume_reclassified_address".to_string(),
            entry_va: 0x20,
            body: vec![Stmt::Call {
                target: Expr::Named {
                    va: 0x1000,
                    name: "consume".to_string(),
                },
                args: vec![Expr::StackAddr {
                    object: VReg::phys("arg3"),
                    size: 8,
                }],
                dst: None,
                call_spec: None,
            }],
        };

        let text = render_decbench(&f);
        assert!(
            text.contains("consume((void *)(arg3));"),
            "a reclassified address must not subscript a scalar argument:\n{text}"
        );
        assert!(!text.contains("&arg3[0]"), "{text}");
    }

    #[test]
    fn decbench_unknown_and_indirect_call_are_valid_c() {
        let f = Function {
            name: "u".to_string(),
            entry_va: 0x30,
            body: vec![
                Stmt::Unknown("cpuid".to_string()),
                Stmt::Assign {
                    dst: VReg::phys("var0"),
                    src: Expr::Unknown("rax".to_string()),
                },
                Stmt::Call {
                    target: Expr::Reg(VReg::phys("var0")),
                    args: vec![Expr::Reg(VReg::phys("arg0"))],
                    dst: None,
                    call_spec: None,
                },
                Stmt::Call {
                    target: Expr::Reg(VReg::phys("var0")),
                    args: vec![],
                    dst: None,
                    call_spec: None,
                },
            ],
        };
        let text = dec_pipeline(&f);
        assert!(text.contains("/* asm: cpuid */"), "unknown stmt:\n{}", text);
        assert!(
            text.contains("extern long __unknown(long, ...);"),
            "unknown values need a C23-compatible helper prototype:\n{text}"
        );
        // Unknown/poison values are deliberately not propagated: keeping the
        // assignment rooted preserves the visible undefined-value boundary.
        assert!(
            text.contains("var0 = __unknown(0);")
                && text.contains("((void (*)(long))(var0))(arg0);")
                && text.contains("((void (*)(void))(var0))();")
                && !text.contains("(*)()"),
            "indirect call:\n{}",
            text
        );
        assert_looks_like_c(&text);
    }

    #[test]
    fn x86_wide_arithmetic_intrinsics_lower_to_executable_int128_c() {
        let cases = [
            (
                "x86.smul_hi.64",
                vec![
                    Value::Reg(VReg::phys("arg0")),
                    Value::Reg(VReg::phys("arg1")),
                ],
                "unsigned __int128",
            ),
            (
                "x86.sdiv_rem.64",
                vec![
                    Value::Reg(VReg::phys("arg0")),
                    Value::Reg(VReg::phys("arg1")),
                    Value::Reg(VReg::phys("arg2")),
                ],
                "%",
            ),
            (
                "x86.udiv_rem.64",
                vec![
                    Value::Reg(VReg::phys("arg0")),
                    Value::Reg(VReg::phys("arg1")),
                    Value::Reg(VReg::phys("arg2")),
                ],
                "unsigned __int128",
            ),
        ];
        for (name, ins, expected) in cases {
            let statements = lower_op(
                &Op::Intrinsic {
                    name: name.to_string(),
                    ins,
                    outs: vec![(VReg::phys("ret"), crate::ir::types::Width::W64)],
                    reads_mem: false,
                    writes_mem: false,
                },
                false,
            );
            assert!(matches!(
                statements.as_slice(),
                [Stmt::Assign {
                    src: Expr::WideArithmetic { width: 8, .. },
                    ..
                }]
            ));
            let function = Function {
                name: "wide".to_string(),
                entry_va: 0x10,
                body: statements,
            };
            let text = render_decbench(&function);
            assert!(
                text.contains(expected),
                "{name} did not retain exact wide semantics:\n{text}"
            );
            assert_looks_like_c(&text);
        }
    }

    #[test]
    fn conditional_return_lowers_to_an_if_with_no_invented_goto() {
        let statements = lower_op(
            &Op::CondReturn {
                cond: VReg::Flag(Flag::Z),
                inverted: true,
            },
            false,
        );
        assert!(matches!(
            statements.as_slice(),
            [Stmt::If {
                cond: Expr::Cmp {
                    op: CmpOp::Eq,
                    lhs,
                    rhs,
                },
                then_body,
                else_body: None,
            }] if **lhs == Expr::Reg(VReg::Flag(Flag::Z))
                && **rhs == Expr::Const(0)
                && then_body == &[Stmt::Return { value: None }]
        ));
    }

    #[test]
    fn conditional_store_lowers_the_memory_effect_inside_the_if() {
        let statements = lower_op(
            &Op::CondStore {
                cond: VReg::Flag(Flag::Z),
                inverted: false,
                addr: MemOp::plain(Some(VReg::phys("arg0")), None, 1, 0, 4),
                src: Value::Reg(VReg::phys("arg2")),
            },
            false,
        );
        assert!(matches!(
            statements.as_slice(),
            [Stmt::If {
                cond: Expr::Reg(VReg::Flag(Flag::Z)),
                then_body,
                else_body: None,
            }] if matches!(then_body.as_slice(), [Stmt::Store { size: 4, .. }])
        ));
    }

    #[test]
    fn conditional_load_lowers_the_dereference_inside_a_lazy_select() {
        let statements = lower_op(
            &Op::CondLoad {
                dst: VReg::phys("r1"),
                cond: VReg::Flag(Flag::Z),
                inverted: true,
                addr: MemOp::plain(Some(VReg::phys("r2")), None, 1, -4, 4),
                fallback: Value::Reg(VReg::phys("r1")),
            },
            false,
        );
        assert!(matches!(
            statements.as_slice(),
            [Stmt::Assign {
                dst,
                src: Expr::Select {
                    cond,
                    if_true,
                    if_false,
                    width: 4,
                },
            }] if *dst == VReg::phys("r1")
                && matches!(**cond, Expr::Cmp { op: CmpOp::Eq, .. })
                && matches!(**if_true, Expr::Deref { size: 4, .. })
                && **if_false == Expr::Reg(VReg::phys("r1"))
        ));
    }

    #[test]
    fn x86_bswap_intrinsics_lower_to_executable_byte_reversal() {
        for (width, ctype, highest_shift) in [
            (Width::W32, "unsigned int", 24),
            (Width::W64, "unsigned long", 56),
        ] {
            let statements = lower_op(
                &Op::Intrinsic {
                    name: "bswap".to_string(),
                    ins: vec![Value::Reg(VReg::phys("arg0"))],
                    outs: vec![(VReg::phys("ret"), width)],
                    reads_mem: false,
                    writes_mem: false,
                },
                false,
            );
            assert!(matches!(
                statements.as_slice(),
                [Stmt::Assign {
                    dst,
                    src: Expr::Cast { signed: false, width: got_width, .. },
                }] if dst == &VReg::phys("ret") && *got_width == width.bytes() as u8
            ));
            let function = Function {
                name: "swap".to_string(),
                entry_va: 0x10,
                body: statements,
            };
            let text = render_decbench(&function);
            assert!(
                text.contains(ctype),
                "{width:?} lost its unsigned width:\n{text}"
            );
            assert!(
                text.contains(&format!("<< {highest_shift}")),
                "{width:?} did not reverse the low byte into the high byte:\n{text}"
            );
            assert!(!text.contains("asm: bswap"), "{text}");
            assert_looks_like_c(&text);
        }
    }

    #[test]
    fn packed_signed_shift_guards_both_c_shift_directions() {
        let statements = lower_op(
            &Op::Intrinsic {
                name: "packed_signed_shift_u32".to_string(),
                ins: vec![
                    Value::Reg(VReg::phys("arg0")),
                    Value::Reg(VReg::phys("arg1")),
                ],
                outs: vec![(VReg::phys("ret"), Width::W32)],
                reads_mem: false,
                writes_mem: false,
            },
            false,
        );
        let function = Function {
            name: "shift_lane".to_string(),
            entry_va: 0x10,
            body: statements,
        };
        let text = render_decbench(&function);
        assert!(text.contains("(int)(arg1) < 0"), "{text}");
        assert!(
            text.contains("32") && text.matches("? 0 :").count() == 2,
            "{text}"
        );
        assert!(text.contains(">>") && text.contains("<<"), "{text}");
        assert_looks_like_c(&text);
    }

    #[test]
    fn halfword_lane_byte_swap_intrinsic_lowers_to_executable_c() {
        let statements = lower_op(
            &Op::Intrinsic {
                name: "byte_swap_16_lanes".to_string(),
                ins: vec![Value::Reg(VReg::phys("arg0"))],
                outs: vec![(VReg::phys("ret"), Width::W32)],
                reads_mem: false,
                writes_mem: false,
            },
            false,
        );
        assert!(matches!(
            statements.as_slice(),
            [Stmt::Assign {
                dst,
                src: Expr::Cast {
                    signed: false,
                    width: 4,
                    ..
                },
            }] if dst == &VReg::phys("ret")
        ));
        let function = Function {
            name: "swap_halfwords".to_string(),
            entry_va: 0x10,
            body: statements,
        };
        let text = render_decbench(&function);
        assert!(
            text.contains("<< 8"),
            "low bytes were not exchanged: {text}"
        );
        assert!(
            text.contains(">> 8"),
            "high bytes were not exchanged: {text}"
        );
        assert!(!text.contains("asm: rev16"), "{text}");
        assert_looks_like_c(&text);
    }

    #[test]
    fn arithmetic_right_shift_keeps_its_signed_machine_width() {
        let statements = lower_op(
            &Op::Bin {
                dst: VReg::phys("edx"),
                op: BinOp::Sar,
                lhs: Value::Reg(VReg::phys("eax")),
                rhs: Value::Const(31),
            },
            false,
        );
        assert!(matches!(
            statements.as_slice(),
            [Stmt::Assign {
                src: Expr::Bin {
                    op: BinOp::Sar,
                    lhs,
                    rhs,
                },
                ..
            }] if matches!(
                lhs.as_ref(),
                Expr::Cast {
                    signed: true,
                    width: 4,
                    expr,
                } if matches!(expr.as_ref(), Expr::Reg(reg) if reg == &VReg::phys("eax"))
            ) && matches!(rhs.as_ref(), Expr::Const(31))
        ));

        let nested = Expr::Cast {
            signed: true,
            width: 8,
            expr: Box::new(Expr::Cast {
                signed: true,
                width: 4,
                expr: Box::new(Expr::Reg(VReg::phys("var0"))),
            }),
        };
        let (ctype32, operand32) = signed_shift_operand(&nested, &Expr::Const(31));
        assert_eq!(ctype32, "int");
        assert_eq!(operand32, &Expr::Reg(VReg::phys("var0")));
        let (ctype64, _) = signed_shift_operand(&nested, &Expr::Const(63));
        assert_eq!(ctype64, "long");
    }

    /// An `Expr::Cast` states a machine width exactly — it *is* the extension
    /// or truncation the machine performed — so `expr_machine_width` must read
    /// it rather than fall through to the eight-byte default.
    ///
    /// Reading past it is how ARM32's `-O0` signed divide-by-two lost its sign
    /// bias: `lsr r2, r3, #31` over a sign-extended byte is `Shr((int)((signed
    /// char)x), 31)` in the AST, and answering `None` here spelled it
    /// `(unsigned long long)(x) >> 31`, which is `0x1ffffffff` for a negative
    /// byte instead of `1`.
    #[test]
    fn a_cast_states_the_machine_width_of_the_expression_it_wraps() {
        let byte_in_a_word = Expr::Cast {
            signed: true,
            width: 4,
            expr: Box::new(Expr::Cast {
                signed: true,
                width: 1,
                expr: Box::new(Expr::Reg(VReg::phys("narrowed"))),
            }),
        };
        assert_eq!(expr_machine_width(&byte_in_a_word), Some(4));

        // The nearest cast wins, not the widest one anywhere in the chain.
        assert_eq!(
            expr_machine_width(&Expr::Cast {
                signed: false,
                width: 2,
                expr: Box::new(byte_in_a_word.clone()),
            }),
            Some(2)
        );

        // A cast is width-preserving arithmetic's operand like any other, so
        // `(int)x + 1` is four bytes wide rather than unknown.
        assert_eq!(
            expr_machine_width(&Expr::Bin {
                op: BinOp::Add,
                lhs: Box::new(byte_in_a_word),
                rhs: Box::new(Expr::Const(1)),
            }),
            Some(4)
        );

        // A width with no C integer spelling (a 16-byte aggregate transport)
        // must stay unknown: both shift renderers turn this number straight
        // into a cast, and `int_ctype(_, 16)` is `long`.
        assert_eq!(
            expr_machine_width(&Expr::Cast {
                signed: true,
                width: 16,
                expr: Box::new(Expr::Reg(VReg::phys("pair"))),
            }),
            None
        );
    }

    #[test]
    fn decbench_undefined_goto_target_gets_trailing_label() {
        let f = Function {
            name: "g".to_string(),
            entry_va: 0x40,
            body: vec![Stmt::Goto { target: 0x44 }],
        };
        let text = render_decbench(&f);
        assert!(text.contains("goto L_44;"), "goto:\n{}", text);
        assert!(
            text.contains("L_44: ;"),
            "missing trailing label for undefined goto:\n{}",
            text
        );
        assert_looks_like_c(&text);
    }

    #[test]
    fn decbench_sanitizes_plt_style_function_name() {
        let f = Function {
            name: "printf@plt".to_string(),
            entry_va: 0x50,
            body: vec![Stmt::Return { value: None }],
        };
        let text = render_decbench(&f);
        assert!(
            text.contains("long printf_plt(void) {"),
            "name not sanitized:\n{}",
            text
        );
        assert!(text.contains("return 0;"), "void return:\n{}", text);
        assert_looks_like_c(&text);
    }

    #[test]
    fn decbench_cast_preserves_extension_width_and_sign() {
        // A width/sign cast must render as `(ctype)(expr)`, preserving the
        // extension semantics that a bare `dst = src` would lose.
        let f = Function {
            name: "ext".to_string(),
            entry_va: 0x10,
            body: vec![
                // sign-extend from 8 bits: (signed char)(arg0)
                Stmt::Assign {
                    dst: VReg::phys("local_4"),
                    src: Expr::Cast {
                        signed: true,
                        width: 1,
                        expr: Box::new(Expr::Reg(VReg::phys("arg0"))),
                    },
                },
                // zero-extend from 32 bits: (unsigned int)(arg1)
                Stmt::Assign {
                    dst: VReg::phys("local_8"),
                    src: Expr::Cast {
                        signed: false,
                        width: 4,
                        expr: Box::new(Expr::Reg(VReg::phys("arg1"))),
                    },
                },
            ],
        };
        let text = render_decbench(&f);
        assert!(
            text.contains("(signed char)(arg0)"),
            "sign cast not rendered:\n{}",
            text
        );
        assert!(
            text.contains("(unsigned int)(arg1)"),
            "zero-extend cast not rendered:\n{}",
            text
        );
        assert_looks_like_c(&text);
    }

    #[test]
    fn decbench_shifts_and_unsigned_compares_are_valid_c() {
        let f = Function {
            name: "sh".to_string(),
            entry_va: 0x70,
            body: vec![
                Stmt::Assign {
                    dst: VReg::phys("var0"),
                    src: Expr::Bin {
                        op: BinOp::Sar,
                        lhs: Box::new(Expr::Reg(VReg::phys("arg0"))),
                        rhs: Box::new(Expr::Const(3)),
                    },
                },
                Stmt::Assign {
                    dst: VReg::phys("var1"),
                    src: Expr::Bin {
                        op: BinOp::Shr,
                        lhs: Box::new(Expr::Reg(VReg::phys("arg0"))),
                        rhs: Box::new(Expr::Const(1)),
                    },
                },
                Stmt::Assign {
                    dst: VReg::Flag(Flag::C),
                    src: Expr::Cmp {
                        op: CmpOp::Ult,
                        lhs: Box::new(Expr::Reg(VReg::phys("arg0"))),
                        rhs: Box::new(Expr::Const(10)),
                    },
                },
                // Use var0/var1 twice each so they survive DCE as declared locals.
                Stmt::Return {
                    value: Some(Expr::Bin {
                        op: BinOp::Add,
                        lhs: Box::new(Expr::Bin {
                            op: BinOp::Mul,
                            lhs: Box::new(Expr::Reg(VReg::phys("var0"))),
                            rhs: Box::new(Expr::Reg(VReg::phys("var0"))),
                        }),
                        rhs: Box::new(Expr::Bin {
                            op: BinOp::Mul,
                            lhs: Box::new(Expr::Reg(VReg::phys("var1"))),
                            rhs: Box::new(Expr::Reg(VReg::phys("var1"))),
                        }),
                    }),
                },
            ],
        };
        let text = render_decbench(&f);
        assert!(!text.contains(">>>"), "arithmetic shift not C:\n{}", text);
        assert!(!text.contains("u<"), "unsigned cmp not C:\n{}", text);
        assert!(
            text.contains("var0 = ((long)(arg0) >> 3);"),
            "sar must state its signed machine width:\n{}",
            text
        );
        assert!(
            text.contains("(unsigned long)(arg0) >> 1"),
            "logical shift cast:\n{}",
            text
        );
        assert!(
            text.contains("(unsigned long)(arg0) < (unsigned long)(10)"),
            "unsigned cmp cast:\n{}",
            text
        );
        assert_looks_like_c(&text);
    }

    #[test]
    fn decbench_logical_shift_uses_the_exact_load_width() {
        let f = Function {
            name: "shift_loaded_word".to_string(),
            entry_va: 0x74,
            body: vec![Stmt::Return {
                value: Some(Expr::Bin {
                    op: BinOp::Shr,
                    lhs: Box::new(Expr::Deref {
                        addr: Box::new(Expr::Reg(VReg::phys("arg0"))),
                        size: 4,
                    }),
                    rhs: Box::new(Expr::Const(8)),
                }),
            }],
        };

        let text = render_decbench(&f);

        assert!(
            text.contains("(unsigned int)(*(int *)(arg0)) >> 8"),
            "a four-byte load must not be sign-extended to host unsigned long:\n{text}"
        );
    }

    #[test]
    fn decbench_i64_min_constants_do_not_overflow() {
        // Regression: negating i64::MIN to render `-0x...` panicked
        // ("attempt to negate with overflow"). Constants and displacements at
        // the extreme must render (as their unsigned magnitude) across all
        // renderers, not abort the whole batch.
        let f = Function {
            name: "m".to_string(),
            entry_va: 0x80,
            body: vec![
                Stmt::Assign {
                    dst: VReg::phys("var0"),
                    src: Expr::Const(i64::MIN),
                },
                Stmt::Assign {
                    dst: VReg::phys("var1"),
                    src: Expr::Bin {
                        op: BinOp::Add,
                        lhs: Box::new(Expr::Reg(VReg::phys("arg0"))),
                        rhs: Box::new(Expr::Const(i64::MIN)),
                    },
                },
                Stmt::Store {
                    addr: Expr::Lea {
                        base: Some(VReg::phys("rbp")),
                        index: None,
                        scale: 1,
                        disp: i64::MIN,
                        segment: None,
                    },
                    src: Expr::Reg(VReg::phys("arg0")),
                    size: 8,
                },
            ],
        };
        // Must not panic in any renderer.
        let _ = render(&f);
        let _ = render_c(&f);
        let text = render_decbench(&f);
        assert!(
            text.contains("0x8000000000000000"),
            "i64::MIN magnitude missing:\n{}",
            text
        );
        assert_looks_like_c(&text);
    }

    #[test]
    fn decbench_switch_folds_default_and_dedups_cases() {
        let f = Function {
            name: "sw".to_string(),
            entry_va: 0x60,
            body: vec![Stmt::Switch {
                discriminant: Expr::Reg(VReg::phys("arg0")),
                cases: vec![
                    (
                        Some(0),
                        vec![Stmt::Return {
                            value: Some(Expr::Const(1)),
                        }],
                    ),
                    // Unlabelled arm -> folded into default.
                    (
                        None,
                        vec![Stmt::Return {
                            value: Some(Expr::Const(2)),
                        }],
                    ),
                ],
                default: Some(vec![Stmt::Return {
                    value: Some(Expr::Const(3)),
                }]),
            }],
        };
        let text = render_decbench(&f);
        assert!(text.contains("case 0:"), "case:\n{}", text);
        assert!(!text.contains("case _:"), "illegal case _::\n{}", text);
        // Exactly one default block.
        assert_eq!(
            text.matches("default:").count(),
            1,
            "expected a single default:\n{}",
            text
        );
        assert!(
            !text.contains("return 1;\n            break;")
                && !text.contains("return 3;\n            break;"),
            "terminal returns must not be followed by dead breaks:\n{text}"
        );
        assert_looks_like_c(&text);
    }

    #[test]
    fn decbench_switch_prints_shared_case_body_once_with_all_labels() {
        let shared = vec![Stmt::Return {
            value: Some(Expr::Const(20)),
        }];
        let f = Function {
            name: "shared_switch".to_string(),
            entry_va: 0x70,
            body: vec![Stmt::Switch {
                discriminant: Expr::Reg(VReg::phys("arg0")),
                cases: vec![
                    (Some(2), shared.clone()),
                    (Some(5), shared),
                    (
                        Some(6),
                        vec![Stmt::Return {
                            value: Some(Expr::Const(60)),
                        }],
                    ),
                ],
                default: None,
            }],
        };

        let text = render_decbench(&f);
        assert!(text.contains("case 2:"), "{text}");
        assert!(text.contains("case 5:"), "{text}");
        assert_eq!(
            text.matches("return 20;").count(),
            1,
            "equal destinations should render as stacked labels over one body:\n{text}"
        );
        assert_looks_like_c(&text);
    }

    #[test]
    fn prepare_turns_an_exhaustive_switch_result_join_into_case_returns() {
        let result = VReg::phys("local_4");
        let cases = vec![
            (
                Some(0),
                vec![Stmt::Assign {
                    dst: result.clone(),
                    src: Expr::Const(10),
                }],
            ),
            (
                Some(1),
                vec![
                    Stmt::Assign {
                        dst: result.clone(),
                        src: Expr::Const(11),
                    },
                    Stmt::Break,
                ],
            ),
        ];
        let f = Function {
            name: "dispatch".to_string(),
            entry_va: 0,
            body: vec![
                Stmt::Switch {
                    discriminant: Expr::Reg(VReg::phys("arg0")),
                    cases,
                    default: Some(vec![Stmt::Assign {
                        dst: result.clone(),
                        src: Expr::Const(-1),
                    }]),
                },
                Stmt::Return {
                    value: Some(Expr::Reg(result)),
                },
            ],
        };

        let prepared = prepare_for_decbench(&f);

        assert_eq!(prepared.body.len(), 1, "{:#?}", prepared.body);
        let Stmt::Switch { cases, default, .. } = &prepared.body[0] else {
            panic!("expected one exhaustive switch: {:#?}", prepared.body)
        };
        assert!(
            cases
                .iter()
                .all(|(_, body)| matches!(body.last(), Some(Stmt::Return { value: Some(_) }))),
            "{cases:#?}"
        );
        assert!(
            matches!(
                default.as_deref().and_then(<[Stmt]>::last),
                Some(Stmt::Return {
                    value: Some(Expr::Const(-1))
                })
            ),
            "{default:#?}"
        );
    }

    #[test]
    fn prepare_turns_a_nested_exhaustive_if_result_join_into_direct_returns() {
        let result = VReg::phys("local_8");
        let inner = Stmt::If {
            cond: Expr::Reg(VReg::phys("arg1")),
            then_body: vec![
                Stmt::Call {
                    target: Expr::Named {
                        va: 0x1000,
                        name: "recursive".into(),
                    },
                    args: vec![Expr::Const(20)],
                    dst: Some(VReg::phys("var1")),
                    call_spec: None,
                },
                Stmt::Assign {
                    dst: result.clone(),
                    src: Expr::Reg(VReg::phys("var1")),
                },
            ],
            else_body: Some(vec![
                Stmt::Call {
                    target: Expr::Named {
                        va: 0x1000,
                        name: "recursive".into(),
                    },
                    args: vec![Expr::Const(30)],
                    dst: Some(VReg::phys("var2")),
                    call_spec: None,
                },
                Stmt::Assign {
                    dst: result.clone(),
                    src: Expr::Reg(VReg::phys("var2")),
                },
            ]),
        };
        let f = Function {
            name: "recursive".into(),
            entry_va: 0,
            body: vec![
                Stmt::If {
                    cond: Expr::Reg(VReg::phys("arg0")),
                    then_body: vec![
                        Stmt::Call {
                            target: Expr::Named {
                                va: 0x1000,
                                name: "recursive".into(),
                            },
                            args: vec![Expr::Reg(VReg::phys("arg0"))],
                            dst: Some(VReg::phys("var0")),
                            call_spec: None,
                        },
                        inner,
                    ],
                    else_body: Some(vec![Stmt::Assign {
                        dst: result.clone(),
                        src: Expr::Const(10),
                    }]),
                },
                Stmt::Comment("x86-64 epilogue: restore rbp".into()),
                Stmt::Return {
                    value: Some(Expr::Reg(result)),
                },
            ],
        };

        let prepared = prepare_for_decbench(&f);

        assert_eq!(
            prepared.body.len(),
            1,
            "joined return survived: {:#?}",
            prepared.body
        );
        let Stmt::If {
            then_body,
            else_body: Some(else_body),
            ..
        } = &prepared.body[0]
        else {
            panic!("expected exhaustive if: {:#?}", prepared.body)
        };
        assert!(matches!(
            else_body.last(),
            Some(Stmt::Return { value: Some(_) })
        ));
        let Some(Stmt::If {
            then_body: inner_then,
            else_body: Some(inner_else),
            ..
        }) = then_body.last()
        else {
            panic!("expected nested exhaustive if: {then_body:#?}")
        };
        assert!(matches!(
            inner_then.last(),
            Some(Stmt::Return { value: Some(_) })
        ));
        assert!(matches!(
            inner_else.last(),
            Some(Stmt::Return { value: Some(_) })
        ));
    }

    #[test]
    fn prepare_recovers_one_early_return_from_a_partial_result_join() {
        let result = VReg::phys("ret");
        let f = Function {
            name: "peek_string".into(),
            entry_va: 0,
            body: vec![
                Stmt::If {
                    cond: Expr::Reg(VReg::phys("too_large")),
                    then_body: vec![Stmt::Assign {
                        dst: result.clone(),
                        src: Expr::Const(-6),
                    }],
                    else_body: Some(vec![
                        Stmt::Call {
                            target: Expr::Named {
                                va: 0x1000,
                                name: "validate_length".into(),
                            },
                            args: Vec::new(),
                            dst: Some(VReg::phys("checked")),
                            call_spec: None,
                        },
                        Stmt::Assign {
                            dst: result.clone(),
                            src: Expr::Const(0),
                        },
                        Stmt::If {
                            cond: Expr::Reg(VReg::phys("lenp")),
                            then_body: vec![Stmt::Store {
                                addr: Expr::Reg(VReg::phys("lenp")),
                                src: Expr::Const(4),
                                size: 8,
                            }],
                            else_body: None,
                        },
                    ]),
                },
                Stmt::Return {
                    value: Some(Expr::Reg(result)),
                },
            ],
        };

        let prepared = prepare_for_decbench(&f);

        let Stmt::If {
            then_body,
            else_body,
            ..
        } = &prepared.body[0]
        else {
            panic!("expected the leading guard: {:#?}", prepared.body)
        };
        assert!(
            else_body.is_none(),
            "fallthrough stayed nested: {prepared:#?}"
        );
        assert_eq!(
            then_body,
            &vec![Stmt::Return {
                value: Some(Expr::Const(-6))
            }],
            "the joined result should become its source-level early return"
        );
        assert!(
            matches!(
                prepared.body.get(1),
                Some(Stmt::Call {
                    target: Expr::Named { name, .. },
                    ..
                }) if name == "validate_length"
            ),
            "the false path should become ordinary fallthrough: {:#?}",
            prepared.body
        );
        assert!(matches!(prepared.body.last(), Some(Stmt::Return { .. })));
    }

    #[test]
    fn prepare_keeps_a_nonterminal_partial_result_join_nested() {
        let result = VReg::phys("ret");
        let f = Function {
            name: "effect_after_result".into(),
            entry_va: 0,
            body: vec![
                Stmt::If {
                    cond: Expr::Reg(VReg::phys("guard")),
                    then_body: vec![
                        Stmt::Assign {
                            dst: result.clone(),
                            src: Expr::Const(-6),
                        },
                        Stmt::Call {
                            target: Expr::Named {
                                va: 0x1000,
                                name: "observe_result".into(),
                            },
                            args: Vec::new(),
                            dst: None,
                            call_spec: None,
                        },
                    ],
                    else_body: Some(vec![Stmt::Assign {
                        dst: result.clone(),
                        src: Expr::Const(0),
                    }]),
                },
                Stmt::Return {
                    value: Some(Expr::Reg(result)),
                },
            ],
        };

        let prepared = prepare_for_decbench(&f);

        let Stmt::If {
            then_body,
            else_body,
            ..
        } = &prepared.body[0]
        else {
            panic!("expected the original conditional: {:#?}", prepared.body)
        };
        assert!(
            else_body.is_some(),
            "a nonterminal result definition must not become an early return: {prepared:#?}"
        );
        assert!(matches!(then_body.last(), Some(Stmt::Call { .. })));
        assert!(matches!(prepared.body.last(), Some(Stmt::Return { .. })));
    }

    #[test]
    fn prepare_carries_a_lossless_join_cast_into_exhaustive_switch_returns() {
        let result = VReg::phys("local_4");
        let ret = VReg::phys("ret");
        let f = Function {
            name: "dispatch".to_string(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: ret.clone(),
                    src: Expr::Cast {
                        signed: false,
                        width: 8,
                        expr: Box::new(Expr::Cast {
                            signed: false,
                            width: 4,
                            expr: Box::new(Expr::Reg(VReg::phys("arg0"))),
                        }),
                    },
                },
                Stmt::Switch {
                    discriminant: Expr::Reg(ret.clone()),
                    cases: vec![(
                        Some(0),
                        vec![Stmt::Assign {
                            dst: result.clone(),
                            src: Expr::Const(10),
                        }],
                    )],
                    default: Some(vec![Stmt::Assign {
                        dst: result.clone(),
                        src: Expr::Const(-1),
                    }]),
                },
                Stmt::Assign {
                    dst: ret.clone(),
                    src: Expr::Cast {
                        signed: false,
                        width: 8,
                        expr: Box::new(Expr::Cast {
                            signed: false,
                            width: 4,
                            expr: Box::new(Expr::Reg(result)),
                        }),
                    },
                },
                Stmt::Comment("x86-64 epilogue: restore rbp".to_string()),
                Stmt::Return {
                    value: Some(Expr::Reg(ret)),
                },
            ],
        };

        let prepared = prepare_for_decbench(&f);

        let switch_index = prepared
            .body
            .iter()
            .position(|statement| matches!(statement, Stmt::Switch { .. }))
            .expect("expected exhaustive switch");
        assert!(
            prepared.body[switch_index + 1..]
                .iter()
                .all(|statement| matches!(statement, Stmt::Comment(_))),
            "{:#?}",
            prepared.body
        );
        let Stmt::Switch { cases, default, .. } = &prepared.body[switch_index] else {
            panic!("expected one exhaustive switch: {:#?}", prepared.body)
        };
        for arm in cases.iter().map(|(_, body)| body).chain(default.iter()) {
            assert!(matches!(
                arm.last(),
                Some(Stmt::Return {
                    value: Some(Expr::Cast { width: 8, .. })
                })
            ));
        }
    }

    #[test]
    fn prepare_keeps_switch_result_join_when_an_arm_defines_another_value() {
        let result = VReg::phys("local_4");
        let original_body = vec![
            Stmt::Switch {
                discriminant: Expr::Reg(VReg::phys("arg0")),
                cases: vec![(
                    Some(0),
                    vec![Stmt::Assign {
                        dst: result.clone(),
                        src: Expr::Const(10),
                    }],
                )],
                default: Some(vec![Stmt::Assign {
                    dst: VReg::phys("different_result"),
                    src: Expr::Const(-1),
                }]),
            },
            Stmt::Return {
                value: Some(Expr::Reg(result.clone())),
            },
        ];
        let f = Function {
            name: "partial_result".to_string(),
            entry_va: 0,
            body: original_body.clone(),
        };

        let prepared = prepare_for_decbench(&f);

        assert_eq!(prepared.body.len(), 2, "{:#?}", prepared.body);
        assert!(matches!(
            prepared.body.last(),
            Some(Stmt::Return {
                value: Some(Expr::Reg(reg))
            }) if reg == &result
        ));
        let Stmt::Switch { cases, .. } = &prepared.body[0] else {
            panic!("expected switch-result join: {:#?}", prepared.body)
        };
        assert!(matches!(
            cases[0].1.last(),
            Some(Stmt::Assign { dst, .. }) if dst == &result
        ));
    }

    #[test]
    fn prepare_keeps_switch_result_join_without_an_explicit_default() {
        let result = VReg::phys("local_4");
        let original_body = vec![
            Stmt::Switch {
                discriminant: Expr::Reg(VReg::phys("arg0")),
                cases: vec![(
                    Some(0),
                    vec![Stmt::Assign {
                        dst: result.clone(),
                        src: Expr::Const(10),
                    }],
                )],
                default: None,
            },
            Stmt::Return {
                value: Some(Expr::Reg(result)),
            },
        ];
        let f = Function {
            name: "non_exhaustive_result".to_string(),
            entry_va: 0,
            body: original_body.clone(),
        };

        let prepared = prepare_for_decbench(&f);

        assert_eq!(prepared.body, original_body);
    }

    #[test]
    fn decbench_select_inside_switch_keeps_expression_semantics() {
        let f = Function {
            name: "select_case".to_string(),
            entry_va: 0x60,
            body: vec![Stmt::Switch {
                discriminant: Expr::Reg(VReg::phys("arg0")),
                cases: vec![(
                    Some(0),
                    vec![Stmt::Assign {
                        dst: VReg::phys("ret"),
                        src: Expr::Select {
                            cond: Box::new(Expr::Reg(VReg::phys("arg1"))),
                            if_true: Box::new(Expr::Const(1)),
                            if_false: Box::new(Expr::Const(0)),
                            width: 4,
                        },
                    }],
                )],
                default: None,
            }],
        };

        let text = render_decbench(&f);

        assert!(text.contains("ret = (arg1 ? 1 : 0);"), "{text}");
        assert!(!text.contains("if (arg1)"), "{text}");
        assert_looks_like_c(&text);
    }

    /// A stub is recorded as `foo@plt` because that is what it is, but a call
    /// EXPRESSION must name the function: `foo@plt` sanitises to `foo_plt`, which
    /// nothing declares, so the emitted C would not link.
    #[test]
    fn a_plt_stub_is_called_by_the_name_it_forwards_to() {
        let f = Function {
            name: "caller".to_string(),
            entry_va: 0x1000,
            body: vec![Stmt::Call {
                target: Expr::Named {
                    va: 0x10a0,
                    name: "signed_step@plt".to_string(),
                },
                args: vec![Expr::Reg(VReg::phys("arg0"))],
                dst: Some(VReg::phys("ret")),
                call_spec: None,
            }],
        };
        let out = render_decbench(&f);
        assert!(
            out.contains("signed_step(arg0)"),
            "expected a call to `signed_step`:\n{out}"
        );
        assert!(
            !out.contains("signed_step_plt"),
            "the @plt stub name must not be called:\n{out}"
        );
    }

    /// A plain name is untouched — only the `@`-suffixed stub spelling is trimmed.
    #[test]
    fn a_plain_callee_name_is_unchanged() {
        assert_eq!(callee_display_name("memcpy"), "memcpy");
        assert_eq!(callee_display_name("signed_step@plt"), "signed_step");
        assert_eq!(callee_display_name("foo@GLIBC_2.2.5"), "foo");
    }

    /// `call_forward_result`: the argument is reconstructed correctly (the
    /// register-style render shows `call signed_step@plt(%ret)`) and then
    /// disappears on the decbench path, so the emitted C calls `signed_step()`
    /// with no arguments at all.
    #[test]
    fn preparing_for_decbench_keeps_call_arguments() {
        let f = Function {
            name: "call_forward_result".to_string(),
            entry_va: 0x1416,
            body: vec![
                Stmt::Store {
                    addr: Expr::Reg(VReg::phys("local_4")),
                    src: Expr::Reg(VReg::phys("arg0")),
                    size: 4,
                },
                Stmt::Assign {
                    dst: VReg::phys("ret"),
                    src: Expr::Reg(VReg::phys("local_4")),
                },
                Stmt::Call {
                    target: Expr::Named {
                        va: 0x10a0,
                        name: "signed_step@plt".to_string(),
                    },
                    args: vec![Expr::Reg(VReg::phys("ret"))],
                    dst: Some(VReg::phys("ret")),
                    call_spec: None,
                },
                Stmt::Return {
                    value: Some(Expr::Reg(VReg::phys("ret"))),
                },
            ],
        };
        let prepared = prepare_for_decbench(&f);
        let call = prepared
            .body
            .iter()
            .find_map(|s| match s {
                Stmt::Call { args, .. } => Some(args.clone()),
                Stmt::Return {
                    value: Some(Expr::Call { args, .. }),
                } => Some(args.clone()),
                _ => None,
            })
            .expect("the call expression must survive preparation");
        assert!(
            !call.is_empty(),
            "the call lost its argument during preparation:\n{:#?}",
            prepared.body
        );
    }

    /// `forward_sum6`: `return sum_arg6(a0, …)`. The return value is written by
    /// the CALL's destination, not by an `Assign`, so the bare-return fixup found
    /// no writer and the function rendered `return 0;` — discarding a call whose
    /// arguments were otherwise perfect.
    #[test]
    fn a_call_result_satisfies_a_bare_return() {
        let f = Function {
            name: "forward_sum6".to_string(),
            entry_va: 0x1000,
            body: vec![
                Stmt::Call {
                    target: Expr::Named {
                        va: 0x2000,
                        name: "sum_arg6".to_string(),
                    },
                    args: vec![Expr::Reg(VReg::phys("arg0"))],
                    dst: Some(VReg::phys("ret")),
                    call_spec: None,
                },
                Stmt::Return { value: None },
            ],
        };
        let out = render_decbench(&prepare_for_decbench(&f));
        assert!(
            out.contains("return sum_arg6(arg0);"),
            "the call's result must satisfy the bare return:\n{out}"
        );
        assert!(
            !out.contains("return 0;"),
            "the result was discarded:\n{out}"
        );
    }

    /// A genuinely void function still returns 0 — the fixup must not invent a
    /// value where no return register was written at all.
    #[test]
    fn a_void_function_still_returns_zero() {
        let f = Function {
            name: "v".to_string(),
            entry_va: 0x1000,
            body: vec![
                Stmt::Call {
                    target: Expr::Named {
                        va: 0x2000,
                        name: "side_effect".to_string(),
                    },
                    args: vec![],
                    dst: None,
                    call_spec: None,
                },
                Stmt::Return { value: None },
            ],
        };
        let out = render_decbench(&prepare_for_decbench(&f));
        assert!(
            out.contains("return 0;"),
            "expected the void default:\n{out}"
        );
    }

    /// `fp_mul` is `(int)(((long)a*b)>>16)`. The machine sign-extends both operands
    /// to 64 bits (`movslq`, `cltq`) and multiplies at 64 bits.
    ///
    /// Lowering `SExt` to `(int)src` alone is correct only as an ASSIGNMENT — `long
    /// d = (int)s` sign-fills in C. It stops being correct the moment `copy_prop`
    /// folds it into an expression: `(int)b * (int)a` is a 32-BIT multiply, and the
    /// high half of the product — the whole point of the source's `(long)` cast —
    /// is discarded. `fixedpoint` returned -65536 where the original returned 0.
    ///
    /// So an extension has to carry its target width with it: `(long)(int)s` means
    /// the same thing wherever it is folded to.
    #[test]
    fn a_sign_extension_survives_being_folded_into_an_expression() {
        use crate::ir::types::{BinOp as B, Value, Width};
        let lf = mk_cfg(vec![(
            0x1000,
            vec![
                Op::SExt {
                    dst: VReg::phys("rdx"),
                    src: Value::Reg(VReg::phys("eax")),
                    from: Width::W32,
                    to: Width::W64,
                },
                Op::SExt {
                    dst: VReg::phys("rax"),
                    src: Value::Reg(VReg::phys("ecx")),
                    from: Width::W32,
                    to: Width::W64,
                },
                Op::Bin {
                    dst: VReg::phys("rax"),
                    op: B::Mul,
                    lhs: Value::Reg(VReg::phys("rax")),
                    rhs: Value::Reg(VReg::phys("rdx")),
                },
                Op::Return,
            ],
            vec![],
        )]);
        let ssa = compute_ssa(&lf);
        let r = recover(&lf, &ssa);
        let f = prepare_for_decbench(&lower(&lf, &r, "fp"));
        let out = render_decbench(&f);
        assert!(
            out.contains("(long)") || out.contains("(unsigned long)"),
            "the extension must state its 64-bit target so folding preserves it:\n{out}"
        );
    }

    /// A zero-extension has the same requirement, through the unsigned type.
    #[test]
    fn a_zero_extension_states_its_target_width() {
        use crate::ir::types::{Value, Width};
        let lf = mk_cfg(vec![(
            0x1000,
            vec![
                Op::ZExt {
                    dst: VReg::phys("rax"),
                    src: Value::Reg(VReg::phys("eax")),
                    from: Width::W32,
                    to: Width::W64,
                },
                Op::Return,
            ],
            vec![],
        )]);
        let ssa = compute_ssa(&lf);
        let r = recover(&lf, &ssa);
        let out = render_decbench(&lower(&lf, &r, "z"));
        assert!(
            out.contains("(unsigned long)"),
            "expected an explicit 64-bit unsigned target:\n{out}"
        );
    }

    /// `while ((c = *s++))` — gcc -O0 puts the load, the pointer bump AND the test in
    /// the loop HEADER, because all three run once per iteration.
    ///
    /// Hoisting that work above the `while` leaves the condition reading a value
    /// nothing updates, so the loop never ends. `strops::hash_djb2` and `str_len`
    /// both spun until the 5s budget on inputs the original returned on:
    ///
    ///     var0 = local_18; local_18 = local_18 + 1;   // hoisted
    ///     local_4 = *(char *)(var0);                  // hoisted
    ///     while ((local_4 != 0)) { h = ...; }         // local_4 never changes
    ///
    /// Hoisting is only sound when the header work is loop-INVARIANT. It is not here,
    /// and a load through a pointer the body advances can never be assumed to be.
    #[test]
    fn per_iteration_header_work_stays_inside_the_loop() {
        use crate::ir::types::{BinOp as B, CmpOp, Flag, MemOp, Value};
        // header: p = p + 1; c = *p; if (c != 0) -> body, else exit
        let lf = mk_cfg(vec![
            (0x1000, vec![Op::Nop], vec![0x1010]),
            (
                0x1010,
                vec![
                    Op::Bin {
                        dst: VReg::phys("rbx"),
                        op: B::Add,
                        lhs: Value::Reg(VReg::phys("rbx")),
                        rhs: Value::Const(1),
                    },
                    Op::Load {
                        dst: VReg::phys("rcx"),
                        addr: MemOp {
                            base: Some(VReg::phys("rbx")),
                            index: None,
                            scale: 1,
                            disp: 0,
                            size: 1,
                            segment: None,
                            endian: crate::ir::types::Endian::Little,
                        },
                    },
                    Op::Cmp {
                        dst: VReg::Flag(Flag::Z),
                        op: CmpOp::Eq,
                        lhs: Value::Reg(VReg::phys("rcx")),
                        rhs: Value::Const(0),
                    },
                    Op::CondJump {
                        cond: VReg::Flag(Flag::Z),
                        target: 0x1030,
                        inverted: false,
                    },
                ],
                vec![0x1020, 0x1030],
            ),
            (
                0x1020,
                vec![
                    Op::Bin {
                        dst: VReg::phys("rax"),
                        op: B::Add,
                        lhs: Value::Reg(VReg::phys("rax")),
                        rhs: Value::Reg(VReg::phys("rcx")),
                    },
                    Op::Jump { target: 0x1010 },
                ],
                vec![0x1010],
            ),
            (0x1030, vec![Op::Return], vec![]),
        ]);
        let out = lower_and_render(&lf, "walk");
        // The load must be inside the loop. Find the `while` and require the
        // dereference to appear after it.
        let wpos = out
            .find("while")
            .expect(&format!("expected a loop:\n{out}"));
        let load = out.find("*(").expect(&format!("expected a load:\n{out}"));
        assert!(
            load > wpos,
            "the per-iteration load was hoisted above the loop, so the condition \
             can never change:\n{out}"
        );
    }

    #[test]
    fn authoritative_fixed_width_prototype_is_kept_at_the_function_boundary() {
        let function = Function {
            name: "fixed_width".into(),
            entry_va: 0x1000,
            body: vec![Stmt::Return {
                value: Some(Expr::Bin {
                    op: BinOp::Add,
                    lhs: Box::new(Expr::Deref {
                        addr: Box::new(Expr::Reg(VReg::phys("arg0"))),
                        size: 4,
                    }),
                    rhs: Box::new(Expr::Reg(VReg::phys("arg1"))),
                }),
            }],
        };
        let prototype = CallPrototype {
            return_type: "uint32_t".into(),
            parameter_types: vec!["const int32_t *".into(), "int32_t".into()],
            variadic: false,
            authority: CallPrototypeAuthority::Authoritative,
        };

        let rendered = render_decbench_typed_with_output_and_prototype(
            &function,
            None,
            None,
            crate::ir::types_recover::RecoveredOutputKind::Direct,
            Some(&prototype),
        );

        assert!(
            rendered.contains("uint32_t fixed_width(const int32_t * arg0, int32_t arg1)"),
            "fixed-width DWARF prototype was discarded:\n{rendered}"
        );
    }

    /// One `_Bool`-returning function, rendered against a declared prototype.
    fn render_bool_return(value: Expr) -> String {
        let function = Function {
            name: "bool_return".into(),
            entry_va: 0x1000,
            body: vec![Stmt::Return { value: Some(value) }],
        };
        let prototype = CallPrototype {
            return_type: "_Bool".into(),
            parameter_types: vec!["int32_t".into()],
            variadic: false,
            authority: CallPrototypeAuthority::Authoritative,
        };
        render_decbench_typed_with_output_and_prototype(
            &function,
            None,
            None,
            crate::ir::types_recover::RecoveredOutputKind::Direct,
            Some(&prototype),
        )
    }

    /// `arg0 & -256 | arg0 & 1` — the merged register a bit-preserving byte
    /// write leaves behind.
    fn merged_partial_byte_write() -> Expr {
        Expr::Bin {
            op: BinOp::Or,
            lhs: Box::new(Expr::Bin {
                op: BinOp::And,
                lhs: Box::new(Expr::Reg(VReg::phys("arg0"))),
                rhs: Box::new(Expr::Const(-256)),
            }),
            rhs: Box::new(Expr::Bin {
                op: BinOp::And,
                lhs: Box::new(Expr::Reg(VReg::phys("arg0"))),
                rhs: Box::new(Expr::Const(1)),
            }),
        }
    }

    /// A `_Bool` result lives in `al` alone; C converts to `_Bool` with `!= 0`
    /// (C23 6.3.1.2), so every surviving high bit of the register becomes
    /// `true`.
    ///
    /// `194_narrow_return_widths:clang:O2:nrw194_bool_and` compiles to
    /// `and %edi,%eax ; and $0x1,%al` — a bit-preserving byte AND this recovery
    /// models exactly and then returned whole. At x == y == -64 the merged
    /// value is 0x1FFFFF00: the source answers 0, the recovery answered `true`.
    #[test]
    fn a_bool_return_is_narrowed_to_the_byte_the_abi_defines() {
        let rendered = render_bool_return(merged_partial_byte_write());
        assert!(
            rendered.contains("_Bool bool_return(int32_t arg0)"),
            "declared `_Bool` prototype was discarded:\n{rendered}"
        );
        assert!(
            rendered.contains("return ((unsigned char)(") && rendered.contains(") != 0);"),
            "a `_Bool` return must be narrowed to the ABI byte before the \
             zero test:\n{rendered}"
        );
        assert_eq!(
            rendered.trim_end().lines().last(),
            Some("}"),
            "the render must still be one complete function:\n{rendered}"
        );
    }

    /// The narrowing is confined to the one conversion C does not perform as a
    /// truncation. An `int32_t` return of the same expression already truncates
    /// by 6.3.1.3, so spelling a cast there would be churn on the ~650
    /// `int32_t`-returning functions in the fixture corpus and nothing else.
    #[test]
    fn an_integer_return_of_the_same_value_is_left_to_c_s_own_conversion() {
        let function = Function {
            name: "int_return".into(),
            entry_va: 0x1000,
            body: vec![Stmt::Return {
                value: Some(merged_partial_byte_write()),
            }],
        };
        let prototype = CallPrototype {
            return_type: "int32_t".into(),
            parameter_types: vec!["int32_t".into()],
            variadic: false,
            authority: CallPrototypeAuthority::Authoritative,
        };
        let rendered = render_decbench_typed_with_output_and_prototype(
            &function,
            None,
            None,
            crate::ir::types_recover::RecoveredOutputKind::Direct,
            Some(&prototype),
        );
        assert!(
            !rendered.contains("(unsigned char)"),
            "an integer return needs no explicit truncation:\n{rendered}"
        );
    }

    /// A recovered `setcc` is already 0 or 1 (C23 6.5.9p3), so it gains nothing
    /// from the narrowing — `nrw194_bool_bit` passes today and must keep its
    /// output. This is the churn guard, not a correctness one.
    #[test]
    fn a_bool_return_that_is_already_a_comparison_is_not_narrowed() {
        let rendered = render_bool_return(Expr::Cmp {
            op: CmpOp::Ne,
            lhs: Box::new(Expr::Bin {
                op: BinOp::And,
                lhs: Box::new(Expr::Reg(VReg::phys("arg0"))),
                rhs: Box::new(Expr::Const(0x100)),
            }),
            rhs: Box::new(Expr::Const(0)),
        });
        assert!(
            !rendered.contains("(unsigned char)"),
            "a comparison is already normalised:\n{rendered}"
        );
        assert!(
            rendered.contains("return ((arg0 & 256) != 0);"),
            "the recovered comparison must survive verbatim:\n{rendered}"
        );
    }

    #[test]
    fn recovered_opaque_typedef_parameter_is_self_contained() {
        let function = Function {
            name: "wcomment".into(),
            entry_va: 0x18a5,
            body: vec![Stmt::Call {
                target: Expr::Named {
                    va: 0x1000,
                    name: "consume".into(),
                },
                args: vec![Expr::Reg(VReg::phys("arg0")), Expr::Reg(VReg::phys("arg1"))],
                dst: None,
                call_spec: None,
            }],
        };
        let prototype = CallPrototype {
            return_type: "void".into(),
            parameter_types: vec!["FILE *".into(), "int".into()],
            variadic: false,
            authority: CallPrototypeAuthority::Recovered,
        };

        let rendered = render_decbench_typed_with_output_and_prototype(
            &function,
            None,
            None,
            crate::ir::types_recover::RecoveredOutputKind::Void,
            Some(&prototype),
        );

        assert!(
            rendered.contains("typedef struct __glaurung_opaque_FILE FILE;"),
            "opaque typedef must be declared in standalone C:\n{rendered}"
        );
        assert!(
            rendered.contains("void wcomment(FILE * arg0, int arg1)"),
            "the semantic parameter spelling was discarded:\n{rendered}"
        );
    }

    #[test]
    fn opaque_dwarf_parameter_does_not_discard_renderable_sibling_types() {
        let function = Function {
            name: "mixed_dwarf_types".into(),
            entry_va: 0x1000,
            body: vec![
                Stmt::Assign {
                    dst: VReg::phys("var0"),
                    src: Expr::Reg(VReg::phys("arg0")),
                },
                Stmt::Assign {
                    dst: VReg::phys("var1"),
                    src: Expr::Reg(VReg::phys("arg1")),
                },
                Stmt::Assign {
                    dst: VReg::phys("var2"),
                    src: Expr::Reg(VReg::phys("arg3")),
                },
                Stmt::Return {
                    value: Some(Expr::Reg(VReg::phys("arg2"))),
                },
            ],
        };
        let prototype = CallPrototype {
            return_type: "long".into(),
            parameter_types: vec![
                "const char *".into(),
                "opaque_callback *".into(),
                "void *".into(),
                "const char * *".into(),
            ],
            variadic: false,
            authority: CallPrototypeAuthority::Authoritative,
        };

        let rendered = render_decbench_typed_with_output_and_prototype_and_dwarf_types(
            &function,
            None,
            None,
            crate::ir::types_recover::RecoveredOutputKind::Direct,
            Some(&prototype),
            &[],
            8,
            &std::collections::HashMap::new(),
        );

        assert!(
            rendered.contains(
                "long mixed_dwarf_types(const char *arg0, long arg1, void *arg2, const char **arg3)"
            ),
            "one opaque parameter discarded independently renderable DWARF types:\n{rendered}"
        );
        assert!(
            !rendered.contains("opaque_callback"),
            "an unavailable typedef escaped into generated C:\n{rendered}"
        );
    }

    #[test]
    fn incomplete_call_keeps_authoritative_declaration_and_owns_a_site_cast() {
        let body = vec![
            Stmt::Call {
                target: Expr::Named {
                    va: 0x2000,
                    name: "dcgettext".to_string(),
                },
                args: vec![Expr::Const(0), Expr::Const(1), Expr::Const(5)],
                dst: Some(VReg::phys("rax")),
                call_spec: None,
            },
            Stmt::Call {
                target: Expr::Named {
                    va: 0x2000,
                    name: "dcgettext".to_string(),
                },
                args: vec![Expr::Const(0)],
                dst: Some(VReg::phys("rax")),
                call_spec: None,
            },
        ];

        let prototypes = recover_named_call_prototypes(&body, "caller");

        assert_eq!(
            prototypes.get("dcgettext"),
            Some(&CallPrototype {
                return_type: "char *".into(),
                parameter_types: vec!["const char *".into(), "const char *".into(), "int".into(),],
                variadic: false,
                authority: CallPrototypeAuthority::Authoritative,
            })
        );

        let rendered = render_decbench(&Function {
            name: "caller".into(),
            entry_va: 0x1000,
            body,
        });
        assert!(rendered.contains("extern char * dcgettext(const char *, const char *, int);"));
        assert!(
            rendered.contains("((char * (*)(const char *))dcgettext)"),
            "the incomplete call did not retain its recovered call-site prototype:\n{rendered}"
        );
    }

    #[test]
    fn indirect_call_arguments_follow_the_emitted_site_prototype() {
        let rendered = render_decbench(&Function {
            name: "caller".into(),
            entry_va: 0x1000,
            body: vec![Stmt::Call {
                target: Expr::Addr(0x2000),
                args: vec![Expr::Reg(VReg::phys("rbp"))],
                dst: Some(VReg::phys("ret")),
                call_spec: Some(CallSiteSpec {
                    callee_prototype: None,
                    call_prototype: CallPrototype {
                        return_type: "long".into(),
                        parameter_types: vec!["long *".into()],
                        variadic: false,
                        authority: CallPrototypeAuthority::Recovered,
                    },
                }),
            }],
        });

        assert!(
            rendered.contains("((long (*)(long *))(0x2000))((long *)(rbp))"),
            "the argument did not consume the same prototype as the indirect callee:\n{rendered}"
        );
    }

    #[test]
    fn recovered_pointer_parameter_casts_address_arithmetic_at_call_boundary() {
        let recovered = CallPrototype {
            return_type: "float".into(),
            parameter_types: vec!["int *".into()],
            variadic: false,
            authority: CallPrototypeAuthority::Recovered,
        };
        let function = Function {
            name: "caller".into(),
            entry_va: 0x1000,
            body: vec![Stmt::Call {
                target: Expr::Named {
                    va: 0x2000,
                    name: "apply".into(),
                },
                args: vec![Expr::Bin {
                    op: BinOp::Add,
                    lhs: Box::new(Expr::Reg(VReg::phys("arg0"))),
                    rhs: Box::new(Expr::Const(64)),
                }],
                dst: Some(VReg::phys("var0")),
                call_spec: Some(CallSiteSpec {
                    callee_prototype: Some(recovered.clone()),
                    call_prototype: recovered,
                }),
            }],
        };
        let mut types = TypeMap::default();
        types.upsert_public(VReg::phys("arg0"), TypeHint::Pointer { pointee_width: 4 });
        types.upsert_public(VReg::phys("var0"), TypeHint::Float { width: 4 });

        let rendered = super::render_decbench_typed(&function, Some(&types), None);

        assert!(
            rendered.contains("apply((int *)((arg0 + 16)))"),
            "exact pointee scaling was not preserved at the call boundary:\n{rendered}"
        );
        assert!(!rendered.contains("arg0 + 64"), "{rendered}");
    }

    /// A recovered pointer parameter is only compatible with an argument that
    /// renders as that same pointer type. A string literal is `char *` and a
    /// frame object is `unsigned char *`; passing either to a recovered
    /// `long *`/`int *` is `-Wincompatible-pointer-types`, which is a hard
    /// error from GCC 14 on. This is exactly the shape that cost 23 of the 250
    /// DecBench holdout functions their compile.
    #[test]
    fn recovered_pointer_parameters_cast_literal_and_frame_arguments() {
        let recovered = CallPrototype {
            return_type: "long".into(),
            parameter_types: vec!["long *".into(), "int *".into(), "void *".into()],
            variadic: false,
            authority: CallPrototypeAuthority::Recovered,
        };
        let rendered = render_decbench(&Function {
            name: "caller".into(),
            entry_va: 0x1000,
            body: vec![Stmt::Call {
                target: Expr::Named {
                    va: 0x2000,
                    name: "record".into(),
                },
                args: vec![
                    Expr::StringLit {
                        value: "boom".into(),
                    },
                    Expr::StackAddr {
                        object: VReg::phys("local_18"),
                        size: 24,
                    },
                    Expr::StackAddr {
                        object: VReg::phys("local_28"),
                        size: 8,
                    },
                ],
                dst: None,
                call_spec: Some(CallSiteSpec {
                    callee_prototype: Some(recovered.clone()),
                    call_prototype: recovered,
                }),
            }],
        });

        assert!(
            rendered.contains(r#"record((long *)("boom"), (int *)(&local_18[0]), &local_28[0])"#),
            "a literal or frame argument reached an incompatible pointer parameter \
             without the reasserting cast, or a `void *` parameter grew a \
             redundant one:\n{rendered}"
        );
    }

    /// A recovered pointer parameter is only compatible with an argument that
    /// renders as that same pointer type. A string literal is `char *` and a
    /// frame object is `unsigned char *`; passing either to a recovered
    /// `long *`/`int *` is `-Wincompatible-pointer-types`, which is a hard
    /// error from GCC 14 on. This is exactly the shape that cost 23 of the 250
    /// DecBench holdout functions their compile.
    #[test]
    fn exceptionally_large_decbench_function_uses_the_gcc_ice_guard() {
        let rendered = render_decbench(&Function {
            name: "generated_parser".into(),
            entry_va: 0x1000,
            body: (0..2_000)
                .map(|index| Stmt::Comment(format!("statement {index}")))
                .collect(),
        });

        assert!(
            rendered.contains("__attribute__((optimize(\"O1\"))) long generated_parser(void)"),
            "the GCC 15 RTL guard was not attached to the exceptional function:\n{rendered}"
        );
    }

    #[test]
    fn versioned_hard_float_call_result_closes_scalar_dataflow() {
        let lf = LlirFunction {
            entry_va: 0x1000,
            blocks: vec![LlirBlock {
                start_va: 0x1000,
                end_va: 0x1008,
                instrs: vec![
                    LlirInstr {
                        va: 0x1000,
                        op: Op::Call {
                            target: CallTarget::Direct(0x2000),
                            effects: Some(crate::ir::types::CallEffects {
                                result: Some(VReg::phys("s0#1")),
                                result_is_source_value: true,
                                args: vec![VReg::phys("s0"), VReg::phys("s1")],
                                proven_args: Vec::new(),
                                args_are_exact: false,
                                is_tail_call: false,
                            }),
                        },
                    },
                    LlirInstr {
                        va: 0x1004,
                        op: Op::Intrinsic {
                            name: "vmov.f32".into(),
                            ins: vec![Value::Reg(VReg::phys("s0#1"))],
                            outs: vec![(VReg::phys("s14#1"), crate::ir::types::Width::W32)],
                            reads_mem: false,
                            writes_mem: false,
                        },
                    },
                ],
                succs: vec![],
            }],
        };

        assert!(super::scalar_float_semantics_are_closed(&lf));
    }

    #[test]
    fn core_to_vfp_move_closes_scalar_dataflow_and_lowers_as_a_copy() {
        // Exact semantic shape of `vmov s14, r3` in DecBench lighthouse.
        // The core register carries the IEEE-754 payload loaded from memory;
        // lowering retains that exact dependency, while the float-consuming
        // renderer reinterprets its bits instead of numerically converting it.
        let core_move = Op::Intrinsic {
            name: "vmov".into(),
            ins: vec![Value::Reg(VReg::phys("r3"))],
            outs: vec![(VReg::phys("s14"), crate::ir::types::Width::W32)],
            reads_mem: false,
            writes_mem: false,
        };
        let lf = LlirFunction {
            entry_va: 0x1000,
            blocks: vec![LlirBlock {
                start_va: 0x1000,
                end_va: 0x1004,
                instrs: vec![LlirInstr {
                    va: 0x1000,
                    op: core_move.clone(),
                }],
                succs: vec![],
            }],
        };

        assert!(super::scalar_float_semantics_are_closed(&lf));
        assert_eq!(
            super::lower_op(&core_move, true),
            vec![Stmt::Assign {
                dst: VReg::phys("s14"),
                src: Expr::Reg(VReg::phys("r3")),
            }]
        );
    }

    #[test]
    fn float_call_context_renders_core_loaded_bits_as_a_float_load() {
        let rendered = render_decbench(&Function {
            name: "caller".into(),
            entry_va: 0x1000,
            body: vec![Stmt::Call {
                target: Expr::Named {
                    va: 0x2000,
                    name: "tanf".into(),
                },
                args: vec![Expr::Bin {
                    op: BinOp::Sub,
                    lhs: Box::new(Expr::FloatConst {
                        bits: 1.0f32.to_bits() as u64,
                        width: 4,
                    }),
                    rhs: Box::new(Expr::Deref {
                        addr: Box::new(Expr::Reg(VReg::phys("arg1"))),
                        size: 4,
                    }),
                }],
                dst: Some(VReg::phys("ret")),
                call_spec: Some(CallSiteSpec {
                    callee_prototype: Some(CallPrototype {
                        return_type: "float".into(),
                        parameter_types: vec!["float".into()],
                        variadic: false,
                        authority: CallPrototypeAuthority::Authoritative,
                    }),
                    call_prototype: CallPrototype {
                        return_type: "float".into(),
                        parameter_types: vec!["float".into()],
                        variadic: false,
                        authority: CallPrototypeAuthority::Recovered,
                    },
                }),
            }],
        });

        assert!(
            rendered.contains("tanf((float)((1.0f - *(float *)(arg1))))"),
            "the float-consuming VFP expression numerically converted integer bits:\n{rendered}"
        );
        assert!(!rendered.contains("*(int *)(arg1)"));
    }

    /// One `float`-declared and one `double`-declared parameter, for the
    /// float-through-an-integer-lvalue tests below.
    fn float_arg_types() -> TypeMap {
        let mut types = TypeMap::default();
        types.upsert_public(VReg::phys("arg0"), TypeHint::Float { width: 4 });
        types.upsert_public(VReg::phys("arg1"), TypeHint::Float { width: 8 });
        types
    }

    /// A four-byte store of a `float`-typed value keeps the IEEE bits.
    ///
    /// `movss %xmm0, -0x8(%rbp)` at `-O0` rendered as
    /// `*(int *)(&local_8[0]) = (float)(...)`, and C's assignment converts a
    /// floating VALUE to `int` (C23 6.3.1.4, truncation toward zero) — so
    /// `3.0f` was written as `0x00000003` where the machine wrote `0x40400000`.
    /// Every byte of the destination is wrong before anything reads it.
    /// `197:*:O0:hfa197_make_tagged` and `198:*:O0:agr198_make_bits`.
    #[test]
    fn a_four_byte_store_of_a_float_keeps_its_bits() {
        let function = Function {
            name: "store_float".into(),
            entry_va: 0x1000,
            body: vec![Stmt::Store {
                addr: Expr::Reg(VReg::phys("arg2")),
                src: Expr::NumericConvert {
                    from: ScalarType::SignedInt(4),
                    to: ScalarType::Float(4),
                    expr: Box::new(Expr::Reg(VReg::phys("arg3"))),
                },
                size: 4,
            }],
        };

        let rendered = render_decbench_typed(&function, None, None);

        assert!(
            rendered.contains("*(float *)(arg2) = (float)("),
            "a `movss` store numerically converted the value it wrote:\n{rendered}"
        );
        assert!(
            !rendered.contains("*(int *)(arg2) = (float)("),
            "the integer pointee survived:\n{rendered}"
        );
    }

    /// ...and the eight-byte form, which is a separate width and a separate
    /// pointee spelling (`long`, not `int`). `198:*:O0:agr198_make_bits`.
    #[test]
    fn an_eight_byte_store_of_a_double_keeps_its_bits() {
        let function = Function {
            name: "store_double".into(),
            entry_va: 0x1000,
            body: vec![Stmt::Store {
                addr: Expr::Reg(VReg::phys("arg2")),
                src: Expr::NumericConvert {
                    from: ScalarType::SignedInt(4),
                    to: ScalarType::Float(8),
                    expr: Box::new(Expr::Reg(VReg::phys("arg3"))),
                },
                size: 8,
            }],
        };

        let rendered = render_decbench_typed(&function, None, None);

        assert!(
            rendered.contains("*(double *)(arg2) = (double)("),
            "a `movsd` store numerically converted the value it wrote:\n{rendered}"
        );
    }

    /// The width has to MATCH. A four-byte store of a `double`-typed value is
    /// not a copy of that value's bits, so it must not claim to be one.
    #[test]
    fn a_narrow_store_of_a_wide_float_is_not_a_bit_copy() {
        let function = Function {
            name: "store_half".into(),
            entry_va: 0x1000,
            body: vec![Stmt::Store {
                addr: Expr::Reg(VReg::phys("arg2")),
                src: Expr::NumericConvert {
                    from: ScalarType::SignedInt(4),
                    to: ScalarType::Float(8),
                    expr: Box::new(Expr::Reg(VReg::phys("arg3"))),
                },
                size: 4,
            }],
        };

        let rendered = render_decbench_typed(&function, None, None);

        assert!(
            !rendered.contains("*(float *)(arg2)") && !rendered.contains("*(double *)(arg2)"),
            "an eight-byte value was stored through a four-byte float pointee:\n{rendered}"
        );
    }

    /// Floating ARITHMETIC stored through the same width-only destination.
    ///
    /// The pointee and the value have to be decided together. Naming a `float`
    /// pointee and then printing the value through the integer renderer spells
    /// the divisor `2.0f` as the integer `0x40000000`, which C converts to
    /// 1073741824.0f — `201:gcc:O0:f201_f32_slot_values`, where the LOAD of
    /// the very same object already read `*(float *)` and truncated it with
    /// `(int)`. Both ends of one object must agree about what it holds.
    #[test]
    fn a_store_of_float_arithmetic_renders_both_ends_as_floats() {
        let function = Function {
            name: "store_quotient".into(),
            entry_va: 0x1000,
            body: vec![Stmt::Store {
                addr: Expr::Reg(VReg::phys("arg2")),
                src: Expr::Bin {
                    op: BinOp::Div,
                    lhs: Box::new(Expr::NumericConvert {
                        from: ScalarType::SignedInt(4),
                        to: ScalarType::Float(4),
                        expr: Box::new(Expr::Reg(VReg::phys("arg3"))),
                    }),
                    rhs: Box::new(Expr::Const(0x4000_0000)),
                },
                size: 4,
            }],
        };

        let rendered = render_decbench_typed(&function, None, None);

        assert!(
            rendered.contains("*(float *)(arg2) = "),
            "a float divide was stored through an integer pointee:\n{rendered}"
        );
        assert!(
            rendered.contains("{ .bits = (unsigned int)(0x40000000) }).value"),
            "the divisor stayed an integer beside a float dividend:\n{rendered}"
        );
    }

    /// ...and the guard. A bitwise operator has no floating operand in C at
    /// all (C23 6.5.11-13 require an integer type), so an `&`/`|`/`^`/shift
    /// beside a float must NOT be swept into the floating renderer by the
    /// arithmetic rule above.
    #[test]
    fn a_bitwise_expression_is_not_floating_arithmetic() {
        let function = Function {
            name: "store_masked".into(),
            entry_va: 0x1000,
            body: vec![Stmt::Store {
                addr: Expr::Reg(VReg::phys("arg2")),
                src: Expr::Bin {
                    op: BinOp::And,
                    lhs: Box::new(Expr::NumericConvert {
                        from: ScalarType::SignedInt(4),
                        to: ScalarType::Float(4),
                        expr: Box::new(Expr::Reg(VReg::phys("arg3"))),
                    }),
                    rhs: Box::new(Expr::Const(0x7fff_ffff)),
                },
                size: 4,
            }],
        };

        let rendered = render_decbench_typed(&function, None, None);

        assert!(
            !rendered.contains("*(float *)(arg2)"),
            "a bitwise expression was rendered as floating arithmetic:\n{rendered}"
        );
    }

    /// The register-assignment mirror, where the lvalue's C type is fixed by a
    /// declaration and cannot be respelled. `memcpy(&bits, &value, 4)` compiles
    /// to `movss %xmm0, -0x14(%rbp)` then `mov -0x14(%rbp), %eax`;
    /// `174:*:O0:fp174_float_bits` is that and nothing else, and every failing
    /// function in that fixture calls it.
    #[test]
    fn an_integer_declared_destination_copies_a_floats_bits() {
        let mut types = float_arg_types();
        types.upsert_public(
            VReg::phys("var0"),
            TypeHint::Int {
                signed: false,
                width: 4,
            },
        );
        let function = Function {
            name: "float_bits".into(),
            entry_va: 0x1000,
            body: vec![Stmt::Assign {
                dst: VReg::phys("var0"),
                src: Expr::Reg(VReg::phys("arg0")),
            }],
        };

        let rendered = render_decbench_typed(&function, Some(&types), None);

        assert!(
            rendered.contains(
                "var0 = ((union { unsigned int bits; float value; }){ .value = arg0 }).bits;"
            ),
            "a four-byte copy out of float storage numerically converted it:\n{rendered}"
        );
    }

    /// The same at `double` width, which uses the other member pair.
    /// `172:gcc:O0:double_precision_horner` renders `ret = arg0;` with `ret`
    /// declared `long`.
    #[test]
    fn a_wide_integer_destination_copies_a_doubles_bits() {
        let mut types = float_arg_types();
        types.upsert_public(
            VReg::phys("var0"),
            TypeHint::Int {
                signed: true,
                width: 8,
            },
        );
        let function = Function {
            name: "double_bits".into(),
            entry_va: 0x1000,
            body: vec![Stmt::Assign {
                dst: VReg::phys("var0"),
                src: Expr::Reg(VReg::phys("arg1")),
            }],
        };

        let rendered = render_decbench_typed(&function, Some(&types), None);

        assert!(
            rendered.contains(
                "var0 = ((union { unsigned long long bits; double value; })\
                 { .value = arg1 }).bits;"
            ),
            "an eight-byte copy out of double storage numerically converted it:\n{rendered}"
        );
    }

    #[test]
    fn a_typed_double_call_is_a_value_not_a_bit_pattern() {
        let call_prototype = crate::ir::call_contracts::CallPrototype {
            return_type: "double".into(),
            parameter_types: vec!["int".into()],
            variadic: false,
            authority: crate::ir::call_contracts::CallPrototypeAuthority::Authoritative,
        };
        let function = Function {
            name: "double_call".into(),
            entry_va: 0x1000,
            body: vec![Stmt::Return {
                value: Some(Expr::NumericConvert {
                    from: ScalarType::Float(8),
                    to: ScalarType::SignedInt(4),
                    expr: Box::new(Expr::Call {
                        target: Box::new(Expr::Named {
                            va: 0x2000,
                            name: "make_double".into(),
                        }),
                        args: vec![Expr::Const(1)],
                        call_spec: Some(crate::ir::call_contracts::CallSiteSpec {
                            callee_prototype: Some(call_prototype.clone()),
                            call_prototype,
                        }),
                        result_width: Some(8),
                    }),
                }),
            }],
        };

        let rendered = render_decbench(&function);

        assert!(
            rendered.contains("return (int)(make_double(1));"),
            "{rendered}"
        );
        assert!(!rendered.contains("union"), "{rendered}");
    }

    /// THE NEGATIVE CONTROL, and the reason the guard is structural rather
    /// than a heuristic. `cvttss2si` IS an arithmetic conversion, and the
    /// lifter states it as `NumericConvert { to: SignedInt }` — which
    /// `write_expr_dec` prints as `(int)(...)`, an integer-typed spelling. A
    /// rule that punned "anything floating reaching an integer destination"
    /// would take the bits of a value the machine had just truncated, and
    /// `(int)2.5` would become 1073741824 instead of 2.
    #[test]
    fn a_genuine_float_to_integer_conversion_is_still_a_conversion() {
        let mut types = float_arg_types();
        types.upsert_public(
            VReg::phys("var0"),
            TypeHint::Int {
                signed: true,
                width: 4,
            },
        );
        let function = Function {
            name: "truncate".into(),
            entry_va: 0x1000,
            body: vec![Stmt::Assign {
                dst: VReg::phys("var0"),
                src: Expr::NumericConvert {
                    from: ScalarType::Float(4),
                    to: ScalarType::SignedInt(4),
                    expr: Box::new(Expr::Reg(VReg::phys("arg0"))),
                },
            }],
        };

        let rendered = render_decbench_typed(&function, Some(&types), None);

        assert!(
            rendered.contains("var0 = (int)(arg0);"),
            "a truncating conversion was reinterpreted as a bit copy:\n{rendered}"
        );
        assert!(
            !rendered.contains(".value = "),
            "the pun escaped onto a genuine conversion:\n{rendered}"
        );
    }

    /// The second negative control, on the STORE path: `cvttsd2si` followed by
    /// a four-byte store is `*(int *)(p) = (int)(x)`, and the pointee must stay
    /// integral. Without this the fix could pass every positive above by
    /// simply never converting.
    #[test]
    fn a_store_of_a_truncated_float_keeps_an_integer_pointee() {
        let function = Function {
            name: "store_truncated".into(),
            entry_va: 0x1000,
            body: vec![Stmt::Store {
                addr: Expr::Reg(VReg::phys("arg2")),
                src: Expr::NumericConvert {
                    from: ScalarType::Float(8),
                    to: ScalarType::SignedInt(4),
                    expr: Box::new(Expr::Reg(VReg::phys("arg3"))),
                },
                size: 4,
            }],
        };

        let rendered = render_decbench_typed(&function, None, None);

        assert!(
            rendered.contains("*(int *)(arg2) = (int)("),
            "a truncating conversion's store acquired a float pointee:\n{rendered}"
        );
        assert!(
            !rendered.contains("*(float *)(arg2)") && !rendered.contains("*(double *)(arg2)"),
            "a truncating conversion's store acquired a float pointee:\n{rendered}"
        );
    }

    #[test]
    fn recovered_float_call_context_preserves_core_loaded_ieee_bits() {
        // Exact semantic boundary from DecBench lighthouse: a project-local
        // helper's prototype is recovered from AAPCS-VFP rather than supplied
        // by the libc catalog, but it still consumes a float.  The preceding
        // `ldr r3, [arg4, #16]; vmov s14, r3` is a bit-preserving field load,
        // not an integer-to-float conversion.
        let recovered_float = CallPrototype {
            return_type: "float".into(),
            parameter_types: vec!["float".into()],
            variadic: false,
            authority: CallPrototypeAuthority::Recovered,
        };
        let rendered = render_decbench(&Function {
            name: "caller".into(),
            entry_va: 0x1000,
            body: vec![Stmt::Call {
                target: Expr::Named {
                    va: 0x80606d8,
                    name: "arm_cos_f32".into(),
                },
                args: vec![Expr::Bin {
                    op: BinOp::Add,
                    lhs: Box::new(Expr::Deref {
                        addr: Box::new(Expr::Lea {
                            base: Some(VReg::phys("arg0")),
                            index: None,
                            scale: 0,
                            disp: 16,
                            segment: None,
                        }),
                        size: 4,
                    }),
                    rhs: Box::new(Expr::FloatConst {
                        bits: 1.0f32.to_bits() as u64,
                        width: 4,
                    }),
                }],
                dst: Some(VReg::phys("ret")),
                call_spec: Some(CallSiteSpec {
                    callee_prototype: None,
                    call_prototype: recovered_float,
                }),
            }],
        });

        assert!(
            rendered.contains("arm_cos_f32((float)((*(float *)"),
            "a recovered float call numerically converted the field bits:\n{rendered}"
        );
        assert!(!rendered.contains("*(int *)"), "{rendered}");
    }

    #[test]
    fn typed_float_store_uses_float_pointee_representation() {
        let function = Function {
            name: "store_result".into(),
            entry_va: 0x1000,
            body: vec![Stmt::Store {
                addr: Expr::Reg(VReg::phys("arg0")),
                src: Expr::Reg(VReg::phys("var0")),
                size: 4,
            }],
        };
        let mut types = TypeMap::default();
        types.upsert_public(VReg::phys("arg0"), TypeHint::Pointer { pointee_width: 4 });
        types.upsert_public(VReg::phys("var0"), TypeHint::Float { width: 4 });

        let rendered = super::render_decbench_typed(&function, Some(&types), None);

        assert!(
            rendered.contains("*(float *)((long)arg0) = var0;"),
            "a proven float store was emitted as integer memory:\n{rendered}"
        );
    }

    #[test]
    fn first_top_level_scalar_definition_becomes_its_declaration_initializer() {
        let local = VReg::phys("local_4");
        let function = Function {
            name: "initialise".into(),
            entry_va: 0x1000,
            body: vec![
                Stmt::Call {
                    target: Expr::Named {
                        va: 0,
                        name: "side_effect".into(),
                    },
                    args: vec![],
                    dst: None,
                    call_spec: None,
                },
                Stmt::Assign {
                    dst: local.clone(),
                    src: Expr::Const(0),
                },
                Stmt::Return {
                    value: Some(Expr::Reg(local.clone())),
                },
            ],
        };
        let mut types = TypeMap::default();
        types.upsert_public(
            local,
            TypeHint::Int {
                signed: true,
                width: 4,
            },
        );

        let rendered = render_decbench_typed(&function, Some(&types), None);

        assert!(rendered.contains("    int local_4 = 0;"), "{rendered}");
        assert_eq!(rendered.matches("int local_4").count(), 1, "{rendered}");
    }

    #[test]
    fn scalar_read_before_definition_keeps_the_entry_declaration() {
        let local = VReg::phys("local_4");
        let function = Function {
            name: "read_first".into(),
            entry_va: 0x1000,
            body: vec![
                Stmt::Call {
                    target: Expr::Named {
                        va: 0,
                        name: "consume".into(),
                    },
                    args: vec![Expr::Reg(local.clone())],
                    dst: None,
                    call_spec: None,
                },
                Stmt::Assign {
                    dst: local.clone(),
                    src: Expr::Const(0),
                },
            ],
        };
        let mut types = TypeMap::default();
        types.upsert_public(
            local,
            TypeHint::Int {
                signed: true,
                width: 4,
            },
        );

        let rendered = render_decbench_typed(&function, Some(&types), None);

        assert!(rendered.contains("    int local_4;"), "{rendered}");
        assert!(rendered.contains("    local_4 = 0;"), "{rendered}");
    }

    #[test]
    fn loop_local_used_only_by_loop_is_declared_in_for_initializer() {
        let index = VReg::phys("local_4");
        let function = Function {
            name: "loop_local".into(),
            entry_va: 0x1000,
            body: vec![Stmt::For {
                init: Box::new(Stmt::Assign {
                    dst: index.clone(),
                    src: Expr::Const(0),
                }),
                cond: Expr::Cmp {
                    op: CmpOp::Slt,
                    lhs: Box::new(Expr::Reg(index.clone())),
                    rhs: Box::new(Expr::Const(3)),
                },
                step: Box::new(Stmt::Assign {
                    dst: index.clone(),
                    src: Expr::Bin {
                        op: BinOp::Add,
                        lhs: Box::new(Expr::Reg(index.clone())),
                        rhs: Box::new(Expr::Const(1)),
                    },
                }),
                body: vec![],
            }],
        };
        let mut types = TypeMap::default();
        types.upsert_public(
            index,
            TypeHint::Int {
                signed: true,
                width: 4,
            },
        );

        let rendered = render_decbench_typed(&function, Some(&types), None);

        assert!(
            rendered.contains("for (int local_4 = 0; local_4 < 3;"),
            "{rendered}"
        );
        assert!(!rendered.contains("    int local_4;"), "{rendered}");
    }

    #[test]
    fn dwarf_named_scalars_use_the_same_proven_inline_declarations() {
        let sum = VReg::phys("sum");
        let index = VReg::phys("i");
        let function = Function {
            name: "source_locals".into(),
            entry_va: 0x1000,
            body: vec![
                Stmt::Assign {
                    dst: sum.clone(),
                    src: Expr::Const(0),
                },
                Stmt::For {
                    init: Box::new(Stmt::Assign {
                        dst: index.clone(),
                        src: Expr::Const(0),
                    }),
                    cond: Expr::Cmp {
                        op: CmpOp::Slt,
                        lhs: Box::new(Expr::Reg(index.clone())),
                        rhs: Box::new(Expr::Const(3)),
                    },
                    step: Box::new(Stmt::Assign {
                        dst: index.clone(),
                        src: Expr::Bin {
                            op: BinOp::Add,
                            lhs: Box::new(Expr::Reg(index.clone())),
                            rhs: Box::new(Expr::Const(1)),
                        },
                    }),
                    body: vec![Stmt::Assign {
                        dst: sum.clone(),
                        src: Expr::Bin {
                            op: BinOp::Add,
                            lhs: Box::new(Expr::Reg(sum.clone())),
                            rhs: Box::new(Expr::Reg(index.clone())),
                        },
                    }],
                },
                Stmt::Return {
                    value: Some(Expr::Reg(sum.clone())),
                },
            ],
        };
        let dwarf_locals = std::collections::HashMap::from([
            ("sum".to_string(), "int".to_string()),
            ("i".to_string(), "int".to_string()),
        ]);
        let mut types = TypeMap::default();
        for local in [sum, index] {
            types.upsert_public(
                local,
                TypeHint::Int {
                    signed: true,
                    width: 4,
                },
            );
        }

        let rendered =
            render_decbench_typed_with_output_and_prototype_and_dwarf_types_and_local_types(
                &function,
                Some(&types),
                None,
                crate::ir::types_recover::RecoveredOutputKind::Direct,
                None,
                &[],
                8,
                &std::collections::HashMap::new(),
                &dwarf_locals,
            );

        assert!(rendered.contains("    int sum = 0;"), "{rendered}");
        assert!(rendered.contains("for (int i = 0; i < 3;"), "{rendered}");
        assert_eq!(rendered.matches("int sum").count(), 1, "{rendered}");
        assert_eq!(rendered.matches("int i").count(), 1, "{rendered}");
    }

    #[test]
    fn loop_index_used_after_loop_keeps_function_scope_declaration() {
        let index = VReg::phys("local_4");
        let function = Function {
            name: "escaped_loop_local".into(),
            entry_va: 0x1000,
            body: vec![
                Stmt::For {
                    init: Box::new(Stmt::Assign {
                        dst: index.clone(),
                        src: Expr::Const(0),
                    }),
                    cond: Expr::Cmp {
                        op: CmpOp::Slt,
                        lhs: Box::new(Expr::Reg(index.clone())),
                        rhs: Box::new(Expr::Const(3)),
                    },
                    step: Box::new(Stmt::Assign {
                        dst: index.clone(),
                        src: Expr::Bin {
                            op: BinOp::Add,
                            lhs: Box::new(Expr::Reg(index.clone())),
                            rhs: Box::new(Expr::Const(1)),
                        },
                    }),
                    body: vec![],
                },
                Stmt::Return {
                    value: Some(Expr::Reg(index.clone())),
                },
            ],
        };
        let mut types = TypeMap::default();
        types.upsert_public(
            index,
            TypeHint::Int {
                signed: true,
                width: 4,
            },
        );

        let rendered = render_decbench_typed(&function, Some(&types), None);

        assert!(rendered.contains("    int local_4;"), "{rendered}");
        assert!(rendered.contains("for (local_4 = 0;"), "{rendered}");
    }
}
