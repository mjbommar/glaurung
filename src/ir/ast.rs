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

use crate::ir::call_contracts::{CallPrototype, CallPrototypeAuthority, CallSiteSpec};
use crate::ir::structure::Region;
use crate::ir::types::{
    is_promoted_local_name as is_internal_promoted_local, BinOp, CallTarget, CmpOp, Flag,
    LlirBlock, LlirFunction, LlirInstr, MemOp, Op, UnOp, VReg, Value, Width,
};
use crate::ir::types_recover::{TypeHint, TypeMap};

fn is_promoted_local(name: &str) -> bool {
    is_internal_promoted_local(name)
        || DEC_SOURCE_LOCALS.with(|locals| locals.borrow().contains(name))
}

mod width_semantics;

use width_semantics::{containing_c_integer_bytes, exact_non_byte_value};

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

/// A C-level expression. v1 is deliberately shallow: we carry raw VReg
/// references and constants without reconstructing use-def chains. The
/// expression-reconstruction pass can later replace `Reg` with compound
/// subexpressions.
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
        }
    }
}

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
    /// A pure three-input select: `cond ? if_true : if_false`.
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
    /// Target of an indirect call / computed value we couldn't simplify.
    Unknown(String),
}

impl Expr {
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
            Self::Un { src, .. } => src.contains_reg(target),
            Self::Cast { expr, .. } => expr.contains_reg(target),
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

// -- Lowering ----------------------------------------------------------------

/// May the loop header's leftover statements be hoisted above the `while`?
///
/// Only when they are **loop-invariant**: hoisting per-iteration work leaves the
/// condition reading a value nothing updates, and the loop never ends.
///
/// Establishing that needs the BODY, not just the preamble. An earlier version of
/// this checked only the preamble and rejected two shapes — a memory read, and a
/// register updating itself (`p = p + 1`). Both rejections are still necessary and
/// neither is sufficient, because a preamble can read a register the *body*
/// assigns:
///
/// ```text
/// t = i + 1;                            <- hoisted: not a self-reference,
/// while (t < n) { ...; i = i + 1; }         reads no memory, still wrong
/// ```
///
/// `t` never changes and the loop spins forever. So the real rule is a def-use
/// question: every register the preamble reads, other than one it defines itself
/// earlier in the chain, must not be assigned anywhere in the body.
///
/// The preamble is *itself* part of that body. It executes at the top of every
/// iteration, so a register it assigns is loop-carried exactly like one the body
/// assigns, and a statement that reads such a register **before** the preamble
/// reassigns it is reading the previous iteration's value:
///
/// ```text
/// cursor = estimate;                    <- reads the carried value
/// estimate = (cursor + n / cursor) / 2; <- and produces the next one
/// while (cursor > estimate) { ... }
/// ```
///
/// Hoisting that runs the recurrence once and leaves the condition comparing two
/// values nothing updates. Checking only the body missed it because the body here
/// is just the latch. `newton_isqrt` at `gcc -O2` is the measured case: its whole
/// Newton step moved out of the loop and the function returned the first estimate.
///

/// What remains disqualifying regardless of the body:
///
/// * a MEMORY read — the body may store through the same pointer via a `Stmt::Store`
///   this analysis does not alias-track, and a reload is exactly what a
///   `while ((c = *s++))` header is doing;
/// * a register that updates ITSELF — a per-iteration side effect;
/// * anything with an effect (a store, a call, a push).
///
/// When this declines, the caller emits `while (1) { pre; if (!cond) break; body }`,
/// which is always correct and merely less pretty. Declining is cheap; hoisting
/// wrongly produces a program that does not terminate.
fn hoisting_the_header_is_safe(pre: &[Stmt], body: &[Stmt]) -> bool {
    fn expr_reads_memory(e: &Expr) -> bool {
        match e {
            Expr::Deref { .. } => true,
            Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
                expr_reads_memory(lhs) || expr_reads_memory(rhs)
            }
            Expr::Select {
                cond,
                if_true,
                if_false,
                ..
            } => {
                expr_reads_memory(cond) || expr_reads_memory(if_true) || expr_reads_memory(if_false)
            }
            Expr::Un { src, .. } => expr_reads_memory(src),
            Expr::Cast { expr, .. } => expr_reads_memory(expr),
            _ => false,
        }
    }
    // Every register the body assigns, at any nesting depth. Over-approximating this
    // is the safe direction: a register listed here merely blocks a hoist.
    fn collect_assigned(stmts: &[Stmt], out: &mut std::collections::HashSet<String>) {
        for s in stmts {
            match s {
                Stmt::Assign {
                    dst: VReg::Phys(n), ..
                } => {
                    out.insert(n.clone());
                }
                Stmt::Call {
                    dst: Some(VReg::Phys(n)),
                    ..
                } => {
                    out.insert(n.clone());
                }
                Stmt::If {
                    then_body,
                    else_body,
                    ..
                } => {
                    collect_assigned(then_body, out);
                    if let Some(e) = else_body {
                        collect_assigned(e, out);
                    }
                }
                Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
                    collect_assigned(body, out)
                }
                Stmt::For {
                    init, step, body, ..
                } => {
                    collect_assigned(std::slice::from_ref(init.as_ref()), out);
                    collect_assigned(body, out);
                    collect_assigned(std::slice::from_ref(step.as_ref()), out);
                }
                Stmt::Switch { cases, default, .. } => {
                    for (_, b) in cases {
                        collect_assigned(b, out);
                    }
                    if let Some(b) = default {
                        collect_assigned(b, out);
                    }
                }
                _ => {}
            }
        }
    }
    fn collect_read(e: &Expr, out: &mut std::collections::HashSet<String>) {
        match e {
            Expr::Reg(VReg::Phys(n)) => {
                out.insert(n.clone());
            }
            Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
                collect_read(lhs, out);
                collect_read(rhs, out);
            }
            Expr::Select {
                cond,
                if_true,
                if_false,
                ..
            } => {
                collect_read(cond, out);
                collect_read(if_true, out);
                collect_read(if_false, out);
            }
            Expr::Un { src, .. } => collect_read(src, out),
            Expr::Cast { expr, .. } => collect_read(expr, out),
            Expr::Deref { addr, .. } => collect_read(addr, out),
            // `Lea` and `PdbFieldAddr` name their base/index as registers directly,
            // not as sub-expressions: an address computed from a register the body
            // bumps is loop-carried just as much as an arithmetic one.
            Expr::Lea { base, index, .. } | Expr::PdbFieldAddr { base, index, .. } => {
                for r in [base, index].into_iter().flatten() {
                    if let VReg::Phys(n) = r {
                        out.insert(n.clone());
                    }
                }
            }
            _ => {}
        }
    }

    let mut body_assigns = std::collections::HashSet::new();
    collect_assigned(body, &mut body_assigns);

    // Everything one iteration can change: the body's writes AND the preamble's
    // own, since the preamble runs once per iteration too.
    let mut carried = body_assigns.clone();
    collect_assigned(pre, &mut carried);

    // Registers the preamble has defined so far: reading one of those is reading a
    // value this chain produced, not a loop-carried one.
    let mut defined_here: std::collections::HashSet<String> = std::collections::HashSet::new();

    for s in pre {
        match s {
            Stmt::Assign { dst, src } => {
                if expr_reads_memory(src) {
                    return false;
                }
                // Self-referential update: a per-iteration side effect.
                if matches!(dst, VReg::Phys(n) if count_reg_uses_in_expr(src, &VReg::phys(n)) > 0) {
                    return false;
                }
                // Loop-invariance: nothing this statement reads may be assigned by
                // the body, unless the preamble itself produced it.
                let mut reads = std::collections::HashSet::new();
                collect_read(src, &mut reads);
                for r in &reads {
                    if carried.contains(r) && !defined_here.contains(r) {
                        return false;
                    }
                }
                if let VReg::Phys(n) = dst {
                    // A preamble that redefines a register the body also assigns is
                    // itself loop-carried work: hoisting it drops the update.
                    if body_assigns.contains(n) {
                        return false;
                    }
                    defined_here.insert(n.clone());
                }
            }
            Stmt::Nop | Stmt::Comment(_) => {}
            // A store, a call, a push — anything with an effect stays put.
            _ => return false,
        }
    }
    true
}

/// `(int<to>)(int<from>)expr` — an extension that keeps its meaning when folded.
///
/// Emits only the inner cast when the two widths agree (nothing is being extended),
/// and only the outer one when `from` is already the full width.
fn widen_cast(expr: Expr, signed: bool, from: Width, to: Width) -> Expr {
    let fw = containing_c_integer_bytes(from);
    let tw = containing_c_integer_bytes(to);
    let inner = Expr::Cast {
        signed,
        width: fw,
        expr: Box::new(exact_non_byte_value(expr, from, signed)),
    };
    if tw <= fw {
        return inner;
    }
    Expr::Cast {
        signed,
        width: tw,
        expr: Box::new(inner),
    }
}

fn lower_value(v: &Value) -> Expr {
    match v {
        Value::Reg(r) => Expr::Reg(r.clone()),
        Value::Const(c) => Expr::Const(*c),
        Value::Addr(a) => Expr::Addr(*a),
    }
}

fn lower_float_value(value: &Value, width: u8) -> Expr {
    match value {
        Value::Const(bits) => Expr::FloatConst {
            bits: *bits as u64,
            width,
        },
        _ => lower_value(value),
    }
}

/// Lower an architecture-neutral repeated scalar memory fill into an exact AST
/// loop. The lifter supplies private pointer/count scratch values, so mutating
/// them here cannot overwrite the architectural registers whose post-operation
/// values are represented by subsequent LLIR operations.
fn memory_fill_intrinsic(name: &str, ins: &[Value], outs: &[(VReg, Width)]) -> Option<Stmt> {
    if !outs.is_empty() {
        return None;
    }
    let suffix = name.strip_prefix("memory.fill.")?;
    let (element_width, word_width) = suffix.split_once(".word")?;
    let element_width: u8 = element_width.parse().ok()?;
    let word_width: u8 = word_width.parse().ok()?;
    if !matches!(element_width, 1 | 2 | 4 | 8) || !matches!(word_width, 4 | 8) {
        return None;
    }
    let [Value::Reg(pointer), Value::Reg(remaining), value, direction] = ins else {
        return None;
    };
    let direction_is_set = Expr::Cmp {
        op: CmpOp::Ne,
        lhs: Box::new(lower_value(direction)),
        rhs: Box::new(Expr::Const(0)),
    };
    Some(Stmt::While {
        cond: Expr::Cmp {
            op: CmpOp::Ne,
            lhs: Box::new(Expr::Reg(remaining.clone())),
            rhs: Box::new(Expr::Const(0)),
        },
        body: vec![
            Stmt::Store {
                addr: Expr::Reg(pointer.clone()),
                src: lower_value(value),
                size: element_width,
            },
            Stmt::Assign {
                dst: pointer.clone(),
                src: Expr::Bin {
                    op: BinOp::Add,
                    lhs: Box::new(Expr::Reg(pointer.clone())),
                    rhs: Box::new(Expr::Select {
                        cond: Box::new(direction_is_set),
                        if_true: Box::new(Expr::Const(-i64::from(element_width))),
                        if_false: Box::new(Expr::Const(i64::from(element_width))),
                        width: word_width,
                    }),
                },
            },
            Stmt::Assign {
                dst: remaining.clone(),
                src: Expr::Bin {
                    op: BinOp::Sub,
                    lhs: Box::new(Expr::Reg(remaining.clone())),
                    rhs: Box::new(Expr::Const(1)),
                },
            },
        ],
    })
}

#[derive(Clone, Copy)]
enum ScalarFloatOperation {
    Move,
    Negate,
    Binary(BinOp),
}

fn scalar_vfp_register(register: &VReg) -> bool {
    matches!(register, VReg::Phys(name) if {
        let base = crate::ir::abi::ssa_base(name);
        base.strip_prefix('s').is_some_and(|n| n.parse::<u8>().is_ok())
            || base.strip_prefix('d').is_some_and(|n| n.parse::<u8>().is_ok())
    })
}

fn scalar_float_intrinsic(
    name: &str,
    ins: &[Value],
    outs: &[(VReg, crate::ir::types::Width)],
) -> Option<(ScalarFloatOperation, u8)> {
    let (base, width) = if let Some(base) = name.strip_suffix(".f32") {
        (base, 4)
    } else if let Some(base) = name.strip_suffix(".f64") {
        (base, 8)
    } else if name == "vmov"
        && matches!(ins, [Value::Reg(source)] if !scalar_vfp_register(source))
        && matches!(outs, [(destination, _)] if scalar_vfp_register(destination))
    {
        let [(_, declared_width)] = outs else {
            return None;
        };
        ("vmov", u8::try_from(declared_width.bytes()).ok()?)
    } else {
        return None;
    };
    let operation = match base {
        "vmov" => ScalarFloatOperation::Move,
        "vneg" => ScalarFloatOperation::Negate,
        "vadd" => ScalarFloatOperation::Binary(BinOp::Add),
        "vsub" => ScalarFloatOperation::Binary(BinOp::Sub),
        "vmul" => ScalarFloatOperation::Binary(BinOp::Mul),
        "vdiv" => ScalarFloatOperation::Binary(BinOp::Div),
        _ => return None,
    };
    Some((operation, width))
}

fn wide_integer_intrinsic(
    name: &str,
    ins: &[Value],
    outs: &[(VReg, crate::ir::types::Width)],
) -> Option<(WideArithmetic, u8)> {
    let [(_, output_width)] = outs else {
        return None;
    };
    // The lowerings below are pure C, not x86 semantics: AArch64's `umulh` and
    // `smulh` are the same wide product as x86's `mul`/`imul` high half, and
    // `sdiv`/`udiv` the same wide quotient. ARM32 has no divide instruction at
    // all, but `ir::soft_helpers` lowers the libgcc division helpers into the
    // same exact form. Accept every producer's namespace rather than
    // duplicating the double-width renderer per architecture.
    let (stem, bits) = name
        .strip_prefix("x86.")
        .or_else(|| name.strip_prefix("aarch64."))
        .or_else(|| name.strip_prefix("arm."))?
        .rsplit_once('.')?;
    let bits: u16 = bits.parse().ok()?;
    if output_width.bits() != bits || !matches!(bits, 16 | 32 | 64) {
        return None;
    }
    let op = match stem {
        "umul_hi" if ins.len() == 2 => WideArithmetic::UnsignedMulHigh,
        "smul_hi" if ins.len() == 2 => WideArithmetic::SignedMulHigh,
        "udiv_quot" if ins.len() == 3 => WideArithmetic::UnsignedDivQuotient,
        "udiv_rem" if ins.len() == 3 => WideArithmetic::UnsignedDivRemainder,
        "sdiv_quot" if ins.len() == 3 => WideArithmetic::SignedDivQuotient,
        "sdiv_rem" if ins.len() == 3 => WideArithmetic::SignedDivRemainder,
        "clz" if ins.len() == 1 => WideArithmetic::CountLeadingZeros,
        _ => return None,
    };
    Some((op, (bits / 8) as u8))
}

/// Lower full-register and lane-local byte swaps to an exact unsigned
/// expression instead of an opaque asm comment. The explicit machine-width
/// casts keep every shift defined and prevent a 32-bit source with its sign bit
/// set from being promoted to a signed C value before the shuffle is complete.
fn byte_swap_intrinsic(name: &str, ins: &[Value], outs: &[(VReg, Width)]) -> Option<Expr> {
    let ([src], [(_, output_width)]) = (ins, outs) else {
        return None;
    };
    if !matches!(*output_width, Width::W32 | Width::W64) {
        return None;
    }

    let bytes = u8::try_from(output_width.bytes()).ok()?;
    let lane_bytes = match name {
        "bswap" => bytes,
        "byte_swap_16_lanes" => 2,
        _ => return None,
    };
    if bytes % lane_bytes != 0 {
        return None;
    }
    let input = Expr::Cast {
        signed: false,
        width: bytes,
        expr: Box::new(lower_value(src)),
    };
    let mut parts = Vec::with_capacity(bytes as usize);
    for source_byte in 0..bytes {
        let source_shift = i64::from(source_byte) * 8;
        let lane_base = (source_byte / lane_bytes) * lane_bytes;
        let lane_offset = source_byte % lane_bytes;
        let destination_byte = lane_base + (lane_bytes - 1 - lane_offset);
        let destination_shift = i64::from(destination_byte) * 8;
        let shifted_down = if source_shift == 0 {
            input.clone()
        } else {
            Expr::Bin {
                op: BinOp::Shr,
                lhs: Box::new(input.clone()),
                rhs: Box::new(Expr::Const(source_shift)),
            }
        };
        let byte = Expr::Bin {
            op: BinOp::And,
            lhs: Box::new(shifted_down),
            rhs: Box::new(Expr::Const(0xff)),
        };
        parts.push(if destination_shift == 0 {
            byte
        } else {
            Expr::Bin {
                op: BinOp::Shl,
                lhs: Box::new(byte),
                rhs: Box::new(Expr::Const(destination_shift)),
            }
        });
    }

    let combined = parts.into_iter().reduce(|lhs, rhs| Expr::Bin {
        op: BinOp::Or,
        lhs: Box::new(lhs),
        rhs: Box::new(rhs),
    })?;
    Some(Expr::Cast {
        signed: false,
        width: bytes,
        expr: Box::new(combined),
    })
}

/// Lower a one-register, 16-byte table lookup into portable scalar C semantics.
///
/// Each intrinsic produces one dword from four table dwords and one dword of
/// byte indices. An index in 0..16 selects that table byte; every other index
/// yields zero, matching AArch64 `TBL` rather than `TBX`. Unsigned casts keep
/// every shift defined even when a table byte sets the source language sign bit.
fn packed_byte_table_intrinsic(name: &str, ins: &[Value], outs: &[(VReg, Width)]) -> Option<Expr> {
    let ([table0, table1, table2, table3, indices], [(_, Width::W32)]) = (ins, outs) else {
        return None;
    };
    if name != "packed_byte_table_16" {
        return None;
    }
    let table: Vec<_> = [table0, table1, table2, table3]
        .into_iter()
        .map(|value| Expr::Cast {
            signed: false,
            width: 4,
            expr: Box::new(lower_value(value)),
        })
        .collect();
    let indices = Expr::Cast {
        signed: false,
        width: 4,
        expr: Box::new(lower_value(indices)),
    };

    let extract_byte = |word: Expr, byte: usize| {
        let shifted = if byte == 0 {
            word
        } else {
            Expr::Bin {
                op: BinOp::Shr,
                lhs: Box::new(word),
                rhs: Box::new(Expr::Const((byte * 8) as i64)),
            }
        };
        Expr::Bin {
            op: BinOp::And,
            lhs: Box::new(shifted),
            rhs: Box::new(Expr::Const(0xff)),
        }
    };

    let mut output_bytes = Vec::with_capacity(4);
    for output_byte in 0..4 {
        let index = extract_byte(indices.clone(), output_byte);
        let mut selected = Expr::Const(0);
        for table_index in (0..16).rev() {
            selected = Expr::Select {
                cond: Box::new(Expr::Cmp {
                    op: CmpOp::Eq,
                    lhs: Box::new(index.clone()),
                    rhs: Box::new(Expr::Const(table_index as i64)),
                }),
                if_true: Box::new(extract_byte(
                    table[table_index / 4].clone(),
                    table_index % 4,
                )),
                if_false: Box::new(selected),
                width: 1,
            };
        }
        let selected = Expr::Cast {
            signed: false,
            width: 4,
            expr: Box::new(selected),
        };
        output_bytes.push(if output_byte == 0 {
            selected
        } else {
            Expr::Bin {
                op: BinOp::Shl,
                lhs: Box::new(selected),
                rhs: Box::new(Expr::Const((output_byte * 8) as i64)),
            }
        });
    }
    let combined = output_bytes.into_iter().reduce(|lhs, rhs| Expr::Bin {
        op: BinOp::Or,
        lhs: Box::new(lhs),
        rhs: Box::new(rhs),
    })?;
    Some(Expr::Cast {
        signed: false,
        width: 4,
        expr: Box::new(combined),
    })
}

/// Lower a signed-count packed shift into C expressions whose shifts are
/// defined for every 32-bit count. AArch64 USHL shifts left for nonnegative
/// counts, right for negative counts, and returns zero when the magnitude is
/// at least 32. The unsigned casts also make INT_MIN negation well-defined.
fn packed_signed_shift_intrinsic(
    name: &str,
    ins: &[Value],
    outs: &[(VReg, Width)],
) -> Option<Expr> {
    let ([value, count], [(_, Width::W32)]) = (ins, outs) else {
        return None;
    };
    if name != "packed_signed_shift_u32" {
        return None;
    }
    let value = Expr::Cast {
        signed: false,
        width: 4,
        expr: Box::new(lower_value(value)),
    };
    let count_unsigned = Expr::Cast {
        signed: false,
        width: 4,
        expr: Box::new(lower_value(count)),
    };
    let count_signed = Expr::Cast {
        signed: true,
        width: 4,
        expr: Box::new(lower_value(count)),
    };
    let zero_unsigned = Expr::Cast {
        signed: false,
        width: 4,
        expr: Box::new(Expr::Const(0)),
    };
    let magnitude = Expr::Bin {
        op: BinOp::Sub,
        lhs: Box::new(zero_unsigned),
        rhs: Box::new(count_unsigned.clone()),
    };
    let guarded_shift = |op: BinOp, amount: Expr| Expr::Select {
        cond: Box::new(Expr::Cmp {
            op: CmpOp::Ule,
            lhs: Box::new(Expr::Const(32)),
            rhs: Box::new(amount.clone()),
        }),
        if_true: Box::new(Expr::Const(0)),
        if_false: Box::new(Expr::Bin {
            op,
            lhs: Box::new(value.clone()),
            rhs: Box::new(amount),
        }),
        width: 4,
    };
    Some(Expr::Select {
        cond: Box::new(Expr::Cmp {
            op: CmpOp::Slt,
            lhs: Box::new(count_signed),
            rhs: Box::new(Expr::Const(0)),
        }),
        if_true: Box::new(guarded_shift(BinOp::Shr, magnitude)),
        if_false: Box::new(guarded_shift(BinOp::Shl, count_unsigned)),
        width: 4,
    })
}

/// Whether every VFP value used by the scalar arithmetic subset has a modeled
/// producer in this function.
///
/// Register-only hard-float leaves (arguments, exact immediates, arithmetic,
/// and an `s0`/`d0` result) are closed and can be rendered as C. Once an opaque
/// VFP instruction or a call participates, lowering only the arithmetic nodes
/// would be actively misleading: an unmodeled `vldr` followed by
/// `vadd.f32 s0, s15, s15` becomes `var = var + var` with an invented live-in.
/// Keep the entire scalar-float subset opaque until those producers are modeled.
fn scalar_float_semantics_are_closed(lf: &LlirFunction) -> bool {
    let mut saw_scalar_float = false;
    for instruction in lf.blocks.iter().flat_map(|block| &block.instrs) {
        match &instruction.op {
            Op::Intrinsic {
                name, ins, outs, ..
            } if scalar_float_intrinsic(name, ins, outs).is_some() => {
                saw_scalar_float = true;
            }
            Op::Intrinsic { name, .. } | Op::Unknown { mnemonic: name }
                if name.starts_with('v') =>
            {
                return false;
            }
            // AAPCS-VFP call annotation selects s0/d0 only when a subsequent
            // machine instruction actually consumes that storage before it is
            // overwritten.  That is a closed producer edge, unlike the legacy
            // integer-only/default call effect, so scalar lowering may safely
            // continue through it.
            Op::Call {
                effects:
                    Some(crate::ir::types::CallEffects {
                        result: Some(result),
                        ..
                    }),
                ..
            } if scalar_vfp_register(result) => saw_scalar_float = true,
            // A call with no typed VFP result may still clobber the value a
            // later scalar op appears to consume. Keep that region opaque.
            Op::Call { .. } => return false,
            // Scalar VFP memory traffic is represented by ordinary typed
            // Load/Store nodes. Those operations close dataflow rather than
            // creating an opaque producer.
            Op::Load { dst, .. } | Op::CondLoad { dst, .. } if scalar_vfp_register(dst) => {
                saw_scalar_float = true
            }
            Op::Store {
                src: Value::Reg(src),
                ..
            }
            | Op::CondStore {
                src: Value::Reg(src),
                ..
            } if scalar_vfp_register(src) => saw_scalar_float = true,
            _ => {}
        }
    }
    saw_scalar_float
}

fn lower_memop(m: &MemOp) -> Expr {
    let addr = if m.base.is_none() && m.index.is_none() && m.segment.is_none() && m.disp >= 0 {
        Expr::Addr(m.disp as u64)
    } else {
        Expr::Lea {
            base: m.base.clone(),
            index: m.index.clone(),
            scale: m.scale,
            disp: m.disp,
            segment: m.segment.clone(),
        }
    };
    Expr::Deref {
        addr: Box::new(addr),
        size: m.size,
    }
}

fn semantic_comment_for_unknown(mnemonic: &str) -> Option<&'static str> {
    match mnemonic.to_ascii_lowercase().as_str() {
        "sgdt" => Some("sgdt: store global descriptor table register (GDTR)"),
        "sidt" => Some("sidt: store interrupt descriptor table register (IDTR)"),
        "str" => Some("str: store task register selector"),
        "sldt" => Some("sldt: store local descriptor table register selector"),
        "lldt" => Some("lldt: load local descriptor table register selector"),
        "wrmsr" => Some("wrmsr: write model-specific register ecx with edx:eax"),
        "rdmsr" => Some("rdmsr: read model-specific register ecx into edx:eax"),
        "ldmxcsr" => Some("ldmxcsr: load SSE MXCSR control/status register"),
        "stmxcsr" => Some("stmxcsr: store SSE MXCSR control/status register"),
        "swapgs" => Some("swapgs: swap GS base with KernelGSBase MSR"),
        "setssbsy" => Some("setssbsy: mark CET shadow stack busy"),
        "rstorssp" => Some("rstorssp: restore CET shadow stack pointer"),
        "saveprevssp" => Some("saveprevssp: save previous CET shadow stack pointer"),
        _ => None,
    }
}

/// The value a jump-table dispatch switches on, read out of the jump's own
/// target expression.
///
/// A relative-table dispatch computes `table + (i32)table[idx]`, so the index is
/// sitting inside the load's address as `base + idx * scale`. Recovering it here
/// means the `switch` names the value the source switched on instead of a
/// synthetic `dispatch_<va>` that nothing defines.
///
/// Returns `None` rather than guessing when the shape is not recognised — a
/// wrong discriminant would render a switch that reads correct and is not.
fn switch_index_of(target: &Expr) -> Option<Expr> {
    fn find_deref(e: &Expr) -> Option<&Expr> {
        match e {
            Expr::Deref { addr, .. } => Some(addr),
            Expr::Bin { lhs, rhs, .. } => find_deref(lhs).or_else(|| find_deref(rhs)),
            Expr::Cast { expr, .. } => find_deref(expr),
            Expr::Un { src, .. } => find_deref(src),
            _ => None,
        }
    }
    /// The `idx` of a `base + idx * scale` address.
    ///
    /// At lowering time the table read is still an `Expr::Lea` — the scaled form
    /// with an explicit `index` field — because the fold that turns it into
    /// `base + idx*4` runs later. Handling only the folded shape found nothing,
    /// which is how the discriminant stayed a placeholder.
    fn scaled_index(addr: &Expr) -> Option<Expr> {
        if let Expr::Lea {
            index: Some(i),
            scale,
            ..
        } = addr
        {
            if *scale > 1 {
                return Some(Expr::Reg(i.clone()));
            }
        }
        if let Expr::Bin {
            op: BinOp::Add,
            lhs,
            rhs,
        } = addr
        {
            for side in [lhs, rhs] {
                if let Expr::Bin {
                    op: BinOp::Mul,
                    lhs: a,
                    rhs: b,
                } = side.as_ref()
                {
                    if matches!(b.as_ref(), Expr::Const(_)) {
                        return Some((**a).clone());
                    }
                    if matches!(a.as_ref(), Expr::Const(_)) {
                        return Some((**b).clone());
                    }
                }
            }
        }
        None
    }
    scaled_index(find_deref(target)?)
}

/// Lower a single LLIR op to one or more Stmts.
fn lower_op(op: &Op, lower_scalar_float: bool) -> Vec<Stmt> {
    fn predicate_expr(cond: &VReg, inverted: bool) -> Expr {
        if inverted {
            Expr::Cmp {
                op: CmpOp::Eq,
                lhs: Box::new(Expr::Reg(cond.clone())),
                rhs: Box::new(Expr::Const(0)),
            }
        } else {
            Expr::Reg(cond.clone())
        }
    }

    match op {
        Op::Nop => vec![Stmt::Nop],
        Op::Assign { dst, src } => vec![Stmt::Assign {
            dst: dst.clone(),
            src: lower_value(src),
        }],
        Op::Undef { dst, reason } => vec![Stmt::Assign {
            dst: dst.clone(),
            src: Expr::Unknown(format!("undefined({reason})")),
        }],
        Op::Bin { dst, op, lhs, rhs } => {
            let mut lhs = lower_value(lhs);
            // Arithmetic right shift is signed at the machine operand width.
            // State that width in the expression itself: copy propagation may
            // replace a 32-bit register with a wider zero-extended producer,
            // and plain C `>>` would then fill with zeros before a later cast.
            if *op == BinOp::Sar {
                let width = match &lhs {
                    Expr::Reg(register) => register.width().or_else(|| dst.width()),
                    _ => dst.width(),
                };
                if let Some(width) = width.filter(|width| matches!(width.bits(), 8 | 16 | 32 | 64))
                {
                    lhs = Expr::Cast {
                        signed: true,
                        width: (width.bits() / 8) as u8,
                        expr: Box::new(lhs),
                    };
                }
            }
            vec![Stmt::Assign {
                dst: dst.clone(),
                src: Expr::Bin {
                    op: *op,
                    lhs: Box::new(lhs),
                    rhs: Box::new(lower_value(rhs)),
                },
            }]
        }
        Op::Un { dst, op, src } => vec![Stmt::Assign {
            dst: dst.clone(),
            src: Expr::Un {
                op: *op,
                src: Box::new(lower_value(src)),
            },
        }],
        Op::Cmp { dst, op, lhs, rhs } => vec![Stmt::Assign {
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
        Op::CondLoad {
            dst,
            cond,
            inverted,
            addr,
            fallback,
        } => vec![Stmt::Assign {
            dst: dst.clone(),
            src: Expr::Select {
                cond: Box::new(predicate_expr(cond, *inverted)),
                if_true: Box::new(lower_memop(addr)),
                if_false: Box::new(lower_value(fallback)),
                width: addr.size,
            },
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
            size: addr.size,
        }],
        Op::CondStore {
            cond,
            inverted,
            addr,
            src,
        } => vec![Stmt::If {
            cond: predicate_expr(cond, *inverted),
            then_body: vec![Stmt::Store {
                addr: Expr::Lea {
                    base: addr.base.clone(),
                    index: addr.index.clone(),
                    scale: addr.scale,
                    disp: addr.disp,
                    segment: addr.segment.clone(),
                },
                src: lower_value(src),
                size: addr.size,
            }],
            else_body: None,
        }],
        Op::Jump { target } => vec![Stmt::Goto { target: *target }],
        // A computed transfer. Where it goes lives in the CFG — the arms are
        // real successors, and the structurer turns them into `Region::Switch`
        // — so there is nothing to emit here. It must NOT become a statement:
        // lifting it as `Op::Call` made the dispatch render as
        // `var = (*(code *)(...))();`, which the switch lowering could not
        // recognise as the terminator to drop, so the bogus call survived
        // *inside* the recovered switch.
        //
        // An UNSTRUCTURED indirect jump — one the structurer did not turn into
        // a switch — still has to say so rather than vanish, or the function
        // silently reads as if control fell through.
        Op::IndirectJump { target, .. } => vec![Stmt::IndirectGoto {
            target: lower_value(target),
        }],
        // A CondJump on its own (not absorbed into a structured If/While)
        // becomes a conditional goto. If the CondJump carries `inverted`
        // (i.e. lifted from JNE / JAE / JGE / b.ne / b.hs / ...), wrap the
        // flag as `flag == 0`. `UnOp::Not` is the machine bitwise operation
        // and renders as `~`; applying it to a 0/1 predicate is always truthy.
        Op::CondJump {
            cond,
            target,
            inverted,
        } => {
            vec![Stmt::If {
                cond: predicate_expr(cond, *inverted),
                then_body: vec![Stmt::Goto { target: *target }],
                else_body: None,
            }]
        }
        Op::CondReturn { cond, inverted } => vec![Stmt::If {
            cond: predicate_expr(cond, *inverted),
            then_body: vec![Stmt::Return { value: None }],
            else_body: None,
        }],
        Op::CondReturnValue {
            cond,
            inverted,
            value,
        } => vec![Stmt::If {
            cond: predicate_expr(cond, *inverted),
            then_body: vec![Stmt::Return {
                value: Some(lower_value(value)),
            }],
            else_body: None,
        }],
        Op::Call { target, effects } => {
            let target = match target {
                CallTarget::Direct(a) => Expr::Addr(*a),
                CallTarget::Indirect(v) => lower_value(v),
            };
            // Carry the call's own result register down from the LLIR, where value
            // numbering has already renamed it to the same name the post-call read
            // carries. Re-deriving it at the AST level from ABI register names does
            // not work: after renaming, the read is `var4`, not `rax`, so the two
            // never meet and the AST ends up with a value nobody defines.
            vec![Stmt::Call {
                target,
                args: Vec::new(),
                dst: effects.as_ref().and_then(|e| e.result.clone()),
                call_spec: None,
            }]
        }
        Op::ReturnValue { value } => vec![Stmt::Return {
            value: Some(lower_value(value)),
        }],
        Op::Return => vec![Stmt::Return { value: None }],
        // Width changes must preserve their semantics, not collapse to `dst = src`.
        //
        // An extension states BOTH widths: `(int<to>)(int<from>)src`. The inner cast
        // reinterprets the low `from` bits with the right signedness; the outer one
        // says how wide the result is.
        //
        // The outer cast is not redundant, and leaving it off was a real bug. As an
        // assignment `long d = (int)s` sign-fills correctly, so `(int<from>)src`
        // alone looked sufficient — until `copy_prop` folded it into an expression.
        // `movslq`/`cltq` feeding a 64-bit `imul` then rendered
        // `(int)b * (int)a`, a THIRTY-TWO bit multiply, discarding exactly the high
        // half that the source's `(long)` cast existed to keep: `fixedpoint::fp_mul`
        // returned -65536 where the original returned 0, and `fp_div` raised SIGFPE.
        // An expression that means the same thing wherever it is folded has to carry
        // its own width.
        //
        //   Trunc to W: keep exactly the low W bits. A C cast provides that mask
        //   for byte-aligned widths; arbitrary LLIR widths need it explicitly.
        Op::ZExt { dst, src, from, to } => vec![Stmt::Assign {
            dst: dst.clone(),
            src: widen_cast(lower_value(src), false, *from, *to),
        }],
        Op::SExt { dst, src, from, to } => vec![Stmt::Assign {
            dst: dst.clone(),
            src: widen_cast(lower_value(src), true, *from, *to),
        }],
        Op::Trunc { dst, src, to, .. } => vec![Stmt::Assign {
            dst: dst.clone(),
            src: Expr::Cast {
                signed: false,
                width: containing_c_integer_bytes(*to),
                expr: Box::new(exact_non_byte_value(lower_value(src), *to, false)),
            },
        }],
        // Bit-slice `src[lo:hi]` → (src >> lo) & ((1<<(hi-lo))-1).
        Op::Extract { dst, src, hi, lo } => {
            let shifted = if *lo == 0 {
                lower_value(src)
            } else {
                Expr::Bin {
                    op: BinOp::Shr,
                    lhs: Box::new(lower_value(src)),
                    rhs: Box::new(Expr::Const(*lo as i64)),
                }
            };
            let width = hi.saturating_sub(*lo);
            let mask: i64 = if width >= 64 { -1 } else { (1i64 << width) - 1 };
            vec![Stmt::Assign {
                dst: dst.clone(),
                src: Expr::Bin {
                    op: BinOp::And,
                    lhs: Box::new(shifted),
                    rhs: Box::new(Expr::Const(mask)),
                },
            }]
        }
        // Concatenation: render as `hi | lo` (the shift amount needs operand
        // widths, refined when widths flow through values — Phase 0.7).
        Op::Concat { dst, hi, lo } => vec![Stmt::Assign {
            dst: dst.clone(),
            src: Expr::Bin {
                op: BinOp::Or,
                lhs: Box::new(lower_value(hi)),
                rhs: Box::new(lower_value(lo)),
            },
        }],
        // A pure select is one expression-level assignment, not manufactured
        // control flow. Keeping both arms inside the expression also preserves
        // the three-input use-def semantics of `Op::Ite`.
        Op::Ite {
            dst,
            cond,
            t,
            e,
            width,
        } => vec![Stmt::Assign {
            dst: dst.clone(),
            src: Expr::Select {
                cond: Box::new(Expr::Reg(cond.clone())),
                if_true: Box::new(lower_value(t)),
                if_false: Box::new(lower_value(e)),
                width: containing_c_integer_bytes(*width),
            },
        }],
        // Opaque intrinsic. For the lowered-`Unknown` case (no typed operands)
        // render exactly as the old `Unknown` did — including the semantic
        // comments for known system instructions — so decompiler output is
        // unchanged by the Phase-0 migration. Intrinsics carrying operands
        // (future richer lifting) render with an argument ellipsis.
        Op::Intrinsic {
            name, ins, outs, ..
        } => {
            if let Some(statement) = memory_fill_intrinsic(name, ins, outs) {
                return vec![statement];
            }
            if let (Some(src), Some((dst, _))) =
                (byte_swap_intrinsic(name, ins, outs), outs.first())
            {
                return vec![Stmt::Assign {
                    dst: dst.clone(),
                    src,
                }];
            }
            if let (Some(src), Some((dst, _))) =
                (packed_byte_table_intrinsic(name, ins, outs), outs.first())
            {
                return vec![Stmt::Assign {
                    dst: dst.clone(),
                    src,
                }];
            }
            if let (Some(src), Some((dst, _))) =
                (packed_signed_shift_intrinsic(name, ins, outs), outs.first())
            {
                return vec![Stmt::Assign {
                    dst: dst.clone(),
                    src,
                }];
            }
            if let (Some((op, width)), Some((dst, _))) =
                (wide_integer_intrinsic(name, ins, outs), outs.first())
            {
                return vec![Stmt::Assign {
                    dst: dst.clone(),
                    src: Expr::WideArithmetic {
                        op,
                        args: ins.iter().map(lower_value).collect(),
                        width,
                    },
                }];
            }
            if let (Some((operation, width)), Some((dst, _))) =
                (scalar_float_intrinsic(name, ins, outs), outs.first())
            {
                // Moves and negation retain exact value semantics even when an
                // unrelated opaque VFP status instruction prevents lowering a
                // whole arithmetic region. Keeping these producer edges is
                // essential at AAPCS-VFP call boundaries (`s0/s1/s2` setup).
                // Binary operations still require the closed-value proof above
                // so an unmodeled producer cannot become an invented live-in.
                if lower_scalar_float
                    || matches!(
                        operation,
                        ScalarFloatOperation::Move | ScalarFloatOperation::Negate
                    )
                {
                    let expression = match (operation, ins.as_slice()) {
                        (ScalarFloatOperation::Move, [src]) => Some(lower_float_value(src, width)),
                        (ScalarFloatOperation::Negate, [src]) => Some(Expr::Un {
                            op: UnOp::Neg,
                            src: Box::new(lower_float_value(src, width)),
                        }),
                        (ScalarFloatOperation::Binary(op), [lhs, rhs]) => Some(Expr::Bin {
                            op,
                            lhs: Box::new(lower_float_value(lhs, width)),
                            rhs: Box::new(lower_float_value(rhs, width)),
                        }),
                        _ => None,
                    };
                    if let Some(src) = expression {
                        return vec![Stmt::Assign {
                            dst: dst.clone(),
                            src,
                        }];
                    }
                }
            }
            match semantic_comment_for_unknown(name) {
                Some(comment) => vec![Stmt::Comment(comment.to_string())],
                None if ins.is_empty() => vec![Stmt::Unknown(name.clone())],
                None => vec![Stmt::Unknown(format!("{}(...)", name))],
            }
        }
        Op::Unknown { mnemonic } => match semantic_comment_for_unknown(mnemonic) {
            Some(comment) => vec![Stmt::Comment(comment.to_string())],
            None => vec![Stmt::Unknown(mnemonic.clone())],
        },
    }
}

/// Lower every op in a block to stmts.
fn lower_block(b: &LlirBlock, lower_scalar_float: bool) -> Vec<Stmt> {
    let mut out = Vec::with_capacity(b.instrs.len());
    for ins in &b.instrs {
        out.extend(lower_op(&ins.op, lower_scalar_float));
    }
    hoist_inline_flag_conds(out)
}

/// Peephole pass: for each control-flow condition or pure select condition whose
/// flag was assigned by a `Stmt::Assign { dst: flag, src: Expr::Cmp(..) }` earlier
/// in the same block (with no intervening read of the flag), fold the comparison
/// into the condition. Raw architectural flags can be removed immediately;
/// versioned predicates are retained for whole-function DCE because the same SSA
/// value may also be consumed in a successor block.
///
/// The structurer's `extract_cond_and_strip` already does this for
/// conditionals that end a block (recognised as `Region::IfThen` /
/// `Region::While` / `Region::IfThenElse`). But when CFG recovery fails
/// to recognise a structured pattern, the conditional jump is lowered as
/// a bare mid-block `Stmt::If { cond: Expr::Reg(flag), then_body: [Goto] }`
/// — and without this hoist the printer emits the opaque `if (%zf) goto L;`.
/// On real PE binaries (e.g. wkssvc!WsOpenCreateConnectionSpecifyImpersonation)
/// most conditionals fall through to this path and produce unreadable output.
fn hoist_inline_flag_conds(stmts: Vec<Stmt>) -> Vec<Stmt> {
    fn take_reaching_cmp(out: &mut Vec<Stmt>, flag: &VReg) -> Option<Expr> {
        for i in (0..out.len()).rev() {
            match &out[i] {
                Stmt::Assign { dst, src } if dst == flag => {
                    if matches!(src, Expr::Cmp { .. }) {
                        let reads: usize = out[i + 1..]
                            .iter()
                            .map(|stmt| count_reg_uses_in_stmt(stmt, flag))
                            .sum();
                        if reads == 0 && moving_condition_to_end_is_safe(src, &out[i + 1..]) {
                            if matches!(flag, VReg::FlagValue { .. }) {
                                // A local scan cannot prove a versioned predicate
                                // dead: a successor block may read this exact SSA
                                // value (GCC's `cmp; jb; ...; cmova` does). Clone
                                // for the condition and let whole-function DCE
                                // remove the definition only when no read remains.
                                return Some(src.clone());
                            }
                            if let Stmt::Assign { src, .. } = out.remove(i) {
                                return Some(src);
                            }
                        }
                    }
                    return None;
                }
                other if count_reg_uses_in_stmt(other, flag) > 0 => return None,
                _ => {}
            }
        }
        None
    }

    let mut out: Vec<Stmt> = Vec::with_capacity(stmts.len());
    for stmt in stmts {
        let stmt = match stmt {
            Stmt::Assign {
                dst,
                src:
                    Expr::Select {
                        mut cond,
                        if_true,
                        if_false,
                        width,
                    },
            } => {
                let flag = match cond.as_ref() {
                    Expr::Reg(flag) => Some(flag.clone()),
                    _ => None,
                };
                if let Some(flag) = flag {
                    let arm_reads = count_reg_uses_in_expr(&if_true, &flag)
                        + count_reg_uses_in_expr(&if_false, &flag);
                    if arm_reads == 0 {
                        if let Some(cmp) = take_reaching_cmp(&mut out, &flag) {
                            cond = Box::new(cmp);
                        }
                    }
                }
                Stmt::Assign {
                    dst,
                    src: Expr::Select {
                        cond,
                        if_true,
                        if_false,
                        width,
                    },
                }
            }
            other => other,
        };
        // Match both `Stmt::If { cond: Reg(flag), .. }` (non-inverted
        // CondJump) and `Stmt::If { cond: Un(Not, Reg(flag)), .. }`
        // (inverted CondJump from JNE / JAE / ...).
        let (flag, was_inverted, then_body, else_body) = match stmt {
            Stmt::If {
                cond: Expr::Reg(flag),
                then_body,
                else_body,
            } => (Some(flag), false, then_body, else_body),
            Stmt::If {
                cond: Expr::Un { op: UnOp::Not, src },
                then_body,
                else_body,
            } => match *src {
                Expr::Reg(flag) => (Some(flag), true, then_body, else_body),
                other => {
                    out.push(Stmt::If {
                        cond: Expr::Un {
                            op: UnOp::Not,
                            src: Box::new(other),
                        },
                        then_body,
                        else_body,
                    });
                    continue;
                }
            },
            Stmt::If {
                cond:
                    Expr::Cmp {
                        op: CmpOp::Eq,
                        lhs,
                        rhs,
                    },
                then_body,
                else_body,
            } if matches!(rhs.as_ref(), Expr::Const(0)) => match *lhs {
                Expr::Reg(flag) => (Some(flag), true, then_body, else_body),
                other => {
                    out.push(Stmt::If {
                        cond: Expr::Cmp {
                            op: CmpOp::Eq,
                            lhs: Box::new(other),
                            rhs,
                        },
                        then_body,
                        else_body,
                    });
                    continue;
                }
            },
            stmt => {
                out.push(stmt);
                continue;
            }
        };

        let flag = flag.expect("Some by match above");
        let hoisted = take_reaching_cmp(&mut out, &flag);

        let cond_expr = match (hoisted, was_inverted) {
            (Some(expr), true) => negate_cmp_expr(expr),
            (Some(expr), false) => expr,
            (None, true) => Expr::Cmp {
                op: CmpOp::Eq,
                lhs: Box::new(Expr::Reg(flag)),
                rhs: Box::new(Expr::Const(0)),
            },
            (None, false) => Expr::Reg(flag),
        };
        out.push(Stmt::If {
            cond: cond_expr,
            then_body,
            else_body,
        });
    }
    out
}

/// If `expr` is an `Expr::Cmp { op, .. }`, return the Cmp with the inverted
/// CmpOp (Eq <-> Ne, Ult <-> Uge — but Uge isn't in CmpOp so we wrap, ...).
/// Anything else becomes `expr == 0`, a logical negation that stays boolean.
pub(crate) fn negate_cmp_expr(expr: Expr) -> Expr {
    if let Expr::Cmp { op, lhs, rhs } = expr {
        // Invert the comparison itself so the result stays a boolean `Cmp`, not a
        // wrapped `Un{Not}` — which would render as C's *bitwise* `~` and, applied
        // to a 0/1 boolean, is always true. There are no `>`/`>=` ops in `CmpOp`,
        // so negate `<`/`<=` by swapping the operands:
        //   !(a <  b) == (b <= a)      !(a <= b) == (b <  a)
        match op {
            CmpOp::Eq => Expr::Cmp {
                op: CmpOp::Ne,
                lhs,
                rhs,
            },
            CmpOp::Ne => Expr::Cmp {
                op: CmpOp::Eq,
                lhs,
                rhs,
            },
            CmpOp::Slt => Expr::Cmp {
                op: CmpOp::Sle,
                lhs: rhs,
                rhs: lhs,
            },
            CmpOp::Sle => Expr::Cmp {
                op: CmpOp::Slt,
                lhs: rhs,
                rhs: lhs,
            },
            CmpOp::Ult => Expr::Cmp {
                op: CmpOp::Ule,
                lhs: rhs,
                rhs: lhs,
            },
            CmpOp::Ule => Expr::Cmp {
                op: CmpOp::Ult,
                lhs: rhs,
                rhs: lhs,
            },
        }
    } else if let Expr::Un { op: UnOp::Not, src } = expr {
        // Double negation cancels.
        *src
    } else {
        Expr::Cmp {
            op: CmpOp::Eq,
            lhs: Box::new(expr),
            rhs: Box::new(Expr::Const(0)),
        }
    }
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
/// Drop the back-edge `goto` from the tail of a loop body.
///
/// A jump to the loop header at the END of the body is the back-edge, which the
/// `while` already expresses; anywhere else it is a `continue` and is left alone
/// (rendering it as a `goto` is ugly but correct, and inventing a `continue`
/// statement is a separate change). Recurses into the tail of trailing branches,
/// because a rotated loop whose body ends in an `if` puts the jump inside it.
fn strip_back_edge(body: &mut Vec<Stmt>, header_va: u64) {
    match body.last_mut() {
        Some(Stmt::Goto { target }) if *target == header_va => {
            body.pop();
        }
        Some(Stmt::If {
            then_body,
            else_body,
            ..
        }) => {
            strip_back_edge(then_body, header_va);
            if let Some(e) = else_body {
                strip_back_edge(e, header_va);
            }
        }
        _ => {}
    }
}

/// True when the header's conditional branch, if TAKEN, leaves the loop.
///
/// A `while` states the condition under which the loop CONTINUES, but the header
/// carries the condition under which its branch is taken. Those coincide only when
/// the taken edge re-enters the body. gcc -O0 lays loops out that way; clang -O0
/// and gcc -O2 rotate them, so the taken edge is the exit and the condition has to
/// be negated. Returns false when the shape cannot be established, which keeps the
/// previous behaviour for anything unrecognised.
fn exit_is_taken_branch(lf: &LlirFunction, header: usize, exit: Option<usize>) -> bool {
    let Some(exit) = exit else { return false };
    let Some(exit_va) = lf.blocks.get(exit).map(|b| b.start_va) else {
        return false;
    };
    matches!(
        lf.blocks.get(header).and_then(|b| b.instrs.last()),
        Some(LlirInstr { op: Op::CondJump { target, .. }, .. }) if *target == exit_va
    )
}

fn extract_cond_and_strip<'a>(block: &LlirBlock, mut stmts: Vec<Stmt>) -> (Expr, Vec<Stmt>) {
    if let Some(LlirInstr {
        op: Op::CondJump { cond, inverted, .. },
        ..
    }) = block.instrs.last()
    {
        let inverted = *inverted;
        // Pop trailing `if (cond) goto ...` we just synthesised. If the
        // inline-hoist pass has already folded a Cmp into that If's
        // condition (because CFG recovery didn't yet recognise this
        // block as structured), use that hoisted condition directly —
        // the trailing-Goto body has no semantics for the structurer
        // since we're rebuilding the whole If anyway.
        if let Some(Stmt::If { cond, .. }) = stmts.last() {
            // For a non-trivial cond (Cmp / negated form) the hoist
            // already accounted for `inverted`; just adopt it.
            if !matches!(cond, Expr::Reg(_))
                && !matches!(
                    cond,
                    Expr::Un {
                        op: UnOp::Not,
                        src: _
                    }
                )
            {
                let cond_expr = cond.clone();
                stmts.pop();
                return (cond_expr, stmts);
            }
            // If the cond is still `!flag` (no Cmp was available to fold),
            // keep the negation and fall through to the lookup.
            if let Expr::Un { op: UnOp::Not, src } = cond {
                if matches!(src.as_ref(), Expr::Cmp { .. }) {
                    let cond_expr = cond.clone();
                    stmts.pop();
                    return (cond_expr, stmts);
                }
            }
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
                        if usages == 0 && moving_condition_to_end_is_safe(src, &stmts[i + 1..]) {
                            if let Stmt::Assign { src, .. } = stmts.remove(i) {
                                let cond_expr = if inverted { negate_cmp_expr(src) } else { src };
                                return (cond_expr, stmts);
                            }
                        }
                    }
                    break;
                }
            }
        }
        let fallback = if inverted {
            Expr::Cmp {
                op: CmpOp::Eq,
                lhs: Box::new(Expr::Reg(cond.clone())),
                rhs: Box::new(Expr::Const(0)),
            }
        } else {
            Expr::Reg(cond.clone())
        };
        return (fallback, stmts);
    }
    // Fallback — no CondJump, synthesise a generic truthy condition.
    (Expr::Const(1), stmts)
}

fn count_reg_uses_in_expr(e: &Expr, target: &VReg) -> usize {
    match e {
        Expr::Reg(r) => (r == target) as usize,
        Expr::StackAddr { object, .. } => (object == target) as usize,
        Expr::Const(_)
        | Expr::FloatConst { .. }
        | Expr::Addr(_)
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::Unknown(_) => 0,
        Expr::Lea { base, index, .. } | Expr::PdbFieldAddr { base, index, .. } => {
            (base.as_ref() == Some(target)) as usize + (index.as_ref() == Some(target)) as usize
        }
        Expr::Deref { addr, .. } => count_reg_uses_in_expr(addr, target),
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            count_reg_uses_in_expr(lhs, target) + count_reg_uses_in_expr(rhs, target)
        }
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => {
            count_reg_uses_in_expr(cond, target)
                + count_reg_uses_in_expr(if_true, target)
                + count_reg_uses_in_expr(if_false, target)
        }
        Expr::Un { src, .. } => count_reg_uses_in_expr(src, target),
        Expr::Cast { expr, .. } => count_reg_uses_in_expr(expr, target),
        Expr::FunctionTableEntry { index, .. } => count_reg_uses_in_expr(index, target),
        Expr::WideArithmetic { args, .. } => args
            .iter()
            .map(|argument| count_reg_uses_in_expr(argument, target))
            .sum(),
    }
}

/// Whether evaluating `condition` after `following` observes the same state as
/// evaluating it before those statements.
///
/// A machine predicate is a value snapshot.  Folding its defining comparison
/// into a later C `if`/`while` condition is only legal when no intervening
/// statement changes a register or memory read by that comparison.  This is the
/// same ordering distinction Ghidra, angr, and Kuna preserve explicitly for
/// `cmp rax, rcx; mov rdx, rcx; jb ...`.
fn moving_condition_to_end_is_safe(condition: &Expr, following: &[Stmt]) -> bool {
    !following
        .iter()
        .any(|stmt| stmt_may_change_condition_input(stmt, condition))
}

fn expr_reads_memory(expr: &Expr) -> bool {
    match expr {
        Expr::Deref { .. } | Expr::FunctionTableEntry { .. } => true,
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            expr_reads_memory(lhs) || expr_reads_memory(rhs)
        }
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => expr_reads_memory(cond) || expr_reads_memory(if_true) || expr_reads_memory(if_false),
        Expr::Un { src, .. } | Expr::Cast { expr: src, .. } => expr_reads_memory(src),
        Expr::WideArithmetic { args, .. } => args.iter().any(expr_reads_memory),
        Expr::Const(_)
        | Expr::FloatConst { .. }
        | Expr::Addr(_)
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::Unknown(_)
        | Expr::Reg(_)
        | Expr::StackAddr { .. }
        | Expr::Lea { .. }
        | Expr::PdbFieldAddr { .. } => false,
    }
}

fn stmt_may_change_condition_input(stmt: &Stmt, condition: &Expr) -> bool {
    let writes_read_register = |dst: &VReg| count_reg_uses_in_expr(condition, dst) > 0;
    match stmt {
        Stmt::Assign { dst, .. } => writes_read_register(dst),
        Stmt::Store { addr, .. } => {
            let promoted_local_write = matches!(addr,
                Expr::Reg(VReg::Phys(name))
                    if (name.starts_with("local_") || name.starts_with("stack_"))
                        && count_reg_uses_in_expr(condition, &VReg::phys(name)) > 0
            );
            promoted_local_write || expr_reads_memory(condition)
        }
        // Calls may change memory and caller-saved registers whose implicit
        // clobbers are not all represented by the structured Call statement.
        Stmt::Call { .. } | Stmt::Push { .. } | Stmt::Pop { .. } | Stmt::Unknown(_) => true,
        Stmt::If {
            then_body,
            else_body,
            ..
        } => {
            then_body
                .iter()
                .any(|stmt| stmt_may_change_condition_input(stmt, condition))
                || else_body.as_ref().is_some_and(|body| {
                    body.iter()
                        .any(|stmt| stmt_may_change_condition_input(stmt, condition))
                })
        }
        Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => body
            .iter()
            .any(|stmt| stmt_may_change_condition_input(stmt, condition)),
        Stmt::For {
            init, step, body, ..
        } => {
            stmt_may_change_condition_input(init, condition)
                || body
                    .iter()
                    .any(|stmt| stmt_may_change_condition_input(stmt, condition))
                || stmt_may_change_condition_input(step, condition)
        }
        Stmt::Switch { cases, default, .. } => {
            cases.iter().any(|(_, body)| {
                body.iter()
                    .any(|stmt| stmt_may_change_condition_input(stmt, condition))
            }) || default.as_ref().is_some_and(|body| {
                body.iter()
                    .any(|stmt| stmt_may_change_condition_input(stmt, condition))
            })
        }
        Stmt::IndirectGoto { .. }
        | Stmt::Return { .. }
        | Stmt::Goto { .. }
        | Stmt::Label(_)
        | Stmt::Break
        | Stmt::Nop
        | Stmt::Comment(_)
        | Stmt::Throw { .. } => false,
        Stmt::TryCatch { try_body, catches } => {
            try_body
                .iter()
                .any(|stmt| stmt_may_change_condition_input(stmt, condition))
                || catches.iter().any(|catch| {
                    catch
                        .body
                        .iter()
                        .any(|stmt| stmt_may_change_condition_input(stmt, condition))
                })
        }
    }
}

/// Whether evaluating `expr` speculatively is side-effect and fault free.
///
/// A one-armed select evaluates its initializer even when the other arm is
/// selected. Register arithmetic is safe to evaluate early; memory reads and
/// opaque expressions are not.
fn can_eagerly_evaluate(expr: &Expr) -> bool {
    match expr {
        Expr::Deref { .. } | Expr::FunctionTableEntry { .. } | Expr::Unknown(_) => false,
        Expr::Bin { op: BinOp::Div, .. } => false,
        Expr::WideArithmetic {
            op:
                WideArithmetic::UnsignedDivQuotient
                | WideArithmetic::UnsignedDivRemainder
                | WideArithmetic::SignedDivQuotient
                | WideArithmetic::SignedDivRemainder,
            ..
        } => false,
        Expr::WideArithmetic { args, .. } => args.iter().all(can_eagerly_evaluate),
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            can_eagerly_evaluate(lhs) && can_eagerly_evaluate(rhs)
        }
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => {
            can_eagerly_evaluate(cond)
                && can_eagerly_evaluate(if_true)
                && can_eagerly_evaluate(if_false)
        }
        Expr::Un { src, .. } => can_eagerly_evaluate(src),
        Expr::Cast { expr, .. } => can_eagerly_evaluate(expr),
        Expr::Reg(_)
        | Expr::StackAddr { .. }
        | Expr::Const(_)
        | Expr::FloatConst { .. }
        | Expr::Addr(_)
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::Lea { .. }
        | Expr::PdbFieldAddr { .. } => true,
    }
}

/// Choose a semantics-preserving one-armed rendering for a pure select.
///
/// The initializer executes before the condition in the rendered form, so the
/// condition must not read `dst`. The conditional arm also executes after the
/// initializer has overwritten `dst`, so that arm must not read the old value.
/// The initializer itself may read `dst`: C evaluates its RHS before the write.
/// If neither orientation is safe, callers retain the expression-level ternary.
fn one_armed_select<'a>(dst: &VReg, src: &'a Expr) -> Option<(&'a Expr, &'a Expr, &'a Expr, bool)> {
    let Expr::Select {
        cond,
        if_true,
        if_false,
        ..
    } = src
    else {
        return None;
    };
    if count_reg_uses_in_expr(cond, dst) != 0 {
        return None;
    }
    if can_eagerly_evaluate(if_false) && count_reg_uses_in_expr(if_true, dst) == 0 {
        return Some((cond, if_false, if_true, false));
    }
    if can_eagerly_evaluate(if_true) && count_reg_uses_in_expr(if_false, dst) == 0 {
        return Some((cond, if_true, if_false, true));
    }
    None
}

fn count_reg_uses_in_stmt(s: &Stmt, target: &VReg) -> usize {
    match s {
        Stmt::Assign { src, .. } => count_reg_uses_in_expr(src, target),
        Stmt::Store { addr, src, .. } => {
            count_reg_uses_in_expr(addr, target) + count_reg_uses_in_expr(src, target)
        }
        Stmt::Call {
            target: t, args, ..
        } => {
            count_reg_uses_in_expr(t, target)
                + args
                    .iter()
                    .map(|a| count_reg_uses_in_expr(a, target))
                    .sum::<usize>()
        }
        Stmt::If { cond, .. } | Stmt::While { cond, .. } | Stmt::DoWhile { cond, .. } => {
            count_reg_uses_in_expr(cond, target)
        }
        Stmt::For {
            init, cond, step, ..
        } => {
            count_reg_uses_in_stmt(init, target)
                + count_reg_uses_in_expr(cond, target)
                + count_reg_uses_in_stmt(step, target)
        }
        Stmt::Return { value } => value
            .as_ref()
            .map(|e| count_reg_uses_in_expr(e, target))
            .unwrap_or(0),
        Stmt::Push { value } => count_reg_uses_in_expr(value, target),
        // It reads the value it jumps through — counting it as zero would let
        // DCE delete the index computation the dispatch depends on.
        Stmt::IndirectGoto { target: t } => count_reg_uses_in_expr(t, target),
        Stmt::Pop { .. }
        | Stmt::Goto { .. }
        | Stmt::Label(_)
        | Stmt::Break
        | Stmt::Nop
        | Stmt::Unknown(_)
        | Stmt::Comment(_) => 0,
        Stmt::Switch { discriminant, .. } => count_reg_uses_in_expr(discriminant, target),
        Stmt::Throw { value } => count_reg_uses_in_expr(value, target),
        Stmt::TryCatch { try_body, catches } => {
            try_body
                .iter()
                .map(|stmt| count_reg_uses_in_stmt(stmt, target))
                .sum::<usize>()
                + catches
                    .iter()
                    .flat_map(|catch| &catch.body)
                    .map(|stmt| count_reg_uses_in_stmt(stmt, target))
                    .sum::<usize>()
        }
    }
}

/// Drop a trailing `goto <target_va>` from a lowered arm — control already
/// falls through to that block, so the jump is redundant (and, if it targets a
/// join emitted after the `if`, actively harmful: it skips the join's body).
fn strip_trailing_goto(stmts: &mut Vec<Stmt>, target_va: u64) {
    if matches!(stmts.last(), Some(Stmt::Goto { target }) if *target == target_va) {
        stmts.pop();
    }
}

/// Spell a direct edge from the current loop body to its distinguished exit as
/// `break`. Recurse through conditionals only: inside a nested loop or switch,
/// a C `break` would target that inner construct rather than this loop.
fn recover_direct_loop_breaks(stmts: &mut [Stmt], exit_va: u64) {
    for statement in stmts {
        match statement {
            Stmt::Goto { target } if *target == exit_va => *statement = Stmt::Break,
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                recover_direct_loop_breaks(then_body, exit_va);
                if let Some(else_body) = else_body {
                    recover_direct_loop_breaks(else_body, exit_va);
                }
            }
            _ => {}
        }
    }
}

/// The successor reached by source-order fallthrough rather than an explicit
/// transfer in `block`'s final instruction.
fn implicit_successor(block: &crate::ir::types::LlirBlock) -> Option<u64> {
    match block.instrs.last().map(|instruction| &instruction.op) {
        Some(Op::CondJump { target, .. }) => block
            .succs
            .iter()
            .copied()
            .find(|successor| successor != target),
        Some(Op::Jump { .. } | Op::IndirectJump { .. }) => None,
        Some(op) if op.is_unconditional_return() => None,
        _ if block.succs.len() == 1 => block.succs.first().copied(),
        _ => None,
    }
}

/// Lower one block owned by [`Region::RawLoop`], preserving a resolved table
/// dispatch as an explicit low-level switch.
///
/// A raw loop deliberately keeps labelled CFG rather than claiming that its
/// cases form source-level structured arms. The indirect machine transfer must
/// still become valid C, though: `goto *expr` is not portable C and the normal
/// renderer cannot recompile it safely. A typed `IndirectJump` with a proven
/// index and ordered CFG successors is exactly a positional switch whose case
/// bodies jump to the original block labels.
fn lower_raw_loop_block(
    block: &crate::ir::types::LlirBlock,
    default_target: Option<u64>,
    lower_scalar_float: bool,
) -> Vec<Stmt> {
    let explicit_index = block
        .instrs
        .iter()
        .rev()
        .find_map(|instruction| match &instruction.op {
            Op::IndirectJump {
                index: Some(index), ..
            } => Some(lower_value(index)),
            _ => None,
        });
    let mut statements = lower_block(block, lower_scalar_float);
    let Some(discriminant) = explicit_index else {
        return statements;
    };
    if block.succs.len() < 2 {
        return statements;
    }
    let Some(indirect_position) = statements
        .iter()
        .rposition(|statement| matches!(statement, Stmt::IndirectGoto { .. }))
    else {
        return statements;
    };
    statements.remove(indirect_position);
    let cases = block
        .succs
        .iter()
        .enumerate()
        .filter(|(_, target)| default_target != Some(**target))
        .map(|(case, target)| (Some(case as i64), vec![Stmt::Goto { target: *target }]))
        .collect();
    statements.push(Stmt::Switch {
        discriminant,
        cases,
        default: default_target.map(|target| vec![Stmt::Goto { target }]),
    });
    statements
}

/// Recover the bounds guard's out-of-range edge for one raw table dispatch.
///
/// The dispatch target list is positional and may contain the guard's default
/// target in many unused slots. A conditional predecessor with exactly two
/// successors proves which edge bypasses the table. Conflicting predecessors
/// fail closed instead of guessing a C `default` arm.
fn raw_dispatch_default_target(
    lf: &LlirFunction,
    raw_blocks: &[usize],
    dispatch: usize,
) -> Option<u64> {
    let dispatch_va = lf.blocks[dispatch].start_va;
    let mut candidates = raw_blocks.iter().copied().filter_map(|block_index| {
        let block = &lf.blocks[block_index];
        if block.succs.len() != 2
            || !block.succs.contains(&dispatch_va)
            || !matches!(
                block.instrs.last().map(|instruction| &instruction.op),
                Some(Op::CondJump { .. })
            )
        {
            return None;
        }
        block
            .succs
            .iter()
            .copied()
            .find(|successor| *successor != dispatch_va)
    });
    let candidate = candidates.next()?;
    if candidates.all(|other| other == candidate) && lf.blocks[dispatch].succs.contains(&candidate)
    {
        Some(candidate)
    } else {
        None
    }
}

fn lower_region(
    r: &Region,
    lf: &LlirFunction,
    targets: &std::collections::HashSet<u64>,
    lower_scalar_float: bool,
) -> Vec<Stmt> {
    let mut out = lower_region_inner(r, lf, targets, lower_scalar_float);
    // A region that *emits* a goto-target block (any shape — a plain block or a
    // structured `if`/`while` that begins at the target) gets a label at the
    // start of its statements so the jump resolves. The block's statements render
    // exactly once, here. A `Region::Goto` is a *reference*, not an emission —
    // labelling it would produce `L: goto L;` self-loops and duplicate labels.
    if !matches!(r, Region::Goto(_)) {
        if let Some(e) = crate::ir::structure::entry_block(r) {
            let va = lf.blocks[e].start_va;
            if targets.contains(&va) && !matches!(out.first(), Some(Stmt::Label(l)) if *l == va) {
                out.insert(0, Stmt::Label(va));
            }
        }
    }
    out
}

fn lower_region_inner(
    r: &Region,
    lf: &LlirFunction,
    targets: &std::collections::HashSet<u64>,
    lower_scalar_float: bool,
) -> Vec<Stmt> {
    match r {
        Region::Block(bi) => lower_block(&lf.blocks[*bi], lower_scalar_float),
        Region::Goto(bi) => vec![Stmt::Goto {
            target: lf.blocks[*bi].start_va,
        }],
        Region::Seq(parts) => {
            let mut out = Vec::new();
            for (idx, p) in parts.iter().enumerate() {
                let mut lowered = lower_region(p, lf, targets, lower_scalar_float);
                // A sequence emits its next region immediately after this one,
                // so an unconditional jump to that region is ordinary
                // fallthrough and must disappear. This includes entry jumps to
                // a recovered loop and zero-distance bridge blocks between a
                // nested-loop exit and its outer latch. Keeping the latter goto
                // makes the following latch statements unreachable.
                let next_entry = parts
                    .get(idx + 1)
                    .and_then(crate::ir::structure::entry_block);
                if let Some(entry) = next_entry {
                    let next_va = lf.blocks[entry].start_va;
                    if matches!(lowered.last(), Some(Stmt::Goto { target }) if *target == next_va) {
                        lowered.pop();
                    }
                }
                out.extend(lowered);
            }
            out
        }
        Region::IfThen {
            cond,
            then_r,
            join,
            invert,
        } => {
            let cond_stmts = lower_block(&lf.blocks[*cond], lower_scalar_float);
            let (cond_expr, mut pre) = extract_cond_and_strip(&lf.blocks[*cond], cond_stmts);
            // The raw condition is true when the branch is taken; if `then_r` is
            // the fall-through arm the structurer flagged `invert`, so negate.
            let cond_expr = if *invert {
                negate_cmp_expr(cond_expr)
            } else {
                cond_expr
            };
            let mut then_stmts = lower_region(then_r, lf, targets, lower_scalar_float);
            // The arm's trailing `goto <join>` is redundant — control falls
            // through to the join right after the `if`. Leaving it makes the arm
            // jump *past* the join's body (e.g. the epilogue's `return`) to a
            // dangling label, dropping the return value.
            if let Some(j) = join {
                strip_trailing_goto(&mut then_stmts, lf.blocks[*j].start_va);
            }
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
            join,
            invert,
        } => {
            let cond_stmts = lower_block(&lf.blocks[*cond], lower_scalar_float);
            let (cond_expr, mut pre) = extract_cond_and_strip(&lf.blocks[*cond], cond_stmts);
            let cond_expr = if *invert {
                negate_cmp_expr(cond_expr)
            } else {
                cond_expr
            };
            let mut then_stmts = lower_region(then_r, lf, targets, lower_scalar_float);
            let mut else_stmts = lower_region(else_r, lf, targets, lower_scalar_float);
            if let Some(j) = join {
                let jva = lf.blocks[*j].start_va;
                strip_trailing_goto(&mut then_stmts, jva);
                strip_trailing_goto(&mut else_stmts, jva);
            }
            pre.push(Stmt::If {
                cond: cond_expr,
                then_body: then_stmts,
                else_body: Some(else_stmts),
            });
            pre
        }
        Region::While { header, body, exit } => {
            let cond_stmts = lower_block(&lf.blocks[*header], lower_scalar_float);
            let (cond_expr, pre) = extract_cond_and_strip(&lf.blocks[*header], cond_stmts);
            // `cond_expr` is the branch-TAKEN condition. Whether that is the
            // loop's CONTINUE condition depends on where the taken edge goes, and
            // the two mainstream layouts disagree:
            //
            //   gcc -O0   test at the BOTTOM, taken edge re-enters the body
            //             -> the condition already is the continue test
            //   clang -O0 test at the TOP, taken edge LEAVES the loop (a rotated
            //   gcc -O2   loop) -> the condition is the EXIT test
            //
            // Emitting it verbatim in the second case states the opposite of the
            // source: `while (n > 1)` came out as `while (n <= 1)`.
            let continue_cond = if exit_is_taken_branch(lf, *header, *exit) {
                negate_cmp_expr(cond_expr)
            } else {
                cond_expr
            };
            let cond_expr = continue_cond;
            let mut body_stmts = lower_region(body, lf, targets, lower_scalar_float);
            if let Some(exit) = exit {
                recover_direct_loop_breaks(&mut body_stmts, lf.blocks[*exit].start_va);
            }
            // The back-edge is what `while` MEANS. Left as an explicit `goto` to
            // the header it jumps OUT of the loop body to a label the renderer
            // pins wherever that block was emitted — after the `return`, in a
            // rotated loop — so the body cannot repeat.
            strip_back_edge(&mut body_stmts, lf.blocks[*header].start_va);
            if body_stmts.is_empty() && !pre.is_empty() {
                // Do-while: the whole loop body sits in the self-looping header,
                // so the `While` body is empty and `pre` is the body itself. The
                // condition is *post*-tested. Emitting `pre; while (cond) {}` (the
                // previous behaviour) is a semantic bug — the body runs once and
                // the loop becomes an empty infinite/stale test. Lower to
                //     while (1) { body; if (!cond) break; }
                // so the body runs each iteration and the post-test exits.
                let mut loop_body = pre;
                loop_body.push(Stmt::If {
                    cond: negate_cmp_expr(cond_expr),
                    then_body: vec![Stmt::Break],
                    else_body: None,
                });
                vec![Stmt::While {
                    cond: Expr::Const(1),
                    body: loop_body,
                }]
            } else if pre.is_empty() {
                vec![Stmt::While {
                    cond: cond_expr,
                    body: body_stmts,
                }]
            } else if hoisting_the_header_is_safe(&pre, &body_stmts) {
                // The header's leftover work is a plain copy chain — no memory read,
                // no register updating itself — so `copy_prop` folds it into the
                // condition downstream and hoisting it once is equivalent.
                let mut out = pre;
                out.push(Stmt::While {
                    cond: cond_expr,
                    body: body_stmts,
                });
                out
            } else {
                // The header does PER-ITERATION work that cannot be folded into the
                // condition, so hoisting it leaves the condition reading a value
                // nothing updates — an infinite loop. `while ((c = *s++))` is the
                // shape: gcc -O0 puts the pointer bump, the load and the test all in
                // the header because all three run every iteration.
                //
                //     var0 = p; p = p + 1;          <- hoisted
                //     c = *(char *)var0;            <- hoisted
                //     while ((c != 0)) { h = ...; } <- c never changes
                //
                // `strops::hash_djb2` and `str_len` both spun until the time budget
                // on inputs the original returned on. Keep the work where it runs:
                //     while (1) { <header work>; if (!cond) break; <body> }
                let mut loop_body = pre;
                loop_body.push(Stmt::If {
                    cond: negate_cmp_expr(cond_expr),
                    then_body: vec![Stmt::Break],
                    else_body: None,
                });
                loop_body.extend(body_stmts);
                vec![Stmt::While {
                    cond: Expr::Const(1),
                    body: loop_body,
                }]
            }
        }
        Region::DoWhile { body, cond, exit } => {
            let mut body_stmts = lower_region(body, lf, targets, lower_scalar_float);
            let cond_stmts = lower_block(&lf.blocks[*cond], lower_scalar_float);
            let (cond_expr, mut latch_stmts) =
                extract_cond_and_strip(&lf.blocks[*cond], cond_stmts);
            // A shared arm can explicitly jump to the bottom test (source-level
            // `continue`). The condition block is otherwise absorbed into the
            // DoWhile node and never emitted as a region of its own, so retain
            // its label at the precise in-loop point where its non-branch
            // statements execute. Without this, label repair can only append an
            // empty target after the function return and the jump skips the
            // latch and result path entirely.
            let latch_va = lf.blocks[*cond].start_va;
            if targets.contains(&latch_va) {
                body_stmts.push(Stmt::Label(latch_va));
            }
            body_stmts.append(&mut latch_stmts);
            let continue_cond = if exit_is_taken_branch(lf, *cond, *exit) {
                negate_cmp_expr(cond_expr)
            } else {
                cond_expr
            };
            vec![Stmt::DoWhile {
                body: body_stmts,
                cond: continue_cond,
            }]
        }
        Region::RawLoop {
            header,
            blocks,
            exits: _,
        } => {
            let header_va = lf.blocks[*header].start_va;
            let mut loop_body = Vec::new();
            for (position, block_index) in blocks.iter().copied().enumerate() {
                let block = &lf.blocks[block_index];
                let default_target = raw_dispatch_default_target(lf, blocks, block_index);
                loop_body.push(Stmt::Label(block.start_va));
                loop_body.extend(lower_raw_loop_block(
                    block,
                    default_target,
                    lower_scalar_float,
                ));

                // Raw blocks normally rely on source order for fallthrough. The
                // loop owns a non-contiguous subset and starts at its header, so
                // make every displaced fallthrough explicit. Falling off the
                // final block naturally starts the next `while (1)` iteration.
                let lexical_next = blocks
                    .get(position + 1)
                    .map(|next| lf.blocks[*next].start_va)
                    .unwrap_or(header_va);
                if let Some(successor) = implicit_successor(block) {
                    if successor != lexical_next {
                        loop_body.push(Stmt::Goto { target: successor });
                    }
                }
            }
            vec![Stmt::While {
                cond: Expr::Const(1),
                body: loop_body,
            }]
        }
        Region::Switch {
            guard,
            dispatch,
            case_labels,
            arms,
            formal_default,
            join,
        } => {
            // Lower the dispatch block as the prefix; the last
            // instruction is the indirect jump itself which we replace
            // with the structured `switch` statement. v0 emits each
            // arm with its case index (positional) and an implicit
            // break at the end.
            let mut prefix = guard
                .map(|guard| lower_block(&lf.blocks[guard], lower_scalar_float))
                .unwrap_or_default();
            // The range branch is now represented by the switch's formal
            // default. Keep normalization/dataflow statements from the guard,
            // but remove its compiler-level conditional transfer.
            while matches!(
                prefix.last(),
                Some(Stmt::Goto { .. }) | Some(Stmt::If { .. })
            ) {
                prefix.pop();
            }
            prefix.extend(lower_block(&lf.blocks[*dispatch], lower_scalar_float));
            let explicit_index = lf.blocks[*dispatch]
                .instrs
                .iter()
                .rev()
                .find_map(|instruction| match &instruction.op {
                    Op::IndirectJump {
                        index: Some(index), ..
                    } => Some(lower_value(index)),
                    _ => None,
                });
            // The switch statement IS the dispatch, so its terminator must not
            // also appear inside it. `IndirectGoto` belongs in this list for the
            // same reason `Goto` does; while the indirect jump lifted to a call
            // it was neither, so the dispatch survived as a phantom call
            // statement *within* the recovered switch.
            let mut discriminant = None;
            if let Some(position) = prefix
                .iter()
                .rposition(|stmt| matches!(stmt, Stmt::IndirectGoto { .. }))
            {
                if let Stmt::IndirectGoto { target } = &prefix[position] {
                    discriminant = switch_index_of(target);
                }
                prefix.remove(position);
            }
            while matches!(
                prefix.last(),
                Some(Stmt::Goto { .. }) | Some(Stmt::If { .. }) | Some(Stmt::IndirectGoto { .. })
            ) {
                if let Some(Stmt::IndirectGoto { target }) = prefix.last() {
                    discriminant = switch_index_of(target);
                }
                let _ = &discriminant;
                prefix.pop();
            }
            let mut cases: Vec<(Option<i64>, Vec<Stmt>)> = Vec::new();
            for (arm_index, arm) in arms.iter().enumerate() {
                let mut body = lower_region(arm, lf, targets, lower_scalar_float);
                if let Some(join) = join {
                    // The renderer supplies the case `break`; a jump to the
                    // block emitted immediately after this switch is plain
                    // structured fallthrough, not a C goto.
                    strip_trailing_goto(&mut body, lf.blocks[*join].start_va);
                }
                let labels = case_labels
                    .get(arm_index)
                    .filter(|labels| !labels.is_empty())
                    .cloned()
                    .unwrap_or_else(|| vec![arm_index as i64]);
                for label in labels {
                    cases.push((Some(label), body.clone()));
                }
            }
            let default = formal_default.as_deref().map(|region| {
                let mut body = lower_region(region, lf, targets, lower_scalar_float);
                if let Some(join) = join {
                    strip_trailing_goto(&mut body, lf.blocks[*join].start_va);
                }
                body
            });
            // The switched value, recovered from the dispatch's own target
            // expression: the table read indexes by exactly the value the
            // source switched on. The placeholder this replaces
            // (`dispatch_<va>`) named nothing and rendered as an undeclared
            // variable, so the recovered switch read as `switch (var6)` with
            // `var6` defined nowhere. Falls back to the placeholder when the
            // index is not recognisable, rather than inventing one.
            let discriminant = explicit_index.or(discriminant).or_else(|| {
                prefix.iter().rev().find_map(|st| match st {
                    Stmt::Assign { src, .. } => switch_index_of(src),
                    _ => None,
                })
            });
            prefix.push(Stmt::Switch {
                discriminant: discriminant.unwrap_or_else(|| {
                    Expr::Reg(VReg::Phys(format!(
                        "dispatch_{:x}",
                        lf.blocks[*dispatch].start_va
                    )))
                }),
                cases,
                default,
            });
            prefix
        }
        Region::Unstructured(blocks) => {
            let mut out = Vec::new();
            for (position, &bi) in blocks.iter().enumerate() {
                out.push(Stmt::Label(lf.blocks[bi].start_va));
                let block = &lf.blocks[bi];
                out.extend(lower_block(block, lower_scalar_float));
                // A partial labelled-CFG fallback need not own every block
                // between two addresses. Preserve a displaced machine
                // fallthrough explicitly instead of relying on vector order.
                let lexical_next = blocks
                    .get(position + 1)
                    .map(|next| lf.blocks[*next].start_va);
                if let Some(successor) = implicit_successor(block) {
                    if Some(successor) != lexical_next {
                        out.push(Stmt::Goto { target: successor });
                    }
                }
            }
            out
        }
    }
}

/// Collect the VAs of blocks referenced by a [`Region::Goto`] anywhere in the
/// tree — these blocks must render a leading `Stmt::Label` so the jumps resolve.
fn collect_goto_targets(r: &Region, lf: &LlirFunction, out: &mut std::collections::HashSet<u64>) {
    match r {
        Region::Goto(bi) => {
            out.insert(lf.blocks[*bi].start_va);
        }
        Region::Seq(parts) => parts.iter().for_each(|p| collect_goto_targets(p, lf, out)),
        Region::IfThen { then_r, .. } => collect_goto_targets(then_r, lf, out),
        Region::IfThenElse { then_r, else_r, .. } => {
            collect_goto_targets(then_r, lf, out);
            collect_goto_targets(else_r, lf, out);
        }
        Region::While { body, .. } | Region::DoWhile { body, .. } => {
            collect_goto_targets(body, lf, out)
        }
        Region::RawLoop { exits, .. } => {
            out.extend(exits.iter().map(|exit| lf.blocks[*exit].start_va));
        }
        Region::Switch {
            arms,
            formal_default,
            ..
        } => {
            arms.iter().for_each(|a| collect_goto_targets(a, lf, out));
            if let Some(default) = formal_default {
                collect_goto_targets(default, lf, out);
            }
        }
        Region::Block(_) | Region::Unstructured(_) => {}
    }
}

/// Keep exactly one C label for each CFG block, preferring the least-nested
/// emission when the region tree references a shared block from more than one
/// structured path.
///
/// Region joins are references as well as ownership boundaries, so lowering a
/// switch arm and the function tail can clone the same epilogue block. That is
/// harmless while it is plain statements, but once a surviving goto requires a
/// label both clones would spell the same `L_x:` and the C translation unit no
/// longer compiles. The shallowest copy is the natural shared destination.
fn deduplicate_labels(body: &mut Vec<Stmt>) {
    fn collect_min_depth(
        body: &[Stmt],
        depth: usize,
        minimum: &mut std::collections::HashMap<u64, usize>,
    ) {
        for stmt in body {
            match stmt {
                Stmt::Label(va) => {
                    minimum
                        .entry(*va)
                        .and_modify(|old| *old = (*old).min(depth))
                        .or_insert(depth);
                }
                Stmt::If {
                    then_body,
                    else_body,
                    ..
                } => {
                    collect_min_depth(then_body, depth + 1, minimum);
                    if let Some(else_body) = else_body {
                        collect_min_depth(else_body, depth + 1, minimum);
                    }
                }
                Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
                    collect_min_depth(body, depth + 1, minimum)
                }
                Stmt::Switch { cases, default, .. } => {
                    for (_, case_body) in cases {
                        collect_min_depth(case_body, depth + 1, minimum);
                    }
                    if let Some(default_body) = default {
                        collect_min_depth(default_body, depth + 1, minimum);
                    }
                }
                _ => {}
            }
        }
    }

    fn retain_at_min_depth(
        body: &mut Vec<Stmt>,
        depth: usize,
        minimum: &std::collections::HashMap<u64, usize>,
        kept: &mut std::collections::HashSet<u64>,
    ) {
        body.retain_mut(|stmt| match stmt {
            Stmt::Label(va) => minimum.get(va) == Some(&depth) && kept.insert(*va),
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                retain_at_min_depth(then_body, depth + 1, minimum, kept);
                if let Some(else_body) = else_body {
                    retain_at_min_depth(else_body, depth + 1, minimum, kept);
                }
                true
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
                retain_at_min_depth(body, depth + 1, minimum, kept);
                true
            }
            Stmt::Switch { cases, default, .. } => {
                for (_, case_body) in cases {
                    retain_at_min_depth(case_body, depth + 1, minimum, kept);
                }
                if let Some(default_body) = default {
                    retain_at_min_depth(default_body, depth + 1, minimum, kept);
                }
                true
            }
            _ => true,
        });
    }

    let mut minimum = std::collections::HashMap::new();
    collect_min_depth(body, 0, &mut minimum);
    retain_at_min_depth(body, 0, &minimum, &mut std::collections::HashSet::new());
}

/// Lower an entire function given its region tree.
pub fn lower(lf: &LlirFunction, region: &Region, name: impl Into<String>) -> Function {
    let lower_scalar_float = scalar_float_semantics_are_closed(lf);
    let mut targets = std::collections::HashSet::new();
    collect_goto_targets(region, lf, &mut targets);
    // Region::Goto is not the only source of an explicit edge. A raw direct
    // jump can survive inside a recovered switch arm when several cases share
    // a latch but one case exits the loop. Discover those statements from the
    // first lowered body, then lower once more with their targets known so the
    // emitted destination block receives its real label. Without this pass the
    // renderer can only append an empty label at function end, changing where
    // the case actually transfers control.
    let mut body = lower_region(region, lf, &targets, lower_scalar_float);
    let known_target_count = targets.len();
    crate::ir::label_prune::collect_goto_targets(&body, &mut targets);
    if targets.len() != known_target_count {
        body = lower_region(region, lf, &targets, lower_scalar_float);
    }
    deduplicate_labels(&mut body);
    let mut f = Function {
        name: name.into(),
        entry_va: lf.entry_va,
        body,
    };
    fold_returns(&mut f.body);
    f
}

/// Whether `name` is a stack slot the promotion pass named — i.e. a real local
/// variable, so a store *to* it is a plain assignment rather than a pointer
/// write.
/// The C scalar type of a given memory-access byte width, for load/store casts.
fn width_ctype(size: u8) -> &'static str {
    match size {
        1 => "char",
        2 => "short",
        4 => "int",
        _ => "long",
    }
}

/// Collapse `result = E; [comments]; return result;` into a direct `return E`,
/// retaining provenance comments in place.
///
/// Both operand-free and explicit returns require proven machine result storage.
/// [`crate::ir::direct_output::is_exact_return_storage`] accepts its exact SSA
/// spelling (for example `rax#7`) while rejecting a returned source local or
/// coalesced parameter. Recurses into nested If / While bodies. Only
/// comments/Nops may intervene, so the expression stays at the same observable
/// point and no state-changing operation is crossed.
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
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => fold_returns(body),
            Stmt::For { body, .. } => fold_returns(body),
            Stmt::Switch { cases, default, .. } => {
                for (_, body) in cases.iter_mut() {
                    fold_returns(body);
                }
                if let Some(b) = default {
                    fold_returns(b);
                }
            }
            _ => {}
        }
    }

    let mut i = 0;
    while i < body.len() {
        let Some(dst) = (match &body[i] {
            Stmt::Assign { dst, .. } if crate::ir::direct_output::is_exact_return_storage(dst) => {
                Some(dst.clone())
            }
            _ => None,
        }) else {
            i += 1;
            continue;
        };
        let mut return_index = i + 1;
        while matches!(body.get(return_index), Some(Stmt::Comment(_) | Stmt::Nop)) {
            return_index += 1;
        }
        let fold_here = match body.get(return_index) {
            Some(Stmt::Return { value: None }) => true,
            Some(Stmt::Return {
                value: Some(Expr::Reg(returned)),
            }) => returned == &dst,
            _ => false,
        };
        if fold_here {
            let Stmt::Assign { src, .. } = body.remove(i) else {
                unreachable!()
            };
            body[return_index - 1] = Stmt::Return { value: Some(src) };
            continue;
        }
        i += 1;
    }
}

/// Remove an ABI return-register assignment immediately before an identical
/// constant return. This deliberately runs after structural recovery: the
/// assignment may still identify a shared switch destination while the CFG is
/// being reconstructed, but it is redundant in the final source AST.
fn remove_redundant_return_constant_assignments(body: &mut Vec<Stmt>) {
    for stmt in body.iter_mut() {
        match stmt {
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                remove_redundant_return_constant_assignments(then_body);
                if let Some(else_body) = else_body {
                    remove_redundant_return_constant_assignments(else_body);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
                remove_redundant_return_constant_assignments(body);
            }
            Stmt::Switch { cases, default, .. } => {
                for (_, case_body) in cases {
                    remove_redundant_return_constant_assignments(case_body);
                }
                if let Some(default_body) = default {
                    remove_redundant_return_constant_assignments(default_body);
                }
            }
            _ => {}
        }
    }

    let mut index = 0;
    while index < body.len() {
        let assigned = match &body[index] {
            Stmt::Assign {
                dst,
                src: Expr::Const(value),
            } if crate::ir::direct_output::is_return_reg(dst) => Some(*value),
            _ => None,
        };
        let Some(assigned) = assigned else {
            index += 1;
            continue;
        };
        let mut return_index = index + 1;
        while matches!(body.get(return_index), Some(Stmt::Comment(_) | Stmt::Nop)) {
            return_index += 1;
        }
        let identical_return = matches!(
            body.get(return_index),
            Some(Stmt::Return {
                value: Some(Expr::Const(returned)),
            }) if *returned == assigned
        );
        if identical_return {
            body.remove(index);
            continue;
        }
        index += 1;
    }
}

/// Turn an exhaustive switch that defines one result immediately consumed by a
/// trailing return into returns in each arm.
///
/// An explicit default makes the switch exhaustive for every discriminator.
/// Requiring the same destination in every arm, immediately at the arm's end,
/// proves that the join contains no additional state transition to preserve.
/// The optional terminal `Break` is the structured spelling of the edge to that
/// join and disappears with the join itself.
pub fn fold_exhaustive_switch_returns(function: &mut Function) {
    // Typed/lossless range recovery can expose the switch only after an
    // adjacent `ret = cast(join); return ret` pair was first prepared. Normalize
    // that pair here as well so every caller sees the same join shape.
    fold_returns(&mut function.body);
    fold_exhaustive_switch_returns_body(&mut function.body);
}

/// Move a joined result return into every arm of an exhaustive `if` tree.
///
/// Both arms must end by defining the exact returned value (possibly through
/// another exhaustive `if`).  Calls and other statements earlier in an arm stay
/// in place; only its terminal definition becomes a return.  Machine-epilogue
/// comments and nops may separate the `if` from the joined return because they
/// carry no source-level state.
pub fn fold_exhaustive_if_returns(function: &mut Function) {
    fold_returns(&mut function.body);
    fold_exhaustive_if_returns_body(&mut function.body);
}

fn fold_exhaustive_if_returns_body(body: &mut Vec<Stmt>) {
    for statement in body.iter_mut() {
        match statement {
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                fold_exhaustive_if_returns_body(then_body);
                if let Some(else_body) = else_body {
                    fold_exhaustive_if_returns_body(else_body);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
                fold_exhaustive_if_returns_body(body)
            }
            Stmt::Switch { cases, default, .. } => {
                for (_, case_body) in cases {
                    fold_exhaustive_if_returns_body(case_body);
                }
                if let Some(default_body) = default {
                    fold_exhaustive_if_returns_body(default_body);
                }
            }
            _ => {}
        }
    }

    let mut index = 0;
    while index + 1 < body.len() {
        let mut return_index = index + 1;
        while match body.get(return_index) {
            Some(Stmt::Nop) => true,
            Some(Stmt::Comment(text)) => text.starts_with("x86-64 epilogue:"),
            _ => false,
        } {
            return_index += 1;
        }
        let Some((result, return_template)) = (match body.get(return_index) {
            Some(Stmt::Return { value: Some(value) }) => {
                cast_chain_root_reg(value).map(|result| (result.clone(), value.clone()))
            }
            _ => None,
        }) else {
            index += 1;
            continue;
        };
        let Stmt::If {
            cond,
            mut then_body,
            else_body: Some(mut else_body),
        } = body[index].clone()
        else {
            index += 1;
            continue;
        };
        if !turn_terminal_result_into_return(&mut then_body, &result, &return_template)
            || !turn_terminal_result_into_return(&mut else_body, &result, &return_template)
        {
            index += 1;
            continue;
        }

        body[index] = Stmt::If {
            cond,
            then_body,
            else_body: Some(else_body),
        };
        body.drain(index + 1..=return_index);
        index += 1;
    }
}

fn fold_exhaustive_switch_returns_body(body: &mut Vec<Stmt>) {
    for statement in body.iter_mut() {
        match statement {
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                fold_exhaustive_switch_returns_body(then_body);
                if let Some(else_body) = else_body {
                    fold_exhaustive_switch_returns_body(else_body);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
                fold_exhaustive_switch_returns_body(body);
            }
            Stmt::Switch { cases, default, .. } => {
                for (_, case_body) in cases {
                    fold_exhaustive_switch_returns_body(case_body);
                }
                if let Some(default_body) = default {
                    fold_exhaustive_switch_returns_body(default_body);
                }
            }
            _ => {}
        }
    }

    let mut index = 0;
    while index + 1 < body.len() {
        // Frame recognisers retain provenance comments at the machine epilogue.
        // They carry no state, so they do not invalidate an otherwise immediate
        // switch-result join.
        let mut return_index = index + 1;
        while matches!(body.get(return_index), Some(Stmt::Comment(_) | Stmt::Nop)) {
            return_index += 1;
        }
        let Some((result, return_template)) = (match body.get(return_index) {
            Some(Stmt::Return { value: Some(value) }) => {
                cast_chain_root_reg(value).map(|result| (result.clone(), value.clone()))
            }
            _ => None,
        }) else {
            index += 1;
            continue;
        };
        let Stmt::Switch {
            discriminant,
            mut cases,
            default: Some(mut default),
        } = body[index].clone()
        else {
            index += 1;
            continue;
        };

        if !cases.iter_mut().all(|(_, case_body)| {
            turn_terminal_result_into_return(case_body, &result, &return_template)
        }) || !turn_terminal_result_into_return(&mut default, &result, &return_template)
        {
            index += 1;
            continue;
        }

        body[index] = Stmt::Switch {
            discriminant,
            cases,
            default: Some(default),
        };
        body.remove(return_index);
        index += 1;
    }
}

fn cast_chain_root_reg(expr: &Expr) -> Option<&VReg> {
    match expr {
        Expr::Reg(reg) => Some(reg),
        Expr::Cast { expr, .. } => cast_chain_root_reg(expr),
        _ => None,
    }
}

fn apply_return_cast_template(template: &Expr, result: &VReg, value: Expr) -> Option<Expr> {
    match template {
        Expr::Reg(reg) if reg == result => Some(value),
        Expr::Cast {
            signed,
            width,
            expr,
        } => Some(Expr::Cast {
            signed: *signed,
            width: *width,
            expr: Box::new(apply_return_cast_template(expr, result, value)?),
        }),
        _ => None,
    }
}

fn turn_terminal_result_into_return(
    body: &mut Vec<Stmt>,
    result: &VReg,
    return_template: &Expr,
) -> bool {
    if matches!(body.last(), Some(Stmt::Break)) {
        body.pop();
    }
    let Some(last) = body.last_mut() else {
        return false;
    };
    match last {
        Stmt::Assign { dst, src } if dst == result => {
            let Some(value) = apply_return_cast_template(return_template, result, src.clone())
            else {
                return false;
            };
            *last = Stmt::Return { value: Some(value) };
            true
        }
        Stmt::Store {
            addr: Expr::Reg(dst),
            src,
            ..
        } if dst == result && matches!(&*dst, VReg::Phys(name) if is_promoted_local(name)) => {
            let Some(value) = apply_return_cast_template(return_template, result, src.clone())
            else {
                return false;
            };
            *last = Stmt::Return { value: Some(value) };
            true
        }
        Stmt::Return { .. } => true,
        Stmt::If {
            then_body,
            else_body: Some(else_body),
            ..
        } => {
            let mut converted_then = then_body.clone();
            let mut converted_else = else_body.clone();
            if !turn_terminal_result_into_return(&mut converted_then, result, return_template)
                || !turn_terminal_result_into_return(&mut converted_else, result, return_template)
            {
                return false;
            }
            *then_body = converted_then;
            *else_body = converted_else;
            true
        }
        _ => false,
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
// `docs/analysis/decompiler/pipeline.md`.

/// Render `f` as parseable C for the DecBench harness (and any consumer that
/// needs valid C rather than the register-level `render_c` view). See the
/// module-level notes above this function for the contract and rationale.
/// Map a recovered [`TypeHint`] to a concrete C type spelling. Widths and
/// signedness come from `types_recover`; pointers carry a pointee-width-derived
/// element type. This is what turns the blanket `long` into `int`/`unsigned
/// int`/`char *`/… for the DecBench renderer.
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

/// Correct declaration widths when the AST proves that the high half of an ABI
/// value is semantically live. Raw-register type recovery deliberately prefers a
/// narrow sub-register signal (`edi` -> 4 bytes), but that rule is wrong for a
/// packed SysV aggregate when the same incoming eightbyte is also shifted by 32
/// or masked above bit 31. The high-bit consumer is stronger evidence: narrowing
/// the C parameter would discard input bits before the body can inspect them.
///
/// The same dataflow supplies the return width. A result assembled from 64-bit
/// casts/operations must not inherit a stray final `eax` hint and render as
/// `int`, which truncates a valid machine `long` at the C ABI boundary.
pub(crate) fn refine_decbench_abi_widths(f: &Function, tm: &mut TypeMap) {
    refine_decbench_abi_widths_with_value_widths(f, tm, None);
}

/// Refine declarations after source-level preparation while retaining exact
/// per-SSA-value width evidence from value numbering.
pub(crate) fn refine_decbench_abi_widths_with_value_widths(
    f: &Function,
    tm: &mut TypeMap,
    value_widths: Option<&std::collections::HashMap<String, u8>>,
) {
    refine_signed_comparison_operands(&f.body, tm);

    let mut required_wide = std::collections::HashSet::new();
    collect_high_half_requirements(&f.body, &mut required_wide);

    // Carry a high-half requirement backwards through copy/definition chains:
    // `local_18 = arg0; y = (unsigned long)local_18 >> 32` proves `arg0` wide.
    loop {
        let before = required_wide.len();
        propagate_required_widths(&f.body, &mut required_wide);
        if required_wide.len() == before {
            break;
        }
    }
    for name in required_wide
        .iter()
        .filter(|name| parse_arg_index(name).is_some())
    {
        tm.force_int_width(VReg::phys(name), 8);
    }

    let mut defs = std::collections::HashMap::new();
    // AST names are almost SSA after value numbering, but promoted locals can
    // have multiple assignments. A bounded monotone fixed point handles both.
    loop {
        let before = defs.clone();
        collect_definition_widths(&f.body, tm, &mut defs);
        if defs == before {
            break;
        }
    }
    for (name, &ast_definition_width) in &defs {
        if !is_high_variable(name) || !all_definitions_proven_scalar(&f.body, name, tm) {
            continue;
        }
        let value = VReg::phys(name);
        if let Some(TypeHint::Int { signed, width }) = tm.get(&value) {
            let definition_width = value_widths
                .and_then(|widths| widths.get(name).copied())
                .unwrap_or(ast_definition_width);
            if definition_width > width {
                // The per-value semantic map belongs to the final rendered
                // identity and therefore outranks a prepared expression whose
                // copy/cast history no longer exposes its machine width.
                tm.force_scalar_int(value, signed, definition_width);
            }
        }
    }
    if let Some(width) = widest_return_value(&f.body, tm, &defs) {
        if all_definitions_proven_scalar(&f.body, "ret", tm) {
            // Raw rax reuse can attach an earlier address-computation pointer
            // hint to the final return role. Prepared value flow is stronger:
            // when every definition is explicitly scalar, the function cannot
            // have a pointer return merely because one physical register once
            // held an address.
            let ret = VReg::phys("ret");
            if let Some(TypeHint::Int {
                signed,
                width: recovered_width,
            }) = tm.get(&ret)
            {
                tm.force_scalar_int(ret, signed, recovered_width.max(width));
            } else {
                tm.force_scalar_int(ret, true, width);
            }
        } else if width >= 8 {
            tm.force_int_width(VReg::phys("ret"), 8);
        }
    }
    refine_pointer_access_widths(&f.body, tm);
}

/// Signed comparison operators carry source-level signedness evidence that is
/// lost when raw-register recovery also observes a zero-extended/index use.
/// Apply that evidence only to direct integer operands: signed arithmetic over
/// a composite expression does not prove every leaf has a signed declaration,
/// and semantic pointer hints must remain pointers.
fn refine_signed_comparison_operands(body: &[Stmt], tm: &mut TypeMap) {
    fn direct_signed_value(expr: &Expr) -> Option<&VReg> {
        match expr {
            Expr::Reg(reg) => Some(reg),
            Expr::Cast {
                signed: true, expr, ..
            } => direct_signed_value(expr),
            _ => None,
        }
    }

    fn expression(expr: &Expr, tm: &mut TypeMap) {
        match expr {
            Expr::Cmp { op, lhs, rhs } => {
                if matches!(op, CmpOp::Slt | CmpOp::Sle) {
                    for operand in [lhs.as_ref(), rhs.as_ref()] {
                        if let Some(reg) = direct_signed_value(operand) {
                            tm.force_int_signedness(reg.clone(), true);
                        }
                    }
                }
                expression(lhs, tm);
                expression(rhs, tm);
            }
            Expr::Deref { addr, .. } => expression(addr, tm),
            Expr::Bin { lhs, rhs, .. } => {
                expression(lhs, tm);
                expression(rhs, tm);
            }
            Expr::Un { src, .. } => expression(src, tm),
            Expr::Select {
                cond,
                if_true,
                if_false,
                ..
            } => {
                expression(cond, tm);
                expression(if_true, tm);
                expression(if_false, tm);
            }
            Expr::Cast { expr, .. } => expression(expr, tm),
            Expr::FunctionTableEntry { index, .. } => expression(index, tm),
            Expr::WideArithmetic { args, .. } => {
                for argument in args {
                    expression(argument, tm);
                }
            }
            Expr::Reg(_)
            | Expr::Const(_)
            | Expr::FloatConst { .. }
            | Expr::Addr(_)
            | Expr::Named { .. }
            | Expr::StringLit { .. }
            | Expr::StackAddr { .. }
            | Expr::Lea { .. }
            | Expr::PdbFieldAddr { .. }
            | Expr::Unknown(_) => {}
        }
    }

    fn statements(body: &[Stmt], tm: &mut TypeMap) {
        for statement in body {
            match statement {
                Stmt::Assign { src, .. } | Stmt::Return { value: Some(src) } => expression(src, tm),
                Stmt::Store { addr, src, .. } => {
                    expression(addr, tm);
                    expression(src, tm);
                }
                Stmt::Call { target, args, .. } => {
                    expression(target, tm);
                    for arg in args {
                        expression(arg, tm);
                    }
                }
                Stmt::IndirectGoto { target } | Stmt::Push { value: target } => {
                    expression(target, tm);
                }
                Stmt::If {
                    cond,
                    then_body,
                    else_body,
                } => {
                    expression(cond, tm);
                    statements(then_body, tm);
                    if let Some(else_body) = else_body {
                        statements(else_body, tm);
                    }
                }
                Stmt::While { cond, body } | Stmt::DoWhile { cond, body } => {
                    expression(cond, tm);
                    statements(body, tm);
                }
                Stmt::For {
                    init,
                    cond,
                    step,
                    body,
                } => {
                    statements(std::slice::from_ref(init.as_ref()), tm);
                    expression(cond, tm);
                    statements(std::slice::from_ref(step.as_ref()), tm);
                    statements(body, tm);
                }
                Stmt::Switch {
                    discriminant,
                    cases,
                    default,
                } => {
                    expression(discriminant, tm);
                    for (_, case_body) in cases {
                        statements(case_body, tm);
                    }
                    if let Some(default) = default {
                        statements(default, tm);
                    }
                }
                Stmt::Return { value: None }
                | Stmt::Label(_)
                | Stmt::Goto { .. }
                | Stmt::Break
                | Stmt::Nop
                | Stmt::Unknown(_)
                | Stmt::Comment(_)
                | Stmt::Pop { .. } => {}
                Stmt::Throw { value } => expression(value, tm),
                Stmt::TryCatch { try_body, catches } => {
                    statements(try_body, tm);
                    for catch in catches {
                        statements(&catch.body, tm);
                    }
                }
            }
        }
    }

    statements(body, tm);
}

fn all_definitions_proven_scalar(body: &[Stmt], target: &str, tm: &TypeMap) -> bool {
    fn walk(body: &[Stmt], target: &str, tm: &TypeMap, found: &mut bool, valid: &mut bool) {
        for statement in body {
            match statement {
                Stmt::Assign {
                    dst: VReg::Phys(name),
                    src,
                } if name == target => {
                    *found = true;
                    *valid &= expression_proven_scalar(src, tm);
                }
                Stmt::Call {
                    dst: Some(VReg::Phys(name)),
                    ..
                } if name == target => {
                    // Without a recovered callee prototype, a call result may
                    // legitimately be a pointer.
                    *found = true;
                    *valid = false;
                }
                Stmt::If {
                    then_body,
                    else_body,
                    ..
                } => {
                    walk(then_body, target, tm, found, valid);
                    if let Some(else_body) = else_body {
                        walk(else_body, target, tm, found, valid);
                    }
                }
                Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
                    walk(body, target, tm, found, valid)
                }
                Stmt::For {
                    init, step, body, ..
                } => {
                    walk(
                        std::slice::from_ref(init.as_ref()),
                        target,
                        tm,
                        found,
                        valid,
                    );
                    walk(
                        std::slice::from_ref(step.as_ref()),
                        target,
                        tm,
                        found,
                        valid,
                    );
                    walk(body, target, tm, found, valid);
                }
                Stmt::Switch { cases, default, .. } => {
                    for (_, case) in cases {
                        walk(case, target, tm, found, valid);
                    }
                    if let Some(default) = default {
                        walk(default, target, tm, found, valid);
                    }
                }
                _ => {}
            }
        }
    }

    let mut found = false;
    let mut valid = true;
    walk(body, target, tm, &mut found, &mut valid);
    found && valid
}

fn expression_proven_scalar(expr: &Expr, tm: &TypeMap) -> bool {
    match expr {
        Expr::Const(_) | Expr::FloatConst { .. } | Expr::Cmp { .. } | Expr::Cast { .. } => true,
        Expr::Reg(VReg::Phys(name)) => matches!(
            tm.get(&VReg::phys(name)),
            Some(TypeHint::Int { .. } | TypeHint::BoolLike)
        ),
        Expr::Bin { lhs, rhs, .. } => {
            expression_proven_scalar(lhs, tm) && expression_proven_scalar(rhs, tm)
        }
        Expr::Un { src, .. } => expression_proven_scalar(src, tm),
        Expr::Select {
            if_true, if_false, ..
        } => expression_proven_scalar(if_true, tm) && expression_proven_scalar(if_false, tm),
        Expr::WideArithmetic { .. } => true,
        Expr::Unknown(_)
        | Expr::Reg(_)
        | Expr::Addr(_)
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::Deref { .. }
        | Expr::StackAddr { .. }
        | Expr::Lea { .. }
        | Expr::PdbFieldAddr { .. } => false,
        Expr::FunctionTableEntry { .. } => false,
    }
}

fn refine_pointer_access_widths(body: &[Stmt], tm: &mut TypeMap) {
    let mut observed: std::collections::HashMap<String, std::collections::BTreeSet<u8>> =
        std::collections::HashMap::new();
    collect_pointer_accesses_body(body, tm, &mut observed);
    for (name, widths) in observed {
        if widths.len() == 1 {
            tm.force_pointer_width(
                VReg::phys(&name),
                *widths.first().expect("one observed pointer width"),
            );
        }
    }
}

fn collect_pointer_accesses_body(
    body: &[Stmt],
    tm: &TypeMap,
    observed: &mut std::collections::HashMap<String, std::collections::BTreeSet<u8>>,
) {
    for statement in body {
        match statement {
            Stmt::Assign { src, .. } | Stmt::Push { value: src } => {
                collect_pointer_accesses_expr(src, tm, observed)
            }
            Stmt::Store { addr, src, size } => {
                if !matches!(addr, Expr::Reg(VReg::Phys(name)) if is_promoted_local(name)) {
                    record_pointer_access(addr, *size, tm, observed);
                }
                collect_pointer_accesses_expr(addr, tm, observed);
                collect_pointer_accesses_expr(src, tm, observed);
            }
            Stmt::Call { target, args, .. } => {
                collect_pointer_accesses_expr(target, tm, observed);
                for arg in args {
                    collect_pointer_accesses_expr(arg, tm, observed);
                }
            }
            Stmt::Return { value: Some(value) } | Stmt::IndirectGoto { target: value } => {
                collect_pointer_accesses_expr(value, tm, observed)
            }
            Stmt::If {
                cond,
                then_body,
                else_body,
            } => {
                collect_pointer_accesses_expr(cond, tm, observed);
                collect_pointer_accesses_body(then_body, tm, observed);
                if let Some(else_body) = else_body {
                    collect_pointer_accesses_body(else_body, tm, observed);
                }
            }
            Stmt::While { cond, body } | Stmt::DoWhile { cond, body } => {
                collect_pointer_accesses_expr(cond, tm, observed);
                collect_pointer_accesses_body(body, tm, observed);
            }
            Stmt::For {
                init,
                cond,
                step,
                body,
            } => {
                collect_pointer_accesses_body(std::slice::from_ref(init.as_ref()), tm, observed);
                collect_pointer_accesses_expr(cond, tm, observed);
                collect_pointer_accesses_body(std::slice::from_ref(step.as_ref()), tm, observed);
                collect_pointer_accesses_body(body, tm, observed);
            }
            Stmt::Switch {
                discriminant,
                cases,
                default,
            } => {
                collect_pointer_accesses_expr(discriminant, tm, observed);
                for (_, case) in cases {
                    collect_pointer_accesses_body(case, tm, observed);
                }
                if let Some(default) = default {
                    collect_pointer_accesses_body(default, tm, observed);
                }
            }
            _ => {}
        }
    }
}

fn collect_pointer_accesses_expr(
    expr: &Expr,
    tm: &TypeMap,
    observed: &mut std::collections::HashMap<String, std::collections::BTreeSet<u8>>,
) {
    match expr {
        Expr::Deref { addr, size } => {
            record_pointer_access(addr, *size, tm, observed);
            collect_pointer_accesses_expr(addr, tm, observed);
        }
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            collect_pointer_accesses_expr(lhs, tm, observed);
            collect_pointer_accesses_expr(rhs, tm, observed);
        }
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => {
            collect_pointer_accesses_expr(cond, tm, observed);
            collect_pointer_accesses_expr(if_true, tm, observed);
            collect_pointer_accesses_expr(if_false, tm, observed);
        }
        Expr::Un { src, .. } | Expr::Cast { expr: src, .. } => {
            collect_pointer_accesses_expr(src, tm, observed)
        }
        _ => {}
    }
}

fn record_pointer_access(
    addr: &Expr,
    size: u8,
    tm: &TypeMap,
    observed: &mut std::collections::HashMap<String, std::collections::BTreeSet<u8>>,
) {
    if let Some(name) = direct_pointer_base(addr, tm) {
        observed.entry(name.to_string()).or_default().insert(size);
    }
}

fn direct_pointer_base<'a>(addr: &'a Expr, tm: &TypeMap) -> Option<&'a str> {
    let is_pointer =
        |name: &str| matches!(tm.get(&VReg::phys(name)), Some(TypeHint::Pointer { .. }));
    match addr {
        Expr::Reg(VReg::Phys(name)) if is_pointer(name) => Some(name),
        Expr::Lea {
            base: Some(VReg::Phys(name)),
            segment: None,
            ..
        }
        | Expr::PdbFieldAddr {
            base: Some(VReg::Phys(name)),
            segment: None,
            ..
        } if is_pointer(name) => Some(name),
        Expr::Bin {
            op: BinOp::Add,
            lhs,
            rhs,
        } => {
            let lhs = match lhs.as_ref() {
                Expr::Reg(VReg::Phys(name)) if is_pointer(name) => Some(name.as_str()),
                _ => None,
            };
            let rhs = match rhs.as_ref() {
                Expr::Reg(VReg::Phys(name)) if is_pointer(name) => Some(name.as_str()),
                _ => None,
            };
            match (lhs, rhs) {
                (Some(name), None) | (None, Some(name)) => Some(name),
                _ => None,
            }
        }
        _ => None,
    }
}

fn constant_needs_wide_word(value: i64) -> bool {
    value < i64::from(i32::MIN) || value > i64::from(u32::MAX)
}

fn collect_high_half_requirements(body: &[Stmt], required: &mut std::collections::HashSet<String>) {
    for stmt in body {
        match stmt {
            Stmt::Assign { src, .. } | Stmt::Push { value: src } => {
                collect_high_half_expr(src, required)
            }
            Stmt::Store { addr, src, .. } => {
                collect_high_half_expr(addr, required);
                collect_high_half_expr(src, required);
            }
            Stmt::Call { target, args, .. } => {
                collect_high_half_expr(target, required);
                for arg in args {
                    collect_high_half_expr(arg, required);
                }
            }
            Stmt::Return { value: Some(expr) } | Stmt::IndirectGoto { target: expr } => {
                collect_high_half_expr(expr, required)
            }
            Stmt::If {
                cond,
                then_body,
                else_body,
            } => {
                collect_high_half_expr(cond, required);
                collect_high_half_requirements(then_body, required);
                if let Some(else_body) = else_body {
                    collect_high_half_requirements(else_body, required);
                }
            }
            Stmt::While { cond, body } | Stmt::DoWhile { cond, body } => {
                collect_high_half_expr(cond, required);
                collect_high_half_requirements(body, required);
            }
            Stmt::For {
                init,
                cond,
                step,
                body,
            } => {
                collect_high_half_requirements(std::slice::from_ref(init.as_ref()), required);
                collect_high_half_expr(cond, required);
                collect_high_half_requirements(std::slice::from_ref(step.as_ref()), required);
                collect_high_half_requirements(body, required);
            }
            Stmt::Switch {
                discriminant,
                cases,
                default,
            } => {
                collect_high_half_expr(discriminant, required);
                for (_, case) in cases {
                    collect_high_half_requirements(case, required);
                }
                if let Some(default) = default {
                    collect_high_half_requirements(default, required);
                }
            }
            _ => {}
        }
    }
}

fn collect_high_half_expr(expr: &Expr, required: &mut std::collections::HashSet<String>) {
    match expr {
        Expr::Bin { op, lhs, rhs } => {
            let high_shift = matches!(op, BinOp::Shl | BinOp::Shr | BinOp::Sar)
                && matches!(rhs.as_ref(), Expr::Const(count) if *count >= 32);
            if high_shift {
                require_wide_expr(lhs, required);
            }
            if matches!(lhs.as_ref(), Expr::Const(value) if constant_needs_wide_word(*value)) {
                require_wide_expr(rhs, required);
            }
            if matches!(rhs.as_ref(), Expr::Const(value) if constant_needs_wide_word(*value)) {
                require_wide_expr(lhs, required);
            }
            collect_high_half_expr(lhs, required);
            collect_high_half_expr(rhs, required);
        }
        Expr::Un { src, .. } | Expr::Cast { expr: src, .. } | Expr::Deref { addr: src, .. } => {
            collect_high_half_expr(src, required)
        }
        Expr::Cmp { lhs, rhs, .. } => {
            collect_high_half_expr(lhs, required);
            collect_high_half_expr(rhs, required);
        }
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => {
            collect_high_half_expr(cond, required);
            collect_high_half_expr(if_true, required);
            collect_high_half_expr(if_false, required);
        }
        _ => {}
    }
}

fn require_wide_expr(expr: &Expr, required: &mut std::collections::HashSet<String>) {
    match expr {
        Expr::Reg(VReg::Phys(name)) => {
            required.insert(name.clone());
        }
        Expr::Bin { op, lhs, rhs } => {
            require_wide_expr(lhs, required);
            if !matches!(op, BinOp::Shl | BinOp::Shr | BinOp::Sar) {
                require_wide_expr(rhs, required);
            }
        }
        Expr::Un { src, .. } | Expr::Cast { expr: src, .. } => require_wide_expr(src, required),
        Expr::Select {
            if_true, if_false, ..
        } => {
            require_wide_expr(if_true, required);
            require_wide_expr(if_false, required);
        }
        _ => {}
    }
}

fn propagate_required_widths(body: &[Stmt], required: &mut std::collections::HashSet<String>) {
    for stmt in body {
        match stmt {
            Stmt::Assign {
                dst: VReg::Phys(name),
                src,
            } if required.contains(name) => require_wide_expr(src, required),
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                propagate_required_widths(then_body, required);
                if let Some(else_body) = else_body {
                    propagate_required_widths(else_body, required);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
                propagate_required_widths(body, required)
            }
            Stmt::For {
                init, step, body, ..
            } => {
                propagate_required_widths(std::slice::from_ref(init.as_ref()), required);
                propagate_required_widths(std::slice::from_ref(step.as_ref()), required);
                propagate_required_widths(body, required);
            }
            Stmt::Switch { cases, default, .. } => {
                for (_, case) in cases {
                    propagate_required_widths(case, required);
                }
                if let Some(default) = default {
                    propagate_required_widths(default, required);
                }
            }
            _ => {}
        }
    }
}

fn type_hint_width(hint: TypeHint) -> Option<u8> {
    match hint {
        TypeHint::Int { width, .. } => Some(width),
        TypeHint::Float { width } => Some(width),
        TypeHint::Pointer { .. } | TypeHint::CodePointer => Some(8),
        TypeHint::BoolLike => Some(4),
    }
}

fn expression_value_width(
    expr: &Expr,
    tm: &TypeMap,
    defs: &std::collections::HashMap<String, u8>,
) -> Option<u8> {
    match expr {
        Expr::Reg(VReg::Phys(name)) => defs
            .get(name)
            .copied()
            .or_else(|| tm.get(&VReg::phys(name)).and_then(type_hint_width)),
        Expr::Const(value) => Some(if constant_needs_wide_word(*value) {
            8
        } else {
            4
        }),
        Expr::FloatConst { width, .. } => Some(*width),
        Expr::Addr(_)
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::StackAddr { .. }
        | Expr::Lea { .. }
        | Expr::PdbFieldAddr { .. } => Some(8),
        Expr::FunctionTableEntry { pointer_size, .. } => Some(*pointer_size),
        Expr::Deref { size, .. } => Some(*size),
        // x86's ordinary 32-bit return write is represented after
        // canonicalisation as a zero-extension into the 64-bit parent. That
        // machine housekeeping does not turn a C `int` return into `long`.
        // When the inner expression is explicitly narrowed first, keep its
        // semantic width and let the recovered return hint decide the ABI.
        Expr::Cast {
            signed: false,
            width: 8,
            expr: inner,
        } if matches!(inner.as_ref(), Expr::Cast { width: 1..=4, .. }) => {
            expression_value_width(inner, tm, defs)
        }
        Expr::Cast { width, .. } => Some(*width),
        Expr::Bin { op, lhs, rhs } => {
            let lhs_width = expression_value_width(lhs, tm, defs);
            if matches!(op, BinOp::Shl | BinOp::Shr | BinOp::Sar) {
                if matches!(rhs.as_ref(), Expr::Const(count) if *count >= 32) {
                    Some(lhs_width.unwrap_or(8).max(8))
                } else {
                    lhs_width
                }
            } else {
                let rhs_width = expression_value_width(rhs, tm, defs);
                lhs_width.into_iter().chain(rhs_width).max()
            }
        }
        Expr::Un { src, .. } => expression_value_width(src, tm, defs),
        Expr::Cmp { .. } => Some(4),
        Expr::Select { width, .. } => Some(*width),
        Expr::WideArithmetic { width, .. } => Some(*width),
        Expr::Unknown(_) | Expr::Reg(_) => None,
    }
}

fn collect_definition_widths(
    body: &[Stmt],
    tm: &TypeMap,
    defs: &mut std::collections::HashMap<String, u8>,
) {
    for stmt in body {
        match stmt {
            Stmt::Assign {
                dst: VReg::Phys(name),
                src,
            } => {
                if let Some(width) = expression_value_width(src, tm, defs) {
                    defs.entry(name.clone())
                        .and_modify(|old| *old = (*old).max(width))
                        .or_insert(width);
                }
            }
            Stmt::Call {
                dst: Some(VReg::Phys(name)),
                ..
            } => {
                if let Some(width) = tm.get(&VReg::phys(name)).and_then(type_hint_width) {
                    defs.entry(name.clone())
                        .and_modify(|old| *old = (*old).max(width))
                        .or_insert(width);
                }
            }
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                collect_definition_widths(then_body, tm, defs);
                if let Some(else_body) = else_body {
                    collect_definition_widths(else_body, tm, defs);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
                collect_definition_widths(body, tm, defs)
            }
            Stmt::For {
                init, step, body, ..
            } => {
                collect_definition_widths(std::slice::from_ref(init.as_ref()), tm, defs);
                collect_definition_widths(std::slice::from_ref(step.as_ref()), tm, defs);
                collect_definition_widths(body, tm, defs);
            }
            Stmt::Switch { cases, default, .. } => {
                for (_, case) in cases {
                    collect_definition_widths(case, tm, defs);
                }
                if let Some(default) = default {
                    collect_definition_widths(default, tm, defs);
                }
            }
            _ => {}
        }
    }
}

fn widest_return_value(
    body: &[Stmt],
    tm: &TypeMap,
    defs: &std::collections::HashMap<String, u8>,
) -> Option<u8> {
    body.iter()
        .filter_map(|stmt| match stmt {
            Stmt::Return { value: Some(expr) } => expression_value_width(expr, tm, defs),
            Stmt::If {
                then_body,
                else_body,
                ..
            } => widest_return_value(then_body, tm, defs)
                .into_iter()
                .chain(
                    else_body
                        .as_deref()
                        .and_then(|body| widest_return_value(body, tm, defs)),
                )
                .max(),
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
                widest_return_value(body, tm, defs)
            }
            Stmt::Switch { cases, default, .. } => cases
                .iter()
                .filter_map(|(_, case)| widest_return_value(case, tm, defs))
                .chain(
                    default
                        .as_deref()
                        .and_then(|body| widest_return_value(body, tm, defs)),
                )
                .max(),
            _ => None,
        })
        .max()
}

/// The `(signed, byte-width)` an identifier is actually **declared** with in the
/// DecBench render, or `None` when it is not an integer.
///
/// This is the one rule, shared with the declaration printer and with
/// [`crate::ir::widen`]: arguments and promoted stack slots take their recovered
/// integer type. Exact SSA-derived `varN` identities use their value-specific
/// integer fact when one exists; otherwise they remain machine-word integers
/// unless the prepared high-variable proof classifies them as pointers. Other
/// raw machine registers and temps are also declared `long`.
pub(crate) fn declared_int_type(ident: &str, tm: Option<&TypeMap>) -> Option<(bool, u8)> {
    if is_high_variable(ident) {
        return match tm.and_then(|types| types.get(&VReg::Phys(ident.to_string()))) {
            Some(TypeHint::Int { signed, width }) => Some((signed, width)),
            Some(TypeHint::Pointer { .. } | TypeHint::CodePointer | TypeHint::Float { .. }) => None,
            _ => Some((true, 8)),
        };
    }
    if parse_arg_index(ident).is_none() && !is_promoted_local(ident) {
        // Declared `long`: already machine-wide, never narrowed.
        return Some((true, 8));
    }
    match tm?.get(&VReg::Phys(ident.to_string()))? {
        TypeHint::Int { signed, width } => Some((signed, width)),
        _ => None,
    }
}

/// The C type of an expression from recovered types, when determinable. Value-
/// keyed: types the value the expression denotes, not a fixed register name.
fn expr_ctype(e: &Expr, tm: Option<&TypeMap>) -> Option<&'static str> {
    match e {
        Expr::Reg(VReg::Phys(n)) => tm
            .and_then(|m| m.get(&VReg::Phys(n.clone())))
            .map(hint_to_ctype),
        // A 32-bit x86 return write is represented losslessly as
        // `zext64(cast32(value))`. The outer cast is ABI register
        // housekeeping, not evidence that the source function returned
        // `unsigned long`. Prefer the inner value's recovered integer type,
        // then the recovered return hint, when either has the exact inner
        // width. This also prevents an unrelated earlier pointer use of `rax`
        // from deciding the signature.
        Expr::Cast {
            signed: false,
            width: 8,
            expr: inner,
        } if matches!(inner.as_ref(), Expr::Cast { width: 1..=4, .. }) => {
            let Expr::Cast {
                signed,
                width,
                expr: value,
            } = inner.as_ref()
            else {
                unreachable!()
            };
            expr_ctype(value, tm)
                .filter(|ctype| integer_ctype_width(ctype) == Some(*width))
                .or_else(|| {
                    tm.and_then(|types| types.get(&VReg::phys("ret")))
                        .and_then(|hint| match hint {
                            TypeHint::Int {
                                signed,
                                width: recovered_width,
                            } if recovered_width == *width => {
                                Some(int_ctype(signed, recovered_width))
                            }
                            _ => None,
                        })
                })
                .or_else(|| Some(target_int_ctype(*signed, *width)))
        }
        // `Expr::Cast` is an integer cast by construction. Its target type is
        // stronger return-type evidence than a flow-insensitive physical
        // register hint.
        Expr::Cast { signed, width, .. } if tm.is_some() => Some(target_int_ctype(*signed, *width)),
        // C comparison operators produce `int`.  This is an expression-level
        // language rule and therefore outranks whichever narrow sub-register
        // (`al` for SETcc) happened to materialise the value on the machine.
        Expr::Cmp { .. } if tm.is_some() => Some("int"),
        // A bare integer literal return (`return 0;`) — most often a function
        // whose real return value was lost to structuring — is an `int`. Only
        // claim this on the typed render path; the untyped path (`tm` is None)
        // stays blanket-`long` by contract.
        Expr::Const(_) if tm.is_some() => Some("int"),
        Expr::FloatConst { width: 4, .. } if tm.is_some() => Some("float"),
        Expr::FloatConst { .. } if tm.is_some() => Some("double"),
        _ => None,
    }
}

fn integer_ctype_width(ctype: &str) -> Option<u8> {
    match ctype {
        "signed char" | "unsigned char" | "char" => Some(1),
        "short" | "unsigned short" => Some(2),
        "int" | "unsigned int" => Some(4),
        "long" | "unsigned long" => Some(8),
        _ => None,
    }
}

/// The function's C return type, derived from the value *actually returned*
/// rather than from a register literally named `ret`. Walks to the first
/// `return <expr>` and types that expression; falls back to `ctype_for("ret")`
/// (finally `long`) when the returned value has no recovered type.
///
/// This is the value-keyed replacement for the bare-`ret` string lookup, which
/// silently defaulted to `long` whenever value renaming moved the return value
/// off the `ret` name (e.g. a return computed as a promoted local `local_8`).
pub(crate) fn infer_return_ctype(body: &[Stmt], tm: Option<&TypeMap>) -> &'static str {
    let ret = VReg::phys("ret");
    if let Some(types) = tm.filter(|types| types.is_locked(&ret)) {
        return types.get(&ret).map(hint_to_ctype).unwrap_or("long");
    }
    first_return_value_ctype(body, tm).unwrap_or_else(|| ctype_for("ret", tm))
}

/// The byte width of the return type this render will declare.
///
/// [`crate::ir::widen`] needs it: a `return` is not automatically a 64-bit context.
/// A function declared to return `int` returns a value the machine computed in 32
/// bits, and widening its operands would compute at 64 (`wrap_sub_u32`'s borrow
/// must not escape the low word).
pub(crate) fn inferred_return_width(body: &[Stmt], tm: Option<&TypeMap>) -> u8 {
    match infer_return_ctype(body, tm) {
        "signed char" | "unsigned char" | "char" => 1,
        "short" | "unsigned short" => 2,
        "int" | "unsigned int" | "float" => 4,
        _ => 8,
    }
}

/// Remove a machine-only zero-extension around a returned narrow integer once
/// the recovered C signature proves that the return conversion has that exact
/// narrow width.
///
/// The typed AST deliberately retains `zext64(cast32(value))` until this late
/// boundary so dataflow, predicates, and widening see the real machine value.
/// Printing the outer wrapper in `return`, however, turns ABI bookkeeping into
/// noisy source C. A function declared to return the inner width performs that
/// widening at the ABI boundary, so the outer cast alone is removed. The inner
/// cast remains because it may carry a real truncation or signedness conversion;
/// arbitrary casts and wide-return signatures remain untouched.
pub(crate) fn fold_typed_return_abi_extensions(f: &mut Function, tm: &TypeMap) {
    let return_width = inferred_return_width(&f.body, Some(tm));
    fold_return_abi_extensions_body(&mut f.body, return_width);
}

fn fold_return_abi_extensions_body(body: &mut [Stmt], return_width: u8) {
    for statement in body {
        match statement {
            Stmt::Return { value: Some(value) } => {
                let replacement = match value {
                    Expr::Cast {
                        signed: false,
                        width: 8,
                        expr: inner,
                    } => match inner.as_ref() {
                        Expr::Cast { width, .. } if *width <= 4 && *width == return_width => {
                            Some(inner.as_ref().clone())
                        }
                        _ => None,
                    },
                    _ => None,
                };
                if let Some(replacement) = replacement {
                    *value = replacement;
                }
            }
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                fold_return_abi_extensions_body(then_body, return_width);
                if let Some(else_body) = else_body {
                    fold_return_abi_extensions_body(else_body, return_width);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
                fold_return_abi_extensions_body(body, return_width);
            }
            Stmt::Switch { cases, default, .. } => {
                for (_, case_body) in cases {
                    fold_return_abi_extensions_body(case_body, return_width);
                }
                if let Some(default) = default {
                    fold_return_abi_extensions_body(default, return_width);
                }
            }
            _ => {}
        }
    }
}

fn first_return_value_ctype(body: &[Stmt], tm: Option<&TypeMap>) -> Option<&'static str> {
    for s in body {
        match s {
            Stmt::Return { value: Some(e) } => {
                if let Some(t) = expr_ctype(e, tm) {
                    return Some(t);
                }
            }
            // A bare machine return renders a synthesized `return 0;` only
            // because lowering could not express the output operation. An
            // SSA-qualified prototype result is stronger evidence than that
            // placeholder. Fall back to `int` only when no result type exists.
            Stmt::Return { value: None } if tm.is_some() => {
                return tm
                    .and_then(|types| types.get(&VReg::phys("ret")))
                    .map(hint_to_ctype)
                    .or(Some("int"));
            }
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                if let Some(t) = first_return_value_ctype(then_body, tm) {
                    return Some(t);
                }
                if let Some(eb) = else_body {
                    if let Some(t) = first_return_value_ctype(eb, tm) {
                        return Some(t);
                    }
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
                if let Some(t) = first_return_value_ctype(body, tm) {
                    return Some(t);
                }
            }
            Stmt::For { body, .. } => {
                if let Some(t) = first_return_value_ctype(body, tm) {
                    return Some(t);
                }
            }
            Stmt::Switch { cases, default, .. } => {
                for (_, b) in cases {
                    if let Some(t) = first_return_value_ctype(b, tm) {
                        return Some(t);
                    }
                }
                if let Some(b) = default {
                    if let Some(t) = first_return_value_ctype(b, tm) {
                        return Some(t);
                    }
                }
            }
            _ => {}
        }
    }
    None
}

/// Untyped entry point (blanket `long`) — used by unit tests and any consumer
/// that has no recovered types.
/// Untyped DecBench rendering of an already-prepared function (see
/// [`prepare_for_decbench`]). Formatting only.
pub fn render_decbench(f: &Function) -> String {
    render_decbench_typed(f, None, None)
}

/// Render `f` as parseable C for DecBench, typing the return value and
/// arguments from `tm` (a TypeMap already remapped to the AST's role names —
/// `arg0`, `ret`, …). Locals stay `long` for now (their TypeMap keys do not
/// survive register renaming; a later pass will type stack slots by size).
/// Coalesce a parameter's spill slot with the parameter. At `-O0` the compiler
/// spills each parameter to a frame slot and reads it back; our lifting turns
/// that slot into a *separate* named local and emits `local_X = argN`, so the
/// recompiled code copies the parameter into a second stack slot the original
/// never used (extra `mov`s + a shifted stack layout that diverges byte_match).
///
/// When a promoted local is the home of exactly one argument — its only
/// register-sourced store is `local_X = argN` — that local *is* the parameter:
/// rename every `local_X` to `argN` and drop the resulting self-assignment. The
/// parameter is then used directly, matching the compiler's own `-O0` codegen.
fn coalesce_param_spills(
    body: &mut Vec<Stmt>,
    protected_locals: &std::collections::HashSet<String>,
) {
    coalesce_frame_object_param_spills(body);
    coalesce_named_param_spills(body, protected_locals);
}

/// Coalesce promoted named slots without reopening frame-object alias proofs.
fn coalesce_named_param_spills(
    body: &mut Vec<Stmt>,
    protected_locals: &std::collections::HashSet<String>,
) {
    // local name -> the single argument it is spilled from ("" = disqualified).
    let mut home: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    collect_param_homes(body, &mut home);
    let map: std::collections::HashMap<String, String> = home
        .into_iter()
        .filter(|(_, arg)| !arg.is_empty())
        // An authoritative source local remains a distinct C object even when
        // its first value is copied from a parameter. Collapsing `child = n`
        // into the parameter is unsound when `child` is later mutated and the
        // original `n` is still read (for example heap insertion's return).
        .filter(|(slot, _)| !protected_locals.contains(slot))
        .filter(|(slot, arg)| {
            let slot = VReg::phys(slot.clone());
            let argument = VReg::phys(arg.clone());
            // Substitution is safe only while the two names remain
            // interchangeable in both directions. A later slot write must not
            // reach an argument read, and an ABI-register overwrite (for
            // example a recursive call result in arg0) must not reach a later
            // reload of the saved slot.
            !crate::ir::structured_reaching::read_may_observe_prior_write(body, &argument, &slot)
                && !crate::ir::structured_reaching::read_may_observe_prior_write(
                    body, &slot, &argument,
                )
        })
        .collect();
    if map.is_empty() {
        return;
    }
    // Convert the slot's own stores to assignments BEFORE renaming, while the name
    // still says `local_`/`stack_` — see `slot_stores_to_assigns`.
    slot_stores_to_assigns(body, &map);
    rename_phys_in_body(body, &map);
    drop_self_stores(body);
}

#[derive(Clone)]
struct FrameParamHome {
    addr: Expr,
    size: u8,
    arg: Option<String>,
    stores: usize,
}

/// Coalesce an immutable parameter home that lives at a fixed offset inside a
/// recovered frame byte-array.
///
/// ARM32 `-O0` frames are intentionally represented as one byte object when
/// saved-register and local ranges overlap. That prevents the ordinary
/// promoted-local coalescer above from seeing `frame + 4` as a named slot. A
/// pointer parameter then round-trips through a four-byte C integer in that
/// byte array and is truncated when the recovered source is executed on LP64.
/// An address with exactly one store, sourced from an entry argument, is an
/// immutable home: replace exact same-width reloads by the argument and remove
/// the redundant store. Any second store disqualifies the address, including a
/// source-level reassignment, so this cannot erase mutable stack state.
fn coalesce_frame_object_param_spills(body: &mut Vec<Stmt>) {
    let mut homes = Vec::new();
    collect_frame_param_homes(body, &mut homes);
    homes.retain(|home| {
        home.stores == 1 && home.arg.is_some() && body_reads_exact_frame_home(body, home)
    });
    if homes.is_empty() {
        return;
    }
    rewrite_frame_param_homes(body, &homes);
}

fn expr_reads_exact_frame_home(expr: &Expr, home: &FrameParamHome) -> bool {
    if matches!(expr, Expr::Deref { addr, size } if *size == home.size && **addr == home.addr) {
        return true;
    }
    match expr {
        Expr::Deref { addr, .. } => expr_reads_exact_frame_home(addr, home),
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            expr_reads_exact_frame_home(lhs, home) || expr_reads_exact_frame_home(rhs, home)
        }
        Expr::Un { src, .. } | Expr::Cast { expr: src, .. } => {
            expr_reads_exact_frame_home(src, home)
        }
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => {
            expr_reads_exact_frame_home(cond, home)
                || expr_reads_exact_frame_home(if_true, home)
                || expr_reads_exact_frame_home(if_false, home)
        }
        Expr::FunctionTableEntry { index, .. } => expr_reads_exact_frame_home(index, home),
        Expr::WideArithmetic { args, .. } => args
            .iter()
            .any(|arg| expr_reads_exact_frame_home(arg, home)),
        _ => false,
    }
}

fn body_reads_exact_frame_home(body: &[Stmt], home: &FrameParamHome) -> bool {
    body.iter().any(|statement| match statement {
        Stmt::Assign { src, .. } => expr_reads_exact_frame_home(src, home),
        Stmt::Store { addr, src, .. } => {
            expr_reads_exact_frame_home(addr, home) || expr_reads_exact_frame_home(src, home)
        }
        Stmt::Call { target, args, .. } => {
            expr_reads_exact_frame_home(target, home)
                || args
                    .iter()
                    .any(|arg| expr_reads_exact_frame_home(arg, home))
        }
        Stmt::Return { value: Some(value) } => expr_reads_exact_frame_home(value, home),
        Stmt::Push { value } | Stmt::Throw { value } => expr_reads_exact_frame_home(value, home),
        Stmt::If {
            cond,
            then_body,
            else_body,
        } => {
            expr_reads_exact_frame_home(cond, home)
                || body_reads_exact_frame_home(then_body, home)
                || else_body
                    .as_deref()
                    .is_some_and(|body| body_reads_exact_frame_home(body, home))
        }
        Stmt::While { cond, body } | Stmt::DoWhile { cond, body } => {
            expr_reads_exact_frame_home(cond, home) || body_reads_exact_frame_home(body, home)
        }
        Stmt::For {
            init,
            cond,
            step,
            body,
        } => {
            body_reads_exact_frame_home(std::slice::from_ref(init.as_ref()), home)
                || expr_reads_exact_frame_home(cond, home)
                || body_reads_exact_frame_home(body, home)
                || body_reads_exact_frame_home(std::slice::from_ref(step.as_ref()), home)
        }
        Stmt::Switch {
            discriminant,
            cases,
            default,
        } => {
            expr_reads_exact_frame_home(discriminant, home)
                || cases
                    .iter()
                    .any(|(_, body)| body_reads_exact_frame_home(body, home))
                || default
                    .as_deref()
                    .is_some_and(|body| body_reads_exact_frame_home(body, home))
        }
        Stmt::IndirectGoto { target } => expr_reads_exact_frame_home(target, home),
        Stmt::TryCatch { try_body, catches } => {
            body_reads_exact_frame_home(try_body, home)
                || catches
                    .iter()
                    .any(|catch| body_reads_exact_frame_home(&catch.body, home))
        }
        _ => false,
    })
}

fn expression_contains_stack_object(expr: &Expr) -> bool {
    match expr {
        Expr::StackAddr { .. } => true,
        Expr::Deref { addr, .. } => expression_contains_stack_object(addr),
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            expression_contains_stack_object(lhs) || expression_contains_stack_object(rhs)
        }
        Expr::Un { src, .. } | Expr::Cast { expr: src, .. } => {
            expression_contains_stack_object(src)
        }
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => {
            expression_contains_stack_object(cond)
                || expression_contains_stack_object(if_true)
                || expression_contains_stack_object(if_false)
        }
        Expr::FunctionTableEntry { index, .. } => expression_contains_stack_object(index),
        Expr::WideArithmetic { args, .. } => args.iter().any(expression_contains_stack_object),
        _ => false,
    }
}

fn parameter_source(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Reg(VReg::Phys(name)) if parse_arg_index(name).is_some() => Some(name.clone()),
        Expr::Cast { expr, .. } => parameter_source(expr),
        _ => None,
    }
}

fn record_frame_store(addr: &Expr, size: u8, src: &Expr, homes: &mut Vec<FrameParamHome>) {
    if !expression_contains_stack_object(addr) {
        return;
    }
    if let Some(home) = homes.iter_mut().find(|home| home.addr == *addr) {
        home.stores += 1;
        if home.size != size || home.arg.as_deref() != parameter_source(src).as_deref() {
            home.arg = None;
        }
        return;
    }
    homes.push(FrameParamHome {
        addr: addr.clone(),
        size,
        arg: parameter_source(src),
        stores: 1,
    });
}

fn collect_frame_param_homes(body: &[Stmt], homes: &mut Vec<FrameParamHome>) {
    for statement in body {
        match statement {
            Stmt::Store { addr, src, size } => record_frame_store(addr, *size, src, homes),
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                collect_frame_param_homes(then_body, homes);
                if let Some(else_body) = else_body {
                    collect_frame_param_homes(else_body, homes);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
                collect_frame_param_homes(body, homes)
            }
            Stmt::For {
                init, step, body, ..
            } => {
                collect_frame_param_homes(std::slice::from_ref(init.as_ref()), homes);
                collect_frame_param_homes(body, homes);
                collect_frame_param_homes(std::slice::from_ref(step.as_ref()), homes);
            }
            Stmt::Switch { cases, default, .. } => {
                for (_, case) in cases {
                    collect_frame_param_homes(case, homes);
                }
                if let Some(default) = default {
                    collect_frame_param_homes(default, homes);
                }
            }
            Stmt::TryCatch { try_body, catches } => {
                collect_frame_param_homes(try_body, homes);
                for catch in catches {
                    collect_frame_param_homes(&catch.body, homes);
                }
            }
            _ => {}
        }
    }
}

fn rewrite_frame_home_expr(expr: &mut Expr, homes: &[FrameParamHome]) {
    if let Expr::Deref { addr, size } = expr {
        if let Some(arg) = homes.iter().find_map(|home| {
            (home.size == *size && home.addr == **addr)
                .then(|| home.arg.clone())
                .flatten()
        }) {
            *expr = Expr::Reg(VReg::phys(arg));
            return;
        }
    }
    match expr {
        Expr::Deref { addr, .. } => rewrite_frame_home_expr(addr, homes),
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            rewrite_frame_home_expr(lhs, homes);
            rewrite_frame_home_expr(rhs, homes);
        }
        Expr::Un { src, .. } | Expr::Cast { expr: src, .. } => rewrite_frame_home_expr(src, homes),
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => {
            rewrite_frame_home_expr(cond, homes);
            rewrite_frame_home_expr(if_true, homes);
            rewrite_frame_home_expr(if_false, homes);
        }
        Expr::FunctionTableEntry { index, .. } => rewrite_frame_home_expr(index, homes),
        Expr::WideArithmetic { args, .. } => {
            for arg in args {
                rewrite_frame_home_expr(arg, homes);
            }
        }
        _ => {}
    }
}

fn rewrite_frame_param_homes(body: &mut Vec<Stmt>, homes: &[FrameParamHome]) {
    body.retain(|statement| {
        !matches!(statement,
            Stmt::Store { addr, size, .. }
                if homes.iter().any(|home| home.size == *size && home.addr == *addr))
    });
    for statement in body {
        match statement {
            Stmt::Assign { src, .. } => rewrite_frame_home_expr(src, homes),
            Stmt::Store { addr, src, .. } => {
                rewrite_frame_home_expr(addr, homes);
                rewrite_frame_home_expr(src, homes);
            }
            Stmt::Call { target, args, .. } => {
                rewrite_frame_home_expr(target, homes);
                for arg in args {
                    rewrite_frame_home_expr(arg, homes);
                }
            }
            Stmt::Return { value: Some(value) } => rewrite_frame_home_expr(value, homes),
            Stmt::Push { value } | Stmt::Throw { value } => rewrite_frame_home_expr(value, homes),
            Stmt::If {
                cond,
                then_body,
                else_body,
            } => {
                rewrite_frame_home_expr(cond, homes);
                rewrite_frame_param_homes(then_body, homes);
                if let Some(else_body) = else_body {
                    rewrite_frame_param_homes(else_body, homes);
                }
            }
            Stmt::While { cond, body } | Stmt::DoWhile { cond, body } => {
                rewrite_frame_home_expr(cond, homes);
                rewrite_frame_param_homes(body, homes);
            }
            Stmt::For {
                init,
                cond,
                step,
                body,
            } => {
                let mut init_body = vec![(**init).clone()];
                rewrite_frame_param_homes(&mut init_body, homes);
                **init = init_body.pop().unwrap_or(Stmt::Nop);
                rewrite_frame_home_expr(cond, homes);
                rewrite_frame_param_homes(body, homes);
                let mut step_body = vec![(**step).clone()];
                rewrite_frame_param_homes(&mut step_body, homes);
                **step = step_body.pop().unwrap_or(Stmt::Nop);
            }
            Stmt::Switch {
                discriminant,
                cases,
                default,
            } => {
                rewrite_frame_home_expr(discriminant, homes);
                for (_, case) in cases {
                    rewrite_frame_param_homes(case, homes);
                }
                if let Some(default) = default {
                    rewrite_frame_param_homes(default, homes);
                }
            }
            Stmt::IndirectGoto { target } => rewrite_frame_home_expr(target, homes),
            Stmt::TryCatch { try_body, catches } => {
                rewrite_frame_param_homes(try_body, homes);
                for catch in catches {
                    rewrite_frame_param_homes(&mut catch.body, homes);
                }
            }
            _ => {}
        }
    }
}

/// Rewrite `Store { addr: Reg(slot), src }` as `Assign { dst: slot, src }` for every
/// slot about to be renamed to its parameter.
///
/// The renderer can only recognise a slot assignment by its `local_`/`stack_` NAME
/// (`write_stmt_dec`'s `is_promoted_local` arm). Once coalescing renames the slot to
/// `argN`, that test fails and the same statement prints as a store *through* the
/// parameter — a write through a value that is not a pointer. That is how `rotr32`
/// segfaulted: `n &= 31u` on a spilled parameter is an `-O0` in-place memory update,
/// and it rendered as `*(int *)(arg1) = (arg1 & 31)`.
///
/// Doing this before the rename is what makes it unambiguous: afterwards,
/// `Store { addr: Reg(arg0) }` could equally be a genuine `*arg0 = v` through a
/// pointer parameter, and converting that would silently turn a memory write into a
/// local assignment. The pre-rename name cannot be confused that way.
fn slot_stores_to_assigns(body: &mut Vec<Stmt>, slots: &std::collections::HashMap<String, String>) {
    for s in body.iter_mut() {
        match s {
            Stmt::Store {
                addr: Expr::Reg(VReg::Phys(name)),
                src,
                ..
            } if slots.contains_key(name) => {
                if slots
                    .get(name)
                    .is_some_and(|argument| parameter_source(src).as_ref() == Some(argument))
                {
                    // The defining spill is redundant even when the machine
                    // width made it `local = (uint32_t)arg0`.  Retaining that
                    // cast as `arg0 = (uint32_t)arg0` truncates a pointer when a
                    // foreign-width host recompiles the recovered C.
                    *s = Stmt::Nop;
                } else {
                    *s = Stmt::Assign {
                        dst: VReg::phys(name.clone()),
                        src: src.clone(),
                    };
                }
            }
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                slot_stores_to_assigns(then_body, slots);
                if let Some(eb) = else_body {
                    slot_stores_to_assigns(eb, slots);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
                slot_stores_to_assigns(body, slots)
            }
            Stmt::For { body, .. } => slot_stores_to_assigns(body, slots),
            Stmt::Switch { cases, default, .. } => {
                for (_, b) in cases.iter_mut() {
                    slot_stores_to_assigns(b, slots);
                }
                if let Some(b) = default {
                    slot_stores_to_assigns(b, slots);
                }
            }
            _ => {}
        }
    }
}

/// Populate `home[local] = arg` for promoted parameter-home candidates.
///
/// The first store must carry an incoming parameter identity. Repeated stores
/// from a different parameter disqualify it; ordinary in-place updates remain
/// candidates because the symmetric reaching-definitions check at the caller
/// can prove whether the original argument and slot are still interchangeable.
fn collect_param_homes(body: &[Stmt], home: &mut std::collections::HashMap<String, String>) {
    collect_param_homes_with_aliases(body, home, &mut std::collections::HashMap::new());
}

fn parameter_alias(
    expr: &Expr,
    aliases: &std::collections::HashMap<VReg, String>,
) -> Option<String> {
    match expr {
        Expr::Reg(register) => aliases
            .get(register)
            .cloned()
            .or_else(|| parameter_source(expr)),
        Expr::Cast { expr, .. } => parameter_alias(expr, aliases),
        _ => None,
    }
}

/// Find parameter homes without rewriting the scratch chain that carries the
/// incoming value to the spill.  In particular, i386 commonly spells it
/// ``eax = arg0; local = (uint32_t)eax``.  Running the general copy propagator
/// first would also rewrite a later ``Store { addr: eax }`` to
/// ``Store { addr: local }``, erasing the distinction between the home address
/// and the pointer value loaded from it.  This tiny straight-line provenance
/// map proves only parameter identity and leaves every address untouched.
fn collect_param_homes_with_aliases(
    body: &[Stmt],
    home: &mut std::collections::HashMap<String, String>,
    aliases: &mut std::collections::HashMap<VReg, String>,
) {
    for s in body {
        match s {
            Stmt::Assign { dst, src } => {
                if let Some(argument) = parameter_alias(src, aliases) {
                    aliases.insert(dst.clone(), argument);
                } else {
                    aliases.remove(dst);
                }
            }
            Stmt::Store {
                addr: Expr::Reg(VReg::Phys(local)),
                src,
                ..
            } if is_promoted_local(local) => {
                let argument = parameter_alias(src, aliases);
                let entry = home.entry(local.clone());
                match entry {
                    std::collections::hash_map::Entry::Vacant(v) => {
                        v.insert(argument.unwrap_or_default());
                    }
                    std::collections::hash_map::Entry::Occupied(mut o) => {
                        // Only a direct repeated store from the same source
                        // parameter remains a home initialization. Alias state
                        // is intentionally insufficient here: a branch-local
                        // status temporary can share one incoming provenance on
                        // another path, yet its store reuses the stack bytes for
                        // a different source object.
                        let same_parameter = parameter_source(src)
                            .as_ref()
                            .is_some_and(|candidate| candidate == o.get());
                        let in_place_update = src.contains_reg(&VReg::phys(local.clone()));
                        if !same_parameter && !in_place_update {
                            o.insert(String::new());
                        }
                    }
                }
                aliases.remove(&VReg::phys(local.clone()));
            }
            // Recurse into nested bodies. Any store seen on any path contributes
            // to the shared, fail-closed home decision.
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                collect_param_homes_with_aliases(then_body, home, &mut aliases.clone());
                if let Some(eb) = else_body {
                    collect_param_homes_with_aliases(eb, home, &mut aliases.clone());
                }
                aliases.clear();
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
                collect_param_homes_with_aliases(body, home, &mut aliases.clone());
                aliases.clear();
            }
            Stmt::For {
                init, step, body, ..
            } => {
                collect_param_homes_with_aliases(
                    std::slice::from_ref(init.as_ref()),
                    home,
                    &mut aliases.clone(),
                );
                collect_param_homes_with_aliases(body, home, &mut aliases.clone());
                collect_param_homes_with_aliases(
                    std::slice::from_ref(step.as_ref()),
                    home,
                    &mut aliases.clone(),
                );
                aliases.clear();
            }
            Stmt::Switch { cases, default, .. } => {
                for (_, b) in cases {
                    collect_param_homes_with_aliases(b, home, &mut aliases.clone());
                }
                if let Some(b) = default {
                    collect_param_homes_with_aliases(b, home, &mut aliases.clone());
                }
                aliases.clear();
            }
            Stmt::Call { .. } | Stmt::Label(_) | Stmt::Goto { .. } => aliases.clear(),
            _ => {}
        }
    }
}

/// Rename physical-register names per `map` throughout `body` (all positions).
fn rename_phys_in_body(body: &mut [Stmt], map: &std::collections::HashMap<String, String>) {
    fn rn(v: &mut VReg, map: &std::collections::HashMap<String, String>) {
        if let VReg::Phys(n) = v {
            if let Some(nn) = map.get(n) {
                *n = nn.clone();
            }
        }
    }
    fn re(e: &mut Expr, map: &std::collections::HashMap<String, String>) {
        match e {
            Expr::Reg(v) => rn(v, map),
            Expr::StackAddr { object, .. } => rn(object, map),
            Expr::Lea { base, index, .. } | Expr::PdbFieldAddr { base, index, .. } => {
                if let Some(v) = base {
                    rn(v, map);
                }
                if let Some(v) = index {
                    rn(v, map);
                }
            }
            Expr::Deref { addr, .. } => re(addr, map),
            Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
                re(lhs, map);
                re(rhs, map);
            }
            Expr::Select {
                cond,
                if_true,
                if_false,
                ..
            } => {
                re(cond, map);
                re(if_true, map);
                re(if_false, map);
            }
            Expr::Un { src, .. } => re(src, map),
            Expr::Cast { expr, .. } => re(expr, map),
            Expr::FunctionTableEntry { index, .. } => re(index, map),
            Expr::WideArithmetic { args, .. } => {
                for argument in args {
                    re(argument, map);
                }
            }
            Expr::Const(_)
            | Expr::FloatConst { .. }
            | Expr::Addr(_)
            | Expr::Named { .. }
            | Expr::StringLit { .. }
            | Expr::Unknown(_) => {}
        }
    }
    for s in body.iter_mut() {
        match s {
            Stmt::Assign { dst, src } => {
                rn(dst, map);
                re(src, map);
            }
            Stmt::Store { addr, src, .. } => {
                re(addr, map);
                re(src, map);
            }
            Stmt::Call { target, args, .. } => {
                re(target, map);
                for a in args.iter_mut() {
                    re(a, map);
                }
            }
            Stmt::Return { value } => {
                if let Some(e) = value {
                    re(e, map);
                }
            }
            Stmt::Push { value } => re(value, map),
            Stmt::Pop { target } => rn(target, map),
            Stmt::If {
                cond,
                then_body,
                else_body,
            } => {
                re(cond, map);
                rename_phys_in_body(then_body, map);
                if let Some(eb) = else_body {
                    rename_phys_in_body(eb, map);
                }
            }
            Stmt::While { cond, body } => {
                re(cond, map);
                rename_phys_in_body(body, map);
            }
            Stmt::For {
                init,
                cond,
                step,
                body,
            } => {
                rename_phys_in_body(std::slice::from_mut(init.as_mut()), map);
                re(cond, map);
                rename_phys_in_body(body, map);
                rename_phys_in_body(std::slice::from_mut(step.as_mut()), map);
            }
            Stmt::DoWhile { body, cond } => {
                rename_phys_in_body(body, map);
                re(cond, map);
            }
            Stmt::Switch {
                discriminant,
                cases,
                default,
            } => {
                re(discriminant, map);
                for (_, b) in cases.iter_mut() {
                    rename_phys_in_body(b, map);
                }
                if let Some(b) = default {
                    rename_phys_in_body(b, map);
                }
            }
            Stmt::IndirectGoto { target } => re(target, map),
            Stmt::Goto { .. }
            | Stmt::Label(_)
            | Stmt::Break
            | Stmt::Nop
            | Stmt::Unknown(_)
            | Stmt::Comment(_) => {}
            Stmt::Throw { value } => re(value, map),
            Stmt::TryCatch { try_body, catches } => {
                rename_phys_in_body(try_body, map);
                for catch in catches {
                    rn(&mut catch.binding, map);
                    rename_phys_in_body(&mut catch.body, map);
                }
            }
        }
    }
}

/// Drop `Store { addr: Reg(x), src: Reg(x) }` self-assignments (recursively) —
/// what a coalesced spill `local = arg` collapses to once `local` became `arg`.
fn drop_self_stores(body: &mut Vec<Stmt>) {
    body.retain(|s| {
        !matches!(
            s,
            Stmt::Store {
                addr: Expr::Reg(VReg::Phys(a)),
                src: Expr::Reg(VReg::Phys(b)),
                ..
            } if a == b
        ) && !matches!(
            // Same collapse, in assignment form: the spill store is now an Assign
            // (see `slot_stores_to_assigns`), so `arg0 = arg0` must go too.
            s,
            Stmt::Assign {
                dst: VReg::Phys(a),
                src: Expr::Reg(VReg::Phys(b)),
            } if a == b
        )
    });
    for s in body.iter_mut() {
        match s {
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                drop_self_stores(then_body);
                if let Some(eb) = else_body {
                    drop_self_stores(eb);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => drop_self_stores(body),
            Stmt::For { body, .. } => drop_self_stores(body),
            Stmt::Switch { cases, default, .. } => {
                for (_, b) in cases.iter_mut() {
                    drop_self_stores(b);
                }
                if let Some(b) = default {
                    drop_self_stores(b);
                }
            }
            _ => {}
        }
    }
}

/// The explicit AST transformation that precedes DecBench rendering.
///
/// These fifteen steps change *definitions, uses, value identities, or control-flow
/// representation* — they are
/// semantic pipeline operations, not formatting:
///
/// 1. `default_return_to_reg` gives a bare `return` its ABI return register, so
///    an always-non-void rendering emits `return ret;` instead of the
///    value-losing `return 0;`;
/// 2. `coalesce_param_spills` folds a parameter's spill slot back into the
///    parameter, so the emitted C uses `argN` directly instead of a redundant
///    `local_X = argN` copy (which recompiles to stack traffic the original never
///    emits);
/// 3. `copy_prop::propagate_copies` and `const_fold::fold_constants` run to a
///    small local fixpoint: mask folding can turn a twice-read partial-register
///    parent into a one-use copy, and propagating that copy exposes the final
///    comparison identity.
/// 4. `select_fold::collapse_assignment_diamonds` turns a proven two-arm,
///    same-destination diamond into one pure select expression, then the narrow
///    promoted-select propagator removes an adjacent one-use stack temporary.
/// 5. `select_fold::recover_guarded_select_returns` turns an initialized result,
///    one guarded select overwrite, and its joined return back into terminating
///    nested returns when the initializer is a pure register view.
/// 6. `select_fold::fold_boolean_masks` renders an exact comparison-derived
///    `0`/`-1` select as arithmetic negation, avoiding fake source-level control
///    flow without changing the mask value.
/// 7. `copy_prop::propagate_adjacent_guard_values` folds a physical scratch's
///    immediately adjacent, sole eager guard use without claiming that physical
///    role is globally SSA.
/// 8. `copy_prop::propagate_adjacent_overwritten_values` carries one pure,
///    immediately consumed value into the assignment that overwrites the same
///    physical scratch without treating that scratch as globally SSA.
/// 9. `label_prune::recover_forward_exit_regions` turns exact forward skips to
///    an adjacent join into guarded continuations, including a tail loop exit
///    that is provably the source-level `break`.
/// 10. `loop_form::recover_linear_latched_do_whiles` turns a uniquely owned
///    `label; body; if (condition) goto label` into the exact source-level
///    `do { body } while (condition)` form.
/// 11. `loop_form::recover_head_tested_whiles` turns the conservative constant-bound
///    countdown `while (1) { if (exit) break; body }` into
///    `while (!exit) { body }` only when folding has made the exit guard first.
/// 12. `label_prune::inline_terminal_goto_tails` duplicates only straight-line,
///    uniquely labelled return tails at their goto sites, recovering ordinary
///    early returns without inventing or reordering an effect.
/// 13. `switch_ladder::recover_switches` runs before select formation and again
///    after loop/copy recovery, converting proven comparison ladders into
///    `switch` nodes without losing a two-case tail to a ternary expression.
/// 14. `guarded_switch::collapse_range_guards` removes a compiler range-check
///    wrapper only when its unsigned domain and every switch label prove that
///    the wrapper cannot select a case the switch would not select itself.
/// 15. `loop_form::promote_for_loops` combines an adjacent initializer, exact head
///    guard, and unconditional same-variable unit increment into a `for` node.
/// 16. `fold_exhaustive_if_returns` and `fold_exhaustive_switch_returns` move an
///    immediately joined result return into every arm only when both `if` arms,
///    or an explicit switch default, make the control flow exhaustive.
///
/// They used to run *inside* `render_decbench_typed`, which made that renderer
/// impure: the AST that was checked or dumped was not the AST that was printed,
/// so def-before-use verification against it produced false positives on correct
/// functions and had to be reverted. Running them here, as a named pass whose
/// output is the thing rendered, makes the emitted C verifiable — see
/// [`crate::ir::verify_defs`].
pub fn prepare_for_decbench(f: &Function) -> Function {
    prepare_for_decbench_with_output(f, crate::ir::types_recover::RecoveredOutputKind::Unknown)
}

/// Prepare DecBench output with the recovered source-level output contract.
/// Unknown/direct outputs retain the compatibility behavior; proven void
/// outputs erase incidental return-register residue before any source-level
/// folding runs.
pub fn prepare_for_decbench_with_output(
    f: &Function,
    output_kind: crate::ir::types_recover::RecoveredOutputKind,
) -> Function {
    prepare_for_decbench_with_output_and_protected_locals(
        f,
        output_kind,
        &std::collections::HashSet::new(),
    )
}

/// Prepare output while preserving debug-proven source-local identities.
///
/// Source locals may be initialized from a parameter without being that
/// parameter's home storage. The protected set is deliberately internal-slot
/// names: semantic passes retain those names until the final presentation
/// boundary, where authoritative source spellings are applied.
pub(crate) fn prepare_for_decbench_with_output_and_protected_locals(
    f: &Function,
    output_kind: crate::ir::types_recover::RecoveredOutputKind,
    protected_locals: &std::collections::HashSet<String>,
) -> Function {
    let mut owned = f.clone();
    if output_kind == crate::ir::types_recover::RecoveredOutputKind::Void {
        crate::ir::direct_output::clear_return_values(&mut owned);
    } else {
        crate::ir::direct_output::materialize_direct_output(&mut owned);
    }
    coalesce_param_spills(&mut owned.body, protected_locals);
    crate::ir::label_prune::prune_unreachable_tails(&mut owned);
    // Copy propagation exposes algebraic flag identities, while folding those
    // identities changes use counts and exposes new one-use copies. Iterate the
    // monotone pair to a small bounded fixpoint: x86 partial-register returns
    // need three rounds (fold the observed mask, inline the parent, delete the
    // now-dead pre-loop copy). Four is a defensive bound, not an unbounded
    // optimiser loop; all transformations strictly remove a copy or expression
    // layer and ordinary functions settle after one round.
    for _ in 0..4 {
        let before = owned.clone();
        crate::ir::copy_prop::propagate_copies(&mut owned);
        crate::ir::const_fold::fold_constants(&mut owned);
        if owned == before {
            break;
        }
    }
    // Folding can prove that an initially composite narrow-register rebuild is
    // exactly its incoming argument (`(arg & ~255) | (arg & 255) == arg`). Run
    // the same guarded home analysis again so byte/halfword parameter spills
    // exposed only at the fixpoint do not survive as fake source locals.
    coalesce_named_param_spills(&mut owned.body, protected_locals);
    // A spill carried through a scratch can become `arg0 = arg0` only after
    // the copy fixpoint. The earlier coalescing cleanup cannot see it yet.
    drop_self_stores(&mut owned.body);
    // Propagation can expose a casted result copy directly before its return.
    // Collapse it before exhaustive-switch joining so the lossless cast chain
    // can be carried into each arm instead of blocking source-level returns.
    fold_returns(&mut owned.body);
    // Copy propagation and the second constant fold can replace a flag read in
    // a condition with its recovered comparison. Prune the now-dead definition
    // before shape recovery: otherwise a redundant `sf_N = ...` remains before
    // an exit guard and blocks exact while/for/select recognition.
    crate::ir::dce::prune_overwritten_flags(&mut owned);
    crate::ir::dce::prune_dead_flags(&mut owned);
    crate::ir::copy_prop::propagate_adjacent_promoted_values(&mut owned);
    crate::ir::copy_prop::propagate_adjacent_guard_values(&mut owned);
    crate::ir::guard_chain::collapse_shared_exit_guard_ladders(&mut owned);
    crate::ir::guard_chain::collapse_shared_assignment_guards(&mut owned);
    crate::ir::guard_chain::collapse_redundant_copy_nested_guards(&mut owned);
    crate::ir::guard_chain::collapse_nested_terminal_return_guards(&mut owned);
    // Region recovery may clone a comparison tree's shared default into
    // sequential terminal guards. Recover that switch before two-case tails
    // become `Select` expressions and erase the final equality arms. The
    // second invocation below remains necessary because select/copy folding can
    // expose ladders whose discriminant was not yet syntactically uniform.
    crate::ir::switch_ladder::recover_switches(&mut owned);
    crate::ir::select_fold::collapse_assignment_diamonds(&mut owned);
    crate::ir::select_fold::recover_guarded_select_returns(&mut owned);
    crate::ir::select_fold::fold_boolean_masks(&mut owned);
    crate::ir::copy_prop::propagate_adjacent_promoted_values(&mut owned);
    crate::ir::copy_prop::propagate_adjacent_guard_values(&mut owned);
    crate::ir::copy_prop::propagate_adjacent_overwritten_values(&mut owned);
    // Recover shared return epilogues before general forward joins. Otherwise a
    // goto from a loop to `return -1` is faithfully but less clearly rendered
    // as `break; ... return -1` instead of the exact early return.
    crate::ir::label_prune::inline_terminal_goto_tails(&mut owned);
    // A forward join may contain a still-linearised inner loop, while removing
    // that join can in turn expose the enclosing linear latch. Two bounded
    // rounds recover inner loop -> forward join -> outer loop without relaxing
    // either pass's internal-label rejection.
    for _ in 0..2 {
        crate::ir::label_prune::recover_forward_exit_regions(&mut owned);
        crate::ir::loop_form::recover_linear_latched_do_whiles(&mut owned);
    }
    // Inlining a shared terminal epilogue can leave its old fallthrough
    // assignment after an explicit return. Remove that newly unreachable tail
    // before exact sentinel-loop matching; it is not an effect the candidate
    // should have to tolerate, but it also must not block a faithful rewrite.
    crate::ir::label_prune::prune_unreachable_tails(&mut owned);
    crate::ir::loop_form::recover_head_tested_whiles(&mut owned);
    crate::ir::loop_form::recover_guarded_do_whiles(&mut owned);
    crate::ir::loop_form::recover_sentinel_search_loops(&mut owned);
    crate::ir::guard_chain::collapse_adjacent_break_guards(&mut owned);
    crate::ir::guard_chain::collapse_nested_terminal_return_guards(&mut owned);
    // Before rendering and before widening (which already understands `Switch`):
    // a gcc -O0 comparison ladder is a `switch`, not a nest of `if`s and `goto`s.
    crate::ir::switch_ladder::recover_switches(&mut owned);
    crate::ir::guarded_switch::collapse_range_guards(&mut owned);
    // Removing a proven range guard can make a prefix copy dominate the switch
    // directly. Carry only those aliases into the switch arms. A general late
    // copy-propagation rerun is unsound here: loops have already been recovered,
    // and a pre-loop snapshot may depend on a value changed by the loop body.
    crate::ir::copy_prop::propagate_switch_entry_copies(&mut owned);
    fold_exhaustive_if_returns(&mut owned);
    fold_exhaustive_switch_returns(&mut owned);
    crate::ir::loop_form::promote_for_loops(&mut owned);
    // Loop promotion can expose sequential terminal guards that were nested in
    // the recovered CFG during the earlier pass. Fuse that final exact shape
    // as well; the transformation is adjacency-checked and idempotent.
    crate::ir::guard_chain::collapse_adjacent_break_guards(&mut owned);
    crate::ir::guard_chain::collapse_redundant_copy_nested_guards(&mut owned);
    crate::ir::guard_chain::collapse_matching_terminal_return_guard(&mut owned);
    // Late copy/guard folding can make an entry-owned do-while's initial and
    // latch predicates structurally identical only after the first loop-form
    // pass. The recovery is exact and idempotent; rerun it on the final AST so
    // phi-coalesced cursors retain their source-level pre-test.
    crate::ir::loop_form::recover_guarded_do_whiles(&mut owned);
    crate::ir::latch_predicate::fold_latched_predicates(&mut owned);
    remove_redundant_return_constant_assignments(&mut owned.body);
    owned
}

/// Render an already-prepared function as DecBench C. FORMATTING ONLY: this must
/// not change definitions, uses, control flow, or value identities — run
/// [`prepare_for_decbench`] first (the pipeline does).
pub fn render_decbench_typed(
    f: &Function,
    tm: Option<&TypeMap>,
    width_tm: Option<&TypeMap>,
) -> String {
    render_decbench_typed_with_output(
        f,
        tm,
        width_tm,
        crate::ir::types_recover::RecoveredOutputKind::Unknown,
    )
}

fn source_prototype_type_is_renderable(c_type: &str, allow_void: bool) -> bool {
    let normalized = c_type.split_whitespace().collect::<Vec<_>>().join(" ");
    if normalized.is_empty()
        || normalized.contains("/*")
        || normalized
            .chars()
            .any(|ch| matches!(ch, '&' | '[' | ']' | '(' | ')' | ';' | '{' | '}'))
    {
        return false;
    }
    let mut base_spelling = normalized.as_str();
    let mut pointer = false;
    while let Some(inner) = base_spelling.trim_end().strip_suffix('*') {
        pointer = true;
        base_spelling = inner;
    }
    let base = base_spelling
        .split_whitespace()
        .filter(|word| !matches!(*word, "const" | "volatile" | "restrict"))
        .collect::<Vec<_>>()
        .join(" ");
    if base.starts_with("struct ") || base.starts_with("union ") {
        let mut words = base.split_whitespace();
        let tag = words.next();
        let name = words.next();
        return pointer
            && matches!(tag, Some("struct" | "union"))
            && name.is_some_and(valid_c_identifier)
            && words.next().is_none();
    }
    crate::ir::dwarf_type_env::builtin_scalar_type(&base)
        || (base == "void" && (allow_void || pointer))
        || crate::ir::call_contracts::opaque_pointer_typedef(c_type).is_some()
}

pub(crate) fn dwarf_prototype_type_is_renderable(
    c_type: &str,
    allow_void: bool,
    dwarf_type_env: &crate::ir::dwarf_type_env::DwarfTypeEnv<'_>,
) -> bool {
    source_prototype_type_is_renderable(c_type, allow_void)
        || dwarf_type_env.aggregate_pointer(c_type).is_some()
        || dwarf_type_env.typedef_declaration(c_type).is_some()
}

fn source_prototype_forward_declarations(
    prototype: &CallPrototype,
    complete_structs: &std::collections::BTreeSet<String>,
    dwarf_type_env: &crate::ir::dwarf_type_env::DwarfTypeEnv<'_>,
) -> std::collections::BTreeSet<String> {
    let mut declarations = std::collections::BTreeSet::new();
    for c_type in std::iter::once(&prototype.return_type).chain(&prototype.parameter_types) {
        if let Some(pointer) = dwarf_type_env.aggregate_pointer(c_type) {
            if !complete_structs.contains(pointer.source_name) {
                declarations.insert(dwarf_type_env.forward_declaration(pointer));
            }
        } else if let Some(declaration) = dwarf_type_env.typedef_declaration(c_type) {
            declarations.insert(declaration);
        } else if let Some(name) = crate::ir::call_contracts::opaque_pointer_typedef(c_type) {
            declarations.insert(format!("typedef struct __glaurung_opaque_{name} {name};"));
        }
    }
    declarations
}

fn valid_c_identifier(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|ch| ch == '_' || ch.is_ascii_alphabetic())
        && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

fn dwarf_scalar_width(c_type: &str, pointer_width: u8) -> Option<u64> {
    let normalized = c_type.split_whitespace().collect::<Vec<_>>().join(" ");
    if normalized.ends_with('*') {
        return Some(u64::from(pointer_width));
    }
    match normalized.as_str() {
        "char" | "signed char" | "unsigned char" | "_Bool" | "bool" | "int8_t" | "uint8_t" => {
            Some(1)
        }
        "short" | "short int" | "signed short" | "signed short int" | "unsigned short"
        | "unsigned short int" | "int16_t" | "uint16_t" => Some(2),
        "int" | "signed" | "signed int" | "unsigned" | "unsigned int" | "float" | "int32_t"
        | "uint32_t" => Some(4),
        "long long"
        | "long long int"
        | "signed long long"
        | "signed long long int"
        | "unsigned long long"
        | "unsigned long long int"
        | "long long unsigned"
        | "long long unsigned int"
        | "double"
        | "int64_t"
        | "uint64_t" => Some(8),
        // `long` is ABI-dependent (notably 4 bytes on Win64), and the AST
        // renderer deliberately does not guess the object format here.
        _ => None,
    }
}

fn pointed_struct_name(c_type: &str) -> Option<&str> {
    crate::ir::dwarf_type_env::pointed_type_name(c_type)
}

fn align_up(value: u64, alignment: u64) -> Option<u64> {
    let mask = alignment.checked_sub(1)?;
    value.checked_add(mask).map(|value| value & !mask)
}

/// Select only complete, ordinary-layout structures that the emitted source
/// prototype actually references. This is intentionally fail-closed: bitfields,
/// packed layouts, ABI-dependent `long`, arrays, unions, and conflicting DWARF
/// definitions stay as raw offset accesses until the middle IR can represent
/// them exactly.
fn renderable_dwarf_structs<'a>(
    prototype: Option<&CallPrototype>,
    dwarf_types: &'a [crate::debug::dwarf::DwarfType],
    dwarf_type_env: &crate::ir::dwarf_type_env::DwarfTypeEnv<'a>,
    pointer_width: u8,
) -> std::collections::BTreeMap<String, &'a crate::debug::dwarf::DwarfType> {
    let Some(prototype) = prototype else {
        return std::collections::BTreeMap::new();
    };
    let referenced = std::iter::once(&prototype.return_type)
        .chain(&prototype.parameter_types)
        .filter_map(|c_type| dwarf_type_env.aggregate_pointer(c_type))
        .filter(|pointer| pointer.kind == crate::debug::dwarf::DwarfTypeKind::Struct)
        .map(|pointer| pointer.tag_name)
        .collect::<std::collections::BTreeSet<_>>();
    let mut selected =
        std::collections::BTreeMap::<String, &'a crate::debug::dwarf::DwarfType>::new();
    let mut conflicts = std::collections::BTreeSet::new();
    for layout in dwarf_types.iter().filter(|layout| {
        layout.kind == crate::debug::dwarf::DwarfTypeKind::Struct
            && referenced.contains(layout.name.as_str())
    }) {
        if !valid_c_identifier(&layout.name) || layout.byte_size == 0 || layout.fields.is_empty() {
            continue;
        }
        let mut cursor = 0_u64;
        let mut max_alignment = 1_u64;
        let mut valid = true;
        for field in &layout.fields {
            let Some(width) = dwarf_scalar_width(&field.c_type, pointer_width) else {
                valid = false;
                break;
            };
            let alignment = width.min(u64::from(pointer_width)).max(1);
            max_alignment = max_alignment.max(alignment);
            if !valid_c_identifier(&field.name)
                || !source_prototype_type_is_renderable(&field.c_type, false)
                || align_up(cursor, alignment) != Some(field.offset)
            {
                valid = false;
                break;
            }
            cursor = match field.offset.checked_add(width) {
                Some(end) => end,
                None => {
                    valid = false;
                    break;
                }
            };
        }
        if !valid || align_up(cursor, max_alignment) != Some(layout.byte_size) {
            continue;
        }
        match selected.get(&layout.name) {
            Some(previous) if **previous != *layout => {
                conflicts.insert(layout.name.clone());
            }
            Some(_) => {}
            None => {
                selected.insert(layout.name.clone(), layout);
            }
        }
    }
    for conflict in conflicts {
        selected.remove(&conflict);
    }
    selected
}

fn source_type_with_complete_struct_alias(
    c_type: &str,
    complete_structs: &std::collections::BTreeSet<String>,
) -> String {
    let Some(name) = pointed_struct_name(c_type) else {
        return c_type.to_string();
    };
    if !complete_structs.contains(name) {
        return c_type.to_string();
    }
    crate::ir::dwarf_type_env::render_pointer_name(c_type, name)
        .unwrap_or_else(|| c_type.to_string())
}

fn collision_safe_local_aggregate_type(
    local_name: &str,
    c_type: &str,
    dwarf_type_env: &crate::ir::dwarf_type_env::DwarfTypeEnv<'_>,
) -> Option<String> {
    let pointer = dwarf_type_env.aggregate_pointer(c_type)?;
    if sanitize_c_ident(local_name) != sanitize_c_ident(pointer.source_name) {
        return None;
    }
    let keyword = match pointer.kind {
        crate::debug::dwarf::DwarfTypeKind::Struct => "struct",
        crate::debug::dwarf::DwarfTypeKind::Union => "union",
        crate::debug::dwarf::DwarfTypeKind::Enum | crate::debug::dwarf::DwarfTypeKind::Typedef => {
            return None
        }
    };
    let qualifiers = c_type
        .find(pointer.source_name)
        .map(|index| c_type[..index].trim())
        .unwrap_or_default()
        .split_whitespace()
        .filter(|token| matches!(*token, "const" | "volatile"))
        .collect::<Vec<_>>()
        .join(" ");
    let qualifiers = if qualifiers.is_empty() {
        String::new()
    } else {
        format!("{qualifiers} ")
    };
    Some(format!("{qualifiers}{keyword} {} *", pointer.tag_name))
}

/// Typed DecBench renderer with an explicit recovered output contract.
pub fn render_decbench_typed_with_output(
    f: &Function,
    tm: Option<&TypeMap>,
    width_tm: Option<&TypeMap>,
    output_kind: crate::ir::types_recover::RecoveredOutputKind,
) -> String {
    render_decbench_typed_with_output_and_prototype(f, tm, width_tm, output_kind, None)
}

/// Typed DecBench renderer with an optional authoritative source prototype.
///
/// Machine-code inference remains responsible for the body and storage model.
/// When DWARF supplies an exactly arity-compatible scalar/pointer prototype,
/// retain its named C types at the function boundary. By-value aggregates are
/// deliberately rejected until their multi-eightbyte ABI reconstruction is
/// represented in the middle IR.
pub fn render_decbench_typed_with_output_and_prototype(
    f: &Function,
    tm: Option<&TypeMap>,
    width_tm: Option<&TypeMap>,
    output_kind: crate::ir::types_recover::RecoveredOutputKind,
    declared_prototype: Option<&CallPrototype>,
) -> String {
    render_decbench_typed_with_output_and_prototype_and_dwarf_types(
        f,
        tm,
        width_tm,
        output_kind,
        declared_prototype,
        &[],
        8,
        &std::collections::HashMap::new(),
    )
}

/// Typed DecBench renderer with optional authoritative source aggregates.
pub fn render_decbench_typed_with_output_and_prototype_and_dwarf_types(
    f: &Function,
    tm: Option<&TypeMap>,
    width_tm: Option<&TypeMap>,
    output_kind: crate::ir::types_recover::RecoveredOutputKind,
    declared_prototype: Option<&CallPrototype>,
    dwarf_types: &[crate::debug::dwarf::DwarfType],
    pointer_width: u8,
    dwarf_pointer_types: &std::collections::HashMap<VReg, String>,
) -> String {
    render_decbench_typed_with_output_and_prototype_and_dwarf_types_and_local_types(
        f,
        tm,
        width_tm,
        output_kind,
        declared_prototype,
        dwarf_types,
        pointer_width,
        dwarf_pointer_types,
        &std::collections::HashMap::new(),
    )
}

/// Typed DecBench renderer with exact source spellings for promoted locals.
pub fn render_decbench_typed_with_output_and_prototype_and_dwarf_types_and_local_types(
    f: &Function,
    tm: Option<&TypeMap>,
    width_tm: Option<&TypeMap>,
    output_kind: crate::ir::types_recover::RecoveredOutputKind,
    declared_prototype: Option<&CallPrototype>,
    dwarf_types: &[crate::debug::dwarf::DwarfType],
    pointer_width: u8,
    dwarf_pointer_types: &std::collections::HashMap<VReg, String>,
    dwarf_local_types: &std::collections::HashMap<String, String>,
) -> String {
    DEC_SOURCE_LOCALS.with(|locals| {
        *locals.borrow_mut() = dwarf_local_types.keys().cloned().collect();
    });
    DEC_POINTER_WIDTH.with(|width| width.set(pointer_width));
    let dwarf_type_env = crate::ir::dwarf_type_env::DwarfTypeEnv::new(dwarf_types);
    let mut ids = DecIdents::default();
    for s in &f.body {
        collect_idents_stmt(s, &mut ids);
    }
    // A debug local can be optimized into a constant or a different induction
    // variable and therefore have no surviving AST use. Its authoritative
    // source declaration is still useful and safe to emit; unlike an invented
    // value, an unused C local changes neither control flow nor dataflow.
    let mut declaration_only_locals = dwarf_local_types
        .keys()
        .filter(|name| crate::ir::naming::valid_authoritative_local_name(name.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    declaration_only_locals.sort();
    for local in declaration_only_locals {
        insert_local(&mut ids, local);
    }
    DEC_GLOBAL_ADDRS
        .with(|addresses| *addresses.borrow_mut() = ids.global_addresses.keys().copied().collect());
    DEC_WIDE_LOCALS.with(|locals| *locals.borrow_mut() = ids.wide_locals.iter().cloned().collect());

    let name = sanitize_c_ident(&f.name);
    // Signature arity: the highest `argN` referenced in the body, *or* recovered
    // in the type map — whichever is larger. Types are recovered from the full
    // pre-structuring IR, so an argument whose only uses were dropped by dead-code
    // elimination (e.g. a `switch` whose cases were lost to `goto`s) still has a
    // type-map entry and must still appear in the signature (an ABI/prototype
    // property, not a "still referenced after DCE" one).
    let mut arg_count = ids.max_arg.map(|m| m + 1).unwrap_or(0);
    if let Some(tm) = tm {
        for (v, _) in tm.iter() {
            if let VReg::Phys(n) = v {
                if let Some(idx) = parse_arg_index(n) {
                    arg_count = arg_count.max(idx + 1);
                }
            }
        }
    }
    let declared_prototype = declared_prototype.filter(|prototype| {
        prototype.parameter_types.len() == arg_count
            && dwarf_prototype_type_is_renderable(&prototype.return_type, true, &dwarf_type_env)
            && ((output_kind == crate::ir::types_recover::RecoveredOutputKind::Void
                && prototype.return_type == "void")
                || (output_kind != crate::ir::types_recover::RecoveredOutputKind::Void
                    && prototype.return_type != "void"))
    });
    let all_declared_parameters_renderable = declared_prototype.is_some_and(|prototype| {
        prototype
            .parameter_types
            .iter()
            .all(|c_type| dwarf_prototype_type_is_renderable(c_type, false, &dwarf_type_env))
    });

    let aggregate_layouts = renderable_dwarf_structs(
        declared_prototype,
        dwarf_types,
        &dwarf_type_env,
        pointer_width,
    );
    let complete_structs = aggregate_layouts
        .keys()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    // Complete layouts already emit `typedef struct T T;`. Give an explicit
    // opaque `struct T *`/`union T *` source contract the same standalone alias
    // so parameter spelling does not depend on whether every field layout was
    // safely renderable.
    let mut source_type_aliases = complete_structs.clone();
    if let Some(prototype) = declared_prototype {
        source_type_aliases.extend(
            std::iter::once(&prototype.return_type)
                .chain(&prototype.parameter_types)
                .filter_map(|c_type| dwarf_type_env.aggregate_pointer(c_type))
                .map(|pointer| pointer.source_name.to_string()),
        );
    }
    source_type_aliases.extend(
        dwarf_local_types
            .values()
            .filter_map(|c_type| dwarf_type_env.aggregate_pointer(c_type))
            .map(|pointer| pointer.source_name.to_string()),
    );
    DEC_RENDERABLE_STRUCTS.with(|selected| *selected.borrow_mut() = complete_structs.clone());
    DEC_STRUCT_PTR_TYPES.with(|selected| {
        let mut exact = std::collections::HashMap::new();
        for (register, type_name) in dwarf_pointer_types {
            if !complete_structs.contains(type_name) {
                continue;
            }
            if let VReg::Phys(name) = register {
                let c_type = format!("{type_name} *");
                exact.insert(name.clone(), c_type.clone());
                exact.insert(sanitize_c_ident(name), c_type);
            }
        }
        for (name, c_type) in dwarf_local_types {
            if dwarf_type_env.aggregate_pointer(c_type).is_none()
                || !dwarf_prototype_type_is_renderable(c_type, false, &dwarf_type_env)
            {
                continue;
            }
            let c_type = collision_safe_local_aggregate_type(name, c_type, &dwarf_type_env)
                .unwrap_or_else(|| {
                    source_type_with_complete_struct_alias(c_type, &source_type_aliases)
                });
            exact.insert(name.clone(), c_type.clone());
            exact.insert(sanitize_c_ident(name), c_type);
        }
        *selected.borrow_mut() = exact;
    });

    let mut out = String::new();
    // Provenance as a C comment (valid, and the harness maps by address anyway).
    let _ = writeln!(out, "// glaurung: {} @ 0x{:x}", f.name, f.entry_va);
    let mut source_declarations = std::collections::BTreeSet::new();
    if let Some(prototype) = declared_prototype {
        source_declarations.extend(source_prototype_forward_declarations(
            prototype,
            &complete_structs,
            &dwarf_type_env,
        ));
    }
    for (local_name, c_type) in dwarf_local_types {
        if let Some(pointer) = dwarf_type_env.aggregate_pointer(c_type) {
            if !complete_structs.contains(pointer.source_name) {
                if collision_safe_local_aggregate_type(local_name, c_type, &dwarf_type_env)
                    .is_some()
                {
                    let keyword = match pointer.kind {
                        crate::debug::dwarf::DwarfTypeKind::Struct => "struct",
                        crate::debug::dwarf::DwarfTypeKind::Union => "union",
                        crate::debug::dwarf::DwarfTypeKind::Enum
                        | crate::debug::dwarf::DwarfTypeKind::Typedef => {
                            unreachable!("aggregate pointers resolve only to struct or union")
                        }
                    };
                    source_declarations.insert(format!("{keyword} {};", pointer.tag_name));
                } else {
                    source_declarations.insert(dwarf_type_env.forward_declaration(pointer));
                }
            }
        } else if let Some(declaration) = dwarf_type_env.typedef_declaration(c_type) {
            source_declarations.insert(declaration);
        }
    }
    for declaration in source_declarations {
        let _ = writeln!(out, "{declaration}");
    }
    for (name, layout) in &aggregate_layouts {
        let guard = format!("GLAURUNG_STRUCT_{name}_DEFINED");
        let _ = writeln!(out, "#ifndef {guard}");
        let _ = writeln!(out, "#define {guard}");
        let _ = writeln!(out, "typedef struct {name} {name};");
        let _ = writeln!(out, "struct {name} {{");
        for field in &layout.fields {
            let _ = writeln!(out, "    {} {};", field.c_type, field.name);
        }
        out.push_str("};\n");
        out.push_str("#endif\n");
    }
    // A direct load/store whose image VA survived readonly-data folding refers
    // to writable static storage. The original VA is meaningless after this C
    // fragment is linked into a new shared object, so give it a portable,
    // zero-initialized identity. Repeated tentative declarations of the same
    // internal-linkage object in a combined helper/root translation unit denote
    // one object, preserving sharing between decompiled sibling functions.
    for address in ids.global_addresses.keys() {
        let _ = writeln!(
            out,
            "static unsigned char {}[16] __attribute__((aligned(16)));",
            dec_global_name(*address)
        );
    }

    // Record every name declared as a pointer with its pointee width, so the
    // array-index render can rewrite
    // `*(T*)(base + i*sizeof(T))` as `base[i]` for those bases.
    DEC_PTRS.with(|m| m.borrow_mut().clear());
    DEC_DECLARED_CTYPES.with(|types| types.borrow_mut().clear());
    DEC_STACK_OBJECTS
        .with(|objects| *objects.borrow_mut() = ids.stack_objects.keys().cloned().collect());
    DEC_INT_WIDTHS.with(|m| m.borrow_mut().clear());
    DEC_INT_TYPES.with(|m| m.borrow_mut().clear());
    DEC_VOID_OUTPUT.with(|is_void| {
        is_void.set(output_kind == crate::ir::types_recover::RecoveredOutputKind::Void)
    });
    if let Some(tm) = tm {
        for (v, hint) in tm.iter() {
            if let (VReg::Phys(n), TypeHint::Pointer { pointee_width }) = (v, hint) {
                if parse_arg_index(n).is_some() || is_promoted_local(n) || is_high_variable(n) {
                    DEC_PTRS.with(|m| m.borrow_mut().insert(n.clone(), *pointee_width));
                }
            }
            if let (VReg::Phys(n), TypeHint::Int { signed, width }) = (v, hint) {
                if parse_arg_index(n).is_some() || is_promoted_local(n) {
                    DEC_INT_TYPES.with(|m| m.borrow_mut().insert(n.clone(), (*signed, *width)));
                }
            }
        }
    }
    // The logical-shift cast needs each operand's *machine* width (`edi`=4),
    // which the pre-canonicalisation `width_tm` carries; it is deliberately
    // decoupled from the recovered *declaration* type in `tm` (canonicalised to
    // 64-bit parents to keep def/use versions aligned). Narrowing only the
    // shift cast — not the declaration or the surrounding arithmetic — avoids
    // changing the width at which a widened value (`(uint64_t)a * b`) computes.
    if let Some(wtm) = width_tm.or(tm) {
        for (v, hint) in wtm.iter() {
            if let (VReg::Phys(n), TypeHint::Int { width, .. }) = (v, hint) {
                if *width > 0 && (parse_arg_index(n).is_some() || is_promoted_local(n)) {
                    DEC_INT_WIDTHS.with(|m| m.borrow_mut().insert(n.clone(), *width));
                }
            }
        }
    }
    let named_call_declarations = recover_named_call_prototypes(&f.body, &name);

    // Signature: recovered return + argument types. Record which arguments are
    // pointers so the body can cast their int↔pointer reuse (see DEC_PTR_ARGS).
    DEC_PTR_ARGS.with(|m| m.borrow_mut().clear());
    let return_type = declared_prototype.map_or_else(
        || {
            if output_kind == crate::ir::types_recover::RecoveredOutputKind::Void {
                "void".to_string()
            } else {
                infer_return_ctype(&f.body, tm).to_string()
            }
        },
        |prototype| {
            source_type_with_complete_struct_alias(&prototype.return_type, &source_type_aliases)
        },
    );
    DEC_RETURN_CTYPE.with(|selected| *selected.borrow_mut() = return_type.clone());
    // GCC 15 can ICE in its final RTL pass at `-O2` on exceptionally large,
    // goto-heavy generated functions even after the C front end accepts them.
    // Keep the source semantics and all producer flags, but lower only that
    // function's optimization level. The 2,000-statement threshold is above
    // every other function in the current 250-function blinded DecBench slice
    // (next-largest rendered body: 1,670 lines) and therefore cannot silently
    // perturb ordinary output.
    if ids.statement_count >= 2_000 {
        out.push_str("__attribute__((optimize(\"O1\"))) ");
    }
    out.push_str(&return_type);
    out.push(' ');
    out.push_str(&name);
    out.push('(');
    let mut parameter_types = Vec::with_capacity(arg_count);
    if arg_count == 0 {
        out.push_str("void");
    } else {
        for i in 0..arg_count {
            if i > 0 {
                out.push_str(", ");
            }
            let aname = format!("arg{}", i);
            let recovered_type = || ctype_for(&aname, tm).to_string();
            let aty = declared_prototype
                .and_then(|prototype| prototype.parameter_types.get(i))
                .filter(|c_type| dwarf_prototype_type_is_renderable(c_type, false, &dwarf_type_env))
                .map_or_else(recovered_type, |c_type| {
                    source_type_with_complete_struct_alias(c_type, &source_type_aliases)
                });
            if aty.ends_with('*') {
                DEC_PTR_ARGS.with(|m| m.borrow_mut().insert(aname.clone(), aty.clone()));
            }
            DEC_DECLARED_CTYPES.with(|types| {
                types.borrow_mut().insert(aname.clone(), aty.clone());
            });
            parameter_types.push(aty.clone());
            let _ = write!(out, "{} arg{}", aty, i);
        }
    }
    out.push_str(") {\n");

    // The current definition is also a callee declaration for recursive calls.
    // Put it in the selected-prototype table with external symbols, but do not
    // print a redundant block-scope declaration. An incompatible recursive
    // call can now own its pointer type without weakening this definition.
    let mut selected_call_prototypes = named_call_declarations.clone();
    selected_call_prototypes.insert(
        name.clone(),
        CallPrototype {
            return_type: return_type.clone(),
            parameter_types,
            variadic: false,
            authority: if all_declared_parameters_renderable {
                CallPrototypeAuthority::Authoritative
            } else {
                CallPrototypeAuthority::Recovered
            },
        },
    );
    DEC_NAMED_CALL_PROTOTYPES.with(|selected| {
        *selected.borrow_mut() = selected_call_prototypes;
    });

    if ids.has_unknown_value {
        out.push_str("    extern long __unknown(long, ...);\n");
    }

    // A resolved named call is still a typed call site. Keep the selected
    // authoritative-or-recovered contract inside the function so the standalone
    // fragment is valid C11/C23 without hiding the function definition behind a
    // translation-unit prelude. The prototype object retains its authority even
    // though both sources share one deterministic declaration table here.
    for (callee, prototype) in &named_call_declarations {
        out.push_str("    extern ");
        if crate::analysis::call_semantics::is_known_noreturn_symbol(callee) {
            out.push_str("__attribute__((noreturn)) ");
        }
        let _ = write!(out, "{} {}(", prototype.return_type, callee);
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
        out.push_str(");\n");
    }

    // The portable objects above are file-scope definitions, which keeps the
    // sharing between decompiled sibling functions that the original static
    // storage had. Consumers that score ONE function definition sliced out of
    // the translation unit never see them, so restate each one here: a
    // block-scope `extern` of an identifier whose file-scope `static` is
    // visible denotes that same internal-linkage object (C11 6.2.2p4), and the
    // sliced fragment declares everything it names.
    for address in ids.global_addresses.keys() {
        let _ = writeln!(
            out,
            "    extern unsigned char {}[16];",
            dec_global_name(*address)
        );
    }

    // A relocation-proven table is source-level data, not a raw image address
    // and not a set of guessed direct calls. Materialise it as a function-local
    // static object so standalone C preserves pointer-table indexing and storage
    // lifetime. Exact local target declarations also let the differential
    // harness include their real decompilations before compiling this fragment.
    let mut table_target_names = std::collections::BTreeSet::new();
    for (_, targets) in ids.function_tables.values() {
        for target in targets {
            let displayed = sanitize_c_ident(callee_display_name(&target.name));
            if displayed != name && !named_call_declarations.contains_key(&displayed) {
                table_target_names.insert(displayed);
            }
        }
    }
    for target in &table_target_names {
        let _ = writeln!(out, "    extern void {}(void);", target);
    }
    for (table_name, targets) in ids.function_tables.values() {
        let table_name = sanitize_c_ident(table_name);
        let _ = writeln!(
            out,
            "    static void (*{}[{}])(void) = {{",
            table_name,
            targets.len()
        );
        for target in targets {
            let target = sanitize_c_ident(callee_display_name(&target.name));
            let _ = writeln!(out, "        (void (*)(void)){},", target);
        }
        out.push_str("    };\n");
    }

    // Promoted stack slots and exact SSA-derived `varN` values may take a
    // recovered type. The high-variable pass admits `varN` only when every
    // definition agrees and no integer/address-arithmetic use exists. Physical
    // frame/ABI registers and unproven values stay `long` to preserve C
    // parseability (`rsp & -16`, `rbp + ret`, etc.).
    for local in ids.source_local_order.iter().chain(
        ids.locals
            .iter()
            .filter(|local| !ids.source_local_members.contains(*local)),
    ) {
        if let Some(size) = ids.stack_objects.get(local) {
            let _ = writeln!(out, "    unsigned char {}[{}];", local, size);
            continue;
        }
        if ids.wide_locals.contains(local) {
            let _ = writeln!(
                out,
                "    unsigned char {}[16] __attribute__((aligned(16)));",
                local
            );
            continue;
        }
        let ty = ids
            .call_result_types
            .get(local)
            .and_then(Option::as_ref)
            .cloned()
            .or_else(|| dec_struct_ptr_type(local))
            .unwrap_or_else(|| {
                if is_promoted_local(local) || is_high_variable(local) {
                    ctype_for(local, tm).to_string()
                } else {
                    "long".to_string()
                }
            });
        DEC_DECLARED_CTYPES.with(|types| {
            types.borrow_mut().insert(local.clone(), ty.clone());
        });
        let _ = writeln!(out, "    {} {};", ty, local);
    }

    // Body.
    for s in &f.body {
        write_stmt_dec(s, &mut out, 1);
    }

    // Any `goto` target that was never emitted as a label would make the unit
    // fail to compile ("label used but not defined"); pin each missing one with
    // a trailing null-statement label so the parse still closes cleanly.
    for target in ids.gotos.difference(&ids.labels) {
        let _ = writeln!(out, "    L_{:x}: ;", target);
    }

    out.push_str("}\n");
    DEC_NAMED_CALL_PROTOTYPES.with(|selected| selected.borrow_mut().clear());
    DEC_RENDERABLE_STRUCTS.with(|selected| selected.borrow_mut().clear());
    DEC_STRUCT_PTR_TYPES.with(|selected| selected.borrow_mut().clear());
    DEC_SOURCE_LOCALS.with(|locals| locals.borrow_mut().clear());
    DEC_GLOBAL_ADDRS.with(|addresses| addresses.borrow_mut().clear());
    DEC_WIDE_LOCALS.with(|locals| locals.borrow_mut().clear());
    DEC_POINTER_WIDTH.with(|width| width.set(8));
    out
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
    /// At least one expression contains an explicit unknown/poison value and
    /// therefore needs the C23-compatible helper declaration.
    has_unknown_value: bool,
    /// Recursive statement count used only for the exceptional GCC RTL-ICE
    /// compilation guard in the DecBench renderer.
    statement_count: usize,
    /// Relocation-proven function tables referenced by the body, keyed by
    /// original VA so repeated call sites emit one stable local definition.
    function_tables: std::collections::BTreeMap<u64, (String, Vec<FunctionTableTarget>)>,
    /// Direct absolute storage VAs still read or written after readonly-data
    /// folding. These need portable C objects rather than original-image
    /// process addresses.
    global_addresses: std::collections::BTreeMap<u64, u8>,
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
fn sanitize_c_ident(name: &str) -> String {
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
        // `Named` in a value position renders as a bare VA constant, and in a
        // call-target position as an (implicitly-declared) function name; either
        // way it is not a declared local, so nothing to collect here.
        Expr::Unknown(_) => ids.has_unknown_value = true,
        Expr::Const(_)
        | Expr::FloatConst { .. }
        | Expr::Addr(_)
        | Expr::Named { .. }
        | Expr::StringLit { .. } => {}
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
                ids.global_addresses
                    .entry(address)
                    .and_modify(|known| *known = (*known).max(*size))
                    .or_insert(*size);
            }
            collect_idents_expr(addr, ids);
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
        Expr::Cast { expr, .. } => collect_idents_expr(expr, ids),
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
                ids.global_addresses
                    .entry(address)
                    .and_modify(|known| *known = (*known).max(*size))
                    .or_insert(*size);
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
            if !matches!(target, Expr::Named { .. }) {
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

fn collect_named_call_observations(
    body: &[Stmt],
    current_name: &str,
    observations: &mut std::collections::BTreeMap<String, Vec<CallPrototype>>,
    authoritative: &mut std::collections::BTreeMap<String, CallPrototype>,
    conflicts: &mut std::collections::BTreeSet<String>,
) {
    for statement in body {
        match statement {
            Stmt::Call {
                target: Expr::Named { name, .. },
                args,
                dst,
                call_spec,
            } => {
                let displayed = sanitize_c_ident(callee_display_name(name));
                if displayed == current_name {
                    continue;
                }
                let call_spec = call_spec.clone().unwrap_or_else(|| {
                    crate::ir::call_contracts::recover_call_site_spec(
                        &Expr::Named {
                            va: 0,
                            name: name.clone(),
                        },
                        args,
                        dst.as_ref(),
                    )
                });
                observations
                    .entry(displayed.clone())
                    .or_default()
                    .push(call_spec.call_prototype);
                if let Some(prototype) = call_spec.callee_prototype {
                    if let Some(existing) = authoritative.get(&displayed) {
                        if existing != &prototype {
                            conflicts.insert(displayed);
                        }
                    } else {
                        authoritative.insert(displayed, prototype);
                    }
                }
            }
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                collect_named_call_observations(
                    then_body,
                    current_name,
                    observations,
                    authoritative,
                    conflicts,
                );
                if let Some(else_body) = else_body {
                    collect_named_call_observations(
                        else_body,
                        current_name,
                        observations,
                        authoritative,
                        conflicts,
                    );
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
                collect_named_call_observations(
                    body,
                    current_name,
                    observations,
                    authoritative,
                    conflicts,
                );
            }
            Stmt::For {
                init, step, body, ..
            } => {
                collect_named_call_observations(
                    std::slice::from_ref(init.as_ref()),
                    current_name,
                    observations,
                    authoritative,
                    conflicts,
                );
                collect_named_call_observations(
                    body,
                    current_name,
                    observations,
                    authoritative,
                    conflicts,
                );
                collect_named_call_observations(
                    std::slice::from_ref(step.as_ref()),
                    current_name,
                    observations,
                    authoritative,
                    conflicts,
                );
            }
            Stmt::Switch { cases, default, .. } => {
                for (_, case) in cases {
                    collect_named_call_observations(
                        case,
                        current_name,
                        observations,
                        authoritative,
                        conflicts,
                    );
                }
                if let Some(default) = default {
                    collect_named_call_observations(
                        default,
                        current_name,
                        observations,
                        authoritative,
                        conflicts,
                    );
                }
            }
            Stmt::TryCatch { try_body, catches } => {
                collect_named_call_observations(
                    try_body,
                    current_name,
                    observations,
                    authoritative,
                    conflicts,
                );
                for catch in catches {
                    collect_named_call_observations(
                        &catch.body,
                        current_name,
                        observations,
                        authoritative,
                        conflicts,
                    );
                }
            }
            _ => {}
        }
    }
}

fn infer_named_call_prototype(observations: &[CallPrototype]) -> Option<CallPrototype> {
    let first = observations.first()?;
    let mut observed_returns = observations
        .iter()
        .filter(|observation| observation.return_type != "void")
        .map(|observation| observation.return_type.as_str());
    let return_type = match observed_returns.next() {
        None => "void",
        Some(first_return) if observed_returns.all(|observed| observed == first_return) => {
            first_return
        }
        // Conflicting recovered result representations have no authoritative
        // winner. Keep the declaration at the machine-word boundary; each
        // pointer-returning use will carry its own call-site cast.
        Some(_) => "long",
    };

    if observations
        .iter()
        .all(|observation| observation.parameter_types == first.parameter_types)
    {
        return Some(CallPrototype {
            return_type: return_type.to_string(),
            parameter_types: first.parameter_types.iter().cloned().collect(),
            variadic: false,
            authority: CallPrototypeAuthority::Recovered,
        });
    }

    let common_len = observations
        .iter()
        .map(|observation| observation.parameter_types.len())
        .min()
        .unwrap_or(0);
    let prefix_len = (0..common_len)
        .take_while(|index| {
            let expected = &first.parameter_types[*index];
            observations
                .iter()
                .all(|observation| &observation.parameter_types[*index] == expected)
        })
        .count();
    if prefix_len == 0 {
        let mut selected = observations
            .iter()
            .max_by_key(|observation| observation.parameter_types.len())?
            .clone();
        selected.return_type = return_type.to_string();
        selected.authority = CallPrototypeAuthority::Recovered;
        return Some(selected);
    }

    Some(CallPrototype {
        return_type: return_type.to_string(),
        parameter_types: first.parameter_types[..prefix_len]
            .iter()
            .cloned()
            .collect(),
        variadic: true,
        authority: CallPrototypeAuthority::Recovered,
    })
}

fn recover_named_call_prototypes(
    body: &[Stmt],
    current_name: &str,
) -> std::collections::BTreeMap<String, CallPrototype> {
    let mut observations = std::collections::BTreeMap::new();
    let mut prototypes = std::collections::BTreeMap::new();
    let mut conflicts = std::collections::BTreeSet::new();
    collect_named_call_observations(
        body,
        current_name,
        &mut observations,
        &mut prototypes,
        &mut conflicts,
    );
    for conflict in &conflicts {
        prototypes.remove(conflict);
    }
    for (name, observations) in observations {
        if let std::collections::btree_map::Entry::Vacant(entry) = prototypes.entry(name) {
            if let Some(prototype) = infer_named_call_prototype(&observations) {
                entry.insert(prototype);
            }
        }
    }
    prototypes
}

thread_local! {
    /// Pointer-typed argument names (`arg0` → `"int *"`) for the function
    /// currently being rendered by `render_decbench_typed`. A pointer argument
    /// is genuinely a pointer in the signature (so type_match credits it), but
    /// our IR uses explicit byte-offset arithmetic and reuses the ABI register
    /// as a scratch integer, which is an int↔pointer conflict in C. We reconcile
    /// it at render time with casts (see `write_reg_dec` / the Assign arm), so
    /// the emitted C compiles (the gate for byte_match) without changing the
    /// recovered signature. Scoped per render; renders are single-threaded.
    static DEC_PTR_ARGS: std::cell::RefCell<std::collections::HashMap<String, String>> =
        std::cell::RefCell::new(std::collections::HashMap::new());

    /// Source-renamed promoted locals for the current render. Semantic passes
    /// retain their offset-bearing internal names; this presentation-only set
    /// preserves scalar assignment semantics after the final DWARF rename.
    static DEC_SOURCE_LOCALS: std::cell::RefCell<std::collections::HashSet<String>> =
        std::cell::RefCell::new(std::collections::HashSet::new());

    /// Names that are *declared as pointers* in the current render (arguments and
    /// promoted pointer locals) → their pointee width in bytes. Consulted by the
    /// array-index render to rewrite `*(T*)(base + i*sizeof(T))` as `base[i]`.
    /// Only declared pointers appear here, so `base[i]` is always valid C.
    static DEC_PTRS: std::cell::RefCell<std::collections::HashMap<String, u8>> =
        std::cell::RefCell::new(std::collections::HashMap::new());

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

    /// The exact C type actually printed for each scalar local and argument.
    /// Type recovery can contain competing facts from different machine-value
    /// lifetimes that later share one rendered name; assignment conversion must
    /// consume the selected declaration, not rescan those candidates.
    static DEC_DECLARED_CTYPES: std::cell::RefCell<std::collections::HashMap<String, String>> =
        std::cell::RefCell::new(std::collections::HashMap::new());

    /// Names declared as complete byte arrays because their addresses escape.
    /// These are C lvalues but not assignable scalars: a machine store whose
    /// address is one of these names must remain a dereference rather than the
    /// promoted-local spelling `object = value`.
    static DEC_STACK_OBJECTS: std::cell::RefCell<std::collections::BTreeSet<String>> =
        std::cell::RefCell::new(std::collections::BTreeSet::new());

    /// Integer-typed names in the current render (arguments and promoted scalar
    /// locals) → their declared byte width. Consulted by the logical-shift render
    /// so `(unsigned)x >> k` on a 32-bit operand casts to `unsigned int` rather
    /// than a blanket `unsigned long`: a blanket 64-bit cast sign-extends a
    /// negative narrow value into the high half before the zero-filling shift,
    /// producing a different result than the original narrow shift.
    static DEC_INT_WIDTHS: std::cell::RefCell<std::collections::HashMap<String, u8>> =
        std::cell::RefCell::new(std::collections::HashMap::new());

    /// Exact signedness and width of integer declarations in this render. This
    /// lets the printer rely on C's built-in integer promotion and pointer-index
    /// conversion when they are exactly the casts already represented in IR.
    static DEC_INT_TYPES: std::cell::RefCell<std::collections::HashMap<String, (bool, u8)>> =
        std::cell::RefCell::new(std::collections::HashMap::new());

    /// Whether the current function's recovered source prototype is `void`.
    /// Unknown scalar output uses `return 0;` for a bare machine return; a
    /// proven void function must emit the distinct C statement `return;`.
    static DEC_VOID_OUTPUT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };

    /// Exact C return type selected for the current DecBench render. Return
    /// statements need the same representation-boundary conversion as local
    /// assignments; keeping this beside `DEC_VOID_OUTPUT` prevents the body
    /// printer from independently guessing the function signature.
    static DEC_RETURN_CTYPE: std::cell::RefCell<String> = std::cell::RefCell::new("long".to_string());

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

    /// C identifiers whose recovered value occupies all 16 bytes of a vector
    /// register. They render as byte-array temporaries, never scalar `long`s.
    static DEC_WIDE_LOCALS: std::cell::RefCell<std::collections::BTreeSet<String>> =
        std::cell::RefCell::new(std::collections::BTreeSet::new());
}

fn dec_global_name(address: u64) -> String {
    format!("glaurung_global_{address:x}")
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

fn dec_ptr_arg_type(name: &str) -> Option<String> {
    DEC_PTR_ARGS.with(|m| m.borrow().get(name).cloned())
}

fn dec_struct_ptr_type(name: &str) -> Option<String> {
    DEC_STRUCT_PTR_TYPES.with(|m| m.borrow().get(name).cloned())
}

/// The pointee width of `name` if it is declared as a pointer in this render.
fn dec_ptr_width(name: &str) -> Option<u8> {
    DEC_PTRS.with(|m| m.borrow().get(name).copied())
}

fn dec_is_stack_object(name: &str) -> bool {
    let displayed = sanitize_c_ident(name);
    DEC_STACK_OBJECTS.with(|objects| objects.borrow().contains(&displayed))
}

/// The declared integer byte-width of `name` if it is an integer-typed
/// argument/local in this render (see `DEC_INT_WIDTHS`).
fn dec_int_width(name: &str) -> Option<u8> {
    DEC_INT_WIDTHS.with(|m| m.borrow().get(name).copied())
}

fn dec_int_type(name: &str) -> Option<(bool, u8)> {
    DEC_INT_TYPES.with(|m| m.borrow().get(name).copied())
}

/// The C spelling of an `size`-byte *unsigned* integer, for logical-shift casts.
fn unsigned_ctype(size: u8) -> &'static str {
    int_ctype(false, size)
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
            return target_int_ctype(false, width);
        }
    }
    if let (Some(w), Expr::Const(k)) = (expr_machine_width(lhs), rhs) {
        if *k >= 0 && (*k as u64) < (w as u64) * 8 {
            return unsigned_ctype(w);
        }
    }
    target_int_ctype(false, 8)
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
fn expr_machine_width(e: &Expr) -> Option<u8> {
    match e {
        Expr::Named { name, .. } => dec_int_width(name),
        Expr::Reg(VReg::Phys(n)) => dec_int_width(n),
        Expr::Deref { size, .. } => Some(*size),
        Expr::Const(_) => None,
        Expr::Select { width, .. } => Some(*width),
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

/// Re-express an array-index constant after the machine's scaled address
/// arithmetic wrapped at 32 bits.
///
/// GCC i386 commonly spells `a[i - 1]` as `add $0x3fffffff, %eax; lea
/// (,%eax,4)`. The quotient `0x3fffffff` is only `-1` after multiplication by
/// four wraps modulo 2^32. Once [`try_array_index`] removes that scale and the
/// generated C is rebuilt for LP64, leaving the quotient unchanged creates a
/// four-gigabyte access. Recover the signed byte displacement first and divide
/// it back by the exact element size. If the wrapped displacement is not
/// divisible by that size, there is no exact C array index and we refuse.
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
        Expr::Named { va, .. } => {
            if dec_is_global_addr(*va) {
                let _ = write!(out, "&{}[0]", dec_global_name(*va));
            } else {
                let _ = write!(out, "0x{:x}", va);
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
                let c_type = if *width == 8 && DEC_SEMANTIC_WIDE_CAST.with(std::cell::Cell::get) {
                    target_int_ctype(*signed, *width)
                } else {
                    int_ctype(*signed, *width)
                };
                let _ = write!(out, "({c_type})(");
                write_expr_dec(expr, out);
                out.push(')');
            }
        }
        Expr::Cmp { op, lhs, rhs } => {
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
            out.push('(');
            write_expr_dec(cond, out);
            out.push_str(" ? ");
            write_expr_dec(if_true, out);
            out.push_str(" : ");
            write_expr_dec(if_false, out);
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
fn callee_display_name(name: &str) -> &str {
    name.split_once('@').map_or(name, |(base, _)| base)
}

fn declared_reg_ctype(reg: &VReg) -> String {
    let VReg::Phys(name) = reg else {
        return "long".to_string();
    };
    let displayed = sanitize_c_ident(name);
    if let Some(selected) =
        DEC_DECLARED_CTYPES.with(|types| types.borrow().get(&displayed).cloned())
    {
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

/// Whether the ordinary call-argument writer already emits a C pointer value.
/// Pointer-shaped arithmetic is deliberately absent: its internal C spelling is
/// a machine word and therefore still needs a cast at the call boundary.
fn call_argument_renders_as_pointer(arg: &Expr) -> bool {
    match arg {
        Expr::Reg(VReg::Phys(name)) => {
            dec_ptr_arg_type(name).is_some()
                || dec_struct_ptr_type(name).is_some()
                || dec_ptr_width(name).is_some()
                || dec_is_stack_object(name)
        }
        Expr::StringLit { .. } | Expr::StackAddr { .. } => true,
        _ => false,
    }
}

/// The exact C pointer type a call argument renders as, when it is known.
///
/// Two different pointer types are still a type error, so "renders as a
/// pointer" is not enough to skip the boundary cast: the rendered type has to
/// be the declared parameter type. Only register arguments have an exact
/// declared spelling; everything else answers `None` and keeps the cast.
fn call_argument_pointer_ctype(arg: &Expr) -> Option<String> {
    match arg {
        Expr::Reg(register @ VReg::Phys(_)) => {
            let declared = declared_reg_ctype(register);
            declared.ends_with('*').then_some(declared)
        }
        _ => None,
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

    out.push('(');
    out.push_str(parameter_type);
    out.push_str(")(");
    write_call_arg_dec(arg, out);
    out.push(')');
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
                || (parameter_type.ends_with('*')
                    && (!call_argument_renders_as_pointer(a)
                        // A pointer argument of a DIFFERENT pointer type is
                        // still incompatible with the declaration this call
                        // emits, so reassert the declared parameter type.
                        || call_argument_pointer_ctype(a).map_or_else(
                            || !matches!(parameter_type.as_str(), "void *" | "const void *"),
                            |rendered| &rendered != parameter_type,
                        )))
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
    }
    out.push(')');
}

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
    write_reg_lvalue_dec(dst, out);
    out.push_str(" = ");
    write_assignment_value_dec(dst, src, out);
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
        // C type-checks the two conditional operands before applying an outer
        // cast. Convert each arm at the recovered destination boundary so a
        // pointer-shaped literal and a machine word form one valid expression.
        out.push('(');
        write_expr_dec(cond, out);
        out.push_str(" ? ");
        write_representation_value_dec(destination_type, if_true, out);
        out.push_str(" : ");
        write_representation_value_dec(destination_type, if_false, out);
        out.push(')');
        return;
    }

    if matches!(destination_type, "float" | "double") {
        write_float_expr_dec(src, if destination_type == "float" { 4 } else { 8 }, out);
        return;
    }

    let destination_is_pointer = destination_type.ends_with('*');
    let source_is_pointer = expression_has_pointer_representation(src);
    if destination_is_pointer && source_is_pointer {
        if let Expr::Reg(reg @ VReg::Phys(_)) = src {
            let source_type = declared_reg_ctype(reg);
            if source_type.ends_with('*')
                && source_type != destination_type
                && source_type != "void *"
                && destination_type != "void *"
            {
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
            // These expressions already have a pointer type in C.
            Expr::StringLit { .. } | Expr::StackAddr { .. } => write_expr_dec(src, out),
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
fn float_store_pointee_ctype(src: &Expr, size: u8) -> Option<&'static str> {
    match src {
        Expr::Reg(register @ VReg::Phys(_)) => {
            match (declared_reg_ctype(register).as_str(), size) {
                ("float", 4) => Some("float"),
                ("double", 8) => Some("double"),
                _ => None,
            }
        }
        Expr::FloatConst { width: 4, .. } if size == 4 => Some("float"),
        Expr::FloatConst { width: 8, .. } if size == 8 => Some("double"),
        _ => None,
    }
}

fn write_stmt_dec(s: &Stmt, out: &mut String, level: usize) {
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
            // `Expr::Select` is already the side-effect-free value semantics
            // (`cond ? true : false`). Keep that typed middle-layer node visible
            // in benchmark C instead of inventing statement-level CFG and an
            // eager initializer that were not present in the AST.
            indent(out, level);
            write_assign_dec(dst, src, out);
            out.push_str(";\n");
        }
        Stmt::Store { addr, src, size } => {
            indent(out, level);
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
                    write_reg_lvalue_dec(&VReg::phys(name), out);
                    out.push_str(" = ");
                    write_assignment_value_dec(&VReg::phys(name), src, out);
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
            let pointee_type =
                float_store_pointee_ctype(src, *size).unwrap_or_else(|| store_pointee_ctype(*size));
            let _ = write!(out, "*({pointee_type} *)(");
            write_expr_dec(addr, out);
            out.push_str(") = ");
            write_store_value_dec(src, *size, out);
            out.push_str(";\n");
        }
        Stmt::Call {
            target,
            args,
            dst,
            call_spec,
        } => {
            indent(out, level);
            // A call's result must land somewhere: dropping it emitted
            // `f(x);` and then read the ARGUMENT where the return value belonged.
            if let Some(VReg::Phys(n)) = dst {
                let _ = write!(out, "{} = ", sanitize_c_ident(n));
            }
            if let Some(dst) = dst {
                write_call_result_conversion_dec(target, args, dst, call_spec.as_ref(), out);
            }
            write_call_dec(target, args, dst.as_ref(), call_spec.as_ref(), out);
            out.push_str(";\n");
        }
        Stmt::Return { value } => {
            indent(out, level);
            match value {
                Some(e) => {
                    out.push_str("return ");
                    DEC_RETURN_CTYPE.with(|return_type| {
                        write_representation_value_dec(return_type.borrow().as_str(), e, out)
                    });
                    out.push_str(";\n");
                }
                None => {
                    if DEC_VOID_OUTPUT.with(std::cell::Cell::get) {
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
            write_expr_dec(cond, out);
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
            write_expr_dec(cond, out);
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
            write_expr_dec(cond, out);
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
            write_expr_dec(cond, out);
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
    write_reg_lvalue_dec(dst, out);
    out.push_str(" = ");
    write_assignment_value_dec(dst, src, out);
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
#[path = "ast_tests/ilp32_wide.rs"]
mod ilp32_wide_tests;

#[cfg(test)]
#[path = "ast_tests/memory_fill.rs"]
mod memory_fill_tests;

#[cfg(test)]
mod tests {

    /// The old rule was UNSOUND, and this is the counterexample.
    ///
    /// `t = i + 1` reads no memory and is not a self-reference, so the previous
    /// preamble-only check hoisted it above the loop. But the body assigns `i`, so
    /// `t` is loop-carried: hoisted, the condition `t < n` never changes and the
    /// loop does not terminate. Rejecting only memory reads and self-references was
    /// necessary and nowhere near sufficient — invariance is a def-use property of
    /// the preamble AND the body, and cannot be decided from the preamble alone.
    #[test]
    fn a_preamble_reading_a_body_modified_register_is_not_hoistable() {
        let pre = vec![Stmt::Assign {
            dst: VReg::phys("t"),
            src: Expr::Bin {
                op: crate::ir::types::BinOp::Add,
                lhs: Box::new(Expr::Reg(VReg::phys("i"))),
                rhs: Box::new(Expr::Const(1)),
            },
        }];
        let body = vec![Stmt::Assign {
            dst: VReg::phys("i"),
            src: Expr::Bin {
                op: crate::ir::types::BinOp::Add,
                lhs: Box::new(Expr::Reg(VReg::phys("i"))),
                rhs: Box::new(Expr::Const(1)),
            },
        }];
        assert!(
            !super::hoisting_the_header_is_safe(&pre, &body),
            "hoisting `t = i + 1` out of a loop whose body bumps `i` freezes the \
             condition and the loop never ends"
        );
        // The same preamble IS hoistable when the body leaves `i` alone.
        let inert = vec![Stmt::Assign {
            dst: VReg::phys("s"),
            src: Expr::Const(0),
        }];
        assert!(
            super::hoisting_the_header_is_safe(&pre, &inert),
            "a genuinely invariant preamble must still hoist, or every rotated loop \
             regresses to `while (1) {{ ... }}`"
        );
    }

    /// Nesting must not hide the assignment. A body that bumps `i` inside an `if`
    /// or an inner loop is still a body that bumps `i`.
    #[test]
    fn a_nested_body_assignment_still_blocks_the_hoist() {
        let bump = Stmt::Assign {
            dst: VReg::phys("i"),
            src: Expr::Bin {
                op: crate::ir::types::BinOp::Add,
                lhs: Box::new(Expr::Reg(VReg::phys("i"))),
                rhs: Box::new(Expr::Const(1)),
            },
        };
        let pre = vec![Stmt::Assign {
            dst: VReg::phys("t"),
            src: Expr::Reg(VReg::phys("i")),
        }];
        for body in [
            vec![Stmt::If {
                cond: Expr::Const(1),
                then_body: vec![bump.clone()],
                else_body: None,
            }],
            vec![Stmt::If {
                cond: Expr::Const(1),
                then_body: vec![],
                else_body: Some(vec![bump.clone()]),
            }],
            vec![Stmt::While {
                cond: Expr::Const(1),
                body: vec![bump.clone()],
            }],
        ] {
            assert!(
                !super::hoisting_the_header_is_safe(&pre, &body),
                "a nested assignment to `i` must block the hoist: {body:?}"
            );
        }
    }

    /// The preamble is part of the loop, so a register IT assigns is loop-carried
    /// too. `newton_isqrt` at `gcc -O2` is the measured case: once value-number
    /// coalescing removed the out-of-SSA copies that had been hiding the shape,
    /// the whole Newton step sat in the header reading `estimate` and then
    /// rewriting it, with only the iteration counter left in the body. Hoisting it
    /// ran the recurrence exactly once and the function returned the first
    /// estimate.
    #[test]
    fn a_preamble_reading_a_register_it_later_assigns_is_not_hoistable() {
        let pre = vec![
            Stmt::Assign {
                dst: VReg::phys("cursor"),
                src: Expr::Reg(VReg::phys("estimate")),
            },
            Stmt::Assign {
                dst: VReg::phys("estimate"),
                src: Expr::Bin {
                    op: crate::ir::types::BinOp::Add,
                    lhs: Box::new(Expr::Reg(VReg::phys("cursor"))),
                    rhs: Box::new(Expr::Const(1)),
                },
            },
        ];
        // The body only decrements the trip counter — it never touches `estimate`,
        // which is exactly why checking the body alone said "safe".
        let body = vec![Stmt::Assign {
            dst: VReg::phys("counter"),
            src: Expr::Bin {
                op: crate::ir::types::BinOp::Sub,
                lhs: Box::new(Expr::Reg(VReg::phys("counter"))),
                rhs: Box::new(Expr::Const(1)),
            },
        }];
        assert!(
            !super::hoisting_the_header_is_safe(&pre, &body),
            "`cursor = estimate` reads the value the next preamble statement \
             produces, so the chain is loop-carried through the header itself"
        );
        // Reading a register the preamble assigns EARLIER is still fine: that is
        // this chain's own value, not the previous iteration's.
        let forward = vec![
            Stmt::Assign {
                dst: VReg::phys("scratch"),
                src: Expr::Const(4),
            },
            Stmt::Assign {
                dst: VReg::phys("limit"),
                src: Expr::Reg(VReg::phys("scratch")),
            },
        ];
        assert!(
            super::hoisting_the_header_is_safe(&forward, &body),
            "a forward-only preamble chain is invariant and must still hoist"
        );
    }

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
    fn return_fold_collapses_an_exact_ssa_result_carrier() {
        let mut body = vec![
            Stmt::Assign {
                dst: VReg::phys("rax#7"),
                src: Expr::Const(42),
            },
            Stmt::Return {
                value: Some(Expr::Reg(VReg::phys("rax#7"))),
            },
        ];

        fold_returns(&mut body);

        assert_eq!(
            body,
            vec![Stmt::Return {
                value: Some(Expr::Const(42)),
            }]
        );
    }

    #[test]
    fn late_return_cleanup_removes_redundant_identical_constant_assignment() {
        let mut body = vec![
            Stmt::Assign {
                dst: VReg::phys("ret"),
                src: Expr::Const(-1),
            },
            Stmt::Return {
                value: Some(Expr::Const(-1)),
            },
        ];

        remove_redundant_return_constant_assignments(&mut body);

        assert_eq!(
            body,
            vec![Stmt::Return {
                value: Some(Expr::Const(-1)),
            }]
        );
    }

    #[test]
    fn late_return_cleanup_preserves_mismatched_constant_assignment() {
        let mut body = vec![
            Stmt::Assign {
                dst: VReg::phys("ret"),
                src: Expr::Const(-1),
            },
            Stmt::Return {
                value: Some(Expr::Const(0)),
            },
        ];
        let expected = body.clone();

        remove_redundant_return_constant_assignments(&mut body);

        assert_eq!(body, expected);
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
    // -- render_decbench (parseable-C) -----------------------------------------

    /// The DecBench pipeline as the product runs it: the explicit semantic
    /// transformation, then formatting. Tests that characterise the folding must go
    /// through it — `render_decbench` alone is formatting-only by design.
    fn dec_pipeline(f: &Function) -> String {
        render_decbench(&prepare_for_decbench(f))
    }

    #[test]
    fn decbench_direct_named_data_uses_portable_static_storage() {
        let function = Function {
            name: "read_counter".to_string(),
            entry_va: 0x1150,
            body: vec![Stmt::Return {
                value: Some(Expr::Deref {
                    addr: Box::new(Expr::Named {
                        va: 0x4024,
                        name: "g_counter".to_string(),
                    }),
                    size: 4,
                }),
            }],
        };

        let rendered = render_decbench(&function);

        assert!(
            rendered.contains(
                "static unsigned char glaurung_global_4024[16] __attribute__((aligned(16)));"
            ),
            "direct data storage needs a portable object:\n{rendered}"
        );
        assert!(
            rendered.contains("*(int *)(&glaurung_global_4024[0])"),
            "the load must address the portable object:\n{rendered}"
        );
        assert!(
            !rendered.contains("*(int *)(0x4024)"),
            "the original image VA cannot survive recompilation:\n{rendered}"
        );
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
            body.contains("extern unsigned char glaurung_global_4024[16];"),
            "the sliced function body must declare the object it reads:\n{rendered}"
        );
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
            Some(&Stmt::Return { value: None }),
            "a void prototype must erase the incidental machine output"
        );
        let text = render_decbench_typed_with_output(
            &prepared,
            None,
            None,
            crate::ir::types_recover::RecoveredOutputKind::Void,
        );
        assert!(text.contains("void tick(void)"), "wrong signature:\n{text}");
        assert!(text.contains("return;"), "wrong return statement:\n{text}");
        assert!(
            !text.contains("return ret;"),
            "machine residue leaked:\n{text}"
        );
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

        assert!(text.contains("consume_pointer(local_20)"), "{text}");
        assert!(text.contains("local_20 = status"), "{text}");
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

        assert!(text.contains("while ((arg0 != 0))"), "{text}");
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
                _ => None,
            })
            .expect("the call must survive preparation");
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
            out.contains("return ret;"),
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
    fn named_call_prototype_preserves_an_exact_observed_contract() {
        let observations = vec![CallPrototype {
            return_type: "long".into(),
            parameter_types: vec!["long".into(), "char *".into()],
            variadic: false,
            authority: CallPrototypeAuthority::Recovered,
        }];

        assert_eq!(
            infer_named_call_prototype(&observations),
            Some(CallPrototype {
                return_type: "long".into(),
                parameter_types: vec!["long".into(), "char *".into()],
                variadic: false,
                authority: CallPrototypeAuthority::Recovered,
            })
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
                "long mixed_dwarf_types(const char * arg0, long arg1, void * arg2, const char * * arg3)"
            ),
            "one opaque parameter discarded independently renderable DWARF types:\n{rendered}"
        );
        assert!(
            !rendered.contains("opaque_callback"),
            "an unavailable typedef escaped into generated C:\n{rendered}"
        );
    }

    #[test]
    fn named_call_prototype_uses_a_variadic_common_prefix_for_mixed_arities() {
        let observations = vec![
            CallPrototype {
                return_type: "long".into(),
                parameter_types: vec!["char *".into(), "long".into()],
                variadic: false,
                authority: CallPrototypeAuthority::Recovered,
            },
            CallPrototype {
                return_type: "long".into(),
                parameter_types: vec!["char *".into(), "long".into(), "int".into()],
                variadic: false,
                authority: CallPrototypeAuthority::Recovered,
            },
        ];

        assert_eq!(
            infer_named_call_prototype(&observations),
            Some(CallPrototype {
                return_type: "long".into(),
                parameter_types: vec!["char *".into(), "long".into()],
                variadic: true,
                authority: CallPrototypeAuthority::Recovered,
            })
        );
    }

    #[test]
    fn named_call_prototype_uses_machine_word_for_conflicting_return_types() {
        let observations = vec![
            CallPrototype {
                return_type: "long".into(),
                parameter_types: vec!["long".into()],
                variadic: false,
                authority: CallPrototypeAuthority::Recovered,
            },
            CallPrototype {
                return_type: "char *".into(),
                parameter_types: vec!["long".into()],
                variadic: false,
                authority: CallPrototypeAuthority::Recovered,
            },
        ];

        assert_eq!(
            infer_named_call_prototype(&observations),
            Some(CallPrototype {
                return_type: "long".into(),
                parameter_types: vec!["long".into()],
                variadic: false,
                authority: CallPrototypeAuthority::Recovered,
            })
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
}
