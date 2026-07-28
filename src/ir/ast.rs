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
    BinOp, CallTarget, CmpOp, Flag, LlirBlock, LlirFunction, LlirInstr, MemOp, Op, UnOp, VReg,
    Value,
};
use crate::ir::types_recover::{TypeHint, TypeMap};

// -- Expressions ---------------------------------------------------------------

/// PDB-backed field candidate for a memory operand offset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdbFieldHint {
    pub type_name: String,
    pub field_name: String,
    pub field_type: Option<String>,
    pub offset: u64,
}

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
    },
    Return {
        value: Option<Expr>,
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
                    if body_assigns.contains(r) && !defined_here.contains(r) {
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
fn widen_cast(
    expr: Expr,
    signed: bool,
    from: crate::ir::types::Width,
    to: crate::ir::types::Width,
) -> Expr {
    let fw = (from.bits() / 8).max(1) as u8;
    let tw = (to.bits() / 8).max(1) as u8;
    let inner = Expr::Cast {
        signed,
        width: fw,
        expr: Box::new(expr),
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
fn lower_op(op: &Op) -> Vec<Stmt> {
    match op {
        Op::Nop => vec![Stmt::Nop],
        Op::Assign { dst, src } => vec![Stmt::Assign {
            dst: dst.clone(),
            src: lower_value(src),
        }],
        Op::CondAssign { dst, cond, src } => vec![Stmt::If {
            cond: Expr::Reg(cond.clone()),
            then_body: vec![Stmt::Assign {
                dst: dst.clone(),
                src: lower_value(src),
            }],
            else_body: None,
        }],
        Op::Bin { dst, op, lhs, rhs } => vec![Stmt::Assign {
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
        Op::IndirectJump { target } => vec![Stmt::IndirectGoto {
            target: lower_value(target),
        }],
        // A CondJump on its own (not absorbed into a structured If/While)
        // becomes a conditional goto. If the CondJump carries `inverted`
        // (i.e. lifted from JNE / JAE / JGE / b.ne / b.hs / ...), wrap the
        // flag in a Not so the printer renders "!flag" and the inline-hoist
        // pass downstream can fold the original Cmp through the negation
        // into an `Expr::Cmp` of the opposite kind.
        Op::CondJump {
            cond,
            target,
            inverted,
        } => {
            let cond_expr = if *inverted {
                Expr::Un {
                    op: UnOp::Not,
                    src: Box::new(Expr::Reg(cond.clone())),
                }
            } else {
                Expr::Reg(cond.clone())
            };
            vec![Stmt::If {
                cond: cond_expr,
                then_body: vec![Stmt::Goto { target: *target }],
                else_body: None,
            }]
        }
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
            }]
        }
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
        //   Trunc to W: keep the low W bits -> `(uint<W>)src`, already self-contained.
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
                width: (to.bits() / 8).max(1) as u8,
                expr: Box::new(lower_value(src)),
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
                width: (width.bits() / 8).max(1) as u8,
            },
        }],
        // Opaque intrinsic. For the lowered-`Unknown` case (no typed operands)
        // render exactly as the old `Unknown` did — including the semantic
        // comments for known system instructions — so decompiler output is
        // unchanged by the Phase-0 migration. Intrinsics carrying operands
        // (future richer lifting) render with an argument ellipsis.
        Op::Intrinsic { name, ins, .. } => match semantic_comment_for_unknown(name) {
            Some(comment) => vec![Stmt::Comment(comment.to_string())],
            None if ins.is_empty() => vec![Stmt::Unknown(name.clone())],
            None => vec![Stmt::Unknown(format!("{}(...)", name))],
        },
        Op::Unknown { mnemonic } => match semantic_comment_for_unknown(mnemonic) {
            Some(comment) => vec![Stmt::Comment(comment.to_string())],
            None => vec![Stmt::Unknown(mnemonic.clone())],
        },
    }
}

/// Lower every op in a block to stmts.
fn lower_block(b: &LlirBlock) -> Vec<Stmt> {
    let mut out = Vec::with_capacity(b.instrs.len());
    for ins in &b.instrs {
        out.extend(lower_op(&ins.op));
    }
    hoist_inline_flag_conds(out)
}

/// Peephole pass: for each control-flow condition or pure select condition whose
/// flag was assigned by a `Stmt::Assign { dst: flag, src: Expr::Cmp(..) }` earlier
/// in the same block (with no intervening read of the flag), fold the comparison
/// into the condition and drop the assignment.
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
                        if reads == 0 {
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
            (None, true) => Expr::Un {
                op: UnOp::Not,
                src: Box::new(Expr::Reg(flag)),
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
/// Anything else gets wrapped in `Expr::Un { Not, .. }` so semantics survive.
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
        Expr::Un {
            op: UnOp::Not,
            src: Box::new(expr),
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
                        if usages == 0 {
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
            Expr::Un {
                op: UnOp::Not,
                src: Box::new(Expr::Reg(cond.clone())),
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
        Expr::Const(_)
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
    }
}

/// Whether evaluating `expr` speculatively is side-effect and fault free.
///
/// A one-armed select evaluates its initializer even when the other arm is
/// selected. Register arithmetic is safe to evaluate early; memory reads and
/// opaque expressions are not.
fn can_eagerly_evaluate(expr: &Expr) -> bool {
    match expr {
        Expr::Deref { .. } | Expr::Unknown(_) => false,
        Expr::Bin { op: BinOp::Div, .. } => false,
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
        | Expr::Const(_)
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

fn lower_region(
    r: &Region,
    lf: &LlirFunction,
    targets: &std::collections::HashSet<u64>,
) -> Vec<Stmt> {
    let mut out = lower_region_inner(r, lf, targets);
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
) -> Vec<Stmt> {
    match r {
        Region::Block(bi) => lower_block(&lf.blocks[*bi]),
        Region::Goto(bi) => vec![Stmt::Goto {
            target: lf.blocks[*bi].start_va,
        }],
        Region::Seq(parts) => {
            let mut out = Vec::new();
            for (idx, p) in parts.iter().enumerate() {
                let mut lowered = lower_region(p, lf, targets);
                // Strip a redundant `goto <header>` when the next region is a
                // loop headed at that VA: the `-O0` for-loop's entry jump to its
                // condition block is just the natural fall-in to the `while`, so
                // keeping it would leave a goto to a synthesized empty label.
                let next_loop_entry = parts.get(idx + 1).and_then(|next| match next {
                    Region::While { header, .. } => Some(*header),
                    Region::DoWhile { .. } => crate::ir::structure::entry_block(next),
                    _ => None,
                });
                if let Some(header) = next_loop_entry {
                    let hva = lf.blocks[header].start_va;
                    if matches!(lowered.last(), Some(Stmt::Goto { target }) if *target == hva) {
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
            let cond_stmts = lower_block(&lf.blocks[*cond]);
            let (cond_expr, mut pre) = extract_cond_and_strip(&lf.blocks[*cond], cond_stmts);
            // The raw condition is true when the branch is taken; if `then_r` is
            // the fall-through arm the structurer flagged `invert`, so negate.
            let cond_expr = if *invert {
                negate_cmp_expr(cond_expr)
            } else {
                cond_expr
            };
            let mut then_stmts = lower_region(then_r, lf, targets);
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
            let cond_stmts = lower_block(&lf.blocks[*cond]);
            let (cond_expr, mut pre) = extract_cond_and_strip(&lf.blocks[*cond], cond_stmts);
            let cond_expr = if *invert {
                negate_cmp_expr(cond_expr)
            } else {
                cond_expr
            };
            let mut then_stmts = lower_region(then_r, lf, targets);
            let mut else_stmts = lower_region(else_r, lf, targets);
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
            let cond_stmts = lower_block(&lf.blocks[*header]);
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
            let mut body_stmts = lower_region(body, lf, targets);
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
            let mut body_stmts = lower_region(body, lf, targets);
            let cond_stmts = lower_block(&lf.blocks[*cond]);
            let (cond_expr, mut latch_stmts) =
                extract_cond_and_strip(&lf.blocks[*cond], cond_stmts);
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
        Region::Switch { dispatch, arms, .. } => {
            // Lower the dispatch block as the prefix; the last
            // instruction is the indirect jump itself which we replace
            // with the structured `switch` statement. v0 emits each
            // arm with its case index (positional) and an implicit
            // break at the end.
            let mut prefix = lower_block(&lf.blocks[*dispatch]);
            // The switch statement IS the dispatch, so its terminator must not
            // also appear inside it. `IndirectGoto` belongs in this list for the
            // same reason `Goto` does; while the indirect jump lifted to a call
            // it was neither, so the dispatch survived as a phantom call
            // statement *within* the recovered switch.
            let mut discriminant = None;
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
            let cases: Vec<(Option<i64>, Vec<Stmt>)> = arms
                .iter()
                .enumerate()
                .map(|(i, arm)| (Some(i as i64), lower_region(arm, lf, targets)))
                .collect();
            // The switched value, recovered from the dispatch's own target
            // expression: the table read indexes by exactly the value the
            // source switched on. The placeholder this replaces
            // (`dispatch_<va>`) named nothing and rendered as an undeclared
            // variable, so the recovered switch read as `switch (var6)` with
            // `var6` defined nowhere. Falls back to the placeholder when the
            // index is not recognisable, rather than inventing one.
            let discriminant = discriminant.or_else(|| {
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
                default: None,
            });
            prefix
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
        Region::Switch { arms, .. } => arms.iter().for_each(|a| collect_goto_targets(a, lf, out)),
        Region::Block(_) | Region::Unstructured(_) => {}
    }
}

/// Lower an entire function given its region tree.
pub fn lower(lf: &LlirFunction, region: &Region, name: impl Into<String>) -> Function {
    let mut targets = std::collections::HashSet::new();
    collect_goto_targets(region, lf, &mut targets);
    let mut f = Function {
        name: name.into(),
        entry_va: lf.entry_va,
        body: lower_region(region, lf, &targets),
    };
    fold_returns(&mut f.body);
    f
}

/// After [`fold_returns`] has collapsed adjacent `ret = E; return;` pairs, any
/// remaining `Return { value: None }` is a return sited in a different block
/// from where its value was computed — ubiquitous in `-O0` goto-heavy code
/// (comparison ladders, switch chains). By the ABI the return register holds
/// the result at every return, so when the function actually writes its return
/// register (i.e. it is not void) we spell these `return <ret_reg>` rather than
/// a bare `return;`.
///
/// Applied only in the DecBench C renderer, which always commits to a non-void
/// return type: there a bare return would be emitted as the value-losing
/// `return 0;`, whereas `return ret;` recovers the data dependency Joern/GED and
/// recompilation both need. The faithful register/`render_c` views keep bare
/// `return;` so a genuinely void function is not given an invented value.
fn default_return_to_reg(body: &mut [Stmt]) {
    let Some(ret_reg) = find_written_return_reg(body) else {
        return;
    };
    apply_default_return(body, &ret_reg);
}

/// Whether the body contains any `Return { value: None }` (including nested).
fn body_has_bare_return(body: &[Stmt]) -> bool {
    body.iter().any(|s| match s {
        Stmt::Return { value } => value.is_none(),
        Stmt::If {
            then_body,
            else_body,
            ..
        } => {
            body_has_bare_return(then_body)
                || else_body.as_deref().is_some_and(body_has_bare_return)
        }
        Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => body_has_bare_return(body),
        Stmt::For { body, .. } => body_has_bare_return(body),
        Stmt::Switch { cases, default, .. } => {
            cases.iter().any(|(_, b)| body_has_bare_return(b))
                || default.as_deref().is_some_and(body_has_bare_return)
        }
        _ => false,
    })
}

/// The first return register the body assigns, or `None` for a void function.
/// Recognises both raw ABI names and the post-naming `ret` alias.
fn find_written_return_reg(body: &[Stmt]) -> Option<VReg> {
    for s in body {
        let found = match s {
            Stmt::Assign { dst, .. }
                if is_return_reg(dst) || matches!(dst, VReg::Phys(n) if n == "ret") =>
            {
                Some(dst.clone())
            }
            // A CALL writes the return register too. Looking only at `Assign`
            // meant a function whose value comes straight from a callee —
            // `return sum_arg6(a0, …)` — found no writer and kept its bare
            // `return`, which renders `return 0;`. The call was right and the
            // result was thrown away one statement later.
            Stmt::Call { dst: Some(d), .. }
                if is_return_reg(d) || matches!(d, VReg::Phys(n) if n == "ret") =>
            {
                Some(d.clone())
            }
            Stmt::If {
                then_body,
                else_body,
                ..
            } => find_written_return_reg(then_body)
                .or_else(|| else_body.as_deref().and_then(find_written_return_reg)),
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => find_written_return_reg(body),
            Stmt::For { body, .. } => find_written_return_reg(body),
            Stmt::Switch { cases, default, .. } => cases
                .iter()
                .find_map(|(_, b)| find_written_return_reg(b))
                .or_else(|| default.as_deref().and_then(find_written_return_reg)),
            _ => None,
        };
        if found.is_some() {
            return found;
        }
    }
    None
}

fn apply_default_return(body: &mut [Stmt], ret_reg: &VReg) {
    for s in body.iter_mut() {
        match s {
            Stmt::Return { value } if value.is_none() => {
                *value = Some(Expr::Reg(ret_reg.clone()));
            }
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                apply_default_return(then_body, ret_reg);
                if let Some(eb) = else_body {
                    apply_default_return(eb, ret_reg);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
                apply_default_return(body, ret_reg)
            }
            Stmt::For { body, .. } => apply_default_return(body, ret_reg),
            Stmt::Switch { cases, default, .. } => {
                for (_, b) in cases.iter_mut() {
                    apply_default_return(b, ret_reg);
                }
                if let Some(b) = default {
                    apply_default_return(b, ret_reg);
                }
            }
            _ => {}
        }
    }
}

/// Common return registers across the ISAs we currently lift. We use a list
/// rather than a single name so this pass works on both x86/x86-64 and
/// AArch64 without having to thread arch info through the AST.
const RETURN_REGS: &[&str] = &[
    "rax", "eax", "ax", "al", // x86 / x86-64
    "x0", "w0", // AArch64
    "r0", // ARM32 AAPCS
];

fn is_return_reg(v: &VReg) -> bool {
    matches!(v, VReg::Phys(n) if RETURN_REGS.iter().any(|r| n == *r))
}

/// Whether `name` is a stack slot the promotion pass named — i.e. a real local
/// variable, so a store *to* it is a plain assignment rather than a pointer
/// write.
fn is_promoted_local(name: &str) -> bool {
    name.starts_with("local_") || name.starts_with("stack_")
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
        BinOp::Div => "/",
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
            | Stmt::Switch { .. } => break,
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
                let _ = write!(out, "-0x{:x}", c.unsigned_abs());
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
        Stmt::Call { target, args, dst } => {
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
    if prefer_increment && write_unit_step(dst, src, out, write_reg_c) {
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
//   * spelling calls as `callee(args)` (implicit-declaration, a warning only)
//     or `((long (*)())(target))(args)` for indirect targets, and
//   * turning constructs with no faithful C spelling — unmodelled instructions,
//     pushes/pops, nops — into comments or elisions rather than invalid tokens.
// Types are intentionally uniform `long` (ABI word width); real type recovery
// is a separate, later effort. See `docs/analysis/decompiler/pipeline.md`.

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
    match hint {
        TypeHint::Int { signed, width } => match (signed, width) {
            (true, 1) => "signed char",
            (false, 1) => "unsigned char",
            (true, 2) => "short",
            (false, 2) => "unsigned short",
            (true, 4) => "int",
            (false, 4) => "unsigned int",
            (false, 8) => "unsigned long",
            _ => "long",
        },
        TypeHint::Pointer { pointee_width } => match pointee_width {
            1 => "char *",
            2 => "short *",
            4 => "int *",
            8 => "long *",
            _ => "void *",
        },
        // A value only ever compared against zero: bool-ish, but recompiles and
        // matches most reliably as `int`.
        TypeHint::BoolLike => "int",
        TypeHint::CodePointer => "void *",
    }
}

/// The C type for an identifier: its recovered hint if the (already remapped)
/// TypeMap has one, else the safe `long` default. We never *guess* a narrower
/// type without a signal — an unknown value stays `long`.
fn ctype_for(ident: &str, tm: Option<&TypeMap>) -> &'static str {
    tm.and_then(|m| m.get(&VReg::Phys(ident.to_string())))
        .map(hint_to_ctype)
        .unwrap_or("long")
}

/// The `(signed, byte-width)` an identifier is actually **declared** with in the
/// DecBench render, or `None` when it is not an integer.
///
/// This is the one rule, shared with the declaration printer and with
/// [`crate::ir::widen`]: only arguments and promoted stack slots take a recovered
/// type. A raw machine register that survives as a local (`ret`, `varN`, temps)
/// is declared `long` no matter what type recovery inferred for it. A second copy
/// of that rule would let the widening pass insert a cast that *truncates* a value
/// the printer had declared 64 bits wide.
pub(crate) fn declared_int_type(ident: &str, tm: Option<&TypeMap>) -> Option<(bool, u8)> {
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
        // A bare integer literal return (`return 0;`) — most often a function
        // whose real return value was lost to structuring — is an `int`. Only
        // claim this on the typed render path; the untyped path (`tm` is None)
        // stays blanket-`long` by contract.
        Expr::Const(_) if tm.is_some() => Some("int"),
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
fn infer_return_ctype(body: &[Stmt], tm: Option<&TypeMap>) -> &'static str {
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
        "int" | "unsigned int" => 4,
        _ => 8,
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
            // A bare return with no recoverable return register renders as the
            // synthesized `return 0;` — an `int`, not the `long` default (only on
            // the typed path; the untyped path keeps blanket-`long`).
            Stmt::Return { value: None } if tm.is_some() => return Some("int"),
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
fn coalesce_param_spills(body: &mut Vec<Stmt>) {
    // local name -> the single argument it is spilled from ("" = disqualified).
    let mut home: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    collect_param_homes(body, &mut home);
    let map: std::collections::HashMap<String, String> = home
        .into_iter()
        .filter(|(_, arg)| !arg.is_empty())
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
                *s = Stmt::Assign {
                    dst: VReg::phys(name.clone()),
                    src: src.clone(),
                };
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

/// Populate `home[local] = arg` for promoted locals whose only register-sourced
/// store is `Store { local, Reg(argN) }`. A local spilled from two different
/// args, or also stored from another register, is disqualified (value "").
fn collect_param_homes(body: &[Stmt], home: &mut std::collections::HashMap<String, String>) {
    for s in body {
        match s {
            Stmt::Store {
                addr: Expr::Reg(VReg::Phys(local)),
                src: Expr::Reg(VReg::Phys(src)),
                ..
            } if is_promoted_local(local) => {
                let arg_ok = parse_arg_index(src).is_some();
                let entry = home.entry(local.clone());
                match entry {
                    std::collections::hash_map::Entry::Vacant(v) => {
                        v.insert(if arg_ok { src.clone() } else { String::new() });
                    }
                    std::collections::hash_map::Entry::Occupied(mut o) => {
                        // A second register store to this slot: only OK if it is
                        // the same arg; otherwise disqualify.
                        if !(arg_ok && o.get() == src) {
                            o.insert(String::new());
                        }
                    }
                }
            }
            // A store to a promoted local from a NON-register expression is a
            // real reassignment of the parameter (`n = n - 1`) — allowed, it does
            // not disqualify the home. Recurse into nested bodies.
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                collect_param_homes(then_body, home);
                if let Some(eb) = else_body {
                    collect_param_homes(eb, home);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
                collect_param_homes(body, home)
            }
            Stmt::For {
                init, step, body, ..
            } => {
                collect_param_homes(std::slice::from_ref(init.as_ref()), home);
                collect_param_homes(body, home);
                collect_param_homes(std::slice::from_ref(step.as_ref()), home);
            }
            Stmt::Switch { cases, default, .. } => {
                for (_, b) in cases {
                    collect_param_homes(b, home);
                }
                if let Some(b) = default {
                    collect_param_homes(b, home);
                }
            }
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
            Expr::Const(_)
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
/// These seven steps change *definitions, uses, value identities, or control-flow
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
/// 3. `copy_prop::propagate_copies` folds the short-lived reload and
///    condition-setup copy chains that otherwise inflate the emitted CFG.
/// 4. `select_fold::collapse_assignment_diamonds` turns a proven two-arm,
///    same-destination terminal return-value diamond into one pure select expression.
/// 5. `loop_form::recover_head_tested_whiles` turns the conservative constant-bound
///    countdown `while (1) { if (exit) break; body }` into
///    `while (!exit) { body }` only when folding has made the exit guard first.
/// 6. `switch_ladder::recover_switches` converts proven comparison ladders into
///    `switch` nodes.
/// 7. `loop_form::promote_for_loops` combines an adjacent initializer, exact head
///    guard, and unconditional same-variable unit increment into a `for` node.
///
/// They used to run *inside* `render_decbench_typed`, which made that renderer
/// impure: the AST that was checked or dumped was not the AST that was printed,
/// so def-before-use verification against it produced false positives on correct
/// functions and had to be reverted. Running them here, as a named pass whose
/// output is the thing rendered, makes the emitted C verifiable — see
/// [`crate::ir::verify_defs`].
pub fn prepare_for_decbench(f: &Function) -> Function {
    let mut owned = f.clone();
    default_return_to_reg(&mut owned.body);
    coalesce_param_spills(&mut owned.body);
    crate::ir::copy_prop::propagate_copies(&mut owned);
    crate::ir::select_fold::collapse_assignment_diamonds(&mut owned);
    crate::ir::loop_form::recover_head_tested_whiles(&mut owned);
    // Before rendering and before widening (which already understands `Switch`):
    // a gcc -O0 comparison ladder is a `switch`, not a nest of `if`s and `goto`s.
    crate::ir::switch_ladder::recover_switches(&mut owned);
    crate::ir::loop_form::promote_for_loops(&mut owned);
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
    let mut ids = DecIdents::default();
    for s in &f.body {
        collect_idents_stmt(s, &mut ids);
    }

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

    let mut out = String::new();
    // Provenance as a C comment (valid, and the harness maps by address anyway).
    let _ = writeln!(out, "// glaurung: {} @ 0x{:x}", f.name, f.entry_va);

    // Record every name declared as a pointer (arguments + promoted pointer
    // locals) with its pointee width, so the array-index render can rewrite
    // `*(T*)(base + i*sizeof(T))` as `base[i]` for those bases.
    DEC_PTRS.with(|m| m.borrow_mut().clear());
    DEC_INT_WIDTHS.with(|m| m.borrow_mut().clear());
    if let Some(tm) = tm {
        for (v, hint) in tm.iter() {
            if let (VReg::Phys(n), TypeHint::Pointer { pointee_width }) = (v, hint) {
                if parse_arg_index(n).is_some() || is_promoted_local(n) {
                    DEC_PTRS.with(|m| m.borrow_mut().insert(n.clone(), *pointee_width));
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

    // Signature: recovered return + argument types. Record which arguments are
    // pointers so the body can cast their int↔pointer reuse (see DEC_PTR_ARGS).
    DEC_PTR_ARGS.with(|m| m.borrow_mut().clear());
    out.push_str(infer_return_ctype(&f.body, tm));
    out.push(' ');
    out.push_str(&name);
    out.push('(');
    if arg_count == 0 {
        out.push_str("void");
    } else {
        for i in 0..arg_count {
            if i > 0 {
                out.push_str(", ");
            }
            let aname = format!("arg{}", i);
            let aty = ctype_for(&aname, tm);
            if aty.ends_with('*') {
                DEC_PTR_ARGS.with(|m| m.borrow_mut().insert(aname.clone(), aty));
            }
            let _ = write!(out, "{} arg{}", aty, i);
        }
    }
    out.push_str(") {\n");

    // Local declarations. Only *promoted stack slots* (`local_c`, `stack_1`)
    // take a recovered type — those are genuine C variables and their recovered
    // width is a clean scalar. Raw machine registers that survive as locals
    // (`rsp`, `rbp`, `varN`, temps, flags) stay `long`: type recovery may tag
    // them as pointers, but they participate in bitwise/address arithmetic
    // (`rsp & -16`, `rbp + ret`) that is a hard error on a pointer-typed operand
    // in C. Keeping them `long` preserves parseability.
    for local in &ids.locals {
        let ty = if is_promoted_local(local) {
            ctype_for(local, tm)
        } else {
            "long"
        };
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
    out
}

/// Identifiers and control-flow anchors gathered from a function body so the
/// DecBench renderer can declare every local and reconcile goto/label pairs.
#[derive(Default)]
struct DecIdents {
    /// Highest `argN` index seen (drives the synthesised signature arity).
    max_arg: Option<usize>,
    /// Every non-argument identifier that will appear in the body, as the exact
    /// (sanitised) spelling the writer emits. `BTreeSet` for stable output.
    locals: std::collections::BTreeSet<String>,
    /// VAs that appear as `Stmt::Label` (defined labels).
    labels: std::collections::BTreeSet<u64>,
    /// VAs that appear as `Stmt::Goto` targets (used labels).
    gotos: std::collections::BTreeSet<u64>,
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
    rest.parse().ok()
}

/// The C-identifier spelling for a processor flag (`Flag::Z` -> `zf`).
fn flag_ident(fl: &Flag) -> &'static str {
    match fl {
        Flag::Z => "zf",
        Flag::C => "cf",
        Flag::Ule => "ule",
        Flag::S => "sf",
        Flag::Slt => "slt",
        Flag::Sle => "sle",
        Flag::O => "of",
        Flag::P => "pf",
        Flag::A => "af",
        // internal one-bit predicate for flag-preserving ISA branches (adr0302)
        Flag::Bit => "bitpred",
    }
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
            sanitize_c_ident(n)
        }
        VReg::Temp(i) => format!("t{}", i),
        VReg::Flag(fl) => flag_ident(fl).to_string(),
    };
    ids.locals.insert(spelling);
}

fn collect_idents_expr(e: &Expr, ids: &mut DecIdents) {
    match e {
        Expr::Reg(v) => collect_reg(v, ids),
        // `Named` in a value position renders as a bare VA constant, and in a
        // call-target position as an (implicitly-declared) function name; either
        // way it is not a declared local, so nothing to collect here.
        Expr::Const(_)
        | Expr::Addr(_)
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::Unknown(_) => {}
        Expr::Lea { base, index, .. } | Expr::PdbFieldAddr { base, index, .. } => {
            if let Some(b) = base {
                collect_reg(b, ids);
            }
            if let Some(i) = index {
                collect_reg(i, ids);
            }
        }
        Expr::Deref { addr, .. } => collect_idents_expr(addr, ids),
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
    }
}

fn collect_idents_stmt(s: &Stmt, ids: &mut DecIdents) {
    match s {
        Stmt::Assign { dst, src } => {
            collect_reg(dst, ids);
            collect_idents_expr(src, ids);
        }
        Stmt::Store { addr, src, .. } => {
            collect_idents_expr(addr, ids);
            collect_idents_expr(src, ids);
        }
        Stmt::Call { target, args, dst } => {
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
        }
        Stmt::IndirectGoto { target } => collect_idents_expr(target, ids),
        // Push/Pop/Nop are elided by the renderer; Unknown/Comment become
        // comments; none introduce a declared identifier.
        Stmt::Push { .. }
        | Stmt::Pop { .. }
        | Stmt::Break
        | Stmt::Nop
        | Stmt::Unknown(_)
        | Stmt::Comment(_) => {}
    }
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
    static DEC_PTR_ARGS: std::cell::RefCell<std::collections::HashMap<String, &'static str>> =
        std::cell::RefCell::new(std::collections::HashMap::new());

    /// Names that are *declared as pointers* in the current render (arguments and
    /// promoted pointer locals) → their pointee width in bytes. Consulted by the
    /// array-index render to rewrite `*(T*)(base + i*sizeof(T))` as `base[i]`.
    /// Only declared pointers appear here, so `base[i]` is always valid C.
    static DEC_PTRS: std::cell::RefCell<std::collections::HashMap<String, u8>> =
        std::cell::RefCell::new(std::collections::HashMap::new());

    /// Integer-typed names in the current render (arguments and promoted scalar
    /// locals) → their declared byte width. Consulted by the logical-shift render
    /// so `(unsigned)x >> k` on a 32-bit operand casts to `unsigned int` rather
    /// than a blanket `unsigned long`: a blanket 64-bit cast sign-extends a
    /// negative narrow value into the high half before the zero-filling shift,
    /// producing a different result than the original narrow shift.
    static DEC_INT_WIDTHS: std::cell::RefCell<std::collections::HashMap<String, u8>> =
        std::cell::RefCell::new(std::collections::HashMap::new());
}

fn dec_ptr_arg_type(name: &str) -> Option<&'static str> {
    DEC_PTR_ARGS.with(|m| m.borrow().get(name).copied())
}

/// The pointee width of `name` if it is declared as a pointer in this render.
fn dec_ptr_width(name: &str) -> Option<u8> {
    DEC_PTRS.with(|m| m.borrow().get(name).copied())
}

/// The declared integer byte-width of `name` if it is an integer-typed
/// argument/local in this render (see `DEC_INT_WIDTHS`).
fn dec_int_width(name: &str) -> Option<u8> {
    DEC_INT_WIDTHS.with(|m| m.borrow().get(name).copied())
}

/// The C spelling of an `size`-byte *unsigned* integer, for logical-shift casts.
fn unsigned_ctype(size: u8) -> &'static str {
    match size {
        1 => "unsigned char",
        2 => "unsigned short",
        4 => "unsigned int",
        _ => "unsigned long",
    }
}

/// The unsigned-cast width for a logical right shift `lhs >> rhs`. The shift
/// must happen at the operand's machine width so a negative narrow value is not
/// sign-extended into the high half before the zero-fill. Narrowing is applied
/// only when (a) the operand's width is positively known from narrow-typed
/// identifiers, and (b) the shift amount is a constant that fits inside that
/// width — a `>> 32` on a value that is genuinely 64-bit (e.g. `mul_widen`'s
/// `(uint64_t)a*b`) must keep `unsigned long`. Everything else falls back to
/// `unsigned long`, correct for genuine 64-bit values.
fn shift_operand_ctype(lhs: &Expr, rhs: &Expr) -> &'static str {
    if let (Some(w), Expr::Const(k)) = (expr_machine_width(lhs), rhs) {
        if *k >= 0 && (*k as u64) < (w as u64) * 8 {
            return unsigned_ctype(w);
        }
    }
    "unsigned long"
}

/// The machine byte-width of an integer expression, when it can be established
/// from narrow-typed identifiers. Single identifiers read their declared width
/// from `DEC_INT_WIDTHS`; width-preserving arithmetic (`a - b`, `a & b`, ...)
/// takes the wider operand, treating a bare constant as width-agnostic. Any
/// operand of unknown width (a load, an untyped local) yields `None`, so the
/// shift render conservatively keeps `unsigned long`.
fn expr_machine_width(e: &Expr) -> Option<u8> {
    match e {
        Expr::Named { name, .. } => dec_int_width(name),
        Expr::Reg(VReg::Phys(n)) => dec_int_width(n),
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
        return Some(off);
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

/// Render a register in **rvalue** position. A pointer-typed argument is cast to
/// `long` here: our byte-offset arithmetic treats it as an integer address, and
/// leaving it a pointer would be an invalid operand for `&`/`*`/`-`/pointer±pointer.
fn write_reg_dec(v: &VReg, out: &mut String) {
    if let VReg::Phys(n) = v {
        if dec_ptr_arg_type(n).is_some() {
            out.push_str("(long)");
            out.push_str(n);
            return;
        }
    }
    write_reg_lvalue_dec(v, out);
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
    } else if c < 0 {
        let _ = write!(out, "-0x{:x}", c.unsigned_abs());
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

fn write_expr_dec(e: &Expr, out: &mut String) {
    match e {
        Expr::Reg(v) => write_reg_dec(v, out),
        Expr::Const(c) => write_const_dec(*c, out),
        Expr::Addr(a) => {
            let _ = write!(out, "0x{:x}", a);
        }
        // In a value position a resolved symbol becomes its address constant;
        // the readable name is kept only where it is *called* (see write_call_dec).
        Expr::Named { va, .. } => {
            let _ = write!(out, "0x{:x}", va);
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
            // Array-index idiom: a `T`-sized read through `base + i*sizeof(T)`
            // where `base` is a declared `T *` renders as `base[i]`. This drops
            // the `(long)` cast + explicit scale, so the compiler re-emits its own
            // scaled-addressing (`lea (%rax,%rdx,4)`) instead of our `shl`+`add`.
            if let Some((base, index)) = try_array_index(addr, *size) {
                out.push_str(base);
                out.push('[');
                write_expr_dec(index, out);
                out.push(']');
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
                write_expr_dec(lhs, out);
                let _ = write!(out, " {} ", binop_sym_c(shown_op));
                write_expr_dec(&shown_rhs, out);
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
            let _ = write!(out, "({})(", int_ctype(*signed, *width));
            write_expr_dec(expr, out);
            out.push(')');
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
                write_expr_dec(lhs, out);
                let _ = write!(out, " {} ", cmpop_sym_c(*op));
                write_expr_dec(rhs, out);
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
        // An unmodelled/indirect value: a call to an undeclared `__unknown`
        // (implicit-declaration warning only) keeps it a valid `long` rvalue.
        Expr::Unknown(_) => out.push_str("__unknown(0)"),
    }
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

/// Render a call: `callee(args)` for a resolved symbol (implicit declaration,
/// a warning only), else `((long (*)())(target))(args)` so an indirect target
/// through a `long`-typed value is a valid call rather than "called object is
/// not a function".
/// The name to call a PLT/IAT stub by: the function it forwards to.
///
/// The address map records a stub as `foo@plt` because that is what it IS, and
/// that spelling is right for an import listing or an xref view. In a call
/// EXPRESSION it is wrong: the source called `foo`, `foo@plt` sanitises to the
/// undeclared identifier `foo_plt`, and nothing in the program defines it.
fn callee_display_name(name: &str) -> &str {
    name.split_once('@').map_or(name, |(base, _)| base)
}

fn write_call_dec(target: &Expr, args: &[Expr], out: &mut String) {
    match target {
        Expr::Named { name, .. } => out.push_str(&sanitize_c_ident(callee_display_name(name))),
        _ => {
            out.push_str("((long (*)())(");
            write_expr_dec(target, out);
            out.push_str("))");
        }
    }
    out.push('(');
    for (i, a) in args.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        write_expr_dec(a, out);
    }
    out.push(')');
}

fn write_assign_dec(dst: &VReg, src: &Expr, out: &mut String) {
    write_reg_lvalue_dec(dst, out);
    out.push_str(" = ");
    // Reassigning a scratch integer into a pointer-typed arg register: cast the
    // RHS to the pointer type so int-to-pointer conversion remains explicit.
    if let VReg::Phys(name) = dst {
        if let Some(pointer_type) = dec_ptr_arg_type(name) {
            let _ = write!(out, "({})(", pointer_type);
            write_expr_dec(src, out);
            out.push(')');
            return;
        }
    }
    write_expr_dec(src, out);
}

fn write_stmt_dec(s: &Stmt, out: &mut String, level: usize) {
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
                    write_expr_dec(cond, out);
                    out.push_str(") {\n");
                    indent(out, level + 1);
                    write_assign_dec(dst, if_true, out);
                    out.push_str(";\n");
                    indent(out, level);
                    out.push_str("} else {\n");
                    indent(out, level + 1);
                    write_assign_dec(dst, if_false, out);
                    out.push_str(";\n");
                    indent(out, level);
                    out.push_str("}\n");
                    return;
                }
            }
            if let Some((cond, init, update, inverted)) = one_armed_select(dst, src) {
                indent(out, level);
                write_assign_dec(dst, init, out);
                out.push_str(";\n");
                indent(out, level);
                out.push_str(if inverted { "if (!(" } else { "if (" });
                write_expr_dec(cond, out);
                out.push_str(if inverted { ")) {\n" } else { ") {\n" });
                indent(out, level + 1);
                write_assign_dec(dst, update, out);
                out.push_str(";\n");
                indent(out, level);
                out.push_str("}\n");
                return;
            }
            indent(out, level);
            write_assign_dec(dst, src, out);
            out.push_str(";\n");
        }
        Stmt::Store { addr, src, size } => {
            indent(out, level);
            // A store whose address is a bare promoted stack local (`local_0`,
            // `stack_1`, …) is a plain variable assignment, not a pointer
            // write: emit `local_0 = src` rather than `*(long *)(local_0) = src`.
            if let Expr::Reg(VReg::Phys(name)) = addr {
                if is_promoted_local(name) {
                    write_expr_dec(addr, out);
                    out.push_str(" = ");
                    write_expr_dec(src, out);
                    out.push_str(";\n");
                    return;
                }
            }
            // Use the access width so a 4-byte store emits `*(int *)`, not a
            // blanket `*(long *)` that would clobber the adjacent element.
            let _ = write!(out, "*({} *)(", store_pointee_ctype(*size));
            write_expr_dec(addr, out);
            out.push_str(") = ");
            write_expr_dec(src, out);
            out.push_str(";\n");
        }
        Stmt::Call { target, args, dst } => {
            indent(out, level);
            // A call's result must land somewhere: dropping it emitted
            // `f(x);` and then read the ARGUMENT where the return value belonged.
            if let Some(VReg::Phys(n)) = dst {
                let _ = write!(out, "{} = ", sanitize_c_ident(n));
            }
            write_call_dec(target, args, out);
            out.push_str(";\n");
        }
        Stmt::Return { value } => {
            indent(out, level);
            match value {
                Some(e) => {
                    out.push_str("return ");
                    write_expr_dec(e, out);
                    out.push_str(";\n");
                }
                None => out.push_str("return 0;\n"),
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
            // the explicit default into a single `default:` block.
            let mut seen: std::collections::HashSet<i64> = std::collections::HashSet::new();
            let mut default_arms: Vec<&Vec<Stmt>> = Vec::new();
            for (label, body) in cases {
                match label {
                    Some(n) if seen.insert(*n) => {
                        indent(out, level + 1);
                        let _ = writeln!(out, "case {}:", n);
                        for s in body {
                            write_stmt_dec(s, out, level + 2);
                        }
                        indent(out, level + 2);
                        out.push_str("break;\n");
                    }
                    _ => default_arms.push(body),
                }
            }
            if let Some(def_body) = default {
                default_arms.push(def_body);
            }
            if !default_arms.is_empty() {
                indent(out, level + 1);
                out.push_str("default:\n");
                for body in default_arms {
                    for s in body {
                        write_stmt_dec(s, out, level + 2);
                    }
                }
                indent(out, level + 2);
                out.push_str("break;\n");
            }
            indent(out, level);
            out.push_str("}\n");
        }
    }
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
    if prefer_increment && write_unit_step(dst, src, out, write_reg_lvalue_dec) {
        return;
    }
    write_reg_lvalue_dec(dst, out);
    out.push_str(" = ");
    if let VReg::Phys(name) = dst {
        if let Some(pointer_type) = dec_ptr_arg_type(name) {
            let _ = write!(out, "({})(", pointer_type);
            write_expr_dec(src, out);
            out.push(')');
            return;
        }
    }
    write_expr_dec(src, out);
}

fn write_unit_step(
    dst: &VReg,
    src: &Expr,
    out: &mut String,
    write_reg: fn(&VReg, &mut String),
) -> bool {
    let integer_local = match dst {
        VReg::Temp(_) => true,
        VReg::Phys(name) => name.starts_with("local_") || name.starts_with("stack_"),
        VReg::Flag(_) => false,
    };
    if !integer_local {
        return false;
    }
    let Expr::Bin { op, lhs, rhs } = src else {
        return false;
    };
    if !matches!(lhs.as_ref(), Expr::Reg(read) if read == dst)
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

    // -- the prepare/render boundary -------------------------------------------
    //
    // These characterise the transformation that used to happen while printing.
    // Each asserts the AST ITSELF changes (so the change is verifiable), and that
    // the renderer alone does not make it (so the renderer is formatting-only).

    #[test]
    fn prepare_gives_a_bare_return_the_abi_return_register() {
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
            prepared.body.last(),
            Some(&Stmt::Return {
                value: Some(Expr::Reg(VReg::phys("ret")))
            }),
            "prepare must materialise the ABI return value in the AST"
        );
        // The renderer must not do it on its own.
        assert!(
            !render_decbench(&f).contains("return ret;"),
            "the renderer must not change what is returned"
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

    /// Assertions that must hold for *any* `render_decbench` output: no
    /// register `%` sigils, no `&[...]` address forms, no `<...>` unknowns, a
    /// real `long` signature, and a balanced brace at the end.
    fn assert_looks_like_c(text: &str) {
        assert!(
            !text.contains('%'),
            "decbench output still has % sigils:\n{}",
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

    #[test]
    fn decbench_bare_return_uses_return_register_not_zero() {
        // The value is computed into `ret` in one block, then returned from
        // another (goto-separated) — the adjacent fold can't reach it. The
        // decbench renderer must emit `return ret;`, never the value-losing
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
            text.contains("return ret;"),
            "bare return should use the return register:\n{}",
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
                },
            ],
        };
        let text = dec_pipeline(&f);
        assert!(text.contains("/* asm: cpuid */"), "unknown stmt:\n{}", text);
        // var0 is single-use, so it folds into the indirect call target.
        assert!(
            text.contains("((long (*)())(__unknown(0)))(arg0);"),
            "indirect call:\n{}",
            text
        );
        assert_looks_like_c(&text);
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
        assert!(text.contains("var0 = (arg0 >> 3);"), "sar:\n{}", text);
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
}
