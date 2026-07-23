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
    BinOp, CallTarget, CmpOp, Flag, LlirBlock, LlirFunction, LlirInstr, MemOp, Op, UnOp,
    VReg, Value,
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
        }],
        Op::Jump { target } => vec![Stmt::Goto { target: *target }],
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
        // Width changes render as a plain assignment of the source — the cast is
        // implicit in the higher-level form (`dst = src`).
        Op::ZExt { dst, src, .. } | Op::SExt { dst, src, .. } | Op::Trunc { dst, src, .. } => {
            vec![Stmt::Assign {
                dst: dst.clone(),
                src: lower_value(src),
            }]
        }
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
        // Pure select renders as a full if/else assigning both arms.
        Op::Ite {
            dst, cond, t, e, ..
        } => vec![Stmt::If {
            cond: Expr::Reg(cond.clone()),
            then_body: vec![Stmt::Assign {
                dst: dst.clone(),
                src: lower_value(t),
            }],
            else_body: Some(vec![Stmt::Assign {
                dst: dst.clone(),
                src: lower_value(e),
            }]),
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

/// Peephole pass: for each `Stmt::If { cond: Expr::Reg(flag), .. }` whose
/// flag was assigned by a `Stmt::Assign { dst: flag, src: Expr::Cmp(..) }`
/// earlier in the same block (with no intervening read of the flag),
/// fold the Cmp into the condition and drop the assignment.
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
    let mut out: Vec<Stmt> = Vec::with_capacity(stmts.len());
    for stmt in stmts {
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
        let mut hoisted: Option<Expr> = None;
        // Walk backwards through what we've already emitted, looking
        // for an assignment to `flag` with an Expr::Cmp RHS.
        for i in (0..out.len()).rev() {
            match &out[i] {
                Stmt::Assign { dst, src } if dst == &flag => {
                    if matches!(src, Expr::Cmp { .. }) {
                        // Make sure no intervening stmt reads the flag.
                        let reads: usize = out[i + 1..]
                            .iter()
                            .map(|s| count_reg_uses_in_stmt(s, &flag))
                            .sum();
                        if reads == 0 {
                            if let Stmt::Assign { src, .. } = out.remove(i) {
                                hoisted = Some(src);
                            }
                        }
                    }
                    // Most recent assign found — stop regardless.
                    break;
                }
                other => {
                    if count_reg_uses_in_stmt(other, &flag) > 0 {
                        break;
                    }
                }
            }
        }

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
fn negate_cmp_expr(expr: Expr) -> Expr {
    if let Expr::Cmp { op, lhs, rhs } = expr {
        let inverted = match op {
            CmpOp::Eq => Some(CmpOp::Ne),
            CmpOp::Ne => Some(CmpOp::Eq),
            // The remaining CmpOps don't have direct opposites in this
            // enum (Ult, Ule, Slt, Sle); express the negation via a
            // wrapping Not so the printer still shows the semantics.
            _ => None,
        };
        match inverted {
            Some(new_op) => Expr::Cmp {
                op: new_op,
                lhs,
                rhs,
            },
            None => Expr::Un {
                op: UnOp::Not,
                src: Box::new(Expr::Cmp { op, lhs, rhs }),
            },
        }
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
            if let Expr::Un {
                op: UnOp::Not,
                src,
            } = cond
            {
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
                                let cond_expr = if inverted {
                                    negate_cmp_expr(src)
                                } else {
                                    src
                                };
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
        Stmt::Return { value } => value
            .as_ref()
            .map(|e| count_reg_uses_in_expr(e, target))
            .unwrap_or(0),
        Stmt::Push { value } => count_reg_uses_in_expr(value, target),
        Stmt::Pop { .. }
        | Stmt::Goto { .. }
        | Stmt::Label(_)
        | Stmt::Nop
        | Stmt::Unknown(_)
        | Stmt::Comment(_) => 0,
        Stmt::Switch { discriminant, .. } => count_reg_uses_in_expr(discriminant, target),
    }
}

fn lower_region(r: &Region, lf: &LlirFunction) -> Vec<Stmt> {
    match r {
        Region::Block(bi) => lower_block(&lf.blocks[*bi]),
        Region::Seq(parts) => {
            let mut out = Vec::new();
            for (idx, p) in parts.iter().enumerate() {
                let mut lowered = lower_region(p, lf);
                // Strip a redundant `goto <header>` when the next region is a
                // loop headed at that VA: the `-O0` for-loop's entry jump to its
                // condition block is just the natural fall-in to the `while`, so
                // keeping it would leave a goto to a synthesized empty label.
                if let Some(Region::While { header, .. }) = parts.get(idx + 1) {
                    let hva = lf.blocks[*header].start_va;
                    if matches!(lowered.last(), Some(Stmt::Goto { target }) if *target == hva) {
                        lowered.pop();
                    }
                }
                out.extend(lowered);
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
        Region::Switch { dispatch, arms, .. } => {
            // Lower the dispatch block as the prefix; the last
            // instruction is the indirect jump itself which we replace
            // with the structured `switch` statement. v0 emits each
            // arm with its case index (positional) and an implicit
            // break at the end.
            let mut prefix = lower_block(&lf.blocks[*dispatch]);
            // Drop the trailing Goto/If-Goto if present — the switch
            // statement encodes the dispatch.
            while matches!(
                prefix.last(),
                Some(Stmt::Goto { .. }) | Some(Stmt::If { .. })
            ) {
                prefix.pop();
            }
            let cases: Vec<(Option<i64>, Vec<Stmt>)> = arms
                .iter()
                .enumerate()
                .map(|(i, arm)| (Some(i as i64), lower_region(arm, lf)))
                .collect();
            // Discriminant is a placeholder — recovering the original
            // switched value requires walking the index computation
            // above the dispatch. Filed as a v1 follow-up.
            prefix.push(Stmt::Switch {
                discriminant: Expr::Reg(VReg::Phys(format!(
                    "dispatch_{:x}",
                    lf.blocks[*dispatch].start_va
                ))),
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
        Stmt::While { body, .. } => body_has_bare_return(body),
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
            Stmt::If {
                then_body,
                else_body,
                ..
            } => find_written_return_reg(then_body)
                .or_else(|| else_body.as_deref().and_then(find_written_return_reg)),
            Stmt::While { body, .. } => find_written_return_reg(body),
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
            Stmt::While { body, .. } => apply_default_return(body, ret_reg),
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
            | Stmt::While { .. }
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

/// Untyped entry point (blanket `long`) — used by unit tests and any consumer
/// that has no recovered types.
pub fn render_decbench(f: &Function) -> String {
    render_decbench_typed(f, None)
}

/// Render `f` as parseable C for DecBench, typing the return value and
/// arguments from `tm` (a TypeMap already remapped to the AST's role names —
/// `arg0`, `ret`, …). Locals stay `long` for now (their TypeMap keys do not
/// survive register renaming; a later pass will type stack slots by size).
pub fn render_decbench_typed(f: &Function, tm: Option<&TypeMap>) -> String {
    // Work on a private copy so the cleanups below don't perturb other renders.
    // First give bare returns (value computed in another block) their ABI return
    // register — so this always-non-void renderer emits `return ret;` not the
    // value-losing `return 0;` — then copy-propagate away the short-lived reload
    // and condition-setup temporaries that otherwise inflate the emitted CFG.
    let mut owned = f.clone();
    default_return_to_reg(&mut owned.body);
    crate::ir::copy_prop::propagate_copies(&mut owned);
    let f = &owned;

    let mut ids = DecIdents::default();
    for s in &f.body {
        collect_idents_stmt(s, &mut ids);
    }

    let name = sanitize_c_ident(&f.name);
    let arg_count = ids.max_arg.map(|m| m + 1).unwrap_or(0);

    let mut out = String::new();
    // Provenance as a C comment (valid, and the harness maps by address anyway).
    let _ = writeln!(out, "// glaurung: {} @ 0x{:x}", f.name, f.entry_va);

    // Signature: recovered return + argument types. Record which arguments are
    // pointers so the body can cast their int↔pointer reuse (see DEC_PTR_ARGS).
    DEC_PTR_ARGS.with(|m| m.borrow_mut().clear());
    out.push_str(ctype_for("ret", tm));
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
fn parse_arg_index(name: &str) -> Option<usize> {
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
        Expr::Const(_) | Expr::Addr(_) | Expr::Named { .. } | Expr::StringLit { .. }
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
        Expr::Un { src, .. } => collect_idents_expr(src, ids),
    }
}

fn collect_idents_stmt(s: &Stmt, ids: &mut DecIdents) {
    match s {
        Stmt::Assign { dst, src } => {
            collect_reg(dst, ids);
            collect_idents_expr(src, ids);
        }
        Stmt::Store { addr, src } => {
            collect_idents_expr(addr, ids);
            collect_idents_expr(src, ids);
        }
        Stmt::Call { target, args } => {
            // A `Named` target is a callee name, not a local; other targets are
            // rendered as value expressions and their registers must be declared.
            if !matches!(target, Expr::Named { .. }) {
                collect_idents_expr(target, ids);
            }
            for a in args {
                collect_idents_expr(a, ids);
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
        // Push/Pop/Nop are elided by the renderer; Unknown/Comment become
        // comments; none introduce a declared identifier.
        Stmt::Push { .. } | Stmt::Pop { .. } | Stmt::Nop | Stmt::Unknown(_) | Stmt::Comment(_) => {}
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
}

fn dec_ptr_arg_type(name: &str) -> Option<&'static str> {
    DEC_PTR_ARGS.with(|m| m.borrow().get(name).copied())
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
        Expr::Deref { addr, .. } => {
            out.push_str("*(long *)(");
            write_expr_dec(addr, out);
            out.push(')');
        }
        Expr::Bin { op, lhs, rhs } => {
            // Logical (unsigned) right shift has no direct signed-`long` C form;
            // cast the operand to `unsigned long` so `>>` is the zero-filling
            // shift the IR means. Arithmetic shift (`Sar`) is plain `>>`.
            if matches!(op, BinOp::Shr) {
                out.push_str("((unsigned long)(");
                write_expr_dec(lhs, out);
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
fn write_call_dec(target: &Expr, args: &[Expr], out: &mut String) {
    match target {
        Expr::Named { name, .. } => out.push_str(&sanitize_c_ident(name)),
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

fn write_stmt_dec(s: &Stmt, out: &mut String, level: usize) {
    match s {
        Stmt::Assign { dst, src } => {
            indent(out, level);
            write_reg_lvalue_dec(dst, out);
            out.push_str(" = ");
            // Reassigning a scratch integer into a pointer-typed arg register:
            // cast the RHS to the pointer type so int→pointer is explicit.
            if let VReg::Phys(n) = dst {
                if let Some(pty) = dec_ptr_arg_type(n) {
                    let _ = write!(out, "({})(", pty);
                    write_expr_dec(src, out);
                    out.push_str(");\n");
                    return;
                }
            }
            write_expr_dec(src, out);
            out.push_str(";\n");
        }
        Stmt::Store { addr, src } => {
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
            out.push_str("*(long *)(");
            write_expr_dec(addr, out);
            out.push_str(") = ");
            write_expr_dec(src, out);
            out.push_str(";\n");
        }
        Stmt::Call { target, args } => {
            indent(out, level);
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
        // arg0 flows to a local `var0`, which is returned.
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
                    value: Some(Expr::Reg(VReg::phys("var0"))),
                },
            ],
        };
        let text = render_decbench(&f);
        assert!(
            text.contains("long add_one(long arg0) {"),
            "got:\n{}",
            text
        );
        assert!(text.contains("long var0;"), "missing local decl:\n{}", text);
        assert!(
            text.contains("var0 = (arg0 + 1);"),
            "body wrong:\n{}",
            text
        );
        assert!(text.contains("return var0;"), "return wrong:\n{}", text);
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
                    value: Some(Expr::Reg(VReg::phys("var0"))),
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
        let text = render_decbench_typed(&f, Some(&tm));
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
        let text = render_decbench(&f);
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
                },
            ],
        };
        let text = render_decbench(&f);
        assert!(text.contains("/* asm: cpuid */"), "unknown stmt:\n{}", text);
        assert!(
            text.contains("var0 = __unknown(0);"),
            "unknown expr:\n{}",
            text
        );
        assert!(
            text.contains("((long (*)())(var0))(arg0);"),
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
                    (Some(0), vec![Stmt::Return { value: Some(Expr::Const(1)) }]),
                    // Unlabelled arm -> folded into default.
                    (None, vec![Stmt::Return { value: Some(Expr::Const(2)) }]),
                ],
                default: Some(vec![Stmt::Return { value: Some(Expr::Const(3)) }]),
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
}
