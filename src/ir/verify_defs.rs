//! Definition-before-use verification over the decompiled AST.
//!
//! A decompilation that reads a value it never produced is not "slightly wrong":
//! the emitted C reads an uninitialised variable, so the recompiled function
//! returns garbage. This is the single most common shape of value-model
//! corruption in this pipeline — a pass drops a definition while its uses
//! survive — and it is invisible to type_match / GED / byte_match.
//!
//! WHY IT RUNS HERE, ON THIS AST
//!
//! An earlier attempt checked the AST *before* rendering and had to be reverted:
//! `render_decbench_typed` folded copy chains while printing, so the checked AST
//! was not the AST that was emitted, and correct functions (`rt_u8`) were flagged.
//! That folding is now an explicit pass ([`crate::ir::ast::prepare_for_decbench`])
//! that runs before rendering, and the renderer is formatting-only. So there is a
//! single AST that is exactly what gets printed, and it is the one this module
//! checks.
//!
//! WHAT IS CHECKED
//!
//! Only names the decompiler itself invents and must therefore define:
//! `ret`, `varN`, `local_*`, `stack_*`, lifter temporaries, and versioned
//! predicate values. Parameters
//! (`argN`) are defined by the ABI, and raw machine registers (`rsp`, `rbp`,
//! `rip`, …) are live-in state, so neither is a violation.
//!
//! Two rules, both chosen to have NO false positives:
//!
//! * [`ViolationKind::NeverDefined`] — the name is read but never assigned
//!   anywhere in the function. Control flow cannot rescue this: no path defines
//!   it. Always checked.
//! * [`ViolationKind::UsedBeforeDefinition`] — flow-sensitive, and deliberately
//!   *may*-defined rather than must-defined: a name defined in only one arm of an
//!   `if` counts as defined at the join, and a loop body is checked with its own
//!   definitions pre-seeded (a later iteration may have produced the value). Only
//!   attempted for structured bodies; a function containing `goto`/labels has
//!   flow this walk does not model, so the rule is skipped there rather than
//!   guessed at.

use std::collections::BTreeSet;

use crate::ir::ast::{Expr, Function, Stmt};
use crate::ir::types::VReg;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ViolationKind {
    /// Read somewhere, assigned nowhere in the function.
    NeverDefined,
    /// Read on a path that reaches no definition of it.
    UsedBeforeDefinition,
    /// A read reaches an explicit poison definition (for example an
    /// architecturally undefined x86 flag), rather than a concrete value.
    UndefinedValue,
    /// A frame-pointer register the emitted C declares as a local and never assigns.
    /// Reading it is an uninitialised read in the printed C whatever it means on the
    /// machine — and when the value is used as an ADDRESS, dereferencing it is how a
    /// decompilation comes to segfault rather than merely return the wrong number.
    UninitialisedFramePointer,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Violation {
    pub name: String,
    pub kind: ViolationKind,
}

impl std::fmt::Display for Violation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.kind {
            ViolationKind::NeverDefined => write!(f, "{} is read but never defined", self.name),
            ViolationKind::UsedBeforeDefinition => {
                write!(f, "{} is read before it is defined", self.name)
            }
            ViolationKind::UndefinedValue => {
                write!(f, "{} reads an explicitly undefined value", self.name)
            }
            ViolationKind::UninitialisedFramePointer => write!(
                f,
                "{} is declared as a local and never assigned, so reading it (and any \
                 address computed from it) is an uninitialised read",
                self.name
            ),
        }
    }
}

/// Insert each violation as a `// glaurung-verify:` line AFTER the
/// `// glaurung: <name> @ <va>` header that `body` begins with, never before it.
///
/// Every consumer splits multi-function output on that header (the structural
/// lane, the CLI's `--all` and multi-`--vas` renders), so a comment placed ahead
/// of the header binds to the PREVIOUS function — which is how the first version of
/// this reporting misfiled every violation by one function. Returns `body`
/// unchanged when there is nothing to report.
pub fn splice_verify_comments(body: &str, violations: &[Violation]) -> String {
    if violations.is_empty() {
        return body.to_string();
    }
    let mut lines = body.splitn(2, '\n');
    let header = lines.next().unwrap_or("");
    let rest = lines.next();
    let mut out = String::with_capacity(body.len() + 64 * violations.len());
    out.push_str(header);
    out.push('\n');
    for v in violations {
        out.push_str(&format!("// glaurung-verify: {v}\n"));
    }
    if let Some(rest) = rest {
        out.push_str(rest);
    }
    out
}

/// A machine register that the emitted C DECLARES as a local.
///
/// The renderer declares every non-argument identifier appearing in the body
/// (`DecIdents::locals`), so a surviving `rbp` is printed as `long rbp;`. On the
/// machine `rbp` is live-in state; in the emitted C it is an uninitialised variable,
/// and `rbp - 32` is therefore a read of garbage. Both facts are true, and only the
/// second one decides whether the recompiled function works.
///
/// That distinction is why two fixture cells emit C that SEGFAULTS —
/// `cpp_ctor_dtor` passes `rbp - 32` as a `this` pointer, `cpp_virtual_dispatch`
/// dereferences a vtable pointer nothing assigns — while this checker stayed silent:
/// it excluded machine registers as "live-in", which is a statement about the
/// machine, not about the C we printed.
///
/// `rsp` and `rip` are deliberately still excluded. A frame-pointer value used as an
/// ADDRESS is a real uninitialised read; a stack pointer appearing in prologue
/// arithmetic the renderer keeps for readability is not the same claim, and widening
/// this to every register would trade a precise finding for noise.
fn declared_machine_register(v: &VReg) -> Option<String> {
    match v {
        VReg::Phys(n) if matches!(n.as_str(), "rbp" | "ebp" | "bp" | "x29" | "w29" | "fp") => {
            Some(n.clone())
        }
        _ => None,
    }
}

/// The name of a value the decompiler invents and is therefore responsible for
/// defining, or `None` for parameters, machine registers, and unversioned
/// architectural flag names (which exist only before SSA value numbering).
fn checked_name(v: &VReg) -> Option<String> {
    match v {
        VReg::Phys(n) => {
            let invented = n == "ret"
                || n.starts_with("local_")
                || n.starts_with("stack_")
                || (n.starts_with("var")
                    && n[3..].chars().all(|c| c.is_ascii_digit())
                    && n.len() > 3);
            invented.then(|| n.clone())
        }
        // A lifter temporary that survives into the emitted AST must have been
        // assigned there too.
        VReg::Temp(i) => Some(format!("t{i}")),
        VReg::Flag(_) => None,
        VReg::FlagValue { .. } => v.predicate_ident(),
    }
}

/// The ABI return-register role name: a `call` defines it (the callee's return
/// value lands there), so `foo(); return ret;` is not a use before definition.
const RETURN_ROLE: &str = "ret";

/// A store whose address is a bare promoted stack slot (`local_4`, `stack_0`) is a
/// DEFINITION of that slot, not a pointer store through it: the renderer prints it
/// as `local_4 = ...` (see `write_stmt_dec`'s `is_promoted_local` arm). Reading it
/// as a use of the address instead is how a first version of this checker managed
/// to flag half the corpus — including functions whose decompilation executes
/// correctly. The name must be a promoted slot: after parameter coalescing the
/// address can be an `argN`, and `*arg0 = x` really is a store through a pointer.
fn stored_slot(addr: &Expr) -> Option<String> {
    match addr {
        Expr::Reg(VReg::Phys(n)) if n.starts_with("local_") || n.starts_with("stack_") => {
            Some(n.clone())
        }
        _ => None,
    }
}

fn reads_expr(e: &Expr, out: &mut Vec<String>) {
    match e {
        Expr::Reg(v) => out.extend(checked_name(v)),
        Expr::Const(_)
        | Expr::FloatConst { .. }
        | Expr::Addr(_)
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        // Taking a local object's address is legal before its scalar contents
        // have been initialised; the callee may be the operation that writes it.
        | Expr::StackAddr { .. }
        | Expr::Unknown(_) => {}
        Expr::Lea { base, index, .. } | Expr::PdbFieldAddr { base, index, .. } => {
            out.extend(base.as_ref().and_then(checked_name));
            out.extend(index.as_ref().and_then(checked_name));
        }
        Expr::Deref { addr, .. } => reads_expr(addr, out),
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            reads_expr(lhs, out);
            reads_expr(rhs, out);
        }
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => {
            reads_expr(cond, out);
            reads_expr(if_true, out);
            reads_expr(if_false, out);
        }
        Expr::Un { src, .. } => reads_expr(src, out),
        Expr::Cast { expr, .. } => reads_expr(expr, out),
    }
}

fn reads_of(e: &Expr) -> Vec<String> {
    let mut v = Vec::new();
    reads_expr(e, &mut v);
    v
}

/// Every name defined anywhere in `body`, including nested bodies.
fn defs_in(body: &[Stmt], out: &mut BTreeSet<String>) {
    for s in body {
        match s {
            Stmt::Assign { dst, .. } => out.extend(checked_name(dst)),
            Stmt::Store { addr, .. } => out.extend(stored_slot(addr)),
            Stmt::Pop { target } => out.extend(checked_name(target)),
            // A call writes the register the ABI returns in — now recorded on the
            // statement itself, so this is the real destination rather than an
            // assumption about which register that is.
            Stmt::Call { dst, .. } => {
                out.extend(dst.as_ref().and_then(checked_name));
                out.insert(RETURN_ROLE.to_string());
            }
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                defs_in(then_body, out);
                if let Some(e) = else_body {
                    defs_in(e, out);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => defs_in(body, out),
            Stmt::For {
                init, step, body, ..
            } => {
                defs_in(std::slice::from_ref(init.as_ref()), out);
                defs_in(body, out);
                defs_in(std::slice::from_ref(step.as_ref()), out);
            }
            Stmt::Switch { cases, default, .. } => {
                for (_, b) in cases {
                    defs_in(b, out);
                }
                if let Some(d) = default {
                    defs_in(d, out);
                }
            }
            _ => {}
        }
    }
}

/// Does this body contain flow this walk does not model (a label or a goto)?
fn has_unstructured_flow(body: &[Stmt]) -> bool {
    body.iter().any(|s| match s {
        Stmt::Label(_) | Stmt::Goto { .. } => true,
        Stmt::If {
            then_body,
            else_body,
            ..
        } => {
            has_unstructured_flow(then_body)
                || else_body.as_deref().is_some_and(has_unstructured_flow)
        }
        Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => has_unstructured_flow(body),
        Stmt::For {
            init, step, body, ..
        } => {
            has_unstructured_flow(std::slice::from_ref(init.as_ref()))
                || has_unstructured_flow(body)
                || has_unstructured_flow(std::slice::from_ref(step.as_ref()))
        }
        Stmt::Switch { cases, default, .. } => {
            cases.iter().any(|(_, b)| has_unstructured_flow(b))
                || default.as_deref().is_some_and(has_unstructured_flow)
        }
        _ => false,
    })
}

/// Names an expression reads that are not yet (maybe-)defined.
fn undefined_reads(e: &Expr, defined: &BTreeSet<String>, found: &mut BTreeSet<String>) {
    for name in reads_of(e) {
        if !defined.contains(&name) {
            found.insert(name);
        }
    }
}

/// Walk `body` forward, accumulating maybe-defined names in `defined` and
/// recording reads that no definition reaches.
fn walk(body: &[Stmt], defined: &mut BTreeSet<String>, found: &mut BTreeSet<String>) {
    for s in body {
        match s {
            // The dispatch READS its target; an undefined read here is as real
            // as any other.
            Stmt::IndirectGoto { target } => undefined_reads(target, defined, found),
            Stmt::Assign { dst, src } => {
                // The source is evaluated first: `x = x + 1` reads x before this
                // definition of it.
                undefined_reads(src, defined, found);
                defined.extend(checked_name(dst));
            }
            Stmt::Store { addr, src, .. } => {
                undefined_reads(src, defined, found);
                match stored_slot(addr) {
                    // `local_4 = src` — a definition of the slot, not a use of it.
                    Some(slot) => {
                        defined.insert(slot);
                    }
                    None => undefined_reads(addr, defined, found),
                }
            }
            Stmt::Call {
                target, args, dst, ..
            } => {
                undefined_reads(target, defined, found);
                for a in args {
                    undefined_reads(a, defined, found);
                }
                defined.extend(dst.as_ref().and_then(checked_name));
                defined.insert(RETURN_ROLE.to_string());
            }
            Stmt::Return { value } => {
                if let Some(v) = value {
                    undefined_reads(v, defined, found);
                }
            }
            Stmt::Push { value } => undefined_reads(value, defined, found),
            Stmt::Pop { target } => {
                defined.extend(checked_name(target));
            }
            Stmt::If {
                cond,
                then_body,
                else_body,
            } => {
                undefined_reads(cond, defined, found);
                // Both arms start from the same state; the join takes the UNION
                // (maybe-defined), so a definition in one arm satisfies a use
                // after the `if`.
                let mut then_defined = defined.clone();
                walk(then_body, &mut then_defined, found);
                let mut else_defined = defined.clone();
                if let Some(e) = else_body {
                    walk(e, &mut else_defined, found);
                }
                defined.extend(then_defined);
                defined.extend(else_defined);
            }
            Stmt::While { cond, body } => {
                // A value the body defines is available to the condition and to
                // the body itself on every iteration after the first, so seed
                // both with the body's definitions.
                let mut body_defs = BTreeSet::new();
                defs_in(body, &mut body_defs);
                let mut loop_defined = defined.clone();
                loop_defined.extend(body_defs);
                undefined_reads(cond, &loop_defined, found);
                let mut inner = loop_defined.clone();
                walk(body, &mut inner, found);
                defined.extend(loop_defined);
            }
            Stmt::For {
                init,
                cond,
                step,
                body,
            } => {
                walk(std::slice::from_ref(init.as_ref()), defined, found);
                let mut loop_defs = BTreeSet::new();
                defs_in(body, &mut loop_defs);
                defs_in(std::slice::from_ref(step.as_ref()), &mut loop_defs);
                let mut loop_defined = defined.clone();
                loop_defined.extend(loop_defs);
                undefined_reads(cond, &loop_defined, found);
                let mut inner = loop_defined.clone();
                walk(body, &mut inner, found);
                walk(std::slice::from_ref(step.as_ref()), &mut inner, found);
                defined.extend(loop_defined);
            }
            Stmt::DoWhile { body, cond } => {
                // The body executes before the first condition test, so its
                // definitions are genuinely available to the latch and after
                // the loop (unlike a pre-tested loop, which may execute zero
                // times).
                walk(body, defined, found);
                undefined_reads(cond, defined, found);
            }
            Stmt::Switch {
                discriminant,
                cases,
                default,
            } => {
                undefined_reads(discriminant, defined, found);
                let mut joined = defined.clone();
                for (_, b) in cases {
                    let mut arm = defined.clone();
                    walk(b, &mut arm, found);
                    joined.extend(arm);
                }
                if let Some(d) = default {
                    let mut arm = defined.clone();
                    walk(d, &mut arm, found);
                    joined.extend(arm);
                }
                *defined = joined;
            }
            Stmt::Label(_)
            | Stmt::Goto { .. }
            | Stmt::Break
            | Stmt::Nop
            | Stmt::Unknown(_)
            | Stmt::Comment(_) => {}
        }
    }
}

/// Collect every name read anywhere in `body`.
fn all_reads(body: &[Stmt], out: &mut BTreeSet<String>) {
    fn push(e: &Expr, out: &mut BTreeSet<String>) {
        out.extend(reads_of(e));
    }
    for s in body {
        match s {
            Stmt::Assign { src, .. } => push(src, out),
            Stmt::Store { addr, src, .. } => {
                if stored_slot(addr).is_none() {
                    push(addr, out);
                }
                push(src, out);
            }
            Stmt::Call { target, args, .. } => {
                push(target, out);
                for a in args {
                    push(a, out);
                }
            }
            Stmt::Return { value } => {
                if let Some(v) = value {
                    push(v, out);
                }
            }
            Stmt::Push { value } => push(value, out),
            Stmt::If {
                cond,
                then_body,
                else_body,
            } => {
                push(cond, out);
                all_reads(then_body, out);
                if let Some(e) = else_body {
                    all_reads(e, out);
                }
            }
            Stmt::While { cond, body } => {
                push(cond, out);
                all_reads(body, out);
            }
            Stmt::For {
                init,
                cond,
                step,
                body,
            } => {
                all_reads(std::slice::from_ref(init.as_ref()), out);
                push(cond, out);
                all_reads(body, out);
                all_reads(std::slice::from_ref(step.as_ref()), out);
            }
            Stmt::DoWhile { body, cond } => {
                all_reads(body, out);
                push(cond, out);
            }
            Stmt::Switch {
                discriminant,
                cases,
                default,
            } => {
                push(discriminant, out);
                for (_, b) in cases {
                    all_reads(b, out);
                }
                if let Some(d) = default {
                    all_reads(d, out);
                }
            }
            _ => {}
        }
    }
}

/// Frame-pointer registers that appear inside an address which is dereferenced.
///
/// This is the shape that crashes. `cpp_ctor_dtor` passes `rbp - 32` as a `this`
/// pointer and `cpp_virtual_dispatch` dereferences a vtable pointer derived the same
/// way; both segfault, and both were invisible to this checker because it excluded
/// machine registers as "live-in state". That exclusion is a statement about the
/// machine. In the emitted C the renderer has DECLARED `long rbp;` and never assigned
/// it, so the address is computed from an uninitialised variable.
fn frame_pointer_addresses(body: &[Stmt]) -> BTreeSet<String> {
    fn regs_in(e: &Expr, out: &mut BTreeSet<String>) {
        if let Some(n) = declared_machine_register_expr(e) {
            out.insert(n);
        }
        match e {
            Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
                regs_in(lhs, out);
                regs_in(rhs, out);
            }
            Expr::Select {
                cond,
                if_true,
                if_false,
                ..
            } => {
                regs_in(cond, out);
                regs_in(if_true, out);
                regs_in(if_false, out);
            }
            Expr::Un { src, .. } => regs_in(src, out),
            Expr::Cast { expr, .. } => regs_in(expr, out),
            Expr::Deref { addr, .. } => regs_in(addr, out),
            Expr::Lea { base, index, .. } => {
                for r in [base, index].into_iter().flatten() {
                    if let Some(n) = declared_machine_register(r) {
                        out.insert(n);
                    }
                }
            }
            _ => {}
        }
    }
    /// Addresses only: the `addr` of a `Deref`, and any `Lea` (an address being
    /// taken, which is how a stack object reaches a callee).
    fn scan_expr(e: &Expr, out: &mut BTreeSet<String>) {
        match e {
            Expr::Deref { addr, .. } => {
                regs_in(addr, out);
                scan_expr(addr, out);
            }
            Expr::Lea { .. } => regs_in(e, out),
            Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
                scan_expr(lhs, out);
                scan_expr(rhs, out);
            }
            Expr::Select {
                cond,
                if_true,
                if_false,
                ..
            } => {
                scan_expr(cond, out);
                scan_expr(if_true, out);
                scan_expr(if_false, out);
            }
            Expr::Un { src, .. } => scan_expr(src, out),
            Expr::Cast { expr, .. } => scan_expr(expr, out),
            _ => {}
        }
    }
    fn scan(body: &[Stmt], out: &mut BTreeSet<String>) {
        for s in body {
            match s {
                Stmt::Assign { src, .. } => scan_expr(src, out),
                Stmt::Store { addr, src, .. } => {
                    regs_in(addr, out);
                    scan_expr(addr, out);
                    scan_expr(src, out);
                }
                Stmt::Call { target, args, .. } => {
                    scan_expr(target, out);
                    for a in args {
                        // ANY argument mentioning an unassigned frame pointer, not
                        // just an `Expr::Lea`. A first version matched only `Lea` and
                        // found nothing corpus-wide — because the real shape is plain
                        // arithmetic: `_ZN6TracerC1EPiii((rbp - 32), ...)` is
                        // `Bin{Sub, Reg(rbp), Const(32)}`. The callee dereferences it
                        // as `this`, so the crash happens THERE and no local `Deref`
                        // exists to key on.
                        regs_in(a, out);
                        scan_expr(a, out);
                    }
                }
                Stmt::Return { value: Some(e) } => scan_expr(e, out),
                Stmt::If {
                    cond,
                    then_body,
                    else_body,
                } => {
                    scan_expr(cond, out);
                    scan(then_body, out);
                    if let Some(e) = else_body {
                        scan(e, out);
                    }
                }
                Stmt::While { cond, body } => {
                    scan_expr(cond, out);
                    scan(body, out);
                }
                Stmt::For {
                    init,
                    cond,
                    step,
                    body,
                } => {
                    scan(std::slice::from_ref(init.as_ref()), out);
                    scan_expr(cond, out);
                    scan(body, out);
                    scan(std::slice::from_ref(step.as_ref()), out);
                }
                Stmt::DoWhile { body, cond } => {
                    scan(body, out);
                    scan_expr(cond, out);
                }
                Stmt::Switch {
                    discriminant,
                    cases,
                    default,
                } => {
                    scan_expr(discriminant, out);
                    for (_, b) in cases {
                        scan(b, out);
                    }
                    if let Some(b) = default {
                        scan(b, out);
                    }
                }
                _ => {}
            }
        }
    }
    let mut out = BTreeSet::new();
    scan(body, &mut out);
    out
}

fn declared_machine_register_expr(e: &Expr) -> Option<String> {
    match e {
        Expr::Reg(v) => declared_machine_register(v),
        _ => None,
    }
}

/// Versioned values whose reaching definition is explicit poison.
fn poisoned_defs(body: &[Stmt], out: &mut BTreeSet<String>) {
    for stmt in body {
        match stmt {
            Stmt::Assign {
                dst,
                src: Expr::Unknown(reason),
            } if reason.starts_with("undefined(") => out.extend(checked_name(dst)),
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                poisoned_defs(then_body, out);
                if let Some(else_body) = else_body {
                    poisoned_defs(else_body, out);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => poisoned_defs(body, out),
            Stmt::For {
                init, step, body, ..
            } => {
                poisoned_defs(std::slice::from_ref(init.as_ref()), out);
                poisoned_defs(body, out);
                poisoned_defs(std::slice::from_ref(step.as_ref()), out);
            }
            Stmt::Switch { cases, default, .. } => {
                for (_, case_body) in cases {
                    poisoned_defs(case_body, out);
                }
                if let Some(default_body) = default {
                    poisoned_defs(default_body, out);
                }
            }
            _ => {}
        }
    }
}

/// Verify `f`, returning every violation found (sorted, deduplicated by name and
/// kind). An empty result means every invented value the function reads has a
/// definition that reaches it.
pub fn check(f: &Function) -> Vec<Violation> {
    let mut defined = BTreeSet::new();
    defs_in(&f.body, &mut defined);
    let mut reads = BTreeSet::new();
    all_reads(&f.body, &mut reads);

    let mut out: Vec<Violation> = reads
        .difference(&defined)
        .map(|name| Violation {
            name: name.clone(),
            kind: ViolationKind::NeverDefined,
        })
        .collect();

    let mut poisoned = BTreeSet::new();
    poisoned_defs(&f.body, &mut poisoned);
    for name in reads.intersection(&poisoned) {
        out.push(Violation {
            name: name.clone(),
            kind: ViolationKind::UndefinedValue,
        });
    }

    // A frame pointer used to compute a DEREFERENCED address. Deliberately narrower
    // than "rbp is read anywhere": a plain `var2 = rbp` yields a garbage VALUE, which
    // is bad, but `*(rbp - 32)` or passing `rbp - 32` as a pointer is what makes a
    // decompilation SEGFAULT — and a rule that fired on every preserved prologue
    // frame pointer would be noise rather than a finding.
    for name in frame_pointer_addresses(&f.body) {
        if !defined.contains(&name) {
            out.push(Violation {
                name,
                kind: ViolationKind::UninitialisedFramePointer,
            });
        }
    }

    if !has_unstructured_flow(&f.body) {
        let mut flow_defined = BTreeSet::new();
        let mut found = BTreeSet::new();
        walk(&f.body, &mut flow_defined, &mut found);
        for name in found {
            // Already reported as never-defined; do not double-report.
            if defined.contains(&name) {
                out.push(Violation {
                    name,
                    kind: ViolationKind::UsedBeforeDefinition,
                });
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::ast::Expr;
    use crate::ir::types::{BinOp, CmpOp};

    fn phys(n: &str) -> VReg {
        VReg::phys(n)
    }

    fn reg(n: &str) -> Expr {
        Expr::Reg(phys(n))
    }

    fn assign(dst: &str, src: Expr) -> Stmt {
        Stmt::Assign {
            dst: phys(dst),
            src,
        }
    }

    fn func(body: Vec<Stmt>) -> Function {
        Function {
            name: "f".into(),
            entry_va: 0x1000,
            body,
        }
    }

    fn names(v: &[Violation]) -> Vec<String> {
        v.iter().map(|x| x.name.clone()).collect()
    }

    #[test]
    fn a_genuine_use_before_definition_is_reported() {
        // local_1 = ret;  ret = (u8)local_1;   <- `ret` is read with no def:
        // exactly the rt_u8 corruption the decbench lowering used to produce.
        let f = func(vec![
            assign("local_1", reg("ret")),
            assign("ret", reg("local_1")),
            Stmt::Return {
                value: Some(reg("ret")),
            },
        ]);
        let v = check(&f);
        assert!(
            v.iter()
                .any(|x| x.name == "ret" && x.kind == ViolationKind::UsedBeforeDefinition),
            "expected a use-before-definition for `ret`, got {v:?}"
        );
    }

    #[test]
    fn a_name_read_but_never_assigned_is_reported() {
        let f = func(vec![Stmt::Return {
            value: Some(reg("var7")),
        }]);
        let v = check(&f);
        assert_eq!(names(&v), vec!["var7"]);
        assert_eq!(v[0].kind, ViolationKind::NeverDefined);
    }

    #[test]
    fn an_explicit_call_destination_is_defined_by_the_call() {
        let f = func(vec![
            Stmt::Call {
                dst: Some(VReg::phys("var2")),
                target: Expr::Named {
                    va: 0x2000,
                    name: "callee".into(),
                },
                args: vec![reg("arg0")],
                call_spec: None,
            },
            Stmt::Return {
                value: Some(reg("var2")),
            },
        ]);

        assert_eq!(check(&f), vec![]);
    }

    #[test]
    fn an_undefined_predicate_live_in_is_reported() {
        let zf_live_in = VReg::FlagValue {
            flag: crate::ir::types::Flag::Z,
            version: 0,
        };
        let f = func(vec![Stmt::If {
            cond: Expr::Reg(zf_live_in),
            then_body: vec![Stmt::Nop],
            else_body: None,
        }]);

        let violations = check(&f);

        assert_eq!(names(&violations), vec!["zf_0"]);
        assert_eq!(violations[0].kind, ViolationKind::NeverDefined);
    }

    #[test]
    fn a_defined_versioned_predicate_is_not_reported() {
        let zf = VReg::FlagValue {
            flag: crate::ir::types::Flag::Z,
            version: 1,
        };
        let f = func(vec![
            Stmt::Assign {
                dst: zf.clone(),
                src: Expr::Const(1),
            },
            Stmt::If {
                cond: Expr::Reg(zf),
                then_body: vec![Stmt::Nop],
                else_body: None,
            },
        ]);

        assert_eq!(check(&f), vec![]);
    }

    #[test]
    fn a_live_explicitly_undefined_predicate_is_reported() {
        let of = VReg::FlagValue {
            flag: crate::ir::types::Flag::O,
            version: 2,
        };
        let f = func(vec![
            Stmt::Assign {
                dst: of.clone(),
                src: Expr::Unknown("undefined(OF after multi-bit shift)".into()),
            },
            Stmt::If {
                cond: Expr::Reg(of),
                then_body: vec![Stmt::Nop],
                else_body: None,
            },
        ]);

        let violations = check(&f);

        assert_eq!(names(&violations), vec!["of_2"]);
        assert_eq!(violations[0].kind, ViolationKind::UndefinedValue);
    }

    #[test]
    fn a_select_keeps_condition_and_both_value_arms_as_reads() {
        let f = func(vec![
            assign(
                "local_0",
                Expr::Select {
                    cond: Box::new(reg("var1")),
                    if_true: Box::new(reg("var2")),
                    if_false: Box::new(reg("var3")),
                    width: 8,
                },
            ),
            Stmt::Return {
                value: Some(reg("local_0")),
            },
        ]);

        let v = check(&f);

        assert_eq!(names(&v), vec!["var1", "var2", "var3"]);
        assert!(
            v.iter()
                .all(|violation| violation.kind == ViolationKind::NeverDefined),
            "all three select inputs must remain visible to verification: {v:?}"
        );
    }

    #[test]
    fn the_correct_rt_u8_shape_is_not_flagged() {
        // The CORRECT lowering of `uint8_t rt_u8(long x){ return (uint8_t)x; }`:
        // every invented value is defined before it is read. This shape produced a
        // false positive in the reverted pre-render checker.
        let f = func(vec![
            assign("ret", reg("arg0")),
            assign("local_14", reg("ret")),
            assign(
                "ret",
                Expr::Cast {
                    signed: false,
                    width: 1,
                    expr: Box::new(reg("local_14")),
                },
            ),
            Stmt::Return {
                value: Some(reg("ret")),
            },
        ]);
        assert_eq!(check(&f), vec![], "correct output must not be flagged");
    }

    #[test]
    fn parameters_and_machine_registers_are_not_definitions_we_owe() {
        let f = func(vec![
            assign("var0", reg("arg3")),
            assign("var1", reg("rsp")),
            assign("var2", reg("rbp")),
            Stmt::Return {
                value: Some(reg("var0")),
            },
        ]);
        assert_eq!(check(&f), vec![]);
    }

    #[test]
    fn a_frame_pointer_used_as_a_dereferenced_address_is_a_violation() {
        // `*(rbp - 32)` — the shape that segfaults.
        //
        // The renderer declares every non-argument identifier in the body, so a
        // surviving `rbp` is printed as `long rbp;` and never assigned. On the machine
        // it is live-in; in the emitted C it is uninitialised, and only the second
        // fact decides whether the recompiled function runs. Two fixture cells —
        // cpp_ctor_dtor and cpp_virtual_dispatch — emit exactly this and crash, and
        // this checker stayed silent through both because it excluded machine
        // registers wholesale.
        let f = func(vec![
            Stmt::Assign {
                dst: VReg::phys("var0"),
                src: Expr::Deref {
                    size: 8,
                    addr: Box::new(Expr::Bin {
                        op: crate::ir::types::BinOp::Sub,
                        lhs: Box::new(reg("rbp")),
                        rhs: Box::new(Expr::Const(32)),
                    }),
                },
            },
            Stmt::Return {
                value: Some(reg("var0")),
            },
        ]);
        let v = check(&f);
        assert_eq!(
            v,
            vec![Violation {
                name: "rbp".into(),
                kind: ViolationKind::UninitialisedFramePointer,
            }],
            "expected the dereferenced frame pointer to be flagged, got {v:?}"
        );
    }

    #[test]
    fn a_frame_pointer_read_as_a_plain_value_is_not_flagged() {
        // The counterexample that keeps the rule precise. `var1 = rbp` yields a
        // garbage VALUE, which is a lesser defect, and a rule firing on every
        // preserved prologue frame pointer would be noise rather than a finding.
        // Narrowing to dereferenced addresses is what makes this assertion
        // actionable.
        let f = func(vec![
            assign("var1", reg("rbp")),
            Stmt::Return {
                value: Some(reg("var1")),
            },
        ]);
        assert_eq!(
            check(&f),
            vec![],
            "a plain frame-pointer read must not fire"
        );
    }

    #[test]
    fn a_frame_pointer_address_passed_to_a_callee_is_a_violation() {
        // `foo(&stack_object)` — the `this`-pointer shape. The callee dereferences
        // it, so the crash happens there rather than here, which is precisely why a
        // check that only looked at local Derefs would miss cpp_ctor_dtor.
        let f = func(vec![
            Stmt::Call {
                dst: None,
                target: Expr::Addr(0x1000),
                args: vec![Expr::Lea {
                    base: Some(VReg::phys("rbp")),
                    index: None,
                    scale: 1,
                    disp: -32,
                    segment: None,
                }],
                call_spec: None,
            },
            Stmt::Return { value: None },
        ]);
        let v = check(&f);
        assert!(
            v.iter()
                .any(|x| x.kind == ViolationKind::UninitialisedFramePointer),
            "an address taken of an unassigned frame pointer and handed to a callee \
             must be flagged, got {v:?}"
        );
    }

    #[test]
    fn a_branch_local_definition_satisfies_a_use_at_the_join() {
        // if (arg0) { var1 = 1; } else { var1 = 2; }  return var1;
        let f = func(vec![
            Stmt::If {
                cond: reg("arg0"),
                then_body: vec![assign("var1", Expr::Const(1))],
                else_body: Some(vec![assign("var1", Expr::Const(2))]),
            },
            Stmt::Return {
                value: Some(reg("var1")),
            },
        ]);
        assert_eq!(check(&f), vec![]);
    }

    #[test]
    fn a_definition_in_only_one_arm_is_accepted_as_maybe_defined() {
        // Deliberately permissive: a def on one path is enough. The checker must
        // never cry wolf about a shape a compiler could legitimately produce.
        let f = func(vec![
            Stmt::If {
                cond: reg("arg0"),
                then_body: vec![assign("var1", Expr::Const(1))],
                else_body: None,
            },
            Stmt::Return {
                value: Some(reg("var1")),
            },
        ]);
        assert_eq!(check(&f), vec![]);
    }

    #[test]
    fn a_use_inside_a_branch_before_any_definition_is_reported() {
        let f = func(vec![
            Stmt::If {
                cond: reg("arg0"),
                then_body: vec![assign("var2", reg("var1"))],
                else_body: Some(vec![assign("var1", Expr::Const(2))]),
            },
            Stmt::Return {
                value: Some(reg("var2")),
            },
        ]);
        let v = check(&f);
        assert!(
            v.iter()
                .any(|x| x.name == "var1" && x.kind == ViolationKind::UsedBeforeDefinition),
            "got {v:?}"
        );
    }

    #[test]
    fn a_loop_carried_value_is_not_a_use_before_definition() {
        // while (var1 < 10) { var1 = var1 + 1; }  — the condition reads a value the
        // body defines on the previous iteration.
        let f = func(vec![
            assign("var1", Expr::Const(0)),
            Stmt::While {
                cond: Expr::Cmp {
                    op: CmpOp::Slt,
                    lhs: Box::new(reg("var1")),
                    rhs: Box::new(Expr::Const(10)),
                },
                body: vec![assign(
                    "var1",
                    Expr::Bin {
                        op: BinOp::Add,
                        lhs: Box::new(reg("var1")),
                        rhs: Box::new(Expr::Const(1)),
                    },
                )],
            },
            Stmt::Return {
                value: Some(reg("var1")),
            },
        ]);
        assert_eq!(check(&f), vec![]);
    }

    #[test]
    fn a_value_only_defined_in_a_loop_body_satisfies_a_later_use() {
        let f = func(vec![
            Stmt::While {
                cond: reg("arg0"),
                body: vec![assign("var3", Expr::Const(7))],
            },
            Stmt::Return {
                value: Some(reg("var3")),
            },
        ]);
        assert_eq!(check(&f), vec![]);
    }

    #[test]
    fn a_call_defines_the_return_register() {
        // foo(); return ret;  — the callee's return value lands in `ret`.
        let f = func(vec![
            Stmt::Call {
                target: Expr::Named {
                    va: 0x2000,
                    name: "foo".into(),
                },
                args: vec![],
                dst: None,
                call_spec: None,
            },
            Stmt::Return {
                value: Some(reg("ret")),
            },
        ]);
        assert_eq!(check(&f), vec![]);
    }

    #[test]
    fn unstructured_flow_disables_only_the_flow_sensitive_rule() {
        // With a label/goto present the walk cannot model the flow, so no
        // use-before-definition is claimed — but a name defined NOWHERE is still a
        // violation, because no control flow can rescue it.
        let f = func(vec![
            Stmt::Label(0x1010),
            assign("var1", reg("var9")),
            Stmt::Goto { target: 0x1010 },
        ]);
        let v = check(&f);
        assert_eq!(names(&v), vec!["var9"]);
        assert_eq!(v[0].kind, ViolationKind::NeverDefined);

        // A backward goto whose definition appears textually later is NOT reported
        // (the flow-sensitive rule is off for this body).
        let f2 = func(vec![
            Stmt::Label(0x1010),
            assign("var1", reg("var2")),
            assign("var2", Expr::Const(1)),
            Stmt::Goto { target: 0x1010 },
        ]);
        assert_eq!(check(&f2), vec![]);
    }

    #[test]
    fn a_store_to_a_promoted_slot_defines_it() {
        // The real `-O0` shape of `for (i = 0; i < n; i++)`: the slot is DEFINED by
        // a store whose address is the slot itself, which the renderer prints as
        // `local_4 = 0;`. Treating that address as a *use* is exactly how a first
        // version of this checker flagged half the fixture corpus, including
        // functions whose decompilation executes correctly.
        let f = func(vec![
            Stmt::Store {
                addr: reg("local_4"),
                src: Expr::Const(0),
                size: 4,
            },
            Stmt::While {
                cond: Expr::Cmp {
                    op: CmpOp::Slt,
                    lhs: Box::new(reg("local_4")),
                    rhs: Box::new(reg("arg1")),
                },
                body: vec![Stmt::Store {
                    addr: reg("local_4"),
                    src: Expr::Bin {
                        op: BinOp::Add,
                        lhs: Box::new(reg("local_4")),
                        rhs: Box::new(Expr::Const(1)),
                    },
                    size: 4,
                }],
            },
            Stmt::Return {
                value: Some(reg("local_4")),
            },
        ]);
        assert_eq!(
            check(&f),
            vec![],
            "a slot store is a definition of the slot"
        );
    }

    #[test]
    fn a_store_through_a_pointer_parameter_is_not_a_definition() {
        // `*arg0 = local_8;` — the address is a parameter, so this is a real store
        // through a pointer, and the VALUE it stores is still a use.
        let f = func(vec![Stmt::Store {
            addr: reg("arg0"),
            src: reg("local_8"),
            size: 4,
        }]);
        assert_eq!(names(&check(&f)), vec!["local_8"]);
    }

    #[test]
    fn stack_slots_and_promoted_locals_are_checked() {
        let f = func(vec![Stmt::Return {
            value: Some(Expr::Bin {
                op: BinOp::Add,
                lhs: Box::new(reg("local_14")),
                rhs: Box::new(reg("stack_0")),
            }),
        }]);
        assert_eq!(names(&check(&f)), vec!["local_14", "stack_0"]);
    }

    #[test]
    fn reads_through_derefs_and_addresses_are_seen() {
        let f = func(vec![Stmt::Store {
            addr: Expr::Lea {
                base: Some(phys("var1")),
                index: Some(phys("var2")),
                scale: 4,
                disp: 0,
                segment: None,
            },
            src: Expr::Deref {
                addr: Box::new(reg("var3")),
                size: 4,
            },
            size: 4,
        }]);
        assert_eq!(names(&check(&f)), vec!["var1", "var2", "var3"]);
    }

    #[test]
    fn a_temporary_that_survives_lowering_must_be_defined() {
        let f = func(vec![Stmt::Return {
            value: Some(Expr::Reg(VReg::Temp(3))),
        }]);
        assert_eq!(names(&check(&f)), vec!["t3"]);
    }

    #[test]
    fn a_var_prefixed_name_that_is_not_a_scratch_value_is_ignored() {
        // `variable_x` is not the `varN` scratch convention.
        let f = func(vec![Stmt::Return {
            value: Some(reg("variable_x")),
        }]);
        assert_eq!(check(&f), vec![]);
    }

    #[test]
    fn switch_arms_join_like_branches() {
        let f = func(vec![
            Stmt::Switch {
                discriminant: reg("arg0"),
                cases: vec![
                    (Some(0), vec![assign("var1", Expr::Const(1))]),
                    (Some(1), vec![assign("var1", Expr::Const(2))]),
                ],
                default: Some(vec![assign("var1", Expr::Const(3))]),
            },
            Stmt::Return {
                value: Some(reg("var1")),
            },
        ]);
        assert_eq!(check(&f), vec![]);
    }

    fn violation(name: &str) -> Violation {
        Violation {
            name: name.into(),
            kind: ViolationKind::NeverDefined,
        }
    }

    #[test]
    fn verify_comments_follow_the_header_and_precede_the_code() {
        // The exact shape a consumer splits on: one header line, then the code.
        let body = "// glaurung: fib @ 0x1571\nlong fib(long arg0) {\n    return arg0;\n}";
        let out = splice_verify_comments(body, &[violation("var0")]);
        let lines: Vec<&str> = out.lines().collect();
        // The header stays first — a comment before it would bind to the PREVIOUS
        // function when the whole multi-function blob is split on the header.
        assert_eq!(lines[0], "// glaurung: fib @ 0x1571");
        assert_eq!(
            lines[1],
            "// glaurung-verify: var0 is read but never defined"
        );
        // ...and the code the header introduces still follows, unshifted.
        assert_eq!(lines[2], "long fib(long arg0) {");
    }

    #[test]
    fn no_violations_returns_the_body_unchanged() {
        let body = "// glaurung: f @ 0x10\nvoid f(void) {\n}";
        assert_eq!(splice_verify_comments(body, &[]), body);
    }

    #[test]
    fn every_violation_sits_between_header_and_code() {
        let body = "// glaurung: g @ 0x20\nint g(void) {\n    return x;\n}";
        let vs = [violation("x"), violation("y")];
        let out = splice_verify_comments(body, &vs);
        let header_idx = out
            .lines()
            .position(|l| l.starts_with("// glaurung:"))
            .unwrap();
        let code_idx = out.lines().position(|l| l.starts_with("int g(")).unwrap();
        for v in &vs {
            let vi = out
                .lines()
                .position(|l| l == format!("// glaurung-verify: {v}"))
                .unwrap();
            assert!(header_idx < vi && vi < code_idx, "violation {v} misplaced");
        }
    }
}
