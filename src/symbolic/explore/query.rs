//! Concrete answers about a symbolic [`State`](super::State).
//!
//! Concretization under the active policy, ABI argument reads, the
//! controllability and feasibility predicates the detectors ask before
//! reporting, and the construction of a [`Sink`](super::Sink) from them.
//!
//! Every function here reads `State`'s private fields. `State` therefore
//! stays in the parent: a child may read an ANCESTOR's private fields but
//! not a SIBLING's, so moving it into any one child would have forced
//! `pub(super)` onto all thirteen of them.

use std::collections::{BTreeMap, BTreeSet};

use crate::exec::domain::Domain;
use crate::exec::{Concrete, RegArch};
use crate::ir::types::{BinOp, CmpOp, Endian, VReg, Width};
use crate::symbolic::concretization::{
    active_concretization_policy, ConcretizationChoice, ConcretizationPolicy,
    ConcretizationRequest, ConcretizationSite,
};
use crate::symbolic::expr::{Expr, ExprId, ExprPool};
use crate::symbolic::solver::{Model, SolveResult};

use super::model::SENTINEL_ADDR;
use super::solve::{select_unsigned_extremum, solve_probe_traced, solve_traced};
use super::{Severity, Sink, SinkKind, State};

/// Concretely evaluate a symbolic [`Expr`] under a model (free symbols not in the
/// model default to 0), reusing the `Concrete` domain's exact semantics so the
/// result matches what the emulator would compute.
fn eval_expr(pool: &ExprPool, id: ExprId, model: &BTreeMap<u32, u128>, dom: &mut Concrete) -> u128 {
    match *pool.get(id) {
        Expr::Const { value, .. } => value,
        Expr::Sym { id, width } => {
            let v = model.get(&id).copied().unwrap_or(0);
            dom.constant(width, v)
        }
        Expr::Bin { op, a, b, width } => {
            let a = eval_expr(pool, a, model, dom);
            let b = eval_expr(pool, b, model, dom);
            dom.binop(op, &a, &b, width)
        }
        Expr::Un { op, a, width } => {
            let a = eval_expr(pool, a, model, dom);
            dom.unop(op, &a, width)
        }
        Expr::Cmp { op, a, b, width } => {
            let a = eval_expr(pool, a, model, dom);
            let b = eval_expr(pool, b, model, dom);
            dom.cmp(op, &a, &b, width)
        }
        Expr::ZExt { a, from, to } => {
            let a = eval_expr(pool, a, model, dom);
            dom.zext(&a, from, to)
        }
        Expr::SExt { a, from, to } => {
            let a = eval_expr(pool, a, model, dom);
            dom.sext(&a, from, to)
        }
        Expr::Trunc { a, to } => {
            let a = eval_expr(pool, a, model, dom);
            dom.trunc(&a, to)
        }
        Expr::Extract { a, hi, lo } => {
            let a = eval_expr(pool, a, model, dom);
            dom.extract(&a, hi, lo)
        }
        Expr::Concat { hi, lo, hi_w, lo_w } => {
            let h = eval_expr(pool, hi, model, dom);
            let l = eval_expr(pool, lo, model, dom);
            dom.concat(&h, &l, hi_w, lo_w)
        }
        Expr::Ite {
            c: cond,
            t,
            e,
            width,
        } => {
            let cc = eval_expr(pool, cond, model, dom);
            let t = eval_expr(pool, t, model, dom);
            let e = eval_expr(pool, e, model, dom);
            dom.ite(&cc, &t, &e, width)
        }
    }
}

/// Concretize a symbolic address: solve the path condition for a model, evaluate
/// the address expression under it, and bind `addr == chosen` so the path stays
/// consistent (the "any" strategy; concretize-with-threshold for reads is a
/// later refinement). Returns `None` when no satisfying model is available; in
/// that case the caller must stop the path rather than inventing a value.
pub(super) fn concretize_addr(st: &mut State, addr_val: ExprId) -> Option<u64> {
    let policy = active_concretization_policy();
    concretize_addr_with_policy(st, addr_val, &policy)
}

pub(super) fn concretize_addr_with_policy(
    st: &mut State,
    addr_val: ExprId,
    policy: &dyn ConcretizationPolicy,
) -> Option<u64> {
    let site = ConcretizationSite::Address;
    let purpose = "canonical-address-extremum";
    let request = ConcretizationRequest {
        site,
        purpose,
        location: st.pc,
    };
    let a = match policy.choose(request) {
        ConcretizationChoice::AnyModel => {
            let model = match solve_traced(st, "address-concretization", st.pc) {
                SolveResult::Sat(m) => m.values,
                _ => return None,
            };
            let mut concrete = Concrete;
            eval_expr(&st.machine.dom.pool, addr_val, &model, &mut concrete)
        }
        ConcretizationChoice::UnsignedExtremum(extremum) => {
            select_unsigned_extremum(st, addr_val, purpose, st.pc, extremum)?
        }
        // A3 must fork states for every checked boundary. A2 must change the
        // memory model. Until those execution paths land, neither choice may be
        // collapsed to one value here.
        ConcretizationChoice::BoundarySet(_) | ConcretizationChoice::Defer => return None,
    };
    if let Some(trace) = &mut st.trace {
        trace.model_choice(
            &st.machine.dom.pool,
            addr_val,
            a,
            true,
            policy.trace_policy_id(site),
            st.pc,
        );
    }
    let chosen = st.machine.dom.constant(Width::W64, a);
    let eq = st
        .machine
        .dom
        .cmp(CmpOp::Eq, &addr_val, &chosen, Width::W64);
    st.assert((eq, true), "concretization", st.pc);
    Some(a as u64)
}

/// If the attacker can drive `addr_val` to exactly `value` under the current path
/// condition, return a triggering model; otherwise `None`. The probe constraint
/// is built in a throwaway copy so the path condition is left untouched. This is
/// the primitive behind both the [`SENTINEL_ADDR`] arbitrariness test and the
/// `addr == 0` null-deref test.
pub(super) fn witness_for_value(st: &mut State, addr_val: ExprId, value: u128) -> Option<Model> {
    let w = st.machine.dom.pool.width_of(addr_val);
    let target = st.machine.dom.constant(w, value);
    let eq = st.machine.dom.cmp(CmpOp::Eq, &addr_val, &target, w);
    match solve_probe_traced(st, (eq, true), "value-witness", "other", st.pc) {
        // The target value is fixed by the probe, not selected from a backend
        // model, so this check has no model-driven exploration choice to record.
        SolveResult::Sat(m) => Some(m),
        _ => None,
    }
}

/// The MS x64 integer argument register for parameter index `n` (0-based).
/// Only the first four parameters are register-passed; index >=4 lives on the
/// stack (see [`read_arg`]).
fn arg_reg(arch: RegArch, n: u8) -> Option<&'static str> {
    match arch {
        RegArch::X86_64 => match n {
            0 => Some("rcx"),
            1 => Some("rdx"),
            2 => Some("r8"),
            3 => Some("r9"),
            _ => None,
        },
        RegArch::AArch64 => match n {
            0 => Some("x0"),
            1 => Some("x1"),
            2 => Some("x2"),
            3 => Some("x3"),
            4 => Some("x4"),
            5 => Some("x5"),
            6 => Some("x6"),
            7 => Some("x7"),
            _ => None,
        },
    }
}

/// Read call argument `n` as a symbolic value. Args 0-3 are in rcx/rdx/r8/r9;
/// args >=4 are on the stack at `[rsp + 0x20 + (n-4)*8]` at the call site -- the
/// 32-byte shadow space precedes the first stack arg in the MS x64 ABI. Reading
/// them (rather than the old `rsp` stub) is what lets a dangerous-call detector
/// see attacker taint that reached a high-numbered parameter, e.g. the
/// attacker-controlled CreateDisposition (param 7) of `ZwCreateFile`, which the
/// handler spills from the IRP system buffer into `[rsp+0x38]`.
pub(super) fn read_arg(st: &mut State, n: u8) -> Option<ExprId> {
    let arch = st.machine.regs.arch();
    match arg_reg(arch, n) {
        Some(r) => Some(st.machine.regs.read(&mut st.machine.dom, &VReg::phys(r))),
        None => {
            let (stack_register, stack_offset) = match arch {
                RegArch::X86_64 => ("rsp", 0x20 + (n as u128 - 4) * 8),
                RegArch::AArch64 => ("sp", (n as u128 - 8) * 8),
            };
            let stack = st
                .machine
                .regs
                .read(&mut st.machine.dom, &VReg::phys(stack_register));
            let off = st.machine.dom.constant(Width::W64, stack_offset);
            let addr = st.machine.dom.binop(BinOp::Add, &stack, &off, Width::W64);
            let a = concretize_addr(st, addr)?;
            Some(
                st.machine
                    .mem
                    .load(&mut st.machine.dom, a, 8, Endian::Little),
            )
        }
    }
}

pub(super) fn read_arg_with_width(st: &mut State, n: u8, width: Width) -> Option<ExprId> {
    if st.machine.regs.arch() == RegArch::AArch64 && width == Width::W32 {
        let register = match n {
            0 => "w0",
            1 => "w1",
            2 => "w2",
            3 => "w3",
            4 => "w4",
            5 => "w5",
            6 => "w6",
            7 => "w7",
            _ => return None,
        };
        return Some(
            st.machine
                .regs
                .read(&mut st.machine.dom, &VReg::phys(register)),
        );
    }
    read_arg(st, n)
}

pub(super) fn witness_for_predicate(st: &mut State, predicate: ExprId) -> Option<Model> {
    match solve_probe_traced(st, (predicate, true), "predicate-witness", "other", st.pc) {
        SolveResult::Sat(model) => Some(model),
        _ => None,
    }
}

/// Concretely evaluate `val` under a model of the current path *without* binding
/// it (a read-only probe, unlike [`concretize_addr`]). Used by the lifecycle
/// checks (free/UAF/stack) that only need a representative concrete value.
/// Returns `None` for UNSAT, unknown, unavailable, or failed solver results;
/// none of those outcomes authorizes a model-driven exploration choice.
pub(super) fn eval_concrete(st: &mut State, val: ExprId) -> Option<u64> {
    let policy = active_concretization_policy();
    eval_concrete_with_policy(st, val, &policy)
}

pub(super) fn eval_concrete_with_policy(
    st: &mut State,
    val: ExprId,
    policy: &dyn ConcretizationPolicy,
) -> Option<u64> {
    let site = ConcretizationSite::Representative;
    let purpose = "canonical-representative-extremum";
    let request = ConcretizationRequest {
        site,
        purpose,
        location: st.pc,
    };
    let value = match policy.choose(request) {
        ConcretizationChoice::AnyModel => {
            let model = match solve_traced(st, "concrete-evaluation", st.pc) {
                SolveResult::Sat(m) => m.values,
                _ => return None,
            };
            let mut concrete = Concrete;
            eval_expr(&st.machine.dom.pool, val, &model, &mut concrete)
        }
        ConcretizationChoice::UnsignedExtremum(extremum) => {
            select_unsigned_extremum(st, val, purpose, st.pc, extremum)?
        }
        ConcretizationChoice::BoundarySet(_) | ConcretizationChoice::Defer => return None,
    };
    if let Some(trace) = &mut st.trace {
        trace.model_choice(
            &st.machine.dom.pool,
            val,
            value,
            true,
            policy.trace_policy_id(site),
            st.pc,
        );
    }
    Some(value as u64)
}

/// A reaching witness for the current path: the empty model when there are no
/// constraints (no solver call needed), otherwise a solve. `None` only when the
/// path is provably infeasible (Unsat); Unknown/NoSolver are kept as a sound
/// over-approximation. This avoids a z3 context-build per sink on shallow paths.
pub(super) fn reach_model(st: &mut State) -> Option<Model> {
    if st.constraints.is_empty() {
        return Some(Model::default());
    }
    match solve_traced(st, "finding-reachability", st.pc) {
        SolveResult::Sat(m) => Some(m),
        SolveResult::Unsat => None,
        _ => Some(Model::default()),
    }
}

/// True only when `pred` has at least one free symbol and none overlaps the
/// existing path condition. In that case either polarity of the non-constant
/// symbolic branch is satisfiable independently and its feasibility check can
/// be skipped. A symbol-free expression is *not* admitted: syntactic
/// `BranchDecision::Fork` does not prove that a constant DAG is semantically
/// satisfiable, and skipping it can preserve an infeasible path.
pub(super) fn can_skip_feasibility_check(st: &State, pred: ExprId) -> bool {
    let pool = &st.machine.dom.pool;
    let mut psyms = BTreeMap::new();
    pool.collect_syms(pred, &mut psyms);
    if psyms.is_empty() {
        return false;
    }
    for (c, _) in &st.constraints {
        let mut csyms = BTreeMap::new();
        pool.collect_syms(*c, &mut csyms);
        if csyms.keys().any(|k| psyms.contains_key(k)) {
            return false;
        }
    }
    true
}

/// True if `expr` has at least one free symbol and *none* of them appear in the
/// path condition — so the attacker can still drive `expr` to any value. For such
/// an address, `addr == sentinel` and `addr == 0` are trivially satisfiable, so
/// the severity and null-deref solves can be skipped (the common case for a fresh
/// attacker pointer with no guards yet).
fn unconstrained(st: &State, expr: ExprId) -> bool {
    let pool = &st.machine.dom.pool;
    let mut esyms = BTreeMap::new();
    pool.collect_syms(expr, &mut esyms);
    if esyms.is_empty() {
        return false;
    }
    for (c, _) in &st.constraints {
        let mut csyms = BTreeMap::new();
        pool.collect_syms(*c, &mut csyms);
        if csyms.keys().any(|k| esyms.contains_key(k)) {
            return false;
        }
    }
    true
}

/// True if `id` is an affine combination of symbols and constants with unit
/// coefficients (`Sym`, `Const`, or `Add` of such) — i.e. its value is *not*
/// bounded by its own structure (no masking, multiply, shift). Such an expression
/// spans the whole width when its symbols are unconstrained, so it can reach the
/// sentinel and 0 without a solve. `BUF + (len & 0xF)` is **not** affine-unit (the
/// `And` bounds it), so it correctly falls through to the solver.
fn is_affine_unit(pool: &ExprPool, id: ExprId) -> bool {
    match *pool.get(id) {
        Expr::Sym { .. } | Expr::Const { .. } => true,
        Expr::Bin {
            op: BinOp::Add,
            a,
            b,
            ..
        } => is_affine_unit(pool, a) && is_affine_unit(pool, b),
        _ => false,
    }
}

/// An address the attacker can drive to *any* value with no solve: affine-unit in
/// shape and unconstrained by the path. Used to skip the sentinel and null solves.
pub(super) fn freely_controllable(st: &State, addr: ExprId) -> bool {
    is_affine_unit(&st.machine.dom.pool, addr) && unconstrained(st, addr)
}

/// The arbitrariness severity of an address: `Arbitrary` if it is freely
/// controllable (fast path, no solve) or the solver can pin it to the sentinel;
/// else `Constrained`.
pub(super) fn severity_of(st: &mut State, addr: ExprId) -> Severity {
    if freely_controllable(st, addr) || witness_for_value(st, addr, SENTINEL_ADDR).is_some() {
        Severity::Arbitrary
    } else {
        Severity::Constrained
    }
}

/// Emit a `kind` sink (with reaching witness and arbitrariness severity from
/// `severity_for`) when the path is satisfiable. `tainted_by` is the provenance.
pub(super) fn push_sink(
    st: &mut State,
    va: u64,
    kind: SinkKind,
    severity_for: ExprId,
    tainted_by: Vec<String>,
    sinks: &mut Vec<Sink>,
) {
    if let Some(reach) = reach_model(st) {
        let severity = severity_of(st, severity_for);
        sinks.push(Sink {
            va,
            kind,
            witness: reach,
            severity,
            tainted_by,
        });
    }
}

pub(super) fn path_provenance(st: &State) -> Vec<String> {
    let mut symbols = BTreeMap::new();
    for (constraint, _) in &st.constraints {
        st.machine.dom.pool.collect_syms(*constraint, &mut symbols);
    }
    symbols
        .keys()
        .filter_map(|id| st.taint.labels.get(id))
        .flatten()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}
