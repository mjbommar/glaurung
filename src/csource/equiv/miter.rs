//! Building the equivalence formula and deciding it.
//!
//! # The summary pair
//!
//! Path enumeration hands back, per side, a list of `(guard, result)`. Those are
//! folded into two expressions:
//!
//! * `defined` --- the disjunction of the guards, true exactly on the inputs
//!   that reached a return within the bounds;
//! * `value` --- the if-then-else chain `ite(g1, r1, ite(g2, r2, ... rn))`,
//!   selecting each path's result under its own guard.
//!
//! The guards come from a decision tree over the same branch values, so they are
//! pairwise exclusive by construction: the chain is exact, not a heuristic
//! merge, and its order does not change what it denotes. Results are compared
//! **truncated to the declared result width**, because a real callee leaves the
//! upper bits of the result register undefined and comparing them would report a
//! divergence the C standard says is not one --- the same masking
//! [`crate::csource::lower::differential`] does.
//!
//! # Two queries, never one
//!
//! `defined_a AND defined_b AND value_a != value_b` decides *difference*. It
//! says nothing about the inputs on which either side was cut. So when either
//! side has a cut path, a second query asks whether `defined_a AND defined_b`
//! can be false; if it can, the `unsat` of the first query is a statement about
//! part of the input space only, and the verdict is
//! [`Unknown::PartialCoverage`]. If it cannot --- which is the ordinary case for
//! a loop whose trip count the unroll bound covers, since the paths past the
//! bound have unsatisfiable guards --- the coverage is total and `unsat` means
//! equivalent.

use crate::exec::Domain;
use crate::ir::types::{BinOp, CmpOp, LlirFunction, VReg, Width};
use crate::symbolic::expr::{Expr, ExprId};
use crate::symbolic::solver::{solve, SolveResult};
use crate::symbolic::Symbolic;

use super::explore::{explore, CompletePath};
use super::{replay, Bounds, DecidedBy, EquivReport, IoSpec, Stats, Unknown, Verdict};

/// One side's folded summary.
struct Summary {
    /// True exactly on the inputs that reached a return within the bounds.
    defined: ExprId,
    /// The result, truncated to the declared width.
    value: ExprId,
}

/// Run both sides, build the miter, and decide it.
pub(super) fn decide(
    left: &LlirFunction,
    right: &LlirFunction,
    io: &IoSpec,
    result_width: Width,
    bounds: Bounds,
) -> EquivReport {
    let mut sym = Symbolic::new();
    let (symbols, seeds) = seed_inputs(&mut sym, io);

    let result_reg = VReg::phys(io.result_reg.clone());
    let (sym, left_paths) = explore(left, sym, &seeds, &result_reg, &bounds);
    let (mut sym, right_paths) = explore(right, sym, &seeds, &result_reg, &bounds);

    let stats = Stats {
        complete_paths: (left_paths.complete.len(), right_paths.complete.len()),
        cut_paths: (left_paths.cuts.len(), right_paths.cuts.len()),
        solves: 0,
    };
    let undecided = |reason: Unknown, stats: Stats| EquivReport {
        verdict: Verdict::Unknown(reason),
        bounds: bounds.clone(),
        witness: None,
        decided_by: DecidedBy::Solver,
        stats,
    };
    if left_paths.complete.is_empty() {
        return undecided(Unknown::NoCompletePath("left"), stats);
    }
    if right_paths.complete.is_empty() {
        return undecided(Unknown::NoCompletePath("right"), stats);
    }

    let left_summary = summarize(&mut sym, &left_paths.complete, result_width);
    let right_summary = summarize(&mut sym, &right_paths.complete, result_width);

    let differs = sym.cmp(
        CmpOp::Ne,
        &left_summary.value,
        &right_summary.value,
        result_width,
    );
    let mut stats = stats;
    let asserts = [
        (left_summary.defined, true),
        (right_summary.defined, true),
        (differs, true),
    ];
    let miter = match ask(&sym, &asserts, &bounds, &mut stats) {
        Ok(result) => result,
        Err(reason) => return undecided(reason, stats),
    };

    match miter {
        SolveResult::Sat(model) => {
            let args: Vec<u64> = symbols
                .iter()
                .map(|(id, slot)| {
                    let raw = model.values.get(id).copied().unwrap_or(0) as u64;
                    slot.canonicalize(raw)
                })
                .collect();
            match replay::confirm(left, right, &args, result_width, &bounds) {
                Some(witness) => EquivReport {
                    verdict: Verdict::Different,
                    bounds,
                    witness: Some(witness),
                    decided_by: DecidedBy::Solver,
                    stats,
                },
                // No `Witness` is attached: a candidate that did not reproduce
                // is not a counterexample, and a `Witness` whose two results
                // are equal would read as one.
                None => EquivReport {
                    verdict: Verdict::Unknown(Unknown::WitnessUnconfirmed),
                    bounds,
                    witness: None,
                    decided_by: DecidedBy::Solver,
                    stats,
                },
            }
        }
        SolveResult::Unsat => {
            let total = left_paths.is_total() && right_paths.is_total();
            let covered = total
                || match coverage(&mut sym, &left_summary, &right_summary, &bounds, &mut stats) {
                    Ok(value) => value,
                    Err(reason) => return undecided(reason, stats),
                };
            if covered {
                EquivReport {
                    verdict: Verdict::Equivalent,
                    bounds,
                    witness: None,
                    decided_by: DecidedBy::Solver,
                    stats,
                }
            } else {
                undecided(Unknown::PartialCoverage, stats)
            }
        }
        SolveResult::Unknown(reason) => undecided(Unknown::Solver(reason), stats),
        SolveResult::NoSolver => undecided(Unknown::NoSolver, stats),
        SolveResult::Error(message) => undecided(Unknown::SolverError(message), stats),
    }
}

/// Mint one symbol per parameter and place it in its argument register.
///
/// The symbol is minted **at the parameter's declared width** and extended to
/// 64 bits the way its signedness says. That is not decoration: a symbol minted
/// at 64 bits lets the solver hand back `0x1_0000_0000` for an `int` parameter,
/// an input no caller can produce, and the "counterexample" that comes with it
/// proves nothing. It also matters for the canonical S5 pair --- a *lifted*
/// function does not necessarily narrow its own arguments the way
/// [`crate::csource::lower`]'s prologue does, so the two sides would disagree on
/// the upper half of a register that the ABI leaves undefined.
///
/// Returns the symbol ids paired with their slots, in parameter order, so a
/// model can be read back as an argument vector.
pub(super) fn seed_inputs<'a>(
    sym: &mut Symbolic,
    io: &'a IoSpec,
) -> (Vec<(u32, &'a super::InputSlot)>, Vec<(VReg, ExprId)>) {
    let mut symbols = Vec::new();
    let mut seeds = Vec::new();
    for slot in &io.inputs {
        let raw = sym.fresh(slot.width);
        let id = match sym.pool.get(raw) {
            Expr::Sym { id, .. } => *id,
            other => unreachable!("fresh_symbol returned {other:?}"),
        };
        let widened = if slot.signed {
            sym.sext(&raw, slot.width, Width::W64)
        } else {
            sym.zext(&raw, slot.width, Width::W64)
        };
        symbols.push((id, slot));
        seeds.push((VReg::phys(slot.reg.clone()), widened));
    }
    (symbols, seeds)
}

/// Whether every input reaches a completed path on both sides.
///
/// Asks for an input where `defined_a AND defined_b` is false. `unsat` is the
/// proof that the enumerated paths cover the whole input space, which is what
/// makes the miter's `unsat` a statement about all of it.
fn coverage(
    sym: &mut Symbolic,
    left: &Summary,
    right: &Summary,
    bounds: &Bounds,
    stats: &mut Stats,
) -> Result<bool, Unknown> {
    let both = sym.binop(BinOp::And, &left.defined, &right.defined, Width::W1);
    match ask(sym, &[(both, false)], bounds, stats)? {
        SolveResult::Unsat => Ok(true),
        SolveResult::Sat(_) => Ok(false),
        SolveResult::Unknown(reason) => Err(Unknown::Solver(reason)),
        SolveResult::NoSolver => Err(Unknown::NoSolver),
        SolveResult::Error(message) => Err(Unknown::SolverError(message)),
    }
}

/// Measure a query, then ask it --- or refuse it.
///
/// The refusal is not a nicety. `crate::symbolic::solver::pipe` spawns a solver
/// binary and waits for it with no `:timeout`, no `-T:` and no reference to
/// `check_timeout_ms`, so on a build with no in-process backend a single query
/// can run without limit. A bounded checker cannot have an unbounded step in
/// it, so the size is checked first and an over-large query becomes
/// [`Unknown::QueryTooLarge`] --- an abstention with its two numbers attached,
/// never an "equivalent".
fn ask(
    sym: &Symbolic,
    asserts: &[(ExprId, bool)],
    bounds: &Bounds,
    stats: &mut Stats,
) -> Result<SolveResult, Unknown> {
    let roots: Vec<ExprId> = asserts.iter().map(|(e, _)| *e).collect();
    let size = super::size::measure(&sym.pool, &roots);
    if !size.within(bounds) {
        return Err(Unknown::QueryTooLarge(size));
    }
    stats.solves += 1;
    Ok(solve(&sym.pool, asserts))
}

/// Fold one side's completed paths into a `(defined, value)` pair.
fn summarize(sym: &mut Symbolic, paths: &[CompletePath], result_width: Width) -> Summary {
    let mut guards: Vec<ExprId> = Vec::with_capacity(paths.len());
    let mut values: Vec<ExprId> = Vec::with_capacity(paths.len());
    for path in paths {
        guards.push(guard_expr(sym, &path.guard));
        values.push(narrow(sym, path.result, result_width));
    }

    // The chain's tail is the last path's value; every earlier path selects its
    // own under its guard. Exclusivity of the guards makes the tail's identity
    // irrelevant on any input `defined` admits.
    let mut value = *values.last().expect("callers reject an empty path set");
    for index in (0..paths.len().saturating_sub(1)).rev() {
        value = sym.ite(&guards[index], &values[index], &value, result_width);
    }

    let mut defined = guards[0];
    for guard in &guards[1..] {
        defined = sym.binop(BinOp::Or, &defined, guard, Width::W1);
    }
    Summary { defined, value }
}

/// Truncate a 64-bit result register to the declared result width.
fn narrow(sym: &mut Symbolic, value: ExprId, width: Width) -> ExprId {
    if width.bits() >= 64 {
        value
    } else {
        sym.trunc(&value, width)
    }
}

/// One path guard as a single 1-bit expression.
///
/// Each recorded decision is a value and the truthiness it must have; the
/// solver's assertion convention is "non-zero is true", so the literal is an
/// explicit comparison against zero at the value's own width. An empty guard is
/// the constant 1: a function with no symbolic branch has one path, and it is
/// reached on every input.
fn guard_expr(sym: &mut Symbolic, decisions: &[(ExprId, bool)]) -> ExprId {
    let mut acc = sym.constant(Width::W1, 1);
    for (value, bit) in decisions {
        let width = sym.pool.width_of(*value);
        let zero = sym.constant(width, 0);
        let op = if *bit { CmpOp::Ne } else { CmpOp::Eq };
        let literal = sym.cmp(op, value, &zero, width);
        acc = sym.binop(BinOp::And, &acc, &literal, Width::W1);
    }
    acc
}
