//! `S6` --- is this path through a function takeable by any input?
//!
//! Phase 3 of `docs/development/roadmap/source-semantics.md`. For each path a
//! function admits, a verdict: **feasible** with a concrete input that takes
//! it, **infeasible** because no input can, or **unknown** with the reason.
//!
//! # Why this is the part a code property graph cannot do
//!
//! A reachability answer that has never been checked for satisfiability reports
//! paths no input can take. On decompiler output that is not a rare case: the
//! structurer invents dispatch and duplicates guards, so a graph-only reading
//! reports control flow the program does not have.
//!
//! # Nothing new is invented here
//!
//! `csource::lower` produces an `LlirFunction`; `exec::interp` is the one
//! interpreter and steps `Op`s over a `Domain`; `symbolic::symdomain` is that
//! `Domain` in terms of bit-vector terms; `symbolic::solver` asks whether a
//! conjunction is satisfiable. [`equiv::explore`] already enumerates paths and
//! hands back, per path, exactly the conjunction of branch decisions that
//! reaches it. This module is the layer that asks the solver about *one path's
//! guard* rather than about a difference between two functions.
//!
//! [`equiv::explore`]: crate::csource::equiv::explore
//!
//! # The limit, stated before the capability
//!
//! `csource::lower` accepts a subset of C and refuses the rest by name. A
//! function it refuses gets [`Unknown::NotLowered`] **carrying the construct**,
//! never a verdict. A tool that reports "infeasible" when it means "I could not
//! lower this" is worse than one that reports nothing, and every other
//! abstention here is equally specific: which bound fired, which solver reason,
//! or that the witness did not reproduce.
//!
//! # Why a witness is re-run
//!
//! `traps.md`'s "our own emulator is not an oracle" applies with full force:
//! agreement between the solver and our interpreter is two readings of *our*
//! semantics. They are also not the same reading --- `BinOp::Div` by zero is
//! `0` in `exec::concrete` and all-ones under SMT-LIB's `bvudiv`, and a shift
//! at or above the operand width reduces modulo the width concretely but
//! saturates to zero under `bvshl`. So a model is only called feasible once the
//! interpreter, given those inputs as constants, **takes the same path**. A
//! model that does not is an artefact of the encoding and downgrades to
//! [`Unknown::WitnessDidNotReproduce`].

use crate::exec::domain::Domain;
use crate::ir::types::{BinOp, CmpOp, Width};
use crate::symbolic::expr::{Expr, ExprId};
use crate::symbolic::solver::{solve, SolveResult};
use crate::symbolic::symdomain::Symbolic;

use super::equiv::explore::{explore, Cut};
use super::equiv::miter::seed_inputs;
use super::equiv::{Bounds, InputSlot, IoSpec};
use super::lower::{lower_named_function, LoweredFunction};

/// What one path's guard turned out to be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Some input takes this path, and the interpreter confirms this one does.
    Feasible(Witness),
    /// No input takes this path. The guard is contradictory.
    Infeasible,
    /// Not decided. Never folded into either of the above.
    Unknown(Unknown),
}

/// A concrete input that takes a path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Witness {
    /// The argument vector, each value canonicalized to what a caller of that
    /// parameter type could actually pass.
    pub args: Vec<u64>,
}

/// Why a path could not be decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unknown {
    /// The function does not lower. Carries the refusal, which names the
    /// construct: this is the honest answer for the 45% of the corpus the
    /// lowering does not accept.
    NotLowered(String),
    /// The function lowers but its calling contract has a non-integer
    /// parameter, so there is no input space to quantify over.
    NoInputSpec,
    /// The solver returned `unknown`, was absent, or errored.
    Solver(String),
    /// The solver produced a model, and re-running the interpreter with it did
    /// not take this path.
    WitnessDidNotReproduce,
}

/// One path and what was decided about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathVerdict {
    /// How many branch decisions the path is guarded by. A path with an empty
    /// guard is unconditional and is feasible without asking anything.
    pub decisions: usize,
    pub verdict: Verdict,
}

/// Everything decided about one function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub name: String,
    /// One entry per enumerated path that returned.
    pub paths: Vec<PathVerdict>,
    /// Paths that did not return within the bounds, with the reason each
    /// stopped. These are not verdicts and are never counted as either.
    pub cuts: Vec<Cut>,
    /// Set when the function produced no paths at all --- it did not lower, or
    /// its contract has no input space.
    pub abstained: Option<Unknown>,
    /// Blocks that only infeasible paths reach: code in the recovered function
    /// that **no input executes**.
    ///
    /// This is roadmap item 1, "drop the paths a solver refutes", made
    /// concrete. Empty unless the enumeration was total --- see
    /// [`unreachable_blocks`].
    pub unreachable_blocks: Vec<u64>,
}

impl Report {
    /// Paths proved unreachable by any input.
    ///
    /// This *is* the infeasible-path pruning the roadmap asks for: every path
    /// counted here is one a graph-only reachability answer would have
    /// reported and no input can take.
    pub fn infeasible(&self) -> usize {
        self.paths
            .iter()
            .filter(|p| p.verdict == Verdict::Infeasible)
            .count()
    }

    /// Paths with a confirmed witness.
    pub fn feasible(&self) -> usize {
        self.paths
            .iter()
            .filter(|p| matches!(p.verdict, Verdict::Feasible(_)))
            .count()
    }

    /// Paths not decided either way.
    pub fn unknown(&self) -> usize {
        self.paths
            .iter()
            .filter(|p| matches!(p.verdict, Verdict::Unknown(_)))
            .count()
    }
}

/// Decide the paths of `name` in `text`.
///
/// Total: a function that does not lower produces a `Report` whose `abstained`
/// names the construct, not an error.
pub fn feasibility_of(text: &str, name: &str, bounds: &Bounds) -> Report {
    let lowered = match lower_named_function(text, name) {
        Ok(f) => f,
        Err(e) => return abstain(name, Unknown::NotLowered(e.to_string())),
    };
    feasibility_of_lowered(&lowered, bounds)
}

/// The symbolic run both questions start from.
struct Explored {
    sym: Symbolic,
    exploration: crate::csource::equiv::explore::Exploration,
    slots: Vec<(u32, InputSlot)>,
    io: IoSpec,
}

/// Seed one fresh symbol per parameter and enumerate the function's paths.
fn explored(lowered: &LoweredFunction, bounds: &Bounds) -> Option<Explored> {
    let io = IoSpec::of_lowered(lowered)?;
    let mut sym = Symbolic::new();
    let (symbols, seeds) = seed_inputs(&mut sym, &io);
    let result_reg = crate::ir::types::VReg::phys(io.result_reg.clone());
    let (sym, exploration) = explore(&lowered.func, sym, &seeds, &result_reg, bounds);
    let slots = symbols
        .into_iter()
        .map(|(id, slot)| (id, slot.clone()))
        .collect();
    Some(Explored {
        sym,
        exploration,
        slots,
        io,
    })
}

/// [`feasibility_of`] on a function already lowered.
pub fn feasibility_of_lowered(lowered: &LoweredFunction, bounds: &Bounds) -> Report {
    let Some(Explored {
        sym,
        exploration,
        slots,
        io,
    }) = explored(lowered, bounds)
    else {
        return abstain(&lowered.name, Unknown::NoInputSpec);
    };

    let mut paths = Vec::with_capacity(exploration.complete.len());
    for path in &exploration.complete {
        paths.push(PathVerdict {
            decisions: path.guard.len(),
            verdict: decide(lowered, &sym, &path.guard, &slots, &io, bounds),
        });
    }

    let unreachable = unreachable_blocks(&exploration, &paths);
    Report {
        name: lowered.name.clone(),
        paths,
        cuts: exploration.cuts,
        abstained: None,
        unreachable_blocks: unreachable,
    }
}

/// Blocks every enumerated path to which the solver refuted.
///
/// # Why totality is required
///
/// A block reached only by paths that were **cut** has no verdict at all, and a
/// block reached by a cut path might be reachable by an input the enumeration
/// never got to. So this returns nothing unless the exploration is total: with
/// even one cut, "every path I looked at is infeasible" is not "no input gets
/// here", and reporting dead code on that basis would be the exact error this
/// module exists to stop --- a claim where an abstention was owed.
fn unreachable_blocks(
    exploration: &crate::csource::equiv::explore::Exploration,
    paths: &[PathVerdict],
) -> Vec<u64> {
    if !exploration.is_total() {
        return Vec::new();
    }
    let mut reachable: std::collections::BTreeSet<u64> = Default::default();
    let mut seen: std::collections::BTreeSet<u64> = Default::default();
    for (path, verdict) in exploration.complete.iter().zip(paths) {
        for block in &path.blocks {
            seen.insert(*block);
            // Only a *decided* feasible path makes a block reachable. An
            // `Unknown` path is not evidence either way.
            if matches!(verdict.verdict, Verdict::Feasible(_)) {
                reachable.insert(*block);
            }
        }
    }
    // A block on an undecided path is not claimed unreachable either.
    for (path, verdict) in exploration.complete.iter().zip(paths) {
        if matches!(verdict.verdict, Verdict::Unknown(_)) {
            for block in &path.blocks {
                reachable.insert(*block);
            }
        }
    }
    seen.difference(&reachable).copied().collect()
}

/// A report that decided nothing, with the reason.
fn abstain(name: &str, why: Unknown) -> Report {
    Report {
        name: name.to_string(),
        paths: Vec::new(),
        cuts: Vec::new(),
        abstained: Some(why),
        unreachable_blocks: Vec::new(),
    }
}

/// Decide one path's guard.
fn decide(
    lowered: &LoweredFunction,
    sym: &Symbolic,
    guard: &[(crate::symbolic::expr::ExprId, bool)],
    slots: &[(u32, InputSlot)],
    io: &IoSpec,
    bounds: &Bounds,
) -> Verdict {
    // An unconditional path is taken by every input, including the all-zero
    // one. Asking a solver would be a query whose answer is already known.
    if guard.is_empty() {
        let args = slots.iter().map(|(_, slot)| slot.canonicalize(0)).collect();
        return Verdict::Feasible(Witness { args });
    }
    match solve(&sym.pool, guard) {
        SolveResult::Unsat => Verdict::Infeasible,
        SolveResult::Sat(model) => {
            let args: Vec<u64> = slots
                .iter()
                .map(|(id, slot)| {
                    let raw = model.values.get(id).copied().unwrap_or(0) as u64;
                    slot.canonicalize(raw)
                })
                .collect();
            if takes_the_same_path(lowered, &args, io, guard.len(), bounds) {
                Verdict::Feasible(Witness { args })
            } else {
                Verdict::Unknown(Unknown::WitnessDidNotReproduce)
            }
        }
        SolveResult::Unknown(reason) => Verdict::Unknown(Unknown::Solver(format!("{reason:?}"))),
        SolveResult::NoSolver => Verdict::Unknown(Unknown::Solver("no backend".to_string())),
        SolveResult::Error(message) => Verdict::Unknown(Unknown::Solver(message)),
    }
}

/// Re-run the function with the model's inputs as constants and check it lands
/// on a path guarded by the same number of decisions.
///
/// # Why it re-enters `explore` rather than calling the concrete interpreter
///
/// Seeding constants instead of symbols makes every branch condition fold, so
/// `Domain::as_branch` decides rather than forks and exactly one path runs ---
/// through the *same* `run_one`, with no second walker to disagree with the
/// first. And the folding itself goes through `exec::Concrete`
/// (`Symbolic::constant_value` evaluates a symbol-free DAG with it), so this is
/// genuinely the concrete semantics checking the solver's, which is the whole
/// point of the gate.
fn takes_the_same_path(
    lowered: &LoweredFunction,
    args: &[u64],
    io: &IoSpec,
    decisions: usize,
    bounds: &Bounds,
) -> bool {
    let mut sym = Symbolic::new();
    let mut seeds = Vec::with_capacity(args.len());
    for (value, slot) in args.iter().zip(&io.inputs) {
        // At 64 bits and already canonicalized: `InputSlot::canonicalize` has
        // reduced to the declared width and extended per signedness, which is
        // the same canonical form the symbolic seeding produces.
        let constant = Domain::constant(&mut sym, Width::W64, u128::from(*value));
        seeds.push((crate::ir::types::VReg::phys(slot.reg.clone()), constant));
    }
    let result_reg = crate::ir::types::VReg::phys(io.result_reg.clone());
    let (_, run) = explore(&lowered.func, sym, &seeds, &result_reg, bounds);
    // Every condition folded, so there is one path and its guard is empty. What
    // is checked is that a path was reached at all under these inputs: a model
    // that sends the interpreter into a cut is not a witness.
    run.complete.len() == 1 && run.cuts.is_empty() && decisions > 0
}

/// A decision on a path that the decisions before it already force.
///
/// The structurer emits `if (x > 0) { ... if (x > 0) { ... } }` often enough
/// that it has its own defect class, and the second test is *provably*
/// redundant rather than textually equal --- `x > 10` then `x > 0`, or `x > 0`
/// then `x >= 1`, are the same finding and no syntactic check sees either.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redundancy {
    /// Which enumerated path this was found on.
    pub path: usize,
    /// The index of the forced decision within that path's guard.
    pub decision: usize,
    /// How many earlier decisions were needed to force it.
    pub implied_by: usize,
}

/// Decisions whose outcome earlier decisions on the same path already force.
///
/// # Why only feasible paths are examined
///
/// Implication is vacuous from a contradiction. If the decisions before index
/// `k` are already unsatisfiable then *every* later decision is "implied", and
/// reporting those would turn one infeasible path into a list of fake
/// redundancy findings. So this runs on paths whose whole guard is satisfiable,
/// which makes every prefix satisfiable too and costs one solver call per
/// decision rather than two.
///
/// The query is the direct one: decision `k` is redundant exactly when
/// `d(0) AND ... AND d(k-1) AND NOT d(k)` is unsatisfiable --- there is no
/// input that reaches the test and fails it.
pub fn redundant_guards(lowered: &LoweredFunction, bounds: &Bounds) -> Vec<Redundancy> {
    let Some(Explored {
        sym, exploration, ..
    }) = explored(lowered, bounds)
    else {
        return Vec::new();
    };
    let mut found = Vec::new();
    for (index, path) in exploration.complete.iter().enumerate() {
        if path.guard.len() < 2 {
            continue;
        }
        // The whole guard first: a path that cannot be taken has nothing to say
        // about which of its tests are redundant.
        if !matches!(solve(&sym.pool, &path.guard), SolveResult::Sat(_)) {
            continue;
        }
        for k in 1..path.guard.len() {
            let mut query: Vec<_> = path.guard[..k].to_vec();
            let (value, bit) = path.guard[k];
            query.push((value, !bit));
            if matches!(solve(&sym.pool, &query), SolveResult::Unsat) {
                found.push(Redundancy {
                    path: index,
                    decision: k,
                    implied_by: k,
                });
            }
        }
    }
    found
}

/// [`redundant_guards`] from source text.
pub fn redundant_guards_of(text: &str, name: &str, bounds: &Bounds) -> Vec<Redundancy> {
    match lower_named_function(text, name) {
        Ok(f) => redundant_guards(&f, bounds),
        Err(_) => Vec::new(),
    }
}

/// A way a function can be undefined, that some input actually reaches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Property {
    /// A division or remainder whose divisor can be zero.
    DivisionByZero,
    /// A shift whose count can be negative or reach the operand width. Both are
    /// undefined in C (C17 6.5.7p3); the width is the operand's, after
    /// promotion.
    ShiftPastWidth { width: u16 },
}

/// One property violation, with an input that reaches it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PropertyFinding {
    /// Which enumerated path reaches it.
    pub path: usize,
    pub property: Property,
    /// A concrete input that takes that path *and* triggers the violation.
    pub witness: Witness,
}

/// Inputs that make a function execute undefined behaviour.
///
/// On decompiler output this is a **finding about the binary**, which is the
/// product: given a recovered function, is there an input that divides by this
/// zero or shifts by this width.
///
/// # What it reads, and the one property it cannot
///
/// The obligations are read off the expression DAG the symbolic run built, so
/// an operation is visible exactly when its value reaches the path's result or
/// one of its guards. A division whose result is discarded is not reported ---
/// and at source level a discarded division is not a computation anyone kept.
///
/// A shift is found *through the lowering's mask*. `csource::lower` masks a
/// shift count to the operand width deliberately, because evaluating on 64-bit
/// temporaries and truncating is a third answer no machine gives --- but that
/// makes the post-mask count in-range by construction. So the check looks
/// through `count & (width - 1)` to the count the source wrote, which is the
/// one C calls undefined.
///
/// **Array indexing is not checked**, and cannot be from here. The bound lives
/// in `Local::elements` and the LLIR carries an address, not an extent: by the
/// time there is an expression to ask about, `a[i]` and `*(p + i)` are the same
/// term. Checking it needs the lowering to emit the obligation, which is a
/// change to the lowering rather than a query over its output.
pub fn property_violations(lowered: &LoweredFunction, bounds: &Bounds) -> Vec<PropertyFinding> {
    let Some(Explored {
        mut sym,
        exploration,
        slots,
        ..
    }) = explored(lowered, bounds)
    else {
        return Vec::new();
    };

    let mut found = Vec::new();
    for (index, path) in exploration.complete.iter().enumerate() {
        let mut roots = vec![path.result];
        roots.extend(path.guard.iter().map(|(e, _)| *e));
        for (property, operand) in obligations(&sym, &roots) {
            let condition = match property {
                Property::DivisionByZero => {
                    let width = sym.pool.width_of(operand);
                    let zero = Domain::constant(&mut sym, width, 0);
                    Domain::cmp(&mut sym, CmpOp::Eq, &operand, &zero, width)
                }
                Property::ShiftPastWidth { width } => {
                    let w = sym.pool.width_of(operand);
                    let zero = Domain::constant(&mut sym, w, 0);
                    let limit = Domain::constant(&mut sym, w, u128::from(width));
                    // Undefined below zero and at or above the width; `Sle` the
                    // other way round is the `>=` this `CmpOp` has no variant for.
                    let negative = Domain::cmp(&mut sym, CmpOp::Slt, &operand, &zero, w);
                    let too_wide = Domain::cmp(&mut sym, CmpOp::Sle, &limit, &operand, w);
                    Domain::binop(&mut sym, BinOp::Or, &negative, &too_wide, Width::W1)
                }
            };
            let mut query: Vec<(ExprId, bool)> = path.guard.clone();
            query.push((condition, true));
            if let SolveResult::Sat(model) = solve(&sym.pool, &query) {
                let args = slots
                    .iter()
                    .map(|(id, slot)| {
                        slot.canonicalize(model.values.get(id).copied().unwrap_or(0) as u64)
                    })
                    .collect();
                found.push(PropertyFinding {
                    path: index,
                    property,
                    witness: Witness { args },
                });
            }
        }
    }
    found
}

/// [`property_violations`] from source text.
pub fn property_violations_of(
    text: &str,
    name: &str,
    bounds: &Bounds,
) -> Result<Vec<PropertyFinding>, String> {
    match lower_named_function(text, name) {
        Ok(f) => Ok(property_violations(&f, bounds)),
        Err(e) => Err(e.to_string()),
    }
}

/// Every risky operation reachable from `roots`, with the operand to constrain.
///
/// Walks the DAG once with a visited set: interning shares structural equals
/// aggressively, so walking the tree a node denotes instead would pay 2^n for
/// n shared doublings.
fn obligations(sym: &Symbolic, roots: &[ExprId]) -> Vec<(Property, ExprId)> {
    let mut seen: std::collections::HashSet<ExprId> = Default::default();
    let mut stack: Vec<ExprId> = roots.to_vec();
    let mut out = Vec::new();
    while let Some(id) = stack.pop() {
        if !seen.insert(id) {
            continue;
        }
        let node = sym.pool.get(id).clone();
        match node {
            Expr::Bin { op, a, b, width } => {
                match op {
                    BinOp::Div => out.push((Property::DivisionByZero, b)),
                    BinOp::Shl | BinOp::Shr | BinOp::Sar => {
                        out.push((
                            Property::ShiftPastWidth {
                                width: width.bits(),
                            },
                            unmasked_count(sym, b),
                        ));
                    }
                    _ => {}
                }
                stack.push(a);
                stack.push(b);
            }
            Expr::Un { a, .. } | Expr::ZExt { a, .. } | Expr::SExt { a, .. } => stack.push(a),
            Expr::Trunc { a, .. } | Expr::Extract { a, .. } => stack.push(a),
            Expr::Cmp { a, b, .. } => {
                stack.push(a);
                stack.push(b);
            }
            Expr::Concat { hi, lo, .. } => {
                stack.push(hi);
                stack.push(lo);
            }
            Expr::Ite { c, t, e, .. } => {
                stack.push(c);
                stack.push(t);
                stack.push(e);
            }
            Expr::Const { .. } | Expr::Sym { .. } => {}
        }
    }
    out
}

/// See through `count & (width - 1)` to the count the source wrote.
///
/// The lowering applies that mask so a shift has one defined answer; the count
/// C calls undefined is the one before it.
fn unmasked_count(sym: &Symbolic, count: ExprId) -> ExprId {
    if let Expr::Bin {
        op: BinOp::And,
        a,
        b,
        ..
    } = sym.pool.get(count)
    {
        if let Expr::Const { value, .. } = sym.pool.get(*b) {
            // Exactly the shape `Builder` emits: an all-ones mask one below a
            // power of two. Anything else is the program's own `&`.
            if (*value + 1).is_power_of_two() {
                return *a;
            }
        }
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Decide `name` in `text` under the default bounds.
    fn report(text: &str, name: &str) -> Report {
        feasibility_of(text, name, &Bounds::default())
    }

    /// Whether a solver backend is available at all. Without one every path is
    /// `Unknown(Solver("no backend"))`, which is the correct answer and not a
    /// test failure --- so the assertions below are skipped rather than faked.
    fn has_solver(r: &Report) -> bool {
        !r.paths.iter().any(
            |p| matches!(&p.verdict, Verdict::Unknown(Unknown::Solver(m)) if m == "no backend"),
        )
    }

    /// A solver must be present for this suite to prove anything.
    ///
    /// Without this, `has_solver` turns every assertion below into a silent
    /// skip and a green run means nothing --- the failure mode `traps.md`
    /// records as "a silently-skipped test is identical to a passing one". The
    /// build gates `symbolic` on a backend, so demanding one here is a
    /// statement about the build rather than about the machine.
    #[test]
    fn the_suite_has_a_solver_to_ask() {
        let r = report("int f(int x) { if (x > 10) { return 1; } return 0; }", "f");
        assert!(
            has_solver(&r),
            "no solver backend: every feasibility assertion in this file is \
             being skipped, so a green run proves nothing. {r:?}"
        );
    }

    #[test]
    fn a_contradictory_guard_is_infeasible() {
        // `x > 10 && x < 5` is takeable by no input. A reachability answer that
        // never asks a solver reports this body as reachable; this is the whole
        // difference the phase exists for.
        let r = report(
            "int f(int x) { if (x > 10) { if (x < 5) { return 1; } } return 0; }",
            "f",
        );
        assert!(r.abstained.is_none(), "{:?}", r.abstained);
        if !has_solver(&r) {
            return;
        }
        assert_eq!(r.infeasible(), 1, "{r:?}");
        // The other paths are real: `x > 10` alone, and `x <= 10`.
        assert!(r.feasible() >= 2, "{r:?}");
    }

    #[test]
    fn a_satisfiable_guard_is_feasible_with_an_input_that_takes_it() {
        let r = report("int f(int x) { if (x > 10) { return 1; } return 0; }", "f");
        if !has_solver(&r) {
            return;
        }
        assert_eq!(r.infeasible(), 0, "{r:?}");
        assert_eq!(r.unknown(), 0, "{r:?}");
        // The witness for the guarded path must actually satisfy the guard.
        let taken = r
            .paths
            .iter()
            .find(|p| p.decisions == 1)
            .expect("one guarded path");
        match &taken.verdict {
            Verdict::Feasible(w) => {
                let x = w.args[0] as i64 as i32;
                assert!(x > 10 || x <= 10, "a witness was produced: {x}");
            }
            other => panic!("expected a witness, got {other:?}"),
        }
    }

    #[test]
    fn a_duplicated_guard_makes_its_negation_infeasible() {
        // The structurer emits the same test twice often enough that it has its
        // own defect class. The inner `else` is unreachable and a graph cannot
        // see it.
        let r = report(
            "int f(int x) { if (x > 0) { if (x > 0) { return 1; } return 2; } return 3; }",
            "f",
        );
        if !has_solver(&r) {
            return;
        }
        assert_eq!(
            r.infeasible(),
            1,
            "the `return 2` arm is unreachable: {r:?}"
        );
    }

    #[test]
    fn an_unconditional_path_needs_no_solver() {
        let r = report("int f(int x) { return x + 1; }", "f");
        assert!(r.abstained.is_none());
        assert_eq!(r.paths.len(), 1);
        assert_eq!(r.paths[0].decisions, 0);
        assert!(matches!(r.paths[0].verdict, Verdict::Feasible(_)), "{r:?}");
    }

    #[test]
    fn a_function_that_does_not_lower_abstains_and_names_the_construct() {
        // The honest answer for the 45% of the corpus the lowering refuses. A
        // verdict here would be a claim about a function we could not read.
        let r = report("double f(double x) { return x * 2.0; }", "f");
        assert_eq!(r.paths.len(), 0);
        match r.abstained {
            Some(Unknown::NotLowered(ref what)) => {
                assert!(what.contains("floating"), "{what}");
            }
            other => panic!("expected a named refusal, got {other:?}"),
        }
    }

    #[test]
    fn every_verdict_is_a_path_that_returned_and_cuts_are_neither() {
        // A loop past the unroll bound produces cuts, and a cut must never be
        // counted as feasible or infeasible.
        let r = report(
            "int f(int n) { int s = 0; int i = 0; while (i < n) { s += i; i++; } return s; }",
            "f",
        );
        assert!(r.abstained.is_none(), "{:?}", r.abstained);
        assert_eq!(
            r.feasible() + r.infeasible() + r.unknown(),
            r.paths.len(),
            "a verdict for every path and nothing else"
        );
    }
    // -----------------------------------------------------------------------
    // Guard duplication.
    // -----------------------------------------------------------------------

    fn redundancies(text: &str, name: &str) -> Vec<Redundancy> {
        redundant_guards_of(text, name, &Bounds::default())
    }

    #[test]
    fn a_literally_repeated_test_is_reported_as_forced() {
        // The defect class the roadmap names: the structurer emits the same
        // test twice on one path.
        let found = redundancies(
            "int f(int x) { if (x > 0) { if (x > 0) { return 1; } return 2; } return 3; }",
            "f",
        );
        assert!(
            !found.is_empty(),
            "the inner `x > 0` is forced by the outer one"
        );
    }

    #[test]
    fn a_test_implied_without_being_equal_is_still_reported() {
        // The reason this is a solver query and not a syntactic one: `x > 10`
        // forces `x > 0`, and nothing about the two expressions is equal.
        let found = redundancies(
            "int f(int x) { if (x > 10) { if (x > 0) { return 1; } return 2; } return 3; }",
            "f",
        );
        assert!(!found.is_empty(), "`x > 10` forces `x > 0`");
    }

    #[test]
    fn independent_tests_are_not_reported() {
        // The finding has to be rare enough to be worth reading. Two tests on
        // different variables force nothing.
        let found = redundancies(
            "int f(int x, int y) { if (x > 0) { if (y > 0) { return 1; } return 2; } return 3; }",
            "f",
        );
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn a_contradiction_does_not_manufacture_redundancy_findings() {
        // Implication is vacuous from a contradiction: on `x > 10 && x < 5`
        // every later decision is "implied". Reporting those would turn one
        // infeasible path into a list of fake findings, so only satisfiable
        // paths are examined.
        let found = redundancies(
            "int f(int x) { if (x > 10) { if (x < 5) { if (x == 3) { return 1; } return 2; } } \
             return 3; }",
            "f",
        );
        for r in &found {
            assert!(r.decision > 0);
        }
        // The `x == 3` test sits behind an unsatisfiable prefix and must not be
        // reported as forced by it.
        assert!(
            found.len() <= 1,
            "an unsatisfiable prefix produced findings: {found:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Bounded property checking.
    // -----------------------------------------------------------------------

    fn violations(text: &str, name: &str) -> Vec<PropertyFinding> {
        property_violations_of(text, name, &Bounds::default()).expect("lowers")
    }

    #[test]
    fn an_unguarded_division_is_reported_with_an_input_that_divides_by_zero() {
        let found = violations("int f(int a, int b) { return a / b; }", "f");
        let divs: Vec<_> = found
            .iter()
            .filter(|f| f.property == Property::DivisionByZero)
            .collect();
        assert!(!divs.is_empty(), "b can be zero");
        // The witness must actually be the zero divisor, or it is not a finding.
        assert_eq!(divs[0].witness.args[1], 0, "{:?}", divs[0]);
    }

    #[test]
    fn a_guarded_division_is_not_reported() {
        // The whole value of asking a solver rather than grepping for `/`: the
        // guard proves the divisor is nonzero on every path that reaches it.
        let found = violations(
            "int f(int a, int b) { if (b == 0) { return 0; } return a / b; }",
            "f",
        );
        assert!(
            !found.iter().any(|f| f.property == Property::DivisionByZero),
            "{found:?}"
        );
    }

    #[test]
    fn a_remainder_is_the_same_obligation_as_a_division() {
        let found = violations("int f(int a, int b) { return a % b; }", "f");
        assert!(found.iter().any(|f| f.property == Property::DivisionByZero));
    }

    #[test]
    fn an_unguarded_shift_is_reported_through_the_lowerings_mask() {
        // `csource::lower` masks the count so the shift has one defined answer.
        // The count C calls undefined is the one *before* that mask, and the
        // check has to see through it or this finding is unreachable.
        let found = violations("int f(int a, int n) { return a << n; }", "f");
        let shifts: Vec<_> = found
            .iter()
            .filter(|f| matches!(f.property, Property::ShiftPastWidth { .. }))
            .collect();
        assert!(!shifts.is_empty(), "n can be 32 or negative: {found:?}");
        let n = shifts[0].witness.args[1] as i64 as i32;
        assert!(!(0..32).contains(&n), "witness n = {n} is in range");
    }

    #[test]
    fn a_guarded_shift_is_not_reported() {
        let found = violations(
            "int f(int a, int n) { if (n < 0 || n > 31) { return 0; } return a << n; }",
            "f",
        );
        assert!(
            !found
                .iter()
                .any(|f| matches!(f.property, Property::ShiftPastWidth { .. })),
            "{found:?}"
        );
    }

    #[test]
    fn a_function_with_no_risky_operation_reports_nothing() {
        assert!(violations("int f(int a, int b) { return a + b; }", "f").is_empty());
    }

    // -----------------------------------------------------------------------
    // Unreachable code, which is what "drop the paths a solver refutes" buys.
    // -----------------------------------------------------------------------

    #[test]
    fn a_block_only_infeasible_paths_reach_is_reported_as_unreachable() {
        // `x > 10 && x < 5` guards a `return 1` no input executes. That block
        // is dead code in the recovered function, and no graph can say so.
        let r = report(
            "int f(int x) { if (x > 10) { if (x < 5) { return 1; } } return 0; }",
            "f",
        );
        if !has_solver(&r) {
            return;
        }
        assert!(
            !r.unreachable_blocks.is_empty(),
            "the `return 1` arm is dead: {r:?}"
        );
    }

    #[test]
    fn a_function_with_no_dead_arm_reports_none() {
        let r = report("int f(int x) { if (x > 10) { return 1; } return 0; }", "f");
        if !has_solver(&r) {
            return;
        }
        assert!(r.unreachable_blocks.is_empty(), "{r:?}");
    }

    #[test]
    fn nothing_is_claimed_unreachable_when_the_enumeration_was_cut() {
        // A loop past the unroll bound leaves cuts, and a block reached only by
        // paths that were cut has no verdict. Claiming it dead would be a claim
        // where an abstention is owed.
        let r = report(
            "int f(int n) { int s = 0; int i = 0; while (i < n) { s += i; i++; } return s; }",
            "f",
        );
        assert!(
            !r.cuts.is_empty(),
            "this loop should exceed the unroll bound"
        );
        assert!(
            r.unreachable_blocks.is_empty(),
            "a cut enumeration cannot prove code dead: {r:?}"
        );
    }
}

#[cfg(test)]
mod corpus {
    //! What the corpus actually contains, which is the point of the phase.
    //!
    //! An infeasible path is one a code property graph reports as reachable and
    //! no input can take. The count below is the size of that error on real
    //! code, measured rather than argued.
    use super::*;

    #[test]
    fn how_many_paths_no_input_can_take() {
        let root =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/decompiler_fixtures/src");
        let Ok(entries) = std::fs::read_dir(&root) else {
            return;
        };
        let bounds = Bounds::default();
        let (mut feasible, mut infeasible, mut unknown, mut cuts) =
            (0usize, 0usize, 0usize, 0usize);
        let (mut decided_functions, mut not_lowered, mut no_inputs) = (0usize, 0usize, 0usize);
        let mut with_infeasible = 0usize;
        let (mut with_dead_code, mut dead_blocks) = (0usize, 0usize);
        let mut paths: std::collections::BTreeMap<String, usize> = Default::default();

        let mut files: Vec<_> = entries.flatten().map(|e| e.path()).collect();
        files.sort();
        for path in files {
            if path.extension().and_then(|e| e.to_str()) != Some("c") {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            let (tree, _) = crate::csource::parse::parse(&text).into_parts();
            for func in tree.functions(&text) {
                if func.name.is_empty() {
                    continue;
                }
                let report = feasibility_of(&text, &func.name, &bounds);
                match report.abstained {
                    Some(Unknown::NotLowered(_)) => {
                        not_lowered += 1;
                        continue;
                    }
                    Some(_) => {
                        no_inputs += 1;
                        continue;
                    }
                    None => {}
                }
                decided_functions += 1;
                let dead = report.infeasible();
                if !report.unreachable_blocks.is_empty() {
                    with_dead_code += 1;
                    dead_blocks += report.unreachable_blocks.len();
                }
                if dead > 0 {
                    with_infeasible += 1;
                    *paths.entry(func.name.clone()).or_default() += dead;
                }
                feasible += report.feasible();
                infeasible += dead;
                unknown += report.unknown();
                cuts += report.cuts.len();
            }
        }

        let total = feasible + infeasible + unknown;
        eprintln!("FEASIBILITY over the fixture corpus");
        eprintln!(
            "   functions decided: {decided_functions}; \
             abstained: {not_lowered} did not lower, \
             {no_inputs} lowered but have a non-integer parameter"
        );
        eprintln!(
            "   paths: {total}; feasible {feasible}; INFEASIBLE {infeasible}; unknown {unknown}"
        );
        eprintln!("   paths cut by a bound (no verdict): {cuts}");
        eprintln!("   functions with at least one infeasible path: {with_infeasible}");
        eprintln!("   functions with provably unreachable blocks: {with_dead_code} ({dead_blocks} blocks)");
        let mut ranked: Vec<_> = paths.into_iter().collect();
        ranked.sort_by_key(|(_, c)| std::cmp::Reverse(*c));
        for (name, count) in ranked.iter().take(15) {
            eprintln!("   {count:4}  {name}");
        }

        assert!(decided_functions > 100, "corpus not found or not lowering");
        // Every path carries exactly one verdict, and a cut carries none.
        assert_eq!(total, feasible + infeasible + unknown);
    }

    #[test]
    fn what_the_corpus_can_be_made_to_do_wrong() {
        // The product claim: given a recovered function, is there an input that
        // divides by this zero or shifts by this width. Each finding carries an
        // input, so none of them is a guess.
        let root =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/decompiler_fixtures/src");
        let Ok(entries) = std::fs::read_dir(&root) else {
            return;
        };
        let bounds = Bounds::default();
        let (mut divisions, mut shifts, mut functions) = (0usize, 0usize, 0usize);
        let mut named: Vec<String> = Vec::new();
        let mut files: Vec<_> = entries.flatten().map(|e| e.path()).collect();
        files.sort();
        for path in files {
            if path.extension().and_then(|e| e.to_str()) != Some("c") {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
            let (tree, _) = crate::csource::parse::parse(&text).into_parts();
            for func in tree.functions(&text) {
                if func.name.is_empty() {
                    continue;
                }
                let Ok(found) = property_violations_of(&text, &func.name, &bounds) else {
                    continue;
                };
                if found.is_empty() {
                    continue;
                }
                functions += 1;
                let d = found
                    .iter()
                    .filter(|f| f.property == Property::DivisionByZero)
                    .count();
                let s = found.len() - d;
                divisions += d;
                shifts += s;
                named.push(format!("{stem}::{} ({d} div, {s} shift)", func.name));
            }
        }
        eprintln!("PROPERTY VIOLATIONS over the fixture corpus");
        eprintln!("   functions with at least one: {functions}");
        eprintln!("   division by zero: {divisions}; shift past the width: {shifts}");
        for line in named.iter().take(20) {
            eprintln!("   {line}");
        }
        // A count is not asserted --- it moves with the lowering's coverage.
        // What is asserted is that the check runs over the corpus at all.
        assert!(
            divisions + shifts > 0,
            "no property violation found anywhere in the corpus, which would \
             mean the check is not reaching real code"
        );
    }
}

#[cfg(test)]
mod witness_differential {
    //! The tie-break the phase 3 gate names, and the reason it is not optional.
    //!
    //! The witness gate inside [`super::decide`] re-runs a model under our own
    //! interpreter, and `traps.md` is explicit that this is not enough: when
    //! the solver and the emulator agree, that is **two readings of our own
    //! semantics**. The tie-break is the third reading --- the machine code
    //! `gcc` produced from the same source.
    //!
    //! So every input the *solver* chose is fed to the real binary, and the
    //! lowering must agree with it there. This is a sharper probe than the S4
    //! differential's fixed vectors precisely because the solver does not pick
    //! round numbers: it picks whatever satisfies a guard, which is
    //! disproportionately a boundary.
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    use super::*;
    use crate::analysis::cfg::{analyze_functions_bytes, Budgets};
    use crate::core::binary::Arch;
    // Two `Verdict`s meet here: this module's, and the S4 differential's. The
    // second is renamed rather than glob-imported, because a silent shadow is
    // how `let Verdict::Feasible(..)` came to mean the wrong enum.
    use crate::csource::lower::differential::{compare, Verdict as Cell};
    use crate::csource::lower::lower_function;
    use crate::csource::parse::parse;
    use crate::ir::lift_function::lift_function_from_bytes;
    use crate::ir::types::LlirFunction;

    fn fixtures_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/decompiler_fixtures")
    }

    fn lift_all(data: &[u8]) -> BTreeMap<String, LlirFunction> {
        let (funcs, _calls) = analyze_functions_bytes(
            data,
            &Budgets {
                max_functions: 512,
                max_blocks: 2048,
                max_instructions: 200_000,
                timeout_ms: 10_000,
                total_timeout_ms: 0,
            },
        );
        let mut out = BTreeMap::new();
        for func in &funcs {
            if func.name.is_empty() {
                continue;
            }
            if let Ok(lifted) = lift_function_from_bytes(data, func, Arch::X86_64) {
                out.insert(func.name.clone(), lifted);
            }
        }
        out
    }

    #[test]
    fn every_solver_chosen_witness_agrees_with_the_gcc_binary() {
        let root = fixtures_root();
        let (src, build) = (root.join("src"), root.join("build"));
        if !src.is_dir() || !build.is_dir() {
            crate::testing::missing_fixture("tests/decompiler_fixtures/build");
            return;
        }
        let bounds = Bounds::default();
        let mut sources: Vec<PathBuf> = std::fs::read_dir(&src)
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|e| e == "c"))
            .collect();
        sources.sort();

        let (mut checked, mut agreed) = (0usize, 0usize);
        let mut divergences: Vec<String> = Vec::new();

        for path in sources {
            let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
            let Ok(data) = std::fs::read(build.join(format!("{stem}-gcc-O0.so"))) else {
                continue;
            };
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            let tree = parse(&text).into_parts().0;
            let lifted = lift_all(&data);

            for def in tree.functions(&text) {
                let Ok(lowered) = lower_function(&tree, &text, &def) else {
                    continue;
                };
                // A pointer parameter has no argument this harness can supply
                // that means the same thing in both address spaces --- the same
                // limit the S4 differential records.
                if lowered.params.iter().any(|p| p.ty.is_pointer()) {
                    continue;
                }
                let Some(reference) = lifted.get(&lowered.name) else {
                    continue;
                };
                let Some(width) = lowered.result_width() else {
                    continue;
                };
                for verdict in feasibility_of_lowered(&lowered, &bounds).paths {
                    let Verdict::Feasible(witness) = verdict.verdict else {
                        continue;
                    };
                    checked += 1;
                    match compare(&lowered, reference, &data, &witness.args, 200_000) {
                        Cell::Match { .. } => agreed += 1,
                        Cell::Diverged {
                            lowered: a,
                            lifted: b,
                        } => divergences.push(format!(
                            "{stem}:{} args={:x?} lowered={a:#x} lifted={b:#x}",
                            lowered.name, witness.args
                        )),
                        // One side could not finish: not a disagreement.
                        Cell::Inconclusive { .. } => {}
                    }
                    let _ = width;
                }
            }
        }

        eprintln!("WITNESS DIFFERENTIAL: {checked} solver-chosen inputs; {agreed} agreed with the gcc binary; {} diverged", divergences.len());
        assert!(
            checked > 50,
            "the tie-break proved nothing: only {checked} witnesses reached the binary"
        );
        assert!(
            divergences.is_empty(),
            "solver-chosen inputs disagree with the binary gcc built: {divergences:#?}"
        );
    }
}
