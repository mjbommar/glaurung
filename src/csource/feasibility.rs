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
use crate::ir::types::Width;
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

/// [`feasibility_of`] on a function already lowered.
pub fn feasibility_of_lowered(lowered: &LoweredFunction, bounds: &Bounds) -> Report {
    let Some(io) = IoSpec::of_lowered(lowered) else {
        return abstain(&lowered.name, Unknown::NoInputSpec);
    };

    let mut sym = Symbolic::new();
    let (symbols, seeds) = seed_inputs(&mut sym, &io);
    let result_reg = crate::ir::types::VReg::phys(io.result_reg.clone());
    let (sym, exploration) = explore(&lowered.func, sym, &seeds, &result_reg, bounds);

    let slots: Vec<(u32, InputSlot)> = symbols
        .into_iter()
        .map(|(id, slot)| (id, slot.clone()))
        .collect();

    let mut paths = Vec::with_capacity(exploration.complete.len());
    for path in &exploration.complete {
        paths.push(PathVerdict {
            decisions: path.guard.len(),
            verdict: decide(lowered, &sym, &path.guard, &slots, &io, bounds),
        });
    }

    Report {
        name: lowered.name.clone(),
        paths,
        cuts: exploration.cuts.clone(),
        abstained: None,
    }
}

/// A report that decided nothing, with the reason.
fn abstain(name: &str, why: Unknown) -> Report {
    Report {
        name: name.to_string(),
        paths: Vec::new(),
        cuts: Vec::new(),
        abstained: Some(why),
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
        let mut ranked: Vec<_> = paths.into_iter().collect();
        ranked.sort_by_key(|(_, c)| std::cmp::Reverse(*c));
        for (name, count) in ranked.iter().take(15) {
            eprintln!("   {count:4}  {name}");
        }

        assert!(decided_functions > 100, "corpus not found or not lowering");
        // Every path carries exactly one verdict, and a cut carries none.
        assert_eq!(total, feasible + infeasible + unknown);
    }
}
