//! `S5` --- bounded equivalence checking between two [`LlirFunction`]s.
//!
//! Plan: `docs/design/static-c-analysis/roadmap.md` section 7. Every oracle this
//! project has today is a proxy for the question a reader of decompiled code
//! actually asks. GED compares degree sequences; `byte_match` compares assembly
//! lines after a best-effort recompile; the execution differential is blind to
//! structure. `tools/metric_mutation.py` measured the ceiling: over the ten
//! mutation classes that cannot change the CFG by construction, GED detected
//! **12 of 1,188** injected defects on sources and **0 of 2,817** on decompiled
//! output, and `src/metrics/tree_distance.rs` asserts in a test that all six
//! semantics-only classes are distance 0 for tree edit distance too. No
//! structural metric closes that gap by getting better at being structural.
//!
//! # The formulation
//!
//! Two functions, one interpreter, one expression pool.
//!
//! 1. Mint one fresh symbol per parameter, **at the parameter's declared width**
//!    and extended to 64 bits the way its signedness says (the canonical-value
//!    invariant [`crate::csource::lower`] states for every lowered value). A
//!    symbol minted at 64 bits would let the solver hand back `0x1_0000_0000`
//!    for an `int` parameter --- an input no caller can produce, and therefore a
//!    counterexample that proves nothing.
//! 2. Enumerate each side's paths under an explicit bound ([`explore`]), giving
//!    per path a guard (the conjunction of the branch decisions that reach it)
//!    and the returned value.
//! 3. Fold the paths of one side into a **summary pair**: `defined`, the
//!    disjunction of the guards of the paths that completed, and `value`, the
//!    if-then-else chain selecting each path's result under its guard. The
//!    guards come from a decision tree, so they are mutually exclusive by
//!    construction and the chain is exact rather than an approximation.
//! 4. Ask one solver query: `defined_a AND defined_b AND value_a != value_b`.
//!
//! `sat` is a counterexample; `unsat` says the two agree on every input both
//! sides completed on. Those are different claims and this module never merges
//! them --- see *Coverage* below.
//!
//! # Why a concrete pass runs first
//!
//! Most differences are found without a solver, by running both functions
//! concretely on a fixed probe vector set ([`replay`]) --- the same idea as
//! [`crate::csource::lower::differential`], with the compiled binary replaced by
//! the second function. A concrete disagreement is a witness that needs no
//! confirmation, so the solver is asked only about the pairs the probes could
//! not separate. [`EquivReport::decided_by`] records which half decided, so the
//! marginal contribution of the solver is measurable rather than assumed.
//!
//! # Why a witness is replayed, and the hole that leaves
//!
//! `src/exec/concrete.rs` and SMT-LIB do not agree everywhere. `BinOp::Div` by
//! zero is `0` in the concrete domain and all-ones under `bvudiv`; a shift
//! amount at or above the operand width is taken **modulo** the width in the
//! concrete domain and saturates to zero under `bvshl`. So a model returned by
//! the solver is a *candidate*, and this module re-runs both functions
//! concretely on it. A candidate that does not reproduce is
//! [`Unknown::WitnessUnconfirmed`], never a `Different`.
//!
//! **That guard is asymmetric, and the asymmetry is this checker's one
//! soundness hole.** A `sat` carries a model, so it can be replayed. An `unsat`
//! carries nothing, so nothing re-checks it --- and `Equivalent` is the one
//! verdict that must never be wrong. The scorecard found a real instance:
//! `constant-bump` on `117_modular_arithmetic.c::modular_exponent_of_two`
//! widens a guard from `e > 31` to `e > 32`, so at `e == 32` the mutant
//! evaluates `1u << 32`, and this checker proved the pair equivalent. Three
//! different answers exist for that expression, and they were all measured:
//!
//! ```text
//! gcc 15.2.0, -O0 and -O1, run:                 original 0, mutant 1
//! this lowering under src/exec/concrete.rs:     original 0, mutant 0
//! the same pair through the SMT rendering:      unsat (proved equal)
//! ```
//!
//! Note where the disagreement is. Our executor and the solver agree with *each
//! other* here and both disagree with the compiler, so this cell is **not** the
//! `bvshl`-versus-concrete mismatch above --- it is [`crate::csource::lower`]
//! evaluating the shift on 64-bit temporaries and renormalizing, where C
//! evaluates it at the promoted operand width and the hardware takes the count
//! modulo 32. A fix to the `bvshl` rendering alone therefore will not change
//! this cell's verdict: both sides would still compute 0 and the miter would
//! still be unsat.
//!
//! The structural fix belongs here and is not yet built: before accepting an
//! `unsat`, ask one more query --- "is there an input, under
//! `defined_a AND defined_b`, that reaches a shift whose count is not provably
//! below the operand width, or a divide whose divisor is not provably
//! non-zero?" --- and downgrade `Equivalent` to `Unknown` when it is
//! satisfiable. Until that exists, an `Equivalent` from this module is a claim
//! *under the shared semantics of the lowering and the solver*, not under the
//! semantics of the compiled program, and it must be quoted that way.
//!
//! # Coverage, and why `unknown` is first class
//!
//! Bounded means bounded. A path cut by the unroll bound, the step budget or an
//! unmodelled construct is a region of the input space on which nothing was
//! checked. An `unsat` over a partially covered input space is **not** evidence
//! of equivalence, so this module never reports [`Verdict::Equivalent`] for one.
//! Instead it asks a second query --- "is there an input on which some side did
//! not complete?" --- and downgrades to [`Unknown::PartialCoverage`] when that
//! is satisfiable. A loop whose trip count the bound covers therefore still
//! reaches a real `Equivalent`, because the paths that exceed the bound have
//! unsatisfiable guards; a loop over an unconstrained input does not, and says
//! so.
//!
//! # Every axis is bounded, including the ones that were not obvious
//!
//! Unrolling depth, per-path steps and path count are the bounds a bounded
//! checker is expected to have. Two more were added because a sweep found them
//! the hard way, and both are recorded in [`Bounds`] like the others:
//!
//! * **Condition tree size.** `Symbolic::as_branch` folds a condition with an
//!   uncached recursive walk, so it costs the expression's size *as a tree*.
//!   `src/exec/memory.rs` rebuilds a 4-byte slot as a `Concat` of four
//!   `Extract`s, so a loop counter living in a frame slot multiplies its tree by
//!   four per iteration while its DAG grows by a handful of nodes. On
//!   `55_modular_arithmetic.c::mod_pow` at 16 enumerated paths the DAG was 273
//!   nodes and the tree was past 10^18, and folding it blocked a 1,810-case
//!   sweep for over forty minutes. Measuring the tree first --- which is linear
//!   in the DAG --- and cutting the path costs 10 ms where it cost 6,598.
//! * **Query size.** `crate::symbolic::solver::pipe` spawns a solver binary and
//!   waits for it with no `:timeout`, no `-T:` and no reference to
//!   `check_timeout_ms`; that wall exists only in the in-process backends. So a
//!   query is measured before it is asked and an over-large one is refused.
//!
//! Both refusals are [`Unknown`], with their numbers attached. Neither is a
//! step this module can leave unbounded and still call itself bounded.
//!
//! # Determinism
//!
//! Path enumeration is a LIFO walk over an explicit stack of decision prefixes,
//! never native recursion and never a hash-map iteration. Blocks are indexed in
//! a [`BTreeMap`](std::collections::BTreeMap). Re-running a check on the same
//! inputs issues the same queries in the same order.

pub mod explore;
pub mod miter;
pub mod replay;
pub mod size;

#[cfg(test)]
mod scorecard_tests;
#[cfg(test)]
mod tests;

use crate::ir::types::{LlirFunction, Width};
use crate::symbolic::solver::SolveUnknownReason;

use super::lower::ctype::IntType;
use super::lower::{CType, LoweredFunction};

/// Every bound the check runs under, carried with the result.
///
/// The roadmap's rule for this stage is that a number is only quotable next to
/// the bound that produced it, so the bounds are part of the report rather than
/// a constant a reader has to go and find.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bounds {
    /// Loop unrolling depth, expressed as the number of times one block may be
    /// entered on a single path. A path that would enter a block once more is
    /// cut.
    pub max_block_visits: u32,
    /// Instructions one path may retire before it is cut.
    pub max_steps: u64,
    /// Paths enumerated per function before enumeration is cut.
    pub max_paths: u64,
    /// Instruction budget for one concrete probe or witness replay.
    pub probe_steps: u64,
    /// The solver's per-check wall, in milliseconds. Read from
    /// [`crate::symbolic::check_timeout_ms`] so the recorded value is the one
    /// the backend actually used, including a `GLAURUNG_CHECK_TIMEOUT_MS`
    /// override.
    pub solver_timeout_ms: u64,
    /// The largest expression **tree** whose truth this check will ask the
    /// symbolic domain to fold.
    ///
    /// This is the bound that stops one case from blocking a sweep, and it is
    /// stated in tree nodes rather than DAG nodes on purpose:
    /// `Symbolic::as_branch` folds a condition with an uncached recursive walk,
    /// so it pays the tree cost. `src/exec/memory.rs` rebuilds a 4-byte slot as
    /// a `Concat` of four `Extract`s, so a loop counter that lives in a frame
    /// slot multiplies its tree by four per iteration while its DAG grows by a
    /// handful of nodes. Measured on `55_modular_arithmetic.c::mod_pow`: at 16
    /// enumerated paths the DAG was 273 nodes and the tree was past 10^18.
    ///
    /// A path whose next condition exceeds this is cut. For a function whose
    /// locals live in memory --- which is every lowered C function --- this,
    /// not [`Bounds::max_block_visits`], is the effective unroll depth.
    pub max_condition_tree_nodes: u64,
    /// Distinct expression nodes a solver query may reach. See
    /// [`size`] for why a query is measured before it is asked.
    pub max_query_nodes: u64,
    /// Multiplications, divisions and variable-distance shifts a solver query
    /// may contain. Node count alone does not separate a small hard query from
    /// a large easy one.
    pub max_nonlinear_ops: u64,
    /// The stack pointer both sides start from. Memory is the softmmu's sparse
    /// model over *concrete* addresses; there is no bounded array abstraction
    /// and no widening. An address that does not concretize halts the path,
    /// which is a cut, not an approximation.
    pub stack_pointer: u64,
}

impl Default for Bounds {
    /// Bounds sized for single-construct functions: deep enough that a loop with
    /// a small constant trip count is fully covered, cheap enough that a corpus
    /// sweep is minutes rather than hours.
    fn default() -> Self {
        Self {
            max_block_visits: 12,
            max_steps: 20_000,
            max_paths: 96,
            probe_steps: 200_000,
            max_condition_tree_nodes: 200_000,
            max_query_nodes: 40_000,
            max_nonlinear_ops: 64,
            solver_timeout_ms: crate::symbolic::check_timeout_ms(),
            stack_pointer: super::lower::differential::STACK_POINTER,
        }
    }
}

/// One scalar input: which register it arrives in, and the type it arrives as.
///
/// The type is not decoration. It is what makes a counterexample a *callable*
/// input rather than a bit pattern no caller could pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputSlot {
    /// The ABI register the value arrives in.
    pub reg: String,
    /// The declared width of the parameter.
    pub width: Width,
    /// Whether the declared type is signed, which decides the extension to 64.
    pub signed: bool,
}

impl InputSlot {
    /// Canonicalize a raw 64-bit value to what a caller of this parameter type
    /// could actually pass: reduce to the declared width, then extend.
    pub fn canonicalize(&self, raw: u64) -> u64 {
        let bits = self.width.bits();
        if bits >= 64 {
            return raw;
        }
        let masked = raw & ((1u64 << bits) - 1);
        if self.signed && masked >> (bits - 1) != 0 {
            masked | !((1u64 << bits) - 1)
        } else {
            masked
        }
    }
}

/// The calling contract both sides are compared under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IoSpec {
    /// Parameters, in ABI register order.
    pub inputs: Vec<InputSlot>,
    /// The register the result arrives in.
    pub result_reg: String,
    /// The result's meaningful width. `None` for a `void` function, which has
    /// no observable this check can compare.
    pub result_width: Option<Width>,
}

impl IoSpec {
    /// The contract a [`LoweredFunction`] was lowered under.
    ///
    /// Returns `None` when a parameter is not an integer type --- the lowering
    /// refuses those already, so this is a defensive path rather than a
    /// reachable one.
    pub fn of_lowered(f: &LoweredFunction) -> Option<Self> {
        let mut inputs = Vec::new();
        for param in &f.params {
            match &param.ty {
                CType::Void => continue,
                CType::Int(IntType { width, signed, .. }) => inputs.push(InputSlot {
                    reg: param.reg.to_string(),
                    width: *width,
                    signed: *signed,
                }),
                _ => return None,
            }
        }
        Some(Self {
            inputs,
            result_reg: super::lower::func::RESULT_REG.to_string(),
            result_width: f.result_width(),
        })
    }
}

/// Why a check could not decide. Never folded into either decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unknown {
    /// A `void` function: the check compares returned values and this pair has
    /// none. Side effects are not modelled as an observable.
    NoObservableResult,
    /// The two sides do not agree on how they are called, so there is no shared
    /// input space to quantify over.
    ContractMismatch(String),
    /// One side completed no path at all within the bounds.
    NoCompletePath(&'static str),
    /// The miter was unsatisfiable, but some input reaches no completed path on
    /// one of the sides, so the `unsat` covers only part of the input space.
    PartialCoverage,
    /// The solver returned `unknown` for the miter or the coverage query.
    Solver(SolveUnknownReason),
    /// No solver backend was compiled in and none was found on `PATH`.
    NoSolver,
    /// The solver backend errored.
    SolverError(String),
    /// The solver produced a model that does not reproduce under the concrete
    /// domain --- see the module docs on `bvudiv` and shift amounts.
    WitnessUnconfirmed,
    /// The query exceeded [`Bounds::max_query_nodes`] or
    /// [`Bounds::max_nonlinear_ops`] and was never asked. See [`size`].
    QueryTooLarge(size::QuerySize),
}

/// What the check concluded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Every input completes on both sides within the bounds and produces the
    /// same result.
    Equivalent,
    /// A concrete input on which the two results differ, replayed and
    /// reproduced under the concrete domain.
    Different,
    /// Neither, with the reason.
    Unknown(Unknown),
}

/// A reproduced counterexample.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Witness {
    /// The argument values, canonicalized to what a caller could pass, in
    /// parameter order.
    pub args: Vec<u64>,
    /// The result the first function returned.
    pub left: u64,
    /// The result the second function returned.
    pub right: u64,
}

/// Which half of the check reached the verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecidedBy {
    /// Settled before any exploration (a `void` result, a contract mismatch).
    Contract,
    /// The concrete probe sweep separated the two.
    Probes,
    /// The solver decided the miter.
    Solver,
}

/// Counts that let a report say how much of the input space was actually
/// examined.
///
/// All zero when [`DecidedBy::Probes`] or [`DecidedBy::Contract`] reached the
/// verdict: neither of those explores paths or asks a solver, so there is
/// nothing for these to count.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Stats {
    /// Paths that reached a return, per side.
    pub complete_paths: (usize, usize),
    /// Paths cut by a bound or an unmodelled construct, per side.
    pub cut_paths: (usize, usize),
    /// Solver checks issued by this check.
    pub solves: u32,
}

/// The result of one equivalence check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EquivReport {
    /// The verdict.
    pub verdict: Verdict,
    /// The bounds it was reached under.
    pub bounds: Bounds,
    /// The counterexample, when the verdict is [`Verdict::Different`].
    pub witness: Option<Witness>,
    /// Which half decided.
    pub decided_by: DecidedBy,
    /// How much was examined.
    pub stats: Stats,
}

impl EquivReport {
    /// A report that decided nothing, for a reason known before exploration.
    fn undecided(bounds: Bounds, reason: Unknown, decided_by: DecidedBy) -> Self {
        Self {
            verdict: Verdict::Unknown(reason),
            bounds,
            witness: None,
            decided_by,
            stats: Stats::default(),
        }
    }
}

/// Check two lowered C functions for bounded equivalence.
///
/// The reference's parameter types decide the input model, because it is the
/// reference that says what a caller may pass; a candidate that disagrees about
/// the contract is [`Unknown::ContractMismatch`] rather than a difference,
/// since the two are then not comparable rather than unequal.
pub fn check_lowered(
    reference: &LoweredFunction,
    candidate: &LoweredFunction,
    bounds: Bounds,
) -> EquivReport {
    let (Some(left), Some(right)) = (IoSpec::of_lowered(reference), IoSpec::of_lowered(candidate))
    else {
        return EquivReport::undecided(
            bounds,
            Unknown::ContractMismatch("a parameter is not an integer type".to_string()),
            DecidedBy::Contract,
        );
    };
    if left.inputs.len() != right.inputs.len() {
        return EquivReport::undecided(
            bounds,
            Unknown::ContractMismatch(format!(
                "{} parameters versus {}",
                left.inputs.len(),
                right.inputs.len()
            )),
            DecidedBy::Contract,
        );
    }
    if left.result_width != right.result_width {
        return EquivReport::undecided(
            bounds,
            Unknown::ContractMismatch(format!(
                "result width {:?} versus {:?}",
                left.result_width, right.result_width
            )),
            DecidedBy::Contract,
        );
    }
    check(&reference.func, &candidate.func, &left, bounds)
}

/// Check two [`LlirFunction`]s called under one shared contract.
///
/// This is the general entry point: nothing here knows that either side came
/// from C. A lifted binary function and a lowered source function are the
/// canonical pair, but so are two lifts of the same function at different
/// optimization levels.
pub fn check(
    left: &LlirFunction,
    right: &LlirFunction,
    io: &IoSpec,
    bounds: Bounds,
) -> EquivReport {
    let Some(result_width) = io.result_width else {
        return EquivReport::undecided(bounds, Unknown::NoObservableResult, DecidedBy::Contract);
    };

    // The concrete sweep first: it needs no solver, and a disagreement it finds
    // is already a reproduced witness.
    if let Some(witness) = replay::probe_sweep(left, right, io, result_width, &bounds) {
        return EquivReport {
            verdict: Verdict::Different,
            bounds,
            witness: Some(witness),
            decided_by: DecidedBy::Probes,
            stats: Stats::default(),
        };
    }

    miter::decide(left, right, io, result_width, bounds)
}
