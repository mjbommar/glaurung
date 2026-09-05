//! Bounded path enumeration over one [`LlirFunction`].
//!
//! # One pool, many paths
//!
//! `src/symbolic/explore.rs` forks a whole [`Machine`] per branch, and a fork
//! clones the [`ExprPool`] with it. That is correct for its purpose --- every
//! query it asks is about one state --- but it makes two paths' `ExprId`s
//! members of two different pools, and an equivalence miter has to name results
//! from *many* paths of *two* functions in a single formula.
//!
//! So this enumerator never forks. It re-executes the function once per path,
//! replaying a recorded prefix of branch decisions and taking the false edge at
//! the first free decision, and it carries **one** pool across every run of both
//! functions. Interning is hash-consed and execution is deterministic, so a
//! replayed prefix re-derives literally the same `ExprId`s it did the first
//! time; the cost is re-executing prefixes, which is bounded by
//! [`Bounds::max_paths`] and, on single-construct functions, small.
//!
//! # Explicit stack, and a guard on every loop
//!
//! The worklist is an explicit `Vec` of decision prefixes and the per-path walk
//! is an iterative block loop. Nothing recurses over the function under test.
//! Three separate counters bound the work --- entries into one block, retired
//! instructions, and enumerated paths --- and each one that fires is recorded as
//! a named [`Cut`] rather than silently ending the walk.

use std::collections::BTreeMap;

use crate::exec::domain::BranchDecision;
use crate::exec::{Domain, Flow, Machine};
use crate::ir::types::{LlirBlock, LlirFunction, Op, VReg, Width};
use crate::symbolic::expr::ExprId;
use crate::symbolic::Symbolic;

use super::Bounds;

/// Why a path stopped without returning. Each variant names a specific bound or
/// a specific unmodelled construct, because "the walk ended" is not a finding
/// and "the unroll bound fired at block 0x1000000c" is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cut {
    /// The unroll bound fired: this block had already been entered
    /// [`Bounds::max_block_visits`] times on this path.
    LoopBound(u64),
    /// The per-path instruction budget was exhausted.
    StepBudget,
    /// The path budget was exhausted before enumeration finished.
    PathBudget,
    /// Control reached a VA with no block --- for a lowered function this is the
    /// deliberate `NO_FALLTHROUGH_VA` trap.
    NoBlock(u64),
    /// The function called out; this checker models no callee.
    CalledOut,
    /// The interpreter halted, with its reason rendered.
    Halt(String),
    /// The next branch condition's expression tree exceeded
    /// [`Bounds::max_condition_tree_nodes`], so folding it would have cost more
    /// than the bound allows. Carries the instruction's VA.
    ExpressionBound(u64),
}

/// One path that reached a return.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompletePath {
    /// The branch decisions that reach it, as solver assertions: each entry is
    /// a value and the truthiness it must have.
    pub guard: Vec<(ExprId, bool)>,
    /// The 64-bit value in the result register (or named by the return op) when
    /// the path returned.
    pub result: ExprId,
}

/// Everything enumeration found for one function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exploration {
    /// Paths that returned within the bounds.
    pub complete: Vec<CompletePath>,
    /// Paths that did not, with the reason each stopped.
    pub cuts: Vec<Cut>,
}

impl Exploration {
    /// Whether every enumerated path returned. When true the summary covers the
    /// whole input space and no coverage query is needed.
    pub fn is_total(&self) -> bool {
        self.cuts.is_empty()
    }
}

/// How one replayed run ended.
enum PathEnd {
    Returned(ExprId),
    Cut(Cut),
}

/// What one replayed run produced.
struct PathRun {
    guard: Vec<(ExprId, bool)>,
    decisions: Vec<bool>,
    end: PathEnd,
}

/// Enumerate the paths of `func` under `bounds`, seeding `seeds` into registers
/// before the entry block.
///
/// The pool is threaded through by value: every returned `ExprId`, from every
/// path, is valid in the [`Symbolic`] this hands back, which is the whole point
/// of not forking.
pub fn explore(
    func: &LlirFunction,
    mut sym: Symbolic,
    seeds: &[(VReg, ExprId)],
    result_reg: &VReg,
    bounds: &Bounds,
) -> (Symbolic, Exploration) {
    let blocks: BTreeMap<u64, &LlirBlock> = func.blocks.iter().map(|b| (b.start_va, b)).collect();
    let mut pending: Vec<Vec<bool>> = vec![Vec::new()];
    let mut complete = Vec::new();
    let mut cuts = Vec::new();
    let mut runs: u64 = 0;

    while let Some(prefix) = pending.pop() {
        if runs >= bounds.max_paths {
            cuts.push(Cut::PathBudget);
            break;
        }
        runs += 1;
        let (next_sym, run) = run_one(func, &blocks, sym, seeds, result_reg, bounds, &prefix);
        sym = next_sym;
        // Every free decision was taken false; its sibling is the same prefix
        // with that bit set. Pushing in ascending order makes the LIFO walk
        // deterministic and depth-first.
        for index in prefix.len()..run.decisions.len() {
            if !run.decisions[index] {
                let mut sibling = run.decisions[..index].to_vec();
                sibling.push(true);
                pending.push(sibling);
            }
        }
        match run.end {
            PathEnd::Returned(result) => complete.push(CompletePath {
                guard: run.guard,
                result,
            }),
            PathEnd::Cut(cut) => cuts.push(cut),
        }
        // The worklist cannot outgrow what the path budget will ever consume.
        if pending.len() as u64 > bounds.max_paths.saturating_mul(4) {
            cuts.push(Cut::PathBudget);
            break;
        }
    }
    (sym, Exploration { complete, cuts })
}

/// Replay one path, forcing `forced` at the first decisions and taking the false
/// edge at every free one.
fn run_one(
    func: &LlirFunction,
    blocks: &BTreeMap<u64, &LlirBlock>,
    sym: Symbolic,
    seeds: &[(VReg, ExprId)],
    result_reg: &VReg,
    bounds: &Bounds,
    forced: &[bool],
) -> (Symbolic, PathRun) {
    let mut machine = Machine::new(sym);
    let sp = machine
        .dom
        .constant(Width::W64, bounds.stack_pointer as u128);
    machine.regs.write(&mut machine.dom, &VReg::phys("rsp"), sp);
    let bp = machine
        .dom
        .constant(Width::W64, bounds.stack_pointer as u128);
    machine.regs.write(&mut machine.dom, &VReg::phys("rbp"), bp);
    for (reg, value) in seeds {
        machine.regs.write(&mut machine.dom, reg, *value);
    }

    let mut guard: Vec<(ExprId, bool)> = Vec::new();
    let mut decisions: Vec<bool> = Vec::new();
    let mut visits: BTreeMap<u64, u32> = BTreeMap::new();
    let mut steps: u64 = 0;
    let mut cur = func.entry_va;

    let end = 'walk: loop {
        let Some(block) = blocks.get(&cur).copied() else {
            break PathEnd::Cut(Cut::NoBlock(cur));
        };
        let entered = visits.entry(cur).or_insert(0);
        *entered += 1;
        if *entered > bounds.max_block_visits {
            break PathEnd::Cut(Cut::LoopBound(cur));
        }

        let mut fell_through = true;
        for ins in &block.instrs {
            steps += 1;
            if steps > bounds.max_steps {
                break 'walk PathEnd::Cut(Cut::StepBudget);
            }
            match &ins.op {
                Op::CondJump {
                    cond,
                    target,
                    inverted,
                } => {
                    let value = machine.regs.read(&mut machine.dom, cond);
                    if oversized(&machine, value, bounds) {
                        break 'walk PathEnd::Cut(Cut::ExpressionBound(ins.va));
                    }
                    let bit = decide(&mut machine, &value, forced, &mut decisions, &mut guard);
                    cur = if bit != *inverted {
                        *target
                    } else {
                        block.end_va
                    };
                    fell_through = false;
                    break;
                }
                Op::CondReturn { cond, inverted } | Op::CondReturnValue { cond, inverted, .. } => {
                    let value = machine.regs.read(&mut machine.dom, cond);
                    if oversized(&machine, value, bounds) {
                        break 'walk PathEnd::Cut(Cut::ExpressionBound(ins.va));
                    }
                    let bit = decide(&mut machine, &value, forced, &mut decisions, &mut guard);
                    if bit != *inverted {
                        let result = result_of(&mut machine, &ins.op, result_reg);
                        break 'walk PathEnd::Returned(result);
                    }
                }
                other => match machine.step(other) {
                    Flow::Next => {}
                    Flow::Jump(target) => {
                        cur = target;
                        fell_through = false;
                        break;
                    }
                    Flow::Return => {
                        let result = result_of(&mut machine, other, result_reg);
                        break 'walk PathEnd::Returned(result);
                    }
                    Flow::Call(_) => break 'walk PathEnd::Cut(Cut::CalledOut),
                    Flow::Halt(halt) => break 'walk PathEnd::Cut(Cut::Halt(format!("{halt:?}"))),
                    // Conditional transfers are intercepted above, so the
                    // interpreter can only produce this for an op this walk does
                    // not know about; treat it as an unmodelled construct.
                    Flow::Branch { .. } => {
                        break 'walk PathEnd::Cut(Cut::Halt("unexpected branch flow".to_string()))
                    }
                },
            }
        }
        if fell_through {
            cur = block.end_va;
        }
    };

    (
        machine.dom,
        PathRun {
            guard,
            decisions,
            end,
        },
    )
}

/// Whether folding this condition would cost more than the bound allows.
///
/// Asked **before** `as_branch`, never after: the whole point is not to make
/// that call. The measurement itself is linear in the DAG (see
/// [`super::size::tree_size`]), so asking is cheap even when the answer is that
/// the tree is astronomically large.
fn oversized(machine: &Machine<Symbolic>, value: ExprId, bounds: &Bounds) -> bool {
    let cap = u128::from(bounds.max_condition_tree_nodes);
    super::size::tree_size(&machine.dom.pool, value, cap.saturating_add(1)) > cap
}

/// Resolve a branch: constant conditions decide themselves and cost no
/// assertion; a symbolic one consumes the next decision and records the
/// assertion that selects it.
fn decide(
    machine: &mut Machine<Symbolic>,
    value: &ExprId,
    forced: &[bool],
    decisions: &mut Vec<bool>,
    guard: &mut Vec<(ExprId, bool)>,
) -> bool {
    match machine.dom.as_branch(value) {
        BranchDecision::Taken => true,
        BranchDecision::NotTaken => false,
        BranchDecision::Fork => {
            let bit = forced.get(decisions.len()).copied().unwrap_or(false);
            decisions.push(bit);
            guard.push((*value, bit));
            bit
        }
    }
}

/// The value a return produces: the one the op names when it names one, else the
/// result register.
fn result_of(machine: &mut Machine<Symbolic>, op: &Op, result_reg: &VReg) -> ExprId {
    match op.returned_value() {
        Some(value) => machine.read(value, Width::W64),
        None => machine.regs.read(&mut machine.dom, result_reg),
    }
}
