//! Symbolic path exploration (Phase 5, initial).
//!
//! Forks execution at *symbolic* conditional branches, accumulates the path
//! condition, prunes infeasible paths with the solver, and searches for an input
//! that drives control to a target address. Built on the same interpreter and
//! the `Symbolic` domain; state forking is a `Machine<Symbolic>` clone (each
//! fork carries its own expression pool — a shared copy-on-write pool is a
//! future optimization).
//!
//! Scope (initial): DFS worklist, bounded by a max-state cap; concrete branches
//! follow deterministically, symbolic branches fork and are feasibility-checked.
//! Concretize-with-threshold symbolic *memory*, directed search ordering, and
//! witness concrete-replay are later Phase-5 increments
//! (`docs/design/execution-engine/02-architecture/symbolic-engine.md`).

use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::exec::domain::{BranchDecision, Domain};
use crate::exec::{Flow, Halt, Machine, RegArch};
use crate::ir::types::{CallTarget, Endian, LlirBlock, LlirFunction, Op, VReg, Value, Width};
use crate::symbolic::expr::ExprId;
use crate::symbolic::ordered_trace::TracePath;
use crate::symbolic::solver::{Assert, SolveResult, WarmAssertionPrefix};
use crate::symbolic::Symbolic;

use std::cell::Cell;
use std::time::Instant;

// `BinOp` and `Expr` left the product code with `check_int_overflow` and
// `eval_expr`; the `tests` module below still builds both by hand.
#[cfg(test)]
use crate::ir::types::BinOp;
#[cfg(test)]
use crate::symbolic::expr::Expr;

mod detect;
mod model;
mod query;
mod solve;
mod stats;

pub use model::{ApiSummary, CallModel, Severity, Sink, SinkKind, TaintSpec};
pub use solve::{canonical_model_choice_stats, CanonicalModelChoiceStats};
pub use stats::{
    execution_path_stats, exploration_limit_stats, reset_execution_path_stats,
    reset_exploration_limit_stats, set_call_site_summaries, ExecutionPathStats,
    ExplorationLimitStats,
};

use detect::{
    apply_summary, check_int_overflow, execute_memory_op, havoc_return, record_access, uaf_check,
};
use query::{can_skip_feasibility_check, eval_concrete, push_sink};
use solve::{
    close_warm_owner, next_warm_path_id, share_serial_warm_owner_with_children, solve_traced,
    warm_owner_transfer_enabled, warm_serial_sibling_reuse_enabled,
};
use stats::{
    call_site_summary, deadline_passed, record_execution_halt, record_path_stat, record_stop_site,
    record_worklist_stop, WorklistStop, DEADLINE, DEADLINE_OBSERVED,
};
// These have no caller in the shipped build -- they are exercised only by the
// `tests` module below, which reaches them through `use super::*`. An
// unconditional re-export would be an unused import in every real build.
#[cfg(test)]
use detect::stack_overflow_check;
#[cfg(test)]
use query::{concretize_addr, concretize_addr_with_policy, eval_concrete_with_policy};
#[cfg(test)]
use solve::{effective_serial_sibling_reuse, maximize_unsigned_value, minimize_unsigned_value};

/// A tracked heap allocation, so frees and use-after-free can be followed across
/// a path. Allocations hand out concrete bases (a bump allocator), so a freed
/// pointer flowing back into a deref or API call is recognizable.
#[derive(Debug, Clone)]
struct Alloc {
    base: u64,
    size: u64,
    freed: bool,
}

/// Base of the bump allocator handing out [`Alloc`] blocks (well clear of the
/// seeded IRP structures and the stack).
const HEAP_BASE: u64 = 0x7000_0000;

/// One in-flight path: a machine snapshot, its program counter, the path
/// condition, and the per-path bookkeeping the lifecycle detectors need.
#[derive(Clone)]
struct State {
    machine: Machine<Symbolic>,
    pc: u64,
    constraints: Vec<Assert>,
    /// Attacker-input provenance, *per path* and growing: reading uninitialized
    /// attacker memory mints a fresh symbol marked here (taint-through-memory), so
    /// data loaded from `*(SystemBuffer)` stays attacker-controlled.
    taint: TaintSpec,
    /// Heap blocks seen on this path (live and freed) for UAF / double-free.
    allocations: Vec<Alloc>,
    /// Next bump-allocator address.
    heap_next: u64,
    /// Symbol ids vouched for by a `ProbeForRead/Write` — a deref built entirely
    /// from validated symbols is trusted (within the probed region) and not
    /// re-flagged; a deref that also mixes in an *un*validated attacker symbol
    /// (e.g. `buf + attacker_offset` past the probed length) is still flagged.
    validated: BTreeSet<u32>,
    /// Attacker-pointer reads already seen on this path, for double-fetch.
    tainted_reads: BTreeSet<ExprId>,
    /// Per-path block-visit counts. A loop unrolled symbolically grows the
    /// path's expressions without bound (obfuscated code can make a single op on
    /// the resulting giant expression non-interruptible); capping revisits per
    /// path bounds expression growth at the source — IOCTLance's `LoopSeer`.
    visits: BTreeMap<u64, u32>,
    /// Ordered-trace lineage and scope state. Absent in ordinary execution.
    trace: Option<TracePath>,
    /// Logical owner of opt-in retained Axeyum mutable state.
    warm_path_id: u64,
    /// Absolute number of persistent constraints known synchronized in that
    /// owner. It advances only when the direct-delta backend confirms success.
    warm_retain_assertions: usize,
    /// Exact copy-on-write ancestry of persistent source assertions. Unlike
    /// expression IDs or depth, shared node identity cannot alias after pools
    /// fork and independently intern different expressions.
    warm_assertion_prefix: WarmAssertionPrefix,
}

/// Max times a single path may re-enter the same block before it is cut.
const MAX_BLOCK_VISITS: u32 = 8;

impl State {
    /// A fresh root state at `pc` with the given machine and seed taint.
    fn root(machine: Machine<Symbolic>, pc: u64, taint: TaintSpec) -> Self {
        State {
            machine,
            pc,
            constraints: Vec::new(),
            taint,
            allocations: Vec::new(),
            heap_next: HEAP_BASE,
            validated: BTreeSet::new(),
            tainted_reads: BTreeSet::new(),
            visits: BTreeMap::new(),
            trace: TracePath::root(pc),
            warm_path_id: next_warm_path_id(),
            warm_retain_assertions: 0,
            warm_assertion_prefix: WarmAssertionPrefix::default(),
        }
    }

    /// Fork this state to a successor `pc`, carrying the path condition and
    /// bookkeeping (used at symbolic branches).
    fn fork(&self, pc: u64) -> Self {
        State {
            machine: self.machine.clone(),
            pc,
            constraints: self.constraints.clone(),
            taint: self.taint.clone(),
            allocations: self.allocations.clone(),
            heap_next: self.heap_next,
            validated: self.validated.clone(),
            tainted_reads: self.tainted_reads.clone(),
            visits: self.visits.clone(),
            trace: self.trace.as_ref().map(|trace| trace.fork(pc)),
            warm_path_id: next_warm_path_id(),
            warm_retain_assertions: self.warm_retain_assertions,
            warm_assertion_prefix: self.warm_assertion_prefix.clone(),
        }
    }

    fn fork_transferring_warm_owner(&mut self, pc: u64) -> Self {
        let mut child = self.fork(pc);
        std::mem::swap(&mut self.warm_path_id, &mut child.warm_path_id);
        child
    }

    /// Returns successors in worklist insertion order. The worklist is LIFO,
    /// so an enabled transfer targets only the second/next-executed child.
    fn fork_branch_successors(
        &mut self,
        pc_if_true: u64,
        pc_if_false: u64,
        transfer_warm_owner: bool,
        serial_sibling_reuse: bool,
    ) -> [(bool, Self); 2] {
        let mut first = self.fork(pc_if_true);
        let mut next = if transfer_warm_owner && !serial_sibling_reuse {
            self.fork_transferring_warm_owner(pc_if_false)
        } else {
            self.fork(pc_if_false)
        };
        if serial_sibling_reuse {
            first.warm_path_id = self.warm_path_id;
            next.warm_path_id = self.warm_path_id;
        }
        [(true, first), (false, next)]
    }

    /// Add one persistent path assertion and its matching trace scope.
    fn assert(&mut self, assertion: Assert, role: &str, location: u64) {
        if let Some(trace) = &mut self.trace {
            trace.push_assert(&self.machine.dom.pool, assertion, role, location);
        }
        self.constraints.push(assertion);
        self.warm_assertion_prefix.push();
    }

    /// Terminate this path in the ordered trace, if capture is active.
    fn end_trace(&mut self, reason: &str) {
        close_warm_owner(self.warm_path_id);
        if let Some(trace) = &mut self.trace {
            trace.end(reason, self.pc);
        }
    }

    /// A stateful round is a new logical root even when it carries machine data.
    fn restart_trace(&mut self) {
        close_warm_owner(self.warm_path_id);
        self.warm_path_id = next_warm_path_id();
        self.warm_retain_assertions = 0;
        self.warm_assertion_prefix = WarmAssertionPrefix::default();
        self.trace = TracePath::root(self.pc);
    }
}

/// Search for an input that reaches `target`, starting from `lf`'s entry with the
/// machine seeded by `seed` (e.g. marking argument registers symbolic). Returns
/// the solver result for the first path that reaches `target`:
/// `Sat(model)` is a reaching witness; `Unsat` means no explored path reached it;
/// `Unknown` means the state cap was hit first; `NoSolver` propagates.
pub fn find_input_reaching(
    lf: &LlirFunction,
    target: u64,
    seed: impl FnOnce(&mut Machine<Symbolic>),
    max_states: usize,
) -> SolveResult {
    let blocks: HashMap<u64, LlirBlock> =
        lf.blocks.iter().map(|b| (b.start_va, b.clone())).collect();

    let mut machine = Machine::new(Symbolic::new());
    seed(&mut machine);

    let mut work = vec![State::root(machine, lf.entry_va, TaintSpec::new())];
    let mut explored = 0usize;

    while let Some(mut st) = work.pop() {
        if explored >= max_states {
            st.end_trace("state-budget");
            for pending in &mut work {
                pending.end_trace("state-budget");
            }
            return SolveResult::Unknown(crate::symbolic::solver::SolveUnknownReason::Other);
        }
        explored += 1;

        if st.pc == target {
            // Reached the target: solve the accumulated path condition for a
            // concrete input that drives execution here.
            let result = solve_traced(&mut st, "target-reachability", target);
            st.end_trace("target-reached");
            return result;
        }

        let apis = CallModel::new();
        for s in process_block(&blocks, st, &apis, &mut Vec::new(), &mut None) {
            work.push(s);
        }
    }
    SolveResult::Unsat
}

/// Explore `lf` (seeded by `seed`) and collect every dangerous memory access
/// through an attacker-controlled address — controlled read/write and null
/// deref — each with a triggering input witness. This is the symbolic successor
/// to the static `ioctl_taint` pass: it *confirms* a sink is reachable and
/// produces the IOCTL input that triggers it.
pub fn find_sinks(
    lf: &LlirFunction,
    seed: impl FnOnce(&mut Machine<Symbolic>) -> TaintSpec,
    apis: &CallModel,
    max_states: usize,
) -> Vec<Sink> {
    find_sinks_with_arch(lf, RegArch::X86_64, seed, apis, max_states)
}

/// Architecture-explicit variant of [`find_sinks`]. The original API remains
/// the MS-x64 default; Linux AArch64 frontends must opt into AAPCS64 register
/// and return semantics rather than writing AArch64 names into an x64 machine.
pub fn find_sinks_with_arch(
    lf: &LlirFunction,
    arch: RegArch,
    seed: impl FnOnce(&mut Machine<Symbolic>) -> TaintSpec,
    apis: &CallModel,
    max_states: usize,
) -> Vec<Sink> {
    let blocks: HashMap<u64, LlirBlock> =
        lf.blocks.iter().map(|b| (b.start_va, b.clone())).collect();

    let mut machine = Machine::new_with_arch(Symbolic::new(), arch);
    let taint = seed(&mut machine);
    let (sinks, _, _) = run_worklist(
        &blocks,
        State::root(machine, lf.entry_va, taint),
        apis,
        max_states,
    );
    sinks
}

/// How far along the alloc→free→use lifecycle a terminal path got, used to pick
/// which path's machine to carry into the next stateful round. A freed block
/// dominates a merely-allocated one.
fn progress(st: &State) -> usize {
    let freed = st.allocations.iter().filter(|a| a.freed).count();
    freed * 1_000_000 + st.allocations.len() * 1_000
}

/// Remember `st` as the round's carry candidate if it made the most lifecycle
/// progress so far (clones only when it wins, to avoid copying every path).
fn consider_terminal(st: &State, best: &mut Option<State>) {
    let p = progress(st);
    if p == 0 {
        return;
    }
    if best.as_ref().is_none_or(|b| progress(b) < p) {
        let mut candidate = st.clone();
        candidate.warm_path_id = next_warm_path_id();
        candidate.warm_retain_assertions = 0;
        *best = Some(candidate);
    }
}

/// Drive the DFS worklist from `root`, returning the sinks found and the terminal
/// path that advanced the heap lifecycle furthest (for stateful carry-over).
/// Bails (returning partial results) when the per-function solver budget is spent
/// — the safety cap that keeps a pathological/obfuscated function from stalling.
fn run_worklist(
    blocks: &HashMap<u64, LlirBlock>,
    root: State,
    apis: &CallModel,
    max_states: usize,
) -> (Vec<Sink>, Option<State>, WorklistStop) {
    use crate::symbolic::solver::{reset_solver_meter, solver_budget, solver_meter, time_budget};
    reset_solver_meter();
    let (max_solves, max_timeouts) = solver_budget();
    let deadline = time_budget().map(|d| Instant::now() + d);
    DEADLINE.with(|c| c.set(deadline)); // checked per-instruction in process_block
    DEADLINE_OBSERVED.with(|observed| observed.set(false));
    let mut work = vec![root];
    let mut explored = 0usize;
    let mut out = Vec::new();
    let mut best: Option<State> = None;
    let mut stop = WorklistStop::Complete;

    while let Some(mut st) = work.pop() {
        if explored >= max_states {
            st.end_trace("state-budget");
            for pending in &mut work {
                pending.end_trace("state-budget");
            }
            stop = WorklistStop::StateBudget;
            break;
        }
        let (solves, timeouts) = solver_meter();
        if solves >= max_solves {
            st.end_trace("solver-budget");
            for pending in &mut work {
                pending.end_trace("solver-budget");
            }
            stop = WorklistStop::SolveBudget;
            break; // solver budget spent: bail with partial findings
        }
        if timeouts >= max_timeouts {
            st.end_trace("timeout-budget");
            for pending in &mut work {
                pending.end_trace("timeout-budget");
            }
            stop = WorklistStop::TimeoutBudget;
            break;
        }
        if deadline.is_some_and(|dl| std::time::Instant::now() >= dl) {
            st.end_trace("deadline");
            for pending in &mut work {
                pending.end_trace("deadline");
            }
            stop = WorklistStop::Deadline;
            break; // wall-clock budget spent: bail with partial findings
        }
        explored += 1;
        let mut sinks = Vec::new();
        let succs = process_block(blocks, st, apis, &mut sinks, &mut best);
        out.append(&mut sinks);
        if DEADLINE_OBSERVED.with(Cell::get) {
            for pending in &mut work {
                pending.end_trace("deadline");
            }
            stop = WorklistStop::Deadline;
            break;
        }
        for s in succs {
            work.push(s);
        }
    }
    record_worklist_stop(stop);
    (out, best, stop)
}

/// Stateful, multi-invocation exploration: run the handler `rounds` times,
/// carrying the machine (memory + heap/allocation table) forward between runs and
/// re-seeding a fresh request each round (via `seed`). This recovers
/// *cross-invocation* bugs a single run cannot see — e.g. an allocation freed on
/// one IOCTL and used (or freed again) on a later IOCTL through a global pointer.
/// Each round keeps the terminal path that advanced the heap lifecycle furthest.
pub fn find_sinks_stateful(
    lf: &LlirFunction,
    seed: impl Fn(&mut Machine<Symbolic>) -> TaintSpec,
    apis: &CallModel,
    max_states: usize,
    rounds: usize,
) -> Vec<Sink> {
    let blocks: HashMap<u64, LlirBlock> =
        lf.blocks.iter().map(|b| (b.start_va, b.clone())).collect();

    let mut carry: Option<State> = None;
    let mut out: Vec<Sink> = Vec::new();
    let mut seen: BTreeSet<(u64, u8)> = BTreeSet::new();

    for _ in 0..rounds {
        // Build this round's root: reuse the carried machine (persistent globals
        // and heap) but re-seed a fresh request and reset the path bookkeeping.
        let root = match carry.take() {
            Some(mut st) => {
                st.taint = seed(&mut st.machine);
                st.pc = lf.entry_va;
                st.constraints.clear();
                st.warm_assertion_prefix = WarmAssertionPrefix::default();
                st.validated.clear();
                st.tainted_reads.clear();
                st.restart_trace();
                st
            }
            None => {
                let mut machine = Machine::new(Symbolic::new());
                let taint = seed(&mut machine);
                State::root(machine, lf.entry_va, taint)
            }
        };

        let (sinks, best, _) = run_worklist(&blocks, root, apis, max_states);
        for s in sinks {
            if seen.insert((s.va, s.kind as u8)) {
                out.push(s);
            }
        }
        match best {
            Some(b) => carry = Some(b),
            None => break, // no progress this round → further rounds are identical
        }
    }
    out
}

/// Execute the block at `st.pc`, returning the feasible successor states.
/// Controlled-write sinks discovered while executing are appended to `sinks`.
fn process_block(
    blocks: &HashMap<u64, LlirBlock>,
    mut st: State,
    apis: &CallModel,
    sinks: &mut Vec<Sink>,
    best: &mut Option<State>,
) -> Vec<State> {
    let Some(block) = blocks.get(&st.pc).cloned() else {
        consider_terminal(&st, best); // ran off the known CFG
        record_path_stat(|stats| {
            stats.off_cfg += 1;
            record_stop_site(stats, st.pc, "off-cfg");
        });
        st.end_trace("off-cfg");
        return Vec::new();
    };

    // Loop bound: cut the path once it has re-entered this block too many times,
    // which bounds symbolic expression growth (the root cause of the few
    // functions that no per-instruction/wall-clock cap can interrupt).
    let visits = st.visits.entry(st.pc).or_insert(0);
    *visits += 1;
    if *visits > MAX_BLOCK_VISITS {
        consider_terminal(&st, best);
        record_path_stat(|stats| {
            stats.loop_limit += 1;
            record_stop_site(stats, st.pc, "loop-limit");
        });
        st.end_trace("loop-limit");
        return Vec::new();
    }

    for ins in &block.instrs {
        // Per-instruction wall-clock guard: a block built from huge obfuscated
        // expressions can take a long time in a single op, so bail mid-block.
        if deadline_passed() {
            DEADLINE_OBSERVED.with(|observed| observed.set(true));
            consider_terminal(&st, best);
            st.end_trace("deadline");
            return Vec::new();
        }
        match &ins.op {
            Op::CondJump {
                cond,
                target,
                inverted,
            } => {
                let c = st.machine.regs.read(&mut st.machine.dom, cond);
                match st.machine.dom.as_branch(&c) {
                    // Constant conditions follow deterministically.
                    BranchDecision::Taken => {
                        st.pc = if !*inverted { *target } else { block.end_va };
                        return vec![st];
                    }
                    BranchDecision::NotTaken => {
                        st.pc = if *inverted { *target } else { block.end_va };
                        return vec![st];
                    }
                    // Symbolic condition: fork both ways, keep the feasible ones.
                    BranchDecision::Fork => {
                        let pc_if_true = if !*inverted { *target } else { block.end_va };
                        let pc_if_false = if *inverted { *target } else { block.end_va };
                        // A branch predicate that shares no symbol with the prior
                        // path condition is independent: adding it can't make the
                        // set unsat (the forked predicate is non-constant, so
                        // satisfiable on its own), so the feasibility solve can be
                        // skipped — the common case of branching on a fresh field.
                        let independent = can_skip_feasibility_check(&st, c);
                        let serial_sibling_reuse = warm_serial_sibling_reuse_enabled();
                        if serial_sibling_reuse {
                            share_serial_warm_owner_with_children(st.warm_path_id, 2);
                        }
                        let mut out = Vec::new();
                        for (bit, mut child) in st.fork_branch_successors(
                            pc_if_true,
                            pc_if_false,
                            warm_owner_transfer_enabled(),
                            serial_sibling_reuse,
                        ) {
                            child.assert((c, bit), "branch", ins.va);
                            let feasible = independent
                                || !matches!(
                                    solve_traced(&mut child, "branch-feasibility", ins.va),
                                    SolveResult::Unsat
                                );
                            if feasible {
                                out.push(child);
                            } else {
                                child.end_trace("unsat-prune");
                            }
                        }
                        st.end_trace("forked");
                        return out;
                    }
                }
            }
            Op::CondReturn { cond, inverted } | Op::CondReturnValue { cond, inverted, .. } => {
                let c = st.machine.regs.read(&mut st.machine.dom, cond);
                let returns = |bit: bool| bit != *inverted;
                let decision = st.machine.dom.as_branch(&c);
                match decision {
                    BranchDecision::Taken | BranchDecision::NotTaken => {
                        let bit = matches!(decision, BranchDecision::Taken);
                        if returns(bit) {
                            if let Some(reason) = ins
                                .op
                                .returned_value()
                                .and_then(|value| st.machine.undefined_value_reason(value))
                            {
                                consider_terminal(&st, best);
                                record_execution_halt(ins.va, &Halt::UndefinedValue(reason));
                                st.end_trace("execution-halt");
                                return Vec::new();
                            }
                            consider_terminal(&st, best);
                            record_path_stat(|stats| {
                                stats.returned += 1;
                                record_stop_site(stats, ins.va, "conditional-return");
                            });
                            st.end_trace("conditional-return");
                            return Vec::new();
                        }
                        st.pc = block.end_va;
                        return vec![st];
                    }
                    BranchDecision::Fork => {
                        let independent = can_skip_feasibility_check(&st, c);
                        let serial_sibling_reuse = warm_serial_sibling_reuse_enabled();
                        if serial_sibling_reuse {
                            share_serial_warm_owner_with_children(st.warm_path_id, 2);
                        }
                        let mut out = Vec::new();
                        for (bit, mut child) in st.fork_branch_successors(
                            block.end_va,
                            block.end_va,
                            warm_owner_transfer_enabled(),
                            serial_sibling_reuse,
                        ) {
                            child.assert((c, bit), "conditional-return", ins.va);
                            let feasible = independent
                                || !matches!(
                                    solve_traced(
                                        &mut child,
                                        "conditional-return-feasibility",
                                        ins.va,
                                    ),
                                    SolveResult::Unsat
                                );
                            if !feasible {
                                child.end_trace("unsat-prune");
                            } else if returns(bit) {
                                if let Some(reason) = ins
                                    .op
                                    .returned_value()
                                    .and_then(|value| child.machine.undefined_value_reason(value))
                                {
                                    consider_terminal(&child, best);
                                    record_execution_halt(ins.va, &Halt::UndefinedValue(reason));
                                    child.end_trace("execution-halt");
                                    continue;
                                }
                                consider_terminal(&child, best);
                                record_path_stat(|stats| {
                                    stats.returned += 1;
                                    record_stop_site(stats, ins.va, "conditional-return");
                                });
                                child.end_trace("conditional-return");
                            } else {
                                out.push(child);
                            }
                        }
                        st.end_trace("forked");
                        return out;
                    }
                }
            }
            Op::Jump { target } => {
                st.pc = *target;
                return vec![st];
            }
            // Resolve the callee VA: a direct call, an `call [rip+__imp_Api]`
            // (lifted to `Indirect(Addr(slot))`), or a register-indirect
            // `mov reg,[__imp_Api]; call reg` whose target evaluates to a concrete
            // IAT slot. A modeled callee is summarized and execution continues; a
            // register-indirect call through an *attacker-controlled* target is a
            // control-flow hijack (shellcode); anything else ends the path.
            Op::Call { target, .. } => {
                // Call-site-keyed summary (indirect WDF function-table calls whose
                // callee is a dynamic thunk, e.g. WdfRequestRetrieveInputBuffer).
                // Checked before callee resolution; args are still in registers here.
                if let Some(summary) = call_site_summary(ins.va) {
                    if !apply_summary(&mut st, ins.va, summary, sinks) {
                        record_path_stat(|stats| {
                            stats.model_unavailable += 1;
                            record_stop_site(stats, ins.va, "model-unavailable");
                        });
                        st.end_trace("model-unavailable");
                        return Vec::new();
                    }
                    continue;
                }
                let callee: Option<u64> = match target {
                    CallTarget::Direct(va) => Some(*va),
                    CallTarget::Indirect(Value::Addr(va)) => Some(*va),
                    CallTarget::Indirect(v) => {
                        let tv = st.machine.read(v, Width::W64);
                        let mut syms = BTreeMap::new();
                        st.machine.dom.pool.collect_syms(tv, &mut syms);
                        if syms.is_empty() {
                            // Concrete function pointer (e.g. loaded from the IAT).
                            let Some(callee) = eval_concrete(&mut st, tv) else {
                                record_path_stat(|stats| {
                                    stats.model_unavailable += 1;
                                    record_stop_site(stats, ins.va, "model-unavailable");
                                });
                                st.end_trace("model-unavailable");
                                return Vec::new();
                            };
                            Some(callee)
                        } else {
                            let prov = st.taint.provenance_of(&st.machine.dom.pool, tv);
                            if !prov.is_empty() {
                                push_sink(&mut st, ins.va, SinkKind::Shellcode, tv, prov, sinks);
                            }
                            None
                        }
                    }
                };
                match callee.and_then(|va| apis.get(&va).copied()) {
                    Some(summary) => {
                        if !apply_summary(&mut st, ins.va, summary, sinks) {
                            record_path_stat(|stats| {
                                stats.model_unavailable += 1;
                                record_stop_site(stats, ins.va, "model-unavailable");
                            });
                            st.end_trace("model-unavailable");
                            return Vec::new();
                        }
                    }
                    // An unmodeled callee (a local helper, logging, etc.) is
                    // treated as opaque: havoc the return and continue, rather than
                    // ending the path. Ending here would cut off everything after a
                    // `DbgPrint`/helper call — including the bug.
                    None => {
                        record_path_stat(|stats| {
                            *stats.unmodeled_calls.entry(ins.va).or_default() += 1;
                        });
                        havoc_return(&mut st);
                    }
                }
                continue;
            }
            Op::Return | Op::ReturnValue { .. } => {
                if let Some(reason) = ins
                    .op
                    .returned_value()
                    .and_then(|value| st.machine.undefined_value_reason(value))
                {
                    consider_terminal(&st, best);
                    record_execution_halt(ins.va, &Halt::UndefinedValue(reason));
                    st.end_trace("execution-halt");
                    return Vec::new();
                }
                if st.machine.regs.arch() == RegArch::X86_64 {
                    // MS x64 `ret` pops [rsp]. AArch64 returns through x30 and
                    // needs separate spill/reload provenance; treating [sp] as
                    // the return slot would be a false detector.
                    let rsp_v = st
                        .machine
                        .regs
                        .read(&mut st.machine.dom, &VReg::phys("rsp"));
                    let Some(rsp) = eval_concrete(&mut st, rsp_v) else {
                        record_path_stat(|stats| {
                            stats.model_unavailable += 1;
                            record_stop_site(stats, ins.va, "model-unavailable");
                        });
                        st.end_trace("model-unavailable");
                        return Vec::new();
                    };
                    if rsp != 0 {
                        let ret = st
                            .machine
                            .mem
                            .load(&mut st.machine.dom, rsp, 8, Endian::Little);
                        let prov = st.taint.provenance_of(&st.machine.dom.pool, ret);
                        if !prov.is_empty() {
                            push_sink(&mut st, ins.va, SinkKind::StackOverflow, ret, prov, sinks);
                        }
                    }
                }
                consider_terminal(&st, best);
                record_path_stat(|stats| {
                    stats.returned += 1;
                    record_stop_site(stats, ins.va, "return");
                });
                st.end_trace("return");
                return Vec::new();
            }
            // Privileged-instruction sinks. `wrmsr`/`rdmsr`/`out`/`in` lift to an
            // opaque `Op::Intrinsic` (empty ins/outs, no register dataflow). We
            // inspect the architectural operand register for attacker taint, raise
            // the matching primitive, then continue (the intrinsic has no declared
            // outputs to havoc, so it is a no-op for the symbolic state).
            // `wrmsr`/`rdmsr` MSR index = ECX (rcx); `out`/`in` port = DX (rdx).
            // Mirrors IOCTLance's wrmsr/out hooks.
            Op::Intrinsic { name, .. } if name == "wrmsr" || name == "rdmsr" => {
                let idx = st
                    .machine
                    .regs
                    .read(&mut st.machine.dom, &VReg::phys("rcx"));
                let prov = st.taint.provenance_of(&st.machine.dom.pool, idx);
                if !prov.is_empty() {
                    let kind = if name == "wrmsr" {
                        SinkKind::ArbitraryMsrWrite
                    } else {
                        SinkKind::ArbitraryMsrRead
                    };
                    push_sink(&mut st, ins.va, kind, idx, prov, sinks);
                }
                continue;
            }
            Op::Intrinsic { name, .. } if name == "out" || name == "in" => {
                let port = st
                    .machine
                    .regs
                    .read(&mut st.machine.dom, &VReg::phys("rdx"));
                let prov = st.taint.provenance_of(&st.machine.dom.pool, port);
                if !prov.is_empty() {
                    push_sink(&mut st, ins.va, SinkKind::PortAccess, port, prov, sinks);
                }
                continue;
            }
            other => {
                check_int_overflow(&mut st, ins.va, other, sinks);
                // Use-after-free is temporal, not address-symbolic: check every
                // load/store target (concrete or symbolic) against freed blocks,
                // so a deref of a freed pointer held in a global is caught.
                let memory_executes = |st: &mut State, op: &Op| match op {
                    Op::CondLoad { cond, inverted, .. } | Op::CondStore { cond, inverted, .. } => {
                        let c = st.machine.regs.read(&mut st.machine.dom, cond);
                        match st.machine.dom.as_branch(&c) {
                            BranchDecision::Taken => !*inverted,
                            BranchDecision::NotTaken => *inverted,
                            // The access exists on one feasible side. Keep the
                            // safety check conservative; execution below will
                            // stop rather than invent a conditional memory
                            // update when the predicate itself is symbolic.
                            BranchDecision::Fork => true,
                        }
                    }
                    _ => true,
                };
                match other {
                    Op::Load { addr, .. } | Op::CondLoad { addr, .. }
                        if memory_executes(&mut st, other) =>
                    {
                        let av = st.machine.eval_addr(addr);
                        record_access(&mut st, ins.va, av, false, sinks);
                        if !uaf_check(&mut st, ins.va, av, sinks) {
                            record_path_stat(|stats| {
                                stats.model_unavailable += 1;
                                record_stop_site(stats, ins.va, "model-unavailable");
                            });
                            st.end_trace("model-unavailable");
                            return Vec::new();
                        }
                    }
                    Op::Store { addr, .. } | Op::CondStore { addr, .. }
                        if memory_executes(&mut st, other) =>
                    {
                        let av = st.machine.eval_addr(addr);
                        record_access(&mut st, ins.va, av, true, sinks);
                        if !uaf_check(&mut st, ins.va, av, sinks) {
                            record_path_stat(|stats| {
                                stats.model_unavailable += 1;
                                record_stop_site(stats, ins.va, "model-unavailable");
                            });
                            st.end_trace("model-unavailable");
                            return Vec::new();
                        }
                    }
                    _ => {}
                }
                // Route every memory operation through the same handler. A
                // symbol-free address DAG is concrete without a solver, but it
                // must still receive taint-through-memory semantics for marked
                // regions such as WDM SystemBuffer.
                if matches!(
                    other,
                    Op::Load { .. } | Op::CondLoad { .. } | Op::Store { .. } | Op::CondStore { .. }
                ) {
                    if execute_memory_op(&mut st, other).is_none() {
                        consider_terminal(&st, best);
                        record_path_stat(|stats| {
                            stats.unresolved_symbolic_memory += 1;
                            record_stop_site(stats, ins.va, "unresolved-symbolic-memory");
                        });
                        st.end_trace("unresolved-symbolic-memory");
                        return Vec::new();
                    }
                    continue;
                }
                match st.machine.step(other) {
                    Flow::Next => continue,
                    Flow::Jump(t) => {
                        st.pc = t;
                        return vec![st];
                    }
                    // A load/store through a symbolic address: concretize it and
                    // execute the op manually, then continue the path.
                    Flow::Halt(Halt::UnresolvedAddress) => {
                        if execute_memory_op(&mut st, other).is_none() {
                            consider_terminal(&st, best);
                            record_path_stat(|stats| {
                                stats.unresolved_symbolic_memory += 1;
                                record_stop_site(stats, ins.va, "unresolved-symbolic-memory");
                            });
                            st.end_trace("unresolved-symbolic-memory");
                            return Vec::new();
                        }
                        continue;
                    }
                    Flow::Halt(halt) => {
                        consider_terminal(&st, best);
                        record_execution_halt(ins.va, &halt);
                        st.end_trace("execution-halt");
                        return Vec::new();
                    }
                    // These operation kinds are normalized and handled before
                    // `Machine::step`; seeing their flow here is a frontend or
                    // executor contract violation, not a successful path end.
                    Flow::Branch { .. } | Flow::Call(_) | Flow::Return => {
                        consider_terminal(&st, best);
                        record_path_stat(|stats| {
                            stats.unexpected_flow += 1;
                            record_stop_site(stats, ins.va, "unexpected-execution-flow");
                        });
                        st.end_trace("unexpected-execution-flow");
                        return Vec::new();
                    }
                }
            }
        }
    }

    // Fell off the end with no terminator → fall through to the next block.
    st.pc = block.end_va;
    vec![st]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::types::{CmpOp, Flag, LlirInstr, Op, VReg, Value, Width};

    fn func(blocks: Vec<(u64, Vec<Op>, u64)>) -> LlirFunction {
        let mut out = Vec::new();
        for (start, ops, end) in blocks {
            out.push(LlirBlock {
                start_va: start,
                end_va: end,
                instrs: ops
                    .into_iter()
                    .enumerate()
                    .map(|(i, op)| LlirInstr {
                        va: start + i as u64 * 4,
                        op,
                    })
                    .collect(),
                succs: vec![],
            });
        }
        LlirFunction {
            entry_va: out[0].start_va,
            blocks: out,
        }
    }

    #[test]
    fn finds_input_that_reaches_target_block() {
        // B0: zf = (rdi == 42) ; if zf jump WIN else fall through
        // WIN @0x2000: ret      ← target, reachable iff rdi == 42
        // FALL @0x1008: ret
        let lf = func(vec![
            (
                0x1000,
                vec![
                    Op::Cmp {
                        dst: VReg::Flag(Flag::Z),
                        op: CmpOp::Eq,
                        lhs: Value::Reg(VReg::phys("rdi")),
                        rhs: Value::Const(42),
                    },
                    Op::CondJump {
                        cond: VReg::Flag(Flag::Z),
                        target: 0x2000,
                        inverted: false,
                    },
                ],
                0x1008,
            ),
            (0x2000, vec![Op::Return], 0x2004),
            (0x1008, vec![Op::Return], 0x100c),
        ]);

        let result = find_input_reaching(
            &lf,
            0x2000,
            |m| {
                let sym = m.dom.fresh(Width::W64); // sym0 = rdi
                m.regs.write(&mut m.dom, &VReg::phys("rdi"), sym);
            },
            1000,
        );

        match result {
            SolveResult::Sat(model) => {
                assert_eq!(
                    model.values.get(&0).copied(),
                    Some(42),
                    "the reaching input must be rdi = 42"
                );
            }
            other => panic!("expected a reaching witness, got {:?}", other),
        }
    }

    #[test]
    fn symbolic_address_store_does_not_halt_exploration() {
        // B0: store [rdi], rax  (rdi symbolic → symbolic address) ; jmp SINK
        // SINK: ret
        // Before symbolic-address handling, the store halted the path and SINK was
        // unreachable. Now the address is concretized and the path reaches SINK —
        // the fundamental that lets driver code dereferencing attacker-controlled
        // pointers be explored (IOCTLance-style).
        use crate::ir::types::MemOp;
        let lf = func(vec![
            (
                0x1000,
                vec![
                    Op::Store {
                        addr: MemOp::plain(Some(VReg::phys("rdi")), None, 1, 0, 8),
                        src: Value::Reg(VReg::phys("rax")),
                    },
                    Op::Jump { target: 0x2000 },
                ],
                0x1008,
            ),
            (0x2000, vec![Op::Return], 0x2004),
        ]);
        let result = find_input_reaching(
            &lf,
            0x2000,
            |m| {
                let rdi = m.dom.fresh(Width::W64);
                m.regs.write(&mut m.dom, &VReg::phys("rdi"), rdi);
                let rax = m.dom.fresh(Width::W64);
                m.regs.write(&mut m.dom, &VReg::phys("rax"), rax);
            },
            1000,
        );
        assert!(
            matches!(result, SolveResult::Sat(_)),
            "symbolic-address store should be concretized, not halt the path; got {:?}",
            result
        );
    }

    #[test]
    fn symbolic_conditional_return_keeps_the_non_returning_path_reachable() {
        let lf = func(vec![
            (
                0x1000,
                vec![
                    Op::Cmp {
                        dst: VReg::Flag(Flag::Z),
                        op: CmpOp::Eq,
                        lhs: Value::Reg(VReg::phys("r0")),
                        rhs: Value::Const(0),
                    },
                    Op::CondReturn {
                        cond: VReg::Flag(Flag::Z),
                        inverted: false,
                    },
                ],
                0x1008,
            ),
            (0x1008, vec![Op::Return], 0x100c),
        ]);
        let result = find_input_reaching(
            &lf,
            0x1008,
            |machine| {
                let input = machine.dom.fresh(Width::W32);
                machine
                    .regs
                    .write(&mut machine.dom, &VReg::phys("r0"), input);
            },
            1000,
        );
        assert!(
            matches!(result, SolveResult::Sat(_)),
            "the false side of a symbolic conditional return must survive: {result:?}"
        );
    }

    #[test]
    fn symbolic_conditional_return_value_does_not_observe_false_path_undef() {
        let lf = func(vec![
            (
                0x1000,
                vec![
                    Op::Undef {
                        dst: VReg::phys("r1"),
                        reason: "unmodelled result".into(),
                    },
                    Op::Cmp {
                        dst: VReg::Flag(Flag::Z),
                        op: CmpOp::Eq,
                        lhs: Value::Reg(VReg::phys("r0")),
                        rhs: Value::Const(0),
                    },
                    Op::CondReturnValue {
                        cond: VReg::Flag(Flag::Z),
                        inverted: false,
                        value: Value::Reg(VReg::phys("r1")),
                    },
                ],
                0x100c,
            ),
            (0x100c, vec![Op::Return], 0x1010),
        ]);
        let result = find_input_reaching(
            &lf,
            0x100c,
            |machine| {
                let input = machine.dom.fresh(Width::W32);
                machine
                    .regs
                    .write(&mut machine.dom, &VReg::phys("r0"), input);
            },
            1000,
        );
        assert!(
            matches!(result, SolveResult::Sat(_)),
            "an undefined return value must not kill the non-returning path: {result:?}"
        );
    }

    #[test]
    fn false_conditional_memory_ops_do_not_concretize_their_address() {
        use crate::ir::types::MemOp;

        let mut machine = Machine::new(Symbolic::new());
        let symbolic_address = machine.dom.fresh(Width::W32);
        machine
            .regs
            .write(&mut machine.dom, &VReg::phys("r2"), symbolic_address);
        let old = machine.dom.constant(Width::W32, 0x1122_3344);
        machine.regs.write(&mut machine.dom, &VReg::phys("r1"), old);
        let false_value = machine.dom.constant(Width::W1, 0);
        machine
            .regs
            .write(&mut machine.dom, &VReg::Flag(Flag::Z), false_value);
        let mut state = State::root(machine, 0x1000, TaintSpec::new());

        assert_eq!(
            execute_memory_op(
                &mut state,
                &Op::CondLoad {
                    dst: VReg::phys("r1"),
                    cond: VReg::Flag(Flag::Z),
                    inverted: false,
                    addr: MemOp::plain(Some(VReg::phys("r2")), None, 1, 0, 4),
                    fallback: Value::Reg(VReg::phys("r1")),
                },
            ),
            Some(())
        );
        let retained = state
            .machine
            .regs
            .read(&mut state.machine.dom, &VReg::phys("r1"));
        assert_eq!(eval_concrete(&mut state, retained), Some(0x1122_3344));

        assert_eq!(
            execute_memory_op(
                &mut state,
                &Op::CondStore {
                    cond: VReg::Flag(Flag::Z),
                    inverted: false,
                    addr: MemOp::plain(Some(VReg::phys("r2")), None, 1, 0, 4),
                    src: Value::Reg(VReg::phys("r1")),
                },
            ),
            Some(())
        );
    }

    #[test]
    fn taint_through_uninitialized_memory_preserves_every_address_source() {
        use crate::ir::types::MemOp;

        let mut machine = Machine::new(Symbolic::new());
        let base = machine.dom.fresh(Width::W64);
        let index = machine.dom.fresh(Width::W64);
        machine
            .regs
            .write(&mut machine.dom, &VReg::phys("rdi"), base);
        machine
            .regs
            .write(&mut machine.dom, &VReg::phys("rsi"), index);

        let mut taint = TaintSpec::new();
        let Expr::Sym { id: base_id, .. } = *machine.dom.pool.get(base) else {
            panic!("fresh base must be a symbol");
        };
        let Expr::Sym { id: index_id, .. } = *machine.dom.pool.get(index) else {
            panic!("fresh index must be a symbol");
        };
        taint.mark(base_id, "Arg0");
        taint.mark(index_id, "SystemBuffer");

        let mut state = State::root(machine, 0x1000, taint);
        let op = Op::Load {
            dst: VReg::phys("rax"),
            addr: MemOp::plain(Some(VReg::phys("rdi")), Some(VReg::phys("rsi")), 1, 0, 8),
        };
        assert_eq!(execute_memory_op(&mut state, &op), Some(()));

        let loaded = state
            .machine
            .regs
            .read(&mut state.machine.dom, &VReg::phys("rax"));
        assert_eq!(
            state.taint.provenance_of(&state.machine.dom.pool, loaded),
            vec!["*Arg0".to_string(), "*SystemBuffer".to_string()],
            "taint-through-memory must not launder generic ArgN provenance into a high-confidence attacker label",
        );
    }

    #[test]
    fn attacker_pointer_constrained_near_rsp_is_not_structural_stack_storage() {
        let mut machine = Machine::new(Symbolic::new());
        let rsp = machine.dom.fresh(Width::W64);
        let dst = machine.dom.fresh(Width::W64);
        let len = machine.dom.fresh(Width::W64);
        machine
            .regs
            .write(&mut machine.dom, &VReg::phys("rsp"), rsp);

        let Expr::Sym { id: dst_id, .. } = *machine.dom.pool.get(dst) else {
            panic!("fresh destination must be a symbol");
        };
        let Expr::Sym { id: len_id, .. } = *machine.dom.pool.get(len) else {
            panic!("fresh length must be a symbol");
        };
        let mut taint = TaintSpec::new();
        taint.mark(dst_id, "*SystemBuffer");
        taint.mark(len_id, "*SystemBuffer");

        let stack_value = machine.dom.constant(Width::W64, 0x20_0000);
        let adjacent_value = machine.dom.constant(Width::W64, 0x1f_8000);
        let rsp_fixed = machine.dom.cmp(CmpOp::Eq, &rsp, &stack_value, Width::W64);
        let dst_fixed = machine
            .dom
            .cmp(CmpOp::Eq, &dst, &adjacent_value, Width::W64);
        let mut state = State::root(machine, 0x1000, taint);
        state.assert((rsp_fixed, true), "test", state.pc);
        state.assert((dst_fixed, true), "test", state.pc);
        let mut sinks = Vec::new();

        assert!(stack_overflow_check(
            &mut state, 0x1010, dst, len, &mut sinks,
        ));
        assert!(
            sinks.iter().all(|sink| sink.kind != SinkKind::StackOverflow),
            "numeric proximity under one model does not make an attacker pointer a stack object: {sinks:?}",
        );
    }

    #[test]
    fn frame_pointer_destination_is_structural_stack_storage() {
        let mut machine = Machine::new(Symbolic::new());
        // Mirror the real test_stack_overflow.sys expression shape: the executor
        // starts from a modeled zero stack, then preserves the pre-allocation
        // stack value in rbp while rsp moves down for the frame.
        let zero = machine.dom.constant(Width::W64, 0);
        let eight = machine.dom.constant(Width::W64, 8);
        let rbp = machine.dom.binop(BinOp::Sub, &zero, &eight, Width::W64);
        let frame_size = machine.dom.constant(Width::W64, 0x90);
        let rsp = machine.dom.binop(BinOp::Sub, &rbp, &frame_size, Width::W64);
        let local_offset = machine.dom.constant(Width::W64, 0x70);
        let dst = machine
            .dom
            .binop(BinOp::Sub, &rbp, &local_offset, Width::W64);
        let len = machine.dom.fresh(Width::W64);
        machine
            .regs
            .write(&mut machine.dom, &VReg::phys("rsp"), rsp);
        machine
            .regs
            .write(&mut machine.dom, &VReg::phys("rbp"), rbp);

        let Expr::Sym { id: len_id, .. } = *machine.dom.pool.get(len) else {
            panic!("fresh length must be a symbol");
        };
        let mut taint = TaintSpec::new();
        taint.mark(len_id, "InputBufferLength");

        let mut state = State::root(machine, 0x1000, taint);
        let mut sinks = Vec::new();

        assert!(stack_overflow_check(
            &mut state, 0x1010, dst, len, &mut sinks,
        ));
        assert!(
            sinks
                .iter()
                .any(|sink| sink.kind == SinkKind::StackOverflow),
            "an rbp-derived destination with attacker length is stack storage: {sinks:?}",
        );
    }

    #[test]
    fn model_driven_choices_require_a_satisfying_model() {
        let mut machine = Machine::new(Symbolic::new());
        let value = machine.dom.fresh(Width::W64);
        let zero = machine.dom.constant(Width::W8, 0);
        let one = machine.dom.constant(Width::W8, 1);
        let contradiction = machine.dom.cmp(CmpOp::Eq, &zero, &one, Width::W8);
        let mut state = State::root(machine, 0x1000, TaintSpec::new());
        state.assert((contradiction, true), "test", state.pc);

        assert_eq!(eval_concrete(&mut state, value), None);
        let constraints_before = state.constraints.clone();
        assert_eq!(concretize_addr(&mut state, value), None);
        assert_eq!(state.constraints, constraints_before);
    }

    #[test]
    fn explicit_concretization_policy_drives_both_value_selection_seams() {
        use crate::symbolic::concretization::BuiltinConcretizationPolicy;

        let mut representative_machine = Machine::new(Symbolic::new());
        let representative = representative_machine.dom.fresh(Width::W8);
        let five = representative_machine.dom.constant(Width::W8, 5);
        let ten = representative_machine.dom.constant(Width::W8, 10);
        let at_least_five =
            representative_machine
                .dom
                .cmp(CmpOp::Ule, &five, &representative, Width::W8);
        let at_most_ten =
            representative_machine
                .dom
                .cmp(CmpOp::Ule, &representative, &ten, Width::W8);
        let mut representative_state =
            State::root(representative_machine, 0x1000, TaintSpec::new());
        representative_state.assert((at_least_five, true), "test", 0x1000);
        representative_state.assert((at_most_ten, true), "test", 0x1000);
        let representative_constraints = representative_state.constraints.clone();

        assert_eq!(
            eval_concrete_with_policy(
                &mut representative_state,
                representative,
                &BuiltinConcretizationPolicy::LeastUnsigned,
            ),
            Some(5),
        );
        assert_eq!(
            representative_state.constraints, representative_constraints,
            "read-only representative selection must not bind the path",
        );

        let mut address_machine = Machine::new(Symbolic::new());
        let address = address_machine.dom.fresh(Width::W64);
        let low = address_machine.dom.constant(Width::W64, 0x1000);
        let high = address_machine.dom.constant(Width::W64, 0x2000);
        let at_least_low = address_machine
            .dom
            .cmp(CmpOp::Ule, &low, &address, Width::W64);
        let at_most_high = address_machine
            .dom
            .cmp(CmpOp::Ule, &address, &high, Width::W64);
        let mut address_state = State::root(address_machine, 0x2000, TaintSpec::new());
        address_state.assert((at_least_low, true), "test", 0x2000);
        address_state.assert((at_most_high, true), "test", 0x2000);
        let address_constraint_count = address_state.constraints.len();

        assert_eq!(
            concretize_addr_with_policy(
                &mut address_state,
                address,
                &BuiltinConcretizationPolicy::GreatestUnsigned,
            ),
            Some(0x2000),
        );
        assert_eq!(
            address_state.constraints.len(),
            address_constraint_count + 1,
            "address selection must bind exactly the chosen value",
        );
    }

    #[test]
    fn unsigned_model_choice_minimizes_the_expression_without_persisting_probes() {
        let mut machine = Machine::new(Symbolic::new());
        let value = machine.dom.fresh(Width::W8);
        let five = machine.dom.constant(Width::W8, 5);
        let ten = machine.dom.constant(Width::W8, 10);
        let at_least_five = machine.dom.cmp(CmpOp::Ule, &five, &value, Width::W8);
        let at_most_ten = machine.dom.cmp(CmpOp::Ule, &value, &ten, Width::W8);
        let mut state = State::root(machine, 0x1000, TaintSpec::new());
        state.assert((at_least_five, true), "test", state.pc);
        state.assert((at_most_ten, true), "test", state.pc);
        let constraints_before = state.constraints.clone();
        let location = state.pc;

        assert_eq!(
            minimize_unsigned_value(&mut state, value, "test-minimize", location),
            Some(5)
        );
        assert_eq!(state.constraints, constraints_before);
    }

    #[test]
    fn unsigned_model_choice_maximizes_the_expression_without_persisting_probes() {
        let mut machine = Machine::new(Symbolic::new());
        let value = machine.dom.fresh(Width::W8);
        let five = machine.dom.constant(Width::W8, 5);
        let ten = machine.dom.constant(Width::W8, 10);
        let at_least_five = machine.dom.cmp(CmpOp::Ule, &five, &value, Width::W8);
        let at_most_ten = machine.dom.cmp(CmpOp::Ule, &value, &ten, Width::W8);
        let mut state = State::root(machine, 0x1000, TaintSpec::new());
        state.assert((at_least_five, true), "test", state.pc);
        state.assert((at_most_ten, true), "test", state.pc);
        let constraints_before = state.constraints.clone();
        let location = state.pc;

        assert_eq!(
            maximize_unsigned_value(&mut state, value, "test-maximize", location),
            Some(10)
        );
        assert_eq!(state.constraints, constraints_before);
    }

    #[test]
    fn unsigned_model_choice_fails_closed_on_an_infeasible_path() {
        let before = canonical_model_choice_stats();
        let mut machine = Machine::new(Symbolic::new());
        let value = machine.dom.fresh(Width::W8);
        let zero = machine.dom.constant(Width::W8, 0);
        let one = machine.dom.constant(Width::W8, 1);
        let contradiction = machine.dom.cmp(CmpOp::Eq, &zero, &one, Width::W8);
        let mut state = State::root(machine, 0x1000, TaintSpec::new());
        state.assert((contradiction, true), "test", state.pc);
        let constraints_before = state.constraints.clone();
        let location = state.pc;

        assert_eq!(
            minimize_unsigned_value(&mut state, value, "test-minimize", location),
            None
        );
        assert_eq!(state.constraints, constraints_before);
        let after = canonical_model_choice_stats();
        assert!(after.infeasible > before.infeasible);
    }

    #[test]
    fn unsigned_model_choice_fails_closed_above_the_concrete_value_width() {
        let before = canonical_model_choice_stats();
        let mut machine = Machine::new(Symbolic::new());
        let value = machine.dom.fresh(Width::W256);
        let mut state = State::root(machine, 0x1000, TaintSpec::new());
        let location = state.pc;

        assert_eq!(
            minimize_unsigned_value(&mut state, value, "test-minimize", location),
            None
        );
        let after = canonical_model_choice_stats();
        assert!(after.inconclusive > before.inconclusive);
        assert!(after.unsupported_width > before.unsupported_width);
    }

    #[test]
    fn unreachable_target_is_unsat_or_exhausted() {
        // Single block that just returns; target 0x9999 is never reached.
        let lf = func(vec![(0x1000, vec![Op::Return], 0x1004)]);
        let result = find_input_reaching(&lf, 0x9999, |_| {}, 1000);
        assert!(
            matches!(result, SolveResult::Unsat | SolveResult::Unknown(_)),
            "got {:?}",
            result
        );
    }

    #[test]
    fn symbol_free_branch_never_skips_feasibility() {
        let mut machine = Machine::new(Symbolic::new());
        let one = machine.dom.constant(Width::W8, 1);
        let two = machine.dom.constant(Width::W8, 2);
        // Construct the constant comparison as a DAG node directly: the branch
        // classifier may see a syntactically non-constant node even though its
        // asserted true polarity is semantically UNSAT.
        let predicate = machine.dom.pool.intern(Expr::Cmp {
            op: CmpOp::Eq,
            a: one,
            b: two,
            width: Width::W8,
        });
        let state = State::root(machine, 0x1000, TaintSpec::new());
        assert!(!can_skip_feasibility_check(&state, predicate));
    }

    #[test]
    fn warm_solver_ownership_is_distinct_across_forks_and_restarts() {
        let machine = Machine::new(Symbolic::new());
        let mut root = State::root(machine, 0x1000, TaintSpec::new());
        root.warm_retain_assertions = 7;
        let child = root.fork(0x2000);
        assert_ne!(root.warm_path_id, child.warm_path_id);
        assert_eq!(child.warm_retain_assertions, 7);

        let original = root.warm_path_id;
        root.restart_trace();
        assert_ne!(root.warm_path_id, original);
        assert_ne!(root.warm_path_id, child.warm_path_id);
        assert_eq!(root.warm_retain_assertions, 0);
    }

    #[test]
    fn warm_owner_transfer_targets_the_next_lifo_successor_only() {
        let machine = Machine::new(Symbolic::new());
        let mut parent = State::root(machine, 0x1000, TaintSpec::new());
        let original_owner = parent.warm_path_id;

        let [(first_bit, first), (next_bit, next)] =
            parent.fork_branch_successors(0x2000, 0x3000, true, false);

        assert!(first_bit);
        assert!(!next_bit);
        assert_ne!(first.warm_path_id, original_owner);
        assert_eq!(next.warm_path_id, original_owner);
        assert_ne!(parent.warm_path_id, original_owner);
        assert_ne!(first.warm_path_id, parent.warm_path_id);
        assert_ne!(first.warm_path_id, next.warm_path_id);
    }

    #[test]
    fn source_ancestry_allows_serial_sibling_leasing_for_direct_delta() {
        assert!(effective_serial_sibling_reuse(true, false));
        assert!(effective_serial_sibling_reuse(true, true));
        assert!(!effective_serial_sibling_reuse(false, false));
        assert!(!effective_serial_sibling_reuse(false, true));
    }

    #[test]
    fn warm_source_ancestry_shares_only_the_exact_fork_prefix() {
        let machine = Machine::new(Symbolic::new());
        let mut parent = State::root(machine, 0x1000, TaintSpec::new());
        let base = parent.machine.dom.constant(Width::W1, 1);
        parent.assert((base, true), "base", parent.pc);

        let mut left = parent.fork(0x2000);
        let mut right = parent.fork(0x3000);
        // Both cloned pools may intern this identical expression to the same
        // numeric ExprId. Distinct source appends must still be distinct nodes.
        let left_branch = left.machine.dom.constant(Width::W1, 1);
        let right_branch = right.machine.dom.constant(Width::W1, 1);
        left.assert((left_branch, true), "left", left.pc);
        right.assert((right_branch, true), "right", right.pc);

        assert_eq!(parent.warm_assertion_prefix.depth(), 1);
        assert_eq!(left.warm_assertion_prefix.depth(), 2);
        assert_eq!(right.warm_assertion_prefix.depth(), 2);
        assert_eq!(
            left.warm_assertion_prefix
                .common_depth(&right.warm_assertion_prefix),
            1
        );
    }

    #[test]
    fn serial_sibling_reuse_keeps_one_logical_owner() {
        let machine = Machine::new(Symbolic::new());
        let mut parent = State::root(machine, 0x1000, TaintSpec::new());
        let owner = parent.warm_path_id;

        let [(first_bit, first), (next_bit, next)] =
            parent.fork_branch_successors(0x2000, 0x3000, true, true);

        assert!(first_bit);
        assert!(!next_bit);
        assert_eq!(parent.warm_path_id, owner);
        assert_eq!(first.warm_path_id, owner);
        assert_eq!(next.warm_path_id, owner);
    }

    /// The solver budget bails out of a runaway exploration. The block loops to
    /// itself on a symbolic condition, so without a cap it would fork forever (up
    /// to the state cap). With a small solver budget and a huge state cap, the
    /// *solver* budget is what stops it — proving the safety cap engages.
    #[test]
    fn solver_budget_bails_on_runaway_exploration() {
        use crate::symbolic::solver::{set_solver_budget, solver_meter, DEFAULT_SOLVER_BUDGET};
        let lf = func(vec![
            (
                0x1000,
                vec![
                    Op::Cmp {
                        dst: VReg::Flag(Flag::Z),
                        op: CmpOp::Eq,
                        lhs: Value::Reg(VReg::phys("rdi")),
                        rhs: Value::Const(0),
                    },
                    Op::CondJump {
                        cond: VReg::Flag(Flag::Z),
                        target: 0x2000,
                        inverted: false,
                    },
                ],
                0x1000, // fall-through loops back to the block's own start
            ),
            (0x2000, vec![Op::Return], 0x2004),
        ]);

        set_solver_budget(40, 5);
        let sinks = find_sinks(
            &lf,
            |m| {
                let s = m.dom.fresh(Width::W64);
                m.regs.write(&mut m.dom, &VReg::phys("rdi"), s);
                TaintSpec::new()
            },
            &CallModel::new(),
            1_000_000, // huge state cap: the *solver* budget must be what stops it
        );
        let (solves, _) = solver_meter();
        set_solver_budget(DEFAULT_SOLVER_BUDGET.0, DEFAULT_SOLVER_BUDGET.1);

        assert!(
            solves <= 80,
            "should bail near the 40-solve budget, did {solves}"
        );
        assert!(sinks.is_empty(), "no attacker memory ops in the loop");
    }

    #[test]
    fn worklist_reports_a_per_function_deadline_stop() {
        use std::time::Duration;

        use crate::symbolic::solver::set_time_budget;

        let lf = func(vec![(0x1000, vec![Op::Return], 0x1004)]);
        let blocks: HashMap<u64, LlirBlock> = lf
            .blocks
            .iter()
            .map(|block| (block.start_va, block.clone()))
            .collect();
        let root = State::root(Machine::new(Symbolic::new()), lf.entry_va, TaintSpec::new());

        reset_exploration_limit_stats();
        set_time_budget(Some(Duration::ZERO));
        let (_, _, stop) = run_worklist(&blocks, root, &CallModel::new(), 1);
        set_time_budget(None);

        assert_eq!(stop, WorklistStop::Deadline);
        assert_eq!(
            exploration_limit_stats(),
            ExplorationLimitStats {
                runs: 1,
                deadline: 1,
                ..ExplorationLimitStats::default()
            }
        );
    }

    #[test]
    fn completed_worklist_still_reports_unsupported_semantic_stop() {
        let lf = func(vec![(
            0x1000,
            vec![Op::Intrinsic {
                name: "unmodeled_vector_op".into(),
                ins: Vec::new(),
                outs: Vec::new(),
                reads_mem: false,
                writes_mem: false,
            }],
            0x1004,
        )]);

        reset_exploration_limit_stats();
        reset_execution_path_stats();
        let _ = find_sinks(&lf, |_| TaintSpec::new(), &CallModel::new(), 8);

        assert_eq!(exploration_limit_stats().completed, 1);
        assert_eq!(
            execution_path_stats(),
            ExecutionPathStats {
                unsupported_intrinsics: BTreeMap::from([("unmodeled_vector_op".to_string(), 1,)]),
                stop_sites: BTreeMap::from([(
                    0x1000,
                    BTreeMap::from([("unsupported-intrinsic:unmodeled_vector_op".to_string(), 1,)]),
                )]),
                ..ExecutionPathStats::default()
            }
        );
        assert_eq!(execution_path_stats().incomplete_stops(), 1);
    }

    #[test]
    fn undefined_value_is_an_explicit_incomplete_semantic_stop() {
        reset_execution_path_stats();

        record_execution_halt(0x1234, &Halt::UndefinedValue("unmodelled-predicate".into()));

        let stats = execution_path_stats();
        assert_eq!(
            stats.undefined_values,
            BTreeMap::from([("unmodelled-predicate".to_string(), 1)])
        );
        assert_eq!(
            stats.stop_sites,
            BTreeMap::from([(
                0x1234,
                BTreeMap::from([("undefined-value:unmodelled-predicate".to_string(), 1)]),
            )])
        );
        assert_eq!(stats.incomplete_stops(), 1);
        assert_eq!(stats.modeled_terminal_paths(), 0);
    }

    #[test]
    fn architectural_trap_is_a_modeled_terminal_not_an_unsupported_stop() {
        let lf = func(vec![(
            0x1000,
            vec![Op::Intrinsic {
                name: "brk".into(),
                ins: Vec::new(),
                outs: Vec::new(),
                reads_mem: false,
                writes_mem: false,
            }],
            0x1004,
        )]);

        reset_execution_path_stats();
        let _ = find_sinks(&lf, |_| TaintSpec::new(), &CallModel::new(), 8);

        let stats = execution_path_stats();
        assert_eq!(stats.traps, BTreeMap::from([("brk".to_string(), 1)]));
        assert_eq!(
            stats.stop_sites,
            BTreeMap::from([(0x1000, BTreeMap::from([("trap:brk".to_string(), 1)]))])
        );
        assert!(stats.unsupported_intrinsics.is_empty());
        assert_eq!(stats.incomplete_stops(), 0);
        assert_eq!(stats.modeled_terminal_paths(), 1);
    }

    /// The per-path loop bound alone (with the *default*, huge solver budget)
    /// stops a self-looping function quickly — bounding symbolic expression growth
    /// at its source. Without it, the loop would fork up to the state cap.
    #[test]
    fn loop_bound_cuts_runaway_path() {
        use crate::symbolic::solver::{set_solver_budget, solver_meter, DEFAULT_SOLVER_BUDGET};
        let lf = func(vec![
            (
                0x1000,
                vec![
                    Op::Cmp {
                        dst: VReg::Flag(Flag::Z),
                        op: CmpOp::Eq,
                        lhs: Value::Reg(VReg::phys("rdi")),
                        rhs: Value::Const(0),
                    },
                    Op::CondJump {
                        cond: VReg::Flag(Flag::Z),
                        target: 0x2000,
                        inverted: false,
                    },
                ],
                0x1000, // fall-through loops back to self
            ),
            (0x2000, vec![Op::Return], 0x2004),
        ]);
        set_solver_budget(DEFAULT_SOLVER_BUDGET.0, DEFAULT_SOLVER_BUDGET.1);
        let _ = find_sinks(
            &lf,
            |m| {
                let s = m.dom.fresh(Width::W64);
                m.regs.write(&mut m.dom, &VReg::phys("rdi"), s);
                TaintSpec::new()
            },
            &CallModel::new(),
            1_000_000, // huge state cap: the loop bound, not the cap, must stop it
        );
        let (solves, _) = solver_meter();
        assert!(
            solves < 200,
            "loop bound should keep a self-loop's solving tiny, did {solves}"
        );
    }
}
