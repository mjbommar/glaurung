//! Worklist and terminal-path accounting for the explorer.
//!
//! Nothing here decides anything: these are the counters and the
//! thread-local telemetry that make a partial exploration legible. A
//! worklist that stopped on a wall-clock deadline and one that exhausted
//! its states both "finish", and only this partition tells them apart.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::time::Instant;

use crate::exec::Halt;

use super::ApiSummary;

/// Process-local accounting for how symbolic worklists finish.
///
/// A function can be counted as selected by a caller while its internal
/// exploration is only partial. Keeping these stop classes explicit prevents a
/// wall-clock safety cutoff from being mistaken for deterministic fixed work.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ExplorationLimitStats {
    /// Worklists started by this process.
    pub runs: u64,
    /// Worklists that exhausted all reachable states under the path semantics.
    pub completed: u64,
    /// Worklists stopped by their state-count ceiling.
    pub state_budget: u64,
    /// Worklists stopped by their solver-call ceiling.
    pub solve_budget: u64,
    /// Worklists stopped by their solver-unknown/timeout ceiling.
    pub timeout_budget: u64,
    /// Worklists stopped by their per-function wall-clock safety deadline.
    pub deadline: u64,
}

/// Process-local accounting for terminal symbolic paths.
///
/// Exhausting a worklist is not enough to establish complete execution: every
/// path may have stopped at an unsupported intrinsic, residual unknown, or
/// unavailable model.  This partition makes those semantic stops visible to
/// evidence producers instead of collapsing them into `completed` worklists.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExecutionPathStats {
    /// Paths that reached an architectural return.
    pub returned: u64,
    /// Paths that reached an architectural trap instruction.
    pub traps: BTreeMap<String, u64>,
    /// Paths that transferred outside the admitted CFG.
    pub off_cfg: u64,
    /// Paths cut by the deterministic per-block visit ceiling.
    pub loop_limit: u64,
    /// Paths stopped because a required concrete model was unavailable.
    pub model_unavailable: u64,
    /// Paths stopped because a symbolic memory address could not be resolved.
    pub unresolved_symbolic_memory: u64,
    /// Unregistered non-trap intrinsics reached by execution.
    pub unsupported_intrinsics: BTreeMap<String, u64>,
    /// Residual unknown operations reached by execution.
    pub residual_unknowns: BTreeMap<String, u64>,
    /// Explicitly undefined or unmodelled values demanded by execution.
    pub undefined_values: BTreeMap<String, u64>,
    /// Paths that unexpectedly requested an interpreter fork.
    pub unexpected_fork: u64,
    /// Paths stopped by an interpreter instruction budget.
    pub budget_exhausted: u64,
    /// Unexpected interpreter flow outcomes after frontend normalization.
    pub unexpected_flow: u64,
    /// Dynamic calls that used the explorer's implicit return-value havoc
    /// fallback instead of a registered callee summary.
    pub unmodeled_calls: BTreeMap<u64, u64>,
    /// Exact terminal instruction/PC sites, partitioned by stable stop reason.
    pub stop_sites: BTreeMap<u64, BTreeMap<String, u64>>,
    /// Dynamic memory-access counts by instruction VA.
    pub memory_access_sites: BTreeMap<u64, u64>,
    /// Dynamic accesses whose address was concretely inside the first page.
    pub low_page_access_sites: BTreeMap<u64, u64>,
    /// Concrete dynamic addresses observed at each memory-access instruction.
    pub concrete_access_addresses: BTreeMap<u64, BTreeMap<u64, u64>>,
}

impl ExecutionPathStats {
    /// Number of semantic/infrastructure stops that make execution incomplete.
    pub fn incomplete_stops(&self) -> u64 {
        self.off_cfg
            + self.loop_limit
            + self.model_unavailable
            + self.unresolved_symbolic_memory
            + self.unsupported_intrinsics.values().sum::<u64>()
            + self.residual_unknowns.values().sum::<u64>()
            + self.undefined_values.values().sum::<u64>()
            + self.unexpected_fork
            + self.budget_exhausted
            + self.unexpected_flow
            + self.unmodeled_calls.values().sum::<u64>()
    }

    /// Number of paths that ended with modeled architectural control flow.
    pub fn modeled_terminal_paths(&self) -> u64 {
        self.returned + self.traps.values().sum::<u64>()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum WorklistStop {
    Complete,
    StateBudget,
    SolveBudget,
    TimeoutBudget,
    Deadline,
}

thread_local! {
    /// Per-function wall-clock deadline, set by [`run_worklist`] and checked
    /// *per instruction* so a single block built from huge (obfuscated)
    /// expressions can still be interrupted — coarser checks at block boundaries
    /// are not enough when one block takes minutes.
    pub(super) static DEADLINE: Cell<Option<Instant>> = const { Cell::new(None) };

    /// Set only when [`process_block`] observes the per-function deadline. This
    /// distinguishes an interrupted final state from a naturally exhausted
    /// worklist whose last instruction happened to finish near the deadline.
    pub(super) static DEADLINE_OBSERVED: Cell<bool> = const { Cell::new(false) };

    /// Process-thread accounting used by the single-threaded analysis examples.
    static EXPLORATION_LIMIT_STATS: Cell<ExplorationLimitStats> =
        const { Cell::new(ExplorationLimitStats {
            runs: 0,
            completed: 0,
            state_budget: 0,
            solve_budget: 0,
            timeout_budget: 0,
            deadline: 0,
        }) };

    /// Terminal-path accounting for the current analysis thread.
    static EXECUTION_PATH_STATS: RefCell<ExecutionPathStats> =
        RefCell::new(ExecutionPathStats::default());

    /// Summaries keyed by CALL-INSTRUCTION VA (not callee VA). Used for indirect
    /// calls whose callee cannot be resolved statically — notably KMDF WDF
    /// function-table calls (`mov rax,[WdfFunctions+idx*8]; call *[thunk]`), which
    /// all share one dynamic thunk so they cannot be keyed by callee. The runner
    /// detects e.g. `WdfRequestRetrieveInputBuffer` call sites and registers a
    /// [`ApiSummary::RetrieveBuffer`] here so the engine taints the retrieved
    /// buffer as `SystemBuffer` (the KMDF analogue of IRP.AssociatedIrp.SystemBuffer).
    static CALL_SITE_SUMMARIES: RefCell<BTreeMap<u64, ApiSummary>> =
        const { RefCell::new(BTreeMap::new()) };
}

/// Return cumulative worklist stop accounting for this analysis thread.
pub fn exploration_limit_stats() -> ExplorationLimitStats {
    EXPLORATION_LIMIT_STATS.with(Cell::get)
}

/// Clear cumulative worklist stop accounting before a new top-level analysis.
pub fn reset_exploration_limit_stats() {
    EXPLORATION_LIMIT_STATS.with(|stats| stats.set(ExplorationLimitStats::default()));
}

/// Return cumulative terminal-path accounting for this analysis thread.
pub fn execution_path_stats() -> ExecutionPathStats {
    EXECUTION_PATH_STATS.with(|stats| stats.borrow().clone())
}

/// Clear cumulative terminal-path accounting before a new top-level analysis.
pub fn reset_execution_path_stats() {
    EXECUTION_PATH_STATS.with(|stats| *stats.borrow_mut() = ExecutionPathStats::default());
}

pub(super) fn record_path_stat(update: impl FnOnce(&mut ExecutionPathStats)) {
    EXECUTION_PATH_STATS.with(|stats| update(&mut stats.borrow_mut()));
}

fn record_named(counter: &mut BTreeMap<String, u64>, name: &str) {
    *counter.entry(name.to_string()).or_default() += 1;
}

pub(super) fn record_stop_site(stats: &mut ExecutionPathStats, va: u64, reason: impl Into<String>) {
    *stats
        .stop_sites
        .entry(va)
        .or_default()
        .entry(reason.into())
        .or_default() += 1;
}

fn is_architectural_trap(name: &str) -> bool {
    matches!(
        name,
        "brk" | "hlt" | "svc" | "hvc" | "smc" | "udf" | "dcps1" | "dcps2" | "dcps3"
    )
}

pub(super) fn record_execution_halt(va: u64, halt: &Halt) {
    record_path_stat(|stats| match halt {
        Halt::UnsupportedIntrinsic(name) if is_architectural_trap(name) => {
            record_named(&mut stats.traps, name);
            record_stop_site(stats, va, format!("trap:{name}"));
        }
        Halt::UnsupportedIntrinsic(name) => {
            record_named(&mut stats.unsupported_intrinsics, name);
            record_stop_site(stats, va, format!("unsupported-intrinsic:{name}"));
        }
        Halt::ResidualUnknown(mnemonic) => {
            record_named(&mut stats.residual_unknowns, mnemonic);
            record_stop_site(stats, va, format!("residual-unknown:{mnemonic}"));
        }
        Halt::UndefinedValue(reason) => {
            record_named(&mut stats.undefined_values, reason);
            record_stop_site(stats, va, format!("undefined-value:{reason}"));
        }
        Halt::UnexpectedFork => {
            stats.unexpected_fork += 1;
            record_stop_site(stats, va, "unexpected-fork");
        }
        Halt::UnresolvedAddress => {
            stats.unresolved_symbolic_memory += 1;
            record_stop_site(stats, va, "unresolved-symbolic-memory");
        }
        Halt::BudgetExhausted => {
            stats.budget_exhausted += 1;
            record_stop_site(stats, va, "budget-exhausted");
        }
    });
}

pub(super) fn record_worklist_stop(stop: WorklistStop) {
    EXPLORATION_LIMIT_STATS.with(|stats| {
        let mut next = stats.get();
        next.runs += 1;
        match stop {
            WorklistStop::Complete => next.completed += 1,
            WorklistStop::StateBudget => next.state_budget += 1,
            WorklistStop::SolveBudget => next.solve_budget += 1,
            WorklistStop::TimeoutBudget => next.timeout_budget += 1,
            WorklistStop::Deadline => next.deadline += 1,
        }
        stats.set(next);
    });
}

pub(super) fn deadline_passed() -> bool {
    DEADLINE
        .with(Cell::get)
        .is_some_and(|dl| Instant::now() >= dl)
}

/// Register call-site-keyed summaries (see [`CALL_SITE_SUMMARIES`]). Set once per
/// function before [`find_function_sinks_with_apis`]; pass an empty map to clear.
pub fn set_call_site_summaries(map: BTreeMap<u64, ApiSummary>) {
    CALL_SITE_SUMMARIES.with(|c| *c.borrow_mut() = map);
}

pub(super) fn call_site_summary(va: u64) -> Option<ApiSummary> {
    CALL_SITE_SUMMARIES.with(|c| c.borrow().get(&va).copied())
}
