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
use crate::exec::{Concrete, Flow, Halt, Machine};
use crate::ir::types::{BinOp, CallTarget, CmpOp, LlirBlock, LlirFunction, Op, VReg, Value, Width};
use crate::symbolic::expr::{Expr, ExprId, ExprPool};
use crate::symbolic::solver::{solve, Assert, Model, SolveResult};
use crate::symbolic::Symbolic;

/// A sentinel address the attacker would "love to" write to — distinct from any
/// plausible legitimate pointer. If the solver can satisfy `addr == SENTINEL`
/// under the path condition, the write target is *fully* attacker-chosen (a true
/// write-where primitive), not merely symbolic-but-bounded. Mirrors IOCTLance's
/// `0x87` arbitrariness probe.
const SENTINEL_ADDR: u128 = 0x8787_8787_8787_8787;

/// How much control the attacker has over a sink's target address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// The address can be pinned to an arbitrary sentinel → write/read-where.
    Arbitrary,
    /// The address is attacker-derived but constrained (e.g. into a bounded
    /// buffer) — controlled *content/offset*, but not an arbitrary location.
    Constrained,
}

/// Which attacker-input fields a value is derived from, so a sink can be
/// labelled with provenance (e.g. an address built from `SystemBuffer`).
/// Symbols not present here are engine-internal (not attacker-controlled), so a
/// sink whose address touches no marked symbol is *not* a controlled primitive.
#[derive(Debug, Clone, Default)]
pub struct TaintSpec {
    labels: BTreeMap<u32, String>,
}

impl TaintSpec {
    pub fn new() -> Self {
        Self::default()
    }

    /// Mark symbol `sym_id` as attacker-controlled input named `label`.
    pub fn mark(&mut self, sym_id: u32, label: impl Into<String>) {
        self.labels.insert(sym_id, label.into());
    }

    /// The label for a symbol, if it is attacker-controlled.
    pub fn label(&self, sym_id: u32) -> Option<&str> {
        self.labels.get(&sym_id).map(String::as_str)
    }

    /// The distinct attacker-input labels an expression's free symbols carry.
    fn provenance_of(&self, pool: &ExprPool, root: ExprId) -> Vec<String> {
        let mut syms = BTreeMap::new();
        pool.collect_syms(root, &mut syms);
        syms.keys()
            .filter_map(|id| self.label(*id).map(str::to_string))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }
}

/// The class of dangerous condition a [`Sink`] represents. These mirror the
/// detector set of the IOCTLance fork, produced here by our own engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SinkKind {
    /// A store through an attacker-derived address (write-what-where primitive).
    ControlledWrite,
    /// A load through an attacker-derived address (arbitrary read / info leak).
    ControlledRead,
    /// A dereference of a pointer the attacker can drive to NULL on this path
    /// (i.e. the path condition does *not* already guard it non-null).
    NullDeref,
    /// An attacker-controlled-length copy onto the stack (`memcpy(stack, …, len)`),
    /// the classic stack buffer overflow → RCE primitive.
    StackOverflow,
    /// A dereference / API use of a heap block that has already been freed.
    UseAfterFree,
    /// A second `ExFreePool` on a pointer already freed on this path.
    DoubleFree,
    /// An attacker-tainted arithmetic op whose result can wrap/overflow.
    IntegerOverflow,
    /// The same attacker pointer is dereferenced twice (TOCTOU double-fetch).
    DoubleFetch,
    /// An indirect call/jump whose target is attacker-controlled (control hijack).
    Shellcode,
    /// An attacker-controlled format string passed to a `printf`-family routine.
    FormatString,
    /// An attacker-tainted physical-address / size into `MmMapIoSpace`-style APIs.
    PhysicalMemory,
    /// A `ProbeForRead`/`ProbeForWrite` that can be bypassed (zero length).
    ProbeBypass,
    /// An attacker-tainted handle/PID into a process-termination API.
    ProcessTermination,
    /// An attacker-tainted path/handle into a file API.
    FileOperation,
}

/// A summary for a known callee, letting the explorer detect attacker-controlled
/// primitives hidden *inside* an API call without descending into it. (Many
/// driver write-what-where bugs are a `memcpy(attacker_ptr, …)`, never a raw
/// symbolic store.) The analysis layer maps each callee VA to a summary; the
/// engine stays import-agnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiSummary {
    /// `memcpy` / `RtlCopyMemory` / `memmove` with the MS x64 ABI
    /// `(dst = rcx, src = rdx, len = r8)`: `dst` is written and `src` is read,
    /// so an attacker-derived `dst`/`src` is a controlled write/read primitive.
    /// Also flags a [`SinkKind::StackOverflow`] when `dst` is on the stack and
    /// `len` is attacker-controlled.
    CopyMemory,
    /// A pool allocator (`ExAllocatePoolWithTag`: `size = rdx`) — hands back a
    /// fresh tracked heap block in `rax` so frees and use-after-free can be
    /// followed.
    Alloc { size_arg: u8 },
    /// A pool free (`ExFreePool`/`ExFreePoolWithTag`: `ptr = rcx`) — marks the
    /// block freed; a second free of the same block is a [`SinkKind::DoubleFree`].
    Free { ptr_arg: u8 },
    /// `ProbeForRead`/`ProbeForWrite` (`addr = rcx, len = rdx`): a probe whose
    /// length can be 0 is bypassable ([`SinkKind::ProbeBypass`]); a successful
    /// probe marks `addr` validated so later derefs of it are not re-flagged.
    Probe { addr_arg: u8, len_arg: u8 },
    /// A routine that is dangerous when any of `args` is attacker-tainted, raising
    /// `kind` (e.g. `ZwTerminateProcess` arg0 → [`SinkKind::ProcessTermination`],
    /// `MmMapIoSpace` args 0/1 → [`SinkKind::PhysicalMemory`], `sprintf` fmt arg →
    /// [`SinkKind::FormatString`], `ZwCreateFile` path → [`SinkKind::FileOperation`]).
    DangerousCall { args: &'static [u8], kind: SinkKind },
}

/// Maps a call-target VA to its [`ApiSummary`]. Populated by the analysis layer
/// (e.g. from a driver's import/thunk table).
pub type CallModel = HashMap<u64, ApiSummary>;

/// A dangerous memory access found during exploration, with a concrete input
/// ([`Model`]) that triggers it. These are the IOCTLance signals — arbitrary
/// read/write primitives and null derefs reachable from an IOCTL — but produced
/// by our own engine, path-sensitively (so a guarded deref is not reported).
#[derive(Debug, Clone)]
pub struct Sink {
    /// VA of the accessing instruction.
    pub va: u64,
    /// What kind of dangerous access this is.
    pub kind: SinkKind,
    /// A satisfying assignment of the symbolic inputs that triggers this sink
    /// (for null derefs, an input that drives the pointer to 0).
    pub witness: Model,
    /// Whether the target address is fully attacker-chosen or merely constrained.
    pub severity: Severity,
    /// The attacker-input fields the target address derives from (provenance).
    pub tainted_by: Vec<String>,
}

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
}

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
        }
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

    while let Some(st) = work.pop() {
        if explored >= max_states {
            return SolveResult::Unknown;
        }
        explored += 1;

        if st.pc == target {
            // Reached the target: solve the accumulated path condition for a
            // concrete input that drives execution here.
            return solve(&st.machine.dom.pool, &st.constraints);
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
    let blocks: HashMap<u64, LlirBlock> =
        lf.blocks.iter().map(|b| (b.start_va, b.clone())).collect();

    let mut machine = Machine::new(Symbolic::new());
    let taint = seed(&mut machine);
    let (sinks, _) = run_worklist(
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
        *best = Some(st.clone());
    }
}

/// Drive the DFS worklist from `root`, returning the sinks found and the terminal
/// path that advanced the heap lifecycle furthest (for stateful carry-over).
fn run_worklist(
    blocks: &HashMap<u64, LlirBlock>,
    root: State,
    apis: &CallModel,
    max_states: usize,
) -> (Vec<Sink>, Option<State>) {
    let mut work = vec![root];
    let mut explored = 0usize;
    let mut out = Vec::new();
    let mut best: Option<State> = None;

    while let Some(st) = work.pop() {
        if explored >= max_states {
            break;
        }
        explored += 1;
        let mut sinks = Vec::new();
        let succs = process_block(blocks, st, apis, &mut sinks, &mut best);
        out.append(&mut sinks);
        for s in succs {
            work.push(s);
        }
    }
    (out, best)
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
                st.validated.clear();
                st.tainted_reads.clear();
                st
            }
            None => {
                let mut machine = Machine::new(Symbolic::new());
                let taint = seed(&mut machine);
                State::root(machine, lf.entry_va, taint)
            }
        };

        let (sinks, best) = run_worklist(&blocks, root, apis, max_states);
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
        return Vec::new();
    };

    for ins in &block.instrs {
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
                        let independent = !shares_symbols(&st, c);
                        let mut out = Vec::new();
                        for (bit, npc) in [(true, pc_if_true), (false, pc_if_false)] {
                            let mut child = st.fork(npc);
                            child.constraints.push((c, bit));
                            if independent
                                || !matches!(
                                    solve(&child.machine.dom.pool, &child.constraints),
                                    SolveResult::Unsat
                                )
                            {
                                out.push(child);
                            }
                        }
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
            Op::Call { target } => {
                let callee: Option<u64> = match target {
                    CallTarget::Direct(va) => Some(*va),
                    CallTarget::Indirect(Value::Addr(va)) => Some(*va),
                    CallTarget::Indirect(v) => {
                        let tv = st.machine.read(v, Width::W64);
                        let mut syms = BTreeMap::new();
                        st.machine.dom.pool.collect_syms(tv, &mut syms);
                        if syms.is_empty() {
                            // Concrete function pointer (e.g. loaded from the IAT).
                            Some(eval_concrete(&mut st, tv))
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
                    Some(summary) => apply_summary(&mut st, ins.va, summary, sinks),
                    // An unmodeled callee (a local helper, logging, etc.) is
                    // treated as opaque: havoc the return and continue, rather than
                    // ending the path. Ending here would cut off everything after a
                    // `DbgPrint`/helper call — including the bug.
                    None => havoc_rax(&mut st),
                }
                continue;
            }
            Op::Return => {
                consider_terminal(&st, best);
                return Vec::new();
            }
            other => {
                check_int_overflow(&mut st, ins.va, other, sinks);
                // Use-after-free is temporal, not address-symbolic: check every
                // load/store target (concrete or symbolic) against freed blocks,
                // so a deref of a freed pointer held in a global is caught.
                if let Op::Load { addr, .. } | Op::Store { addr, .. } = other {
                    let av = st.machine.eval_addr(addr);
                    uaf_check(&mut st, ins.va, av, sinks);
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
                        if symbolic_mem_op(&mut st, other, ins.va, sinks).is_none() {
                            consider_terminal(&st, best);
                            return Vec::new();
                        }
                        continue;
                    }
                    // Branch shouldn't occur (CondJump handled above); other
                    // halts / return / call end the path.
                    _ => {
                        consider_terminal(&st, best);
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

/// Concretize a symbolic address: solve the path condition for a model, evaluate
/// the address expression under it, and bind `addr == chosen` so the path stays
/// consistent (the "any" strategy; concretize-with-threshold for reads is a
/// later refinement). Returns the concrete address.
fn concretize_addr(st: &mut State, addr_val: ExprId) -> u64 {
    let model = match solve(&st.machine.dom.pool, &st.constraints) {
        SolveResult::Sat(m) => m.values,
        _ => BTreeMap::new(),
    };
    let mut c = Concrete;
    let a = eval_expr(&st.machine.dom.pool, addr_val, &model, &mut c);
    let chosen = st.machine.dom.constant(Width::W64, a);
    let eq = st
        .machine
        .dom
        .cmp(CmpOp::Eq, &addr_val, &chosen, Width::W64);
    st.constraints.push((eq, true));
    a as u64
}

/// If the attacker can drive `addr_val` to exactly `value` under the current path
/// condition, return a triggering model; otherwise `None`. The probe constraint
/// is built in a throwaway copy so the path condition is left untouched. This is
/// the primitive behind both the [`SENTINEL_ADDR`] arbitrariness test and the
/// `addr == 0` null-deref test.
fn witness_for_value(st: &mut State, addr_val: ExprId, value: u128) -> Option<Model> {
    let w = st.machine.dom.pool.width_of(addr_val);
    let target = st.machine.dom.constant(w, value);
    let eq = st.machine.dom.cmp(CmpOp::Eq, &addr_val, &target, w);
    let mut probe = st.constraints.clone();
    probe.push((eq, true));
    match solve(&st.machine.dom.pool, &probe) {
        SolveResult::Sat(m) => Some(m),
        _ => None,
    }
}

/// The MS x64 integer argument register for parameter index `n` (0-based).
fn arg_reg(n: u8) -> &'static str {
    match n {
        0 => "rcx",
        1 => "rdx",
        2 => "r8",
        3 => "r9",
        _ => "rsp", // beyond arg3 args are on the stack; unmodeled → harmless
    }
}

/// Read call argument `n` as a symbolic value.
fn read_arg(st: &mut State, n: u8) -> ExprId {
    st.machine
        .regs
        .read(&mut st.machine.dom, &VReg::phys(arg_reg(n)))
}

/// Concretely evaluate `val` under a model of the current path *without* binding
/// it (a read-only probe, unlike [`concretize_addr`]). Used by the lifecycle
/// checks (free/UAF/stack) that only need a representative concrete value.
fn eval_concrete(st: &mut State, val: ExprId) -> u64 {
    let model = match solve(&st.machine.dom.pool, &st.constraints) {
        SolveResult::Sat(m) => m.values,
        _ => BTreeMap::new(),
    };
    let mut c = Concrete;
    eval_expr(&st.machine.dom.pool, val, &model, &mut c) as u64
}

/// A reaching witness for the current path: the empty model when there are no
/// constraints (no solver call needed), otherwise a solve. `None` only when the
/// path is provably infeasible (Unsat); Unknown/NoSolver are kept as a sound
/// over-approximation. This avoids a z3 context-build per sink on shallow paths.
fn reach_model(st: &State) -> Option<Model> {
    if st.constraints.is_empty() {
        return Some(Model::default());
    }
    match solve(&st.machine.dom.pool, &st.constraints) {
        SolveResult::Sat(m) => Some(m),
        SolveResult::Unsat => None,
        _ => Some(Model::default()),
    }
}

/// True if `pred`'s free symbols overlap any symbol already in the path
/// condition — i.e. adding `pred` could interact with (and possibly contradict)
/// the existing constraints, so a feasibility solve is warranted.
fn shares_symbols(st: &State, pred: ExprId) -> bool {
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
            return true;
        }
    }
    false
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
fn freely_controllable(st: &State, addr: ExprId) -> bool {
    is_affine_unit(&st.machine.dom.pool, addr) && unconstrained(st, addr)
}

/// The arbitrariness severity of an address: `Arbitrary` if it is freely
/// controllable (fast path, no solve) or the solver can pin it to the sentinel;
/// else `Constrained`.
fn severity_of(st: &mut State, addr: ExprId) -> Severity {
    if freely_controllable(st, addr) || witness_for_value(st, addr, SENTINEL_ADDR).is_some() {
        Severity::Arbitrary
    } else {
        Severity::Constrained
    }
}

/// Emit a `kind` sink (with reaching witness and arbitrariness severity from
/// `severity_for`) when the path is satisfiable. `tainted_by` is the provenance.
fn push_sink(
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

/// Record the sink(s) for a memory access at `va` through `addr_val`. Emits a
/// controlled read/write (severity from the sentinel test), a double-fetch if the
/// same attacker pointer was read before, a null-deref if the pointer can be NULL
/// on this path, and a use-after-free if it lands in a freed block. An address
/// touching no attacker input — or one already validated by a probe — is not a
/// primitive and is skipped (the precision gate).
fn record_access(st: &mut State, va: u64, addr_val: ExprId, write: bool, sinks: &mut Vec<Sink>) {
    // A deref entirely covered by a probed (validated) region is trusted.
    if is_validated(st, addr_val) {
        return;
    }
    let tainted_by = st.taint.provenance_of(&st.machine.dom.pool, addr_val);
    if tainted_by.is_empty() {
        return; // internally-symbolic address: not an attacker primitive
    }
    // Solve the path condition once and reuse it for every sink at this access
    // (controlled R/W, double-fetch, null-deref) instead of re-solving per sink.
    let Some(reach) = reach_model(st) else {
        return; // path infeasible
    };
    let free_addr = freely_controllable(st, addr_val);
    let severity = if free_addr {
        Severity::Arbitrary
    } else {
        severity_of(st, addr_val)
    };
    let kind = if write {
        SinkKind::ControlledWrite
    } else {
        SinkKind::ControlledRead
    };
    sinks.push(Sink {
        va,
        kind,
        witness: reach.clone(),
        severity,
        tainted_by: tainted_by.clone(),
    });

    // Double-fetch (TOCTOU): a second read of the same attacker pointer.
    if !write && !st.tainted_reads.insert(addr_val) {
        sinks.push(Sink {
            va,
            kind: SinkKind::DoubleFetch,
            witness: reach.clone(),
            severity,
            tainted_by: tainted_by.clone(),
        });
    }

    // Null deref: trivially possible for a freely-controllable pointer (no solve);
    // otherwise only if the path does not already guard it non-null.
    let null_witness = if free_addr {
        Some(reach)
    } else {
        witness_for_value(st, addr_val, 0)
    };
    if let Some(w) = null_witness {
        sinks.push(Sink {
            va,
            kind: SinkKind::NullDeref,
            witness: w,
            severity: Severity::Arbitrary,
            tainted_by,
        });
    }
}

/// True if every free symbol of `addr` was vouched for by a probe (and there is
/// at least one) — i.e. the deref lies wholly within a probed region.
fn is_validated(st: &State, addr: ExprId) -> bool {
    let mut syms = BTreeMap::new();
    st.machine.dom.pool.collect_syms(addr, &mut syms);
    !syms.is_empty() && syms.keys().all(|id| st.validated.contains(id))
}

/// Flag a [`SinkKind::UseAfterFree`] if `ptr` concretizes into a freed block.
fn uaf_check(st: &mut State, va: u64, ptr: ExprId, sinks: &mut Vec<Sink>) {
    let a = eval_concrete(st, ptr);
    let hit = st
        .allocations
        .iter()
        .any(|al| al.freed && a >= al.base && a < al.base.saturating_add(al.size));
    if hit {
        push_sink(st, va, SinkKind::UseAfterFree, ptr, Vec::new(), sinks);
    }
}

/// Stack window (bytes) around `rsp` within which a `memcpy` destination is
/// treated as an on-stack buffer for overflow purposes.
const STACK_WINDOW: u64 = 0x1_0000;

/// Apply a callee summary, recording the attacker-controlled primitives it
/// exposes, then modeling its return value.
fn apply_summary(st: &mut State, va: u64, summary: ApiSummary, sinks: &mut Vec<Sink>) {
    match summary {
        ApiSummary::CopyMemory => {
            let dst = read_arg(st, 0);
            let src = read_arg(st, 1);
            let len = read_arg(st, 2);
            uaf_check(st, va, dst, sinks);
            uaf_check(st, va, src, sinks);
            record_access(st, va, dst, true, sinks);
            record_access(st, va, src, false, sinks);
            stack_overflow_check(st, va, dst, len, sinks);
            havoc_rax(st);
        }
        ApiSummary::Alloc { size_arg } => {
            let size_val = read_arg(st, size_arg);
            // Choose a concrete size in a sane range for the bump allocator.
            let size = eval_concrete(st, size_val).clamp(1, 0x10_000);
            let base = st.heap_next;
            st.heap_next = st.heap_next.saturating_add((size + 0xF) & !0xF);
            st.allocations.push(Alloc {
                base,
                size,
                freed: false,
            });
            let ret = st.machine.dom.constant(Width::W64, base as u128);
            st.machine
                .regs
                .write(&mut st.machine.dom, &VReg::phys("rax"), ret);
        }
        ApiSummary::Free { ptr_arg } => {
            let ptr = read_arg(st, ptr_arg);
            do_free(st, va, ptr, sinks);
            havoc_rax(st);
        }
        ApiSummary::Probe { addr_arg, len_arg } => {
            let addr = read_arg(st, addr_arg);
            let len = read_arg(st, len_arg);
            // A probe whose length can be zero validates nothing (bypassable).
            if witness_for_value(st, len, 0).is_some() {
                let prov = st.taint.provenance_of(&st.machine.dom.pool, addr);
                push_sink(st, va, SinkKind::ProbeBypass, len, prov, sinks);
            }
            // A successful probe vouches for the address's symbols on this path.
            let mut syms = BTreeMap::new();
            st.machine.dom.pool.collect_syms(addr, &mut syms);
            for id in syms.keys() {
                st.validated.insert(*id);
            }
            havoc_rax(st);
        }
        ApiSummary::DangerousCall { args, kind } => {
            dangerous_call(st, va, args, kind, sinks);
            havoc_rax(st);
        }
    }
}

/// Havoc the return register (`rax`) with a fresh symbol — the sound
/// over-approximation for a summarized callee whose result we don't model.
fn havoc_rax(st: &mut State) {
    let ret = st.machine.dom.fresh(Width::W64);
    st.machine
        .regs
        .write(&mut st.machine.dom, &VReg::phys("rax"), ret);
}

/// `ExFreePool(ptr)`: a second free of an already-freed block is a double-free;
/// otherwise mark the matching live block freed.
fn do_free(st: &mut State, va: u64, ptr: ExprId, sinks: &mut Vec<Sink>) {
    let a = eval_concrete(st, ptr);
    if let Some(al) = st.allocations.iter_mut().find(|al| al.base == a) {
        if al.freed {
            push_sink(st, va, SinkKind::DoubleFree, ptr, Vec::new(), sinks);
        } else {
            al.freed = true;
        }
    }
}

/// Flag a [`SinkKind::StackOverflow`] when a `memcpy` destination is on the stack
/// and the length is attacker-controlled (an unbounded copy onto the frame).
fn stack_overflow_check(st: &mut State, va: u64, dst: ExprId, len: ExprId, sinks: &mut Vec<Sink>) {
    let len_prov = st.taint.provenance_of(&st.machine.dom.pool, len);
    if len_prov.is_empty() {
        return; // a fixed-length copy can't overflow under attacker control
    }
    let rsp_v = st
        .machine
        .regs
        .read(&mut st.machine.dom, &VReg::phys("rsp"));
    let rsp = eval_concrete(st, rsp_v);
    if rsp == 0 {
        return; // stack pointer not modeled on this path
    }
    let dst_a = eval_concrete(st, dst);
    let lo = rsp.saturating_sub(STACK_WINDOW);
    let hi = rsp.saturating_add(STACK_WINDOW);
    if dst_a >= lo && dst_a <= hi {
        push_sink(st, va, SinkKind::StackOverflow, len, len_prov, sinks);
    }
}

/// Flag a [`SinkKind::IntegerOverflow`] when an attacker-tainted `add`/`sub`/`mul`
/// can wrap at its operand width — the kind of unchecked size arithmetic that
/// precedes an undersized allocation or bounds bypass. Only `Bin` ops are
/// considered; everything else is a no-op.
fn check_int_overflow(st: &mut State, va: u64, op: &Op, sinks: &mut Vec<Sink>) {
    let Op::Bin {
        dst,
        op: bop,
        lhs,
        rhs,
    } = op
    else {
        return;
    };
    // Restrict to size-style arithmetic (add/mul); subtraction is dominated by
    // compare lowering on dispatch codes and is overwhelmingly noise.
    if !matches!(bop, BinOp::Add | BinOp::Mul) {
        return;
    }
    let w = dst.width().unwrap_or(Width::W64);
    let a = st.machine.read(lhs, w);
    let b = st.machine.read(rhs, w);

    // Only attacker-influenced arithmetic is interesting.
    let mut prov: BTreeSet<String> = BTreeSet::new();
    prov.extend(st.taint.provenance_of(&st.machine.dom.pool, a));
    prov.extend(st.taint.provenance_of(&st.machine.dom.pool, b));
    if prov.is_empty() {
        return;
    }

    // Build the overflow predicate at width `w`:
    //   add: (a + b) <u a          (unsigned carry out)
    //   sub: a <u b                (unsigned borrow / underflow)
    //   mul: widen to 2w, result's high half != 0
    let dom = &mut st.machine.dom;
    let pred = match bop {
        BinOp::Add => {
            let sum = dom.binop(BinOp::Add, &a, &b, w);
            dom.cmp(CmpOp::Ult, &sum, &a, w)
        }
        BinOp::Sub => dom.cmp(CmpOp::Ult, &a, &b, w),
        BinOp::Mul => {
            let dw = Width(w.bits().saturating_mul(2));
            if dw.bits() > 128 || dw.bits() <= w.bits() {
                return; // can't widen safely
            }
            let za = dom.zext(&a, w, dw);
            let zb = dom.zext(&b, w, dw);
            let prod = dom.binop(BinOp::Mul, &za, &zb, dw);
            let hi = dom.extract(&prod, dw.bits(), w.bits());
            let zero = dom.constant(Width(dw.bits() - w.bits()), 0);
            dom.cmp(CmpOp::Ne, &hi, &zero, Width(dw.bits() - w.bits()))
        }
        _ => unreachable!(),
    };

    let mut probe = st.constraints.clone();
    probe.push((pred, true));
    if let SolveResult::Sat(witness) = solve(&st.machine.dom.pool, &probe) {
        sinks.push(Sink {
            va,
            kind: SinkKind::IntegerOverflow,
            witness,
            severity: Severity::Arbitrary,
            tainted_by: prov.into_iter().collect(),
        });
    }
}

/// A routine dangerous when any of `args` is attacker-tainted: aggregate the
/// provenance of the tainted args and raise one `kind` sink.
fn dangerous_call(st: &mut State, va: u64, args: &[u8], kind: SinkKind, sinks: &mut Vec<Sink>) {
    let mut prov: BTreeSet<String> = BTreeSet::new();
    let mut tainted_arg: Option<ExprId> = None;
    for &a in args {
        let v = read_arg(st, a);
        let p = st.taint.provenance_of(&st.machine.dom.pool, v);
        if !p.is_empty() {
            prov.extend(p);
            tainted_arg = Some(v);
        }
    }
    if let Some(v) = tainted_arg {
        push_sink(st, va, kind, v, prov.into_iter().collect(), sinks);
    }
}

/// Execute a memory op whose address is symbolic by concretizing the address,
/// recording any attacker-controlled access as a sink first. Returns `Some(())`
/// when handled.
fn symbolic_mem_op(st: &mut State, op: &Op, va: u64, sinks: &mut Vec<Sink>) -> Option<()> {
    match op {
        Op::Load { dst, addr } => {
            let av = st.machine.eval_addr(addr);
            let addr_tainted = !st.taint.provenance_of(&st.machine.dom.pool, av).is_empty();
            record_access(st, va, av, false, sinks);
            let a = concretize_addr(st, av);
            // Taint-through-memory: a load from an attacker-controlled pointer into
            // *uninitialized* memory yields fresh attacker data (mirrors a
            // fully-symbolic memory model). Mark the fresh symbol so values read
            // out of `*(SystemBuffer)` stay attacker-controlled downstream — this
            // is what lets handle/PID/pointer args derived from buffer contents be
            // detected. Detect "uninitialized" via the memory map, not the loaded
            // value, since an uninitialized multi-byte load is a `Concat` of zero
            // bytes (never a bare `Const`).
            let val = if addr_tainted && !st.machine.mem.is_initialized(a, addr.size) {
                let w = Width::from_bytes(addr.size as u16);
                let fresh = st.machine.dom.fresh(w);
                if let Expr::Sym { id, .. } = *st.machine.dom.pool.get(fresh) {
                    st.taint.mark(id, "*attacker");
                }
                st.machine
                    .mem
                    .store(&mut st.machine.dom, a, &fresh, addr.size, addr.endian);
                fresh
            } else {
                st.machine
                    .mem
                    .load(&mut st.machine.dom, a, addr.size, addr.endian)
            };
            st.machine.regs.write(&mut st.machine.dom, dst, val);
            Some(())
        }
        Op::Store { addr, src } => {
            let av = st.machine.eval_addr(addr);
            record_access(st, va, av, true, sinks);
            let a = concretize_addr(st, av);
            let w = Width::from_bytes(addr.size as u16);
            let v = st.machine.read(src, w);
            st.machine
                .mem
                .store(&mut st.machine.dom, a, &v, addr.size, addr.endian);
            Some(())
        }
        _ => None,
    }
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
    fn unreachable_target_is_unsat_or_exhausted() {
        // Single block that just returns; target 0x9999 is never reached.
        let lf = func(vec![(0x1000, vec![Op::Return], 0x1004)]);
        let result = find_input_reaching(&lf, 0x9999, |_| {}, 1000);
        assert!(
            matches!(result, SolveResult::Unsat | SolveResult::Unknown),
            "got {:?}",
            result
        );
    }
}
