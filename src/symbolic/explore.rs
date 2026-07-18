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
use crate::ir::types::{
    BinOp, CallTarget, CmpOp, Endian, LlirBlock, LlirFunction, Op, VReg, Value, Width,
};
use crate::symbolic::Symbolic;
use crate::symbolic::concretization::{
    ConcretizationChoice, ConcretizationPolicy, ConcretizationRequest, ConcretizationSite,
    UnsignedExtremum, active_concretization_policy,
};
use crate::symbolic::expr::{Expr, ExprId, ExprPool};
use crate::symbolic::ordered_trace::{TracePath, WarmReplayCheck};
use crate::symbolic::solver::{
    Assert, Model, SolveResult, WarmAssertionPrefix, last_solve_timing, solve_for_path_delta,
};

use std::cell::Cell;
use std::cell::RefCell;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

static CANONICAL_MODEL_CHOICE_ATTEMPTS: AtomicU64 = AtomicU64::new(0);
static CANONICAL_MODEL_CHOICE_COMPLETED: AtomicU64 = AtomicU64::new(0);
static CANONICAL_MODEL_CHOICE_INFEASIBLE: AtomicU64 = AtomicU64::new(0);
static CANONICAL_MODEL_CHOICE_PROBES: AtomicU64 = AtomicU64::new(0);
static CANONICAL_MODEL_CHOICE_INCONCLUSIVE: AtomicU64 = AtomicU64::new(0);
static CANONICAL_MODEL_CHOICE_UNSUPPORTED_WIDTH: AtomicU64 = AtomicU64::new(0);
static CANONICAL_MODEL_CHOICE_UNKNOWN: AtomicU64 = AtomicU64::new(0);
static CANONICAL_MODEL_CHOICE_NO_SOLVER: AtomicU64 = AtomicU64::new(0);
static CANONICAL_MODEL_CHOICE_ERROR: AtomicU64 = AtomicU64::new(0);
static CANONICAL_MODEL_CHOICE_FINAL_UNSAT: AtomicU64 = AtomicU64::new(0);

/// Process-wide accounting for backend-independent model choices.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CanonicalModelChoiceStats {
    /// Active model-selection policy.
    pub policy: &'static str,
    /// Expressions for which an unsigned extremum was requested.
    pub attempts: u64,
    /// Attempts that produced and rechecked an extremum.
    pub completed: u64,
    /// Attempts made on a path that was already infeasible.
    pub infeasible: u64,
    /// Temporary solver checks issued by the minimizer.
    pub probes: u64,
    /// Attempts that failed closed because no checked minimum was available.
    pub inconclusive: u64,
    /// Attempts whose expression exceeded the concrete-value representation.
    pub unsupported_width: u64,
    /// Attempts stopped by a solver `unknown` result.
    pub unknown: u64,
    /// Attempts stopped because no solver was available.
    pub no_solver: u64,
    /// Attempts stopped by a backend error.
    pub error: u64,
    /// Attempts whose final equality unexpectedly returned UNSAT.
    pub final_unsat: u64,
}

/// Return the active canonical-model policy and its process-wide counters.
pub fn canonical_model_choice_stats() -> CanonicalModelChoiceStats {
    CanonicalModelChoiceStats {
        policy: active_concretization_policy().policy_id(),
        attempts: CANONICAL_MODEL_CHOICE_ATTEMPTS.load(Ordering::Relaxed),
        completed: CANONICAL_MODEL_CHOICE_COMPLETED.load(Ordering::Relaxed),
        infeasible: CANONICAL_MODEL_CHOICE_INFEASIBLE.load(Ordering::Relaxed),
        probes: CANONICAL_MODEL_CHOICE_PROBES.load(Ordering::Relaxed),
        inconclusive: CANONICAL_MODEL_CHOICE_INCONCLUSIVE.load(Ordering::Relaxed),
        unsupported_width: CANONICAL_MODEL_CHOICE_UNSUPPORTED_WIDTH.load(Ordering::Relaxed),
        unknown: CANONICAL_MODEL_CHOICE_UNKNOWN.load(Ordering::Relaxed),
        no_solver: CANONICAL_MODEL_CHOICE_NO_SOLVER.load(Ordering::Relaxed),
        error: CANONICAL_MODEL_CHOICE_ERROR.load(Ordering::Relaxed),
        final_unsat: CANONICAL_MODEL_CHOICE_FINAL_UNSAT.load(Ordering::Relaxed),
    }
}

thread_local! {
    /// Per-function wall-clock deadline, set by [`run_worklist`] and checked
    /// *per instruction* so a single block built from huge (obfuscated)
    /// expressions can still be interrupted — coarser checks at block boundaries
    /// are not enough when one block takes minutes.
    static DEADLINE: Cell<Option<Instant>> = const { Cell::new(None) };

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

fn deadline_passed() -> bool {
    DEADLINE
        .with(Cell::get)
        .is_some_and(|dl| Instant::now() >= dl)
}

/// Register call-site-keyed summaries (see [`CALL_SITE_SUMMARIES`]). Set once per
/// function before [`find_function_sinks_with_apis`]; pass an empty map to clear.
pub fn set_call_site_summaries(map: BTreeMap<u64, ApiSummary>) {
    CALL_SITE_SUMMARIES.with(|c| *c.borrow_mut() = map);
}

fn call_site_summary(va: u64) -> Option<ApiSummary> {
    CALL_SITE_SUMMARIES.with(|c| c.borrow().get(&va).copied())
}

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
    labels: BTreeMap<u32, BTreeSet<String>>,
}

impl TaintSpec {
    pub fn new() -> Self {
        Self::default()
    }

    /// Mark symbol `sym_id` as attacker-controlled input named `label`.
    ///
    /// A value derived from more than one attacker source retains every source;
    /// adding a label never overwrites provenance already attached to the symbol.
    pub fn mark(&mut self, sym_id: u32, label: impl Into<String>) {
        self.labels.entry(sym_id).or_default().insert(label.into());
    }

    /// The first stable label for a symbol, if it is attacker-controlled.
    ///
    /// Use sink provenance rather than this compatibility accessor when every
    /// source matters; symbols may carry multiple labels.
    pub fn label(&self, sym_id: u32) -> Option<&str> {
        self.labels
            .get(&sym_id)
            .and_then(|labels| labels.first())
            .map(String::as_str)
    }

    /// The distinct attacker-input labels an expression's free symbols carry.
    fn provenance_of(&self, pool: &ExprPool, root: ExprId) -> Vec<String> {
        let mut syms = BTreeMap::new();
        pool.collect_syms(root, &mut syms);
        syms.keys()
            .filter_map(|id| self.labels.get(id))
            .flatten()
            .cloned()
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
    /// An attacker-tainted MSR index reaching `wrmsr` (`__writemsr`): a write to
    /// an attacker-chosen model-specific register. Writing IA32_LSTAR
    /// (0xC0000082) redirects the syscall entry to attacker code -> ring-0 code
    /// execution. (IOCTLance "arbitrary wrmsr".)
    ArbitraryMsrWrite,
    /// An attacker-tainted MSR index reaching `rdmsr` (`__readmsr`): reads an
    /// attacker-chosen MSR. Reading IA32_LSTAR leaks KiSystemCall64 -> defeats
    /// KASLR and EDR syscall-hook detection.
    ArbitraryMsrRead,
    /// An attacker-tainted port reaching a port-I/O instruction (`out`/`in`,
    /// `__outbyte`/`__inbyte`): arbitrary hardware port access. Port 0xCF9 forces
    /// a platform reset (unauth DoS); general access enables firmware / PCI-config
    /// manipulation. (IOCTLance "arbitrary out".)
    PortAccess,
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
    /// A KMDF buffer-retrieval call (`WdfRequestRetrieveInputBuffer`/`InputMemory`):
    /// `(globals, request, minlen, OUT *Buffer = arg[out_ptr_arg], OUT *Length)`.
    /// Writes a fresh `SystemBuffer`-tainted pointer to `*arg[out_ptr_arg]`, so the
    /// subsequent `mov reg,[buf_slot]; ...[reg]` loads carry precise attacker taint
    /// — the KMDF analogue of seeding `IRP.AssociatedIrp.SystemBuffer`. Used via the
    /// call-site-keyed map (the WDF callee is a dynamic function-table thunk).
    RetrieveBuffer { out_ptr_arg: u8 },
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

/// Process-local identity for explicit warm-solver ownership. It never enters
/// formulas or evidence; ordered trace paths retain their separate stable IDs.
static NEXT_WARM_PATH_ID: AtomicU64 = AtomicU64::new(1);

fn next_warm_path_id() -> u64 {
    NEXT_WARM_PATH_ID.fetch_add(1, Ordering::Relaxed)
}

fn warm_owner_transfer_enabled() -> bool {
    if crate::symbolic::solver::fair_shadow_enabled() {
        return true;
    }
    #[cfg(feature = "solver-axeyum")]
    {
        crate::symbolic::solver::axeyum_backend::warm_owner_transfer_enabled()
    }
    #[cfg(not(feature = "solver-axeyum"))]
    {
        false
    }
}

fn warm_serial_sibling_reuse_enabled() -> bool {
    if crate::symbolic::solver::fair_shadow_enabled() {
        return true;
    }
    #[cfg(feature = "solver-axeyum")]
    {
        effective_serial_sibling_reuse(
            crate::symbolic::solver::axeyum_backend::warm_serial_sibling_reuse_enabled(),
            crate::symbolic::solver::axeyum_backend::direct_delta_enabled(),
        )
    }
    #[cfg(not(feature = "solver-axeyum"))]
    {
        false
    }
}

fn effective_serial_sibling_reuse(configured: bool, _direct_delta: bool) -> bool {
    configured
}

fn share_serial_warm_owner_with_children(path_id: u64, children: u64) {
    crate::symbolic::ordered_trace::warm_owner_share(path_id, children);
    #[cfg(feature = "solver-axeyum")]
    crate::symbolic::solver::axeyum_backend::share_serial_warm_owner_with_children(
        path_id, children,
    );
    #[cfg(all(feature = "solver-z3", feature = "solver-axeyum"))]
    if crate::symbolic::solver::fair_shadow_enabled() {
        crate::symbolic::solver::z3_backend::share_serial_warm_owner_with_children(
            path_id, children,
        );
    }
    #[cfg(not(feature = "solver-axeyum"))]
    let _ = (path_id, children);
}

fn close_warm_owner(path_id: u64) {
    crate::symbolic::ordered_trace::warm_owner_release(path_id);
    #[cfg(feature = "solver-axeyum")]
    if crate::symbolic::solver::fair_shadow_enabled() {
        crate::symbolic::solver::axeyum_backend::close_fair_warm_path(path_id);
    } else {
        crate::symbolic::solver::axeyum_backend::close_warm_path(path_id);
    }
    #[cfg(all(feature = "solver-z3", feature = "solver-axeyum"))]
    if crate::symbolic::solver::fair_shadow_enabled() {
        crate::symbolic::solver::z3_backend::close_warm_path(path_id);
    }
}

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

/// Solve the current path condition and record the exact query occurrence.
fn solve_traced(st: &mut State, purpose: &str, location: u64) -> SolveResult {
    let persistent = st.constraints.len();
    let requested_retain_assertions = st.warm_retain_assertions;
    let (result, synced) = solve_for_path_delta(
        &st.machine.dom.pool,
        &st.constraints,
        st.warm_path_id,
        st.warm_retain_assertions,
        persistent,
        &st.warm_assertion_prefix,
    );
    if synced {
        st.warm_retain_assertions = persistent;
    }
    let timing = last_solve_timing();
    if let Some(trace) = &mut st.trace {
        let warm_replay = WarmReplayCheck {
            owner_id: st.warm_path_id,
            requested_retain_assertions,
            persistent_assertions: persistent,
            synchronized: synced,
        };
        trace.check(
            &st.machine.dom.pool,
            &st.constraints,
            &result,
            purpose,
            timing,
            Some(&warm_replay),
            location,
        );
    }
    result
}

/// Solve with one temporary assertion, preserving explicit push/check/pop
/// history while leaving the path condition unchanged.
fn solve_probe_traced(
    st: &mut State,
    assertion: Assert,
    purpose: &str,
    role: &str,
    location: u64,
) -> SolveResult {
    if let Some(trace) = &mut st.trace {
        trace.push_temporary(&st.machine.dom.pool, assertion, role, location);
    }
    let mut probe = st.constraints.clone();
    probe.push(assertion);
    let persistent = st.constraints.len();
    let requested_retain_assertions = st.warm_retain_assertions;
    let (result, synced) = solve_for_path_delta(
        &st.machine.dom.pool,
        &probe,
        st.warm_path_id,
        st.warm_retain_assertions,
        persistent,
        &st.warm_assertion_prefix,
    );
    if synced {
        st.warm_retain_assertions = persistent;
    }
    let timing = last_solve_timing();
    if let Some(trace) = &mut st.trace {
        let warm_replay = WarmReplayCheck {
            owner_id: st.warm_path_id,
            requested_retain_assertions,
            persistent_assertions: persistent,
            synchronized: synced,
        };
        trace.check(
            &st.machine.dom.pool,
            &probe,
            &result,
            purpose,
            timing,
            Some(&warm_replay),
            location,
        );
        trace.pop(location);
    }
    result
}

/// Select an unsigned extremum of `value` under the current path condition.
///
/// Every bound is a temporary assertion, so the search cannot mutate the path.
/// The final equality probe both rechecks the selected value and leaves an
/// immediately preceding SAT event for ordered model-choice tracing. Widths
/// above 128 bits cannot be represented by this engine's concrete value type
/// and therefore fail closed.
fn select_unsigned_extremum(
    st: &mut State,
    value: ExprId,
    purpose: &str,
    location: u64,
    extremum: UnsignedExtremum,
) -> Option<u128> {
    CANONICAL_MODEL_CHOICE_ATTEMPTS.fetch_add(1, Ordering::Relaxed);
    let width = st.machine.dom.pool.width_of(value);
    let bits = width.bits();
    if bits == 0 || bits > 128 {
        CANONICAL_MODEL_CHOICE_INCONCLUSIVE.fetch_add(1, Ordering::Relaxed);
        CANONICAL_MODEL_CHOICE_UNSUPPORTED_WIDTH.fetch_add(1, Ordering::Relaxed);
        return None;
    }

    CANONICAL_MODEL_CHOICE_PROBES.fetch_add(1, Ordering::Relaxed);
    match solve_traced(st, "canonical-model-choice-feasibility", location) {
        SolveResult::Sat(_) => {}
        SolveResult::Unsat => {
            CANONICAL_MODEL_CHOICE_INFEASIBLE.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        SolveResult::Unknown => {
            CANONICAL_MODEL_CHOICE_INCONCLUSIVE.fetch_add(1, Ordering::Relaxed);
            CANONICAL_MODEL_CHOICE_UNKNOWN.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        SolveResult::NoSolver => {
            CANONICAL_MODEL_CHOICE_INCONCLUSIVE.fetch_add(1, Ordering::Relaxed);
            CANONICAL_MODEL_CHOICE_NO_SOLVER.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        SolveResult::Error(_) => {
            CANONICAL_MODEL_CHOICE_INCONCLUSIVE.fetch_add(1, Ordering::Relaxed);
            CANONICAL_MODEL_CHOICE_ERROR.fetch_add(1, Ordering::Relaxed);
            return None;
        }
    }

    let mut low = 0u128;
    let mut high = if bits == 128 {
        u128::MAX
    } else {
        (1u128 << bits) - 1
    };
    while low < high {
        let distance = high - low;
        let midpoint = match extremum {
            UnsignedExtremum::Minimum => low + (distance >> 1),
            UnsignedExtremum::Maximum => low + (distance >> 1) + (distance & 1),
        };
        let bound = st.machine.dom.constant(width, midpoint);
        let probe = match extremum {
            UnsignedExtremum::Minimum => {
                st.machine.dom.cmp(CmpOp::Ule, &value, &bound, width)
            }
            UnsignedExtremum::Maximum => {
                st.machine.dom.cmp(CmpOp::Ule, &bound, &value, width)
            }
        };
        CANONICAL_MODEL_CHOICE_PROBES.fetch_add(1, Ordering::Relaxed);
        match solve_probe_traced(
            st,
            (probe, true),
            purpose,
            "canonical-model-choice-bound",
            location,
        ) {
            SolveResult::Sat(_) => match extremum {
                UnsignedExtremum::Minimum => high = midpoint,
                UnsignedExtremum::Maximum => low = midpoint,
            },
            SolveResult::Unsat => match extremum {
                UnsignedExtremum::Minimum => low = midpoint + 1,
                UnsignedExtremum::Maximum => high = midpoint - 1,
            },
            SolveResult::Unknown => {
                CANONICAL_MODEL_CHOICE_INCONCLUSIVE.fetch_add(1, Ordering::Relaxed);
                CANONICAL_MODEL_CHOICE_UNKNOWN.fetch_add(1, Ordering::Relaxed);
                return None;
            }
            SolveResult::NoSolver => {
                CANONICAL_MODEL_CHOICE_INCONCLUSIVE.fetch_add(1, Ordering::Relaxed);
                CANONICAL_MODEL_CHOICE_NO_SOLVER.fetch_add(1, Ordering::Relaxed);
                return None;
            }
            SolveResult::Error(_) => {
                CANONICAL_MODEL_CHOICE_INCONCLUSIVE.fetch_add(1, Ordering::Relaxed);
                CANONICAL_MODEL_CHOICE_ERROR.fetch_add(1, Ordering::Relaxed);
                return None;
            }
        }
    }

    let selected = st.machine.dom.constant(width, low);
    let equal = st.machine.dom.cmp(CmpOp::Eq, &value, &selected, width);
    CANONICAL_MODEL_CHOICE_PROBES.fetch_add(1, Ordering::Relaxed);
    match solve_probe_traced(
        st,
        (equal, true),
        purpose,
        "canonical-model-choice-final",
        location,
    ) {
        SolveResult::Sat(_) => {
            CANONICAL_MODEL_CHOICE_COMPLETED.fetch_add(1, Ordering::Relaxed);
            Some(low)
        }
        SolveResult::Unsat => {
            CANONICAL_MODEL_CHOICE_INCONCLUSIVE.fetch_add(1, Ordering::Relaxed);
            CANONICAL_MODEL_CHOICE_FINAL_UNSAT.fetch_add(1, Ordering::Relaxed);
            None
        }
        SolveResult::Unknown => {
            CANONICAL_MODEL_CHOICE_INCONCLUSIVE.fetch_add(1, Ordering::Relaxed);
            CANONICAL_MODEL_CHOICE_UNKNOWN.fetch_add(1, Ordering::Relaxed);
            None
        }
        SolveResult::NoSolver => {
            CANONICAL_MODEL_CHOICE_INCONCLUSIVE.fetch_add(1, Ordering::Relaxed);
            CANONICAL_MODEL_CHOICE_NO_SOLVER.fetch_add(1, Ordering::Relaxed);
            None
        }
        SolveResult::Error(_) => {
            CANONICAL_MODEL_CHOICE_INCONCLUSIVE.fetch_add(1, Ordering::Relaxed);
            CANONICAL_MODEL_CHOICE_ERROR.fetch_add(1, Ordering::Relaxed);
            None
        }
    }
}

#[cfg(test)]
fn minimize_unsigned_value(
    st: &mut State,
    value: ExprId,
    purpose: &str,
    location: u64,
) -> Option<u128> {
    select_unsigned_extremum(
        st,
        value,
        purpose,
        location,
        UnsignedExtremum::Minimum,
    )
}

#[cfg(test)]
fn maximize_unsigned_value(
    st: &mut State,
    value: ExprId,
    purpose: &str,
    location: u64,
) -> Option<u128> {
    select_unsigned_extremum(
        st,
        value,
        purpose,
        location,
        UnsignedExtremum::Maximum,
    )
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
            return SolveResult::Unknown;
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
) -> (Vec<Sink>, Option<State>) {
    use crate::symbolic::solver::{reset_solver_meter, solver_budget, solver_meter, time_budget};
    reset_solver_meter();
    let (max_solves, max_timeouts) = solver_budget();
    let deadline = time_budget().map(|d| Instant::now() + d);
    DEADLINE.with(|c| c.set(deadline)); // checked per-instruction in process_block
    let mut work = vec![root];
    let mut explored = 0usize;
    let mut out = Vec::new();
    let mut best: Option<State> = None;

    while let Some(mut st) = work.pop() {
        if explored >= max_states {
            st.end_trace("state-budget");
            for pending in &mut work {
                pending.end_trace("state-budget");
            }
            break;
        }
        let (solves, timeouts) = solver_meter();
        if solves >= max_solves || timeouts >= max_timeouts {
            st.end_trace("solver-budget");
            for pending in &mut work {
                pending.end_trace("solver-budget");
            }
            break; // solver budget spent: bail with partial findings
        }
        if deadline.is_some_and(|dl| std::time::Instant::now() >= dl) {
            st.end_trace("deadline");
            for pending in &mut work {
                pending.end_trace("deadline");
            }
            break; // wall-clock budget spent: bail with partial findings
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
        st.end_trace("loop-limit");
        return Vec::new();
    }

    for ins in &block.instrs {
        // Per-instruction wall-clock guard: a block built from huge obfuscated
        // expressions can take a long time in a single op, so bail mid-block.
        if deadline_passed() {
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
                // Call-site-keyed summary (indirect WDF function-table calls whose
                // callee is a dynamic thunk, e.g. WdfRequestRetrieveInputBuffer).
                // Checked before callee resolution; args are still in registers here.
                if let Some(summary) = call_site_summary(ins.va) {
                    if !apply_summary(&mut st, ins.va, summary, sinks) {
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
                            st.end_trace("model-unavailable");
                            return Vec::new();
                        }
                    }
                    // An unmodeled callee (a local helper, logging, etc.) is
                    // treated as opaque: havoc the return and continue, rather than
                    // ending the path. Ending here would cut off everything after a
                    // `DbgPrint`/helper call — including the bug.
                    None => havoc_rax(&mut st),
                }
                continue;
            }
            Op::Return => {
                // Controllable-PC check: `ret` pops the saved return address from
                // [rsp]. If a stack-buffer overflow (or any attacker write) has made
                // that slot attacker-controlled, this is the classic
                // stack-overflow -> hijacked-return primitive (ioctlance reports it
                // as "Buffer Overflow - Controllable PC"). Mirrors the Shellcode
                // check on attacker-controlled indirect-call targets.
                let rsp_v = st
                    .machine
                    .regs
                    .read(&mut st.machine.dom, &VReg::phys("rsp"));
                let Some(rsp) = eval_concrete(&mut st, rsp_v) else {
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
                consider_terminal(&st, best);
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
                if let Op::Load { addr, .. } | Op::Store { addr, .. } = other {
                    let av = st.machine.eval_addr(addr);
                    if !uaf_check(&mut st, ins.va, av, sinks) {
                        st.end_trace("model-unavailable");
                        return Vec::new();
                    }
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
                            st.end_trace("unresolved-symbolic-memory");
                            return Vec::new();
                        }
                        continue;
                    }
                    // Branch shouldn't occur (CondJump handled above); other
                    // halts / return / call end the path.
                    _ => {
                        consider_terminal(&st, best);
                        st.end_trace("execution-halt");
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
/// later refinement). Returns `None` when no satisfying model is available; in
/// that case the caller must stop the path rather than inventing a value.
fn concretize_addr(st: &mut State, addr_val: ExprId) -> Option<u64> {
    let policy = active_concretization_policy();
    concretize_addr_with_policy(st, addr_val, &policy)
}

fn concretize_addr_with_policy(
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
fn witness_for_value(st: &mut State, addr_val: ExprId, value: u128) -> Option<Model> {
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
fn arg_reg(n: u8) -> Option<&'static str> {
    match n {
        0 => Some("rcx"),
        1 => Some("rdx"),
        2 => Some("r8"),
        3 => Some("r9"),
        _ => None,
    }
}

/// Read call argument `n` as a symbolic value. Args 0-3 are in rcx/rdx/r8/r9;
/// args >=4 are on the stack at `[rsp + 0x20 + (n-4)*8]` at the call site -- the
/// 32-byte shadow space precedes the first stack arg in the MS x64 ABI. Reading
/// them (rather than the old `rsp` stub) is what lets a dangerous-call detector
/// see attacker taint that reached a high-numbered parameter, e.g. the
/// attacker-controlled CreateDisposition (param 7) of `ZwCreateFile`, which the
/// handler spills from the IRP system buffer into `[rsp+0x38]`.
fn read_arg(st: &mut State, n: u8) -> Option<ExprId> {
    match arg_reg(n) {
        Some(r) => Some(st.machine.regs.read(&mut st.machine.dom, &VReg::phys(r))),
        None => {
            let rsp = st
                .machine
                .regs
                .read(&mut st.machine.dom, &VReg::phys("rsp"));
            let off = st
                .machine
                .dom
                .constant(Width::W64, 0x20 + (n as u128 - 4) * 8);
            let addr = st.machine.dom.binop(BinOp::Add, &rsp, &off, Width::W64);
            let a = concretize_addr(st, addr)?;
            Some(
                st.machine
                    .mem
                    .load(&mut st.machine.dom, a, 8, Endian::Little),
            )
        }
    }
}

/// Concretely evaluate `val` under a model of the current path *without* binding
/// it (a read-only probe, unlike [`concretize_addr`]). Used by the lifecycle
/// checks (free/UAF/stack) that only need a representative concrete value.
/// Returns `None` for UNSAT, unknown, unavailable, or failed solver results;
/// none of those outcomes authorizes a model-driven exploration choice.
fn eval_concrete(st: &mut State, val: ExprId) -> Option<u64> {
    let policy = active_concretization_policy();
    eval_concrete_with_policy(st, val, &policy)
}

fn eval_concrete_with_policy(
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
fn reach_model(st: &mut State) -> Option<Model> {
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
fn can_skip_feasibility_check(st: &State, pred: ExprId) -> bool {
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
fn uaf_check(st: &mut State, va: u64, ptr: ExprId, sinks: &mut Vec<Sink>) -> bool {
    if !st.allocations.iter().any(|allocation| allocation.freed) {
        return true;
    }
    let Some(a) = eval_concrete(st, ptr) else {
        return false;
    };
    let hit = st
        .allocations
        .iter()
        .any(|al| al.freed && a >= al.base && a < al.base.saturating_add(al.size));
    if hit {
        push_sink(st, va, SinkKind::UseAfterFree, ptr, Vec::new(), sinks);
    }
    true
}

/// Stack window (bytes) around `rsp` within which a `memcpy` destination is
/// treated as an on-stack buffer for overflow purposes.
const STACK_WINDOW: u64 = 0x1_0000;

/// Apply a callee summary, recording the attacker-controlled primitives it
/// exposes, then modeling its return value.
fn apply_summary(st: &mut State, va: u64, summary: ApiSummary, sinks: &mut Vec<Sink>) -> bool {
    match summary {
        ApiSummary::CopyMemory => {
            let Some(dst) = read_arg(st, 0) else {
                return false;
            };
            let Some(src) = read_arg(st, 1) else {
                return false;
            };
            let Some(len) = read_arg(st, 2) else {
                return false;
            };
            if !uaf_check(st, va, dst, sinks) || !uaf_check(st, va, src, sinks) {
                return false;
            }
            record_access(st, va, dst, true, sinks);
            record_access(st, va, src, false, sinks);
            if !stack_overflow_check(st, va, dst, len, sinks) {
                return false;
            }
            havoc_rax(st);
        }
        ApiSummary::Alloc { size_arg } => {
            let Some(size_val) = read_arg(st, size_arg) else {
                return false;
            };
            // Choose a concrete size in a sane range for the bump allocator.
            let Some(size) = eval_concrete(st, size_val) else {
                return false;
            };
            let size = size.clamp(1, 0x10_000);
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
            let Some(ptr) = read_arg(st, ptr_arg) else {
                return false;
            };
            if !do_free(st, va, ptr, sinks) {
                return false;
            }
            havoc_rax(st);
        }
        ApiSummary::Probe { addr_arg, len_arg } => {
            let Some(addr) = read_arg(st, addr_arg) else {
                return false;
            };
            let Some(len) = read_arg(st, len_arg) else {
                return false;
            };
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
            if !dangerous_call(st, va, args, kind, sinks) {
                return false;
            }
            havoc_rax(st);
        }
        ApiSummary::RetrieveBuffer { out_ptr_arg } => {
            // *arg[out_ptr_arg] := fresh SystemBuffer-tainted pointer.
            let Some(out_ptr) = read_arg(st, out_ptr_arg) else {
                return false;
            };
            let Some(addr) = eval_concrete(st, out_ptr) else {
                return false;
            };
            if addr != 0 {
                let e = st.machine.dom.fresh(Width::W64);
                if let Expr::Sym { id, .. } = st.machine.dom.pool.get(e) {
                    let id = *id;
                    st.taint.mark(id, "SystemBuffer");
                }
                st.machine
                    .mem
                    .store(&mut st.machine.dom, addr, &e, 8, Endian::Little);
            }
            havoc_rax(st); // returns NTSTATUS
        }
    }
    true
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
fn do_free(st: &mut State, va: u64, ptr: ExprId, sinks: &mut Vec<Sink>) -> bool {
    let Some(a) = eval_concrete(st, ptr) else {
        return false;
    };
    if let Some(al) = st.allocations.iter_mut().find(|al| al.base == a) {
        if al.freed {
            push_sink(st, va, SinkKind::DoubleFree, ptr, Vec::new(), sinks);
        } else {
            al.freed = true;
        }
    }
    true
}

/// Flag a [`SinkKind::StackOverflow`] when a `memcpy` destination is on the stack
/// and the length is attacker-controlled (an unbounded copy onto the frame).
fn stack_overflow_check(
    st: &mut State,
    va: u64,
    dst: ExprId,
    len: ExprId,
    sinks: &mut Vec<Sink>,
) -> bool {
    let len_prov = st.taint.provenance_of(&st.machine.dom.pool, len);
    if len_prov.is_empty() {
        return true; // a fixed-length copy can't overflow under attacker control
    }
    let rsp_v = st
        .machine
        .regs
        .read(&mut st.machine.dom, &VReg::phys("rsp"));
    let Some(rsp) = eval_concrete(st, rsp_v) else {
        return false;
    };
    if rsp == 0 {
        return true; // stack pointer not modeled on this path
    }
    let Some(dst_a) = eval_concrete(st, dst) else {
        return false;
    };
    let lo = rsp.saturating_sub(STACK_WINDOW);
    let hi = rsp.saturating_add(STACK_WINDOW);
    if dst_a >= lo && dst_a <= hi {
        push_sink(st, va, SinkKind::StackOverflow, len, len_prov, sinks);
    }
    true
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

    if let SolveResult::Sat(witness) =
        solve_probe_traced(st, (pred, true), "integer-overflow", "other", va)
    {
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
fn dangerous_call(
    st: &mut State,
    va: u64,
    args: &[u8],
    kind: SinkKind,
    sinks: &mut Vec<Sink>,
) -> bool {
    let mut prov: BTreeSet<String> = BTreeSet::new();
    let mut tainted_arg: Option<ExprId> = None;
    for &a in args {
        let Some(v) = read_arg(st, a) else {
            return false;
        };
        let p = st.taint.provenance_of(&st.machine.dom.pool, v);
        if !p.is_empty() {
            prov.extend(p);
            tainted_arg = Some(v);
        }
    }
    if let Some(v) = tainted_arg {
        push_sink(st, va, kind, v, prov.into_iter().collect(), sinks);
    }
    true
}

/// Execute a memory op whose address is symbolic by concretizing the address,
/// recording any attacker-controlled access as a sink first. Returns `Some(())`
/// when handled.
fn symbolic_mem_op(st: &mut State, op: &Op, va: u64, sinks: &mut Vec<Sink>) -> Option<()> {
    match op {
        Op::Load { dst, addr } => {
            let av = st.machine.eval_addr(addr);
            let address_provenance = st.taint.provenance_of(&st.machine.dom.pool, av);
            let addr_tainted = !address_provenance.is_empty();
            record_access(st, va, av, false, sinks);
            let a = concretize_addr(st, av)?;
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
                    for source in &address_provenance {
                        st.taint.mark(id, format!("*{source}"));
                    }
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
            let a = concretize_addr(st, av)?;
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
            addr: MemOp::plain(
                Some(VReg::phys("rdi")),
                Some(VReg::phys("rsi")),
                1,
                0,
                8,
            ),
        };
        let mut sinks = Vec::new();
        assert_eq!(symbolic_mem_op(&mut state, &op, 0x1000, &mut sinks), Some(()));

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
        let at_least_five = representative_machine.dom.cmp(
            CmpOp::Ule,
            &five,
            &representative,
            Width::W8,
        );
        let at_most_ten = representative_machine.dom.cmp(
            CmpOp::Ule,
            &representative,
            &ten,
            Width::W8,
        );
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
            representative_state.constraints,
            representative_constraints,
            "read-only representative selection must not bind the path",
        );

        let mut address_machine = Machine::new(Symbolic::new());
        let address = address_machine.dom.fresh(Width::W64);
        let low = address_machine.dom.constant(Width::W64, 0x1000);
        let high = address_machine.dom.constant(Width::W64, 0x2000);
        let at_least_low =
            address_machine
                .dom
                .cmp(CmpOp::Ule, &low, &address, Width::W64);
        let at_most_high =
            address_machine
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
            matches!(result, SolveResult::Unsat | SolveResult::Unknown),
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
        use crate::symbolic::solver::{DEFAULT_SOLVER_BUDGET, set_solver_budget, solver_meter};
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

    /// The per-path loop bound alone (with the *default*, huge solver budget)
    /// stops a self-looping function quickly — bounding symbolic expression growth
    /// at its source. Without it, the loop would fork up to the state cap.
    #[test]
    fn loop_bound_cuts_runaway_path() {
        use crate::symbolic::solver::{DEFAULT_SOLVER_BUDGET, set_solver_budget, solver_meter};
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
