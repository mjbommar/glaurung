//! The explorer's finding vocabulary: attacker-input provenance and the
//! sink/callee-summary types the analysis layer consumes.
//!
//! These are the public data types of `symbolic::explore` — what a finding
//! *is* — held apart from the search that produces them.
//!
//! `TaintSpec::labels` is `pub(super)` because `query::path_provenance`
//! reads the map directly; that marker restores exactly the visibility the
//! field had as a private item of the undivided `explore.rs`, no wider.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::ir::types::Width;
use crate::symbolic::expr::{ExprId, ExprPool};
use crate::symbolic::solver::Model;

/// A sentinel address the attacker would "love to" write to — distinct from any
/// plausible legitimate pointer. If the solver can satisfy `addr == SENTINEL`
/// under the path condition, the write target is *fully* attacker-chosen (a true
/// write-where primitive), not merely symbolic-but-bounded. Mirrors IOCTLance's
/// `0x87` arbitrariness probe.
pub(super) const SENTINEL_ADDR: u128 = 0x8787_8787_8787_8787;

/// How much control the attacker has over a sink's target address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// The address can be pinned to an arbitrary sentinel → write/read-where.
    Arbitrary,
    /// The address is attacker-derived but constrained (e.g. into a bounded
    /// buffer) — controlled *content/offset*, but not an arbitrary location.
    Constrained,
}

#[derive(Debug, Clone)]
struct TaintedMemoryRegion {
    base: u64,
    end_exclusive: u64,
    label: String,
}

/// Which attacker-input fields a value is derived from, so a sink can be
/// labelled with provenance (e.g. an address built from `SystemBuffer`).
///
/// Symbols not present here are engine-internal (not attacker-controlled), so a
/// sink whose address touches no marked symbol is *not* a controlled primitive.
#[derive(Debug, Clone, Default)]
pub struct TaintSpec {
    pub(super) labels: BTreeMap<u32, BTreeSet<String>>,
    memory_regions: Vec<TaintedMemoryRegion>,
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

    /// Mark data loaded from a concrete memory interval as attacker-controlled
    /// without claiming that the interval's base pointer is attacker-selected.
    ///
    /// This distinction is required for I/O-manager-owned buffers such as a
    /// WDM `AssociatedIrp.SystemBuffer`: user input controls its contents, while
    /// Windows chooses and validates the kernel address itself.
    pub fn mark_memory_region(&mut self, base: u64, len: u64, label: impl Into<String>) {
        let Some(end_exclusive) = base.checked_add(len) else {
            return;
        };
        if base == end_exclusive {
            return;
        }
        self.memory_regions.push(TaintedMemoryRegion {
            base,
            end_exclusive,
            label: label.into(),
        });
        self.memory_regions
            .sort_by(|left, right| (left.base, &left.label).cmp(&(right.base, &right.label)));
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
    pub(super) fn provenance_of(&self, pool: &ExprPool, root: ExprId) -> Vec<String> {
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

    /// Stable provenance for an access wholly contained in a marked concrete
    /// memory region. Partial overlap is deliberately rejected.
    pub(super) fn memory_provenance(&self, addr: u64, size: u8) -> Vec<String> {
        let Some(end_exclusive) = addr.checked_add(u64::from(size)) else {
            return Vec::new();
        };
        self.memory_regions
            .iter()
            .filter(|region| addr >= region.base && end_exclusive <= region.end_exclusive)
            .map(|region| region.label.clone())
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
    /// A signed scalar reaches a fixed-size table outside its valid index range.
    OutOfBoundsIndex,
}

/// A summary for a known callee, letting the explorer detect attacker-controlled
/// primitives hidden *inside* an API call without descending into it. (Many
/// driver write-what-where bugs are a `memcpy(attacker_ptr, …)`, never a raw
/// symbolic store.) The analysis layer maps each callee VA to a summary; the
/// engine stays import-agnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiSummary {
    /// An explicitly accepted opaque callee: preserve memory and path state,
    /// but conservatively havoc its return register.
    HavocReturn,
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
    /// A callee that indexes a fixed-size table with a signed scalar argument.
    /// Reaching it with an index outside `[min, max]` is an out-of-bounds sink.
    BoundedSignedIndex {
        index_arg: u8,
        width: Width,
        min: i64,
        max: i64,
    },
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
