# IOCTL taint analysis

> **Kind:** architecture · **Status:** maintained

`src/analysis/ioctl_taint.rs` — a domain-specific abstract interpretation over
`LlirFunction` for Windows WDM driver IOCTL handlers. It is the **cheap static
half** of the driver work: it nominates candidate IRP-derived dereferences in a
single dataflow pass, where upstream IOCTLance spends full angr symbolic
execution. The expensive half exists too and is complementary rather than
superseded — [`src/symbolic/ioctl.rs`](execution-engine.md) confirms reachability
and emits a concrete IOCTL witness for what this pass merely flags.

## Why a new module

The python detector in ASB v5 catches the right bugs but produces
~10x false positives on the NUCBOX sweep because it treats register
taint as monotonic — once a register holds SystemBuffer anywhere in
the function, it is treated as SystemBuffer at every deref. On
multi-major-function dispatchers (xboxgip, parport, fltMgr) and on
file-system handlers (volsnap, rdbss), the same physical register is
reused for different IRP fields on different paths.

IOCTLance solves this with full angr symbolic execution. That works
but pays a ~30s/driver startup cost, brings in z3 / unicorn /
claripy, and still missed NDKPing.sys's handler in our test.

This module solves it with a tiny abstract domain over the existing
LLIR + SSA + CFG that glaurung already builds.

## Abstract domain

```
enum Taint {
    Top,              // no info
    Const(i64),       // known integer (used for NULL checks)
    DeviceObject,     // arg1 (rcx on x64) at entry
    Irp,              // arg2 (rdx on x64) at entry
    StackLoc,         // [Irp + 0xB8]   = Irp->Tail.Overlay.CurrentStackLocation
    SystemBuffer,     // [Irp + 0x18]   = Irp->AssociatedIrp.SystemBuffer
    Type3InputBuffer, // [StackLoc + 0x20]
    InputLen,         // [StackLoc + 0x10]
    OutputLen,        // [StackLoc + 0x8]
    IoCtlCode,        // [StackLoc + 0x18]
    UserBuffer,       // [Irp + 0x30]
}
```

The lattice is flat: `Top` joins everything. For `meet`, equal values
stay; otherwise → `Top`. Memory locations are NOT tracked; the
analysis is register-only. A SystemBuffer that gets spilled to the
stack and reloaded loses taint at the spill; in practice the
compiler keeps SystemBuffer in a callee-saved register across the
dispatch switch, so we recover taint on the reload side via the
LLIR's natural register lifetime.

## Transfer function

For each `Op` in source order within a block:

| Op | Effect |
|----|--------|
| `Assign { dst, src: Reg(r) }` | `state[dst] = state[r]` |
| `Assign { dst, src: Const(c) }` | `state[dst] = Const(c)` |
| `Assign { dst, src: Addr(_) }` | `state[dst] = Top` |
| `Load { dst, addr: MemOp { base, disp, .. } }` | apply the struct-field map below; on no match → `Top` |
| `CondLoad { dst, .. }` | `state[dst] = Top` (the guard is not modelled) |
| `ZExt`/`SExt`/`Trunc`/`Extract { dst, src, .. }` | `state[dst] = state[src]` — a width change **preserves** the kind; a zero-extended `InputLen` is still a length |
| `Bin { dst, .. }` / `Un { dst, .. }` | `state[dst] = Top`, except `xor r, r`, which is recognised as the zero idiom and yields `Const(0)` |
| `Concat { dst, .. }` / `Ite { dst, .. }` | `state[dst] = Top` (conservative) |
| `Intrinsic { outs, .. }` | every declared output becomes `Top` |
| `Cmp { dst, op, lhs, rhs }` | record a `FlagInference` (null or length); `state[dst] = Top` |
| `Undef { dst, .. }` | `state[dst] = Top` |
| `Store`/`CondStore { .. }` | no register change |
| `Call { .. }` | kill MS x64 caller-saved: `rax, rcx, rdx, r8, r9, r10, r11`; preserve callee-saved `rbx, rbp, rsi, rdi, r12-r15` |
| `IndirectJump`, `Jump`, `CondJump`, `Return`, `ReturnValue`, `CondReturn`, `CondReturnValue`, `Nop`, `Unknown` | no register change |

Register names are canonicalized to their 64-bit root before lookup
(`canon_reg`), so `eax`/`ax`/`al` all read and write the `rax` cell; unknown
names (ARM64, x86-32) map to themselves.

Struct-field map (only when `state[base]` is in the table):

| `state[base]` | `disp` | new dst taint |
|--------------|--------|---------------|
| `Irp`        | `0x18` | `SystemBuffer` |
| `Irp`        | `0x30` | `UserBuffer` |
| `Irp`        | `0xB8` | `StackLoc` |
| `StackLoc`   | `0x08` | `OutputLen` |
| `StackLoc`   | `0x10` | `InputLen` |
| `StackLoc`   | `0x18` | `IoCtlCode` |
| `StackLoc`   | `0x20` | `Type3InputBuffer` |

The displacements above match the documented Windows kernel struct
layouts for x64.

## Worklist algorithm

Iterative dataflow on `LlirFunction`:

1. Initialize entry-block IN = `{ rcx → DeviceObject, rdx → Irp }`; all
   other blocks IN = empty (every reg is implicitly `Top`).
2. Worklist starts with the entry block.
3. Pop a block, run the transfer function through its ops to derive
   OUT. For each successor, `meet` OUT into successor's IN. If
   successor's IN changed, add it to the worklist.
4. Repeat until empty.

Terminates because the lattice is finite (10 abstract values per
register × ~32 GPR sub-registers, all monotonically toward `Top`).
Typical convergence ≤ 4 iterations per block for the functions
glaurung sees.

## Null-check tracking

For null-deref precision we also need: "is register `R` known to be
non-NULL at instruction `I`?". A compiler emits null checks as
either `test R, R; je null_handler` or `cmp R, 0; je null_handler`.

A `Cmp` therefore returns a `FlagInference`, of which there are two kinds:

- `Null(NullEq)` — the flag register holds the result of an `R == 0` test, and
  `NullEq` records which source register `R` was compared;
- `Length(LengthCheck)` — a `len < K` (`Ult`) or `len <= K` (`Ule`) test with
  `K > 0`, which implies SystemBuffer is non-NULL on the not-taken branch. A
  length check thus feeds the *same* non-NULL set as an explicit null check;
  there is no separate `guarded_by_length_check` output.

When a `CondJump { cond, target, inverted }` reads a flag that carries a
`Null` inference for some `R`, we know:
- on the "taken" branch (target), `R == 0` (if `!inverted`) or `R != 0` (if `inverted`)
- on the "fall-through" branch, the opposite

We attach this fact to the successor block's IN: a per-block
`NonNull = BTreeSet<String>` of canonical register names. The meet for this set is
intersection (a register is known-nonnull on entry iff it's nonnull
on *every* incoming edge).

A deref `Load/Store { addr: MemOp { base, .. } }` is flagged
"guarded" if `state[base]` says `SystemBuffer` and `base` is in the
block's `nonnull_in` (or has been refined to nonnull within this
block before the deref).

## Detector output

`Vec<TaintFinding>` where each:

```rust
pub struct TaintFinding {
    pub deref_va: u64,             // VA of the Load/Store op
    pub block_va: u64,             // VA of the containing block start
    pub base_reg: String,          // physical register name at the deref
    pub base_kind: Taint,          // SystemBuffer / UserBuffer / Type3InputBuffer / …
    pub disp: i64,
    pub access_width: u8,          // 1, 2, 4 or 8
    pub access: Access,            // Read | Write
    pub guarded_by_nullcheck: bool,
}
```

A consumer filters by `base_kind ∈ {SystemBuffer, UserBuffer,
Type3InputBuffer} ∧ !guarded_by_nullcheck`.

## Rust API

```rust
pub fn analyze(lf: &LlirFunction) -> IoctlTaintResult
```

```rust
pub struct IoctlTaintResult {
    pub findings: Vec<TaintFinding>,   // IRP-derived accesses, in deref-VA order
    pub block_in: BTreeMap<u64, State>, // per-block IN state, for follow-up detectors
    pub dispatcher_state: State,        // seed for orphan (jump-table) case bodies
}
```

`block_in` is exposed so a detector that needs register provenance at a
particular block head does not have to re-run the analysis, and
`dispatcher_state` is the heuristically chosen state used to seed jump-table
case bodies that no CFG edge reaches.

**There is no Python binding.** The pass is Rust-only; `glaurung.analysis`
exposes `ioctl_surface_map_bytes` / `ioctl_surface_map_path`, which are a
different, coarser surface. The consumer inside this repository is
`src/symbolic/ioctl.rs`, which reuses the same IRP offsets and dispatch ABI and
then *confirms* what this pass nominates — see
[`execution-engine.md`](execution-engine.md).

Verified with `rg -n 'pub fn analyze|pub struct (TaintFinding|IoctlTaintResult)|guarded_by' src/analysis/ioctl_taint.rs`
and `rg -n 'ioctl_taint' src/python_bindings python/glaurung` (no hits).

## Not in scope (v1)

- Memory model: SystemBuffer spills to stack are lost.
- Indirect calls.
- Anything beyond x86-64. The lifter supports x86 and ARM64; null
  deref on ARM64 drivers can come later.
- Other detector classes (double-fetch, arbitrary-RW, probe-bypass) — those
  reuse the same primitive, and the ones that shipped did so on the *symbolic*
  engine (`src/symbolic/ioctl.rs`), not on this pass.
- Length-aware bounds checking. A `LengthCheck` here only implies non-NULL; it
  does not compare an access against `InputBufferLength`/`OutputBufferLength`.
