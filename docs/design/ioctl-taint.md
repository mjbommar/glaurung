# IOCTL taint analysis

Domain-specific abstract interpretation over `LlirFunction` for Windows
WDM driver IOCTL handlers. Implements the precision layer that
`tools/windows/ioctl_null_deref_audit.py` (in ASB) lacks, and replaces
the symbolic-execution path used by upstream IOCTLance with a much
cheaper static analysis.

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
| `Load { dst, addr: MemOp { base, disp, .. } }` | apply struct-field map below; on no match → `Top` |
| `Bin { dst, .. }` / `Un { dst, .. }` | `state[dst] = Top` |
| `Cmp { dst, op, lhs, rhs }` | record null-check info; `state[dst] = Top` |
| `Store { .. }` | no register change |
| `Call { .. }` | kill MS x64 caller-saved: `rax, rcx, rdx, r8, r9, r10, r11`; preserve callee-saved `rbx, rbp, rsi, rdi, r12-r15` |
| `Return`, `Jump`, `CondJump`, `Nop`, `Unknown` | no register change |

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

We record the following per block:
- `null_eq_flag` — VReg flag-reg holding the result of "R == 0" test
- `null_eq_subj` — the source-level VReg `R` being compared against 0

When a `CondJump { cond, target, inverted }` reads a flag that is
`null_eq_flag` for some `R`, we know:
- on the "taken" branch (target), `R == 0` (if `!inverted`) or `R != 0` (if `inverted`)
- on the "fall-through" branch, the opposite

We attach this fact to the successor block's IN: a side table
`nonnull_in: HashSet<VReg>` per block. The meet for this set is
intersection (a register is known-nonnull on entry iff it's nonnull
on *every* incoming edge).

A deref `Load/Store { addr: MemOp { base, .. } }` is flagged
"guarded" if `state[base]` says `SystemBuffer` and `base` is in the
block's `nonnull_in` (or has been refined to nonnull within this
block before the deref).

## Detector output

`Vec<TaintFinding>` where each:

```rust
struct TaintFinding {
    deref_va: u64,           // VA of the Load/Store op
    block_va: u64,           // VA of the containing block start
    base_reg: String,        // physical register name at deref
    base_kind: Taint,        // SystemBuffer / UserBuffer / Type3InputBuffer
    disp: i64,
    access_width: u8,
    access: Access,          // Read | Write
    guarded_by_nullcheck: bool,
    guarded_by_length_check: bool,
}
```

The detector layer in Python filters this list by
`base_kind ∈ {SystemBuffer, UserBuffer, Type3InputBuffer} ∧ !guarded`.

## Python API

```python
import glaurung as g
findings = g.analysis.ioctl_taint(path, entry_va)
# -> list[dict] with the fields above
```

## Validation criteria

A v6 detector built on this primitive must:

1. **Catch** every site in `findings/.../sweep-2026-05-25-ranked.json`
   marked as confirmed TP: NDKPing.sys (6), usbprint.sys (3 public),
   amd64_libusb0.sys (≥10 of the 17 focal).
2. **Drop** the FP clusters in: xboxgip.sys sub_1400045e0,
   Classpnp.sys ClassDeviceControl, fltMgr.sys sub_18005dcb0,
   parport.sys sub_1c000a9b4, stream.sys sub_1c0016c40, rdpdr.sys
   sub_140024190 — these should drop to 0–2 findings (from 80 / 62 /
   58 / 20 / 1 / 3 — only the rdpdr 3 was already low).
3. Run end-to-end on the 402-driver corpus in under 5 minutes (vs
   v5's ~10 minutes).

## Not in scope (v1)

- Memory model: SystemBuffer spills to stack are lost.
- Indirect calls.
- Anything beyond x86-64. The lifter supports x86 and ARM64; null
  deref on ARM64 drivers can come later.
- Other detector classes (double-fetch, arbitrary-RW, probe-bypass)
  — those reuse the same primitive and ship in later phases.
