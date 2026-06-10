# Architecture Abstraction — `CpuModel`

The engine is arch-agnostic over the typed LLIR. All ISA-specificity lives in
four places: **(1) the lifter** (exists), **(2) register-layout data**, **(3)
intrinsic/helper handlers**, **(4) ABI/syscall conventions**. This file specs
(2) and (4) as a `CpuModel` descriptor; (1) is the existing `lift_*`; (3) is
[`helpers-and-intrinsics.md`](helpers-and-intrinsics.md).

## What exists today

- `core::disassembler::Architecture` enum (`X86`, `X86_64`, `ARM`, `ARM64`,
  `MIPS`, …) with `address_bits()` / `is_64_bit()`.
- `core::register::Register` (name, size, kind, `parent_register`,
  `offset_in_parent`) — already encodes sub-register hierarchy.
- `ir::lift_function::{lift_function_from_bytes, supports_arch}` — supports
  `X86`, `X86_64`, `AArch64`.
- `ir::call_args` — partial calling-convention recovery.

These are the raw materials; `CpuModel` assembles them into a descriptor the
engine consumes.

## The descriptor

```rust
pub trait CpuModel {
    fn arch(&self) -> Architecture;
    fn endian(&self) -> Endian;
    fn pointer_width(&self) -> Width;

    /// Register-bank layout: cells, offsets, sizes, alias relationships,
    /// vector/FP banks. Drives RegFile (machine-state.md).
    fn reg_layout(&self) -> &'static RegLayout;

    /// Special registers by role.
    fn pc(&self) -> RegId;
    fn sp(&self) -> RegId;
    fn flags(&self) -> &'static [RegId];

    /// Calling convention(s) for SimProcedures / call-arg extraction.
    fn default_cc(&self) -> &'static CallConv;   // arg regs, return reg, callee/caller-saved, stack order

    /// Syscall convention.
    fn syscall(&self) -> &'static SyscallConv;   // number reg, arg regs, trap instruction/intrinsic name
}

pub struct CallConv {
    pub int_args: &'static [RegId],     // e.g. x86-64 SysV: rdi,rsi,rdx,rcx,r8,r9 ; Win64: rcx,rdx,r8,r9
    pub ret: RegId,                     // rax / x0
    pub callee_saved: &'static [RegId],
    pub stack_args_after: usize,        // # of register args before spilling to stack
    pub stack_cleanup: StackCleanup,    // caller (SysV/Win64) vs callee (stdcall)
}
```

## The two v1 implementations

### `x86_64` (`src/exec/arch/x86_64.rs`)
- 16 GPRs (rax..r15) with 32/16/8 sub-register aliases (incl. `ah`-style
  high-byte), `rip`, `rflags` decomposed into the condition-code flag cells,
  `xmm0..15`/`ymm`/`zmm` vector bank, segment bases (`fs`/`gs`) as cells (TLS).
- CCs: **SysV** (`rdi,rsi,rdx,rcx,r8,r9`, ret `rax`, caller-clean) and **Win64**
  (`rcx,rdx,r8,r9` + 32-byte shadow space, ret `rax`). Selected per-binary OS.
- Syscall: number in `rax`, args `rdi,rsi,rdx,r10,r8,r9`, `syscall` instruction →
  `Intrinsic{name:"syscall"}` → OS layer.

### `arm64` (`src/exec/arch/arm64.rs`)
- 31 GPRs `x0..x30` with `w0..w30` 32-bit views (a 32-bit write zero-extends the
  64-bit reg — encoded by the lifter), `sp`, `pc`, `NZCV` → flag cells
  (`N`→`S`, `Z`→`Z`, `C`→`C`, `V`→`O`), `v0..v31` SIMD/FP bank.
- CC: **AAPCS64** (`x0..x7` args, ret `x0`, callee-saved `x19..x28`).
- Syscall: number in `x8`, args `x0..x5`, `svc #0` → `Intrinsic{name:"svc"}`.

The flag mapping is trivial precisely because our flags are condition-codes, not
EFLAGS bits — the same `Flag::Z`/`S`/`C`/`O` cells serve both arches.

## Selecting the model

`lift_function` already knows the arch; the engine picks the `CpuModel` from
`Architecture` + the binary's OS (from triage/format detection) to choose SysV vs
Win64, Linux vs Windows syscall tables (see [`os-abi-layer.md`](os-abi-layer.md)).

## Adding a new architecture later

The cost of, e.g., 32-bit x86, RISC-V, or MIPS is exactly: extend the lifter to
emit hardened ops for that arch + write a `CpuModel` descriptor + register any
arch-specific intrinsic handlers. **No engine, memory, solver, or search code
changes.** This is the cross-arch payoff (VEX/P-code/BINSEC model).

## References
- [`../01-research/ir-design-lessons.md`](../01-research/ir-design-lessons.md) §7
- [`machine-state.md`](machine-state.md), [`os-abi-layer.md`](os-abi-layer.md)
