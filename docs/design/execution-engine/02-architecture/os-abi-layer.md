# OS / ABI Layer — SimProcedures, Syscalls, Library Stubs

To "execute" a real binary that calls `malloc`/`strcmp`/`CreateFileW` without
dragging in a real libc or kernel, we **summarize** library/OS calls instead of
executing them (angr SimProcedures, Qiling OS layer). The engine core stays
platform-agnostic (Manticore model); OS-specific behavior is pluggable.

## Mechanism — sentinel addresses + summary registry

1. When loading a binary's imports (reuse existing PE IAT / ELF PLT/GOT analysis:
   `src/analysis/pe_iat.rs`, `elf_plt.rs`, `elf_got.rs`), resolve each imported
   symbol to a unique **sentinel address** in an unmapped, non-executable region.
2. A call/fetch to a sentinel triggers the `MemUnmapped`(exec) hook.
3. The engine looks the sentinel up in the **summary registry** and dispatches.
4. The summary reads arguments per the `CallConv` (from `CpuModel`), performs its
   modeled effect on `Machine` state, writes the return register, pops the return
   address, and resumes at the caller.

```rust
pub trait SimProc<D: Domain> {
    fn call(&self, m: &mut Machine<D>, cc: &CallConv) -> Result<Flow, ExecError>;
}
pub struct OsLayer<D: Domain> {
    summaries: HashMap<Symbol, Box<dyn SimProc<D>>>,   // by import name
    syscalls:  HashMap<(Os, Abi, u64), Box<dyn SimProc<D>>>,  // by (os, abi, number)
}
```

## Syscalls

`syscall`/`svc` lifts to `Op::Intrinsic{name:"syscall"|"svc"}`. The helper reads
the syscall number from the arch's `SyscallConv` register, looks up
`(Os, Abi, number)`, and dispatches. Unmodeled syscalls: in concrete mode return a
configurable default (often success/0) and log; in symbolic mode havoc the result
(fresh symbol) — never silently corrupt state.

## v1 scope (correctness over coverage)

Model the **minimal set that lets target functions run to completion**, not all of
libc/Win32:

- **Memory:** `malloc`/`calloc`/`realloc`/`free` over a deterministic bump
  allocator (fixed bases — see [`determinism.md`](determinism.md)); `memcpy`,
  `memset`, `memmove`.
- **Strings:** `strlen`, `strcmp`/`strncmp`, `strcpy`/`strncpy`, `strcat`.
- **Linux syscalls (subset):** `brk`/`mmap` (back the allocator), `read`/`write`
  (against a crude symbolic/concrete fd model), `exit`/`exit_group`.
- **Stubs:** unmodeled imports get a default stub that returns a fresh
  symbol/0 and logs, so execution proceeds.

## Windows kernel surface (the IOCTL sink-finding payoff)

For the driver use case (a symbolic successor to `ioctl_taint`), model the IRP /
IOCTL entry surface enough to drive a dispatch routine:

- Seed an **IRP** structure in memory with a **symbolic** `SystemBuffer` /
  `Type3InputBuffer` and symbolic `InputBufferLength` / `OutputBufferLength` /
  `IoControlCode` — exactly the taint sources `ioctl_taint` already enumerates
  (`src/analysis/ioctl_taint.rs` lists `SystemBuffer`, `IoCtlCode`, `InputLen`,
  `OutputLen`, …).
- Stub the common `nt!`/`ntoskrnl` imports a dispatcher touches
  (`IoCompleteRequest`, `RtlCopyMemory`/`memcpy`, `ProbeForRead/Write`,
  `ExAllocatePool*`, `MmIsAddressValid`, …) as SimProcedures.
- Mark dangerous sinks (controlled-length `memcpy`, arbitrary write,
  `ProbeForWrite` bypass) as **target addresses** for directed search
  ([`symbolic-engine.md`](symbolic-engine.md)). Reaching one + solving the path
  yields a concrete IOCTL input witness.

This reuses the existing taint-source taxonomy and Windows knowledge in
`ioctl_taint`/`docs/windows-port/` rather than reinventing it.

## Calling-convention reuse

`src/ir/call_args.rs` already reconstructs call arguments; the `CallConv` in
[`arch-abstraction.md`](arch-abstraction.md) formalizes the same data for the
engine. SimProcedures consume `CallConv` to read args uniformly across SysV/Win64/
AAPCS64.

## References
- [`../01-research/emulator-engineering.md`](../01-research/emulator-engineering.md) §4
- [`../01-research/symbolic-execution-survey.md`](../01-research/symbolic-execution-survey.md) §7
- existing: `src/analysis/{pe_iat,elf_plt,elf_got,ioctl_taint}.rs`, `src/ir/call_args.rs`
