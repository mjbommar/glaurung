# Linux system calls

> **Kind:** reference · **Status:** maintained

Linux system calls form a userspace/kernel ABI. Existing syscall interfaces are
expected to remain available, but numbers, argument registers, compatibility
wrappers, and entry instructions are architecture- and ABI-specific. Bind every
number lookup to an architecture and ABI such as x86-64, i386, x32, AArch64, or
RISC-V.

Application code normally calls a libc wrapper. A wrapper can adapt arguments,
select a newer syscall, or provide userspace behavior. When no wrapper exists,
Linux exposes `syscall(2)` for a direct call. Therefore a source-level function
name and a machine-level syscall are related evidence, not always a one-to-one
mapping.

## Finding authoritative definitions

For the kernel revision being analyzed, use:

- `scripts/syscall.tbl` for architectures using the common generated table on
  current kernels;
- `include/uapi/asm-generic/unistd.h` for generic UAPI definitions where still
  applicable;
- `arch/x86/entry/syscalls/syscall_64.tbl` and `syscall_32.tbl` for x86 ABIs;
- architecture-specific tables and entry code under `arch/<arch>/`; and
- `SYSCALL_DEFINEn(name, ...)` implementations plus their UAPI structures.

The kernel's
[adding-syscalls guide](https://www.kernel.org/doc/html/latest/process/adding-syscalls.html)
documents the common and x86 table locations, compatibility wrappers, and the
post-6.11 common-table workflow. The
[ABI guide](https://www.kernel.org/doc/html/latest/admin-guide/abi.html)
describes the stability expectation. Manual pages document user-visible
semantics, but the exact kernel tree remains the implementation ground truth.

## Calling-convention example

On the native x86-64 Linux ABI, the syscall number is placed in `rax`; arguments
use `rdi`, `rsi`, `rdx`, `r10`, `r8`, and `r9`; the `syscall` instruction enters
the kernel; and a negative return in the kernel error range is translated by
libc into `-1` plus `errno`. Do not reuse that register map for i386, x32, ARM,
or another ABI.

Static analysis must also account for indirect wrappers, vDSO calls,
compatibility entry points, seccomp filtering, and dynamically constructed
numbers. Seeing a trap instruction establishes a boundary, not the syscall name
or argument meaning by itself.

## Current Glaurung boundary

`src/core/instruction.rs` classifies mnemonics such as `syscall`, `sysenter`,
`int`, and `svc` as system-call instructions. The typed IR can carry a generic
`syscall` intrinsic name. The current checkout does **not** ship a complete
Linux syscall-number table, argument decoder, libc-wrapper resolver, or OS
emulation layer.

The OS/syscall layer described under `docs/history/execution-engine-2026-06/` is design
work. Do not cite it as implemented behavior. For present analysis, report the
instruction, architecture/ABI, number evidence, and unresolved argument roles
separately.

Focused instruction classification is covered by:

```bash
uv run pytest python/tests/test_instruction.py -q
```
