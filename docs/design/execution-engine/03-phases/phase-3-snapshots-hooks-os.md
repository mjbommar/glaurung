# Phase 3 — Snapshots, Hooks, and the OS/ABI Layer

**Goal:** make the emulator *usable on real binaries* — COW snapshots for cheap
forking/replay, a Unicorn-compatible hook API, and a SimProcedure/syscall layer so
functions that call libc/Win32 run to completion. Specs:
[`machine-state.md`](../02-architecture/machine-state.md),
[`os-abi-layer.md`](../02-architecture/os-abi-layer.md).

**Feature gate:** `exec`. Can run in **parallel with Phase 2**.

## Tasks

- **3.1 Dirty-page COW snapshots.** Add `snapshot()/restore()` to `exec/memory.rs`:
  baseline + per-store dirty-page log; restore copies back only dirty pages.
  Register-context save/restore (cheap clone). *Test:* snapshot → mutate → restore
  → byte-identical; restore cost ∝ dirty pages (assert only dirty frames touched).
- **3.2 Hook API (`exec/hooks.rs`).** Unicorn taxonomy (`Code`/`Block`/`MemRead`/
  `MemWrite`/`MemReadAfter`/`MemUnmapped`/`MemProt`/`Intr`/`Insn`); non-`Continue`
  return aborts; hot-loop `is_empty()` gating; memory hooks fire only for
  guest-instruction accesses. *Test:* each hook kind fires with correct args;
  abort semantics; zero-hook fast path.
- **3.3 SMC coherence.** On a `MemWrite` to a `code_pages` page, evict affected
  lift-cache blocks + successor pointers. *Test:* self-modifying snippet
  re-executes the new bytes.
- **3.4 SimProcedure registry (`os/simproc.rs`).** Sentinel-address resolution via
  existing IAT/PLT/GOT analysis; dispatch on unmapped-exec fetch; read args via
  `CallConv`; write return; pop return addr; resume. *Test:* a call to a stubbed
  `strlen` returns the right length and control resumes at the caller.
- **3.5 libc/syscall subset (`os/linux.rs`).** `malloc`/`free`/`memcpy`/`memset`/
  `strlen`/`strcmp`/`strcpy` over a deterministic bump allocator; Linux syscalls
  `brk`/`mmap`/`read`/`write`/`exit`. *Test:* a real ELF function that mallocs +
  memcpys runs to `ret` with correct memory.
- **3.6 Windows stub surface (`os/windows.rs`), v1.** IRP seeding (symbolic-ready
  fields per `ioctl_taint`'s taxonomy), common `nt!`/`ntoskrnl` stubs
  (`IoCompleteRequest`, `RtlCopyMemory`, `ProbeForRead/Write`, `ExAllocatePool*`).
  *Test:* a real driver dispatch routine runs without unmapped-fetch aborts.
- **3.7 Win64/SysV CC selection** wired from binary OS detection. *Test:* arg
  extraction correct for both.

## Deliverables

- `exec/hooks.rs`; `os/{mod,simproc,linux,windows}.rs`; snapshot/restore in
  `exec/memory.rs`.
- `emulate_function` now accepts hooks + an OS model and runs library-calling
  functions to completion.

## Exit criteria

- Snapshot/restore is O(dirty-pages) and byte-exact (test-proven).
- Hooks match Unicorn semantics on the hook test suite.
- A real ELF function and a real Windows driver dispatch routine each run to a
  clean stop using only the v1 stub set (or report exactly which import/syscall is
  missing — never silent corruption).
- `cargo test --features exec` green.

## Notes

The Windows surface deliberately reuses the taint-source taxonomy and import
knowledge already in `src/analysis/ioctl_taint.rs` and `docs/windows-port/` — this
phase is where the emulator and the existing static driver analysis start to
converge, setting up Phase 5/7 sink-finding.
