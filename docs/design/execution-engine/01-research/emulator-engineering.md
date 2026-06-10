# Emulator Engineering — QEMU / Unicorn / bochscpu / Snapshot Fuzzers

How to build an IR-level concrete emulator in Rust (x86-64 + ARM64). Distilled
from QEMU TCG, Unicorn, Triton's concrete engine, Miasm's jitters, Qiling, and
Rust snapshot fuzzers (bochscpu/wtf, Lucid, snapchange).

## 1. Execution model: interpret vs JIT

- **QEMU TCG** is a dynamic translator: lift a guest block to IR, emit host code,
  cache as a Translation Block, and **directly chain** TBs (`goto_tb` patches a
  jump slot) so hot paths never re-enter dispatch.
- **Miasm** ships three jitters over one IR (Python interpreter, C, LLVM) — proof
  that you can add a JIT later behind the same IR.
- **bochscpu** (wtf/Lucid) is a straight **interpreter**, chosen because
  per-instruction callbacks + fidelity matter more than raw speed for snapshot
  fuzzing.

**Decision for us: cached IR interpreter, not JIT** (ADR-0003). Rationale:
determinism, trivial per-instruction hooks, easy self-modifying-code handling,
inspectability — exactly what an AI-native RE tool needs. Realistic perf: ~1–2
orders slower than native, fine for bounded/forensic analysis. Make it fast via:

1. **Lift once, cache by address** (`HashMap<Addr, Arc<LiftedBlock>>`) — the
   single biggest win (TCG's TB cache).
2. **Block-at-a-time dispatch** — amortize decode/match over the block.
3. **Successor caching (software block chaining)** — cache resolved
   constant-target successor pointers (the `goto_tb` analog).
4. **Flat, index-based IR** — `Vec<Op>` with `#[repr(u8)]` enum opcodes,
   registers as indices; `match` compiles to a jump table; no `Box<dyn>` in the
   hot loop.
5. **No per-instruction allocation** — immutable `Arc<LiftedBlock>`, reused
   scratch.

JIT is worth it only when CPU-bound on the same code millions of times with
sparse hooks — a later optional backend, never v1.

## 2. Memory model (softmmu)

- **Page-table mapping with permissions** (`R/W/X`), 4 KB-aligned, like Unicorn's
  `uc_mem_map`. QEMU fronts it with a direct-mapped TLB; misses fall to a helper.
- **Sparse/lazy allocation** — bochscpu allocates physical pages on first touch
  via an unmapped-access callback (GVA/GPA/HVA spaces). Ideal for emulating tiny
  slices of a huge address space.
- **MMIO/hook regions** — Unicorn's `UC_HOOK_MEM_*` and `*_UNMAPPED`/`*_PROT`
  callbacks can map-on-demand or abort (non-zero return).
- **COW snapshots via dirty-page differential restore (the fuzzing core).** wtf
  restores only written pages by `memcpy` from the pristine snapshot — **no
  syscalls in the hot path**; Lucid forces dirty tracking via `PROT_READ` +
  fault; snapchange uses KVM dirty bits. **Reset cost ∝ bytes modified, not memory
  size.** This is our forking primitive for symbolic exploration and "what-if"
  replay.

→ [`../02-architecture/machine-state.md`](../02-architecture/machine-state.md).

## 3. Hooks / instrumentation API (Unicorn taxonomy = de-facto standard)

| Hook | Fires |
|---|---|
| `CODE` | before every instruction (expensive — defeats block fast paths) |
| `BLOCK` | on entering a basic block (default coarse instrumentation) |
| `MEM_READ`/`WRITE`/`READ_AFTER` | on data access |
| `MEM_*_UNMAPPED` / `*_PROT` | map-on-demand or abort |
| `INTR` | interrupt/syscall |
| `INSN` | a specific instruction (`SYSCALL`/`CPUID`/`IN`/`OUT`) |

Semantics to replicate: **non-zero return aborts**; memory hooks fire only for
*guest-instruction* accesses, not direct API writes. Gate the hot loop on
`hooks.is_empty()` (predictable branch) so zero-hook runs pay nothing. **Context
save/restore** (`uc_context_*`) checkpoints registers cheaply; full snapshot =
register context + dirty-page memory restore.

→ [`../02-architecture/machine-state.md`](../02-architecture/machine-state.md#hooks).

## 4. Library / OS call modeling — summarize, don't execute libc

- **angr SimProcedures** — replace `strlen`/`malloc`/etc. with a summary keyed by
  symbol; read args via calling convention; fresh instance per call.
- **Syscalls** — `SimSyscallLibrary` with per-ABI number maps.
- **Qiling** — OS layer over Unicorn; ~40% of Win32 + Linux syscalls + UEFI;
  candid that a userspace model can't fully mirror a kernel.
- **Mechanism:** resolve imports to **sentinel addresses**; a fetch to a sentinel
  triggers the unmapped-fetch hook → dispatch to a `HashMap<Symbol, Summary>`;
  the summary writes the return register, pops the return address, resumes.

→ [`../02-architecture/os-abi-layer.md`](../02-architecture/os-abi-layer.md).

## 5. Complex instructions via a helper registry (QEMU's lesson)

Keep the IR core small; push SIMD/FP/`DIV`/`CPUID`/`RDTSC`/syscalls into
**helpers** — plain functions over canonical state. **Calling contract:** flush
dirty register operands to the canonical register file *before* a helper, reload
*after* (QEMU's global-sync rule), so helpers see consistent state. Mark
side-effect-free helpers `pure` for elision. SIMD can start as scalar-loop
helpers and later be promoted to vector ops.

→ [`../02-architecture/helpers-and-intrinsics.md`](../02-architecture/helpers-and-intrinsics.md).

## 6. Self-modifying code

x86 has no app-signaled I-cache invalidation, so the emulator detects writes to
executable pages itself. QEMU keeps a per-page linked list of TBs and a
`code_bitmap`; a write invalidates exactly the affected blocks. **For us:** mark
lifted pages as code pages; on a store-hook to a code page, evict the lift-cache
entries (and successor pointers) for that page. Per-page bulk eviction is the
simple correct default since SMC is rare.

## 7. Bounded / forensic / deterministic execution

- **Instruction budget** decremented per insn/block → `Halt::BudgetExhausted`
  (doubles as timeout; prefer counts over wall-clock for determinism).
- **Region/context fencing** (wtf stops on CR3 change) → stop when leaving the
  target module/region.
- **No real time/random** (Glaurung rule): `RDTSC` → virtual monotonic counter
  derived from instruction count; `CPUID` → fixed feature set; `RDRAND`/random
  syscalls → seeded deterministic PRNG. Route every nondeterministic
  instruction/syscall through a helper that reads only emulator state.

→ [`../02-architecture/determinism.md`](../02-architecture/determinism.md).

## 8. Differential testing (validation)

Run identical instruction streams on the emulator and an oracle; compare
post-execution architectural state; any divergence is a bug. EXAMINER did this
across 2.77M streams (found 12 real bugs in common instructions, and 100k+
divergences of *Unicorn/QEMU themselves* from real ARM silicon). **For us:** a
`dev-oracle` Cargo feature single-steps our interpreter and the `unicorn-engine`
crate on identical pre-state and diffs the full register file + flags + memory
writes. Unicorn is a **dev dependency and oracle only** — never shipped; for
exotic encodings fall back to real hardware.

→ [`../04-testing/differential-oracle.md`](../04-testing/differential-oracle.md).

## Cross-cutting takeaways

1. **Cached IR interpreter, not JIT, for v1** — determinism + hooks + SMC all get
   easier; JIT slots behind the same IR later (Miasm pattern).
2. **Two highest-leverage mechanisms:** lift-cache + software block chaining
   (perf) and dirty-page differential snapshot restore (forking) — both
   O(work-done), not O(memory-size).
3. **Small core + helper registry** keeps the interpreter fast at total coverage,
   with a strict flush-before-helper contract.
4. **Determinism falls out** if every nondeterministic op routes through a helper
   over virtual state + seeded PRNG.
5. **Unicorn = ideal dev-only oracle**, but not ground truth for exotic encodings.

## Sources

- [QEMU TCG internals](https://www.qemu.org/docs/master/devel/tcg.html), [Airbus TCG deep-dive](https://airbus-seclab.github.io/qemu_blog/tcg_p1.html)
- [Unicorn Hooks.md](https://github.com/unicorn-engine/unicorn/blob/master/docs/Hooks.md), [mem_apis.c](https://github.com/unicorn-engine/unicorn/blob/master/samples/mem_apis.c), [context save/restore](https://deepwiki.com/ipasimulator/unicorn/6.4-advanced-use-cases)
- [wtf snapshot fuzzer / bochscpu](https://doar-e.github.io/blog/2021/07/15/building-a-new-snapshot-fuzzer-fuzzing-ida/), [Lucid](https://github.com/h0mbre/Lucid), [snapchange](https://github.com/awslabs/snapchange)
- [angr SimProcedures](https://docs.angr.io/extending-angr/simprocedures), [Qiling syscall/OS](https://docs.qiling.io/en/latest/syscall_api/)
- [Miasm jitters](https://miasm.re/blog/2018/12/20/release_v0_1_0.html), [EXAMINER (ASPLOS'22)](https://dl.acm.org/doi/10.1145/3503222.3507736), [Icicle](https://arxiv.org/pdf/2301.13346)
