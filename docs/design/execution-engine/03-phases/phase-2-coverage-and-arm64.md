# Phase 2 — Instruction Coverage & ARM64 Parity

**Goal:** broaden the helper set (SIMD/x87/atomics) so real functions run without
`UnsupportedIntrinsic` halts, and bring ARM64 to emulation parity with x86-64.
Specs: [`helpers-and-intrinsics.md`](../02-architecture/helpers-and-intrinsics.md),
[`arch-abstraction.md`](../02-architecture/arch-abstraction.md).

**Feature gate:** `exec`. Can run in **parallel with Phase 3**.

## Tasks

- **2.1 ARM64 IR hardening.** Finish Phase-0 width/intrinsic threading in
  `lift_arm64.rs` (it was deferred): widths from `capstone` operand info, `w`-reg
  32-bit zero-extend, NEON/atomics/barriers/system-regs → `Intrinsic`. *Test:*
  `ir::verify` passes on ARM64 fixtures.
- **2.2 `exec/arch/arm64.rs`** — `RegLayout` (`x0..x30`/`w*`, `sp`, `pc`, NZCV→
  flag cells, `v0..v31`) + `CpuModel` (AAPCS64, `svc` syscall). *Test:* sub-reg
  aliasing; flag mapping.
- **2.3 ARM64 scalar helpers** — `udiv`/`sdiv`, `madd`/`msub`, `rev` (bswap),
  `clz`, load/store-pair already lowered by the lifter. *Test:* per-helper.
- **2.4 x86 SIMD helpers** — SSE/AVX as scalar-loop over lanes on vector cells
  (`movdqa`, `pxor`, `paddb/w/d/q`, `pcmpeqb`, `pshufb`, `punpck*`, `pmovmskb`).
  *Test:* differential vs Unicorn on a SIMD corpus.
- **2.5 ARM64 NEON helpers** — the common vector ops mirroring 2.4. *Test:*
  differential.
- **2.6 Software FP helpers** — x87 + SSE scalar FP and ARM VFP, correctness-first
  (exotic rounding deferred, N6). *Test:* differential on FP corpus (tolerance
  documented).
- **2.7 Atomics** — `lock`-prefixed RMW, `cmpxchg`/`xchg`, ARM `ldxr`/`stxr`
  modeled as non-atomic in the single-threaded emulator (documented). *Test:*
  semantics match Unicorn for single-threaded sequences.
- **2.8 Extend the differential corpus** to ARM64 + SIMD/FP.

## Deliverables

- `exec/helpers/{x86,arm64}.rs` populated; `exec/arch/arm64.rs`.
- ARM64 reaches the same `emulate_function` entry point.

## Exit criteria

- ARM64 emulator matches Unicorn on **≥95%** of its corpus.
- The combined x86-64 + ARM64 differential corpus has **zero**
  `UnsupportedIntrinsic` halts (everything either lifts to real ops or has a
  helper); residual divergences are fixture-backed regression tests.
- `cargo test --features exec,dev-oracle` green for both arches.

## Notes

ARM64 parity is cheap *because* the engine, memory, helpers framework, and tests
are arch-agnostic — Phase 2 is mostly a lifter pass + a descriptor + arch-specific
helpers, exactly the cross-arch payoff the architecture promised. SIMD breadth is
the main effort sink; scalar-loop helpers are deliberately simple and can be
promoted to vector IR ops later if profiling demands.
