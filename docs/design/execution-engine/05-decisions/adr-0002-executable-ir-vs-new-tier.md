# ADR-0002 — Harden the Existing LLIR In Place

**Status:** Accepted · **Date:** 2026-06

## Context

The current LLIR is lossy (no per-op width, `Op::Unknown`, approximate
sub-registers). Execution needs a total, typed IR. We could (a) evolve the LLIR in
place, or (b) introduce a separate lower "executable IR" tier below it (the VEX/
P-code/DBA approach where lifters target a distinct micro-IR).

## Decision

**Evolve the LLIR in place**, behind a verifier and a compatibility shim, then
optionally add an SSA tier *above* it later (the Binary Ninja LLIL→MLIL split).

## Alternatives rejected

- **A new lower IR tier (b)** — cleanest in theory, but it forks the lifter effort
  (now two targets), duplicates the decompiler/dataflow consumers' integration,
  and doubles maintenance for a single-crate project. The LLIR is already three-
  address and architecturally close to what we need; the gaps are *additive*
  (widths, ext ops, intrinsics), not structural.
- **Leave the IR lossy and special-case execution** — non-starter; an emulator on
  a lossy IR diverges from the real CPU.

## How we avoid breaking consumers

1. Additive type changes with sensible defaults so construction sites compile.
2. `Op::Unknown` kept as a deprecated alias lowering to a conservative
   `Op::Intrinsic` during a transition window.
3. A new **IR verifier** (`src/ir/verify.rs`) asserts width agreement, defined
   reads, and no residual `Unknown` — run over the whole sample corpus.
4. The existing Rust + Python test suite is the migration safety net.

→ [`../02-architecture/executable-llir.md`](../02-architecture/executable-llir.md),
[`../03-phases/phase-0-ir-hardening.md`](../03-phases/phase-0-ir-hardening.md).

## Consequences

- (+) One IR, one lifter effort, existing consumers keep working.
- (+) Width info is *recovered* from the decoder, not invented — mostly mechanical.
- (−) Phase 0 touches many construction/match sites (migration cost); the verifier
  + tests bound the risk.
- (Future) An SSA/mid tier can be built *above* the hardened LLIR for the
  decompiler without disturbing the executable core.
