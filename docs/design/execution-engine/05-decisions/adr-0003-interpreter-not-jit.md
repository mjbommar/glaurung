# ADR-0003 — Cached IR Interpreter for v1 (Not a JIT)

**Status:** Accepted · **Date:** 2026-06

## Context

An IR-level emulator can interpret the IR or JIT it to host code (QEMU TCG). JIT is
faster on hot code; interpretation is simpler, deterministic, and easy to
instrument.

## Decision

Ship a **cached IR interpreter** for v1. Keep the IR backend-agnostic so a JIT can
be added later as an alternate backend behind the same IR (the Miasm multi-jitter
pattern), without touching the lifter, hooks, or memory model.

## Rationale

For an AI-native RE / forensic tool, the things that matter most are:

- **Determinism** (a house rule and a symbolic-execution correctness requirement)
  — trivial in an interpreter, harder across a JIT.
- **Per-instruction hooks** — free in an interpreter; in a JIT they force
  deopt/recompile and defeat block chaining.
- **Self-modifying-code handling** — straightforward cache invalidation in an
  interpreter.
- **Inspectability** — single-step, snapshot, diff against an oracle.

Realistic interpreter perf is ~1–2 orders of magnitude slower than native — fine
for *bounded, forensic* execution of function slices (we do not boot OSes, N1).
Speed comes from: lift-once block cache, block-at-a-time dispatch, successor
caching (software block chaining), flat index-based IR, no per-instruction
allocation. → [`../01-research/emulator-engineering.md`](../01-research/emulator-engineering.md) §1.

## Alternatives rejected

- **JIT from day one** — large complexity (codegen, regalloc, code cache),
  hostile to hooks/SMC/determinism, premature for our workloads.
- **Reuse Unicorn/QEMU at runtime** — violates the native-Rust goal (N5); Unicorn
  is a dev-only oracle, not a runtime engine.

## Consequences

- (+) Simple, deterministic, fully instrumentable; fast to build and validate.
- (+) JIT remains a clean future option behind the same IR.
- (−) Not suitable for million-iteration fuzzing campaigns at native speed — an
  explicit non-goal for v1; revisit with a JIT backend if needed.
