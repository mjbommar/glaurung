# ADR-0004 — Symbolic Memory: BV + Flat + Concretize-with-Threshold

**Status:** Accepted · **Date:** 2026-06

## Context

Symbolic memory is the hardest part of symbolic execution. A write through a
symbolic pointer can touch any byte (up to 2⁴⁸ on x86-64). The design space
(Borzacchiello survey) is {Bitvector vs Array theory} × {flat vs segmented}.

## Decision

**Bitvectors + flat layout + concretize-with-threshold** — the angr/Mayhem
"partial memory model":

- Concrete address → direct paged access (off the solver).
- Symbolic-address **write** → concretize to a single value (default; use the
  **max** address when hunting overflows, to maximize sink-trigger probability);
  record the binding constraint.
- Symbolic-address **read** → if the address range ≤ **1024 bytes**, build a
  bounded `Ite` tree; else concretize.

Keep a narrow escape hatch to full SMT array theory only on a concrete-heavy DSE
trace where precision pays.

## Alternatives rejected

- **KLEE-style segmented arrays + fork-per-object** — forks `n+1` states per
  symbolic access; explodes on a driver's large kernel address space (the exact
  blowup we must avoid).
- **Full flat SMT array (BINSEC)** — precise/sound but queries get complex and a
  single-formula flat memory is **hard to merge across parallel states**; fits
  trace-DSE, not parallel exploration.
- **Pure ITE trees for all reads** — lengthy for large objects.

## Evidence

The memory-models survey identifies concretize-with-threshold as the binary-
analysis de-facto default (the only one that scales, merges cleanly via per-byte
`Ite`, and tolerates loss of object boundaries in stripped binaries); 1024 B is
the Mayhem-proposed scalability/accuracy knob. →
[`../01-research/symbolic-execution-survey.md`](../01-research/symbolic-execution-survey.md) §2.

## Consequences

- (+) Scales on large address spaces; merge-friendly; fast common (concrete) path.
- (+) Max-write concretization directly serves overflow/sink-finding.
- (−) **Incomplete** — silently drops some reachable buggy states (e.g. a bug that
  only triggers when two symbolic indices are equal). Accepted: this is a
  bug-finder, not a verifier (see ADR-0006); the threshold is tunable, and the
  static `ioctl_taint` pre-filter catches a different slice of cases.

→ [`../02-architecture/symbolic-engine.md`](../02-architecture/symbolic-engine.md)
