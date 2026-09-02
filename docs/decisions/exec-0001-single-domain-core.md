# ADR-0001 — One Interpreter Parameterized by a `Domain` Trait

> **Kind:** decision · **Status:** maintained

**ADR status:** Accepted · **Date:** 2026-06

## Context

We need both a concrete emulator and a symbolic executor over the same LLIR, for
x86-64 and ARM64. The naive approach writes two interpreters; they inevitably
drift out of sync, doubling instruction-semantics bugs.

## Decision

Write **one** IR interpreter (`step()`/`run()`) generic over a `Domain` trait that
abstracts the value type and its bit-vector primitives. Implement `Domain` for
`Concrete` (the emulator) and `Symbolic` (the executor); later optionally
`Interval`/`VSA`. The only places concrete and symbolic legitimately diverge are
`as_branch` (concrete always decides; symbolic may `Fork`) and the
concretization hook (shipped as `as_u64`, not the `concretize_addr` named here).

## Alternatives rejected

- **Two separate engines** — guarantees semantic drift; double the test burden.
- **An enum of value kinds** dispatched at runtime — branches on value-kind every
  op (slow concrete path) and bloats the hot loop; no monomorphization.
- **Adopt angr/Triton/Miasm** — violates the "native Rust core, don't ship those
  frameworks" goal; this is the whole premise.

## Evidence

Every mature dual-mode framework converged on this: angr/claripy backends
(`BackendConcrete`/`BackendZ3`/`BackendVSA`) over one VEX `SimEngine`; Triton's
concolic AST; BINSEC's one DBA core; Miasm's `SymbolicExecutionEngine` over the
same IR the jitter runs. → [`design/execution-engine-research/ir-design-lessons.md`](../design/execution-engine-research/ir-design-lessons.md) §6.

**Validated by prototype** (compiled `rustc -O`): a single `step()` drove both a
concrete run (`ebx=0x100, zf=1`) and a symbolic run emitting a valid SMT-LIB2
constraint — zero duplicated interpreter logic.

## Consequences

- (+) One place to get semantics right; the differential oracle validates it once.
- (+) Monomorphized concrete path is tight; symbolic machinery costs the concrete
  path nothing.
- (+) New domains (interval/taint) added without touching the interpreter — could
  eventually subsume `ioctl_taint`.
- (−) The interpreter is generic → compiled once per domain (code size). Accepted;
  prototype-proven.

## What the implementation changed

The ADR predicted a second consequence — "the memory model must also be
domain-parameterized (`type Mem`)" — and that did not happen. `src/exec/memory.rs`
is `Memory<D: Domain>`, generic over the *domain*, storing `Option<D::Val>` bytes
and assembling multi-byte accesses through `concat`/`extract`; the `Domain` trait
itself carries no associated memory type and no `load`/`store`/`concretize_addr`
(`src/exec/domain.rs`). One memory implementation serves both domains, so the
trait stayed narrower than this ADR expected. Verified with
`rg -n 'type (Mem|Val)' src/exec/domain.rs src/exec/concrete.rs src/symbolic/symdomain.rs`
and `rg -n 'pub struct Memory' src/exec/memory.rs`.

→ [`architecture/execution-engine.md`](../architecture/execution-engine.md)
