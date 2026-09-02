# ADR-0004 — Symbolic Memory: Concrete Paging Plus a Concretization Policy Seam

> **Kind:** decision · **Status:** maintained

**ADR status:** Accepted 2026-06, superseded in implementation 2026-08 · **Date:** 2026-06

## Context

Symbolic memory is the hardest part of symbolic execution: a write through a
symbolic pointer can touch any byte of the address space. The design space
(Borzacchiello's survey) is {bitvector vs array theory} × {flat vs segmented},
crossed with how much precision an engine is willing to buy from the solver.

## The decision as originally taken

Bitvectors, flat layout, **concretize-with-threshold** — the angr/Mayhem
"partial memory model": concrete addresses take a direct paged path; a symbolic
**write** concretizes to one value (the maximum when hunting overflows) and
records the binding constraint; a symbolic **read** builds a bounded `Ite` tree
when the feasible address range is ≤ **1024 bytes**, and otherwise concretizes.

### Alternatives rejected then

- **KLEE-style segmented arrays with fork-per-object** — forks `n+1` states per
  symbolic access and explodes on a driver's kernel address space.
- **A full flat SMT array (BINSEC)** — precise and sound, but the queries grow
  and a single-formula flat memory is hard to merge across parallel states.
- **Pure `Ite` trees for every read** — unbounded for large objects.

## What was built instead

The **1024-byte ITE-tree read path was never implemented**, and no separate
symbolic-memory module exists: there is no `src/symbolic/symmem.rs`, and
`src/exec/memory.rs` — the one memory implementation, shared by the concrete and
symbolic domains — is a plain sparse 4 KiB page map of `Option<D::Val>` bytes
with no permissions, no copy-on-write, and no address-set machinery. Forking is
`Machine<Symbolic>: Clone`.

The threshold knob was replaced by a different, narrower seam. The engine
concretizes a symbolic address to exactly one model value, and the *choice of
which* value is a first-class, swappable policy:

```rust
// src/symbolic/concretization.rs
pub trait ConcretizationPolicy: Send + Sync {
    fn id(&self) -> &str;
    fn choose(&self, request: &ConcretizationRequest) -> ConcretizationChoice;
    // …
}
```

`ConcretizationChoice` is `AnyModel | LeastUnsigned | GreatestUnsigned |
BoundarySet(Vec<u128>) | Defer`. The built-in policies are `AnyModel` (the
default), `LeastUnsigned` (`glaurung-min-unsigned-v1`), `GreatestUnsigned`
(`glaurung-max-unsigned-v1`) and two site-hash schedules
(`glaurung-site-hash-{0,1}-v1`), selected by `GLAURUNG_CONCRETIZATION_POLICY`.
The explorer, not the policy, still owns every checked solve, the equality
binding, and the ordered-trace record, so a policy cannot widen the engine's
soundness surface. `BoundarySet` and `Defer` are contract values that **fail
closed** at today's single-successor seams: they exist so that forking over a
bounded address set, or keeping an address symbolic, does not need another API
redesign later.

So the original decision's *spirit* held — concretize rather than reason
precisely about memory, and accept the incompleteness — but its one tunable
number did not survive, and the escape hatch to array theory was never built.

Verified with `rg -n 'ConcretizationChoice|BoundarySet|Defer|POLICY_ID'
src/symbolic/concretization.rs`, `ls src/symbolic` (no `symmem.rs`), and
`rg -n 'perms|copy_on_write|dirty' src/exec/memory.rs` (no hits).

## Where the live record is

The shipped seam is specified in
[`architecture/solver/concretization-policy.md`](../architecture/solver/concretization-policy.md)
and decided in [`solver-026`](solver-026-concretization-as-a-policy.md) ("Make
concretization a first-class policy"). Read those first; this ADR is kept for
the alternatives it rejected, which remain the right map of the design space.

## Consequences

- (+) The fast path stays fully concrete, and the policy seam is small enough to
  be swept experimentally without touching the explorer.
- (−) **Incomplete.** A bug that only fires when two symbolic indices are equal
  is silently unreachable. Accepted: this is a bug-finder, not a verifier
  ([exec-0006](exec-0006-execution-mode.md)), and the static
  [`ioctl_taint`](../architecture/ioctl-taint.md) pass covers a different slice.
- (−) The 1024-byte knob the original text promises does not exist; anyone
  looking for it should read the policy seam instead.

→ [`architecture/execution-engine.md`](../architecture/execution-engine.md),
[`design/execution-engine-research/symbolic-execution-survey.md`](../design/execution-engine-research/symbolic-execution-survey.md) §2
