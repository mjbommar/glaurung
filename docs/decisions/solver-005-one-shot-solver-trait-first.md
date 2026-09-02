# Solver ADR-005 — Keep the one-shot `Solver` trait for v1; add incremental later

> **Kind:** decision · **Status:** maintained

**ADR status:** Proposed.
**Context:** The `Solver` trait is one-shot (`check` over the full assert
list); axeyum's perf advantage is *warm incrementality*, which the
one-shot contract cannot exploit.
**Decision:** v1 honors the existing one-shot trait (fresh arena+solver per
`check`). An **incremental** trait extension (push/pop mapping to axeyum's
`IncrementalBvSolver`, exploiting glaurung's fork structure) is a later,
additive, opt-in phase (P5).
**Consequences:** v1 is simple and low-risk but leaves axeyum's main perf
lever on the table - accepted, because correctness/shippability (G1-G3)
come first and the perf lever is real, sequenced work, not a redesign.
**Alternatives rejected:** widening the trait in v1 (couples the shippable
correctness milestone to a larger engine change).

---

Part of the solver decision series; the index is
[`docs/decisions/README.md`](README.md). The subsystem these records
govern is described in
[`docs/architecture/solver-backends.md`](../architecture/solver-backends.md).
