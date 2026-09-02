# Solver ADR-006 — Proofs threaded off-trait in v1 (no trait signature change)

> **Kind:** decision · **Status:** maintained

**ADR status:** Proposed.
**Context:** Only axeyum can produce proofs today; the `Solver` trait
returns `SolveResult` with no proof slot. Widening the trait for one
backend is premature.
**Decision:** Surface DRAT proofs via
`AxeyumSolver::prove_infeasible_path`, returning a concrete
`InfeasiblePathVerdict` whose infeasible variant owns a source-recheckable
certificate. Do not widen the shared `Solver` trait in v1. Revisit a trait-level
proof return only if a second backend gains proofs.
**Consequences:** A consumer that wants "path infeasible, DRAT-checked"
evidence explicitly requests the bounded proof second pass and can persist its
DIMACS/DRAT/LRAT. `recheck_for_path` binds it to the exact Glaurung assertions.
The generic trait and ordinary pruning stay unchanged, so z3/pipe are
unaffected.
**Alternatives rejected:** adding an `Option<Proof>` to `SolveResult` now
(pollutes every backend's return for one producer).

---

Part of the solver decision series; the index is
[`docs/decisions/README.md`](README.md). The subsystem these records
govern is described in
[`docs/architecture/solver-backends.md`](../architecture/solver-backends.md).
