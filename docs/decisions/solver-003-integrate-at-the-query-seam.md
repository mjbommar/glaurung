# Solver ADR-003 — Integrate at the SMT-query seam only, not the executor

> **Kind:** decision · **Status:** maintained

**ADR status:** Proposed.
**Context:** axeyum ships its own `SymbolicExecutor` + BMC + k-induction;
glaurung ships its own `explore.rs` DFS explorer. The two overlap almost
completely in shape.
**Decision:** Consume axeyum **only** as a solver
(`IncrementalBvSolver`/`solve_smtlib` + `Model` + proof export). Do not
adopt axeyum's executor; do not expose axeyum's BMC layer through
glaurung. glaurung builds path conditions; axeyum decides them.
**Consequences:** Minimal coupling, one clear seam (`02`), each project's
executor evolves independently. axeyum's executor remains a useful
*reference* for a future incremental trait (P5), not a dependency.
**Alternatives rejected:** replacing glaurung's explorer with axeyum's
(throws away the x64/WDM detection layer + IOCTLance parity work).

---

Part of the solver decision series; the index is
[`docs/decisions/README.md`](README.md). The subsystem these records
govern is described in
[`docs/architecture/solver-backends.md`](../architecture/solver-backends.md).
