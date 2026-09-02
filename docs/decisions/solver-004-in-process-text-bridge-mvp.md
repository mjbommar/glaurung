# Solver ADR-004 — MVP is an in-process SMT-LIB text bridge, not a subprocess

> **Kind:** decision · **Status:** maintained

**ADR status:** Proposed.
**Context:** glaurung's `pipe` backend shells out to an SMT-LIB solver
binary. axeyum has **no** stdin `sat/unsat` CLI - only the `axeyum-bench`
harness. But axeyum exposes `solve_smtlib(&str, &config)` as a library fn,
and glaurung's `pipe::build_script` already renders the exact SMT-LIB2.
**Decision:** The P1 walking skeleton is an **in-process** backend that
renders with glaurung's existing serializer and calls `solve_smtlib` -
no subprocess, no CLI shim, no term translator. The subprocess route
(20-line shim + `GLAURUNG_SMT_SOLVER`) is a documented fallback only.
**Consequences:** MVP is in-process (a real step toward G1), reuses proven
code on both sides, and yields the first differential + latency data
before committing to the native term translator (P2).
**Alternatives rejected:** building an axeyum SMT-LIB REPL CLI just to fit
the subprocess pattern (more code, subprocess overhead, no benefit).

---

Part of the solver decision series; the index is
[`docs/decisions/README.md`](README.md). The subsystem these records
govern is described in
[`docs/architecture/solver-backends.md`](../architecture/solver-backends.md).
