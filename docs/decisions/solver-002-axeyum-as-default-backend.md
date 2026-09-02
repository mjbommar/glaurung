# Solver ADR-002 — Axeyum is the default backend; z3 stays an opt-in perf backend

> **Kind:** decision · **Status:** maintained

> **Superseded.** Axeyum was never made a default feature. The shipped
> configuration is `default = ["triage-core"]` with every solver opt-in, and
> `solve()`'s cascade is z3 > axeyum > pipe only among the backends a build
> explicitly enables (`src/symbolic/solver/mod.rs`, `Cargo.toml` `[features]`).
> The perf gate this ADR made the default conditional on never closed; see
> [solver-014](solver-014-source-prefix-production-win.md) and
> [solver-021](solver-021-defer-wider-direct-delta-default.md).

**ADR status:** Proposed.
**Context:** Axeyum is pure-Rust, wheel-shippable, proof-carrying, but not
yet perf-parity with z3. z3 is fast but links libz3 (C/C++) and is kept
out of the wheel.
**Decision:** Make `solver-axeyum` a **default feature**; keep `solver-z3`
**opt-in**. Priority cascade in `solve()`:
`solver-z3` (if explicitly enabled) -> `solver-axeyum` (default) -> pipe.
**Consequences:** The shipped/default build gets a real pure-Rust
in-process solver (G1). Users who want maximum speed opt into z3. No
silent provider swap - the choice is an explicit build feature.
**Alternatives rejected:** replacing z3 outright (loses the perf escape
hatch while axeyum's perf gate is open, NG1); keeping z3 default (defeats
the pure-Rust/shippability goal).

---

Part of the solver decision series; the index is
[`docs/decisions/README.md`](README.md). The subsystem these records
govern is described in
[`docs/architecture/solver-backends.md`](../architecture/solver-backends.md).
