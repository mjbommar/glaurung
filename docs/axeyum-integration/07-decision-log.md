# 07 - Decision log

ADR-style records of the load-bearing choices, so a future reader (or a
future us) sees the reasoning, not just the outcome. Status: all
**Proposed** until the plan is acted on; promote to **Accepted** as each is
implemented.

---

## ADR-001 - Depend on axeyum by path (dev) then git-rev (release)

**Status:** Proposed.
**Context:** All axeyum crates are `publish = false`; nothing is on
crates.io. glaurung needs `axeyum-ir` + `axeyum-solver` (rest transitive).
Both repos are the author's, both edition 2024 / rustc >= 1.88.
**Decision:** Use a **path dependency** during co-development (P1-P3), then
pin a **git-rev dependency** at P4 (the default-landing) so the shipped
artifact is reproducible and decoupled from local checkout paths. Never
crates.io (blocked by `publish=false`; not needed).
**Consequences:** glaurung's MSRV floor rises to rustc 1.88 / edition 2024
(already met). API drift is bounded by keeping the consumed surface tiny
(term building + one-shot solve + model read + proof export).
**Alternatives rejected:** vendoring a copy (drift + license duplication);
crates.io (not published).

## ADR-002 - Axeyum is the default backend; z3 stays an opt-in perf backend

**Status:** Proposed.
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

## ADR-003 - Integrate at the SMT-query seam only, not the executor

**Status:** Proposed.
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

## ADR-004 - MVP is an in-process SMT-LIB text bridge, not a subprocess

**Status:** Proposed.
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

## ADR-005 - Keep the one-shot `Solver` trait for v1; add incremental later

**Status:** Proposed.
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

## ADR-006 - Proofs threaded off-trait in v1 (no trait signature change)

**Status:** Proposed.
**Context:** Only axeyum can produce proofs today; the `Solver` trait
returns `SolveResult` with no proof slot. Widening the trait for one
backend is premature.
**Decision:** Surface DRAT proofs via the concrete `AxeyumSolver` type
(a `check_with_proof` method or a stashed last-proof), not via the shared
`Solver` trait, in v1. Revisit a trait-level proof return only if a second
backend gains proofs.
**Consequences:** The reachability/verdict layer that wants "path
infeasible, DRAT-checked" evidence calls the concrete type; the generic
trait stays unchanged, so z3/pipe are unaffected.
**Alternatives rejected:** adding an `Option<Proof>` to `SolveResult` now
(pollutes every backend's return for one producer).

## ADR-007 - Placement: this plan lives in glaurung

**Status:** Accepted.
**Context:** The integration adds a backend *to glaurung*; axeyum is an
unchanged dependency. The agentic-security-bot repo (where the request
originated) explicitly excludes non-method engineering docs.
**Decision:** Keep the design record in `glaurung/docs/axeyum-integration/`.
**Consequences:** Co-located with the code that will implement it. The
Android-hunting side (agentic-security-bot) links to it as the binary
reachability engine, not owns it.
