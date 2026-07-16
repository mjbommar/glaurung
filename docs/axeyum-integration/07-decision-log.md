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

## ADR-008 - Auto warm reuse requires observed same-path reuse

**Status:** Accepted as an opt-in measurement candidate; default decision open.
**Context:** Fixed lineage reuse is faster than Z3 on every repeated held-out
stream, but eagerly retains a solver for paths that may never issue a second
query. GQ9 needs a production admission signal that is observable before paying
the retained arena/AIG/CNF/SAT-state cost.
**Decision:** `GLAURUNG_AXEYUM_WARM_REUSE=auto` solves a path's first query
one-shot while retaining only its numeric explorer-owned path ID. A second query
for the same still-live path promotes its current complete assertion snapshot to
the existing bounded 9-path/512-assertion lineage adapter; later queries reuse
deltas. Terminal/restarted paths erase both probe and solver state. The default
stays off, and explicit `lineage` remains the fixed control.
**Consequences:** Single-check paths cost one set entry rather than a solver,
while repeated paths sacrifice their first reuse opportunity. Separate probe and
activation counters make the tradeoff measurable. Promotion still performs
original-term model replay inside Axeyum; path/assertion caps still fall back
one-shot. Accept or reject only after fixed-work SurfacePen and NETwtw10
comparison against off and lineage.
**Alternatives rejected:** formula-size thresholds repeat GQ4's unmeasured-cost
mistake; eager first-check retention cannot distinguish singletons; sharing a
mutable solver across siblings violates the accepted lineage ownership model.

**Initial real evidence (2026-07-16):** One same-binary SurfacePen triplet keeps
all 2,551 checks/findings identical. Off is 1.995 seconds Axeyum / 64,228 KiB;
auto is 1.154 seconds / 65,136 KiB with 358 probes and 191 activations; fixed
lineage is 1.062 seconds / 82,480 KiB. One fixed-budget NETwtw10 auto process
keeps all 28,356 checks/findings identical, partitions them exactly into 17,669
warm checks plus 10,687 probes, and records 4,099 activations: 19.595 seconds /
216,016 KiB versus the clean fixed-lineage baseline's 18.751 seconds / 257,632
KiB. Auto trades about 4.5--8.7% Axeyum time for 16--21% lower RSS than lineage
while preserving much of the cold-to-warm gain. Repeat and automate this policy
before any default decision.

**Repeated gate:** The clean three-process-per-driver artifact at Glaurung
`5c4ec0f` and Axeyum `0b77ccff` repeats every exact counter and all 92,721
agreements. Auto measures 1.141 seconds / 65,404 KiB on SurfacePen and 19.554
seconds / 216,580 KiB on NETwtw10. Against the committed lineage baseline,
Axeyum time regresses 7.37%/4.28% while median RSS improves 20.66%/15.93%.
Both time changes exceed ADR-0180's 3% alarm; Z3 also drifts -2.21%/+2.63%, so
cross-run ratio changes are environment-flagged. Keep auto as an explicit
memory-optimized option and retain fixed lineage as the faster opt-in policy;
do not make auto the production default.
