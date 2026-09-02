# Solver ADR-023 — Add a topology-equivalent four-cell solver control

> **Kind:** decision · **Status:** maintained

**ADR status:** Accepted.
**Context:** ADR-022 makes the existing cold-Z3/warm-Axeyum population
statistically auditable, but it does not remove the reviewer checklist's most
important baseline objection. A fresh Z3 solver and a retained Axeyum lineage
conflate solver choice with session reuse. Re-labeling the old shadow numbers
would preserve that confound.
**Decision:** Add the off-by-default `GLAURUNG_FAIR_SHADOW` diagnostic. For
every authoritative cold-Z3 query, time four independently named cells in a
deterministically rotating order: Z3 cold, Z3 persistent direct-lineage,
Axeyum cold, and Axeyum persistent direct-lineage. Both warm cells use the same
explorer owner, serial sibling lease, exact source-prefix LCP, one-scope-per-
root push/pop discipline, and temporary-assumption boundary. Z3 implements the
existing `IncrementalSolver` contract with a retained native context/solver;
Axeyum bypasses product admission policy only for this diagnostic and forces
the already checked direct-lineage topology. Cold Z3 remains authoritative, so
all four cells observe one query stream. Rotate cell order by ordered check
occurrence to reduce systematic cache/order bias. Publish the four timings,
outcomes, and both warm execution classes under the additive
`glaurung-ordered-check-measurement-v2` marker; preserve v1 fields as explicit
cold-Z3/warm-Axeyum aliases.
**Evidence:** Real Z3 incremental tests cover push/pop depth, persistent model
lifting, temporary assumptions, and post-assumption restoration. A lineage
test switches between equal-depth cloned sibling pools and proves rewind by
source identity rather than numeric expression ID, then proves a contradictory
temporary assumption does not persist. The ordered-trace validator requires
all four v2 cells, checks their total-time bound, validates closed execution
vocabularies, and checks the legacy aliases. A real DptfDevGen smoke published
227 checks under v2; all four cells decided identically, both warm populations
were 7 created plus 220 retained, no fallback occurred, and the independent
trace validator accepted the artifact. The clean detached `4ae96cf` exercise
then runs five fresh processes with a predeclared 60-second solver bound. Every
run preserves 561 checks; all four cells decide every occurrence; both warm
populations are 7 created plus 554 retained; and no fallback, operational
result, disagreement, or replay failure occurs. Paired geomeans are 0.9661x
[0.8709, 1.0706] cold Z3/Axeyum, 0.7875x [0.6893, 0.8977] warm Z3/Axeyum,
8.9752x [8.5511, 9.4112] Z3 cold/warm, and 7.3157x [6.4477, 8.2741] Axeyum
cold/warm; every per-run CV is below 1.67%.
**Consequences:** The old ADR-022 evidence remains a mechanism/control result,
not a paper speedup. Publication comparisons can now report cold-vs-cold,
warm-vs-warm, and each backend's incremental benefit from the same fixed-work
traces. Four checks consume more of any wall/solver budget than two; production
runs must predeclare a bound large enough to preserve fixed work. This control
does not admit Axeyum direct delta as a product default. A neutral third-party
solver, timeout-sensitive driver, and authoritative finding parity remain open
ADR-0213 gates. The fair warm result favors Z3 on this driver, so the old
cold-Z3/warm-Axeyum headline must be retired rather than presented beside it.
**Alternatives rejected:** compare warm Axeyum only with fresh Z3; infer a warm
Z3 result from cold timing; reuse expression IDs across cloned pools as
lineage identity; let one backend use snapshots while the other consumes
deltas; run the cells in a fixed order; or replace v1 semantics in place.

---

Part of the solver decision series; the index is
[`docs/decisions/README.md`](README.md). The subsystem these records
govern is described in
[`docs/architecture/solver-backends.md`](../architecture/solver-backends.md).
