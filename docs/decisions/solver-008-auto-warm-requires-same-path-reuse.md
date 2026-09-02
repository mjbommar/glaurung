# Solver ADR-008 — Auto warm reuse requires observed same-path reuse

> **Kind:** decision · **Status:** maintained

**ADR status:** Accepted by the repeated gate; default wiring is the next bounded
change.
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

---

Part of the solver decision series; the index is
[`docs/decisions/README.md`](README.md). The subsystem these records
govern is described in
[`docs/architecture/solver-backends.md`](../architecture/solver-backends.md).
