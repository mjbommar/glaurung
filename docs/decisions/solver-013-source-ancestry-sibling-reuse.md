# Solver ADR-013 — Exact source ancestry for direct serial sibling reuse

> **Kind:** decision · **Status:** maintained

**ADR status:** Accepted as opt-in functionality; production admission pending.
**Context:** ADR-012 identifies serial sibling sharing as the missing direct-
entry topology, but the first attempt proved that retained depth and cloned-
pool `ExprId` values are not source identity. Cloning mutable Axeyum/SAT state
would add a new solver contract and multiply memory. Re-translating complete
snapshots would erase the direct-entry win.
**Decision:** Represent each persistent assertion append as an immutable node
whose parent is the exact prior source prefix. Explorer forks clone the node's
`Arc` in O(1); divergent appends create distinct nodes even when cloned pools
assign the same numeric `ExprId`. A worker-local direct session retains its
active ancestry. Before every check it computes the exact common ancestor by
pointer identity, pops to that depth, and translates only the target suffix.
The caller's confirmed depth remains telemetry/admission input, never identity.
One mutable solver is serially leased; no solver or SAT state is cloned or used
concurrently. Depth/ancestry mismatches and operational errors fail closed.
**Evidence:** The RED test first reproduced the stale equal-depth behavior at
the adapter boundary. The green test starts with source-related siblings whose
second roots require `x=5` and `x=7`, deliberately supplies stale retain depth
two for the right sibling, and proves the session rewinds to the one-root
ancestor, pops once, adds the right root, and returns model `x=7`. All 42
Axeyum-backend tests pass. All 12 explorer tests pass, including a cloned-pool
case where equal numeric expression IDs still produce distinct sibling source
nodes with exactly one shared ancestor. Builds are serialized under 4 GiB.
**Consequences:** Direct mode may safely use the established serial owner lease
again, but remains behind `GLAURUNG_AXEYUM_DIRECT_DELTA=1`. The gate must learn
the direct+serial policy, calibrate its exact traffic from real drivers, and
repeat the ADR-012 production comparison before any default change. Ancestry
nodes are reclaimed by `Arc` lifecycle when no state/session retains them.
**Alternatives rejected:** depth-only reuse is unsound by measurement; hashing
source expressions would make collision handling part of the trust boundary;
numeric `ExprId` equality aliases across independently growing cloned pools;
cloning mutable solver state violates exclusive ownership and worsens RSS;
complete-snapshot LCP reconstructs the work direct entry is intended to remove.

The subsequent gate calibration adds explicit `source-prefix-v1` policy
identity and exact direct+serial traffic for both held-out drivers. One clean-
behavior process each remains 100% agreed with zero unknown/replay failures:
SurfacePen measures 298.6 ms Axeyum / 4,490.9 ms Z3 at 74,384 KiB RSS;
NETwtw10 measures 10.383 s / 52.531 s at 224,712 KiB. These are plumbing and
traffic evidence, not acceptance; three clean processes and both named
comparisons remain mandatory.

---

Part of the solver decision series; the index is
[`docs/decisions/README.md`](README.md). The subsystem these records
govern is described in
[`docs/architecture/solver-backends.md`](../architecture/solver-backends.md).
