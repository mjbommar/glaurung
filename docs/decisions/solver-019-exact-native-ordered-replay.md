# Solver ADR-019 — Exact native ordered replay in the production topology

> **Kind:** decision · **Status:** maintained

**ADR status:** Accepted functionality boundary; repeated continuation evidence
pending.
**Context:** The public SMT-LIB ordered consumer fixes occurrence order and
query bytes, but its independent snapshot/lineage policies do not reproduce
Glaurung's source-prefix identity, direct-delta entry, adaptive capacity
fallbacks, or serial sibling leases. Live control/candidate exploration also
cannot hold work fixed because an authoritative Z3 timeout changes the
worklist. Native admission therefore needs a replay boundary that preserves
both exact work and the real production adapter.
**Decision:** Extend ordered trace v1 additively. Each unique assertion gets a
deterministic, topologically ordered native expression-DAG pack bound to its
existing SMT assertion hash. Every check records owner ID, requested retain
depth, persistent/temporary partition, exact source-prefix digest, and whether
the live direct session synchronized. Serial owner share/release events retain
their observation order. The `ordered_native_replay` executable reconstructs
one typed pool, shared immutable source-prefix nodes, and lease lifecycle, then
submits every occurrence through `solve_for_path_delta`. It rejects native/SMT
identity drift, opposite decided verdicts, synchronization drift, operational
resets, cache replay failures, or nonzero terminal owner/session gauges.
Control and one-continuation candidates run in fresh processes and bind the
same trace, finding hash, and independent SMT/model replay artifact.
**Acceptance gate:** The producer validator must accept the complete trace;
the independent Axeyum consumer must replay every query and model read; native
control/candidate repetitions must match event/check/assertion/owner traffic,
source synchronization, findings, and artifact hashes. Require zero opposite
decisions, solver errors, resets, cache replay failures, or terminal gauges,
then apply the existing 3% time, 5% RSS, and variance alarms. `Unknown` remains
a first-class result and is reported rather than scored as a win.
**Evidence:** Native-pack round-trip and malformed-topology tests cover shared
DAGs and all expression variants. Producer tests cover the full owner lease
lifecycle and independently reject a tampered pack. The replay executable
compiles with only `solver-axeyum`; the exact full-driver repetition remains
the next gate.
**Consequences:** The extra native files are restricted Glaurung-local replay
inputs, not a replacement for the public SMT-LIB evidence or a new Axeyum
product dependency. The timeout-continuation switch remains explicit/off until
the repeated native gate passes. A structurally valid trace alone cannot
enable it.
**Alternatives rejected:** reparsing SMT-LIB would bypass the native client
translation; another live pair cannot guarantee exact work; serializing pool
indices without a closed reachable DAG would make packs order- and
allocation-dependent; treating a fallback as synchronized would hide topology
drift.

---

Part of the solver decision series; the index is
[`docs/decisions/README.md`](README.md). The subsystem these records
govern is described in
[`docs/architecture/solver-backends.md`](../architecture/solver-backends.md).
