# Solver ADR-011 — First-class direct-delta solver session

> **Kind:** decision · **Status:** maintained

**ADR status:** Accepted as the P5 contract plus opt-in explorer-wiring tranche;
production default deferred by ADR-012.
**Context:** The accepted warm lineage adapter proves retained Axeyum state is
the right performance lever, but Glaurung's only framework trait still accepts
`check(pool, complete_snapshot)`. The adapter must retranslate every root and
reconstruct the longest common prefix before it can issue Axeyum push/pop/assert
operations. Axeyum ADR-0201 now exposes an object-safe retained session trait,
but Glaurung still needs an IR-level lifecycle contract.
**Decision:** Add a separate object-safe `IncrementalSolver` trait with
`assert`, `push`, `pop`, `scope_depth`, `check`, and `check_assuming`. Implement
it first as `IncrementalAxeyumSolver`. Each assert translates only the new
Glaurung root, then delegates to Axeyum's retained trait. The session retains
its arena/AIG/CNF/SAT state and keeps symbol mappings in matching frames so
popped scopes and temporary assumptions cannot leak values into later models.
The existing one-shot `Solver`, snapshot adapter, adaptive default, and every
off/fixed/serial control remain unchanged.
**Evidence:** The complete 39-test Axeyum-backend group passes under the 4 GiB
serialized build. A new trait-object test drives a base assertion, scoped SAT
branch, pop underflow, contradictory one-shot assumption, and a subsequent SAT
check proving non-persistence; the scoped SAT model maps back to the exact
Glaurung symbol value. Two additional lineage-transition tests prove that a
retained owner translates only suffix roots, switches siblings by absolute
prefix depth, treats probes as ephemeral assumptions, and fails closed on an
impossible prefix by dropping state and fully rematerializing on the next call.
The explorer-wiring tranche expands that group to 41/41 and adds a deterministic
adapter test covering full materialization, suffix extension, prefix pop,
ephemeral contradictory assumptions, synchronization acknowledgement, and
invalid-partition teardown. Both warm explorer ownership tests pass: forked
owners remain distinct while inheriting only the confirmed depth, and restart
resets ownership and depth.
Warm-profile v7 then makes the entry contract observable rather than
overloading snapshot counters: `entry_mode` and exact persistent/temporary
query, translation, and root-encoding partitions are mandatory. A four-check
direct producer smoke (three SAT, one UNSAT) and a six-check snapshot smoke
both validate at 100% decided through Axeyum's strict v7 summarizer; the direct
summary records two persistent roots and one temporary root translated/encoded
across the exact extension/pop/assumption/reuse sequence.
The first real SurfacePen attempt deliberately exercised direct deltas with the
snapshot-only serial sibling lease and failed the correctness gate: 497/2,551
same-stream verdicts disagreed with Z3. Root cause was exact, not solver
unsoundness: sibling states inherited equal retain depths but had opposite last
branch assertions, so depth-only retention kept the wrong sibling root. Direct
mode now forces serial leasing off and falls back to exclusive LIFO owner
transfer plus distinct sibling sessions. The identical stream then agrees
2,551/2,551 with zero unknowns or replay failures. A pure policy test prevents
the incompatible combination from reappearing.
**Consequences:** Glaurung now drives the real P5 session from explicit path
deltas behind `GLAURUNG_AXEYUM_DIRECT_DELTA=1`. The full query remains intact
for the Z3 authority, ordered capture, and every one-shot fallback. The
explorer advances its prefix marker only on an explicit backend
acknowledgement, so admission fallback, a lost owner, or an operational error
cannot cause a naked suffix to be asserted. The route is not a production
default or a performance claim. Its causal comparison is exclusive-transfer
snapshot versus direct delta; production admission must additionally beat the
current serial-snapshot policy or add a sound source-identity/COW sibling-prefix
contract. Repeated ordered correctness/time/RSS gates remain mandatory.
**Alternatives rejected:** adding default incremental methods to `Solver` would
make one-shot emulation indistinguishable from retained state; storing one
trait object inside cloned `State` would imply illegal mutable-session cloning;
exposing configured preprocessing would hide a measured cold-path loss behind
the general contract.

---

Part of the solver decision series; the index is
[`docs/decisions/README.md`](README.md). The subsystem these records
govern is described in
[`docs/architecture/solver-backends.md`](../architecture/solver-backends.md).
