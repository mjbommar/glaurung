# Solver ADR-017 — Opt-in synchronized-warm timeout cold retry

> **Kind:** decision · **Status:** maintained

**ADR status:** Deferred; explicit diagnostic remains off by default.
**Context:** ADR-016 removes every widened-driver adapter error. The nine
distinct tcpip formulas where Z3 decides and warm Axeyum does not are all
decided correctly by cold Axeyum under a diagnostic cap. At the production
250 ms cap, cold Axeyum decides 5/9 and explicitly times out on four. A bounded
fresh retry can recover cases where retained SAT state is less favorable, but
it may spend another full per-check budget and must not silently become the
default.
**Decision:** Add `GLAURUNG_AXEYUM_WARM_TIMEOUT_COLD_RETRY=1` as an opt-in
direct-lineage policy. Retry only when the retained direct session returned
`Unknown` and remained synchronized with the complete assertion snapshot. Use
a fresh ordinary Axeyum solver under the same 250 ms configuration. Return a
recovered SAT/UNSAT result; otherwise preserve the original `Unknown`, including
when the retry errors. Never retry existing one-shot resource fallbacks,
unsynchronized/error sessions, or decided results. Export process counters for
retries, recoveries, repeated unknowns, and hidden retry errors.
**Acceptance gate:** On the exact post-ADR-016 tcpip stream, require zero
SAT/UNSAT disagreements, replay failures, adapter resets, or retry errors;
`retries = recoveries + unknowns + errors`; Axeyum nondecisions must fall; and
the same-stream time/RSS cost must be reported before any default proposal.
Repeat dxgkrnl to prove the no-timeout case is a policy no-op.
**Evidence:** The single-process tcpip candidate executes 71,909 queries with
zero SAT/UNSAT disagreements or retry errors. Its exact counter partition is
15 retries = 4 recovered decisions + 11 repeated unknowns + 0 errors. Axeyum
time rises 128,281.6→131,335.4 ms (+2.38%), but RSS rises
447,888→494,728 KiB (+10.46%), failing the 5% production alarm; 11 Axeyum
nondecisions remain. Query-count drift also prevents treating this as a causal
performance artifact. The candidate therefore fails admission even before
repetition. The dxgkrnl control executes the exact same 17,712 queries and warm
traffic, performs zero retries, keeps zero Axeyum nondecisions/disagreements,
and changes Axeyum time/RSS only 9,190.0→9,220.9 ms / 341,732→341,680 KiB.
**Consequences:** This is a downstream completeness policy, not an Axeyum
solver verdict cache or a relaxation of `Unknown`. It remains off by default.
Profile-v7 records the retained attempt rather than the external retry, so use
the explicit footer counters and unprofiled same-stream timing for this first
candidate; a profile schema revision is required before profiled admission.
Do not repeat this whole-snapshot retry without a topology that avoids its
memory spike or a stricter admission predictor for recoverable formulas.
**Alternatives rejected:** raising every Axeyum timeout changes the common-case
budget; retrying every one-shot timeout simply repeats identical work; using Z3
as an implicit fallback expands the native dependency contract; treating
timeouts as agreement hides incomplete exploration.

---

Part of the solver decision series; the index is
[`docs/decisions/README.md`](README.md). The subsystem these records
govern is described in
[`docs/architecture/solver-backends.md`](../architecture/solver-backends.md).
