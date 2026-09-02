# Solver ADR-021 — Defer wider direct-delta default after the dxgkrnl no-op gate

> **Kind:** decision · **Status:** maintained

**ADR status:** Deferred.
**Context:** ADR-020 admits bounded continuation only after direct delta is
separately selected. Wider admission needs a no-timeout driver where the enabled
continuation policy is observably inert, exact work and outcomes remain fixed,
and the existing time/RSS/variance alarms still pass.
**Decision:** Keep `GLAURUNG_AXEYUM_DIRECT_DELTA` opt-in. Extend Axeyum's native
comparison tool with a `noop` expectation: the candidate must perform zero
continuations and recoveries, while actual outcomes and complete replay-cache
behavior match within and across policies. Preserve every existing identity,
correctness, terminal, time, RSS, and CV check. Classify `win32k.sys` outside
the current IOCTL frontend; its system-service/callout roots require a separate
sound frontend rather than fabricated IRP dispatch roots.
**Evidence:** Clean Glaurung `9ace064` publishes a complete real
`dxgkrnl.sys` trace with 85,449 events, 4,258 paths, 13,577 unique queries,
3,005 assertions, 17,400 checks, 8,816 model reads, and 312 stable findings.
All 17,400 shadow checks have zero decided disagreement, with four honest Z3
`Unknown`/Axeyum-decided splits; independent Axeyum `1cc19181` replay validates
every query, occurrence, and model read with zero failure. Three ordinary-core
control/candidate pairs preserve exact work, verdicts, cache traffic, owner
lifecycle, and zero continuation traffic. The standard comparison rejects
control/candidate Axeyum-time CV of 14.430%/8.306%, above 3%. A relaxed 20%
comparison is diagnostic only. Slower-core calibration steadies time but moves
one or two control queries across the 250 ms deadline while candidates decide
all four; the no-op gate correctly rejects that semantic/cache drift.
**Consequences:** `dxgkrnl` is green functionality evidence, not admission or a
causal performance win. Repeat the identical, predeclared comparison in a
quieter/exclusive environment or add another valid no-timeout IOCTL driver.
Keep bounded continuation's accepted default inside selected direct sessions,
and keep direct delta itself opt-in.
**Alternatives rejected:** relaxing CV after seeing the samples, selecting only
stable-looking runs, accepting slower-core outcome drift, counting zero-query
`win32k` as solver success, or inventing IRP roots for a different driver
architecture.

---

Part of the solver decision series; the index is
[`docs/decisions/README.md`](README.md). The subsystem these records
govern is described in
[`docs/architecture/solver-backends.md`](../architecture/solver-backends.md).
