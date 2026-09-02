# Solver ADR-012 — Keep first-class direct deltas opt-in after the dual-control gate

> **Kind:** decision · **Status:** maintained

**ADR status:** Accepted decision to defer production admission.
**Context:** ADR-011's sound exclusive-transfer direct route removes whole-
snapshot translation and prefix reconstruction, but it also gives up ADR-0199's
serial sibling LCP sharing. A fair decision therefore needs two controls: the
same exclusive-transfer topology to measure entry overhead, and the current
serial-snapshot production policy to measure the replacement users would
actually receive.
**Decision:** Keep `GLAURUNG_AXEYUM_DIRECT_DELTA` strictly opt-in and preserve
serial snapshot as the production default. Accept the first-class contract,
producer, validator, and causal win; reject default admission until direct
sessions gain sound source-identity/COW sibling-prefix sharing or another
bounded topology that clears time and RSS alarms.
**Evidence:** Three clean processes per driver and policy execute 92,721 checks
per artifact with 100% Z3 agreement, zero unknown splits/replay failures,
identical finding hashes, exact traffic, terminal zero cache/session gauges,
and the 4 GiB child limit.

Against topology-equivalent exclusive-transfer snapshot, direct improves
SurfacePen Axeyum time 438.600→390.433 ms (-10.98%), ratio 11.61%, and RSS
0.05%; NETwtw10 improves time 11.148→10.582 s (-5.08%) and ratio 4.84%, with
RSS +1.21%. Z3 drift is +0.71%/-0.25%; every alarm passes.

Against same-current serial snapshot, direct regresses SurfacePen time
362.067→390.433 ms (+7.83%) and ratio 9.54%, while RSS rises 4.88%. NETwtw10
time improves 10.868→10.582 s (-2.64%) and ratio 3.78%, but RSS rises
224,860→262,484 KiB (+16.73%). The production comparator correctly rejects
three alarms. The committed candidate, transfer baseline, and serial baseline
SHA-256 values are respectively
`798c5dd2a6426592c84f255844b1cd7ceaf1d7fc488d3ff18c26d8ee1c832ceb`,
`b7585adf8d4caf62dd2989ac352018bcf64bbf145a7a63affc4bdd9293b55713`, and
`c9502152efa155a8d3f32c8a947ce7e75b45c2538b37d01a4bd95c6c8243ef47`.
**Consequences:** Direct deltas remain an executable causal control and the
right substrate for future P5 work, but no user silently loses serial sharing.
The next direct design must carry prefix identity, not depth alone, preserve
exclusive mutable ownership, and re-run both comparisons. Cold GQ5 and the
accepted serial-snapshot path remain unchanged.
**Alternatives rejected:** enabling direct because it beats equivalent
topology ignores the actual default; retaining serial leases by depth repeats
the measured wrong-verdict bug; accepting NETwtw10 time while waiving its RSS
alarm violates the established production contract.

---

Part of the solver decision series; the index is
[`docs/decisions/README.md`](README.md). The subsystem these records
govern is described in
[`docs/architecture/solver-backends.md`](../architecture/solver-backends.md).
