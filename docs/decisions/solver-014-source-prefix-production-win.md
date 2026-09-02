# Solver ADR-014 — Accept the source-prefix production win, keep direct opt-in for widening

> **Kind:** decision · **Status:** maintained

**ADR status:** Accepted two-driver evidence; default admission deferred.
**Context:** ADR-013 restores sound direct serial reuse. Production admission
must compare it to the current serial-snapshot default, while a separate
exclusive-direct control isolates sibling topology. New external evidence also
adds much larger `tcpip`/`dxgkrnl` streams that are correctness-clean once but
not yet variance/RSS-gated.
**Decision:** Accept the clean repeated SurfacePen/NETwtw10 production win and
commit its artifact. Keep `GLAURUNG_AXEYUM_DIRECT_DELTA` opt-in until the larger
drivers enter the same fail-closed repeated gate and the exclusive-control
environment drift is resolved. Treat zero-query `win32k`/`pciidex` runs as a
dispatch-recovery coverage question, not solver evidence.
**Evidence:** The source-prefix artifact executes 92,721 checks with exact work,
findings, traffic, replay, lifecycle, and 4 GiB identity. SurfacePen Axeyum
time/ratio/RSS improve 16.11%/17.39%/0.36% against serial snapshot; NETwtw10
improve 6.07%/6.61%/1.72%. Z3 drift is +1.55%/+0.58%, so every production alarm
passes. The artifact SHA-256 is
`ba006d2f8edfdf7754f09702ff172112c5ea3e1134669a7855f5a0a3343660cc`.

A fresh exclusive-direct control shows source-prefix time/RSS improvements of
23.17%/5.33% on SurfacePen and 4.40%/15.81% on NETwtw10, but SurfacePen Z3 drift
is +4.06%. That named comparator remains rejected; no alarm is waived.
**Consequences:** Source ancestry is proven sound and wins the actual current
production comparison, but the default remains unchanged. Add exact repeated
`tcpip`/`dxgkrnl` contracts next, then re-run admission. The comparator now
ignores absolute sample path only while retaining content hash, size, budget,
system, repetitions, work, findings, and every threshold.
**Alternatives rejected:** enabling after only two drivers would ignore the new
51k-query widening signal; counting zero-query drivers would inflate coverage;
waiving Z3 drift would make normalized comparisons non-causal; requiring equal
absolute paths would contradict the byte-identity contract and prevent clean
detached worktrees.

---

Part of the solver decision series; the index is
[`docs/decisions/README.md`](README.md). The subsystem these records
govern is described in
[`docs/architecture/solver-backends.md`](../architecture/solver-backends.md).
