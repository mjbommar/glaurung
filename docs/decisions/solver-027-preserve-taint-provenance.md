# Solver ADR-027 — Preserve taint provenance before scoring policy coverage

> **Kind:** decision · **Status:** maintained

**ADR status:** Accepted.
**Context:** The first-15 tcpip AnyModel authority control has two stable Z3-only
double-fetch rows, and the four-schedule experiments used raw sink-set growth as
a bounded coverage observation. Exact trace inspection showed both rows occur
inside `TcpSendTrackerMarkTransmits` and depend only on generic `Arg0` ancestry
plus fresh values loaded through it. The explorer nevertheless relabeled every
uninitialized load through any tainted address as `*attacker`, bypassing the
normal high-confidence rejection of `ArgN` pointer noise.
**Decision:** Store every stable source label on a tainted symbol and propagate
an uninitialized load by prefixing each exact address source. Never replace
specific provenance with generic `*attacker`. Keep raw diagnostics available,
but score future concretization-policy coverage on a preregistered nonzero
labeled-positive population while reporting raw, confidence-gated, and
validated partitions separately.
**Evidence:** The red regression expected an uninitialized mixed-source load to
retain `*Arg0` and `*SystemBuffer` but observed only `*attacker`; it passes after
the correction, together with all 18 explorer tests. Both sole-authority
release builds complete two clean repetitions on the exact 15-of-338 tcpip
boundary. AnyModel remains deterministically 128 Z3 versus 126 Axeyum raw rows,
with the two differences relabeled `**Arg0`; least unsigned remains exactly
110/110. Normal confidence-gated execution reports zero findings for both
authorities, and every least-unsigned raw row carries only `Arg0`, `Arg1`, or a
dereference thereof. PDB symbols map the sites to the 2,104-byte internal
`TcpSendTrackerMarkTransmits` function; disassembly shows tree-node field reads
at offsets `-0xc` and `+0x8`.
**Consequences:** ADR-026's A0 abstraction remains accepted. The older raw
authority artifacts remain deterministic exploration evidence, but their
interpretation as a true-positive coverage frontier is superseded. Do not
select BoundarySet, DiverseEnum, or symbolic memory to recover these two rows
or maximize the arbitrary-model raw union. First select and label a corpus with
nonzero accepted findings; begin symbolic memory only if the corrected cheap
policy sweep leaves validated recall headroom.
**Alternatives rejected:** suppress the two addresses by special case; keep
`*attacker` and document the false positives; treat every `ArgN` dereference as
attacker-controlled; discard raw output; or call least-unsigned preservation
because its two authorities emit the same zero-confidence diagnostic set.

---

Part of the solver decision series; the index is
[`docs/decisions/README.md`](README.md). The subsystem these records
govern is described in
[`docs/architecture/solver-backends.md`](../architecture/solver-backends.md).
