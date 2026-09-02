# Solver ADR-007 — Placement: this plan lives in glaurung

> **Kind:** decision · **Status:** maintained

**ADR status:** Accepted.
**Context:** The integration adds a backend *to glaurung*; axeyum is an
unchanged dependency. The agentic-security-bot repo (where the request
originated) explicitly excludes non-method engineering docs.
**Decision:** Keep the design record in `glaurung/docs/history/axeyum-integration-2026-07/`.
**Consequences:** Co-located with the code that will implement it. The
Android-hunting side (agentic-security-bot) links to it as the binary
reachability engine, not owns it.

---

Part of the solver decision series; the index is
[`docs/decisions/README.md`](README.md). The subsystem these records
govern is described in
[`docs/architecture/solver-backends.md`](../architecture/solver-backends.md).
