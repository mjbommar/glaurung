# Solver ADR-009 — Assertion exports preserve arbitrary-width truthiness

> **Kind:** decision · **Status:** maintained

**ADR status:** Accepted.
**Context:** Native Z3 and Axeyum deliberately treat every `Assert` as
bit-vector truthiness at the expression's actual width. Concretization can
therefore assert a wide value directly. The shared SMT-LIB renderer and ordered
trace instead compared every assertion with a BV1 literal, and the trace
rejected non-BV1 roots. A real SurfacePen trace exposed the mismatch at event
53 with a 64-bit assertion; this is also the likely source of the capture's
2,225 previously excluded ill-sorted scripts.
**Decision:** Define the producer contract once: expected-true renders
`distinct(term, 0@width)` and expected-false renders `term = 0@width`.
`pipe::build_script`, query dumps, and ordered assertion artifacts share that
renderer. Trace assertions record a positive `assertion_width`; the independent
validator checks it. Native and text bridge tests cover both polarities at
width 64 against zero.
**Consequences:** Text, trace, Z3, and Axeyum now agree without weakening
Axeyum's strict sort checking. Existing query hashes and corpus membership are
not stable across this producer correction and must be regenerated before the
next GQ1/GQ10 baseline. Warm lineage verdict/work counts are expected to remain
semantic controls, but that expectation is not a substitute for rerunning the
exact gate.
**Alternatives rejected:** restricting `Assert` to BV1 would break existing
native concretization behavior; zero-extending a BV1 literal would preserve
the ill-specified equality-to-one semantics for wide values; teaching the
consumer to accept ill-sorted text would conceal a producer defect.

---

Part of the solver decision series; the index is
[`docs/decisions/README.md`](README.md). The subsystem these records
govern is described in
[`docs/architecture/solver-backends.md`](../architecture/solver-backends.md).
