# Solver ADR-024 — Preserve full-width values in the native Z3 adapter

> **Kind:** decision · **Status:** maintained

**ADR status:** Accepted.
**Context:** The benchmark review exposed a concrete correctness defect in the
consumer adapter: `Expr::Const` and model projection narrowed every value
through `u64`, even though Glaurung's IR supports 128-bit scalar bit-vectors.
Z3 accepted the well-sorted but truncated term, so differential agreement could
silently grade the wrong formula. The fair baseline must not retain that known
oracle defect.
**Decision:** Keep the IR strict and preserve its full scalar width. Construct
bit-vector numerals wider than 64 bits through Z3's decimal numeral API rather
than an integer cast. Lift evaluated models through an exact u128 parser for
Z3 hexadecimal, binary, and indexed decimal numeral forms. Retain the cheap
native `u64` route at widths up to 64 bits. Do not coerce, mask, or downgrade a
malformed value to make the native backend accept it.
**Evidence:** A real W128 regression constrains a symbol to a value with bit
100 and nonzero low bits, then requires the lifted Glaurung model to contain
the exact u128. It fails on the old adapter by returning only the low 64 bits
and passes after the change. The existing Z3, Axeyum, concat-width, direct-
delta, timeout, and ordered-trace suites remain green.
**Consequences:** Z3 can again serve as an adapter oracle for Glaurung's full
scalar width range, subject to the rest of the stated TCB. Historical
primitive results containing the truncation are stale and must be regenerated;
they are evidence that strict typing found a consumer bug, not evidence of a
Z3-core failure.
**Alternatives rejected:** scope all comparisons to at most 64 bits while
leaving the defect; truncate both backends for apparent parity; represent a
128-bit scalar as two unrelated symbols; or classify the wrong UNSAT as a Z3
solver bug.

---

Part of the solver decision series; the index is
[`docs/decisions/README.md`](README.md). The subsystem these records
govern is described in
[`docs/architecture/solver-backends.md`](../architecture/solver-backends.md).
