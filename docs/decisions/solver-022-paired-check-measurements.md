# Solver ADR-022 — Add publication-grade paired check measurements

> **Kind:** decision · **Status:** maintained

**ADR status:** Accepted.
**Context:** The pre-submission reviewer audit identifies ratio-of-sums,
single-run timing, mixed decided populations, and unnamed warm fallbacks as
critical blockers. Existing trace v1 timings cannot reconstruct all four
decided/nondecided buckets because they retain only the Z3-authoritative result,
and aggregate fallback counters cannot assign a particular latency to its
execution population.
**Decision:** Extend ordered trace v1 additively under the explicit
`glaurung-ordered-check-measurement-v1` marker. Record both backend result
classes beside their timings and a closed Axeyum execution-class vocabulary.
Keep the authoritative `outcome` field and all native replay fields unchanged.
Historical traces without the marker remain valid for their original replay
purpose but are ineligible for paired publication analysis. Use Axeyum's
fail-closed analyzer over at least five fixed-work repetitions; compare latency
only on occurrences both backends decide in every repetition, use per-
occurrence geomean ratios with deterministic bootstrap confidence intervals,
and report timeout splits and warm/fallback classes separately.
**Evidence:** Focused dual-backend ordered-trace tests publish and validate the
new marker and fields across SAT and UNSAT checks. A negative test recomputes
the event hash after changing an execution class and proves the semantic
validator still rejects it. Direct-delta tests distinguish newly created,
retained, and invalid sessions. The Axeyum analyzer has synthetic five-run
tests for the exact 2x geomean/CI, nondecision buckets, minimum repetitions,
fixed-work drift, execution-population drift, and operational errors.
**Consequences:** Existing engineering admission ratios keep their historical
meaning but are not paper speedups. The next real run must regenerate traces;
old dxgkrnl/tcpip traces cannot be retrofitted because their per-backend result
classes and per-check fallback reasons were never recorded. Warm Z3, neutral-
solver cells, timeout sweeps, and authoritative finding parity remain separate
ADR-0213 gates.
**Alternatives rejected:** infer Axeyum outcomes from timing or aggregate
unknown counters; infer fallback rows from end-of-run totals; silently
reinterpret historical v1; use all observations in the latency ratio even when
one backend did not decide; or publish a ratio of sums with a caveat.

---

Part of the solver decision series; the index is
[`docs/decisions/README.md`](README.md). The subsystem these records
govern is described in
[`docs/architecture/solver-backends.md`](../architecture/solver-backends.md).
