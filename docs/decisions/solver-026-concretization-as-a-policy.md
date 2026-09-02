# Solver ADR-026 — Make concretization a first-class policy

> **Kind:** decision · **Status:** maintained

**ADR status:** Accepted.
**Context:** The accepted authority experiments show that arbitrary, least,
greatest, and two site-hash choices are settings of one model-value knob, not
separate solver algorithms. They were nevertheless implemented as an enum and
environment parser embedded in `explore.rs`, duplicating selection logic at
`concretize_addr` and `eval_concrete`. The publication plan requires a measured
policy sweep, while symbolic memory must remain a separate architecture item.
**Decision:** Extract a public, `Send + Sync` `ConcretizationPolicy` contract.
Give each request only a stable seam, semantic purpose, and instruction address.
Keep checked solving, model evaluation, address binding, and ordered tracing in
the explorer. Route both value-selection seams through injectable policy-aware
helpers. Make `GLAURUNG_CONCRETIZATION_POLICY` the preferred built-in selector,
retain `GLAURUNG_CANONICAL_MODEL_CHOICE` exactly for preregistered campaigns,
and reject simultaneous use. Preserve every existing policy ID and both legacy
AnyModel trace IDs. Represent `BoundarySet` and `Defer` in the contract, but
fail closed until A3 state forking and A2 symbolic memory actually implement
their distinct semantics.
**Evidence:** The TDD red gate failed on the absent policy types and resolver,
then six contract tests passed for the AnyModel default and trace IDs, every new
and legacy alias, precise invalid/conflicting config errors, complementary
site-hash decisions, and custom set/defer policy values. Seventeen focused
explorer tests pass, including explicit least/greatest injection at both seams,
path binding versus read-only evaluation, infeasible-path handling, unsupported
widths, and all prior extrema. On the exact tcpip 15-of-338 boundary, two clean
A0 Axeyum runs reproduce the three accepted pre-A0 runs: 126 findings, ordered
hash `a67d7bca28602ab20bbc46d9a5d42705463bd340067dc8e6ec660b35d58ba265`,
2,991 solves, and identical AnyModel counters. The expected two Z3-only rows
remain. A separate one-function gate proves preferred and legacy minimum config
produce identical output and work: 13 completed choices, 858 probes, 869 solves,
and zero failure partition.
**Consequences:** A0 is behavior-preserving enabling infrastructure. The next
coverage work is a preregistered sweep over policy configurations. A3 must add
bounded set forking before `BoundarySet` becomes production-selectable. A2 must
change the memory model and starts only if the cheap sweep leaves measured
coverage headroom. Existing experiment scripts can migrate to the preferred
variable without invalidating archived commands.
**Alternatives rejected:** keep adding one-off enum branches in the explorer;
rename the legacy variable without compatibility; collapse a boundary set to
its first value; treat deferred symbolic memory as another scalar policy;
change default traces while claiming byte-for-byte reproduction.

---

Part of the solver decision series; the index is
[`docs/decisions/README.md`](README.md). The subsystem these records
govern is described in
[`docs/architecture/solver-backends.md`](../architecture/solver-backends.md).
