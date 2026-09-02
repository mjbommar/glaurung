# Solver ADR-031 — Add a pinned in-process Bitwuzla neutral measurement cell

> **Kind:** decision · **Status:** maintained

**ADR status:** Implemented; performance measurement pending preregistration.
**Context:** ADR-023 removed the fresh-Z3 versus retained-Axeyum topology
confound, but both measured implementations remain project participants. The
existing cvc5 neutral controls are external textual protocols and cannot test
whether the observed warm regime map survives a topology-equivalent neutral
in-process solver. Axeyum PLAN item 2 therefore requires Bitwuzla in both cold
and retained modes without changing Glaurung's authoritative solver.
**Decision:** Add benchmark-only `solver-bitwuzla` using the official Bitwuzla
0.9.1 C API. Reuse one thread-confined term manager as the peer of Z3's reused
context; create a fresh configured solver for every cold check; and retain one
push/pop solver per exact explorer owner for warm checks. Share the source
prefix, serial lease, one-scope-per-assertion topology, temporary assumptions,
250 ms default safety cap, model production, and full-width model lifting with
the existing cells. Keep cold Z3 authoritative. Extend the additive ordered
measurement contract from v2 to v3 with two Bitwuzla timing/outcome cells and a
closed warm execution class, and cyclically rotate all six cells. Require an
explicit library directory and reject a linked runtime version other than
0.9.1. Never include Bitwuzla in normal backend selection.
**Evidence:** Tests bind and read the real library version, lift a constrained
128-bit model, exercise every Glaurung QF_BV expression variant, and prove
incremental push/pop plus temporary-assumption restoration. A direct-lineage
test switches between equal-depth sibling pools and proves rewind by source
ancestry. The three-backend integration test executes all six cells on the same
delta and observes six SAT outcomes. A v3 trace fixture passes the independent
Python validator, while the legacy four-cell v2 fixture remains accepted. The
ordinary build passes without Bitwuzla environment configuration, while an
explicit `solver-bitwuzla` build without its pinned library directory fails
closed. The all-three-backend library run passes 1,030/1,032 tests; its two
remaining WinAPI signature-render failures are the same untouched-baseline
failures already recorded by ADR-030.
**Consequences:** The mechanism is ready to be frozen and preregistered, but it
contains no publishable timing result yet. The eventual analyzer must require
fixed-work identity, all-cell decision parity, exact created/retained
partitions, N>=5 processes, and per-occurrence paired statistics. Bitwuzla's
C/C++ dependency remains isolated from Axeyum's pure-Rust/deployability claim
and from Glaurung's default build.
**Alternatives rejected:** use the version-mismatched third-party
`bitwuzla-sys` 0.8 wrapper; treat external cvc5 reset/retained text protocols as
an in-process cell; make Bitwuzla authoritative; reuse one solver while calling
the cell cold; compare only aggregate process times; or claim a result before a
zero-row preregistration.

---

Part of the solver decision series; the index is
[`docs/decisions/README.md`](README.md). The subsystem these records
govern is described in
[`docs/architecture/solver-backends.md`](../architecture/solver-backends.md).
