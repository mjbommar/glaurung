# Solver ADR-015 — Exact shadow unknown-split corpus

> **Kind:** decision · **Status:** maintained

**ADR status:** Accepted diagnostic infrastructure; corpus capture pending.
**Context:** The proposed `tcpip` widening row was measured with a 60-second
per-function ceiling. Raising that ceiling to the lineage gate's 600 seconds
changes both the query set and the validity result: 70,639 queries contain 973
one-backend-only decisions. Zero SAT/UNSAT disagreement does not prove parity
when one solver returns `Unknown` or errors.
**Decision:** Add `GLAURUNG_DUMP_SHADOW_SPLITS` as a combined-shadow-only,
explicit diagnostic. Capture exactly the queries where one backend decides
SAT/UNSAT and the other is `Unknown`/`Error`. Publish content-addressed SMT-LIB
bytes atomically and append only stable backend result classes to
`shadow-splits.tsv`. Never include error strings in identity, count both-
unknown rows as splits, or tax ordinary solving/capture.
**Evidence:** The full source-prefix `tcpip` run has 70,639 same-stream queries,
zero SAT/UNSAT disagreements, 43 Z3 non-decisions, 936 Axeyum non-decisions,
973 unknown splits, 925 warm resets, 480 assertion-cap fallbacks, 1.7x speedup,
and 440,384 KiB RSS. Two focused tests prove the exact one-decided predicate,
stable result classes, atomic exact-byte publication, and TSV row shape under
combined features.
**Consequences:** `tcpip` is not yet a green DriverSpec. Rebuild the release
binary, capture the 60-second split tier, and ingest the formulas into Axeyum's
real-query diagnostic lane. Attribute timeout versus translation/error versus
resource fallback before choosing solver or client work. The larger 600-second
corpus may follow only if its cost is justified.
**Alternatives rejected:** counting unknowns as agreement hides missing
functionality; capturing every query duplicates GQ1 and adds large diagnostic
overhead; storing only hashes is not reproducible; storing error text makes
identity unstable and may expose incidental paths/details.

---

Part of the solver decision series; the index is
[`docs/decisions/README.md`](README.md). The subsystem these records
govern is described in
[`docs/architecture/solver-backends.md`](../architecture/solver-backends.md).
