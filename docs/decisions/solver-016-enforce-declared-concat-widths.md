# Solver ADR-016 — Enforce declared concat operand widths at every solver boundary

> **Kind:** decision · **Status:** maintained

**ADR status:** Accepted correctness fix; repeated widened gate pending.
**Context:** Strict replay of the 60-second `tcpip` shadow-split corpus reduces
733 distinct Axeyum errors to an exact malformed shape. A `setcc` result is a
one-bit expression stored into an eight-bit register slice; `Expr::Concat`
records that low half as eight bits, but the SMT renderer plus both native
solver adapters ignored `hi_w`/`lo_w`. They constructed a 57-bit term while
`ExprPool::width_of` and the concrete domain correctly treated the node as 64
bits. The next extract therefore failed in Axeyum as `extract [63:8] out of
range for width 57`. Z3's later coercion hid the malformed child and also
shifted the high half by one rather than eight bits, changing program meaning.
**Decision:** Keep strict Axeyum sorts. Coerce each concat child to its declared
half-width, by zero-extension or low-bit truncation, in the SMT-LIB renderer,
the Z3 adapter, and the Axeyum adapter before concatenation. This is the
existing `Domain::concat(hi, lo, hi_w, lo_w)` contract and matches the concrete
domain; it is not a solver-specific workaround. Generate Axeyum manifests from
the strict split-corpus index and retain the old bytes as the reproducer.
**Evidence:** The two smallest tcpip error representatives, one Z3-SAT and one
Z3-UNSAT, independently fail Axeyum SMT-LIB ingestion with the same 57-bit
out-of-range diagnostic. Focused renderer, Z3, and native Axeyum regressions
prove that a one-bit low child declared as eight bits becomes a 64-bit concat
with value `0x1201`, and the combined-feature tests pass under the 4 GiB cap.
The archived corpora contain 784 tcpip and four dxgkrnl distinct split formulas
with byte-owning Axeyum manifests.
The exact post-fix reruns then remove every adapter error and warm reset:
`tcpip` falls from 977 to 55 split occurrences (52 distinct: 43 decided only by
Axeyum, nine decided only by Z3) across 72,291 queries, while `dxgkrnl` falls
from six to three occurrences (two distinct, both decided by Axeyum) across
17,712 queries. SAT/UNSAT disagreements remain zero; Axeyum is 1.9x/2.7x faster
in these single processes.
Axeyum's independent cold manifest replay decides all nine Z3-decided residual
tcpip formulas under a 30-second diagnostic cap (1 SAT / 8 UNSAT, 9/9 expected,
no unsupported/errors). SAT search consumes 93.2% of their pipeline time and
total p50/max are 213.7/399.0 ms. Under the production-equivalent 250 ms cap,
5/9 decide and four return explicit `Unknown(Timeout)`, completing the
error-versus-timeout attribution.
**Consequences:** Every old capture containing this shape remains valuable as a
bug reproducer but is not valid post-fix performance evidence. Rebuild and
repeat tcpip/dxgkrnl before admitting either driver to the lineage gate; compare
findings because the old Z3 path used the wrong bit placement. Add no coercion
inside Axeyum IR and do not weaken its error messages.
**Alternatives rejected:** coercing only in the Axeyum adapter would leave Z3,
text capture, and concrete execution semantically inconsistent; teaching
Axeyum to accept mismatched concat sorts would hide a consumer soundness bug;
changing only `setcc` would leave every other declared-width concat exposed.

---

Part of the solver decision series; the index is
[`docs/decisions/README.md`](README.md). The subsystem these records
govern is described in
[`docs/architecture/solver-backends.md`](../architecture/solver-backends.md).
