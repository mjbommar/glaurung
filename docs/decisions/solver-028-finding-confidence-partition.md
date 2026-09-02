# Solver ADR-028 — Emit an exhaustive finding-confidence partition

> **Kind:** decision · **Status:** maintained

**ADR status:** Accepted.
**Context:** ADR-027 requires policy experiments to report raw diagnostics and
confidence-gated findings separately. `IOCTLANCE_ALL=1` exposed raw rows, but
the producer emitted no row-level classification and its summary labeled the
raw count as high confidence. A downstream harness would otherwise have to
reimplement Glaurung's confidence policy or run separate processes whose
exploration could not be proven identical.
**Decision:** Add opt-in `IOCTLANCE_ANNOTATE_CONFIDENCE=1` output. Classify each
finding with the producer's existing `is_attacker_real` policy after sorting,
append `confidence=high|diagnostic` only at print time, and emit the exhaustive
versioned footer `glaurung-ioctlance-confidence-v1`. Keep every unannotated
legacy byte unchanged. Report actual high and diagnostic counts even when all
raw findings are displayed.
**Evidence:** The red tests first failed because nested `ArgN` output had no
machine-readable class. The accepted implementation proves nested generic
ancestry remains diagnostic and that both annotations can be stripped to the
exact historical finding bytes. Both focused tests pass. Two independently
built release binaries are then consumable by Axeyum's fail-closed v5 authority
harness, which validates the footer and the exhaustive row partition.
**Consequences:** One process now supplies raw, high-confidence, and diagnostic
sets over exactly the same exploration. Raw hashes remain comparable to prior
artifacts. A high-confidence acceptance run must reject a missing or malformed
partition; legacy raw-only consumers may continue without the opt-in variable.
Manual or independent validation remains a third population and is not
manufactured by this annotation.
**Alternatives rejected:** duplicate the filter in Axeyum; compare separate
normal and show-all processes; change default output bytes; infer confidence
from taint strings; or equate producer confidence with ground-truth validity.

---

Part of the solver decision series; the index is
[`docs/decisions/README.md`](README.md). The subsystem these records
govern is described in
[`docs/architecture/solver-backends.md`](../architecture/solver-backends.md).
