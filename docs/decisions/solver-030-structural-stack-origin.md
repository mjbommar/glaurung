# Solver ADR-030 — Require structural stack origin before stack-overflow classification

> **Kind:** decision · **Status:** maintained

**ADR status:** Accepted.
**Context:** ADR-0245's preregistered Axeyum-side policy sweep failed closed at
maximum's positive-control validation. Both authorities and repetitions retained
all 14 expected rows but added `StackOverflow` at the arbitrary-pointer
`RtlCopyMemory` in `test_physical_memory.sys`. Source review proves
`TargetAddress` is loaded from METHOD_BUFFERED user content, not a local stack
object. The detector had separately concretized `dst` and `rsp` and interpreted
proximity within 64 KiB as semantic stack membership.
**Decision:** Require the destination and current stack or frame pointer to be
the same expression, require the destination DAG to contain the non-leaf stack
expression, or require both expressions to share at least one free symbol
before applying the existing bounded proximity check. Constants and free-symbol
leaves do not establish DAG ancestry on their own. Keep attacker-controlled
destinations classified by the independent arbitrary-read/write/null detectors.
Do not let any concretization policy manufacture a memory-region label from
unrelated scalar witnesses.
**Evidence:** The TDD regression constrains independent attacker `dst` and
internal `rsp` symbols to adjacent concrete values; it reproduces the false
stack sink before the change and emits none afterward. The existing positive
control now models `dst = rsp` structurally and continues to emit
`StackOverflow` for attacker-controlled length. A first `rsp`-only candidate
then failed the real source-backed control at the genuine `[rbp-0x70]` fixture.
A second candidate admitted `rbp` but still failed because the real executor
represents `rbp` and `rsp` as constant-base expression DAGs with no free
symbols; its simplified fresh-symbol unit fixture had hidden that distinction.
An environment-gated diagnostic trace exposed the real terms, was removed, and
the replacement TDD fixture reproduced `rbp = 0 - 8`, `rsp = rbp - 0x90`, and
`dst = rbp - 0x70`. That test failed before non-leaf DAG ancestry was admitted
and passes afterward, while the independent attacker-pointer regression stays
clean. The exact two-repetition maximum-policy control at `0581f57` then
restored all 14 expected high-confidence rows with precision and recall 1.0,
zero false negatives, zero unexpected rows, and exact Z3/Axeyum parity. The
final dual-backend library run passes 992/994 tests; the two remaining WinAPI
signature-render failures are outside the changed symbolic/IOCTL files and
reproduce on the untouched baseline.
**Consequences:** Policy selection remains a cheap A0 configuration surface,
but semantic detector facts must be model-robust. The failed v2 prefix remains
rejected, and the unobserved site-hash cells cannot be spliced onto it. The
source-backed maximum-policy repair gate is now accepted; preregister a new
five-policy sweep at the corrected revision and rerun every cell. Symbolic
memory is still gated on independently validated residual coverage.
**Alternatives rejected:** suppress the one address; downgrade every
stack-overflow row; accept 14/15 precision as policy diversity; require only an
untainted destination; or continue comparing independently chosen concrete
addresses without structural origin evidence.

---

Part of the solver decision series; the index is
[`docs/decisions/README.md`](README.md). The subsystem these records
govern is described in
[`docs/architecture/solver-backends.md`](../architecture/solver-backends.md).
