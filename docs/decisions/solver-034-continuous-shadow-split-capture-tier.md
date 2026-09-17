# Solver ADR-034 — A scheduled shadow-split capture tier, so the next divergence is seen the week it appears

> **Kind:** decision · **Status:** maintained

**ADR status:** Sizing measured 2026-09-17; the tier is being built on this
branch. Sections below the sizing table are filled in as the work lands.
**Context:** Improvement-list item 7
([`development/improvement-list-2026-09-16.md`](../development/improvement-list-2026-09-16.md)):
[`solver-032`](solver-032-axeyum-pin-bump-and-shadow-corpus-prune.md) pruned
the shadow-split corpus to 107 z3-valid scripts with pinned verdicts and made
`tools/axeyum/split_verdicts.py` the gate, but nothing *produces* new captures.
The July corpus sat for two months with 735 exporter-defect scripts counted as
solver misses because capture was a one-off command in a README. A divergence
between Axeyum and z3 on a real driver query — a new capability gap, or worse a
decided disagreement — is seen only when somebody re-runs that command.

## Sizing (2026-09-17, host s4, load ~1.7)

One combined-shadow capture (`--release --example ioctlance --features
solver-z3,solver-axeyum`, `GLAURUNG_FAIR_SHADOW=1`,
`GLAURUNG_DUMP_SHADOW_SPLITS`, `IOCTLANCE_SOLVE_SECS=60`,
`IOCTLANCE_DEADLINE_SECS=600`, `IOCTLANCE_SOLVE_BUDGET=20000`,
`IOCTLANCE_MAX_ANALYZED_FUNCTIONS=100000`, default 250 ms check timeout) over
`sqfs-intel-DptfDevGen.sys`, Glaurung `3b3f2b4b`, Axeyum pin `8df853252`:

| measure | value |
|---|---|
| wall time | 59.5 s (`/usr/bin/time`; `[symbolic] 59.45 s`, 7 of 12 reachable functions analyzed, `runs=8 completed=7`) |
| checks (`[shadow-diff] queries=`) | 1,388 (agree 1,388, disagree 0) |
| split occurrences (`unknown-split=`) | 33, all z3-decided / Axeyum-unknown |
| distinct split scripts published | 15 (`shadow-splits.tsv`, all `sat`/`unknown`) |
| malformed (`malformed.tsv`) | 0 |
| max RSS | 147 MiB |
| release build, incremental over the solver-033 target | 53 s |

The wall time is the per-function ceiling, not the driver: warm Axeyum at this
pin pushes the root dispatch function into the 60 s budget
([`solver-033`](solver-033-six-cell-rerun-at-the-2026-09-16-pin.md)), so a
capture costs roughly `ceiling × dispatch roots` per driver and is bounded by
`IOCTLANCE_DEADLINE_SECS`. Four July drivers at 60 s are therefore minutes, not
hours, and the tier is a **weekly scheduled** job with a manual entry point,
not a per-push gate.

---

Part of the solver decision series; the index is
[`docs/decisions/README.md`](README.md). The subsystem these records
govern is described in
[`docs/architecture/solver-backends.md`](../architecture/solver-backends.md).
