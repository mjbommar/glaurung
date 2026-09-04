# Measuring decompiler quality

> **Kind:** design · **Status:** proposed

Glaurung is replacing Joern as the CFG provider for DecBench's structural
metric. `src/csource/joern/` reproduces 62,416 of 85,645 stored GED cells exactly
with zero coverage loss
([`../static-c-analysis/roadmap.md`](../static-c-analysis/roadmap.md) §5), so the
JVM is on its way out of the loop. **This directory asks what should replace the
number, not just the tool that computes it.**

The answer starts with an audit of the incumbent, and the audit is worse than
expected.

## The finding

> A "decompiler" that emits `int f(void) { return 0; }` for every function in the
> DecBench corpus scores **27.24% GED-perfect** — fifth of fifteen columns, above
> Ghidra, Binary Ninja, r2dec, Phoenix, dewolf and every LLM entry.

It is not a trick. DecBench's GED metric awards a perfect score when the
decompiled control-flow graph is isomorphic to the source one, and 24,243 of the
89,014 scorable functions have a control-flow graph that is a single node.
Between **62.5% and 100%** of every real column's GED score comes from that kind
of function, and no column earns more than 9.1% of its score on functions with
eight CFG nodes or more.

Two further measurements set the ceiling for any replacement:

* **58.61%** of corpus functions have a CFG-isomorphic twin in the same binary
  (`bash`'s `all_digits` and `strvec_search`, `base-passwd`'s `read_passwd` and
  `read_group`), so emitting the wrong function's body often scores perfect.
* Of **795** injected semantics-only defects — negated conditions, flipped
  comparisons, changed constants, substituted arithmetic — the metric detected
  **7**. No structural metric of any kind can do better on those, because the
  mutants have the same control-flow graph by construction.

Every number in this directory was computed offline from the materialized
DecBench tree. **No Joern process and no DecBench pipeline was run**, per
`CLAUDE.md`. The scripts and their raw output are in
[`evidence.md`](evidence.md).

## The documents

| document | what it holds |
|---|---|
| [what-ged-measures.md](what-ged-measures.md) | **the audit** — what `vj_ged` and the isomorphism check can and cannot see, the null decompiler, the wrong-body attack, the defect-injection ceiling, and the discovery that two different GED metrics are in use |
| [structural-metrics.md](structural-metrics.md) | six candidate structural replacements, argued down or up, ending in one recommendation: a normalized control-skeleton tree edit distance, graded and stratified |
| [semantic-metrics.md](semantic-metrics.md) | why the structural family is at its ceiling, and the two-tier semantic metric that gets past it — behavioural agreement as the headline, bounded equivalence as the arbiter |
| [calibration.md](calibration.md) | how a replacement earns the right to be quoted: the mutation harness with both its halves, the confusion table against the incumbent, the null baseline as a permanent gate, and which knobs are principled |
| [roadmap.md](roadmap.md) | **the plan** — six increments with gates and stop conditions, ordered by value per unit of work |
| [evidence.md](evidence.md) | the eight scratch scripts behind every number, verbatim, with their command lines and output |

## The three recommendations, in priority order

**1. Fix the aggregation before fixing the distance.** Stratify by function size
and publish the null baseline beside every score. Both are arithmetic over data
already published — no new metric, no new front end, no DecBench change — and
together they are a larger correction than any new distance would be.
[`structural-metrics.md`](structural-metrics.md) §1, [`roadmap.md`](roadmap.md) M0.

**2. Build the mutation harness before the metric.** It is the only offline
source of ground truth, it took under a minute to run in pilot form, and it is
what turns "this metric is better" into a number. It has two halves —
sensitivity to defects and *insensitivity to legitimate rewrites* — and the pilot
built only the first, so no specificity number appears anywhere in this
directory. [`calibration.md`](calibration.md) §2, [`roadmap.md`](roadmap.md) M1.

**3. Replace CFG isomorphism with a control-skeleton tree edit distance, and
accept that structural metrics stop there.** The tree metric is the only
structural candidate that splits the 24,243-function class every CFG metric
collapses, and the only one that sees structuring quality — a `while` loop and
its goto-ified equivalent have the same CFG, which is the project's own recorded
trap from the other direction. Past that, only semantics helps.
[`structural-metrics.md`](structural-metrics.md) §2.6,
[`semantic-metrics.md`](semantic-metrics.md).

## Two things worth knowing before reading further

**There are two GED metrics in circulation and we run the older one.** Upstream
`bd49c83` (2026-08-07) added an isomorphism fast path and a `max(1.0, raw)`
clamp and raised the node cap from 60 to 200. Our fork is at `efc5d5a`, on the
old side of that change, where a perfect score means only that two degree
multisets agree — and **94.41% of degree-preserving graph rewirings are awarded
`0.0` under that rule**. The published cells use the new semantics; the local
gate uses the old one. [`what-ged-measures.md`](what-ged-measures.md) §0.

**1-WL colour refinement is complete on this corpus.** It produced exactly the
same 8,034 isomorphism classes as VF2 over 89,014 functions. That is why this
directory uses a WL certificate as an exact isomorphism test, and it is also why
[`structural-metrics.md`](structural-metrics.md) §2.2 rejects graph kernels: a WL
kernel cannot distinguish anything here that the existing isomorphism check does
not already distinguish.

## Related

* [`../static-c-analysis/`](../static-c-analysis/README.md) — the C front end
  this depends on. [`joern-behavior.md`](../static-c-analysis/joern-behavior.md)
  §2 is the proof that `vj_ged` reads only degree sequences;
  [`roadmap.md`](../static-c-analysis/roadmap.md) §6–§7 are stages S4 and S5,
  which [`semantic-metrics.md`](semantic-metrics.md) is blocked on.
* [`../source-front-ends/`](../source-front-ends/README.md) — the substrate the
  tree metric would be built on.
* [`../../development/decompiler-testing.md`](../../development/decompiler-testing.md)
  — where the current metrics sit in the iteration loop.
* [`../../development/traps.md`](../../development/traps.md) — *"Execution
  differential is blind to structure"* and *"The differential endorses bad
  changes"* are the two incidents this directory generalizes.
