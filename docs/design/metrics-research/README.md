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

## The same weakness, in the second metric

The audit below covers `ged`. `type_match` was measured the same way on
2026-09-04 while porting it (`7a00d586`), against real DWARF from 321 functions
across 30 fixture binaries and scored by **the reference implementation
itself**:

| "backend" | mean | perfect functions |
|---|---:|---:|
| width-echo (`undefinedN` at the right slot) | 0.9051 | **236/321 = 73.5%** |
| everything typed `int` | 0.8110 | 193/321 = 60.1% |
| everything typed `undefined8` | 0.0582 | 12/321 = 3.7% |

**A backend that recovers no type at all -- only each slot's width -- is scored
perfect on 73.5% of functions by a metric named "Type Correctness."** The causes
are the same two this directory found in `ged`: the population is trivial (89.2%
of ground-truth variables are integer or bool scalars; pointers 9.9%, aggregates
1.0%) and the denominators are tiny (52% of functions have two or fewer
ground-truth variables).

One structural fact compounds it. `tp + fp + fn` is identically
`len(ground_truth_vars)` -- the reference indexes its `decided` array by
ground-truth variable -- so the score is **recall, not a Jaccard**, and
inventing variables is free unless the invention collides on ABI index, offset
or name. Verified over 10,272 differential cases, 10,272 of 10,272, and the
inventory row that said otherwise is corrected.

So the recommendation this directory makes for `ged` -- stratify, and publish a
null baseline beside every column -- applies unchanged to `type_match`, and
`tools/metric_stratify.py` is the shape the fix should take.

## What has been built from this

Recommendation 1 has landed. `tools/metric_stratify.py` (`db09aed9`) computes
the null baseline from whatever corpus it is pointed at rather than quoting the
27.24% figure, stratifies by CFG size, and reports
`skill = (perfect% - null%) / (100% - null%)`. Its full-corpus run is the
evidence for the sentence this directory exists to make sayable: **Ghidra
(25.52%) and Binary Ninja (20.58%) score below a `return 0;` stub (27.24%)**,
and claude-code and codex fall from first and second on DecBench's
own-denominator style to ninth and tenth when judged on the population everyone
else is judged on, having attempted 242 and 243 of 89,014 functions.

Recommendation 2 has landed. `tools/metric_mutation.py` (`a2d9e292`) implements
both halves -- 15 semantics-changing classes and 14 semantics-preserving ones,
the latter validated by compiling each rewrite and requiring byte-identical
output over 24 inputs. **GED measures 21.8% sensitivity and 95.3% specificity**
on published samples (20.5% / 99.2% on our own decompiled output). Two results
sharpen the audit above: across the ten classes that cannot change the CFG by
construction, GED detected **12 of 1,188** on sources and **0 of 2,817** on
decompiled output; and its false alarms are one front-end fact, not a spread --
every `and-to-nested-if` (44/44) and `demorgan` (21/21) false alarm is our C
front end collapsing a short-circuit condition into fewer blocks than explicit
branching.

Recommendation 3 has landed. `src/metrics/tree_distance.rs` (`eaa62fda`) is a
Zhang-Shasha edit distance over the control skeleton. It splits the class every
CFG metric collapses -- 34 distinct skeletons among the branchless functions
where GED has one, 92.28% of pairs at non-zero distance -- and takes the null
decompiler's false-perfect rate from **27.24% to 6.09%**. It sees
goto-ification, where the parity CFG is byte-identical and GED is correctly
0.0. Its documented weakness is the normalization rather than the distance:
`1 - TED/|source|` saturates past 2x expansion, so the raw distance must be
published beside it.

Two caveats travel with any number these produce. The tree metric cannot see
the six semantics-only defect classes at all -- asserted in a test, and a
ceiling that closes only with semantics, i.e. stages S4/S5. And **175 of 1,998
offered decompiler outputs (8.76%) hold no resolvable definition for our front
end, 144 of them `dewolf`** (85% of its offers), so a per-column mean is
meaningless without its unresolved count beside it.

## Start here

[`interpreting-results.md`](interpreting-results.md) is the practical summary:
the base-rate, guessing and degenerate-case traps that change how a DecBench
number should be read, each with its measurement and command, plus a checklist.
Read it before quoting any score from this benchmark.

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
