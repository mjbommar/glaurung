# Calibration, configurability and determinism

> **Kind:** design · **Status:** proposed

A new metric that is merely *different* from GED is worth nothing: it moves the
ranking and cannot say why. This document is how a replacement earns the right to
be quoted, and which of its knobs are allowed to exist.

## 1. The position

**A metric is defensible when its disagreements with the incumbent are each
explainable by a named defect class, and when it beats the incumbent on an
injected-defect experiment that was written before either metric was tuned.**

Not "when it correlates with human judgement" — we have no human labels, and a
correlation over fifty hand-ranked pairs cannot separate two candidate metrics.
Not "when it looks more principled". Mutation is the only lever available offline
that produces ground truth, and it produces a lot of it.

## 2. The mutation harness is the instrument, and it ships first

[`what-ged-measures.md`](what-ged-measures.md) §5 is a pilot of it: 300 published
sample functions, ten mutation classes, 1,289 applied mutants, run in well under
a minute. Productionize it as `tools/metric_mutants.py`, with a fixed seed, a
versioned mutation catalogue, and a JSON report. It has **two halves, and the
pilot only built one.**

### 2.1 Sensitivity — does the metric see a defect?

The pilot's ten classes, extended. Each mutant carries a ground-truth label
asserting that it changes behaviour, and the label has to be justified per class,
not assumed:

| class | changes behaviour? | pilot detection by GED |
|---|---|---|
| `negate-condition` | yes | 0 / 191 |
| `constant-bump` | yes on any live path | 0 / 174 |
| `equality-flip` | yes | 0 / 137 |
| `relational-flip` | yes | 1 / 122 |
| `arith-flip` | yes | 0 / 67 |
| `logic-flip` | yes | 6 / 104 |
| `null-body` | yes | 206 / 279 |
| `while->if` | yes | 38 / 56 |
| `drop-break` | yes | 42 / 48 |
| `else->if(0)` | yes | 85 / 111 |

Classes to add, each aimed at a defect a real decompiler actually commits:

> **Correction, measured 2026-09-04.** The first two entries below are listed
> here under sensitivity, whose contract is that each mutant carries a
> ground-truth label asserting it *changes* behaviour. `goto-ify` and
> `duplicate-tail` **preserve** behaviour, so they belong to the specificity
> half, and `tools/metric_mutation.py` implements them there. They turn out to
> be the two most discriminating classes in it: `goto-ify` is invisible to GED
> (13/14 quiet on samples, 30/30 on the tree), and `duplicate-tail` is its
> largest genuine false-alarm class at 60-64%. The label was wrong; the
> reasoning about what each class is *for* was right.


* **`goto-ify`** — replace a `while` with a label and a conditional `goto`. The
  CFG is unchanged, so every CFG metric scores it perfect; the control skeleton
  changes, so the recommended tree metric should catch all of them. This is the
  single most discriminating class between the two structural candidates, and it
  is the one the project already knows matters
  ([`../../development/traps.md`](../../development/traps.md): *"goto soup passes
  every fixture"*).
* **`duplicate-tail`** — copy a join block into both predecessors. Real
  structuring algorithms do this; it changes the CFG and should not be scored as
  a defect of the same magnitude as losing a branch.
* **`drop-call`** — delete a call with side effects but no used result. Invisible
  to every structural metric and to a return-value-only differential; the
  motivating case for including the call trace in
  [`semantic-metrics.md`](semantic-metrics.md) §2.1.
* **`swap-args`** — exchange two arguments of the same type at a call site.
  Invisible to everything structural.
* **`off-by-one`** — `<=` for `<` in a loop bound. Detected only by a semantic
  metric with a boundary input.

### 2.2 Specificity — does the metric stay quiet on a legitimate rewrite?

**The pilot did not measure this, and it matters exactly as much.** A metric that
flags a legitimate decompiler choice is punishing the decompiler for being right
in a different way, and it will drive the tool toward mimicking the source rather
than toward being correct.

Semantics-preserving mutations, each of which the metric must score **identically
to the original**:

| class | must not move the score | tests |
|---|---|---|
| whitespace, comments, line breaks | any metric | that the metric reads structure, not text |
| variable and parameter renaming | any metric | that the skeleton alphabet excludes identifiers |
| `for` ↔ `while` rewriting | tree metric | the §2.6 canonicalization in [`structural-metrics.md`](structural-metrics.md) |
| `else if` nesting versus chaining | tree metric | the second canonicalization |
| declaration hoisting to the top of the body | tree metric | decompilers all do this |
| `x = x + 1` ↔ `x++` | tree metric, semantic metric | expression-level, must be a leaf |
| adding a redundant `else { }` | tree metric | a real structuring artefact |
| reordering two independent statements | semantic metric | the observable is not write order ([`semantic-metrics.md`](semantic-metrics.md) §2.1) |

A metric's specificity number is the fraction of these it scores exactly
unchanged. **The bar is 100% on the first two rows and published-with-a-reason on
the rest**; a canonicalization that cannot get its own row to 100% is not
implemented correctly.

### 2.3 What the harness reports

Per metric, per mutation class: detection rate, and for the specificity classes,
the false-alarm rate. Then one summary that is not an average — a metric with 90%
sensitivity and 40% specificity is useless, and averaging hides it. Report the
pair.

## 3. Comparison to the incumbent

Run the candidate and GED over the same 89,014 functions and publish a
**four-cell confusion table per decompiler**, not a correlation:

```
                        GED perfect   GED not perfect
new metric perfect          A               B
new metric not perfect      C               D
```

* **C is the point of the exercise.** These are functions GED called perfect and
  the new metric does not. The single-node class should dominate it: 24,243
  functions are branchless, and a tree metric that scores them all perfect has
  failed. Expected magnitude is thousands, not tens.
* **B needs a per-case explanation, not an aggregate.** A function the new metric
  calls perfect and GED does not is either a GED false negative (good) or a new
  false positive (bad), and only reading them tells which. Cap the number that
  may go unexamined; the pilot's `worst[:20]` convention in
  `tools/source_cfg_parity.py` is the right shape.
* Rank the columns under both. **Do not require the ranking to be preserved** —
  if the incumbent is broken, preserving its order is not a virtue. Require
  instead that every inversion be attributable: name the functions that moved and
  the defect class they belong to.

## 4. The null baseline is a permanent gate

The cheapest audit any metric can have, and the one that found the largest defect
in this whole investigation:

> **Score a decompiler that emits one constant body for every function. Publish
> the number beside the metric, forever.**

For DecBench GED it is **27.24%** (`m4.py`), which places a constant `return 0;`
fifth of fifteen columns on the GED metric, and sixth on the published Union
scoreboard. That number took an afternoon to compute and it is
worth more than any amount of argument about edit distances.

Make it a gate:

* Every metric publishes `null_baseline` alongside every score.
* A metric whose null baseline exceeds **5%** is reporting corpus composition
  rather than decompilation quality, and does not ship as a headline.
* The null decompiler is not one body but a small family — the empty body, `return 0;`,
  `return *(int*)a;`, an infinite loop, a single unconditional call — and the
  baseline is the **maximum** over the family, because a real decompiler in a
  degenerate mode will land on whichever is best.

Add a second, harder baseline: the **transplant baseline** — score each function
against the CFG of a *different* function, drawn uniformly from the same binary.
GED's is bounded below by the twin rate, 58.61% of functions having an isomorphic
same-binary twin (`m7.py`). A metric on which emitting a neighbour's body scores
well is not identifying functions.

## 5. Which knobs are principled

A knob is principled when its value can be argued from the problem rather than
from the resulting scores. The test is simple: **if changing it moves the ranking
and there is no argument that fixes its value, it is score-shopping and it must
not be an option.**

### Principled, but fixed and versioned

| knob | why it is principled | discipline |
|---|---|---|
| size-band boundaries | the corpus is bimodal and pooling is the largest defect | fix once; changing them is a new metric version |
| normalization denominator | an unnormalized distance lets big functions dominate any mean | must be a property of the **ground truth** only, never of the decompiled side |
| node cap / fallback threshold | a real complexity limit | recorded in the output as a flag; must never change the *perfect* verdict, only the magnitude — GED's `approximated` flag is the right pattern |
| evaluation bound (unroll depth, memory size, input count) | bounded means bounded | quoted **with every number**; a semantic result without its bound is not a claim |
| the canonicalization list | each entry is a decision about program identity | enumerated, versioned, and each one tested by its own specificity mutation (§2.2) |

### Score-shopping — must not be exposed at all

| knob | how it is abused |
|---|---|
| edit cost weights (node insert vs edge insert vs substitute) | reweighting reorders the columns; a change of weights is a **new metric name**, not an option |
| similarity curve (`exp(-d/τ)`, `1/(1+d)`, linear) | `τ` can be tuned until any chosen column wins |
| the aggregation (perfect-% vs mean vs median) | the largest lever in the current system, currently an unexamined default; fix it and publish the whole distribution |
| random seeds in input generation or mutation | a seed that changes results is a knob; fix the seed and publish it |
| solver backend selection | Z3 and `axeyum` may disagree on `unknown`; the backend is part of the metric identity |

### Where determinism has to be preserved

Non-negotiable, in order of how easily each is lost:

1. **No hash-map iteration order reaches output.** Already the house rule
   ([`src/metrics/mod.rs`](../../../src/metrics/mod.rs)); it survives only if
   every new metric restates it.
2. **Every tie-break is a total order.** The LSAP in
   [`src/syntax/ged.rs`](../../../src/syntax/ged.rs) does this with an ascending
   column scan and a strict `<`; a tree edit distance needs the same discipline
   in its traceback, because equal-cost edit scripts are common on small trees.
3. **Budgets are work, not wall clock.** This is the one that will actually
   break. `DEFAULT_CHECK_TIMEOUT_MS = 250` in
   [`src/symbolic/solver/mod.rs`](../../../src/symbolic/solver/mod.rs) is a wall
   clock, and a wall-clock-bounded metric produces different scores on a loaded
   machine — the same failure the project already records for baseline
   regeneration (*"Baseline regen needs a quiet machine"*,
   [`../../development/traps.md`](../../development/traps.md)). Count solver
   steps or `Budget` ticks. Keep a wall clock only as a safety valve whose expiry
   is an **error that fails the run**, never a value that scores it.
4. **The cache key covers the semantics.** DecBench's `cache_version` bump on
   `bd49c83` is why the two GED semantics did not silently mix in one cache; the
   incident in [`what-ged-measures.md`](what-ged-measures.md) §0 is what happens
   when two versions of a metric exist and only one of them is labelled. Any new
   metric carries a version in its key from the first commit.

## 6. What could not be established offline

Stated plainly so nothing here is over-claimed:

* **Agreement with human judgement.** The corpus has no human labels. The 300
  `samples` records carry a `difficulty` field, but it is a dataset annotation,
  not a judgement about a decompilation. A fifty-pair ranking study is proposed
  in [`roadmap.md`](roadmap.md) R1 and is explicitly described there as
  underpowered for separating two good metrics; it can only catch a metric that
  is badly wrong.
* **Specificity of any metric**, including GED's. §2.2's semantics-preserving
  half was not run — the mutations are easy to write but the pilot did not
  include them, so **no specificity number appears anywhere in this directory.**
  Nobody should quote one until the harness exists.
* **The cost of a semantic metric.** Stage S4 is not built.
* **Anything about other decompilers' output text.** Every decompiled artifact in
  the materialized tree is Glaurung's own
  ([`../static-c-analysis/roadmap.md`](../static-c-analysis/roadmap.md) §3).
