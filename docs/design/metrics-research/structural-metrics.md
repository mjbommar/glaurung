# Structural metrics: what to measure instead

> **Kind:** design · **Status:** proposed

[`what-ged-measures.md`](what-ged-measures.md) establishes three defects, in
descending order of how much they cost:

1. **The aggregation.** The scoreboard is `perfect_percentage` over an indicator,
   and 62.5%–100% of every column's positive class is functions with a
   single-node CFG.
2. **The equivalence.** A perfect verdict carries 3.64 bits: 24,243 of 89,014
   functions occupy one isomorphism class, and 58.61% of functions have an
   isomorphic twin in the same binary.
3. **The distance.** `vj_ged` reads degree multisets only, and the fork we run
   locally awards `0.0` to 94.41% of degree-preserving rewirings.

They are independent, and the cheapest one is the most valuable. This document
takes a position on each candidate replacement and ends with one recommendation.

## 1. Fix the aggregation first — it costs nothing and it is the largest effect

Before any new distance exists, two changes are available today:

**Stratify by function size, and publish the strata.** A single number over a
population where 27.24% of the members are branchless is not a measurement of
decompilation, it is a measurement of how many branchless functions the corpus
has. The bands already used by `tools/source_cfg_census.py`
(`1, 2-3, 4-7, 8-15, 16-31, 32-60, >60`) are adequate and already implemented;
the per-band perfect rates in
[`what-ged-measures.md`](what-ged-measures.md) §3 are what a stratified report
looks like. It changes the ranking's meaning immediately: `dewolf` scores 3.09%
overall, and **every one of its 2,808 perfect cells is a single-node
function** — its score on functions with any control flow at all is zero.

**Publish the null baseline beside the score.** 27.24% is what a constant body
earns. Any metric whose null baseline is not near zero is reporting mostly
corpus composition. See [`calibration.md`](calibration.md) §4; this is the
single cheapest audit available and it should be permanent.

Neither of these needs a new metric, a new front end, or a DecBench change. They
are arithmetic over data already published. **Everything below is worth less than
these two.**

## 2. The candidates, argued

### 2.1 True graph edit distance with real assignment costs — rejected as the headline

Exact GED is NP-hard. On this corpus that is survivable for the median function
(12 nodes) and not for the tail (zlib `inflate`, 416 nodes), so any
implementation acquires a node budget, and a budget that changes the answer is a
knob (§5 of [`calibration.md`](calibration.md)). Worse, exact GED fixes the
*magnitude* channel — and the magnitude channel does not reach the scoreboard at
all, because the aggregation is `perfect_percentage`. Paying NP-hardness to
improve a number nobody scores is the wrong trade.

**What is worth taking from this family** is the standard bipartite fix, not the
exact algorithm. Riesen–Bunke's local-edge-structure cost keeps one LSAP but
makes the substitution cost adjacency-aware: substituting source node *i* for
decompiled node *j* also pays the edit distance between their incident-edge
multisets. That is enough to separate a 4-cycle from two 2-cycles — the
canonical counterexample in
[`../static-c-analysis/joern-behavior.md`](../static-c-analysis/joern-behavior.md)
§2 — and it costs `O(n·m·d)` to build the matrix instead of `O(n·m)`. It reuses
`solve_assignment(cells: &[Cost], order: usize) -> Assignment` in
[`src/syntax/ged.rs`](../../../src/syntax/ged.rs) unchanged, including its
determinism contract (ascending column scan, strict `<` tie-break). **Verdict:
build it as a graded diagnostic, never as the headline.**

### 2.2 Graph kernels (Weisfeiler–Lehman, random-walk) — rejected, on measured grounds

This one is settled by measurement rather than argument. Over the 89,014
non-degenerate published source CFGs, 1-WL colour refinement produced **8,034**
classes and VF2 inside every WL bucket produced **8,034** classes
(`census.py`). 1-WL is complete on this corpus.

A WL *kernel* therefore adds nothing to the perfect/not-perfect question that
upstream's existing `_is_isomorphic` does not already answer. As a graded
similarity it is worse than it looks: the WL subtree feature vector of a
median-size graph here (12 nodes, refinement stabilizing in two or three rounds)
is dominated by the degree histogram, which is exactly the information `vj_ged`
already uses. Random-walk kernels are `O(n³)` at best and carry a halting
probability with no principled setting — a pure score-shopping knob.

**Verdict: no. The one thing WL is good for here is as a cheap exact isomorphism
certificate, and this directory uses it that way.**

### 2.3 Spectral distances — rejected

Three reasons, all specific to this corpus rather than general. The graphs are
directed, so the natural Laplacian is not symmetric and the spectrum is complex.
49.0% of published functions carry no exit-flagged node at all (the
singleton-funcend rule), and 27.24% are a single isolated node, whose spectrum is
a point — a metric that cannot say anything about a quarter of the corpus is not
a replacement for one that says the wrong thing about it. And an eigenvalue
distance is uninterpretable: it cannot name the edge that is wrong, which is the
first thing anyone asks of a failing cell.

**Verdict: no.**

### 2.4 Dominator and loop-nesting tree comparison — a component, not the headline

Genuinely informative: nesting depth is exactly what a degree sequence destroys,
and a decompiler that flattens a doubly-nested loop into two sequential loops is
committing a real error that CFG isomorphism sometimes misses. Lengauer–Tarjan is
`O(n α(n))`, deterministic, and already the kind of thing
[`src/csource/cfg/`](../../../src/csource/cfg/mod.rs) can support.

But it is a *coarsening* of the CFG. Every blindness the CFG has, the dominator
tree inherits — including the 27.24% single-node class, whose dominator tree is a
single node. It cannot be the headline for the same reason the CFG cannot.

**Verdict: yes as an input to the graded distance of §2.1; no as a metric.**

### 2.5 Path-based and control-dependence measures — folded in, not separate

Path-set comparison needs a length bound, and the bound is a knob that moves the
score. Control dependence is more informative than plain control flow and is a
real improvement — but it is derived from the CFG plus the post-dominator tree,
so it is §2.4 again with more edges. **Verdict: use control-dependence edges as
the edge-cost input to §2.1's adjacency-aware substitution cost. Do not publish a
separate number.**

### 2.6 Tree edit distance over the recovered control structure — the recommendation

This is the only structural candidate that is not saturated by the corpus's
dominant class, and it is the only one that measures what decompilers are
actually built to do.

**It splits the class nothing else can.** The 24,243-function single-node class
holds 7,393 distinct pyjoern statement bodies and 5,284 distinct names, with
statement counts from 3 to 618 (`m5.py`, `m6.py`). Every CFG-derived metric
assigns all of them one value, by construction. A tree over the statement
structure assigns `pgResetFn_osdConfig` (618 statements) and zlib `adler32` (one
line) different values, because they are different trees.

**It measures structuring, which is the decompiler's actual job, and which every
CFG metric is blind to by construction.** A `while` loop and its goto-ified
equivalent have the *same* control-flow graph. The project has this recorded as a
trap from the other direction — *"Execution differential is blind to structure —
goto soup passes every fixture"*
([`../../development/traps.md`](../../development/traps.md)) — and the fixture
suite answers it by asserting `switch` and `goto_free` explicitly. A
control-skeleton tree distance is the general form of those assertions: it is a
graded measure of exactly the property the fixture gates spot-check.

**It is computable today.** S1 and S2 have landed: `csource::parse` reads
1,606 decompiled files and 11.9 M lines with zero errors, and `csource::cfg`
builds 188,716 CFGs
([`../static-c-analysis/roadmap.md`](../static-c-analysis/roadmap.md) §3–§4).
The AST is [`src/syntax/tree.rs`](../../../src/syntax/tree.rs). Nothing new has
to exist.

**It is cheap and deterministic.** Zhang–Shasha on ordered trees is
`O(n₁·n₂·min(depth,leaves)²)`, and the trees in question are the *control
skeleton*, not the full AST — see the alphabet below. Order comes from source
order, which is canonical. No solver, no timeout, no budget that changes the
answer.

#### What the tree must be, precisely

The failure mode of this proposal is a tree edit distance over the full AST,
which would be dominated by expression shape and would move when a decompiler
renames a variable. The metric must be over a fixed, small alphabet:

```
Seq  If  Then  Else  While  DoWhile  For  Switch  Case  Default
Break  Continue  Goto  Label  Return  Call  Assign  Expr  Decl
```

Every expression collapses to a single leaf of its statement's kind. No
identifiers, no literals, no types, no operators. That is what makes the metric
insensitive to renaming and to the `constant-bump` and `arith-flip` mutations —
and, honestly, it is also what makes it unable to *detect* them. §3 says why that
is the right trade.

Two canonicalizations are required, and each is a decision about what counts as
the same program, so each is versioned and each is tested by a
semantics-preserving mutation ([`calibration.md`](calibration.md) §2):

* `for (a; b; c) S` normalizes to `a; while (b) { S; c; }` — a decompiler
  choosing `while` over `for` is not wrong.
* `else if` flattens to a `Switch`-free chain of `If` nodes rather than nesting —
  otherwise chain length is scored twice.

Explicitly **not** canonicalized: `if (!c) A else B` versus `if (c) B else A`.
They are the same program, and treating them as different is a small false
positive; treating them as the same requires reading the condition, which
reintroduces expression sensitivity. Take the false positive and measure it.

#### What it cannot do

It cannot detect a negated condition, a flipped comparison, a changed constant
or a substituted arithmetic operator. Those are the six semantics-only classes of
the [`what-ged-measures.md`](what-ged-measures.md) §5 pilot: 795 applied
mutations, of which the CFG metric detected 7. A control-skeleton tree detects
the same 7 or fewer, and it will not close the gap by getting better, because
those mutants have identical control skeletons by construction. That is the ceiling, and it is where
[`semantic-metrics.md`](semantic-metrics.md) starts.

## 3. The recommendation

**One structural metric: normalized control-skeleton tree edit distance,
reported graded and stratified by source function size, with the null-decompiler
baseline published beside it.**

```
score(f) = 1 - TED(skeleton(source_f), skeleton(decompiled_f)) / |skeleton(source_f)|
```

clamped to `[0, 1]`, with `|skeleton|` the node count of the source skeleton, so
the denominator is a property of the ground truth and cannot be inflated by the
decompiler. Report:

* the mean per size band, never pooled across bands;
* the exact-match rate (`TED = 0`) per band, as the successor to
  `perfect_percentage`;
* the null baseline, which for this metric is the score a constant `return 0;`
  earns and which must be measured, not assumed to be zero.

Keep the adjacency-aware graded CFG distance of §2.1 as a **diagnostic**, not a
published score: it is what tells a developer *which* edge is wrong when the tree
distance says a function regressed. Keep upstream's isomorphism check as a
second diagnostic for the same reason.

Retire two things: the fork's degree-only `vj_ged` verdict (94.41% false-perfect
on rewiring), and `perfect_percentage` as a headline over any indicator.

## 4. Ordering, and the honest caveat

The order of work is the reverse of the order of interest:

1. §1's stratification and null baseline — arithmetic over published data, no new
   code, largest effect.
2. The mutation harness ([`calibration.md`](calibration.md) §2) — because a
   metric shipped before its instrument cannot be argued for.
3. §2.6's tree distance.
4. §2.1's graded CFG distance, as a diagnostic.

The caveat carried from
[`../static-c-analysis/roadmap.md`](../static-c-analysis/roadmap.md) §3 applies
here unchanged and must be repeated wherever a coverage number is quoted: **every
decompiled artifact in the materialized tree is Glaurung's own output.** The
parse-coverage evidence that makes §2.6 look free was measured on well-formed C
that Glaurung emitted. A tree metric over Ghidra or IDA text — `undefined4`,
`__usercall`, `@ rax` annotations — is untested, and the decompiled side of the
tree distance is only as good as the parse. That is a gap in the corpus, not in
the design, and it closes only with a corpus carrying other decompilers' columns.
