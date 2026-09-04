# Higher-order structure: hypergraphs, dependence graphs, and whether any of it helps

> **Kind:** design · **Status:** proposed

[`structural-metrics.md`](structural-metrics.md) argues six candidate structural
families and recommends one. Every one of those six is an object over the
control-flow graph or a coarsening of it. It never considers the family that
sits *above* the CFG: hypergraphs, simplicial complexes, and -- most
conspicuously, because it is the native object of the tool Glaurung is replacing
-- the **program dependence graph**. Joern builds a code property graph (AST +
CFG + PDG overlaid); DecBench scores the CFG projection of it and throws the
rest away. Everything this directory has measured is therefore about a strictly
weaker object than the tool it is displacing already has in memory.

That is a real gap in the argument, and it deserves the same treatment the other
six got. This document closes it.

**The answer is no, and it is a stronger no than expected.** A data-dependence
overlay detects **0 of 1,197** expression-level defects -- the same ceiling the
CFG has -- and the one defect class it does catch that the CFG misses
(`drop-call`) is already caught at **100%** by the control-skeleton tree
distance that landed in [`src/metrics/tree_distance.rs`](../../../src/metrics/tree_distance.rs).
On the corpus's dominant degenerate class the higher-order objects are *worse*
than the tree, not better. And the premise itself is largely absent from the
data: **84.34% of the corpus's 4,402,807 statements mention two or fewer
distinct variables**, so for five statements in six the "hypergraph" is an
ordinary graph.

One thing in this family *is* worth taking, and it is not a new object. It is
the statistical framing the degenerate-graph problem needs: a **per-cell
null-model correction**, which turns "27.24% of the corpus is a single node"
from a complaint into an arithmetic adjustment. Section 7.

## 1. How this was measured, and with what

Everything below was computed offline from the materialized DecBench tree and
the published sample set. **No Joern process, no JVM, and no DecBench pipeline
was run**, per `CLAUDE.md`; the DecBench checkout was read, not executed.

```bash
export TMPDIR="$HOME/.cache/glaurung/tmp"; mkdir -p "$TMPDIR"
```

**The build.** Every native call went through
`python/glaurung/_native.cpython-314-x86_64-linux-gnu.so`, SHA-256
`89ddf8cf369056ddaf55440d300812fb8c89d0ebb0c2b1637fb9ad4d735a3430`, built
2026-09-04 18:42. `uv run python tools/build_guard.py` reports it **STALE**
against `src/csource/lower/expr.rs`, which was under live edit during this work,
and the build profile was not verified. Three native entry points were used and
nothing else: `glaurung._native.csource.parity_cfgs`,
`glaurung._native.metrics.skeletons` and
`glaurung._native.metrics.tree_edit_distance`
([`src/python_bindings/metrics.rs`](../../../src/python_bindings/metrics.rs);
`SKELETON_VERSION` 1, `MAX_SKELETON_NODES` 2048). A stale extension cannot
change a parse or a tree distance for the constructs used here, but it is
recorded rather than assumed away.

**The corpora.** Two, and they answer different questions.

| corpus | what it is | size, measured |
|---|---|---|
| `~/.cache/glaurung/decbench-full/tree/*/*/source_cfgs/*.json` | the published **ground-truth** CFGs, each carrying pyjoern's per-block statement dump in `labels` | 800 files, **91,548** functions with a non-empty CFG, **4,402,807** statements |
| `~/.cache/glaurung/decbench-full/decbench/site/data/samples.json` | 539 benchmark functions with real source **and** real decompiled text from twelve columns | **4,385** offered cells, all non-empty |

The 91,548 is the raw file population and is **not** the 89,014 of
[`what-ged-measures.md`](what-ged-measures.md), which is the subset joined to
`published_function_results.json`. Numbers below are on the population named
beside them and are not interchangeable with that document's.

Two independent cross-checks say the reading of this corpus is right. Over the
91,548 functions, joint 1-WL colour refinement produces **8,034** classes --
exactly the figure [`what-ged-measures.md`](what-ged-measures.md) §2 measured
over its 89,014, by a different implementation. And the twin rate restricted to
functions with at least four CFG nodes comes out at **17,325 / 53,379 =
32.46%**, which is that document's §4 figure to the unit.

**The instrument.** Sensitivity and specificity were measured with the committed
mutation harness, [`tools/metric_mutation.py`](../../../tools/metric_mutation.py)
(`CATALOGUE_VERSION` 1, seed 20260904), imported as a module by a scratch runner
so that two extra objects could be scored on the same mutants that GED is scored
on. The GED verdict is the harness's own, unmodified. The scratch scripts live
in `$TMPDIR` and are not committed; §10 gives the definitions that matter.

## 2. Three objects, and what each can see before anything is measured

### 2.1 Control dependence adds exactly nothing over the CFG

The control-dependence graph is a *function* of the control-flow graph and its
post-dominator tree, and the post-dominator tree is a function of the CFG. So if
two role-labelled CFGs are isomorphic, their control-dependence graphs are
isomorphic. **A perfect/not-perfect verdict on control dependence can therefore
never fire where CFG isomorphism does not**, and it can fire *less* often,
because distinct CFGs can share a CDG.

[`structural-metrics.md`](structural-metrics.md) §2.5 already says control
dependence "is derived from the CFG plus the post-dominator tree, so it is §2.4
again with more edges". That is right, and the consequence is stronger than the
sentence lets on: as a *detector* the CDG is weaker-or-equal by construction, so
the interesting half of a PDG is the data half. The rest of this document is
about the data half.

Stated on the mutation catalogue: a `negate-condition` mutation changes no CFG
edge, and it changes control dependence not at all either. It is worth saying
why that is not a quirk. Control dependence records *which* branch
a statement hangs off, never *which way* the branch goes. Inverting a predicate
is invisible to it by definition, not by accident.

### 2.2 Data dependence and the variable-incidence hypergraph are the same experiment

A basic block is naturally a hyperedge over the variables it reads and writes.
Take that seriously and the object is a hypergraph `H = (V, E)` with `V` the
variables and `E` the statements, `s` incident to `v` when `s` mentions `v`. Its
standard encoding is the bipartite incidence graph.

A statement-level def-use graph is the same incidence relation, oriented: an
edge from the statement that last defined `v` to each statement that uses it.
Every def-use edge is derivable from the incidence relation plus an order.

They therefore agree on every defect that changes *which statements mention
which variables*, and they are both blind to every defect that does not. That
collapses the dependence question and the hypergraph question into one
experiment, which is why both are scored side by side below rather than argued
separately.

### 2.3 The natural counterexample, and why it fails

The obvious case for a dependence overlay is `swap-args`: a defect that changes
no control flow, so it looks like data dependence should be the thing that sees
it. It is not. `f(a, b)` and `f(b, a)` have the same def set, the same use set,
and the same def-use edges: the use multiset at a call site is *unordered* in a
statement-level PDG. Measured, over 173 real `swap-args` mutants (§3): the CFG,
the control skeleton, the incidence hypergraph and the def-use graph all score
**0.0%**.

Nor does labelling dependence edges with the argument position rescue it. Under
any *name-invariant* graph invariant -- and a metric that reads variable names
is reading text, not structure -- `a` and `b` are anonymous vertices, so
swapping their roles at one call site produces a graph that is isomorphic to the
original whenever the two arguments are not distinguished by their other
incidences. To see `swap-args` reliably you need the ordered expression tree,
which is the full AST that [`structural-metrics.md`](structural-metrics.md) §2.6
rejects for a separate and good reason (it moves when a decompiler renames a
variable). Argument order is *semantics*, and semantics is where it has to be
caught.

## 3. Measured: what a dependence overlay actually catches

The scratch runner scores four objects on the same mutants:

* `ged` -- DecBench's, taken from the harness unchanged (isomorphism, then the
  `max(1.0, raw)` clamp);
* `skeleton` -- `metrics.tree_edit_distance(...) == 0` over the landed control
  skeleton, native;
* `incidence` -- the variable-incidence hypergraph's joint 1-WL certificate;
* `defuse` -- the straight-line def-use graph's joint 1-WL certificate.

A 1-WL certificate match is *necessary*, not sufficient, for isomorphism, so
every "unchanged" verdict for the two overlays is an upper bound on what they
can see. That is the conservative direction for an argument that concludes they
see too little. A pair either object cannot form -- a function with no variable
at all -- is an **abstention** and leaves the denominator, per
[`src/metrics/mod.rs`](../../../src/metrics/mod.rs)'s rule that a non-answer is
a value; abstention counts are reported.

```
uv run python <scratch>/h4_overlay_mutation.py --corpus samples
# 291 units scored, 9 skipped; abstentions: skeleton 114, incidence 337, defuse 11
```

Rate = the share of mutants on which the object stopped calling the pair
perfect. For the `Y` rows that is detection; for the `n` rows it is a false
alarm.

```
class              chg applied      ged   skeleton  incidence     defuse
negate-condition     Y     190      0.0%      0.5%       0.0%       0.0%
equality-flip        Y     136      0.0%      0.0%       0.0%       0.0%
relational-flip      Y     120      0.0%      0.0%       0.0%       0.0%
off-by-one           Y     120      0.0%      0.0%       0.0%       0.0%
logic-flip           Y      99     12.1%      0.0%       0.0%       0.0%
arith-flip           Y      75      0.0%      0.0%       0.0%       0.0%
assign-op-flip       Y      32      0.0%      0.0%       0.0%       0.0%
constant-bump        Y     218      0.0%      0.0%       0.0%       0.0%
incr-to-decr         Y      34      0.0%      0.0%       0.0%       0.0%
swap-args            Y     173      0.0%      0.0%       0.0%       0.0%
drop-call            Y     192      8.3%    100.0%      80.7%      98.3%
drop-break           Y      48     87.5%    100.0%       0.0%      72.9%
while->if            Y      44    100.0%    100.0%       0.0%       0.0%
else->if(0)          Y     100    100.0%    100.0%       0.0%       0.0%
null-body            Y     291     71.5%     92.3%       0.0%      83.8%
ws-reflow            n     291      0.0%      0.0%       0.0%       0.0%
comment-insert       n     291      0.0%      0.0%       0.0%       0.0%
rename-param         n     249      0.0%      0.0%       3.3%       0.4%
int-identity         n     218      0.9%      0.5%       0.0%       0.0%
extra-braces         n     284      0.0%      0.0%       0.0%       0.0%
if-else-swap         n      66      0.0%     81.0%       3.0%      47.0%
demorgan             n      67     31.3%      3.1%       0.0%       0.0%
and-to-nested-if     n      44    100.0%    100.0%      84.1%      97.7%
for-to-while         n      37      0.0%      0.0%       2.8%      89.2%
else-if-nest         n      23      8.7%      0.0%       0.0%      95.7%
redundant-else       n     133      1.5%    100.0%       0.0%      99.2%
incr-expand          n      34      0.0%    100.0%       0.0%      76.5%
goto-ify             n      14      7.1%    100.0%     100.0%     100.0%
duplicate-tail       n      20     60.0%    100.0%      90.0%      95.0%

expression-level classes only (the ten that cannot change the CFG):
  ged        12 / 1197 =  1.00%
  skeleton    1 / 1146 =  0.09%
  incidence   0 / 1192 =  0.00%
  defuse      0 / 1197 =  0.00%

noise floor (ws-reflow + comment-insert, which change nothing readable):
  all four objects: 0 / (568..582) = 0.00%
```

Three readings, in descending order of how much they settle.

**A data-dependence overlay detects zero expression-level defects.** Not few --
zero, out of 1,197. It sits at the same ceiling
[`semantic-metrics.md`](semantic-metrics.md) opens with, and it gets there while
being *less* sensitive than the incumbent (whose 12 detections are `logic-flip`
short-circuit rewrites that our front end turns into extra blocks). Paying for a
richer object to arrive at the same ceiling is the whole argument against this
family in one row.

**Its single win is already won.** `drop-call` is the one class where the
overlays beat GED decisively -- 98.3% and 80.7% against 8.3%. It is also the one
class where the landed tree distance scores **100.0%**, because dropping a call
statement removes a `Call` leaf from the skeleton. The overlay's unique
contribution over the CFG is a strict subset of what a metric this project
already shipped does better, deterministically, in Rust.

**The overlays lose the classes GED wins.** `drop-break`, `while->if` and
`else->if(0)` -- 192 mutants that change control flow -- are 0.0% for the
incidence hypergraph. A dependence overlay is not a refinement of the CFG
verdict; it is a different, smaller verdict. Any deployment would have to run
both, which doubles the cost to add zero classes.

### 3.1 Three real functions

Taken from `samples.json`, mutated by the committed catalogue, with GED's own
verdict:

```
libedit  history_def_last   drop the call  he_seterrev(ev, _HE_LAST_NOTFOUND);
    CFG n=3 m=2 | ged perfect | TED = 1 | incidence moved | defuse moved
dpkg     cu_prermupgrade    drop the call  post_postinst_tasks(pkg, PKG_STAT_INSTALLED);
    CFG n=3 m=2 | ged perfect | TED = 1 | incidence moved | defuse moved
iproute2 rmnet_print_help   drop the call  print_explain(f);
    CFG n=1 m=0 | ged perfect | TED = 1 | incidence moved | defuse moved

libedit  history_def_last   he_seterrev(ev, _HE_LAST_NOTFOUND)
                         -> he_seterrev(_HE_LAST_NOTFOUND, ev)
    CFG n=3 m=2 | ged perfect | TED = 0 | incidence same | defuse same
dpkg     cu_prermupgrade    pkg_clear_eflags(pkg, PKG_EFLAG_REINSTREQ)
                         -> pkg_clear_eflags(PKG_EFLAG_REINSTREQ, pkg)
    CFG n=3 m=2 | ged perfect | TED = 0 | incidence same | defuse same
```

`history_def_last` is the first record in `samples.json`. A decompiler that
writes libedit's error code into the event pointer's slot and the event pointer
into the code's slot is producing code that will corrupt memory on the failure
path, and **every structural object in this document, higher-order included,
calls it perfect.**

### 3.2 The specificity side, and what is proxy and what is real

The `defuse` column's false alarms (`for-to-while` 89.2%, `else-if-nest` 95.7%,
`redundant-else` 99.2%, `incr-expand` 76.5%) are mostly the **proxy's** fault,
not data dependence's: the scratch overlay segments statements textually and
uses a "last def in text order wins" approximation, which is exact for a
branchless function and wrong across a loop back edge. A real PDG built on
[`src/ir/use_def.rs`](../../../src/ir/use_def.rs) would not move on any of them.
Those four rows are therefore **not** evidence against a dependence overlay and
must not be quoted as such.

Two specificity rows *are* real and survive any implementation.
`and-to-nested-if` (84.1% / 97.7%) is the same front-end fact that gives GED
100% there: our C front end makes short-circuit operators control flow
([`../static-c-analysis/roadmap.md`](../static-c-analysis/roadmap.md)), so
`if (A && B)` and `if (A) if (B)` differ in statement count for any
statement-level object. `duplicate-tail` (90% / 95%) is a genuine hazard for
anything counting statements, and the tree distance shares it at 100%.

The incidence hypergraph's headline specificity looks excellent -- 95.4% overall
against GED's 95.3% -- but the number is bought with abstentions. It abstained
337 times, including on **all 291** `null-body` mutants, because a body of
`return 0;` mentions no variable and the object is empty. That is not caution;
it is a metric that cannot report on the null decompiler at all. §6.

### 3.3 A statement-indexed object measures temporary-introduction style first

Any dependence overlay, and any hypergraph over statements, is indexed by
statements. Real decompilers do not preserve statement identity: they spill
subexpressions into temporaries. Over every resolvable cell of `samples.json`,
scored with Glaurung's own front end:

```
uv run python <scratch>/h2_skeleton_census.py
column          cells  unres   med skel  med assign  med cfgN   skel  assign   cfg
                                                                ratio  ratio  ratio
SOURCE            524     15       14.0         3.0       6.0
angr              482      0       19.0         6.0       7.0   1.25    1.75  1.00
binja             465      1       20.0         7.0       8.0   1.31    2.00  1.00
claude-code       238      3       16.0         4.0       7.0   1.00    1.00  1.00
codex             239      1       14.5         5.0       7.5   1.00    1.00  1.00
dewolf            337     38       15.0         6.0       6.0   1.47    2.00  1.00
fission           239      0       35.0        22.0       9.0   2.33    5.33  1.26
ghidra            490      0       20.0         8.0       8.0   1.40    2.00  1.03
glaurung          239      0       26.0        13.0       8.0   1.69    3.08  1.00
ida               486      0       18.5         6.5       7.0   1.25    1.80  1.00
kuna              500      0       18.0         6.0       7.0   1.33    1.80  1.00
manifold          140      0       53.5        24.5      15.5   1.91    2.94  1.00
r2dec             412      6       53.0        33.0       8.5   3.24    7.19  1.00
```

The ratios are per-cell medians against that cell's own source. **The median
CFG-node ratio is 1.00 for ten of the twelve columns; the median
assignment-count ratio is 1.75 or more for ten of them and reaches 7.19.** The
graph the incumbent metric scores is close to preserved; the statement sequence
that a dependence overlay would be indexed by is not.

Exact agreement tells the same story
(`uv run python <scratch>/h3_exact_match.py`, 4,218 resolvable cells): the
decompiled CFG has the same node count as the source's in **37.5%** of cells and
the same node *and* edge count in 31.7%, while the assignment count matches in
only **20.1%**. An object indexed by statements starts from a 79.9% disagreement
rate that has nothing to do with correctness.

## 4. Measured: the hypergraph is a graph

The hypergraph proposal rests on a premise: that statements are hyperedges of
arity three or more, so that an object which can only represent pairwise
relations loses something. Over every statement in the published corpus:

```
uv run python <scratch>/h13_arity.py
# 91,548 functions, 4,402,807 statements

  arity   statements    share   cumulative
      0      942,448   21.41%      21.41%
      1    1,653,894   37.56%      58.97%
      2    1,117,106   25.37%      84.34%
      3      456,157   10.36%      94.70%
      4      171,763    3.90%      98.60%
     5+       61,311    1.39%     100.00%

  statements of arity <= 2:                     3,713,448 / 4,402,807 = 84.34%
  functions with no statement of arity 3+:         28,433 /    91,548 = 31.06%
```

**For 84.34% of statements the hyperedge is an edge, a self-loop or nothing at
all, and 31.06% of functions contain no genuinely higher-order relation
anywhere.** The premise is true of roughly one statement in six. That does not make a
hypergraph wrong; it makes it a graph with a 15.66% decoration, and the
decoration is concentrated in exactly the large functions where every metric in
this directory already agrees the answer is "not perfect".

### 4.1 Simplicial complexes, briefly and finally

A simplicial complex demands downward closure: every subset of a face is a face.
The natural faces here -- the variable set a statement touches -- are not
downward closed, and forcing closure is not a modelling choice but a destruction
of the data, because the closure of a single arity-`k` face is the whole
`(k-1)`-simplex, whose homology is trivial in every dimension. With 84.34% of
faces at arity `<= 2` the resulting complex is a graph plus isolated points, so
its only non-trivial invariant is `beta_0`, the number of connected components
-- which the incidence graph already reports, and which
[`structural-metrics.md`](structural-metrics.md) §2.3 has already rejected in
its spectral form for the reason that applies here unchanged: **an eigenvalue or
a Betti number cannot name the edge that is wrong**, and naming the wrong edge
is the first thing anyone asks of a failing cell.

Persistent homology needs a filtration, and the filtration parameter is a knob
with no principled setting -- precisely the class of knob
[`calibration.md`](calibration.md) §5 forbids as score-shopping. **Rejected, and
not on cost.**

## 5. Measured: resolution, and where it comes from

[`what-ged-measures.md`](what-ged-measures.md) §2 measures the incumbent's
resolution as bits: the Simpson collision probability over exact isomorphism
classes. Repeating that computation for four objects turns "higher-order
structure adds resolution" into a number.

```
uv run python <scratch>/h8_resolution.py            # 91,548 functions, 2m34s
object            classes   collision p   eff. classes   bits    largest class
cfg                  8034      0.091399          10.94   3.45           26,777
cfg + kinds         17843      0.002364         422.95   8.72            3,024
cfg + incidence     17555      0.004384         228.11   7.83            5,103
cfg + defuse        14774      0.005867         170.46   7.41            4,099
all three           19228      0.001577         634.00   9.31            3,024
```

`kinds` here is the CFG certificate refined by each block's statement-**kind**
string -- a cheap stand-in for what the control skeleton adds, using no
identifiers and no operators.

**Statement kinds alone take the corpus from 3.45 bits to 8.72. Adding the full
variable-incidence hypergraph *and* the def-use graph on top of that buys 0.59
bits more.** Each higher-order object *on its own* is worse than the statement
kinds (7.83 and 7.41 against 8.72), and each leaves a larger residual class
(5,103 and 4,099 against 3,024). Two new objects, two new dataflow analyses, and
a 6.8% improvement on a channel the recommendation already owns.

## 6. Measured: the two baselines every metric here must publish

[`calibration.md`](calibration.md) §4 makes the null baseline and the transplant
baseline permanent gates. Both were computed for all four objects.

**Null baseline** -- `int f(void) { return 0; }` scored against every resolvable
published sample source (524 of 539):

```
uv run python <scratch>/h10_cost_null.py
  CFG, node and edge counts equal            129 / 524 = 24.62%
  control skeleton, TED == 0                  23 / 524 =  4.39%   (6 abstentions)
  def-use certificate equal                   62 / 524 = 11.83%
  incidence certificate equal                  0 / 524 =  0.00%   (524 abstentions)
```

The def-use graph's null baseline is **11.83%**, more than twice the control
skeleton's and more than twice `calibration.md`'s 5% ceiling for a headline
metric. The incidence hypergraph's cannot be computed at all: the null
decompiler's body mentions no variable, so the object is empty and abstains on
every single function. **A metric that abstains on the null decompiler cannot
pass the gate that exists to catch metrics like it.** That is disqualifying on
its own.

**Transplant baseline** -- the share of functions that have a same-binary
neighbour sharing their certificate, i.e. for which emitting the wrong body
scores perfect:

```
uv run python <scratch>/h12_null.py <certs>
  object     all 91,548           >= 4 CFG nodes (53,379)
  cfg        54,696  59.75%       17,325  32.46%
  kinds      23,029  25.16%        2,937   5.50%
  incidence  25,741  28.12%        3,771   7.06%
  defuse     42,891  46.85%       12,935  24.23%
```

The CFG row reproduces [`what-ged-measures.md`](what-ged-measures.md) §4 (58.61%
and 32.46%) from an independent implementation. Statement kinds cut the
wrong-body attack from 32.46% to 5.50% at four nodes and up; the incidence
hypergraph reaches 7.06%; the def-use graph only reaches 24.23%. **On the attack
that says "a perfect score does not identify a function", the def-use graph is
closer to the incumbent than to the recommendation.**

**Degeneracy on the decompiled side**, over the real cells of `samples.json`:

```
uv run python <scratch>/h9_degeneracy.py
column          cells   1-node CFG   branchless   no variable
SOURCE            524   129  24.6%   136  26.0%     5   1.0%
ALL DECOMPILED  4,335   895  20.6%   910  21.0%   115   2.7%
```

The hypergraph is undefined for 2.7% of real decompiled cells and 5.76% of the
91,548 published sources (`h12`), which is a *new* abstention class on top of
the one the CFG already has -- it does not rescue degenerate functions, it adds
its own.

## 7. The degenerate class, and the one idea here worth keeping

24,243 of 89,014 functions have a one-node CFG in
[`what-ged-measures.md`](what-ged-measures.md)'s population; **26,783 of 91,548
(29.26%)** in the raw file population measured here. Is there a principled way
to make trivial graphs comparable that is not just "add more node attributes"?
There are two honest answers and they point in opposite directions.

### 7.1 Enriching the object does not work here

Restricting to the 26,783 branchless functions and asking how many distinct
values each invariant assigns:

```
uv run python <scratch>/h7_branchless.py
invariant           distinct values   largest class   share in it
stmt-count                      132           4,143       15.47%
distinct-vars                    51           5,109       19.08%
kind-string                   1,861           3,030       11.31%
incidence-WL                  1,928           5,109       19.08%
defuse-WL                       872           4,099       15.30%
incidence + defuse            2,377           3,030       11.31%
```

The kind string -- which on a branchless function is exactly what the control
skeleton reduces to, a string over `{Assign, Call, Return, Expr, ...}` compared
by string edit distance -- splits the class into 1,861 pieces with a largest
class of 11.31%. The incidence hypergraph splits it into slightly more pieces
(1,928) but leaves a largest class of **19.08%**, because its coarsest cell is
"functions whose statements touch the same small number of variables". The
def-use graph is worse on both counts. Combining all three does not move the
largest class at all: the residual 3,030 functions are those whose published
block carries no statement, and no invariant of statement structure can split
something that has no statements.

**Higher-order structure discriminates finely where discrimination is cheap and
collapses where it is expensive.** That is the wrong shape for a metric, and it
is the same shape the CFG has, one level up.

### 7.2 Null-model correction is the principled framing, and it needs no new object

The degenerate class is not a defect of the *object*. It is a defect of the
*aggregation*: a verdict is being scored as if every cell carried the same
information, when the information in a cell depends on how many other functions
could have produced the same answer by accident. The statistical fix is the
adjusted-for-chance construction that the Adjusted Rand Index uses, applied per
cell.

For an indicator metric over object `O`, define the chance agreement
**conditional on the source function** under a size-matched null model:

```
E[S | f] = (band-mates sharing f's certificate - 1) / (band-mates - 1)
```

with bands the ones `tools/source_cfg_census.py` already uses
(`1, 2-3, 4-7, 8-15, 16-31, 32-60, >60`). The adjusted value of a cell is then

```
A(f, g) = (S(f, g) - E[S | f]) / (1 - E[S | f])
```

which is 1 for a correct answer that was hard, near 0 for a correct answer that
was chance, and negative for a wrong answer. Where `E[S | f] == 1` -- every
band-mate shares the certificate -- the expression is `0/0` and the cell carries
no information: it must **abstain**, not score. That is the principled version
of "the singleton class is 27% of the corpus", and it generalizes
[`tools/metric_stratify.py`](../../../tools/metric_stratify.py)'s marginal
`skill = (perfect% - null%) / (100% - null%)` from the column to the cell.

Measured over the 91,548 published sources:

```
uv run python <scratch>/h12_null.py <certs>
object   mean E[S|f]   cells with E > 0.5     cells with E == 1   median bits
cfg           0.3357   26,777  (29.25%)          0  (0.00%)              5.11
kinds         0.0085        0  ( 0.00%)          0  (0.00%)             10.90
incidence     0.0158        0  ( 0.00%)          0  (0.00%)             10.62
defuse        0.0233        0  ( 0.00%)          0  (0.00%)              8.82
```

**For 26,777 of 91,548 functions a GED-perfect verdict is more likely than not
under a size-matched null model.** That is the 3.64-bits finding restated as a
per-cell quantity a report can actually publish, and it is the strongest single
argument for the aggregation fix that
[`structural-metrics.md`](structural-metrics.md) §1 already puts first.

It also settles the higher-order question one more way: once the object is the
CFG refined by statement kinds, **no cell in the corpus has chance agreement
above 0.5**. The degenerate-cell problem is already solved by the landed metric.
The higher-order objects have nothing left to solve, and they solve it worse
(10.62 and 8.82 median bits against 10.90).

## 8. What is computable on 85,645 cells

The scoreboard is 85,645 stored GED cells
([`README.md`](README.md)); a metric has to run on all of them, deterministically,
twice, and agree with itself.

Measured cost, native calls only, over the 4,267 resolvable source/decompiled
pairs of `samples.json`, on the stale-but-current extension described in §1:

```
uv run python <scratch>/h10_cost_null.py
parity CFG (decompiled side)      484.5 us/pair   ->  41.5 s for 85,645 cells
skeleton + Zhang-Shasha TED     2,073.7 us/pair   -> 177.6 s for 85,645 cells
```

Single-threaded, on a machine that was not quiet. The two overlays were measured
at 3,711 and 3,116 us/pair, but those are **pure-Python proxies and the numbers
are not comparable** to the native ones; they are quoted only to say that
nothing here is bounded by the certificate computation.

Cost is not the reason to reject this family, and it is important to say so
plainly, because the honest reason is worse. Here is the table:

| step | complexity | deterministic | already exists |
|---|---|---|---|
| build the CFG | linear in the AST | yes | yes, [`src/csource/cfg/`](../../../src/csource/cfg/mod.rs) |
| dominators / post-dominators | `O(n a(n))` Lengauer-Tarjan | yes | no, but standard |
| reaching definitions | bit-vector fixpoint, `O(n * m * vars / w)` | yes | yes over LLIR, [`src/ir/use_def.rs`](../../../src/ir/use_def.rs) and [`src/ir/ssa.rs`](../../../src/ir/ssa.rs) |
| 1-WL certificate of any of the above | `O(r (n + m))` | yes | no, but trivial |
| **a graded distance between two of them** | **graph matching: NP-hard** | -- | -- |
| Zhang-Shasha on ordered trees | `O(n1 n2 min(depth, leaves)^2)` | yes | yes, [`src/metrics/tree_distance.rs`](../../../src/metrics/tree_distance.rs) |

**Constructing a higher-order object is cheap. Comparing two of them gradedly is
exactly the NP-hard problem [`structural-metrics.md`](structural-metrics.md)
§2.1 already rejected**, on a graph that is *larger* than the CFG rather than
smaller. The tree distance escapes that only because trees are *ordered* and
source order is canonical, so there is nothing to match.

And the escape does not generalize. To make a hypergraph distance polynomial you
must impose a canonical order on its hyperedges, and the only canonical order
available is source order -- at which point the hypergraph is a sequence of
statements with variable annotations, which is the control skeleton with
attributes on its leaves. **Higher-order structure, made computable, degenerates
into the thing that is already built.** That is the deepest reason this family
does not pay, and it is why the answer would still be no if all four objects
were free.

There is one twist worth stating, because it cuts against a "too expensive"
framing. Stage **S4 landed at `f15d179e`** ("csource: S4 -- lower C to LLIR, and
execute it against the lifted binary",
[`src/csource/lower/mod.rs`](../../../src/csource/lower/mod.rs)). With C lowering
to `LlirFunction`, [`src/ir/use_def.rs`](../../../src/ir/use_def.rs) gives a
def-use index over the C side essentially for free. So a data-dependence overlay
is now *cheap to build and still worthless*, which is a stronger conclusion than
"expensive and unproven". It also sharpens the opportunity cost: the same
landed prerequisite buys either an overlay that detects 0 of 1,197
expression-level defects, or the Tier 1 behavioural agreement of
[`semantic-metrics.md`](semantic-metrics.md) §2, which detects all six of those
classes with one well-chosen input each. Building the overlay would be spending
S4 on the worse of the two things it unlocked.

## 9. The recommendation

**Do not build a program dependence graph, a hypergraph, or a simplicial complex
as a decompiler-quality metric. The landed control-skeleton tree distance plus
the semantic tier that S4 now unblocks dominates every candidate in this
family.** In priority order, with the evidence:

1. **Do nothing new, structurally.** The tree distance already scores 100% on
   `drop-call`, the only class the dependence overlays win over the CFG (§3); it
   already takes the corpus from 3.45 to 8.72 bits, where the two higher-order
   objects together add 0.59 (§5); it already cuts the wrong-body attack to 5.50%
   at four nodes and up, where the def-use graph reaches only 24.23% (§6); and it
   already leaves no cell in the corpus with chance agreement above 0.5 (§7.2).
2. **Adopt the per-cell null-model correction of §7.2**, and make abstention at
   `E[S|f] == 1` a rule. It is arithmetic over data already published, it needs
   no new object, and it is the principled form of the degenerate-graph
   complaint. This is the one thing in the higher-order family worth taking, and
   it is not an object -- it is a denominator.
3. **Spend the effort on M4 instead**
   ([`roadmap.md`](roadmap.md) §6). Every argument above ends at the same wall:
   1,197 expression-level defects, zero detected, no structural object can do
   better. S4 has landed; the blocker named in that plan is gone.
4. **If a diagnostic is wanted anyway**, prefer the adjacency-aware graded CFG
   distance of [`structural-metrics.md`](structural-metrics.md) §2.1 over any
   dependence overlay. It reuses `solve_assignment` in
   [`src/syntax/ged.rs`](../../../src/syntax/ged.rs) with its determinism
   contract, and it answers the question a developer actually asks -- *which
   edge* -- which no certificate over any higher-order object can answer at all.

**What would change this conclusion.** A corpus in which statements routinely
had arity three or more (§4 measures 15.66%); a defect class that changes the
incidence relation without changing the statement sequence, which none of the
29 catalogued classes does; or a decompiler column whose output preserved
statement identity, which §3.3 shows none does -- the median decompiled function
carries 1.75x to 7.19x the assignments of its source in ten of twelve columns,
so any statement-indexed object is measuring temporary-introduction style before
it measures anything else.

## 10. What could not be determined offline, and the proxy's limits

**The `defuse` specificity numbers are proxy-limited.** The scratch overlay
segments C textually on `;`, `{` and `}` and resolves reaching definitions by
"last def in text order", which is exact on a branchless function and wrong
across a back edge. The four rows named in §3.2 would not move under a real
PDG. The **sensitivity** numbers do not have this weakness: the ten
expression-level classes leave the def and use *sets* untouched by
construction, so 0 of 1,197 is a property of the object, not of the segmenter.

**No decompiled side exists for the 91,548-function corpus.** Every decompiled
artifact in the materialized tree is Glaurung's own output -- the caveat
[`structural-metrics.md`](structural-metrics.md) §4 already carries. So the
corpus-wide numbers in §4, §5, §6 and §7 are about *ground truth*, and the only
multi-backend population available is `samples.json`'s 4,385 cells.

**Human agreement is unmeasurable here.** There are no human labels in the
corpus. Whether a dependence overlay agrees better with "would I trust this to
understand the function" is R1 in [`roadmap.md`](roadmap.md) §8 and stays open.

**A native overlay's cost is unmeasured.** §8's overlay timings are Python.

**The tree metric's own specificity is worse than the incumbent's** -- 83.2%
against 95.3% on the full catalogue -- and the largest contributors are
`if-else-swap` (81.0%, deliberately accepted in
[`structural-metrics.md`](structural-metrics.md) §2.6), `redundant-else` (100%)
and `incr-expand` (100%), none of which the M2 gate in
[`roadmap.md`](roadmap.md) §4 lists. Its `goto-ify` row is 100%, which the
catalogue labels a false alarm and
[`structural-metrics.md`](structural-metrics.md) §2.6 celebrates as the metric's
headline win. **The same measurement is being read two ways**, and which reading
is right is a decision about whether goto-ification is a defect, not a
measurement. That is outside this document's question but it is on the same
table, and it should be settled before the tree metric's specificity is quoted.

### The definitions the scratch scripts turn on

The two overlays are defined by three things, stated here so the measurements
can be re-derived without the scripts. Everything else is bookkeeping.

* **Variables.** All identifiers in a statement, minus the C keywords and minus
  any identifier immediately followed by `(` (a callee name is not a variable).
  Identifiers are never used as labels -- only as anonymous vertices -- so every
  object is invariant under renaming by construction, which the `rename-param`
  row confirms empirically.
* **Defs.** The identifier left of a simple `=` (the last one when the left side
  is a plain declarator, so `T x = e` defines `x`; the first one when the left
  side contains `[`, `.`, `->` or a leading `*`, so `a[i] = e` defines `a`), plus
  any identifier carrying `++` or `--`.
* **The certificate.** Three rounds of joint 1-WL refinement in which a colour is
  a *global* hash of `(own colour, sorted multiset of (edge kind, neighbour
  colour))` -- global, not a per-graph renumbering, or the certificates of two
  different graphs are not comparable. The certificate is the hash of the sorted
  final colour histogram. This implementation reproduces the corpus's 8,034
  isomorphism classes (§1), which is the check that it is right.

## Related

* [`structural-metrics.md`](structural-metrics.md) -- the six candidates this
  document is the seventh family for, and the recommendation it defends.
* [`what-ged-measures.md`](what-ged-measures.md) -- the audit whose 3.64-bit and
  32.46% figures §1 reproduces independently.
* [`semantic-metrics.md`](semantic-metrics.md) -- where the ceiling this document
  re-derives is actually broken.
* [`calibration.md`](calibration.md) -- the null and transplant gates §6 applies.
* [`../static-c-analysis/roadmap.md`](../static-c-analysis/roadmap.md) -- S4,
  landed, and S5.
