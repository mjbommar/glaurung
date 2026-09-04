# What DecBench's GED actually measures

> **Kind:** design · **Status:** proposed

This is the load-bearing document of the directory. Everything proposed in the
others follows from what is measured here.

The claim, stated up front and defended below:

> **DecBench's `ged` column is a binary indicator of role-labelled CFG
> isomorphism whose positive class is dominated by trivially small functions. A
> "decompiler" that emits `int f(void) { return 0; }` for every function in the
> corpus scores 27.24% GED-perfect — fifth of fifteen columns, above Ghidra,
> Binary Ninja, r2dec, Phoenix, dewolf and every LLM entry.**

All numbers below were computed offline from the materialized DecBench tree at
`~/.cache/glaurung/decbench-full` (dataset revision `e5eb576`, config `full`,
803 binaries, 800 with published source CFGs). **No Joern process and no
DecBench pipeline was run.** The scratch scripts, their exact command lines and
their raw output are in [`evidence.md`](evidence.md); each number below names
the script that produced it.

## 0. There are two GED metrics in the world, and we run the older one

`decbench/metrics/ged.py` has been rewritten once, and the rewrite changed the
meaning of a perfect score.

```bash
cd ~/.cache/glaurung/decbench-full/decbench && \
  git log --oneline --format='%h %ad %s' --date=short -- decbench/metrics/ged.py
```

| commit | date | isomorphism fast path | `max(1.0, raw)` clamp | `GED_MAX_NODES` | `cache_version` |
|---|---|---|---|---|---|
| `fe5990c` | 2026-07-22 | no | no | 60 | 2 |
| `daec037` | 2026-07-27 | no | no | 60 | 2 |
| `bd49c83` | 2026-08-07 | **yes** | **yes** | **200** | 3 |
| `f76dae0` | 2026-08-29 | yes | yes | 200 | 4 |

`bd49c83` is titled *"Fix GED scoring for large isomorphic CFGs (#57)"*. Before
it, `value == 0` meant `vj_ged == 0`, which — as
[`../static-c-analysis/joern-behavior.md`](../static-c-analysis/joern-behavior.md)
§2 proves — means only *the two degree multisets and the two role flags agree*.
After it, the metric runs a colour-refined VF2 isomorphism test first and returns
`0.0` only when the two role-labelled CFGs are genuinely isomorphic, and clamps
every other outcome to at least `1.0`.

**Our fork is at `efc5d5a`, which is on the old side of that line.**

```bash
cd /nas4/data/workspace-infosec/decbench && git log --oneline -1 && \
  grep -n 'GED_MAX_NODES\|cache_version\|_is_isomorphic' decbench/metrics/ged.py
# efc5d5a fix(publish): export per-TU-resolved source CFGs, not a project-wide union (#55)
# 20:GED_MAX_NODES = int(os.environ.get("DECBENCH_GED_MAX_NODES") or "60")
# 43:    cache_version = "2"
#   (no _is_isomorphic anywhere)
```

So `scripts/decbench-local-gate.sh --decbench` computes a *different metric*
from the one that produced the published scoreboard. §2 quantifies how different.

**The published cells use the new semantics.** The scoreboard was generated
`2026-08-19`, after `bd49c83`, and the stored values confirm it independently.
Both versions fall back to `|Δnodes| + |Δedges|` above the cap, and that fallback
is far smaller than `vj_ged`, so the cap shows up as a discontinuity in stored
value against source size. It sits at 200, not 60 (`m3.py`, 3.7 s over 486,965
joined cells):

```
cells with source nodes > 200 whose stored value exceeds n+m:      12 / 1,659  (0.72%)
cells with 61 <= source nodes <= 200 whose value exceeds n+m:   1,513 / 15,110 (10.01%)
```

Under a cap of 60 the second band would be governed by `|Δn| + |Δm|` and would
look like the first. It does not. Two named cells settle it arithmetically. zlib
`inflate_table` has a published source CFG of 88 nodes and 122 edges and a stored
value of `333.0` for the `glaurung-229fbb1-clean` column. Under the fork's cap of
60 the value would be `|88 − dn| + |122 − dm|`; under upstream it is `vj_ged`,
and deleting all 88 source nodes costs `Σ(1 + in + out) = 88 + 2·122 = 332`, plus
`1` to insert a single isolated decompiled node — exactly `333`. zlib `inflate`
(416 nodes, 752 edges) stores `1167.0`, and `415 + 752 = 1167` is precisely the
size-delta against a one-node graph. Both are consistent with the same thing:
**upstream semantics, and a decompiled CFG that collapsed to one node.**

### Consequence for `tools/source_cfg_parity.py`, measured

The parity gate computes bare `vj_ged` (line 238) and diffs it against the stored
cell. It imports `GED_MAX_NODES` only to report it (line 253) and applies neither
the cap, the clamp, nor the isomorphism path. For any cell whose stored value
came from another path, the gate is comparing two different functions and
attributing the difference to the front end.

Measured over the 88,963 stored cells of the `glaurung-229fbb1-clean` column
(`m8.py`):

```
source nodes > 200  (size-delta fallback, unreproducible by raw vj_ged):   273  (0.31%)
stored exactly 1.0  (candidates for the max(1.0, raw) clamp):               85  (0.10%)
stored exactly 0.0  (isomorphism fast path):                            29,463 (33.12%)
cells the fork's cap of 60 would route differently from upstream's 200:  2,547
```

The zeros are safe — isomorphic graphs have equal degree multisets, so raw
`vj_ged` returns 0 for them too. **The defect is real but small: at most 358 of
88,963 cells (0.40%).** It does not explain the parity gap, and it should be
fixed anyway, because a gate that models the wrong function will mislead as soon
as the front end gets good enough for the residue to matter.

## 1. What the cost model can see

`vj_ged` builds an `(n+m) × (n+m)` cost matrix and solves it with an LSAP. Every
cell is a function of four numbers per node — in-degree, out-degree,
`is_entrypoint`, `is_exitpoint` — and nothing else. The proof is in the reference
implementation's shape and is already ported and asserted in
[`src/syntax/ged.rs`](../../../src/syntax/ged.rs) (`degree_multiset_is_the_only_topology_that_matters`).

Two consequences follow immediately, and both are measurable.

**A degree-preserving rewiring is free.** A double-edge swap that replaces edges
`(a,b)` and `(c,d)` with `(a,d)` and `(c,b)` leaves every in-degree and every
out-degree untouched, so `vj_ged` scores the result `0.0` by construction. It
almost always destroys the graph (`m7.py`, 8.9 s):

```
degree-preserving double-edge swaps over 20,000 sampled functions (n>=5, m>=5)
  swaps constructed:                                 19,829
  resulting graph non-isomorphic to the original:    18,720 / 19,829 = 94.41%
  vj_ged score for every one of the 19,829:          0.0
```

**Under the fork's semantics — the ones our local gate runs — 94.41% of these
corrupted control-flow graphs are awarded a perfect score.** Upstream's
isomorphism check catches them. This is the single strongest argument for
retiring the fork's metric rather than reproducing it.

**Nothing above the degree sequence reaches the number.** The published
serialization carries pyjoern's per-block statement dump in `labels`, and
`vj_ged` never reads it. The volume is not marginal (`m6.py`):

```
total statement lines carried in `labels` and never read by any GED path: 5,460,786
```

## 2. What the isomorphism test can see, and what it cannot

Upstream's `_is_isomorphic` runs joint 1-WL colour refinement and then VF2 with
the refined colours as a node-match constraint. It is a correct isomorphism test
for role-labelled digraphs. Two facts about it, measured over the 89,014
non-degenerate published source CFGs (`census.py`, 20.7 s):

```
distinct vj_ged signatures (in/out degree + flag multisets):  6,694
distinct 1-WL certificates:                                   8,034
exact isomorphism classes (VF2 within each WL bucket):        8,034
```

**1-WL is complete on this corpus.** VF2 never split a WL bucket. That is a
useful negative result for [`structural-metrics.md`](structural-metrics.md): a
Weisfeiler–Lehman kernel cannot distinguish anything on these graphs that the
existing isomorphism check does not already distinguish.

The gap between 6,694 and 8,034 is the fork's blind spot expressed on real code:

```
signature classes holding more than one isomorphism class:  632
functions living in one:                                 23,509 of 89,014 (26.41%)
```

Now the harder question. Isomorphism is the *right* equivalence for "same shape".
The problem is that **same shape is a very weak certificate**, because real C
functions are concentrated in a handful of shapes:

```
Simpson collision probability (two random corpus functions isomorphic): 0.080371
effective number of distinct CFG shapes:                                12.44
information in a "GED perfect" verdict:                                 3.64 bits
largest isomorphism classes: 24243, 4967, 3207, 1502, 1396, 1390, 1198, 1051, ...
```

3.64 bits. A perfect GED score tells you roughly as much about a decompiled
function as knowing one hexadecimal digit of its body.

### 2.1 The largest class

The largest isomorphism class is a single node with no edges, flagged both entry
and exit — 24,243 of 89,014 functions (27.24%). It is not a class of trivial
functions. It is the class of functions with no *branches*, whatever their size
(`m5.py`, `m6.py`):

```
1-node / 0-edge / entry+exit class:  24,243 functions
  distinct function names:            5,284
  distinct pyjoern statement bodies:  7,393
  statements per function: min=3  median=7  p75=14  p95=45  p99=136  max=618
  functions in the class with >20 statements: 3,902 (16.1%)
  largest: cleanflight/cleanflight_DALRCF405 [O0] pgResetFn_osdConfig
           618 statements, 38,571 characters of block text
```

`pgResetFn_osdConfig` is 618 straight-line statements. zlib `adler32` is one
line. To this metric they are the same graph, and both are the same graph as
`int f(void) { return 0; }`.

That last equivalence is not an inference from documentation — Glaurung's own
Joern-parity layer confirms the shape it produces:

```bash
uv run python -c "
from glaurung.source_cfg import parity_cfgs
print(parity_cfgs('int f(void){return 0;}'))"
# {'f': {'nodes': [0], 'edges': [], 'entry': [0], 'exit': [0], 'degenerate': False}}
```

### 2.2 The null decompiler

Score that constant body against every benchmark function that has a
non-degenerate published source CFG (`m4.py`). The rule applied is upstream's:
perfect iff the role-labelled CFGs are isomorphic.

```
benchmark functions joined to a non-degenerate published source CFG: 89,014

decompiler          perfect   scored  perfect%   perfect% over all 89,014
ida                   32586    81900    39.79%                     36.61%
kuna                  32952    84241    39.12%                     37.02%
angr                  30924    83584    37.00%                     34.74%
binja                 18323    55997    32.72%                     20.58%
ghidra                22716    72961    31.13%                     25.52%
NULL (return 0;)      24243    89014    27.24%                     27.24%
r2dec                 15508    59555    26.04%                     17.42%
phoenix                8387    34428    24.36%                      9.42%
dewolf                 2808    13193    21.28%                      3.15%
```

The null decompiler has 100% coverage, so its 27.24% is on the full denominator
while every real column's first percentage is on a smaller one. On the common
denominator it places **fifth of fifteen**, above Ghidra (25.52%) and below the
`glaurung-229fbb1` column (29,463 / 88,963 = 33.12%, which
`published_function_results.json` does not carry). Carried into the
published Union scoreboard — GED is 69 of Glaurung's 82 Union points
([`../../development/decompiler-testing.md`](../../development/decompiler-testing.md))
— it would score `24,243 / 94,423 = 25.67%` Union, again sixth, between Ghidra
(27.07%) and Binary Ninja (23.44%).

**Nothing about this is a trick.** The null decompiler is not gaming a
tie-break or exploiting a parser bug. It is producing, for a quarter of the
corpus, exactly the graph the metric asks for.

## 3. Where the score comes from

Because the metric is an indicator, it has no way to say "nearly right", and the
functions it *can* say `perfect` about are almost all the ones with no control
flow. Perfect cells by source CFG size, pooled over all thirteen columns
(`m4.py`):

```
source nodes    cells   perfect%   non-zero values: p10   p50    p90     max
        =1     123273     90.36%                    8.0  13.0   52.0    785
      2..3      59823     35.77%                    3.0   6.0   12.0    446
      4..7     103278     20.26%                    3.0   8.0   20.0  11907
     8..15      98130      8.66%                    4.0  11.0   34.0   1148
    16..31      59731      3.40%                    6.0  18.0   68.0   1037
    32..60      25961      1.10%                   11.0  32.0  120.0   3938
      >=61      16769      0.44%                   19.0  69.0  291.0   5378
```

Per column, the share of each decompiler's perfect cells contributed by each size
band (`m5.py`):

```
decompiler      perfect | n=1     n in 2..3  n in 4..7   n>=8
kuna              32952 |  62.9%     14.8%      14.5%     7.8%
ida               32586 |  62.5%     13.7%      14.7%     9.1%
angr              30924 |  68.0%     12.8%      12.2%     7.0%
ghidra            22716 |  72.6%     11.4%      11.6%     4.5%
binja             18323 |  65.5%     14.8%      13.3%     6.4%
r2dec             15508 |  77.7%     11.6%       9.1%     1.6%
phoenix            8387 |  68.2%     11.4%      12.1%     8.3%
dewolf             2808 | 100.0%      0.0%       0.0%     0.0%
glaurung-229fbb1  29463 |  64.2%     13.4%      14.9%     7.5%
```

**Between 62.5% and 100% of every column's GED score comes from functions with a
single-node CFG, and no column earns more than 9.1% of its score on functions
with eight or more.** The dewolf row is the reductio: its entire GED standing is
branchless functions.

Above 16 nodes the metric is effectively a constant: it says `not perfect`
96.6% of the time, and the magnitude it reports instead is a degree-sequence
artefact that never reaches the scoreboard, because the scoreboard aggregation is
`perfect_percentage` (`decbench/models/metrics.py`, `MetricResult.compute_aggregates`;
`GEDMetric.default_aggregation = AggregationType.PERCENT`, `perfect_value = 0.0`).

## 4. The wrong-body attack

A perfect score does not identify a function. For a majority of the corpus,
another function *in the same binary* has an isomorphic CFG, so emitting the
wrong body scores perfect (`m7.py`):

```
functions with a CFG-isomorphic twin in the same binary: 52,167 / 89,014 = 58.61%
  restricted to functions with >= 4 CFG nodes:           17,325 / 53,379 = 32.46%
```

Real pairs, all at eight nodes or more, all in the same binary:

```
base-passwd/update-passwd [O0]  read_passwd   ~  read_group    (n=15, m=19)
base-passwd/update-passwd [O0]  write_passwd  ~  write_shadow  (n=15, m=17)
base-passwd/update-passwd [O0]  write_group   ~  write_passwd  (n=15, m=17)
bash/bash [O0]                  all_digits    ~  strvec_search (n=8,  m=9)
bash/bash [O0]                  xrealloc      ~  sh_xrealloc   (n=8,  m=13)
bash/bash [O0]                  sh_mktmpdir   ~  sh_mktmpname  (n=12, m=16)
```

`all_digits` and `strvec_search` do entirely different things. A decompiler that
confused them would lose nothing on this metric.

## 5. Defect injection: the measured ceiling

The previous sections show the metric is weak. This section shows it is weak in a
way no *structural* metric can fix, which is the finding that drives
[`semantic-metrics.md`](semantic-metrics.md).

The instrument is the 300 `samples` records in
`~/.cache/glaurung/decbench-full/published_function_results.json`, each carrying
the real `source_code` of one benchmark function. Each source is parsed by
Glaurung's own C front end (`glaurung.source_cfg.parity_cfgs` — the landed S3
layer, no Joern), mutated at the source level, and reparsed. 285 of 300 parse,
resolve the named function, and yield a non-degenerate CFG.

`GED says perfect` is the fraction of mutants whose CFG is isomorphic to the
original's — that is, the fraction of injected defects a decompiler could ship
with no score penalty (`mutate.py`; extension `python/glaurung/_native.cpython-314-x86_64-linux-gnu.so`
as built at 2026-09-04 10:26 — build profile not verified, and it does not affect
a parse):

```
mutation            applied   GED says perfect     vj_ged==0     n/a  unparsed
relational-flip         122    121 ( 99.2%)   121 ( 99.2%)      163         0
equality-flip           137    137 (100.0%)   137 (100.0%)      148         0
logic-flip              104     98 ( 94.2%)    98 ( 94.2%)      181         0
arith-flip               67     67 (100.0%)    67 (100.0%)      218         0
constant-bump           174    174 (100.0%)   174 (100.0%)      111         0
negate-condition        191    191 (100.0%)   191 (100.0%)       94         0
null-body               279     73 ( 26.2%)    73 ( 26.2%)        0         6
while->if                56     18 ( 32.1%)    19 ( 33.9%)      229         0
drop-break               48      6 ( 12.5%)     6 ( 12.5%)      237         0
else->if(0)             111     26 ( 23.4%)    26 ( 23.4%)      174         0
```

Read the top six rows as one statement: **a decompiler that inverts every
condition, flips every comparison, turns every `+` into `-` and changes every
constant is, to GED, a perfect decompiler.** Those defects do not change the
control-flow graph, and they do not change the recovered AST's *shape* either,
so no structural metric of any kind will ever see them.

Read the bottom four rows as a second statement: even mutations that *do* change
control flow escape 12.5% to 33.9% of the time.

And read the `null-body` row as a cross-check: replacing an entire function body
with `return 0;` goes undetected on 26.2% of the 279 samples where it applied —
independent confirmation of the 27.24% corpus-wide figure from a different
population and a different code path.

## 6. What this does and does not license

**Measured, and safe to quote:** everything in §1 through §5, with the script
named beside it and the raw output in [`evidence.md`](evidence.md).

**Read, not measured:** the pyjoern and Joern behaviour summarized in
[`../static-c-analysis/joern-behavior.md`](../static-c-analysis/joern-behavior.md);
this document did not run Joern and cannot confirm what Joern emits for any
particular C text. Where §2.1 claims `int f(void){return 0;}` yields a one-node
entry+exit CFG, the confirmation came from Glaurung's parity layer, which is a
*reimplementation* scoring 72.88% exact against the oracle — strong evidence, not
proof.

**Inferred:** that the decompiled CFGs behind zlib `inflate` (1167.0) and
`inflate_table` (333.0) collapsed to a single node. The arithmetic matches to the
unit in both cases, but the decompiled CFGs themselves are not in the tree.

**Not determined offline:** whether any of the proposed replacements agrees
better with human judgement (there are no human labels in the corpus), and what a
semantic metric costs per function (stage S4 is not built).

## 7. The three things that follow

1. The headline aggregation is wrong before the distance is wrong. An indicator
   over an equivalence with 3.64 bits of resolution cannot rank decompilers, and
   stratifying it by function size is free. → [`structural-metrics.md`](structural-metrics.md) §1.
2. Structural metrics have a measured ceiling at "detects zero of six
   semantics-only defect classes". Further structural work buys the four
   *structural* mutation rows and nothing else. → [`semantic-metrics.md`](semantic-metrics.md).
3. The null-decompiler baseline is the cheapest possible metric audit, it cost
   one afternoon, and it should be a standing published number for every metric
   forever. → [`calibration.md`](calibration.md) §4.
