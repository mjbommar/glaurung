# Cross-decompiler structure: what Ghidra and angr do on our own corpus

> **Kind:** design · **Status:** maintained

Every structural number this programme has published compares our decompiled C
against the fixture *source*. That answers "how far are we from the source" and
it cannot answer "is that distance normal", because the only other reference
point in the estate is the null decompiler. `tests/test_decompiler_fixture_*`
and the structure census in
[`../../../tools/fixture_structure_census.py`](../../../tools/fixture_structure_census.py)
both stop there.

So the structural gate could say we are worse than a `return 0;` stub and could
not say whether a mature decompiler would look any better. This page closes
that gap by running **Ghidra 12.1.3** and **angr 9.2.213** over the same fixture
binaries and scoring all three columns with the same instrument.

## Method

* **Corpus.** Every `*-gcc-O0.so` in `tests/decompiler_fixtures/build/build.aside`
  (206 binaries), restricted to `manifest.REQUIRED_FUNCTIONS`. The `gcc-O0` lane
  only: at `-O2` the source skeleton is not the decompiler's target, so a low
  score there is a joint statement about the compiler and the decompiler
  (`fixture_structure_census.py`'s own caveat).
* **Instrument.** `src/metrics/tree_distance.rs` through PyO3 — `metrics.skeletons`
  to project a control skeleton from arbitrary C text, `metrics.tree_edit_distance`
  and `metrics.skeleton_score` to compare. The identical projection the structural
  gate uses on our own output, applied unchanged to foreign C. No backend is
  scored by a rule invented for it.
* **Denominator.** The intersection: functions every backend produced *and* that
  have a source skeleton. 709 functions. Coverage differences cannot flatter
  anyone.
* **Reference.** The null decompiler (`int f(void) { return 0; }`, skeleton
  `(seq return)`) scored on the same 709.

Columns are built by
`~/.cache/glaurung/structcmp/{run_glaurung,assemble_ghidra}.py` and compared by
`compare.py` in the same directory.

## Coverage and cost

| backend | fixtures | functions | missing | failed | wall |
|---|---|---|---|---|---|
| glaurung | 206 | 751 | 0 | 0 | **30 s**, single process |
| ghidra 12.1.3 | 206 | 751 | 0 | 0 | 3 m 45 s, 10-way parallel, one JVM per binary |
| angr 9.2.213 | 206 | 747 | 4 | 4 | 81 s |

Cost is a result, not an aside: the reason the DecBench matrix takes hours is
that Joern and Ghidra each pay a JVM per file.

## Results

| backend | exact | exact% | median dist | mean dist |
|---|---|---|---|---|
| **glaurung** | 156 | **22.0%** | 6.0 | 11.17 |
| angr | 141 | 19.9% | 6.0 | 13.57 |
| ghidra | 79 | 11.1% | **5.0** | **8.86** |
| NULL (`return 0;`) | 91 | 12.8% | 7.0 | 14.31 |

Constructs per function, same 709:

| backend | goto | break | continue | switch | do | while | `?:` |
|---|---|---|---|---|---|---|---|
| glaurung | **0.869** | 0.103 | 0.000 | 0.031 | 0.004 | 0.188 | 0.566 |
| ghidra | 0.063 | **0.286** | 0.000 | 0.035 | 0.017 | 0.103 | **0.000** |
| angr | 0.269 | 0.142 | 0.006 | 0.051 | 0.007 | 0.086 | 0.616 |

### Report medians, not means

Means here are dominated by a handful of functions. Adding angr's column drops
four functions from the shared set, three of them enormous
(`151_wide_branch_ladder::big151_branch_ladder` at 1,678 source nodes,
`154_wide_switch::wide154_dense_switch` at 517, `wide154_sparse_switch` at 406),
and Ghidra's mean distance moves 12.97 → 8.86 on that alone. The medians barely
move. Any claim built on the mean of this population is fragile; the earlier
working claim that closing the goto gap would put our mean "ahead of Ghidra
outright" was such a claim and does not survive medians.

One of those four is worth keeping in view: on `wide154_dense_switch` we score
**distance 0** — exact — where Ghidra scores 515 and emits 256 `break`s.

## What this establishes

**1. We lead on exact structural recovery.** 22.0% against angr's 19.9% and
Ghidra's 11.1%. Ghidra is *below* the null decompiler on this measure, which is
the same trivial-class effect [`what-ged-measures.md`](what-ged-measures.md)
documents for GED: 91 of the 709 source functions project to `(seq return)`, and
a tool that never emits a bare `return` cannot collect them.

**2. On 87% of functions we are the best of the three.**

| bucket | n | glaurung | ghidra | angr |
|---|---|---|---|---|
| we emit no goto | 618 (87%) | med 5.0, **25.2%** exact | med 5.0, 12.8% | med 5.0, 22.0% |
| we emit goto | 91 (13%) | med **22.0**, 0% | med 8.0, 0% | med 7.0, 5.5% |

Identical median distance to both, and the highest exact rate.

**3. The entire deficit is goto-ification, and it is a breadth problem.** Our
median distance on the affected functions is 22.0 against 7–8 for both others.
But note angr emits *more* gotos per affected function than we do (191 gotos
across 17 functions, ~11 each; ours 616 across 91, ~6.8 each). The difference is
how often: **12.8% of functions for us, 3.1% for Ghidra, 2.4% for angr.** We do
not goto worse; we goto four to five times more often.

**4. Ghidra shows the mechanism.** It emits `break` at 0.286/fn against our
0.103 and almost no `goto` at all. Converting an exit edge into a `break` is the
substitution we are not making.

**5. Two of our supposed defects are not ours.** `continue` is recovered zero
times by Ghidra as well as by us, and angr manages 0.006/fn — on this corpus it
is not a differentiator. And Ghidra emits **no ternaries at all** where we manage
0.566/fn; the "short-circuit and ternary" gap recorded against us is a gap
Ghidra has more severely.

## A warning about cross-corpus comparison

The first version of this analysis used DecBench's `samples.json`, where Ghidra
shows **8.53 goto/function** against source's 0.81. Read across corpora that
suggested goto inflation was industry-normal and our 0.875/fn was unremarkable.
Matched on the same functions, Ghidra emits **0.065**. The DecBench figure is
high because those functions are real-world code and far more complex, not
because Ghidra structures them badly.

Ratios do not rescue this either: goto count tracks control-flow complexity, and
so does the source's own goto count, so neither the rate nor the inflation
factor transfers between corpora. Only matched functions answer the question.
This is the same denominator error [`interpreting-results.md`](interpreting-results.md)
records for DecBench's own scoreboard, arrived at from the opposite direction.

## Reproducing

```
export TMPDIR="$HOME/.cache/glaurung/tmp"
uv run python tools/cross_decompiler_structure.py collect --backend glaurung
# ghidra sweep is external, one JVM per binary:
#   analyzeHeadless <proj> P -import <so> -scriptPath ~/glaurung-ghidra \
#     -postScript DumpCStruct.java ~/glaurung-ghidra/dump/<stem>.txt \
#     -deleteProject -readOnly
uv run python tools/cross_decompiler_structure.py collect --backend ghidra \
    --ghidra-dumps ~/glaurung-ghidra/dump
uv run python tools/cross_decompiler_structure.py compare
```

The angr column comes from a sweep in an isolated environment -- angr is
deliberately not a project dependency -- and only has to match the column schema
in the tool's docstring.

Construct counts above are keyword regexes over the C text with comments and
string literals stripped. `glaurung.source` (`docs/reference/source-metrics.md`)
now exposes per-function `node_kinds`, `cognitive` and `max_nesting` from the
parsed CFG; rerunning the 91-function bucket through that would replace the
regex with one definition across all three backends and say whether those
functions separate on nesting depth or are a particular shape. Not yet done.
