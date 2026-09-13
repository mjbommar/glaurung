# Joern versus Glaurung: executive summary

> **Kind:** record · **Date:** 2026-09-13

## Outcome

Glaurung is a credible replacement for the Java Joern/pyjoern source-CFG
frontend on this pinned DecBench corpus. It covered every executable definition
present in the stored C, produced no extra declaration names, and completed the
strict scored pass roughly 196 times faster than the sum of the checkpointed
Java shard wall times while using far less peak memory.

Java remains the exact implementation of DecBench's stored source-CFG oracle:
it reproduced all 85,645 stored GED cells. Glaurung reproduced 81,524 cells,
or 95.1883%. That remaining 4.8117% is not an unexplained failure bucket. Every
difference was assigned to a measured structural class, and several large
classes reflect Joern-specific representation choices or defects that should
not be copied into Glaurung's general CFG.

## Headline comparison

| Measure | Java Joern/pyjoern | Glaurung |
|---|---:|---:|
| Scored binaries | 785/785 | 785/785 |
| Scored GED cells attempted | 85,645 | 85,645 |
| Agreement with stored Joern GED | 85,645 (100%) | 81,524 (95.1883%) |
| Uncovered cells | 0 | 0 |
| Provider failures | 0 | 0 |
| Full stored-C definition coverage | 94,334/94,358 | **94,358/94,358** |
| Names beyond definition markers | 78,902 | **0** |
| Nontrivial extra graphs | 0 | 0 |
| Scored wall time | 11,716.9 s summed over 79 shards | **59.74 s** |
| Peak measured RSS | 9,255,808 KiB | **339,952 KiB** |

The timing commands, execution model, and limitations are recorded in
[PERFORMANCE.md](PERFORMANCE.md). The denominator derivation is in
[COVERAGE-AND-SCORING.md](COVERAGE-AND-SCORING.md).

## What improved during the comparison

The first Glaurung full pass matched 80,484 of 85,645 cells (93.9740%). Four
broad, semantics-based compatibility corrections raised this to 81,524
(95.1883%), a net gain of 1,040 exact cells:

| Correction | Exact cells after correction | Net gain |
|---|---:|---:|
| Initial replacement | 80,484 | - |
| Parallel-edge normalization | 81,274 | +790 |
| Constant-true-loop handling | 81,501 | +227 |
| Literal-`if` granularity | 81,515 | +14 |
| Ternary nested in loop condition | 81,524 | +9 |

These were not fixture-name special cases. Each correction expresses a general
CFG rule, has focused positive and negative controls, and was followed by a
complete 85,645-cell rerun. A broader ternary rewrite that regressed 162 exact
cells was rejected rather than tuned around its score.

## What the remaining differences mean

The final 4,121 GED differences comprise:

- 1,457 equal-size graphs whose only metric-visible difference is entry/exit
  role assignment; Java creates multiple entries in every case;
- 2,311 graph-size differences, overwhelmingly tied to constant-loop policy;
- 313 cases where Glaurung is source-isomorphic and Java is not;
- 40 cases where Java is source-isomorphic and Glaurung is not.

All 40 apparent Java wins were inspected: 35 erase a reachable `while (1)`
cycle, three add merge-order-dependent entry flags, and two retain infeasible
loop exits. The remaining graph-size tail was also classified, including 12
cases where Java loses a reachable non-returning cycle and ten expression-
granularity cases where Glaurung preserves the branch structure and has lower
source GED. See [DIFFERENCE-REVIEW.md](DIFFERENCE-REVIEW.md).

## Bottom line

For exact compatibility with a Joern-generated oracle, Java necessarily scores
100% and Glaurung scores 95.1883%. For practical source-CFG extraction from the
stored decompiler output, Glaurung has the stronger result in this experiment:
complete definition coverage, no declaration noise, no provider failures, and
substantially lower observed time and memory. This is a source-CFG frontend
comparison, not evidence about binary decompilation quality or semantic
equivalence of reconstructed C.

Nothing in this record authorizes an autonomous DecBench issue, comment, pull
request, or Discord post.
