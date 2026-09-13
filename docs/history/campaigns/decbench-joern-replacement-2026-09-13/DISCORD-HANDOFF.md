# DecBench source-CFG replacement: human handoff

This is a draft for a human to edit and share. An agent must not post it or
create any DecBench issue, comment, or pull request.

We ran the complete published DecBench source-CFG comparison universe with
both Java Joern/pyjoern and Glaurung. Inputs were DecBench
`f76dae075d4d82004fb21132b3f15e43b680e179`, dataset
`e5eb576d66ee36793b800a4dd45e291e0add4472` (`full`), pyjoern 4.0.150.4 /
Joern 4.0.150, and the stored `glaurung-229fbb1-clean` C column.

The manifest has 803 binaries and 94,575 functions, but only 785 binaries and
85,645 stored GED cells have all three artifacts needed to recompute the
metric: published source CFG, stored decompiled C, and stored GED. Another
3,318 stored cells in 15 binaries cannot be recomputed because their source
CFGs are absent from the published tree.

Java reproduced all 85,645 stored values exactly with no provider failure or
uncovered cell. It used 79 checkpointed shards, 11,716.9 seconds of summed
shard wall time, and a peak shard RSS of 9,255,808 KiB.

The initial Glaurung replacement agreed on 80,484/85,645 cells (93.9740%), with
zero uncovered cells, in about 61 seconds and 336 MiB peak RSS. Differential
review found a broad parity-layer bug: parallel true/false edges around empty
branches were deduplicated after, rather than before, Joern-compatible chain
contraction. Fixing that general rule—not any fixture-specific case—and
rerunning the whole corpus raised agreement to 81,274/85,645 (94.8964%), a net
gain of 790 exact cells with no coverage regression. A second general fix
removed infeasible false exits from provably constant-true loops while keeping
their cycles and reachable `break`s. The next complete rerun reached
81,501/85,645 (95.1614%). A third measured Joern granularity fix for bare
literal `if` tests reached 81,515/85,645 (95.1778%), for a cumulative gain of
1,031 exact cells, with no regression in that increment.

The apparent coverage gain also needs qualification. Joern reports 76,312
additional names that Glaurung does not, but every graph is one entry-and-exit
node with no edge, and every stored C artifact lacks DecBench's
`// Function:` definition marker for that name. These are declarations/import
prototypes, not executable definitions. There are zero nontrivial Joern-only
graphs. Glaurung reports 24 definition-marked one-node non-returning functions
that Joern omits (`__idle_thread` once and `blocking_handler` 23 times).

After both corrections, 4,144 GED differences remain. The detailed review has
classified all 40 apparent Java-source-isomorphic wins: 35 are Joern erasing
`while (1)` cycles, three are merge-order entry flags, and two retain infeasible
Java loop-exit edges. All 1,457 role-only differences have the same unlabelled
degree multiset; Java gives every one multiple entries and flags an internal
positive-indegree node in 1,441. Glaurung now matches the published source graph
isomorphically in 313 cases where Java does not. Of 2,334 graph-size
differences, 2,289 are explained constant-loop edge-policy differences. Of the
45 unaffected cases, nine are now traced to duplicated branching for a
value-only ternary nested in a loop condition. A literal-`if` correction makes
14 more exact; 22 unaffected cells remain unclassified.

The complete commands, provenance, limitations, hashes, and follow-up are in
the adjacent `README.md`. Lossless per-function graph ledgers and the
fail-closed joined aggregate are retained locally for review.
