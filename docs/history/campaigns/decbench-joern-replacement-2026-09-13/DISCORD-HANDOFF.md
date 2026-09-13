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
gain of 790 exact cells with no coverage regression.

The apparent coverage gain also needs qualification. Joern reports 76,312
additional names that Glaurung does not, but every graph is one entry-and-exit
node with no edge, and every stored C artifact lacks DecBench's
`// Function:` definition marker for that name. These are declarations/import
prototypes, not executable definitions. There are zero nontrivial Joern-only
graphs. Glaurung reports 24 definition-marked one-node non-returning functions
that Joern omits (`__idle_thread` once and `blocking_handler` 23 times).

After the first correction, 4,371 GED differences remain: 2,783 graph-size
differences, 1,456 entry/exit-role differences, 92 where Glaurung is
source-isomorphic and Joern is not, and 40 where Joern is source-isomorphic and
Glaurung is not. We are treating these as an investigation queue, not claiming
that every difference is a Glaurung defect. In particular, many Joern
multi-entry graphs mark internal nodes with predecessors as entries, which may
be a Joern merge/order artifact rather than source CFG truth.

The complete commands, provenance, limitations, hashes, and follow-up are in
the adjacent `README.md`. Lossless per-function graph ledgers and the
fail-closed joined aggregate are retained locally for review.
