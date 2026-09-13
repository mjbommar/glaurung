# Coverage and scoring results

> **Kind:** record · **Date:** 2026-09-13

## Why there are several denominators

The word "full" is ambiguous in this dataset. This comparison keeps four
populations separate:

| Population | Count | Meaning |
|---|---:|---|
| Manifest binaries | 803 | Every binary named by the full manifest |
| Manifest function names | 94,575 | Every function entry named by that manifest |
| Stored C definitions | 94,358 | Manifest functions with a definition marker providers can parse |
| Recomputable stored GED cells | 85,645 | Cells with stored C, published source CFG, and stored GED |

The 217 manifest names absent from stored C are upstream output omissions, not
frontend misses: neither provider receives a function body to parse. Separately,
18 binaries do not participate in the strict GED recomputation because their
published artifact triples are incomplete. Those 18 files still contain 4,380
definitions, so they were processed by a separate fail-closed coverage pass.

## Strict apples-to-apples GED result

The comparable scored universe contains 785 binaries and 85,645 cells. Both
providers received the identical stored decompiled C and were measured against
the identical published source graph with DecBench's `GEDMetric` policy.

| Result | Java | Glaurung |
|---|---:|---:|
| Attempted | 85,645 | 85,645 |
| Equal to stored GED | 85,645 | 81,524 |
| Different from stored GED | 0 | 4,121 |
| Uncovered | 0 | 0 |
| Provider failures | 0 | 0 |

Java's 100% is expected because the stored source CFG and stored GED were made
through the Java path. It demonstrates that the pinned environment reproduced
the oracle. It does not independently prove that each Java graph is the most
faithful CFG for the C source.

Glaurung's final exact rate is `81,524 / 85,645 = 95.1883%`. The comparison
runner returned a nonzero status while differences remained; that was the
intended fail-closed result, not a parser crash. Every difference has a
lossless graph record and a classification in
[DIFFERENCE-REVIEW.md](DIFFERENCE-REVIEW.md).

## Whole-manifest definition coverage

The strict GED universe cannot answer whether either frontend silently loses
definitions outside the published triples. The 18-file tail pass and the 785
scored-file ledgers were therefore joined against definition markers across all
803 stored C files.

| Full-definition result | Java | Glaurung |
|---|---:|---:|
| Definitions available | 94,358 | 94,358 |
| Definitions reported | 94,334 | **94,358** |
| Missing definitions | 24 | **0** |
| Names beyond definition markers | 78,902 | **0** |
| Extra graphs with more than one node or any edge | 0 | 0 |
| Provider failures | 0 | 0 |

Java's 24 misses are one `__idle_thread` and 23 `blocking_handler` definitions.
Glaurung returns each as a one-node, non-returning graph. Java's 78,902 extra
names are declarations or import prototypes; every graph has one node, zero
edges, and no matching definition marker. They may be useful parser facts, but
counting them as executable coverage would be noise.

## Additional-name interpretation

Within the strict scored ledgers, 4,309 names beyond DecBench's function list
were shared by both providers. Java alone reported another 76,312, all with the
same declaration-like one-node/zero-edge shape. Glaurung alone reported the 24
definition-marked non-returning functions described above. Thus Glaurung loses
no unique nontrivial Java result on the available definitions.

## Limits

- The 3,318 stored GED cells in 15 binaries lacking published source CFGs
  cannot be recomputed from this dataset.
- Another 1,044 NuttX definitions and 18 other definitions have no stored GED.
- Definition coverage proves that a graph was returned, not that its semantics
  are correct.
- GED agreement measures compatibility with the published Joern-derived graph,
  not binary-level or execution-level correctness.
