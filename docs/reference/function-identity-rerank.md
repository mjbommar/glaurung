# Context re-ranking of function-identity candidates

> **Kind:** reference · **Status:** maintained

`glaurung::identity::rerank` is **not a matcher**. It takes the per-function
candidate lists some other identity scheme already produced —
[structural](function-identity-structural.md),
[the CFR](function-identity-cfr.md),
[WARP](function-identity-warp.md), anything that can score a query function
against a reference corpus — and re-orders every list at once, using context no
per-pair comparison can see: which query function calls which, which reference
function calls which, and which reference functions came from the same library.

It is plan item 10 of
[`docs/history/program-measures-2026-09-02.md`](../history/program-measures-2026-09-02.md),
after Ren, Che, Gilman, De Carli and Walls, **"RevDecode: Enhancing Binary
Function Matching with Context-Aware Graph Representations and Relevance
Decoding"** (USENIX Security 2025,
<https://www.usenix.org/system/files/usenixsecurity25-ren.pdf>). It is a
dynamic program, not a model: no training, no random seed, no floating-point
tolerance in the control flow.

## The one-line answer

**Run the call-agreement term; leave RevDecode's provenance terms off.** In 40
measured cells — two schemes, two corpora, twelve tasks, both candidate lanes —
the call term never cost a single query a rank and improved up to 1.8% of them.
The paper's own adjacency and library terms moved 8 cells up and **31 down**,
by as much as 0.225 MRR10. The [measured table](#measured) has the whole grid
and [why](#why-the-papers-provenance-terms-lose-here) has the reading.

**That is what the defaults do**, so the short form is the right form:

```rust
use glaurung::identity::rerank::{rerank, CallContext, Candidate, QueryFunction, RerankSettings};

let decoded = rerank(&queries, &context, &RerankSettings::default());
for layer in &decoded.layers {
    // best first; `reference == None` is the "no match" node
    println!("{} -> {:?}", layer.query, layer.ranked.first());
}
```

```python
from glaurung import analysis

analysis.rerank_candidates(
    [(0, 0x1000, [(10, 0.90), (11, 0.80)]), (1, 0x2000, [(20, 0.80), (21, 0.90)])],
    query_calls=[(0, 1)],
    reference_calls=[(11, 20)],
)
```

`RerankSettings::revdecode_paper()` — or `adjacency_weight=1.0,
library_weight=1.0` from Python — is the paper's own configuration, available
and named because both terms are implemented and faithful. It is not the default
because a default that loses on 31 of 40 measured cells is a trap.

## The graph

One **layer** per query function, in a caller-chosen deterministic order
(`QueryFunction::order_key`; every caller we ship passes the entry VA, which is
what RevDecode orders on). One **node** per candidate in that query's top-K
list, plus one **"no match"** node per layer — the paper's *uncertain* node,
which exists so an incomplete corpus can be answered with "nothing here is it"
rather than with the least bad wrong answer. A start node before the first
layer, an end node after the last, and an edge from every node in layer `j-1`
to every node in layer `j`.

**K defaults to 10**, because MRR10 and every Recall@k a retrieval protocol
reports live inside the first ten candidates. Ties at the K-th place are *all*
admitted: without that, an arbitrary index tie-break rather than the decode
would decide which candidate got a chance, and the decode would collect credit
for it.

### Edge weights

Each term lands in `[0, 1]` and carries its own weight in `RerankSettings`.

| Term | Depends on | Formula | In the paper |
|---|---|---|---|
| similarity | destination candidate | the underlying matcher's score, optionally through a logistic | yes |
| confidence | destination candidate | a TF-IDF sum over shared minus unique features | yes (Eq. 7) — **socket only, see below** |
| library | destination candidate's library | `1 - n_library / n_corpus` | yes (Eq. 8) |
| adjacency | both endpoints' libraries | `0.7` when they match, else `0` | yes (Alg. 1) |
| call agreement | both endpoints, and both call graphs | matched call directions / directions present in the query pair | **ours** |

Call agreement is asymmetric on purpose. If query `A` calls query `B` and
candidate `a` calls candidate `b` in the reference corpus, the pair scores
`1.0`; if the corpus edge runs the other way it scores nothing. Direction is
most of what a call edge says. Mutual recursion reproduced in one direction only
scores `0.5`. A query pair with **no** call relation scores `0.0` — no evidence,
never evidence against, which matters because a call graph recovered from
discovery is a lower bound: an unresolved indirect call contributes no edge.

### The decode

Forward pass (RevDecode Eq. 1–3, with `W(start) = 0` and zero-weight edges into
the end node):

```text
W(v_{i,1}) = w(start, v_{i,1})
W(v_{i,j}) = max_k [ W(v_{k,j-1}) + w(v_{k,j-1}, v_{i,j}) ]
```

Backward pass, its mirror: `B(v_{i,n}) = 0`, `B(v_{i,j}) = max_k [ w(v_{i,j},
v_{k,j+1}) + B(v_{k,j+1}) ]`.

`W(v) + B(v)` is the weight of the heaviest path **through** `v`, and that is
the re-ranking key. Ties break by the matcher's own similarity, then by
reference id, with the "no match" node last among equals.

Cost is `2 * sum_j K_{j-1} * K_j` edge relaxations —
`O(layers * K^2)` — reported exactly as `RerankResult::relaxations` so a caller
can assert the bound rather than trust a comment. Measured: 118,584 relaxations
in 11 ms for the largest in-house task (487 layers, release build).

## Where this departs from the paper

Seven departures, none of them silent. The first is an addition, the last is a
change of default rather than of algorithm, and the rest are
reductions.

1. **A call-agreement term is added.** RevDecode's contextual edge term is
   *adjacency*: candidates are rewarded for sharing a library, version,
   optimisation level and compilation unit, and the layers are ordered by memory
   offset because compilers place a translation unit's functions contiguously.
   That is provenance agreement, not a call graph. We keep it and add the term
   the plan item asks for.
2. **The confidence term is a socket, and no scheme fills it.** The paper's
   confidence score is a TF-IDF sum over shared minus unique features (Eq. 7),
   which needs the matcher's feature multisets and a corpus count table —
   neither of which crosses the `Scheme` boundary in
   [the measurement harness](../development/identity-measurement.md), where a
   comparison is one `f64`. `Candidate::confidence` accepts one when a scheme
   can produce it; when it is `None` the term contributes nothing. The CFR's
   TF-IDF weighting (plan item 5) is where such a number would come from.
3. **The "no match" node is an explicit threshold, not a derived one.** The
   paper sets the uncertain node's similarity to the layer maximum and its
   confidence to 85% of self-confidence, so nearly all of its power comes from
   the confidence term we do not have; reproducing only the first half gives a
   node that can never win. `RerankSettings::no_match_similarity` is instead the
   score a candidate must beat, stated in the same units as the similarities.
   **The default is `Some(0.0)`**: the node is in the graph, so the structure is
   faithful and a caller can raise it, but it never displaces a candidate that
   scores above zero. Every measured number below was produced at `0.0`.
4. **The backward pass is the standard best-path-through-a-node score.** The
   paper's ranking phase walks back from the end node, collects a separate
   ranking from each rank-one node and merges them by best rank. `W(v) + B(v)`
   yields exactly the same rank-one set — asserted against brute-force path
   enumeration in `src/identity/rerank/tests.rs` — gives every node a total
   order rather than a merged one, and costs one more sweep.
5. **Adjacency has one grouping level, not four.** Alg. 1 adds 0.7 for the same
   library, then 0.03 / 0.02 / 0.05 for version, optimisation level and
   compilation unit. A candidate pool drawn from one corpus slice fixes version
   and optimisation by construction, and we have no compilation-unit key that is
   not the library key.
6. **No GPU.** Sections 4 and 5 of the paper are a parallel implementation of
   the same recurrence.
7. **The default turns the paper's two provenance terms off.** Not a change to
   the algorithm — both are implemented and `RerankSettings::revdecode_paper()`
   runs them — but a change to what a caller gets without asking, made on the
   measurement below rather than on taste. `RerankSettings::default()` sets
   `adjacency_weight` and `library_weight` to `0.0`;
   `the_default_runs_the_call_term_and_not_the_provenance_terms` pins it, so the
   recommendation cannot drift away from the code that carries it.

## Measured

Read on 2026-09-03, release build, from `cargo test --release --features
python-ext --test identity_retrieval -- --ignored --nocapture
rerank_full_sweep`. Protocol, corpora and filters:
[Measuring function identity](../development/identity-measurement.md). Ties are
pessimistic on **both** sides of every before/after pair, and
`the_rerank_is_a_no_op_without_context` asserts that the baseline column here is
rank-for-rank the one `metrics::evaluate_slices` computes, so movement is
attributable to context and not to the machinery.

`imp/wor` is the count of queries whose *twin's* rank moved better / worse.
That is a stricter accounting than the paper's, which reports NDCG movement
anywhere in the ranked list; RevDecode's headline "56.3% to 98.8% of rankings
improved" is not the same statistic as the columns below.

### The two candidate lanes

**Sampled** is Marcelli's protocol — 100 negatives per positive, drawn
independently for each query, so two consecutive layers see two nearly disjoint
random subsets of the corpus. **Global** is RevDecode's own setting: every layer
ranks against the same candidate universe, the whole pool slice. The distinction
was added specifically so a provenance term could be measured on the lane where
the paper's question is the one being asked. It made no material difference: the
sign of every finding below is the same on both lanes.

### In-house fixture matrix, `structural` (L1 CFG invariants)

Sampled lane, pool 101 (chance R@1 0.0099).

| Task | Scored | base MRR10 | base R@1 | call MRR10 | call R@1 | imp/wor | adj MRR10 | adj R@1 | imp/wor | paper MRR10 | paper R@1 | imp/wor |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| XO-gcc | 389 | 0.1753 | 0.1183 | 0.1770 | 0.1208 | 1/0 | 0.1810 | 0.1157 | 36/42 | 0.1815 | 0.1157 | 37/42 |
| XO-clang | 366 | 0.1171 | 0.0738 | 0.1171 | 0.0738 | 0/0 | 0.1293 | 0.0792 | 33/31 | 0.1293 | 0.0792 | 33/31 |
| **XC-O0** | 487 | 0.5824 | 0.4723 | **0.5952** | **0.4908** | **9/0** | 0.6759 | 0.5955 | 120/56 | 0.6770 | 0.5975 | 121/56 |
| XC-O2 | 357 | 0.2381 | 0.1709 | 0.2381 | 0.1709 | 0/0 | 0.2643 | 0.2073 | 47/40 | 0.2643 | 0.2073 | 47/40 |
| XM | 365 | 0.1117 | 0.0685 | 0.1131 | 0.0712 | 1/0 | 0.1280 | 0.0740 | 36/29 | 0.1280 | 0.0740 | 36/29 |
| XM-S | 308 | 0.0819 | 0.0422 | 0.0819 | 0.0422 | 0/0 | 0.0652 | 0.0162 | 15/35 | 0.0652 | 0.0162 | 15/35 |
| XM-M | 54 | 0.2868 | 0.2222 | 0.2868 | 0.2222 | 0/0 | 0.2487 | 0.1667 | 7/11 | 0.2487 | 0.1667 | 7/11 |
| XM-L *(underpowered, n=3)* | 3 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0/0 | 1.0000 | 1.0000 | 0/0 | 1.0000 | 1.0000 | 0/0 |

Global lane, pool 377–494.

| Task | Scored | base MRR10 | base R@1 | call MRR10 | call R@1 | imp/wor | adj MRR10 | adj R@1 | imp/wor |
|---|---|---|---|---|---|---|---|---|---|
| XO-gcc | 389 | 0.1054 | 0.0797 | 0.1075 | 0.0823 | 1/0 | 0.0958 | 0.0617 | 18/25 |
| XO-clang | 366 | 0.0603 | 0.0437 | 0.0603 | 0.0437 | 0/0 | 0.0547 | 0.0301 | 13/15 |
| XC-O0 | 487 | 0.4064 | 0.3183 | 0.4110 | 0.3244 | 3/0 | 0.4837 | 0.3963 | 112/54 |
| XC-O2 | 357 | 0.1573 | 0.1176 | 0.1573 | 0.1176 | 0/0 | 0.1559 | 0.1092 | 24/29 |
| XM | 365 | 0.0617 | 0.0438 | 0.0637 | 0.0466 | 1/0 | 0.0607 | 0.0411 | 8/16 |
| XM-S | 308 | 0.0397 | 0.0260 | 0.0421 | 0.0292 | 1/0 | 0.0426 | 0.0292 | 4/12 |
| XM-M | 54 | 0.1534 | 0.1296 | 0.1534 | 0.1296 | 0/0 | 0.1358 | 0.0926 | 5/5 |
| XM-L *(underpowered, n=3)* | 3 | 0.6667 | 0.3333 | 0.6667 | 0.3333 | 0/0 | 0.6111 | 0.3333 | 0/1 |

### In-house fixture matrix, `cfr` (L2 Weisfeiler-Lehman)

Sampled lane.

| Task | Scored | base MRR10 | base R@1 | call MRR10 | call R@1 | imp/wor | adj MRR10 | adj R@1 | imp/wor |
|---|---|---|---|---|---|---|---|---|---|
| XO-gcc | 389 | 0.2543 | 0.1799 | 0.2573 | 0.1851 | 2/0 | 0.2242 | 0.1311 | 51/74 |
| XO-clang | 366 | 0.1808 | 0.1120 | 0.1840 | 0.1175 | 2/0 | 0.1712 | 0.0956 | 38/51 |
| XC-O0 | 487 | 0.9162 | 0.8706 | 0.9192 | 0.8768 | 3/0 | 0.9095 | 0.8522 | 40/47 |
| XC-O2 | 357 | 0.5688 | 0.5014 | 0.5688 | 0.5014 | 0/0 | 0.5249 | 0.4230 | 41/67 |
| XM | 365 | 0.1990 | 0.1342 | 0.1990 | 0.1342 | 0/0 | 0.1941 | 0.1178 | 42/51 |
| XM-S | 308 | 0.1637 | 0.1039 | 0.1637 | 0.1039 | 0/0 | 0.1684 | 0.1039 | 37/36 |
| XM-M | 54 | 0.3125 | 0.2037 | 0.3125 | 0.2037 | 0/0 | 0.2494 | 0.1296 | 9/18 |
| XM-L *(underpowered, n=3)* | 3 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0/0 | 0.4444 | 0.0000 | 0/3 |

Global lane.

| Task | Scored | base MRR10 | base R@1 | call MRR10 | call R@1 | imp/wor | adj MRR10 | adj R@1 | imp/wor |
|---|---|---|---|---|---|---|---|---|---|
| XO-gcc | 389 | 0.1509 | 0.1131 | 0.1560 | 0.1208 | 3/0 | 0.1049 | 0.0514 | 17/49 |
| XO-clang | 366 | 0.1021 | 0.0683 | 0.1054 | 0.0710 | 3/0 | 0.0619 | 0.0109 | 14/46 |
| XC-O0 | 487 | 0.8320 | 0.7680 | 0.8371 | 0.7762 | 4/0 | 0.7756 | 0.6694 | 60/93 |
| XC-O2 | 357 | 0.4641 | 0.4034 | 0.4678 | 0.4090 | 2/0 | 0.3947 | 0.3025 | 34/70 |
| XM | 365 | 0.1160 | 0.0795 | 0.1160 | 0.0795 | 0/0 | 0.0681 | 0.0219 | 11/52 |
| XM-S | 308 | 0.0939 | 0.0617 | 0.0939 | 0.0617 | 0/0 | 0.0594 | 0.0227 | 10/35 |
| XM-M | 54 | 0.1929 | 0.1296 | 0.1929 | 0.1296 | 0/0 | 0.1391 | 0.0741 | 2/12 |
| XM-L *(underpowered, n=3)* | 3 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0/0 | 0.7778 | 0.6667 | 0/1 |

### Cisco Talos Dataset-1, `structural`

47 to 72 scored per row: over the 30-query floor
(`MIN_SCORED_FOR_A_MEASUREMENT`), so quotable, but only just. A single query is
worth 1.4 to 2.1 points of Recall@1 here, so read the *sign* and the imp/wor
counts rather than the third decimal.

| Lane | Task | Scored | Pool | base MRR10 | base R@1 | call MRR10 | call R@1 | imp/wor | adj MRR10 | adj R@1 | imp/wor |
|---|---|---|---|---|---|---|---|---|---|---|---|
| sampled | XO | 50 | 101 | 0.2797 | 0.2000 | 0.2797 | 0.2000 | 0/0 | 0.2038 | 0.1000 | 6/13 |
| sampled | XC | 65 | 101 | 0.4043 | 0.3077 | 0.4178 | 0.3231 | 1/0 | 0.1999 | 0.0615 | 5/27 |
| sampled | XB | 72 | 101 | 0.4884 | 0.3056 | 0.4884 | 0.3056 | 0/0 | 0.3429 | 0.1944 | 11/37 |
| sampled | XA-arm64 | 47 | 101 | 0.5953 | 0.4681 | 0.6130 | 0.4894 | 1/0 | 0.3702 | 0.2340 | 7/26 |
| global | XO | 50 | 229 | 0.2135 | 0.1600 | 0.2135 | 0.1600 | 0/0 | 0.1524 | 0.1000 | 1/7 |
| global | XC | 65 | 348 | 0.3326 | 0.2769 | 0.3326 | 0.2769 | 0/0 | 0.1440 | 0.0462 | 2/26 |
| global | XB | 72 | 260 | 0.3682 | 0.2500 | 0.3682 | 0.2500 | 0/0 | 0.2484 | 0.0972 | 11/32 |
| global | XA-arm64 | 47 | 228 | 0.4848 | 0.3404 | 0.4848 | 0.3404 | 0/0 | 0.3231 | 0.1915 | 6/23 |

### Reading it

**1. The call-agreement term never cost a rank, in any of the 40 cells.** Two
schemes, twelve tasks, two corpora, two lanes: `worsened` is 0 everywhere. It
improved between 0 and 1.8% of queries, up to +0.0177 MRR10 and +0.0213 Recall@1
(Dataset-1 XA-arm64). `the_call_graph_term_never_costs_a_rank` in
`tests/identity_retrieval/main.rs` is that property as a test. It is an
empirical result and not a theorem — a call reward can in principle promote a
wrong candidate — which is exactly why it is a test rather than a claim.

**2. The improved fraction is small because the call graph is thin, not because
the term is weak.** On XO-gcc the scored population of 389 query functions has
**10** call edges between two of its own members, and only **5** of 388
consecutive layer pairs have a call relation at all; XC-O0, the one row where
the term moves nine queries, has 50. The published filters are the reason: a
callee has to survive the five-basic-block floor to be a layer, and the small
helpers a function most often calls do not. The harness prints
`call edges q<n> r<n>` and `related layer pairs n/m` on every row so a null
result can be told from an untested one, and
`the_decode_sees_a_non_empty_call_graph` fails if the graph is empty.

**3. RevDecode's own provenance terms lose on both of our corpora.** See below.

## Why the paper's provenance terms lose here

The adjacency and library terms move 8 of the 40 cells up, 31 down and 1 not at
all. Every gain is `structural`, and the two largest are XC-O0 (+0.094 MRR10
sampled, +0.077 global); the losses reach −0.225 (Dataset-1 XA-arm64, sampled)
and −0.204 (Dataset-1 XC). On the CFR the terms are negative on 15 of 16 cells.
By query rather than by cell the split is 933 improved against 1,297 worsened,
where the call term is 38 improved against 0. Three things are going on, and
none of them is a defect in the paper.

**The 0.7 constant is calibrated against a different score distribution.**
RevDecode tuned it on 30 synthetic firmware samples with sigmoid-normalised
similarities spread over the whole of `[0, 1]`. Our matchers' scores occupy a
narrow band — the CFR's cosine gaps between adjacent candidates are typically
well under 0.1 — so the same constant is a far larger prior here than there. We
tested that reading directly with a `paper-sigmoid` preset that re-spreads the
similarities through a logistic before they enter the weight: it does not
recover the loss (CFR XO-gcc sampled −0.0258 paper, −0.0206 paper-sigmoid), so
score compression is at most part of it.

**The stronger the matcher, the more a prior costs.** `structural` on XC-O0
starts at MRR10 0.58 and gains 0.09; the CFR starts the same row at 0.92 and
loses 0.007. A provenance prior can only help where the matcher's own evidence is
weak enough to be overruled, and it overrules correct answers at the same rate.

**Our "libraries" are the wrong size.** On the fixture matrix a library is one
206-line fixture with two to four scored functions; on Dataset-1 it is one
binary. RevDecode's setting is firmware linking whole third-party libraries,
where a same-library run really does span many consecutive functions. A term
that says "your neighbour came from library L, so you probably did too" needs
neighbours, and ours mostly have none.

The terms are implemented and faithful, and `RerankSettings::revdecode_paper()`
runs them. They are **off in `RerankSettings::default()`**, which is departure 7
above and the only place this stage disagrees with the paper about what should
happen by default rather than about what the algorithm is.

One further interaction is worth knowing because it looks like a bug and is not:
the library and adjacency terms *pull against each other*. Two candidates
sharing a library earn 0.7 of adjacency but each score `1 - n_lib/n_corpus`,
which is **lower** than a candidate from a singleton library. A singleton pair
can therefore beat a consistent pair. Both are the paper's own formulas
(Alg. 1 and Eq. 8); `adjacency_prefers_a_consistent_library` in
`src/identity/rerank/tests.rs` asserts the interaction in both directions so it
cannot be mistaken for a regression later.

## Running it

```bash
export TMPDIR="$HOME/.cache/glaurung/tmp"; mkdir -p "$TMPDIR"

# The algorithm's own tests: hand-built graphs, brute-force enumeration,
# the relaxation bound. Milliseconds.
cargo test --features python-ext identity::rerank

# The harness lane: the no-op assertion, the call-graph floor, the ratchets.
GLAURUNG_IDENTITY_CORPUS=/path/to/tests/decompiler_fixtures/build \
  cargo test --features python-ext --test identity_retrieval

# The full grid above -- every scheme, every ablation, both lanes, both
# corpora. Under a minute once the corpora are loaded.
GLAURUNG_IDENTITY_CORPUS=/path/to/tests/decompiler_fixtures/build \
GLAURUNG_CISCO_CORPUS="$HOME/.cache/glaurung/corpora/cisco-talos-dataset1" \
  cargo test --release --features python-ext --test identity_retrieval -- \
    --ignored --nocapture rerank_full_sweep

# The Python surface.
uv run pytest python/tests/test_rerank_candidates.py -q
```

The sweep writes one JSON per `(corpus, scheme, settings, lane)` to
`target/identity-eval/rerank-*.json`, carrying the pool sizes, the lane, the
build profile, the call-edge counts and every per-task number.

## Known gaps

- **No KB helper.** The plan item asked for one that applies the decode to
  `function_match` rows. That table does not exist on `master`; it arrives with
  the membership-gate lane (plan item 7). Nothing here writes to the KB.
- **The confidence term has no supplier.** Departure 2 above. The CFR's TF-IDF
  weighting (plan item 5) is the natural one.
- **Layer order is memory order.** RevDecode's, and it is why the call term
  fires on so few pairs here: a caller and its callee are adjacent layers only
  when the linker happened to place them so. Ordering layers by a call-graph
  traversal instead would let the term fire far more often, and is the obvious
  next experiment — it is a change to `order_key` at the call site and nothing
  in the decode.
- **Only the twin's rank is counted.** `improved`/`worsened` say nothing about
  movement elsewhere in the list, which is what the paper's NDCG measures. Our
  numbers are not comparable to its 56.3–98.8%.
- **No global-lane extraction-cost figure.** The decode itself is 8–11 ms per
  task; what a caller pays to *produce* the candidate lists is the scheme's cost
  and is reported in
  [identity-measurement.md](../development/identity-measurement.md).

## Where the code is

| File | What it holds |
|---|---|
| `src/identity/rerank/mod.rs` | the public API, `RerankSettings`, the departures list |
| `src/identity/rerank/graph.rs` | layer construction, top-K admission with boundary ties |
| `src/identity/rerank/context.rs` | the two call graphs, the library partition, all four score formulas |
| `src/identity/rerank/decode.rs` | forward and backward passes, the ranking total order |
| `src/identity/rerank/tests.rs` | hand-built graphs and the brute-force cross-check |
| `src/python_bindings/identity.rs` | `glaurung.analysis.rerank_candidates` |
| `tests/identity_retrieval/rerank.rs` | the measured lane: candidate lists from any `Scheme`, before/after |
| `python/tests/test_rerank_candidates.py` | the Python surface |
