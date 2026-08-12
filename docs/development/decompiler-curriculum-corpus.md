# Decompiler curriculum corpus

> **Status: maintained corpus guide.** The fixtures and selectors are current;
> capability counts below are a revision-bound snapshot and must be rerun before
> they are presented as current behavior.

The curriculum corpus extends the focused bug fixtures with recognizable,
composed programs from an undergraduate computer-science sequence. Its purpose is
not to reward source-text resemblance. Every exported function crosses the real
pipeline:

```text
reference C -> GCC/Clang at O0/O2 -> ELF shared object -> Glaurung C
            -> pinned GCC rebuild -> isolated differential execution
```

The worker compares the exact DWARF-width return and every caller-owned buffer
after each call. Deterministic boundary cases, a stable seeded fuzz sample, and at
least one canonical textbook vector cover both normal and malformed inputs. The
separate compiled oracle checks the canonical answers produced by the reference
sources, so differential agreement cannot bless a mislabeled algorithm.

## Projects and decompiler stressors

| fixture | project | exported semantic units | primary stressors |
|---|---|---|---|
| `15_binary_search_tree` | flat binary-search tree | search, in-order checksum | struct arrays, data-dependent traversal, explicit stack |
| `16_red_black_tree` | red-black invariant checker | validate | colored nodes, parent accounting, black-height worklist |
| `17_hash_table` | open addressing | lookup, insert | modular indexing, sentinel values, mutation |
| `18_binary_heap` | min heap | push, pop | parent/child indexing, swaps, output parameters |
| `19_disjoint_set` | union-find | path-compressing find, union by rank | local callees, pointer mutation, bounded malformed cycles |
| `20_graph_bfs` | breadth-first search | BFS order | adjacency matrix, queue, visited state, output buffer |
| `21_graph_dfs` | depth-first search | DFS preorder | explicit stack, reverse neighbor traversal, continue |
| `22_dijkstra` | shortest paths | dense Dijkstra | nested selection/relaxation loops, saturation guard |
| `23_topological_sort` | DAG ordering | Kahn sort | indegree accumulation, queue, cycle result |
| `24_merge_sort` | stable sorting | bottom-up merge sort | nested loops, local scratch array, in-place mutation |
| `25_kmp_search` | substring search | KMP | byte pointers, prefix table, fallback loop |
| `26_sparse_matrix` | CSR sparse matrix-vector product | mat-vec | five buffers, irregular row ranges, unsigned accumulation |
| `27_newton_raphson` | integer Newton iteration | integer square root | unsigned divide, convergence, bounded iteration |
| `28_euler_ode` | fixed-point ODE integration | Euler decay | 64-bit intermediate, division, saturation |
| `29_polynomial` | polynomial arithmetic | Horner evaluation, derivative | reverse loops, defined modular overflow |
| `30_finite_difference` | one-dimensional heat stencil | one time step | neighboring loads, 64-bit accumulation, output mutation |

The tree and graph representations use bounded flat arrays rather than native
heap pointers. This is intentional: arbitrary fuzz bytes cannot safely construct
a recursive pointer graph, whereas index-based structures retain the same
control-flow and memory-recovery challenge while making every generated input
terminating and memory-safe. Malformed indices and cycles are explicit negative
inputs, not undefined behavior.

## Domain expansion (fixtures 31-80)

The founding sixteen reached 84/84 and stopped discriminating: a corpus that
never fails can catch a regression but cannot locate a weakness. Fifty further
projects extend the same contract into algorithm families and applied-science
kernels the original set never reached.

| fixtures | family | exported semantic units | primary stressors |
|---|---|---|---|
| 31-35 | dynamic programming | edit distance, LCS + reconstruction, 0/1 and unbounded knapsack, coin change, matrix-chain order | flat 2D tables, reverse iteration, sentinel values in arithmetic, triangular interval loops |
| 36-40 | sorting and selection | quicksort, heapsort, insertion/shell, counting/radix, quickselect | genuine self-recursion, sift-down child indexing, gap sequences, prefix-sum scatter, two-sided narrowing |
| 41-45 | strings and parsing | lexer, RPN evaluation, base64, run-length coding, decimal conversion | dense switch dispatch, operand stack, cross-byte shift lattices, saturating accumulation |
| 46-50 | bit manipulation | rank/select bit sets, Huffman code lengths, Gray coding, CRC-32, LEB128 varints | SWAR popcount, two-minimum scans, masked swap ladders, table construction, continuation-bit loops |
| 51-54 | hashing and cryptography | RC4, FNV-1a/djb2/Murmur, xorshift and LCG, one SHA-256 compression | byte-width index truncation, pure multiply/xor chains, 64-bit multiply lowering, a 64-entry constant table with four rotations per round |
| 55-60 | number theory and algebra | Euclid and extended Euclid, modular exponentiation, sieving, factorisation, multi-limb arithmetic, exact rationals, combinatorics, integer matrices | simultaneous recurrences, non-unit strides, carry propagation, exact division ordering, two-stride triple loops |
| 61-64 | fixed-point numerics | Q16.16 primitives, Gaussian elimination with partial pivoting, quadrature, root finding | 64-bit intermediates, pivot row swapping, back substitution, alternating quadrature weights, self-correcting recurrences |
| 65-68 | physics | projectile motion, an orbital step, elastic collisions, thermodynamics | coupled state updates, inverse-square division, shared-parameter cross-checks, geometric decay |
| 69-70 | chemistry | molar-mass formula parsing, integer reaction balancing | symbol/count parsing with table lookup, four nested bounded searches with early exit |
| 71-76 | finance | compounding and annuities, loan amortisation, NPV and IRR, moving statistics, order matching, portfolio rebalancing | multiply-accumulate chains, parallel output buffers, nested search over a discount loop, book compaction, weight normalisation |
| 77-80 | systems data structures | LRU cache, ring buffer, segment tree, trie | recency scans with two reduction operators, masked wraparound on unsigned counters, parent/child index climbing, index-based pointer chasing |

Everything is integer or Q16.16. That is a harness constraint, not a modelling
preference: `tools/diff_decompile.py` accepts integer scalars only (`float` and
`complex` are rejected at signature recovery), so a native floating-point
fixture would report as an infrastructure failure rather than a decompiler
result. Real `float`/`double` coverage needs the differential worker to grow
floating-point ABI support first; until then fixture 61 supplies the numeric
substrate the rest of the applied kernels are built on.

### Capability map at the recording revision

The expansion recorded **395 pass / 29 fail** across 424 function/lane
outcomes, with **36 of 50** projects green in all four lanes and zero
infrastructure failures. As with the founding set, these are baseline facts,
not readiness claims.

| project | recorded debt |
|---|---|
| `54_sha256_block` | fails all four lanes — the densest constant/rotation case in the corpus |
| `36_quicksort` | fails three of four — the only genuinely self-recursive fixture |
| `33_knapsack` | both exports fail at `-O2` (reverse-iterated rolling array) |
| `58_rational` | normalisation and comparison fail three of eight |
| `39_counting_radix_sort` | histogram scatter fails three of eight |
| `42_rpn_evaluator` | fails both Clang lanes |
| `56_sieve` | fails both `-O2` lanes (non-unit stride from `p*p`) |
| `53_pseudorandom` | rejection sampling fails both `-O2` lanes |
| `35_matrix_chain`, `62_gaussian_elimination`, `77_lru_cache` | one lane each |
| `45_string_algorithms`, `49_crc32`, `74_moving_statistics` | one export, one lane each |

Two clusters stand out and are worth more than their raw counts: **recursion**
(`36_quicksort`) and **wide constant/rotation schedules** (`54_sha256_block`).
Both were absent from the founding corpus entirely.

### Running the expansion

```bash
tools/dectest.py @curriculum                     # all 66 projects
tools/dectest.py @curriculum-dynamic-programming
tools/dectest.py @curriculum-sorting
tools/dectest.py @curriculum-strings
tools/dectest.py @curriculum-bits
tools/dectest.py @curriculum-crypto
tools/dectest.py @curriculum-number-theory
tools/dectest.py @curriculum-numerics
tools/dectest.py @curriculum-physics
tools/dectest.py @curriculum-chemistry
tools/dectest.py @curriculum-finance
tools/dectest.py @curriculum-structures
```

Fixtures 15-30 remain a strict all-pass ratchet
(`test_founding_curriculum_round_trips_in_every_lane`). Fixtures 31-80 are
compared against `baseline.json` exactly
(`test_expanded_curriculum_matches_recorded_baseline`), so a recorded `fail`
that starts passing fails the suite just as loudly as a regression — the
capability map cannot quietly go stale.

## Running it

```bash
tools/dectest.py @curriculum --full
tools/dectest.py @curriculum-data-structures --show
tools/dectest.py @curriculum-graphs --show
tools/dectest.py @curriculum-sequences --show
```

The named sets always select all four compiler/optimization lanes. A recorded
`fail` is visible decompiler debt; `missing`, `nocases`, timeout, compilation
failure, or worker failure is infrastructure debt and may not be baselined.

## Initial capability map

The recorded results at `1525bdf0` produced 84 function/lane outcomes: 49
passed and 35 failed. Hashing, heaps, union-find, CSR mat-vec, Newton integer
square root, polynomial arithmetic, and the finite-difference stencil passed all
four lanes. The explicit-stack traversal family exposed the largest coherent
gap: red-black validation, BFS, DFS, Dijkstra, topological sort, merge sort, and
KMP failed all four lanes. Euler passed only Clang O2, and BST search passed all
four while its in-order traversal failed all four.

These are baseline facts, not readiness claims. They identify general recovery
work around stack-resident arrays, nested worklists, and loop-carried indices;
improving one of those mechanisms should move several independent projects.
