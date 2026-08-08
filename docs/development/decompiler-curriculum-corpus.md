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
