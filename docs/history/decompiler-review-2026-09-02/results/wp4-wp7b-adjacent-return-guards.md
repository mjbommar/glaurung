# WP4/WP7B adjacent matching-return guards

> **Kind:** record · **Date:** 2026-09-08

## Outcome

Commit `921dfd9b` closes the historical duplicated-loop defect in pinned Clang
O2 `bst_search` and improves its validation prefix. The current structurer had
already reduced the former two `do` loops to one faithful head-tested `while`,
but emitted the source's three-way invalid-input check as two adjacent guards
that both returned `-1`.

The final AST cleanup now folds exactly adjacent, else-free guards with
semantically identical single-return bodies:

```c
if (bad_count) return -1;
if (null_nodes) return -1;
```

becomes:

```c
if (bad_count || null_nodes) return -1;
```

The rule preserves left-to-right short-circuit evaluation, refuses differing
returns or intervening statements, recurses through structured bodies, and
unions the consumed guard and return origins. It runs again after redundant
return-result assignments are removed, because that normalization is what
exposes this exact source-level shape in `bst_search`.

## Evidence

- All 27 `guard_chain` module tests pass. The new focused tests prove both the
  matching-return fold and the differing-return refusal, including exact
  origin unions.
- The pinned Clang O2 `bst_search` test is now an ordinary pass: one recovered
  loop, one three-way validation guard, three returns, and no goto.
- Exact execution round trips for both `bst_search` and
  `bst_inorder_checksum` pass.
- The former broad strict xfail was split. A distinct strict xfail now records
  the remaining `bst_inorder_checksum` inner-loop issue: two break guards are
  separated by a loop-carried depth copy and cannot be fused by this adjacency
  rule without a stronger identity proof.

The generated census remains deferred while the shared checkout contains 17
uncommitted Rust tests from another lane in addition to this workstream's three
new tests. No broad suite, DecBench run, or upstream interaction was performed.
