# WP3/WP4 equal-value loop exits

> **Kind:** record · **Date:** 2026-09-12

## Outcome

Commit `fa4ac102` closes the remaining pinned Clang O2 binary-search-tree
structuring xfail. `bst_inorder_checksum` previously rendered two inner-loop
exit guards separated by `var9 = var14`:

```c
if (current < 0) break;
var9 = var14;
if (n <= current) break;
```

The two immediately reaching definitions already assigned both values the
same stable expression. The late guard cleanup now proves that exact local
fact, removes the redundant copy without moving it across either exit, and
feeds the resulting adjacent guards to the existing short-circuit rule:

```c
if (current < 0 || n <= current) break;
```

The proof operates on AST register identities and exact reaching expressions,
not rendered variable names. It accepts only cast shells around a register or
constant, rejects expressions dependent on either destination, requires a
side-effect-free first predicate, and requires the two definitions, two guards,
and copy to be adjacent in the exact expected order. The deleted assignment's
statement and source origins are merged into the surviving destination
definition. Unequal reaching definitions remain unchanged.

## Evidence

- Observed red before implementation:
  `cargo test --features python-ext break_guards -- --nocapture` failed the new
  equal-value case with two guards, two breaks, and the redundant copy intact;
  the unequal-definition refusal passed.
- Focused Rust gate after implementation:
  `cargo test --lib --features python-ext ir::guard_chain::tests -- --nocapture`
  passes all 29 tests, including exact origin preservation and the unequal
  refusal.
- A fresh release extension build completed with
  `TMPDIR=/home/mjbommar/.cache/glaurung/tmp uv run maturin develop --release`.
- The two exact fixture-output regressions pass:
  `uv run pytest python/tests/test_decompiler_curriculum_corpus.py::test_optimized_bst_search_recovers_latch_and_terminal_returns python/tests/test_decompiler_curriculum_corpus.py::test_optimized_bst_inorder_recovers_one_inner_loop_exit -q`.
- Exact compiled execution round trips pass for both functions:
  `uv run python tools/dectest.py '15_binary_search_tree:clang:O2:bst_search' '15_binary_search_tree:clang:O2:bst_inorder_checksum' --full`.

No broad Python/Rust suite, corpus sweep, DecBench run, or upstream interaction
was performed. The release build included concurrent uncommitted source-metrics
and stack-local work in the shared checkout; the committed change itself owns
only `src/ir/guard_chain.rs` and the curriculum regression test.

## Follow-on origin closure

Commit `7f8f25fa` repairs the adjacent-break rule's terminal-node provenance.
Before the change, an attributed pair retained both condition expressions and
both enclosing guard owners but constructed a fresh unowned `break`, silently
losing the two consumed exit instruction sets. The replacement break now owns
their sorted, deduplicated union.

The exact origin test was observed red with no owner on the synthesized break.
After repair, all 30 guard-chain tests pass and separately prove guard origins,
predicate origins, and the merged break origins. A fresh release extension
build plus the same two BST output tests and exact execution round trips remain
green. No broad suite or corpus ran.
