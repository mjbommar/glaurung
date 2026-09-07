# WP3 exhaustive-return origin propagation

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commit `1c909df4` makes exhaustive-if and exhaustive-switch joined-return
recovery transparent to statement origins. Attributed control nodes, terminal
result definitions, optional breaks, machine-epilogue comments, and shared
returns now participate in the same proofs as their unwrapped forms.

Control-node owners remain on the `if` or `switch`. When the shared return is
materialized into multiple arms, its owner and any intervening machine-comment
owners are deliberately duplicated into every new arm return. Each arm also
keeps only its own terminal definition and optional break owners. One-sided
early-return recovery copies the join owners only to the path that previously
reached that join; already-terminal returns are not falsely reattributed.

## Focused evidence

Both attributed join tests were observed red before their respective repairs:
the wrapped control node prevented either join from folding. Exact assertions
cover disjoint arm ownership, shared-tail duplication, optional break
consumption, and preservation of the outer control owner.

```text
cargo test --features python-ext \
  ir::ast::return_folds::tests::attributed_exhaustive_if_duplicates_join_owners_into_each_return \
  -- --exact
1 passed; 0 failed

cargo test --features python-ext \
  ir::ast::return_folds::tests::attributed_exhaustive_switch_duplicates_join_owners_into_each_return \
  -- --exact
1 passed; 0 failed

cargo test --features python-ext ir::ast::return_folds::tests
6 passed; 0 failed
```

A fresh release extension was built in 35.17 seconds. Four exact O0 functions
cover the two production shapes:

```text
uv run python tools/dectest.py \
  '01_conditional_polarity:*:O0:classify' \
  '106_switch_shapes_dense_sparse:*:O0:dense_switch' \
  --jobs 2 --full --show
4 passed; 0 regressions in scope
```

No broad Rust, Python, architecture, fixture, or DecBench sweep was run.

## Next action

Re-audit `ast/return_folds.rs` for remaining raw readers and close any narrow
omission before moving to the next enabled WP3 output transformation.
