# WP3 typed-view expression origins

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commit `5289e459` makes `fold_typed_declared_views` transparent to expression
origin carriers. The pass still removes only the exact unsigned nested view
whose source declaration proves the inner width and signedness. When it does,
the source retains the deterministic union of outer-cast, inner-cast, and
source owners. Nested carriers are flattened canonically.

Mismatched signedness/width and root return-promotion refusals are unchanged.
This is one bounded typed-expression migration, not completion of WP3 or WP6.

## Focused verification

The three-owner declared-parameter test was observed red first because the
outer and inner carriers blocked the raw nested-cast matcher. After repair:

```text
cargo test --features python-ext --lib \
  ir::const_fold::tests::attributed_typed_register_view_unions_both_cast_and_source_origins \
  -- --exact
1 passed; 0 failed; 4,377 filtered out

cargo test --features python-ext --lib 'ir::const_fold::tests::'
76 passed; 0 failed; 4,302 filtered out; 0.02 s
```

Filtered tests were not executed. The touched-module run includes mismatched-
type, return-promotion, origin, and checked-in real-binary controls. No full
Rust, Python, fixture, architecture, DecBench, or Joern suite was run.
