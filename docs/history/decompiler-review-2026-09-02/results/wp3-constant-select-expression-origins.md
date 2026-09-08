# WP3 constant-select expression origins

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commit `5e04d66a` makes constant-select collapse transparent to an attributed
literal predicate and enforces WP3's hoisting rule. When a constant condition
makes exactly one arm reachable, the hoisted arm retains its own origins and
receives the consumed condition origins. The surrounding select owner remains
on the replacement, while the unreachable arm's origins are deliberately not
transferred.

Select evaluation and refusal behavior are unchanged. This is one bounded
constant-fold migration, not completion of WP3.

## Focused verification

The new four-owner test was observed red first because an attributed literal
condition blocked the collapse and left the full select in the AST. After
repair:

```text
cargo test --features python-ext \
  ir::const_fold::tests::attributed_constant_select_hoists_selected_and_control_origins \
  -- --exact
1 passed; 0 failed; 4,363 filtered out

cargo test --features python-ext 'ir::const_fold::tests::'
62 passed; 0 failed; 4,302 filtered out
```

The touched-module run includes its existing checked-in real-binary
end-to-end test. No full Rust, Python, fixture, architecture, DecBench, or
Joern suite was run.

## Next boundary

Continue one independently proved expression-constructor family at a time.
For every hoist, retain the selected value and consumed control origins while
excluding unreachable semantics.
