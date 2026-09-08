# WP3 switch-operand expression origins

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commit `320cb2e5` completes the next switch-ladder expression boundary. Direct
range tests now inspect attributed discriminants and bounds semantically, so
operand carriers do not block structured-switch recovery. The synthesized
switch receives the deterministic union of origins from the complete consumed
condition expression trees, not only each condition's outer owner.

The expression-origin walk is exhaustive over the AST enum, including calls,
selects, table indices, numeric conversions, and wide arithmetic. Existing
single-discriminant, signed-range, reachability, and control-flow refusals are
unchanged. This is a bounded WP3/WP5 migration, not completion of either
package.

## Focused verification

The attributed GCC-ladder test now attributes every comparison operand and
includes those owners in the expected switch union. After the prior outer-
condition migration it remained red: recognition failed at the raw direct-
range operand matcher, then the recovered switch omitted operand owners. After
repair:

```text
cargo test --features python-ext --lib \
  ir::switch_ladder::tests::an_attributed_gcc_comparison_ladder_becomes_an_attributed_switch \
  -- --exact
1 passed; 0 failed; 4,377 filtered out

cargo test --features python-ext --lib 'ir::switch_ladder::tests::'
28 passed; 0 failed; 4,350 filtered out; 0.00 s
```

Filtered tests were not executed. No full Rust, Python, fixture, architecture,
DecBench, or Joern suite was run.
