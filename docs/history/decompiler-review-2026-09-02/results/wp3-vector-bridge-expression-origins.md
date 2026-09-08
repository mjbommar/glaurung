# WP3 vector-bridge expression origins

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commit `57f6c625` makes x86 scalar-view bridge recognition transparent to
expression-origin carriers on the bridge tree, shift, casts, and lane
registers. An attributed synthetic XMM bridge no longer hides an otherwise
provable four-lane load/store transport from 16-byte vector-copy recovery.

When the dead bridge is removed, the recovered wide load receives the complete
deterministic origin union from the bridge statement and its expression tree.
The expression walk is exhaustive over the AST enum. The pass still requires a
dead whole-register view, exact lane identities, one consumer, and adjacent
matching load/store batches. This is a bounded WP3 migration, not completion of
the package.

## Focused verification

The real dead-bridge transport test was strengthened with an origin on the
bridge expression and required that owner on the recovered wide load. It was
observed red first because the raw bridge matcher rejected the carrier. After
repair:

```text
cargo test --features python-ext --lib \
  ir::vector_copy::tests::a_dead_scalar_view_bridge_does_not_hide_the_transport \
  -- --exact
1 passed; 0 failed; 4,377 filtered out

cargo test --features python-ext --lib 'ir::vector_copy::tests::'
8 passed; 0 failed; 4,370 filtered out; 0.00 s
```

Filtered tests were not executed. No full Rust, Python, fixture, architecture,
DecBench, or Joern suite was run.
