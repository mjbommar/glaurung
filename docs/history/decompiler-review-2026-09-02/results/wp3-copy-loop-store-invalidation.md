# WP3 copy loop-store invalidation

> **Kind:** result · **Date:** 2026-09-08

Commit `ce55594e` makes copy propagation's loop write-set collection recognize
an origin carrier around a register store target. A pre-loop alias whose source
is changed by that store is now invalidated before loop-condition/body
substitution, preserving the loop-carried value instead of freezing its entry
snapshot.

The negative regression was observed RED first: the attributed store target
was absent from the write set and the stale alias remained available. The fix
does not widen propagation; it restores the existing conservative invalidation
rule for the attributed spelling.

```text
cargo test --features python-ext --lib \
  ir::copy_prop::env::tests::attributed_loop_store_target_invalidates_preloop_copy \
  -- --exact
1 passed; 0 failed; 4,382 filtered out

cargo test --features python-ext --lib ir::copy_prop::
53 passed; 0 failed; 4,330 filtered out
```

No full Rust, Python, fixture, DecBench, or Joern sweep was run for this bounded
WP3 increment.
