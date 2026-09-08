# WP3 disjoint-mask expression origins

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commit `c0e296e7` makes observed-mask simplification transparent to attributed
inner `value & mask` terms and their mask constants. When a keep mask proves a
stale partial-register value cannot affect the observed bits, the readable
surviving predicate now retains the mask-tree and mask-constant owners that
justify that proof. The stale value's owner remains excluded because its value
is genuinely irrelevant to the result.

The same helper now preserves attributed mask evidence when combining nested
masks. Mask-disjointness remains mandatory; this does not broaden the algebraic
rewrite. This is one bounded wildcard-consumer migration, not completion of
WP3.

## Focused verification

The strengthened partial-register test was observed red first because the raw
inner-`And` matcher could not see through the carrier. After repair:

```text
cargo test --features python-ext --lib \
  ir::const_fold::tests::attributed_observed_mask_keeps_surviving_low_bit_origins \
  -- --exact
1 passed; 0 failed; 4,377 filtered out

cargo test --features python-ext --lib 'ir::const_fold::tests::'
76 passed; 0 failed; 4,302 filtered out; 0.01 s
```

Filtered tests were not executed. No full Rust, Python, fixture, architecture,
DecBench, or Joern suite was run.
