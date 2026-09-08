# WP3 observed-mask expression origins

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commit `1647953d` makes observed-mask simplification transparent to an origin
carrier around a partial-register merge. The surviving low-bit predicate keeps
its own, merge, and observing-mask owners; the masked-out high-parent owner is
not transferred. If masking proves a non-boolean value contributes no bits,
that genuinely dead value origin is likewise discarded.

Mask-disjointness and boolean-width proofs are unchanged. This is one bounded
constant-fold migration, not completion of WP3.

## Focused verification

The four-owner test was observed red first because the merge carrier blocked
recognition. After repair:

```text
cargo test --features python-ext \
  ir::const_fold::tests::attributed_observed_mask_keeps_surviving_low_bit_origins \
  -- --exact
1 passed; 0 failed; 4,368 filtered out

cargo test --features python-ext 'ir::const_fold::tests::'
67 passed; 0 failed; 4,302 filtered out
```

The touched-module run includes the existing mask, boolean, and checked-in
real-binary controls. No full Rust, Python, fixture, architecture, DecBench,
or Joern suite was run.
