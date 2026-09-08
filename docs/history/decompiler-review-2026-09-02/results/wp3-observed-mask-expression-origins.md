# WP3 observed-mask expression origins

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commit `1647953d` makes observed-mask simplification transparent to an origin
carrier around a partial-register merge. The surviving low-bit predicate keeps
its own, merge, and observing-mask owners; the masked-out high-parent owner is
not transferred. If masking proves a non-boolean value contributes no bits,
that genuinely dead value origin is likewise discarded.

Follow-on commit `997ec48c` closes the entry matcher itself: a carrier around
the mask constant no longer blocks recognition, and that constant's owner joins
the surviving predicate while the dead high-parent owner remains excluded.

Mask-disjointness and boolean-width proofs are unchanged. This is one bounded
constant-fold migration, not completion of WP3.

## Focused verification

The original four-owner test was observed red before `1647953d`. It was then
strengthened to five owners and observed red again before `997ec48c`, because
the mask carrier blocked entry recognition. After both repairs:

```text
cargo test --features python-ext --lib \
  ir::const_fold::tests::attributed_observed_mask_keeps_surviving_low_bit_origins \
  -- --exact
1 passed; 0 failed; 4,374 filtered out

cargo test --features python-ext --lib 'ir::const_fold::tests::'
73 passed; 0 failed; 4,302 filtered out; 0.01 s
```

Filtered tests were not executed.
The touched-module run includes the existing mask, boolean, and checked-in
real-binary controls. No full Rust, Python, fixture, architecture, DecBench,
or Joern suite was run.
