# WP3 stored-value expression origins

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commit `dfa2fa22` makes the storage-width cleanup boundary transparent to an
expression origin carrier. Casts and masks proven redundant by the machine
store width are still removed when attributed, and any carrier exposed by the
replacement is flattened into the enclosing canonical origin set.

This preserves the existing low-bit proof and improves stored-expression
readability without discarding cast/value ownership. It is one bounded
constant-fold migration, not completion of WP3.

## Focused verification

The attributed one-byte-store test was observed red first because the carrier
hid a redundant four-byte cast. After repair:

```text
cargo test --features python-ext --lib \
  ir::const_fold::tests::attributed_store_width_fold_unions_cast_and_value_origins \
  -- --exact
1 passed; 0 failed; 4,376 filtered out

cargo test --features python-ext --lib 'ir::const_fold::tests::'
75 passed; 0 failed; 4,302 filtered out; 0.01 s
```

Filtered tests were not executed. The touched-module run includes the existing
store-mask, cast, origin, refusal, and checked-in real-binary controls. No full
Rust, Python, fixture, architecture, DecBench, or Joern suite was run.
