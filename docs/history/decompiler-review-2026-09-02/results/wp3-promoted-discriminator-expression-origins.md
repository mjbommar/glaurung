# WP3 promoted-discriminator expression origins

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commit `5a7e76d6` makes the typed promoted-stack discriminator-copy path
transparent to origin carriers on the stack-object address and stored value.
An attributed `Store` representing a promoted local assignment can still be
removed when recovered width proves it is a lossless one-use discriminator
copy.

The replacement switch receives the store statement, address, and value
owners, while the replacement discriminant retains its value owner. The
promoted `local_`/`stack_` identity, recovered-width, and one-use proofs remain
mandatory. This is a bounded WP3/WP5 migration, not completion of either
package.

## Focused verification

The typed promoted-store test now attributes the store, address, and source and
requires all three owners after recovery. It was observed red first because the
raw address matcher left the store and guarded switch uncombined. After repair:

```text
cargo test --features python-ext --lib \
  ir::guarded_switch::tests::typed_promoted_stack_store_is_a_lossless_discriminant_copy \
  -- --exact
1 passed; 0 failed; 4,377 filtered out

cargo test --features python-ext --lib 'ir::guarded_switch::tests::'
18 passed; 0 failed; 4,360 filtered out; 0.00 s
```

Filtered tests were not executed. No full Rust, Python, fixture, architecture,
DecBench, or Joern suite was run.
