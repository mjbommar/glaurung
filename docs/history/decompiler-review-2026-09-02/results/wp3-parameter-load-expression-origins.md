# WP3 parameter-load expression origins

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commit `02791f18` makes full-width cdecl32 parameter-address load folding
transparent to expression-origin carriers. An attributed
`Deref(StackAddr(argN))` now recovers the same source parameter as the bare
form, and the parameter expression owns the deterministic union of the
address-producing and load origins.

The existing proof remains unchanged: load and parameter-object widths must
match exactly, and the stack object must be a recognized ABI parameter.
Partial loads, aggregates, and locals still decline. This is one bounded
constant-fold migration, not completion of WP3.

## Focused verification

The attributed-address test was observed red first because the carrier blocked
recognition. After repair:

```text
cargo test --features python-ext \
  ir::const_fold::tests::attributed_full_width_parameter_load_unions_address_and_load_origins \
  -- --exact
1 passed; 0 failed; 4,364 filtered out

cargo test --features python-ext 'ir::const_fold::tests::'
63 passed; 0 failed; 4,302 filtered out
```

The touched-module run includes both the adjacent partial-load refusal and its
existing checked-in real-binary end-to-end test. No full Rust, Python, fixture,
architecture, DecBench, or Joern suite was run.

## Next boundary

Continue the constructor audit one proved family at a time. Storage-to-value
identity folds must preserve exact width/object refusal and transfer only the
origins that contribute to the recovered value.
