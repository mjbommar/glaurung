# WP3 address-reconstruction expression origins

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commit `64781964` makes `Addr/Named +/- Const` reconstruction transparent to
expression origin carriers. The reconstructed absolute address retains the
page/base, offset, and enclosing arithmetic owners. Existing safety remains:
only additive address forms fold, `Const - Addr` is refused, and a stale
page-level `Named` spelling is discarded before the final VA is independently
resolved.

This is one bounded constant-fold migration, not completion of WP3.

## Focused verification

The three-owner AArch64-style page-plus-offset test was observed red first
because the carriers blocked both base and constant matching. After repair:

```text
cargo test --features python-ext --lib \
  ir::const_fold::tests::attributed_address_reconstruction_unions_base_and_offset_origins \
  -- --exact
1 passed; 0 failed; 4,374 filtered out

cargo test --features python-ext --lib 'ir::const_fold::tests::'
73 passed; 0 failed; 4,302 filtered out; 0.02 s
```

Filtered tests were not executed. The touched-module run includes address
ordering, named-page, non-additive refusal, origin, and checked-in real-binary
controls. No full Rust, Python, fixture, architecture, DecBench, or Joern suite
was run.
