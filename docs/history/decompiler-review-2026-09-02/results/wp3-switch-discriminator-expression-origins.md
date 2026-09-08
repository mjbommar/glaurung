# WP3 switch-discriminator expression origins

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commit `af10e4e7` makes guarded-switch copy elimination compare an attributed
temporary discriminator by semantic register identity. Replacing that one-use
temporary with its proven source no longer fails merely because the switch
discriminator carries an instruction owner, and that owner remains attached to
the replacement discriminant.

The exact temporary identity, unsigned-extension proof, and one-use condition
remain mandatory. This is a bounded WP3/WP5 migration, not completion of either
package.

## Focused verification

The attributed guard/copy/switch test now gives the temporary switch
discriminator its own owner and requires it on the replacement. It was observed
red first because raw expression equality left the copy and guarded switch
uncombined. After repair:

```text
cargo test --features python-ext --lib \
  ir::guarded_switch::tests::attributed_guard_copy_and_switch_compose_into_the_replacement \
  -- --exact
1 passed; 0 failed; 4,377 filtered out

cargo test --features python-ext --lib 'ir::guarded_switch::tests::'
18 passed; 0 failed; 4,360 filtered out; 0.00 s
```

Filtered tests were not executed. No full Rust, Python, fixture, architecture,
DecBench, or Joern suite was run.
