# WP3 constant-identity expression origins

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commit `3627ca65` makes the complete constant-identity family transparent to
expression origin carriers: neutral zero, neutral one, boolean identities,
zero annihilation, and all-bits identities. A neutral fold retains the
surviving value and constant owners. An absorbing fold retains its determining
constant owner but does not transfer the genuinely irrelevant value owner.
The enclosing operation owner remains attached by the parent carrier.

This is one bounded constant-fold migration, not completion of WP3.

## Focused verification

The neutral and absorbing policy test was observed red first because an
attributed constant blocked the raw matcher. After repair:

```text
cargo test --features python-ext --lib \
  ir::const_fold::tests::attributed_constant_identities_keep_only_semantic_contributors \
  -- --exact
1 passed; 0 failed; 4,372 filtered out

cargo test --features python-ext --lib 'ir::const_fold::tests::'
71 passed; 0 failed; 4,302 filtered out; 0.01 s
```

Filtered tests were not executed. The touched-module run includes the existing
identity, boolean, origin, refusal, and checked-in real-binary controls. No full
Rust, Python, fixture, architecture, DecBench, or Joern suite was run.
