# WP3 guarded-switch expression origins

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commit `0a8ba2bb` makes guarded-switch recovery transparent to expression-origin
carriers on guard comparisons, bounds, discriminants, and unsigned cast chains.
Adding instruction provenance no longer leaves a redundant `if` around an
otherwise proven structured switch or prevents removal of its one-use
discriminator copy.

The replacement switch receives the complete deterministic origin union from
each consumed guard/copy statement and expression tree. The expression walk is
exhaustive over the AST enum. Existing case-domain, exhaustiveness, recovered-
width, one-use, and control-flow refusal rules remain unchanged. This is a
bounded WP3/WP5 migration, not completion of either package.

## Focused verification

The existing attributed guard/copy/switch test now attributes the guard
comparison and both operands and requires those owners on the replacement. It
was observed red first because the raw comparison matcher left two statements
instead of the one recovered switch. After repair:

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
