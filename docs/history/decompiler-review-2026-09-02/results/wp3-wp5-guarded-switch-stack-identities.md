# WP3/WP5 guarded-switch stack identities

> **Kind:** record · **Date:** 2026-09-08

## Outcome

Commit `dad31027` moves the promoted discriminator-copy proof in guarded-switch
cleanup from `local_`/`stack_` display spelling to stack-promotion ownership.
The untyped preparation pass and the later typed range-guard pass both receive
the pipeline's `ValueIdentities` sidecar. An opaque owned stack object can now
participate in the exact one-use copy proof, while an unowned value merely
named `local_28` declines.

The public no-sidecar entry points retain the old spelling behavior for
compatibility. Width fit, one-use, range, case completeness, and default-arm
proofs are unchanged.

## Focused validation

```text
cargo test --features python-ext --lib ir::guarded_switch::tests -- --nocapture
20 passed; 4,580 filtered out

uv run maturin develop
success

uv run python tools/build_guard.py
fresh; SHA-256 1faf9b6534c16606502fd9e4091f2031b23e9696a9c561f00b6236e1d53bcde8

uv run python tools/dectest.py \
  204_adjacent_dispatch_tables:clang:O2:adt204_guarded_control --show
SCOPED: 1 lane of 838 - no regressions in scope

uv run pytest python/tests/test_test_census.py -q
6 passed
```

The regenerated census records 5,137 declared Rust tests and zero outside
every gate. No broad Rust/Python suite, fixture matrix, DecBench, or Joern lane
ran. This proves the identity boundary and one directly owning production
fixture; it is not corpus-wide WP5 promotion evidence.
