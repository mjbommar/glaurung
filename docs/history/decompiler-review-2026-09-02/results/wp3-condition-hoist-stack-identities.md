# WP3 condition-hoist stack identities

> **Kind:** record · **Date:** 2026-09-08

## Outcome

Commit `003e4fc1` moves the stack-write barrier used by condition hoisting from
`local_`/`stack_` display spelling to producer-owned promoted-stack identity.
Both block-local flag inlining and structured-region condition extraction now
receive the pipeline's `ValueIdentities` sidecar. An opaque promoted object
therefore blocks moving a comparison across its store, while an unowned value
merely named `local_8` no longer acquires storage semantics in production.

The legacy spelling check remains only when no identity sidecar exists, for
explicit compatibility callers.

## Focused validation

```text
cargo test --features python-ext --lib hoist -- --nocapture
17 passed; 4,581 filtered out

uv run maturin develop
success

uv run python tools/build_guard.py
fresh; SHA-256 2ac9670df266f034c3caa619e9e67ac54f6ebcd44ecfcc07aac95ce4cfecba4c

uv run python tools/dectest.py 03_loop_shapes:gcc:O0:for_sum --show
SCOPED: 1 lane of 838 - no regressions in scope

uv run pytest python/tests/test_test_census.py -q
6 passed
```

The regenerated census records 5,135 declared Rust tests and zero outside
every gate. No broad Rust/Python suite, fixture matrix, DecBench, or Joern lane
ran. This increment proves the condition-motion safety boundary; it does not
claim a corpus-wide output-quality movement.
