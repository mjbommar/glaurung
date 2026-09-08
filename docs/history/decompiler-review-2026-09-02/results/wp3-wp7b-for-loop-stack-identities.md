# WP3/WP7B for-loop stack identities

> **Kind:** record · **Date:** 2026-09-08

## Outcome

Commit `50cc926d` moves store-backed induction-variable recognition from
`local_`/`stack_` display spelling to stack-promotion ownership. Recursive
counted-loop promotion receives the pipeline's `ValueIdentities` sidecar. An
opaque owned object can therefore become the initializer and unit step of an
exact `for` loop, while an unowned value merely named `local_i` declines.

The compatibility entry point retains its spelling rule when no sidecar is
available. The existing requirements remain unchanged: adjacent initializer,
same-variable loop condition and unit iterator, and no control transfer that
can bypass the iterator.

## Focused validation

```text
cargo test --features python-ext --lib ir::loop_form::tests -- --nocapture
31 passed; 4,572 filtered out

uv run maturin develop
success

uv run python tools/build_guard.py
fresh; SHA-256 bf34d130631f3cf2943cd4c65aa4a6bcbc009e5a5a6ded5445b7d6b7eb654044

uv run python tools/dectest.py 03_loop_shapes:gcc:O0:for_sum --show
SCOPED: 1 lane of 838 - no regressions in scope

uv run pytest python/tests/test_test_census.py -q
6 passed
```

The regenerated census records 5,140 declared Rust tests and zero outside
every gate. No broad Rust/Python suite, fixture matrix, DecBench, or Joern lane
ran. This proves the identity authority and one counted-loop integration cell;
it does not complete the general WP7B idiom framework.
