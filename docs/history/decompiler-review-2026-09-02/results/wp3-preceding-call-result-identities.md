# WP3 preceding-call result identities

Date: 2026-09-08

Source commit: `fba2ee95`

## Result

The backward call-argument scan now recognizes an explicit preceding-call
destination as ABI result storage through `ValueIdentities`. Every candidate
must be a result register for the active calling convention. Opaque exact
storage is therefore preserved when forwarded into the next call, while a
misleading result-register spelling backed by argument storage is rejected.

This is a call-definition storage classification only. It does not infer that
an arbitrary later AST presentation name is immutable.

## Focused verification

```text
cargo test --features python-ext --lib \
  preceding_call_result_uses_exact_identity_not_display_spelling -- --nocapture
1 passed; 0 failed; 4483 filtered out

cargo test --features python-ext --lib 'ir::call_args::'
143 passed; 0 failed; 4341 filtered out; 0.20s

uv run maturin develop
uv run python tools/build_guard.py
fresh

uv run python tools/dectest.py \
  11_call_shapes:clang:O0:call_into_spill --show
SCOPED: 1 lane of 838 - no regressions in scope
```

The initially selected GCC O2 form stopped at the existing fail-closed
`const_fold::fold_constants reported no change but edited the body` invariant.
An exact patch-off rebuild produced the identical infrastructure failure, so it
is not attributed to this increment. No broad Rust/Python suite, fixture sweep,
DecBench, or Joern ran.
