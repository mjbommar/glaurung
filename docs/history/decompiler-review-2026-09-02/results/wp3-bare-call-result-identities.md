# WP3 bare call-result identities

Date: 2026-09-08

Source commit: `4ce03e4f`

## Result

The call-argument folder no longer uses an unversioned-looking return-register
name to decide whether a preceding call destination needs a fresh result value.
With production identities, every candidate must be version-zero ABI result
storage. An opaque entry carrier is replaced and forwarded consistently; an
opaque versioned result remains explicit; a misleading `rax#...` value backed
by argument storage is not rewritten.

This classifies the call definition only and does not treat an arbitrary AST
presentation name as immutable after coalescing.

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

No broad Rust/Python suite, fixture sweep, DecBench, or Joern ran.
