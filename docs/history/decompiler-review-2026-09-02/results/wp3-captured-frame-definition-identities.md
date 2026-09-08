# WP3 captured frame-definition identities

Status: bounded production consumer migration landed at `d2518e37` on
`agent/wp5-next-switch`.

## Result

Call-argument recovery now classifies stable frame loads and intervening frame
writes through exact `ValueIdentities`. An opaque AST register whose SSA base
is `rbp` or `ebp` qualifies as a frame coordinate; a scratch value merely
spelled `rbp#version` does not. The same rule governs fixed-frame reads,
potentially aliasing stores, and frame-base invalidation.

Missing or ambiguous production identity declines the optimization. Explicit
no-sidecar compatibility entry points retain the pre-migration spelling rule.

## Focused evidence

```text
cargo test --features python-ext --lib \
  ir::call_args::tests::stable_frame_load_uses_exact_identity_not_display_spelling \
  -- --exact
1 passed; 0 failed; 4,472 filtered out

cargo test --features python-ext --lib ir::call_args -- --nocapture
132 passed; 0 failed; 4,341 filtered out
elapsed 9.8 s including incremental compilation

uv run maturin develop
completed

uv run python tools/build_guard.py
fresh

uv run python tools/dectest.py \
  11_call_shapes:clang:O0:call_into_spill --show
1 of 838 lanes selected; no regression in scope
```

Build fingerprint: commit `d2518e37`, debug Cargo/maturin profile, CPython
3.14, and `python-ext` enabled.

## Measurement boundary

The owning Rust module and one directly related C fixture lane passed. No broad
Rust/Python suite, fixture matrix, DecBench, Joern, GED, performance, or
corpus-wide execution measurement ran. This deliberately follows the bounded
WP3 iteration rule; wider gates are paid once for a coherent source batch.

## Remaining scope

This removes captured-definition frame aliasing from the production
semantic-name surface. Stack-area recovery, slot marking, and the remaining
AAPCS/cdecl readers still parse architectural display names and remain separate
WP3 migrations. WP3 remains open.
