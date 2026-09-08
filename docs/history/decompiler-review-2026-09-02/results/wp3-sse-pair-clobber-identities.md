# WP3 SSE-pair clobber identities

Date: 2026-09-08

Source commit: `094c1055`

## Result

The contract-proved SysV SSE-pair forwarding path now detects intervening
writes through complete `ValueIdentities` candidates rather than destination
text. Opaque exact pair/lane storage blocks forwarding. A misleading
`xmm1#...` presentation value backed by integer storage does not.

The recovered consumer layout and producer/consumer prototypes remain the
authoritative facts that permit forwarding; this change only makes the
clobber refusal exact.

## Focused verification

```text
cargo test --features python-ext --lib \
  sysv_sse_pair_clobber_uses_exact_identity_not_display_spelling -- --nocapture
1 passed; 0 failed; 4484 filtered out

cargo test --features python-ext --lib 'ir::call_args::'
144 passed; 0 failed; 4341 filtered out; 0.20s

uv run maturin develop
uv run python tools/build_guard.py
fresh

uv run python tools/dectest.py \
  217_complex_arithmetic:clang:O2:complex_multiply --show
SCOPED: 1 lane of 838 - no regressions in scope
```

No broad Rust/Python suite, fixture sweep, DecBench, or Joern ran.
