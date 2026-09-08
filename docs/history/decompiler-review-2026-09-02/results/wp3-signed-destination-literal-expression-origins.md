# WP3 signed destination-literal expression origins — 2026-09-08

> **Kind:** record · **Date:** 2026-09-08

Commit `8e8e63d7` closes one exact destination-side origin consumer. It does not
complete WP3 or the general WP6 signedness solver.

## Defect and boundary

The typed destination renderer already canonicalizes a positive all-ones
machine literal to its signed source value when the consuming declaration
proves the exact narrow signed type. For `int32_t`, `0xffffffff` therefore
renders as `-1`, avoiding an implementation-defined out-of-range conversion
and producing the readable value intended by source such as the motivating
`classify` example.

That rule matched only a raw `Expr::Const`. Adding an origin carrier to its
existing assignment contract reproduced:

```c
int var0;
var0 = 0xffffffff;
```

The repair makes that single constant read semantic. Its existing helper still
declines negative values, unsigned and boolean destinations, pointers, 64-bit
destinations, and values outside the exact narrow bit pattern.

## Focused verification

```bash
export TMPDIR=/home/mjbommar/.cache/glaurung/tmp
cargo test --features python-ext --lib \
  ir::ast::tests::signed_destination_spells_an_all_ones_literal_as_minus_one \
  -- --exact
cargo test --features python-ext --lib \
  ir::ast::tests::signed_destination_literal_spelling_preserves_every_narrow_bit_pattern \
  -- --exact
uv run maturin develop --release
uv run --no-sync python tools/dectest.py \
  '97_signed_unsigned_pitfalls:*:*:size_like_loop' --full --show
```

Results: both exact Rust contracts pass with 4,671 unrelated tests filtered
out; the exhaustive test checks every 8- and 16-bit pattern plus the signed and
unsigned 32-bit boundaries. All four selected Clang/GCC O0/O2 fixture lanes
pass with no regression in scope. No broad fixture matrix or whole repository
suite was run.

## Next action

Continue the destination-side audit with aggregate and scalar-float direct
register readers. Each must preserve its exact declaration proof and retain the
machine-carrier fallback for any unproven or incompatible source.
