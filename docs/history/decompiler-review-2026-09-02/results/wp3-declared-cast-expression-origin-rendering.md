# WP3 declared-cast expression-origin rendering

> **Kind:** record · **Date:** 2026-09-08

## Outcome

Commit `40da0e41` makes the typed renderer's redundant integer-promotion proof
transparent to WP3 expression-origin carriers inside a cast chain. A declared
`signed char` promoted through its ordinary C integer promotion now renders as
`local_byte == 97`, even when the byte value and narrow cast carry instruction
attribution, instead of expanding back to:

```c
(int)((signed char)(local_byte)) == 97
```

The proof is also stricter than the pre-migration implementation: it compares
the cast's signedness and width with the declaration actually selected for
output. It does not trust a conflicting internal type fact for a renamed value.
That distinction preserves semantically necessary conversions such as
`uint32_t` to `uint64_t` before multiplication or shifting.

This is a bounded render-consumer migration, not completion of WP3 expression
attribution or the general WP7B idiom framework.

## Focused verification

The existing typed-promotion contract was strengthened with independent origins
inside both cast layers. It was observed red before the production change. The
positive contract and its adjacent signed-comparison refusal pass after the
fix:

```text
cargo test --features python-ext --lib \
  ir::ast::tests::decbench_uses_declared_integer_promotions_and_array_index_conversion \
  -- --exact
1 passed; 0 failed; 4,670 filtered out

cargo test --features python-ext --lib \
  ir::ast::tests::signed_comparison_drops_only_a_value_preserving_declared_widening \
  -- --exact
1 passed; 0 failed; 4,670 filtered out
```

The filtered count increased by one during the work because another shared
checkout lane added a Rust test; this increment itself adds no test declaration
and therefore requires no generated census edit.

After `uv run maturin develop --release`, the fixture canary was restricted to
the directly relevant host integer-width families:

```text
uv run python tools/dectest.py \
  02_integer_widths 96_integer_promotion \
  97_signed_unsigned_pitfalls 194_narrow_return_widths \
  --jobs 4
```

The current shared tip reports four pass-to-fail movements, all in fixture-02
O0 `mul_widen` and `rt_u64` for GCC and Clang. An exact A/B reversed only the
owned `dec_render.rs` diff, rebuilt release, and reran those four cells; all four
remained failures. The owned patch was then restored and the release extension
rebuilt. Those movements are therefore not attributed to this increment and
remain separate shared-tip drift.

No broad Rust or Python suite, cross-architecture corpus, DecBench, or Joern
ran.

## Next boundary

Add a real typed field-address rendering contract before migrating
`renderable_field_access`. Preserve layout selection, identifier validity,
single-hint, scale/index, and emitted-struct refusals.
