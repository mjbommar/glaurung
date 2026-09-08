# WP3 boolean-expression origin rendering

> **Kind:** record · **Date:** 2026-09-08

## Outcome

Commit `56ed8169` makes the `_Bool` destination renderer transparent to the WP3
expression-origin carrier. A C comparison already evaluates to exactly zero or
one. Attaching instruction ownership does not change that fact, so an attributed
comparison now renders directly instead of becoming a redundant
`((unsigned char)(comparison) != 0)` expression.

This preserves the existing ABI safety rule for values that are not proven
normalized: arbitrary machine values returned as `_Bool` are still narrowed to
the ABI byte before the zero test. Only the metadata carrier is transparent.
This is one bounded output consumer, not universal expression attribution or
completion of WP3.

## Focused verification

The new contract was observed red before the production change:

```text
left:  "((unsigned char)((arg0 == 0)) != 0)"
right: "(arg0 == 0)"
```

After adding the origin-transparent recursion, the exact test passes:

```text
cargo test --features python-ext --lib \
  ir::ast::dec_render::boolean_origin_tests::attributed_comparison_remains_a_normalised_boolean \
  -- --exact
1 passed; 0 failed; 4,667 filtered out
```

After `uv run maturin develop --release`, the blast-radius check stayed within
the two directly relevant host fixture families:

```text
uv run python tools/dectest.py \
  89_bool_semantics 194_narrow_return_widths \
  --full --allow-stale
52 passed; 0 failed
```

The build guard still reported the concurrent uncommitted native-AArch64 source
as newer than the extension, so `--allow-stale` was required. The extension was
fresh for this owned `dec_render.rs` change. No broad Rust or Python suite,
cross-architecture corpus, DecBench, or Joern ran.

## Next boundary

Continue the non-exhaustive renderer-consumer audit with a separately observed
origin-carrier mismatch. Preserve each semantic and ABI refusal rule and test
only the owning unit plus its directly relevant fixture family.
