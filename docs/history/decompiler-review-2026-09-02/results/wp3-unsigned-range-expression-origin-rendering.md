# WP3 unsigned-range expression-origin rendering

> **Kind:** record · **Date:** 2026-09-08

## Outcome

Commit `b6786298` makes the typed renderer's unsigned-subtract range idiom
transparent to WP3 expression-origin carriers. Metadata around the comparison
bound, integer casts, subtraction/addition shell, or source value no longer
prevents the existing width and range proof from recognizing compiler forms
such as `(unsigned)(x - low) <= span`.

The output recovers the readable, width-explicit two-sided range rather than
falling back to raw unsigned machine arithmetic. Width, representability,
operator, and bound proofs are unchanged. This is one bounded render consumer,
not universal expression attribution or completion of WP3.

## Focused verification

The existing typed-render test was strengthened with independent origins on the
bound, arithmetic shell, and offset. Before the production change it was red:

```c
if ((unsigned long)(15) < (unsigned long)((arg0 + -1)))
```

After making only the cast/range readers carrier-transparent, the exact test
passes and retains its expected source-level spelling:

```c
(unsigned int)(arg0) < 1 || 16 < (unsigned int)(arg0)
```

```text
cargo test --features python-ext --lib \
  ir::ast::tests::typed_renderer_spells_reversed_unsigned_subtract_as_an_explicit_range \
  -- --exact
1 passed; 0 failed; 4,668 filtered out
```

After the required release rebuild, a host-only run covered the three fixture
families whose sources contain the relevant range guards:

```text
uv run python tools/dectest.py \
  165_bitstream_reader 172_float_double_widths 173_float_int_conversions \
  --full --allow-stale
```

That narrow run reported two `bit165_roundtrip` regressions and one
`single_precision_horner` improvement. Reversing only this commit's production
lines, rebuilding, and rerunning those exact three functions reproduced the
same two failures and one pass. They therefore belong to concurrent checkout
changes or pre-existing baseline movement, not this range-render slice.

The build guard reported a concurrent uncommitted native-AArch64 source newer
than the extension, so `--allow-stale` was required; each A/B extension was
fresh for the owned production state it measured. No broad Rust or Python
suite, full corpus, DecBench, or Joern ran. No census baseline changed because
this commit strengthens an existing test rather than declaring another one.

## Next boundary

Continue the non-exhaustive expression-consumer audit from an independently
observed carrier mismatch. Preserve every semantic refusal rule, and attribute
fixture movement only after an exact owned-line A/B.
