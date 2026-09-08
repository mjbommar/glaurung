# WP3 float-expression origin rendering

> **Kind:** record · **Date:** 2026-09-08

## Outcome

Commit `c2c7f36a` makes the typed decimal float renderer transparent to the
WP3 expression-origin carrier. `write_float_expr_dec` now renders the semantic
child of an attributed expression, and `float_rendered_width` obtains its width
from that same child. The carrier remains metadata rather than a C expression.

Before this change, attributed floating arithmetic lost its proven numeric
width at the final renderer and fell back to representation-oriented union-bit
spelling. The exact affected outputs included a binary32 negation and a
compensated binary64 expression. Both now render as direct floating arithmetic.
This is a bounded rendering-consumer migration, not universal expression
attribution or completion of WP3.

## Focused verification

The focused test was observed red before the production change: the attributed
expression had no rendered float width and emitted union-bit spelling. It now
retains width four and renders `(-1.0f)`:

```text
cargo test --features python-ext --lib \
  ir::ast::dec_render::float_origin_tests::attributed_float_arithmetic_remains_a_numeric_value \
  -- --exact
1 passed; 0 failed
```

After the required extension rebuild, these two exact compiled fixture cells
moved from regression to pass:

```text
uv run python tools/dectest.py \
  174_float_compare_classify:armv7:O2:negate_binary32 \
  181_compensated_summation:armv7:O2:compensation_of_step \
  --full --show --allow-stale
2 passed; 0 failed
```

A release-built blast-radius check was restricted to the directly relevant
float/vector families on ARMv7 and AArch64, 32 binary lanes in total. It removed
the two intended ARMv7 regressions with no attributable addition. The remaining
AArch64 O0 `int32_round_trip_delta` regression produced byte-identical output in
an exact one-file parent/tip reversal, so it remains separate baseline debt.

No broad Rust or Python suite, full fixture corpus, DecBench, or Joern ran.

## Next boundary

Continue the WP3 consumer audit from an independently observed origin-carrier
failure. Keep recognition and refusal proofs unchanged, and use exact fixture
A/B checks rather than broad unrelated suites.
