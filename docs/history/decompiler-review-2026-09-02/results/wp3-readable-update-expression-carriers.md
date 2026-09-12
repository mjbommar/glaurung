# WP3 readable updates through expression carriers

> **Kind:** record · **Date:** 2026-09-12

## Outcome

Commit `b6fd4d4e` makes the DecBench renderer's compound-assignment and global
unit-step recognizers inspect the semantic expression beneath `Expr::Origin`.
An instruction owner can therefore no longer turn an otherwise identical
`var += 2` or `counter++` update back into a verbose assignment. The repair
peels presentation-only integer casts when proving the self-update, but does
not cross `NumericConvert`; value-changing conversions remain visible.

This closes one WP3 expression-carrier consumer and one bounded WP7B
readability defect. It does not implement the planned SSA-native idiom
framework.

## Observed-red and focused verification

`authoritative_integer_local_keeps_attributed_compound_assignment` was first
observed rendering `var0 = (var0 + 2);` instead of `var0 += 2;`.
`attributed_global_unit_update_keeps_increment_syntax` was first observed
rendering `counter = (counter + 1);` instead of `counter++;`. Both pass after
the repair, along with the corresponding plain-expression controls and the
complete unit-step test filter.

```text
cargo test --features python-ext \
  authoritative_integer_local_keeps_attributed_compound_assignment --quiet
cargo test --features python-ext \
  attributed_global_unit_update_keeps_increment_syntax --quiet
cargo test --features python-ext \
  decbench_exact_sized_global_renders_as_a_scalar_object --quiet
cargo test --features python-ext \
  authoritative_integer_local_keeps_unit_step_syntax --quiet
cargo test --features python-ext unit_step --quiet

all commands passed
```

Filtered tests were not executed. The four exact static-local fixture lanes
also retain their semantic verdicts:

```text
uv run --no-sync python tools/dectest.py \
  '101_static_locals:*:*:counter_reset' --jobs 4 --full

4 passed; 0 regressions in scope
```

## Exact parent/tip output comparison

A clean detached worktree was release-built first at parent `56ed2f4c` and
then at exact tip `b6fd4d4e`. For both GCC O0 and Clang O0, `counter_reset`
moves from:

```c
generation = ((unsigned long)((unsigned int)(generation)) + 1);
```

to:

```c
generation++;
```

That is an attributable product-output improvement, not merely a unit-level
capability. GCC O2 and Clang O2 are byte-for-byte unchanged: both still create
`var1 = ((unsigned int)(generation) + 1)`, store `var1`, and return it. Those
cells require safe temporary-copy coalescing before the renderer can recognize
a direct self-update.

The final exact-tip release extension has SHA-256
`e8830ac5a08138f3ff9ffe2088ab25fbe30e266e3dc901b09b3c52e91e6f3c5d`.
No whole-Python, DecBench, or Joern gate was run for this bounded increment.

## Next boundary

Trace the O2 temporary through stable value identity and prove whether its
single store and return uses can be coalesced without crossing effects or
value-changing conversions. Keep that dataflow repair separate from rendering;
the renderer should continue recognizing only updates already proven direct.
