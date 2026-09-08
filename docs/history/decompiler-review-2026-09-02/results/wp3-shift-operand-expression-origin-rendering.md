# WP3 shift-operand expression-origin rendering

> **Kind:** record · **Date:** 2026-09-08

## Outcome

Commit `c5a623ad` completes the adjacent shift-render semantic readers. The
logical-right-shift renderer now recognizes attributed constant counts and
attributed exact-width operands. The wide-left-shift renderer likewise sees an
attributed declared narrow register and count, preserving the source-width
zero-extension before a wider machine shift.

Without the first rule a four-byte load rendered through host `unsigned long`.
Without the second, `(int32_t)x << 33` was emitted directly even though that C
expression is undefined and does not describe the 64-bit machine operation.
Instruction provenance now remains metadata at both decisions. Existing width,
count-range, declaration, and supported-target refusal rules are unchanged.

This is a bounded semantic-reader migration, not universal expression
attribution or completion of WP3.

## Focused verification

Two contracts were observed red before the production change. The attributed
logical shift widened a four-byte load:

```c
((unsigned long)(*(int *)(arg0)) >> 8)
```

The attributed wide-left shift discarded the required zero-extension:

```c
(arg0 << 33)
```

Both exact tests pass after the four metadata-transparent reads:

```text
cargo test --features python-ext --lib \
  ir::ast::tests::decbench_logical_shift_uses_the_exact_load_width -- --exact
1 passed; 0 failed; 4,669 filtered out

cargo test --features python-ext --lib \
  ir::ast::tests::decbench_wide_left_shift_keeps_declared_narrow_operand_through_origins \
  -- --exact
1 passed; 0 failed; 4,669 filtered out
```

After a release extension rebuild, the canary stayed limited to the shift
fixture and the two aggregate-carrier families explicitly named by the wide
shift invariant:

```text
uv run python tools/dectest.py \
  98_shift_semantics 197_homogeneous_float_aggregates \
  198_aggregate_return_edges --full --allow-stale
```

Every function that directly exercises the intended shift producers remains
green. Six aggregate round-trip cells were baseline regressions in the shared
checkout. Reversing only this commit's four production reads, rebuilding, and
rerunning those six exact cells reproduced all six failures unchanged, so none
is attributed to this slice.

The build guard reported a concurrent uncommitted native-AArch64 source newer
than the extension, so `--allow-stale` was required; each A/B extension was
fresh for the owned production state. No broad Rust or Python suite,
cross-architecture corpus, DecBench, or Joern ran.

## Next boundary

Continue into the pointer/array renderer consumers, where origins around a base,
scale, or offset must not hide a separately proven `base[index]` form. Preserve
the exact pointee-width and scale gates.
