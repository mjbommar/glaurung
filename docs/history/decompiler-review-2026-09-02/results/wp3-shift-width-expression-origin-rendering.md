# WP3 shift-width expression-origin rendering

> **Kind:** record · **Date:** 2026-09-08

## Outcome

Commit `2c9a91bf` makes the integer shift-width readers transparent to WP3
expression-origin carriers. `expr_machine_width` now obtains explicit cast,
load, call-result, select, and width-preserving arithmetic widths through
metadata. `signed_shift_operand` likewise follows attributed cast chains and an
attributed constant count when choosing the narrowest signed operand width that
can legally supply the shift.

This prevents provenance from widening a 32-bit or narrower operation to host
`long`, which can change the value of right shifts rather than merely changing
their spelling. The existing count-range, supported-width, signedness, and
unknown-operand refusal rules remain intact. This is a bounded semantic reader
migration, not universal expression attribution or completion of WP3.

## Focused verification

Two existing contracts were strengthened with independent origins. Both were
observed red before the production change:

```text
a_cast_states_the_machine_width_of_the_expression_it_wraps
left: None
right: Some(4)

arithmetic_right_shift_keeps_its_signed_machine_width
left: "long"
right: "int"
```

After the carrier-transparent readers were added, exactly those two contracts
pass:

```text
cargo test --features python-ext --lib machine_width
2 passed; 0 failed; 4,667 filtered out
```

After `uv run maturin develop --release`, the fixture canary was restricted to
the host shift-semantics and narrow-return families:

```text
uv run python tools/dectest.py \
  98_shift_semantics 194_narrow_return_widths \
  --full --allow-stale
60 passed; 0 failed
```

The build guard reported a concurrent uncommitted native-AArch64 source newer
than the extension, so `--allow-stale` was required. The extension was fresh for
this owned `ast.rs` change. No broad Rust or Python suite, cross-architecture
corpus, DecBench, or Joern ran. No census baseline changed because the commit
strengthens existing tests rather than declaring another one.

## Next boundary

Continue the non-exhaustive expression-consumer audit from an independently
observed carrier mismatch. Preserve width and effect refusal rules, and keep the
fixture canary tied to the affected expression family.
