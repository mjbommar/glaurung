# WP3 pointer-null expression-origin rendering

> **Kind:** record · **Date:** 2026-09-08

## Outcome

Commit `6e867230` makes pointer-null comparison rendering transparent to WP3
expression-origin carriers. A direct value with an authoritative pointer
declaration now remains a C pointer on either side of `==` or `!=` when the
pointer, the zero constant, or both carry instruction attribution. Previously,
the metadata hid those facts and the renderer emitted the pointer's integer
machine representation, for example `(long)arg0 != 0`.

The rule remains deliberately narrow. It accepts only direct proven pointer
values and lossless pointer-width casts. A narrowing cast is still rendered
explicitly, and arbitrary address arithmetic still crosses the integer
representation boundary. This is one bounded render-consumer migration, not
completion of WP3 identity or expression attribution.

## Focused verification

The existing direct-pointer contract was strengthened with independent origins
on both pointer/null operand orders. Before the production change, the exact
test was observed red with:

```c
while ((long)arg0 != 0) {
```

After zero recognition and the direct-pointer semantic reader were made
carrier-transparent, both focused contracts pass:

```text
cargo test --features python-ext --lib \
  ir::ast::tests::declared_pointer_null_test_does_not_round_trip_through_an_integer \
  -- --exact
1 passed; 0 failed; 4,669 filtered out

cargo test --features python-ext --lib \
  ir::ast::tests::narrowing_pointer_cast_in_null_test_remains_explicit \
  -- --exact
1 passed; 0 failed; 4,669 filtered out
```

After `uv run maturin develop --release`, the canary was limited to four
pointer and scaled-address fixture families:

```text
uv run python tools/dectest.py \
  110_pointer_arithmetic 192_pointer_chased_list \
  199_pointer_return_kinds 207_scaled_index_addressing \
  --jobs 4 --full
```

All 16 selected binary lanes report no regression. The two printed Clang O2
fixture-207 failures are existing baseline failures, so the harness summary is
`SCOPED: 16 lanes of 838 (2%) — no regressions in scope`.

No broad Rust or Python suite, cross-architecture corpus, DecBench, or Joern
ran. No census baseline changed because both contracts extend existing tests.

## Next boundary

Continue the pointer-render audit with field-address recognition and declared
integer casts. Preserve exact field-layout, pointer-width, and
representation-boundary refusals.
