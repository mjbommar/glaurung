# WP3 pointer-call expression-origin rendering — 2026-09-08

> **Kind:** record · **Date:** 2026-09-08

Commit `90c21f7f` closes one bounded origin-consumer inconsistency at typed call
boundaries. It does not complete WP3's universal production attribution or
WP8's remaining corpus-wide declaration closure criterion.

## Defect and boundary

The pointer-compatibility oracle already treated `Expr::Origin` as a transparent
carrier, but the argument writer and the pointer-width transport-cast cleanup
matched the raw tree. That allowed the renderer to prove that a declared
pointer argument needed no conversion and then print the same value through its
machine-integer spelling.

Origins were added to the existing authoritative `strdup` contract around both
the pointer register and its pointer-width cast. Before the production repair,
the exact test failed with:

```c
saved_locale = (long)strdup((const char *)((long)((long)arg0)));
```

The repair makes only two reads semantic: the direct register check in
`write_call_arg_dec` and the transport-cast check in
`write_typed_call_arg_dec`. Origin sets remain attached to their expressions.
Pointer compatibility, declaration authority, cast width, and pointee-type
checks are unchanged. A second attributed contract proves that an incompatible
recovered `int *` parameter still receives an explicit conversion.

## Focused verification

```bash
export TMPDIR=/home/mjbommar/.cache/glaurung/tmp
cargo test --features python-ext --lib \
  ir::ast::tests::declared_pointer_call_keeps_parameter_types_when_result_needs_conversion \
  -- --exact
cargo test --features python-ext --lib \
  ir::ast::tests::decbench_recovered_pointer_parameter_is_reasserted_at_the_call \
  -- --exact
cargo test --features python-ext --lib \
  ir::ast::dec_render::pointer_parameter_tests
uv run maturin develop --release
uv run --no-sync pytest \
  python/tests/test_libc_pointer_roundtrip.py::test_nullable_saved_locale_pointer_round_trip -q
```

Results: both exact AST contracts pass with 4,669 unrelated tests filtered out;
all four pointer-parameter helper tests pass; and the one selected real C
round trip recompiles and executes equivalently. No broad fixture matrix or
whole repository suite was run for this bounded renderer change.

## Next action

Continue the WP3 renderer audit at the next raw typed call or destination
consumer. Require an existing semantic contract, preserve its refusal case,
and run only the real fixture that exercises the same boundary.
