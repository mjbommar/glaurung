# WP3 pointer-destination expression-origin rendering — 2026-09-08

> **Kind:** record · **Date:** 2026-09-08

Commit `0cd9dcaf` closes the pointer-valued portion of one destination-side
origin consumer. It does not complete the remaining aggregate, select,
constant, or universal WP3 renderer audit.

## Defect and boundary

At a pointer-typed assignment or return, the renderer can remove exactly one
pointer-width integer transport cast when its underlying value already has a
declared pointer type. It can also retain a real pointer-to-pointer conversion
when source and destination pointee types differ. Those checks matched the raw
expression tree while the general pointer-representation oracle already treated
`Expr::Origin` as transparent.

Origins were added around both the transport cast and its pointer register in
the existing return test. Before the repair, the same-type case regressed to:

```c
return (char *)((long)((long)arg0));
```

The repair makes the pointer-only destination reads semantic. Afterward the
same source returns `arg0` directly, while rendering it against `int *` retains
the required `(int *)arg0`. It does not change pointer-width checks, source or
destination declarations, stack-object handling, field-pointer proofs, or
pointee compatibility.

## Focused verification

```bash
export TMPDIR=/home/mjbommar/.cache/glaurung/tmp
cargo test --features python-ext --lib \
  ir::ast::tests::pointer_return_strips_integer_transport_but_keeps_real_pointer_conversion \
  -- --exact
cargo test --features python-ext --lib \
  ir::ast::tests::declared_pointer_call_keeps_parameter_types_when_result_needs_conversion \
  -- --exact
uv run maturin develop --release
uv run --no-sync pytest \
  python/tests/test_libc_pointer_roundtrip.py::test_nullable_saved_locale_pointer_round_trip -q
```

Results: both exact Rust contracts pass with 4,671 unrelated tests filtered
out, and the one selected nullable-locale round trip compiles and executes
equivalently. No broad fixture matrix or whole repository suite was run for
this bounded renderer change.

## Next action

Continue within `write_representation_value_dec`: make the select and outer-
cast shape readers transparent only after their mixed pointer/integer arm
contracts carry origins and preserve the existing per-arm conversion rules.
