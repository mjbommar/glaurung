# WP3 pointer/null select expression-origin rendering

> **Kind:** record · **Date:** 2026-09-08

## Outcome

Commit `d9cbaca6` completes the pointer/null select boundary queued by the
earlier pointer-destination audit. A zero arm wrapped in an expression-origin
carrier is now recognized as the null pointer constant in either arm order.
When the other arm is an exact declared pointer identity, the select renders
that identity as a native C pointer rather than its generic integer-address
representation.

This is deliberately narrower than general pointer/integer selection. A
nonzero integer arm still forces both arms through the common machine
representation, and a narrowing pointer cast remains explicit.

## Focused TDD

The bidirectional attributed contract was observed red as:

```text
while ((zf_0 ? (long)arg0 : 0) != 0)
while ((zf_1 ? 0 : (long)arg0) != 0)
```

After the repair, both conditionals retain the native pointer/null form. The
positive and adjacent refusals pass:

```text
cargo test --features python-ext --lib \
  ir::ast::tests::attributed_pointer_null_select_keeps_the_native_null_pointer_form \
  -- --exact
1 passed; 0 failed; 4,674 filtered out

cargo test --features python-ext --lib \
  ir::ast::tests::decbench_casted_select_converts_pointer_and_integer_arms_before_selection \
  -- --exact
1 passed; 0 failed; 4,674 filtered out

cargo test --features python-ext --lib \
  ir::ast::tests::narrowing_pointer_cast_in_null_test_remains_explicit -- --exact
1 passed; 0 failed; 4,674 filtered out
```

## Release real-binary evidence

After the required release rebuild, the established nullable-locale pointer
round trip still compiles and executes equivalently:

```text
uv run --no-sync pytest \
  python/tests/test_libc_pointer_roundtrip.py::test_nullable_saved_locale_pointer_round_trip -q
1 passed
```

The release extension included unrelated concurrent Rust edits in the shared
worktree, so this is shared-snapshot regression evidence rather than a clean-
tip performance measurement. No broad fixture matrix or baseline refresh was
run.

## Scope

This closes one bounded WP3 scored-text consumer. It does not infer new pointer
types, weaken representation boundaries, or complete universal expression
attribution.
