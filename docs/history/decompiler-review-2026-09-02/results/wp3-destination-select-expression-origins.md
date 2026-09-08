# WP3 destination-select expression origins

Commit `80ec2b73` makes the destination-aware value renderer consume the
semantic expression beneath an `Expr::Origin` carrier before choosing its
select/cast conversion strategy. The origin set remains stored on the AST; it
no longer changes emitted C.

## Observed defect

The new exact renderer contract wraps the same mixed pointer/integer select in
an origin set and compares it with the unwrapped form. Before the repair, the
two forms differed:

```c
/* attributed */ var0 = (char *)((zf_0 ? (long)arg0 : 7));
/* plain */      var0 = (zf_0 ? arg0 : (char *)(7));
```

The outer cast in the attributed form is too late: C type-checks the two
conditional operands before applying it. The repaired forms are byte-identical
and retain the existing per-arm representation conversions.

## Focused evidence

All commands used `TMPDIR=/home/mjbommar/.cache/glaurung/tmp`.

```text
cargo test --features python-ext --lib \
  ir::ast::tests::attributed_pointer_assignment_select_is_render_byte_neutral \
  -- --exact
1 passed; 0 failed; 4,678 filtered out

cargo test --features python-ext --lib \
  ir::ast::tests::decbench_pointer_assignment -- --nocapture
2 passed; 0 failed; 4,677 filtered out

cargo test --features python-ext --lib \
  ir::ast::dec_render::boolean_origin_tests::attributed_comparison_remains_a_normalised_boolean \
  -- --exact
1 passed; 0 failed; 4,678 filtered out

uv run maturin develop --release
finished release profile; editable wheel installed

uv run --no-sync pytest \
  python/tests/test_decompiler_fixture_harness.py::test_real_pointer_word_select_converts_each_conditional_arm -q
1 passed
```

The Rust commands compiled the concurrent shared checkout, so their warning
stream includes unrelated in-flight files. Only `src/ir/ast.rs` and
`src/ir/ast/dec_render.rs` belong to this increment. No broad fixture or test
sweep was run.
