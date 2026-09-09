# WP3 promoted-diamond expression origins

Commit `3e8bc8dc` closes the remaining expression-carrier boundary in
`select_fold::select_from_diamond` for promoted stack locals.

Two branches that store alternative values into the same promoted local should
become one store of a lazy select. The recognizer previously required each
store address to be a bare register expression. Instruction-origin ownership
around that address therefore prevented the structural recovery and left an
otherwise reducible `if` in the output.

The repair identifies the address through its semantic expression. It retains
the exact promoted-local and same-destination checks, preserves the condition
and alternative-value owners on the recovered select, and transfers both
consumed address owners together with both arm statements and the original
diamond to the synthesized store.

## Focused evidence

The strengthened attributed promoted-local contract was observed red before
the repair: the diamond remained an `if` instead of collapsing to one store.

```text
cargo test --features python-ext --lib \
  ir::select_fold::tests::promoted_local_assignment_diamond_becomes_a_nonterminal_select \
  -- --exact --quiet
1 passed; 4,733 filtered out

cargo test --features python-ext --lib ir::select_fold::tests:: --quiet
24 passed; 4,710 filtered out
```

An exact detached release build of `3e8bc8dc` passed the build guard with native
SHA-256 `160e585c20d4fd4b625dafa59c65d97e8d15f51b79c6300dec210f66cae03810`.
The adjacent real select-fold controls pass:

```text
pytest -q \
  python/tests/test_decompiler_fixture_structural.py::test_signs_renders_lifted_select_as_pure_ternary
2 passed (GCC O0 and O2)
```

The promoted-address path is pinned directly by the Rust contract; the real
fixture is the adjacent end-to-end select-fold control. No broad Rust, Python,
fixture, DecBench, or Joern suite ran. The 12-cell cross-architecture Hello
checkpoint passed two increments earlier and was not repeated for this local
recognizer repair.
