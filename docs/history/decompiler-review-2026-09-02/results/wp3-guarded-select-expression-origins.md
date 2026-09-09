# WP3 guarded-select-return expression origins

Commit `2d7f9e6a` closes the expression-carrier boundary in
`select_fold::recover_guarded_select_returns`.

The statement-level migration at `e92d7248` preserved owners after this fold,
but expression carriers could still block its proof. An attributed initializer
was no longer recognized as a movable register view; attributed select and
terminal-result roots did not match their semantic shapes; and attributed
comparison operands blocked the stronger false-edge `return 0` result.

The repair uses semantic projections only for recognition and equality. It
retains the original owned predicate, arms, and default value in the output.
Owners on a consumed select root and terminal result read transfer to the
replacement statements. When the default expression is proved equal to the
tested value and replaced by zero, its complete deterministic expression-origin
tree transfers to the synthesized constant. The existing no-memory-movement,
single-statement-arm, same-result, no-self-read, and exact-comparison gates are
unchanged.

## Focused evidence

The strengthened full-expression ownership contract was observed red before
repair: the three-statement input remained unchanged. The false-edge contract
then exposed a second red result: structure recovered, but the eliminated
default expression's owner was absent from `return 0`.

```text
cargo test --features python-ext --lib \
  ir::select_fold::tests::attributed_guarded_select_distributes_consumed_origins \
  -- --exact
1 passed; 4,732 filtered out

cargo test --features python-ext --lib \
  ir::select_fold::tests::guarded_return_select_recovers_nested_direct_returns \
  -- --exact
1 passed; 4,732 filtered out

cargo test --features python-ext --lib ir::select_fold::tests::
23 passed; 4,710 filtered out
```

An exact detached release build of `2d7f9e6a` passed the build guard with native
SHA-256 `f494bbf05ecfc3937ae307af82324a56eb385978dfddc3e9ede839457c9ad31b`.
The directly owning real integration test also passes:

```text
pytest -q \
  python/tests/test_decompiler_fixture_structural.py::test_nested_conditional_result_recovers_direct_returns
1 passed
```

Direct inspection of GCC O2 `tests/decbench_corpus/src/branches.c:nested`
shows two nested `if`s, three direct returns, no ternary, and no result join
temporary. Width casts around the two predicates remain separate WP6/WP7
readability work.

No broad Rust, Python, fixture, DecBench, or Joern suite ran. This closes one
guarded-select expression family, not WP3; universal attribution and the
remaining identity/expression consumers remain open.
