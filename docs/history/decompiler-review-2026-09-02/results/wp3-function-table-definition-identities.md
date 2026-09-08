# WP3 function-table reaching-definition identities

Commit `33371b23` removes a production semantic dependency on value-numbered
display spelling from `src/ir/function_tables.rs`.

Function-table recovery carries address proofs across structured branches when
the branch cannot overwrite their definitions. A nested call must invalidate
ordinary physical-register proofs, but it cannot overwrite an explicit SSA
value. The pass previously distinguished those cases with `name.contains('#')`.
The production pipeline now supplies `ValueIdentities`; a physical definition
survives only when every identity represented by that value is an explicit
non-entry SSA definition. Missing, entry, and mixed identity sets fail closed.
The no-sidecar entry point retains its spelling behavior for compatibility
tests while consumers migrate incrementally.

This advances WP3's semantic-consumer migration. It does not complete SSA
invalidation, origin propagation, or removal of value-numbered display names.

## Focused validation

All commands used `TMPDIR=/home/mjbommar/.cache/glaurung/tmp`.

```text
cargo test --features python-ext --lib ir::function_tables::tests:: -- --nocapture
12 passed; 0 failed; 4,495 filtered out

uv run maturin develop
passed; debug extension rebuilt

uv run python tools/build_guard.py
fresh; native SHA-256 2e20be293e61cbfd1f4583686650ee60eff48d6141e8ffb09826b4dafb658416

uv run python tools/dectest.py \
  95_function_pointer_table:gcc:O0:dispatch_operation --show
1 of 838 lanes selected; no regression in scope
```

After the topic branch merged to `master`, the exact real fixture probe exposed
adjacent WP3 debt: expression origins wrapped its scaled table index, while the
address proof stripped casts but not origin carriers. Commit `b5f96b91` makes
this semantic inspection origin-transparent and adds the exact wrapped-index
unit regression. The owning module then passed 13 tests with 4,575 filtered
out; a fresh native rebuild returned the single fixture cell from `pass ->
fail` to no regression in scope.

No broad Rust or Python suite, fixture sweep, DecBench run, or Joern run was
performed for this bounded increment.
