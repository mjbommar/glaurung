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
fresh; native SHA-256 21142b2d469ec16b3558e81db1da7ab606b78de198ec0d923a4a1565e33656e0
```

The exact real fixture probe
`95_function_pointer_table:gcc:O0:dispatch_operation` remains red. An A/B
rebuild that restored the production caller to the pre-increment compatibility
entry point produced byte-identical unresolved-table output and the same
`pass -> fail` verdict. This is therefore existing branch-tip debt rather than
a regression caused by the identity migration, but it remains open and is not
reported as green evidence.

No broad Rust or Python suite, fixture sweep, DecBench run, or Joern run was
performed for this bounded increment.
