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

## Internal authority closure

Follow-on commit `58fa0cdf` removes the remaining optional-identity engine from
function-table recovery. Non-test builds can now construct only
`FunctionTableAuthority::Exact(&ValueIdentities)`; the legacy spelling route and
the untyped top-level adapter compile only for unit tests over hand-written
ASTs. Reaching-definition retention and promoted-stack invalidation therefore
cannot silently fall back to `#version` spelling in shipped code.

Focused evidence:

```text
cargo test --features python-ext ir::function_tables::tests:: --lib -- --test-threads=1
20 passed; 0 failed; 4826 filtered out

cargo check --features python-ext
exit 0

uv run maturin develop
exit 0

uv run python tools/build_guard.py
fresh
```

The required post-commit Python gate was run once with fail-fast. It passed the
former ARM Thumb and hard-float blockers, then stopped at the independently
known committed-baseline disagreement at 17%:

```text
uv run pytest -q python/tests/ -x
FAILED test_decompiler_arch_roundtrip.py::test_the_committed_baseline_is_valid_and_has_a_clean_control_lane
```

The disagreement is the already-recorded x86-64 control verdict mismatch for
fixtures 157, 172, and 81. Neither baseline was regenerated from the shared
dirty checkout. No fixture sweep, DecBench, Joern, output, corpus, or timing
claim accompanies this authority-only follow-on. Function-table identity
authority is now closed; wider WP3 invalidation and origin work remains.
