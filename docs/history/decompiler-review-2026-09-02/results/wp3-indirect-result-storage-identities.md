# WP3 indirect-result storage identities

Commit `b71cdc92` removes display-name parsing from the production indirect
aggregate-result consumer in `src/ir/aapcs64_indirect_result.rs`.

Before stack promotion, AArch64 `x8` buffer setup and AArch64/SysV frame
coordinates are now resolved through the pipeline-owned `ValueIdentities`
sidecar. After promotion, binding the named stack object to the call result uses
the same identity authority. Complete candidate sets must agree on one physical
storage base; missing, mixed, or non-physical candidates fail closed. The old
public entry points remain as explicit no-sidecar compatibility wrappers, while
`src/python_bindings/ir/pipeline.rs` always calls the identity-aware forms.

The exact regression proves both sides of the contract:

- opaque presentation values backed by exact `x8` and `sp` identities recover
  and bind the result buffer;
- a value whose text looks like versioned `x8` but whose identity is `x0` is
  rejected.

Focused validation only:

```text
cargo test --features python-ext --lib \
  ir::aapcs64_indirect_result::tests::indirect_result_storage_uses_exact_identity_not_display_spelling \
  -- --exact
# 1 passed; 4,485 filtered out

cargo test --features python-ext --lib ir::aapcs64_indirect_result::tests::
# 6 passed; 4,480 filtered out

uv run maturin develop
uv run python tools/build_guard.py
# fresh

uv run python tools/dectest.py \
  198_aggregate_return_edges:aarch64:O2:agr198_five_roundtrip --show
# SCOPED: 1 lane of 3304; no regressions in scope
```

No broad Rust/Python suite, fixture matrix, DecBench run, or Joern run was used
for this bounded increment.
