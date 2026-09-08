# WP3 SSE-pair object identity

Commit `e82617fd` removes one more display-name classification from canonical
local naming.

The SysV AMD64 naming pass now suppresses the ordinary `xmm0 -> ret` role only
when the AST contains the exact producer-owned synthetic object
`sse_pair_return_object`. A misleading value such as
`sse_pair_return_object#fake` no longer impersonates that object merely because
SSA suffix stripping makes its text look similar. The genuine materialized
SSE-pair path and the ordinary scalar-return path remain unchanged.

Focused validation only:

```text
cargo test --features python-ext --lib \
  ir::naming::tests::sse_pair_object_requires_its_exact_producer_owned_name \
  -- --exact
cargo test --features python-ext --lib \
  ir::naming::tests::materialized_sse_pair_keeps_integer_and_sse_scratch_identities_distinct \
  -- --exact
cargo test --features python-ext --lib \
  ir::naming::tests::ordinary_scalar_return_still_gets_ret_role_without_materialized_object \
  -- --exact
# 1 passed in each command; 4,492 filtered out in each

uv run maturin develop
uv run python tools/build_guard.py
# fresh; native SHA-256
# aa7ae00ada09b0caeccb5b7ec7053d1c67d67271d40885053423be18d5a34a68

uv run python tools/dectest.py \
  197_homogeneous_float_aggregates:gcc:O2:hfa197_tagged_control
# SCOPED: 1 lane of 838; no regressions in scope
```

No broad Rust/Python suite, fixture matrix, DecBench run, or Joern run was used.
