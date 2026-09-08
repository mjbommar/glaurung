# WP3 float-register identities

Commit `64eb116d` removes display-name classification from production scalar
float gating and LLIR-to-AST lowering.

The pipeline-owned `ValueIdentities` sidecar now travels into AST lowering,
including every structured, raw-loop, switch, and multi-exit recursive path.
The scalar-float gate uses exact canonical storage identities to decide:

- whether a value belongs to the ARM VFP, x86 SSE, or x87 register bank;
- whether a call has a modeled floating result;
- whether the function's float registers are all caller-saved; and
- whether packed dword lanes and `vmov` operands have the required storage
  shape.

Missing or ambiguous production identity evidence declines the classification.
The spelling fallback remains only for compatibility and isolated test callers
that do not carry the sidecar. The reusable caller-environment mini-pipeline
also passes its existing sidecar into lowering.

The adversarial regression proves that an opaque value backed by `xmm0` is
recognized, a value merely spelled `xmm0#looks_float` but backed by `rax` is
rejected, and an ambiguous `xmm1`/`rcx` value fails closed.

Focused validation only:

```text
cargo test --features python-ext \
  ir::ast::float_gate::tests::float_register_roles_use_exact_identity_not_display_spelling \
  --no-fail-fast
# 1 passed; 4,490 filtered out at the first exact run

cargo test --features python-ext ir::ast::float_gate::tests --no-fail-fast
# 2 passed; 4,489 filtered out

uv run maturin develop
uv run python tools/build_guard.py
# fresh; native SHA-256
# 91cce5709aee2521f2730d78473a280109bb0535cd4ccc45b7be1fdf0bd272b0

uv run python tools/dectest.py \
  197_homogeneous_float_aggregates:gcc:O2:hfa197_tagged_control --show
# SCOPED: 1 lane of 838; no regressions in scope
```

No broad Rust/Python suite, fixture matrix, DecBench run, or Joern run was used
for this bounded increment.
