# WP3: typed lowering retains return-fold authority

> **Kind:** record · **Date:** 2026-09-13

## Outcome

Commit `122730b4` closes an identity-loss seam at the final LLIR-to-AST
boundary. `lower_with_identities` now requires `&ValueIdentities` and uses the
typed return-fold entry point. An assignment merely rendered as `ret` can no
longer authorize return materialization unless the value-numbering sidecar
owns the ABI-result role.

The identity-free `lower` entry point remains as an explicit compatibility
surface. It continues to use the legacy spelling fold, while the Python
decompile pipeline, caller-environment analysis, canary example, and all three
IR/decompile Criterion benchmarks use typed lowering. A search of
`benches/*.rs` finds no remaining `ast::lower` call.

## Focused evidence

The new regression constructs real LLIR with an unowned physical value named
`ret`. Typed lowering preserves the assignment and return as two statements;
the compatibility control retains its historical one-statement fold. The
first assertion was observed red because the control statement was wrapped in
an origin node; unwrapping through the public semantic view corrected the test
without weakening the identity contract.

```text
cargo test -q --features python-ext \
  typed_lowering_does_not_trust_an_unowned_result_spelling
exit 0

cargo test -q --features python-ext \
  return_fold_does_not_trust_an_unowned_ret_spelling
exit 0

cargo test -q --features python-ext \
  return_fold_accepts_a_pipeline_owned_ret_role
exit 0

cargo check -q --features python-ext --lib
cargo check -q --features python-ext --bench ir_dataflow
cargo check -q --features python-ext --bench ir_structure
cargo check -q --features python-ext --bench decompile_pipeline
cargo check -q --features python-ext --example check_canary
all exit 0

uv run maturin develop
uv run python tools/build_guard.py
exit 0; native extension fresh
```

The periodic symbol-bearing PIE Hello checkpoint passed six exact GCC cells:
O0 and O2 on x86-64, AArch64, and ARMv7.

## Measurement boundary

This is an authority and correctness-boundary change, not an output or timing
claim. No fixture matrix, DecBench, Joern, GED, or performance run was used.
The required post-source-commit fail-fast Python gate is recorded separately
below after it runs. WP3 remains open: the compatibility lowering surface and
remaining spelling-only helpers still require caller classification, and
general origin/invalidation closure is not complete.

