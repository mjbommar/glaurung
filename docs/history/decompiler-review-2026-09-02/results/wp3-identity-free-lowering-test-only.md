# WP3: identity-free AST lowering is test-only

> **Kind:** record · **Date:** 2026-09-13

## Outcome

Commit `658452b8` removes identity-free AST lowering from the shipped Rust API.
`ast::lower_with_identities` is now the only non-test lowering entry point.
The legacy `lower` implementation and re-export remain under `#[cfg(test)]`
solely for explicit compatibility and adversarial unit contracts.

The real AST demonstration example and the external Rust canary now compute
SSA value numbering, retain its `ValueIdentities`, lower the numbered LLIR, and
pass the sidecar explicitly. The remaining four bare calls are all internal
unit-test diagnostics in modules compiled under `#[cfg(test)]`; there is no
bare call in production code, an example, a benchmark, or an integration test.

## Focused evidence

```text
cargo check -q --features python-ext --lib
exit 0

cargo check -q --features python-ext --example ast_demo
exit 0

cargo test -q --features python-ext --test decompiler_canary_rust
4 passed; 0 failed

cargo test -q --features python-ext --lib \
  ir::ast::lower_region::lowering_stack_tests::
2 passed; 0 failed
```

The four surviving source matches are the structure-v2 diagnostic renderer,
one Python-binding production-handoff unit test, one value-identity unit test,
and one CFG unit test. All are in internal test configurations.

## Measurement boundary

This is an API and authority-boundary change. It intentionally does not alter
the Python decompile pipeline, so no output, GED, or timing movement is claimed.
No fixture matrix, DecBench, or Joern run was performed. The required
post-source-commit native rebuild and fail-fast Python gate are recorded after
they run. WP3 still requires the wider origin/invalidation completion audit,
but shipped LLIR-to-AST lowering can no longer omit value identity authority.

