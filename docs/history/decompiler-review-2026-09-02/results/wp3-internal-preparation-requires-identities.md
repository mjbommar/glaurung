# WP3: internal AST preparation requires value identities

> **Kind:** record · **Date:** 2026-09-12

## Outcome

Commit `edb9b91d` removes `Option<&ValueIdentities>` from the shared AST
preparation boundary. Product code must pass `&ValueIdentities`; the production
renderer and the typed library wrapper do so directly.

The implementation uses a closed `PreparationAuthority` enum to share the pass
schedule without duplicating it. In non-test builds that enum has exactly one
variant, `Identities`. The `LegacySpelling` variant, its match arms, the bare
copy/constant fixpoint entry points, and the spelling-based constant authority
exist only under `#[cfg(test)]`. Compatibility tests can still characterize old
AST-only behavior, but shipped preparation cannot select it or accidentally
pass `None`.

## Red/green evidence

The first test compile was observed red with two `E0308` errors. One correctly
identified the still-unmigrated test helper call; the other exposed an
over-broad mechanical edit to an unrelated condition-hoisting test. Correcting
those exact call sites restored the test build without changing condition
lowering.

```text
cargo check --features python-ext --lib
exit 0

cargo test --features python-ext --lib ir::ast::prepare::fixpoint_tests:: \
  -- --test-threads=1
4 passed; 0 failed

cargo test --features python-ext --lib \
  ir::ast::tests::prepare_folds_a_uniquely_shared_bare_return_to_its_value \
  -- --exact --test-threads=1
1 passed; 0 failed

cargo test --features python-ext --lib \
  python_bindings::ir::tests::production_preparation_exposes_the_verified_clang_wide_switch_region \
  -- --exact --test-threads=1
1 passed; 0 failed

uv run maturin develop
exit 0
```

No output movement is intended or claimed: the production route already
always supplied identities. The change makes that invariant structural and
unrepresentable as `None`. The native build includes unrelated concurrent
dirty source, so it proves the live tree builds rather than exact-clean commit
provenance. No corpus matrix, DecBench, or Joern run was performed.

## Next boundary

Classify the now-unreferenced spelling-only helper implementations reported by
the non-test compiler, beginning with direct-output and return-fold wrappers.
Gate a helper only after a repository-wide caller audit proves that no product,
benchmark, or example consumes it. The broader WP3 origin and invalidation work
remains open.
