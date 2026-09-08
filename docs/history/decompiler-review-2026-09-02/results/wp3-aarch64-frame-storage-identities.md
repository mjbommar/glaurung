# WP3 AArch64 frame-storage identities

> **Kind:** record · **Date:** 2026-09-08

## Outcome

Commit `2f664dfe` removes `stack_` display-name inference from the production
AArch64 frame recognizer's complete scalar save/restore surface. Both early
post-promotion cleanup and the later machine-frame pass now consume the
pipeline's `ValueIdentities`. Opaque producer-owned fp/lr slots are recognized;
unowned values that merely look like stack slots fail closed. Typed
`Expr::StackAddr` frame records remain self-describing, and the no-sidecar
wrapper remains available for compatibility tests.

This closes one more enabled WP3 consumer. It does not complete authoritative
identity, invalidation, origin tracking, or AArch64 target-model work.

## Focused evidence

```text
cargo test --features python-ext \
  'ir::arm64_prologue::tests::identity_aware' -- --nocapture
4 passed; 0 failed

cargo test --features python-ext 'ir::arm64_prologue::tests' -- --nocapture
16 passed; 0 failed

uv run maturin develop
uv run python tools/build_guard.py
fresh

uv run python tools/dectest.py \
  '15_binary_search_tree:gcc:O2:bst_inorder_checksum' --arch aarch64 --show
SCOPED: 1 lane of 3304; no regressions in scope

uv run pytest python/tests/test_test_census.py -q
6 passed
```

The census records 5,162 declared Rust tests and zero outside every gate. No
broad Rust/Python suite, fixture matrix, corpus, DecBench, or Joern run was
made. The periodic Hello matrix was not repeated because the recent exact
four-cell checkpoint remains current and this slice targets frame ownership.

## Next ordered increment

Re-audit enabled `local_`/`stack_` and version-tag readers. Migrate the next
production consumer only where the identity sidecar is already available;
preserve explicitly pre-sidecar compatibility paths.
