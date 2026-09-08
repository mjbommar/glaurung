# WP3 ARM32 frame-storage identities

> **Kind:** record · **Date:** 2026-09-08

## Outcome

Commit `00aba798` removes raw `stack_`/`stack_top` recognition from the
production ARM32 frame recognizer's storage surface. Prologue saves, aliased
frame-pointer stores, frame anchors, deallocation pieces, nested restores, and
fixed-address recursion now share the same optional `ValueIdentities`
authority. Opaque producer-owned storage is accepted; misleading stack-like
spelling fails closed. Typed `Expr::StackAddr` remains authoritative on its AST
shape, and the no-sidecar API retains compatibility behavior.

This complements the earlier ARM32 register-identity migration. WP3 remains
open for the remaining semantic consumers, invalidation, and origin criteria.

## Focused evidence

```text
cargo test --features python-ext --lib \
  'ir::arm32_prologue::tests::identity_aware_arm32_frame' -- --nocapture
2 passed; 0 failed

cargo test --features python-ext --lib \
  'ir::arm32_prologue::tests' -- --nocapture
12 passed; 0 failed

uv run maturin develop
uv run python tools/build_guard.py
fresh

uv run pytest python/tests/test_decompiler_arm_frame_spills.py -q
1 passed
```

An isolated archive of the exact pushed commit passes all six census checks
and reproduces 5,168 declared Rust tests, 2,463 in `ir`, with zero outside a
gate. The shared checkout's uncommitted native-decoder tests are excluded.

No broad suite, fixture matrix, corpus, DecBench, or Joern run was made. The
recent four-cell Hello checkpoint was not repeated for this identity seam.

## Next ordered increment

Classify the remaining `local_`/`stack_` readers as renderer naming,
compatibility-only, already identity-aware, or still-semantic production work.
Migrate only the last category before widening WP3 work.
