# WP3: structure-v2 prepared-text diagnostics are test-only

> **Kind:** record · **Date:** 2026-09-12

## Outcome

Commit `a0dcdfb1` removes the identity-free structure-v2 prepared-text path
from non-test builds. `structure_v2::observe` and `observe_cfg`, the diagnostic
observation variant, and `render::render_pseudocode` now exist only for their
isolated compatibility tests.

The production `render::adapt_tree` function remains compiled because the
Python IR pipeline uses it to lower a verified v2 tree into the common AST
pipeline. Production tree observation continues to preserve candidate,
refusal, graph-fidelity, and selected-tree evidence, but cannot accidentally
run the legacy no-sidecar copy/constant preparation path as a diagnostic side
effect.

## Red/green evidence

The first boundary attempt gated the complete render module. A non-test library
check was observed red with `E0433` because the production pipeline could no
longer resolve `structure_v2::render::adapt_tree` (and a consequent `E0282`
inference error). This established that the adapter is production-required and
must remain separate from the diagnostic renderer.

After narrowing the gate to the text renderer and diagnostic observer:

```text
cargo check --features python-ext --lib
exit 0

cargo test --features python-ext --lib \
  ir::structure_v2::tests::tree_only_observation_preserves_evidence_without_preparing_text \
  -- --exact --test-threads=1
1 passed; 0 failed

cargo test --features python-ext --lib ir::structure_v2::tests:: \
  -- --test-threads=1
30 passed; 0 failed

cargo test --features python-ext --lib \
  python_bindings::ir::tests::production_preparation_exposes_the_verified_clang_wide_switch_region \
  -- --exact --test-threads=1
1 passed; 0 failed

uv run maturin develop
exit 0
```

No output change is intended or claimed. No broad suite, corpus matrix,
DecBench, or Joern run was performed. The native build included unrelated
concurrent dirty source and therefore proves buildability of the live tree,
not exact-clean provenance for the commit.

## Next boundary

Audit the remaining public identity-free preparation APIs and their callers.
Delete or test-gate only those with no supported non-test use; production
decompilation must continue through the identity-required typed preparation
route.
