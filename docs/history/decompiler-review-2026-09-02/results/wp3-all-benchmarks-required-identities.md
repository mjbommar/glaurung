# WP3 all AST benchmarks require identities

> **Kind:** record · **Date:** 2026-09-12

## Outcome

Commit `113fb494` closes two no-sidecar benchmark callers missed by the first
bounded audit:

- `benches/decompile_pipeline.rs` now supplies its retained sidecar to the
  context-free constant-fold step; and
- `benches/ir_structure.rs` retains identities from value numbering and uses a
  new typed full-preparation API in its micro and shape-sweep lanes.

The typed preparation boundary also requires an explicit pointer width. The
structure benchmark derives four versus eight bytes from the target calling
convention, so its ARM32/i386 lanes cannot accidentally measure LP64 behavior.

The preceding `wp3-dataflow-benchmark-required-identities.md` record claimed
too broadly that no benchmark still invoked a spelling-based AST path. A
repository-wide benchmark search contradicted that statement and triggered
this immediate follow-up. The claim becomes true only at `113fb494`.

## Focused evidence

```text
prepare::fixpoint_tests:                           4 passed, 0 failed
cargo check --features python-ext
  --bench decompile_pipeline:                      passed
cargo check --features python-ext
  --bench ir_structure:                            passed
cargo bench --bench decompile_pipeline --no-run:   passed
cargo bench --bench ir_structure --no-run:         passed
benchmark search for bare prepare/vector/copy/fold: 0 matches
```

The final search covered every Rust file under `benches/` and the bare entry
points `prepare_for_decbench`, `settle_copies_and_constants`,
`fold_constants`, `propagate_copies`, and `recover_wide_copies`.

`uv run maturin develop` completed and `tools/build_guard.py` reported
`fresh`, with native SHA-256
`7d87caa4bd28300f0be811410ac2df4db507361a5fe7014c88379d772c1ed605`.
Concurrent unstaged shared-worktree changes are included in that build, so it
is live-tree rather than exact-clean-checkout evidence.

No timings or product-output changes are claimed. No test census change. No
broad Rust, Python, fixture, DecBench, or Joern suite ran.

## Scope

All repository benchmarks now use typed identity-aware entry points for these
AST passes. No-sidecar preparation remains public library compatibility and is
used by hand-written AST tests plus the legacy structure-v2 diagnostic text
view. It is not used by the shipped decompiler or a benchmark. WP3 remains
incomplete; the next step is the final semantic-reader and `tag_phys` design
audit, not another benchmark migration.
