# WP3: stack-frame recovery APIs require identities

> **Kind:** record · **Date:** 2026-09-13

## Outcome

Commit `c3780881` carries the authoritative `ValueIdentities` snapshot through
the composed decompile benchmark, the dataflow benchmark, and the AArch64
prologue diagnostic. The public typed stack-promotion entry point is now
available to those separate crates, while the identity-free ARM32 and ARM64
frame-recognition entry points are test-only.

These routes can no longer silently classify numbered or role-like display
names as machine-frame facts. Production behavior is unchanged because the
production pipeline already retained and supplied the identity snapshot.

## Focused evidence

```text
cargo test --features python-ext ir::arm64_prologue::tests:: --lib -q
16 passed; 0 failed; 4826 filtered out

cargo test --features python-ext ir::arm32_prologue::tests:: --lib -q
13 passed; 0 failed; 4829 filtered out

cargo check --features python-ext --bench decompile_pipeline --bench ir_dataflow \
  --example check_prologue
exit 0

uv run maturin develop
exit 0

uv run python tools/build_guard.py
fresh
```

The required post-source-commit Python gate was run once, fail-fast:

```text
uv run pytest python/tests/ -q -x
stopped at 11%: 1 failed
```

Its first ordinary failure remains the established ARM Thumb leaf-frame
regression. The output still contains the spurious
`*(int *)((&local_18[0] + 20)) = var0;` frame-save store. No ordinary failure
appeared earlier. No fixture matrix, DecBench, Joern, corpus sweep, or timing
benchmark was run. This is an authority/API change, not an output or performance
claim.

## Remaining boundary

Stack promotion still exposes identity-free compatibility entry points, and
the ARM implementations retain optional identities for legacy unit tests. WP3
remains open pending classification and isolation of those adapters, the
remaining production parser audit, conservative invalidation, and universal
origin preservation.
