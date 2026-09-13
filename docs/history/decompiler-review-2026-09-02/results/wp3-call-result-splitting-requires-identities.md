# WP3: call-result splitting requires identities

> **Kind:** record · **Date:** 2026-09-13

## Outcome

Commit `5d77ddc9` makes the identity-free call-result lifetime splitter
test-only. The composed decompile benchmark now uses the typed splitter and
mutates the same `ValueIdentities` snapshot that follows the AST, matching the
production pipeline's contract.

Criterion iterations clone the AST and identity sidecar together before the
measured pass sequence. This preserves isolation between iterations while
allowing newly versioned ABI result registers to publish their exact physical
storage identities.

## Focused evidence

```text
cargo test --features python-ext ir::call_result_split::tests:: --lib -q
17 passed; 0 failed; 4825 filtered out

cargo check --features python-ext --lib --bench decompile_pipeline
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
regression, including the unchanged spurious
`*(int *)((&local_18[0] + 20)) = var0;` store. No ordinary failure appeared
earlier. No fixture matrix, DecBench, Joern, corpus sweep, or timing benchmark
was run. This is an authority/API and benchmark-fidelity change, not an output
or performance claim.

## Remaining boundary

The splitter retains an optional identity field internally only for legacy
unit-test adapters. WP3 remains open pending isolation or deletion of that
adapter, the remaining production parser audit, conservative invalidation, and
universal origin preservation.
