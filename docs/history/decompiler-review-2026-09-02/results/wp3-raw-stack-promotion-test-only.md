# WP3: raw stack promotion is test-only

> **Kind:** record · **Date:** 2026-09-13

## Outcome

Commit `eca072a0` removes all five identity-free stack-promotion entry points
from non-test builds. The canary diagnostic now passes its existing
`ValueIdentities` snapshot to the same typed facts API used by production and
the decompile benchmarks.

The raw adapters remain available only to the module's hand-written AST unit
tests. A shipped caller can therefore no longer promote numbered or role-like
display spellings into stack/frame facts by omitting the identity sidecar.

## Focused evidence

```text
cargo test --features python-ext ir::stack_locals::tests:: --lib -q
92 passed; 0 failed; 4750 filtered out

cargo check --features python-ext --lib --example check_canary
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
was run. This is an authority/API change, not an output or performance claim.

## Remaining boundary

The shared stack-promotion and ARM frame engines still accept optional
identities internally to serve legacy unit-test adapters. WP3 remains open
pending isolation or deletion of those adapters, the remaining production
parser audit, conservative invalidation, and universal origin preservation.
