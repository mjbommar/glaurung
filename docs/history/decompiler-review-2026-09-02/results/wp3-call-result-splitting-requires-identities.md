# WP3: call-result splitting requires identities

> **Kind:** record · **Date:** 2026-09-13

## Outcome

Commit `5d77ddc9` makes the identity-free call-result lifetime splitter
test-only. The composed decompile benchmark now uses the typed splitter and
mutates the same `ValueIdentities` snapshot that follows the AST, matching the
production pipeline's contract.

Follow-on commit `8b983ea2` removes optional identity state from the shipped
splitter itself. Its authority is now an explicit enum: non-test builds contain
only the exact-identity variant, while the legacy-spelling variant exists only
under `cfg(test)`. Missing identities are therefore unrepresentable inside the
production engine, not merely hidden behind its API.

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

cargo check --features python-ext --lib  # after internal isolation
exit 0, with no call-result or irrefutable-pattern warning

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

The call-result splitter's compatibility authority is now isolated to test
builds. WP3 remains open pending the remaining production parser/adapter audit,
conservative invalidation, and universal origin preservation.
