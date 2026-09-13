# WP3: tail-call recovery APIs require identities

> **Kind:** record · **Date:** 2026-09-13

## Outcome

Commit `79496134` makes all three production tail-call recovery routes require
`&ValueIdentities`: resolved import/function-table jumps, resolved direct
external jumps, and proven Rust vtable tail dispatch. Their raw functions and
top-level re-exports are test-only.

The production pipeline already owns the authoritative snapshot and now passes
it directly. A shipped caller therefore cannot recover argument forwarding,
register setup, or a fat-pointer vtable tail from `register#version` display
spelling alone. Unresolved or ambiguously owned transfers continue to remain
explicit `Goto`/`IndirectGoto` nodes.

## Red/green evidence

The first non-test library check failed because `call_args.rs` still re-exported
the newly test-only raw functions. Gating that stale re-export completed the
boundary. Final evidence:

```text
cargo test --features python-ext ir::call_args::tail_calls::tests:: --lib
16 passed; 0 failed; 4826 filtered out

cargo check --features python-ext --lib
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
regression, with the unchanged spurious
`*(int *)((&local_18[0] + 20)) = var0;` store. No ordinary failure appeared
earlier. No fixture matrix, DecBench, Joern, or corpus sweep was run. This is
an authority/API change, not an output or timing claim.

## Remaining boundary

Tail-call internals retain optional identities only for legacy unit-test
adapters. WP3 remains open pending isolation or deletion of those adapters,
the remaining production parser audit, conservative invalidation, and
universal origin preservation.
