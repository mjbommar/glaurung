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

Commit `5b2e8083` closes the internal compatibility boundary as well. The shared
walkers now take a closed `TailCallAuthority`: production can construct only
`Exact(&ValueIdentities)`, while `LegacySpelling` exists only under
`#[cfg(test)]`. There is no optional-identity state inside tail-call recovery
and no production route can accidentally fall back to rendered register names.

Focused evidence for the follow-on commit:

```text
cargo test --features python-ext ir::call_args::tail_calls::tests:: --lib -- --test-threads=1
16 passed; 0 failed; 4830 filtered out

cargo check --features python-ext
exit 0

uv run maturin develop
exit 0

uv run python tools/build_guard.py
fresh
```

The required post-source-commit Python gate was run once, fail-fast. It reached
17% without an earlier failure, then stopped at the established disagreement
between `arch_baseline.json` and `baseline.json` for fixture 157 at x86-64
O0/O2, fixture 172 at x86-64 O0, and fixture 81 at x86-64 O2. The shared dirty
tree was not used to regenerate either ledger. No fixture matrix, DecBench,
Joern, or corpus sweep was run.

The tail-call identity-authority slice is now complete. WP3 remains open for
the residual production semantic-reader audit, conservative invalidation, and
universal origin preservation.
