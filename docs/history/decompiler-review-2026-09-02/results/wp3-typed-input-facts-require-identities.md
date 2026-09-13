# WP3: typed input facts require identities

> **Kind:** record · **Date:** 2026-09-13

## Outcome

Commit `d7e6411d` tightens three connected identity-aware contracts:

- DWARF field annotation now requires `&ValueIdentities`, and its raw AST
  adapter is test-only;
- the identity-aware proven-call-input predicate requires an actual snapshot;
- identity-aware LLIR parameter-slot discovery requires an actual snapshot.

Raw proven-input and parameter-slot analysis remains available because
pre-numbering production consumers legitimately operate before an identity
sidecar exists. The implementation dispatches explicitly between raw and typed
semantics at that boundary; a caller can no longer invoke a function named
`with_identities` while passing `None`.

This preserves the intended phase order: exact identities govern numbered
DWARF, call-input, phi-plumbing, and parameter facts, while unnumbered type and
format analysis retains its separate conservative raw route.

## Focused evidence

```text
cargo test --features python-ext ir::dwarf_fields::tests:: --lib
13 passed; 0 failed; 4829 filtered out

cargo test --features python-ext ir::use_def::tests:: --lib
16 passed; 0 failed; 4826 filtered out

cargo test --features python-ext ir::value_number::tests:: --lib
65 passed; 0 failed; 4777 filtered out

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
regression and retains the same spurious
`*(int *)((&local_18[0] + 20)) = var0;` store. No ordinary failure appeared
earlier. No fixture matrix, DecBench, Joern, or corpus sweep was run. This is
an authority/API change, not an output or timing claim.

## Remaining boundary

The raw and typed shared implementations still use internal optional identity
parameters. WP3 remains open pending isolation of those compatibility engines,
the remaining production parser audit, conservative invalidation, and
universal origin preservation.
