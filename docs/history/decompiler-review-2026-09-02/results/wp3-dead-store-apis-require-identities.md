# WP3: shipped dead-store APIs require identities

> **Kind:** record · **Date:** 2026-09-13

## Outcome

Commit `1379efdc` removes three identity-free dead-store entry points from
non-test builds. Both IR benchmarks and the canary diagnostic example now
retain and supply the `ValueIdentities` snapshot they already computed. The
production Python pipeline was already on these typed routes.

Consequently, shipped callers can no longer choose cleanup that treats `ret`,
`local_*`, `stack_*`, or a parsed `register#version` as semantic authority.
The raw top-level elimination and top-level/nested callee-save functions remain
available only to unit tests over legacy hand-written ASTs.

## Focused evidence

```text
cargo test --features python-ext ir::dead_stores::tests:: --lib
51 passed; 0 failed; 4791 filtered out

cargo check --features python-ext \
  --bench decompile_pipeline --bench ir_dataflow --example check_canary
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

Its first ordinary failure remains
`test_real_thumb_leaf_frame_save_does_not_become_a_source_local`, with the
unchanged spurious `*(int *)((&local_18[0] + 20)) = var0;` store. No ordinary
failure appeared earlier. No fixture matrix, DecBench, Joern, or corpus sweep
was run, and no output or timing improvement is claimed for this authority-only
change.

## Remaining boundary

The shared implementation still contains explicit optional-identity branches
for its test-only compatibility adapters. WP3 remains open pending separation
of those adapters, the rest of the production identity/parser audit,
conservative invalidation, and universal origin preservation.
