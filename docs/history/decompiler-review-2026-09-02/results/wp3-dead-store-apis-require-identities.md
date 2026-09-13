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

## Follow-on closure and remaining WP3 boundary

Follow-on commit `fb05d414` closes this family's remaining internal authority
boundary. The shared implementation now accepts a closed
`DeadStoreAuthority`: non-test builds can construct only `Exact(&ValueIdentities)`,
while the spelling-compatible variant is compiled only for legacy unit tests.
The adjacent-store, callee-save, promoted-object, and entry-value helpers no
longer represent missing identities as `Option<&ValueIdentities>` in shipped
code.

Focused follow-on evidence:

```text
cargo test --features python-ext ir::dead_stores::tests:: --lib -- --test-threads=1
51 passed; 0 failed; 4795 filtered out

cargo check --features python-ext
exit 0

uv run maturin develop
exit 0

uv run python tools/build_guard.py
fresh
```

The required post-commit Python gate was run once with fail-fast. It passed the
previous ARM Thumb and hard-float blockers and stopped at the independently
known committed-baseline disagreement at 17%:

```text
uv run pytest -q python/tests/ -x
FAILED test_decompiler_arch_roundtrip.py::test_the_committed_baseline_is_valid_and_has_a_clean_control_lane
```

The disagreement is limited to the already-recorded x86-64 control verdicts
for fixtures 157, 172, and 81; neither baseline was regenerated from the shared
dirty checkout. No DecBench, Joern, fixture matrix, corpus sweep, output, or
timing claim accompanies this authority-only follow-on.

This dead-store family is now internally closed. WP3 remains open pending the
rest of the semantic-reader audit, conservative invalidation, and universal
origin preservation.
