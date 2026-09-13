# WP3: shipped x86 frame APIs require identities

> **Kind:** record · **Date:** 2026-09-13

## Outcome

Commit `d99633ae` removes the two identity-free x86 frame entry points from
non-test builds. The shipped Python pipeline already called
`recognise_x86_prologue_with_identities` and
`recognise_cdecl32_call_alignment_with_identities`; the composed decompile
benchmark now also retains and supplies its existing `ValueIdentities`
snapshot instead of exercising the legacy spelling parser.

The bare entry points remain available only to unit tests that specify old
hand-written ASTs without an identity sidecar. This is an authority-boundary
change: it prevents new production or benchmark callers from silently
classifying `#version`, `stack_`, `local_`, or `argN` display spellings as
machine/storage facts. It intentionally makes no output or timing claim.

## Focused evidence

```text
cargo test --features python-ext ir::x86_prologue::tests:: --lib
45 passed; 0 failed; 4797 filtered out

cargo check --features python-ext --bench decompile_pipeline
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

Its first ordinary failure is the established ARM Thumb leaf-frame defect in
`test_real_thumb_leaf_frame_save_does_not_become_a_source_local`, with the
unchanged spurious output
`*(int *)((&local_18[0] + 20)) = var0;`. No ordinary failure appeared before
it. No fixture matrix, DecBench, Joern, or corpus sweep was run.

## Remaining boundary

The shared x86 implementation still has explicit optional-identity branches
to support its test-only compatibility entry points. WP3 remains open until
the typed implementation and legacy test adapter are separated, the remaining
production identity/name readers are migrated, and conservative invalidation
and universal origin preservation are complete.
