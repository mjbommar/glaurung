# WP3: result-buffer and canary APIs require identities

> **Kind:** record · **Date:** 2026-09-13

## Outcome

Commit `0f657984` makes two additional production contracts genuinely typed.
The AArch64/SysV indirect-result hint and binding APIs now require
`&ValueIdentities` rather than accepting `Option<&ValueIdentities>`. Their raw
adapters are test-only. The composed decompile benchmark now retains its
existing identity snapshot through indirect-result binding.

The same batch makes bare canary-save collapse test-only. The benchmark and
the canary diagnostic example now call the identity-required form, matching
both production rendering paths. New shipped callers therefore cannot silently
downgrade aggregate-result storage or promoted canary storage classification
to rendered-name parsing.

## Focused evidence

```text
cargo test --features python-ext \
  ir::aapcs64_indirect_result::tests:: --lib
6 passed; 0 failed; 4836 filtered out

cargo test --features python-ext ir::canary::tests:: --lib
26 passed; 0 failed; 4816 filtered out

cargo check --features python-ext \
  --bench decompile_pipeline --example check_canary
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

Both modules retain internal optional-identity implementations solely for
their test-only legacy adapters. WP3 still requires those compatibility engines
to be isolated or deleted, the remaining production identity/parser audit,
conservative invalidation, and universal origin preservation.
