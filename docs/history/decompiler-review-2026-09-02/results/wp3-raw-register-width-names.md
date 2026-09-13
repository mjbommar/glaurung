# WP3: raw register widths do not parse numbered names

> **Kind:** record · **Date:** 2026-09-13

## Outcome

Commit `7c46146f` removes `#version` stripping from raw register-view width
recovery. The pre-numbering path now accepts only exact architectural names.
For example, `xmm0_d0` proves a four-byte lane, while the rendered spelling
`xmm0_d0#3` supplies no raw storage authority and conservatively falls back to
the machine word.

Numbered type recovery retains the correct view width through
`ValueIdentities::unambiguous_physical_base` and identity-owned definition
widths. Production raw inputs therefore keep their existing exact-name facts,
while opaque, misleading, or numbered inputs must use the typed route.

## Red/green evidence

The old compatibility test asserted that the raw helper decoded
`xmm0_d0#3`. It was renamed and inverted before the implementation change and
was observed red with `left: 4`, `right: 8`.

After removing the parser:

```text
cargo test -q --features python-ext --lib \
  raw_register_width_does_not_parse_value_number_tags
1 passed; 0 failed

cargo test -q --features python-ext --lib \
  identity_owned_width_does_not_parse_a_misleading_numbered_name
1 passed; 0 failed

cargo test -q --features python-ext --lib \
  numbered_type_recovery_uses_original_subregister_width
1 passed; 0 failed

cargo test -q --features python-ext --lib ir::types_recover::tests::
93 passed; 0 failed

cargo check -q --features python-ext --bench ir_dataflow
exit 0
```

## Measurement boundary

This is a fail-closed authority change, not an output or timing claim. No
fixture matrix, DecBench, Joern, or corpus sweep was run. The required native
rebuild is fresh. The post-source-commit Python gate again reached 11% before
its first ordinary failure:

```text
uv run pytest python/tests/ -q -x
stopped at 11%: 1 failed
```

It reproduces the established ARM Thumb frame-save defect with the unchanged
`*(int *)((&local_18[0] + 20)) = var0;` output. No ordinary failure appears
earlier, but the whole gate remains red and incomplete. WP3's remaining
identity and origin/invalidation audit stays open.
