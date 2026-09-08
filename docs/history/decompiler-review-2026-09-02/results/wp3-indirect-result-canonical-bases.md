# WP3 indirect-result canonical bases

Commit `df62ee4c` stops indirect-result buffer tracking from reparsing an
authoritative identity base as a display name.

The AArch64 `x8` and SysV hidden-result coordinate tracker now keys exact
physical bases supplied by `ValueIdentities`. A malformed identity base such as
`x8#not_canonical` cannot impersonate `x8` and fabricate either a pre-promotion
stack-object hint or a post-promotion call destination. The explicit no-sidecar
compatibility path continues to accept value-numbered display spellings.

The extended exact-identity regression was observed red before the production
change.

Focused validation only:

```text
cargo test --features python-ext --lib \
  ir::aapcs64_indirect_result::tests::indirect_result_storage_uses_exact_identity_not_display_spelling \
  -- --exact
cargo test --features python-ext --lib \
  ir::aapcs64_indirect_result::tests::a_bare_frame_base_in_x8_is_a_buffer_at_offset_zero \
  -- --exact
cargo test --features python-ext --lib \
  ir::aapcs64_indirect_result::tests::a_promoted_buffer_becomes_the_call_destination \
  -- --exact
# 1 passed in each command; 4,493 filtered out in each

uv run maturin develop
uv run python tools/build_guard.py
# fresh; native SHA-256
# 40234a703c3f1235a5c77d0d5b2a42dd9d53b4bc3005ac0c4632cf8c7ef6dd1f

uv run python tools/dectest.py \
  198_aggregate_return_edges:aarch64:O2:agr198_five_roundtrip
# SCOPED: 1 lane of 3,304; no regressions in scope
```

No broad Rust/Python suite, fixture matrix, DecBench run, or Joern run was used.

