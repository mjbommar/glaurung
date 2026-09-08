# WP3 canonical parameter authority

Commit `0d8a77cc` moves source-parameter role attachment behind WP3's shared
canonical SSA-base boundary.

`ValueIdentities::attach_abi_parameter_slots` no longer passes an identity's
raw base to the ABI helper that intentionally tolerates value-numbered display
spellings. A valid version-zero identity for `rdi` still receives source slot
zero; a malformed identity whose base is `rdi#not_canonical` receives no
parameter authority.

The exact ownership-level regression was observed red before the production
change: the malformed value incorrectly received slot zero.

Focused validation only:

```text
cargo test --features python-ext --lib \
  ir::value_number::tests::abi_parameter_slots_decline_a_noncanonical_identity_base \
  -- --exact
cargo test --features python-ext --lib \
  ir::value_number::tests::abi_parameter_slots_attach_only_to_live_version_zero_values \
  -- --exact
cargo test --features python-ext --lib \
  ir::ssa::tests::ssa_identity_exposes_only_a_canonical_physical_base \
  -- --exact
# 1 passed in each command; 4,496 filtered out in each

uv run maturin develop
uv run python tools/build_guard.py
# fresh; native SHA-256
# 0fff2c45f79846681196e92148fd41e69c8eb22d40d2689f7bc5160f94f8b0ff

uv run python tools/dectest.py \
  06_calling_conventions:gcc:O0:sum_arg7
# SCOPED: 1 lane of 838; no regressions in scope
```

No broad Rust/Python suite, fixture matrix, DecBench run, or Joern run was used.
