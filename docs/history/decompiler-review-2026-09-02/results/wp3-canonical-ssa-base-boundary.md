# WP3 canonical SSA base boundary

Commit `d9e77a0a` centralizes the rule that an SSA identity exposes physical
storage only when its base is canonical.

`SsaValue::canonical_physical_base` declines temporaries and malformed
`#`-bearing physical bases before an identity-aware consumer reaches ABI
helpers whose documented compatibility contract accepts value-numbered display
text. The call-recovery, slot-read/write, live-in parameter, AAPCS float-bank,
wide tail-result, enclosing-state, and indirect-result consumers now share that
boundary. Explicit no-sidecar branches retain their prior compatibility
parsing.

The two preceding increments had already observed the malformed call-storage
and enclosing-state cases red before their local fixes. This consolidation adds
a direct primitive test and moves the remaining related consumers behind the
same fail-closed rule.

Focused validation only:

```text
cargo test --features python-ext --lib \
  ir::ssa::tests::ssa_identity_exposes_only_a_canonical_physical_base -- --exact
cargo test --features python-ext --lib \
  ir::value_number::tests::live_in_arg_slots_use_exact_identity_not_display_spelling -- --exact
cargo test --features python-ext --lib \
  ir::call_args::tests::argument_slot_uses_exact_identity_not_display_spelling -- --exact
cargo test --features python-ext --lib \
  ir::call_args::tests::preceding_call_result_uses_exact_identity_not_display_spelling -- --exact
cargo test --features python-ext --lib \
  ir::call_args::tests::enclosing_reaching_state_does_not_reparse_an_identity_base -- --exact
cargo test --features python-ext --lib \
  ir::call_args::aapcs::tests::pure_vfp_setup_uses_exact_identity_not_display_spelling -- --exact
cargo test --features python-ext --lib \
  ir::call_args::tail_calls::tests::vtable_tail_uses_exact_high_result_identity_not_display_spelling -- --exact
# 1 passed in each command; 4,495 filtered out in each
```

An initial parameter-slot selector included the private module in the test
path and selected zero tests. The corrected parent-module selector above ran
and passed; the zero-test command is not counted as evidence.

```text
uv run maturin develop
uv run python tools/build_guard.py
# fresh; native SHA-256
# b269f74286c13edcf05728d8cf86ae86f876111a9f66bfa42f602e83a1b967a2

uv run python tools/dectest.py \
  189_effectful_select:gcc:O2:se189_select_call
# SCOPED: 1 lane of 838; no regressions in scope
```

No broad Rust/Python suite, fixture matrix, DecBench run, or Joern run was used.
