# WP3 live-in parameter identities

Commit `0e824a04` removes `tag_phys` display spelling as the production
authority for live-in parameter inference.

`value_number_with_parameter_slots_lifetimes_and_identities` now supplies the
partially built `ValueIdentities` sidecar to `live_in_arg_slots_llir`. The
classifier uses complete identity candidates to:

- accept a read only when every candidate agrees on one ABI argument slot and
  is version zero;
- recognize definitions and zero idioms by their actual ABI storage; and
- classify ARM `r3`/link-register alignment padding and stack bases without
  parsing numbered names.

Callers that analyze raw LLIR before a sidecar exists retain the original
public no-sidecar entry point. Production value numbering no longer depends on
the convention that a bare display name denotes SSA version zero.

The exact regression accepts an opaque version-zero `rsi` as argument 1 and
rejects a value whose text looks like numbered `rdi` but whose exact version is
3.

Focused validation only:

```text
cargo test --features python-ext --lib \
  ir::value_number::tests::live_in_arg_slots_use_exact_identity_not_display_spelling \
  -- --exact
# 1 passed; 4,488 filtered out

cargo test --features python-ext --lib ir::value_number::tests::live_in_arg_slots
# 4 passed; 4,485 filtered out

cargo test --features python-ext --lib ir::value_number::tests::arm_r3
# 2 passed; 4,487 filtered out

cargo test --features python-ext --lib \
  ir::value_number::tests::real_arm_alignment_save_does_not_invent_four_parameters \
  -- --exact
# 1 passed; 4,488 filtered out

uv run maturin develop
uv run python tools/build_guard.py
# fresh

uv run python tools/dectest.py \
  11_call_shapes:gcc:O2:call_accumulate_bytes --show
# SCOPED: 1 lane of 838; no regressions in scope
```

An earlier selector named a function absent from fixture 11 and ran no lane;
it is not counted as evidence. No broad Rust/Python suite, fixture matrix,
DecBench run, or Joern run was used for this bounded increment.
