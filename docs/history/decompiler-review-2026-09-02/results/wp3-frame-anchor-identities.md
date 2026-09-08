# WP3 frame-anchor identities

Commit `e4aaabf8` removes display-name classification from stack promotion's
frame-anchor proof.

The production `ValueIdentities` sidecar now decides whether:

- x86 `rbp`/`ebp`/`bp` is established from `rsp`/`esp`/`sp`;
- the nominal x86 frame register is instead repurposed as ordinary storage;
- ARM32 `fp`, `r7`, or `r11` is established from `sp`; and
- nested add/sub expressions still derive from the exact stack-pointer value.

Opaque numbered values with exact frame/stack identities are accepted.
Misleading frame-looking display names backed by ordinary registers are
ignored, and missing or ambiguous production identity evidence declines.

Focused validation only:

```text
cargo test --features python-ext \
  ir::stack_locals::tests::frame_anchor_detection_uses_exact_identity_not_display_spelling \
  --no-fail-fast
# 1 passed; 4,491 filtered out

cargo test --features python-ext --lib \
  ir::stack_locals::tests::repurposed_rbp_value_is_not_promoted_as_a_stack_object_address \
  -- --exact
cargo test --features python-ext --lib \
  ir::stack_locals::arm32_tests::thumb_scratch_r7_is_not_a_frame_anchor \
  -- --exact
cargo test --features python-ext --lib \
  ir::stack_locals::tests::a_cfa_object_is_left_alone_when_the_frame_pointer_is_established \
  -- --exact
# 1 passed in each command; 4,491 filtered out in each

uv run maturin develop
uv run python tools/build_guard.py
# fresh; native SHA-256
# 3cd48df446a60d908903899e327d8cd7ddff2c0589e315c35c4c58d80bdc85b6

uv run python tools/dectest.py \
  06_calling_conventions:gcc:O0:sum_arg7 --show
# SCOPED: 1 lane of 838; no regressions in scope
```

The initially selected GCC O0
`196_disjoint_frame_slots:dfs196_alias_control` lane reports its pre-existing
`pass -> fail` baseline debt. A controlled same-checkout parent/tip test removed
only this one-file patch, rebuilt, and reproduced byte-identical output and the
same failure before restoring the patch. It is therefore not claimed as either
positive or negative evidence for this increment.

No broad Rust/Python suite, stack-local module sweep, fixture matrix, DecBench
run, or Joern run was used.
