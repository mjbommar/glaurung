# WP3 enclosing canonical identities

Commit `20f0575c` prevents enclosing call-argument reaching state from
reinterpreting an authoritative identity base as versioned display text.

`EnclosingSlots::advance_reaching` now declines a non-canonical, `#`-bearing
identity base before calling the compatibility slot parsers. A valid opaque
value whose exact identity is `rdi` still becomes the proven reaching value for
slot zero; an identity claiming `rdi#not_canonical` no longer crosses a
structured boundary and becomes a fabricated call argument. The explicit
no-sidecar path continues to recognize ordinary value-numbered display names.

The adversarial exact test was observed red before the production change.

Focused validation only:

```text
cargo test --features python-ext --lib \
  ir::call_args::tests::enclosing_reaching_state_does_not_reparse_an_identity_base \
  -- --exact
cargo test --features python-ext --lib \
  ir::call_args::tests::origin_wrappers_do_not_hide_enclosing_reaching_definitions \
  -- --exact
cargo test --features python-ext --lib \
  ir::call_args::tests::a_proven_table_call_reads_the_enclosing_reaching_definitions \
  -- --exact
# 1 passed in each command; 4,494 filtered out in each

uv run maturin develop
uv run python tools/build_guard.py
# fresh; native SHA-256
# 174292f695cebde275934c716136793a2d0cdabf3ec44f6a6e1a5c6f14b68cc7

uv run python tools/dectest.py \
  189_effectful_select:gcc:O2:se189_select_call
# SCOPED: 1 lane of 838; no regressions in scope
```

No broad Rust/Python suite, fixture matrix, DecBench run, or Joern run was used.
