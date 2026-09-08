# WP3 exact typed-local widths

Commit `13fd396c` applies the pipeline-owned definition-width sidecar to every
identity-owned numbered definition in production typed recovery, rather than
using it only for the ABI return value.

An opaque local whose exact SSA identity is `rbx` and whose definition width is
four bytes now receives a four-byte integer type even though its presentation
name carries no register-width clue. Width and role remain separate facts: a
value misleadingly named `rax#9` but identified as `rdi` is not treated as a
return, while its own exact four-byte definition width still applies. The type
lattice continues to keep pointer, code-pointer, float, and boolean evidence
stronger than this integer-width fact.

The opaque-local regression was observed red before the production change: it
was widened to eight bytes.

Focused validation only:

```text
cargo test --features python-ext --lib \
  ir::types_recover::tests::ordinary_definition_width_comes_from_the_exact_width_sidecar \
  -- --exact
cargo test --features python-ext --lib \
  ir::types_recover::tests::return_refinement_uses_identity_and_definition_width \
  -- --exact
cargo test --features python-ext --lib \
  ir::value_number::tests::exact_definition_widths_survive_parent_register_canonicalisation \
  -- --exact
# 1 passed in each command; 4,497 filtered out in each

uv run maturin develop
uv run python tools/build_guard.py
# fresh; native SHA-256
# 18abc7b5cfdd99d455094c7561bb563873fa5520d96aaf70cdd85a1ed3582bd2

uv run python tools/dectest.py \
  174_float_compare_classify:gcc:O2:sign_bit_of_binary32
# SCOPED: 1 lane of 838; no regressions in scope
```

No broad Rust/Python suite, fixture matrix, DecBench run, or Joern run was used.
This is the first general typed-definition slice; uses without a definition
width still rely on raw operand views, and `tag_phys` is not yet removable.

