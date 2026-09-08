# WP3 value-keyed use types

Date: 2026-09-08

Source commit: `23a8ef7e`

## Change

The common prepared decompiler pipeline now retains the `TypeMapV` recovered
from raw LLIR occurrences and their SSA identities. Ordinary typed rendering
projects those facts onto a numbered value only when `ValueIdentities::exact`
proves a single owner. This preserves the raw machine view after value
numbering replaces it with an opaque presentation name, while coalesced
ambiguity remains fail-closed.

This is an incremental WP3 consumer migration. It does not remove the legacy
storage-keyed type pass or `tag_phys`, and it does not establish WP3 completion.

## Focused validation

All commands used `TMPDIR=/home/mjbommar/.cache/glaurung/tmp`.

```text
cargo test --features python-ext --lib \
  ir::types_recover::tests::use_only_width_comes_from_exact_value_facts_not_numbered_spelling \
  -- --exact
1 passed; 0 failed; 4,498 filtered out

cargo test --features python-ext --lib \
  ir::types_recover::tests::ambiguous_numbered_use_declines_value_keyed_width_projection \
  -- --exact
1 passed; 0 failed; 4,499 filtered out

cargo test --features python-ext --lib \
  ir::types_recover::tests::ordinary_definition_width_comes_from_the_exact_width_sidecar \
  -- --exact
1 passed; 0 failed; 4,498 filtered out

cargo test --features python-ext --lib \
  ir::types_recover::tests::return_refinement_uses_identity_and_definition_width \
  -- --exact
1 passed; 0 failed; 4,498 filtered out

uv run maturin develop
passed; debug extension rebuilt

uv run python tools/build_guard.py
fresh; native SHA-256 5084cc702264b44fd494e5a5837fd39a2914c2596669d70afb6c0b9b3a4720bc

uv run python tools/dectest.py 01_conditional_polarity:gcc:O0:classify --show
1 of 838 lanes selected; no regression in scope
```

No broad Rust or Python suite, fixture sweep, DecBench run, or Joern run was
performed for this bounded increment.
