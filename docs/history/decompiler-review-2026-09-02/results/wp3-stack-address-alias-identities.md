# WP3 stack-address alias identities

Date: 2026-09-08

Source commit: `6ac46be4`

## Change

Optimized ARM code often constructs a stack-relative indexed address through a
short chain of physical scratch values. The bounded stack-address alias pass
previously admitted each component only when its presentation name contained
`#version`.

Stack promotion already owns the projected `ValueIdentities` sidecar. It now
passes that authority into address expansion, which admits physical components
only when they own a non-entry SSA value. Opaque identities therefore preserve
the existing affine recovery, while a misleading tagged spelling attached to
an entry value is refused. Temporary VRegs and explicit no-sidecar tests keep
their established compatibility behavior.

This advances the WP3 semantic-reader audit. It does not make the bounded pass
a general reaching-definitions analysis, remove `tag_phys`, or complete WP3.

## Focused validation

All commands used `TMPDIR=/home/mjbommar/.cache/glaurung/tmp`.

```text
cargo test --features python-ext --lib \
  ir::stack_locals::address_aliases::tests::opaque_ssa_stack_address_chain_is_expanded_by_identity \
  -- --exact
1 passed; 0 failed; 4,504 filtered out

cargo test --features python-ext --lib \
  ir::stack_locals::address_aliases::tests::identity_version_outranks_a_misleading_stack_alias_spelling \
  -- --exact
1 passed; 0 failed; 4,504 filtered out

uv run maturin develop
passed; debug extension rebuilt

uv run python tools/build_guard.py
fresh; native SHA-256 eced9b05ae5d0287bb35ad10d802b29b4514e4030fb053052062181df55b3292

uv run python tools/dectest.py 25_kmp_search:armv7_a32:O0:kmp_search --show
1 of 3,304 architecture lanes selected; no regression in scope
```

No broad Rust or Python suite, fixture sweep, DecBench run, or Joern run was
performed for this bounded increment.
