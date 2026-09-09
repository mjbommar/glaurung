# WP3 parameter-spill proofs through expression origins

> **Kind:** record · **Date:** 2026-09-09

## Outcome

Commit `025264fd` makes the named parameter-home proof transparent to
expression-origin carriers. The pass now recognizes an attributed promoted
slot address, incoming parameter or straight-line parameter alias, and final
self-store. Renaming still mutates only semantic registers and retains each
expression owner.

The safety policy is unchanged. Production with an identity sidecar still
requires a typed source-parameter slot; protected debug locals cannot collapse;
and both directions of structured reaching-definition interference must be
absent before a spill is treated as an immutable parameter home.

This is a bounded WP3 consumer migration. It advances the ARM hard-float trace
but, as the release result below proves, does not yet close that capability.

## Observed-red and focused verification

`attributed_named_parameter_expressions_are_coalesced` was observed red first:
the attributed slot and parameter prevented the defining store from becoming
removable scaffolding. After the repair it proves that the spill becomes a
`Nop`, the reload becomes the source parameter, and the reload expression keeps
its exact owner.

```text
cargo test --features python-ext --lib \
  ir::ast::param_spills::tests::attributed_named_parameter_expressions_are_coalesced \
  -- --exact
1 passed; 0 failed; 4,711 filtered out

cargo test --features python-ext --lib ir::ast::param_spills::tests::
5 passed; 0 failed; 4,707 filtered out
```

Filtered tests were not executed.

## Release fixture checkpoint

A clean detached worktree at exact commit `025264fd` was release-built. The
build guard reported fresh with native SHA-256
`8fcf2b7e1226c13341bb2e7112b8b31ecfbc14b6f4f7f4c297d2fe5f255836b9`.

```text
uv run pytest -q \
  python/tests/test_cli_decompile.py::test_real_arm_hard_float_call_round_trip
1 failed
```

The fixture remains byte-for-byte at the previously recorded failure: its
first argument and later `x` use still pass through `local_c` and an
integer/float union. This rules out expression-carrier blindness as the only
cause. The next trace must distinguish three remaining proof boundaries:
debug-local protection, float bit-carrier type compatibility, and symmetric
reaching-definition interference.

No full Rust, Python, fixture, architecture, DecBench, or Joern suite was run.

## Next boundary

Capture the prepared AST, protected-local set, typed parameter-slot facts, and
the two reaching-definition refusal results for `arm_hf_caller`. Add the next
regression at whichever authoritative proof boundary actually declines; do not
erase the union in the renderer.
