# WP3 Boolean-mask expression origins

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commit `8c84c4ed` makes the safe eager-Boolean recognizer transparent to an
origin carrier on its byte-mask constant. The recognized SETcc-style
`predicate_tree & 255` form now retains the mask instruction owner on the
recovered short-circuit expression, together with the mask tree, cast,
predicate-tree, and terminal-test owners.

Commit `600f9900` closes the adjacent `select_fold` mask idiom. Attributed
conditions and `-1`/`0` arms still recover as arithmetic negation, and the
synthesized expression receives the flattened union of all four consumed
owners. An outer expression carrier is normalized instead of producing nested
origin wrappers.

The existing safety boundary is unchanged: the pass still requires a complete,
side-effect-free Boolean tree, at least two predicate leaves, and machine byte-
view evidence before converting eager bitwise operations into short-circuit
logic. This is one bounded wildcard-consumer migration, not completion of WP3.

## Focused verification

The strengthened attributed Boolean-tree test was observed red first because
the origin carrier around `255` prevented the raw constant match. After repair:

```text
cargo test --features python-ext --lib \
  ir::const_fold::tests::attributed_eager_boolean_tree_recovers_logical_origins \
  -- --exact
1 passed; 0 failed; 4,377 filtered out

cargo test --features python-ext --lib 'ir::const_fold::tests::'
76 passed; 0 failed; 4,302 filtered out; 0.02 s

cargo test --features python-ext --lib \
  ir::select_fold::tests::comparison_select_mask_becomes_arithmetic_negation \
  -- --exact
1 passed; 0 failed; 4,699 filtered out

cargo test --features python-ext --lib 'ir::select_fold::tests::' --quiet
23 passed; 0 failed; 4,677 filtered out

uv run pytest -q \
  python/tests/test_decompiler_control_flow_semantics.py::test_clang_o2_vectorized_max_round_trips
1 passed
```

The Python contract was run after a clean release extension build. It rejects
the unreduced `? -1 : 0` spelling, recompiles the decompiler output, and checks
its execution. Filtered tests were not executed. No full Rust, Python, fixture,
architecture, DecBench, or Joern suite was run.
