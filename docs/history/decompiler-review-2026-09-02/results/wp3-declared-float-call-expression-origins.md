# WP3 declared-float call rendering through expression origins

> **Kind:** record · **Date:** 2026-09-09

## Outcome

Commit `72b3478b` makes the exact declared-float argument boundary transparent
to expression-origin carriers. A register already declared as the callee's
exact `float` or `double` parameter type must remain a value: adding instruction
ownership previously changed `consume(arg0)` into the redundant
`consume((float)(arg0))`.

The renderer now classifies that register through its semantic expression.
Explicit machine-word carriers still retain their required float conversion;
aggregate, pointer, integer, and variadic boundaries are unchanged.

This is a bounded WP3 renderer-consumer migration. It does not repair the
separate ARM hard-float spill/reload reconstruction debt described below or
complete universal expression attribution.

## Observed-red and focused verification

`attributed_declared_float_argument_is_render_byte_neutral` was observed red
first with the exact redundant conversion above. After the one-node semantic
lookup, the plain and attributed compilable-C outputs are byte-equal.

```text
cargo test --features python-ext --lib \
  ir::ast::tests::attributed_declared_float_argument_is_render_byte_neutral \
  -- --exact
1 passed; 0 failed; 4,710 filtered out

cargo test --features python-ext --lib float_call
5 passed; 0 failed; 4,706 filtered out
```

Filtered tests were not executed.

## Release fixture A/B

Clean detached worktrees at parent `340831a5` and tip `72b3478b` were
release-built. Their fresh native SHA-256 values were respectively
`cb8a565d336575254227ab870784770cdbd53354dc9b732da92997617c9cf767` and
`f79c65741d832b85d5532ee458037c2e85ad2fa0eda6ad7dd5aaff89dccf451a`.

```text
uv run pytest -q \
  python/tests/test_cli_decompile.py::test_real_arm_hard_float_call_round_trip
```

Both parent and tip fail the same assertion. Both render the first call
argument through `local_c` and an integer/float union instead of recovering
`arm_hf_callee(x, y)`. The tip adds no fixture regression, but this red test is
not evidence for closing the broader ARM hard-float capability. It identifies
the next owning problem as redundant parameter spill/reload reconstruction,
not declared-register call rendering.

No full Rust, Python, fixture, architecture, DecBench, or Joern suite was run.

## Next boundary

Trace the ARM O0 parameter spill from its stack object through the call
argument and return expression. Repair it at authoritative value/storage
identity rather than teaching the renderer to erase the union spelling.
