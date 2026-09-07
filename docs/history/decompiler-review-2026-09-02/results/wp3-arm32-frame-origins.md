# WP3 ARM32 frame origin propagation

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commit `51d3c9df` makes the transactional ARM32 prologue/epilogue recognizer
transparent to statement origins. Attributed stack adjustments, saved-register
stores, frame-pointer setup, restored registers, nested control, and returns
now participate in the same exact balance proof as unwrapped statements.

The two synthesized machine-frame comments receive deterministic unions of the
instructions they replace. Source statements and the return retain their own
owners. The recognizer still declines the whole transformation when any return
path is unbalanced or an architectural stack-pointer use remains.

## Focused evidence

The attributed Thumb frame test was observed red before repair: all eight
machine statements remained in the function because the first wrapped stack
adjustment was invisible. After the repair it collapses to the prologue comment,
unchanged attributed body statement, epilogue comment, and return with exact
owners `[1000,1004,1008,100c]`, `[1010]`, `[1014,1018]`, and `[101c]`.

```text
cargo test --features python-ext \
  ir::arm32_prologue::tests::attributed_thumb_frame_collapses_with_exact_machine_owners \
  -- --exact
1 passed; 0 failed

cargo test --features python-ext ir::arm32_prologue::tests
9 passed; 0 failed
```

A fresh release extension was built in 34.99 seconds. The exact architecture
cell previously used to protect the ARM32 frame/value handoff remains green:

```text
uv run python tools/dectest.py \
  '03_loop_shapes:armv7_a32:O0:while_prefix' --full --show
1 passed; 0 regressions in scope
```

No architecture-wide matrix or whole repository suite was run for this bounded
consumer migration.

## Next action

Audit the parallel x86 frame recognizer under the same contract: observe one
attributed-frame failure, preserve exact owners on synthesized comments, run its
module, rebuild release, and select only the matching x86 fixture function.
