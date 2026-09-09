# WP3 ARM frame-anchor expression origins

Date: 2026-09-09

Commit: `9393db47`

## Defect

ARM32 stack-local recovery identifies `fp`, A32 `r11`, or Thumb `r7` as a frame
anchor only when a top-level prologue assignment derives it from `sp`. That
reader matched the assignment expression literally. An expression-origin
carrier on `sp`, the constant in `sp +/- C`, or the complete expression made a
valid frame establishment disappear, leaving frame-relative locals as raw
pointer-like accesses.

This is distinct from the earlier structural-storage repair: the identity
sidecar could prove that opaque values denoted `sp` and `r7`, but the expression
wrapper prevented the frame-pattern reader from reaching those facts.

## Change

`src/ir/stack_locals.rs` now classifies the frame-source expression and its
constant offset through `Expr::semantic()`. The existing restrictions remain:
the assignment must be top-level, the destination must have exact ARM frame
storage, the source must have unambiguous `sp` storage, and only direct or
constant-add/sub forms qualify.

No provenance is removed or moved because this classifier is read-only.

## Focused RED/GREEN evidence

The existing exact-identity contract now wraps an opaque `sp + 0` source and
both operands with independent expression owners. Before the repair
`arm_frame_register` returned `None`; afterward it returns `r7`:

```text
cargo test --features python-ext --lib \
  ir::stack_locals::tests::frame_anchor_detection_uses_exact_identity_not_display_spelling --quiet
1 passed; 0 failed

cargo test --features python-ext --lib arm_frame --quiet
4 passed; 0 failed

cargo test --features python-ext --lib thumb_frame --quiet
3 passed; 0 failed
```

No broad Rust or Python suite ran.

## Exact release evidence

Commit `9393db47` was built in a detached clean worktree. The build guard
reported `fresh`, and Python imported the extension from that exact worktree.
Two real compiler-output controls pass:

```text
python -m pytest -q \
  python/tests/test_decompiler_arm_frame_spills.py \
  python/tests/test_cli_decompile.py::test_real_thumb_leaf_frame_save_does_not_become_a_source_local
2 passed
```

The first checks an ordinary `push {r7, lr}` prologue. The second checks a
Cortex-M Thumb leaf that saves only `r7`, ensuring the repair does not erase a
different saved-register shape.

The periodic three-architecture Hello sample passed in the immediately
preceding cdecl increment and was not repeated here.

## Boundary

This closes the ARM32 frame-anchor reader only. Other stack-local consumers,
remaining raw expression readers, and universal production attribution keep
WP3 open.
