# WP3 call-argument slot identities

Date: 2026-09-08

Source commit: `f79d7909`

## Result

The ordinary backward call-argument scan no longer derives an assignment's
ABI slot from its display name when the production `ValueIdentities` sidecar is
available. It accepts an opaque value only when all of its exact SSA candidates
identify the same calling-convention slot. A misleading name such as
`rdi#looks_versioned` mapped to `rax` is not treated as argument zero.

The no-sidecar compatibility entry point retains its existing spelling-based
behavior. No renderer or public output format changed intentionally.

## Rejected adjacent migration

The first implementation also replaced `name.contains('#')` tests with
`identity.version > 0` when deciding whether a scratch AST name was immutable.
The exact GCC O2 `call_accumulate_bytes` canary regressed from pass to fail and
rendered the next iteration's value in `wrap_byte`. A patch-off rebuild restored
the pass. The original SSA identity does not by itself prove that a later AST
presentation name has one definition after coalescing, so that portion was
removed rather than weakening the canary.

## Focused verification

Only the requested narrow ladder ran:

```text
cargo test --features python-ext --lib \
  argument_slot_uses_exact_identity_not_display_spelling -- --nocapture
1 passed; 0 failed; 4481 filtered out

cargo test --features python-ext --lib 'ir::call_args::'
141 passed; 0 failed; 4341 filtered out; 0.21s

uv run maturin develop
uv run python tools/build_guard.py
fresh

uv run python tools/dectest.py \
  11_call_shapes:gcc:O2:call_accumulate_bytes --show
SCOPED: 1 lane of 838 - no regressions in scope
```

No broad Rust/Python suite, fixture sweep, DecBench, or Joern run was used for
this increment.
