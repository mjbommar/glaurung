# WP3 call stack-area identities

Status: landed in `79da282c` on `agent/wp5-next-switch`.

## Result

Call argument recovery now identifies stack allocation, cleanup, lowered
push/pop pairs, preallocated SysV outgoing areas, phase-sensitive stack reads,
frame-prologue boundaries, and captured outgoing pushes from exact SSA storage
identities when the pipeline sidecar is available. Display spellings such as
`rsp#3` are no longer accepted as proof that a value is the stack pointer.

Compatibility entry points without an identity sidecar retain their existing
name-based behavior for the cdecl and AAPCS callers. Ambiguous exact identities
continue to fail closed.

## Focused evidence

- Exact regression: `sysv_stack_area_uses_exact_identity_not_display_spelling`
  passed (`1 passed`, `4474 filtered out`). An opaque value proved to be `rsp`
  is accepted; a misleading `rsp#3` display name mapped to `rax` is rejected.
- Owning module: `cargo test --features python-ext --lib ir::call_args --
  --nocapture` passed (`134 passed`, `0 failed`, `4341 filtered out`) in about
  16.4 seconds.
- Native extension: `uv run maturin develop` completed, then
  `uv run python tools/build_guard.py` reported the extension fresh.
- Direct fixture: `uv run python tools/dectest.py
  11_call_shapes:clang:O0:call_into_spill --show` selected exactly one of 838
  cells and showed no regression.

No full Rust suite, Python suite, fixture sweep, DecBench run, or Joern run was
used for this increment.

## Remaining WP3 work

WP3 remains open. The next call-recovery surfaces are loop-carried slot
discovery and the AAPCS/cdecl readers that still operate without authoritative
identity data.
