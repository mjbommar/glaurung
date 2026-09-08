# WP3 machine-save storage identities

Commit `00b7ebbc` removes the remaining production display-name shortcut from
callee-save spill cleanup. A removable spill now requires two independent
pipeline facts: the destination is producer-owned machine-save storage and the
source has exact version-zero identity for an ABI callee-saved register. The
explicit no-sidecar compatibility APIs retain their historical `stack_` and
architecture-specific `local_` conventions.

Both boundary regressions were observed red before the fix. An unowned
`stack_2` was deleted merely because of its spelling, while an opaque owned
`frame_save` was missed. Production now preserves the former and removes the
latter. The existing entry-versus-later SSA control was tightened to require
storage ownership. Those three exact tests and all 49
`ir::dead_stores::tests` pass with 4,566 unrelated Rust tests filtered out.

After a fresh serial debug extension build, `tools/build_guard.py` reports the
native module fresh and the exact committed
`test_real_x86_stack_clash_frame_does_not_expose_callee_save_inputs` fixture
passes. The census records 5,152 declared Rust tests and zero outside every
gate; all six census checks pass after the source commit. The periodic Hello
World canary was not repeated because its four exact cells passed immediately
before this non-Hello identity seam. No broad Rust suite, Python suite, fixture
matrix, DecBench, or Joern lane ran.
