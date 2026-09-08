# WP3 late copy-cleanup storage identities

Commit `00943c69` gives the late production copy-propagation pass an identity-
aware scratch/storage boundary. Dead-copy elimination, straight-line dead
stores, counted single-use propagation, and closed scratch-dataflow pruning now
treat producer-owned promoted objects as storage. An unowned physical value no
longer gains storage authority merely because its display name begins with
`local_` or `stack_`.

Two exact tests pin the boundary: an unused unowned `local_8` is ordinary
scratch state and is removed, while an opaque owned `frame_object` remains
storage and is preserved for the dedicated stack passes. Both exact tests and
all 64 `ir::copy_prop` tests pass with 4,553 unrelated Rust tests filtered out.

After a fresh serial debug extension build, `tools/build_guard.py` reports the
native module fresh and the exact committed
`test_real_x86_stack_clash_frame_does_not_expose_callee_save_inputs` fixture
passes. The census records 5,154 declared Rust tests and zero outside every
gate; all six census checks pass after the source commit. The earlier AST
preparation pass, which runs before this sidecar exists, deliberately retains
the compatibility classifier; this increment therefore advances but does not
complete WP3 copy-propagation migration. The four-cell Hello checkpoint had
just passed and was not repeated. No broad Rust suite, Python suite, fixture
matrix, DecBench, or Joern lane ran.
