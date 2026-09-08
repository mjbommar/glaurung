# WP3 typed promoted-value identities

Commit `f90a277c` moves the late typed adjacent promoted-value mover from
display-name inference to producer-owned stack-object identity. A recovered
scalar type remains necessary to distinguish a promoted-store assignment from
an indirect pointer write, but `local_` / `stack_` spelling is no longer
sufficient storage proof in production.

Two exact tests pin both sides. An opaque owned `frame_object` with a proven
integer type folds its one-use comparison directly into the return. An unowned
`local_4` with the same type evidence refuses the fold. Both exact tests and
all 66 `ir::copy_prop` tests pass with 4,553 unrelated Rust tests filtered out.

After a fresh serial debug extension build, `tools/build_guard.py` reports the
native module fresh and only the Clang O0
`212_loop_with_returning_arm:fsm_returns_from_arm` fixture was exercised; it
reports no scoped regression. The census records 5,156 declared Rust tests and
zero outside every gate, and all six census checks pass after the source
commit. The untyped pre-sidecar adjacent mover retains its compatibility
classifier, so WP3 copy propagation remains open. The four-cell Hello check
was not repeated after its recent checkpoint. No broad Rust suite, Python
suite, fixture matrix, DecBench, or Joern lane ran.
