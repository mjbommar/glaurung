# WP3 final-verifier stack identities

Commit `bdb1e0eb` moves the final rendered-output verifier's stack-store
classification from `local_` / `stack_` display spelling to producer-owned
promoted-stack identity. The identity authority is threaded through the
ordinary structured walk, whole-function definition/read inventories, and the
goto-aware CFG walk. Compatibility callers without an identity sidecar retain
the legacy spelling behavior.

Two adversarial tests pin both directions: an identity-owned object named
`var7` is treated as a storage definition, while an unowned object named
`local_4` is treated as a pointer read and cannot manufacture a definition.
Both exact tests and all 43 `ir::verify_defs::tests` pass; 4,562 unrelated Rust
tests were filtered out. The census records 5,142 declared Rust tests and zero
outside every gate, and all six census checks pass after the source commit.

After a fresh debug extension build, the single directly relevant invariant
cell
`test_every_local_used_is_also_declared[-O0-x86_64]` remains red for two known
outputs: `buffer_adjacent_scalars` and `two_buffers_and_a_scalar` use undeclared
`local_8`. This increment makes the verifier's classification authoritative;
it does not create missing declarations, so that producer defect remains open.

The periodic Hello World canary ran only four exact canonical cells: amd64 and
AArch64, Clang O0 and O2, symbol-bearing PIE. All four currently fail the exact
readability contract because rendering adds a redundant `(const char *)` cast
around the string literal. amd64 O2 additionally renders `main` as
`unsigned long`. These are explicit WP6/WP7 output-quality regressions; the
canonical tests were not weakened. No broad Rust suite, Python suite, fixture
matrix, DecBench, or Joern lane ran.
