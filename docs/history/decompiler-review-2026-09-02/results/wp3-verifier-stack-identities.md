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
cell initially reported undeclared `local_8` in `buffer_adjacent_scalars` and
`two_buffers_and_a_scalar`. Direct output inspection disproved that diagnosis:
both render `long local_8 = (long)(0x28);`. The test regex recognized only bare
and array declarations, not initialized declarations. Commit `4c905ab7` fixes
that parser; the exact x86-64 O0 cell and all eight architecture/optimization
cells pass. No decompiler behavior was changed or relaxed.

The periodic Hello World canary ran only four exact canonical cells: amd64 and
AArch64, Clang O0 and O2, symbol-bearing PIE. All four currently fail the exact
readability contract because rendering adds a redundant `(const char *)` cast
around the string literal. amd64 O2 additionally renders `main` as
`unsigned long`. These are explicit WP6/WP7 output-quality regressions; the
canonical tests were not weakened. No broad Rust suite, Python suite, fixture
matrix, DecBench, or Joern lane ran.
