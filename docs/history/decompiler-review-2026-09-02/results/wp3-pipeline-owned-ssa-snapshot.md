# WP3 pipeline-owned SSA snapshot

Date: 2026-09-10

## Result

Commit `85afee69` removes the last independent SSA reconstruction from the
production decompiler pipeline. `prepare_llir_for_lowering_with_shadow` now
returns the final owner-produced `SsaInfo` in `PreparedLlir`, and
`lower_and_run_ast_passes` passes that same snapshot to passthrough-parameter
refinement. The consumer therefore sees the same post-mutation SSA artifact as
indirect-target recovery, structuring, and value numbering.

The source ratchet in `src/ir/ssa.rs` requires
`src/python_bindings/ir/pipeline.rs` to contain zero direct `compute_ssa(`
calls. The remaining production call under `src/python_bindings/ir/` is in
recursive direct-callee recovery: it constructs the initial SSA snapshot for a
newly lifted callee function, rather than reconstructing the caller snapshot.
All other search hits under `src/ir/` and `src/python_bindings/ir/` are the SSA
implementation itself or test-local fixture construction.

## Red/green evidence

Before the implementation change, the new lifecycle ratchet failed with one
direct pipeline construction where zero were permitted. After the change:

```text
cargo test --features python-ext \
  ir::ssa::tests::production_pipeline_ratchets_classified_mutations_and_legacy_all
1 passed

cargo test --features python-ext \
  python_bindings::ir::pipeline::request_tests::
7 passed

cargo test --features python-ext \
  python_bindings::ir::callee_contracts::tests::
10 passed
```

## Exact-commit shipped-build evidence

A clean detached worktree at `85afee69186b3f8f4b65f1ed2eed6cac4925a0c3`
was synchronized and release-built with CPython 3.12.13. The loaded extension
was:

```text
python/glaurung/_native.cpython-312-x86_64-linux-gnu.so
SHA-256 a3c36b30dae001999acf2df5572fb9bce300cb65d6eb2528d77563c7f58e8e02
build_guard.py: fresh
```

Focused product checks on that build passed:

```text
uv run --no-sync python tools/dectest.py @calls
SCOPED: 8 lanes of 838 (1%) - no regressions in scope

uv run --no-sync pytest -q <six canonical Hello nodes>
6 passed
```

The six nodes cover GCC PIE Hello fixtures at O0 and O2 on x86-64, AArch64,
and ARMv7. No broad suite or DecBench run was used for this bounded increment.

## Scope

This closes the WP3 rule that SSA construction occurs only for initial demand
or through the owner's declared invalidation path. It does not complete WP3:
remaining display-name semantic consumers, AST identity propagation, and
origin coverage remain open.
