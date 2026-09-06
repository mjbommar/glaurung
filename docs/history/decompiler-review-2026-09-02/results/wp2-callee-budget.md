# WP2 nested-callee budget

Revisions under test: `e9518094`, `b3a6543a`, `dc303793`, `87edaeb6`

## Result

Nested callee-contract recovery is now controlled by a pipeline-owned
`CalleeBudget { max_depth }`. The budget is part of `AnalysisBudget`, therefore
part of the existing pipeline fingerprint, and crosses the same typed request
boundary for address, exact-range, all, many, and reusable-session adapters.

The enforced value reaches both demand-driven recovery paths:

- direct call targets;
- entries in relocation-proven function-pointer tables.

This removes the hidden `NESTED_CALLEE_DEPTH` production constant. A changed
callee depth now changes fingerprint identity, while CFG discovery conversion
continues to preserve its five existing limits exactly.

## Validation

```text
cargo check --features python-ext
  passed

cargo test --features python-ext pipeline_budget_preserves_every_discovery_limit
  1 passed

cargo test --features python-ext fingerprint_changes_with_budget_and_carries_the_pass_version
  1 passed

uv run maturin develop --release
  release wheel built and installed

uv run pytest -q python/tests/test_decompiler_entrypoint_equivalence.py \
  python/tests/test_decompiler_session.py
  6 passed
```

## Completed follow-on slices

- `b3a6543a` separates `DiscoveryBudget` from `CfgBudget`; their five fields
  still project exactly into the existing discovery engine.
- `dc303793` makes the float-copy type fixed point consume a fingerprinted
  `TypeBudget`. Exhaustion preserves its best-effort lattice facts, and zero
  rounds decline only that refinement.
- `87edaeb6` makes range fallback bytes and all/many result counts consume a
  fingerprinted `SizeBudget` instead of adapter-local arithmetic or loop
  limits.

The pipeline request/result production item is now complete: callee, discovery,
CFG, type, and size limits are distinct, enforced, and included in request
identity. The separate WP2 test and exit-criterion checkboxes remain open until
the public adapters can be exercised with one exactly equal complete budget.

Additional validation after each slice included a fresh release extension and:

```text
cargo test --features python-ext python_bindings::ir::pipeline::request_tests
  6 passed

cargo test --features python-ext python_bindings::ir::type_maps::tests
  16 passed

uv run pytest -q python/tests/test_decompiler_entrypoint_equivalence.py \
  python/tests/test_decompiler_session.py \
  python/tests/test_pipeline_profile_report.py
  13 passed
```
