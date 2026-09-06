# WP2 nested-callee budget

Revision under test: `e9518094`

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

## Scope

This is one enforced slice of WP2's explicit budget model, not closure of that
model. Discovery and CFG limits must become distinct types, the type refinement
cap must enter the request, and batch/range output sizing must stop borrowing
discovery fields before the production checkbox or equal-budget exit criterion
can be marked complete.
