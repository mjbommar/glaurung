# WP2 equal entry-point budgets

Revision under test: `c077ccca`

## Result

All four public decompilation adapters can now construct the same complete
`AnalysisBudget`. In particular:

- exact-range exposes `max_functions` rather than fixing discovery and size to
  one;
- `decompile_all` exposes `max_functions` independently of its output `limit`;
- module and reusable-session single-function requests use their explicit
  function limit for size identity rather than silently fixing it to one.

The real-fixture equivalence test now gives address, exact-range, all, and many
the same discovery, CFG, callee, type, and size limits. It requires exact
pseudocode equality in DecBench, C, and untyped styles.

## Validation

```text
cargo check --features python-ext
  passed

uv run maturin develop --release
  release wheel built and installed

uv run pytest -q python/tests/test_decompiler_entrypoint_equivalence.py \
  python/tests/test_decompiler_session.py \
  python/tests/test_pipeline_profile_report.py
  13 passed
```

This closes the equal-budget test and exit criterion. It does not close WP2:
shared-session fact reuse, fingerprint/order determinism, and deliberately low
range-budget completeness evidence remain separate open checkboxes.
