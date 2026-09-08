# WP2 fingerprint and request-order determinism

Revision under test: `c907121a`

## Result

The pipeline fingerprint now has a canonical JSON representation containing
its schema, pass version, all five budget classes, render selectors, debug-fact
selection, analyst-overlay presence, and shadow-structurer selection. Opt-in
pipeline profile events carry that representation next to the checked ordered
stage sequence. Serialization is evaluated lazily, so unprofiled production
requests do not pay this diagnostic cost.

The determinism test selects three real exported functions and runs
`decompile_many` twice in fresh processes, once forward and once reversed. It
compares maps keyed by function address and requires equality of both:

- complete pseudocode;
- canonical pipeline fingerprint.

This covers request-order leaks from shared name maps, callee caches, program
facts, and randomized per-process hash seeds.

## Validation

```text
cargo test --features python-ext \
  fingerprint_changes_with_budget_and_carries_the_pass_version
  1 passed

uv run maturin develop --release
  release wheel built and installed

uv run pytest -q python/tests/test_decompiler_determinism.py \
  python/tests/test_pipeline_profile_report.py
  15 passed
```

This closes WP2's fingerprint and function-order determinism checkbox. The
deliberately reduced range-budget completeness test is the last listed WP2 test
item still open.
