# WP2 checked pipeline profile

Revision under test: `a7797e28`

## Result

The opt-in pipeline profile now reports the checked semantic transaction as an
ordered sequence separate from granular timing events. The production trace is:

1. `lift`
2. `prepare_direct_callee_facts`
3. `prepare_llir_for_lowering_with_shadow`
4. `lower_and_run_ast_passes`
5. `finalize_prepared_ast`
6. `render_prepared_ast`

The sequence comes directly from the same `PipelineStageTracker` transitions
that fail closed on invalid production ordering. It is therefore evidence of
the checked transaction that ran, rather than a second hand-maintained list.
The report parser validates non-empty unique stages and refuses more than one
pipeline trace for a function. Timing stages remain independent and can be
subdivided without silently redefining the semantic order.

## Validation

```text
cargo fmt --check
cargo test --features python-ext decompile::profile::tests
  4 passed; 0 failed

uv run maturin develop --release
  release wheel built and installed

uv run pytest -q python/tests/test_pipeline_profile_report.py
  7 passed
```

The real-profile test compares an unprofiled and profiled decompilation byte
for byte, requires the exact six-stage sequence above, and continues to require
both bounded fixpoint reports with their closed termination vocabulary.

## Remaining WP2 work

This closes the profile-report checkbox, not WP2. The next production increment
must split `AnalysisBudget` into genuinely enforced discovery, CFG, callee,
type, and size limits. After that, the remaining session, determinism,
lower-budget completeness, and equal-budget four-entry-point tests can close on
one explicit budget identity.
