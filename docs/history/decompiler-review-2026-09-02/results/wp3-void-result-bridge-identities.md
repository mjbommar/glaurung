# WP3 void result-bridge identities

> **Kind:** record · **Date:** 2026-09-08

## Outcome

Commit `70b6dc82` removes two presentation-name guesses from void-function
cleanup. A save/restore bridge is eligible only when stack promotion owns its
storage object and every SSA candidate for the saved value has a canonical
machine-result base. An opaque owned object carrying exact `rax` identity is
accepted. An unowned value merely named `local_8`, or a value named `rax#3`
whose identity is actually `rdi`, declines.

The spelling implementation remains only in the explicit no-sidecar
compatibility wrapper. Production preparation uses the identity-aware entry
point whenever the pipeline sidecar is present.

## Focused validation

```text
opaque_void_result_bridge_is_removed_by_typed_identities: 1 passed
unowned_local_spelling_does_not_authorize_void_bridge_cleanup: 1 passed
misleading_result_spelling_does_not_authorize_void_bridge_cleanup: 1 passed
ir::direct_output::tests: 21 passed
python/tests/test_test_census.py: 6 passed
```

The regenerated census records 5,133 declared Rust tests and zero outside
every gate. A fresh serial `uv run maturin develop` completed and
`tools/build_guard.py` reported the extension fresh with SHA-256
`d56b905fd2acc68081f2a563210ee1d8cce26e42aa2f7bff7f54082e91bfac63`.

Only the directly relevant void fixture was exercised:

```text
uv run python tools/dectest.py 09_memory_effects:clang:O0:tick_n --show
SCOPED: 1 lane of 838 - no regressions in scope
```

Two earlier concurrent native rebuild attempts raced while staging the same
extension and left an incomplete install. No result from that install is used
as evidence; the single serial rebuild above repaired and superseded it.

No broad Rust/Python suite, fixture matrix, DecBench, or Joern lane ran.
