# WP3 source-loop updates require identities

> **Kind:** record · **Date:** 2026-09-12

## Outcome

Commit `ccd4b5db` removes the optional identity path from source-loop update
coalescing. The pass now requires pipeline-owned `ValueIdentities`, and its
parameter-scratch refusal consults the typed parameter slot directly instead
of parsing an `argN` display name.

This is the sibling of the earlier loop-entry migration. An owned parameter
scratch still refuses, an exact non-parameter scratch can still merge into its
source carrier, and missing identity evidence fails closed regardless of the
name printed for the value.

## Focused validation

```text
ir::latch_predicate::tests: 17 passed, 0 failed, 4,819 filtered out
```

After a fresh release extension build, the directly owning named fixture set
reported:

```text
tools/dectest.py @loops --jobs 4
SCOPED: 12 lanes of 838 (1%) - no regressions in scope
```

`tools/build_guard.py` reported the extension fresh with SHA-256
`01df3d34712b25fdf15882988f875dbc43bb1f3ca55b22975d46bd33faca0079`.
No broad Rust, Python, fixture, DecBench, or Joern suite ran.

## Scope

Both loop-entry and source-loop-update coalescing now require identities. This
does not complete the remaining parameter-spill, declaration, naming, or
copy-propagation migrations, nor WP3's universal provenance exit criteria.
