# WP3 indirect-result and caller-arity authority

> **Kind:** record · **Date:** 2026-09-13

## Outcome

Commit `618d3917` makes two post-numbering semantic engines unable to omit
identity evidence in production:

- AAPCS64 and SysV indirect aggregate-result hinting and binding now route
  through a closed authority type. Its exact sidecar variant is the only
  variant in non-test builds; legacy display-spelling semantics compile only
  for the old hand-written unit fixtures.
- direct-caller stack-arity recovery now requires `&ValueIdentities` at its
  shipped API and at `Program` caller-environment recovery. Its optional
  identity engine has the same test-only legacy boundary.

This completes the internal half of two earlier public-API migrations. A future
production caller cannot pass `None` and silently reinterpret numbered display
names as architectural stack or argument storage.

## Focused evidence

```text
cargo test --features python-ext ir::aapcs64_indirect_result::tests:: -- --test-threads=1
6 passed; 0 failed

cargo test --features python-ext ir::caller_arity::tests:: -- --test-threads=1
4 passed; 0 failed

cargo check --features python-ext --lib
pass
```

The tests retain the exact-identity, misleading-spelling, unprovable-buffer,
balanced-cleanup, alignment, lowered-pop, and attributed-statement controls.
A fresh debug extension build passes `tools/build_guard.py`.

The required whole-Python fail-fast gate passed both repaired 11% ARM blockers
and again reached 17%. It stopped at the already identified disagreement
between committed `arch_baseline.json` control rows and committed
`baseline.json`; this commit changes neither ledger.

This increment intentionally changes authority and API shape, not rendered
output. Other optional internal identity engines, invalidation, and origin
closure remain WP3 work.
