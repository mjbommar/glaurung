# WP3 aggregate-return internal authority

> **Kind:** record · **Date:** 2026-09-13

## Outcome

Commit `3b19b747` closes the internal optional-identity engines for the complete
callee aggregate-return family. Integer-pair composition, stack-backed banked
returns, register-resident INTEGER+SSE returns, and `xmm0:xmm1` returns now
route through a closed identity authority. Its exact `ValueIdentities` variant
is the only variant in non-test builds; legacy display-spelling behaviour is
compiled solely for hand-written unit fixtures.

This completes the internal half of the earlier public aggregate-return API
migration. Production code can no longer accidentally recover high result
halves, promoted return objects, or register-bank roles without the pipeline's
authoritative identity snapshot.

## Focused evidence

```text
cargo test --features python-ext ir::callee_return_bank::tests:: -- --test-threads=1
23 passed; 0 failed

cargo test --features python-ext ir::callee_return_pair::tests:: -- --test-threads=1
10 passed; 0 failed

cargo check --features python-ext --lib
pass
```

The covered controls include misleading display spellings, unowned promoted
locals, missing and clobbered halves, control-flow joins, mixed result banks,
partial high occupancy, exact object extents, AAPCS64 pairs, and preservation
of statement/expression origins.

A fresh debug extension passes `tools/build_guard.py`. The required
whole-Python fail-fast gate passes both repaired 11% ARM blockers and again
reaches 17%, where the already identified committed `arch_baseline.json` versus
`baseline.json` control-row disagreement remains the first failure. This
commit changes neither ledger.

This is an authority/API closure, not a rendered-output claim. Remaining WP3
optional engines, invalidation, and origin tracking stay open.
