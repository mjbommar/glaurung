# WP3 vector-copy internal identity authority

> **Kind:** record · **Date:** 2026-09-13

## Outcome

Commit `58e45ccd` closes the optional identity engine inside packed-vector copy
recovery. Every non-test helper now receives an exact `ValueIdentities`
authority, including lane and whole-register recognition, scalar-view bridge
classification, nested read accounting, dead-bridge removal, exclusivity
proof, and wide-copy synthesis. The spelling-based compatibility authority is
compiled only for hand-written unit tests.

This prevents an internal production recursion path from silently changing
from SSA identity to rendered register spelling. The public production API was
already identity-required, so this is an authority/API closure rather than a
new output or performance claim.

## Focused evidence

```text
cargo test --features python-ext ir::vector_copy::tests:: -- --test-threads=1
11 passed; 0 failed; 4832 filtered out

cargo check --features python-ext --lib
pass
```

The focused tests cover exact identity independent of display spelling,
single-consumer safety, live and dead scalar bridges, nested transports,
interleaving, computation refusal, and deterministic origin unions.

A fresh debug extension passes `tools/build_guard.py`. The required
whole-Python fail-fast gate passes every earlier test and again stops at 17% on
`test_the_committed_baseline_is_valid_and_has_a_clean_control_lane`: committed
`arch_baseline.json` and `baseline.json` disagree for the existing fixture 157,
172, and 81 control rows. This source commit changes neither ledger, and the
baseline was not regenerated from the shared dirty checkout.

Remaining WP3 work includes other semantic-reader/optional-engine closures,
AST mutation identity maintenance, and completion of origin coverage.
