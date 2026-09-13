# WP3 canary internal identity authority

> **Kind:** record · **Date:** 2026-09-13

## Outcome

Commit `153591fa` closes the optional identity engine inside stack-canary save
collapse. Every non-test recursive path now carries an exact
`ValueIdentities` authority when deciding whether the save destination is a
pipeline-owned promoted stack object. The `stack_*` spelling compatibility
authority is compiled only for hand-written unit tests.

This prevents a future production caller from collapsing an unowned value into
a stack-canary comment merely because its display name resembles promoted
storage. The shipped API already supplied exact identities, so this is an
authority/API closure rather than a new output or performance claim.

## Focused evidence

```text
cargo test --features python-ext ir::canary::tests:: --lib -- --test-threads=1
26 passed; 0 failed; 4817 filtered out

cargo check --features python-ext --lib
pass
```

The owning slice covers exact owned and misleading unowned stack objects,
prologue saves, structured and unstructured exit checks, x86/i386/AArch64 TLS
forms, refusal cases, numeric-conversion transparency, and deterministic origin
unions. Using `--lib` avoids building and enumerating unrelated integration
test binaries.

A fresh debug extension passes `tools/build_guard.py`. The required
whole-Python fail-fast gate passes every earlier test and again stops at 17% on
`test_the_committed_baseline_is_valid_and_has_a_clean_control_lane`: committed
`arch_baseline.json` and `baseline.json` disagree for the existing fixture 157,
172, and 81 control rows. This source commit changes neither ledger, and the
baseline was not regenerated from the shared dirty checkout.

Remaining WP3 work includes other semantic-reader/optional-engine closures,
AST mutation identity maintenance, and completion of origin coverage.
