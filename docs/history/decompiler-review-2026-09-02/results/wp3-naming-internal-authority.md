# WP3 naming internal identity authority

> **Kind:** record · **Date:** 2026-09-13

## Outcome

Commit `2fd6a7df` closes the optional identity engine inside role-based
presentation naming. The shipped `role_names_with_identities` path now carries
an exact `ValueIdentities` authority into direct-return storage
classification, while the display-spelling authority is compiled only for
legacy hand-written unit tests.

This makes it impossible for a future non-test caller of the shared naming
engine to classify a returned source local as ABI result storage merely from
its rendered name. The production API already supplied exact identities, so
this is an authority/API closure rather than an output or performance claim.

## Focused evidence

```text
cargo test --features python-ext ir::naming::tests:: --lib -- --test-threads=1
23 passed; 0 failed; 4820 filtered out

cargo check --features python-ext --lib
pass
```

The owning slice covers exact return storage, misleading numbered spellings,
mixed and scalar result roles, AArch64 argument/result overlap, stack parameter
ownership, deterministic scratch naming, and origin-transparent presentation.
Using `--lib` avoids building and enumerating unrelated integration-test
binaries.

A fresh debug extension passes `tools/build_guard.py`. The required
whole-Python fail-fast gate passes every earlier test and again stops at 17% on
`test_the_committed_baseline_is_valid_and_has_a_clean_control_lane`: committed
`arch_baseline.json` and `baseline.json` disagree for the existing fixture 157,
172, and 81 control rows. This source commit changes neither ledger, and the
baseline was not regenerated from the shared dirty checkout.

Remaining WP3 work includes other semantic-reader/optional-engine closures,
AST mutation identity maintenance, and completion of origin coverage.
