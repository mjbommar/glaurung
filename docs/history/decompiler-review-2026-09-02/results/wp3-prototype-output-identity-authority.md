# WP3 prototype-output identity authority

> **Kind:** record · **Date:** 2026-09-13

## Outcome

Commit `800c7304` removes the optional-identity production API from
prototype-driven direct-output projection. The sole shipped caller in
`src/python_bindings/ir/pipeline.rs` now passes `ValueIdentities` directly, and
the internal path-sensitive return walk uses that closed authority when it
chooses the SSA result value reaching each bare return. The no-identity
compatibility path is compiled only for hand-written unit tests.

This prevents a future production caller from silently falling back to display
spelling while deciding whether a body overwrote ABI result storage. It is an
authority/API closure rather than a new output or performance claim.

## Focused evidence

```text
cargo test --features python-ext ir::direct_output::tests:: --lib -- --test-threads=1
24 passed; 0 failed; 4819 filtered out

cargo check --features python-ext --lib
pass
```

The owning slice covers path-sensitive AArch64 live-in results, integer and SSE
result banks, call-result identity, misleading `ret` and local spellings,
promoted return slots, void-result cleanup, and origin preservation. Using
`--lib` avoids building and enumerating unrelated integration-test binaries.

A fresh debug extension passes `tools/build_guard.py`. The required
whole-Python fail-fast gate passes every earlier test and again stops at 17% on
`test_the_committed_baseline_is_valid_and_has_a_clean_control_lane`: committed
`arch_baseline.json` and `baseline.json` disagree for the existing fixture 157,
172, and 81 control rows. This source commit changes neither ledger, and the
baseline was not regenerated from the shared dirty checkout.

Remaining WP3 work includes other semantic-reader/optional-engine closures,
AST mutation identity maintenance, and completion of origin coverage.
