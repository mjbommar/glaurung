# WP3 AArch64 prologue internal identity authority

> **Kind:** record · **Date:** 2026-09-13

## Outcome

Commit `464b9364` closes the optional identity engine inside AArch64
prologue/epilogue recovery. Every non-test path now carries exact
`ValueIdentities` authority through prologue save recognition, epilogue restore
scanning, and promoted-stack-object classification. The `stack_*` spelling
compatibility authority is compiled only for hand-written unit tests.

Both production pipeline call sites already used the identity-aware API. This
change prevents a future shared-internal caller from consuming an unowned value
as frame bookkeeping merely because its display name resembles a promoted
stack slot. It is an authority/API closure rather than a new output or
performance claim.

## Focused evidence

```text
cargo test --features python-ext ir::arm64_prologue::tests:: --lib -- --test-threads=1
16 passed; 0 failed; 4827 filtered out

cargo check --features python-ext --lib
pass
```

The owning slice covers exact owned and misleading unowned frame slots,
prologue and epilogue recovery, partial-shape refusals, pruned spills, source
argument spill preservation, promoted frame records, and deterministic origin
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
