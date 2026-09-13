# WP3 ARM32 frame internal identity authority

> **Kind:** record · **Date:** 2026-09-13

## Outcome

Commit `c7f0facd` closes the optional identity engine used by ARM32 AAPCS frame
recognition. Every non-test path now carries exact `ValueIdentities` authority
through stack adjustment, saved-register and frame-pointer recognition,
promoted-stack ownership, linear-definition tracing, balanced epilogue proof,
and residual stack-pointer-use rejection. Display-name parsing and spelling
authority are compiled only for hand-written unit tests.

The sole shipped caller, in `src/python_bindings/ir/pipeline.rs`, already used
the identity-aware entry point. This change prevents future internal production
callers from treating an unowned `stack_*` name or register spelling as frame
evidence. It is an authority/API closure, not a new output or performance claim.

## Focused evidence

```text
cargo test --features python-ext ir::arm32_prologue::tests:: --lib -- --test-threads=1
14 passed; 0 failed; 4829 filtered out

cargo check --features python-ext --lib
pass
```

The owning slice covers A32 and Thumb frames, exact owned and misleading
unowned storage, core and VFP saves, multiple return paths, stack-pointer
restoration, promoted frame records, malformed-width refusal, and origin
preservation. Using `--lib` avoids building and enumerating unrelated
integration-test binaries.

A fresh debug extension passes `tools/build_guard.py`. The required
whole-Python fail-fast gate passes every earlier test and again stops at 17% on
`test_the_committed_baseline_is_valid_and_has_a_clean_control_lane`: committed
`arch_baseline.json` and `baseline.json` disagree for the existing fixture 157,
172, and 81 control rows. This source commit changes neither ledger, and the
baseline was not regenerated from the shared dirty checkout.

Remaining WP3 work includes other semantic-reader/optional-engine closures,
AST mutation identity maintenance, and completion of origin coverage.
