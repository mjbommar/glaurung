# WP3 x86 frame internal identity authority

> **Kind:** record · **Date:** 2026-09-13

## Outcome

Commit `79ff0bee` closes the optional identity engine shared by x86-64 frame
recognition and cdecl32 alignment/realignment recovery. Every non-test path now
carries exact `ValueIdentities` authority through promoted-slot and parameter
classification, callee-save identity, balanced multi-exit restore proof,
ordinary prologue collapse, and recursive epilogue collapse. The display-name
parsers and spelling authority are compiled only for hand-written unit tests.

Both production pipeline call sites already used identity-aware APIs. This
change prevents a future internal caller from consuming an unowned `stack_*`,
`local_*`, `argN`, or numbered register spelling as machine frame evidence. It
is an authority/API closure rather than a new output or performance claim.

## Focused evidence

```text
cargo test --features python-ext ir::x86_prologue::tests:: --lib -- --test-threads=1
45 passed; 0 failed; 4798 filtered out

cargo check --features python-ext --lib
pass
```

The owning slice covers x86-64 and cdecl32 frames, exact owned and misleading
unowned storage, omit-frame-pointer save areas, multiple exits, alignment
padding, partial-shape refusals, x87 cleanup, load preservation, and
deterministic origin unions. Using `--lib` avoids building and enumerating
unrelated integration-test binaries.

A fresh debug extension passes `tools/build_guard.py`. The required
whole-Python fail-fast gate passes every earlier test and again stops at 17% on
`test_the_committed_baseline_is_valid_and_has_a_clean_control_lane`: committed
`arch_baseline.json` and `baseline.json` disagree for the existing fixture 157,
172, and 81 control rows. This source commit changes neither ledger, and the
baseline was not regenerated from the shared dirty checkout.

Remaining WP3 work includes other semantic-reader/optional-engine closures,
AST mutation identity maintenance, and completion of origin coverage.
