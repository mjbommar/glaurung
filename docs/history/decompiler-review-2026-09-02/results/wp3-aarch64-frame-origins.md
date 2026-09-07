# WP3 AArch64 frame origin propagation

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commit `2efa3106` makes AArch64 prologue and epilogue recognition transparent
to statement origins. Canonical scalar-slot frames, promoted frame records,
stack adjustments, frame-pointer setup, and paired `fp`/`lr` restores now see
attributed statements without weakening their existing shape proofs.

Replacement prologue and epilogue comments receive the exact union of the
machine statements they replace. A stack adjustment that is proven adjacent
to a paired restore joins the epilogue owner; the return remains independently
owned. Ambiguous lone allocations and incomplete restore pairs still decline.

## Focused evidence

The attributed canonical-prologue test was observed red before repair because
all four wrapped machine statements remained visible. A second focused test
covers the paired restore plus stack adjustment and independent return owner.

```text
cargo test --features python-ext \
  ir::arm64_prologue::tests::attributed_prologue_collapses_with_exact_machine_owners \
  -- --exact
1 passed; 0 failed

cargo test --features python-ext \
  ir::arm64_prologue::tests::attributed_epilogue_collapses_with_exact_machine_owners \
  -- --exact
1 passed; 0 failed

cargo test --features python-ext ir::arm64_prologue::tests
12 passed; 0 failed
```

A fresh release extension was built in 35.24 seconds. One exact AArch64 O0
review function remains execution-correct:

```text
uv run python tools/dectest.py \
  '01_conditional_polarity:*:O0:classify' --arch aarch64 --full --show
1 passed; 0 regressions in scope
```

No broad Rust, Python, architecture, fixture, or DecBench sweep was run.

## Next action

Continue the production-reader audit outside the now-clean x86 frame module,
prioritizing another enabled transformation with raw statement matches and an
exact architecture-specific fixture.
