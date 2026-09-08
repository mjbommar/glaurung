# WP3 x86 frame origin propagation

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commit `6e4cd9ec` makes the canonical x86 frame-prologue recognizer transparent
to statement origins. Attributed leading nops, `push rbp`, frame-pointer setup,
dead stack-allocation predicates, and stack allocation now follow the existing
strict recognition contract.

The synthesized prologue comment receives the deterministic union of every
machine statement it replaces. The return and all source statements retain
their own owners. Live allocation predicates and malformed frame sequences
still prevent the corresponding collapse.

## Focused evidence

The attributed full-frame test was observed red before repair: its three frame
statements remained visible. After repair they become one comment owned by
`[0x1000, 0x1004, 0x1008]`, while the return keeps `0x100c`.

```text
cargo test --features python-ext \
  ir::x86_prologue::tests::attributed_full_prologue_collapses_with_exact_machine_owners \
  -- --exact
1 passed; 0 failed

cargo test --features python-ext ir::x86_prologue::tests
31 passed; 0 failed
```

A fresh release extension was built in 36.23 seconds. The exact O0 function
that anchors the review's signed-condition example remains execution-correct
under both host compilers:

```text
uv run python tools/dectest.py \
  '01_conditional_polarity:*:O0:classify' --jobs 2 --full --show
2 passed; 0 regressions in scope
```

No broad suite was run.

## Next action

Continue the x86 audit with its still-raw cdecl32 alignment/frame consumers,
separating call-padding deletion from whole-frame replacement so each owner
transfer and refusal boundary receives an independent test.
