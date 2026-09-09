# WP3 split string expression origins

> **Kind:** record · **Date:** 2026-09-09

## Outcome

Commit `00cb555d` makes ARM-style split string addresses transparent to
expression provenance. The string folder now recognizes an attributed
`Addr(page) + Const(offset)` pair and gives the replacement literal the
deterministic union of both contributing instruction owners.

The proof remains narrow: the arithmetic must still be addition, the semantic
operands must be one address and one signed offset, the addition must not
overflow, and the combined address must identify a string in the indexed
readonly pool.

## Focused TDD

The new contract attributed the page and offset separately. It was observed
red before the production repair and green afterward:

```text
originated_split_address_folds_and_unions_ownership: pass
ir::strings_fold: 12 passed, 4,686 filtered out
```

No broad Rust or Python suite was run.

## Periodic Hello World checkpoint

A clean detached release build at `00cb555d` ran six exact GCC symbols/PIE
cells rather than the 88-node Hello collection:

| Architecture | O0 | O2 | Current debt |
|---|---:|---:|---|
| AMD64 | pass | pass | none in these cells |
| AArch64 | pass | pass | none in these cells |
| ARMv7 | fail | fail | O0 frame artifacts; O2 four spurious parameters |

ARMv7 recovers `puts("Hello, World!")` in both outputs. Its failures are the
previously recorded ARM32 frame and entry-signature defects, not string-address
recovery regressions.

## Scope

This closes the split-address portion of the string-fold expression consumer.
Universal expression attribution and ARMv7 ABI/frame closure remain open.
