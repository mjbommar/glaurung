# WP3 string expression origins

> **Kind:** record · **Date:** 2026-09-09

## Outcome

Commit `54ff918b` makes authoritative character-pointer string folding
transparent to expression provenance. A named call target can retain its
instruction owner while still selecting the correct call contract, and an
attributed constant argument can become a string literal without losing that
owner.

This closes the measured AMD64 GCC symbols/non-PIE Hello World defect where
the otherwise canonical output rendered `puts((const char *)(0x402004))`
instead of `puts("Hello, World!")`.

## Focused TDD

The new contract wraps both the `puts` target and its constant argument in
expression origins. It was observed red before the production repair and green
after it:

```text
originated_constant_character_pointer_folds_and_preserves_ownership: pass
ir::strings_fold: 11 passed, 4,686 filtered out
```

No broad Rust or Python suite was run.

## Release real-binary evidence

A clean detached release build at `54ff918b` passed the two formerly-red exact
cells:

```text
test_dynamic_hello_is_canonical[symbols-nonpie-O0-gcc]: pass
test_dynamic_hello_is_canonical[symbols-nonpie-O2-gcc]: pass
```

Both now recover the canonical string literal and round trip successfully.
The wider periodic Hello matrix was not repeated because its six PIE cells had
just been measured at the preceding checkpoint; AMD64 and AArch64 were green
at O0/O2 and ARMv7 remained known-red.

## Scope

This closes the direct constant character-pointer consumer in string folding
and the sampled non-PIE Hello failure. Universal expression attribution, split
address ownership in the remaining consumers, and ARMv7 Hello closure remain
open.
