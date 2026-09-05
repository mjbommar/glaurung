# WP6 SysV split-bank return evidence — 2026-09-05

> **Kind:** record · **Date:** 2026-09-05

## Outcome

Commit `9fed7199` repairs optimized SysV AMD64 callees whose declared aggregate
result is split between the integer and SSE register banks. GCC and Clang both
return `struct bv195_mixed { int32_t tag; double value; }` in `RAX` plus
`XMM0`, but generic direct-output projection selected only one bank: GCC lost
the `double`, while Clang lost the integer tag.

The new early, prototype-gated pass captures exact SSA definitions from both
banks before role naming and dead-store elimination. It materializes them into
one synthetic 16-byte aggregate object in declared eightbyte order and returns
the whole object through the existing ABI tag. Calls invalidate both banks;
uncertain joins, missing definitions, wrong conventions, and scalar return
classes decline the transformation all-or-nothing.

Commit `41af392d` separately repairs the execution oracle. Its former raw-byte
comparison included internal and trailing C structure padding, whose value is
indeterminate. The comparator now uses DWARF member extents as a byte mask. A
focused test proves padding differences are ignored while a changed `double`
member is still detected.

## Validation

Focused Rust validation reports 13 `callee_return_bank` tests passed, including
GCC/Clang projection shapes and refusal cases. The freshly rebuilt release
extension changes all four `bv195_make_mixed` cells from fail to pass:

- GCC O0 and Clang O0: semantic fields were already correct; the oracle no
  longer compares four bytes of indeterminate interior padding.
- GCC O2 and Clang O2: both machine return banks are now preserved.

The combined host aggregate slice reports zero regressions and seven verified
baseline improvements:

```text
uv run python tools/dectest.py \
  '195_by_value_aggregates:*:*' \
  '197_homogeneous_float_aggregates:*:*' \
  '198_aggregate_return_edges:*:*' \
  --jobs 8 --full
```

Every fixture `195` and `198` function is now pass or intentionally structural
across GCC/Clang O0/O2. Fixture `197` retains its known O2 all-SSE aggregate
failures and is the next bounded WP6 ABI target.

The full Rust gate at `41af392d` is green: the library target reports 4,065
passed, zero failed, and five ignored; all integration targets passed, and the
documentation target reports two passed and one ignored. The regenerated
census records 4,582 declared Rust tests, five more than the previous record,
with zero tests outside every gate.

## Scope and limits

The production rewrite is specific to declared SysV AMD64 split INTEGER+SSE
returns. It does not infer a return class from register liveness, change scalar
return precedence, or claim equivalent behavior on Win64, AArch64, ARM32, or
i386. The DWARF padding mask is convention-independent because padding is
indeterminate in the C object model, but it compares only layouts the existing
signature reader already validated.

No DecBench run, publication, issue, comment, or pull request was performed.
