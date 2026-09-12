# WP3 store and aggregate-return rendering through expression carriers

> **Kind:** record · **Date:** 2026-09-12

## Outcome

Commit `32186aca` closes three adjacent DecBench render consumers that treated
`Expr::Origin` as value semantics:

- pointer-valued register stores retain the same representation conversion as
  plain registers instead of acquiring another redundant cast;
- promoted-local store destinations remain assignments to the recovered local,
  and inline declaration planning recognizes the same attributed first
  definition;
- synthesized aggregate returns retain their complete object load instead of
  narrowing to the renderer's scalar fallback.

Only ownership carriers are transparent. Pointer facts, promoted-local
classification, declaration eligibility, synthesized ABI return types, and
access widths remain the existing authorities.

## Observed-red contracts

All three contracts were observed red before implementation.

`attributed_pointer_register_store_matches_plain_representation` showed that
an owner changed `(long)((long)var13)` into
`(long)((long)((long)var13))`.

`attributed_promoted_local_store_matches_plain_assignment` showed the more
serious semantic change:

```c
long local_8;
*(int *)(local_8) = 7;
```

The plain expression correctly rendered `long local_8 = 7;`. Repairing the
statement renderer exposed the independent inline-declaration planner
omission; both consumers now inspect the semantic address.

`attributed_synthesised_aggregate_return_matches_plain_object_load` showed a
16-byte `struct __glaurung_sse_pair` return narrowing from:

```c
return *(struct __glaurung_sse_pair *)(&local_10[0]);
```

to an incompatible eight-byte `return *(long *)(&local_10[0]);` solely because
the dereference carried an owner.

## Focused verification

The three observed-red tests pass, along with the genuine-pointer-store,
coalesced-slot, pointer-assignment, stack-pointer conversion, and attributed
bank-composition controls. Commands used only exact tests or
narrow name filters; filtered tests were not executed.

## Exact release checkpoint

A clean detached worktree at exact commit `32186aca` was release-built. Its
extension SHA-256 is
`c7b25fbedf70d1f84abec57b855fa585fa8c91d4c64ec99c6d96920ede19d37b`.

The complete by-value-aggregate and aggregate-return-edge fixture families
retain their established verdicts across GCC/Clang O0/O2:

```text
uv run --no-sync python tools/dectest.py \
  '195_by_value_aggregates:*:*:*' \
  '198_aggregate_return_edges:*:*:*' --jobs 4 --full

100 function cells: 92 pass, 8 baseline-accepted structural, 0 regressions
```

The first attempted selector used the obsolete descriptive name
`195_split_bank_returns`; the harness failed closed before running a fixture,
then the command above used the live manifest keys. No attributable corpus-text
change is claimed. No whole-Python, DecBench, or Joern gate was run.

## Next boundary

Continue the renderer audit for remaining direct expression destructures, then
return to the broader WP3 semantic-consumer and invalidation work. Do not use
presentation-only transparency across `NumericConvert` or any other
value-changing node.
