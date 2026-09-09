# WP3 contradictory-guard expression origins

Commit `b3343fd7` makes exact contradictory nested-guard pruning transparent to
expression ownership on either comparison. A compiler-duplicated impossible
inner test such as `x <= 5` followed on that path by `5 < x` no longer remains
as misleading recovered control flow merely because the comparisons carry
different provenance.

The rule remains fail-closed. Both semantic conditions must be comparisons,
both must be safe to short-circuit, and exact comparison inversion must produce
the other condition. Changed widths, memory reads, intervening work, nonleading
guards, and guards with an `else` remain visible. The surviving outer condition
keeps its original expression owner.

The existing ownership contract was strengthened with distinct owners on the
outer and inner comparisons. It was observed red before repair because the
impossible nested `if` remained. After repair:

```text
attributed_contradictory_guard_is_pruned_without_losing_outer_origin: 1 passed
changed_width_memory_or_intervening_work_blocks_contradiction_pruning: 1 passed
ir::guard_chain::tests:                                                25 passed
```

An exact detached release build of `b3343fd7` was fresh. The nearest guarded-
switch O2 controls pass under both host compilers:

```text
186_defaultless_guarded_switch:clang:O2:dense_no_default  pass
186_defaultless_guarded_switch:gcc:O2:dense_no_default    pass
```

The periodic canonical Hello checkpoint also passes all six selected GCC
symbols/PIE cells: O0 and O2 on x86-64, AArch64, and ARMv7. No broad Rust,
Python, fixture, DecBench, or Joern suite ran.

This closes one bounded comparison consumer, not WP3. Authoritative SSA
identity, explicit invalidation, and the remaining semantic-consumer audit stay
open.
