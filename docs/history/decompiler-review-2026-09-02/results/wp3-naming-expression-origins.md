# WP3 naming expression origins

> **Kind:** record · **Date:** 2026-09-09

## Outcome

Commit `95556536` makes two final presentation decisions transparent to
expression provenance. A direct attributed return value can still establish
the canonical `ret` output role, and attributed promoted-local addresses,
initializers, increments, and additive updates can still establish the
fallback `i` and `sum` loop names.

The recursive rename already preserved expression carriers. This increment
changes only recognition: it inspects semantic expressions while retaining the
existing exact return, promoted-storage, zero-initializer, unit-step, and
additive-update requirements.

## Focused TDD

The two existing statement-origin contracts were strengthened with expression
owners. Before repair, the return assignment stayed under its machine name and
the loop produced neither canonical role. After repair:

```text
origin_wrapped_ssa_return_carrier_keeps_the_output_role: pass
canonical_loop_names_see_through_origins_without_reassigning_them: pass
ir::naming::tests: 21 passed, 4,675 filtered out
```

## Release real-binary evidence

After a clean detached release build at `95556536`, only the directly adjacent
loop witness ran:

```text
12_loop_rotation:clang:O0:skip_odd_sum  pass
12_loop_rotation:clang:O2:skip_odd_sum  pass
12_loop_rotation:gcc:O0:skip_odd_sum    pass
12_loop_rotation:gcc:O2:skip_odd_sum    pass
```

This is four lanes of 838 with no regression in scope. No broad Rust, Python,
fixture, DecBench, or Joern run was performed. The periodic Hello World matrix
was not repeated because it ran two increments earlier.

## Scope

This closes the direct-return and canonical-loop naming expression readers. It
does not complete universal expression attribution or the remaining wildcard
audit.
