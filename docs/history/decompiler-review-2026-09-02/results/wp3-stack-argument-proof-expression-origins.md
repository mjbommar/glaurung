# WP3 stack-argument proof expression origins

> **Kind:** record · **Date:** 2026-09-10

## Outcome

Commit `b0b09e5d` makes the outgoing-stack argument proof chain transparent to
expression ownership. Exact stack subtraction, push-store addresses,
preallocated stack areas, post-call addition, and lowered-pop loads now inspect
their semantic expressions and operands.

This preserves recovered calls when those machine operations carry independent
instruction provenance. The proof remains fail-closed: exact stack storage
identity, positive widths, zero-based aligned slots, pointer width, balanced
cleanup, and supported architecture rules are unchanged.

## Focused TDD

The existing opaque-identity and origin-wrapped SysV contracts were
strengthened with owners on their arithmetic, register, literal, address, load,
and cleanup expressions. Before repair, the exact allocation proof returned
`None` instead of eight bytes. After repair:

```text
sysv_stack_area_uses_exact_identity_not_display_spelling:       pass
origin_wrapped_sysv_push_and_cleanup_are_recognized:             pass
sysv_balanced_stack_argument_keeps_only_its_value_store_owner:   pass
sysv_balances_stack_arguments_consumed_by_lowered_pop_pairs:     pass
```

The negative opaque value whose spelling resembles `rsp` still fails closed.

An exact detached release build of `b0b09e5d` was fresh. The directly owning
real fixture passes:

```text
06_calling_conventions:i386:O2:forward_sum6  pass
```

That function exercises six lowered cdecl pushes and their cleanup. No broad
Rust, Python, fixture, DecBench, or Joern suite ran. The recent Hello checkpoint
was not repeated because this increment has a direct architecture-specific
witness.

This closes the bounded outgoing-stack helper family, not general MemorySSA or
WP3. Authoritative identity, explicit invalidation, and the remaining semantic-
consumer audit stay open.
