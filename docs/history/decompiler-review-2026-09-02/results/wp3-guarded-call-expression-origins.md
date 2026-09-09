# WP3 guarded-call expression origins

> **Kind:** record · **Date:** 2026-09-09

## Outcome

Commit `e9c64a87` makes guarded-call false-edge recovery transparent to
expression provenance. Attributed guards, tested values, zero literals, copied
call results, and store addresses now retain the same semantic proof as their
plain forms. The synthesized zero assignment carries the union of the guarded
statement and guard-expression owners.

## Focused validation

The existing statement-attribution contract was strengthened to attribute the
condition and its operands. It failed before the repair because the pass left
the false edge implicit, then passed after the repair:

```text
attributed_guarded_call_preserves_the_false_edge_proof: pass
ir::guarded_call::tests: 3 passed, 4,693 filtered out
```

After a clean detached release build at `e9c64a87`, the directly owning binary
round trip also passes:

```text
test_guarded_call_select_retains_both_value_edges: 1 passed
```

No broad Rust, Python, fixture, DecBench, or Joern run was performed.

## Periodic Hello World checkpoint

Six exact GCC symbols/PIE cells sampled the principal Linux architectures at
O0 and O2. AMD64 and AArch64 are canonical at both optimization levels (4/4).
ARMv7 remains known-red at both levels (0/2): O0 retains the previously recorded
frame object, link-register local, and `no_stack_protector` annotation; O2
still invents four parameters for `main`. Two accidentally selected AMD64
non-PIE cells also reproduce the existing raw string-address failure. None of
these outputs are on the guarded-call transformation path.

## Scope

This closes one bounded WP3 expression-consumer omission. Universal expression
ownership, the remaining wildcard audit, and the ARMv7/non-PIE Hello debts
remain open.
