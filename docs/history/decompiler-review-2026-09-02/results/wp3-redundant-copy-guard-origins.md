# WP3 redundant-copy guard expression origins

Commit `b58c5322` makes redundant reaching-copy guard fusion transparent to
expression ownership. Two copies of the same register or constant value may
now be recognized as semantically identical even when their source expressions
have distinct provenance, allowing nested guards to recover as one readable
short-circuit `if (a && b)`.

The safety boundary remains fail-closed. Both statements must assign the same
destination and their semantic sources must be the same register or constant.
Memory-backed, changed-source, or differently targeted copies remain visible.
When the duplicate is removed, both its statement origin and its source-
expression origin move to the surviving copy; that copy's original expression
owner remains attached to its source.

The existing ownership contract was strengthened with different owners on the
two source expressions. It was observed red before repair: fusion did not run,
and only the first statement owner remained. After repair:

```text
attributed_duplicate_copy_and_nested_guards_preserve_separate_origins: 1 passed
duplicate_reaching_copy_exposes_nested_conjunction:                    1 passed
changed_or_memory_backed_copy_blocks_nested_conjunction:               1 passed
ir::guard_chain::tests:                                                25 passed
```

An exact detached release build of `b58c5322` was fresh. Two guard-heavy
`tlv164_max_depth` O2 controls retained their existing baseline-fail verdicts
under GCC and Clang, with no regression in scope. Those controls are not proof
that this specific fold fired; the red-first AST contract is that proof. Their
remaining output defects are primarily stack-local and type recovery.

No broad Rust, Python, fixture, DecBench, or Joern suite ran. The periodic
six-cell Hello checkpoint was not repeated because it passed at exact commit
`bf8718e9` shortly before this increment.

This closes one bounded guard-expression consumer, not WP3. Authoritative SSA
identity, explicit invalidation, and the remaining semantic-consumer audit stay
open.
