# WP3 matching-return expression origins

Commit `f8433a3f` completes the adjacent single-guard matching-return origin
boundary. An attributed exact predicate and independently attributed but
semantically identical early/final return values no longer prevent recovery of
`if (!bad) { work; } return x;` from duplicated terminal control flow.

The rule still requires one early return, a matching final return, a non-empty
structured continuation, no unstructured transfer, and an exactly negatable
predicate. Semantic equality remains limited to the terminal statement helper
introduced for this guard family. Negating an expression-origin carrier keeps
that carrier around the exact inverse comparison. The eliminated early return's
statement and value owners transfer to the retained return, whose value keeps
its own owner.

The ownership contract was strengthened with an attributed condition and
different owners on the two `result` expressions. It was observed red before
repair because all three statements remained. After repair:

```text
attributed_matching_returns_preserve_guard_and_both_terminal_origins: 1 passed
mismatched_or_unnegatable_terminal_guard_stays_early:                  1 passed
shared_terminal_pair_with_memory_predicate_stays_separate:            1 passed
ir::guard_chain::tests:                                               25 passed
```

An exact detached release build of `f8433a3f` was fresh. Both directly adjacent
guard-heavy O2 controls pass:

```text
07_packet_parser:clang:O2:validate_header  pass
07_packet_parser:gcc:O2:validate_header    pass
```

No broad Rust, Python, fixture, DecBench, or Joern suite ran. The periodic
six-cell Hello checkpoint was not repeated because it passed at exact commit
`bf8718e9` shortly before this coherent guard batch.

This closes the bounded matching-return expression layer, not WP3.
Authoritative SSA identity, explicit invalidation, and the remaining semantic-
consumer audit stay open.
