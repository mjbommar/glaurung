# WP3 terminal-tail expression origins

Commit `2688c23e` makes matching terminal-guard recovery transparent to
expression ownership on the duplicated return value. Semantically identical
terminal tails can now recover from
`if (bad) return x; if (good) return y; return x;` into the source-like
`if (bad || !good) return x; return y;` even when the two copies of `x` carry
different provenance.

The comparison is deliberately limited to the terminal-tail vocabulary already
accepted by this rule: identical comments, no-ops, and returns whose optional
semantic values agree. It does not introduce general provenance-insensitive AST
equality. When a duplicate return is removed, its statement and return-value
owners move to the retained statement, while the retained value keeps its own
expression owner. Existing exact-Boolean and non-trapping predicate gates are
unchanged.

The ownership contract was strengthened with distinct owners on the two `-7`
return values. It was observed red before repair because all three guards/tails
remained. After repair:

```text
attributed_terminal_pair_merges_guard_and_duplicate_tail_origins: 1 passed
mismatched_or_unnegatable_terminal_guard_stays_early:              1 passed
ir::guard_chain::tests:                                           25 passed
```

An exact detached release build of `2688c23e` was fresh. The directly adjacent
guard-heavy `validate_header` control passes under both host O2 compilers:

```text
07_packet_parser:clang:O2:validate_header  pass
07_packet_parser:gcc:O2:validate_header    pass
```

No broad Rust, Python, fixture, DecBench, or Joern suite ran. The periodic
six-cell Hello checkpoint was not repeated because it passed at exact commit
`bf8718e9` shortly before this increment.

This closes one bounded terminal-tail consumer, not WP3. Authoritative SSA
identity, explicit invalidation, and the remaining semantic-consumer audit stay
open.
