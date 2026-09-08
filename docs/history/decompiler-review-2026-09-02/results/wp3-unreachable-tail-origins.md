# WP3 attributed unreachable-tail pruning

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commit `91432a22` makes lexical unreachable-tail pruning recognize attributed
labels and terminal transfers. A wrapped return, goto, indirect goto, or break
now terminates the current lexical run exactly like its unwrapped form; a
wrapped label still opens a possible region entry.

Statements proven unreachable are removed with their mappings rather than
reattributed to executable source. Surviving statements retain their exact
owners. The existing iterative label/goto proof is unchanged: removing an
unreachable goto can make its former target label unreferenced on the next
round, but referenced region-entry labels remain.

## Focused evidence

The attributed-return test was observed red before repair: all five statements,
including an unreachable store and backward goto, remained. After repair only
the live store and return remain with their original owners.

```text
cargo test --features python-ext \
  ir::label_prune::tests::attributed_return_prunes_unreachable_tail_and_keeps_surviving_owners \
  -- --exact
1 passed; 0 failed

cargo test --features python-ext ir::label_prune::tests
20 passed; 0 failed
```

A fresh release extension was built in 35.09 seconds. The two exact host O0
review functions remain execution-correct:

```text
uv run python tools/dectest.py \
  '01_conditional_polarity:*:O0:classify' --jobs 2 --full --show
2 passed; 0 regressions in scope
```

No broad Rust, Python, architecture, fixture, or DecBench sweep was run.

## Next action

Continue the enabled production-reader audit after confirming the remainder of
`label_prune.rs` already uses semantic statement access.
