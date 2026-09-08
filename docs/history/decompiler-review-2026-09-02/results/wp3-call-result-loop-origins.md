# WP3 call-result loop origin propagation

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commit `876bddf6` closes two bounded origin-carrier omissions in
`src/ir/call_result_split.rs`:

- an attributed `break` is now visible to the loop result-flow safety check, so
  speculative result rewriting cannot treat an early-exit loop like a
  fallthrough-only loop;
- an attributed call in a boxed `for` initializer or step is inspected in
  place, preserving the existing rule that a boxed clause cannot receive an
  inserted compatibility statement.

Both are semantic-safety repairs. They do not broaden call-result inference or
change its ABI assumptions.

## Focused TDD and real-binary evidence

Both tests were observed red before the two-line production repair:

```text
attributed_break_remains_a_loop_result_barrier
attributed_embedded_call_keeps_the_boxed_statement_shape
```

The exact module and real call-result lanes are green:

```text
cargo test --features python-ext ir::call_result_split::tests --lib -- --nocapture
15 passed; 0 failed

uv run maturin develop --release

uv run python tools/dectest.py \
  '11_call_shapes:*:*:call_chain_in_loop' \
  '11_call_shapes:*:*:call_fold_wide_result' \
  --jobs 4 --full
8 passed; 0 regressions; GCC/Clang O0/O2; 2.9 s
```

No repository-wide suite was started for this increment. The development loop
remains module-local plus exact affected real-binary functions; broader gates
are reserved for a coherent integration boundary.

## Next action

Re-audit the remaining enabled raw statement matches. Migrate the next reader
or in-place rewrite as a focused batch; do not start expression ownership until
the statement-consumer audit is closed.
