# WP3 ordinary x86 epilogue origin propagation

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commit `96e86313` makes the ordinary x86-64 epilogue transaction transparent
to statement origins. Canonical `leave`, standalone `pop rbp`, promoted-stack
restore, pre-rematerialized pop, and idempotent second-round teardown forms now
recognize attributed statements.

Every replacement comment receives the exact union of the machine statements
it replaces. If a later recognition round consumes an adjacent stack teardown,
that owner merges into the existing epilogue comment. Returns keep their
independent owners, and the structural/balance predicates are unchanged.

## Focused evidence

The attributed canonical-`leave` test was observed red before repair because
both wrapped machine statements leaked. Focused assertions also cover
standalone pop with preceding teardown, promoted-stack restore, and merging a
late teardown into an already attributed comment.

```text
cargo test --features python-ext \
  ir::x86_prologue::tests::attributed_leave_epilogue_unions_exact_machine_owners \
  -- --exact
1 passed; 0 failed

cargo test --features python-ext ir::x86_prologue::tests
39 passed; 0 failed; finished in 0.20s
```

A fresh release extension was built in 35.17 seconds. The exact O0 review
anchor remains execution-correct under both host compilers:

```text
uv run python tools/dectest.py \
  '01_conditional_polarity:*:O0:classify' --jobs 2 --full --show
2 passed; 0 regressions in scope
```

No broad Rust, Python, architecture, fixture, or DecBench sweep was run.

## Next action

Re-audit `src/ir/x86_prologue.rs` for any remaining production raw-statement
reader. If the module is clean, move to the next enabled WP3 wildcard consumer
rather than expanding validation around this completed local transaction.
