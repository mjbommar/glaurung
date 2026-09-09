# WP3 lazy-call select expression origins

Date: 2026-09-09

Commit: `327b6734`

## Defect

The lazy-call select pass already traversed statement-origin carriers, but its
constant-arm, signed range, saturation-call, duplicated-result, and promoted
destination classifiers still inspected several expressions literally. An
`Expr::Origin` could therefore prevent an otherwise safe call diamond from
collapsing into a lazy C conditional expression. The statement-level origin
union also omitted owners carried inside the consumed expressions.

That loses readability and increases tree distance without reflecting a real
semantic ambiguity: provenance is metadata, while the existing single-call,
single-use, width, constant-sentinel, and signed-range proofs decide whether
the transformation is legal.

## Change

`src/ir/lazy_call_select.rs` now classifies those expressions through their
canonical semantic view. When `call_result + call_result` becomes one call
multiplied by two, the two operands must still be semantically identical and
the resulting expression retains their complete origin union. The enclosing
replacement statement also collects all expression and statement owners from
the consumed diamond.

No effect, join, width, eager-evaluation, or call-count refusal was weakened.

## Focused RED/GREEN evidence

The new structured saturation contract assigns independent owners to the
condition, call target, doubled result and both operands, constant sentinel,
arm statements, and enclosing branch. Before the repair the diamond remained
an attributed `if`/`else`. After it:

```text
cargo test --features python-ext --lib \
  ir::lazy_call_select::tests::attributed_saturation_expressions_fold_with_all_consumed_origins --quiet
1 passed; 0 failed

cargo test --features python-ext --lib ir::lazy_call_select::tests --quiet
19 passed; 0 failed
```

No broad Rust or Python suite ran for this bounded change.

## Exact release fixture evidence

Commit `327b6734` was built in a detached clean worktree. The build guard
reported `fresh`, and Python imported the extension from that exact worktree.
The directly affected fixture and dedicated round trip are green:

```text
python tools/dectest.py 189_effectful_select --full --jobs 4
20 passed across 4 GCC/Clang O0/O2 lanes; no regressions in scope

python -m pytest -q python/tests/test_decompiler_lazy_call_select.py
1 passed
```

The periodic Hello grid was not repeated because the recent identity increment
had just reconfirmed selected O2 cells on all three architectures and the latest
complete checkpoint remains 72/72. Hello remains a periodic
cross-architecture canary rather than a per-pass tax.

## Boundary

This closes the lazy-call expression-consumer slice only. Universal production
expression attribution and the remaining enabled wildcard consumers keep WP3
open.
