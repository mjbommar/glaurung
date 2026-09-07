# WP3 canonical loop naming origin propagation

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commit `bd31420d` makes fallback canonical loop naming transparent to
statement origins. An attributed recovered `for` can still receive `i` for
its zero-initialized unit-step induction local and `sum` for a distinct
zero-initialized additive accumulator.

The change is deliberately presentation-only. It reads the semantic statement
through its carrier and lets the existing recursive rename operate in place;
the loop, initializer, step, accumulator initializer, and body update retain
their exact independent `OriginSet`s. The recognizer's existing refusal rules
are unchanged.

## Focused evidence

The new test was observed red before the repair because the origin-wrapped
top-level `For` was not recognized:

```text
canonical_loop_names_see_through_origins_without_reassigning_them
assertion failed: left None, right Some("i")
```

After changing only the three naming reads, the exact test and complete touched
module pass:

```text
cargo test --features python-ext \
  ir::naming::tests::canonical_loop_names_see_through_origins_without_reassigning_them \
  -- --exact
1 passed; 0 failed

cargo test --features python-ext ir::naming::tests
18 passed; 0 failed
```

A fresh release extension was built in 35.42 seconds. The directly relevant
real loop remains execution-correct across its four host cells:

```text
uv run python tools/dectest.py \
  '12_loop_rotation:*:*:skip_odd_sum' --jobs 4 --full --show
4 passed; 0 regressions in scope
```

That fixture carries authoritative debug names in its O0 scored output, so the
real-binary run is adjacent regression evidence rather than proof that fallback
`i`/`sum` naming fired. The observed-red attributed-AST test is the direct proof
of the repaired behavior. No broad suite was run.

## Next action

Continue the ordered WP3 enabled-reader audit with the architecture-specific
prologue consumers. Preserve every existing ABI refusal boundary and use one
observed-red unit case plus only the matching architecture fixture cells.
