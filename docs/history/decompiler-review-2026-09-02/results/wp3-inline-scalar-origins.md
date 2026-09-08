# WP3 attributed inline-scalar declarations

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commit `0c7b4e0f` makes the DecBench declaration planner's scalar write and
first-definition scans transparent to statement origins. A promoted or
debug-proven integer whose first safe definition is attributed can now render
as `int local = value;` instead of a separate declaration and assignment.

The existing safety proof is unchanged: a prior read or write, a self-reading
initializer, a non-integer source local, or a loop value used outside its loop
still keeps function-scope declaration. This changes presentation only; the
statement and its instruction origins remain intact.

## Focused evidence

The attributed initializer test was observed red before repair and rendered:

```c
int local_4;
local_4 = 0;
```

After repair it renders `int local_4 = 0;`. The unwrapped initializer,
read-before-definition refusal, and loop-scope declaration controls also pass.

```text
cargo test --features python-ext \
  ir::ast::tests::attributed_first_scalar_definition_becomes_its_declaration_initializer \
  -- --exact
1 passed; 0 failed

Three adjacent exact declaration tests
3 passed; 0 failed
```

A fresh release extension was built in 35.28 seconds. The exact initialized-
local loop function remains execution-correct under both host compilers:

```text
uv run python tools/dectest.py \
  '125_loop_shapes:*:O0:while_zero_trips' --jobs 2 --full --show
2 passed; 0 regressions in scope
```

No broad Rust, Python, architecture, fixture, or DecBench sweep was run.

## Next action

Continue the declaration/render consumer audit for provenance-blind scans,
then return to the remaining WP3 semantic transformations before claiming the
WP8 declaration boundary complete.
