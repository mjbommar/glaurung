# WP3 unit-step render origins

Commit `e54bd1d7` closes a bounded output-readability hole in the scored-C
renderer. Its integer-local unit-step recognizer now skips expression-origin
carriers while peeling the existing width-cast chain and while checking the
same-variable left operand and literal-one right operand.

The strengthened contract attributed the outer cast, addition, induction
value, and constant independently. It was observed red before the repair:

```c
for (i = 0; i < 3; i = (unsigned int)((i + 1)))
```

After the repair, the same semantic AST renders the source-like form:

```c
for (i = 0; i < 3; i++)
```

The safety boundary is unchanged: only an integer local updated from itself by
literal one becomes `++` or `--`; other operators, values, and destinations
still decline.

Focused validation:

```text
cargo test --features python-ext --lib unit_step --quiet
1 passed

python tools/dectest.py '03_loop_shapes:*:*:for_sum' --jobs 4 --full
GCC O0/O2 and Clang O0/O2: 4 passed; no regressions in scope
```

An exact detached release build of `e54bd1d7` was fresh. Direct inspection of
the real GCC-O0 `for_sum` output confirms `for (int i = 0; i <= 7; i++)` and a
clean `s += p[i]` body. No broad suite ran. The six-cell Hello checkpoint was
not repeated because it passed immediately before this increment.

This complements the earlier counted-loop recovery repair: that pass preserves
an attributed machine step while reconstructing a `for`; this change ensures
the shared renderer still spells that recovered step cleanly. WP3 and the
remaining expression-consumer audit stay open.
