# §V — Typed locals from call prototypes

> **Kind:** guide · **Status:** maintained

Goal: inspect stack types propagated from known call prototypes and distinguish
automated refinement from a manual type assertion.

## Create and inspect the project

```bash
BIN=samples/binaries/platforms/linux/amd64/export/native/clang/O0/c2_demo-clang-O0
DB=c2-types.glaurung
uv run glaurung kickoff "$BIN" --db "$DB"
uv run glaurung view "$DB" 0x1160 --binary "$BIN" \
  --pane pseudo --pseudo-lines 8
```

The current view shows three locals with `set_by=propagated`. See
[`view-typed-locals.out`](../_fixtures/04-typed-locals/view-typed-locals.out).

Audit provenance directly in the SQLite project:

```bash
sqlite3 "$DB" -cmd ".mode column" \
  "SELECT printf('%#x', function_va) AS function_va,
          printf('-%#x', -offset) AS offset, name, c_type, set_by
   FROM stack_frame_vars
   WHERE function_va = 0x1160 AND set_by = 'propagated'
   ORDER BY stack_frame_vars.offset;"
```

The verified rows are
[`find-stack-vars-propagated.out`](../_fixtures/04-typed-locals/find-stack-vars-propagated.out).

## Re-run propagation in the REPL

```text
g 0x1160
propagate
save
```

The command reports how many slots it refined in that run; the count is not a
stable compatibility promise. See
[`repl-propagate.out`](../_fixtures/04-typed-locals/repl-propagate.out).

Prototype-derived types remain hypotheses. Check the callsite argument flow,
width, and lifetime before using them to justify a security or semantic claim.
Manual retyping should occur only when stronger evidence warrants overriding
the propagated result.

Continue to [§W — Benchmark harness](bench-harness-as-ci.md).
