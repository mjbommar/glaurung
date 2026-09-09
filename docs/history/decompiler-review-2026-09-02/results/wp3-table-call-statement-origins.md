# WP3 function-table call statement origins

Commit `a4d8598a` closes the statement-owner half of optimized function-table
argument recovery. The prior target-reader repair proved all five callees had
the same `(rdi, rsi)` layout, but `fold_one_table_call` installed the computed
arguments only when the call statement itself was a raw `Stmt::Call`.
Production lowering attributes that call, so the final mutation declined and
`dispatch_operation` rendered a zero-argument indirect call.

The existing table behavior contract was strengthened to attribute both the
call target and the enclosing call statement. It was observed red with zero
arguments before the repair. The production mutation now uses the semantic
statement view while leaving its owner intact.

Exactly five focused Rust tests passed, covering the positive attributed call,
missing-entry and disagreeing-layout refusals, the unversioned-definition
refusal, and the adjacent direct-layout control. Each invocation filtered out
4,726 unrelated tests.

After an exact detached release build of `a4d8598a`:

```text
95_function_pointer_table:gcc:O2:dispatch_operation  pass
95_function_pointer_table:gcc:O0:dispatch_operation  pass
test_real_arm_mixed_hard_float_call_round_trip       pass
```

The O2 output improves from `OPERATIONS[var0]()` to an indirect call carrying
both recovered values through a two-argument function-pointer cast. This
closes the exact pass-to-fail baseline regression reproduced at both parent
`51b07fa4` and intermediate target-only commit `71123306`.

No broad Rust, Python, fixture, DecBench, or Joern suite ran. Function-table
declaration spelling still says `void` and remains separate WP8 prototype
presentation work; execution-correct call arguments are restored.
