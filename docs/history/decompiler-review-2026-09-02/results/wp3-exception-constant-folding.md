# WP3 exception constant folding

Commit `826571a8` extends the ordinary, purely syntactic constant-fold surface
through `throw` values and every try/catch body. Arithmetic and condition
expressions inside recovered exception control flow therefore no longer retain
machine-shaped constant trees solely because of their enclosing statement.
The enclosing exception node and its ownership are unchanged.

This is a bounded WP3 consumer repair. It does not extend the two type-aware
constant folds, establish authoritative SSA identities, or complete the wider
exception consumer audit.

## Focused evidence

The new exception-surface contract was observed red first: `fold_constants`
reported no change and both `40 + 2` expressions survived. After the repair,
the throw value and catch return both become `42`.

```text
cargo test --features python-ext --lib \
  ir::const_fold::tests::exception_expressions_share_the_constant_fold_surface
1 passed; 4,739 filtered out

cargo test --features python-ext --lib ir::const_fold::tests::
82 passed; 4,658 filtered out
```

An exact detached release build of `826571a8` produced native SHA-256
`3a5a1bb42e9d07bc5f14647b6d81cb2cf23492c2523688e6f3814d4fb4327a7d`.
The periodic symbol/PIE Hello checkpoint stayed canonical in six cells: GCC O0
and O2 on x86-64, AArch64, and ARMv7.

The directly relevant C++ exception fixture was restricted to four cells:

```text
10_cpp_runtime_shapes:clang:O0:cpp_exception  fail
10_cpp_runtime_shapes:clang:O2:cpp_exception  pass
10_cpp_runtime_shapes:gcc:O0:cpp_exception    fail
10_cpp_runtime_shapes:gcc:O2:cpp_exception    pass
```

Both O0 executions crash on `INT_MIN` because the recovered catch path reads an
invalid call-lifetime value. An exact release rebuild of parent `3a1c798c`
produces the same output and the same two failures, proving this increment did
not introduce them. They contradict the currently committed passing baseline
and remain explicit exception-recovery/execution debt. No broad Rust, Python,
fixture, architecture, DecBench, or Joern suite ran.
