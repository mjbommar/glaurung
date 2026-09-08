# WP3 exception stack identities

> **Kind:** record · **Date:** 2026-09-08

## Outcome

Commit `54e67cb5` migrates the complete promoted-copy surface in integer
exception recovery from `local_`/`stack_` spelling to producer-owned stack
identity. Address propagation before the RTTI proof, relocation-backed `_ZTIi`
recognition, and throw-value resolution now share the same identity authority.
Both production entry paths pass the projected AST sidecar. Explicit
no-sidecar APIs retain the compatibility spelling rule.

The migration exposed an adjacent real defect: `_ZTIi` inside an
`Expr::Origin` was invisible to the direct RTTI recognizer because it did not
recurse through expression attribution. The first exact fixture run therefore
moved `cpp_exception` from pass to fail and retained raw
`__cxa_allocate_exception`/`__cxa_throw` calls. That run is not evidence of
success. The recognizer now traverses `Expr::Origin` and `NumericConvert`, and
the existing exact ABI test carries attributed RTTI evidence.

## Focused validation

```text
cargo test --features python-ext --lib ir::exception_recover::tests -- --nocapture
10 passed; 4,592 filtered out

uv run maturin develop
success

uv run python tools/build_guard.py
fresh; SHA-256 acc117242a211abd8e8821d53d32a365cbdf128df14b796f57801a41d3e84535

uv run python tools/dectest.py \
  10_cpp_runtime_shapes:clang:O2:cpp_exception --show
SCOPED: 1 lane of 838 - no regressions in scope

uv run pytest python/tests/test_test_census.py -q
6 passed
```

The regenerated census records 5,139 declared Rust tests and zero outside
every gate. No broad Rust/Python suite, fixture matrix, DecBench, or Joern lane
ran. This proves the exception-recovery identity boundary and its established
real regression cell, not all C++ exception ABIs or architectures.
