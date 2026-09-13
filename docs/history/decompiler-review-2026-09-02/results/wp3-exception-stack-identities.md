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

## Internal authority closure

Follow-on commit `54245e36` removes the remaining optional-identity engine from
integer exception recovery. Non-test builds can now construct only
`ExceptionAuthority::Exact(&ValueIdentities)`; the three raw adapters and their
promoted-local spelling authority compile only for legacy unit tests. RTTI
address propagation and final throw-value recovery therefore cannot silently
fall back to `local_*` or `stack_*` spelling in shipped code.

Focused evidence:

```text
cargo test --features python-ext ir::exception_recover::tests:: --lib -- --test-threads=1
13 passed; 0 failed; 4833 filtered out

cargo check --features python-ext
exit 0

uv run maturin develop
exit 0

uv run python tools/build_guard.py
fresh
```

The required post-commit Python gate ran once with fail-fast. It passed the
former ARM Thumb and hard-float blockers and stopped at the independently known
committed-baseline disagreement at 17%:

```text
uv run pytest -q python/tests/ -x
FAILED test_decompiler_arch_roundtrip.py::test_the_committed_baseline_is_valid_and_has_a_clean_control_lane
```

That disagreement is the already-recorded x86-64 control verdict mismatch for
fixtures 157, 172, and 81. Neither baseline was regenerated from the shared
dirty checkout. No fixture sweep, DecBench, Joern, output, corpus, or timing
claim accompanies this authority-only follow-on. The exception-recovery
identity family is now internally closed; wider WP3 invalidation and origin
work remains.
