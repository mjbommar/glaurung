# WP6/WP9 compiler complex-helper boundary

> **Kind:** record · **Date:** 2026-09-05

## Outcome

The bounded SysV AMD64 boundary for the compiler support routines `__mulsc3`
and `__muldc3` is implemented. Both calls now receive the exact source-ordered
SSE argument layout `xmm0`, `xmm1`, `xmm2`, `xmm3`, and their results retain
the distinct storage contracts observed in the fixture machine code:

- `__mulsc3` returns two binary32 components packed into the low 64 bits of
  `xmm0`;
- `__muldc3` returns two binary64 components in `xmm0:xmm1`.

This distinction is load-bearing. Describing both helpers as multi-register
returns invents an `xmm1` result for `__mulsc3`; describing either as an
ordinary scalar loses one complex component. The implementation instead uses
one synthetic packed-SSE aggregate for the former and the existing homogeneous
SSE-pair representation for the latter.

The call-argument reconstruction also accepts exact SSE layouts whose setup is
visible through an enclosing structured branch. This preserves all four helper
inputs on the exceptional path rather than recovering only the last assignment
adjacent to the call.

## Production surface

- `src/ir/call_contracts.rs` owns the normalized compiler-runtime prototypes,
  exact SysV scalar SSE allocation, and SSE result selection.
- `src/python_bindings/ir/callee_contracts.rs` keeps the helpers external to
  body-liveness inference and transports their exact layouts and prototypes.
- `src/ir/call_args.rs` and `src/ir/call_args/enclosing_slots.rs` recover the
  four values across their enclosing structured region.
- `src/ir/abi/return_spelling.rs` defines the one-register packed two-float
  representation independently of the existing two-register SSE pair.
- `src/ir/call_result_split.rs` materializes the packed lanes or paired
  carriers from the proven call-site return spelling.
- `tools/diff_decompile.py` treats these toolchain support routines as external
  runtime boundaries when recompiling a caller, rather than recursively adding
  their local linked implementations to the source unit under test.

## Fixture evidence

The release-built focused command was:

```bash
uv run python tools/dectest.py \
  '217_complex_arithmetic:*:O2:complex_float_multiply' \
  '217_complex_arithmetic:*:O2:complex_multiply' \
  --jobs 4 --full
```

It reports four improvements and no scoped regressions:

| Fixture cell | Before | After |
|---|---:|---:|
| Clang O2 `complex_float_multiply` | fail | pass |
| Clang O2 `complex_multiply` | fail | pass |
| GCC O2 `complex_float_multiply` | fail | pass |
| GCC O2 `complex_multiply` | fail | pass |

The adjacent release-built slice retains all eight vector-transport passes and
all twenty non-structural optimized homogeneous-float passes; its two
structural homogeneous-float rows remain at their expected baseline status.
The previously known fixture-172 failures are unchanged.

Focused implementation checks also passed:

```text
cargo test --features python-ext ir::call_args:: --lib
102 passed

cargo test --features python-ext call_result_split --lib
13 passed

uv run pytest -q python/tests/test_decompiler_fixture_harness.py \
  -k compiler_complex_runtime_stays_an_external_boundary
1 passed
```

## Scope and remaining work

This is a deliberately bounded compiler-runtime contract, not a claim that the
general call model is complete. It proves two named SysV helpers only. Other
calling conventions, arbitrary aggregate parameters and returns, and vector
source types remain outside this increment.

The next generalization should replace the helper-specific transport with one
exact call-boundary fact capable of describing source-ordered argument storage,
carrier registers, component offsets, component widths, and provenance. It
must fail closed when any required layout fact is incomplete.

Finite fixture execution is covered by the four round trips above. A dedicated
exceptional-input matrix for NaNs, infinities, signed zero, overflow, and
underflow remains required before the broader WP6 call-result exit criteria can
close. Scalar, integer-pair, HFA, vector-transport, consecutive-call, and
control-flow-join cases remain required controls during that generalization.

No DecBench run or upstream interaction was performed.
