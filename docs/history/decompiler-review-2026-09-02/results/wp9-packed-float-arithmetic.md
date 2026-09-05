# WP9 legacy packed-float arithmetic evidence — 2026-09-05

> **Kind:** record · **Date:** 2026-09-05

## Outcome

The x86 lifter now gives the complete legacy `ADDPS`, `SUBPS`, `MULPS`, and
`DIVPS` family explicit binary32 semantics. Each instruction becomes four
typed scalar IEEE-754 intrinsics over the four XMM dword lanes. Register and
memory sources are supported; memory operands retain four exact four-byte
accesses. VEX and EVEX forms still decline rather than inheriting incorrect
two-operand or upper-lane behavior.

This removes the opaque `mulps` and `addps` operations from Clang O2
`217_complex_arithmetic:complex_float_multiply`. The recovered output now
contains the real and imaginary arithmetic on both packed components. The
execution cell remains RED because its exceptional path calls `__mulsc3`, and
the current call IR cannot represent that helper's four SSE arguments plus its
two-component complex result. The double sibling has the same call-boundary
defect at `__muldc3`. This increment therefore improves instruction semantics
and visible output without claiming the complex-arithmetic fixture is fixed.

## Production boundary

- `src/ir/lift_x86/packed.rs` owns the reusable lane-wise lowering.
- `src/ir/lift_x86.rs` dispatches all four legacy mnemonics to it.
- The operation names reuse the scalar `addss`, `subss`, `mulss`, and `divss`
  intrinsic contracts, so type recovery and AST lowering consume one existing
  IEEE-754 representation rather than a parallel vector-only expression type.
- Unsupported operand shapes remain `Op::Unknown`; VEX/EVEX packed arithmetic
  is not generalized from legacy SSE.

## Verification

The release Python extension was rebuilt with:

```text
uv run maturin develop --release
```

Its `target/release/libglaurung.so` SHA-256 was
`1a586020b31ab41b44a6946957f55648e583bbf2628054c42cf134082133a837`.
The fixture source SHA-256 was
`0cf6cf633eaedd332f144d7102586f98fc096220d83e526991e1e0abf21e3be5`.

Focused unit validation:

```text
cargo test --features python-ext packed_float
```

reported four passed tests. The two new tests cover every register-form
mnemonic and every lane, plus the exact offsets and widths of a memory-form
`MULPS` source. The regenerated test census records 4,601 declared tests,
2,096 under `ir`, and zero outside all gates.

The adjacent release-built fixture command was:

```text
uv run python tools/dectest.py \
  '172_float_double_widths:*:O2:*' \
  '188_vector_transport:*:O2:*' \
  '197_homogeneous_float_aggregates:*:O2:*' \
  '217_complex_arithmetic:*:O2:complex_float_multiply' \
  --jobs 4 --full
```

It reported no scoped regression. All eight vector-transport cells passed and
all twenty non-structural optimized HFA cells passed; the existing scalar-width
failures stayed unchanged. Both selected complex-float cells remain failures
for the separately diagnosed helper-call boundary.

The authoritative Rust command:

```text
cargo test --features python-ext
```

completed green: 4,084 library tests passed, five were ignored, every
integration target passed, and both doc tests passed with one ignored. The
identity-retrieval integration tail took 522.21 seconds but completed with 44
passed and ten ignored.

The required whole Python command was also allowed to finish:

```text
uv run pytest python/tests/
```

It remained broadly red after 2,685.31 seconds: 4,611 passed, 119 failed, 68
skipped, 896 expected-failed, and 125 deselected. The failures span the already
recorded fixture, architecture, structural, def-use, documentation, fitness,
and generated-reference drift; the semantic baselines were not rewritten.
The focused fixture command above is the regression evidence for this slice,
not the red repository-wide total. Two bookkeeping facts are relevant to
interpreting the broad result: `packed.rs` was already 1,174 lines and above
the large-module threshold before this increment, and the documentation index
already omitted nineteen other review-result records. This record is now
listed explicitly in `docs/history/README.md`; the unrelated historical/index,
fitness, and generated-pass-reference failures remain visible.

## Next production increment

The two helpers do not share one result shape. System V `__mulsc3` returns two
binary32 components packed into the low 64 bits of `xmm0`; `__muldc3` returns
one binary64 component in each of `xmm0:xmm1`. Treating both as a
multi-register result would be as wrong as retaining the former single-scalar
model. The follow-on work is recorded in
`wp6-compiler-complex-helper-boundary.md`.

The landed WP6/WP9 slice carries an exact source-ordered SSE parameter layout
and materializes each helper through its proven carrier shape. Generalizing
that exact fact beyond these two compiler-runtime contracts and completing the
exceptional-input execution matrix remain open. Incomplete layouts must still
be refused, and scalar, integer-pair, HFA, and vector-call controls must remain
green.

No DecBench run or upstream interaction was performed.
