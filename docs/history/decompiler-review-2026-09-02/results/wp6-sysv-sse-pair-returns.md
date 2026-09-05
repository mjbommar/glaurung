# WP6 SysV SSE-pair return evidence — 2026-09-05

> **Kind:** record · **Date:** 2026-09-05

## Outcome

The bounded fixture-197 slice is closed at behavioral commit `db750dbc`, with
its nine exact baseline changes and test-census refresh committed at
`1bee3fb1`. All non-structural functions in
`197_homogeneous_float_aggregates` now pass the GCC/Clang O0/O2 host matrix.
The two `hfa197_consume_pair2d` cells remain intentionally structural because
the execution oracle does not synthesize aggregate-by-value inputs.

This is a SysV AMD64 C result/argument and x86 instruction-semantics increment,
not completion of WP6's general type-constraint solver.

## Issue-to-capability map

| former failure | production capability | safety boundary |
|---|---|---|
| six optimized `make_pair2d`, `make_quad4f`, and `make_trio3f` cells | `cf9160ba` materializes declared SSE/SSE aggregate returns from exact `xmm0:xmm1` definitions; `db750dbc` supplies the packed conversions, shuffles, qword load, and cross-bank naming identity needed by the remaining optimized bodies | SysV AMD64 only; both ABI-classified parts must reach every return; calls, uncertain joins, missing carriers, and unsupported forms decline |
| GCC and Clang O2 `pair2d_roundtrip` | `fe50a360` forwards an immediately reaching SSE pair from a direct producer into a direct consumer | both recovered prototypes and the exact `xmm0:xmm1` layout must agree; intervening writes, calls, assembly, or control boundaries decline |
| Clang O2 `quad4f_roundtrip` | `3f4f12fe` lowers legacy `CVTTPS2DQ` into four typed scalar truncations | legacy 128-bit XMM forms only; AVX remains unsupported; NaN/out-of-range behavior inherits the existing scalar conversion limitation |

`db750dbc` additionally models legacy `CVTDQ2PS`, register-form `UNPCKLPS`
and `UNPCKHPD`, preserves `MOVQ xmm,m64` as one eight-byte memory access, and
renders concatenated packed dword payloads as widened bit composition. The
concat rewrite is restricted to physical packed-dword lane names; unknown
operand widths retain the conservative historical form. It also prevents the
plain-AST role pass from merging integer and SSE scratch registers into one
`ret` identity after a proved SSE-pair object has already been materialized.
Ordinary scalar returns retain the existing role mapping.

## Release-built fixture evidence

The extension was rebuilt with:

```text
uv run maturin develop --release
```

The resulting `target/release/libglaurung.so` had SHA-256
`f8ec19745373ff272330a0bb71a0e09c83413ab80d9bfd7e54b3fc91b5ad43e9`.
Fixture source SHA-256 was
`d3e802bed2ed9c17af66ef674ae6c7cb3d7bc82936dfb6df7f8eb00f8e503a7f`;
the recorded compilers are GCC 11.4.0 and Clang 14.0.0.

Against the pre-slice baseline at `6f82dc61`, the release build produced these
nine changes and no fixture-197 regression:

| compiler | optimization | functions changed from fail to pass |
|---|---|---|
| Clang | O2 | `make_pair2d`, `make_quad4f`, `make_trio3f`, `pair2d_roundtrip`, `quad4f_roundtrip` |
| GCC | O2 | `make_pair2d`, `make_quad4f`, `make_trio3f`, `pair2d_roundtrip` |

The exact current-baseline command covers four lanes and 44 functions:

```text
uv run python tools/dectest.py \
  '197_homogeneous_float_aggregates:*:*' \
  --jobs 4 --full
```

Every non-structural row passes. The adjacent aggregate regression command:

```text
uv run python tools/dectest.py \
  '195_by_value_aggregates:*:*' \
  '197_homogeneous_float_aggregates:*:*' \
  '198_aggregate_return_edges:*:*' \
  --jobs 4 --full
```

covers 12 lanes with no regression; fixtures 195 and 198 also remain entirely
pass or intentionally structural.

## Focused tests and records

The slice adds 16 declared Rust tests, moving the generated census from 4,582
to 4,598 and the `ir` subtotal from 2,077 to 2,093, with zero declared tests
outside every gate. Focused checks cover:

- all-or-nothing SSE-pair composition and clobber/branch refusal;
- prototype-proved tail forwarding plus an intervening-`xmm1` refusal;
- packed conversion and shuffle lane order, memory access width, and unsupported
  memory/AVX shapes;
- 64-bit widening before packed high-lane shifts and unknown-width concat
  preservation;
- distinct integer/SSE scratch identities and the ordinary scalar-return
  control case.

`cargo test --features python-ext packed_ --lib` reports 37 passed, while the
focused concat and naming filters also pass. The committed census reproduces
under `python/tests/test_test_census.py` (six passed). Full Rust and whole-Python
results are reported separately when run; the focused and fixture evidence is
not a current-tip release-gate claim.

## Scope and limits

No behavior is generalized to Win64, AArch64, ARM32, i386, Rust ABIs, AVX
forms, or unknown aggregate layouts. The fixture validates finite, in-range
float/integer conversions; exceptional conversion behavior remains the same
known limitation as scalar `CVTTSS2SI` lowering. The general WP6 equality,
pointer, pointee, aggregate, call, confidence, conflict, and stable-value
constraint work remains open.

No DecBench run, publication, issue, comment, or pull request was performed.
