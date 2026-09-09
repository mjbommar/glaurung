# WP3 scoped byte-neutrality contract

Status: focused WP3 test contract implemented on `master` after `6427fe45`.

## Result

`python/tests/test_dectest_equivalence.py` now checks rendered output, not only
semantic verdicts. For one required function in the compact real
`08_indirect_dispatch:clang:O0` lane, it decompiles the same fixture binary in
two ways:

1. one native batch containing every exported function; and
2. one native batch containing only the selected function.

The selected function's emitted C must be byte-identical in both maps. Stable
identity metadata is therefore prevented from leaking batch population into
presentation names, types, or statement order during scoped iteration.

This is a fast within-build contract. The 419-pair output sweep remains the
authoritative before/after gate for an identity-only migration; this test does
not replace it.

## Focused evidence

```text
TMPDIR=/home/mjbommar/.cache/glaurung/tmp \
  uv run pytest \
  python/tests/test_dectest_equivalence.py::test_a_scoped_decompile_is_byte_identical_to_the_whole_lane \
  -q
1 passed
```

The periodic exact-release Hello checkpoint also passed all six selected
symbols/PIE GCC cells: x86-64, AArch64, and ARMv7 at O0 and O2. The native
extension was the unchanged exact release build from `27910f65`; intervening
commits through `6427fe45` changed documentation only.

## Measurement boundary

Only the new byte-neutrality test and six Hello cells ran. No broad Rust or
Python suite, fixture matrix, DecBench, Joern, GED, performance, or corpus-wide
measurement ran.
