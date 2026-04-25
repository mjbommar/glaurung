# Glaurung benchmark — 2026-04-25T15:26:29.008179+00:00
_glaurung HEAD: `a733037f0bd1`_

## Aggregate
- Binaries scored: **10** (errored: 0)
- Functions discovered: **103** (named: 94)
- Multi-chunk functions: **2** (cold orphans: 0)
- Decompiled OK: **103** (failed: 0)
- DWARF types: **139** (structs with fields: 15)
- Stack-frame slots: **754** (across 68 functions)
- Type-KB lift: **0** propagated, **95** auto-struct candidates

## Rates
- Symbol-name resolution (avg): **90.0%**
- Decompile success (avg): **100.0%**
- Language detection match: **80.0%**

## Per binary

| binary | funcs | named | chunks>1 | cold orphans | decompiled | ms |
|---|---:|---:|---:|---:|---:|---:|
| `hello-c-gcc-O2` | 7 | 7 | 0 | 0 | 7/7 | 5875 |
| `hello-cpp-g++-O2` | 11 | 11 | 1 | 0 | 11/11 | 593 |
| `hello-gcc-O2` | 11 | 11 | 1 | 0 | 11/11 | 579 |
| `hello-gfortran-O2` | 7 | 7 | 0 | 0 | 7/7 | 355 |
| `hello-c-clang-O2` | 7 | 7 | 0 | 0 | 7/7 | 348 |
| `hello-cpp-clang++-O2` | 13 | 13 | 0 | 0 | 13/13 | 809 |
| `hello-clang-debug` | 16 | 16 | 0 | 0 | 16/16 | 2839 |
| `hello-clang-stripped` | 8 | 8 | 0 | 0 | 8/8 | 397 |
| `poly-cpp-virtual` | 14 | 14 | 0 | 0 | 14/14 | 640 |
| `poly-cpp-virtual-stripped` | 9 | 0 | 0 | 0 | 9/9 | 289 |
