# Glaurung benchmark — 2026-04-25T12:56:06.272406+00:00
_glaurung HEAD: `3343395b1ade`_

## Aggregate
- Binaries scored: **8** (errored: 0)
- Functions discovered: **80** (named: 80)
- Multi-chunk functions: **2** (cold orphans: 0)
- Decompiled OK: **80** (failed: 0)

## Rates
- Symbol-name resolution (avg): **100.0%**
- Decompile success (avg): **100.0%**
- Language detection match: **100.0%**

## Per binary

| binary | funcs | named | chunks>1 | cold orphans | decompiled | ms |
|---|---:|---:|---:|---:|---:|---:|
| `hello-c-gcc-O2` | 7 | 7 | 0 | 0 | 7/7 | 133 |
| `hello-cpp-g++-O2` | 11 | 11 | 1 | 0 | 11/11 | 89 |
| `hello-gcc-O2` | 11 | 11 | 1 | 0 | 11/11 | 74 |
| `hello-gfortran-O2` | 7 | 7 | 0 | 0 | 7/7 | 29 |
| `hello-c-clang-O2` | 7 | 7 | 0 | 0 | 7/7 | 21 |
| `hello-cpp-clang++-O2` | 13 | 13 | 0 | 0 | 13/13 | 136 |
| `hello-clang-debug` | 16 | 16 | 0 | 0 | 16/16 | 411 |
| `hello-clang-stripped` | 8 | 8 | 0 | 0 | 8/8 | 51 |
