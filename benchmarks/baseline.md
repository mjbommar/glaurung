# Glaurung benchmark — 2026-04-25T12:17:37.311786+00:00
_glaurung HEAD: `6b69239705d6`_

## Aggregate
- Binaries scored: **6** (errored: 0)
- Functions discovered: **56** (named: 56)
- Multi-chunk functions: **2** (cold orphans: 0)
- Decompiled OK: **56** (failed: 0)

## Rates
- Symbol-name resolution (avg): **100.0%**
- Decompile success (avg): **100.0%**
- Language detection match: **100.0%**

## Per binary

| binary | funcs | named | chunks>1 | cold orphans | decompiled | ms |
|---|---:|---:|---:|---:|---:|---:|
| `hello-c-gcc-O2` | 7 | 7 | 0 | 0 | 7/7 | 41 |
| `hello-cpp-g++-O2` | 11 | 11 | 1 | 0 | 11/11 | 63 |
| `hello-gcc-O2` | 11 | 11 | 1 | 0 | 11/11 | 65 |
| `hello-gfortran-O2` | 7 | 7 | 0 | 0 | 7/7 | 25 |
| `hello-c-clang-O2` | 7 | 7 | 0 | 0 | 7/7 | 18 |
| `hello-cpp-clang++-O2` | 13 | 13 | 0 | 0 | 13/13 | 124 |
