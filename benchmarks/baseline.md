# Glaurung benchmark — 2026-04-25T12:38:18.046310+00:00
_glaurung HEAD: `6f0b8968f1b6`_

## Aggregate
- Binaries scored: **8** (errored: 0)
- Functions discovered: **73** (named: 72)
- Multi-chunk functions: **2** (cold orphans: 0)
- Decompiled OK: **73** (failed: 0)

## Rates
- Symbol-name resolution (avg): **87.5%**
- Decompile success (avg): **100.0%**
- Language detection match: **100.0%**

## Per binary

| binary | funcs | named | chunks>1 | cold orphans | decompiled | ms |
|---|---:|---:|---:|---:|---:|---:|
| `hello-c-gcc-O2` | 7 | 7 | 0 | 0 | 7/7 | 42 |
| `hello-cpp-g++-O2` | 11 | 11 | 1 | 0 | 11/11 | 65 |
| `hello-gcc-O2` | 11 | 11 | 1 | 0 | 11/11 | 64 |
| `hello-gfortran-O2` | 7 | 7 | 0 | 0 | 7/7 | 26 |
| `hello-c-clang-O2` | 7 | 7 | 0 | 0 | 7/7 | 20 |
| `hello-cpp-clang++-O2` | 13 | 13 | 0 | 0 | 13/13 | 126 |
| `hello-clang-debug` | 16 | 16 | 0 | 0 | 16/16 | 196 |
| `hello-clang-stripped` | 1 | 0 | 0 | 0 | 1/1 | 8 |
