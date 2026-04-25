# Glaurung benchmark — 2026-04-25T14:26:50.057708+00:00
_glaurung HEAD: `7f80928fdc2d`_

## Aggregate
- Binaries scored: **10** (errored: 0)
- Functions discovered: **103** (named: 94)
- Multi-chunk functions: **2** (cold orphans: 0)
- Decompiled OK: **103** (failed: 0)
- DWARF types: **139** (structs with fields: 15)

## Rates
- Symbol-name resolution (avg): **90.0%**
- Decompile success (avg): **100.0%**
- Language detection match: **80.0%**

## Per binary

| binary | funcs | named | chunks>1 | cold orphans | decompiled | ms |
|---|---:|---:|---:|---:|---:|---:|
| `hello-c-gcc-O2` | 7 | 7 | 0 | 0 | 7/7 | 46 |
| `hello-cpp-g++-O2` | 11 | 11 | 1 | 0 | 11/11 | 74 |
| `hello-gcc-O2` | 11 | 11 | 1 | 0 | 11/11 | 75 |
| `hello-gfortran-O2` | 7 | 7 | 0 | 0 | 7/7 | 30 |
| `hello-c-clang-O2` | 7 | 7 | 0 | 0 | 7/7 | 22 |
| `hello-cpp-clang++-O2` | 13 | 13 | 0 | 0 | 13/13 | 136 |
| `hello-clang-debug` | 16 | 16 | 0 | 0 | 16/16 | 435 |
| `hello-clang-stripped` | 8 | 8 | 0 | 0 | 8/8 | 52 |
| `poly-cpp-virtual` | 14 | 14 | 0 | 0 | 14/14 | 39 |
| `poly-cpp-virtual-stripped` | 9 | 0 | 0 | 0 | 9/9 | 19 |
