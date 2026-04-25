# Glaurung benchmark — 2026-04-25T14:52:38.046637+00:00
_glaurung HEAD: `23dff9ef663d`_

## Aggregate
- Binaries scored: **10** (errored: 0)
- Functions discovered: **103** (named: 94)
- Multi-chunk functions: **2** (cold orphans: 0)
- Decompiled OK: **103** (failed: 0)
- DWARF types: **139** (structs with fields: 15)
- Stack-frame slots: **754** (across 68 functions)

## Rates
- Symbol-name resolution (avg): **90.0%**
- Decompile success (avg): **100.0%**
- Language detection match: **80.0%**

## Per binary

| binary | funcs | named | chunks>1 | cold orphans | decompiled | ms |
|---|---:|---:|---:|---:|---:|---:|
| `hello-c-gcc-O2` | 7 | 7 | 0 | 0 | 7/7 | 2993 |
| `hello-cpp-g++-O2` | 11 | 11 | 1 | 0 | 11/11 | 204 |
| `hello-gcc-O2` | 11 | 11 | 1 | 0 | 11/11 | 201 |
| `hello-gfortran-O2` | 7 | 7 | 0 | 0 | 7/7 | 115 |
| `hello-c-clang-O2` | 7 | 7 | 0 | 0 | 7/7 | 102 |
| `hello-cpp-clang++-O2` | 13 | 13 | 0 | 0 | 13/13 | 298 |
| `hello-clang-debug` | 16 | 16 | 0 | 0 | 16/16 | 1029 |
| `hello-clang-stripped` | 8 | 8 | 0 | 0 | 8/8 | 138 |
| `poly-cpp-virtual` | 14 | 14 | 0 | 0 | 14/14 | 192 |
| `poly-cpp-virtual-stripped` | 9 | 0 | 0 | 0 | 9/9 | 23 |
