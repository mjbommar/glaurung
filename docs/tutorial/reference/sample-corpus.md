# Sample corpus

Glaurung ships ~150 sample binaries under `samples/binaries/` so a
fresh clone has everything the tutorial track needs without external
downloads. This page lists the **canonical samples** — the ones
referenced from a tutorial chapter or used by the bench harness.

The full inventory is browsable at `samples/binaries/`. This page is
a curated index keyed by **what each binary teaches**.

## The "Hello World ladder" — optimization spectrum

| Binary | Compiler | Flags | Demonstrates |
|---|---|---|---|
| `samples/binaries/platforms/linux/amd64/export/native/clang/debug/hello-clang-debug` | clang | -g -O0 | Tier 1 §B first binary; full DWARF; trivial main + libc puts |
| `samples/binaries/platforms/linux/amd64/export/native/clang/debug/hello-clang-stripped` | clang | -g -O0 -s | DWARF still present; symbol table stripped |
| `samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-c-gcc-O2` | gcc | -O2 | Inlining, dead-code elimination |
| `samples/binaries/platforms/linux/amd64/export/native/clang/O2/hello-c-clang-O2` | clang | -O2 | clang's idioms vs gcc |
| `samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-cpp-g++-O2` | g++ | -O2 | C++ at -O2; mangled names |

## Polymorphic C++ — vtable + RTTI

| Binary | Demonstrates |
|---|---|
| `samples/binaries/platforms/linux/amd64/synthetic/poly-cpp-virtual` | Polymorphic class hierarchy with vtables; full symbols |
| `samples/binaries/platforms/linux/amd64/synthetic/poly-cpp-virtual-stripped` | Stripped sibling — vtable walker (#160) lights up the virtual methods |

## Fortran (gfortran)

| Binary | Demonstrates |
|---|---|
| `samples/binaries/platforms/linux/amd64/export/fortran/hello-gfortran-O2` | libgfortran I/O; #157 DWARF lift signal; the "language detection" edge case (#140 bug fix) |
| `samples/binaries/platforms/linux/amd64/export/fortran/hello-gfortran-debug` | Same, with debug info |

## Rust

| Binary | Demonstrates |
|---|---|
| `samples/binaries/platforms/linux/amd64/export/rust/hello-rust-release` | Rust release build |
| `samples/binaries/platforms/linux/amd64/export/rust/hello-rust-debug` | Rust debug build |
| `samples/binaries/platforms/linux/amd64/export/rust/hello-rust-musl` | musl-linked static Rust |

## Stripped Go (the #212 demo)

| Binary | Demonstrates |
|---|---|
| `samples/binaries/platforms/linux/amd64/export/go/hello-go` | Stripped Go binary; gopclntab walker (#212) recovers 1801 names |
| `samples/binaries/platforms/linux/amd64/export/go/hello-go-static` | Statically linked Go; same recovery |
| `samples/binaries/platforms/linux/amd64/export/go/hello-go-debug` | Go with -gcflags="all=-N -l"; for comparison |

**Tutorial:** Tier 3 §N `02-stripped-go-binary.md`.

## .NET / Mono managed PE (the #210 demo)

| Binary | Demonstrates |
|---|---|
| `samples/binaries/platforms/linux/amd64/export/dotnet/mono/Hello-mono.exe` | Mono .NET PE assembly; CIL metadata walker (#210) recovers `Hello::Main`, `Hello::.ctor` |

**Tutorial:** Tier 3 §O `03-managed-dotnet-pe.md`.

## JVM bytecode (the #209 demo)

| Binary | Demonstrates |
|---|---|
| `samples/binaries/platforms/linux/amd64/export/java/HelloWorld.class` | Single classfile; `glaurung classfile` decodes class + method descriptors |
| `samples/binaries/platforms/linux/amd64/export/java/HelloWorld.jar` | JAR archive; classfile walker iterates every `.class` entry |

**Tutorial:** Tier 3 §P `04-jvm-classfile.md`.

## Lua bytecode (the #211 demo)

| Binary | Demonstrates |
|---|---|
| `samples/binaries/platforms/linux/amd64/export/lua/hello-lua5.3.luac` | Lua 5.3 .luac with embedded source filename in debug info |
| `samples/binaries/platforms/linux/amd64/export/lua/hello-lua5.4.luac` | Lua 5.4 |
| `samples/binaries/platforms/linux/amd64/export/lua/hello-luajit.luac` | LuaJIT — different magic + layout |

**Tutorial:** sibling to Tier 3 §P.

## Cross-platform / cross-arch

| Binary | Demonstrates |
|---|---|
| `samples/binaries/platforms/linux/amd64/export/cross/arm64/hello-arm64-gcc` | AArch64 ELF; AAPCS64 arg recovery (#162) |
| `samples/binaries/platforms/linux/amd64/export/cross/riscv64/hello-riscv64-gcc` | RISC-V (currently triage-only; full lift is #166) |
| `samples/binaries/platforms/linux/amd64/export/cross/windows-x86_64/hello-c-x86_64-mingw.exe` | Win64 PE; Win64 calling convention; ABI-aware arg recovery (#162) |

## Malware analogs (the flagship demo)

| Binary | Demonstrates |
|---|---|
| `samples/binaries/platforms/linux/amd64/export/native/clang/O0/c2_demo-clang-O0` | C2-callback malware analog; hardcoded URLs/IPs, libc-driven syscalls. The flagship Demo 1 (#205). |
| `samples/binaries/platforms/linux/amd64/export/cross/windows-x86_64/c2_demo-c-x86_64-mingw.exe` | Same logic, MinGW-built Windows PE |
| `samples/binaries/platforms/linux/amd64/export/cross/windows-x86_64/suspicious_win-c-x86_64-mingw.exe` | Win-API-heavy: process injection / persistence / network calls |

**Tutorial:** Tier 3 §S `07-malware-c2-demo.md`.

## Vulnerable parser (Demo 2)

| Binary | Demonstrates |
|---|---|
| `samples/binaries/platforms/linux/amd64/export/native/gcc/O0/vulnparse-c-gcc-O0` | A buffer-overflow-prone C parser; vulnerability hunting walkthrough (Demo 2, #207) |

**Tutorial:** Tier 3 §Q `05-vulnerable-parser.md`.

## Patch analysis (Demo 3)

| Binary | Demonstrates |
|---|---|
| `samples/binaries/platforms/linux/amd64/export/native/gcc/O2/switchy-c-gcc-O2` | Switch-table-heavy program (vulnerable build) |
| `samples/binaries/platforms/linux/amd64/export/native/gcc/O2/switchy-c-gcc-O2-v2` | Patched build — `glaurung diff` shows what changed |

**Tutorial:** Tier 4 §T `diffing-two-binaries.md`.

## Packed binaries (the #213 corpus)

UPX-packed corpus, 10 samples covering Fortran (5 opt levels), Go
(static + dynamic), Rust (debug + musl + release):

```
samples/packed/hello-gfortran-O0.upx9
samples/packed/hello-gfortran-O1.upx9
samples/packed/hello-gfortran-O2.upx9
samples/packed/hello-gfortran-O3.upx9
samples/packed/hello-gfortran-debug.upx9
samples/packed/hello-go.upx9
samples/packed/hello-go-static.upx9
samples/packed/hello-rust-debug.upx9
samples/packed/hello-rust-musl.upx9
samples/packed/hello-rust-release.upx9
```

All ten detect as UPX with confidence ≥ 0.9 and entropy in [7.17, 7.89].

**Tutorial:** Tier 3 §R `06-upx-packed-binary.md`.
**Bench harness:** `python -m glaurung.bench --packed-matrix`.

## Adversarial / pathological samples

Hand-crafted byte sequences for triage robustness tests (#214):

```
samples/adversarial/elf_truncated_phdr.bin     # ELF magic + truncated phdr
samples/adversarial/magic_dope_mz_elf.bin      # MZ-then-ELF magic confusion
samples/adversarial/pe_bad_optional_header.bin # MZ + insufficient optional hdr
samples/adversarial/zip_masquerade_exe.exe     # ZIP local hdr with .exe ext
samples/adversarial/gzip_truncated.gz          # GZIP magic, truncated body
samples/adversarial/embedded/{...}             # b64/xor payloads in valid ELFs
```

These don't have a tutorial chapter — they exist to keep our
parsers honest. Run the matrix:

```bash
uv run pytest python/tests/test_adversarial_coverage.py
```

## Bench-harness CI matrix

The 10-binary set the bench harness ships against by default:

```python
DEFAULT_CI_MATRIX = [
    ".../hello-c-gcc-O2",
    ".../hello-cpp-g++-O2",
    ".../hello-gcc-O2",
    ".../hello-gfortran-O2",
    ".../hello-c-clang-O2",
    ".../hello-cpp-clang++-O2",
    ".../hello-clang-debug",
    ".../hello-clang-stripped",
    ".../poly-cpp-virtual",
    ".../poly-cpp-virtual-stripped",
]
```

(See `python/glaurung/bench/__main__.py`.)

## Metadata sidecars

Many samples have a sibling `<name>.json` under
`samples/binaries/platforms/.../export/metadata/` describing how
they were built (compiler, flags, source path). The bench harness
reads these to score `language_match_rate`.

## See also

- [`cli-cheatsheet.md`](cli-cheatsheet.md) — every command
- Tier 3 walkthroughs — each names the binary it uses
- `docs/architecture/IDA_GHIDRA_PARITY.md` — what every shipped
  feature does
