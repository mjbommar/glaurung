# Compiler and source-language detection

Glaurung contains a Rust heuristic for estimating the source language and
compiler family of an artifact. It combines symbol names, imported libraries,
selected strings, PE Rich Header or ELF comment metadata, bytecode magic, and
packer state.

This whole-artifact detector is not exposed as a standalone CLI command and is
not part of the current `glaurung triage` JSON contract. Do not claim that
`triage` identified a source language unless a separate caller actually invoked
this Rust API.

## Do not confuse two language features

The triage and `strings` commands can assign a natural language or script to
individual decoded strings. That answers questions such as “does this string
look English or Cyrillic?” It does not infer whether the binary was written in
C, Rust, Go, Java, or another programming language.

The source-language detector lives in
`src/triage/compiler_detection.rs` and works at artifact scope.

## Current Rust surface

The public module exports:

- `detect_language_and_compiler(...)` for evidence already held in memory;
- `detect_language_and_compiler_with_path(...)` when file-path context is
  available;
- individual symbol, runtime-library, string, Rich Header, ELF comment, and
  bytecode helpers; and
- `LanguageDetectionResult`, containing the primary language, optional compiler
  information, confidence, alternatives, and an evidence summary.

The `SourceLanguage` enum currently includes C, C++, Rust, Go, Swift,
Objective-C, D, Fortran, Pascal, Ada, Zig, Nim, Crystal, C#, Java, Python,
JavaScript, TypeScript, Kotlin, Scala, and `Unknown`. An enum variant does not
mean every language has strong or independently validated detection coverage.

## Evidence and decision behavior

The combined detector currently considers:

- Itanium/MSVC C++ mangling, Rust mangling, Go names, Swift names, Objective-C
  names, and a small set of plain-C symbols;
- C++, Microsoft runtime, Rust, and Go library/runtime signals;
- Rust panic, Go runtime, and C++ exception-shaped strings;
- Microsoft Rich Header and ELF compiler-comment metadata;
- Java class, CPython bytecode, Lua-like header, and managed-PE signatures; and
- an early packed-file result that reports the original language as unknown.

Confidence is a normalized heuristic score, not a probability. Stripping,
packing, static linking, LTO, mixed-language programs, embedded runtimes, and
toolchain-compatible frontends can all reduce or misdirect the evidence.
Alternatives are leads, not independent verdicts.

## Operator workflow

There is no supported CLI flag that prints this result. For current observable
facts, collect format/architecture and symbol evidence separately:

```bash
BIN="samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-gcc-O2"

uv run glaurung triage "$BIN" --json
uv run glaurung symbols "$BIN" --json --limit 100
```

If source-language inference is required by an application, call the Rust API,
preserve the input evidence and revision, and present the result as heuristic.
Do not substitute a filename, file extension, or compiler string for behavioral
proof.

## Validation

The focused Rust tests are the executable contract:

```bash
cargo test compiler_detection
cargo test --test compiler_detection_test
```

The comprehensive corpus test derives expected labels from checked-in sample
paths. Its rate is a repository-snapshot measurement, not a universal accuracy
claim. Historical rates and failure breakdowns remain in the adjacent documents
with explicit status banners.
