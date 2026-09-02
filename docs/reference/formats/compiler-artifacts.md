# Compiler and language-detection evidence

> **Kind:** reference · **Status:** maintained

Compiler and source-language detection is probabilistic. Linkers, stripping,
LTO, obfuscation, runtime choice, and mixed-language builds can remove or combine
signals. Preserve the evidence and confidence with a result; do not turn a
heuristic into provenance proof.

## Current inputs and APIs

The detector combines six evidence families:

- symbol mangling and well-known symbol names;
- imported runtime libraries;
- runtime-specific diagnostic strings;
- PE Rich-header entries;
- ELF `.comment` contents;
- byte signatures, including bytecode magic, Go build metadata, and packer
  markers.

`detect_language_and_compiler_with_path` combines those inputs and may use the
path as weak context. The path-free `detect_language_and_compiler` variant uses
only binary-derived evidence. `LanguageDetectionResult` returns the selected
language, optional compiler information, confidence, alternatives, and an
evidence summary.

Focused helpers expose individual stages:

- `detect_language_from_symbols`;
- `detect_runtime_libraries`;
- `detect_language_from_strings`;
- `detect_from_rich_header` and `detect_from_elf_comment`;
- `detect_bytecode_format`;
- `detect_packer`;
- `has_go_buildid` and `extract_go_version`; and
- `is_likely_stripped` and `is_shared_library`.

The enums list more languages and compiler families than every input can
currently distinguish. An enum variant is a data-model capability, not proof
that all binaries from that toolchain are detected.

## Evidence interpretation

### Symbols

The live symbol classifier recognizes, among other signals:

- Rust v0 names beginning `_R`, legacy Rust names with a `17h` hash, Rust
  escape forms, and names accepted by `rustc_demangle`;
- Itanium C++ `_Z...` and common MSVC `?`/`@@` forms;
- common Go package/runtime names;
- Swift `$s` and older `_T` forms;
- Objective-C method/runtime forms; and
- a small set of plain-C library names.

These signals can coexist in one executable. Missing symbols after stripping do
not imply C, and an isolated demangleable name does not prove the whole program
was written in that language.

### Runtime libraries and strings

Imports such as `libstdc++`, `libc++`, MSVC/UCRT components, or Rust-named
libraries can support a language hypothesis. Panic, runtime, and exception text
adds weaker evidence. Statically linked runtimes, dead-code elimination, and
user-controlled strings limit both methods.

### ELF comments

`detect_from_elf_comment` currently recognizes Clang, rustc, and GCC version
text. It checks Clang before GCC because one `.comment` section can contain both
toolchain strings. The parser returns the last version-like GCC token it finds.

`.comment` is optional and can be removed. Its presence identifies a contributing
tool, not necessarily the compiler for every object in the final binary.

### PE Rich headers

`detect_from_rich_header` maps selected product-ID ranges to Visual C++ release
families. Rich-header interpretation is heuristic: entries can reflect several
build tools, mappings are incomplete, and the structure may be absent or
modified. Retain the product/build evidence rather than reporting a release name
without qualification.

### Go and bytecode markers

Go build IDs and `Go buildinf:` data can survive when ordinary symbols do not.
The current bytecode helper recognizes Java class magic, a limited family of
Python `.pyc` prefixes, Lua bytecode as an unsupported/unknown language, and a
bounded CLR metadata check. Container classification such as JAR versus APK is
handled elsewhere; a ZIP magic value is not a Java class.

### Packer markers

`detect_packer` recognizes a bounded list of byte and section-name signatures,
including UPX. A marker is a useful triage signal, not sufficient proof by
itself: validate layout and downstream parsing before making a packer claim.

## What not to infer

- Instruction preferences such as `mov` versus `lea` are not stable compiler
  identities across versions, targets, optimization levels, or surrounding
  code.
- A symbol-count threshold is not a format-independent definition of stripped.
- A filename extension is weak context, not source-language proof.
- A compiler version found in metadata does not establish the build host or the
  toolchain used for every linked object.
- Confidence is detector confidence, not a calibrated probability of authorship.

For high-impact attribution, corroborate at least two independent evidence
families and preserve contradictory signals in the report.

## Validation

The focused real-sample gates are:

```bash
cargo test --test compiler_detection_test
cargo test --test compiler_detection_comprehensive
uv run pytest python/tests/test_compiler_detection_improvements.py -q
```

The Rust tests exercise checked-in GCC, Clang, Go, Rust, Java, Python, PE, and
other sample families when their fixtures are present. Some older tests skip a
missing fixture by returning early, so read the test output and fixture inventory
before interpreting a green exit as complete corpus coverage.

When adding a signal, start with a real fixture and a negative or mixed-evidence
control. Then update the detector, focused tests, and this page together.
