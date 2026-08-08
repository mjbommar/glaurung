# Binary formats and parsers

Glaurung handles binary formats at several layers. The universal triage path
identifies a broad set of file and container formats. Dedicated parsers then
provide deeper structure for selected formats, while other format-specific
analysis lives in `src/analysis/`, `src/symbols/`, or the Python package.

This distinction matters: detecting a format does not imply full parsing,
disassembly, decompilation, or safe extraction of every structure it can
contain.

## Start with triage

Use `triage` for an unfamiliar file:

```bash
FILE=samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-gcc-O2

uv run glaurung triage "$FILE"
uv run glaurung triage "$FILE" --json
```

The result combines header checks, content sniffing, bounded parser probes,
entropy, strings, packer signals, and optional recursive container discovery.
Inspect nested `containers` in JSON. `--tree` is advertised but is not currently
wired into plain output. Use `--max-read-bytes`, `--max-file-size`, and
`--max-depth` to tighten resource limits.

The triage format enum currently includes:

- ELF;
- PE/COFF;
- Mach-O;
- WebAssembly;
- CPython bytecode;
- Dalvik DEX;
- COFF, raw, and unknown fallbacks.

Container detection recognizes ZIP and its JAR/APK/AAB subtypes, TAR, gzip,
7z, AR, XZ, bzip2, Zstandard, LZ4, CPIO, and RAR signatures. Detection returns
bounded metadata where implemented; it is not a general archive extraction
API.

## Current implementation map

- **ELF:** owned parser for headers, sections, segments, symbols, dynamic
  entries, notes, relocations, Android packed relocations, and security
  features. Start with `triage`, `symbols`, `disasm`, or `kickoff`.
- **PE/COFF:** owned PE parser for headers, sections, imports, exports,
  debug/PDB records, resources, TLS, IAT mapping, security features, and
  anomalies. Start with `triage`, `pe`, `windows`, or `kickoff`.
- **Mach-O:** triage plus object/symbol, stub, fixup, signing, and analysis
  helpers. There is no owned `src/formats/macho` parser module. Start with
  `triage`, `symbols`, `disasm`, or `kickoff`.
- **Android APK, AXML, and DEX:** owned parsers for ZIP-backed APK access,
  binary XML, DEX metadata, strings, classes, methods, and fields. Triage is
  available through the CLI; deeper parsing is currently a Rust API.
- **Android SEPolicy:** owned policy-header parser with version-aware tests and
  real fixtures. This is currently a Rust API.
- **Java class files and JARs:** classfile and bounded JAR-index analysis outside
  `src/formats`. Use `classfile`; `java` provides optional LLM workflows.
- **.NET and CIL:** PE detection plus CLR metadata and method-body analysis
  outside `src/formats`. Use `kickoff` and the Windows workflows.
- **Lua bytecode:** header and version parsing outside `src/formats`. Use
  `luac`.
- **Go:** native binary analysis plus `gopclntab` recovery outside
  `src/formats`. Use `kickoff`.
- **WebAssembly:** header and signature detection in triage. There is no
  dedicated deep parser in the current tree.
- **CPython bytecode:** header and signature detection in triage. There is no
  dedicated marshal or code-object parser in the current tree.
- **Archives and compression:** signature detection and bounded metadata. Java
  JAR indexing is a separate analysis path. Use `triage --tree`.

This table describes the current source layout, not a promise of complete
coverage for every variant of a format. Consult command help and focused tests
for exact fields and limits.

## Format-specific CLI workflows

### Java class files and JARs

Parse one class as JSON:

```bash
CLASS=samples/binaries/platforms/linux/amd64/export/java/HelloWorld.class
uv run glaurung classfile "$CLASS" --json
```

Walk the class entries in a JAR:

```bash
JAR=samples/binaries/platforms/linux/amd64/export/java/HelloWorld.jar
uv run glaurung classfile "$JAR"
```

The archive path currently emits a text summary even if `--json` is supplied;
use the single-class path when machine-readable class details are required.
The `glaurung java` subcommands are LLM-assisted workflows and need provider
credentials; `classfile` is deterministic and offline.

See the [Java parser guide](java/README.md) for classfile fields and the
[agentic Java plan](java/JVM_AGENTIC_ANALYSIS_PLAN.md) for planned work. Do not
interpret unchecked or planned items in that plan as current CLI behavior.

### Lua bytecode

```bash
LUA=samples/binaries/platforms/linux/amd64/export/lua/hello-lua5.4.luac
uv run glaurung luac "$LUA" --json
```

The command reports the recognized Lua family, endianness, and source marker.
It is a bytecode-header workflow, not a Lua decompiler.

### PE resources

```bash
PE=samples/binaries/platforms/windows/amd64/export/windows/x86_64/O2/hello-c-mingw64-O2.exe

uv run glaurung pe resources "$PE" --json
uv run glaurung pe manifest "$PE" --json
uv run glaurung pe version "$PE" --json
```

These actions are bounded views of the PE resource tree. An empty result is
valid for a PE with no matching resource. `resources` returns zero for a valid
PE even when the list is empty. `manifest` and `version` still emit a structured
result but return status 4 when the requested resource is absent; scripts should
inspect both the exit status and the JSON `found` or `stop_reasons` fields.
Broader PE/PDB workflows are covered by the
[Windows documentation](../windows-port/README.md).

## Developer API layout

The dedicated Rust format modules are exported from `src/formats/mod.rs`:

```rust
pub mod apk;
pub mod axml;
pub mod dex;
pub mod elf;
pub mod pe;
pub mod sepolicy;
```

Related functionality deliberately lives elsewhere:

- `src/triage/` owns broad detection, parser probes, recursion, container
  metadata, entropy, signatures, and bounded I/O;
- `src/analysis/` owns Java class/JAR, CIL, Lua, Go, and Mach-O analysis helpers;
- `src/symbols/` owns ELF, PE/PDB, and Mach-O symbol collection;
- `src/debug/` owns DWARF ingestion; and
- `src/python_bindings/` exposes supported native functionality to Python.

Do not invent a common parser trait based on older design sketches. Additions
should follow the current owning module's API and data model.

## Current ledgers and historical format records

- [Java class files and JARs](java/) — living capability ledger and roadmap.
- [ELF](elf/) — historical design record; use this index for current entry
  points.
- [PE/COFF](pe-coff/) — historical design record; use this index and the
  Windows documentation for current entry points.
- [Mach-O](macho/) — historical design record for an unimplemented consolidated
  parser.
- [Android APK and DEX](android/) — historical design record; the current owned
  Rust modules are summarized above.
- [Archives](archive/) — historical extraction design; current triage is bounded
  discovery, not a general extraction API.
- [.NET and CIL](dotnet/) — historical design record.
- [Python bytecode](python/) — historical deep-parser design; current support is
  header/signature detection.
- [WebAssembly](wasm/) — historical deep-parser design; current support is
  header/signature detection.

The historical pages preserve useful format background, but their proposed Rust
types, paths, phase checklists, performance claims, and test lists are not
current API or implementation status.

Format specifications and vendored reference implementations live under
[`reference/specifications/`](../../reference/specifications/) and
[`reference/`](../../reference/). They are reference material, not Glaurung's
public API.

## Safety and validation requirements

Format parsers operate on attacker-controlled bytes. Parser changes must:

- validate offsets, lengths, counts, arithmetic, and string termination;
- apply explicit file, recursion, allocation, and iteration bounds;
- return typed errors instead of panicking on malformed input;
- avoid extracting or executing embedded content implicitly;
- use real valid and malformed fixtures; and
- keep detection, parsing, analysis, and decompilation claims separate.

Useful focused gates include:

```bash
cargo test formats::elf
cargo test formats::pe
cargo test --test android_dex_triage
uv run pytest python/tests/test_triage_integration.py -xvs
uv run pytest python/tests/test_classfile.py -xvs
uv run pytest python/tests/test_luac.py -xvs
```

Run the broader Rust and Python suites required by [`CLAUDE.md`](../../CLAUDE.md)
before merging parser behavior changes.
