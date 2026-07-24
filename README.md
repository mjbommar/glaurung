# Glaurung

<p align="center">
  <img src="assets/glaurung-512.png" alt="Glaurung Logo" width="256">
</p>

A modern reverse engineering framework designed to replace Ghidra with first-class AI integration throughout the analysis pipeline.

## Vision

Glaurung aims to be what Ghidra would look like if built today: a modern architecture leveraging Rust's performance and safety, Python's accessibility, and AI agents integrated at every level of binary analysis. Not just AI-assisted, but AI-native - from format detection to decompilation.

## At a Glance: Capability Comparison

A high-level orientation for newcomers, **not a benchmark**. Glaurung is young (pre-1.0); the mature
tools below lead on architecture coverage, decompiler quality, signatures, similarity, and ecosystem.
Several corrections to an earlier version of this table were kindly provided by the radare2 maintainer
in [glaurung#2](https://github.com/mjbommar/glaurung/issues/2) and are reflected below — see **Notes & sources**.

| Capability | Glaurung | IDA Pro | Ghidra | radare2 / rizin |
|---|---|---|---|---|
| Core intent | AI-native, automation-first | Interactive RE | Interactive RE | Scriptable, automation-first framework |
| Disassembly | x86/x64, ARM64/ARM, RISC-V | Very broad | Broad (SLEIGH) | Very broad (dozens of ISAs) |
| Decompilation | IR -> C-like pseudocode (rough, early) | Hex-Rays (best-in-class) | P-Code + C (strong)[^ghidra] | External: r2ghidra / rz-ghidra, r2dec[^r2dec] |
| Type system | Persistent KB + DWARF + stdlib bundles + auto-recovery | TIL | GDT | DWARF/PDB/Java/Dalvik import, pluggable parser[^r2types] |
| Signatures / symbol ID | FLIRT-lite (exact-prologue) + sibling-debug donor | FLIRT + Lumina | FunctionID + BSim[^bsim] | FLIRT + sigdb; radare2 also zignatures; BN sigs via warrp[^r2sig] |
| Persistence | SQLite `.glaurung` project files | IDB | GZF / Server | Versioned project files (radare2 since 2023; rizin SDB)[^r2proj] |
| Testing / regression | Per-commit analysis-quality scorecard (`python -m glaurung.bench`) | Internal suites | Internal suites | Unit / API / ASan / fuzz, continuous[^r2ci] |
| AI integration | Built-in `pydantic-ai` agent (~160 tools) | 3rd-party | 3rd-party (MCP bridges) | r2ai, decai, r2mcp[^r2ai] |
| Scripting / embedding | Python API + REPL | SDK, IDC/IDAPython | Headless, Java/Python | r2pipe (35+ langs), native bindings (20+ langs), r2js, rlang[^r2script] |
| UI | CLI + REPL (UI planned) | Mature GUI | Mature GUI | CLI-first; iaito GUI; web UIs[^r2ui] |
| License | OSS (Apache-2.0) | Commercial | OSS (Apache-2.0) | OSS (LGPL-3.0) |

**Notes & sources.** Glaurung's decompiler lifts x86/x64/ARM only (RISC-V is disassembly-only today), and
its signature layer is exact-prologue matching ("FLIRT-lite"), weaker than a full masked-byte FLIRT.
Sourcing for the mature-tool cells:

[^ghidra]: Ghidra decompiler and P-Code IR — <https://ghidra-sre.org>, [SLEIGH docs](https://ghidra.re/ghidra_docs/languages/html/sleigh.html).
[^r2dec]: radare2/rizin decompile via external plugins: [r2ghidra](https://github.com/radareorg/r2ghidra) / rz-ghidra (which embed Ghidra's decompiler) and [r2dec](https://github.com/wargio/r2dec-js).
[^r2types]: radare2 and rizin import DWARF/PDB/Java/Dalvik debug info and support pluggable demanglers and header parsing (per the radare2 maintainer, [glaurung#2](https://github.com/mjbommar/glaurung/issues/2)).
[^bsim]: Ghidra [BSim](https://github.com/NationalSecurityAgency/ghidra/blob/master/GhidraDocs/GhidraClass/BSim/BSimTutorial_Intro.md) — feature-vector (high P-Code) function similarity with an LSH index; ahead of Glaurung's CTPH.
[^r2sig]: rizin ships a full masked-byte [FLIRT](https://github.com/rizinorg/rizin/tree/dev/librz/sign) implementation + a community sigdb; radare2 additionally has zignatures; and Binary Ninja's open **WARP** signature format imports via the [r2warp](https://github.com/radareorg/warrp) plugin.
[^r2proj]: radare2 has had chunk-versionable binary project files since 2023; rizin uses a versioned SDB project format.
[^r2ci]: radare2 and rizin run unit, API, memory-leak, ASan, and fuzz suites continuously (per [glaurung#2](https://github.com/mjbommar/glaurung/issues/2)); IDA and Ghidra maintain their own regression suites. Glaurung's harness additionally tracks aggregate *analysis-quality* metrics (named %, decompile success, type recovery) per commit.
[^r2ai]: radare2 AI: [r2ai and the decai decompiler plugin](https://github.com/radareorg/r2ai), plus [r2mcp](https://github.com/radareorg/radare2-mcp).
[^r2script]: radare2 scripting/embedding spans r2pipe, native API bindings, the r2js runtime, and rlang — see the [radare2 book](https://book.rada.re). The "35+ / 20+ languages" figures are the maintainer's ([glaurung#2](https://github.com/mjbommar/glaurung/issues/2)), counting community ports; the book enumerates a smaller core set.
[^r2ui]: radare2's GUI is [iaito](https://github.com/radareorg/iaito); it also ships web UIs. [Cutter](https://github.com/rizinorg/cutter) is the GUI of the **rizin** fork (a separate project) — it is not radare2's UI.

## Current Status

Active development. Foundations and analyst‑facing surface area are largely in place; the active frontier is decompiler quality (control‑flow structuring, type‑aware re‑render).

### What Works Now

**Static analysis pipeline**
- Multi‑format triage (ELF/PE/Mach‑O), entry/arch/endian, safe VA mapping
- Bounded multi‑arch disassembly windows (x86/x64, ARM64/ARM, RISC‑V)
- Function discovery with callgraph/CFG, function‑chunk model for non‑contiguous functions (auto‑folds GCC `<fn>.cold` and `.part.N` splits)
- Symbol resolution: defined symbols + PLT/GOT/IAT + DWARF subprograms (chunk‑aware) + FLIRT prologue match for stripped binaries + vtable walker for virtual methods
- Demangler pass: Itanium / Rust v0+legacy / MSVC — every persisted name carries both raw and pretty forms
- Strings + IOC detection, entropy/overlay, similarity (CTPH)

**Persistent knowledge base** (`.glaurung` SQLite project files)
- Session‑scoped: function names, comments (per‑VA), data labels, struct/enum/typedef definitions, xrefs, stack‑frame vars, function prototypes
- `set_by` provenance (manual / dwarf / stdlib / flirt / propagated / auto / borrowed) with manual‑always‑wins precedence
- Additive schema created on open (`CREATE TABLE IF NOT EXISTS`); versioned migration is not yet implemented

**Type system**
- DWARF type ingestion (struct/union/enum/typedef with field bodies and resolved c_type)
- Standard‑library type bundles ship by default: 75+ canonical libc/POSIX/WinAPI types (`size_t`, `FILE *`, `HANDLE`, `struct stat`, `struct sockaddr`, `errno_e`, …)
- 77 canonical libc/POSIX function prototypes (printf/strlen/malloc/socket/pthread_*)
- Auto‑struct recovery from `[reg+offset]` access patterns (no DWARF required)
- Cross‑function type propagation: callsite arg → callee prototype param → originating stack slot

**Cross‑binary**
- Symbol borrowing from a debug‑build sibling: `glaurung repl` `borrow <donor>`
- Exact-prologue ("FLIRT-lite") signature library + matcher (default library committed at `data/sigs/glaurung-base.x86_64.flirt.json`)

**LLM tools**
- ~160 deterministic memory tools registered with the `pydantic-ai` agent (roughly 50 general-purpose, plus Windows- and Java-specific toolkits): `view_hex`, `search_byte_pattern`, `scan_until_byte`, `decompile_function`, `view_function`, `view_strings`, `list_xrefs_*`, `propose_types_for_function`, `verify_semantic_equivalence`, etc.
- Source‑recovery orchestrator (`scripts/recover_source.py`) — multi‑LLM pipeline that lifts a binary into idiomatic C/C++/Rust source with audit report

**Operator tooling — daily-basics floor (the IDA/Ghidra parity floor)**
- `glaurung repl <binary>`: navigation, `n`/`y` rename+retype keystrokes (auto-rerender), `c` comment, `x` xrefs, `l` locals, struct, label, borrow, proto, propagate, recover-structs, ask
- `glaurung xrefs <db> <va>` — cross-references panel (callers/readers/writers with src-function + disasm snippet)
- `glaurung frame <db> <fn-va>` — stack-frame editor with inline rename/retype
- `glaurung view <db> <va>` — synchronised hex / disasm / pseudocode tri-pane
- `glaurung find <db> <query>` — substring/regex search across functions, comments, labels, types, stack vars, strings, disassembly
- `glaurung strings-xrefs <db>` — IDA-style strings window (string + length + use sites)
- `glaurung patch in out --va N --nop|--jmp|--force-branch [--verify]` — mnemonic patch shorthands with re-disasm verification
- `glaurung bookmark <db> add|list|delete` and `glaurung journal <db>` — analyst notes
- `glaurung undo <db>` / `glaurung redo <db>` — reverse any analyst KB write (rename / retype / comment / data label / stack var)
- `glaurung classfile <path>` — JVM .class / .jar triage
- `glaurung luac <path>` — Lua bytecode (.luac, LuaJIT) recognizer
- `glaurung graph <binary> callgraph | cfg <fn>`: DOT export for any visualizer
- `python -m glaurung.bench --ci-matrix` / `--packed-matrix`: per-commit scorecard tracking 12+ metrics across the sample matrix

**Corpus reach**
- ELF / Mach-O / PE native binaries (C / C++ / Fortran / Rust / Go)
- Stripped Go binaries — `g.analysis.gopclntab_names_path` recovers full namespaced names from `.gopclntab`
- .NET / Mono managed PEs — `g.analysis.cil_methods_path` walks ECMA-335 metadata to recover full `Namespace.Type::Method` names
- JVM `.class` and `.jar`/`.war`/`.ear` archives — `glaurung classfile` decodes class metadata + method descriptors
- Lua bytecode (Lua 5.1/5.2/5.3/5.4 + LuaJIT) — `glaurung luac` recognizes engine + recovers source filename

### Active Frontier

The deterministic backbone is in place. Remaining tracked work is now larger projects and follow-up slices:

- **PDB ingestion** (#179): PE/PDB type ingestion has landed for cache hits, including struct/union layouts, function-prototype type records, provenance, and `.glaurung` type DB import. Remaining broad PDB work is public symbol-to-VA name persistence and optional scalar-alias summaries.
- **PE format hardening** (#199): delay imports, manifest, version info, TLS callbacks -- shipped for grounded malware triage claims
- **Web chat UI** (#203/#204): the actual product surface for the agentic workflow; deterministic backbone is fully done
- **More architectures** (#166): MIPS, RISC-V, PowerPC, WASM
- **C → Rust translate end-to-end demo** (#173)
- **BSim-equivalent function similarity** (#186)
- **Plugin architecture** (#168), **headless project management** (#188), **debugger bridge** (#189)

## Quick start: agentic workflow today

```bash
# One‑shot first‑touch analysis: detect packer + triage + analyze + index +
# demangle + per‑function discover/propagate/recover‑structs in ~300ms.
glaurung kickoff samples/binaries/platforms/linux/amd64/export/native/clang/O0/c2_demo-clang-O0

# Function‑level diff between two binaries (BinDiff‑style).
glaurung diff old.elf new.elf

# Packer detection (UPX / Themida / VMProtect / ASPack / MPRESS / ...).
glaurung detect-packer suspicious.bin

# DOT export — pipe into `dot -Tsvg` for callgraph or per‑function CFG visuals.
glaurung graph my.elf callgraph
glaurung graph my.elf cfg main

# Patch hex bytes at a VA, producing a new binary file.
glaurung patch in.elf out.elf --va 0x1140 --bytes "90 90 90"

# Interactive REPL with persistent KB (.glaurung project file).
glaurung repl my.elf
0x1234> goto main
0x1234> locals discover
0x1234> propagate
0x1234> locals rename -0x10 my_request_buf
0x1234> decomp
```

Three end‑to‑end demo conversations are written up in
[`docs/demos/`](./docs/demos/) — malware triage, vulnerability hunting,
and patch analysis — each reproducible from the current HEAD.

## Installation

### Prerequisites

- Rust 1.70+ 
- Python 3.11+
- [uv](https://github.com/astral-sh/uv) (recommended) or pip

### Building from Source

```bash
# Clone the repository
git clone https://github.com/mjbommar/glaurung.git
cd glaurung

# Build the Rust extension with uv
uvx maturin develop --uv

# Run tests
cargo test
uv run pytest python/tests/
```

## Current Usage

### CLI

```bash
# Basic binary triage
glaurung triage samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-gcc-O2

# Extract symbols
glaurung symbols samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-gcc-O2

# JSON output for processing
glaurung triage samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-gcc-O2 --json
```

Example output:
```
# Basic binary
path: samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-gcc-O2
size: 18248 bytes (17.8 KiB)
verdicts: 1
_top_: format=ELF arch=x86_64 64-bit endianness=Little confidence=0.92
symbols: imports=30 exports=2 libs=3 flags: nx,aslr,relro,pie
strings: ascii=192 utf8=0 u16le=0 u16be=0
similarity: ctph=8:4:…

# Suspicious binary with detected imports
path: samples/binaries/platforms/linux/amd64/export/native/gcc/O2/suspicious_linux-gcc-O2
symbols: imports=10 exports=0 libs=1 flags: nx,aslr,relro,pie; suspicious=3
  → ptrace@GLIBC_2.2.5 (debugger detection)
  → mprotect@GLIBC_2.2.5 (memory protection manipulation)
  → execve@GLIBC_2.2.5 (process execution)

# Binary with embedded C2 IOCs (compiled from C source with hardcoded IPs/domains)
path: samples/binaries/platforms/linux/amd64/export/native/gcc/O2/c2_demo-gcc-O2
strings: ascii=256 utf8=0 u16le=0 u16be=0; ioc: ipv4=2, domain=3, email=1, url=1
  → C2 servers: 192.168.100.50, 10.0.2.15
  → C2 domains: malware-c2.evil.com, beacon.command-control.badguys.org
  → Exfil email: stolen-data@evil-corp.com
  → Persistence paths: /etc/cron.d/evil-persistence, /etc/systemd/system/backdoor.service
```

### Python API

```python
from glaurung import triage

# Basic analysis
artifact = triage.analyze_path("samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-gcc-O2")
print(f"Format: {artifact.verdicts[0].format if artifact.verdicts else 'Unknown'}")
print(f"Entropy: {artifact.entropy.overall if artifact.entropy else 0}")
# Output:
# Format: ELF
# Entropy: 3.7123344999208134

# Detect suspicious symbols
suspicious = triage.analyze_path("samples/binaries/platforms/linux/amd64/export/native/gcc/O2/suspicious_linux-gcc-O2")
if suspicious.symbols and suspicious.symbols.suspicious_count > 0:
    print(f"Found {suspicious.symbols.suspicious_count} suspicious imports")
    # Output: Found 3 suspicious imports

# Detect IOCs in compiled binaries (C2 servers, domains, etc.)
c2_binary = triage.analyze_path("samples/binaries/platforms/linux/amd64/export/native/gcc/O2/c2_demo-gcc-O2")
if c2_binary.strings and c2_binary.strings.ioc_counts:
    print(f"IOCs found in binary: {c2_binary.strings.ioc_counts}")
    # Output: IOCs found in binary: {'ipv4': 2, 'domain': 3, 'email': 1, 'url': 1, 'path_posix': 8, ...}
    # This binary contains hardcoded C2 server IPs (192.168.100.50, 10.0.2.15)
    # and malicious domains (malware-c2.evil.com, beacon.command-control.badguys.org)

# Future: Full disassembly and decompilation
# dis = glaurung.disassemble(binary)
# decomp = glaurung.decompile(dis, ai_assist=True)
```

## Architecture

The project is structured to support the full reverse engineering pipeline:

```
glaurung/
├── src/
│   ├── core/           # Data models (Binary, Function, Instruction, etc.)
│   ├── triage/         # Analysis pipeline (working)
│   ├── disasm/         # Disassembly engine (planned)
│   ├── ir/             # Intermediate representation (planned)
│   ├── decompile/      # Decompiler (planned)
│   ├── ai/             # AI agent integration (planned)
│   └── ui/             # User interface (planned)
├── python/             # Python bindings
└── samples/            # Test binaries
```

## Why Not Just Use Ghidra?

Ghidra is powerful but shows its age:
- **Java-based**: Memory hungry, deployment complexity
- **Monolithic**: Hard to embed, extend, or integrate
- **Pre-AI era**: No native LLM integration for analysis
- **Batch unfriendly**: GUI-centric design

Glaurung is built for modern workflows:
- **Rust core**: Fast, safe, embeddable
- **Python-first API**: Native integration with ML/data science stack
- **AI-native**: Agents for naming, typing, pattern recognition
- **Cloud-ready**: Designed for distributed analysis
- **Programmatic**: API-first, UI second

## Development

This is an active research project. Current focus areas:

1. Completing the disassembly engine
2. Building the IR and basic decompiler
3. Integrating first AI agents for function identification
4. Creating a minimal web UI

### Contributing

Early contributors welcome! Key areas needing work:
- Architecture-specific disassembly (ARM, MIPS, RISC-V)
- File format parsers (DEX, WebAssembly, firmware formats)
- AI agent development (function similarity, vulnerability detection)
- Testing and sample generation

### Building Samples

```bash
cd samples
./build-multiplatform.sh linux/amd64
# Generates test binaries in samples/binaries/
```

## Roadmap

- **Phase 1** (Current): Foundation - triage, parsing, basic analysis
- **Phase 2**: Disassembly - multi-architecture instruction decoding
- **Phase 3**: Decompilation - IR, control flow recovery
- **Phase 4**: AI Integration - agents throughout the pipeline
- **Phase 5**: Collaboration - multi-user, cloud deployment

## License

Apache License 2.0 - See [LICENSE](LICENSE) for details.

## Acknowledgments

Standing on the shoulders of:
- [Ghidra](https://github.com/NationalSecurityAgency/ghidra) - The inspiration and target to beat
- [radare2](https://github.com/radareorg/radare2) - Demonstrating what's possible in open-source, automation-first RE
- [rizin](https://github.com/rizinorg/rizin) - RzIL and a thoroughly documented framework, with the [Cutter](https://github.com/rizinorg/cutter) GUI
- [LIEF](https://github.com/lief-project/LIEF) - Excellence in format parsing
- [Capstone](https://github.com/capstone-engine/capstone) - Multi-architecture disassembly

---

**Note**: This is not a Ghidra plugin or extension. It's a ground-up reimplementation with fundamentally different architecture and goals.
