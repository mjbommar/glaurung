# Glaurung

<p align="center">
  <img src="assets/glaurung-512.png" alt="Glaurung Logo" width="256">
</p>

A modern reverse engineering framework designed to replace Ghidra with first-class AI integration throughout the analysis pipeline.

## Vision

Glaurung aims to be what Ghidra would look like if built today: a modern architecture leveraging Rust's performance and safety, Python's accessibility, and AI agents integrated at every level of binary analysis. Not just AI-assisted, but AI-native - from format detection to decompilation.

## At a Glance: High‑Level Comparison + Roadmap

| Capability | Glaurung (Now) | Roadmap | IDA Pro | Ghidra | Cutter/r2 |
|---|---|---|---|---|---|
| Core intent | AI‑native, automation‑first | — | Interactive RE | Interactive RE | Interactive RE |
| Platforms/arches | Mainstream OS + multi‑arch | Broader parity | Very broad | Broad | Broad |
| Disassembly | Multi‑arch, bounded | Arch depth/parity | Yes | Yes | Yes |
| Decompilation | — | Planned (IR → C‑like) | Yes (Hex‑Rays) | Yes | Yes |
| Analysis depth | Triage, symbols, graphs, names/strings | Types/prototypes | Deep | Deep | Moderate |
| Automation/API | Python/Rust, JSON/JSONL | Stable plugin API | SDK, IDC/Python | Headless/Java | r2pipe/CLI |
| AI integration | Built‑in evidence + naming | Typing/vuln agents | Limited/3rd‑party | Limited/3rd‑party | Limited/3rd‑party |
| Scale/batch | Deterministic budgets | — | Scriptable, heavier | Scriptable | Strong |
| UI | CLI; UI planned | TUI/HTML, Web | Mature GUI | Mature GUI | Mature GUI |
| License/Cost | OSS | — | Commercial | OSS | OSS |

Notes
- “Bounded” means deterministic, time/size‑guarded analysis suited for CI and LLM pipelines.
- Evidence is a first‑class artifact: compact, structured, and multi‑format (plain/rich/JSON/JSONL).

## Current Status

**This is early work in progress.** The foundation is being built with the triage and analysis pipeline operational, but full disassembly, decompilation, and AI integration are still under development.

### What Works Now

- Multi‑format triage (ELF/PE/Mach‑O), entry/arch/endian, safe VA mapping
- Bounded multi‑arch disassembly windows (x86/x64, ARM64/ARM, RISC‑V)
- Fast function discovery with callgraph/CFG (under budgets)
- Practical name resolution (symbols + PLT/GOT/IAT) across OS/arch
- Strings + IOC detection, entropy/overlay, similarity (CTPH)
- LLM‑ready evidence bundles (plain/rich/JSON/JSONL)
- Python API (Rust core via PyO3)

### What's Coming

- Mach‑O stubs/lazy pointers → name parity with ELF/PE
- ARM depth: Thumb mode; AArch64 literal reconstruction (ADRP+MOVZ/MOVK)
- Decompiler: IR lifting → C‑like output; type/prototype hints
- Evidence UX: source tags, richer per‑arch annotations
- UI + Plugins: minimal TUI/HTML, web UI; stable plugin/export APIs

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
- [Radare2](https://github.com/radareorg/radare2) - Demonstrating what's possible in open source RE
- [LIEF](https://github.com/lief-project/LIEF) - Excellence in format parsing
- [Capstone](https://github.com/capstone-engine/capstone) - Multi-architecture disassembly

---

**Note**: This is not a Ghidra plugin or extension. It's a ground-up reimplementation with fundamentally different architecture and goals.
