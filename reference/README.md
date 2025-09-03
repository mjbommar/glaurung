# Reference Implementations

This directory contains git submodules of reference implementations that inform the design of Glaurung:

## Binary Analysis Frameworks
- **angr**: Binary analysis framework with symbolic execution capabilities
- **ghidra**: NSA reverse engineering framework
- **radare2**: Unix-like reverse engineering framework and command-line toolset
- **rizin**: radare2 fork with refactors and improvements
- **REDasm**: Cross-platform disassembler with modern C++ UI

## Binary Loaders and Parsers
- **cle**: CLE Loads Everything — cross-platform binary loader used by angr
- **LIEF**: Parsing, modification, and instrumentation of ELF, PE, and Mach-O
- **binary-inspector**: Extracts symbols from ELF/Mach-O/PE; ScanCode plugin for fast symbol harvesting

## Symbolic Execution and Constraint Solving
- **claripy**: Symbolic expression and solver interface (used by angr; Z3 backend)
- **Triton**: Dynamic binary analysis framework with symbolic execution
- **manticore**: Symbolic execution tool for binary analysis

## Debug Info and Symbolication
- **symbolic**: Debug info and symbolication library (ELF/PE/Mach-O, DWARF/PDB), demangling, symcache
- **object**: A unified object file parser for ELF, Mach-O, PE/COFF, and more.

## Disassembly and Assembly
- **capstone**: Lightweight, multi-architecture disassembly engine
- **keystone**: Lightweight, multi-architecture assembler engine
- **zydis**: Fast and lightweight x86/x64 disassembler library
- **xed**: Intel x86 encoder-decoder library (official Intel reference)
- **bddisasm**: High-performance x86 disassembler with zero memory allocation
- **iced**: Blazing fast x86/x64 disassembler, assembler, and instruction decoder

## Malware Analysis and Detection
- **capa**: FLARE tool to identify capabilities in executable files
- **Detect-It-Easy**: Program for determining file types
- **pharos**: Binary static analysis framework from CMU SEI

## Debugging and Dynamic Analysis
- **pwndbg**: GDB plugin for exploit development
- **HyperDbg**: Hypervisor-based debugger
- **unicorn**: Lightweight CPU emulator engine

## Decompilers
- **retdec**: Machine code to high-level language decompiler
- **reko**: Open source decompiler for machine code binaries
- **b2r2**: Binary analysis framework with advanced IR lifting and decompilation
- **snowman**: Native code to C/C++ decompiler
- **ilspy**: Cross-platform .NET decompiler and assembly browser

## Bytecode and Specialized Tools
- **wabt**: WebAssembly Binary Toolkit (wasm2wat, wasm-decompile)
- **spirv-tools**: Official Khronos SPIR-V tools for GPU shader analysis

## Constraint Solvers
- **z3**: SMT solver used for symbolic reasoning and constraint solving

## GUI Frontends
- **Cutter**: Qt-based GUI for rizin (formerly the radare2 GUI)

## Setup

To initialize these submodules after cloning the repository:

```bash
# Option 1: Use the setup script
./scripts/setup-references.sh

# Option 2: Use git directly
git submodule update --init --recursive
```

## Updating

To update the reference implementations to their latest versions:

```bash
git submodule update --remote --merge
```

## Note

These are external projects included as git submodules for reference and study purposes only. They are not part of the Glaurung codebase and are subject to their own licenses.
