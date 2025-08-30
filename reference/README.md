# Reference Implementations

This directory contains git submodules of reference implementations that inform the design of Glaurung:

## Binary Analysis Frameworks
- **angr**: Binary analysis platform with symbolic execution capabilities
- **ghidra**: NSA's software reverse engineering framework
- **radare2**: Unix-like reverse engineering framework and command-line toolset
- **rizin**: Fork of radare2 with refactored codebase
- **REDasm**: Cross platform disassembler with modern C++ UI

## Binary Loaders and Parsers
- **cle**: CLE Loads Everything - binary loader backend for angr
- **LIEF**: Library to Instrument Executable Formats
- **binary-inspector**: Binary analysis library for executable formats

## Symbolic Execution and Constraint Solving
- **claripy**: Abstracted constraint-solving wrapper
- **Triton**: Dynamic binary analysis framework with symbolic execution
- **manticore**: Symbolic execution tool for binary analysis
- **symbolic**: Library for symbolic execution and debugging formats

## Malware Analysis and Detection
- **capa**: FLARE tool to identify capabilities in executable files
- **Detect-It-Easy**: Program for determining file types
- **pharos**: Binary static analysis framework from CMU SEI

## Debugging and Dynamic Analysis
- **pwndbg**: GDB plugin for exploit development
- **HyperDbg**: Hypervisor-based debugger
- **unicorn**: Lightweight CPU emulator framework

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