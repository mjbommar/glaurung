# Project Structure

## Overview

Glaurung is a modern binary analysis framework written in Rust with Python bindings, designed as a spiritual successor to Ghidra with first-class AI integration.

## Directory Layout

```
glaurung/
├── src/                    # Rust source code
│   └── lib.rs             # Main Rust library entry point
├── python/                 # Python source code
│   └── glaurung/
│       ├── __init__.py    # Python package initialization
│       └── cli.py         # Command-line interface
├── docs/                   # Documentation
│   ├── Maturin.md         # Maturin build system docs
│   └── project-structure.md
├── reference/              # Reference implementations for study
│   ├── angr/              # Binary analysis platform
│   ├── cle/               # Binary loader
│   ├── claripy/           # Constraint solver
│   └── LIEF/              # Binary instrumentation
├── .claude/                # Claude AI assistant configuration
│   └── modules/           # Context modules for development
├── todo/                   # Task tracking
├── notes/                  # Development notes
├── target/                 # Rust build artifacts (gitignored)
├── Cargo.toml             # Rust package configuration
├── Cargo.lock             # Rust dependency lock file
├── pyproject.toml         # Python package configuration
├── README.md              # Project readme
├── LICENSE                # MIT license
├── CLAUDE.md              # AI assistant context (auto-generated)
└── cm.py                  # Claude module manager

```

## Key Components

### Rust Core (`src/`)
The core binary analysis engine written in Rust for performance and safety.

### Python Bindings (`python/glaurung/`)
Python interface to the Rust core, providing a high-level API for binary analysis tasks.

### Documentation (`docs/`)
Technical documentation, guides, and references.

### Reference Implementations (`reference/`)
Included for study and design inspiration:
- **angr**: Symbolic execution and binary analysis
- **cle**: Cross-platform binary loading
- **claripy**: Abstract constraint solving
- **LIEF**: Binary format instrumentation

### Development Tools
- **`.claude/`**: AI assistant configuration and context modules
- **`cm.py`**: Tool for managing Claude context modules
- **`todo/`**: Task tracking and project planning

## Build System

The project uses Maturin to build Python extensions from Rust code. Key configuration files:
- `Cargo.toml`: Rust dependencies and package metadata
- `pyproject.toml`: Python package configuration and Maturin settings

## Getting Started

1. Install dependencies:
   ```bash
   pip install maturin
   ```

2. Build the project:
   ```bash
   maturin develop
   ```

3. Run the CLI:
   ```bash
   glaurung --help
   ```