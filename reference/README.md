# Reference Implementations

This directory contains git submodules of reference implementations that inform the design of Glaurung:

- **angr**: A binary analysis platform with symbolic execution capabilities
- **cle**: CLE Loads Everything - a binary loader backend for angr
- **claripy**: An abstracted constraint-solving wrapper
- **LIEF**: Library to Instrument Executable Formats

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