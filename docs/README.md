# Glaurung Documentation

This directory contains technical documentation, implementation notes, and research for the Glaurung binary analysis framework.

## Directory Structure

### `architecture/`
System design decisions and core data model specifications.
- `data-model/` - Unified data model design, proposals, and implementation tracking

### `triage/`
Complete documentation for the triage analysis pipeline - the core system that processes binaries through multiple analysis stages.
- Implementation plans, advanced features, signature design
- Packer detection, similarity analysis configurations

### `parsers/`
Binary format parser specifications organized by format type.
- Native formats: `elf/`, `pe-coff/`, `macho/`
- Bytecode formats: `java/`, `python/`, `dotnet/`, `wasm/`
- Container formats: `archive/`, `android/`
- Additional parsers for compression, debug info, firmware

### `analysis/`
Analysis subsystem documentation.
- `language-detection/` - Programming language and compiler detection
- `symbols/` - Symbol extraction and analysis
- `disassembly/` - Multi-engine disassembly architecture
- `lifting/` - Binary lifting to intermediate representations (LLVM IR, VEX)
- `decompiler/` - Decompilation pipeline and AI integration
- `interpreted/` - Interpreted & VM bytecode (Python/Java/DEX) analysis plan

### `formats/`
Technical reference documentation for binary formats.
- `compiler-artifacts.md` - Detailed compiler signatures, magic numbers, mangling patterns

### `development/`
Development environment setup and project management.
- `setup.md` - Build system configuration (Maturin, PyO3)
- `guidelines.md` - Error handling, logging, coding standards
- `project-structure.md` - Repository organization
- `roadmap.md` - Development milestones and future plans

### `research/`
Experimental features and proposals.
- `pyext-separation.md` - PyO3 extension separation design

## Quick Reference

**Working on triage?** → `triage/`
**Adding a new parser?** → `parsers/[format]/`
**Improving language detection?** → `analysis/language-detection/`
**Binary lifting to IR?** → `analysis/lifting/`
**Understanding the data model?** → `architecture/data-model/`
**Setting up development?** → `development/setup.md`
**Looking for compiler signatures?** → `formats/compiler-artifacts.md`
**Planning interpreted/VM support?** → `analysis/interpreted/`

## Documentation Standards

- Each major component has its own README
- Implementation tracking uses checkboxes: ✅ Complete, 🔄 In Progress, ❌ Not Started
- Technical specs include concrete examples and code snippets
- Design decisions are documented with rationale

## Finding Information

Use grep or your editor's search to quickly find what you need:

```bash
# Find all mentions of a specific topic
grep -r "symbol extraction" docs/

# Find implementation status
grep -r "✅\|🔄\|❌" docs/

# Find TODO items
grep -r "TODO\|FIXME" docs/
```

## Contributing

When adding documentation:
1. Place it in the appropriate component directory
2. Update the component's README if adding a new file
3. Use clear, descriptive filenames
4. Include implementation status markers where relevant
