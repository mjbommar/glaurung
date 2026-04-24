# Phase 2 Kickoff

Current focus areas:

- [ ] Mach-O stubs/lazy pointers → name parity with ELF/PE (`src/analysis/macho_stubs.rs`)
- [ ] ARM Thumb-mode selection + AArch64 ADRP+MOVZ/MOVK literal reconstruction (`src/disasm/capstone.rs`)
- [ ] Minimal LLIR (`src/ir/`): three-address form, x86-64 only, lifted from iced-x86 CFG blocks
- [ ] Reconcile `docs/llm/ROADMAP.md` against shipped code in `python/glaurung/llm/`

Phase 1 (triage, parsing, name resolution, strings/IOCs, similarity) is complete and covered by
356 Rust tests + 665 Python tests.
