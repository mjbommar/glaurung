# Triage Roadmap & Checklist

Purpose: guide development of a safe, fast, and extensible binary triage pipeline (detection → validation → scoring → recursion) with Python API/CLI, tests, fuzzing, and performance baselines. This file tracks status with checkboxes and organizes work by milestones and cross-cutting concerns.

Legend: [ ] = TODO, [x] = Done

## Current Baseline
- [x] Add this roadmap file
- [x] Basic parse: ELF
- [x] Basic parse: PE
- [x] Basic parse: Mach-O

Notes
- The baseline above reflects the current docs claim (basic format parsing present). Update checkboxes below as implementation lands.

---

## M0 — Foundations: Budgets, Safety, Determinism
Outcome: strict time/byte/depth budgets, deterministic results, clear truncation semantics.

Core
- [ ] Define `TriageBudgets` config (max-read-bytes, max-file-size, max-depth, per-pass time budgets, global time budget)
- [x] Thread budgets through core passes (sniffers, parsers, recursion, entropy, strings)
- [x] Enforce byte ceilings with short reads; propagate partial status to outputs
- [ ] Determinism audit (no RNG; stable iteration orders; stable JSON key ordering)
- [x] Truncation visibility (bytes/time/depth counters + `hit_byte_limit` flag; include `limit_bytes`, `max_recursion_depth`)
- [x] Time guards in hot loops (coarse checks in strings extraction)
- [x] CLI flags for budgets with sane defaults; document trade-offs (CLI supports `--max-read-bytes`, `--max-file-size`, `--max-depth`; budgets printed)

Errors/Logging
- [x] Expand error taxonomy for budget/timeouts vs corruption vs mismatch (emit BudgetExceeded when byte limit is hit)
- [x] Structured logs for truncation/early-exit (debug logs on strings time-guard)

Validation
- [x] Unit tests for budget enforcement (bytes/time/depth and byte-limit flag)
- [x] Integration test for budget error taxonomy (BudgetExceeded in errors)
- [ ] Integration tests on large/packed samples (graceful truncation)
- [x] Criterion perf baseline for core passes (existing benches for entropy/triage)

Docs
- [ ] Document budgets and determinism guarantees in triage README
- [ ] Add CLI examples showing truncation indicators

---

## M1 — Strings v2 (IOC-Focused, Budgeted)
Outcome: high‑signal string/IOC summaries, fast and bounded.

Extraction
- [x] Scanner: ASCII + UTF-8 (valid), UTF-16LE (simple heuristic), min length configurable
- [x] Language detection: whatlang language detection

Classification
- [x] Network addresses (IPv4, IPv6, URL, domain, email)
- [x] Paths (Windows, Linux, registry keys, UNC paths, etc.)

Validation
- [x] Unit tests for language detection
- [x] Unit tests for classification
- [x] Benchmarks on files in samples/

Notes
- Schema additions are additive and backwards‑compatible: `utf8_count`, `ioc_counts` in `StringsSummary`.
- Defaults are budgeted (`max_scan_bytes`, `time_guard_ms`, `max_lang_detect`, `max_classify`, `max_ioc_per_string`).
- CLI exposes string tuning flags (`--str-*`) and falls back gracefully if native module is older.

---

## M2 — Symbols, Imports/Exports, Flags (PE/ELF/Mach-O)
Outcome: concise cross-format summaries that drive strong heuristics.

Cross-Format Summary Fields
- [x] `imports_count`, `exports_count`, `libs_count`
- [x] `stripped:boolean`, `tls_used:boolean`, `debug_info_present:boolean`
- [x] `suspicious_imports[]` (normalized API names)
- [ ] `entry_section`

PE
- [x] Import table parse (normal + delay-load)
- [x] Export table summary (count; names captured, capped)
- [x] TLS presence bit (directory present)
- [ ] TLS callbacks enumeration
- [ ] Relocations presence; timestamp sanity check
- [x] Debug directory presence
- [ ] RSDS/PDB path extraction (optional)
 - [x] NX/ASLR/CFG flags (DllCharacteristics)

ELF
- [x] dynsym/symtab counts; stripped detection
- [x] DT_NEEDED libraries (distinct set; capped)
- [ ] rpath/runpath extraction
- [x] NX/RELRO/PIE flags (from program headers)

Mach-O
- [x] LC_SYMTAB/DYSYMTAB counts; stripped detection
- [x] Imported dylibs (distinct set; capped)
- [ ] rpaths; minOS target
- [ ] Code signature presence flag (validation deferred to M4)

Scoring/Output
- [x] Suspicious import list (CreateRemoteThread, VirtualAllocEx, NtWriteVirtualMemory, syscalls, ptrace)
- [ ] Flag abnormal combos (writable+executable sections, no RELRO, stripped+network strings)
- [x] JSON fields added; Python getters

Validation
- [ ] Unit tests per format; corpus samples
- [ ] Fuzz import parsers (bounds and count limits)

Docs
- [ ] Format-specific notes and examples

---

## M3 — Recursion Tree + Packers Heuristics
Outcome: nested children-of-children discovery with safe budgets; clearer packer signals.

Recursion
- [ ] Represent children as a tree with offsets/sizes and format hints
- [ ] Depth-first with budgets; cycle/overlap guards
- [ ] Detect overlays and non-zero-offset embeddings (ZIP/GZIP/TAR/XZ/BZIP2/ZSTD; extendable)
- [ ] Output rollups: total_children, max_depth, dangerous_child_present
- [ ] CLI tree view (budgeted)

Packers/Compression
- [ ] Signature-based hints (UPX/ASPack section names; PE characteristics)
- [ ] Entropy + section-shape heuristics (PE .text high entropy + small imports)
- [ ] Clear score contribution with explanation strings

Validation
- [ ] Integration tests with nested samples (ZIP-in-PE, PE-in-ZIP, overlays)
- [ ] Fuzz recursive discovery on adversarial containers

Docs
- [ ] Recursion behavior, limits, and examples

---

## M4 — Code Signing Presence + Schema/Signals Versioning
Outcome: signal clarity and stable, versioned output schemas.

Signing (Presence First)
- [ ] PE Authenticode presence bit (avoid heavy validation here)
- [ ] Mach-O code signature presence; entitlements presence bit
- [ ] Optional: gated full verification behind budget/flag (future)

Schema/Signals
- [ ] Introduce `schema_version` in JSON
- [ ] Publish canonical signal names/weights (versioned)
- [ ] Stabilize JSON shapes; add changelog for clients

Validation
- [ ] Tests for presence detection and schema roundtrips

Docs
- [ ] Document schema versioning and deprecation policy

---

## M5 — Mini Disassembler (Opt-In, Budgeted)
Outcome: tiny entrypoint probe for a few high-value heuristics; off by default.

Design
- [ ] iced-x86 (or arch-appropriate) decode N instructions at entrypoint
- [ ] Compute: jump density, anti-debug idioms, suspicious API thunks, decoder loops
- [ ] Strict budgets: max N instructions and ≤10 ms per sample
- [ ] Feature flag; disabled by default

Integration
- [ ] Add signals (e.g., high_jump_density, anti_debug_idiom_present)
- [ ] CLI `--enable-mini-disasm`; JSON fields gated by flag

Validation
- [ ] Unit tests on curated tiny functions
- [ ] Benchmarks to ensure budget adherence

Docs
- [ ] Document risks, budgets, and outputs

---

## Cross-Cutting: CI, Corpus, Tooling
Outcome: confidence at speed with guardrails.

CI
- [ ] Add coverage gates and smoke fuzzers (short runs)
- [ ] Perf thresholds for critical paths (fail on 2× regressions)
- [ ] Lints and format checks across languages

Corpus
- [ ] Curate adversarial and real-world samples (safe set)
- [ ] Automate sample download/mirroring with hashes (no redistribution)
- [ ] Golden JSON outputs for stability checks

Python API/CLI
- [x] Expose new fields with typed stubs; keep backwards-compatible (pyi updated)
- [x] CLI flags for strings budgets (min len, samples, lang/classify, caps)
- [ ] CLI examples page; Quickstart in docs

Docs Site
- [ ] Unify docs into a navigable structure; add “How triage works”
- [ ] Publish stable signals list and field definitions

---

## Nice-to-Haves (Later)
- [ ] Similarity: ssdeep/SDHash/Imphash summaries
- [ ] YARA integration (budgeted, opt-in)
- [ ] Additional containers: 7z/RAR (read-only metadata)
- [ ] Sandbox hooks (hash-only diff of outputs under confinement)
- [ ] Telemetry-free usage metrics (local only) for perf budgeting

---

## Status Update Protocol
- Update checkboxes as work progresses; keep items short and testable.
- When schema or signals change, bump `schema_version` and update this file.
- For new ideas, add to Nice-to-Haves or spawn a new milestone.
