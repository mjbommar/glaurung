# Binary Triage Implementation Plan and Checklist

This document turns the triage design into an actionable plan with clear scope, folder layout, milestones, and test coverage targets. It complements docs/triage/README.md (design/flow) and focuses on “what to build next” and “how we prove it works”.


Goals
- Safe, bounded, deterministic triage for unknown inputs.
- Content-first identification with advisory sniffers (infer/mime_guess), mandatory header validation, and structured parser confirmation.
- First-class reporting via TriagedArtifact (hints, verdicts, signals, budgets, errors) with Python access.
- 100% test coverage for all exposed Rust functionality, plus Python API tests.


Status Summary (today)
- Data models: TriagedArtifact and related types implemented and exposed to Python. [COMPLETED]
- Documentation: Design updated to include infer/mime_guess; new implementation plan. [COMPLETED]
- Sniffer/header/entropy/heuristics/parsers implementations: [PENDING]
- CLI/API entrypoints: [PENDING]
- CI and coverage gates: [PENDING]
- Corpus: samples/ not in repo; plan assumes a curated micro-corpus for tests. [PENDING]


Milestones and Checklists

1) Core Crate Structure [IN PROGRESS]
- [x] Add triage data models (TriagedArtifact, …) in Rust and expose to Python
- [ ] Create `src/triage/` runtime modules (detailed below)
- [ ] Add feature flags to keep optional deps gated (heuristics, containers, packers)

2) Sniffers (Stage 0b) [PENDING]
- [ ] Add `infer` content sniff wrapper (bounded prefix read once)
- [ ] Add `mime_guess` extension hint wrapper (path-based)
- [ ] Map results to `TriageHint` and record `SnifferMismatch` when disagreeing with headers
- [ ] Unit tests for edge cases: deceptive extensions, extensionless files

3) Containers/Compression Probe (Stage 1) [PENDING]
- [ ] Fast magic checks for zip/7z/tar/ar/cpio, gzip/xz/bzip2/zstd/lz4
- [ ] Optional bounded metadata extraction (no heavy unpack) + `ContainerChild`
- [ ] Unit tests for each container signature; short-read/garbage cases

4) Headers and Minimal Validation (Stage 2) [PENDING]
- [ ] ELF/PE/Mach-O/Wasm fast header peek with strict bounds and precise errors
- [ ] Nom-based tiny parsers for resilience (just minimal invariants)
- [ ] Unit tests for truncated/corrupt headers and valid fixtures (32/64, LE/BE)

5) Heuristics (Stage 3) [PENDING]
- [ ] Endianness guess (word sampling)
- [ ] Arch guess (byte histogram vs known profiles); optional decode viability (feature-gated)
- [ ] Strings quick scan (ASCII/UTF-16 variants)
- [ ] Unit tests with synthetic buffers + small real samples

6) Entropy/Packers (Stage 4/5) [PENDING]
- [ ] Overall + sliding-window entropy; thresholds configurable
- [ ] UPX and common packer signatures; record `PackerMatch`
- [ ] Unit tests for entropy ranges and packer signatures

7) Structured Parsers (Stage 5) [PENDING]
- [ ] `object` crate as primary parser; `goblin` and `pelite` as optional cross-checks
- [ ] Record `ParserResult` per parser and unify into verdict signals
- [ ] Unit tests for format coverage and error propagation

8) Recursion/Extraction (Stage 6) [PENDING]
- [ ] FAT Mach-O iteration; overlays/trailers scan for nested payloads
- [ ] Bounded recursion with budgets and parent/child DAG via `ContainerChild`
- [ ] Unit tests for nested scenarios and budget exhaustion

9) Scoring and Reporting (Stage 7) [PENDING]
- [ ] Implement confidence aggregation using `ConfidenceSignal` model
- [ ] Penalize sniffer/header mismatches; surface per-signal breakdown
- [ ] Round-trip JSON tests; end-to-end classification tests

10) Safety and Budgets (Stage 8) [PENDING]
- [ ] Global budget struct with per-stage accounting (bytes/time/depth)
- [ ] Fail-fast on limit with `BudgetExceeded`; partial results preserved
- [ ] Unit tests for budget accounting and graceful degradation

11) Public Interfaces [PENDING]
- [ ] Rust: `triage::analyze_path(&Path, &Limits) -> TriagedArtifact`
- [ ] Rust: `triage::analyze_bytes(&[u8], &Limits) -> TriagedArtifact`
- [ ] Python: `glaurung.triage.analyze(path|bytes, deep=False, json=False)`
- [ ] CLI: `glaurung triage <path> [--json] [--deep] […]`
- [ ] Integration tests: analyze a small matrix; assert verdicts and budgets

12) CI and Coverage [PENDING]
- [ ] GitHub Actions job: cargo test + cargo-llvm-cov with coverage threshold 100% for exposed Rust API (triage module)
- [ ] Pytest with coverage; fail below target for Python API
- [ ] Include minimal corpus artifacts required for tests (small, LFS if needed)


Proposed Folder and File Organization

Rust (library/runtime)
- `src/core/triage.rs` — data models [done]
- `src/triage/mod.rs` — module root
  - `io.rs` — bounded readers, prefix caching
  - `sniffers.rs` — infer/mime_guess wrappers
  - `containers.rs` — archive/compression detectors
  - `headers.rs` — magic + minimal header peekers (ELF/PE/Mach-O/Wasm)
  - `heuristics.rs` — endianness/arch/strings
  - `entropy.rs` — overall + sliding entropy
  - `packers.rs` — packer signatures (UPX, etc.)
  - `parsers.rs` — object/goblin/pelite adapters
  - `recurse.rs` — children discovery + budgets
  - `score.rs` — confidence aggregation
  - `api.rs` — analyze_path/analyze_bytes orchestrator

Python (package)
- `python/glaurung/__init__.py` — re-exports; exposes `triage` submodule [done]
- `python/glaurung/triage.py` — Python-facing re-exports [done]
- `python/glaurung/triage.pyi` + `py.typed` — stubs and typing [done]
- `python/glaurung/cli.py` — CLI entry glue (optional now)
- `python/tests/` — pytest suite for triage types and API

Samples (test corpus)
- `samples/` (not present yet):
  - `binaries/platforms/<os>/<arch>/export/{native,containers}` — tiny fixtures
  - Include only minimal, redistributable artifacts required for tests
  - If larger: use LFS and keep tests referencing a tiny subset

CI
- `.github/workflows/triage.yml` — cargo test + coverage; pytest + coverage; build wheel smoke test


Crates and Features
- Required: `infer`, `mime_guess`, `object`, `serde`, `serde_json`, `aho-corasick`, `encoding_rs`
- Optional (feature-gated):
  - `goblin`, `pelite` (parsers)
  - `capstone`, `yaxpeax-*`, `iced-x86` (heuristics)
  - `statrs` (extra stats)
  - `flate2`, `xz2`, `bzip2`, `zstd`, `zip`, `tar` (containers)
- Suggested features:
  - `triage-core` (default): infer, mime_guess, object
  - `triage-heuristics`: disassemblers, statrs
  - `triage-containers`: compression/archives
  - `triage-parsers-extra`: goblin, pelite


Test Plan (100% coverage for exposed Rust triage API)

Rust unit tests
- `sniffers.rs`: content/extension hints; mismatches → TriageErrorKind::SnifferMismatch
- `headers.rs`: happy paths + truncation/garbage; precise error kinds
- `heuristics.rs`: determinism on synthetic buffers; seeds for known profiles
- `entropy.rs`: boundary/windowing; entropy ranges
- `packers.rs`: packer signatures on small hand-crafted buffers
- `parsers.rs`: parser success/failure mapped to ParserResult; multi-format coverage
- `score.rs`: confidence aggregation math; penalties for mismatches
- `api.rs`: budgets enforced; partial results on timeouts

Rust integration tests
- End-to-end `analyze_path` small matrix (ELF/PE/Mach-O/Wasm, at least one container); assert verdict fields and budgets; JSON round-trip equality

Fuzzing and property tests
- `cargo-fuzz` targets: header peekers and container detectors
- Property tests: random truncation/corruption; bounded reads; no panics

Python tests
- Type instantiation and round-trips (already added for models)
- API tests: `glaurung.triage.analyze(path)` on tiny fixtures; JSON option parity with Rust
- CLI tests: `glaurung triage <path> --json` smoke tests (optional now)

Coverage tooling
- Rust: `cargo llvm-cov` with threshold gates (100% for triage public API)
- Python: `pytest -q --cov=glaurung --cov-report=term-missing`


Deliverables by Phase
- MVP (Phase A)
  - Code: `io.rs`, `sniffers.rs`, `headers.rs`, `parsers.rs`, `score.rs`, `api.rs`
  - API: `analyze_path`, `analyze_bytes`
  - Tests: unit + minimal integration + Python wrappers
  - Docs: Update README with CLI/API examples
- Heuristics + Entropy (Phase B)
  - Code: `heuristics.rs`, `entropy.rs`, penalties in `score.rs`
  - Tests: synthetic buffers + corpus checks
- Containers + Recursion (Phase C)
  - Code: `containers.rs`, `recurse.rs`; children DAG
  - Tests: nested container fixtures; budget limits
- Packers (Phase D)
  - Code: `packers.rs` (UPX first)
  - Tests: packer signatures; classification adjustment
- Hardening (Phase E)
  - Fuzz/property tests; CI gates; performance telemetry


Open Questions / Inputs Needed
- Test corpus: `samples/` folder is not present. Provide minimal fixtures, or have me scaffold a tiny corpus (license-safe) under `samples/`?
- CI policy: enforce coverage gates now or after MVP?
- Feature split: which optional features do we enable by default in `Cargo.toml`?


Quick Start (once MVP lands)
- Rust: `let art = analyze_path("/path/to/file", &limits)?; println!("{}", art.to_json()?);`
- Python: `from glaurung import triage; r = triage.analyze("/path/to/file"); print(r.to_json())`
- CLI: `glaurung triage /path/to/file --json`
