# Fuzzing Glaurung Triage

This folder contains cargo-fuzz targets for robustness testing of the triage stage.

Targets:
- headers_validate: Fuzzes header validation (ELF/PE/Mach-O heuristics).
- containers_detect: Fuzzes container detection and metadata extraction.
- sniffers_sniff: Fuzzes content/extension sniffers.
- parsers_parse: Fuzzes structured parser probes.
- entropy_analyze: Fuzzes entropy analysis.

Run locally:
1. Install cargo-fuzz: `cargo install cargo-fuzz`.
2. Run a target, e.g.: `cargo fuzz run headers_validate`.
3. For longer runs or CI, add `--sanitizer address` where supported.

Notes:
- This uses the library crate with default features (no Python extension).
- Findings should never panic; any crash is a bug to fix.

