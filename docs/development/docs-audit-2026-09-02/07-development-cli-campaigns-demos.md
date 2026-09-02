# Audit: docs/development/, docs/test-inventory/, docs/cli/, docs/campaigns/, docs/sessions/, docs/demos/, docs/README.md

## Executive summary

This slice (50 files) is, with a handful of exceptions, the best-maintained documentation in the
repository. `docs/development/setup.md`, `decompiler-testing.md`, `project-structure.md`, all
three `docs/cli/` files, and `docs/README.md` were checked claim-by-claim against `Cargo.toml`,
`pyproject.toml`, argparse definitions, `sets.toml`, and live `os.environ`/`env::var` greps, and
were found accurate except two concrete errors: **setup.md and project-structure.md both claim
"Python 3.11+", but `pyproject.toml` requires `>=3.12`** (setup.md even cites pyproject.toml as
its own source), and setup.md's env-var table omits `GLAURUNG_REQUIRE_LLM`, `GLAURUNG_TOOL_STRICT`,
`GLAURUNG_PROJECT_ROOT`. `decompiler-testing.md`'s only defect is a dead example (`@exceptions`,
a set that no longer exists in `sets.toml`). `docs/test-inventory/` is a generated snapshot that
is **currently, provably stale**: `index.json` says 984 entries / commit `abbab830`, `coverage.md`
still says 986 entries / commit `2ce51f9d` — exactly the drift `test-inventory-authority-plan-2026-08-31.md`
diagnoses, still true today, and the generator cannot be rerun from a fresh checkout (its required
`*.jsonl` survey fragments are not committed). The 14 dated "2026-08-31" plan documents in
`docs/development/` are unusually rigorous — every path, script, commit hash, and fixture count I
spot-checked (dozens) resolved — but several read as open work that has since landed same-day or
next-day (the perf-nightly workflow, Go fixture lanes), because the docs were drafted before a
concurrent commit and only git-committed afterward. `docs/development/test-estate/` is a 10-phase
plan whose own `EXECUTION.md` shows phases 1, 2, 6, and most of 5 and 9 are **already landed**
(confirmed independently against the tree) even though the phase files themselves still read as
open TODOs — `EXECUTION.md` is the real live status and should be linked more prominently.
`docs/cli/`, `docs/campaigns/`, `docs/sessions/`, `docs/demos/`, and `docs/README.md` are all
accurate; every link in `docs/README.md` (37 checked) resolves, and every campaign/demo sample
path checked exists on disk.

---

## Per-file table

Columns: `path | lines | last commit (date, short sha) | kind | verdict | evidence | recommendation`

### docs/development/ — top level (18 files)

| path | lines | last commit | kind | verdict | evidence | recommendation |
|---|---:|---|---|---|---|---|
| `roadmap.md` | 223 | 0ec35a2e, 2026-08-07 | roadmap/plan | historical | Self-labeled at the top: "Status: historical triage roadmap... do not infer current CLI support from this list." Content is an M0–M5 checklist for the *triage* pipeline (pre-decompiler), largely `[x]`-complete plus abandoned Nice-to-Haves (YARA, ssdeep). Accurately describes itself. | `keep` — it already carries the correct disclaimer; no change needed. |
| `guidelines.md` | 167 | 0ec35a2e, 2026-08-07 | reference | current | Verified `src/error.rs` PyO3 mapping (`Io→PyIOError`, `Timeout→PyTimeoutError`, `InvalidInput`/`InvalidFormat→PyValueError`, rest→`PyException`) matches code exactly; `TriageRunError does not currently exist` is literally asserted by `python/tests/test_verify_tutorial.py:343`; `src/logging.rs`, `python/glaurung/logging.py`, `src/triage/api.rs` all exist as described. | `keep`. |
| `decompiler-parity-backlog.md` | 417 | e8dafd33, 2026-09-01 | record/roadmap | current | A live, actively-edited backlog (glaurung vs angr/Ghidra). Every referenced file (`tools/compare_decompilers.py`, `src/ir/{data_symbols,cmp_fusion,named_constants,types_recover}.rs`, `src/ir/call_args/fold_one_call.rs`) and every cited commit (`dfd2ddb4`, `96948a4b`) exists/resolves. Item #4's long correction trail (two candidate fixes tried and reverted, with an exact def-use table) is corroborated by `test-estate/10-ci-environment-gap.md`. | `keep` — actively maintained ground truth, update as items land. |
| `decompiler-curriculum-corpus.md` | 101 | 8060ee01, 2026-08-31 | reference | mostly-current | Claims "no Go toolchain in `tools/fixture_harness.py`... Nothing builds or runs" the 5 Go fixtures. **Stale by hours**: commit `6660f1f7` ("fixtures: the five Go fixtures now have a toolchain and lanes, opt-in"), 2026-08-31 23:06, landed *after* this doc's 19:43 edit — `fixture_harness.py` now has `go_lanes_enabled()`/`GLAURUNG_FIXTURE_GO`. Everything else (fixture table 15–30, `@curriculum*` sets in `tests/decompiler_fixtures/sets.toml`) verified correct. | `revise`: update the "Go fixtures are written but not wired in" section to describe the opt-in `GLAURUNG_FIXTURE_GO=1` path. |
| `decompiler-test-strategy.md` | 162 | 3827cf79, 2026-08-13 | roadmap/plan | stale | Written at "131 fixtures"; corpus is now **219** sources (196 .c/10 .cpp/7 .rs/5 .go/1 .S). Explicitly lists "Rust and Go fixtures" under "Explicitly out of scope for now" — both now exist (7 `.rs`, 5 `.go` fixtures). Items 1–5 self-report "Built and recorded" inline, items 6–8 (producer-matrix expansion, csmith fuzzing, coverage-guided gaps) remain genuinely unimplemented (no csmith, no llvm-cov wiring found). | `revise`: correct the fixture count and the Rust/Go "out of scope" claim, or `archive` items 1–5 and keep only 6–8 as the live plan. |
| `2026-07-27-uncommitted-work-handoff.md` | 317 | 0ec35a2e, 2026-08-07 | record | historical | Self-labeled "historical closed handoff." All cited files/commits verified to exist (`src/analysis/dispatch.rs`, `docs/analysis/decompiler/2026-07-27-three-way-roundtrip-diary.md`, `docs/design/decompiler-plan-2026-07-27.md`). Accurately describes itself as closed 2026-07-28. | `keep`/`archive` — already reads as closed; fine where it is. |
| `decbench-failure-remediation-plan-2026-08-31.md` | 262 | 5c4df8d2, 2026-09-01 | roadmap/plan | current | Live TDD plan for the 217-row DecBench failure taxonomy. "Progress update" says Increment B (F1a) landed at `0d6b30d1` (verified), F1c/F1d/F2a open. `tools/decbench_failure_taxonomy.py` (Increment A's proposed artifact) does **not** exist yet — confirms it as still-open, not done. | `keep`, update progress section as increments land. |
| `decompiler-roadmap-package-2026-08-31.md` | 342 | 5c4df8d2, 2026-09-01 | index/roadmap | current | The R0–R8/M1–M8 hub document. Every cited commit (`1329382d`, `a938d897`, `610d3afd`, `8fb47f62`, `1b9f19c9`, `55246eff`, `753bf1dd`, `18640412`, `3fb3184c`, `4f4f88e3`, `1694bb06`, `7be914cf`, `ba2fe5c2`) and every cited doc (`decbench-full-failure-taxonomy-2026-08-31.md`, `decompiler-roadmap-diary-2026-08-31.md`) resolves. Cross-checked R8 table (2,829/2,951 passing) against current `.github/workflows/test-suite.yml` — matches the "cargo test" vs "--features python-ext" split described in `CLAUDE.md`. | `keep` — this is the file other auditors/plan-writers should treat as the current index of the whole decompiler workstream. |
| `large-function-plan-2026-08-31.md` | 210 | dbf4f5ca, 2026-09-01 | roadmap/plan | current | Fully unimplemented: no `@large` set in `tests/decompiler_fixtures/sets.toml`, no phase-telemetry fields (`identity_ms`, `discovery_ms`, etc.) anywhere in `src/`/`python/`. Table of compile/GED/byte-match collapse by output-line-count is presented as measured data, not independently re-verifiable without the raw run, but is internally consistent with the R2 summary in `decompiler-roadmap-package`. | `keep` — genuinely open plan, no action needed beyond normal maintenance. |
| `optimized-structural-quality-plan-2026-08-31.md` | 239 | 5c4df8d2, 2026-09-01 | roadmap/plan | current | Progress update cites census growth to 3,580 rows at `1329382d` — matches `decompiler-roadmap-package-2026-08-31.md` and `test-estate/07-matrix-extension.md` exactly (85 switches / 4,604 gotos / 545 breaks, all three docs agree). | `keep`. |
| `pe-pdb-macho-parity-plan-2026-08-31.md` | 308 | dbf4f5ca, 2026-09-01 | roadmap/plan | current | Verified: `tests/fixtures/msvc-pdb/MANIFEST.json`/`README.md` exist, no CI workflow references them (`grep` over `.github/workflows/` for "msvc-pdb"/"MANIFEST.json" returns nothing), `clang-cl`/`lld-link` presence claim is corroborated by `test-estate/04-pe-macho.md`'s independent 2026-09-01 measurement. | `keep`. |
| `performance-determinism-ratchet-plan-2026-08-31.md` | 402 | 5c4df8d2, 2026-09-01 | roadmap/plan | mostly-current | **P9 ("the gate is never run automatically... appears in no workflow") is now false.** `.github/workflows/perf-nightly.yml` exists, was added by commit `4f4f88e3` at 14:28 on 2026-09-01 — *before* this doc's own last commit (`5c4df8d2`, 21:42 same day) — and implements exactly the fail-closed/scheduled/"prove it measured something" contract the plan's Increment G calls for. The doc's prose was drafted earlier in the day and committed late, so it describes an already-superseded gap. Everything else (P1–P8, the typed-measurement-result contract, the reference ladder) remains open and accurately described. | `revise`: mark P9 landed, point to `perf-nightly.yml`, keep P1–P8/Increments A–F open. |
| `real-binary-decompiler-roadmap-2026-08-31.md` | 274 | 5c4df8d2, 2026-09-01 | roadmap/plan | mostly-current | Top-level product roadmap; "Immediate increments" item 8 ("Make `tools/perf_gate.py` fail closed") is also stale for the same reason as above — three of the fail-open states it refers to already exit 3 as of `4f4f88e3`. Everything else (R0–R7 status, milestone table) matches `decompiler-roadmap-package-2026-08-31.md` verbatim in substance. | `revise`: same P9/fail-closed correction; otherwise `keep`. |
| `real-world-malware-asset-plan-2026-08-31.md` | 259 | dbf4f5ca, 2026-09-01 | roadmap/plan | current | `samples/binaries/index.json` stale-count claim verified exactly: JSON lists 552 paths, `find` counts 736 files on disk. `samples/packed/` verified at exactly 10 entries (UPX). `tests/realistic_corpus/` structure matches description. | `keep`. |
| `test-inventory-authority-plan-2026-08-31.md` | 235 | dbf4f5ca, 2026-09-01 | roadmap/plan | current | The drift it diagnoses is reproduced live today (see `docs/test-inventory/` section below): `index.json` now at 984 entries/commit `abbab830`, `coverage.md` still at 986/`2ce51f9d`. `docs/test-inventory/records/*.jsonl` (its proposed I0 deliverable) does not exist — confirms the plan is still fully open. | `keep` — this is the authoritative diagnosis of `docs/test-inventory/`'s generator problem; do not duplicate its content elsewhere. |
| `decompiler-testing.md` | 977 | 960fc31b, 2026-08-30 | reference | current | THE reference for decompiler testing, linked from `CLAUDE.md`. Verified ~30 script/tool paths, all four baseline files, `sets.toml` set names, `GLAURUNG_PASS_HEALTH`/`GLAURUNG_ALLOW_STALE` env vars, and numeric claims (656 x86-64 lanes, 328/328 control-lane pass, the `24b3826`→`d8665dd` Union/GED table) all resolve or are internally consistent. One defect found: the example `tools/dectest.py @exceptions --stripped` names a set (`@exceptions`) that does **not** exist in `tests/decompiler_fixtures/sets.toml` (confirmed by full `grep '^\['` listing of every set). | `revise`: fix/replace the `@exceptions` example (nearest real sets are `@switch`/`@structuring`/`@dispatch-forms`). Otherwise keep as-is — this is the gold-standard file in the audited scope. |
| `project-structure.md` | 105 | 55fb9038, 2026-08-18 | reference | mostly-current | Deliberately abstract ("the exact module list evolves"). All top-level dirs/files, all `src/` subsystems (`triage/formats/disasm/analysis/symbols/ir/exec/symbolic/python_bindings`), `docs/refactoring/README.md`, `samples/README.md`, `tests/decompiler_fixtures/README.md` all verified present. **One factual error**: "declares Python 3.11+" — `pyproject.toml:7` says `requires-python = ">=3.12"`. | `revise`: fix "3.11+" → "3.12+" (same fix needed in `setup.md`). |
| `setup.md` | 321 | c3e92a93, 2026-08-16 | reference | mostly-current | THE install/config reference linked from `docs/README.md`. Verified: `requires-python` is actually `>=3.12`, **not** "3.11 or newer" as stated twice (prerequisites list and "validated on... CPython 3.11"); this is a direct contradiction of the file's own cited source. Cargo features `python-ext`/`symbolic`/`exec` all exist and match `Cargo.toml`; the "include python-ext when passing --features" caveat is real Maturin behavior. All 5 referenced docs (`design/execution-engine/05-decisions/`, `axeyum-integration/README.md`, `agentic-glaurung/operations/01-model-configuration-and-budgets.md`, `windows-port/windows-analysis-config.md`, `triage/packer-config.md`) and both sample paths exist. Rust "1.88" claim is unverifiable directly (`Cargo.toml` has no `rust-version` field, no `rust-toolchain` file in the repo) but is at least consistent with `README.md`/tutorial docs. Env-var tables: all 8 "Analysis limits and caches" vars and all 6 LLM vars verified present in code by grep; **3 real Python-side env vars are undocumented**: `GLAURUNG_REQUIRE_LLM`, `GLAURUNG_TOOL_STRICT`, `GLAURUNG_PROJECT_ROOT` (none are solver/symbolic/decompiler-debug vars, so the doc's own carve-out doesn't excuse them). | `revise`: fix the Python version (3.12+, not 3.11+) and add the three missing env vars. This is CLAUDE.md-adjacent and gets read often — worth prioritizing. |

### docs/development/test-estate/ (12 files)

`EXECUTION.md` is the authoritative live status tracker for this whole directory (and for `decompiler-parity-backlog.md`); its "Landed" table lets every phase file below be checked against ground truth cheaply. Cross-referenced against `decompiler-roadmap-package-2026-08-31.md` and `real-binary-decompiler-roadmap-2026-08-31.md`: **not superseded**, explicitly complementary — `real-binary-decompiler-roadmap` says it "retain[s] this plan's reachability and fixture discipline" and `test-estate/README.md` links back to the R0–R8 docs as the product-facing ordering layered on top of this estate-hygiene layer.

| path | lines | last commit | kind | verdict | evidence | recommendation |
|---|---:|---|---|---|---|---|
| `README.md` | 120 | 3bca286a, 2026-09-01 | index/roadmap | mostly-current | Phase table and "definition of done" cross-checked: item 3 (CI runs `cargo test --features python-ext` + Python suite) is **done** (`.github/workflows/test-suite.yml` confirmed); item 4 (fuzz targets for disasm/CFG/lift/structuring, nightly CI) is **partial** — `fuzz-nightly.yml` exists and runs `disasm_decode`, but no `cfg_discover`/`ir_lift`/`structure_cfg` targets exist in `fuzz/fuzz_targets/`. | `revise`: annotate which phases are done (1, 2, 6, most of 5, 9) vs open (3's deep targets, 4, 7.2-7.4, 8) rather than reading as a flat unstarted list. |
| `EXECUTION.md` | 380 | 5c4df8d2, 2026-09-01 | record (live log) | current | The single most trustworthy status artifact in this whole audit scope. Spot-checked 6 of its ~45 commit citations (`dfd2ddb4`, `937425d0`, `6d865bc7`, `f6ade219`, `78ad620e`, `6660f1f7`) — all resolve. Its claims directly falsify or confirm the "open plan" reading of phases 1/2/5/6/9 below. | `keep` — link it more prominently from `test-estate/README.md`'s top, not just "Related." |
| `01-reachability.md` | 115 | 54576e35, 2026-08-31 | roadmap/plan | stale (superseded by landed work) | Reads as an open plan, but **every item has landed**: `python/tests/test_estate_reachability.py` exists; `pytest.ini`'s `addopts` already has `-ra`; all 14 `tests/triage/*.rs` files (not 4) are declared in `mod.rs` (verified full listing). `EXECUTION.md` confirms via commits `6d865bc7`, `95249c54`. | `archive`/`revise`: mark done, since a reader today would think Phase 1 is still to-do. |
| `02-canary-determinism.md` | 83 | 54576e35, 2026-08-31 | roadmap/plan | stale (superseded by landed work) | `tests/decompiler_fixtures/canary/` exists with 8 committed `.so` objects + `MANIFEST.json`; `python/tests/test_decompiler_canary.py` and `test_decompiler_determinism.py` both exist. `EXECUTION.md` confirms landed at `b4d23221`. | `archive`/`revise`: mark done. |
| `03-fuzzing.md` | 103 | 54576e35, 2026-08-31 | roadmap/plan | current | Core problem statement (nothing fuzzes disasm/lift/CFG/structurer) is **still true**: `fuzz/fuzz_targets/` has 8 files (`containers_detect`, `demangle_all`, `disasm_decode`, `entropy_analyze`, `formats_parse`, `headers_validate`, `parsers_parse`, `sniffers_sniff`) — `disasm_decode` and `demangle_all`/`formats_parse` landed since this was written, but `cfg_discover`, `ir_lift`, `structure_cfg` (the "deepest" targets, the actual point of the phase) do not exist. `tools/gen_adversarial.py` and `scripts/fuzz-smoke.sh` also do not exist. Gate lane 12 and nightly CI (3.1, 3.4) did land, confirmed against `scripts/feature-build-gate.sh` and `fuzz-nightly.yml`. | `revise`: mark 3.1/3.4 done, keep 3.2/3.3/3.5 open. |
| `04-pe-macho.md` | 133 | 8fb47f62, 2026-09-01 | roadmap/plan | current | Actively updated same-day as `pe-pdb-macho-parity-plan-2026-08-31.md`, explicitly says that plan "supersed[es] the rough counts in this phase" — self-aware partial supersession. Retains unique, non-duplicated measured findings (the `lld-link`/`libcmt.lib` three caveats, the `win10-dismcore.dll` TLS-directory finding) not present in the newer plan. | `merge-into pe-pdb-macho-parity-plan-2026-08-31.md`: fold the unique clang-cl/lld-link measurements in, then archive this file. |
| `05-thin-modules.md` | 91 | 54576e35, 2026-08-31 | roadmap/plan | mostly-current | Landed per `EXECUTION.md` (`36d0e0f3`, `4c0f2ffe`): `tests/fixtures/demangle/corpus.jsonl` exists with **2,115** pairs (verified by `wc -l`), similarity/flirt/target work landed. But the doc's own acceptance bar — "demangle ≥5,000" pairs — was **not** met (2,115 < 5,000); the phase shipped at less than its stated target. | `revise`: mark landed, note the demangle corpus fell short of its own 5,000-pair target (open follow-up), or lower the stated bar to match what shipped. |
| `06-perf-ratchet.md` | 81 | 54576e35, 2026-08-31 | roadmap/plan | superseded | `bench/perf_baseline.json` and `tools/perf_gate.py` both exist and are wired into `decbench-local-gate.sh` and now `perf-nightly.yml` — this phase's design is realized and then substantially extended by `performance-determinism-ratchet-plan-2026-08-31.md` (typed states, provenance, RSS, output-health, which this file's simpler design didn't specify). | `merge-into performance-determinism-ratchet-plan-2026-08-31.md` / `archive`. |
| `07-matrix-extension.md` | 143 | 1329382d, 2026-09-01 | roadmap/plan | current | Self-correcting inline ("Measured 2026-09-01, and it is worse than the plan assumed"). 7.1 (Go) landed opt-in (`GLAURUNG_FIXTURE_GO`, confirmed). 7.5 (structural baseline at O2) **landed**: 3,580-entry census, 85 switches/4,604 gotos/545 breaks — exact match to `optimized-structural-quality-plan`'s progress update. 7.2 (`O0strip`), 7.3 (LTO lane), 7.4 (musl lane) confirmed **not** implemented (`grep` for `O0strip`/`:lto`/`musl` in `fixture_harness.py` and `stripped_differential.py` returns nothing). | `revise`: mark 7.1/7.5 done, keep 7.2–7.4 and the "full closure/effects map at O2" open. |
| `08-dwarf-oracle.md` | 89 | 54576e35, 2026-08-31 | roadmap/plan | current | Fully unimplemented and correctly presented as such: `tools/dwarf_oracle.py` and `tests/dwarf_oracle_baseline.json` do not exist. The `dev-oracle` cargo feature it proposes investigating first does exist in `Cargo.toml`. | `keep`. |
| `09-asset-hygiene.md` | 85 | 54576e35, 2026-08-31 | roadmap/plan | stale (superseded by landed work) | 9.1 (63 unparseable metadata files) verified **fixed**: `samples/binaries/**/metadata/*.json` now globs 339 files, 0 fail to parse (the flat `samples/binaries/metadata/` path from the doc no longer exists — the tree was restructured under `platforms/`). `EXECUTION.md` confirms 9.1/9.3/9.4 landed at `937425d0`. | `archive`/`revise`: mark done. |
| `10-ci-environment-gap.md` | 263 | 1329382d, 2026-09-01 | record (live investigation) | current | Every cited commit (`f0c1009c`, `9bbfd50c`, `c5f7df15`, `09f4d511`) and file (`test_decompiler_control_flow_semantics.py`, `test_frame_cli.py`) verified. Contains a unique, detailed, three-times-corrected investigation of a dispatch-loop structuring defect (the `detect_raw_dispatch_loop` guard) with a real measured table showing a candidate fix was built, endorsed by the execution differential, and correctly reverted on def-use-census evidence. | `keep` — this content exists nowhere else and documents a genuine near-miss (a change that looked safe by one gate and was not, caught by another). |

### docs/test-inventory/ (7 files)

| path | lines | last commit | kind | verdict | evidence | recommendation |
|---|---:|---|---|---|---|---|
| `README.md` | 77 | 1f819d63, 2026-09-01 | reference/index | mostly-current | Documents `tools/build_test_inventory.py --fragments <dir> --out docs/test-inventory` as "Regenerate." Verified `--fragments` is `required=True` and globs `*.jsonl` from that dir — but **no `*.jsonl` survey fragments exist anywhere in the repo** (`find . -iname '*.jsonl'` returns only unrelated files: demangle corpus, decbench scoreboard fixture, an axeyum benchmark result). The documented command **cannot be run on a fresh checkout**. Also lists `coverage.md` as one of the generator's "Files," but the generator (confirmed by reading it) writes only `index.json`/`index.yaml`/`unreachable.json` — `coverage.md` is not regenerated by this command at all. | `revise`: add a caveat that the fragments are not currently committed (points to `test-inventory-authority-plan-2026-08-31.md`'s I0), and correct the "Files" table to not imply `coverage.md` is produced by the same command. |
| `coverage.md` | 84 | 25a48176, 2026-08-31 | generated | stale | **Provably stale right now**: header says "Generated at `2ce51f9d`... 986 entries, 6,282 test functions," "unreachable: 89." Current `index.json` (commit `abbab830`, `1f819d63`) reports 984 entries, 74 unreachable. This is not a hypothetical drift — it is the live state of the two files today, exactly the failure mode `test-inventory-authority-plan-2026-08-31.md` diagnoses. | `revise`: regenerate once the generator can produce it (blocked on the same plan doc's I0/I2), or add a stale-data banner until it can. |
| `findings.md` | 211 | dc4c9759, 2026-09-01 | record | current | Self-correcting: header explicitly says "kept as written... three claims turned out to be wrong when checked," with inline `[FIXED]`/`[CORRECTED]` annotations pointing to `test-estate/EXECUTION.md` for live status. Verified several corrections against code: `scripts/fetch-reference.sh`, `scripts/format-python.sh`, `tools/gen_defuse_baseline.py`, `scripts/build_adversarial_samples.py` all exist as named. | `keep` — a good model for how a "living record" doc should be written; nothing else in the audited scope self-corrects this cleanly. |
| `index.json` | 23,761 | 1f819d63, 2026-09-01 | generated | mostly-current | The primary machine-readable inventory, actively regenerated (commit `abbab830` stamped inside, `by_reach.unreachable: 74` matches `unreachable.json`'s 74 entries and `unreachable-triage.md`'s "74" exactly). Internally consistent with its siblings `index.yaml` and `unreachable.json`, but out of sync with `coverage.md` (see above) — the two "views" of the same survey disagree. | `keep`, but see `coverage.md`'s row — regenerating `coverage.md` from this file would resolve the split. |
| `index.yaml` | 20,504 | 1f819d63, 2026-09-01 | generated | mostly-current | Same commit/counts as `index.json` (its stated twin). Not independently spot-checked beyond confirming same last-commit and file existence. | `keep`. |
| `unreachable.json` | 1,737 | 1f819d63, 2026-09-01 | generated | current | 74 entries, matching `index.json`'s `by_reach.unreachable` and `unreachable-triage.md`'s count exactly. | `keep`. |
| `unreachable-triage.md` | 61 | 1f819d63, 2026-09-01 | record/reference | current | Classifies the 74 unreachable entries into 5 buckets (42 feature-gated/acceptable, 13 real gaps, 10 criterion benches, 5 fuzz targets, 4 opt-in eval). All 6 named "genuinely nothing runs it" scripts verified present (`scripts/fetch-reference.sh`, `format-python.sh`, `lint-python.sh`, `typecheck-python.sh`, `build-macho-samples.sh`, `build_adversarial_samples.py`, `tools/gen_defuse_baseline.py`, `tools/gen_fixture_gallery.py`). | `keep` — this is the actionable complement to the raw `unreachable.json`; read-this-first framing is correct. |

### docs/cli/ (3 files)

| path | lines | last commit | kind | verdict | evidence | recommendation |
|---|---:|---|---|---|---|---|
| `ASK_COMMAND.md` | 240 | 0ec35a2e, 2026-08-07 | reference | current | Every flag in the doc's tables (`--max-iterations`=5, `--min-confidence`=0.7, `--timeout`=120, `--max-functions`=5, `--max-instructions`=50000, `--disasm-window`=4096, `--max-read-bytes`=10485760, `--max-file-size`=104857600) matches `python/glaurung/cli/commands/ask.py`'s argparse defaults exactly. All ~26 named flags exist in that file; `--format`/`--json`/`--no-color`/`--quiet`/`--verbose` are shared base flags, confirmed in `commands/base.py`. Referenced tests all exist. | `keep`. |
| `analyst-ergonomics.md` | 122 | d2d0aa99, 2026-08-28 | reference | current | Commands `kickoff`, `disasm`, `locks`, `group`, `diff` (file `binary_diff.py`, registered CLI name `diff`) all verified to exist with the exact flags cited (`--pdb-cache`, `--no-fetch-pdb`, `--no-pdb`, `--pdb-struct`, `--function`, `--member`). `relocation_only` field confirmed in `python/glaurung/llm/kb/binary_diff.py`. | `keep`. |
| `analyst-annotation-loop.md` | 228 | a977e755, 2026-08-29 | reference | current | Commands `rename`/`comment`/`label`/`proto` confirmed registered via `annotate.py` in `cli/main.py`'s command table; `frame`, `undo`, `decompile`, `graph` all exist as separate files. Provenance rank ladder (`manual 100 > dwarf=pdb=gopclntab 80 > stdlib 60 > flirt=cil 50 > ported 40 > propagated 30 > auto=analyzer=borrowed 20`) matches `python/glaurung/llm/kb/provenance.py` exactly, constant-for-constant. All 9 referenced test files exist. | `keep` — exemplary cross-checking discipline (this doc names the exact test file for each claim). |

### docs/campaigns/ (4 files)

| path | lines | last commit | kind | verdict | evidence | recommendation |
|---|---:|---|---|---|---|---|
| `analyst-ergonomics-2026-06-DIFF.md` | 126 | 26d02854, 2026-06-01 | record | historical | Landed-feature record; all named modules (`python/glaurung/pdb_fetch.py`, `llm/coverage.py`, `llm/kb/lock_state.py`, `llm/kb/module_group.py`) and tests exist. `relocation_only`/`RELOCATION_ONLY_SIMILARITY` confirmed in `binary_diff.py`. Referenced `tools/windows/diff_explain.py` lives in the separate `agentic-security-bot` repo (correctly out of this repo's scope). | `keep` — this is the origin record for `docs/cli/analyst-ergonomics.md` and `analyst-annotation-loop.md`, cited from both; deleting it would orphan those citations. |
| `decbench-readacross-2026-08-12.md` | 114 | c4a961cc, 2026-08-12 | record | historical | A read-only review of an external fork (DecBench); explicitly states nothing was written upstream, consistent with the DecBench no-autonomous-action policy in `CLAUDE.md`. `_report_unresolved_vas` and `program::image::normalize_function_entry` both confirmed to exist. | `keep`. |
| `float-recovery-2026-08-12.md` | 181 | 5e24383a, 2026-08-12 | record | historical | Dense engineering log (x86 scalar float lifting). `NumericConvert` AST variant and `synchronise_xmm_views` (found in `src/ir/lift_x86/xmm_views.rs` and 6 other files) both confirmed. Fixtures `172`–`175` confirmed present. | `keep` — this level of implementation detail (why `movss` needed 5 separate layers to agree) exists nowhere else; would be a real loss if deleted. |
| `windows-poc-2026-05-25-cross-name-matching.md` | 112 | 3cf45986, 2026-08-31 | record | historical | `cross_name_threshold`, `CROSS_NAME_THRESHOLD_DEFAULT = 0.85`, and the `--cross-name-threshold` CLI flag all confirmed in `python/glaurung/llm/kb/binary_diff.py`; `test_binary_diff_cross_name.py` exists. | `keep`. |

### docs/sessions/ (1 file)

| path | lines | last commit | kind | verdict | evidence | recommendation |
|---|---:|---|---|---|---|---|
| `2026-04-26-tutorial-and-bug-L-verification.md` | 136 | c41d0276, 2026-04-26 | record | historical | Old (2026-04-26) but internally consistent session log. `scripts/recover_source.py` and `scripts/verify_tutorial.py` both still exist and are still referenced in `docs/test-inventory/index.json`; the `out/hello-fortran-recovered/` tree it describes is (correctly) gitignored build output, not present on disk today, which is expected rather than a defect. | `keep` — single example of `docs/sessions/`'s intended purpose (dated record, not current guidance); nothing to fix. |

### docs/demos/ (4 files)

| path | lines | last commit | kind | verdict | evidence | recommendation |
|---|---:|---|---|---|---|---|
| `README.md` | 30 | 0ec35a2e, 2026-08-07 | index | current | The three named verifier chapters (`03-c2-demo`, `03-vulnparse`, `04-diff`) are all registered in `scripts/verify_tutorial.py`'s chapter table, and their fixture directories exist under `docs/tutorial/_fixtures/`. | `keep`. |
| `demo-1-malware-triage.md` | 74 | 0ec35a2e, 2026-08-07 | user-guide | current | Sample binary `samples/binaries/platforms/linux/amd64/export/native/clang/O0/c2_demo-clang-O0`, source `samples/source/c/c2_demo.c`, and the linked walkthrough `docs/tutorial/03-walkthroughs/07-malware-c2-demo.md` all confirmed to exist. | `keep`. |
| `demo-2-vulnerability-hunting.md` | 81 | 0ec35a2e, 2026-08-07 | user-guide | current | `samples/binaries/platforms/linux/amd64/synthetic/vulnparse-c-gcc-O0` and `samples/source/c/vulnparse.c` confirmed present. | `keep`. |
| `demo-3-patch-analysis.md` | 81 | 0ec35a2e, 2026-08-07 | user-guide | current | Both `switchy-c-gcc-O2` and `switchy-c-gcc-O2-v2` binaries confirmed present under `samples/binaries/platforms/linux/amd64/synthetic/`. | `keep`. |

### docs/README.md (1 file)

| path | lines | last commit | kind | verdict | evidence | recommendation |
|---|---:|---|---|---|---|---|
| `docs/README.md` | 139 | 1181bf46, 2026-08-29 | index | current | Checked all 37 distinct linked paths in "Start here," the "Find a workflow" table, and "Documentation by subsystem" — **every single one resolves** (`tutorial/README.md`, `../README.md`, `development/setup.md`, `triage/README.md`, `cli/analyst-ergonomics.md`, `cli/analyst-annotation-loop.md`, `architecture/PERSISTENT_PROJECT.md`, `architecture/data-model/README.md`, `tutorial/reference/set-by-precedence.md`, `design/decompiler-ux-competitive-ranking.md`, `analysis/README.md`, `analysis/disassembly/README.md`, `analysis/decompiler/README.md`, `development/decompiler-testing.md`, `windows-port/README.md`, `windows-port/windows-analysis-config.md`, `triage/packer-config.md`, `triage/similarity.md`, `cli/ASK_COMMAND.md`, `llm/README.md`, `demos/README.md`, `../examples/README.md`, `../samples/README.md`, `../CLAUDE.md`, `../AGENTS.md`, `development/guidelines.md`, `parsers/README.md`, `formats/README.md`, `syscalls/README.md`, `agentic-glaurung/README.md`, `agentic-glaurung/STATUS.md`, `axeyum-integration/README.md`, plus the 4 `tutorial/01-getting-started/*` links and `tutorial/02-daily-basics`, `tutorial/03-walkthroughs` directories). No stale links, no rows pointing at deleted/renamed material. | `keep` — this is the strongest single file in the entire audited scope; no action needed. |

---

## Directory-level summaries

**`docs/development/` (top level, excluding `test-estate/`).** A working mix of three genres that
are currently interfiled with no visual distinction: (a) durable reference (`setup.md`,
`project-structure.md`, `decompiler-testing.md`, `guidelines.md`) that belongs at the top of any
new-contributor path; (b) a cluster of 11 dated "2026-08-31" planning documents (`decbench-failure-remediation-plan`,
`decompiler-roadmap-package`, `large-function-plan`, `optimized-structural-quality-plan`,
`pe-pdb-macho-parity-plan`, `performance-determinism-ratchet-plan`, `real-binary-decompiler-roadmap`,
`real-world-malware-asset-plan`, `test-inventory-authority-plan`) that form one coherent,
cross-referenced R0–R8 workstream and should visually travel together (they already link to each
other correctly, they just aren't grouped in the filesystem); and (c) closed historical records
(`roadmap.md`, `2026-07-27-uncommitted-work-handoff.md`, `decompiler-test-strategy.md`) that read
as live plans but describe work that is done or superseded. A clean structure would put (a) at
`docs/development/` top level, move (b) into a `docs/development/roadmap/` subdirectory (mirroring
`test-estate/`'s own subdirectory pattern), and move (c) into an explicit `docs/development/archive/`
or delete-after-confirming-nothing-links-to-them.

**`docs/development/test-estate/`.** A 10-phase estate-hygiene plan, ~70% executed. The gap between
what the phase files *say* (open TODO) and what `EXECUTION.md` *proves* (landed) is the single
biggest structural problem in this directory — a reader who opens `01-reachability.md` cold has no
way to know it's done without separately opening `EXECUTION.md` and cross-referencing. A clean
structure would either (a) add a one-line "STATUS: landed, see EXECUTION.md" banner to each
completed phase file, generated/checked mechanically, or (b) fold `EXECUTION.md`'s per-phase
status directly into each phase file's top, the way `decompiler-curriculum-corpus.md` and several
`test-estate/*` phase files already self-correct inline. Phases 4 and 6 substantially overlap with
newer top-level plans (`pe-pdb-macho-parity-plan-2026-08-31.md`, `performance-determinism-ratchet-plan-2026-08-31.md`)
and should be merged into them rather than left as parallel "phase" framing.

**`docs/test-inventory/`.** Purely generated output plus one hand-written classification doc
(`unreachable-triage.md`) and one narrative doc (`findings.md`). The core problem — `coverage.md`
is stale relative to `index.json`/`index.yaml`/`unreachable.json`, and the generator's documented
regenerate command cannot run because its `*.jsonl` inputs aren't committed — is fully diagnosed
already by `docs/development/test-inventory-authority-plan-2026-08-31.md` (out of this directory,
in `docs/development/`). A clean structure keeps this directory 100% generated (delete `findings.md`
and `unreachable-triage.md`'s prose into `docs/development/test-estate/` alongside the plan that
acts on them, or keep them here but clearly mark them as hand-authored companions, not part of the
generated set) — right now the directory silently mixes machine output and human prose with no
visual boundary.

**`docs/cli/`.** Three files, all excellent, all current. No changes needed structurally; this
is the smallest and cleanest directory in scope.

**`docs/campaigns/`.** Four dated, self-contained engineering-effort records. All historical by
design, all verified accurate against current code, all contain implementation detail (the float
lifting five-layer fix, the DecBench read-across findings, the cross-name diff matcher) that exists
**nowhere else** in the documented tree — deleting any of the four would be a real loss of
institutional memory. Correctly kept separate from `docs/sessions/` (session logs) and
`docs/development/test-estate/` (ongoing plans).

**`docs/sessions/`.** One file. Too small a sample to generalize, but it is exactly what the
directory's stated purpose (`docs/README.md`: "dated verification or development-session notes")
promises, and it's accurate. No action needed; if more session logs accumulate, they belong here.

**`docs/demos/`.** Four files, all deterministic and reproducible against `scripts/verify_tutorial.py`.
Clean, small, no issues.

## Cross-cutting findings

**Contradictions between docs and code (real, current):**
1. `docs/development/setup.md` and `docs/development/project-structure.md` both claim Python
   3.11+; `pyproject.toml:7` requires `>=3.12`. `setup.md` explicitly cites `pyproject.toml` as its
   own authority for this claim, making it self-contradicting once checked. (Note: `docs/README.md`
   itself makes no Python-version claim, so it is not affected.)
2. `docs/development/performance-determinism-ratchet-plan-2026-08-31.md`'s P9 and
   `real-binary-decompiler-roadmap-2026-08-31.md`'s "Immediate increments" item 8 both describe the
   performance gate as unscheduled/fail-open; `.github/workflows/perf-nightly.yml` (commit
   `4f4f88e3`, 2026-09-01 14:28) already implements the fail-closed, scheduled, "prove it measured
   something" contract both docs call for. Root cause: doc content was drafted earlier the same day
   as a concurrent commit and only git-committed hours later (see commit `5c4df8d2`'s own message:
   "lands the planning-document edits that had been sitting uncommitted"). This is a real, if
   narrow, lesson for whoever maintains this cluster: a doc's git-commit timestamp is not proof its
   prose reflects the code at that timestamp.
3. `docs/development/decompiler-curriculum-corpus.md` (edited 19:43 on 2026-08-31) says Go
   fixtures are "built by nothing"; commit `6660f1f7` (23:06 the same day) wired them in as opt-in.
   Same root cause as #2.
4. `docs/development/decompiler-testing.md` references a `@exceptions` dectest set that does not
   exist in `tests/decompiler_fixtures/sets.toml`.
5. `docs/test-inventory/coverage.md` (986 entries / commit `2ce51f9d`) disagrees with
   `docs/test-inventory/index.json` (984 entries / commit `abbab830`) **right now** — not a
   hypothetical, a live discrepancy in the committed tree.

**Duplicated coverage (name the files):**
- `docs/development/test-estate/06-perf-ratchet.md` and `docs/development/performance-determinism-ratchet-plan-2026-08-31.md`
  both specify a performance gate; the second supersedes and substantially extends the first
  (typed failure states, provenance, RSS, output-health — none of which 06 specifies).
- `docs/development/test-estate/04-pe-macho.md` and `docs/development/pe-pdb-macho-parity-plan-2026-08-31.md`
  both cover PE/Mach-O fixture work; 04 says so itself ("superseding the rough counts in this
  phase") but retains unique measured findings (the `lld-link` linking caveats, the
  `win10-dismcore.dll` finding) that the newer plan does not restate.
- `docs/development/roadmap.md` and `docs/development/decompiler-test-strategy.md` both describe
  themselves as historical/stale-counted; neither duplicates current guidance, but both could be
  moved to an explicit archive location to stop them surfacing in a "what's current" search.
- `docs/development/guidelines.md` does **not** meaningfully duplicate `CLAUDE.md` — it covers
  error-boundary and logging conventions CLAUDE.md does not touch. `docs/development/roadmap.md`
  likewise does not duplicate CLAUDE.md (it predates the current CLAUDE.md entirely and covers a
  different layer — triage milestones vs. repo-wide policy).

**Knowledge that exists ONLY in these docs and would be lost if deleted:**
- `docs/campaigns/float-recovery-2026-08-12.md` — the five-layer x86 float-lifting fix story
  (lifting, compare semantics, the `NumericConvert` AST node rationale, the SSE parameter/return
  bank generalization, the `synchronise_xmm_views` representation bug) is not documented anywhere
  else; the *why* behind several still-live source-code comments traces back to this file.
- `docs/campaigns/decbench-readacross-2026-08-12.md` — the ARM Thumb-bit reasoning, the
  `--require-llm` confident-heuristic-skip analysis, and the `decompile --vas` fail-closed fix
  rationale (`_report_unresolved_vas`) are recorded only here.
- `docs/development/test-estate/10-ci-environment-gap.md`'s appendix — the `detect_raw_dispatch_loop`
  investigation, including the measured table showing a change endorsed by the execution
  differential and correctly reverted on def-use-census evidence, is a load-bearing example of why
  the project keeps two independent correctness gates. Losing it would lose the concrete
  justification for that architecture choice.
- `docs/development/decompiler-parity-backlog.md`'s backlog item #4 — the multi-day investigation
  narrative (two candidate fixes built, measured, and reverted, with the exact def-use delta table)
  is the only place this reasoning is preserved; the code comments in `fold_one_call.rs` reference
  it but don't reproduce it.
- `docs/development/setup.md`'s env-var reference tables and clean-room Docker recipe — no other
  file in the repository documents `GLAURUNG_LLM_MODEL`/budget vars or the Docker validation
  command end to end.

## Proposed new structure for this scope

```
docs/development/
├── setup.md                          keep — THE install/config reference; fix Python version, add 3 missing env vars
├── project-structure.md              keep — fix Python version
├── decompiler-testing.md             keep — fix the @exceptions example
├── guidelines.md                     keep — accurate, no overlap with CLAUDE.md
├── roadmap/                          new — group the 9 dated 2026-08-31 plans + decbench-failure-remediation-plan
│   ├── README.md                     new — index page: R0-R8 map (currently decompiler-roadmap-package-2026-08-31.md, keep filename or rename)
│   ├── decbench-failure-remediation-plan.md          rewrite of decbench-failure-remediation-plan-2026-08-31.md (drop date from filename, keep content)
│   ├── large-function-plan.md                        rewrite of large-function-plan-2026-08-31.md
│   ├── optimized-structural-quality-plan.md           rewrite of optimized-structural-quality-plan-2026-08-31.md
│   ├── pe-pdb-macho-parity-plan.md                    merge of pe-pdb-macho-parity-plan-2026-08-31.md + test-estate/04-pe-macho.md
│   ├── performance-determinism-ratchet-plan.md        rewrite of performance-determinism-ratchet-plan-2026-08-31.md + test-estate/06-perf-ratchet.md (revise P9 as landed)
│   ├── real-binary-decompiler-roadmap.md              rewrite of real-binary-decompiler-roadmap-2026-08-31.md (revise stale perf-gate item)
│   ├── real-world-malware-asset-plan.md               rewrite of real-world-malware-asset-plan-2026-08-31.md
│   └── test-inventory-authority-plan.md               rewrite of test-inventory-authority-plan-2026-08-31.md
├── decompiler-parity-backlog.md      keep — live backlog, update as items land
├── decompiler-curriculum-corpus.md   keep — revise the Go-wiring section
├── test-estate/                      keep directory, revise phase files with landed/open status
│   ├── README.md                     rewrite — add explicit done/open markers per phase, link EXECUTION.md at top
│   ├── EXECUTION.md                  keep — the real live status, promote its visibility
│   ├── 01-reachability.md            archive — landed, EXECUTION.md confirms
│   ├── 02-canary-determinism.md      archive — landed
│   ├── 03-fuzzing.md                 revise — mark 3.1/3.4 done, keep 3.2/3.3/3.5 open
│   ├── 04-pe-macho.md                merge-into ../roadmap/pe-pdb-macho-parity-plan.md
│   ├── 05-thin-modules.md            revise — mark landed, note demangle corpus short of its own 5,000 target
│   ├── 06-perf-ratchet.md            merge-into ../roadmap/performance-determinism-ratchet-plan.md
│   ├── 07-matrix-extension.md        revise — mark 7.1/7.5 done, keep 7.2-7.4 + O2 closure map open
│   ├── 08-dwarf-oracle.md            keep — fully open
│   ├── 09-asset-hygiene.md           archive — landed
│   └── 10-ci-environment-gap.md      keep — live, unique investigative content
└── archive/                          new — dated/historical docs, explicit "not current guidance"
    ├── roadmap.md                    archive of roadmap.md (already self-labeled historical)
    ├── decompiler-test-strategy.md   archive — fixture counts long stale (131 -> 219)
    └── 2026-07-27-uncommitted-work-handoff.md  archive (already self-labeled historical)

docs/test-inventory/
├── README.md                         revise — note fragments aren't committed; correct coverage.md provenance claim
├── index.json / index.yaml / unreachable.json   keep — generated, mutually consistent
├── coverage.md                       revise — regenerate or stale-mark until generator I0/I2 lands
├── unreachable-triage.md             keep
└── findings.md                       keep — good self-correcting-record model

docs/cli/            no changes — all three files current and accurate
docs/campaigns/       no changes — all four files historical and accurate, unique content
docs/sessions/        no changes — one accurate file
docs/demos/           no changes — all four files current and accurate
docs/README.md        no changes — every link verified, "Find a workflow" table fully current
```

## Ground truth established (for other auditors / the plan writer)

- **Real dectest set names** (from `tests/decompiler_fixtures/sets.toml`, full `grep '^\['`
  listing): `smoke, vector-float, region, switch, loops, early-exit, flags, calls, polarity,
  widths, structs, aggregates, returns, bias, o0, o2, clang-o0, curriculum,
  curriculum-dynamic-programming, curriculum-sorting, curriculum-strings, curriculum-bits,
  curriculum-crypto, curriculum-number-theory, curriculum-numerics, curriculum-physics,
  curriculum-chemistry, curriculum-finance, curriculum-structures, curriculum-data-structures,
  curriculum-graphs, curriculum-sequences, coverage, sentinel, subword-division, bit-scan,
  structuring, dispatch-forms, effect-model`. There is **no `@exceptions` set** — a doc reference to
  it is wrong.
- **Real four behavioral baseline paths**: `tests/decompiler_fixtures/baseline.json`,
  `tests/decompiler_fixtures/arch_baseline.json`, `tests/decompiler_fixtures/structural_baseline.json`,
  `tests/decompiler_fixtures/defuse_baseline.json` — all confirmed at exactly those paths (not
  `tools/`, which CLAUDE.md's parenthetical suggests but doesn't confirm).
- **`tests/decompiler_fixtures/sets.toml`** is the real path for named dectest sets — NOT
  `tools/sets.toml`.
- **Current fixture corpus size**: 219 source files under `tests/decompiler_fixtures/src/` — 196
  `.c`, 10 `.cpp`, 7 `.rs` (fixtures 166–171, 219), 5 `.go` (176–180, opt-in via
  `GLAURUNG_FIXTURE_GO=1`, landed 2026-08-31 commit `6660f1f7`), 1 `.S`.
- **`requires-python = ">=3.12"`** in `pyproject.toml` — two docs in this scope say "3.11+."
- **Cargo feature list** (from `Cargo.toml`): `default = ["triage-core"]`; `triage-core`,
  `triage-heuristics`, `triage-containers`, `triage-parsers-extra`, `python-ext`, `exec`,
  `symbolic`, `dev-oracle`, `solver-z3`, `solver-axeyum`, `solver-bitwuzla`, `solver-axeyum-text`.
  No `rust-version` field exists in `Cargo.toml`, and there is no `rust-toolchain.toml`/`rust-toolchain`
  file in the repo — the "Rust 1.88" claim used consistently across `setup.md`, `README.md`, and
  several tutorial docs is not pinned anywhere machine-readable.
- **`docs/test-inventory/index.json` right now**: 984 entries, 6,282 test functions, 74
  unreachable, commit `abbab830`. **`docs/test-inventory/coverage.md` right now**: 986 entries, 89
  unreachable, commit `2ce51f9d`. These actively disagree.
- **`docs/test-inventory/records/*.jsonl`** (the canonical-input directory
  `test-inventory-authority-plan-2026-08-31.md` calls for) does not exist — the plan's I0 is fully
  open.
- **Undocumented-but-real Python env vars** (missing from `setup.md`'s tables, confirmed by
  `grep -rn` over `python/glaurung/`): `GLAURUNG_REQUIRE_LLM` (`llm/tools/_llm_helpers.py`,
  `cli/commands/explain.py`), `GLAURUNG_TOOL_STRICT` (`llm/tools/base.py:146`),
  `GLAURUNG_PROJECT_ROOT` (`llm/tools/windows_build_corpus.py`). Also real but arguably
  belongs with the Windows-port docs rather than `setup.md`'s general table: `ASB_REPO`
  (`llm/tools/windows_surface_metadata.py:150` and ~30 other `windows_*` tool files — the
  path to a sibling `agentic-security-bot` checkout).
- **`.github/workflows/perf-nightly.yml`** exists (added by commit `4f4f88e3`, 2026-09-01) and
  implements a fail-closed, scheduled performance gate — several 2026-08-31-dated docs describe
  this as not yet done; it is done as of that commit.
- **`samples/binaries/index.json`** lists 552 paths; the directory on disk has 736 files — the
  staleness claim in `real-world-malware-asset-plan-2026-08-31.md` is exactly correct, still true.
