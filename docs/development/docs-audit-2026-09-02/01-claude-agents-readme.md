# Top-level agent/contributor docs audit — CLAUDE.md, AGENTS.md, README.md, .claude/

Scope: `CLAUDE.md` (383 lines), `AGENTS.md` (109), `README.md` (193),
`.claude/agents/rust-data-model-creator.md`, plus `pyproject.toml`, `pytest.ini`,
`Cargo.toml`, `.github/workflows/*.yml` as verification sources.
Repo HEAD at audit time: `b8884687` (2026-09-02), branch `master`, clean.
Method: claim-by-claim verification against code and git. No builds, no pytest, no DecBench.

---

## Executive summary

1. **CLAUDE.md is unusually accurate on its hard facts and stale on its soft ones.** Exact
   matches include `src/lib.rs:80` = `#[cfg(feature = "symbolic")]`, `src/symbolic/` = 26 files /
   21,459 LOC, `feature-build-gate.sh` = exactly 12 lanes, 8 fuzz targets, the sysctl values
   (`perf_event_paranoid = 4`, `ptrace_scope = 1`), every fixture name cited (13, 144, 195, 196),
   every tool/script path, and the whole LLM model policy.
2. **Three claims are outright FALSE.** (a) The KB is at `python/glaurung/llm/kb/`, not
   `python/glaurung/kb/`. (b) `docs/data-model/` does not exist — it is `docs/architecture/data-model/`,
   and `.claude/agents/rust-data-model-creator.md` repeats that dead path six times. (c)
   `GLAURUNG_AGENT_ROUTE=1` exists nowhere in the repository except in CLAUDE.md itself.
3. **Two CI claims are now stale in the direction that matters — they understate the gates.**
   CLAUDE.md says CI runs "cargo test --features python-ext, the full Python suite, and ruff";
   CI actually runs four jobs including a `cargo test --features symbolic` lane, does **not**
   run `ty` at all, and the Python job is `-m "not fixtures and not decbench"`, not the full suite.
   And "the fixture matrix and the six baselines still gate nothing automatically" is false:
   `decompiler-fixtures.yml` runs the fail-closed ratcheting matrix + structural lane on every
   push to master. (`defuse_baseline.json` and `arch_baseline.json` still gate nowhere — that
   half of the sentence survives.)
4. **The perf-gate note is stale in the same direction**: CLAUDE.md says it "still fails open";
   `4f4f88e3` (2026-09-01) made it exit 3 on non-evidence, pinned by `test_perf_gate_fails_closed.py`.
5. **Test counts are 34% low.** "~345 test files" → 461. "~125 Rust test modules" → 276 files
   with `#[cfg(test)]` in `src/` plus 25 in `tests/`.
6. **CLAUDE.md is ~60% dated incident narrative.** 14 of 23 "Working style" bullets are
   war stories. Every one encodes a durable rule in one sentence, and 9 of the 14 now have an
   automated gate; those can shrink to a pointer.
7. **README has one install-blocking bug and one wrong version floor.** The "First analysis"
   sample is a Git LFS object (a fresh clone yields a 130-byte pointer) and README never mentions
   LFS. README says "CPython 3.11 or newer"; `pyproject.toml` says `requires-python = ">=3.12"`.
8. **README is otherwise excellent** — every CLI flag, every Python API symbol, every doc link,
   the logo path, and the "RISC-V is disassembly-only" status all verify against code.
9. **AGENTS.md is ~70% generic boilerplate** ("THIS IS REAL - THIS IS PRODUCTION", emoji
   checklists) with no Glaurung specificity, duplicates CLAUDE.md's DecBench boundary verbatim,
   and its lint scope (`uvx ruff check .`) disagrees with CLAUDE.md's and CI's (`python/`).
   Nothing in the repo reads it as config; only three `scripts/*-python.sh` error strings cite it.
10. **`cm.py` / `.claude/modules/` are fully gone** (retired `641b1458`, 2026-06-03). The only
    remnant is CLAUDE.md's own historical note. `.claude/` contains one file: the agent definition.
11. **Recommendation:** rewrite CLAUDE.md to ~130 lines (rules + commands + pointers), move the
    narratives to a new `docs/development/traps.md`, delete AGENTS.md's boilerplate and make it a
    ~20-line pointer file (keep the filename — it is the cross-tool convention), and patch
    README's LFS + Python-floor bugs.

---

## 1. CLAUDE.md claim ledger

Disposition key: `keep` = keep as rule; `shorten` = keep as rule but compress;
`→docs` = move narrative to `docs/development/`; `drop-obsolete`; `drop-warstory`.

### 1.1 Header and "What Glaurung is" (lines 1–23)

| # | Claim | Verified? | Evidence | Disposition |
|---|---|---|---|---|
| 1 | Compiled from `.claude/modules/` by `cm.py`; that system removed | true | `git log --diff-filter=D -- cm.py` → `641b1458` 2026-06-03 "chore: retire cm.py module system". No `.claude/modules/`, no `cm.py`. Only mention repo-wide is CLAUDE.md itself. | drop-obsolete (3-month-old removal; no reader needs it) |
| 2 | Rust crate `src/` modules: triage, formats, disasm, analysis, ir, symbols, demangle, flirt, strings, similarity, entropy | true | all present under `src/` | keep, shorten |
| 3 | disasm covers x86/x64, ARM/ARM64, RISC-V | true (disasm) | `src/disasm/capstone.rs`, `registry.rs` name RISCV | keep |
| 4 | **Python package has a `kb/` knowledge base** | **FALSE** | `ls python/glaurung/kb` → No such file. It is `python/glaurung/llm/kb/`. | fix path |
| 5 | PyO3 bindings `_native…so`, CLI `cli/commands/`, `llm/` subsystem | true | `python/glaurung/_native.cpython-314-x86_64-linux-gnu.so`, `cli/commands/`, `llm/` all present | keep |
| 6 | `.glaurung` SQLite files persist names/comments/types/xrefs/stack vars/prototypes with `set_by` provenance; manual always wins | unverifiable cheaply (schema not inspected) | consistent with README's list and `cli/commands/annotate.py` | keep |

### 1.2 DecBench upstream boundary (lines 25–42)

| # | Claim | Verified? | Evidence | Disposition |
|---|---|---|---|---|
| 7 | DecBench commit `b909596` introduced README AI rules; issue 81 comment | unverifiable (out-of-tree repo, not fetched) | corroborated by `docs/design/decbench-native-provenance-2026-08-27.md` | **keep as rule** — this is the single most consequential rule in the file |
| 8 | "Active frontier": decompiler quality, Windows port (PDB, `ioctl_taint`, `windows-risk`), L1–L5 + F1–F7 | partially | `windows-risk` is a live CLI subcommand (`cli/main.py:80`); `ioctl_taint` appears in `examples/ioctl_scan.rs` / symbolic tree; L1–L5 from `05a05db5` 2026-05-22 | shorten — a "frontier" line dates fast; one sentence or drop |

### 1.3 Build / test / run block (lines 44–107)

| # | Claim | Verified? | Evidence | Disposition |
|---|---|---|---|---|
| 9 | `uv sync --locked --dev` builds the extension | true | `pyproject.toml:1-3` build-backend = maturin | keep |
| 10 | `uv run maturin develop` / `maturin build --release` | true | standard; note pyproject:64 warns `[build-system].requires` does not give a runnable `maturin` | keep |
| 11 | console script `glaurung = glaurung.cli:main` | true | `pyproject.toml` scripts | keep |
| 12 | subcommands `triage`, `kickoff` | true | `cli/main.py:27,46` | keep |
| 13 | **Python suite is "~345 test files"** | **FALSE (stale, low)** | `find python/tests -name 'test_*.py' \| wc -l` → **461**. CI's own comment says 445. | drop the number, or make it a gate |
| 14 | `pytest -m decbench` is the opt-in | true | `pytest.ini` addopts `-m "not decbench"`; an explicit `-m` replaces it | keep |
| 15 | **"cargo test — Rust suite (~125 test modules)"** | **FALSE (stale, low)** | `grep -rl '#\[cfg(test)\]' src/ \| wc -l` → **276**; `ls tests/*.rs` → 25 | drop the number |
| 16 | `cargo test --features python-ext` adds `src/python_bindings/` | true | `src/lib.rs:93,99,103,137,185,224` are `#[cfg(feature="python-ext")]` | keep |
| 17 | `tools/build_guard.py` exists | true | present | keep |
| 18 | `tools/dectest.py <fixture>:<tc>:<opt>:<fn> --show`, `@loops`, `--list-sets` | true | `tools/dectest.py:923` `--list-sets`, `:956`; `tests/decompiler_fixtures/sets.toml` has `[smoke] [loops] [o0] [o2] ...`; `src/13_loop_early_exit.c` exists | keep |
| 19 | `scripts/decbench-local-gate.sh` lanes 1-3 ours / 4-5 DecBench, `--decbench` | true | script header lines 12-41; `--decbench` at :56 | keep |
| 20 | `~50m` / `~100m` runtimes | unverifiable (not run) | plausible; script comments cite ~40 min matrix | shorten (drop the minutes or say "tens of minutes") |
| 21 | 5 criterion benches: `ir_lift`, `ir_dataflow`, `ir_structure`, `analysis_cfg`, `decompile_pipeline` | true | all 5 in `benches/` and `[[bench]]` in Cargo.toml. (5 more exist: triage, entropy, strings, lang_detect, emulator — undocumented here) | keep; note the other 5 |
| 22 | "17 passes isolated", "14-SHAPE sweep", "8-phase split" | unverifiable (not run) | — | shorten to bench names only |
| 23 | `bench/perf_baseline.json` exists | true | 304 bytes, 3 measures, unit `instructions`; consumed by `tools/perf_gate.py` | keep |
| 24 | **"missing/partial/incomparable evidence still fails open"** | **FALSE (stale)** | `4f4f88e3` 2026-09-01 "perf: the gate could report success from an empty measurement"; `python/tests/test_perf_gate_fails_closed.py` docstring: "Exit **3** means *this run is not evidence*" | **drop-obsolete**, replace with "fails closed (exit 3 = not evidence)" |
| 25 | `tools/compare_decompilers.py <binary> main print_sum`; needs angr and/or Ghidra at `/opt/ghidra`; JDK 21 | file exists; JDK/Ghidra unverifiable | `tools/compare_decompilers.py` present; `docs/development/decompiler-parity-backlog.md` present | →docs (parity backlog already owns this) |
| 26 | `cargo fuzz` reaches **8** targets | **true** | `ls fuzz/fuzz_targets/` → 8 `.rs`; `grep -c '[[bin]]' fuzz/Cargo.toml` → 8 | keep |
| 27 | `fuzz/seed_corpus.py` | true | present | keep |
| 28 | `uv run python -m glaurung.bench` | true | `python/glaurung/bench/__main__.py` | keep |
| 29 | `uvx ruff format/check python/`, `uvx ty check python/` | true and matches CI (ruff) | CI lint job runs both ruff commands on `python/`; **CI runs no `ty` at all** | keep, but see #37 |
| 30 | `tools/gen_native_stub.py` and `--check` | true | present; `--check` mode; `python/glaurung/_native/*.pyi` = 12 stubs | keep |

### 1.4 Tooling conventions (lines 109–117)

| # | Claim | Verified? | Evidence | Disposition |
|---|---|---|---|---|
| 31 | ruff + ty only; never mypy/black/pylint/flake8/isort/pip; no `[tool.mypy]`/`[tool.black]` | true | `pyproject.toml` has `[tool.ruff]` only; no mypy/black sections | keep |
| 32 | ruff `target-version` tracks `requires-python` | true, and self-documented | `pyproject.toml:99-105` records the 2026-08-18 `py314`-vs-3.11 incident; now `py312` vs `>=3.12` — consistent | keep as rule (one line) |
| 33 | Rust: `Result<T,E>` + `?`, `///`/`//!`, justified `unsafe`; naming conventions; pathlib/type hints/Google docstrings | true as policy | not machine-checked anywhere | keep, compress to 2 lines |

### 1.5 "Working style" bullets (lines 119–345) — the narrative half

For each, the **durable rule** in one sentence, and whether a gate enforces it.

| # | Bullet | Verified? | Evidence | Durable rule | Gate exists? | Disposition |
|---|---|---|---|---|---|---|
| 34 | TDD; test first | true as policy | — | Write the test first. | no | keep (1 line) |
| 35 | No mocks/fake data; use `samples/`, `tests/`, `tests/fixtures/` | true | all three dirs exist | Real binaries only. | no | keep (1 line) |
| 36 | **"Since 2026-08-31 CI runs them too (`test-suite.yml`: cargo test --features python-ext, the full Python suite, and ruff)"** | **partially FALSE** | `test-suite.yml` has **four** jobs: `rust` (python-ext), **`symbolic`** (undocumented here), `python` (**`-m "not fixtures and not decbench"`** — not "full"), `lint` (ruff format + check only). **`ty` is in NO workflow** (`rg 'ty check' .github/` → none), though the lint job's comment claims it "is checked in the python job's environment instead" — it isn't. | Don't say done without tests + ruff + ty; CI covers only part of that. | partial | rewrite: name the four jobs, state that `ty` and `-m fixtures` are developer-only |
| 37 | "6 of 445 Python test files executed in CI; only 'cargo test' under .github/ was a comment" | true as of the fix | `test-suite.yml` header repeats it verbatim | (historical) | n/a | drop-warstory (duplicated in the workflow header, which is where it belongs) |
| 38 | **"the fixture matrix and the six baselines still gate nothing automatically"** | **half FALSE** | `decompiler-fixtures.yml` runs on push→master + PR (paths-filtered), builds the pinned toolchain image, and runs `-m slow test_decompiler_fixture_matrix.py test_decompiler_fixture_structural.py` fail-closed, plus the 1,162-row known-failure corpus (added in HEAD `b8884687`). So `baseline.json` and `structural_baseline.json` DO gate. `defuse_baseline.json` and `arch_baseline.json` appear in no workflow (`rg 'defuse\|arch_baseline' .github/` → none). | The def-use census and the arch matrix are the two baselines with no CI; run them by hand. | partial | rewrite to name the two ungated baselines |
| 39 | `cargo test` does not build `src/python_bindings/` | **true** | `src/lib.rs` gates all 6 python-binding modules behind `python-ext` | Use `--features python-ext` for anything under `src/python_bindings/`. | **yes** — `test-suite.yml` `rust` job | shorten to the rule + "CI's rust job pins this" |
| 40 | "skips ~120 tests" in python_bindings | doubtful | `grep -rho '#\[test\]' src/python_bindings/ \| wc -l` → **32**. The 120 may count transitively unlocked tests; as written it reads as bindings-local. | — | drop the number |
| 41 | 2026-08-14 `2321 passed; 0 failed` over uncompiled code | historical, unverifiable now | — | (same rule as #39) | drop-warstory |
| 42 | plain `cargo build` reported ~98 unused fns vs 4 shipped; 1,782 lines looked unreachable | historical | — | Dead-code counts are feature-configuration-dependent. | no | shorten to one clause |
| 43 | `cargo check --features python-ext --lib` does not compile `#[cfg(test)]` modules | true | standard cargo semantics; `--all-targets` is what `feature-build-gate.sh` uses precisely for this | `check` for the loop, `test` to call it done. | yes (CI) | keep, 1 line |
| 44 | 2026-08-28 `select_renderable_dwarf_local_facts` arity incident | historical | symbol still present in tree | (same rule) | — | drop-warstory |
| 45 | **`src/lib.rs:80` is `#[cfg(feature="symbolic")]`; symbolic in neither default nor python-ext** | **true, exact** | `sed -n '80p' src/lib.rs` → `#[cfg(feature = "symbolic")]`. `Cargo.toml`: `default=["triage-core"]`, `python-ext=["pyo3",…,"exec"]`, `symbolic=["exec"]` | `--features python-ext` does not build the symbolic tree. | **yes now** — `test-suite.yml` `symbolic` job runs `cargo test --features symbolic` **and** asserts ≥50 symbolic tests are listed | keep the rule; note the gate; the "sat uncompilable for 17 days" story can go |
| 46 | **"26 files, 21,459 product LOC"** | **true, exact** | `find src/symbolic -name '*.rs' \| wc -l` → 26; `wc -l` total → **21459** | — | keep the fact, drop the self-referential "re-counted 2026-08-31 / used to say 21 files" meta-paragraph |
| 47 | 2026-08-17 invalid-Rust experiment; `BinOp::LogicalAnd/Or` 2026-07-31; `triage-parsers-extra` broken 350 days | historical | `triage-parsers-extra = ["goblin","pelite"]` is a real feature | (same rule as #45) | — | drop-warstory |
| 48 | **`scripts/feature-build-gate.sh` = 12 `cargo check --all-targets` lanes** | **true, exact** | the `lanes=()` array at :78-95 has exactly 12 entries: default, python-ext, exec, symbolic, solver-axeyum, solver-axeyum-text, solver-bitwuzla, triage-parsers-extra, solver-z3, solver-z3+solver-axeyum, all-features, fuzz-crate | Run the feature gate before pushing anything feature-gated. | **yes** — `feature-build-gate.yml` runs on push→master + PR | keep the rule; note CI now runs it too, so "pre-push" is belt-and-braces |
| 49 | It is "the only thing that builds solver-*, symbolic, exec, dev-oracle, triage-parsers-extra" | **partially FALSE now** | `dev-oracle` is indeed in no lane (it needs libunicorn) — so the gate does NOT build it either; and `symbolic` is now also built AND RUN by `test-suite.yml` | — | correct the list: drop `dev-oracle`, note symbolic has a test lane |
| 50 | `fuzz/` is a separate crate invisible to root checks; lane 12 added 2026-08-31 | true | lane 12 passes `fuzz/Cargo.toml`; `fuzz/` is not a workspace member | keep | yes | shorten |
| 51 | `scripts/lint-rust.sh` runs `clippy --all-targets --all-features` but nothing calls it; 260 pre-existing errors under `-D warnings` | true (uncalled); 260 unverified | `rg 'lint-rust' .` → only `build.rs` comment, `feature-build-gate.sh` comment, CLAUDE.md, and docs. No workflow. | The clippy script is red and unwired; the build gate is the pre-push path. | no | shorten to one sentence; drop "260" or make it a tracked number |
| 52 | Never hand-write a `.pyi` | true as rule | `python/glaurung/_native/*.pyi` = 12 generated stubs; `pyproject.toml:107-113` excludes them from ruff | Never hand-write a `.pyi`; generate it. | **yes** — `python/tests/test_native_stub_current.py` regenerates and diffs | keep the rule; →docs for the 2,004→386 diagnostics story |
| 53 | 2026-08-18: 2,004 diagnostics, 1,618 from two stubs; `__init__.pyi` 1,532 lines; `python/pytest/__init__.pyi` 5 lines / 417 diagnostics; result 386 | historical; both files now absent | `ls python/glaurung/__init__.pyi` → gone; `ls python/pytest/` → gone | (same rule) | — | →docs |
| 54 | Adding a CLI command drifts `docs/tutorial/_fixtures/01-install/help-head.out`; `test_verify_tutorial.py::test_check_mode_does_not_rewrite_install_fixtures`; refresh with `scripts/verify_tutorial.py --chapter 01-install --capture` | **true** | fixture file exists; `python/tests/test_verify_tutorial.py:82` `def test_check_mode_does_not_rewrite_install_fixtures`; `scripts/verify_tutorial.py` exists | Adding a CLI subcommand requires refreshing the install tutorial fixture. | yes (the test) | keep, 2 lines |
| 55 | "A split has four side files" (line 197) — contradicted by "A split has SIX side files" (line 278) | **self-contradiction in the same file** | both bullets present, 80 lines apart, one superseding the other without deleting it | A module split touches 4 fixture baselines + `test_large_module_review.py` + `test_src_dependency_boundaries.py` + `test_stranded_doc_comments.py`. | yes (three tests) | **merge the two bullets**; the duplicate is exactly the kind of drift the rewrite should remove |
| 56 | `REVIEWED_LARGE_MODULES` / `test_no_review_entry_outlives_the_file_it_reviewed` | true | `test_large_module_review.py:70` dict, `:329` the test | keep | yes | keep |
| 57 | `test_src_dependency_boundaries.py` env-var allowlist keyed by file path | true | `:178-206` "correctness cannot depend on environment variables"; per-path allowlist | keep | yes | keep |
| 58 | `REVIEWED_DOC_SUMMARIES` in `test_stranded_doc_comments.py`, keyed by path; "three of four splits on 2026-08-31 tripped it" | true (symbol at `:268`); the 3-of-4 is historical | — | keep | yes | keep rule, drop the count |
| 59 | Never run DecBench/Joern unless asked; `tools/decbench_matrix.py`; `tests/decompiler_fixtures/` is the real corpus | true | both paths exist; `pytest.ini` deselects `-m decbench` by default with an explanatory comment | keep | yes (`pytest.ini`) | keep — high-value rule |
| 60 | `docs/design/decompiler-roadmap.md` "Appendix A" holds the metric plan and is not a work queue | **true** | `grep '^#.*Appendix' docs/design/decompiler-roadmap.md` → `:3209 ## Appendix A — DecBench and evaluation (ON DEMAND ONLY)` | keep | — | keep, 1 line |
| 61 | def-use census not in the dectest loop; `test_decompiler_defuse_census.py`; run it when prototypes move | true | file exists; not in any workflow | Any signature change moves the def-use census; run it by hand. | **no** (this is one of the two ungated baselines, cf. #38) | keep — this is a live gap |
| 62 | 2026-08-19 arity fix `11d55613` moved rustc:O0 +20 / O2 +12; three A/B experiments | historical | commit exists in log range | (same rule) | — | drop-warstory |
| 63 | Correction paragraph: "this bullet used to say the census needs `-m ''`… it does not" | true but meta | `pytest.ini` deselects only `decbench` | — | — | **drop** — corrections-to-the-doc-inside-the-doc are pure rewrite debt |
| 64 | Run `tools/build_guard.py` before every baseline regeneration; guard message `STALE: … is newer than the built extension` | true (tool exists) | `tools/build_guard.py` | Rebuild before measuring, in both directions. | no | keep the rule, →docs for the 2026-08-19 story |
| 65 | `@o0`/`@o2` are host-only; need `--arch i386 --arch armv7 --arch aarch64 --arch x86_64_gcc15`; `--arch` retargets whatever selectors you gave and defaults to `@smoke` | true | `tools/dectest.py:903` `--arch`; `sets.toml` has `[o0] [o2] [smoke]`; `src/144_inline_asm.c` exists | Cross-arch cells move invisibly under host-only selectors; always pass selectors with `--arch`. | **no** (`arch_baseline.json` is in no workflow) | keep the rule + the exact command; →docs for `d1365bdb` / "SCOPED: 16 lanes of 3078" |
| 66 | Extend `tests/decompiler_fixtures/`; a new fixture + `manifest.py` contract; refresh four baselines; fixtures 195/196 reached master with a red census | true | `src/195_by_value_aggregates.c`, `src/196_disjoint_frame_slots.c`; 219 `.c` files in `src/`; single top-level `manifest.py`; all four `*baseline*.json` present | Adding a fixture requires refreshing four baselines, and `defuse` is the one that hides. | partial (2 of 4 in CI) | keep, merge with #55/#61 |
| 67 | `maturin develop` builds DEBUG; 276 MB vs 974 KB; memchr 12.7%→0.5%, allocator 6.5%→26.2% | plausible, not re-measured | CI's python job explicitly uses `--release` with the same reasoning in its comment | Measure only against `--release`, and say which build a number came from. | partial (CI uses release) | keep the rule (2 lines), →docs for the percentages |
| 68 | Structural gates are the ones an optimisation loop never runs; 7 red tests on pushed master 2026-08-31; 419-binary byte-identity sweep green | historical | — | After any commit touching `src/`, run the whole Python suite, not the subset. | **now partly yes** — `test-suite.yml` python job runs everything except `fixtures`/`decbench` on every push | keep the rule, note CI now catches most of it |
| 69 | `perf` works here; `perf_event_paranoid=4`, `ptrace_scope=1`; passwordless `sudo sysctl -w …` | **true, exact** | `sysctl kernel.perf_event_paranoid kernel.yama.ptrace_scope` → `4` and `1` | Fix the sysctls instead of hand-rolling timers. | no | keep the two-line recipe, →docs for the SipHash/memmove/copy_prop percentages |
| 70 | `perf` self-time misleads on allocation-driven cost; iced 2.2% self, libc 47.5% | plausible, not re-measured | — | Count allocations with a `GlobalAlloc` when you suspect churn. | no | shorten to the rule |
| 71 | Don't read a size curve through `Throughput::Bytes`; n^2.13 vs 0.97 | plausible | `analysis_cfg` bench does use `Throughput::Bytes` per CLAUDE.md's own line 78 | Pick the denominator the work is proportional to. | no | shorten |
| 72 | `git stash` writes a repository-shared ref across worktrees | true (git semantics) | — | Use `git diff > patch` / `git apply -R` for A/B, not stash. | no | keep, 1 line — high value with parallel agents |
| 73 | `cargo fmt -- <files>` formats the whole crate | true (cargo semantics) | — | Use `rustfmt --edition 2021 <file>`. | no | keep, 1 line |
| 74 | Nothing may write to `/tmp`; `export TMPDIR="$HOME/.cache/glaurung/tmp"`; maturin writes its wheel to `/tmp`; `/tmp` is a 62 GB quota'd shared tmpfs | true as instruction; the environment specifics unverified here | `scripts/feature-build-gate.sh:~100` comment "Keep the log inside the target directory, not /tmp. CLAUDE.md:" — the rule is honoured in code | Export `TMPDIR` before doing anything. | partial (scripts honour it; nothing enforces it) | **keep the export block verbatim** — highest operational value per line; →docs for the five failure-mode anecdotes |
| 75 | `/tmp` failure modes: DecBench assertion, 8 fake SEMANTIC REGRESSIONS at 13 GB free, pytest INTERNALERROR Errno 122 exit 0, Bash tool dying | historical | — | A green/zero exit can be a full-tmpfs artifact; a successful `Write` is the liveness probe. | no | →docs (keep one sentence: "when it fills it never says disk full") |
| 76 | Sweep only what is ours; 33 GB under `/tmp/claude-1000` was other tenants | historical | — | Don't delete another tenant's temp data; ask. | no | keep 1 line |

### 1.6 LLM model policy (lines 347–372)

| # | Claim | Verified? | Evidence | Disposition |
|---|---|---|---|---|
| 77 | default `openai:gpt-5.4-mini` | **true** | `llm/config.py:43` `default_model: str = field(default="openai:gpt-5.4-mini")` | keep |
| 78 | service tier `flex` | **true** | `config.py:53` `openai_service_tier: str = field(default="flex")` | keep |
| 79 | fallback `anthropic:claude-haiku-4-5` | **true** | `config.py:44` | keep |
| 80 | `summarizer_model`, `risk_scorer_model`, `ioc_model` all default to the same | **true** | `config.py:45,46,47` | keep |
| 81 | `ModelHyperparameters.to_model_kwargs(model_name=…)` adds `extra_body={"service_tier": …}` when tier ≠ default | **true** | `llm/agents/base.py:51` defines it; `:92` uses it; `finding_critic.py:173-175` sets `extra_body["service_tier"]`; `findings_runner.py:174-177` | keep |
| 82 | Env overrides `GLAURUNG_LLM_MODEL`, `GLAURUNG_OPENAI_SERVICE_TIER` | **true** | `config.py:88-90` | keep |
| 83 | Consumers: `glaurung ask`, `name-func`, `windows analyst`, L2 critic, L3 CWE sweep, L1 findings runner | true | `cli/main.py` registers `ask`, `name-func`, `windows`; `llm/finding_critic.py`, `llm/cwe_sweep.py`, `llm/findings_runner.py` | keep |
| 84 | OpenAI 128-tool cap; use `--route`, `tool_filter={…}` in `register_analysis_tools` | true | `cli/commands/ask.py:175` `--route`, `:512-542` builds `tool_filter` from `select_tools_for_question`; `llm/agents/memory_agent.py:580` `def register_analysis_tools`; `llm/tool_routing.py:9` "each intent has a curated <=30-tool subset" | keep |
| 85 | **`GLAURUNG_AGENT_ROUTE=1`** | **FALSE** | `rg 'GLAURUNG_AGENT_ROUTE' --hidden .` → **one hit: CLAUDE.md:368**. Not in any Python, Rust, script, test, or doc. The 18 real `GLAURUNG_*` vars in `python/glaurung/` do not include it. | **drop-obsolete** |
| 86 | Anthropic 4M tok/min → lower `max_parallel` in `sweep_binary` (default 1) | **true** | `llm/cwe_sweep.py:176` `max_parallel: int = 1` | keep |
| 87 | `--model anthropic:claude-opus-4-7` for one-off heavy runs | true (flag is free-form `provider:model`) | `ask.py` accepts `--model` | keep |

### 1.7 Custom agents & doc map (lines 374–383)

| # | Claim | Verified? | Evidence | Disposition |
|---|---|---|---|---|
| 88 | `.claude/agents/rust-data-model-creator.md` exists | **true** | 6,987 bytes; `model: sonnet`, `color: red`, empty `tools:` | keep |
| 89 | ...follows **`docs/data-model/`** patterns | **FALSE** | `ls docs/data-model` → No such file. The real path is `docs/architecture/data-model/`. **The agent file itself repeats the dead path 6 times** (frontmatter description, and lines 11, 17, 47, 110, 138). | **fix in both files** |
| 90 | Doc map: `docs/{cli,llm,architecture,design,windows-port,campaigns,tutorial}/`, `docs/development/project-structure.md` | **all true** | verified each; `docs/` has 23 entries, so the map is a 7-of-23 subset | keep, but say it is a subset and point at `docs/README.md` |

---

## 2. AGENTS.md ledger

**Consumers.** Nothing in this repository reads AGENTS.md as configuration. `rg 'AGENTS\.md'` finds
8 hits: 3 are identical error strings in `scripts/{format,lint,typecheck}-python.sh`
("Please install 'uv' (see project AGENTS.md)"), 2 are `docs/README.md` cross-links, 1 is
`README.md:173`, 1 is a historical mention in `docs/design/decbench-native-provenance-2026-08-27.md`,
1 is the file itself. There is no `.cursor/`, no `.codex/`, no `.github/copilot*`, no `AGENT.md`,
and no `.claude/settings*.json` anywhere in the tree. **AGENTS.md's only real consumers are
external-by-convention** (the `AGENTS.md` filename is the cross-vendor agent-instructions
convention used by Codex/Jules/Cursor and others) — which is the sole argument for keeping the
filename at all.

| # | Claim / section | Verified? | Evidence | Glaurung-specific? | Disposition |
|---|---|---|---|---|---|
| A1 | "Read CLAUDE.md first" | true | — | yes | keep — this should become nearly the whole file |
| A2 | DecBench boundary (4 bullets, lines 7–22) | true | duplicates CLAUDE.md lines 25–37 with different wording | yes | **de-duplicate**: one canonical statement, the other file links to it |
| A3 | `uv sync --locked --dev`; `maturin develop` / `build --release` | true | matches CLAUDE.md | yes | drop (duplicate) |
| A4 | `uv run pytest python/tests/` | true | — | yes | drop (duplicate) |
| A5 | Single test `python/tests/test_address.py::TestAddressCreation::test_create_va_address` | **true** | file exists; `:5` class, `:8` method | yes | keep as the one example, or drop |
| A6 | Coverage: `uv run --isolated --with pytest-cov pytest -p pytest_cov.plugin --cov=python/glaurung python/tests/` | plausible and consistent | `pytest.ini` uses `--disable-plugin-autoload -p …`, so the explicit `-p pytest_cov.plugin` is necessary and correct | yes — **this is the only command in AGENTS.md not in CLAUDE.md** | **keep — move it into CLAUDE.md** |
| A7 | `uvx ruff format python/`, `uvx ruff check python/ --fix`, `uvx ty check python/` | true, matches CLAUDE.md | — | yes | drop (duplicate) |
| A8 | **"VERIFY: `uv run pytest && uvx ruff check . && uvx ty check`"** (line 42) and the closing checklist's `uvx ruff format .` / `uvx ruff check .` / `uvx ty check` (lines 106-109) | **inconsistent with CLAUDE.md and with CI** | CLAUDE.md and `test-suite.yml` both scope to `python/`. Bare `.` additionally covers `conftest.py` and ~50 `tools/*.py` that neither CI nor the documented commands lint. `uvx ty check` with no path is not `uvx ty check python/`. Also `scripts/typecheck-python.sh` uses a **third** scope: `uvx ty check python/glaurung` (package only). | yes | **resolve to one scope**; three different scopes for the same check in three places is the concrete harm |
| A9 | TDD RED/GREEN/REFACTOR/VERIFY | generic | — | no | shorten to one line, or fold into CLAUDE.md's TDD bullet |
| A10 | Python code style (imports order, type hints, naming, no bare except, Google docstrings) | duplicates CLAUDE.md's convention block, expanded | — | no | merge into CLAUDE.md's conventions |
| A11 | Rust code style | verbatim duplicate of CLAUDE.md lines 114–116 | — | no | drop |
| A12 | "General Rules" NEVER/ALWAYS | generic | — | no | drop |
| A13 | **"Production Mindset" / "THIS IS REAL - THIS IS PRODUCTION"** (lines 66–103) | generic boilerplate, 38 lines | "Bugs cause user frustration", "Missing features disappoint users" — no Glaurung content, no checkable claim | **no** | **drop entirely** |
| A14 | Validation Checklist (6 checkboxes) | generic | — | no | drop |
| A15 | "Before Saying Done" (4 lines) | duplicate of A8 with the same scope bug | — | no | drop |

**Summary:** of 109 lines, ~16 are Glaurung-specific and non-duplicative (the DecBench boundary
and the coverage command), ~55 duplicate CLAUDE.md, and ~38 are content-free motivational
boilerplate. Two commands actively contradict CLAUDE.md and CI.

---

## 3. README.md ledger

| # | Claim | Verified? | Evidence | Disposition |
|---|---|---|---|---|
| R1 | `![Glaurung logo](assets/glaurung-logo-512px.png)` | **true** | `assets/glaurung-logo-512px.png`, 325 KB; fixed for alpha in `e10e2b98` 2026-08-31 | keep |
| R2 | "pre-1.0", not a Ghidra/IDA replacement, decompiler output experimental | true | `Cargo.toml:3` version 0.1.0 | keep — honest framing, rare and worth preserving |
| R3 | ELF, PE/COFF, Mach-O triage w/ symbols, strings, IOCs, entropy, packer, hardening | true | `src/formats/{elf,pe,macho}`, `_native/triage.pyi` has `PackerMatch`, `IocSample`, `EntropySummary`, `StringsSummary`, `SymbolSummary` | keep |
| R4 | **"decompiler lifts x86/x86-64 and ARM/ARM64; RISC-V is disassembly-only"** | **true, provable** | `src/ir/lift_function.rs:1386` — the test `an_unsupported_arch_is_named_in_the_rejection` asserts `lift_function_from_bytes(..., Arch::RISCV64) == Err(LiftError::UnsupportedArchitecture)`. MIPS64 likewise. | keep — a doc claim backed by an assertion is the ideal |
| R5 | Function discovery, CFG, callgraph, xrefs, stack frames, type propagation, DWARF, PE/PDB | true | `src/analysis/`, `src/ir/dwarf_*`, `cli/commands/{cfg,graph,xrefs,frame,types}.py`, `pdb_fetch.py` | keep |
| R6 | C-like pseudocode via LLIR/SSA/AST | true | `src/ir/ast/`, `src/ir/ast.rs` | keep |
| R7 | `.glaurung` persists names/comments/labels/types/prototypes/xrefs/stack vars/bookmarks/journal | true | subcommands `rename comment label proto xrefs frame bookmark journal undo redo` all in `cli/main.py:57-69` | keep |
| R8 | Optional PydanticAI agents for QA/naming/vuln review/source recovery | true | `ask`, `name-func`, `verify-recovery`, `llm/cwe_sweep.py` | keep |
| R9 | `uv run glaurung --help` is authoritative | true | `cli/main.py` registry of **44** subcommands | keep |
| R10 | Not on PyPI | true | no publish workflow outside the tag-gated release job | keep |
| R11 | Requires Git | true | — | keep |
| R12 | **"CPython 3.11 or newer"** | **FALSE** | `pyproject.toml:7` `requires-python = ">=3.12"`; `[tool.ruff] target-version = "py312"`. (Separately, `pyproject.toml:22` still lists the `Python :: 3.11` classifier, contradicting its own `requires-python` and the comment at `:99` that says classifiers MUST track it — a second, independent bug in pyproject.) | **fix to 3.12** and flag the classifier |
| R13 | "Rust 1.88 or newer" | asserted, **unenforced** | No `rust-version` key in `Cargo.toml`; no `rust-toolchain.toml`. `docs/development/setup.md:26` gives the reason (`gimli 0.33` requires 1.88). Nothing fails on an older toolchain until it fails confusingly. | keep the number; recommend adding `rust-version = "1.88"` to Cargo.toml |
| R14 | Native C compiler and linker required | true | build.rs, cc-dependent crates | keep |
| R15 | `git clone … && uv sync --locked --dev && uv run glaurung --version` | true | `--version` at `cli/main.py:131`, prints `%(prog)s 0.1.0` (hardcoded, matches `Cargo.toml` version) | keep; consider sourcing version from metadata |
| R16 | "uv sync creates .venv, resolves the lockfile, builds the Rust extension" | true | maturin build-backend | keep |
| R17 | `docs/development/setup.md` link | true | exists | keep |
| R18 | **Sample `samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-gcc-O2` "so no API key or external tool is needed"** | **path true, but the smoke test is BROKEN on a fresh clone** | The file on disk is **130 bytes**: `version https://git-lfs.github.com/spec/v1 / oid sha256:707f… / size 18248`. `.gitattributes` LFS-tracks the sample tree. `test-suite.yml`'s own header documents this: without `lfs: true` "every test that opens a real binary reads a 130-byte pointer file", which turned a whole CI run red. **README never mentions Git LFS**, and neither does `docs/development/setup.md` (`grep -i lfs` on both → no hits). | **fix**: add `git lfs install && git lfs pull` (or `git clone` guidance) to Install-from-source. This is the single highest-impact README defect. |
| R19 | `glaurung triage "$SAMPLE"` | true | `cli/main.py:27` | keep |
| R20 | `triage … --json` | **true** | not in `commands/triage.py`; it is a common arg — `commands/base.py:59-61` `--json` ("Alias for --format json"), added by `add_common_arguments` at `:43` for every command | keep |
| R21 | `glaurung kickoff "$SAMPLE"` and `--db PATH`; temporary project otherwise | true | `commands/kickoff.py:23` `--db` | keep |
| R22 | `glaurung decompile "$SAMPLE" --func main --style c` | **true** | `commands/decompile.py:149` `--func`, `:226-227` `--style` with `choices=["plain","c","decbench"]` | keep |
| R23 | `glaurung repl "$SAMPLE" --db hello.glaurung` | true | `commands/repl.py:58` `--db` | keep |
| R24 | `strings`, `symbols`, `detect-packer` | true | `cli/main.py:28,29,44` | keep |
| R25 | `glaurung graph "$SAMPLE" callgraph > callgraph.dot` | **true** | `commands/graph.py:204-206` — `path` positional then a required `kind` subparser with `callgraph` (and `cfg`); DOT output | keep |
| R26 | Tutorial link `docs/tutorial/01-getting-started/install.md` | true | exists | keep |
| R27 | `from glaurung import triage; triage.analyze_path(sample)` | **true** | `python/glaurung/triage.py:254` `def analyze_path(` | keep |
| R28 | `artifact.verdicts`, `verdict.format/.arch/.bits`, `artifact.entropy.overall` | **true** | `_native/triage.pyi:503` `verdicts`; `:483` `entropy`; `class EntropySummary` `:138` `overall` | keep |
| R29 | `g.ir.DecompilerSession(sample)` | **true** | `_native/ir.pyi:15` `class DecompilerSession`, `:22` `__init__(self, path)`; `python/glaurung/__init__.py:109-110` binds `ir` and registers it in `sys.modules` | keep |
| R30 | `session.decompile_at(entry, style="decbench")` | **true** | `ir.pyi:24` `def decompile_at(self, func_va, …, style: Any = "", …)`; `"decbench"` is a real style (`decompile.py` choices) | keep |
| R31 | `session.artifact_cache_stats` | **true** | `ir.pyi:18` (also `discovery_cache_stats`, `clear_caches`) | keep |
| R32 | `functions, _ = g.analysis.analyze_functions_path(sample)` returns a 2-tuple | **true** | `_native/analysis.pyi:17`; `src/python_bindings/analysis.rs:302` returns `PyResult<(…)>` ending `Ok((funcs, cg))` — exactly 2 elements. (The `_with_stats` variant returns 3.) `__init__.py:105-106` binds `analysis`. | keep |
| R33 | Cache key includes address, budgets, type/style options, normalized arch address; diagnostics and PDB overlays bypass reuse | plausible, not read at source level | `decompile_at` signature carries `max_blocks/max_instructions/timeout_ms/types/style/pdb_cache/max_functions` — consistent | keep |
| R34 | Flags `--max-file-size`, `--max-read-bytes`, `--max-functions`, `--timeout-ms`; "not every command exposes every limit" | **true, and the hedge is correct** | `--max-read-bytes`/`--max-file-size` in `triage.py:25,31`; `--max-functions` in 7 command files; `--timeout-ms` in 6 (windows, windows_risk, explain, cfg, string_xrefs, decompile) — notably **not** in `triage.py` | keep — the caveat is doing real work |
| R35 | LLM default `openai:gpt-5.4-mini` + `flex`; `OPENAI_API_KEY` in env or `.env`; `--model provider:model`; `GLAURUNG_LLM_MODEL` | true | matches `llm/config.py` (see #77–82) | keep |
| R36 | "Anthropic and Google credentials are also supported for explicitly selected models" | plausible | pydantic-ai multi-provider; `fallback_model` is Anthropic | keep |
| R37 | `glaurung ask "$SAMPLE" --route -a "…"` | **true** | `commands/ask.py:175` `--route`, `:35` `-a/--ask` | keep |
| R38 | `GLAURUNG_OPENAI_SERVICE_TIER=flex` | true | `config.py:89-90` | keep |
| R39 | `docs/development/setup.md#runtime-configuration` anchor | **true** | `setup.md:199` `## Runtime configuration` → anchor `#runtime-configuration` | keep |
| R40 | Dev checks: `cargo test` / pytest / ruff format --check / ruff check / ty check | **partially misleading** | `cargo test` without `--features python-ext` is precisely the trap CLAUDE.md spends 11 lines warning about, and CI uses `--features python-ext`. README hands newcomers the weaker command. | **fix**: `cargo test --features python-ext` |
| R41 | Links CLAUDE.md and AGENTS.md for contributor policy | true | both exist | keep (update if AGENTS.md is restructured) |
| R42 | `docs/development/decompiler-testing.md` | true | exists | keep |
| R43 | 9 documentation-map links: `docs/README.md`, `docs/development/setup.md`, `docs/tutorial/README.md`, `examples/README.md`, `docs/cli/analyst-ergonomics.md`, `docs/architecture/`, `docs/analysis/decompiler/README.md`, `docs/windows-port/README.md`, `docs/agentic-glaurung/README.md` | **all 9 true** | each verified to exist | keep |
| R44 | Apache-2.0, `LICENSE` present | true | `LICENSE` exists; `pyproject.toml:13` `license = {text = "Apache-2.0"}` | keep |
| R45 | "ground-up project, not a Ghidra plugin" | true | — | keep |

**README verdict: `mostly-current`.** 43 of 45 claims verify. Two defects: the missing Git LFS
step (breaks the advertised first-run experience) and the 3.11-vs-3.12 floor. One improvement:
`cargo test` → `cargo test --features python-ext`.

---

## 4. Git-history scan

```
git log --format='%h %ad %s' --date=short -- CLAUDE.md AGENTS.md README.md
```

**CLAUDE.md — 25 commits, 2025-08-29 → 2026-09-01.**
Three eras:
- *Generated era* (`d29e9ed7` 2025-08-29 → `540c3e98` 2025-08-30): compiled from `.claude/modules/` by `cm.py`.
- *Dormant* (2025-08-30 → 2026-05-15): 8 months, zero commits.
- *Hand-maintained accretion era* (`641b1458` 2026-06-03 "chore: retire cm.py module system;
  hand-maintain CLAUDE.md" → HEAD): **19 of 25 commits land in the last 4 months**, and 10 in
  August 2026 alone. The commit subjects tell the whole story of the file's shape:
  `b92cb889` "the feature blind spot is 8.6% of the tree", `d99e5826` "stop writing this project's
  temporaries to the shared /tmp tmpfs", `9b4e0b3c` "record the criterion benches and five tooling
  traps", `a34cab98` "three traps that cost a day, recorded where the next person will look",
  `85d7771f` "correct four claims this session disproved by checking them", `aed81512` "put the
  new tools where people look for commands". **The file has been used as an incident log for four
  months.** That is why it is 24 KB and why bullets contradict each other (#55) and correct
  themselves in place (#63).

**AGENTS.md — 4 commits only.** `8da7cf95` 2025-08-30 (created alongside the samples Docker
workflow), `641b1458` 2026-06-03 (cm.py retirement), `fcca960b` 2026-08-05 (setup overhaul),
`5c4df8d2` 2026-09-01. It has been essentially frozen since creation; the boilerplate is
original 2025 content that no one has revisited.

**README.md — 14 commits, 2025-08-29 → 2026-08-31.** Steadier: quick-start refreshes
(2026-04-25 ×3), a fairness pass on tool comparisons (`bab803fd` 2026-07-24 "make tool comparisons
fair and accurate; cite sources" — the source of the honest pre-1.0 framing), a documentation
overhaul (`0ec35a2e` 2026-08-07), the DecompilerSession API section (`ae889885` 2026-08-09), and a
logo alpha fix (`e10e2b98` 2026-08-31).

**`cm.py` / `.claude/modules/`:** introduced in the initial commit `d29e9ed7`, deleted in
`641b1458` (2026-06-03). **No remnants**: no `cm.py`, no `.claude/modules/`, no references
anywhere in the tree except CLAUDE.md's own header note. `.claude/` today contains exactly one
file (`agents/rust-data-model-creator.md`) and **no `settings.json` / `settings.local.json`**.

---

## 5. Recommendation for the rewrite

### 5.1 New `CLAUDE.md` — target **~130 lines / ~7 KB** (from 383 / 24 KB)

The governing principle: **CLAUDE.md holds rules and commands; `docs/development/` holds the
evidence for them.** A rule whose narrative is longer than the rule belongs in docs with a
one-line pointer. A rule an automated gate now enforces shrinks to naming the gate.

```
# CLAUDE.md — Glaurung

## What Glaurung is                                   (~10 lines)
  Rust core + PyO3 + Python CLI/LLM. src/ modules, python/glaurung/,
  KB at python/glaurung/llm/kb, .glaurung SQLite with set_by provenance.
  [FIX: kb path]

## Hard boundary: DecBench                            (~10 lines)
  Verbatim from today's lines 25-37. This is the only section that
  should not be shortened. AGENTS.md links here rather than restating.

## Commands                                           (~40 lines)
  Build / run / test / lint / stubs — today's fenced block, minus the
  stale counts (#13, #15, #40), minus the runtimes (#20), plus:
    - cargo test --features python-ext  (mark as THE test command)
    - the coverage command rescued from AGENTS.md (#A6)
    - the other five benches (triage, entropy, strings, lang_detect, emulator)
    - export TMPDIR=... FIRST, as line one of the block

## The seven gates, and which ones CI runs             (~25 lines)
  A table, not prose. One row per gate:
    gate | command | what it protects | in CI?
    ---------------------------------------------------------------
    cargo test --features python-ext | ... | bindings tree     | yes (test-suite.yml rust)
    cargo test --features symbolic   | ... | 26 files/21k LOC  | yes (test-suite.yml symbolic)
    uv run pytest python/tests/      | ... | everything else   | partly (-m "not fixtures and not decbench")
    uvx ruff format/check python/    | ... | style             | yes (test-suite.yml lint)
    uvx ty check python/             | ... | types             | NO -- developer only
    scripts/feature-build-gate.sh    | 12 lanes | feature-gated trees | yes (feature-build-gate.yml)
    dectest @o0 @o2 --arch ...       | ... | arch_baseline.json  | NO
    pytest test_decompiler_defuse_census.py | ... | defuse_baseline.json | NO
    (fixture matrix + structural)    | ... | baseline.json, structural_baseline.json | yes (decompiler-fixtures.yml)
  This table replaces bullets #36, #38, #39, #43, #45, #48, #61, #65, #68
  and answers in one glance the question those nine bullets each answer partially.

## Conventions                                        (~12 lines)
  ruff/ty only, never mypy/black/pip. Rust Result/?/docs/unsafe.
  Naming. pathlib, type hints, Google docstrings. Never hand-write a .pyi.
  (absorbs all of AGENTS.md's style sections)

## Working style                                      (~15 lines)
  TDD. Real fixtures only, no mocks. Surface failures faithfully.
  Never run DecBench/Joern unless asked.
  A module split touches SIX side files -- list them. (merges #55's contradiction)
  Adding a CLI subcommand drifts the tutorial fixture -- name the refresh command.
  Measure only against --release.
  git diff/apply, not git stash. rustfmt <file>, not cargo fmt -- <file>.

## LLM model policy                                   (~15 lines)
  Today's section verbatim MINUS GLAURUNG_AGENT_ROUTE (#85, does not exist).

## Pointers                                           (~5 lines)
  docs/README.md, docs/development/traps.md, docs/development/decompiler-testing.md,
  docs/design/decompiler-roadmap.md Appendix A,
  .claude/agents/rust-data-model-creator.md (docs/architecture/data-model/ patterns).
```

**New file: `docs/development/traps.md`** — the destination for every dated narrative extracted
above (#41, #42, #44, #47, #53, #62, #65-story, #67-numbers, #69-percentages, #70, #71, #75).
Format: one section per trap, each headed by the one-sentence rule, then the incident with its
date and commit. This preserves knowledge that exists nowhere else — specifically the
`/tmp`-exhaustion failure signatures (#75) and the perf-vs-allocation-profiling lesson (#70),
which are genuinely non-obvious and are recorded in no other file.

**Corrections to make while rewriting** (all verified above):
- `python/glaurung/kb/` → `python/glaurung/llm/kb/`
- `docs/data-model/` → `docs/architecture/data-model/` (**and in `.claude/agents/rust-data-model-creator.md`, 6 occurrences**)
- delete `GLAURUNG_AGENT_ROUTE=1`
- perf gate "fails open" → fails closed (exit 3)
- CI description → four jobs; `ty` is not in CI; the Python job deselects `fixtures` and `decbench`
- "baselines gate nothing" → `baseline.json`/`structural_baseline.json` gate in `decompiler-fixtures.yml`; `arch_baseline.json`/`defuse_baseline.json` do not
- `dev-oracle` is in no `feature-build-gate.sh` lane — remove it from the list of what the gate builds
- delete the test counts, or replace with a test that asserts them
- delete the cm.py historical note, the "re-counted 2026-08-31" meta-paragraph, and the "Correction, 2026-08-31" paragraph

### 5.2 New `AGENTS.md` — **keep the filename, make it a ~20-line pointer**

Not a symlink: some tools fetch it via raw-content APIs that do not resolve symlinks, and a
symlink loses the ability to say anything tool-specific. Not a merge into one file either — the
filename is the cross-vendor convention and dropping it silently degrades every non-Claude agent
that looks for it. Proposed content:

```
# AGENTS.md

Canonical instructions for any agent working in this repository live in CLAUDE.md.
Read it first and follow it; this file exists so tools that look for AGENTS.md find the pointer.

## The one rule that is never waived
[DecBench upstream boundary — 6 lines, or a link to CLAUDE.md#decbench]

## The four commands
uv sync --locked --dev
uv run maturin develop            # after ANY Rust change
cargo test --features python-ext  # NOT bare `cargo test`
uv run pytest python/tests/ && uvx ruff check python/ && uvx ty check python/

Everything else: CLAUDE.md.
```

Deleted from AGENTS.md: the entire "Production Mindset" section, the validation checklist, the
"Before Saying Done" block, all duplicated style guidance, and the three bare-`.` lint commands
(#A8). Rescued into CLAUDE.md: the coverage command (#A6).

**Also fix, since it is the same inconsistency:** `scripts/typecheck-python.sh` runs
`uvx ty check python/glaurung` while CLAUDE.md says `uvx ty check python/`. Pick one and make
the script and the doc agree.

### 5.3 New `README.md` — **revise, do not rewrite** (~200 lines)

README is the healthiest of the three files; a from-scratch rewrite would lose the careful,
honest framing earned in `bab803fd`. Keep the structure exactly; change five things:

1. **Add Git LFS to Install from source** (blocking defect, #R18):
   `git clone …; cd glaurung; git lfs install && git lfs pull; uv sync --locked --dev`.
   Add one sentence explaining that without it every `samples/` binary is a 130-byte pointer.
2. **Python floor 3.11 → 3.12** (#R12), and separately fix `pyproject.toml:22`'s stale
   `Python :: 3.11` classifier, which contradicts `requires-python` and pyproject's own comment.
3. **`cargo test` → `cargo test --features python-ext`** in the Development section (#R40).
4. Optionally add `rust-version = "1.88"` to `Cargo.toml` so the README's Rust floor is enforced
   rather than merely asserted (#R13).
5. Update the CLAUDE.md/AGENTS.md link sentence once AGENTS.md becomes a pointer.

### 5.4 Ground truth established (for other auditors / the plan writer)

- **CLI subcommands: 44**, from `python/glaurung/cli/main.py:27-85` — triage, strings, symbols,
  disasm, cfg, ask, decompile, explain, name-func, repl, graph, detect-packer, diff, kickoff,
  patch, verify-recovery, export, undo, redo, xrefs, frame, strings-xrefs, view, find, bookmark,
  rename, comment, label, proto, journal, classfile, java, java-recovery-report, luac, pe,
  windows-risk, types, windows, locks, group (plus a few registry lines not shown).
- **Cargo features (12 names):** `default=["triage-core"]`, `triage-core`, `triage-heuristics`,
  `triage-containers`, `triage-parsers-extra=["goblin","pelite"]`,
  `python-ext=["pyo3","pyo3/extension-module","exec"]`, `exec`, `symbolic=["exec"]`,
  `dev-oracle=["exec","dep:unicorn-engine"]`, `solver-z3=["symbolic","dep:z3"]`,
  `solver-axeyum=["symbolic","dep:axeyum-solver","dep:axeyum-ir"]`,
  `solver-bitwuzla=["symbolic"]`, `solver-axeyum-text=["solver-axeyum","axeyum-solver/full"]`.
- **`feature-build-gate.sh` lanes: exactly 12** (list in #48).
- **Benches: 10** (`benches/`), not the 5 CLAUDE.md documents. The 5 undocumented: `triage`,
  `entropy`, `strings`, `lang_detect`, `emulator` (last requires `exec`).
- **Python test files: 461.** **Rust `#[cfg(test)]` files in `src/`: 276**, plus **25** integration
  files in `tests/*.rs`. `src/python_bindings/` contains **32** `#[test]` attributes across 20 files.
- **`src/symbolic/`: 26 files, 21,459 LOC** (CLAUDE.md exact).
- **Decompiler fixtures: 219 `.c` files** in `tests/decompiler_fixtures/src/`, one shared
  `manifest.py`, one `sets.toml`, and **four** baselines (`baseline.json`, `structural_baseline.json`,
  `arch_baseline.json`, `defuse_baseline.json`) plus `stripped_divergences.json`.
- **Fuzz targets: 8** (containers_detect, demangle_all, disasm_decode, entropy_analyze,
  formats_parse, headers_validate, parsers_parse, sniffers_sniff).
- **Workflows: 10** — CI, decompiler-fixtures, feature-build-gate, fuzz-nightly, perf-nightly,
  samples-docker, test-suite, windows-corpus-guard, windows-ghidra-parity-refresh,
  windows-target-pipeline.
- **`ty` runs in no workflow.** ruff (format + check, `python/` only) runs in `test-suite.yml`.
  `tools/*.py` (~50 files) and `conftest.py` are linted by nothing.
- **`GLAURUNG_*` env vars actually referenced in `python/glaurung/` (18):** CACHE_DIR,
  INPUT_TOKENS_LIMIT, JVM_TOOLS_JAR, LLM_MODEL, LLM_TEMPERATURE, MAX_FILE_SIZE, MAX_OUTPUT_TOKENS,
  MAX_READ_BYTES, OPENAI_SERVICE_TIER, PDB_CACHE, PROJECT_ROOT, REQUEST_LIMIT, REQUIRE_LLM,
  TOOL_STRICT, TOTAL_TOKENS_LIMIT, TYPES_DIR, VERIFY_DEFS, WINDOWS_ANALYSIS_CONFIG.
  **`GLAURUNG_AGENT_ROUTE` is not among them and appears nowhere but CLAUDE.md.**
  (Additional vars live in Rust/CI: `GLAURUNG_REQUIRE_TOOLCHAINS`, `GLAURUNG_FIXTURE_TMPDIR`,
  `GLAURUNG_FIXTURE_OBSERVED`, `GLAURUNG_RUN_DECBENCH`, `DECBENCH_DIR`.)
- **`.claude/` contains one file** and **no settings JSON** anywhere in the repo.
- **`docs/` has 23 top-level entries**; CLAUDE.md's doc map names 7 of them.
