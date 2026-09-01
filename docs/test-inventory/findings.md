# What the survey found

Five surveys walked disjoint territories: the Python suite, the Rust tests and
targets, the binary assets, the fixture corpora, and the tooling. Counts below
were obtained by counting. Where a claim contradicted `CLAUDE.md` or a project
doc, it was re-verified by hand before being written down; those corrections are
marked.

## 1. Almost nothing is enforced automatically

**No CI workflow runs `cargo test`.** Zero invocations across all seven
workflows; the single occurrence of the string is a comment in
`feature-build-gate.yml:14` explaining that the lane is deliberately `cargo
check` and not `cargo test`. The only `cargo` CI actually runs is
`scripts/feature-build-gate.sh` (11 `cargo check` lanes) and `cargo fmt
--check`. The sole automated caller of `cargo test` is
`scripts/decbench-local-gate.sh` lane 1 — local, opt-in, roughly 50 minutes.

**No CI workflow runs the general Python suite.** `CI.yml` builds and publishes
wheels. Across all workflows exactly **6 of 445** Python test files execute.
The other **439 run only when a human types `uv run pytest`**.

The estate is inverted: the expensive slow matrix runs on every push, and the
cheap 439-file suite has no workflow at all.

## 2. Ten Rust integration files are tracked and never compiled

`tests/triage/mod.rs` declares four modules — `budgets`, `io`, `real_files`,
`sniffers`. Ten further `.rs` files sit beside it, named by no `mod` anywhere:

```
adversarial  determinism_json  entropy_real  ioc_integration  packers_real
suspicious_integration  symbols_elf  symbols_macho  symbols_pe  truncation_json
```

**28 tests that never run**, including the whole UPX packer suite, entropy over
real samples, and the adversarial suite whose stated purpose is that a truncated
ELF/PE/gzip *must error rather than panic*.

`tests/register_view_semantics.rs` is `#![cfg(feature = "exec")]` at line 24, so
a plain `cargo test` compiles it to an empty target **and reports it passing**.
That is 24 tests, and the only thing closing the lifter↔emulator loop.

## 3. Feature gates hide 11% of the Rust suite

`cargo test` reaches **2,777 of 3,132** test functions.

| gate | files | LOC | hidden tests |
|---|---:|---:|---:|
| `symbolic` | 26 | 21,459 | 110 |
| `exec` | 10 | 3,591 | 89 |
| `solver-*` | 7 | — | 85 |
| `python-ext` | 20 | 10,429 | 32 |

**Three corrections to `CLAUDE.md`**, each verified here: `src/symbolic/` is 26
files and 21,459 LOC, not 21 and 14,649 — it has grown 46%; its gate is at
`src/lib.rs:80`, not line 65 (which is now `pub mod decompile;`); and the
"~120 python-ext tests" are 32 in the bindings, the other 89 arriving because
`python-ext` implies `exec`.

## 4. Tests that cannot pass, and skips that look like passes

* **Three permanently dead Python files.** `test_symbols_demangled.py`,
  `test_demangle_integration.py` and `test_view_function_tools.py` hardcode
  `"../samples/..."` **CWD-relative**, which resolves outside the repository from
  every plausible working directory. Two of the three are duplicates of each
  other.
* **13 files / 142 tests** wait on `tests/fixtures/msvc-pdb/*.exe|dll`, which are
  gitignored and fetched on demand — and **nothing in the repository calls
  `fetch.sh`**. The fixture README's claim that "test invocations call fetch.sh
  first; CI caches the result" is not true of any file in the tree.
* **176 Python files call `pytest.skip()` at runtime** and `addopts` has no
  `-ra`, so a run with 200 silent skips is visually identical to a clean one.
* `test_cli_explain*.py` gate on a path under `/tmp`, which this project is
  forbidden from writing to and which `TMPDIR` is exported away from. It can
  never exist.

**Correction to `CLAUDE.md`:** it states that
`test_decompiler_defuse_census.py` "needs `-m ""` to run at all". That is false
against the current `pytest.ini`, which deselects only `decbench` — the census
*is* collected by the default run, verified by collecting it. The real gap is
the bullet's second half: iteration happens through `tools/dectest.py`, which is
not pytest.

## 5. The benches gate nothing

Ten criterion targets, **no baseline for any of them**, and nothing anywhere
invokes `cargo bench`. A change that doubles decompile time still ships green.

The five newest also read the **gitignored** `tests/decompiler_fixtures/build/`
and print-and-return when it is absent, so `cargo bench` on a fresh checkout
succeeds having measured nothing.

`fuzz/` is a separate crate, not a workspace member, so `cargo check
--all-targets` never sees it in any gate lane; no CI calls `cargo fuzz` and no
corpus is committed.

## 6. Only one ratchet runs by default, and it is not about behaviour

| baseline | entries | how it runs |
|---|---:|---|
| `baseline.json` | 3,456 verdicts | `-m slow` |
| `arch_baseline.json` | 9,809 verdicts | `-m slow`; gate lane 3, ~35 min |
| `structural_baseline.json` | 2,253 | `-m slow`, gcc -O0 only |
| `defuse_baseline.json` | 3,140 | `-m slow`; in practice only via the ~50 min gate |
| `stripped_divergences.json` | 95 | `-m slow`, O2 only |
| `tools/fitness_baseline.json` | 23 | **default suite — the only one** |

The single ratchet in the default run is a **code-size** check. Every
behavioural baseline is `slow`-marked.

## 7. Committed weight nothing reads

* `assets/` is **92% unreferenced** — 12.76 MB of 13.8 MB, including a 9.5 MB
  `glaurung-logo-full.png`. Only the README banner and `glaurung-original.png`
  are used, the latter as a genuine triage negative-case fixture at
  `src/triage/api.rs:807`.
* `samples/binaries/metadata/` — **all 63 files fail `json.load`**, containing
  literal `\n` two-character sequences instead of newlines. They describe host
  binaries (bash, gcc, clang-20, initrd.img) absent from the corpus. Nothing
  reads them. The other 339 metadata sidecars parse.
* **18.8 MB of exact duplication** — 85 byte-identical pairs between
  `samples/binaries/linux/amd64/export/` and the legacy tree, md5-confirmed,
  including a 4.5 MB `hello-rust-debug`. Both sides are live, referenced by
  different tests; the bytes simply exist twice.
* `scripts/setup-references.sh` calls `git submodule add` against repositories
  that are no longer submodules — `.gitmodules` was removed. It cannot work.
* `scripts/lint-rust.sh` runs `cargo clippy --all-targets --all-features` and
  would catch much of §3, but nothing calls it and it is currently red with
  ~260 pre-existing errors under `-D warnings`.

## 8. Corpus gaps

* **Five Go fixtures (176–180) and one `.S` are written but not wired in** — no
  binaries, no verdicts in any of the six baselines, no Go toolchain in
  `tools/fixture_harness.py`, whose source glob covers `.c`, `.cpp` and `.rs`
  only. The visible symptom is a numbering gap: reports run 175 then 181.
  Recorded in `docs/development/decompiler-curriculum-corpus.md`.
* **Fixture 200 does not exist** — the numbering jumps 199 → 201, undocumented.
* `java/glaurung-jvm-tools` self-builds at runtime via `mvn -DskipTests
  package`; its five JUnit tests run nowhere.

## 9. What the suite is actually about

| domain | Python files |
|---|---:|
| llm | 220 |
| windows | 146 |
| decompiler | 75 |
| java | 53 |
| **entire native surface combined** | **39** |

Half the Python suite tests the LLM surface. And **59 files test `tools/`
scripts rather than the product** — the three highest test counts in the suite
(`arch_roundtrip` 90, `fixture_harness` 84, `dectest_selection` 68) are all
tests of the test harness.

Rust test mass is equally lopsided: `src/ir/` holds **1,847 test functions, 62%
of the unit suite**, while `src/target/` has 1, `src/demangle/` 1, and
`src/similarity/` 2.
