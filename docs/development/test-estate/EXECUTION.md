# Execution log

Live status for [`README.md`](README.md) (the estate plan) and
[`../decompiler-parity-backlog.md`](../decompiler-parity-backlog.md) (the
parity backlog). `[x]` landed and verified, `[~]` in flight, `[ ]` not started.

**This file is the todo list.** `TodoWrite` is not available in this session's
toolset, so the plan lives here instead — which is more durable anyway, since
it survives the session and is reviewable in a diff.

The full-corpus evidence update and cross-plan priority order live in
[`../real-binary-decompiler-roadmap-2026-08-31.md`](../real-binary-decompiler-roadmap-2026-08-31.md).
Its missing-body ledger is
[`../../design/decbench-full-failure-taxonomy-2026-08-31.md`](../../design/decbench-full-failure-taxonomy-2026-08-31.md).

## Landed

| item | plan ref | commit |
|---|---|---|
| [x] Symbol-table names for static storage | parity #1 | `dfd2ddb4` |
| [x] `tools/compare_decompilers.py` | parity #7, #10 | `dfd2ddb4` |
| [x] 63 never-parsing metadata files deleted | estate 9.1 | `937425d0` |
| [x] `assets/` cut to the 2 referenced files (-12.9 MB) | estate 9.3 | `937425d0` |
| [x] `scripts/setup-references.sh` deleted | estate 9.4 | `937425d0` |
| [x] Comparison-guard fusion | parity #2 | `96948a4b` |
| [x] Ten dead `tests/triage/` files wired (+28 tests) | estate 1.2 | `6d865bc7` |
| [x] PE32+ optional-header offsets | (found by 1.2) | `6d865bc7` |
| [x] IPv4 classifier overflow panic | (found by 1.2) | `6d865bc7` |
| [x] Triage JSON determinism | (found by 1.2) | `6d865bc7` |
| [x] Arch-guess `HashMap` order leak | (found by 1.2) | `6d865bc7` |
| [x] UPX confidence calibration + dead config knob | (found by 1.2) | `6d865bc7` |
| [x] `samples/adversarial/` fixtures repaired | (found by 1.2) | `6d865bc7` |
| [x] CI runs `cargo test` and the Python suite | estate 1.5 | `f6ade219` |
| [x] Named constants for syscall arguments | parity #5 | `9b8be51b` |
| [x] Fuzz crate in a gate lane (12 lanes now) | estate 3.1 | `78ad620e` |
| [x] Three deeper fuzz targets + seed generator | estate 3.2, 3.3 | `f57014dc` |
| [x] Inventory regenerated: 89 -> 77 unreachable | — | `c320b3f7` |
| [x] Reachability ratchet (15 tests) | estate 1.1 | `95249c54` |
| [x] Three CWD-dead Python files fixed | estate 1.4 | `95249c54` |
| [x] `-ra` for visible skips | estate 1.6 | `95249c54` |
| [x] Demangle corpus (2,115 pairs) + versioned-symbol fix | estate 5.1 | `4c0f2ffe` |
| [x] Perf ratchet, instructions-based | estate 6 | `a5f47189` |
| [x] Full Python suite green | — | `4c0f2ffe` |
| [~] Go fixtures: toolchain + lanes wired, opt-in | estate 7.1 | `6660f1f7` |
| [x] target: 396-spec conformance table | estate 5.4 | `36d0e0f3` |
| [x] similarity: measured retrieval ratchets | estate 5.2 | `36d0e0f3` |
| [x] flirt: recall + false-positive + prologue sweep | estate 5.3 | `36d0e0f3` |
| [x] CTPH panic reachable from Python, fixed | (found by 5.2) | `36d0e0f3` |
| [x] Perf baseline recorded and verified both ways | estate 6 | `a938d897` |

## Next

| item | plan ref | state |
|---|---|---|
| [ ] i386 stdcall identity fixture + collision-safe normalization | real-binary R1 / failure F1a | proven cause of 33 pinned rows |
| [ ] External/import disposition contract | real-binary R1 / failure F1b | 63 rows have no local body |
| [ ] Dataset manifest/source-CFG/binary consistency validator | real-binary R1 / failure F1c | 88 manifest-only rows |
| [ ] gzip `__printf__` source/build provenance trace | real-binary R1 / failure F1d | 2 source-CFG-only rows |
| [ ] PE entry/TLS/import identity fixture | real-binary R1/R4 | write failing fixture first |
| [ ] Minimal clang-cl PE32/PE32+ identity lane | estate 4 / real-binary R4 | O0/O2, map+PDB, local/import/thunk dispositions |
| [ ] Hermetic PDB type/layout lane | estate 4 / real-binary R4 | source declarations through recovered fields and prototypes |
| [ ] Mach-O x86-64/ARM64 thin and universal lanes | estate 4 / real-binary R4 | body/DWARF/stub/fixup/slice identity oracles |
| [ ] Rescope fetched Microsoft PE/PDB tests | estate 4 / real-binary R4 | migrate generic assertions; fail provisioned lane on zero pairs |
| [ ] Cortex-M MRS/MSR body-recovery fixture | real-binary R1 / failure F2a | proven common cause of all 31 F2 rows |
| [ ] `@large` source-grounded corpus + phase/resource ratchets | real-binary R2 | specify smallest tier first |
| [ ] Promote realistic corpus beyond discovery-only evidence | real-binary R5 | body accounting, semantic subset, signal predicates, mandatory release lane |
| [ ] Source-grounded PE hostile-shape family | real-binary R4/R5 | PE32/PE32+, identity/TLS/SEH/import oracles |
| [ ] Source-grounded ARM64/Cortex-M hostile family | real-binary R1/R5 | ARM64 parity plus independent F2a guard |
| [ ] Page-align fixture + symbol-snapping guard | parity #9 | needs 4 baselines |
| [ ] Pointer/array render (`char **argv`) | parity #6 | |
| [ ] Variadic / call-site arity | parity #3 | |
| [ ] Inlined-body register threading | parity #4 | |
| [ ] Go fixtures: manifest entries + 4 baselines | estate 7.1 | wiring landed; needs a quiet machine |
| [ ] Structural baseline at O2 | estate 7.5 / parity #8 | |
| [ ] Structural schema v2 + GCC/Clang O0/O2 populations | estate 7.5 / real-binary R3 | preserve lane denominators and binary hashes |
| [ ] Optimized shape/readability predicates | estate 7.5 / real-binary R3 | loops, switches, conditions, casts, temporaries, output expansion |
| [ ] Canary + determinism in the default suite | estate 2 | |
| [ ] Make current perf gate fail closed | estate 6 / real-binary R6 | no baseline; missing/unit-mismatch/partial evidence currently exits zero |
| [ ] Record provenance-complete release perf baseline | estate 6 / real-binary R6 | wait for clean committed Rust tree and exact release build |
| [ ] Join perf with completeness, RSS, and determinism report | estate 2/6 / real-binary M7 | reuse profiler and existing determinism tests |
| [ ] `samples/` 18.8 MB dedup | estate 9.2 | investigated, see below |

## Findings worth keeping

**The inventory was wrong about one thing.** `docs/test-inventory/findings.md`
says two of the three CWD-dead Python files are duplicates. They are not:
`test_symbols_demangled.py` calls `list_symbols_demangled` directly while
`test_demangle_integration.py` checks the same evidence surviving a full
`analyze_path`. Both were kept.

**The 18.8 MB duplication is not a straight delete.** 85 md5-identical pairs,
but same-relative-path is *not* proof of identical content — `mathlib.dll`
exists at both paths and differs. Five pairs are referenced from both sides
and need repointing first. Do this per-file, verifying content, not by path.

**CTPH does not work at function granularity.** Measured, not assumed: 0.32%
top-1 against a global pool (chance 0.09%), 20% same-binary (chance 12%), and
a sweep over ten parameter triples did not rescue it. Any KB feature ranking
candidates by this score is ranking noise. The ratchets now pin the honest
numbers so an improvement is visible and a regression is caught.

**`src/flirt/` is not FLIRT.** It reads neither `.sig` nor `.pat` -- a bespoke
JSON of prologue bytes, matched by exact equality over 32 bytes, no wildcard
mask or CRC. And 19 of the 20 functions in the one committed static library
have a relocation inside that window, so signatures built from static archives
match linker placeholders. That is the matcher's ceiling, not our corpus.

**Two FLIRT defects documented, not fixed** (both need a decision, not a
patch): `FlirtLibrary::from_file` resolves ambiguous prologues
last-insert-wins, and with `set_by=flirt` outranking `auto` the losing name
lands in the KB above the correct one; `prologue_len` is unenforced input.

**`scripts/lint-rust.sh` is red**: 255 clippy errors on the lib target, 296
with tests, under `-D warnings`. Left alone deliberately; it is a decision to
make, not a thing to silently delete.

**Skips are now visible: 41 of them**, 21 waiting on the gitignored
`tests/fixtures/msvc-pdb/` binaries that nothing fetches (estate 1.7), 7 on
`GLAURUNG_IOCTL_FIXTURES`, 4 on live-LLM opt-in.

## Ground rules

Verified before any claim of done: `cargo test --features python-ext`,
`uv run pytest python/tests/`, `uvx ruff check python/`, `uvx ty check
python/`, and `dectest @o0 @o2` for anything touching the decompiler.
`TMPDIR` exported. No DecBench, no Joern. Every fixture change refreshes the
six side files.

**A readability change is a semantic change.** The comparison-guard fusion
looked purely cosmetic and turned eleven execution-differential lanes red on
its first version. The fixture matrix is the thing that knows.
