# Execution log

Live status for [`README.md`](README.md) (the estate plan) and
[`../decompiler-parity-backlog.md`](../decompiler-parity-backlog.md) (the
parity backlog). `[x]` landed and verified, `[~]` in flight, `[ ]` not started.

**This file is the todo list.** `TodoWrite` is not available in this session's
toolset, so the plan lives here instead — which is more durable anyway, since
it survives the session and is reviewable in a diff.

The full-corpus evidence update and cross-plan priority order live in
`docs/development/real-binary-decompiler-roadmap-2026-08-31.md`, and its
missing-body ledger in
`docs/design/decbench-full-failure-taxonomy-2026-08-31.md`.

> Both are written by a concurrent session and are **not committed yet**, so
> they are named here as plain paths rather than links: a link to an untracked
> file resolves in the author's working tree and is broken in every clone.
> Turn these back into links when those documents land.

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
| [x] CI reads real binaries (Git LFS) | estate 1.5 | `40ebe2cc` |
| [x] Host-compiler test scoped to validated majors | (found by CI) | `09f4d511` |
| [x] Canary set: default suite exercises the decompiler | estate 2 | `b4d23221` |
| [x] Determinism: same bytes in-process and cross-process | estate 2.3 | `b4d23221` |
| [x] Nightly fuzz runner + "is it run" invariant | estate 3.4 | `665fe25d` |
| [x] 74 unreachable entries classified into 5 buckets | — | `1f819d63` |
| [x] 12 test files anchored off CWD (21 silent skips) | estate 1.7 | `c26b2464` |
| [x] conftest sample paths anchored (59 usages) | estate 1.7 | `62bda4cc` |
| [x] Structural lane seam + the O2 measurement | estate 7.5 | `b02b5883` |
| [x] Readability census at O2 (1,502 entries) | estate 7.5 | `225088fb` |
| [x] Dispatch-loop defect located to one guard | parity/estate 10 | `294d2a2d` |
| [x] CI cross-toolchain + compile-probe availability | estate 10 | `c5f7df15` |
| [x] Concurrent session's 11 planning docs landed | — | `dbf4f5ca` |
| [x] Fixture gallery regenerated + arch lanes rendered | — | glaurung.dev |
| [x] Census -> both corpora, both O-levels (3,580 entries) | estate 7.5 | `1329382d` |
| [x] Dispatch relaxation judged and REVERTED on its evidence | parity/estate 10 | `1329382d` |
| [x] i386 stdcall resolver + real PE32 fixture (F1a, 33 rows) | real-binary R1 | `0d6b30d1` |
| [x] `symbol_table_entries` binding (kind + definedness) | (needed by F1a c5) | `0d6b30d1` |
| [x] Import disposition, explicit not absent (F1b core) | real-binary R1 | `0d6b30d1` |
| [x] `list_symbols` reported hardcoded False for 6 fields | estate 4 / R4 | `610d3afd` |
| [x] `pdb_path` PyO3 getter (field existed, was unreachable) | estate 4 / R4 | `610d3afd` |
| [x] RSDS scan read 199,416 bytes short of the record | estate 4 / R4 | `610d3afd` |
| [x] clang-cl/lld-link lane: measured, 3 caveats recorded | estate 4.1 | doc |

## Findings that change a plan's premise

Recorded here rather than edited into the plan documents, several of which have
uncommitted local edits that are not mine to touch.

**`decbench-failure-remediation-plan` Increment C (F2a) had the wrong layer.**
It is written as an ARM32 *lifter* gap -- "Packet tests in
`src/ir/lift_arm32.rs`... assert mnemonic-specific intrinsic" -- and the lifter
was never reached. Capstone **rejected** every Cortex-M system-register
encoding: `mrs r1, BASEPRI` (`f3ef 8111`) returned `InvalidInstruction`, and a
function whose first instruction cannot be decoded is abandoned whole. That is
why the symptom was 31 rows with no body rather than 31 bodies full of opaque
unknowns. Three defects were stacked, each hidden by the one above it: no
Cortex-M decoder mode, `ArmOperandType::SysReg` discarded by the operand
match's catch-all, and only then the lift the plan describes. Fixed in
`0031c3ee`; the plan's third bullet was correct and the first two were
invisible from where it was written.

The plan's "RED at three layers" structure is what found this -- layer 1 failed
for a reason layer 1 could not have predicted. The generalisation for future
increments: **confirm the instruction decodes before specifying how it lifts.**

**`test-estate/07-matrix-extension.md` 7.5 assumed the wrong lane.** "O0
structuring is nearly free, O2 is where goto-soup happens" is true of the
absolute counts and is exactly why a census scoped to O2 measures where the
least is at risk. All seven readability regressions from the
`detect_raw_dispatch_loop` experiment were at **-O0**. Annotated in place, in a
file I own.

**`test-estate/04-pe-macho.md` overstated the clang-cl lane.** `lld-link`
cannot link without the MSVC import libraries; `/nodefaultlib` is required,
which makes every fixture in that lane freestanding, and lld emits no TLS
directory for such a DLL at all. Annotated in place.

## Next

Test-automation work (R8) heads the list deliberately: every other item's
evidence depends on gates that actually run and actually assert.

| item | plan ref | state |
|---|---|---|
| [ ] Close the local/CI denominator gap | R8.4 / phase 10 | CI lacks cross toolchains and the built fixture dir; difference absorbed, not reported |
| [ ] Widen the thinnest format/arch cells | R8.5 | 1 macOS sample, 0 MIPS/PPC64 under test; Mach-O thin lanes `ba2fe5c2` are the template |

| item | plan ref | state |
|---|---|---|
| [ ] Dataset manifest/source-CFG/binary consistency validator | real-binary R1 / failure F1c | 88 manifest-only rows |
| [ ] gzip `__printf__` source/build provenance trace | real-binary R1 / failure F1d | 2 source-CFG-only rows |
| [x] PE entry/TLS/import identity fixture | real-binary R1/R4 | `99113bc8` |
| [x] TLS callbacks read from the wrong struct offset | estate 4 / R4 | `99113bc8` |
| [x] parity #4 located: an intervening-read gate, not inlining | parity #4 | `576db136` |
| [x] parity #4 both candidates measured and REVERTED | parity #4 | `e8dafd33` |
| [x] Cortex-M sysregs undecodable (F2a, 31 rows) | real-binary R1 / F2a | `0031c3ee` |
| [x] MClass fallback decoder + SysReg operand + MRS/MSR lift | real-binary R1 / F2a | `0031c3ee` |
| [x] Cortex-M MRS/MSR body-recovery fixture | real-binary R1 / F2a | `0031c3ee` |
| [x] Hermetic PDB type/layout lane | estate 4 / R4 | `c7200d2d` |
| [x] clang-cl PE32/PE32+ identity lane | estate 4.1 / R4 | `8c0a89f6` |
| [x] Resolver was COFF-only, blind to shipped Windows binaries | estate 4 / R4 | `8c0a89f6` |
| [x] Mach-O x86-64 + ARM64 thin lanes | estate 4 / R4 | `ba2fe5c2` |
| [x] AArch64 scalar FP immediate dropped by the decoder | estate 4 / R4 | `ba2fe5c2` |
| [x] AArch64 FMA lifting measured and REVERTED | estate 4 / R4 | `ba2fe5c2` |
| [x] samples duplication measured, corrected and ratcheted | — | `dc4c9759` |
| [x] R8.1 silent toolchain gates -> recorded, demanded in CI | R8.1 | `1b9f19c9` |
| [x] R8.2 `cargo test` decompiles a real binary end to end | R8.2 | `55246eff` |
| [x] R8.3 per-module census: 271 tests no gate executes | R8.3 | `753bf1dd` |
| [x] R6 A+G perf gate fails closed, and is finally scheduled | R6 P1/P2/P3/P9 | `4f4f88e3` |
| [~] Mach-O universal (fat) lane | estate 4 / R4 | thin x86-64+ARM64 landed `ba2fe5c2`; fat slices still open |
| [ ] Rescope fetched Microsoft PE/PDB tests | estate 4 / real-binary R4 | migrate generic assertions; fail provisioned lane on zero pairs |
| [ ] `@large` source-grounded corpus + phase/resource ratchets | real-binary R2 | specify smallest tier first |
| [ ] Promote realistic corpus beyond discovery-only evidence | real-binary R5 | body accounting, semantic subset, signal predicates, mandatory release lane |
| [ ] Source-grounded PE hostile-shape family | real-binary R4/R5 | PE32/PE32+, identity/TLS/SEH/import oracles |
| [ ] Source-grounded ARM64/Cortex-M hostile family | real-binary R1/R5 | ARM64 parity plus independent F2a guard |
| [ ] Page-align fixture + symbol-snapping guard | parity #9 | needs 4 baselines |
| [ ] Pointer/array render (`char **argv`) | parity #6 | |
| [ ] Variadic / call-site arity | parity #3 | |
| [ ] Inlined-body register threading | parity #4 | |
| [ ] Go fixtures: manifest entries + 4 baselines | estate 7.1 | wiring landed; needs a quiet machine |
| [~] Structural baseline at O2 | estate 7.5 / parity #8 | readability census landed; closure/effects map still needs a lane key |
| [ ] Structural schema v2 + GCC/Clang O0/O2 populations | estate 7.5 / real-binary R3 | preserve lane denominators and binary hashes |
| [ ] Optimized shape/readability predicates | estate 7.5 / real-binary R3 | loops, switches, conditions, casts, temporaries, output expansion |
| [ ] Make current perf gate fail closed | estate 6 / real-binary R6 | baseline exists; missing/unit-mismatch/partial evidence currently exits zero |
| [ ] Record provenance-complete release perf baseline | estate 6 / real-binary R6 | wait for clean committed Rust tree and exact release build |
| [ ] Join perf with completeness, RSS, and determinism report | estate 2/6 / real-binary M7 | reuse profiler and existing determinism tests |
| [~] `samples/` dedup: 22.4 MB, ratcheted not deleted | — | needs a canonical-tree decision, `dc4c9759` |

## Verified state, 2026-09-01

| gate | result |
|---|---|
| `cargo test` (**default**, no features) | **2,829 passed, 0 failed, 4 ignored** |
| `cargo test --features python-ext` (local) | **2,951 passing** |
| `uv run pytest python/tests/` (local) | **3,724 passed, 0 failed** |
| `uv run pytest python/tests/` (**CI**) | 25 environment-only failures — see [phase 10](10-ci-environment-gap.md) |
| `dectest @o0 @o2` + 4 arch lanes | 1,644 of 3,304 lanes, no regressions |
| def-use census / structural / fitness | 6 / 24 / 40 passed |
| perf gate | passes; verified it also FAILS an injected 10% regression |
| feature build gate | 12/12 lanes |
| ruff + ty (local and CI) | clean |

The plain `cargo test` row is new and is the one a Rust contributor actually
runs. The 122-test difference from `--features python-ext` is
`src/python_bindings/`, which a bare `cargo test` does not even compile.

The 25 CI-only failures are environment, not product: no cross toolchains and
no built fixture directory on the runner. That gap is phase 10, opened by the
run that found it.

## Findings worth keeping

**The inventory was wrong about one thing.** `docs/test-inventory/findings.md`
says two of the three CWD-dead Python files are duplicates. They are not:
`test_symbols_demangled.py` calls `list_symbols_demangled` directly while
`test_demangle_integration.py` checks the same evidence surviving a full
`analyze_path`. Both were kept.

**The duplication figure was stale, and larger: 22.4 MB, not 18.8.**
Re-measured by sha256 on 2026-09-01: 75 groups of byte-identical files. The
tree the old note named (`samples/binaries/linux/amd64/export/` and "the legacy
tree") no longer exists; the duplication is between
`platforms/linux/amd64/export/` and its siblings. Of the 75 groups, 6 have
every copy referenced by literal path. The other 123 redundant copies are named
by no literal path — which is *not* proof they are unused, because much of the
suite globs `samples/**`, so a delete sweep would shrink test populations
silently rather than fail. Ratcheted instead (`dc4c9759`); choosing a canonical
tree is a corpus decision.

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

**-O2 is where readability goes.** Measured through the new structural lane
seam on `212_loop_with_returning_arm::fsm_returns_from_arm`: `gcc:O0` gives 5
`goto` and 1 `switch`; `gcc:O2` gives 11 `goto` and **no** `switch`. The
execution differential passes the fixture in both lanes, because the behaviour
is correct. Nothing in the gate can currently see that the output stopped
being readable — which is phase 7.5, now with a number attached.

**Two things that were true in the working tree and false in the repository.**
`git add` on the canary directory skipped all nine `.so` objects silently,
because `.gitignore` carries a blanket `*.so` -- so a commit landed tests and
a manifest describing binaries that were not there. And a link check that
passed against the working tree found four broken links when run against
`git archive HEAD`. Check what a CLONE gets, not what your disk has.

**A structuring gap on another clang, found by CI.** `cfg.rs`'s
`clang_o2_statemachine_retains_cross_block_dispatch_edges` compiles a fixture
with the HOST clang and asserts the four-way dispatch stays inside its loop.
On clang 21 it does; on a GitHub `ubuntu-latest` runner's clang the structurer
returned `Unstructured` for the same source. The CFG half is
version-independent and still asserted unconditionally -- it is only the
STRUCTURING claim that is now scoped to validated compiler majors, and the
test prints which version it saw and whether the property held. Worth its own
investigation: it is a real gap on a real compiler's output, not a flake.
Eight tests in that module shell out to a host compiler and have the same
latent exposure.

**The default suite measures one thing well and nine things barely.** Measured
2026-09-01, by module: `ir` holds **1,867 of 2,859** named tests — 65% of the
suite is decompiler IR internals — against `analysis` 264, `core` 183, `triage`
106, `formats` 99, `strings` 33, `symbols` 22, `entropy` 20, `disasm` **19**,
and `decompile` **4**, all four of which test the profiler wrapper rather than
decompilation. There is no end-to-end decompile in the default Rust suite.

Its real-binary coverage is narrower still: 75 distinct sample paths across all
Rust tests — **55 Linux, 9 Windows, 1 macOS** — and by language 22 native, 3
rust, 3 go, 2 java, 2 dotnet, 1 fortran, with the non-C entries used for format
work rather than decompilation. Four cross-compiled targets appear as real
binaries (`windows-x86_64`, `armhf`, `arm64`, `riscv64`); MIPS, PPC64 and s390x
appear only in strings and comments.

**No Rust test uses `tests/decompiler_fixtures/` as a corpus.** The fixture
matrix that proves the decompiler correct is driven entirely from Python, so
`cargo test` cannot fail on a decompilation regression. Individual `src/` tests
`include_bytes!` single fixture *sources* and compile them ad hoc, which is a
much weaker guarantee.

**Twenty Rust tests pass without testing anything.** `Err(error) if
error.kind() == std::io::ErrorKind::NotFound => return` — a test that compiles
a fixture and cannot find its compiler returns `ok` having asserted nothing.
Not skipped, not reported, indistinguishable from a pass. On a machine without
cross-compilers an unknown fraction of the 2,829 is vacuous and the total does
not move. This is the `-ra` problem of phase 1.6 one layer down, and worse:
these are not skips, so no flag reveals them. Tracked as R8 in the
[roadmap package](../decompiler-roadmap-package-2026-08-31.md).

**R8, measured and closed.** The coverage findings above now have numbers
attached and gates behind them:

* **33 test executions passed while asserting nothing** on a machine without
  compilers — 23 gcc, 8 clang, 2 arm-none-eabi-gcc — measured with a PATH
  shim. On a provisioned machine the count is **0**, proven by
  `GLAURUNG_REQUIRE_TOOLCHAINS=1`, which turns a would-be silent skip into a
  failure. CI sets it and installs `gcc-arm-none-eabi` without `|| true`, so a
  provisioning failure is loud at the install step.
* The real site count was **21, not the 20 first reported**: two use
  `=> continue` inside a per-compiler loop, where a partially-provisioned
  machine tests half the matrix and reports a full pass. A grep for the
  one-line `=> return,` form missed them; the source-scan ratchet finds them
  because it looks for the guard, not the exit.
* **The correct pattern already existed.** `src/program/*_tests.rs` uses
  `.expect("host C compiler is available")` and goes red on a bare machine —
  21 tests doing the right thing while 21 sites did the wrong one.
* **271 tests are compiled and executed by nothing.** `src/symbolic/` (195)
  and `src/exec/` (76) are behind features neither `cargo test` nor
  `--features python-ext` enables, and `feature-build-gate.sh` runs
  `cargo check --all-targets`, which compiles test code without running it.
  Ratcheted: the pool may only shrink.
* **The perf gate could report success from an empty measurement**, and
  nothing invoked it. Both fixed — and in that order, because scheduling a
  fail-open gate manufactures assurance.

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
