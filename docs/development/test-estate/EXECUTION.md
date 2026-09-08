# Execution log

> **Kind:** plan · **Status:** proposed

Live status for [`README.md`](README.md) (the estate plan) and
[`../decompiler-parity-backlog.md`](../decompiler-parity-backlog.md) (the
parity backlog). `[x]` landed and verified, `[~]` in flight, `[ ]` not started.

**This file is the todo list.** `TodoWrite` is not available in this session's
toolset, so the plan lives here instead — which is more durable anyway, since
it survives the session and is reviewable in a diff.

The full-corpus evidence update and cross-plan priority order live in
[`../roadmap/real-binary-decompiler.md`](../roadmap/real-binary-decompiler.md),
under [`../roadmap/README.md`](../roadmap/README.md); its missing-body ledger
is the pinned
[failure taxonomy](../../history/design/campaigns/decbench-full-failure-taxonomy-2026-08-31.md).
Both have since landed, so they are links again.

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
| [x] ARM32 definition identity and stack-coordinate phase repairs | review WP3/WP9 | `4fa0b12f`, `a8ba1b87`, `dcdc99cc` |
| [x] Pipeline-owned request model for module/session `decompile_at` | review WP2 | `d6a65779`, closed `e7b7de67` |
| [x] Exact-range CFG/callee convergence across all four entry points | review WP2 | `5a2d6c86`, closed `e7b7de67` |
| [x] One ordered callee-preparation boundary used by all four entry points | review WP2 | `e19bd73b` |
| [x] One LLIR-to-AST stage used by all four entry points | review WP2 | `41bd90a6`, closed `e7b7de67` |
| [x] Combined symbol/data/GOT context reuses one parsed object (21 -> 20 parses) | review WP2 | `73a79d61` |
| [x] Structured single-function result with health/completeness/provenance/fingerprint | review WP2 | `5ea45dca`, closed `e7b7de67` |
| [x] All four adapters construct typed requests/results before legacy projection | review WP2 | `15d044eb` |
| [x] Pipeline-owned image-wide render context used once per adapter/batch | review WP2 | `e0588083`, closed `e7b7de67` |
| [x] Pipeline-owned DWARF/PDB context used once per adapter/batch | review WP2 | `21f8b29a`, closed `e7b7de67` |
| [x] Pipeline-owned binary-truth name/data context used once per adapter/batch | review WP2 | `2ef9c4eb`, closed `e7b7de67` |
| [x] Pipeline-owned discovery pairs exact budgets with function facts | review WP2 | `d900cf1b`, closed `e7b7de67` |
| [x] One post-lowering AST-finalization boundary used by all four adapters | review WP2 | `1e1ac0a8`, closed `e7b7de67` |
| [x] One declaration/type/style renderer used by all four adapters | review WP2 | `2f7a6149`, closed `e7b7de67` |
| [x] One lift-to-render per-function transaction used by all four adapters | review WP2 | `2ee8fa15` |
| [x] Checked coarse pipeline stages reject invalid ordering | review WP2 | `74853fcc`, closed `e7b7de67` |
| [x] Canonical 20-pass AST order rejects unknown, repeated, and backward passes | review WP2 | `4ea067df` |
| [x] Bounded AST fixpoints report rounds, firings, and termination | review WP2 | `5f7df194` |
| [x] Tracked post-SSA LLIR lifecycle: classified-only mutation gateway, reconstruction, and zero-legacy-All ratchet | review WP3 | `925dc002`, `09522773`, `bac6cef8`, `e8bec18c`, `2fe827df`, census `4bfee20c` |
| [x] Opaque SSA identity sidecar through AST lowering and role-projected loop/pointer/ABI-width/declaration/typed-view/typed-comparison/widening/consumed-extension/unsigned-literal consumers | review WP3 | `f05c9a5d`, `af65c260`, `ef444751`, `697d6358`, `ee65638e`, `48cf15a0`, `6a7ec0b5`, `05a524e8`, `49a78f31`, `17dff536`, `403296e0`, `2ccd8ce1`, `f889e200` |
| [x] Multi-output intrinsic definitions retain positional SSA identities and widths through value numbering/coalescing | review WP3 | `8bc75c71`, `ad81c123` |
| [x] First AST-native identity mutation: loop-entry coalescing returns and applies exact renames | review WP3 | `3afd711a` |
| [x] Second AST-native identity mutation: source-loop update coalescing returns and applies exact renames | review WP3 | `d8da5f13` |
| [x] Final presentation-name maps move opaque identity candidates and preserve collision ambiguity | review WP3 | `97f65ae6` |
| [x] Loop-entry coalescing requires exact identity when the authoritative sidecar is installed | review WP3 | `633df9f7` |
| [x] High-value pointer/signedness refinement requires exact identity when the sidecar is installed | review WP3 | `db6c4756` |
| [x] DWARF aggregate fields identify parameter pointers from the authoritative prototype, not `argN` spelling | review WP3 | `3e302824` |
| [x] AST value identities carry pipeline-owned parameter slots independently of display spelling | review WP3 | `7eeb84ca` |
| [x] Callee-contract pointer back-propagation resolves parameters from typed roles | review WP3 | `53eb97ec` |
| [x] Recursive pointer classification and copy-origin proofs require exact value or typed parameter roles | review WP3 | `14f6d24a` |
| [x] Exact integer/float role projection protects parameters from pipeline-owned slots, not `argN` spelling | review WP3 | `11ae7601` |
| [x] Exact-definition-width merging protects parameters from pipeline-owned slots; `type_maps.rs` has no `argN` parsing | review WP3 | `5c88a5bd` |
| [x] High-half ABI-width refinement widens only typed parameter roles when identities are installed | review WP3 | `f6c9d0ce` |
| [x] Source-loop update coalescing distinguishes parameters through typed roles, not `argN` spelling | review WP3 | `f3781342` |
| [x] Optimized DWARF register-local merging protects parameters from pipeline-owned slots, not `argN` spelling | review WP3 | `4219eee0` |
| [x] Opaque library-call type refinement observes only identity-owned parameter slots | review WP3 | `0c1d0819` |
| [x] Full-width parameter-address load folding uses owned slots early and projected identities after promotion | review WP3 | `40cb2904` |
| [x] Named and frame-array parameter-spill coalescing follows identity-owned slots through casts and scratch aliases | review WP3 | `d5b69f98` |
| [x] Shared declared-integer typing narrows only identity-owned parameters when a sidecar is installed | review WP3 | `964b66d6` |
| [x] Promoted stack storage retains ABI-proved parameter slots; home writes and slot composition do not parse `argN` | review WP3 | `b0197ec9` |
| [x] Declaration pointer/integer/width facts recognize parameters from typed roles, not `argN` spelling | review WP3 | `bc8c7755` |
| [x] Production identifier census and signature arity derive parameters from typed roles | review WP3 | `973d1931` |
| [x] Immutable declaration plan owns parameter-role rendering; `dec_render.rs` has no `argN` parser | review WP3 | `5cbb36bd` |
| [x] Pre-naming prototype output trusts ABI result storage, not an unowned `ret` spelling | review WP3 | `e79bb7b5` |
| [x] Production post-naming output carries a typed result role instead of trusting `ret` spelling | review WP3 | `e30c727f` |
| [x] Production late return cleanup deletes only typed result-role assignments | review WP3 | `e27ab2cc` |
| [x] Final structured/goto-aware verifier grants implicit call results only to a typed `ret` role | review WP3 | `aab2921d` |
| [x] Production direct/exhaustive return folding recognizes canonical `ret` through typed authority | review WP3 | `c599ac49` |
| [x] Production dead-store call clobbers recognize canonical `ret` through typed authority | review WP3 | `fbb7f596` |
| [x] Production canonical naming preserves only stack-promotion-owned `argN` roles | review WP3 | `b3210392` |
| [x] Plain typed rendering projects numbered values through exact role and identity facts | review WP3 | `32698e2e` |
| [x] Ordinary typed rendering retains raw-occurrence type facts through exact SSA identities and declines ambiguous projections | review WP3 | `23a8ef7e` |
| [x] Call argument motion detects intervening rewrites by SSA identity candidates, not `#version` spelling | review WP3 | `e0c5fc11` |
| [x] Captured call scratch state distinguishes numbered definitions from live-ins by SSA identity version | review WP3 | `45c12f56` |
| [x] ARM stack-address alias expansion admits bounded affine components by SSA identity version | review WP3 | `6ac46be4` |
| [x] First production expression-origin attachments with exact fixture A/B | review WP3 | `9b10f06e`, `3c5c74b9`, `f30167f7`, `b269a3f2`, `86ac95a6`, `fb878925`, `5f8dec01`, `76753c05`, `bb98a3a9`, `e68ff86f`, `a756a6d5`, `f2e69784`, `4c19cb2e`, `97aef0c3`, `65162531`, `6c737361`, `5e04d66a`, `02791f18`, `3b1f34ca`, `22cb5827`, `66e533d7`, `1647953d`, `14eef6d2`, `e2df3e60`, `ff0ced1c`, `3627ca65`, `c79f57db`, `64781964`, `997ec48c`, `072412ce`, `2fccded5`, `dfa2fa22`, `5289e459`, `251ae25e`, `8c84c4ed`, `c0e296e7`, `321d205b`, `8f499b04`, `af0c014b`, `93de6232`, `320cb2e5`, `57f6c625`, `0a8ba2bb`, `7ff9bdc2`, `af10e4e7`, `5a7e76d6`, `bfeb4974`, `fca387da`, `9523e980`, `fa8b0656`, `c4e3f4b3`, `ca3ff99a`, `a4326607`, `82deec7a`, `2fac94e2`, `f7a3afe9`, `eb414739`, `1bc1f57f`, `ab046385`, `e8dab427`, `2644823c`, `c6795d65`, `5b8909b3`, `de7c13d1`, `767664db`, `08f0f858`, `ce55594e`, `be69b02b`, `82d7f3db`, `de1cd148`, `13b1143a`, `b5cde5e3`, `7c60441e`, `0e7aa4bb`, `e3b29fe3`, `129a5277` |
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
| [x] R8 correction: never-executed 271 -> 195 (exec already ran) | R8.3 | `18640412` |
| [x] R8 symbolic CI lane: never-executed pool reaches 0 | R8.3 | `3fb3184c` |
| [x] Known defects encoded as strict xfails, not pinned output | TDD | `1694bb06` |
| [x] 1,162 measured failures across six axes | TDD | `7be914cf` |
| [x] Facets by requirement, applied as markers; 7 facets over 461 files | phase 11 | `65ff0a24` |
| [x] Wheel matrix gated on tags; corpus runs where fixtures exist | phase 11 | `b8884687` |
| [x] Python CI split into `core` (no LFS) and `extended` | phase 11 | `6085e525` |
| [x] The suite was SERIAL on 24 cores; xdist added, `-n auto` in CI: core 11:19 -> 4:13 | phase 11 | this commit |
| [~] Mach-O universal (fat) lane | estate 4 / R4 | thin x86-64+ARM64 landed `ba2fe5c2`; fat slices still open |
| [ ] Rescope fetched Microsoft PE/PDB tests | estate 4 / real-binary R4 | migrate generic assertions; fail provisioned lane on zero pairs |
| [ ] `@large` source-grounded corpus + phase/resource ratchets | real-binary R2 | specify smallest tier first |
| [ ] Promote realistic corpus beyond discovery-only evidence | real-binary R5 | body accounting, semantic subset, signal predicates, mandatory release lane |
| [ ] Source-grounded PE hostile-shape family | real-binary R4/R5 | PE32/PE32+, identity/TLS/SEH/import oracles |
| [ ] Source-grounded ARM64/Cortex-M hostile family | real-binary R1/R5 | ARM64 parity plus independent F2a guard |
| [ ] Page-align fixture + symbol-snapping guard | parity #9 | needs 4 baselines |
| [ ] Pointer/array render (`char **argv`) | parity #6 | |
| [~] Variadic / call-site arity | parity #3 | literal `printf`-family arity landed; generic `ptrace`-like recovery remains |
| [x] Inlined-body register threading | parity #4 | format-proved real GCC/Clang O2 fixture; this commit |
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
| `uv run pytest python/tests/` (local, serial) | **3,735 passed, 0 failed, 1,210 xfailed** — 48 min |
| `-m core -n auto` (local, 24 workers) | **2,367 passed, 0 failed — 4:13** (11:19 serial) |
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
[roadmap package](../roadmap/README.md).

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
* **Tests executed by no gate: 271 -> 195 -> 0.** Both earlier numbers were
  wrong, in different ways, and the sequence is the useful part.

  271 counted `src/exec/` (76) as unreachable from `src/lib.rs`'s `cfg` gate,
  but `Cargo.toml` defines `python-ext = [..., "exec"]`, so
  `--features python-ext` runs 65 of them; the other 11 are `oracle.rs` behind
  `dev-oracle`, which links libunicorn and is never shipped. Reading a `cfg`
  gate tells you what a module needs; only running the suite tells you what
  executed.

  195 was a correct measurement and an obsolete claim: **nothing was
  preventing those tests from running.** `symbolic = ["exec"]` is pure Rust,
  and the first `cargo test --features symbolic` passed 3,025 / 0 with 103
  symbolic tests executing. A CI lane now runs them (`3fb3184c`). A ratchet
  that merely counted the hole would have recorded it indefinitely while the
  fix was one workflow stanza — worth remembering the next time a measurement
  feels like progress.

  92 remain behind `solver-*` features linking external SMT libraries,
  recorded as `solver_gated_estimate` rather than hidden in the pool.
* **The perf gate could report success from an empty measurement**, and
  nothing invoked it. Both fixed — and in that order, because scheduling a
  fail-open gate manufactures assurance.

**The suite is not supposed to be all green.** A decompiler with known
trade-offs whose suite passes 100% is not measuring the trade-offs. The estate
now carries **1,210 `OPEN DEFECT` xfails across 9 files**, up from 41, each
asserting the CORRECT behaviour under `strict=True` so that a FIX turns it red
and announces itself.

`tools/gen_known_failures.py` measures six axes against ground truth over all
1,676 built objects (~23 min), writing `tests/open_defects/known_failures.json`:

| axis | count | |
|---|---:|---|
| parameter type vs DWARF | 307 | 187 signedness, 120 width |
| goto-free source recovers with `goto` | 715 | 6,791 goto statements |
| return type vs DWARF | 92 | the shape that makes a function look `void` |
| `unrecovered` construct emitted | 48 | the renderer conceding a hole |
| pointer parameter -> scalar | **0** | pinned as an achievement |
| DWARF function with no body | **0** | pinned as an achievement |

DWARF is the ground truth, so a disagreement is a recovery gap rather than a
style preference. The two zeros are asserted `== 0` rather than left as
absences: recovered C never dereferences an integer, and every function DWARF
names produces a body — losing either is a failure, not a number quietly
appearing in a file.

**Pinning current output is the wrong shape, and two lanes I added did it.**
`test_pdb_type_recovery.py` and `test_macho_lane.py` first asserted
`got == today`, which makes a fix indistinguishable from a regression — the
test goes red either way and the message says "changed", not "fixed". Both were
converted to strict xfails asserting the source-declared behaviour.

**Three bugs in the harness, each found by the corpus disagreeing with
itself.** Rust emits many functions named `{closure#0}`, so name-keyed lookup
produced 41 spurious XPASSes (rows now carry VAs). The test re-implemented
parameter splitting with a naive `split(",")` while the generator used a
depth-aware one, so they disagreed about which parameter `arg2` is — 36 more
(the test now imports the generator's splitter). And `ruff format` reflowed a
dict so three of four `str.replace` edits silently no-opped, producing a
byte-identical "regeneration" after 23 minutes; every edit now asserts its
anchor count.

**`scripts/lint-rust.sh` is red**: 255 clippy errors on the lib target, 296
with tests, under `-D warnings`. Left alone deliberately; it is a decision to
make, not a thing to silently delete.

**Skips are now visible: 41 of them**, 21 waiting on the gitignored
`tests/fixtures/msvc-pdb/` binaries that nothing fetches (estate 1.7), 7 on
`GLAURUNG_IOCTL_FIXTURES`, 4 on live-LLM opt-in.

## Early typed ABI parameter identities

Commit `079e26d5` makes value numbering record a live ABI parameter slot on
the exact version-zero SSA value itself. A later definition of that register
and an unused ABI argument register remain unowned. Commit `86a3b39a` projects
owned stack-parameter slots into the same sidecar, switches the production
early constant fold to identity authority, and deletes its slot parser.

Focused evidence:

```text
cargo test --lib --features python-ext \
  abi_parameter_slots_attach_only_to_live_version_zero_values
1 passed; 4,458 filtered out

cargo test --lib --features python-ext \
  stack_parameter_projection_records_only_owned_slots
1 passed; 4,460 filtered out

cargo test --lib --features python-ext \
  early_constant_fold_uses_typed_stack_parameter_roles
1 passed; 4,460 filtered out

cargo test --lib --features python-ext \
  parameter_address_load_requires_a_typed_parameter_role
1 passed; 4,460 filtered out

uv run maturin develop
success

uv run pytest \
  python/tests/test_pe32_cdecl_roundtrip.py::test_i386_optimized_cdecl_stack_arguments_round_trip \
  -q
1 passed
```

The two other cdecl tests remain red, but a one-line A/B rebuild with the old
caller reproduced both failures unchanged. They are the existing PE32 `_main`
signature and redundant unoptimized call-cast regressions, not regressions from
this migration.

No broad Rust or Python suite, fixture matrix, DecBench, or Joern lane ran.

## Function-table reaching-definition identities

Commit `33371b23` moves nested-call clobber decisions in function-table
recovery from `#version` display spelling to the pipeline-owned SSA identity
sidecar. The production path preserves only explicit non-entry values across a
nested call; missing, entry, or mixed identities fail closed.

Focused evidence: all 12 initial `ir::function_tables::tests` passed with 4,495
library tests filtered out. The single real fixture initially remained red,
and restoring the old production caller reproduced the same output. After
integration, commit `b5f96b91` fixed the adjacent cause: an expression-origin
wrapper hid the scaled table index from address analysis. All 13 owning tests
now pass, and `95_function_pointer_table:gcc:O0:dispatch_operation` is green
after a fresh native rebuild. No broad suite ran. Full commands and limits are in
`docs/history/decompiler-review-2026-09-02/results/wp3-function-table-definition-identities.md`.

## Promoted stack-object identities

Commit `c591c7e5` makes stack promotion publish every object it minted through
the pipeline-owned `ValueIdentities` sidecar. Production cleanup of unread
stack bookkeeping now consumes that typed ownership instead of parsing
`local_` or `stack_` display spelling; the no-sidecar compatibility wrapper is
unchanged.

Focused evidence: the two exact positive/adversarial tests and all 18
`ir::direct_output::tests` pass. The regenerated census records 5,127 declared
Rust tests and zero outside every gate; all six census checks pass after the
commit. A fresh debug extension passes `tools/build_guard.py`, and a real
Clang O0 executable built from `link_configuration_shapes.c` renders `main`
without an invented return-slot local. No broad suite or corpus ran.

## Promoted float-store identities

Commit `84099fbb` extends stack-promotion ownership through presentation aliases
and into the float-copy type-map fixed point. Two exact adversarial tests, one
alias-projection test, and all 22 type-map tests pass; the census is 5,130
declared Rust tests with zero outside every gate. A parent/tip comparison of the
Clang O0 `accumulate_wide` rendering is byte-identical. Its execution cell is
already red at the parent, so this increment neither claims nor hides that
existing float-output defect.

The periodic four-cell Hello World compile canary (amd64/arm64, Clang O0/O2)
passes syntax compilation. The amd64 O2 executable matches output and status
with controlled `argv[0]`; arm64 O2 still omits the second variadic `printf`
value and remains explicit WP6/WP9 debt. No broad suite or corpus ran.

## Void result-bridge identities

Commit `70b6dc82` requires producer-owned promoted storage plus complete SSA
machine-result candidates before deleting a void function's entry-result
save/restore bridge. Three exact tests and all 21 direct-output tests pass; the
census is 5,133 declared Rust tests with zero outside every gate. After a fresh
serial extension rebuild, only `09_memory_effects:clang:O0:tick_n` was run and
reported no regression. No broad suite or corpus ran.

## Condition-hoist stack identities

Commit `003e4fc1` makes the safety barrier for moving comparisons across stores
consume producer-owned promoted-stack identities. An opaque owned object
blocks unsafe motion; an unowned value named `local_8` does not receive stack
semantics from spelling alone. All 17 hoisting-related Rust tests pass with
4,581 unrelated tests filtered out. The census records 5,135 declared Rust
tests and zero outside every gate. A fresh serial extension rebuild passes the
build guard, and only `03_loop_shapes:gcc:O0:for_sum` was exercised; it reports
no scoped regression. No broad suite or corpus ran.

## Guarded-switch stack identities

Commit `dad31027` moves the guarded-switch promoted discriminator-copy proof
from `local_`/`stack_` spelling to producer-owned stack identity in both the
untyped preparation and typed range-guard paths. All 20 owning tests pass with
4,580 unrelated tests filtered out. The census records 5,137 declared Rust
tests and zero outside every gate. After a fresh serial native rebuild, only
`204_adjacent_dispatch_tables:clang:O2:adt204_guarded_control` ran and reported
no scoped regression. No broad suite or corpus ran.

## Exception stack identities

Commit `54e67cb5` moves promoted-copy tracking for integer exception recovery
from display spelling to producer-owned stack identity in both production
paths. The first exact fixture run found a real adjacent regression: attributed
`_ZTIi` was invisible to direct RTTI recognition. Expression-origin and
numeric-conversion transparency repaired it before commit. All 10 exception
tests pass with 4,592 unrelated tests filtered out; the census records 5,139
Rust tests and zero outside every gate. After a fresh serial rebuild, only
`10_cpp_runtime_shapes:clang:O2:cpp_exception` ran and reported no scoped
regression. No broad suite or corpus ran.

## For-loop stack identities

Commit `50cc926d` makes store-backed counted-loop promotion consume
producer-owned stack identity instead of `local_`/`stack_` spelling. An opaque
owned induction object promotes, while an unowned `local_i` declines. All 31
loop-form tests pass with 4,572 unrelated tests filtered out; the census records
5,140 Rust tests and zero outside every gate. After a fresh serial rebuild,
only `03_loop_shapes:gcc:O0:for_sum` ran and reported no scoped regression. No
broad suite or corpus ran.

## Final-verifier stack identities

Commit `bdb1e0eb` moves promoted-stack store classification in the final
structured and goto-aware output verifier from `local_` / `stack_` spelling to
the pipeline-owned identity sidecar. Both exact adversarial tests and all 43
verifier tests pass with 4,562 unrelated tests filtered out. The regenerated
census records 5,142 declared Rust tests and zero outside every gate; all six
census checks pass after the source commit.

A fresh debug extension passes `tools/build_guard.py`. The owning compiled
invariant first claimed two functions used undeclared `local_8`, but direct
inspection showed initialized declarations in both. Commit `4c905ab7` teaches
the gate to recognize `name = value`; the exact x86-64 O0 cell and all eight
architecture/optimization cells pass.

## Hosted Hello contract

Commits `76eb1329` and `fea34010` make pointer-type comparison transparent to
expression origins and extend the standard hosted-`main` contract to a
recovered zero-argument body. The exact new tests and their four- and six-test
owning modules pass. After a fresh debug extension build, all four canonical
Hello World cells—amd64/AArch64, Clang O0/O2—render exact `int main(void)`, a
plain `puts("Hello, World!")`, and `return 0`. The census records 5,144 declared
Rust tests and zero outside every gate. No broad suite or corpus ran.

## Renderer-owned local verification

Commit `7d0095af` replaces the production verifier's generic local-name parser
with the renderer's identity-aware owned-local inventory. Parameters and raw
machine-state placeholders are excluded by the same census that determines C
declarations. Both adversarial tests and all 45 verifier tests pass with 4,564
unrelated tests filtered out. A fresh debug extension passes the exact x86-64
O0 declaration/use invariant and the exact shadow verification-metadata test.
The census records 5,146 declared Rust tests and zero outside every gate; all
six census checks pass. No broad suite or corpus ran.

## Unobserved object-store identities

Commit `ca6a4df7` makes production cleanup of unobserved promoted-object field
stores require producer-owned stack identity. An opaque owned object remains
eligible, while an unowned object named `local_10` fails closed. Both exact
adversarial tests and all 45 dead-store tests pass, with 4,566 unrelated Rust
tests filtered out. The regenerated census records 5,148 declared Rust tests
and zero outside every gate; all six census checks pass after the source
commit. A fresh serial native rebuild passes the build guard, and only
`09_memory_effects:clang:O0:tick_n` ran and reported no scoped regression. The
periodic Hello matrix was not repeated for this non-rendering identity seam.
No broad suite or corpus ran.

## Adjacent overwritten-store identities

Commit `592ea81b` makes the adjacent overwritten promoted-store cleanup inside
production dead-store elimination require producer-owned stack identity. Its
fail-closed test was observed red before the fix: an unowned `local_8` lost a
store solely because of its spelling. An opaque owned `frame_object` remains
eligible. Both exact tests and all 47 dead-store tests pass, with 4,566
unrelated Rust tests filtered out. The census records 5,150 declared Rust tests
and zero outside every gate; all six census checks pass after the source
commit. A fresh serial native rebuild passes the build guard and the exact
committed Win64/PDB `record_value` regression passes. The periodic Hello matrix
then passes four-for-four across x86-64 Clang and AArch64, each at O0 and O2
with symbol-bearing PIE input and exact canonical output. No broad suite or
corpus ran.

## Machine-save storage identities

Commit `00b7ebbc` makes production callee-save cleanup require both producer-
owned machine-save storage and an exact version-zero ABI callee-saved source.
The two boundary regressions were observed red before the fix: an unowned
`stack_2` was deleted from spelling alone, while an opaque owned `frame_save`
was missed. Both now behave by identity, and the existing entry-versus-later
SSA control also requires storage ownership. Those three exact tests and all
49 dead-store tests pass with 4,566 unrelated Rust tests filtered out. The
census records 5,152 declared Rust tests and zero outside every gate; all six
census checks pass after the source commit. A fresh serial native rebuild
passes the build guard and the exact committed x86 stack-clash regression.
The four-cell Hello checkpoint had just passed and was not repeated for this
non-Hello seam. No broad suite or corpus ran.

## Late copy-cleanup storage identities

Commit `00943c69` makes late production copy cleanup distinguish scratch state
from promoted storage by producer-owned identity. An unowned `local_8` is
ordinary scratch state; an opaque owned `frame_object` remains storage. The
identity reaches counted propagation, dead-copy removal, straight-line dead
stores, and closed scratch-dataflow pruning. Both exact tests and all 64 copy-
propagation tests pass with 4,553 unrelated Rust tests filtered out. The census
records 5,154 declared Rust tests and zero outside every gate; all six census
checks pass after the source commit. A fresh serial native rebuild passes the
build guard and the exact committed x86 stack-clash regression. The pre-sidecar
preparation pass remains a compatibility boundary, so the wider WP3 migration
is still open. The four-cell Hello checkpoint had just passed and was not
repeated. No broad suite or corpus ran.

## Typed promoted-value identities

Commit `f90a277c` makes late typed adjacent promoted-value folding require
producer-owned stack identity in addition to the existing scalar type and
one-use proofs. An opaque owned `frame_object` folds, while an unowned
`local_4` with the same scalar type declines. Both exact tests and all 66 copy-
propagation tests pass with 4,553 unrelated Rust tests filtered out. The census
records 5,156 declared Rust tests and zero outside every gate; all six census
checks pass after the source commit. A fresh serial native rebuild passes the
build guard and only the exact Clang O0 `fsm_returns_from_arm` fixture ran,
reporting no scoped regression. The untyped pre-sidecar mover remains a
compatibility boundary. The recent four-cell Hello checkpoint was not
repeated. No broad suite or corpus ran.

## Canary-storage identities

Commit `2d53096b` makes production stack-canary save collapse consume
producer-owned promoted-stack identity instead of granting storage semantics to
the `stack_` prefix. An opaque owned `frame_canary` collapses, while an unowned
`stack_4` remains untouched. Both exact boundary tests and all 24 canary tests
pass, with 4,597 unrelated library tests filtered out. The census records 5,158
declared Rust tests and zero outside every gate; all six census checks pass.

A fresh serial native rebuild passes the build guard, and only the exact
committed GCC O2 packet-parser canary ran through the production decompiler.
The recent four-cell Hello checkpoint was not repeated for this metadata seam.
No broad suite or corpus ran.

## AArch64 frame-storage identities

Commit `2f664dfe` moves production AArch64 fp/lr scalar save and restore
recognition from `stack_` display spelling to producer-owned promoted-stack
identity. Four exact positive/adversarial tests and all 16 module tests pass,
with 4,609 unrelated library tests filtered out. The census records 5,162
declared Rust tests and zero outside every gate; all six census checks pass.

A fresh serial extension rebuild passes the build guard, and only the exact
AArch64 O2 `bst_inorder_checksum` lane ran, reporting no scoped regression. The
recent four-cell Hello checkpoint was not repeated. No broad suite or corpus
ran.

## x86 scalar-frame storage identities

Commit `21599ad4` makes the production x86-64 scalar rbp-frame prologue and
recursive epilogue recognizers consume producer-owned promoted-stack identity.
An opaque owned slot collapses and an unowned `stack_0` fails closed. Both
exact boundary tests and all 42 x86 frame tests pass using `cargo test --lib`,
with 4,588 unrelated library tests filtered out. A fresh serial extension build
passes the build guard and the exact compiled x86 stack-clash execution fixture.

A concurrent uncommitted decoder lane appeared during census generation.
Corrective commit `681594ed` excludes its three tests and records this source
increment alone: 5,164 declared Rust tests and zero outside every gate. An
isolated archive of the pushed tip reproduces the baseline and passes all six
census checks. The recent Hello checkpoint was not repeated. No broad suite or
corpus ran.

## cdecl32 frame-role identities

Commit `26f7fe57` makes production cdecl32 entry-realignment consume stack
promotion's owned storage and parameter-slot facts instead of parsing
`stack_top` and `arg0`. Both exact boundary tests and all 44 x86 frame tests
pass with 4,589 unrelated library tests filtered out. A fresh extension build
passes the guard, and only the i386 O0 `call_into_spill` fixture ran, reporting
no scoped regression.

An isolated archive of the exact pushed commit reproduces 5,166 declared Rust
tests with zero outside a gate and passes all six census checks. The shared
checkout's active native-decoder tests were not counted. Narrow PE evidence
still exposes two pre-existing debts: a raw string address in checked-in PE32
`main`, and redundant integer casts in a generated cdecl call. Parent/tip A/B
shows this increment repairs the PE signature from `main(void)` to two
arguments; it does not claim the unrelated assertions green. The recent Hello
checkpoint was not repeated. No broad suite or corpus ran.

## ARM32 frame-storage identities

Commit `00aba798` moves production ARM32 frame storage recognition from
`stack_`/`stack_top` spelling to producer-owned promoted-stack identity across
saves, anchors, deallocation, and restores. Both exact boundary tests and all
12 owning tests pass, with 4,623 unrelated library tests filtered out. A fresh
serial extension build passes the guard and the single compiled ARM frame-spill
test passes.

An isolated archive of the pushed commit reproduces 5,168 declared Rust tests
with zero outside a gate and passes all six census checks. The active native-
decoder lane is excluded. The recent Hello checkpoint was not repeated. No
broad suite or corpus ran.

## Ground rules

Verified before any claim of done: `cargo test --features python-ext`,
`uv run pytest python/tests/`, `uvx ruff check python/`, `uvx ty check
python/`, and `dectest @o0 @o2` for anything touching the decompiler.
`TMPDIR` exported. No DecBench, no Joern. Every fixture change refreshes the
six side files.

**A readability change is a semantic change.** The comparison-guard fusion
looked purely cosmetic and turned eleven execution-differential lanes red on
its first version. The fixture matrix is the thing that knows.
