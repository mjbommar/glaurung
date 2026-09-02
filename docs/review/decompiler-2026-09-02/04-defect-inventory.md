# 04. Defect inventory

Everything the test estate records as known-broken, known-bad, accepted, or
ratcheted, counted on 2026-09-02 at `master` @ `5c4df8d2`. Counts come from
the JSON files and test sources named; nothing here was re-measured by running
the decompiler over the corpus.

## 1. The strict-xfail corpus (1,162 rows)

**Files.** `python/tests/test_known_decompiler_failures.py` (208 lines),
`tests/open_defects/known_failures.json` (8,105 lines, generated),
`tools/gen_known_failures.py` (225 lines, the only generator).

**Mechanism.** One JSON record per `(object, function, VA[, arg])` across six
axes, each measured against ground truth (DWARF, or the fixture's source text),
not against a prior run. Every row becomes one `pytest.param(..., marks=
pytest.mark.xfail(strict=True, reason="OPEN DEFECT (...)"))`
(`test_known_decompiler_failures.py:112-176`). Each test asserts the correct
behaviour, so today it fails and is reported as xfail; when the decompiler
improves the assertion passes, `strict=True` turns the XPASS into a failure,
and the reason text says to regenerate the inventory.
`test_the_failure_count_does_not_grow` (`:238-270`) caps each axis at its
recorded count so new failures also fail.
`test_the_inventory_is_present_and_populated` (`:199`) fails below 900 rows so
the file can never be vacuous; the corpus is gitignored, so on a fresh clone
each row skips naming the missing object.

Regeneration: 1,676 objects, 1,365.8 s.

| axis | rows | test | meaning |
|---|---:|---|---|
| `types` (parameter vs DWARF) | 307 | `test_recovered_prototype_matches_dwarf` (`:213`) | 187 signedness, 120 width |
| `structure` (goto in goto-free source) | 715 (6,791 `goto` statements) | `test_goto_free_source_recovers_without_goto` (`:227`) | function emits a `goto`; its source file has none |
| `returns` (return type vs DWARF) | 92 | `test_recovered_return_type_matches_dwarf` (`:179`) | all 92 are width; 0 `ptr_lost` |
| `unrecovered` (renderer marker) | 48 | `test_no_unrecovered_construct_remains` (`:191`) | literal `unrecovered` in the C |
| `pointers` (DWARF pointer degraded to scalar) | 0 | pinned `== 0` (`:264`) | |
| `no_body` (DWARF function with no body) | 0 | pinned `== 0` (`:268`) | |

**Double counting.** The corpus includes both `-O2` and `-O2strip.dwarf`
objects. Of the 419 current pairs, 412 are byte-identical and seven Rust pairs
differ. The per-axis O2 counts happen to mirror as 89 + 89, 242 + 242, 25 + 25,
and 18 + 18; normalising the lane identity yields **218 / 473 / 67 / 30**.
The generator should deduplicate by content hash or explicit build provenance,
not assume every filename pair has identical bytes.

### 1.1 `types` (307)

By compiler: rustc 298, gcc 7, clang 2. By opt: O0 129, O2 89 (x2).

Top fixtures: `171_rust_overflow` 62, `169_rust_slices_bounds` 50,
`168_rust_enum_niche` 45, `166_rust_generics` 39, `170_rust_panic_unwind` 37,
`219_rust_iterator_chains` 34, `167_rust_trait_objects` 31. The C-language
rows are `08_indirect_dispatch` 4, `02_integer_widths` 2,
`195_by_value_aggregates` 2, `129_struct_by_value` 1.

Dominant shapes: signed wanted, `unsigned int` recovered (68); 4-byte wanted,
`long` recovered (65); unsigned wanted, `long` recovered (52); unsigned wanted,
`int` recovered (50); unsigned wanted, `bool` recovered (14).

Representative C row: `02_integer_widths-gcc-O2.so::trunc_u8`, arg 0, wants
width 4, recovers `signed char`. The source is `int trunc_u8(unsigned x) {
return (uint8_t)x; }` and the body renders correctly as
`return (unsigned int)((unsigned char)((arg0 & 255)));`.

### 1.2 `structure` (715 functions, 6,791 gotos)

By compiler: clang 335, gcc 286, rustc 94. By opt: O0 231, O2 242 (x2).
By goto statements per lane: clang:O0 1,600; gcc:O2 1,202 (x2); clang:O2 815
(x2); gcc:O0 591; rustc:O0 288.

Per function: median 4, mean 9.5, 139 functions with 10 or more. Worst:
`151_wide_branch_ladder-clang-O0.so::big151_branch_ladder` 845;
`154_wide_switch::wide154_dense_effects` 208 (clang O0), 203 (gcc O2), 190
(gcc O0); `wide154_sparse_switch` 133 (gcc O2), 70 (clang O2).

Top fixtures: `169_rust_slices_bounds` 33, `170_rust_panic_unwind` 22,
`212_loop_with_returning_arm` 22, `167_rust_trait_objects` 19,
`137_cpp_templates` 14, `45_string_algorithms` 14, then a 12-way tie at 12
(`03_loop_shapes`, `40_quickselect`, `44_run_length`,
`76_portfolio_rebalance`, `80_trie`, `166_rust_generics`, ...).

Representative rows are decompiled in 03-observed-output.md.

### 1.3 `returns` (92)

By compiler: rustc 59, gcc 17, clang 16. All width. Top fixtures:
`166_rust_generics` 20, `219_rust_iterator_chains` 13,
`197_homogeneous_float_aggregates` 12, `195_by_value_aggregates` 10,
`198_aggregate_return_edges` 9. C rows: `08_indirect_dispatch-gcc-O2.so::
tail_dispatch` wants 4 bytes, recovers `long`; the aggregate fixtures want
16-, 20- and 32-byte struct returns and recover `long` / `int` / `double` /
`void`.

### 1.4 `unrecovered` (48)

By compiler: clang 29, gcc 13, rustc 6. Fixtures: `102_duffs_device` 6,
`103_computed_goto` 6, `145_control_flow_flattening` 5, `154_wide_switch` 4,
`159_ifunc_resolver` 4, `168_rust_enum_niche` 4, `206_aarch64_wide_dispatch`
4, `215_switch_on_wide_selector` 4, `126_x_macros` 1,
`150_obfuscation_composite` 1, `167_rust_trait_objects` 1,
`204_adjacent_dispatch_tables` 1. Every one is a switch or dispatch shape.

## 2. Hand-written strict xfails

| file | cells | defect |
|---|---:|---|
| `test_open_decompiler_defects.py:104` | 2 | `call_args` intervening read: an inlined `printf("... %d", static_var)` loses its argument at -O2; repro `tests/open_defects/inlined_printf_arg.c` |
| `test_pdb_type_recovery.py:67-118` | 4 of 5 | PDB prototypes: struct-by-value flattened to `long`; pointee guessed from first access; `double` parameter recovered as `float`; `unsigned long long widen(unsigned int)` recovered as `widen(int)` returning `unsigned long` |
| `test_macho_lane.py:145` | 1 | AArch64 `fmadd` unlifted, so `double mix_float(double, float)` collapses to `void(void)`; the reason records an intrinsic fix that was tried and rejected because it broke `217_complex_arithmetic:aarch64:O2` |
| `test_decompiler_curriculum_corpus.py:170` | 1 (slow) | gcc 11 -O2 `bst_search`: peeled and rotated loop structured as two `do {}` loops |
| `test_decompiler_control_flow_semantics.py:207` | 1 | clang 14 -O2 `fsm`: no `switch`, `goto L_1153` / `goto L_113b`; `detect_raw_dispatch_loop` declines on `exits.len() < 3`; `BackEdgeUnowned { 3 -> 4 }` |
| `test_build_configuration_invariants.py:531, 865, 915` | 3 (`lto` config) | `-flto`: all five return types collapse to `void`; parameters degrade to register width; `bc_buffer_and_scalars` recovers no frame object (`long rsp; rsp = rsp - 88`) |
| `test_build_configuration_invariants.py:732-743, 810-816` | 10 configs (`DECIDABLE_GUARD_KNOWN_BAD`) | the stack-guard load is modelled so the canary compare is statically decidable; every lane but `no_stack_protector` |
| `test_decompiler_emission_invariants.py:336` | 1 arch x 2 opts | AArch64 `signed_remainder`: the negative arm reads unassigned `var3` |
| `test_decompiler_emission_invariants.py:296` | 0 | `FRAME_OVERLAP_KNOWN_BAD = set()`; `:570-576` records the aarch64 -O2 entry removed on XPASS 2026-08-16 |
| `test_variadic_abi_invariants.py:318, 505` | 24 | x86-64 register save area: `va_start` spills rsi/rdx/rcx/r8/r9/xmm0-7/`al` that nothing defines (5 to 38 undefined reads); the recovered prototype does not declare `...` |
| `test_recovered_tree_buildability.py:79` | 0 | `_KNOWN_BROKEN = {}` |

Pinned without xfail: `test_decompiler_curriculum_corpus.py:304` hard-codes
`33_knapsack:clang:O2:knapsack_best_value = "fail"` (vectorised 0/1 knapsack).

Rust: 3 `#[ignore]` (`src/ir/effect_census_tests.rs:246` prints a histogram;
`src/ir/memory_objects/partition_tests.rs:845`;
`src/ir/memory_objects/shape_tests.rs:461`) and 0 `#[should_panic]`.

## 3. Fixture baselines under `tests/decompiler_fixtures/`

| baseline | population | `fail` cells | detail |
|---|---:|---:|---|
| `baseline.json` (gcc / clang / rustc x O0 / O2) | 838 lanes, 3,449 cells | 433 (12.6%) | clang 190, gcc 177, rustc 66; O2 220, O0 213; 43 lanes fail every function |
| `arch_baseline.json` (6 arches x O0 / O2) | 2,472 lanes, 9,805 cells | 1,909 (19.5%) | armv7_a32 437, armv7 422, i386 355, aarch64 322, x86_64_gcc15 196, x86_64 177; O2 1,086 vs O0 823; 221 lanes fail entirely; 391 structural; 38 incomparable |
| `structural_baseline.json` | 3,580 readability rows, 751 verify rows, 2,253 closure rows | n/a | 4,604 `goto` over 461 function-lanes (clang:O2 138, clang:O0 113, gcc:O2 111, gcc:O0 99); 85 `switch`; 13 functions carry `verify` diagnostics (e.g. `111_self_referential_struct:link_and_sum` "rbp ... never assigned"); 7 Rust fixtures skipped; all closure rows closed; GCC -O0 only |
| `defuse_baseline.json` | 3,140 required cells | 198 functions with 351 undefined reads | lane totals: rustc:O0 7,658 / 2,218 fns; rustc:O2 4,933 / 1,367; clang:O2 256 / 86; clang:O0 140 / 36; gcc:O2 136 / 65; gcc:O0 124 / 20 |
| `stripped_divergences.json` | 95 | 87 regressions, 8 improvements | `197_homogeneous_float_aggregates` 7, `195_by_value_aggregates` 6, `217_complex_arithmetic` 6 |

Host fixtures with the most failing cells: `158_weak_symbols` 16,
`205_x87_long_double` 16, `140_thread_local_storage` 14,
`217_complex_arithmetic` 14, `173_float_int_conversions` 13,
`174_float_compare_classify` 13, `135_cpp_rtti` 12,
`136_cpp_exception_unwinding` 12, `157_symbol_visibility` 12,
`170_rust_panic_unwind` 12. Lanes that fail every function include
`102_duffs_device` (all 4), `103_computed_goto` (all 4), `54_sha256_block`
(all 4), `87_variable_length_array` (all 4), `136_cpp_exception_unwinding`
(all 4).

## 4. DecBench no-body taxonomy

`docs/design/decbench-full-failure-taxonomy-2026-08-31.md`: full run at
`7bc73539`, 803 binaries, 94,575 manifest functions, **217 without a body
(0.2295%)**.

| class | rows | cause |
|---|---:|---|
| F1a | 33 | i386 stdcall `_name@N` name resolution (landed in `0d6b30d1`, not yet observed in a rerun) |
| F1b | 63 | import-only identity |
| F1c | 88 | manifest-only functions |
| F1d | 2 | source-CFG-only (`gzip __printf__`) |
| F2a | 31 | Cortex-M `MRS` / `MSR` over `BASEPRI` / `IPSR` / `PSP` unlifted (landed after the doc: `0031c3ee`, `b84ed29b`) |

By family: PE32/i386 171, ELF32/ARM 44, ELF64/x86-64 2. By project: mydoom 88,
dexter 41, minipig 27. E1: 13 Dexter O2 functions lacking a `compiles` fact
(evaluator side).

Full-corpus scores (`docs/design/decbench-full-score-audit-2026-08-30.md`, rev
`229fbb1`): GED 32.28%, type 21.81%, byte 5.89%, **Union 41.55%**. Competitors
on their scored populations: IDA 41.27%, Kuna 41.03%, angr 39.61%, Ghidra
33.24%, Binja 33.20%, dewolf 8.03%. Large functions: 24 of 1,987 Union-perfect,
0 byte-perfect; compile rate 84.6% at 25-49 lines and 36.2% at 500-999.

## 5. Recorded trade-offs

- **`defuse_baseline.json` `accepted_regressions`: 7.** rustc:O0 +25
  violations / +5 functions ("NOT ATTRIBUTED, and the earlier reason recorded
  here was WRONG"); rustc:O2 +15 / +3 attributed to the exception fix
  `965f8585`; rustc:O0 +20 and rustc:O2 +12 attributed to the arity fix
  `11d55613`; one renumbering. Ratchet rules in
  `tools/defuse_ratchet.py:221-321`; gates in
  `test_decompiler_defuse_census.py:87-130` (a new violation in a tracked
  function, any lane growth, and an improvement without refresh all fail).
- **Fitness ratchet: 29 accepted regressions** (`tools/fitness_baseline.json`,
  `tools/fitness_report.py:82-112`). Nine targets, three missing: product
  median 301 vs 250; `ir_files_above_1000` 13 vs 5; largest file 2,268
  (`ir/lift_x86.rs`) vs 1,000. Medians are reported but never ratcheted
  (`test_fitness_report.py:543`). 23 files are over 1,000 LOC.
- **Path-keyed allowlists.** `REVIEWED_LARGE_MODULES` 23 entries
  (`test_large_module_review.py:70`); `ENV_VAR_ALLOWLIST` 53 entries keyed by
  `(file, var)` (`test_src_dependency_boundaries.py:210`);
  `REVIEWED_DOC_SUMMARIES` 26 entries (`test_stranded_doc_comments.py:268`).
  All keyed by file path, which is why any split orphans them (CLAUDE.md "six
  side files").
- **Known-bad sets.** `DECIDABLE_GUARD_KNOWN_BAD` 10 configs, may only shrink;
  `FRAME_OVERLAP_KNOWN_BAD` and `_KNOWN_BROKEN` empty.
- **Markers.** `pytest.mark.slow` 73 uses in 34 files; `pytest.mark.decbench`
  7, deselected by `pytest.ini`; about 500 `pytest.skip` / `skipif` sites
  across 43+ files; `pytest.ini` says 176 files call `pytest.skip()` at
  runtime, hence `-ra`, and by design there is no skip budget.
- **Perf gate.** `test_perf_gate_fails_closed.py`: the gate now exits 3 ("not
  evidence") for no baseline, unit mismatch, or fewer references than the
  baseline. `bench/perf_baseline.json` holds 3 instruction-count references.
  CLAUDE.md still calls it "not yet a provenance-complete release gate".
- **Goto thresholds.** None numeric in tests. Gotos are gated by the
  structural baseline's per-function counts and by the 715 / 6,791 caps.
  `docs/design/goto-density-measurement-2026-08-12.md` records 8.63 gotos per
  100 lines against Ghidra's 3.18, and that a sinking pass which cut gotos by
  11% moved `statemachine:gcc:O0` GED from 10 to 35 and lost 5 byte-match
  cells; it was deleted with the instruction "do not reintroduce sinking
  without a metric that says goto density is worth it".

## 6. Vacuous and never-executed tests

- **`1b9f19c9` (33 tests passing while asserting nothing).** 21 Rust sites in
  `analysis/cfg.rs`, `ir/types_recover.rs`, `ir/value_number.rs`,
  `ir/memory_objects/partition_tests.rs` returned `ok` on
  `ErrorKind::NotFound` for a compiler. Fix: `src/testing.rs::missing_tool()`
  (23 call sites) panics under `GLAURUNG_REQUIRE_TOOLCHAINS=1`, which CI sets;
  a source-scan ratchet catches new guards.
- **`753bf1dd` -> `18640412` -> `3fb3184c` / `489085a2`.** Declared-test
  census (`tests/test_census_baseline.json`, 3,187 declared). Never-executed
  reported as 271, corrected to 195, then to 0 after
  `.github/workflows/test-suite.yml` gained a `--features symbolic` lane (103
  symbolic tests now execute; the job fails under 50). Remaining by design:
  92 tests behind `solver-axeyum` / `-bitwuzla` / `-z3`; 11 behind
  `dev-oracle`.

## 7. Where defects cluster, ranked

1. **Rust fixtures (166-171, 219).** 298 of 307 parameter rows, 59 of 92
   return rows, 94 of 715 goto rows, 7 fixtures skipped from the structural
   lane, and 12,591 of 13,247 undefined reads.
2. **Floating point and by-value aggregates.** `197_homogeneous_float_
   aggregates` (82 arch fails, 7 stripped divergences, 12 return rows),
   `217_complex_arithmetic` 60, `201_float_bit_stores` 59,
   `205_x87_long_double` 58, `173_float_int_conversions` 57, `172` / `174` /
   `175` 44-49, `195` / `198` 47 each. Also the theme of the hand-written
   xfails (PDB `double` -> `float`, AArch64 FMA, LTO `void` collapse).
3. **32-bit ARM.** 859 of the 1,909 arch fails; DecBench F2a was the same
   lifter.
4. **-O2 for execution correctness** (arch 1,086 vs 823; defuse clang/gcc O2
   lanes 3-4x O0) but **-O0 for goto volume** (clang:O0 1,600 goto statements;
   the single worst function at 845).
5. **Irreducible and dispatch control flow.** `102`, `103`, `145`, `154`,
   `215`, `206` supply 29 of 48 `unrecovered` rows and 8 wholly-failing host
   lanes; 85 switches recovered corpus-wide against 4,604 gotos.
6. **Linkage and runtime edge cases.** `158_weak_symbols` 48 arch / 16 host,
   `157_symbol_visibility` 36 / 12, `140_thread_local_storage` 42 / 14, C++
   RTTI / EH / vtables (`132`-`139`) 22-36 each.
7. **Clang slightly ahead of gcc** in host fails (190 vs 177), goto functions
   (335 vs 286), unrecovered (29 vs 13), and defuse O2 (256 vs 136).
8. **Prototype and ABI gaps.** Signedness (187) over width (120); varargs (24
   xfail cells, `113_varargs` 25 arch fails); indirect and tail dispatch
   (`08_indirect_dispatch` in types, returns, stripped divergences and the
   open armv7 item).
9. **Stripping** regresses 87 cells and improves 8, concentrated in the same
   float-aggregate and dispatch fixtures.
