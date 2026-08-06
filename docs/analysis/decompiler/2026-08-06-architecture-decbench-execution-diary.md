# Architecture and DecBench execution diary — 2026-08-06

This is the evidence log for the ten-item architecture and evaluation follow-through.
It records claims before they are synthesized into the ranked plan so a later summary
cannot erase failed hypotheses, incomplete gates, or environmental limitations.

## Evidence rules

- Keep local tests, committed state, remote refs, and remote CI as separate facts.
- Do not pair newly generated source artifacts with an old binary unless executable
  code identity is proved.
- Do not call a metric unavailable until the current evaluator has been exercised.
- Preserve the 250-function holdout manifest and compare like-for-like function keys.
- Treat behavior, compilation, GED, type match, and byte match as distinct oracles.

## 09:00–09:45 — orphaned ARMv7 integration

The stale worktree contained four additive fixes worth retaining: multi-operation
Thumb IT predication, ARM-safe SSA register aliasing, literal-pool/table-base
resolution, and ARM frame-base normalization. They were ported conflict-aware onto
`origin/master`; stale value-numbering and binding changes were not copied wholesale.

TDD evidence:

- Six focused regression tests failed before their corresponding fixes and pass after.
- `cargo test --all-targets`: pass (1,757 library tests plus integration/example
  targets).
- Python suite: 2,771 passed, 43 skipped, 6 warnings.
- Architecture ratchet, repeated three times: x86-64 328/328, i386 251/272,
  AArch64 279/328, ARMv7 235/272.
- Exactly seven ARMv7 cells changed fail-to-pass and no cell regressed or changed
  classification.
- Repository-wide Ruff and type checks remain red on pre-existing debt and are not
  represented as green evidence for this change.

Commit `904332409b40877ebb9788fd644476c498717e0a` was pushed to both
`refs/heads/agent/armv7-orphan-integration` and `refs/heads/master`; remote refs were
read back and matched exactly.

## 09:45–10:05 — DecBench tree audit and rebuild start

The durable holdout tree is `/tmp/decbench-holdout/tree`: 224 compiled binaries,
38 project checkpoints, 221 materialized source-CFG JSON files, and no preprocessed
`.i` files. A smaller 15-function tree also has source-CFG JSON, despite initially
appearing empty under a shallow directory inspection.

Two claims needed correction before rebuilding:

1. GED is already scoreable from materialized source-CFG JSON. The absence of `.i`
   prevents fresh source-CFG extraction, not materialized GED evaluation.
2. Type match is not wholly unscoreable from artifacts. A clean-copy
   `evaluate-tree -m type_match` run over the 15-function tree produced 13 non-null
   values (aggregate across the 15 recorded rows approximately 0.1201). The weak
   path reconstructs code but not structured `VariableInfo`, so matching falls back
   to emitted declarations; two sampled binaries exposed no usable DWARF.

The rebuild is still required: live source-CFG extraction, serialized variable
recovery, and reproducible rescoring should not depend on old checkpoint internals.

A partial host rebuild proved that new sources cannot simply be grafted onto the old
binaries. Among 52 overlapping outputs, whole-file SHA-256 matched zero and `.text`
matched only six. Current GCC/source/dependency shapes differ from the retained tree.
The new tree therefore lives separately at
`/nas4/data/binary-analysis/decbench-holdout-source-rebuild-2026-08-06`.

The first documented host build covered 25 SAILR projects at O0, O2, and
O2-noinline. Sixteen projects produced linked binaries and `.i` files at every level;
nine failed under host GCC 15 or current network/dependency conditions. Its raw report
is retained as `compile_report.host-gcc15.json`. The DecBench compile container is
being built for the remaining SAILR, CPS, and malware slices.

An accidental earlier invocation treated `--help` as an output directory because
`compile_all.py` has positional arguments only. Its exact output and worker temp
directories were stopped and moved, recoverably, to
`/tmp/decbench-accidental-build.MHMjVr`; the DecBench source checkout was restored to
its prior dirty state.

## 10:05–10:35 — rebuild coverage and compiler-driver defects

The documented Ubuntu 24.04 compile image (GCC 13.3, Arm GNU 13.2.1, MinGW 13)
completed 13 additional projects. Three projects reported as failures actually
produced all requested PE outputs: `dexter`, `mydoom`, and `x0r-usb`. The report is
wrong because `_count_outputs` counts ELF only. A second driver defect schedules the
global O0/O2/O2-noinline list for every project instead of respecting each project's
declared optimization levels; this creates a false O0 failure for `u-boot`, whose
manifest supports only O2 and O2-noinline.

Accounting for those report defects, 32 of 38 projects are complete at all declared
optimization levels and `u-boot` is complete at both of its declared levels. The
remaining five projects are `libacl`, `libbsd`, `libedit`, `openssh-portable`, and
`rsyslog`; their missing packages were added to a derived compile image for the final
rebuild pass. Raw host and container reports remain beside the artifacts as
`compile_report.host-gcc15.json` and `compile_report.container-gcc13.json`.

## 10:35–10:55 — direct `type_match` audit

The retained latest 250-function checkpoint has 235 non-null `type_match` values
with mean 0.201615. Although every serialized Glaurung decompilation currently has an
empty structured `variables` list, the evaluator reparses emitted declarations, so
the scores are real but lossy. An experiment adding only structured argument types
to the 15-function tree reduced the mean from approximately 0.1385 to 0.1330 because
the non-empty structured list suppressed parsed locals. Partial metadata is therefore
unsafe; the decompiler must publish a complete, first-class variable record or leave
the fallback intact.

Zero-score samples identify concrete recovery failures rather than an adapter-only
problem:

- `gyroInitFilterNotch1`: two source `unsigned short` arguments become two `int`
  arguments, losing exact narrow-width provenance.
- `pkg_array_match_patterns`: object pointers, a function pointer, `void *`, and
  `char **` collapse to `long *`/`long`, exposing pointer-depth and prototype gaps.
- `compare_files`: `char **`, aggregates, arrays, and booleans collapse to synthetic
  longs and byte blobs despite some correct stack offsets.
- `commit_files`: unmatched no-location/repeated DWARF local names appear partly
  metric/debug-artifact driven and should not be optimized as ordinary type recovery.

The direct type work should therefore preserve exact value widths, pointer depth and
function-pointer signatures, aggregate identity/extents, and structured stack-slot
metadata. A naive adapter parser would merely duplicate the evaluator's existing
fallback.

## 10:55–11:05 — ARM32 CFA coordinate widening

ARM32 ordinary SP-relative slots were already normalized to `entry_sp`; the missing
path was narrower: DWARF CFA aggregates and two reconciliation helpers remained
gated and named for AArch64. A focused test first reproduced the gate as `None` for
ARM current `sp+8` at delta -32, where CFA requires `entry_sp-24`. The helper and
metadata migration gates now cover `Arm`, `ArmHardFloat`, and `Aarch64`, and ARM
DWARF `CallFrameCfa` objects map to `entry_sp`. Both focused Rust tests pass, including
the Python-binding path built with `--features python-ext`; broad architecture gates
remain pending.

## 11:05 — CFA implementation corrected and broad-gated

The first apparently DRY implementation routed every architecture through one richer
stack-address resolver. That was wrong: the existing x86 paths intentionally have two
different precedence rules, and the change regressed `21_graph_dfs:x86_64:gcc:O0`.
The x86 control rejected the change before it was accepted. The final implementation
keeps those legacy paths intact and opts ARM/AArch64 into a named
`aapcs_entry_stack_coordinate` plus an ARM-only active-base preference.

A realistic C++ constructor/destructor regression then exposed a second issue. ARM
frame-pointer setup is represented in SSA as `r7#1 = sp`; mapping only DWARF CFA
objects did not put that definition in entry-SP coordinates. `collect_stack_address_defs`
now records that exact assignment as an entry-SP address. Before the fix the constructor
still took an unresolved machine address; after it both constructor and destructor use
`&local_18[0]` for the same aggregate.

Broad `tools/arch_roundtrip.py --write-baseline` evidence is green:

- pinned GCC 11 x86-64: 328/328;
- host GCC 15 x86-64: 323/328;
- i386: 251/272;
- AArch64: 279/328;
- Thumb ARMv7: 238/272; and
- A32 ARMv7: 112/272.

Total: 1,531 pass, 269 fail, 228 structural-only, and six declared unsupported.
Relative to commit `9043324`, the CFA widening changes three Thumb cells from fail to
pass (`graph_bfs`, `graph_dfs`, and `dijkstra_dense`, all O0), changes no Thumb cell
from pass to fail, and preserves the 328/328 pinned x86 control.

## 11:06 — missing A32 lane and compiler-shape control

The architecture harness now has a real `armv7_a32` target built with `-marm` and run
under `qemu-arm`. A regression test distinguishes its compiler flags from the existing
Thumb `-mthumb` lane. Its first honest baseline is 112/272 (41.2%): 160 behavioral
failures, 38 structural-only results, and two unsupported source cases. This is not a
passing lane; it is the evidence surface that was absent when the incorrect r11
sign-convention hypothesis survived review.

The pinned GCC 11.4 x86-64 lane remains the regression control. A second x86-64 lane
uses host GCC 15 and scores 323/328. Its five failures are exactly:

- `02_integer_widths:O2:reconstruct_64`;
- `03_loop_shapes:O2:for_sum`;
- `03_loop_shapes:O2:loop_continue`;
- `11_call_shapes:O2:call_into_spill`; and
- `14_flag_effects:O2:shift_until_zero`.

Those five shapes therefore cannot be described as architecture-only gaps: the current
compiler shape is sufficient to reproduce every one on x86-64 while the pinned GCC 11
control remains perfect.

## 11:07 — DecBench metric-soundness correction

The proposed `byte_match` empty/empty defect was re-audited against production code.
Production does not award a free perfect score when both disassemblies are empty; it
falls back to extracted raw function bytes. The real M1–M3 defect is ARM mode and range
selection: symbol-declared functions may carry a Thumb T-bit, object extraction must
mask that bit, and Capstone must select Thumb versus A32 from the declared address.

The DecBench fix is commit `cc680f8` with nine focused tests passing, related metric
tests passing, and the complete suite at 453 pass / 13 skip plus eight current-main or
environment failures recorded separately. It is pushed as upstream DecBench PR #61.
It bumps the cache version so stale ARM scores cannot survive the correction. Published
ARM byte-match figures should be regenerated after that PR; the corrected root cause
does not support the broader claim that every empty ARM disassembly received 1.0.

## 11:08 — persistent preprocessed evaluation tree

The new tree at
`/nas4/data/binary-analysis/decbench-holdout-source-rebuild-2026-08-06` is complete for
the current 41-project corpus: 122/122 manifest-declared project/optimization cells,
880 linked binaries, 11,885 preprocessed source files, and no missing cell. It is kept
separate from the old tree because the rebuilt `.text` is not generally identical.
Raw host/container/final-pass reports are retained beside the artifacts.

Two build-driver fixes were required and were covered by RED/GREEN tests: linked PE
images must count as successful outputs, and each project must schedule only its own
declared optimization levels. The compile image also needed the actual development
packages used by the present corpus, and libacl's unresponsive download endpoint was
replaced by the Savannah mirror. The clean upstream commit is `a3583d7`, pushed as
DecBench PR #62; its two focused tests and scoped Ruff gate pass.

The exact historical 250-function manifest is not present. To avoid relabeling a new
draw as the old holdout, a deterministic manifest was reconstructed from the 239 unique
function keys having a published Codex sample. A fresh Glaurung run over those keys is
in progress and is explicitly labeled `published-codex-239`, not the historical
250-function checkpoint.

## 11:09 — linked-list byte-match regression

The exact historical base `b83a066` reproduces `linkedlist:clang:O0` GED 0.0,
type match 1.0, and byte match 0.47 under the current evaluator. The pre-follow-through
`master` reproduces GED 0.0 and byte match 0.10 on the same compiled input. A corrected
`git bisect run` identifies `b2003b556cea929b333f4699c26d207700626482`
(`fix(decompiler): make cross-arch C++ recovery ABI-honest`) as the first bad commit.
The change is a real emission regression, not justified by the unchanged graph
topology:

- historical `list_sum` recompiles to 23 lines with byte match 0.3793; current output
  recompiles to 30 lines with byte match 0.1190;
- historical `list_find` recompiles and scores 0.5667; current `list_find` does not
  compile because it returns `char *` from a `node *` function; and
- current output invents both `stack_0` and `stack_top[8]`, which forces a stack
  protector and a substantially different native frame.

Coalescing O0 pointer spills into argument/field expressions may make the C shorter or
more idiomatic, but GED observes only CFG topology and is 0.0 at both revisions. It is
not evidence that the emitted program is structurally closer at the instruction level.
The fix belongs in storage/high-variable recovery, frame definedness, and locked return
types rather than a byte-match-specific printer exception. The direct type/storage
slices on the follow-through branch recover `node * local_8`, preserve a promoted
slot as an assignment target rather than rewriting it as `local_8->next`, and emit a
valid pointer lvalue. With the extension rebuilt from commit `1fc76ab`, `list_find`
compiles and rises from 0.0 to 0.4194, while `list_sum` is 0.1935. The official cell is
therefore GED 0.0, type match 1.0, byte match 0.31. This repairs most of the 0.10
regression but does not restore the historical 0.47; the residual is retained as open
O0 parameter-home/instruction-shape debt.

## 11:10 — AArch64-only failures reclassified

The recorded “43 AArch64-only” verdict was stale. Against the current pinned x86-64,
i386, and Thumb lanes, the strict set is 21 functions. They do not form one
architecture defect:

- AArch64 SIMD semantics are missing for optimized horizontal reductions
  (`for_sum` becomes an `addv`/`fmov` assembly escape and returns zero).
- Call-result definitions overwrite live argument identities in
  `validate_header`, `hash_lookup`, and `dsu_find`.
- Indirect/direct call outputs and outgoing arguments are not materialized soundly in
  `dispatch` and `call_into_spill`.
- Width provenance/phi roles corrupt the long accumulator in `factorial_while`.
- Fake frame/canary storage remains in `kmp_search` and contributes to its crash.

The full strict list is retained in the defect register. The largest common owner is
the missing sound reaching-definitions/value-role oracle (EPIC 5), followed by
program-level call prototypes (EPIC 1), AArch64 SIMD lifting (EPIC 4), and shared frame
storage recovery (EPIC 3). “AArch64-only” is now a triage filter, not a root cause.

## 11:36 — direct type-match work reached source contracts

The DWARF prototype path rejected an entire signature when any one parameter used an
opaque source typedef. That all-or-nothing policy directly depressed `type_match` and
discarded valid siblings. Commit `199af22` now retains each independently renderable
parameter, downgrades only the opaque slot, accepts multi-level and `void *` parameters,
and normalizes repeated qualifiers. Fresh real-binary signatures include:

- `void gyroInitFilterNotch1(uint16_t arg0, uint16_t arg1)`;
- `void compare_files(char * * arg0)`; and
- `int pkg_array_match_patterns(pkg_array * arg0, char * arg1, void * arg2,
  const char * * arg3)`.

The remaining opaque callback slot demonstrates the architectural boundary: a flat C
type string cannot represent all declarators soundly. It belongs in EPIC 1's canonical
program type environment, not another printer heuristic.

Commits `9a6f627` and `1fc76ab` carry authoritative aggregate-pointer identity through
promoted stack results and keep storage identity distinct from pointee field identity.
The latter defect was exposed only after rebuilding the Python extension: a stale
extension initially repeated the old 0.10 metric despite green Rust source tests. All
subsequent output and metric evidence is from the rebuilt extension.

## 11:40 — final campaign and gate state

The stable `published-codex-239` direct metric campaign ran against `git-1fc76ab` in
four disjoint project shards with four workers each. Each shard wrote only its own
project checkpoints; one canonical finalization then loaded all 34 checkpoints. No
score from the deliberately interrupted pre-fix run was accepted.

The 239-entry manifest realized 222 exact rows across 205 binaries, with no extra row.
The 17 absent keys are retained by name in the shell evidence; causes include missing
DWARF/source filters and successful decompiler processes that returned no matched
function. Metric coverage and arithmetic means over finite values are:

| metric | finite / 222 | mean | median | perfect |
|---|---:|---:|---:|---:|
| GED (lower) | 218 | 22.9312 | 10.0 | 53 |
| type match | 210 | 0.26185 | 0.11111 | 18 |
| byte match | 222 | 0.13425 | 0.0 | 5 |

These are a new compiler/corpus universe and do not replace the historical 250 figures
or prove the Ghidra comparison cleared. They do make the current claims falsifiable.
The type proxy exceeds the historical Glaurung 0.194 and historical Ghidra 0.231 figures,
but not on identical binaries/functions. GED remains above the historical Ghidra 20.43
comparison. Its mean is concentrated: the five worst rows contribute 1,003 of 4,999
total GED, and removing them lowers the mean to 18.76. The current largest owner is
generated/large-function control recovery (`yyparse` alone is GED 337), followed by
large buffer/parser/sort functions—not one generic loop heuristic.

The audit reports 200 `OVERLAY-GAP` notices because this fresh run stores current metrics
inline in checkpoints and has no later `*_new.json` overlay; it reports zero silent-drop
gaps and exits successfully. The artifacts bind the decompiler version to
`git-1fc76ab`.

The final architecture ratchet matches its baseline exactly at 1,531 passes, 269
behavioral failures, 228 structural-only rows, and six declared unsupported cases, with
zero missing cells, timeouts, or lane errors. The post-fix complete Rust gate passes
1,763 library tests plus every integration, example, and benchmark target. The complete
Python gate also terminates green: 2,774 passed, 43 skipped, and six existing pytest
mark warnings in 37 minutes 23 seconds.

## 13:32 — AArch64 call-result ownership fixed at the first corrupting pass

The three requested canaries reproduced as AArch64 O0 failures with green x86-64
controls. Their first shared corruption was `split_spilled_arg_reuse`: after an O0
prologue spilled `x0`, the pass renamed post-spill consumers to `scr_x0` but ignored a
call destination that defined the same value. The AST therefore said `call -> x0` and
`store <- scr_x0`; role naming subsequently made the first the pointer `arg0` and the
second an uninitialised scalar.

A failing Rust ownership test and three real cross-compiled execution tests were added
before the fix. Treating a consumed call destination as a definition and renaming it
with its consumers repairs `validate_header`, `hash_lookup`, and `dsu_find`. The full
matrix exposes eight additional repairs with the same owner: `fib`, `dispatch`,
`dispatch_switch`, `tail_dispatch`, `call_accumulate_bytes`,
`call_twice_and_combine`, `hash_insert`, and `dsu_union`. The final matrix is 1,542
passes, 258 failures, 228 structural rows, and six unsupported rows, with zero
regressions, reclassifications, missing rows, timeouts, or lane errors.
The post-fix full gates also terminate green: Rust has 1,764 library tests plus
all integration and documentation targets, and Python has 2,777 passes, 43 skips,
and the same six existing pytest-mark warnings.

## 14:42 — AArch64 O2 implicit call inputs fixed in shared call-site modeling

`11_call_shapes:aarch64:O2:call_chain_in_loop` and `call_into_spill` both first
lost meaning in `reconstruct_args`, not in lifting or C rendering. The lifted AST
still held every register computation. The first call had no setup because the
loop-carried value was already in x0; the second used a preceding helper result
directly as x0 while x1-x7 were populated for a terminal eight-argument call.

Two failing Rust regressions and one real cross-compiled execution regression were
added before the repair. The shared pass now:

- admits a value-producing AAPCS64 zero-setup call only with proven live-in or
  loop-carried parameter evidence;
- uses the ABI's contiguous register prefix to keep an x1 definition rooted when
  higher call arguments also read it; and
- only on ABIs where the return register is also slot zero, gives the immediately
  preceding call result a distinct identity and substitutes it through every
  derived argument.

An initially broader rule correctly failed existing SysV and Win64 safety tests;
it was narrowed before any matrix claim. All 74 call-argument tests then passed.
The rebuilt extension executes both target functions correctly over the fixture's
seeded vectors. The complete architecture matrix changes exactly those two cells:
1,544 passes, 256 failures, 228 structural rows, and six unsupported rows. The
unrelated AArch64 O2 `call_fold_wide_result` failure and every control-lane verdict
remain unchanged. The strict AArch64-only set is now eight functions.

The complete post-fix gates terminate green: Rust passes 1,766 library tests plus
all integration, example, and benchmark targets; Python reaches 100% with no
failures and the same six pre-existing pytest-mark warnings. Changed-path Rust
formatting and Python Ruff checks pass. Repository-wide Ruff/format/type checks
remain red on pre-existing debt (354 files would be reformatted, 3,830 lint
errors, and 2,044 type diagnostics); this slice adds none of those diagnostics.

## 16:59 — AArch64 rotated-loop results separated from entry parameters

`factorial_while` was traced from its source contract through AArch64 O2 assembly,
lifted IR, every AST pass, emitted DecBench C, and execution. GCC emits a 64-bit
`mul x0,x0,x1`; lifting and structuring preserved it. The first semantic loss was
role projection: the raw x0 result was renamed to the 32-bit input `arg0`, and C
emission inserted `(unsigned long)(unsigned int)` on the loop-carried product.
The failing differential made the truncation concrete: source returned
1,307,674,368,000 while rebuilt C returned 2,004,310,016 for `INT_MAX`.

Three Rust value-role tests and a real cross-compiled execution test were added
before repair. The existing post-spill splitter is now the shared
argument-storage-reuse pass. It consumes the central ABI slot/return tables,
tracks unspilled definitions independently through structured branches, and
enables an unspilled slot-zero split only when the recovered prototype proves a
direct result with exact definitions and a scalar width different from the entry
parameter sharing that storage. Post-spill state remains monotone across
unstructured goto joins, pinned by a separate regression.

The first broad ABI-overlap rule was rejected: the full matrix exposed five gains
and ten regressions. The first proof-gated revision removed nine regressions but
exposed `nested_switch:aarch64:O0`, because structured-arm intersection had lost
the existing post-spill fact across gotos. After correcting that state merge, the
final full matrix changes exactly `factorial_while` and `nested_rotated` from fail
to pass: 1,546 passes, 254 failures, 228 structural rows, and six unsupported
rows, with zero missing cells, timeouts, lane errors, toolchain differences, or
control disagreements. `cargo test --all-targets` is green (including 1,769
library tests), and the complete `uv run pytest python/tests/ -q` run reaches
100% with exit zero and only the same six pytest-mark warnings. Changed-path
Rust formatting and Python Ruff checks pass. Repository-wide checks still expose
established debt: 354 files would be reformatted, 3,830 lint errors, and 2,043
type diagnostics (one fewer than the preceding recorded run).
