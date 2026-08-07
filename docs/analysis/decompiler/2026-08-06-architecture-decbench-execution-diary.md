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

## 18:35 — DWARF array extents reunified AArch64 O0 frame storage

`kmp_search` was traced from source through the retained AArch64 O0 ELF,
disassembly, raw lift, every AST pass, emitted C, and the crashing differential
input. Assembly stores `prefix[0]` at `[sp+40]` and addresses later elements as
`sp+40+4*i`. Promotion emitted the first store as scalar `stack_8 = 0` but the
indexed accesses through a separate `local_58[]`. On the official KMP vector,
the prefix-building loop therefore read uninitialised `local_58[0]`, made
`matched` a large negative value, and faulted at `pattern[matched]`.

The first loss was upstream of stack promotion. DWARF describes `prefix` at
CFA-88 as `int32_t[16]`, but its array DIE has no direct `DW_AT_byte_size`.
The reader followed `DW_AT_type` to the four-byte element and recorded a
non-aggregate four-byte object, discarding the authoritative 64-byte boundary.
The repair derives an array extent from `DW_AT_count` or inclusive lower/upper
bounds, uses the compilation unit language for an omitted lower bound, and
multiplies all dimensions by the recursively recovered element size. Cycles,
unknown bounds, negative extents, and arithmetic overflow fail closed.

After rebuilding the extension, emitted C declares `local_58[64]`; both
`prefix[0]` and every indexed access use that one object, and the 128-vector KMP
differential passes. The canonical full matrix finds the same storage defect in
three neighboring AArch64 O0 fixtures and changes exactly `graph_bfs`,
`graph_dfs`, `dijkstra_dense`, and `kmp_search` from fail to pass: 1,550 passes,
250 failures, 228 structural rows, and six declared unsupported rows, with no
toolchain or metadata drift. A separate 128-vector full run exposed three
indirect-dispatch failures; controlled replay at parent `ec5b2b8` reproduced
them, proving they are higher-fuzz pre-existing defects rather than regressions
from array recovery.

The complete Rust gate passes all 1,769 library tests plus every integration,
example, and benchmark target. The complete Python suite reaches 100% with exit
zero and its six established pytest-mark warnings. Rust formatting, changed-file
Python formatting/linting, and whitespace checks pass. Repository-wide static
checks retain the established debt unchanged: 354 files would be reformatted,
3,830 lint errors, and 2,043 type diagnostics.

## 19:26 — typed AArch64 dword lanes closed the horizontal reduction

`for_sum` was reproduced from its source through the retained GCC 15 AArch64 O2
ELF, disassembly, lifted LLIR, emitted C, and a 128-vector differential. The five
machine instructions are `ldp q31,q30,[x0]`, `add v30.4s,v31.4s,v30.4s`,
`addv s31,v30.4s`, `fmov w0,s31`, and `ret`. Before repair, the pair load read
only two eight-byte scalars, the packed add was represented as one 128-bit
scalar operation, and `addv` plus `fmov` were opaque; emitted C returned zero.

The repair carries a generic `(lane count, element width)` shape on decoded
operands and centralizes packed-dword register spelling for both x86 and
AArch64. A dedicated 203-line AArch64 packed module decomposes Q loads/stores,
lane-wise 4S addition, the horizontal reduction, and the proven 32-bit
FP-to-GPR transfer into ordinary LLIR. The `sN` scalar view is the low dword of `vN`, so
the reduction and transfer share one storage identity. The existing large
AArch64 lifter gains only dispatch glue; the component and its tests do not add
another packed-semantics copy to that file.

The first canonical run appeared to improve `find_first_set` too, but its
emitted C still contained uninitialised vector temporaries. That false pass
exposed an over-broad `xN`/`dN` FMOV claim and the missing `sN`/`vN[0]` alias.
Restricting FMOV to the proven 32-bit form and unifying the low-lane identity
keeps the target green at 128 vectors while returning `find_first_set` to its
honest failure until `dup`, `movi`, `mvni`, `ushl`, `cmtst`, and `umaxp` are
modeled. The fresh six-lane canonical ratchet matches exactly at 1,551 passes,
249 failures, 228 structural rows, and six declared unsupported rows, with the
pinned x86-64 control still 328/328.

The final code passes all 1,774 Rust library tests and every integration,
example, and benchmark target. The complete architecture-roundtrip Python
module and the complete Python suite both reach 100% with exit zero; the latter
retains only the same six pytest-mark warnings. Rust formatting, changed-file
Python formatting/linting, and whitespace checks pass. Repository-wide static
checks retain the established debt: 354 files would be reformatted, 3,830 lint
errors, and 2,043 type diagnostics.

## 20:27 — signed lanes and byte tables closed the AArch64 O2 loop pair

The two remaining `03_loop_shapes` AArch64 O2 failures were round-tripped from
source through retained GCC 15 binaries, disassembly, raw LLIR, emitted C, and
128-vector execution. The retained target ELF at
`/tmp/glaurung-a64-loop-control-20260806/03_loop_shapes-aarch64-O2.so` has SHA-256
`550e1d54f7a2d0f7e3268486d7acfe43517d9ef6e221c415ce134d769d78aa4d`.
`loop_continue` is completely vectorized into `ldp`, a zero `movi`, two signed
`smax vN.4s` operations, lane-wise `add`, `addv`, and `fmov`; only `movi` and
`smax` were opaque. The RED differential returned -14 where the source returned
12 on the first mixed-sign vector. `mutate_reverse` is completely vectorized
into two Q loads, one read-only byte-index vector, two `tbl vN.16b` operations,
and a Q pair store. Both `tbl` instructions were opaque and the RED differential
reported a changed output buffer.

Zero `MOVI` now defines every 4S lane. Non-zero forms remain fail-closed because
the decoded operand does not yet retain the shift/replication modifier. Signed
`SMAX` lowers each lane to an `Slt` comparison and a 32-bit pure select. A
one-register 16-byte `TBL` snapshots all table and index dwords before any
possibly aliasing destination write, then emits one single-output semantic
intrinsic per dword. Each intrinsic declares all four table inputs and its index
dword, reads and writes no memory, and lowers to the complete architectural byte
lookup: indices 0 through 15 select a byte and every other index produces zero.
This keeps the ordinary one-definition SSA model instead of introducing a
multi-output vector exception.

The exact dynamic table expression initially rendered as 45,921 bytes. The
compiler mask is a read-only constant, but read-only folding runs after the main
copy/constant pipeline. A bounded late re-propagation plus two missing general
algebra rules—constant comparisons and constant-condition selects—reduces it to
2,803 bytes while preserving the fully dynamic fallback semantics. Both target
functions then pass 128 vectors, and all 18 functions in the AArch64 O2 loop
fixture pass together.

The first full ratchet found two additional O0 improvements, so neither was
accepted on verdict alone. Source and assembly show both are the same zero-splat
defect: `rb_validate` initializes `parents[16]` and `topological_sort` initializes
`indegree[16]` with `movi v31.4s,#0` followed by four Q stores. Retained ELFs
`16_red_black_tree-aarch64-O0.so` and `23_topological_sort-aarch64-O0.so` under
`/tmp/glaurung-a64-const-select-20260806` have SHA-256
`ed673ff8c3825da818765c9b009ebbacda45e84f59ffec2747a27171f7ff4d3a` and
`debc52da3bc5baca736d4cd841de97f0e5db6e028d759bc0c14cf77381581ca6`.
Their raw LLIR now has four zero lane definitions reaching all sixteen stack
stores, emitted C initializes every array element, and both pass separate
128-vector differentials. The six-lane matrix therefore has exactly four honest
fail-to-pass changes and no regressions: 1,555 passes, 245 failures, 228
structural rows, and six declared unsupported rows; pinned x86-64 remains
328/328.

The final code passes all 1,777 Rust library tests and every integration,
example, benchmark, and other all-targets test. The complete
architecture-roundtrip Python module and the complete Python suite both reach
100% with exit zero; the latter retains only the same six pytest-mark warnings.
Rust formatting, changed-file Python formatting/linting, and whitespace checks
pass. Repository-wide static checks retain the established debt unchanged: 354
files would be reformatted, 3,830 lint errors, and 2,043 type diagnostics.

## 21:33 — explicit AArch64 narrow-load widening closed `process`

The register called the remaining strict row `05_struct_arrays:O0:process` and
classified it as aggregate-shape recovery. The authoritative baseline and
source instead name `05_cleanup_and_state_machine:aarch64:O0:process`; the
function is a cleanup ladder over scalar locals and a `const uint8_t *`, with no
struct or array. That discrepancy was treated as evidence against the existing
diagnosis rather than normalized away.

The retained GCC 15 AArch64 O0 ELF at
`/tmp/glaurung-a64-process-20260806/05_cleanup_and_state_machine-aarch64-O0.so`
has SHA-256
`cb32c7d2aa8f5f42d6f6c37a9395d46ec9680ddbdd9621729fd2a978819990bc`.
Its first failing 128-vector differential returned 1248 where the source
returned 1504 for bytes beginning `[188,19,98,251]`. Assembly uses unsigned
`ldrb w0,[x0]` for byte zero. Raw LLIR had no unknown operations, but represented
that instruction as a one-byte load directly into `w0` followed only by the
generic 32-to-64-bit W-register zero-extension. The architectural 8-to-32-bit
zero-extension was absent. Emitted C therefore evaluated byte zero as signed
`*(char *)arg0`; the high byte 188 became -68. Offset-one through offset-three
loads happened to render as `arg0[n]` and inherit the DWARF `uint8_t *` element
type, which explains why the defect appeared offset-specific despite identical
machine load semantics.

A RED exact-instruction test now requires `LDRB` to load into a distinct value
and explicitly zero-extend it from 8 to 32 bits. A RED real-fixture differential
pins the high-byte mismatch. The lifter now emits explicit widening for every
narrow GPR load: signed load mnemonics retain `SExt`, while unsigned `LDRB` and
`LDRH` use `ZExt`; equal-width and SIMD scalar loads are unchanged. Post-fix
LLIR for `0x5c4` is `Load %temp` then `ZExt %temp, W8 -> W32`, before the existing
W-register canonicalization. Emitted C preserves `(unsigned char)` even for the
zero-offset dereference, and the unchanged O0 binary passes 138 cases.

The full ratchet exposed O2 as the same honest defect, not a free verdict. The
retained O2 ELF has SHA-256
`e552cdca7e9d92a6d1cef6ca67be80ca8bbb94be0649626e19518b34b3e6f32a`;
its optimized body uses four `ldrb` instructions for offsets zero through three,
and post-fix LLIR gives every one an 8-to-32-bit `ZExt`. It also passes 138
cases. The canonical six-lane matrix changes exactly O0 and O2 `process` from
fail to pass and has no regressions: 1,557 passes, 243 failures, 228 structural
rows, and six declared unsupported rows; pinned x86-64 remains 328/328.

The final code passes all 1,778 Rust library tests and every integration,
example, benchmark, and other all-targets test. The complete
architecture-roundtrip Python module and the complete Python suite both reach
100% with exit zero; the latter retains only the same six pytest-mark warnings.
Rust formatting, changed-file Python formatting/linting, and whitespace checks
pass. Repository-wide static checks retain the established debt unchanged: 354
files would be reformatted, 3,830 lint errors, and 2,043 type diagnostics.

## 22:30 — exact `REV16` semantics closed the tracked AArch64 set

The final row in the tracked 43-function AArch64 set was first classified as a
packet-parser value-role defect. A source-to-machine round trip disproved that
hypothesis.
The retained GCC 15 AArch64 O2 ELF at
`/tmp/glaurung-a64-packet-20260806/07_packet_parser-aarch64-O2.so` has SHA-256
`2515a764c691f94b7566b002c7eac91b9de1282f1cc9ec7ac226832b05d8f74e`.
Its `validate_header` symbol is 140 bytes at `0x5e0`. The critical tail loads the
big-endian packet length with `ldrh w0,[x0,#4]`, computes `len - 7`, executes
`rev16 w0,w0`, compares the swapped halfword, and takes the `-6` path when the
declared payload does not fit. Before repair, raw LLIR preserved every value and
branch around `0x628` but represented that one `REV16` as `Unknown`; emitted C
therefore compared the host-endian value. A valid length-four packet returned
source `0` versus recovered `-6`.

Three RED semantic canaries now pin the instruction at its ownership seams: the
AArch64 decoder must emit one pure `byte_swap_16_lanes` intrinsic plus the normal
W-register zero-extension; AST lowering must produce executable unsigned C; and
the concrete AArch64 engine must transform `0x11223344` into `0x22114433` without
halting. A fourth RED test cross-builds the real fixture and reproduces the valid
packet mismatch. The implementation uses one architecture-neutral intrinsic.
Its AST lowering and domain-level executor share the same lane contract, and
AArch64 execution now also registers the existing full-register `bswap` used by
`REV`. Unsupported widths and malformed operand shapes remain fail-safe instead
of indexing unchecked vectors.

Post-fix LLIR replaces the sole `Unknown` at `0x628` with the explicit pure
intrinsic. Emitted C swaps bytes independently in both halfwords before the
existing signed bound. The unchanged binary passes all 138 vectors for
`validate_header`. The broad fixture run also changed `parse_packet` from fail
to pass; this was audited separately rather than accepted from the verdict. Its
assembly has the same `rev16 w2,w2` at `0x690` before the defensive declared-
length check, and its post-fix LLIR carries the same intrinsic. Both AArch64 O2
packet functions and both pinned x86-64 controls pass.

The complete six-architecture ratchet changes exactly those two functions from
fail to pass: 1,559 passes, 241 failures, 228 structural rows, six declared
unsupported rows, no missing/no-case/timeout/lane errors, and pinned x86-64 at
328/328. This empties the original tracked 43-row AArch64 set, but a fresh
unfiltered baseline intersection finds four additional AArch64-only cells that
the later strict-set narrative had omitted: `02_integer_widths:O0:rotl16_3`,
`02_integer_widths:O0:trunc_u16_after_mul`, `02_integer_widths:O2:mul_widen`, and
`02_integer_widths:O2:rt_u32`. The August 1 gap plan already classified all four
as one 16-bit-width residue, so they are restored as the next AArch64 work rather
than silently erased. Other remaining AArch64 failures are shared with at least
one comparator architecture or compiler-shape lane and should be clustered from
their exact verdict intersections.

## 22:50 — the four restored AArch64 width cells split into three owners

The first fresh round trip rejects the August 1 plan's “one 16-bit-width residue”
classification. Retained GCC 15 ELFs are under
`/tmp/glaurung-a64-widths-20260806.yMgUdF`: O0 SHA-256
`09e9f7a92fbd5860d3784059db6485f04e3be552f72ccecb52c0f3a6b3af5c37`
and O2 SHA-256
`6d08b849a4f9d3975e1afa80cb4878d7479f6154bd6a66583b47e1c7c6e0ce30`.
The 128-vector RED differentials are exact: O0 `rotl16_3` returns 2,047 instead
of 65,535 and `trunc_u16_after_mul` returns 509 instead of 65,533 for input
`UINT_MAX`; O2 `mul_widen(UINT_MAX,UINT_MAX)` returns 1 instead of -1; and O2
`rt_u32(1)` returns 0 instead of 1.

The O0 pair share one downstream width-rendering defect. Assembly uses
`ubfiz w0,w0,#3,#13` and `ubfiz w0,w0,#1,#15`. Raw LLIR exactly preserves the
13- and 15-bit extracts, zero-extends them to 32 bits, and shifts at W32. Emitted
C nevertheless casts each extracted value to `unsigned char` before the shift,
discarding five or seven live bits. The first loss is therefore after lifting.

The O2 cells are separate. `mul_widen` assembly is `umull x0,w0,w1`, high-half
shift, then a 32-bit XOR. Raw LLIR preserves the widened inputs and 64-bit
product, but emitted C assigns the product to the 32-bit parameter `arg0`, so
the high half is already gone. This is value-role/storage reuse. `rt_u32` is the
single instruction `ret`; raw LLIR contains only `Return`, and emitted C returns
zero instead of recognizing that the incoming x0 is simultaneously the direct
result. This is an ABI parameter/result-alias case. The next implementation slice
therefore targets the shared O0 rendering defect first and keeps both O2 cells
as independent canaries rather than accepting a four-cell heuristic.

## 23:24 — one exact-width boundary closes both O0 cells

Four AST RED canaries expose the shared design error independently: i13/i15
zero-extension floors its source carrier to one byte, i13 truncation both floors
and lacks an exact mask, an i13 select advertises one-byte storage, and naive
signed i13 extension would use bit 15 rather than the declared bit 12. The real
fixture RED reproduces both retained-ELF failures on the manifest's 128 vectors:
`rotl16_3(UINT_MAX)` is source 65,535 versus recovered 2,047, and
`trunc_u16_after_mul(UINT_MAX)` is source 65,533 versus recovered 509.

The repair adds one architecture-neutral bit-width-to-C boundary. It chooses the
smallest containing ordinary C integer, masks non-byte-aligned values explicitly,
and reconstructs a signed value as `(x ^ sign) - sign` using the LLIR sign bit.
Extension, truncation, and select lowering all consume this one rule. The logic
and its four unit canaries live in `src/ir/ast/width_semantics.rs`; this adds a
232-line cohesive module while shrinking the 15,000-line `ast.rs` rather than
adding another special case to it.

After rebuilding the Python extension, the unchanged O0 ELF passes both
functions. The full `02_integer_widths` O0 slice is 28/28 AArch64 and 28/28
pinned x86-64. The complete six-lane ratchet changes exactly the two expected
cells and nothing else: 1,561 passes, 239 failures, 228 structural rows, six
declared unsupported rows, no missing/no-case/timeout/lane errors, and the
x86-64 control remains 328/328. All 1,784 default-feature Rust library tests
also pass. The full-matrix AArch64-only set is now the two genuinely independent
O2 owners: `mul_widen` value-role/storage reuse and `rt_u32` ABI live-in/result
aliasing.

## 00:25 (2026-08-07) — significant high-bit proof closes the wide x0 roles

The retained O2 integer-width ELF remains
`/tmp/glaurung-a64-widths-20260806.yMgUdF/02_integer_widths-aarch64-O2.so`
(SHA-256 `6d08b849a4f9d3975e1afa80cb4878d7479f6154bd6a66583b47e1c7c6e0ce30`).
`mul_widen` is four instructions: `umull x0,w0,w1`, a 32-bit high-half shift,
an XOR, and `ret`. Raw LLIR and reconstructed AST preserve the 64-bit product.
The loss occurred when source-role naming projected every x0 lifetime onto the
32-bit `arg0`; the high-half shift then read an already truncated parameter.
The exact RED vector was `(UINT_MAX, UINT_MAX)`: source `-1`, recovered `1`.

A prototype-width comparison was insufficient because both the parameter and
final result are 32-bit. The missing witness is an intermediate definition in
the same storage that can carry significant bits above the live-in width. That
query now shares the AST's explicit expression-width oracle with select folding,
and the unspilled-role policy lives beside the value splitter rather than in the
3,000-line Python binding. The policy is evaluated after reconstruction, where
the multiply's 64-bit casts are visible; evaluating it at pipeline entry saw
only widthless temporaries and did not repair the real ELF.

The first implementation treated every eight-byte cast as widening evidence.
The complete six-lane pre-ratchet correctly rejected it: in addition to three
apparent improvements, `27_newton_raphson:aarch64:O2:newton_isqrt` regressed on
input `2` from source `1` to recovered `2`. Its assembly performs only 32-bit
arithmetic and the AST's `(unsigned long)(unsigned int)` is the architectural
W-to-X zero-extension, not a 64-bit source value. Splitting that loop left its
post-break return on the stale parameter role. A RED Rust canary now requires
that shape to remain non-widening. `can_carry_bits_above` accepts actual wide
arithmetic, loads, selects, and signed extensions while failing closed on an
unsigned container canonicalization.

The same audit rejected the temporary `call_fold_wide_result` improvement. Its
wide value comes from `widen_mul`, but the AST call still reconstructed only one
argument and carried no explicit result-width witness; the split happened only
because of the final W-to-X zero-extension. That cell remains a call-contract
and call-result-width defect instead of receiving an incidental behavioral
ratchet.

One additional improvement survived the narrowed proof and was verified from
source through execution. Fresh retained ELF
`/tmp/glaurung-a64-mul-role-20260807.4HJHxh/28_euler_ode-aarch64-O2.so`
has SHA-256 `80000370f7fd8f847e184de6ef33a60767033aed630c0b8409c83fd7606a3fe3`.
`euler_decay_q16` uses `sxtw` for its inputs, 64-bit multiply/subtract/clamps,
and an eight-byte select feeding x0; the source likewise declares `int64_t
state`. Splitting that state from the 32-bit `arg0` changes its real differential
from fail to pass. `newton_isqrt` is restored to pass, and the call-fold cell is
restored to its honest prior failure.

The final six-lane pre-ratchet has exactly two changes:
`02_integer_widths:aarch64:O2:mul_widen` and
`28_euler_ode:aarch64:O2:euler_decay_q16`, both fail to pass. Totals are 1,563
passes / 237 failures, 228 structural rows, six declared unsupported rows, no
missing/no-case/timeout/lane errors, and pinned x86-64 remains 328/328. The
focused real-ELF test passes, all 1,785 Rust library tests pass, and every Rust
all-targets test passes. The sole remaining full-matrix AArch64-only owner is
O2 `rt_u32`, whose body is just `ret` and therefore requires prototype-proven
live-in/result alias materialization rather than another value-role split.

## 01:05 (2026-08-07) — locked live-in/result alias closes `rt_u32`

The last full-matrix AArch64-only row uses the same retained O2 integer-width
ELF and SHA-256 recorded above. Source `rt_u32(uint32_t x)` returns
`(int)(uint32_t)x`; GCC 15 emits only `ret` at `0xa10`. Raw LLIR and every AST
stage therefore contain one bare `Return` and no definition. Machine-only
prototype recovery reasonably classifies that shape as void, but the retained
DWARF contract then locks one unsigned 32-bit parameter and a direct signed
32-bit result. Before repair, direct-result materialization searched only for a
register written inside the body, found none, and DecBench emission fabricated
`return 0`. The exact RED vector was input `1`: source `1`, recovered `0`.

The repair does not pretend the no-op body wrote x0. It permits a live-in result
only when the source prototype locks both direct output and parameter arity, the
result has no machine definition, and parameter zero's storage aliases the ABI
return register. AArch64 x0 satisfies that proof; the pinned SysV control does
not because arg0 is rdi and the result is rax. Unknown, unlocked, void, written-
result, and non-aliasing cases retain their previous behavior. A separate
recursive storage scan recognizes SSA spellings such as `x0#1` and rejects the
fallback rather than returning stale `arg0`. The real ELF now emits `return
arg0` and passes the fixture differential.

Return projection and clearing were also extracted from `ast.rs` into the
300-line `src/ir/direct_output.rs` owner, with locked-alias and negative SysV
unit canaries. This removes 194 lines from the already oversized AST module and
keeps the PyO3 pipeline as orchestration: it passes the recovered prototype and
calling convention, while the semantic policy lives with direct-output
materialization. The pass dump now names this boundary explicitly.

The full `02_integer_widths` O2 slice is 28/28 for AArch64 and 28/28 for pinned
x86-64. The complete six-lane pre-ratchet changes exactly
`02_integer_widths:aarch64:O2:rt_u32` from fail to pass: 1,564 passes / 236
failures, AArch64 312/328, 228 structural rows, six declared unsupported rows,
no missing/no-case/timeout/lane errors, and pinned x86-64 remains 328/328. All
1,787 Rust library tests and the Rust all-targets gate pass. Both the original
43-row set and the fresh full-matrix AArch64-only set are now empty.

## 01:42 (2026-08-07) — exact callee inputs and result width close `call_fold_wide_result`

Retained ELF
`/tmp/glaurung-a64-mul-role-20260807.4HJHxh/11_call_shapes-aarch64-O2.so`
has SHA-256 `21989d9ddf4d8720e6a401afb161a0abe320413e286874893a5a7398c4b8eeeb`.
Source `call_fold_wide_result(uint32_t a, uint32_t b)` calls the 64-bit
`widen_mul(a, b)` and XOR-folds its high and low halves. GCC 15 emits `bl
widen_mul@plt; lsr x1, x0, #32; eor w0, w1, w0`. Before repair, Glaurung had
already recovered `widen_mul`'s locked `[x0, x1]` layout and unsigned-long
result, but emitted a one-argument call assigned back into 32-bit `arg0`.
Input `[4294967295, 4294967295]` therefore returned `1` instead of source `-1`.

Two independent RED canaries identify the owners. `call_args` now requires an
exact two-argument call when both caller live-ins remain untouched;
`value_split` now treats the call-owned 64-bit return contract as a significant
wide definition. The live-in fallback is fail-closed: every storage item must
map to a proven caller parameter slot, and any prior write or call rejects it.
Within a structured loop it uses the existing reaching override instead of the
function-entry register. That last condition came from the first broad run:
the initial rule improved AArch64 but regressed pinned and GCC 15 x86-64
`call_chain_in_loop` by passing entry rdi instead of loop-carried rdi#1. The
attempt was rejected, a RED canary reproduced it, and both real x86-64 controls
now pass all 22 vectors again.

The final AArch64 C is `var0 = widen_mul(arg0, arg1)` with `var0` declared
`unsigned long`; all 22 width-sensitive vectors pass, and all 13 AArch64 O2
call-shape functions pass. The implementation is convention-parametric and has
no AArch64 name gate: exact layout, caller parameter proof, reaching value, and
call-owned width are the semantic inputs.

The complete six-lane ratchet changes exactly
`11_call_shapes:aarch64:O2:call_fold_wide_result` from fail to pass: 1,565
passes / 235 failures, AArch64 313/328, 228 structural rows, six declared
unsupported rows, no missing/no-case/timeout/lane errors, and pinned x86-64
remains 328/328.

## 02:33 (2026-08-07) — structured AArch64 canary removal closes four O2 crashes

The apparent five-function graph/search cluster was partially shared. Retained
AArch64 O2 ELFs and SHA-256 values were:

- `15_binary_search_tree`: `432536005a47887bfd9b6505cc15aeb09b43d48be6ebac2e97530843591747f0`;
- `20_graph_bfs`: `c1c5ef92e12f5430172ae0035fe8821399ec919df6371c04140c08dccb5e8e8f`;
- `21_graph_dfs`: `ce536d154747dee952da25a4f651e1dd784f13e91d2c298c6cc44e82d46fc114`;
- `22_dijkstra`: `cd994f76120c60a5defc9947186d1f1b2b7c1e9941b231e5cb376a61b8dce1ef`;
- `25_kmp_search`: `22be2d0cf6088781ecb2485fab03ed3fe10f2d9641fe9d67cb0b9116ba707c90`.

All five recovered workers initially crashed on their first invalid-input guard
vector. Four shared the same complete cause. GCC's stack protector loaded the
guard address through its GOT slot, loaded the guard value, saved it in the
frame, and compared a fresh value at exit before calling `__stack_chk_fail`.
Late name resolution recognized only the exit value. The source-level AST still
saved through the split form `%addr = *(u64)__stack_chk_guard; store %stack_N =
*(u64)&%addr`, then rendered the exit as `stack_N ==
&glaurung_global_1ffd8[0]`. The portable synthetic global is an address, not the
process guard value, so every legitimate return took the failure path.

The canary owner now recognizes that split GOT sequence across only a
straight-line, definition-safe prologue. After proving the matching saved slot,
it also handles the structured epilogue form `if (saved == guard) { ...;
return; } __stack_chk_fail()`: the successful body is retained and only the
compiler-inserted check/failure path is removed. The proof requires the named
guard relocation, two 64-bit loads, a promoted stack destination, no intervening
use or overwrite, equality with that same slot, and the exact noreturn failure
symbol. A negative unit canary keeps an ordinary following call untouched.

The real AArch64 BFS fixture was RED before the implementation and passes all
vectors after rebuilding the extension. The same pass changes O2 `graph_bfs`,
`graph_dfs`, `dijkstra_dense`, and `kmp_search` from fail to pass. O2
`bst_inorder_checksum` remains fail, proving the fifth row has a second owner
and is not being credited to this repair. The complete six-lane ratchet has
exactly those four improvements and no regressions or reclassifications: 1,569
passes / 231 failures, AArch64 317/328, pinned x86-64 328/328, 228 structural
rows, six declared unsupported rows, and no missing/no-case/timeout/lane errors.

## 03:13 (2026-08-07) — direct failure-arm canary closes the remaining BST row

After the four-function repair, retained O2 `bst_inorder_checksum` still crashed
on its first invalid-input vector. Its prologue was already normalized to a
proven `stack canary: save guard to %stack_3` comment, but its early-return
epilogue had a third post-structuring form:
`if (stack_3 != 0x1ffd8) __stack_chk_fail(); return checksum`. Copy folding had
reduced the fresh guard load to its GOT VA, so the older canary marker test could
not recognize it and the uninitialized synthetic stack slot always selected the
failure call.

Canary normalization now removes this form only when the prologue has already
proved the compared slot is saved guard storage, the predicate is inequality,
the arm contains exactly one call, and that call is the decorated
`__stack_chk_fail` symbol. No guard-address guess is required: the saved-slot
provenance and exact failure sink own the classification. A RED unit test
retains the literal-GOT form, and the real architecture test now covers both
`bst_inorder_checksum` and `graph_bfs`.

The retained BST ELF with SHA-256
`432536005a47887bfd9b6505cc15aeb09b43d48be6ebac2e97530843591747f0`
passes every differential vector after rebuilding. The complete six-lane
ratchet changes exactly `15_binary_search_tree:aarch64:O2:bst_inorder_checksum`
from fail to pass: 1,570 passes / 230 failures, AArch64 318/328, pinned x86-64
328/328, 228 structural rows, six declared unsupported rows, and no regression,
reclassification, missing/no-case/timeout, or lane error.

## 04:02 (2026-08-07) — `BR`/`BLR` separation closes optimized indirect tails

Retained O2 `08_indirect_dispatch` ELF
`/tmp/glaurung-a64-dispatch.xaPqzP/08_indirect_dispatch-aarch64-O2.so`
has SHA-256 `fdb99e68d7cf667fae210c0fe60b54b02f2935203174fec52ffd62da3b4434ba`.
Both `dispatch` and `tail_dispatch` compile to the same guarded tail-transfer
shape: the table entry is loaded from `ops[tag]`, arguments move into w0/w1,
and `br x16` leaves the current frame. Source input `[0, 0, 0]` returns 100;
before repair the recovered function returned -1.

The table, index, and arguments were not the defect. At `0x6d0` and `0x770`,
the AArch64 lifter represented `BR` as `Op::Call`, exactly as it represented
the link-producing `BLR`. The structured AST therefore owned a returning call
inside the guard and then fell through to the source fallback return. This was
the first incorrect stage: the machine instruction has no link/continuation
edge. The ARM64 lifter now emits `Op::IndirectJump` for `BR` and retains
`Op::Call` for `BLR`. Existing function-table resolution then turns the proven
terminal table entry into the architecture-neutral `Call + Return` form;
argument reconstruction supplies the two inputs, and final C returns the call
result rather than the fallback.

The opcode canary uses the real fixture encodings `d61f0200` (`br x16`) and
`d63f0040` (`blr x2`). A real O2 fixture differential covers both optimized
functions, while the complete O0 indirect-dispatch lane is the continuation
control: its ordinary `BLR` calls remain 3/3 pass. The full six-lane pre-ratchet
changes exactly `dispatch` and `tail_dispatch` from fail to pass. Totals are
1,572 passes / 228 failures, AArch64 320/328, pinned x86-64 328/328, 228
structural rows, six declared unsupported rows, and no regression,
reclassification, missing/no-case/timeout, or lane error.

Final validation retains that exact matrix against the updated baseline. Rust
all-targets is green, including 1,793 library tests plus every integration,
example, and benchmark target. The complete Python suite is green at 2,791
passed / 43 skipped with six existing pytest-mark warnings. Rust formatting and
owned-file Ruff formatting/lint are clean. Repository-wide Ruff/ty remain the
pre-existing red debt (354 unformatted files, 3,830 lint findings, and 2,150
type diagnostics); the focused type check reports only six existing pytest-stub
diagnostics outside the added test.

## 04:48 (2026-08-07) — terminating guards make fallthrough tables portable

The remaining O2 switch-table crashes were round-tripped from source through
three machine encodings. AArch64 `negative_cases` adds three, rejects unsigned
indices above five, and loads a dword from the table at `0xc28`; Thumb-2 and A32
emit the same guard/load shape at `0x64c` and `0x6b8`, with PC-relative tables at
`0x8bc` and `0x9fc`. AArch64 `sparse_shared_tail` similarly guards an index up to
22 before loading its shared-tail multiplier. In every case the prepared AST was
already faithful: `if (max u< index) return default; return table[index]`. The
portable readonly materializer did nothing because it understood bounds inside
the taken arm but discarded all facts at the conditional join. Recompiled C
therefore dereferenced the original image VA and crashed.

The architecture-neutral readonly pass now recognizes a no-else arm that is
provably straight-line and ends in `return`. Because that taken edge cannot
reach the following statement, the false edge retains incoming aliases and an
inverted unsigned bound. Signed comparisons are deliberately rejected: their
false path can contain negative table indices. Non-returning arms still clear
all state. The terminal-arm predicate was moved out of `guarded_switch.rs` into
one shared control-semantics module, so guard normalization and readonly folding
use the same transfer proof.

Retained ARM audit objects live in `/tmp/glaurung-arm-readonly.HdvOOf` with
SHA-256 `138605ae5eb34192f3685e3349eebbdb6639074adc326bd6bfb8bfa5e8b46b79`
(Thumb-2) and
`d9dfed1f172eddff5187f8d2ae175921a6138ae0881baa413567f34b92e366f4`
(A32). Both execute 28 native-target-ABI vectors successfully. The AArch64
fixture test executes both affected functions, and the two ARM tests execute
the same source contract under Thumb-2 and A32. The complete pre-ratchet matrix
changes exactly four cells: AArch64 `negative_cases` and `sparse_shared_tail`,
plus Thumb-2 and A32 `negative_cases`. Totals are 1,576 passes / 224 failures,
AArch64 322/328, ARMv7 239/272, A32 113/272, pinned x86-64 328/328, 228
structural rows, six declared unsupported rows, and no regression,
reclassification, missing/no-case/timeout, or lane error.

Final validation reproduces that matrix exactly against the four-cell-updated
baseline. Rust all-targets is green with 1,795 library tests plus every
integration, example, and benchmark target. The complete Python suite is green
at 2,794 passed / 43 skipped with the same six existing pytest-mark warnings.
The new unit proof lives in a 110-line child module, leaving the production
`readonly_fold.rs` at 952 lines instead of growing it past 1,000. Rust formatting
and owned Python formatting/lint are clean; the focused type check has only the
six pre-existing pytest-stub diagnostics. Repository-wide checks retain their
pre-existing debt: 354 Python files would be reformatted, Ruff reports 3,830
findings, and ty reports 2,150 diagnostics.

## 05:27 — exact AArch64 CLZ semantics close the optimized bit-length idiom

`14_flag_effects:shift_until_zero` is a source loop at O0 and passes all 19
vectors there. GCC 15 replaces the O2 loop with `clz w2,w0`, `32-w2`, and a
zero-select. The retained O2 ELF at `/tmp/glaurung-a64-clz.Vhi16O` has SHA-256
`20ae5f5aac1eed32ee7cb57520b80468789fb1d69c56c698cd6659894b073c9c`.
Before repair, the very first LLIR operation was `unknown(clz)`, `%x2` had no
definition, and source input `[1]` returned 1 while rebuilt C returned
1515870843 from stack residue.

AArch64 now emits the same architecture-neutral, width-carrying CLZ intrinsic
already consumed for ARM32. Both instruction forms are pinned by their real
encodings: `5ac01002` (`clz w2,w0`) and `dac01002` (`clz x2,x0`). The downstream
AST owns the exact C semantics, including the architectural `clz(0)==width`
case that `__builtin_clz(0)` alone would leave undefined. Post-fix LLIR defines
`%x2#1 = count_leading_zeros32(%x0)`, and the recovered function passes all 19
vectors. The full pre-ratchet changes exactly this one cell: 1,577 passes / 223
failures, AArch64 323/328, pinned x86-64 328/328, 228 structural rows, six
declared unsupported rows, and no regression, reclassification,
missing/no-case/timeout, or lane error.

Final validation reproduces that one-cell ratchet exactly against the updated
baseline. Rust all-targets is green with 1,796 library tests plus every
integration, example, and benchmark target. The complete Python suite is green
at 2,795 passed / 43 skipped with the same six existing pytest-mark warnings.
Rust formatting and owned Python formatting/lint are clean; the focused type
check reports only the six pre-existing pytest-stub diagnostics. The unrelated
repository-wide debt remains the last measured 354 files needing format, 3,830
Ruff findings, and 2,150 type diagnostics.

## 06:21 — exact call-result lifetimes and bounded frame overlap close packet O0

The retained AArch64 O0 packet ELF at
`/tmp/glaurung-a64-parse-packet.HfJ4bV` has SHA-256
`a774cb71e959fdcf13f4e90991a3f064271a4f3642e1d0a9bc9f7bfa72b1ca48`;
its host reference is
`1e7ece7a6402e900fbd0e51703aeef45dfa49b8c5e89064faebe74f4e739e439`.
The first differential failure was an invalid zero-length packet: source
`parse_packet` returned -2, while recovered C returned 65534. The caller's
assembly and lift were correct. The corruption began in local `decode_header`:
`validate_header` returns a signed `int` through x0, followed by three
`read_be16` calls returning `unsigned short` through the same storage. The
post-spill pass named every definition `scr_x0`, so one source role inherited
the narrow prototype and truncated the validator error.

A shared AST pass now gives every attributed ABI result a fresh definition,
rewrites only its proven reaching uses, and intersects exact identities at
structured joins. It leaves a compatibility copy in architectural storage;
unproven loop-carried or label-crossing uses therefore retain pre-pass semantics
instead of becoming undefined. In the repaired helper the validator result is
an `int`, and all three halfword readers have distinct `unsigned short` roles.

That exposed a second pre-existing valid-packet failure, 266 versus 284. Source
stores the one-byte `ver_type_bits` temporary at `[sp+56]`. Assembly writes it
with `strb`, then GCC loads the word ending exactly at entry SP (`ldr x0,[sp,#56]`)
before extracting only bits 0..7. DWARF proves a one-byte object at CFA-8, but
stack promotion named byte accesses `local_8` and the word view an unrelated,
uninitialized `stack_6`. The AAPCS overlap component now projects an exact
bounded scalar when a wider non-indexed load begins at that object and extends
only through top-of-frame padding. Interior padding, entry-SP crossings,
unbounded slots, indexed accesses, and non-scalar objects remain rejected.

The real fixture passes every invalid and valid vector after both repairs. The
complete pre-ratchet changes exactly
`07_packet_parser:aarch64:O0:parse_packet` from fail to pass: 1,578 passes / 222
failures, AArch64 324/328, pinned x86-64 328/328, 228 structural rows, six
declared unsupported rows, and no regression, reclassification,
missing/no-case/timeout, or lane error.

The first complete Python gate then found a real i386 integration regression,
not an acceptable cosmetic delta. The O2 `cdecl_pair` source calls
`int read_marker(void)`, but the fresh result role was emitted as `long`; the
rebuilt translation unit therefore conflicted with the real callee definition.
Round-tripping that source through its i386 assembly, LLIR, and pass dump showed
that direct-callee recovery reported `no recovered layout`: it discarded every
zero-argument callee because an empty register layout was being used as a proxy
for failed recovery. That also discarded DWARF's complete `int (void)` contract.
The program contract now retains an empty layout only when `DW_AT_prototyped`
and the absence of formal parameters jointly prove `f(void)`. Old-style or
unprototyped empty layouts remain conservative, so a missed machine-code
parameter cannot silently truncate a caller. Recovered C now declares both the
callee and its fresh result role as `int`, and all four real signed input vectors
match the original i386 executable.

Final validation reproduces the 1,578 / 222 ratchet exactly. Rust all-targets is
green with 1,802 library tests plus every integration, example, and benchmark
target; the Python-extension-only zero-arity contract unit proof is separately
green. The complete Python suite is green at 2,796 passed / 43 skipped with six
existing pytest-mark warnings. Rust formatting and the diff whitespace gate are
clean. Owned Python formatting/lint is clean; the focused type check retains the
same 12 pre-existing pytest-stub and test-helper import diagnostics across the
two touched test modules.

## 07:59 — reaching writes preserve recursive saved parameters

The retained AArch64 O2 calling-conventions ELF at
`/tmp/glaurung-a64-fact-mod.1NKIYR` has SHA-256
`10a642211edac267610f26c71dd275f8825fa04fe953992898c3e0428d028466`.
Source `fact_mod(10)` returns 3,628,800; recovered C returned 43,545,600. GCC 15
unrolls five factorial steps, saves `n..n-4` in x4/x5/x6 and frame slots, calls
`fact_mod(n-5)`, restores those values, and applies the modulo chain. The lift,
SSA identities, call-result split, and promoted stack objects all retained that
exact sequence.

The corruption began only in `prepare_for_decbench`. Parameter-home coalescing
recognized the x4 spill as originating from `arg0` and globally renamed its
reload to `arg0`; the recursive call's compatibility result copy had already
overwritten that role. The final multiplication therefore used the recursive
result twice instead of restoring `n`. A shared structured reaching-write query
now tracks a monotone may-write state across sequence, joins, switches,
exceptions, and loop fixed points. A home is coalesced only when none of its
reads can observe a later definition of the proposed source role. Unstructured
label/goto regions fail closed. Ordinary parameter reads before an output write
still coalesce, so the fix does not globally disable the optimization.

The real round trip now passes all 22 recursion vectors. The complete
pre-ratchet matrix changes exactly
`06_calling_conventions:aarch64:O2:fact_mod` from fail to pass: 1,579 passes /
221 failures, AArch64 325/328, pinned x86-64 328/328, 228 structural rows, six
declared unsupported rows, and no regression, reclassification,
missing/no-case/timeout, or lane error.

Final validation reproduces the 1,579 / 221 ratchet exactly. Rust all-targets is
green with 1,806 library tests plus every integration, example, and benchmark
target. The complete Python suite is green at 2,797 passed / 43 skipped with six
existing pytest-mark warnings. Rust/Python formatting, Ruff, and the diff
whitespace gate are clean; the focused type check retains only the same six
pre-existing pytest-stub diagnostics. The reusable production oracle lives in
its own 452-line module rather than adding another dataflow implementation to
the already 15,000-line AST renderer.

## 09:01 — packed AArch64 pre-scan recovers `find_first_set`

The retained GCC 15 AArch64 O2 ELF at
`/tmp/glaurung-a64-find-first-set.doul2e/12_loop_rotation-aarch64-O2.so` has
SHA-256 `d15318f73075d04b3c5c5b203fc1816977dac747d87520e362a31f6b3623551f`.
Source `find_first_set(1)` returns zero; the recovered translation returned -1.
This was not the historical loop-header-hoist defect suggested by the fixture's
warning. The scalar bit-search loop and both exits were already structured
correctly.

GCC had introduced a packed four-lane pre-scan. Assembly at `0x780..0x7d4`
broadcasts `x`, constructs the dword position/count vectors, applies `NEG`,
signed-count `USHL`, `CMTST`, pairwise unsigned `UMAXP`, and transfers the low
qword to x0. The old LLIR made `DUP`, nonzero `MOVI`, `MVNI`, `USHL`, `CMTST`,
`UMAXP`, and the qword `FMOV` opaque; worse, it treated the packed `NEG` as one
scalar operation on an unmodelled whole-vector register. The AST therefore kept
the scalar fallback but derived its window from undefined lane values.

The AArch64 packed lowering now decomposes the sequence into the same shared
32-bit lane identities used by x86 SIMD. Pairwise operations snapshot aliased
inputs before writing destinations. The signed variable shift is one typed,
single-output intrinsic per lane; its architecture-neutral AST expression uses
guarded unsigned left/right shifts, so magnitudes of 32 or greater produce zero
without evaluating an undefined C shift. The low-qword FMOV explicitly joins
the two low dword lanes after zero extension. Shifted/replicated modified
immediates remain fail-closed behind the raw `cmode` check.

The encoded machine-sequence unit test and the real AArch64 execution
differential are green (23 input vectors). The complete pre-ratchet changes
exactly `12_loop_rotation:aarch64:O2:find_first_set` from fail to pass: 1,580
passes / 220 failures, AArch64 326/328, with all other architecture counts,
228 structural rows, six declared-unsupported rows, toolchain fingerprints,
schema checks, and the pinned x86-64 control unchanged.

Final validation reproduces the 1,580 / 220 ratchet exactly. Rust all-targets is
green with 1,808 library tests plus every integration, example, and benchmark
target. The complete Python suite is green at 2,798 passed / 43 skipped with the
same six pytest-mark warnings. Rust formatting, the diff whitespace gate, and
owned Python formatting/lint are clean. The focused type check retains only the
same six pre-existing pytest-stub diagnostics; repository-wide Ruff remains a
pre-existing non-gate with 3,830 diagnostics outside this change.

## 09:44 — aliased load-pair address fixes `rb_validate`

The retained GCC 15 AArch64 O2 ELF at
`/tmp/glaurung-a64-rb-validate.IIvujL/16_red_black_tree-aarch64-O2.so` has
SHA-256 `8c5db55492e46ad70612714b9828b7c65ac67c07d7f2ce201fd02fd5f8890547`.
The original accepted the seven-node balanced tree; the recovered worker died
with SIGSEGV on that same input.

Assembly at `0x8c0` contains `ldp w4,w5,[x4,#4]`: both child fields use the
pre-instruction node pointer in x4. The scalar LLIR expansion emitted the w4
load first and the w5 load second. Because AArch64 w4 is a zero-extending view
of x4, the first destination definition replaced the second load's address.
Recovered C consequently loaded `left`, then dereferenced `left + 8` as a host
pointer. For the leaf value -1 this is the immediate crash path.

Pair-load lowering now queries the shared AArch64 register-view descriptor and
snapshots a base or index only when the first destination aliases that address
storage. Both scalar loads use the preserved pre-instruction address; ordinary
non-aliasing pairs retain their old two-op shape, and writeback still targets
the architectural base. The encoded `LDP` unit proof and the real tree
differential are green across 23 input vectors.

The complete pre-ratchet changes exactly
`16_red_black_tree:aarch64:O2:rb_validate` from fail to pass: 1,581 passes / 219
failures, AArch64 327/328, with every other verdict, all 228 structural rows,
the six declared-unsupported rows, schema/toolchain checks, and the pinned
x86-64 control unchanged.

Independent definedness finding: the earlier `BFI x12,x4,#32,#32` preserves an
architecturally unknown low half that is never observed, but the whole-value IR
still renders that preservation as an uninitialized C read before a later
high-half extraction. It did not cause the differential failure and cannot be
soundly replaced by zero without a bit-level use proof. This is direct evidence
for EPIC 5's definedness oracle rather than a reason to weaken this exact fix.

Final validation reproduces the 1,581 / 219 ratchet exactly. Rust all-targets is
green with 1,809 library tests plus every integration, example, and benchmark
target. The complete Python suite is green at 2,799 passed / 43 skipped with the
same six pytest-mark warnings. Rust/Python formatting, owned Python lint, and
the diff whitespace gate are clean; focused typing retains the repository's six
existing pytest-stub diagnostics.

## 10:11 — packed bit insert closes the AArch64 execution lane

The retained GCC 15 AArch64 O2 ELF at
`/tmp/glaurung-a64-topological-sort.pnl6Ru/23_topological_sort-aarch64-O2.so`
has SHA-256
`6e86b42b2d3f5fef905ada1810868b786b8db14e9082fd482465ecfec1f26d34`.
For a dense four-vertex graph the source returned -1 because no vertex has
indegree zero; the recovered translation returned 4 after incorrectly queuing
every vertex.

The first semantic divergence is assembly `0x714`:
`bit v31.16b,v28.16b,v29.16b`. The preceding packed load, add, and `CMTST`
were explicit in LLIR, but `BIT` remained `Unknown` and rendered as
`/* asm: bit */`. Consequently v31 retained its all-zero initializer instead
of selecting the incremented indegrees under the all-ones comparison masks.
Queue construction then observed four zero indegrees. Control-flow recovery,
stack-array recovery, and the scalar fallback path were not the cause.

The AArch64 packed lifter now implements the complete read-modify-write
semantics `(old Vd & ~Vm) | (Vn & Vm)` over the shared four-dword scalar lane
model. Each lane computes both masked candidates before defining its
destination, so destination/source aliasing remains architectural. Grouping
the `.16B` operation into dwords is exact because the operation is purely
bitwise; it does not assume the mask came from `CMTST` or is all-or-nothing.

The encoded machine-instruction unit proof and the real AArch64 execution
differential are green across all 23 generated cases. The complete pre-ratchet
changes exactly `23_topological_sort:aarch64:O2:topological_sort` from fail to
pass: 1,582 passes / 218 failures, AArch64 328/328, with every other verdict,
all 228 structural rows, six declared-unsupported rows, schema and toolchain
fingerprints, and the pinned x86-64 328/328 control unchanged. The guarded
baseline writer changes one JSON verdict and no metadata.

Final validation reproduces the 1,582 / 218 ratchet exactly. Rust all-targets
is green with 1,810 library tests plus every integration, example, and
benchmark target. The complete Python suite exits zero at an inferred 2,800
passed / 43 skipped, one passing test above the preceding run, with the same
six pytest-mark warnings. Rust/Python formatting, owned Python lint, and the
diff whitespace gate are clean; focused typing retains only the repository's
six existing pytest-stub diagnostics.

## 11:33 — A32 instruction predicates become typed conditional effects

The proposed `aarch64_entry_stack_coordinate` widening was stale against live
main: commit `401ac4f` had already replaced it with the AAPCS-wide coordinate
used by `Arm`, `ArmHardFloat`, and `Aarch64`. The exact remaining A32 failure
was earlier in the pipeline. The retained A32 ELF at
`/tmp/glaurung-armv7-a32-classify.oeNtRa` has SHA-256
`a8243b19c60993b1ce479171b63a0e0df0ebb0d2f850cbb209df78cfacb96303`;
its source `tests/decompiler_fixtures/src/01_conditional_polarity.c` has SHA-256
`eed9d99623f169699046a916c753fef0ad9412831ca84bdd15623a4ca6409df9`.
GCC 15's O2 `early_return` is only four A32 instructions:

```text
cmp   r0, #0
movlt r0, #77
movge r0, #88
bx    lr
```

The old lift emitted `Unknown("movlt")` and `Unknown("movge")`. In `elseif`,
CFG classification also treated `bxeq lr` as neither branch nor return, losing
the returning edge. This explains all nine O2 conditional-polarity failures:
A32 stores a condition code in bits 31:28 of each instruction rather than in a
Thumb IT block, and that encoding was never represented by the A32 lifter.

The lifter now decodes the word's condition field, strips only the matching
Capstone suffix, lifts the base operation, and predicates its effects. Pure
register definitions compute in scratch and conditionally commit. Direct
conditional branches retain their exact `CondJump`; condition-suffixed returns
use the new typed `CondReturn`. Unsupported conditional calls and computed
branches fail closed as `Unknown("predicated control effect")` instead of
silently executing unconditionally.

A scan of all 58 compiled A32 fixture ELFs then found real conditional memory
effects (`streq`, `strne`, `strlt`, conditional byte stores and loads) and
conditional multi-register pops ending in `pc`. That exposed two further
safety defects: stores were unconditional, while loads dereferenced memory
before an `Ite`, even on a hardware path that skips the instruction. Typed
`CondStore` and `CondLoad` operations now keep the memory access itself behind
the predicate; `CondLoad` carries an explicit false-path fallback for SSA.
Conditional pop restores use scratch fallbacks and end in `CondReturn`, so the
false path touches neither the stack nor control flow.

The three conditional operations are carried through use/def, SSA value
numbering, verification, type recovery, xrefs, the Python IR encoding, AST
lowering, concrete interpretation, taint analysis, and symbolic exploration.
The C AST uses a lazy conditional expression for loads and an `if` body for
stores/returns. Concrete and symbolic tests prove a false conditional memory
operation does not resolve its address; symbolic `CondReturn` forks and keeps
the non-returning path reachable. Encoded tests cover exact `movlt`/`movge`,
`bxeq lr`, `streq`, `ldrne`, `popne {...,pc}`, `blne`, and `bxne r3` words. Real
fixture tests cover all 12 conditional-polarity functions and `cas_update`.

The complete pre-ratchet matrix changes 45 cells from fail to pass with zero
regressions: 1,627 passes / 173 failures, 228 structural rows, and six declared
unsupported rows. A32 improves from 113/272 to 156/272 (+43); Thumb improves
from 239/272 to 241/272 (+2). AArch64 and pinned x86-64 remain 328/328, i386
remains 251/272, and the GCC 15 x86-64 comparison remains 323/328. The gains
span conditional polarity, switches, loops, memory effects, call shapes, flag
effects, hash tables, disjoint set, and polynomial evaluation rather than one
fixture family. No lane error, timeout, missing case, status reclassification,
toolchain drift, or new execution failure is present.

The guarded baseline writer reproduces the 1,627 / 173 ratchet exactly: its
diff contains 45 `fail` to `pass` transitions and no added/removed case,
metadata change, or new failure. Rust all-targets is green with 1,820 library
tests plus every integration, example, and benchmark target; the execution
feature library is green at 1,884/1,884. The complete Python suite exits zero
at 2,802 passed / 43 skipped with the same six pytest-mark warnings. The exact
new symbolic-return and conditional-memory proofs pass, and the symbolic
feature compiles. Its complete library run reaches 1,984/1,986: the two
unchanged ordered-trace backend-identity tests require `bitwuzla`, while this
environment reports no Bitwuzla backend; the all-features build independently
confirms the missing `BITWUZLA_LIB_DIR` prerequisite. Rust/Python formatting,
owned Python lint, Cargo checks, and the diff whitespace gate are clean;
focused typing retains only the repository's six existing pytest-stub
diagnostics.

## 12:59 — linked-list residual separated into real emission bugs and a cross-compiler metric confound

The retained source is `tests/decbench_corpus/src/linkedlist.c` at SHA-256
`bd9c934db1c7f83e3aa92b904283c4e4fbf379966356864fb2dd52c78afc89e3`.
The exact Clang O0 ELF used for this audit is
`/tmp/glaurung-linkedlist-current.aPvE3m/roundtrip/build/linkedlist-clang-O0.so`
at SHA-256 `23d6fa7a7914d7febc2f740ac391f889b7408b22fd44b3ea3f2c5347bfd0495a`.
Source, binary disassembly, raw LLIR, prepared AST, emitted C, recompiled
disassembly, behavior, and each official metric were compared. Raw LLIR from
current `master` and historical `b83a066` is identical; the residual begins in
typed source-AST preparation/rendering, not decoding or lifting.

Two real emission defects were present after parameter-home coalescing:

- a declared pointer used in `arg0 != 0` rendered as `(long)arg0 != 0`, making
  Clang emit a register load plus compare instead of the original memory compare;
- a four-byte accumulator consumed
  `zext64(zext32(node->val)) + local_c`, forcing 64-bit arithmetic even though the
  destination observes only the low word. Matching extensions around equality
  operands similarly forced a wide `list_find` compare.

Pointer/null comparisons now consume the pointer representation directly.
Matching equality extensions retain only their common source-width cast. A new
199-line `typed_simplify` module owns the destination-width proof that removes an
outer unsigned machine-parent extension only for modulo-preserving arithmetic and
only when the inner unsigned cast exactly matches the recovered destination.
Division, shifts, signed inner views, and lone extensions fail closed. The real
Clang O0 `list_sum` source now recompiles to the exact original 53 function bytes;
both behavior functions still pass all 38 vectors, GED remains 0.0, and type match
remains 1.0.

The audit also found an independent safety bug. Adjacent promoted-value
propagation treated every `Store { addr: Reg(local_*), ... }` as a local
assignment. Stack promotion currently overloads that shape for both a frame-slot
write and a genuine pointee write. Consequently
`local = pointer; *local = 42; return local` could become `return 42`. Generic
copy propagation now accepts only explicit `Assign` nodes and leaves ambiguous
stores untouched; a direct counterexample regression test proves the pointer
return is retained.

The official 0.47-to-0.31 residual is not evidence that current parameter-home
coalescing is less faithful to the Clang input. DecBench detects this x86-64 ELF
but selects GCC as its recompiler; the producer is Clang 21.1.8, while the metric
actually invokes GCC 15 with `-c -fno-builtin -w`. Per-function uncached scores
are:

| Output | `list_sum` | `list_find` | mean |
|---|---:|---:|---:|
| historical `b83a066` | 0.379310 | 0.566667 | 0.472989 |
| current `master` | 0.193548 | 0.419355 | 0.306452 |
| typed fixes | 0.193548 | 0.419355 | 0.306452 |

The historical extra cursor/result locals happen to make GCC's O0 instruction
selection resemble the original Clang output. A proof-gated experiment that
removed the compiler result home made `list_find` byte-identical when recompiled
with Clang, but reduced its official GCC-vs-Clang score from 0.419355 to 0.322581
and the cell mean from 0.31 to 0.26. That experiment was reverted. The retained
changes fix real representation errors and the pointer-store safety defect while
preserving the official 0.31 score; restoring 0.47 by reintroducing a redundant
source local would optimize for the metric's compiler mismatch rather than the
audited source/binary round trip.

## 14:58 — full ratchets exposed and closed two integration-level defects

The first complete uncached 56-cell metric run rejected an over-broad version of
the pointer-store correction: `statemachine:clang:O0` retained compiler result
homes `local_2c` and `local_4`, dropping type match from 1.0 to 0.4. The retained
state-machine source is SHA-256
`49c3d37927d150e9937d944c7c2a3e19c1b6014d5ba15598ed651a0a1e91b692`; the
exact Clang O0 ELF is
`/tmp/glaurung-statemachine-current.drI0aG/statemachine-clang-O0.so` at SHA-256
`24052f7924d188292e07265774877ad91696fd235853d40839910de6f92e6e73`.
Its source, disassembly, LLIR, AST, emitted declarations, recompiled behavior,
and uncached metrics established that those two stores are scalar result homes,
not pointee writes.

The generic pass still accepts only explicit `Assign` nodes. A separate late
typed path now permits the overloaded `Store` form only when recovered storage is
an integer or boolean, the destination and source widths preserve the store's
truncation, and the original adjacency/single-use proof holds. Pointer,
code-pointer, float, unknown, self-referential, memory-reading, and wider-source
cases fail closed. This removes `local_2c` and `local_4` while retaining the real
`signed char local_1d`; the exact uncached state-machine metric is restored to
GED 0.0, type match 1.0, and byte match 0.13. A synthetic pointer counterexample
and a wider-source truncation counterexample remain unchanged under both passes.

The executable matrix then exposed a distinct backend integration defect before
semantic evaluation. Current DecBench supplies source function names as strings,
but Glaurung's adapter treated every selector as an address and called `hex()` on
it. The adapter now keeps integer address selection on the `--vas` batch path and
handles string selection by enumerating once with `--all --limit 2000`, then
narrowing by exact symbol name with DecBench's existing fail-open denominator
guard. Real adapter tests exercise both selector forms; the legacy and curriculum
executable matrices subsequently pass every required function, including
linked-list and state-machine cells.

The final immutable-code validation is green at every decompiler gate:

- `scripts/decbench-local-gate.sh` runs all five lanes and passes;
- the architecture matrix exactly retains 1,627 pass / 173 known fail, with
  x86-64 and AArch64 both 328/328 and no lane errors;
- both executable round-trip matrices pass every printed required function;
- GED, type match, and byte match have no per-cell regression across 56/56
  official cells; `linkedlist:clang:O0` remains GED 0.0, type 1.0, byte 0.31;
- `cargo test --all-targets` passes 1,827 library tests and all integration,
  example, and benchmark targets;
- the complete 2,847-test Python collection exits zero, and owned Python Ruff
  checks plus the diff whitespace gate pass.

The repository-wide `uvx ty check python/` command is still non-green with 2,044
diagnostics in the existing Python/test-stub surface; it is recorded separately
from the green runtime, Rust, metric, and owned-path lint evidence rather than
misreported as a passing gate.

## 15:56 — bit-demand evidence removes the undefined AArch64 BFI live-in

The independent definedness finding recorded after the `rb_validate` pair-load
repair was reproduced before changing code. The retained source is
`tests/decompiler_fixtures/src/16_red_black_tree.c` at SHA-256
`ab01ca5165d9d63a77b8403f6c566ed47c038c5d07e6b11f72dae3aba16f12f5`.
The exact GCC 15 AArch64 O2 ELF is
`/tmp/glaurung-definedness-bfi.O1W0EJ/16_red_black_tree-aarch64-O2.so` at
SHA-256 `e78eec859bfcaad10f69b840be436bac749f1c7a82a71ce18405446849bec330`.

The source-to-machine path established that lifting was correct. At `0x768`,
`bfi x12,x4,#32,#32` became the architecture-neutral sequence
`(x12 & 0xffffffff) | (zext32(x4) << 32)`. At `0x7cc`, the only observation of
that value was `lsr x3,x12,#32`. Whole-register SSA nevertheless placed an x12
loop phi and value-numbering materialized its entry lane as `var32 = var33`.
`var33` was declared but never assigned, so emitted C read uninitialized storage
even though the low lane could not affect behavior. The existing AST definition
verifier did not catch it: version-zero physical-register live-ins are excluded
before renderer-local naming turns that value into `var33`.

A new architecture-independent `BitDemandOracle` computes demanded masks per
`SsaValue` and per exact `(InstrAddr,use_index)`. Observable memory, control, and
call operands seed the backward fixed point; phi edges propagate the destination
mask to their exact incoming versions. Assignments, masks, shifts, extensions,
extracts, comparisons, and conservative arithmetic transfers preserve the proof.
Unsupported widths and operations expand demand. Return values remain
conservative because LLIR Return does not yet carry an explicit operand. The
fixed point mutates masks in place rather than cloning its maps on every
iteration.

The consuming rewrite is intentionally smaller than the oracle: it replaces a
register input only in a constant-mask `AND`, only when the destination has an
observable demanded lane, and only when that exact input's demand mask is zero.
Functions containing `CondAssign` fail closed because its false-path dependency
on the previous destination is still implicit in LLIR and therefore has no SSA
use identity. All four Python decompilation entry points now share one helper
that builds exceptional-edge SSA, runs the proof, normalizes LLIR, and recomputes
SSA before both region recovery and value numbering.

The real fixture was RED on the undefined-copy assertion and is now green after
rebuilding the extension. Its emitted C contains no source-only live-in copy;
the inserted high lane is retained and the unobserved preserved low lane is not
materialized. All behavior vectors still pass. Synthetic unit proofs separately
show that a high-only observation erases the preserved input while returning the
preserved lane keeps its full low-word demand.

The closure gates are green:

- the five-lane local gate passes, including the exact 1,627/173 architecture
  ratchet, AArch64 and pinned x86-64 at 328/328, both executable corpora, and
  56/56 GED/type/byte cells with no per-cell regression;
- `cargo test --all-targets` passes 1,829 library tests plus every integration,
  example, and benchmark target;
- the complete 2,847-test Python collection exits zero;
- focused Python format/lint, Rust format, and the diff whitespace gate pass.

Repository-wide Ruff formatting remains non-green on 355 pre-existing files and
was not mass-applied. Repository-wide `uvx ty check python/` remains at the same
2,044 existing diagnostics; the changed fixture file has the same six pytest-stub
diagnostics. These baseline limitations remain separate from the green runtime
and decompiler evidence.

## 16:43 — real CMPXCHG failure exposes an implicit-definition memory corruption

The next EPIC 5 slice started from an actual compiler-generated conditional
read-modify-write. The retained C11 source is
`/tmp/glaurung-cmpxchg-source.c` at SHA-256
`f7ad2fd083046667e8117bf73141c1da8d825d4f9c9ba7458d57266b21be3dc0`.
GCC 15 O2 produced `/tmp/glaurung-cmpxchg-gcc-O2.so` at SHA-256
`283e87c1b0c5a57d7f07b0a9d0c06b7061cf45bfffb4728e430fa420bbbc0c1f`.
The decisive machine sequence is `mov %esi,%eax; lock cmpxchg %edx,(%rdi);
jne ...`: success stores `edx`, while failure leaves memory unchanged and puts
the old memory word in `eax`.

The pre-fix lift represented both conditional register updates with
`CondAssign`. For the memory destination it first assigned the old word to a
temporary, conditionally overwrote that temporary, and then emitted an
unconditional store. SSA treated the conditional destination as a pure
definition because the retained false-path value was implicit. Value numbering
therefore emitted `if (equal) t136 = desired; *slot = t136;`; `t136` was
uninitialized on failure. The real round trip returned `-7` correctly for
`slot=7, expected=5, desired=9`, but changed the slot from 7 to arbitrary stack
residue. A second negative-value failure changed `slot=-17` to 4.

The fixed raw LLIR contains a `CondStore` guarded by ZF and an accumulator
`Ite` whose true and false inputs are both explicit. Register-form CMPXCHG uses
the same explicit select for its destination. Emitted C now conditionally writes
`arg2`, defines the accumulator result with a complete ternary, and preserves
the slot on failure. The real round trip agrees on return value and memory for
two success and two failure vectors, including negative values.

An inventory found no remaining producer of `CondAssign`: ordinary conditional
moves had already migrated to `Ite`, ARM predication uses explicit `Ite`,
`CondLoad`, and `CondStore`, and CMPXCHG was the last lifter. The legacy variant
was removed across the IR type, use-def/SSA consumers, value numbering, AST,
interpreter, xrefs, taint, and Python encoding. This deletes more code than the
fix adds and removes the bit-demand oracle's conservative whole-function
bailout. Self-review found that xref address-state handling still understood the
removed operation but not `Ite`: an explicit select could leave a stale pointer
fact or omit address-valued arms. Two RED unit tests now prove ambiguous selects
kill the old fact, both explicit address arms are reported, and `max_xrefs` is
still a hard bound when one instruction names two targets. The retained
limitation is concurrency: LLIR does not yet encode the `lock` prefix's atomicity
or memory ordering, so the current behavioral proof is single-threaded
architectural-state equivalence, not a concurrent C11 proof.

The final gates are green. `cargo test --all-targets` passes 1,831 library tests
and every integration, example, and benchmark target. The five-lane local gate
retains exactly 1,627 architecture passes / 173 known failures, with AArch64 and
the pinned x86-64 control at 328/328, both executable corpora complete, and no
GED/type/byte regression in 56/56 cells. The first full Python run overlapped
these heavy lanes and tripped one 100 ms per-function timeout in the unrelated
30-file Windows vendor corpus. That exact test passed alone after the final
extension rebuild; a subsequent sequential run of the complete 2,848-test
collection exited zero, confirming contention rather than a code regression.

Owned Python format/lint, focused typing, Rust format, and the whitespace gate
pass. Repository-wide baselines remain separately non-green: 354 files would be
reformatted, Ruff reports 3,830 existing diagnostics, and `ty` reports the same
2,044 diagnostics as before. None were mass-edited into this decompiler change.
